/**
 *
 * SSH public-key parser/serializer covering Ed25519, DSA, ECDSA P-256,
 * and ECDSA P-384.
 *
 * Mirrors `ssh_key::PublicKey` (crate `ssh-key` v0.6.7) — same OpenSSH
 * single-line text format, same SSH wire-format blob layout (RFC 4253 §6.6),
 * so byte-for-byte round-trips with bytes the reference emits.
 *
 * OpenSSH single-line public key format:
 *
 *     <algorithm> <base64-encoded-blob> [<comment>]
 *
 * Per-algorithm blob layouts (RFC 4253 §6.6 + extensions):
 *
 *   ssh-ed25519:
 *     string  "ssh-ed25519"
 *     string  <32-byte raw public key>
 *
 *   ssh-dss:
 *     string  "ssh-dss"
 *     mpint   p   (1024-bit prime)
 *     mpint   q   (160-bit prime divisor of p-1)
 *     mpint   g   (generator)
 *     mpint   y   (public)
 *
 *   ecdsa-sha2-nistp256:
 *     string  "ecdsa-sha2-nistp256"
 *     string  "nistp256"
 *     string  <0x04 || X (32 bytes) || Y (32 bytes)>   (SEC1 uncompressed)
 *
 *   ecdsa-sha2-nistp384:
 *     string  "ecdsa-sha2-nistp384"
 *     string  "nistp384"
 *     string  <0x04 || X (48 bytes) || Y (48 bytes)>   (SEC1 uncompressed)
 */

import { base64 } from "@scure/base";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { sha1 } from "@noble/hashes/legacy.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { p256, p384 } from "@noble/curves/nist.js";
import { SshBufferReader, SshBufferWriter } from "./internal/ssh-buffer.js";
import { dsaVerify } from "./internal/dsa.js";
import {
  parseSshAlgorithm,
  sshAlgorithmName,
  sshCurveName,
  sshEcdsaPointLen,
  type SshAlgorithm,
  type SshEcdsaCurve,
} from "./ssh-algorithm.js";
import { ComponentsError } from "../error.js";

const ED25519_PUBLIC_KEY_LEN = 32;

/**
 * Internal discriminated union for the algorithm-specific public-key data.
 *
 *   - ed25519: the 32-byte raw public key.
 *   - ecdsa:   curve + 65/97-byte SEC1 uncompressed point.
 *   - dsa:     four canonical-positive mpint bytes (p, q, g, y) — sign
 *              byte already stripped on parse, re-added by the writer.
 */
export type SshPublicKeyData =
  | {
      /** `ssh-ed25519`. */
      kind: "ed25519";
      /** The 32 raw public key bytes. */
      pubBytes: Uint8Array;
    }
  | {
      /** `ecdsa-sha2-nistp256` / `ecdsa-sha2-nistp384`. */
      kind: "ecdsa";
      /** The NIST curve. */
      curve: SshEcdsaCurve;
      /** The SEC1 uncompressed point (65 or 97 bytes). */
      point: Uint8Array;
    }
  | {
      /** `ssh-dss`. */
      kind: "dsa";
      /** The prime modulus, canonical positive bytes. */
      p: Uint8Array;
      /** The subgroup order, canonical positive bytes. */
      q: Uint8Array;
      /** The generator, canonical positive bytes. */
      g: Uint8Array;
      /** The public value, canonical positive bytes. */
      y: Uint8Array;
    };

export class SSHPublicKey {
  /** The parsed key material by algorithm. */
  readonly data: SshPublicKeyData;
  /** The comment field of the OpenSSH text form (may be empty). */
  readonly comment: string;

  private constructor(data: SshPublicKeyData, comment: string) {
    this.data = data;
    this.comment = comment;
  }

  /** Algorithm tag for this key. */
  get algorithm(): SshAlgorithm {
    const data = this.data;
    switch (data.kind) {
      case "ed25519":
        return { kind: "ed25519" };
      case "dsa":
        return { kind: "dsa" };
      case "ecdsa":
        return { kind: "ecdsa", curve: data.curve };
      default: {
        const _exhaustive: never = data;
        throw ComponentsError.ssh(`SSHPublicKey: unreachable kind ${String(_exhaustive)}`);
      }
    }
  }

  // --------------------------------------------------------------------------
  // Constructors
  // --------------------------------------------------------------------------

  /** An Ed25519 key from its 32 raw bytes. */
  static ed25519(keyBytes: Uint8Array, comment = ""): SSHPublicKey {
    if (keyBytes.length !== ED25519_PUBLIC_KEY_LEN) {
      throw ComponentsError.ssh(
        `SSHPublicKey ed25519: expected ${ED25519_PUBLIC_KEY_LEN} bytes, got ${keyBytes.length}`,
      );
    }
    return new SSHPublicKey({ kind: "ed25519", pubBytes: new Uint8Array(keyBytes) }, comment);
  }

  /** A P-256 key from its 65-byte SEC1 uncompressed point. */
  static ecdsaP256(uncompressedPoint: Uint8Array, comment = ""): SSHPublicKey {
    return SSHPublicKey.ecdsa("nistp256", uncompressedPoint, comment);
  }

  /** A P-384 key from its 97-byte SEC1 uncompressed point. */
  static ecdsaP384(uncompressedPoint: Uint8Array, comment = ""): SSHPublicKey {
    return SSHPublicKey.ecdsa("nistp384", uncompressedPoint, comment);
  }

  /** An ECDSA key on `curve` from its SEC1 uncompressed point. */
  static ecdsa(curve: SshEcdsaCurve, uncompressedPoint: Uint8Array, comment = ""): SSHPublicKey {
    const expected = sshEcdsaPointLen(curve);
    if (uncompressedPoint.length !== expected || uncompressedPoint[0] !== 0x04) {
      throw ComponentsError.ssh(
        `SSHPublicKey ecdsa-${curve}: expected ${expected}-byte uncompressed SEC1 point (0x04 prefix), got ${uncompressedPoint.length} bytes prefix=0x${uncompressedPoint[0]?.toString(16) ?? "?"}`,
      );
    }
    return new SSHPublicKey(
      { kind: "ecdsa", curve, point: new Uint8Array(uncompressedPoint) },
      comment,
    );
  }

  /** DSA public key. p/q/g/y must already be canonical positive bytes (no sign byte). */
  static dsa(
    p: Uint8Array,
    q: Uint8Array,
    g: Uint8Array,
    y: Uint8Array,
    comment = "",
  ): SSHPublicKey {
    return new SSHPublicKey(
      {
        kind: "dsa",
        p: new Uint8Array(p),
        q: new Uint8Array(q),
        g: new Uint8Array(g),
        y: new Uint8Array(y),
      },
      comment,
    );
  }

  /**
   * Returns a copy of this SSH public key with the comment replaced,
   * leaving this instance untouched.
   */
  withComment(comment: string): SSHPublicKey {
    return new SSHPublicKey(this.data, comment);
  }

  // --------------------------------------------------------------------------
  // OpenSSH text format
  // --------------------------------------------------------------------------

  /** Parses the single-line OpenSSH text form (`<algorithm> <base64 blob> [comment]`). */
  static fromOpenssh(text: string): SSHPublicKey {
    const trimmed = text.trim();
    if (trimmed.length === 0) {
      throw ComponentsError.ssh("SSHPublicKey.fromOpenssh: empty input");
    }
    const firstSpace = trimmed.indexOf(" ");
    if (firstSpace < 0) {
      throw ComponentsError.ssh(
        `SSHPublicKey.fromOpenssh: expected '<algo> <base64> [comment]', got '${trimmed}'`,
      );
    }
    const algoName = trimmed.slice(0, firstSpace);
    const rest = trimmed.slice(firstSpace + 1);

    const secondSpace = rest.indexOf(" ");
    let blobB64: string;
    let comment: string;
    if (secondSpace < 0) {
      blobB64 = rest;
      comment = "";
    } else {
      blobB64 = rest.slice(0, secondSpace);
      comment = rest.slice(secondSpace + 1);
    }

    parseSshAlgorithm(algoName); // validate early — throws on unsupported
    const blob = base64.decode(blobB64);
    const parsed = SSHPublicKey.fromBlob(blob, comment);
    if (sshAlgorithmName(parsed.algorithm) !== algoName) {
      throw ComponentsError.ssh(
        `SSHPublicKey.fromOpenssh: outer algorithm '${algoName}' does not match inner '${sshAlgorithmName(parsed.algorithm)}'`,
      );
    }
    return parsed;
  }

  /** The single-line OpenSSH text form. */
  toOpenssh(): string {
    const algoName = sshAlgorithmName(this.algorithm);
    const blobB64 = base64.encode(this.toBlob());
    return this.comment.length === 0
      ? `${algoName} ${blobB64}`
      : `${algoName} ${blobB64} ${this.comment}`;
  }

  // --------------------------------------------------------------------------
  // SSH wire-format blob
  // --------------------------------------------------------------------------

  /** Parses the binary key blob (the base64 payload of the text form). */
  static fromBlob(blob: Uint8Array, comment = ""): SSHPublicKey {
    const reader = new SshBufferReader(blob);
    const algoName = decodeUtf8(reader.readString());
    const algorithm = parseSshAlgorithm(algoName);
    switch (algorithm.kind) {
      case "ed25519": {
        const pub = reader.readString();
        if (!reader.isAtEnd()) {
          throw ComponentsError.ssh(
            "SSHPublicKey.fromBlob ed25519: trailing bytes after public key",
          );
        }
        return SSHPublicKey.ed25519(pub, comment);
      }
      case "dsa": {
        const p = stripDsaMpint(reader.readMpint());
        const q = stripDsaMpint(reader.readMpint());
        const g = stripDsaMpint(reader.readMpint());
        const y = stripDsaMpint(reader.readMpint());
        if (!reader.isAtEnd()) {
          throw ComponentsError.ssh("SSHPublicKey.fromBlob dsa: trailing bytes after y");
        }
        return SSHPublicKey.dsa(p, q, g, y, comment);
      }
      case "ecdsa": {
        const curveName = decodeUtf8(reader.readString());
        if (curveName !== sshCurveName(algorithm.curve)) {
          throw ComponentsError.ssh(
            `SSHPublicKey.fromBlob ecdsa: blob curve '${curveName}' does not match algorithm '${sshCurveName(algorithm.curve)}'`,
          );
        }
        const point = reader.readString();
        if (!reader.isAtEnd()) {
          throw ComponentsError.ssh(
            "SSHPublicKey.fromBlob ecdsa: trailing bytes after public point",
          );
        }
        return SSHPublicKey.ecdsa(algorithm.curve, point, comment);
      }
    }
  }

  /** The binary key blob, byte for byte as OpenSSH writes it. */
  toBlob(): Uint8Array {
    const writer = new SshBufferWriter();
    writer.writeStringUtf8(sshAlgorithmName(this.algorithm));
    switch (this.data.kind) {
      case "ed25519":
        writer.writeString(this.data.pubBytes);
        break;
      case "dsa":
        writer.writeMpintUnsigned(this.data.p);
        writer.writeMpintUnsigned(this.data.q);
        writer.writeMpintUnsigned(this.data.g);
        writer.writeMpintUnsigned(this.data.y);
        break;
      case "ecdsa":
        writer.writeStringUtf8(sshCurveName(this.data.curve));
        writer.writeString(this.data.point);
        break;
    }
    return writer.bytes();
  }

  // --------------------------------------------------------------------------
  // Reference / display
  // --------------------------------------------------------------------------

  /** SHA-256 of the OpenSSH text form (the reference's `Reference` image). */
  digest(): Uint8Array {
    return sha256(new TextEncoder().encode(this.toOpenssh()));
  }

  /** The first four bytes of `digest()` in hex, the reference's `ref_hex_short`. */
  refHexShort(): string {
    const d = this.digest();
    let s = "";
    for (let i = 0; i < 4; i++) s += d[i].toString(16).padStart(2, "0");
    return s;
  }

  /** `SSHPublicKey(<short reference>)`, the reference's `Display`. */
  toString(): string {
    return `SSHPublicKey(${this.refHexShort()})`;
  }

  /** `true` when algorithm, key material and comment are all equal. */
  equals(other: SSHPublicKey): boolean {
    return this.toOpenssh() === other.toOpenssh();
  }

  /**
   * Comment-insensitive equality: matches when algorithm and key data
   * agree, ignoring the comment. Used by verify paths since SSH
   * wire-format pubkey blobs carry the key but not the comment.
   */
  keyEquals(other: SSHPublicKey): boolean {
    return bytesEqual(this.toBlob(), other.toBlob());
  }

  // --------------------------------------------------------------------------
  // Legacy accessors retained for backward compatibility / direct callers
  // --------------------------------------------------------------------------

  /**
   * Algorithm-specific raw payload bytes. Throws for DSA — DSA needs structured
   * access via `data.p/q/g/y`.
   */
  get keyBytes(): Uint8Array {
    const data = this.data;
    switch (data.kind) {
      case "ed25519":
        return data.pubBytes;
      case "ecdsa":
        return data.point;
      case "dsa":
        throw ComponentsError.ssh(
          "SSHPublicKey.keyBytes is not defined for DSA — use `data.p/q/g/y` instead",
        );
      default: {
        const _exhaustive: never = data;
        throw ComponentsError.ssh(`SSHPublicKey: unreachable kind ${String(_exhaustive)}`);
      }
    }
  }

  // --------------------------------------------------------------------------
  // SSHSIG verify (PROTOCOL.sshsig §3.1)
  // --------------------------------------------------------------------------

  /** Verifies an `sshsig` signature made over `message` in `namespace`. */
  verifySshSignature(
    namespace: string,
    message: Uint8Array,
    signature: {
      publicKey: SSHPublicKey;
      namespace: string;
      hashAlgorithm: "sha256" | "sha512";
      signatureBytes: Uint8Array;
    },
  ): boolean {
    if (!this.keyEquals(signature.publicKey)) return false;
    if (signature.namespace !== namespace) return false;
    const messageDigest = signature.hashAlgorithm === "sha256" ? sha256(message) : sha512(message);
    const signedData = signedDataBlobInline(namespace, signature.hashAlgorithm, messageDigest);
    try {
      switch (this.data.kind) {
        case "ed25519":
          return ed25519.verify(signature.signatureBytes, signedData, this.data.pubBytes);
        case "ecdsa":
          switch (this.data.curve) {
            case "nistp256":
              return p256.verify(signature.signatureBytes, signedData, this.data.point, {
                format: "compact",
              });
            case "nistp384":
              return p384.verify(signature.signatureBytes, signedData, this.data.point, {
                format: "compact",
              });
          }
          return false;
        case "dsa": {
          // SSH-DSA always hashes the signed-data with SHA-1 before signing.
          const innerDigest = sha1(signedData);
          return dsaVerify({
            p: this.data.p,
            q: this.data.q,
            g: this.data.g,
            y: this.data.y,
            messageDigest: innerDigest,
            signature: signature.signatureBytes,
          });
        }
      }
    } catch {
      return false;
    }
  }
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

function decodeUtf8(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Strip the optional 0x00 sign byte from a positive `mpint` and return the
 * canonical (unsigned) bytes. Used for DSA p/q/g/y components.
 */
function stripDsaMpint(mpint: Uint8Array): Uint8Array {
  if (mpint.length > 0 && mpint[0] === 0x00) {
    return new Uint8Array(mpint.subarray(1));
  }
  return new Uint8Array(mpint);
}

// Re-create the SSHSIG signed-data layout inline to avoid a circular import
// from `ssh-signature.ts`. Keep in sync with `SSHSignature.signedDataBlob`.
const SSHSIG_MAGIC = new TextEncoder().encode("SSHSIG");

function signedDataBlobInline(
  namespace: string,
  hashAlg: "sha256" | "sha512",
  messageDigest: Uint8Array,
): Uint8Array {
  const w = new SshBufferWriter();
  w.writeRaw(SSHSIG_MAGIC);
  w.writeStringUtf8(namespace);
  w.writeString(new Uint8Array(0));
  w.writeStringUtf8(hashAlg);
  w.writeString(messageDigest);
  return w.bytes();
}
