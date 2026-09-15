/**
 *
 * SSH public-key parser/serializer covering Ed25519, DSA, RSA and ECDSA
 * P-256 / P-384 / P-521.
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
 *   ssh-rsa:
 *     string  "ssh-rsa"
 *     mpint   e   (public exponent)
 *     mpint   n   (modulus)
 *
 *   ecdsa-sha2-nistp{256,384,521}:
 *     string  "ecdsa-sha2-nistp{256,384,521}"
 *     string  "nistp{256,384,521}"
 *     string  <0x04 || X || Y>   (SEC1 uncompressed: 65 / 97 / 133 bytes)
 */

import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { sha1 } from "@noble/hashes/legacy.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { p256, p384, p521 } from "@noble/curves/nist.js";
import { SshBufferReader, SshBufferWriter } from "./internal/ssh-buffer.js";
import { dsaVerify } from "./internal/dsa.js";
import { rsaPkcs1v15Verify } from "./internal/rsa-pkcs1v15.js";
import { decodeBase64Strict, decodeSshFormat, encodeBase64 } from "./internal/ssh-pem.js";
import {
  parseSshAlgorithm,
  sshAlgorithmName,
  sshCurveName,
  sshEcdsaPointLen,
  sshRsaSignatureHash,
  type SshAlgorithm,
  type SshEcdsaCurve,
} from "./ssh-algorithm.js";
import { ComponentsError } from "../error.js";

const ED25519_PUBLIC_KEY_LEN = 32;

/**
 * Internal discriminated union for the algorithm-specific public-key data.
 *
 *   - ed25519: the 32-byte raw public key.
 *   - ecdsa:   curve + 65/97/133-byte SEC1 uncompressed point.
 *   - dsa:     four canonical-positive mpint bytes (p, q, g, y) — sign
 *              byte already stripped on parse, re-added by the writer.
 *   - rsa:     canonical-positive e and n.
 */
export type SshPublicKeyData =
  | {
      /** `ssh-ed25519`. */
      kind: "ed25519";
      /** The 32 raw public key bytes. */
      pubBytes: Uint8Array;
    }
  | {
      /** `ecdsa-sha2-nistp256` / `ecdsa-sha2-nistp384` / `ecdsa-sha2-nistp521`. */
      kind: "ecdsa";
      /** The NIST curve. */
      curve: SshEcdsaCurve;
      /** The SEC1 uncompressed point (65, 97 or 133 bytes). */
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
    }
  | {
      /** `ssh-rsa`. */
      kind: "rsa";
      /** The public exponent, canonical positive bytes. */
      e: Uint8Array;
      /** The modulus, canonical positive bytes. */
      n: Uint8Array;
    };

/** The parts of an `sshsig` signature `verifySshSignature` needs. */
export interface SshSignatureParts {
  /** The key embedded in the signature. */
  publicKey: SSHPublicKey;
  /** The namespace the signature was made in. */
  namespace: string;
  /** The hash the message was digested with. */
  hashAlgorithm: "sha256" | "sha512";
  /** The algorithm name inside the signature blob (`rsa-sha2-256`, `ssh-ed25519`, …). */
  signatureAlgorithm: string;
  /** The raw algorithm-specific signature bytes. */
  signatureBytes: Uint8Array;
}

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
      case "rsa":
        return { kind: "rsa" };
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

  /** A P-521 key from its 133-byte SEC1 uncompressed point. */
  static ecdsaP521(uncompressedPoint: Uint8Array, comment = ""): SSHPublicKey {
    return SSHPublicKey.ecdsa("nistp521", uncompressedPoint, comment);
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

  /** RSA public key. `e` and `n` must already be canonical positive bytes (no sign byte). */
  static rsa(e: Uint8Array, n: Uint8Array, comment = ""): SSHPublicKey {
    return new SSHPublicKey({ kind: "rsa", e: new Uint8Array(e), n: new Uint8Array(n) }, comment);
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

  /**
   * Parses the single-line OpenSSH text form (`<algorithm> <base64 blob> [comment]`)
   * as `ssh-key` 0.6.7 `PublicKey::from_openssh`: trailing whitespace is
   * removed, the algorithm and Base64 segments end at a single space, the
   * Base64 is strict, and the text's algorithm name must equal the blob's
   * (`unknown algorithm` otherwise).
   */
  static fromOpenssh(text: string): SSHPublicKey {
    const { algorithmId, base64Data, comment } = decodeSshFormat(text);
    const blob = decodeBase64Strict(base64Data);
    const parsed = SSHPublicKey.fromBlob(blob, comment);
    if (algorithmId !== sshAlgorithmName(parsed.algorithm)) {
      throw ComponentsError.ssh("unknown algorithm");
    }
    return parsed;
  }

  /** The single-line OpenSSH text form. */
  toOpenssh(): string {
    const algoName = sshAlgorithmName(this.algorithm);
    const blobB64 = encodeBase64(this.toBlob());
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
    let key: SSHPublicKey;
    switch (algorithm.kind) {
      case "ed25519":
        key = SSHPublicKey.ed25519(reader.readString(), comment);
        break;
      case "dsa": {
        const p = stripPositiveMpint(reader.readMpint());
        const q = stripPositiveMpint(reader.readMpint());
        const g = stripPositiveMpint(reader.readMpint());
        const y = stripPositiveMpint(reader.readMpint());
        key = SSHPublicKey.dsa(p, q, g, y, comment);
        break;
      }
      case "rsa": {
        const e = stripPositiveMpint(reader.readMpint());
        const n = stripPositiveMpint(reader.readMpint());
        key = SSHPublicKey.rsa(e, n, comment);
        break;
      }
      case "ecdsa": {
        const curveName = decodeUtf8(reader.readString());
        if (curveName !== sshCurveName(algorithm.curve)) {
          throw ComponentsError.ssh("unknown algorithm");
        }
        key = SSHPublicKey.ecdsa(algorithm.curve, reader.readString(), comment);
        break;
      }
    }
    if (!reader.isAtEnd()) {
      throw ComponentsError.ssh(
        `unexpected trailing data at end of message (${reader.remaining()} bytes)`,
      );
    }
    return key;
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
      case "rsa":
        writer.writeMpintUnsigned(this.data.e);
        writer.writeMpintUnsigned(this.data.n);
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
   * Algorithm-specific raw payload bytes. Throws for DSA and RSA, whose
   * keys are several integers — use `data.p/q/g/y` or `data.e/n` instead.
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
      case "rsa":
        throw ComponentsError.ssh(
          "SSHPublicKey.keyBytes is not defined for RSA — use `data.e/n` instead",
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

  /**
   * Verifies an `sshsig` signature made over `message` in `namespace`, as
   * `ssh_key::PublicKey::verify`: the embedded key must be this key, the
   * namespace must match, and the algorithm-specific signature must verify
   * over the signed-data blob. Never throws on malformed input.
   */
  verifySshSignature(
    namespace: string,
    message: Uint8Array,
    signature: SshSignatureParts,
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
          // `lowS: false`: SSH has no low-s rule. The reference's signatures
          // (RustCrypto `ecdsa`, no normalisation) and OpenSSH's are high-s
          // half the time; noble's default would reject them. Each curve
          // prehashes with its RFC 5656 hash (SHA-256 / SHA-384 / SHA-512).
          switch (this.data.curve) {
            case "nistp256":
              return p256.verify(signature.signatureBytes, signedData, this.data.point, {
                format: "compact",
                lowS: false,
              });
            case "nistp384":
              return p384.verify(signature.signatureBytes, signedData, this.data.point, {
                format: "compact",
                lowS: false,
              });
            case "nistp521":
              return p521.verify(signature.signatureBytes, signedData, this.data.point, {
                format: "compact",
                lowS: false,
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
        case "rsa": {
          // RFC 8332: the signature blob names its own hash
          // (`rsa-sha2-256` / `rsa-sha2-512`); `ssh-rsa` (SHA-1) is never
          // accepted, as `ssh-key` 0.6.7 `Signature::new` rejects it.
          const hash = sshRsaSignatureHash(signature.signatureAlgorithm);
          if (hash === undefined) return false;
          return rsaPkcs1v15Verify({
            n: this.data.n,
            e: this.data.e,
            hash,
            message: signedData,
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
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
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
 * canonical (unsigned) bytes. Used for the DSA and RSA integer components.
 */
function stripPositiveMpint(mpint: Uint8Array): Uint8Array {
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
