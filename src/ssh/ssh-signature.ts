/**
 *
 * SSHSIG (PROTOCOL.sshsig) parser/serializer — the OpenSSH armored
 * signature format used by `ssh-keygen -Y sign`.
 *
 * Mirrors `ssh_key::SshSig` (crate `ssh-key` v0.6.7), so blobs round-trip
 * byte-identically with bytes the reference emits.
 *
 * Outer PEM:
 *
 *     -----BEGIN SSH SIGNATURE-----
 *     <base64, 70-char wrap, LF newlines>
 *     -----END SSH SIGNATURE-----
 *
 * Inner blob (`PROTOCOL.sshsig` §2):
 *
 *     6 bytes "SSHSIG" magic
 *     uint32  version          (must be 1)
 *     string  publickey         (SSH wire-format pubkey blob)
 *     string  namespace         (UTF-8)
 *     string  reserved          (currently empty)
 *     string  hash_algorithm    ("sha256" | "sha512")
 *     string  signature         (algorithm-specific signature blob):
 *
 *   ssh-ed25519 signature blob:
 *     string  algorithm "ssh-ed25519"
 *     string  raw 64-byte signature
 *
 *   ecdsa-sha2-nistp{256,384,521} signature blob:
 *     string  algorithm "ecdsa-sha2-nistp{256,384,521}"
 *     string  inner-blob:
 *         mpint r
 *         mpint s
 *
 *   ssh-dss signature blob:
 *     string  algorithm "ssh-dss"
 *     string  raw 40-byte signature  (r || s, 20 bytes each, q = 160 bits)
 *
 *   ssh-rsa key, signature blob (RFC 8332):
 *     string  algorithm "rsa-sha2-256" | "rsa-sha2-512"
 *     string  RSASSA-PKCS1-v1_5 signature (modulus-sized)
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { SshBufferReader, SshBufferWriter } from "./internal/ssh-buffer.js";
import { decodePem, encodePem, SSH_PEM_LINE_WIDTH } from "./internal/ssh-pem.js";
import {
  parseSshAlgorithm,
  sshAlgorithmName,
  sshEcdsaScalarLen,
  sshRsaSignatureAlgorithmName,
  sshRsaSignatureHash,
  type SshAlgorithm,
} from "./ssh-algorithm.js";
import { SSHPublicKey } from "./ssh-public-key.js";
import { ComponentsError } from "../error.js";

const PEM_LABEL = "SSH SIGNATURE";
const MAGIC = new TextEncoder().encode("SSHSIG");
const SUPPORTED_VERSION = 1;
/** The hash an `sshsig` signature is made over. */
export type SshHashAlgorithm = "sha256" | "sha512";

const ED25519_SIGNATURE_LEN = 64;
const DSA_SIGNATURE_LEN = 40; // r (20) || s (20), q = 160 bits

/** An OpenSSH `sshsig` signature (`-----BEGIN SSH SIGNATURE-----`), version 1. */
export class SSHSignature {
  /** The signing key, embedded in the signature. */
  readonly publicKey: SSHPublicKey;
  /** The application namespace the signature was made in. */
  readonly namespace: string;
  /** The reserved field (empty in every signature OpenSSH writes). */
  readonly reserved: Uint8Array;
  /** The hash the message was digested with. */
  readonly hashAlgorithm: SshHashAlgorithm;
  /**
   * The algorithm name inside the signature blob: the key's wire name for
   * Ed25519, DSA and ECDSA keys, and `rsa-sha2-256` / `rsa-sha2-512` (the
   * hash the RSA signature was made with) for RSA keys.
   */
  readonly signatureAlgorithm: string;
  /**
   * Raw signature bytes specific to the algorithm:
   *   ed25519 → 64-byte concatenation `r || s`
   *   ecdsa   → fixed-width `r || s` (64 / 96 / 132 bytes; the SSH mpint
   *     sign bytes are stripped on parse and re-added on serialize)
   *   dsa     → 40-byte `r || s`
   *   rsa     → the RSASSA-PKCS1-v1_5 signature as stored
   */
  readonly signatureBytes: Uint8Array;

  private constructor(
    publicKey: SSHPublicKey,
    namespace: string,
    reserved: Uint8Array,
    hashAlgorithm: SshHashAlgorithm,
    signatureAlgorithm: string,
    signatureBytes: Uint8Array,
  ) {
    this.publicKey = publicKey;
    this.namespace = namespace;
    this.reserved = reserved;
    this.hashAlgorithm = hashAlgorithm;
    this.signatureAlgorithm = signatureAlgorithm;
    this.signatureBytes = signatureBytes;
  }

  /** Parses the PEM-armoured `sshsig` text, as `ssh_key::SshSig::from_pem`. */
  static fromPem(text: string): SSHSignature {
    return SSHSignature.fromBlob(decodePem(text, PEM_LABEL));
  }

  /** Parses the binary `sshsig` blob (the base64 payload of the text form). */
  static fromBlob(blob: Uint8Array): SSHSignature {
    if (blob.length < MAGIC.length || !bytesEqual(blob.subarray(0, MAGIC.length), MAGIC)) {
      throw ComponentsError.ssh("SSHSignature: missing 'SSHSIG' magic");
    }
    const reader = new SshBufferReader(blob.subarray(MAGIC.length));
    const version = reader.readUint32();
    if (version !== SUPPORTED_VERSION) {
      throw ComponentsError.general(
        `SSHSignature: unsupported SSHSIG version ${version} (expected ${SUPPORTED_VERSION})`,
      );
    }
    const publicKeyBlob = reader.readString();
    const publicKey = SSHPublicKey.fromBlob(publicKeyBlob);
    const namespace = decodeUtf8(reader.readString());
    const reserved = reader.readString();
    const hashAlgRaw = decodeUtf8(reader.readString());
    if (hashAlgRaw !== "sha256" && hashAlgRaw !== "sha512") {
      throw ComponentsError.general(`SSHSignature: unsupported hash algorithm '${hashAlgRaw}'`);
    }
    const sigBlob = reader.readString();
    if (!reader.isAtEnd()) {
      throw ComponentsError.ssh(
        `unexpected trailing data at end of message (${reader.remaining()} bytes)`,
      );
    }
    const { algorithmName, signatureBytes } = decodeAlgorithmSignature(
      publicKey.algorithm,
      sigBlob,
    );
    return new SSHSignature(
      publicKey,
      namespace,
      reserved,
      hashAlgRaw,
      algorithmName,
      signatureBytes,
    );
  }

  /** The PEM-armoured text, wrapped at 70 columns like OpenSSH. */
  toPem(): string {
    return encodePem(PEM_LABEL, this.toBlob(), SSH_PEM_LINE_WIDTH);
  }

  /** The binary `sshsig` blob, byte for byte as OpenSSH writes it. */
  toBlob(): Uint8Array {
    const writer = new SshBufferWriter();
    writer.writeRaw(MAGIC);
    writer.writeUint32(SUPPORTED_VERSION);
    writer.writeString(this.publicKey.toBlob());
    writer.writeStringUtf8(this.namespace);
    writer.writeString(this.reserved);
    writer.writeStringUtf8(this.hashAlgorithm);
    writer.writeString(
      encodeAlgorithmSignature(
        this.publicKey.algorithm,
        this.signatureAlgorithm,
        this.signatureBytes,
      ),
    );
    return writer.bytes();
  }

  /**
   * Build the message that gets signed/verified: the **signed-data** blob
   * defined by `PROTOCOL.sshsig` §3.1.
   *
   *     "SSHSIG" magic
   *     string  namespace
   *     string  reserved
   *     string  hash_algorithm
   *     string  H(message)        ← *digest*, not the raw message
   */
  static signedDataBlob(
    namespace: string,
    hashAlgorithm: SshHashAlgorithm,
    messageDigest: Uint8Array,
  ): Uint8Array {
    const w = new SshBufferWriter();
    w.writeRaw(MAGIC);
    w.writeStringUtf8(namespace);
    w.writeString(new Uint8Array(0));
    w.writeStringUtf8(hashAlgorithm);
    w.writeString(messageDigest);
    return w.bytes();
  }

  /**
   * Construct from already-decoded parts (used by the sign path).
   *
   * `signatureAlgorithm` defaults to the key's wire name; for an RSA key it
   * defaults to `rsa-sha2-512`, the algorithm `ssh-key`'s RSA signer names.
   */
  static fromParts(
    publicKey: SSHPublicKey,
    namespace: string,
    hashAlgorithm: SshHashAlgorithm,
    signatureBytes: Uint8Array,
    signatureAlgorithm?: string,
  ): SSHSignature {
    const algorithm = publicKey.algorithm;
    const defaultName =
      algorithm.kind === "rsa"
        ? sshRsaSignatureAlgorithmName("sha512")
        : sshAlgorithmName(algorithm);
    return new SSHSignature(
      publicKey,
      namespace,
      new Uint8Array(0),
      hashAlgorithm,
      signatureAlgorithm ?? defaultName,
      new Uint8Array(signatureBytes),
    );
  }

  /** Fixed-string mirror of the reference's summarizer for `TAG_SSH_TEXT_SIGNATURE`. */
  toString(): string {
    return "SSHSignature";
  }

  /** SHA-256 digest of canonical PEM bytes — kept for parity with key types. */
  digest(): Uint8Array {
    return sha256(new TextEncoder().encode(this.toPem()));
  }
}

// ---- helpers ---------------------------------------------------------------

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
 * Strip the algorithm wrapping from a signature blob and return the
 * algorithm name it carries plus the raw algorithm-specific bytes:
 *   ed25519 → 64 bytes raw
 *   ecdsa   → `r || s`, fixed-width per curve (32 / 48 / 66 per component)
 *   dsa     → 40 bytes raw `r || s` (q = 160 bits)
 *   rsa     → the PKCS#1 v1.5 signature; the name must be `rsa-sha2-256` or
 *             `rsa-sha2-512` (a plain `ssh-rsa` blob is `length invalid`,
 *             as `ssh-key` 0.6.7 `Signature::new` rejects it)
 */
function decodeAlgorithmSignature(
  algorithm: SshAlgorithm,
  sigBlob: Uint8Array,
): { algorithmName: string; signatureBytes: Uint8Array } {
  const r = new SshBufferReader(sigBlob);
  const algorithmName = decodeUtf8(r.readString());
  if (algorithm.kind === "rsa") {
    if (sshRsaSignatureHash(algorithmName) === undefined) {
      throw ComponentsError.ssh("length invalid");
    }
    const sig = r.readString();
    if (!r.isAtEnd()) {
      throw ComponentsError.ssh("SSHSignature rsa: trailing bytes after raw signature");
    }
    return { algorithmName, signatureBytes: new Uint8Array(sig) };
  }
  const expected = sshAlgorithmName(algorithm);
  if (algorithmName !== expected) {
    throw ComponentsError.ssh(
      `SSHSignature: signature algorithm '${algorithmName}' does not match key algorithm '${expected}'`,
    );
  }
  switch (algorithm.kind) {
    case "ed25519": {
      const sig = r.readString();
      if (!r.isAtEnd()) {
        throw ComponentsError.ssh("SSHSignature ed25519: trailing bytes after raw signature");
      }
      if (sig.length !== ED25519_SIGNATURE_LEN) {
        throw ComponentsError.ssh(
          `SSHSignature ed25519: expected ${ED25519_SIGNATURE_LEN}-byte signature, got ${sig.length}`,
        );
      }
      return { algorithmName, signatureBytes: new Uint8Array(sig) };
    }
    case "ecdsa": {
      const inner = r.readString();
      if (!r.isAtEnd()) {
        throw ComponentsError.ssh("SSHSignature ecdsa: trailing bytes after inner signature blob");
      }
      const innerR = new SshBufferReader(inner);
      const scalarLen = sshEcdsaScalarLen(algorithm.curve);
      const rBytes = stripAndPad(innerR.readMpint(), scalarLen, "ecdsa");
      const sBytes = stripAndPad(innerR.readMpint(), scalarLen, "ecdsa");
      if (!innerR.isAtEnd()) {
        throw ComponentsError.ssh("SSHSignature ecdsa: trailing bytes after r,s");
      }
      const out = new Uint8Array(scalarLen * 2);
      out.set(rBytes, 0);
      out.set(sBytes, scalarLen);
      return { algorithmName, signatureBytes: out };
    }
    case "dsa": {
      const sig = r.readString();
      if (!r.isAtEnd()) {
        throw ComponentsError.ssh("SSHSignature dsa: trailing bytes after raw signature");
      }
      if (sig.length !== DSA_SIGNATURE_LEN) {
        throw ComponentsError.ssh(
          `SSHSignature dsa: expected ${DSA_SIGNATURE_LEN}-byte signature, got ${sig.length}`,
        );
      }
      return { algorithmName, signatureBytes: new Uint8Array(sig) };
    }
  }
}

function encodeAlgorithmSignature(
  algorithm: SshAlgorithm,
  algorithmName: string,
  signatureBytes: Uint8Array,
): Uint8Array {
  const w = new SshBufferWriter();
  w.writeStringUtf8(algorithmName);
  switch (algorithm.kind) {
    case "ed25519": {
      if (signatureBytes.length !== ED25519_SIGNATURE_LEN) {
        throw ComponentsError.ssh(
          `SSHSignature ed25519: signatureBytes length ${signatureBytes.length} != ${ED25519_SIGNATURE_LEN}`,
        );
      }
      w.writeString(signatureBytes);
      break;
    }
    case "ecdsa": {
      const scalarLen = sshEcdsaScalarLen(algorithm.curve);
      const expectedLen = scalarLen * 2;
      if (signatureBytes.length !== expectedLen) {
        throw ComponentsError.ssh(
          `SSHSignature ecdsa: signatureBytes length ${signatureBytes.length} != ${expectedLen} (r||s)`,
        );
      }
      const inner = new SshBufferWriter();
      inner.writeMpintUnsigned(signatureBytes.subarray(0, scalarLen));
      inner.writeMpintUnsigned(signatureBytes.subarray(scalarLen));
      w.writeString(inner.bytes());
      break;
    }
    case "dsa": {
      if (signatureBytes.length !== DSA_SIGNATURE_LEN) {
        throw ComponentsError.ssh(
          `SSHSignature dsa: signatureBytes length ${signatureBytes.length} != ${DSA_SIGNATURE_LEN} (r||s)`,
        );
      }
      w.writeString(signatureBytes);
      break;
    }
    case "rsa": {
      if (sshRsaSignatureHash(algorithmName) === undefined) {
        throw ComponentsError.ssh(
          `SSHSignature rsa: signature algorithm must be rsa-sha2-256 or rsa-sha2-512, got '${algorithmName}'`,
        );
      }
      w.writeString(signatureBytes);
      break;
    }
  }
  return w.bytes();
}

function stripAndPad(mpint: Uint8Array, len: number, label: string): Uint8Array {
  // EC signature components (r, s) are < curve order, so they fit in `len` bytes.
  const stripped = mpint[0] === 0x00 ? mpint.subarray(1) : mpint;
  if (stripped.length > len) {
    throw ComponentsError.ssh(
      `SSHSignature ${label}: r/s component too large (${stripped.length} bytes)`,
    );
  }
  if (stripped.length === len) return new Uint8Array(stripped);
  const out = new Uint8Array(len);
  out.set(stripped, len - stripped.length);
  return out;
}

// `parseSshAlgorithm` is exported by ssh-algorithm.js; we re-export here so that
// callers wanting to feed raw algorithm strings into SSHSignature builders can
// import a single module. (Kept as a re-export to avoid a long import path.)
export { parseSshAlgorithm };
