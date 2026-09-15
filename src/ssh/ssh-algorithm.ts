import { ComponentsError } from "../error.js";
import { SignatureScheme } from "../signing/signature-scheme.js";
/**
 * SSH key algorithm identifiers.
 *
 * The six key algorithms `ssh-key` 0.6.7 generates and parses, and that the
 * reference derives from a `PrivateKeyBase`:
 *
 *   - Ed25519 (`ssh-ed25519`)
 *   - DSA (`ssh-dss`) — 1024-bit p, 160-bit q, SHA-1
 *   - RSA (`ssh-rsa`) — 2048-bit keys; `sshsig` signatures name their hash
 *     as `rsa-sha2-256` / `rsa-sha2-512` (RFC 8332)
 *   - ECDSA P-256 (`ecdsa-sha2-nistp256`) — SHA-256
 *   - ECDSA P-384 (`ecdsa-sha2-nistp384`) — SHA-384
 *   - ECDSA P-521 (`ecdsa-sha2-nistp521`) — SHA-512
 *
 * Not supported: FIDO/U2F `sk-*` keys, opaque `name@domain` algorithms,
 * encrypted private keys and `*-cert-v01@openssh.com` certificates.
 */

export type SshAlgorithm =
  | {
      /** `ssh-ed25519`. */
      kind: "ed25519";
    }
  | {
      /** `ssh-dss`. */
      kind: "dsa";
    }
  | {
      /** `ssh-rsa`. */
      kind: "rsa";
    }
  | {
      /** `ecdsa-sha2-nistp256` / `ecdsa-sha2-nistp384` / `ecdsa-sha2-nistp521`. */
      kind: "ecdsa";
      /** The NIST curve of an ECDSA key. */
      curve: SshEcdsaCurve;
    };

/** The NIST curves an SSH ECDSA key can use. */
export type SshEcdsaCurve = "nistp256" | "nistp384" | "nistp521";

/** Wire-format algorithm name as it appears in OpenSSH text and in the key blob. */
export const SSH_ALGO_ED25519 = "ssh-ed25519";
/** Wire-format name of DSA keys. */
export const SSH_ALGO_DSA = "ssh-dss";
/** Wire-format name of RSA keys. */
export const SSH_ALGO_RSA = "ssh-rsa";
/** RFC 8332 name of an RSA signature made with SHA-256 (`sshsig` signature blobs). */
export const SSH_ALGO_RSA_SHA2_256 = "rsa-sha2-256";
/** RFC 8332 name of an RSA signature made with SHA-512 (`sshsig` signature blobs). */
export const SSH_ALGO_RSA_SHA2_512 = "rsa-sha2-512";
/** Wire-format name of ECDSA P-256 keys. */
export const SSH_ALGO_ECDSA_NISTP256 = "ecdsa-sha2-nistp256";
/** Wire-format name of ECDSA P-384 keys. */
export const SSH_ALGO_ECDSA_NISTP384 = "ecdsa-sha2-nistp384";
/** Wire-format name of ECDSA P-521 keys. */
export const SSH_ALGO_ECDSA_NISTP521 = "ecdsa-sha2-nistp521";

/** OpenSSH curve identifier embedded inside ECDSA key blobs. */
export const SSH_CURVE_NISTP256 = "nistp256";
/** OpenSSH curve identifier for P-384. */
export const SSH_CURVE_NISTP384 = "nistp384";
/** OpenSSH curve identifier for P-521. */
export const SSH_CURVE_NISTP521 = "nistp521";

/** The hash an RSA `sshsig` signature was made with. */
export type SshRsaSignatureHash = "sha256" | "sha512";

/** The wire-format name of `algo` (`ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`, …). */
export function sshAlgorithmName(algo: SshAlgorithm): string {
  switch (algo.kind) {
    case "ed25519":
      return SSH_ALGO_ED25519;
    case "dsa":
      return SSH_ALGO_DSA;
    case "rsa":
      return SSH_ALGO_RSA;
    case "ecdsa":
      switch (algo.curve) {
        case "nistp256":
          return SSH_ALGO_ECDSA_NISTP256;
        case "nistp384":
          return SSH_ALGO_ECDSA_NISTP384;
        case "nistp521":
          return SSH_ALGO_ECDSA_NISTP521;
      }
  }
}

/**
 * The algorithm for a wire-format name.
 *
 * As `ssh-key` 0.6.7 `Algorithm::from_str`, the RFC 8332 names
 * `rsa-sha2-256` / `rsa-sha2-512` also denote an RSA key. A name the
 * package does not support is an `Ssh` failure: `ssh-key` accepts any
 * `name@domain` identifier as an opaque algorithm, which this package does
 * not implement (`unsupported algorithm: <name>`); every other unknown name
 * fails its label parser (`invalid label: '<name>'`).
 */
export function parseSshAlgorithm(name: string): SshAlgorithm {
  switch (name) {
    case SSH_ALGO_ED25519:
      return { kind: "ed25519" };
    case SSH_ALGO_DSA:
      return { kind: "dsa" };
    case SSH_ALGO_RSA:
    case SSH_ALGO_RSA_SHA2_256:
    case SSH_ALGO_RSA_SHA2_512:
      return { kind: "rsa" };
    case SSH_ALGO_ECDSA_NISTP256:
      return { kind: "ecdsa", curve: "nistp256" };
    case SSH_ALGO_ECDSA_NISTP384:
      return { kind: "ecdsa", curve: "nistp384" };
    case SSH_ALGO_ECDSA_NISTP521:
      return { kind: "ecdsa", curve: "nistp521" };
    default:
      if (isOpaqueAlgorithmName(name)) {
        throw ComponentsError.ssh(`unsupported algorithm: ${name}`);
      }
      throw ComponentsError.ssh(`invalid label: '${name}'`);
  }
}

/**
 * `ssh-key` 0.6.7 `AlgorithmName::new`: a printable ASCII `name@domain`
 * identifier of at most 64 bytes with a non-empty name and domain and a
 * single `@`.
 */
function isOpaqueAlgorithmName(name: string): boolean {
  if (name.length > 64) return false;
  for (let i = 0; i < name.length; i++) {
    if (name.charCodeAt(i) > 0x7f) return false;
  }
  const at = name.indexOf("@");
  if (at <= 0) return false;
  const domain = name.slice(at + 1);
  return domain.length > 0 && !domain.includes("@");
}

/**
 * The RSA signature-hash for an `sshsig` signature-blob algorithm name
 * (`rsa-sha2-256` / `rsa-sha2-512`), or `undefined` for any other name.
 */
export function sshRsaSignatureHash(name: string): SshRsaSignatureHash | undefined {
  switch (name) {
    case SSH_ALGO_RSA_SHA2_256:
      return "sha256";
    case SSH_ALGO_RSA_SHA2_512:
      return "sha512";
    default:
      return undefined;
  }
}

/** The `sshsig` signature-blob algorithm name of an RSA signature with `hash`. */
export function sshRsaSignatureAlgorithmName(hash: SshRsaSignatureHash): string {
  switch (hash) {
    case "sha256":
      return SSH_ALGO_RSA_SHA2_256;
    case "sha512":
      return SSH_ALGO_RSA_SHA2_512;
  }
}

/**
 * Wire-format curve name corresponding to a `SshEcdsaCurve`.
 */
export function sshCurveName(curve: SshEcdsaCurve): string {
  switch (curve) {
    case "nistp256":
      return SSH_CURVE_NISTP256;
    case "nistp384":
      return SSH_CURVE_NISTP384;
    case "nistp521":
      return SSH_CURVE_NISTP521;
  }
}

/**
 * Byte length of an uncompressed SEC1 point (`0x04 || X || Y`) for the curve.
 */
export function sshEcdsaPointLen(curve: SshEcdsaCurve): number {
  switch (curve) {
    case "nistp256":
      return 65;
    case "nistp384":
      return 97;
    case "nistp521":
      return 133;
  }
}

/**
 * Byte length of the canonical (no sign byte) private scalar for the curve.
 */
export function sshEcdsaScalarLen(curve: SshEcdsaCurve): number {
  switch (curve) {
    case "nistp256":
      return 32;
    case "nistp384":
      return 48;
    case "nistp521":
      return 66;
  }
}

/**
 * Checks that `value` is a well-formed `SshAlgorithm` object and returns it.
 * Anything else — a non-object, an unknown `kind` or an unknown `curve` — is
 * `InvalidData` for `algorithm`.
 */
export function validateSshAlgorithm(value: unknown): SshAlgorithm {
  if (typeof value !== "object" || value === null) {
    throw ComponentsError.invalidDataForType(
      "algorithm",
      `expected an SshAlgorithm object, got ${value === null ? "null" : typeof value}`,
    );
  }
  const kind: unknown = (value as { kind?: unknown }).kind;
  switch (kind) {
    case "ed25519":
    case "dsa":
    case "rsa":
      return { kind };
    case "ecdsa": {
      const curve: unknown = (value as { curve?: unknown }).curve;
      switch (curve) {
        case "nistp256":
        case "nistp384":
        case "nistp521":
          return { kind, curve };
        default:
          throw ComponentsError.invalidDataForType(
            "algorithm",
            `unknown ECDSA curve ${String(curve)}; expected nistp256, nistp384 or nistp521`,
          );
      }
    }
    default:
      throw ComponentsError.invalidDataForType(
        "algorithm",
        `unknown kind ${String(kind)}; expected ed25519, dsa, rsa or ecdsa`,
      );
  }
}

// ---------------------------------------------------------------------------
// Mapping onto `SignatureScheme`
// ---------------------------------------------------------------------------

/**
 * The `SignatureScheme` of an SSH algorithm, or `undefined` for RSA and
 * P-521: the reference defines `SshEd25519`, `SshDsa`, `SshEcdsaP256` and
 * `SshEcdsaP384` only, and its `Signature::scheme()` fails for the others.
 */
export function sshSignatureScheme(algorithm: SshAlgorithm): SignatureScheme | undefined {
  switch (algorithm.kind) {
    case "ed25519":
      return SignatureScheme.SshEd25519;
    case "dsa":
      return SignatureScheme.SshDsa;
    case "rsa":
      return undefined;
    case "ecdsa":
      switch (algorithm.curve) {
        case "nistp256":
          return SignatureScheme.SshEcdsaP256;
        case "nistp384":
          return SignatureScheme.SshEcdsaP384;
        case "nistp521":
          return undefined;
      }
  }
}

/**
 * The failure the reference's `Signature::scheme()` reports for an SSH
 * algorithm without a `SignatureScheme`: `Unsupported SSH ECDSA curve` for
 * an ECDSA curve other than P-256 / P-384, `Unsupported SSH signature
 * algorithm` for everything else (RSA).
 */
export function sshSchemeUnsupportedError(algorithm: SshAlgorithm): ComponentsError {
  return ComponentsError.ssh(
    algorithm.kind === "ecdsa"
      ? "Unsupported SSH ECDSA curve"
      : "Unsupported SSH signature algorithm",
  );
}

/** The `keyType` name of an SSH key (`SSH-Ed25519`, `SSH-RSA`, `SSH-ECDSA-P521`, …). */
export function sshKeyTypeName(algorithm: SshAlgorithm): string {
  switch (algorithm.kind) {
    case "ed25519":
      return "SSH-Ed25519";
    case "dsa":
      return "SSH-DSA";
    case "rsa":
      return "SSH-RSA";
    case "ecdsa":
      switch (algorithm.curve) {
        case "nistp256":
          return "SSH-ECDSA-P256";
        case "nistp384":
          return "SSH-ECDSA-P384";
        case "nistp521":
          return "SSH-ECDSA-P521";
      }
  }
}

/** The `signatureType` name of an `sshsig` signature (`SshEd25519`, `SshRsa`, `SshEcdsaP521`, …). */
export function sshSignatureTypeName(algorithm: SshAlgorithm): string {
  switch (algorithm.kind) {
    case "ed25519":
      return "SshEd25519";
    case "dsa":
      return "SshDsa";
    case "rsa":
      return "SshRsa";
    case "ecdsa":
      switch (algorithm.curve) {
        case "nistp256":
          return "SshEcdsaP256";
        case "nistp384":
          return "SshEcdsaP384";
        case "nistp521":
          return "SshEcdsaP521";
      }
  }
}
