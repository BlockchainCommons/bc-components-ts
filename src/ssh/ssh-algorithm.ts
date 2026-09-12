import { ComponentsError } from "../error.js";
/**
 * SSH key algorithm identifiers.
 *
 * Supports the four algorithms the reference implementation actually wires
 * through `SignatureScheme`:
 *
 *   - Ed25519 (`ssh-ed25519`)
 *   - DSA (`ssh-dss`) — 1024-bit p, 160-bit q, SHA-1
 *   - ECDSA P-256 (`ecdsa-sha2-nistp256`) — SHA-256
 *   - ECDSA P-384 (`ecdsa-sha2-nistp384`) — SHA-384
 *
 * Deferred (blocked upstream in the reference's dependencies): RSA (commented out in
 * `signature_scheme.rs:80-81`), P-521 (`ssh-key` upstream bug
 * https://github.com/RustCrypto/SSH/issues/232), encrypted private
 * keys, `cert-v01@openssh.com`.
 */

export type SshAlgorithm =
  | {
      /** `ssh-ed25519`. */
      kind: "ed25519";
    }
  | {
      /** `ssh-dss` (parse only). */
      kind: "dsa";
    }
  | {
      /** `ecdsa-sha2-nistp256` / `ecdsa-sha2-nistp384`. */
      kind: "ecdsa";
      /** The NIST curve of an ECDSA key. */
      curve: SshEcdsaCurve;
    };

/** The NIST curves an SSH ECDSA key can use. */
export type SshEcdsaCurve = "nistp256" | "nistp384";

/** Wire-format algorithm name as it appears in OpenSSH text and in the key blob. */
export const SSH_ALGO_ED25519 = "ssh-ed25519";
/** Wire-format name of DSA keys. */
export const SSH_ALGO_DSA = "ssh-dss";
/** Wire-format name of ECDSA P-256 keys. */
export const SSH_ALGO_ECDSA_NISTP256 = "ecdsa-sha2-nistp256";
/** Wire-format name of ECDSA P-384 keys. */
export const SSH_ALGO_ECDSA_NISTP384 = "ecdsa-sha2-nistp384";

/** OpenSSH curve identifier embedded inside ECDSA key blobs. */
export const SSH_CURVE_NISTP256 = "nistp256";
/** OpenSSH curve identifier for P-384. */
export const SSH_CURVE_NISTP384 = "nistp384";

/** The wire-format name of `algo` (`ssh-ed25519`, `ecdsa-sha2-nistp256`, …). */
export function sshAlgorithmName(algo: SshAlgorithm): string {
  switch (algo.kind) {
    case "ed25519":
      return SSH_ALGO_ED25519;
    case "dsa":
      return SSH_ALGO_DSA;
    case "ecdsa":
      switch (algo.curve) {
        case "nistp256":
          return SSH_ALGO_ECDSA_NISTP256;
        case "nistp384":
          return SSH_ALGO_ECDSA_NISTP384;
      }
  }
}

/** The algorithm for a wire-format name; an unknown name is an `Ssh` failure. */
export function parseSshAlgorithm(name: string): SshAlgorithm {
  switch (name) {
    case SSH_ALGO_ED25519:
      return { kind: "ed25519" };
    case SSH_ALGO_DSA:
      return { kind: "dsa" };
    case SSH_ALGO_ECDSA_NISTP256:
      return { kind: "ecdsa", curve: "nistp256" };
    case SSH_ALGO_ECDSA_NISTP384:
      return { kind: "ecdsa", curve: "nistp384" };
    default:
      throw ComponentsError.general(
        `Unsupported SSH algorithm '${name}'. Supported: ${SSH_ALGO_ED25519}, ${SSH_ALGO_DSA}, ${SSH_ALGO_ECDSA_NISTP256}, ${SSH_ALGO_ECDSA_NISTP384}.`,
      );
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
  }
}
