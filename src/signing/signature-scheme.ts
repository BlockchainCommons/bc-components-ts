/**
 * Supported digital signature schemes.
 *
 * This enum represents the various signature schemes supported in this crate,
 * including Ed25519, ECDSA, Schnorr, post-quantum ML-DSA, and SSH-based signatures.
 */

import type { RandomNumberGenerator } from "@blockchaincommons/rand";

/**
 * Supported digital signature schemes.
 *
 * This enum represents the various signature schemes supported in this package.
 * - Schnorr: BIP-340 Schnorr signature scheme (secp256k1) - DEFAULT
 * - ECDSA: ECDSA signature scheme (secp256k1)
 * - Ed25519: RFC 8032 signatures
 * - MLDSA44: ML-DSA44 post-quantum signature scheme (NIST level 2)
 * - MLDSA65: ML-DSA65 post-quantum signature scheme (NIST level 3)
 * - MLDSA87: ML-DSA87 post-quantum signature scheme (NIST level 5)
 * - SshEd25519: Ed25519 via SSH agent
 * - SshDsa: DSA via SSH agent
 * - SshEcdsaP256: ECDSA P-256 via SSH agent
 * - SshEcdsaP384: ECDSA P-384 via SSH agent
 *
 * Wire format note: the reference models `SignatureScheme` as a unit-only enum;
 * TypeScript uses string-typed values for ergonomic `switch`/`equals`
 * checks. The CBOR/UR wire format never includes the scheme name —
 * only the scheme's integer/byte-string discriminator on `Signature`,
 * `SigningPrivateKey`, `SigningPublicKey` — so this is a stylistic
 * difference, not a parity gap.
 */
export const SignatureScheme: Readonly<{
  /** BIP-340 Schnorr over secp256k1 — the default scheme. */
  readonly Schnorr: "Schnorr";
  /** ECDSA over secp256k1 (low-s, as the reference's `secp256k1` crate). */
  readonly Ecdsa: "Ecdsa";
  /** Ed25519 (RFC 8032), verified strictly as the reference's `verify_strict`. */
  readonly Ed25519: "Ed25519";
  /** ML-DSA-44 (FIPS 204), post-quantum. */
  readonly MLDSA44: "MLDSA44";
  /** ML-DSA-65 (FIPS 204), post-quantum. */
  readonly MLDSA65: "MLDSA65";
  /** ML-DSA-87 (FIPS 204), post-quantum. */
  readonly MLDSA87: "MLDSA87";
  /** SSH `ssh-ed25519` (`sshsig`). */
  readonly SshEd25519: "SshEd25519";
  /** SSH `ssh-dss` (`sshsig`); parsed keys only, no generation. */
  readonly SshDsa: "SshDsa";
  /** SSH `ecdsa-sha2-nistp256` (`sshsig`); no low-s normalisation, as the reference and OpenSSH. */
  readonly SshEcdsaP256: "SshEcdsaP256";
  /** SSH `ecdsa-sha2-nistp384` (`sshsig`); no low-s normalisation, as the reference and OpenSSH. */
  readonly SshEcdsaP384: "SshEcdsaP384";
}> = /*#__PURE__*/ Object.freeze({
  /**
   * BIP-340 Schnorr signature scheme (secp256k1)
   * Default scheme
   */
  Schnorr: "Schnorr",

  /**
   * ECDSA signature scheme (secp256k1)
   */
  Ecdsa: "Ecdsa",

  /**
   * Ed25519 signature scheme (RFC 8032)
   */
  Ed25519: "Ed25519",

  /**
   * ML-DSA44 post-quantum signature scheme (NIST level 2)
   */
  MLDSA44: "MLDSA44",

  /**
   * ML-DSA65 post-quantum signature scheme (NIST level 3)
   */
  MLDSA65: "MLDSA65",

  /**
   * ML-DSA87 post-quantum signature scheme (NIST level 5)
   */
  MLDSA87: "MLDSA87",

  /**
   * Ed25519 signature via SSH agent.
   * Requires SSH agent daemon support.
   */
  SshEd25519: "SshEd25519",

  /**
   * DSA signature via SSH agent.
   * Requires SSH agent daemon support.
   */
  SshDsa: "SshDsa",

  /**
   * ECDSA P-256 signature via SSH agent.
   * Requires SSH agent daemon support.
   */
  SshEcdsaP256: "SshEcdsaP256",

  /**
   * ECDSA P-384 signature via SSH agent.
   * Requires SSH agent daemon support.
   */
  SshEcdsaP384: "SshEcdsaP384",
} as const);

/** One of the `SignatureScheme` values. */
export type SignatureScheme = (typeof SignatureScheme)[keyof typeof SignatureScheme];

/**
 * Get the default signature scheme.
 * Defaults to Schnorr.
 */
export function defaultSignatureScheme(): SignatureScheme {
  return SignatureScheme.Schnorr;
}

/**
 * Check if a signature scheme requires SSH agent support.
 *
 * @param scheme - The signature scheme to check
 * @returns true if the scheme requires SSH agent
 */
export function isSshScheme(scheme: SignatureScheme): boolean {
  return (
    scheme === SignatureScheme.SshEd25519 ||
    scheme === SignatureScheme.SshDsa ||
    scheme === SignatureScheme.SshEcdsaP256 ||
    scheme === SignatureScheme.SshEcdsaP384
  );
}

/**
 * Check if a signature scheme is a post-quantum ML-DSA scheme.
 *
 * @param scheme - The signature scheme to check
 * @returns true if the scheme is an ML-DSA scheme
 */
export function isMldsaScheme(scheme: SignatureScheme): boolean {
  return (
    scheme === SignatureScheme.MLDSA44 ||
    scheme === SignatureScheme.MLDSA65 ||
    scheme === SignatureScheme.MLDSA87
  );
}

/**
 * Options for configuring signature creation.
 *
 * Different signature schemes may require specific options:
 * - Schnorr: Optionally accepts a custom random number generator
 * - Ssh: Requires a namespace and hash algorithm
 *
 * Other signature types like ECDSA, Ed25519, and ML-DSA don't require options.
 */
export type SigningOptions =
  | {
      /** Schnorr: the auxiliary randomness is drawn from `rng`. */
      type: "Schnorr";
      /** Custom random number generator for signature creation */
      rng: RandomNumberGenerator;
    }
  | {
      /** SSH: a namespace and hash algorithm select the `sshsig` form. */
      type: "Ssh";
      /** The namespace used for SSH signatures */
      namespace: string;
      /** The hash algorithm used for SSH signatures */
      hashAlg: "sha256" | "sha512";
    };
