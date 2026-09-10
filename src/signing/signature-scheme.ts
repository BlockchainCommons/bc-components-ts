/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * Supported digital signature schemes.
 *
 * This enum represents the various signature schemes supported in this crate,
 * including Ed25519, SR25519, ECDSA, Schnorr, post-quantum ML-DSA, and SSH-based signatures.
 *
 * Ported from bc-components-rust/src/signing/signature_scheme.rs
 */

import type { RandomNumberGenerator } from "@blockchaincommons/rand";

/**
 * Supported digital signature schemes.
 *
 * This enum represents the various signature schemes supported in this package.
 * - Schnorr: BIP-340 Schnorr signature scheme (secp256k1) - DEFAULT
 * - ECDSA: ECDSA signature scheme (secp256k1)
 * - Ed25519: RFC 8032 signatures
 * - Sr25519: Schnorr over Ristretto25519, used by Polkadot/Substrate
 * - MLDSA44: ML-DSA44 post-quantum signature scheme (NIST level 2)
 * - MLDSA65: ML-DSA65 post-quantum signature scheme (NIST level 3)
 * - MLDSA87: ML-DSA87 post-quantum signature scheme (NIST level 5)
 * - SshEd25519: Ed25519 via SSH agent
 * - SshDsa: DSA via SSH agent
 * - SshEcdsaP256: ECDSA P-256 via SSH agent
 * - SshEcdsaP384: ECDSA P-384 via SSH agent
 *
 * Wire format note: Rust models `SignatureScheme` as a unit-only enum;
 * TypeScript uses string-typed values for ergonomic `switch`/`equals`
 * checks. The CBOR/UR wire format never includes the scheme name —
 * only the scheme's integer/byte-string discriminator on `Signature`,
 * `SigningPrivateKey`, `SigningPublicKey` — so this is a stylistic
 * difference, not a parity gap.
 */
export enum SignatureScheme {
  /**
   * BIP-340 Schnorr signature scheme (secp256k1)
   * Default scheme (matching Rust bc-components default when secp256k1 is enabled)
   */
  Schnorr = "Schnorr",

  /**
   * ECDSA signature scheme (secp256k1)
   */
  Ecdsa = "Ecdsa",

  /**
   * Ed25519 signature scheme (RFC 8032)
   */
  Ed25519 = "Ed25519",

  /**
   * SR25519 signature scheme (Schnorr over Ristretto25519)
   * Used by Polkadot/Substrate
   */
  Sr25519 = "Sr25519",

  /**
   * ML-DSA44 post-quantum signature scheme (NIST level 2)
   */
  MLDSA44 = "MLDSA44",

  /**
   * ML-DSA65 post-quantum signature scheme (NIST level 3)
   */
  MLDSA65 = "MLDSA65",

  /**
   * ML-DSA87 post-quantum signature scheme (NIST level 5)
   */
  MLDSA87 = "MLDSA87",

  /**
   * Ed25519 signature via SSH agent.
   * Requires SSH agent daemon support.
   */
  SshEd25519 = "SshEd25519",

  /**
   * DSA signature via SSH agent.
   * Requires SSH agent daemon support.
   */
  SshDsa = "SshDsa",

  /**
   * ECDSA P-256 signature via SSH agent.
   * Requires SSH agent daemon support.
   */
  SshEcdsaP256 = "SshEcdsaP256",

  /**
   * ECDSA P-384 signature via SSH agent.
   * Requires SSH agent daemon support.
   */
  SshEcdsaP384 = "SshEcdsaP384",
}

/**
 * Get the default signature scheme.
 * Defaults to Schnorr (matching Rust bc-components default when secp256k1 is enabled).
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
 * Other signature types like ECDSA, Ed25519, Sr25519, and ML-DSA don't require options.
 */
export type SigningOptions =
  | {
      type: "Schnorr";
      /** Custom random number generator for signature creation */
      rng: RandomNumberGenerator;
    }
  | {
      type: "Ssh";
      /** The namespace used for SSH signatures */
      namespace: string;
      /** The hash algorithm used for SSH signatures */
      hashAlg: "sha256" | "sha512";
    };
