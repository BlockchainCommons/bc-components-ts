/**
 * MLDSA Security Level - ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
 *
 * ML-DSA is a post-quantum digital signature algorithm standardized by NIST.
 * It provides three security levels corresponding to different NIST security categories.
 *
 * Security levels:
 * - MLDSA44: NIST Level 2 (equivalent to AES-128)
 * - MLDSA65: NIST Level 3 (equivalent to AES-192)
 * - MLDSA87: NIST Level 5 (equivalent to AES-256)
 *
 * Naming note: the reference calls this enum `MLDSA`. TypeScript uses `MLDSALevel`
 * to avoid colliding with the keypair type names (`MLDSAPrivateKey` /
 * `MLDSAPublicKey` / `MLDSASignature`). The CBOR discriminator (the
 * numeric level) is identical in both languages — this is a TS-only
 * naming choice with no wire-format effect.
 */

import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { type RandomNumberGenerator, secureRng, randomBytes } from "@blockchaincommons/rand";
import { ComponentsError } from "../error.js";

/**
 * ML-DSA security levels.
 *
 * The numeric values correspond to NIST security levels:
 * - 2: NIST Level 2 (MLDSA44)
 * - 3: NIST Level 3 (MLDSA65)
 * - 5: NIST Level 5 (MLDSA87)
 */
export const MLDSALevel: Readonly<{
  /** ML-DSA-44 (NIST security category 2); the CBOR discriminator is 2. */
  readonly MLDSA44: 2;
  /** ML-DSA-65 (category 3); the CBOR discriminator is 3. */
  readonly MLDSA65: 3;
  /** ML-DSA-87 (category 5); the CBOR discriminator is 5. */
  readonly MLDSA87: 5;
}> = /*#__PURE__*/ Object.freeze({
  /** NIST Level 2 - AES-128 equivalent security */
  MLDSA44: 2,
  /** NIST Level 3 - AES-192 equivalent security */
  MLDSA65: 3,
  /** NIST Level 5 - AES-256 equivalent security */
  MLDSA87: 5,
} as const);

/** One of the `MLDSALevel` values. */
export type MLDSALevel = (typeof MLDSALevel)[keyof typeof MLDSALevel];

/** The byte lengths of an ML-DSA level's objects. */
export interface MLDSASizes {
  /** The private (secret) key length. */
  readonly privateKey: number;
  /** The public key length. */
  readonly publicKey: number;
  /** The signature length. */
  readonly signature: number;
}

/**
 * Key sizes for each ML-DSA security level.
 */
export const MLDSA_KEY_SIZES: Readonly<Record<MLDSALevel, MLDSASizes>> =
  /*#__PURE__*/ Object.freeze({
    [MLDSALevel.MLDSA44]: /*#__PURE__*/ Object.freeze({
      privateKey: 2560,
      publicKey: 1312,
      signature: 2420,
    }),
    [MLDSALevel.MLDSA65]: /*#__PURE__*/ Object.freeze({
      privateKey: 4032,
      publicKey: 1952,
      signature: 3309,
    }),
    [MLDSALevel.MLDSA87]: /*#__PURE__*/ Object.freeze({
      privateKey: 4896,
      publicKey: 2592,
      signature: 4627,
    }),
  } as const);

/**
 * Get the private key size for a given ML-DSA level.
 */
/** The size table for `level`; an unknown level is a `PostQuantum` failure. */
function sizesFor(level: MLDSALevel): (typeof MLDSA_KEY_SIZES)[MLDSALevel] {
  const sizes = (MLDSA_KEY_SIZES as Partial<typeof MLDSA_KEY_SIZES>)[level];
  if (sizes === undefined) {
    throw ComponentsError.postQuantum(`Invalid MLDSA level value: ${String(level)}`);
  }
  return sizes;
}

export function mldsaPrivateKeySize(level: MLDSALevel): number {
  return sizesFor(level).privateKey;
}

/**
 * Get the public key size for a given ML-DSA level.
 */
export function mldsaPublicKeySize(level: MLDSALevel): number {
  return sizesFor(level).publicKey;
}

/**
 * Get the signature size for a given ML-DSA level.
 */
export function mldsaSignatureSize(level: MLDSALevel): number {
  return sizesFor(level).signature;
}

/**
 * Convert an ML-DSA level to its string representation.
 */
export function mldsaLevelToString(level: MLDSALevel): string {
  switch (level) {
    case MLDSALevel.MLDSA44:
      return "MLDSA44";
    case MLDSALevel.MLDSA65:
      return "MLDSA65";
    case MLDSALevel.MLDSA87:
      return "MLDSA87";
  }
}

/**
 * Parse an ML-DSA level from its numeric value.
 */
export function mldsaLevelFromValue(value: number): MLDSALevel {
  switch (value) {
    case 2:
      return MLDSALevel.MLDSA44;
    case 3:
      return MLDSALevel.MLDSA65;
    case 5:
      return MLDSALevel.MLDSA87;
    default:
      throw ComponentsError.postQuantum(`Invalid MLDSA level value: ${value}`);
  }
}

/**
 * Internal type for ML-DSA keypair generation result.
 */
export interface MLDSAKeypairData {
  /** The public key bytes. */
  publicKey: Uint8Array;
  /** The secret key bytes. */
  secretKey: Uint8Array;
}

/**
 * Generate an ML-DSA keypair for the given security level.
 *
 * @param level - The ML-DSA security level
 * @returns Object containing publicKey and secretKey bytes
 */
export function mldsaGenerateKeypair(level: MLDSALevel): MLDSAKeypairData {
  const rng = secureRng();
  return mldsaGenerateKeypairUsing(level, rng);
}

/**
 * Generate an ML-DSA keypair using a provided RNG.
 *
 * @param level - The ML-DSA security level
 * @param rng - Random number generator
 * @returns Object containing publicKey and secretKey bytes
 */
export function mldsaGenerateKeypairUsing(
  level: MLDSALevel,
  rng: RandomNumberGenerator,
): MLDSAKeypairData {
  // Generate random seed for keypair generation
  mldsaLevelFromValue(level);
  const seed = randomBytes(32, { rng: rng });

  switch (level) {
    case MLDSALevel.MLDSA44: {
      const keypair = ml_dsa44.keygen(seed);
      return { publicKey: keypair.publicKey, secretKey: keypair.secretKey };
    }
    case MLDSALevel.MLDSA65: {
      const keypair = ml_dsa65.keygen(seed);
      return { publicKey: keypair.publicKey, secretKey: keypair.secretKey };
    }
    case MLDSALevel.MLDSA87: {
      const keypair = ml_dsa87.keygen(seed);
      return { publicKey: keypair.publicKey, secretKey: keypair.secretKey };
    }
  }
}

/**
 * Sign a message using ML-DSA.
 *
 * @param level - The ML-DSA security level
 * @param secretKey - The secret key bytes
 * @param message - The message to sign
 * @returns The signature bytes
 */
export function mldsaSign(
  level: MLDSALevel,
  secretKey: Uint8Array,
  message: Uint8Array,
): Uint8Array {
  switch (level) {
    case MLDSALevel.MLDSA44:
      return ml_dsa44.sign(message, secretKey);
    case MLDSALevel.MLDSA65:
      return ml_dsa65.sign(message, secretKey);
    case MLDSALevel.MLDSA87:
      return ml_dsa87.sign(message, secretKey);
  }
}

/**
 * Verify a signature using ML-DSA.
 *
 * @param level - The ML-DSA security level
 * @param publicKey - The public key bytes
 * @param message - The message that was signed
 * @param signature - The signature to verify
 * @returns True if the signature is valid
 */
export function mldsaVerify(
  level: MLDSALevel,
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    switch (level) {
      case MLDSALevel.MLDSA44:
        return ml_dsa44.verify(signature, message, publicKey);
      case MLDSALevel.MLDSA65:
        return ml_dsa65.verify(signature, message, publicKey);
      case MLDSALevel.MLDSA87:
        return ml_dsa87.verify(signature, message, publicKey);
    }
  } catch {
    return false;
  }
}
