/**
 * MLKEM Security Level - ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism)
 *
 * ML-KEM is a post-quantum key encapsulation mechanism standardized by NIST.
 * It provides three security levels corresponding to different NIST security categories.
 *
 * Security levels:
 * - MLKEM512: NIST Level 1 (equivalent to AES-128)
 * - MLKEM768: NIST Level 3 (equivalent to AES-192)
 * - MLKEM1024: NIST Level 5 (equivalent to AES-256)
 *
 * Naming note: the reference calls this enum `MLKEM`. TypeScript uses `MLKEMLevel`
 * to avoid colliding with the keypair type names (`MLKEMPrivateKey` /
 * `MLKEMPublicKey` / `MLKEMCiphertext`). The CBOR discriminator (the
 * numeric level) is identical in both languages — this is a TS-only
 * naming choice with no wire-format effect.
 */

import { ml_kem512, ml_kem768, ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { type RandomNumberGenerator, secureRng, randomBytes } from "@blockchaincommons/rand";
import { ComponentsError } from "../error.js";

/**
 * ML-KEM security levels.
 *
 * The numeric values correspond to the ML-KEM parameter set:
 * - 512: ML-KEM-512 (NIST Level 1)
 * - 768: ML-KEM-768 (NIST Level 3)
 * - 1024: ML-KEM-1024 (NIST Level 5)
 */
export const MLKEMLevel: Readonly<{
  readonly MLKEM512: 512;
  readonly MLKEM768: 768;
  readonly MLKEM1024: 1024;
}> = /*#__PURE__*/ Object.freeze({
  /** NIST Level 1 - AES-128 equivalent security */
  MLKEM512: 512,
  /** NIST Level 3 - AES-192 equivalent security */
  MLKEM768: 768,
  /** NIST Level 5 - AES-256 equivalent security */
  MLKEM1024: 1024,
} as const);

/** One of the `MLKEMLevel` values. */
export type MLKEMLevel = (typeof MLKEMLevel)[keyof typeof MLKEMLevel];

/** The byte lengths of an ML-KEM level's objects. */
export interface MLKEMSizes {
  /** The private (decapsulation) key length. */
  readonly privateKey: number;
  /** The public (encapsulation) key length. */
  readonly publicKey: number;
  /** The ciphertext length. */
  readonly ciphertext: number;
  /** The shared secret length (always 32). */
  readonly sharedSecret: number;
}

/**
 * Key sizes for each ML-KEM security level.
 */
export const MLKEM_KEY_SIZES: Readonly<Record<MLKEMLevel, MLKEMSizes>> =
  /*#__PURE__*/ Object.freeze({
    [MLKEMLevel.MLKEM512]: /*#__PURE__*/ Object.freeze({
      privateKey: 1632,
      publicKey: 800,
      ciphertext: 768,
      sharedSecret: 32,
    }),
    [MLKEMLevel.MLKEM768]: /*#__PURE__*/ Object.freeze({
      privateKey: 2400,
      publicKey: 1184,
      ciphertext: 1088,
      sharedSecret: 32,
    }),
    [MLKEMLevel.MLKEM1024]: /*#__PURE__*/ Object.freeze({
      privateKey: 3168,
      publicKey: 1568,
      ciphertext: 1568,
      sharedSecret: 32,
    }),
  } as const);

/**
 * Get the private key size for a given ML-KEM level.
 */
/** The size table for `level`; an unknown level is a `PostQuantum` failure. */
function sizesFor(level: MLKEMLevel): (typeof MLKEM_KEY_SIZES)[MLKEMLevel] {
  const sizes = (MLKEM_KEY_SIZES as Partial<typeof MLKEM_KEY_SIZES>)[level];
  if (sizes === undefined) {
    throw ComponentsError.postQuantum(`Invalid MLKEM level value: ${String(level)}`);
  }
  return sizes;
}

export function mlkemPrivateKeySize(level: MLKEMLevel): number {
  return sizesFor(level).privateKey;
}

/**
 * Get the public key size for a given ML-KEM level.
 */
export function mlkemPublicKeySize(level: MLKEMLevel): number {
  return sizesFor(level).publicKey;
}

/**
 * Get the ciphertext size for a given ML-KEM level.
 */
export function mlkemCiphertextSize(level: MLKEMLevel): number {
  return sizesFor(level).ciphertext;
}

/**
 * Get the shared secret size for a given ML-KEM level.
 * Note: This is always 32 bytes for all ML-KEM levels.
 */
export function mlkemSharedSecretSize(level: MLKEMLevel): number {
  return sizesFor(level).sharedSecret;
}

/**
 * Convert an ML-KEM level to its string representation.
 */
export function mlkemLevelToString(level: MLKEMLevel): string {
  switch (level) {
    case MLKEMLevel.MLKEM512:
      return "MLKEM512";
    case MLKEMLevel.MLKEM768:
      return "MLKEM768";
    case MLKEMLevel.MLKEM1024:
      return "MLKEM1024";
  }
}

/**
 * Parse an ML-KEM level from its numeric value.
 */
export function mlkemLevelFromValue(value: number): MLKEMLevel {
  switch (value) {
    case 512:
      return MLKEMLevel.MLKEM512;
    case 768:
      return MLKEMLevel.MLKEM768;
    case 1024:
      return MLKEMLevel.MLKEM1024;
    default:
      throw ComponentsError.postQuantum(`Invalid MLKEM level value: ${value}`);
  }
}

/**
 * Internal type for ML-KEM keypair generation result.
 */
export interface MLKEMKeypairData {
  /** The public key bytes. */
  publicKey: Uint8Array;
  /** The secret key bytes. */
  secretKey: Uint8Array;
}

/**
 * Internal type for ML-KEM encapsulation result.
 */
export interface MLKEMEncapsulationResult {
  /** The 32-byte shared secret. */
  sharedSecret: Uint8Array;
  /** The ciphertext the recipient decapsulates. */
  ciphertext: Uint8Array;
}

/**
 * Generate an ML-KEM keypair for the given security level.
 *
 * @param level - The ML-KEM security level
 * @returns Object containing publicKey and secretKey bytes
 */
export function mlkemGenerateKeypair(level: MLKEMLevel): MLKEMKeypairData {
  const rng = secureRng();
  return mlkemGenerateKeypairUsing(level, rng);
}

/**
 * Generate an ML-KEM keypair using a provided RNG.
 *
 * @param level - The ML-KEM security level
 * @param rng - Random number generator
 * @returns Object containing publicKey and secretKey bytes
 */
export function mlkemGenerateKeypairUsing(
  level: MLKEMLevel,
  rng: RandomNumberGenerator,
): MLKEMKeypairData {
  // Generate random seed for keypair generation
  mlkemLevelFromValue(level);
  const seed = randomBytes(64, { rng: rng });

  switch (level) {
    case MLKEMLevel.MLKEM512: {
      const keypair = ml_kem512.keygen(seed);
      return { publicKey: keypair.publicKey, secretKey: keypair.secretKey };
    }
    case MLKEMLevel.MLKEM768: {
      const keypair = ml_kem768.keygen(seed);
      return { publicKey: keypair.publicKey, secretKey: keypair.secretKey };
    }
    case MLKEMLevel.MLKEM1024: {
      const keypair = ml_kem1024.keygen(seed);
      return { publicKey: keypair.publicKey, secretKey: keypair.secretKey };
    }
  }
}

/**
 * Encapsulate a new shared secret using a public key.
 *
 * @param level - The ML-KEM security level
 * @param publicKey - The public key bytes
 * @returns Object containing sharedSecret and ciphertext bytes
 */
export function mlkemEncapsulate(
  level: MLKEMLevel,
  publicKey: Uint8Array,
  seed?: Uint8Array,
): MLKEMEncapsulationResult {
  switch (level) {
    case MLKEMLevel.MLKEM512: {
      const result = ml_kem512.encapsulate(publicKey, seed);
      return { sharedSecret: result.sharedSecret, ciphertext: result.cipherText };
    }
    case MLKEMLevel.MLKEM768: {
      const result = ml_kem768.encapsulate(publicKey, seed);
      return { sharedSecret: result.sharedSecret, ciphertext: result.cipherText };
    }
    case MLKEMLevel.MLKEM1024: {
      const result = ml_kem1024.encapsulate(publicKey, seed);
      return { sharedSecret: result.sharedSecret, ciphertext: result.cipherText };
    }
  }
}

/**
 * Decapsulate a shared secret using a private key and ciphertext.
 *
 * @param level - The ML-KEM security level
 * @param secretKey - The secret key bytes
 * @param ciphertext - The ciphertext bytes
 * @returns The shared secret bytes
 */
export function mlkemDecapsulate(
  level: MLKEMLevel,
  secretKey: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  switch (level) {
    case MLKEMLevel.MLKEM512:
      return ml_kem512.decapsulate(ciphertext, secretKey);
    case MLKEMLevel.MLKEM768:
      return ml_kem768.decapsulate(ciphertext, secretKey);
    case MLKEMLevel.MLKEM1024:
      return ml_kem1024.decapsulate(ciphertext, secretKey);
  }
}

/**
 * Private key portion sizes for each ML-KEM level.
 * The decapsulation key structure is: dk = (dk_pke || ek_pke || H(ek) || z)
 * where dk_pke is the private portion before the public key.
 */
const MLKEM_DK_PKE_SIZES = /*#__PURE__*/ Object.freeze({
  [MLKEMLevel.MLKEM512]: 768, // 12 * 64
  [MLKEMLevel.MLKEM768]: 1152, // 12 * 96
  [MLKEMLevel.MLKEM1024]: 1536, // 12 * 128
} as const);

/**
 * Extract the public key from a secret key.
 *
 * In ML-KEM (FIPS 203), the decapsulation key contains the encapsulation key (public key)
 * embedded within it. The structure is: dk = (dk_pke || ek_pke || H(ek) || z)
 *
 * @param level - The ML-KEM security level
 * @param secretKey - The secret key bytes
 * @returns The public key bytes extracted from the secret key
 */
export function mlkemExtractPublicKey(level: MLKEMLevel, secretKey: Uint8Array): Uint8Array {
  const dkPkeSize = MLKEM_DK_PKE_SIZES[level];
  const publicKeySize = sizesFor(level).publicKey;
  const offset = dkPkeSize;
  return secretKey.slice(offset, offset + publicKeySize);
}
