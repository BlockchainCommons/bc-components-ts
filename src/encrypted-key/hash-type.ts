/**
 * Hash type enum for key derivation functions
 *
 * This enum represents the supported hash algorithms for HKDF and PBKDF2.
 *
 * CDDL:
 * ```cddl
 * HashType = SHA256 / SHA512
 * SHA256 = 0
 * SHA512 = 1
 * ```
 */

import { type Cbor, cbor, expectNumber } from "@blockchaincommons/dcbor";
import { ComponentsError } from "../error.js";

/**
 * Enum representing supported hash types for key derivation.
 */
export const HashType: Readonly<{ readonly SHA256: 0; readonly SHA512: 1 }> =
  /*#__PURE__*/ Object.freeze({
    /** SHA-256 hash algorithm */
    SHA256: 0,
    /** SHA-512 hash algorithm */
    SHA512: 1,
  } as const);

/** One of the `HashType` values. */
export type HashType = (typeof HashType)[keyof typeof HashType];

/**
 * Convert HashType to its string representation.
 */
export function hashTypeToString(hashType: HashType): string {
  switch (hashType) {
    case HashType.SHA256:
      return "SHA256";
    case HashType.SHA512:
      return "SHA512";
    default:
      throw ComponentsError.invalidData(`Unknown HashType: ${String(hashType)}`);
  }
}

/**
 * Convert HashType to CBOR.
 */
export function hashTypeToCbor(hashType: HashType): Cbor {
  return cbor(hashType);
}

/**
 * Parse HashType from CBOR.
 */
export function hashTypeFromCbor(cborValue: Cbor): HashType {
  const value = expectNumber(cborValue);
  switch (value) {
    case 0:
      return HashType.SHA256;
    case 1:
      return HashType.SHA512;
    default:
      throw ComponentsError.invalidData(`Invalid HashType: ${value}`);
  }
}
