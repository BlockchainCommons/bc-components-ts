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

import { type Cbor, cbor, expectUnsigned } from "@blockchaincommons/dcbor";
import { decodeComponent } from "../codable.js";
import { U8_FIELD } from "../domain.js";
import { ComponentsError } from "../error.js";

/**
 * Enum representing supported hash types for key derivation.
 */
export const HashType: Readonly<{
  /** SHA-256; the CBOR discriminator is 0. */
  readonly SHA256: 0;
  /** SHA-512; the CBOR discriminator is 1. */
  readonly SHA512: 1;
}> = /*#__PURE__*/ Object.freeze({
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
/**
 * As the reference's `TryFrom<CBOR>` (error type `Error`): a `u8` with
 * dcbor's negative wrap (`-256` reads as 0, SHA-256), then `General`
 * `Invalid HashType` for any other value; a non-integer or out-of-width
 * head is `Cbor` (`CBOR error: …`).
 */
export function hashTypeFromCbor(cborValue: Cbor): HashType {
  return decodeComponent(() => {
    switch (Number(expectUnsigned(cborValue, U8_FIELD))) {
      case 0:
        return HashType.SHA256;
      case 1:
        return HashType.SHA512;
      default:
        throw ComponentsError.general("Invalid HashType");
    }
  });
}
