/**
 * Key derivation method enum
 *
 * This enum represents the supported key derivation methods for encrypting keys.
 *
 * CDDL:
 * ```cddl
 * KeyDerivationMethod = HKDF / PBKDF2 / Scrypt / Argon2id / SSHAgent
 * HKDF = 0
 * PBKDF2 = 1
 * Scrypt = 2
 * Argon2id = 3
 * SSHAgent = 4
 * ```
 */

import { type Cbor, expectUnsigned } from "@blockchaincommons/dcbor";
import { ComponentsError } from "../error.js";
import { decodeComponent } from "../codable.js";
import { USIZE_FIELD } from "../domain.js";

/**
 * Enum representing supported key derivation methods.
 */
export const KeyDerivationMethod: Readonly<{
  /** HKDF (RFC 5869); the CBOR discriminator is 0. */
  readonly HKDF: 0;
  /** PBKDF2 (RFC 8018); the CBOR discriminator is 1. */
  readonly PBKDF2: 1;
  /** scrypt (RFC 7914); the CBOR discriminator is 2. */
  readonly Scrypt: 2;
  /** Argon2id (RFC 9106); the CBOR discriminator is 3. */
  readonly Argon2id: 3;
  /** An SSH agent signature as key material; the CBOR discriminator is 4. */
  readonly SSHAgent: 4;
}> = /*#__PURE__*/ Object.freeze({
  /** HKDF (HMAC-based Key Derivation Function) - RFC 5869 */
  HKDF: 0,
  /** PBKDF2 (Password-Based Key Derivation Function 2) - RFC 8018 */
  PBKDF2: 1,
  /** Scrypt - RFC 7914 */
  Scrypt: 2,
  /** Argon2id - RFC 9106 (default, most secure for passwords) */
  Argon2id: 3,
  /** SSH Agent - Uses SSH agent for key derivation */
  SSHAgent: 4,
} as const);

/** One of the `KeyDerivationMethod` values. */
export type KeyDerivationMethod = (typeof KeyDerivationMethod)[keyof typeof KeyDerivationMethod];

/**
 * Returns the default key derivation method (Argon2id).
 */
export function defaultKeyDerivationMethod(): KeyDerivationMethod {
  return KeyDerivationMethod.Argon2id;
}

/**
 * Returns the zero-based index of the key derivation method.
 */
export function keyDerivationMethodIndex(method: KeyDerivationMethod): number {
  return method;
}

/**
 * Attempts to create a KeyDerivationMethod from a zero-based index.
 */
export function keyDerivationMethodFromIndex(index: number): KeyDerivationMethod | undefined {
  switch (index) {
    case 0:
      return KeyDerivationMethod.HKDF;
    case 1:
      return KeyDerivationMethod.PBKDF2;
    case 2:
      return KeyDerivationMethod.Scrypt;
    case 3:
      return KeyDerivationMethod.Argon2id;
    case 4:
      return KeyDerivationMethod.SSHAgent;
    default:
      return undefined;
  }
}

/**
 * Convert KeyDerivationMethod to its string representation.
 */
export function keyDerivationMethodToString(method: KeyDerivationMethod): string {
  switch (method) {
    case KeyDerivationMethod.HKDF:
      return "HKDF";
    case KeyDerivationMethod.PBKDF2:
      return "PBKDF2";
    case KeyDerivationMethod.Scrypt:
      return "Scrypt";
    case KeyDerivationMethod.Argon2id:
      return "Argon2id";
    case KeyDerivationMethod.SSHAgent:
      return "SSHAgent";
    default:
      throw ComponentsError.invalidData(`Unknown KeyDerivationMethod: ${String(method)}`);
  }
}

/**
 * Parse KeyDerivationMethod from CBOR.
 */
/**
 * As the reference's `TryFrom<CBOR>` (error type `Error`): the index as a
 * `usize` with dcbor's negative wrap, then `General`
 * `Invalid KeyDerivationMethod` for an unknown one; a non-integer or
 * out-of-width head is `Cbor` (`CBOR error: …`).
 */
export function keyDerivationMethodFromCbor(cborValue: Cbor): KeyDerivationMethod {
  return decodeComponent(() => {
    const method = keyDerivationMethodFromIndex(Number(expectUnsigned(cborValue, USIZE_FIELD)));
    if (method === undefined) throw ComponentsError.general("Invalid KeyDerivationMethod");
    return method;
  });
}
