/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * PBKDF2 (Password-Based Key Derivation Function 2) parameters
 *
 * PBKDF2 is a key derivation function defined in RFC 8018 (PKCS #5 v2.1).
 * It is suitable for password-based key derivation.
 *
 * CDDL:
 * ```cddl
 * PBKDF2Params = [1, Salt, iterations: uint, HashType]
 * ```
 *
 */

import { type Cbor, cbor, expectArray, expectNumber } from "@blockchaincommons/dcbor";
import { pbkdf2Sha256, pbkdf2Sha512 } from "@blockchaincommons/crypto";

import { Salt } from "../salt.js";
import { Nonce } from "../nonce.js";
import { SymmetricKey } from "../symmetric/symmetric-key.js";
import { type EncryptedMessage } from "../symmetric/encrypted-message.js";
import { HashType, hashTypeToCbor, hashTypeFromCbor, hashTypeToString } from "./hash-type.js";
import { KeyDerivationMethod } from "./key-derivation-method.js";
import { SALT_LEN } from "./hkdf-params.js";
import type { KeyDerivation } from "./key-derivation.js";
import { ComponentsError } from "../error.js";

/** Default number of iterations for PBKDF2 */
export const DEFAULT_PBKDF2_ITERATIONS = 100_000;

/**
 * PBKDF2 parameters for password-based key derivation.
 */
export class PBKDF2Params implements KeyDerivation {
  static readonly INDEX: KeyDerivationMethod = KeyDerivationMethod.PBKDF2;

  private readonly _salt: Salt;
  private readonly _iterations: number;
  private readonly _hashType: HashType;

  private constructor(salt: Salt, iterations: number, hashType: HashType) {
    this._salt = salt;
    this._iterations = iterations;
    this._hashType = hashType;
  }

  /** Parameters with a fresh random salt unless one is given. */
  static from({
    salt = Salt.random({ length: SALT_LEN }),
    iterations = DEFAULT_PBKDF2_ITERATIONS,
    hashType = HashType.SHA256,
  }: { salt?: Salt; iterations?: number; hashType?: HashType } = {}): PBKDF2Params {
    return new PBKDF2Params(salt, iterations, hashType);
  }

  /** Returns the salt. */
  get salt(): Salt {
    return this._salt;
  }

  /** Returns the number of iterations. */
  get iterations(): number {
    return this._iterations;
  }

  /** Returns the hash type. */
  get hashType(): HashType {
    return this._hashType;
  }

  /** Returns the method index for CBOR encoding. */
  index(): number {
    return PBKDF2Params.INDEX;
  }

  /**
   * Derive a key from the secret and encrypt the content key.
   */
  lock(contentKey: SymmetricKey, secret: Uint8Array): EncryptedMessage {
    const derivedKeyData = this._deriveKey(secret);
    const derivedKey = SymmetricKey.from(derivedKeyData);

    // Encode the method parameters as AAD
    const encodedMethod = this.toCbor().toData();

    // Encrypt the content key using the derived key
    return derivedKey.encrypt(contentKey.bytes, encodedMethod, Nonce.random());
  }

  /**
   * Derive a key from the secret and decrypt the content key.
   */
  unlock(encryptedMessage: EncryptedMessage, secret: Uint8Array): SymmetricKey {
    const derivedKeyData = this._deriveKey(secret);
    const derivedKey = SymmetricKey.from(derivedKeyData);

    // Decrypt to get the content key
    const contentKeyData = derivedKey.decrypt(encryptedMessage);
    return SymmetricKey.from(contentKeyData);
  }

  private _deriveKey(secret: Uint8Array): Uint8Array {
    switch (this._hashType) {
      case HashType.SHA256:
        return pbkdf2Sha256(secret, this._salt.bytes, {
          iterations: this._iterations,
          dkLen: 32,
        });
      case HashType.SHA512:
        return pbkdf2Sha512(secret, this._salt.bytes, {
          iterations: this._iterations,
          dkLen: 32,
        });
      default:
        throw ComponentsError.invalidData(`Unknown hash type: ${String(this._hashType)}`);
    }
  }

  /**
   * Get string representation.
   */
  toString(): string {
    return `PBKDF2(${hashTypeToString(this._hashType)})`;
  }

  /**
   * Check equality with another PBKDF2Params.
   */
  equals(other: PBKDF2Params): boolean {
    return (
      this._salt.equals(other._salt) &&
      this._iterations === other._iterations &&
      this._hashType === other._hashType
    );
  }

  // ============================================================================
  // CBOR Serialization
  // ============================================================================

  /**
   * Convert to CBOR.
   * Format: [1, Salt, iterations, HashType]   (Salt is encoded as a tagged value — `#6.40018(bytes)`)
   */
  toCbor(): Cbor {
    return cbor([
      cbor(PBKDF2Params.INDEX),
      this._salt.toCbor(),
      cbor(this._iterations),
      hashTypeToCbor(this._hashType),
    ]);
  }

  /**
   * Convert to CBOR binary data.
   */
  toCborData(): Uint8Array {
    return this.toCbor().toData();
  }

  /**
   * Parse from CBOR.
   */
  static fromCbor(cborValue: Cbor): PBKDF2Params {
    const array = expectArray(cborValue);

    if (array.length !== 4) {
      throw ComponentsError.invalidData(
        `Invalid PBKDF2Params: expected 4 elements, got ${array.length}`,
      );
    }

    const index = expectNumber(array[0]);
    if (index !== PBKDF2Params.INDEX) {
      throw ComponentsError.invalidData(
        `Invalid PBKDF2Params index: expected ${PBKDF2Params.INDEX}, got ${index}`,
      );
    }

    const salt = Salt.fromCbor(array[1]);
    const iterations = Number(expectNumber(array[2]));
    const hashType = hashTypeFromCbor(array[3]);

    return new PBKDF2Params(salt, iterations, hashType);
  }
}
