/**
 * HKDF (HMAC-based Key Derivation Function) parameters
 *
 * HKDF is a key derivation function based on HMAC, defined in RFC 5869.
 * It is NOT suitable for password-based key derivation (use PBKDF2, Scrypt,
 * or Argon2id instead).
 *
 * CDDL:
 * ```cddl
 * HKDFParams = [0, Salt, HashType]
 * ```
 */

import { type Cbor, cbor, expectArray, expectNumber } from "@blockchaincommons/dcbor";
import { hkdfSha256, hkdfSha512 } from "@blockchaincommons/crypto";

import { Salt } from "../salt.js";
import { Nonce } from "../nonce.js";
import { SymmetricKey } from "../symmetric/symmetric-key.js";
import { type EncryptedMessage } from "../symmetric/encrypted-message.js";
import { HashType, hashTypeToCbor, hashTypeFromCbor, hashTypeToString } from "./hash-type.js";
import { KeyDerivationMethod } from "./key-derivation-method.js";
import type { KeyDerivation } from "./key-derivation.js";
import { ComponentsError } from "../error.js";
import { guarded } from "../domain.js";

/** Default salt length for key derivation */
export const SALT_LEN = 16;

/**
 * HKDF parameters for key derivation.
 *
 * HKDF is suitable for deriving keys from high-entropy inputs (like other keys),
 * but NOT for password-based key derivation.
 */
export class HKDFParams implements KeyDerivation {
  /** The method discriminant that opens the HKDF parameter array on the wire. */
  static readonly INDEX: KeyDerivationMethod = KeyDerivationMethod.HKDF;

  private readonly _salt: Salt;
  private readonly _hashType: HashType;

  private constructor(salt: Salt, hashType: HashType) {
    this._salt = salt;
    this._hashType = hashType;
  }

  /** Parameters with a fresh random salt unless one is given. */
  static from({
    salt = Salt.random({ length: SALT_LEN }),
    hashType = HashType.SHA256,
  }: { salt?: Salt; hashType?: HashType } = {}): HKDFParams {
    return new HKDFParams(salt, hashType);
  }

  /** Returns the salt. */
  get salt(): Salt {
    return this._salt;
  }

  /** Returns the hash type. */
  get hashType(): HashType {
    return this._hashType;
  }

  /** Returns the method index for CBOR encoding. */
  index(): number {
    return HKDFParams.INDEX;
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
    return derivedKey.encrypt(contentKey.bytes, { aad: encodedMethod, nonce: Nonce.random() });
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
    return guarded("HKDFParams", () => this._deriveKeyRaw(secret));
  }

  private _deriveKeyRaw(secret: Uint8Array): Uint8Array {
    switch (this._hashType) {
      case HashType.SHA256:
        return hkdfSha256(secret, this._salt.bytes, { dkLen: 32 });
      case HashType.SHA512:
        return hkdfSha512(secret, this._salt.bytes, { dkLen: 32 });
      default:
        throw ComponentsError.invalidData(`Unknown hash type: ${String(this._hashType)}`);
    }
  }

  /**
   * Get string representation.
   */
  toString(): string {
    return `HKDF(${hashTypeToString(this._hashType)})`;
  }

  /**
   * Check equality with another HKDFParams.
   */
  equals(other: HKDFParams): boolean {
    return this._salt.equals(other._salt) && this._hashType === other._hashType;
  }

  // ============================================================================
  // CBOR Serialization
  // ============================================================================

  /**
   * Convert to CBOR.
   * Format: [0, Salt, HashType]   (Salt is encoded as a tagged value — `#6.40018(bytes)`)
   */
  toCbor(): Cbor {
    return cbor([cbor(HKDFParams.INDEX), this._salt.toCbor(), hashTypeToCbor(this._hashType)]);
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
  static fromCbor(cborValue: Cbor): HKDFParams {
    const array = expectArray(cborValue);

    if (array.length !== 3) {
      throw ComponentsError.invalidData(
        `Invalid HKDFParams: expected 3 elements, got ${array.length}`,
      );
    }

    const index = expectNumber(array[0]);
    if (index !== HKDFParams.INDEX) {
      throw ComponentsError.invalidData(
        `Invalid HKDFParams index: expected ${HKDFParams.INDEX}, got ${index}`,
      );
    }

    const salt = Salt.fromCbor(array[1]);
    const hashType = hashTypeFromCbor(array[2]);

    return new HKDFParams(salt, hashType);
  }
}
