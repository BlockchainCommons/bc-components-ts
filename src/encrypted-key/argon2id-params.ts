/**
 * Argon2id parameters for password-based key derivation
 *
 * Argon2id is a memory-hard key derivation function defined in RFC 9106.
 * It combines Argon2i (resistant to side-channel attacks) and Argon2d
 * (resistant to GPU cracking attacks). It is the recommended choice for
 * password-based key derivation.
 *
 * CDDL:
 * ```cddl
 * Argon2idParams = [3, Salt]
 * ```
 *
 * Note: Argon2id uses sensible defaults for memory, iterations, and parallelism.
 * Only the salt is configurable in the CBOR encoding for simplicity.
 */

import { type Cbor, cbor, expectArray, expectUnsigned, CborError } from "@blockchaincommons/dcbor";
import { argon2id } from "@blockchaincommons/crypto";

import { Salt } from "../salt.js";
import { Nonce } from "../nonce.js";
import { SymmetricKey } from "../symmetric/symmetric-key.js";
import { type EncryptedMessage } from "../symmetric/encrypted-message.js";
import { KeyDerivationMethod } from "./key-derivation-method.js";
import { SALT_LEN } from "./hkdf-params.js";
import type { KeyDerivation } from "./key-derivation.js";
import { decodeWith } from "../codable.js";
import { guarded, USIZE_FIELD } from "../domain.js";

/**
 * Argon2id parameters for password-based key derivation.
 *
 * This is the recommended method for password-based key derivation as it
 * provides the best protection against both GPU cracking and side-channel
 * attacks.
 */
export class Argon2idParams implements KeyDerivation {
  /** The method discriminant that opens the Argon2id parameter array on the wire. */
  static readonly INDEX: KeyDerivationMethod = KeyDerivationMethod.Argon2id;

  private readonly _salt: Salt;

  private constructor(salt: Salt) {
    this._salt = salt;
  }

  /** Parameters with a fresh random salt unless one is given. */
  static from({ salt = Salt.random({ length: SALT_LEN }) }: { salt?: Salt } = {}): Argon2idParams {
    return new Argon2idParams(salt);
  }

  /** Returns the salt. */
  get salt(): Salt {
    return this._salt;
  }

  /** Returns the method index for CBOR encoding. */
  index(): number {
    return Argon2idParams.INDEX;
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
    return guarded("Argon2idParams", () => this._deriveKeyRaw(secret));
  }

  private _deriveKeyRaw(secret: Uint8Array): Uint8Array {
    return argon2id(secret, this._salt.bytes, { dkLen: 32 });
  }

  /**
   * Get string representation.
   */
  toString(): string {
    return "Argon2id";
  }

  /**
   * Check equality with another Argon2idParams.
   */
  equals(other: Argon2idParams): boolean {
    return this._salt.equals(other._salt);
  }

  // ============================================================================
  // CBOR Serialization
  // ============================================================================

  /**
   * Convert to CBOR.
   * Format: [3, Salt]   (Salt is encoded as a tagged value — `#6.40018(bytes)`)
   */
  toCbor(): Cbor {
    return cbor([cbor(Argon2idParams.INDEX), this._salt.toCbor()]);
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
  /**
   * From the CBOR array, as the reference's `TryFrom<CBOR>` (a dcbor error):
   * every failure is `Cbor` with the bare message. The index element is
   * read as a `usize` (with dcbor's negative wrap) and its value ignored;
   * the fixed-width fields wrap the same way.
   */
  static fromCbor(cborValue: Cbor): Argon2idParams {
    return decodeWith(() => {
      const array = expectArray(cborValue);
      if (array.length !== 2) throw CborError.custom("Invalid Argon2idParams");
      expectUnsigned(array[0], USIZE_FIELD);
      const salt = Salt.fromCbor(array[1]);
      return new Argon2idParams(salt);
    });
  }
}
