/**
 * Scrypt parameters for password-based key derivation
 *
 * Scrypt is a memory-hard key derivation function defined in RFC 7914.
 * It is suitable for password-based key derivation and is more resistant
 * to hardware brute-force attacks than PBKDF2.
 *
 * CDDL:
 * ```cddl
 * ScryptParams = [2, Salt, log_n: uint, r: uint, p: uint]
 * ```
 */

import { type Cbor, cbor, expectArray, expectUnsigned, CborError } from "@blockchaincommons/dcbor";
import { scrypt } from "@blockchaincommons/crypto";

import { Salt } from "../salt.js";
import { Nonce } from "../nonce.js";
import { SymmetricKey } from "../symmetric/symmetric-key.js";
import { type EncryptedMessage } from "../symmetric/encrypted-message.js";
import { KeyDerivationMethod } from "./key-derivation-method.js";
import { SALT_LEN } from "./hkdf-params.js";
import type { KeyDerivation } from "./key-derivation.js";
import { decodeWith } from "../codable.js";
import { expectU8, expectU32, guarded, USIZE_FIELD, U8_FIELD, U32_FIELD } from "../domain.js";

// Defaults match the reference's `ScryptParams::new()` in the reference implementation v0.34.x
// (`log_n = 15, r = 8, p = 1`). Distinct from the reference implementation's `bc_crypto::scrypt()`
// helper, which uses the heavier `scrypt::Params::recommended()` defaults
// (`log_n = 17`).
/** Default log_n parameter (2^15 = 32768 iterations) */
export const DEFAULT_SCRYPT_LOG_N = 15;
/** Default r parameter (block size) */
export const DEFAULT_SCRYPT_R = 8;
/** Default p parameter (parallelism) */
export const DEFAULT_SCRYPT_P = 1;

/**
 * Scrypt parameters for password-based key derivation.
 *
 * Parameters:
 * - log_n: CPU/memory cost parameter (N = 2^log_n)
 * - r: Block size parameter
 * - p: Parallelization parameter
 */
export class ScryptParams implements KeyDerivation {
  /** The method discriminant that opens the scrypt parameter array on the wire. */
  static readonly INDEX: KeyDerivationMethod = KeyDerivationMethod.Scrypt;

  private readonly _salt: Salt;
  private readonly _logN: number;
  private readonly _r: number;
  private readonly _p: number;

  private constructor(salt: Salt, logN: number, r: number, p: number) {
    this._salt = salt;
    this._logN = logN;
    this._r = r;
    this._p = p;
  }

  /** Parameters with a fresh random salt unless one is given. */
  static from({
    salt = Salt.random({ length: SALT_LEN }),
    logN = DEFAULT_SCRYPT_LOG_N,
    r = DEFAULT_SCRYPT_R,
    p = DEFAULT_SCRYPT_P,
  }: { salt?: Salt; logN?: number; r?: number; p?: number } = {}): ScryptParams {
    return new ScryptParams(salt, expectU8(logN, "logN"), expectU32(r, "r"), expectU32(p, "p"));
  }

  /** Returns the salt. */
  get salt(): Salt {
    return this._salt;
  }

  /** Returns the log_n parameter. */
  get logN(): number {
    return this._logN;
  }

  /** Returns the r parameter (block size). */
  get r(): number {
    return this._r;
  }

  /** Returns the p parameter (parallelism). */
  get p(): number {
    return this._p;
  }

  /** Returns the method index for CBOR encoding. */
  index(): number {
    return ScryptParams.INDEX;
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
    return guarded("ScryptParams", () => this._deriveKeyRaw(secret));
  }

  private _deriveKeyRaw(secret: Uint8Array): Uint8Array {
    return scrypt(secret, this._salt.bytes, {
      dkLen: 32,
      logN: this._logN,
      r: this._r,
      p: this._p,
    });
  }

  /**
   * Get string representation.
   */
  toString(): string {
    return "Scrypt";
  }

  /**
   * Check equality with another ScryptParams.
   */
  equals(other: ScryptParams): boolean {
    return (
      this._salt.equals(other._salt) &&
      this._logN === other._logN &&
      this._r === other._r &&
      this._p === other._p
    );
  }

  // ============================================================================
  // CBOR Serialization
  // ============================================================================

  /**
   * Convert to CBOR.
   * Format: [2, Salt, log_n, r, p]   (Salt is encoded as a tagged value — `#6.40018(bytes)`)
   */
  toCbor(): Cbor {
    return cbor([
      cbor(ScryptParams.INDEX),
      this._salt.toCbor(),
      cbor(this._logN),
      cbor(this._r),
      cbor(this._p),
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
  /**
   * From the CBOR array, as the reference's `TryFrom<CBOR>` (a dcbor error):
   * every failure is `Cbor` with the bare message. The index element is
   * read as a `usize` (with dcbor's negative wrap) and its value ignored;
   * the fixed-width fields wrap the same way.
   */
  static fromCbor(cborValue: Cbor): ScryptParams {
    return decodeWith(() => {
      const array = expectArray(cborValue);
      if (array.length !== 5) throw CborError.custom("Invalid ScryptParams");
      expectUnsigned(array[0], USIZE_FIELD);
      const salt = Salt.fromCbor(array[1]);
      const logN = Number(expectUnsigned(array[2], U8_FIELD));
      const r = Number(expectUnsigned(array[3], U32_FIELD));
      const p = Number(expectUnsigned(array[4], U32_FIELD));
      return new ScryptParams(salt, logN, r, p);
    });
  }
}
