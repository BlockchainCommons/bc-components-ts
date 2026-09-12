/**
 * Encrypted key for secure symmetric key storage
 *
 * `EncryptedKey` provides symmetric encryption and decryption of content keys
 * using various key derivation methods (HKDF, PBKDF2, Scrypt, Argon2id).
 *
 * The form of an `EncryptedKey` is an `EncryptedMessage` that contains the
 * encrypted content key, with its Additional Authenticated Data (AAD) being
 * the CBOR encoding of the key derivation method and parameters.
 *
 * CDDL:
 * ```cddl
 * EncryptedKey = #6.40027(EncryptedMessage)
 *
 * EncryptedMessage =
 *     #6.40002([ ciphertext: bstr, nonce: bstr, auth: bstr, aad: bstr .cbor KeyDerivation ])
 *
 * KeyDerivation = HKDFParams / PBKDF2Params / ScryptParams / Argon2idParams
 * ```
 */

import { type Cbor, type Tag, decodeCbor, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "../codable.js";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { TAG_ENCRYPTED_KEY } from "@blockchaincommons/tags";

import { type SymmetricKey } from "../symmetric/symmetric-key.js";
import { EncryptedMessage } from "../symmetric/encrypted-message.js";
import { ComponentsError } from "../error.js";
import { KeyDerivationMethod } from "./key-derivation-method.js";
import {
  type KeyDerivationParams,
  hkdfParams,
  pbkdf2Params,
  scryptParams,
  argon2idParams,
  keyDerivationParamsMethod,
  keyDerivationParamsToString,
  keyDerivationParamsFromCbor,
  lockWithParams,
  isPasswordBased,
  isSshAgent,
} from "./key-derivation-params.js";
import { guarded } from "../domain.js";

// The codec is built on first use so that an unused class tree-shakes away.
let ENCRYPTED_KEY_CODEC: ComponentCodec<EncryptedKey> | undefined;

/**
 * Encrypted key providing secure storage of symmetric keys.
 *
 * Use `lock()` to encrypt a content key with a password or secret,
 * and `unlock()` to decrypt it.
 */
export class EncryptedKey implements ToCbor, ToUR {
  private readonly _params: KeyDerivationParams;
  private readonly _encryptedMessage: EncryptedMessage;

  private constructor(params: KeyDerivationParams, encryptedMessage: EncryptedMessage) {
    this._params = params;
    this._encryptedMessage = encryptedMessage;
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Lock (encrypt) a content key using custom derivation parameters.
   *
   * @param params - The key derivation parameters to use
   * @param secret - The secret (password or key material) to derive from
   * @param contentKey - The symmetric key to encrypt
   * @returns The encrypted key
   */
  static lockOpt(
    params: KeyDerivationParams,
    secret: Uint8Array,
    contentKey: SymmetricKey,
  ): EncryptedKey {
    const encryptedMessage = lockWithParams(params, contentKey, secret);
    return new EncryptedKey(params, encryptedMessage);
  }

  /**
   * Lock (encrypt) a content key using a specific derivation method with defaults.
   *
   * @param method - The key derivation method to use
   * @param secret - The secret (password or key material) to derive from
   * @param contentKey - The symmetric key to encrypt
   * @returns The encrypted key
   */
  static lock(
    method: KeyDerivationMethod,
    secret: Uint8Array,
    contentKey: SymmetricKey,
  ): EncryptedKey {
    let params: KeyDerivationParams;

    switch (method) {
      case KeyDerivationMethod.HKDF:
        params = hkdfParams();
        break;
      case KeyDerivationMethod.PBKDF2:
        params = pbkdf2Params();
        break;
      case KeyDerivationMethod.Scrypt:
        params = scryptParams();
        break;
      case KeyDerivationMethod.Argon2id:
        params = argon2idParams();
        break;
      case KeyDerivationMethod.SSHAgent:
        throw ComponentsError.invalidData(
          "SSH Agent key derivation cannot be used with lock() - use lockOpt() with sshAgentParams() instead",
        );
    }

    return EncryptedKey.lockOpt(params, secret, contentKey);
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /**
   * Returns the encrypted message.
   */
  get encryptedMessage(): EncryptedMessage {
    return this._encryptedMessage;
  }

  /**
   * Returns the key derivation parameters.
   */
  get params(): KeyDerivationParams {
    return this._params;
  }

  /**
   * Returns the key derivation method.
   */
  get method(): KeyDerivationMethod {
    return keyDerivationParamsMethod(this._params);
  }

  /**
   * Check if this uses a password-based key derivation method.
   */
  isPasswordBased(): boolean {
    return isPasswordBased(this._params);
  }

  /**
   * Check if this uses SSH Agent for key derivation.
   *
   * Note: SSH Agent key derivation is not yet functional in TypeScript.
   * This method is useful for detecting envelopes locked by other
   * implementations (the reference included).
   */
  isSshAgent(): boolean {
    return isSshAgent(this._params);
  }

  /**
   * Unlock (decrypt) the content key.
   *
   * @param secret - The secret (password or key material) used to lock
   * @returns The decrypted symmetric key
   * @throws ComponentsError if decryption fails (wrong password, tampered data, etc.)
   */
  unlock(secret: Uint8Array): SymmetricKey {
    // Get the AAD from the encrypted message, which contains the derivation params
    const aad = this._encryptedMessage.aad;
    if (aad.length === 0) {
      throw ComponentsError.invalidData("Missing AAD in EncryptedKey");
    }

    // Parse the derivation parameters from AAD
    const paramsCbor = guarded("EncryptedKey", () => decodeCbor(aad));
    const params = keyDerivationParamsFromCbor(paramsCbor);

    // Unlock using the parsed parameters
    switch (params.type) {
      case "hkdf":
        return params.params.unlock(this._encryptedMessage, secret);
      case "pbkdf2":
        return params.params.unlock(this._encryptedMessage, secret);
      case "scrypt":
        return params.params.unlock(this._encryptedMessage, secret);
      case "argon2id":
        return params.params.unlock(this._encryptedMessage, secret);
      case "sshagent":
        return params.params.unlock(this._encryptedMessage, secret);
    }
  }

  /**
   * Check equality with another EncryptedKey.
   */
  equals(other: EncryptedKey): boolean {
    return this._encryptedMessage.equals(other._encryptedMessage);
  }

  /**
   * Get string representation.
   */
  toString(): string {
    return `EncryptedKey(${keyDerivationParamsToString(this._params)})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<EncryptedKey> {
    return (ENCRYPTED_KEY_CODEC ??= defineCodec({
      tags: [TAG_ENCRYPTED_KEY],
      decodeUntagged: (cborValue) => {
        // The untagged content is a tagged EncryptedMessage
        const encryptedMessage = EncryptedMessage.fromCbor(cborValue);

        // Parse the derivation parameters from AAD
        const aad = encryptedMessage.aad;
        if (aad.length === 0) {
          throw ComponentsError.invalidData("Missing AAD in EncryptedKey");
        }
        const paramsCbor = guarded("EncryptedKey", () => decodeCbor(aad));
        const params = keyDerivationParamsFromCbor(paramsCbor);

        return new EncryptedKey(params, encryptedMessage);
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...EncryptedKey.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding.
   * The EncryptedMessage is encoded with its own tag (40002).
   */
  untaggedCbor(): Cbor {
    return this._encryptedMessage.toCbor();
  }

  /** The tagged CBOR form. */
  toCbor(): Cbor {
    return taggedCborOf(this);
  }

  /** As a UR, typed by the first tag's name. */
  toUR(): UR {
    return urFor(this);
  }

  /** Decode tagged or untagged CBOR. */
  static fromCbor(cborValue: Cbor): EncryptedKey {
    return EncryptedKey.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
