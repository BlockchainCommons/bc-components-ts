/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * MLKEMPrivateKey - ML-KEM Private Key for post-quantum key decapsulation
 *
 * MLKEMPrivateKey wraps an ML-KEM secret key for decapsulating shared secrets.
 * It supports all three security levels (MLKEM512, MLKEM768, MLKEM1024).
 *
 * # CBOR Serialization
 *
 * MLKEMPrivateKey is serialized with tag 40100:
 * ```
 * #6.40100([level, h'<private-key-bytes>'])
 * ```
 *
 * # UR Serialization
 *
 * UR type: `mlkem-private-key`
 *
 * Ported from bc-components-rust/src/mlkem/mlkem_private_key.rs
 */

import {
  type Cbor,
  type Tag,
  cbor,
  expectArray,
  expectInteger,
  expectBytes,
  type ToCbor,
} from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "../codable.js";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { MLKEM_PRIVATE_KEY as TAG_MLKEM_PRIVATE_KEY } from "@blockchaincommons/tags";
import { type RandomNumberGenerator, secureRng } from "@blockchaincommons/rand";

import {
  MLKEMLevel,
  mlkemLevelFromValue,
  mlkemLevelToString,
  mlkemPrivateKeySize,
  mlkemGenerateKeypairUsing,
  mlkemDecapsulate,
  mlkemExtractPublicKey,
} from "./mlkem-level.js";
import { MLKEMPublicKey } from "./mlkem-public-key.js";
import type { MLKEMCiphertext } from "./mlkem-ciphertext.js";
import { SymmetricKey } from "../symmetric/symmetric-key.js";
import { bytesToHex } from "../utils.js";
import { ComponentsError } from "../error.js";

/**
 * MLKEMPrivateKey - Post-quantum key decapsulation private key using ML-KEM.
 */
export class MLKEMPrivateKey implements ToCbor, ToUR {
  private readonly _level: MLKEMLevel;
  private readonly _data: Uint8Array;

  private constructor(level: MLKEMLevel, data: Uint8Array) {
    const expectedSize = mlkemPrivateKeySize(level);
    if (data.length !== expectedSize) {
      throw ComponentsError.postQuantum(
        `MLKEMPrivateKey (${mlkemLevelToString(level)}) must be ${expectedSize} bytes, got ${data.length}`,
      );
    }
    this._level = level;
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Generate a new random MLKEMPrivateKey with the specified security level.
   *
   * @param level - The ML-KEM security level (default: MLKEM768)
   */
  static new(level: MLKEMLevel = MLKEMLevel.MLKEM768): MLKEMPrivateKey {
    const rng = secureRng();
    return MLKEMPrivateKey.newUsing(level, rng);
  }

  /**
   * Generate a new random MLKEMPrivateKey using the provided RNG.
   *
   * @param level - The ML-KEM security level
   * @param rng - Random number generator
   */
  static newUsing(level: MLKEMLevel, rng: RandomNumberGenerator): MLKEMPrivateKey {
    const keypair = mlkemGenerateKeypairUsing(level, rng);
    return new MLKEMPrivateKey(level, keypair.secretKey);
  }

  /**
   * Create an MLKEMPrivateKey from raw bytes.
   *
   * @param level - The ML-KEM security level
   * @param data - The private key bytes
   */
  static fromBytes(level: MLKEMLevel, data: Uint8Array): MLKEMPrivateKey {
    return new MLKEMPrivateKey(level, data);
  }

  /**
   * Generate a keypair and return both private and public keys.
   *
   * @param level - The ML-KEM security level (default: MLKEM768)
   * @returns Tuple of [privateKey, publicKey]
   */
  static keypair(level: MLKEMLevel = MLKEMLevel.MLKEM768): [MLKEMPrivateKey, MLKEMPublicKey] {
    const rng = secureRng();
    return MLKEMPrivateKey.keypairUsing(level, rng);
  }

  /**
   * Generate a keypair using the provided RNG.
   *
   * @param level - The ML-KEM security level
   * @param rng - Random number generator
   * @returns Tuple of [privateKey, publicKey]
   */
  static keypairUsing(
    level: MLKEMLevel,
    rng: RandomNumberGenerator,
  ): [MLKEMPrivateKey, MLKEMPublicKey] {
    const keypairData = mlkemGenerateKeypairUsing(level, rng);
    const privateKey = new MLKEMPrivateKey(level, keypairData.secretKey);
    const publicKey = MLKEMPublicKey.fromBytes(level, keypairData.publicKey);
    return [privateKey, publicKey];
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /**
   * Returns the security level of this key.
   */
  level(): MLKEMLevel {
    return this._level;
  }

  /**
   * Returns the raw key bytes.
   */
  asBytes(): Uint8Array {
    return this._data;
  }

  /**
   * Returns a copy of the raw key bytes.
   */
  data(): Uint8Array {
    return new Uint8Array(this._data);
  }

  /**
   * Returns the size of the key in bytes.
   */
  size(): number {
    return this._data.length;
  }

  /**
   * Decapsulate a shared secret from a ciphertext.
   *
   * @param ciphertext - The ML-KEM ciphertext
   * @returns The decapsulated shared secret as a SymmetricKey
   */
  decapsulate(ciphertext: MLKEMCiphertext): SymmetricKey {
    if (ciphertext.level() !== this._level) {
      throw ComponentsError.postQuantum(
        `Ciphertext level (${mlkemLevelToString(ciphertext.level())}) does not match key level (${mlkemLevelToString(this._level)})`,
      );
    }
    const sharedSecret = mlkemDecapsulate(this._level, this._data, ciphertext.asBytes());
    return SymmetricKey.fromData(sharedSecret);
  }

  /**
   * Derives and returns the corresponding public key.
   *
   * In ML-KEM (FIPS 203), the decapsulation key contains the encapsulation key (public key)
   * embedded within it. This method extracts that public key.
   *
   * @returns The corresponding MLKEMPublicKey
   */
  publicKey(): MLKEMPublicKey {
    const publicKeyData = mlkemExtractPublicKey(this._level, this._data);
    return MLKEMPublicKey.fromBytes(this._level, publicKeyData);
  }

  // ============================================================================
  // Equality and String Representation
  // ============================================================================

  /**
   * Compare with another MLKEMPrivateKey.
   */
  equals(other: MLKEMPrivateKey): boolean {
    if (this._level !== other._level) return false;
    if (this._data.length !== other._data.length) return false;
    for (let i = 0; i < this._data.length; i++) {
      if (this._data[i] !== other._data[i]) return false;
    }
    return true;
  }

  /**
   * Get string representation (truncated for security).
   */
  toString(): string {
    const hex = bytesToHex(this._data);
    return `MLKEMPrivateKey(${mlkemLevelToString(this._level)}, ${hex.substring(0, 8)}...)`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static readonly codec: ComponentCodec<MLKEMPrivateKey> = defineCodec({
    tags: [TAG_MLKEM_PRIVATE_KEY],
    decodeUntagged: (cborValue) => {
      const elements = expectArray(cborValue);
      if (elements.length !== 2) {
        throw ComponentsError.postQuantum(
          `MLKEMPrivateKey CBOR must have 2 elements, got ${elements.length}`,
        );
      }
      const levelValue = Number(expectInteger(elements[0]));
      const level = mlkemLevelFromValue(levelValue);
      const data = expectBytes(elements[1]);
      return MLKEMPrivateKey.fromBytes(level, data);
    },
    encodeUntagged: (value) => value.untaggedCbor(),
  });

  cborTags(): Tag[] {
    return [...MLKEMPrivateKey.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: [level, key_bytes]
   */
  untaggedCbor(): Cbor {
    return cbor([this._level, this._data]);
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
  static fromCbor(cborValue: Cbor): MLKEMPrivateKey {
    return MLKEMPrivateKey.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
