/**
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
import { TAG_MLKEM_PRIVATE_KEY } from "@blockchaincommons/tags";
import { secureRng, type RngOptions } from "@blockchaincommons/rand";

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
import { ComponentsError } from "../error.js";
import { Reference } from "../reference.js";
import { Digest } from "../digest.js";

// The codec is built on first use so that an unused class tree-shakes away.
let M_L_K_E_M_PRIVATE_KEY_CODEC: ComponentCodec<MLKEMPrivateKey> | undefined;

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

  /** A fresh private key at `level`; pass `rng` to make it deterministic. */
  static random(
    level: MLKEMLevel = MLKEMLevel.MLKEM768,
    { rng = secureRng() }: RngOptions = {},
  ): MLKEMPrivateKey {
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

  /** A fresh private key at `level` and its public key. */
  static keypair(
    level: MLKEMLevel = MLKEMLevel.MLKEM768,
    { rng = secureRng() }: RngOptions = {},
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
  get level(): MLKEMLevel {
    return this._level;
  }

  /** The bytes (a view; do not mutate). */
  get bytes(): Uint8Array {
    return new Uint8Array(this._data);
  }

  /** Number of bytes. */
  get byteLength(): number {
    return this._data.length;
  }

  /**
   * Decapsulate a shared secret from a ciphertext.
   *
   * @param ciphertext - The ML-KEM ciphertext
   * @returns The decapsulated shared secret as a SymmetricKey
   */
  decapsulate(ciphertext: MLKEMCiphertext): SymmetricKey {
    if (ciphertext.level !== this._level) {
      throw ComponentsError.postQuantum(
        `Ciphertext level (${mlkemLevelToString(ciphertext.level)}) does not match key level (${mlkemLevelToString(this._level)})`,
      );
    }
    const sharedSecret = mlkemDecapsulate(this._level, this._data, ciphertext.bytes);
    return SymmetricKey.from(sharedSecret);
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
  /** The reference: the digest of the tagged CBOR, as the reference computes it. */
  reference(): Reference {
    return Reference.fromDigest(Digest.fromImage(this.toCbor().toData()));
  }

  /** The first four bytes of `reference()` in hex, the reference's `ref_hex_short`. */
  refHexShort(): string {
    return this.reference().refHexShort();
  }

  /** The reference's `Display`: the type name over the short reference. */
  toString(): string {
    return `${mlkemLevelToString(this._level)}PrivateKey(${this.refHexShort()})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<MLKEMPrivateKey> {
    return (M_L_K_E_M_PRIVATE_KEY_CODEC ??= defineCodec({
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
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
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
