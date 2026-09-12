/**
 * MLKEMPublicKey - ML-KEM Public Key for post-quantum key encapsulation
 *
 * MLKEMPublicKey wraps an ML-KEM public key for encapsulating shared secrets.
 * It supports all three security levels (MLKEM512, MLKEM768, MLKEM1024).
 *
 * # CBOR Serialization
 *
 * MLKEMPublicKey is serialized with tag 40101:
 * ```
 * #6.40101([level, h'<public-key-bytes>'])
 * ```
 *
 * # UR Serialization
 *
 * UR type: `mlkem-public-key`
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
import { TAG_MLKEM_PUBLIC_KEY } from "@blockchaincommons/tags";

import {
  type MLKEMLevel,
  mlkemLevelFromValue,
  mlkemLevelToString,
  mlkemPublicKeySize,
  mlkemEncapsulate,
} from "./mlkem-level.js";
import { MLKEMCiphertext } from "./mlkem-ciphertext.js";
import { SymmetricKey } from "../symmetric/symmetric-key.js";
import { ComponentsError } from "../error.js";
import { type RngOptions, randomBytes } from "@blockchaincommons/rand";
import { Reference } from "../reference.js";
import { Digest } from "../digest.js";

/**
 * Result of encapsulation operation.
 */
export interface MLKEMEncapsulationPair {
  /** The shared secret as a SymmetricKey */
  sharedSecret: SymmetricKey;
  /** The ciphertext to send to the private key holder */
  ciphertext: MLKEMCiphertext;
}

// The codec is built on first use so that an unused class tree-shakes away.
let M_L_K_E_M_PUBLIC_KEY_CODEC: ComponentCodec<MLKEMPublicKey> | undefined;

/**
 * MLKEMPublicKey - Post-quantum key encapsulation public key using ML-KEM.
 */
export class MLKEMPublicKey implements ToCbor, ToUR {
  private readonly _level: MLKEMLevel;
  private readonly _data: Uint8Array;

  private constructor(level: MLKEMLevel, data: Uint8Array) {
    const expectedSize = mlkemPublicKeySize(level);
    if (data.length !== expectedSize) {
      throw ComponentsError.postQuantum(
        `MLKEMPublicKey (${mlkemLevelToString(level)}) must be ${expectedSize} bytes, got ${data.length}`,
      );
    }
    this._level = level;
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Create an MLKEMPublicKey from raw bytes.
   *
   * @param level - The ML-KEM security level
   * @param data - The public key bytes
   */
  static fromBytes(level: MLKEMLevel, data: Uint8Array): MLKEMPublicKey {
    return new MLKEMPublicKey(level, data);
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
   * Encapsulate a new shared secret.
   *
   * This creates a random shared secret and encapsulates it, returning both
   * the shared secret (to be used as a symmetric key) and the ciphertext
   * (to be sent to the private key holder for decapsulation).
   *
   * @returns Object containing sharedSecret and ciphertext
   */
  encapsulate({ rng }: RngOptions = {}): MLKEMEncapsulationPair {
    // The encapsulation randomness (32 bytes) comes from `rng` when given.
    const result = mlkemEncapsulate(
      this._level,
      this._data,
      rng === undefined ? undefined : randomBytes(32, { rng }),
    );
    const sharedSecret = SymmetricKey.from(result.sharedSecret);
    const ciphertext = MLKEMCiphertext.fromBytes(this._level, result.ciphertext);
    return { sharedSecret, ciphertext };
  }

  // ============================================================================
  // Equality and String Representation
  // ============================================================================

  /**
   * Compare with another MLKEMPublicKey.
   */
  equals(other: MLKEMPublicKey): boolean {
    if (this._level !== other._level) return false;
    if (this._data.length !== other._data.length) return false;
    for (let i = 0; i < this._data.length; i++) {
      if (this._data[i] !== other._data[i]) return false;
    }
    return true;
  }

  /**
   * Get string representation.
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
    return `${mlkemLevelToString(this._level)}PublicKey(${this.refHexShort()})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<MLKEMPublicKey> {
    return (M_L_K_E_M_PUBLIC_KEY_CODEC ??= defineCodec({
      tags: [TAG_MLKEM_PUBLIC_KEY],
      decodeUntagged: (cborValue) => {
        const elements = expectArray(cborValue);
        if (elements.length !== 2) {
          throw ComponentsError.postQuantum(
            `MLKEMPublicKey CBOR must have 2 elements, got ${elements.length}`,
          );
        }
        const levelValue = Number(expectInteger(elements[0]));
        const level = mlkemLevelFromValue(levelValue);
        const data = expectBytes(elements[1]);
        return MLKEMPublicKey.fromBytes(level, data);
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...MLKEMPublicKey.codec.tags];
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
  static fromCbor(cborValue: Cbor): MLKEMPublicKey {
    return MLKEMPublicKey.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
