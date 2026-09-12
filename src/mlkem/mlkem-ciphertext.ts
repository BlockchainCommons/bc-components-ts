/**
 * MLKEMCiphertext - ML-KEM Ciphertext for post-quantum key encapsulation
 *
 * MLKEMCiphertext wraps an ML-KEM ciphertext for transmission and decapsulation.
 * It supports all three security levels (MLKEM512, MLKEM768, MLKEM1024).
 *
 * # CBOR Serialization
 *
 * MLKEMCiphertext is serialized with tag 40102:
 * ```
 * #6.40102([level, h'<ciphertext-bytes>'])
 * ```
 *
 * # UR Serialization
 *
 * UR type: `mlkem-ciphertext`
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
import { TAG_MLKEM_CIPHERTEXT } from "@blockchaincommons/tags";

import {
  type MLKEMLevel,
  mlkemLevelFromValue,
  mlkemLevelToString,
  mlkemCiphertextSize,
} from "./mlkem-level.js";
import { bytesToHex } from "../utils.js";
import { ComponentsError } from "../error.js";

// The codec is built on first use so that an unused class tree-shakes away.
let M_L_K_E_M_CIPHERTEXT_CODEC: ComponentCodec<MLKEMCiphertext> | undefined;

/**
 * MLKEMCiphertext - Post-quantum key encapsulation ciphertext using ML-KEM.
 */
export class MLKEMCiphertext implements ToCbor, ToUR {
  private readonly _level: MLKEMLevel;
  private readonly _data: Uint8Array;

  private constructor(level: MLKEMLevel, data: Uint8Array) {
    const expectedSize = mlkemCiphertextSize(level);
    if (data.length !== expectedSize) {
      throw ComponentsError.postQuantum(
        `MLKEMCiphertext (${mlkemLevelToString(level)}) must be ${expectedSize} bytes, got ${data.length}`,
      );
    }
    this._level = level;
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Create an MLKEMCiphertext from raw bytes.
   *
   * @param level - The ML-KEM security level
   * @param data - The ciphertext bytes
   */
  static fromBytes(level: MLKEMLevel, data: Uint8Array): MLKEMCiphertext {
    return new MLKEMCiphertext(level, data);
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /**
   * Returns the security level of this ciphertext.
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

  // ============================================================================
  // Equality and String Representation
  // ============================================================================

  /**
   * Compare with another MLKEMCiphertext.
   */
  equals(other: MLKEMCiphertext): boolean {
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
  toString(): string {
    const hex = bytesToHex(this._data);
    return `MLKEMCiphertext(${mlkemLevelToString(this._level)}, ${hex.substring(0, 16)}...)`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<MLKEMCiphertext> {
    return (M_L_K_E_M_CIPHERTEXT_CODEC ??= defineCodec({
      tags: [TAG_MLKEM_CIPHERTEXT],
      decodeUntagged: (cborValue) => {
        const elements = expectArray(cborValue);
        if (elements.length !== 2) {
          throw ComponentsError.postQuantum(
            `MLKEMCiphertext CBOR must have 2 elements, got ${elements.length}`,
          );
        }
        const levelValue = Number(expectInteger(elements[0]));
        const level = mlkemLevelFromValue(levelValue);
        const data = expectBytes(elements[1]);
        return MLKEMCiphertext.fromBytes(level, data);
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...MLKEMCiphertext.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: [level, ciphertext_bytes]
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
  static fromCbor(cborValue: Cbor): MLKEMCiphertext {
    return MLKEMCiphertext.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
