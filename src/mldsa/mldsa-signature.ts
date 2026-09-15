/**
 * MLDSASignature - ML-DSA Digital Signature
 *
 * MLDSASignature wraps an ML-DSA signature for serialization and verification.
 * It supports all three security levels (MLDSA44, MLDSA65, MLDSA87).
 *
 * # CBOR Serialization
 *
 * MLDSASignature is serialized with tag 40105:
 * ```
 * #6.40105([level, h'<signature-bytes>'])
 * ```
 *
 * # UR Serialization
 *
 * UR type: `mldsa-signature`
 */

import {
  type Cbor,
  type Tag,
  cbor,
  expectBytes,
  type ToCbor,
  asArray,
  CborError,
} from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "../codable.js";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { TAG_MLDSA_SIGNATURE } from "@blockchaincommons/tags";

import {
  type MLDSALevel,
  mldsaLevelToString,
  mldsaSignatureSize,
  mldsaLevelFromCbor,
} from "./mldsa-level.js";
import { bytesToHex } from "../utils.js";
import { ComponentsError } from "../error.js";

// The codec is built on first use so that an unused class tree-shakes away.
let M_L_D_S_A_SIGNATURE_CODEC: ComponentCodec<MLDSASignature> | undefined;

/**
 * MLDSASignature - Post-quantum digital signature using ML-DSA.
 */
export class MLDSASignature implements ToCbor, ToUR {
  private readonly _level: MLDSALevel;
  private readonly _data: Uint8Array;

  private constructor(level: MLDSALevel, data: Uint8Array) {
    // pqcrypto's `DetachedSignature::from_bytes` accepts any length up to
    // the scheme's; a shorter signature verifies as `false`.
    const expectedSize = mldsaSignatureSize(level);
    if (data.length > expectedSize) {
      throw ComponentsError.postQuantum(
        `error: DetachedSignature expected ${expectedSize} bytes, got ${data.length}`,
      );
    }
    this._level = level;
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Create an MLDSASignature from raw bytes.
   *
   * @param level - The ML-DSA security level
   * @param data - The signature bytes
   */
  static fromBytes(level: MLDSALevel, data: Uint8Array): MLDSASignature {
    return new MLDSASignature(level, data);
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /**
   * Returns the security level of this signature.
   */
  get level(): MLDSALevel {
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
   * Compare with another MLDSASignature.
   */
  equals(other: MLDSASignature): boolean {
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
    return `MLDSASignature(${mldsaLevelToString(this._level)}, ${hex.substring(0, 16)}...)`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<MLDSASignature> {
    return (M_L_D_S_A_SIGNATURE_CODEC ??= defineCodec({
      tags: [TAG_MLDSA_SIGNATURE],
      decodeUntagged: (cborValue) => {
        const elements = asArray(cborValue);
        if (elements === undefined) throw CborError.custom("MLDSASignature must be an array");
        if (elements.length !== 2) throw CborError.custom("MLDSASignature must have two elements");
        const level = mldsaLevelFromCbor(elements[0]);
        const data = expectBytes(elements[1]);
        return MLDSASignature.fromBytes(level, data);
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...MLDSASignature.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: [level, signature_bytes]
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
  static fromCbor(cborValue: Cbor): MLDSASignature {
    return MLDSASignature.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
