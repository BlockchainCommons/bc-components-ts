/**
 * MLDSAPublicKey - ML-DSA Public Key for post-quantum signature verification
 *
 * MLDSAPublicKey wraps an ML-DSA public key for verifying signatures.
 * It supports all three security levels (MLDSA44, MLDSA65, MLDSA87).
 *
 * # CBOR Serialization
 *
 * MLDSAPublicKey is serialized with tag 40104:
 * ```
 * #6.40104([level, h'<public-key-bytes>'])
 * ```
 *
 * # UR Serialization
 *
 * UR type: `mldsa-public-key`
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
import { TAG_MLDSA_PUBLIC_KEY } from "@blockchaincommons/tags";

import {
  type MLDSALevel,
  mldsaLevelFromValue,
  mldsaLevelToString,
  mldsaPublicKeySize,
  mldsaVerify,
} from "./mldsa-level.js";
import type { MLDSASignature } from "./mldsa-signature.js";
import { ComponentsError } from "../error.js";
import { Reference } from "../reference.js";
import { Digest } from "../digest.js";

// The codec is built on first use so that an unused class tree-shakes away.
let M_L_D_S_A_PUBLIC_KEY_CODEC: ComponentCodec<MLDSAPublicKey> | undefined;

/**
 * MLDSAPublicKey - Post-quantum signature verification key using ML-DSA.
 */
export class MLDSAPublicKey implements ToCbor, ToUR {
  private readonly _level: MLDSALevel;
  private readonly _data: Uint8Array;

  private constructor(level: MLDSALevel, data: Uint8Array) {
    const expectedSize = mldsaPublicKeySize(level);
    if (data.length !== expectedSize) {
      throw ComponentsError.postQuantum(
        `MLDSAPublicKey (${mldsaLevelToString(level)}) must be ${expectedSize} bytes, got ${data.length}`,
      );
    }
    this._level = level;
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Create an MLDSAPublicKey from raw bytes.
   *
   * @param level - The ML-DSA security level
   * @param data - The public key bytes
   */
  static fromBytes(level: MLDSALevel, data: Uint8Array): MLDSAPublicKey {
    return new MLDSAPublicKey(level, data);
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /**
   * Returns the security level of this key.
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

  /**
   * Verify a signature against a message.
   *
   * @param signature - The ML-DSA signature to verify
   * @param message - The message that was signed
   * @returns True if the signature is valid
   */
  verify(signature: MLDSASignature, message: Uint8Array): boolean {
    if (signature.level !== this._level) {
      return false;
    }
    return mldsaVerify(this._level, this._data, message, signature.bytes);
  }

  // ============================================================================
  // Equality and String Representation
  // ============================================================================

  /**
   * Compare with another MLDSAPublicKey.
   */
  equals(other: MLDSAPublicKey): boolean {
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
    return `${mldsaLevelToString(this._level)}PublicKey(${this.refHexShort()})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<MLDSAPublicKey> {
    return (M_L_D_S_A_PUBLIC_KEY_CODEC ??= defineCodec({
      tags: [TAG_MLDSA_PUBLIC_KEY],
      decodeUntagged: (cborValue) => {
        const elements = expectArray(cborValue);
        if (elements.length !== 2) {
          throw ComponentsError.postQuantum(
            `MLDSAPublicKey CBOR must have 2 elements, got ${elements.length}`,
          );
        }
        const levelValue = Number(expectInteger(elements[0]));
        const level = mldsaLevelFromValue(levelValue);
        const data = expectBytes(elements[1]);
        return MLDSAPublicKey.fromBytes(level, data);
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...MLDSAPublicKey.codec.tags];
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
  static fromCbor(cborValue: Cbor): MLDSAPublicKey {
    return MLDSAPublicKey.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
