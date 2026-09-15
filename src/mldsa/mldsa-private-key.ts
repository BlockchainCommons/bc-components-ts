/**
 * MLDSAPrivateKey - ML-DSA Private Key for post-quantum digital signatures
 *
 * MLDSAPrivateKey wraps an ML-DSA secret key for signing messages.
 * It supports all three security levels (MLDSA44, MLDSA65, MLDSA87).
 *
 * # CBOR Serialization
 *
 * MLDSAPrivateKey is serialized with tag 40103:
 * ```
 * #6.40103([level, h'<private-key-bytes>'])
 * ```
 *
 * # UR Serialization
 *
 * UR type: `mldsa-private-key`
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
import { TAG_MLDSA_PRIVATE_KEY } from "@blockchaincommons/tags";
import { secureRng, type RngOptions } from "@blockchaincommons/rand";

import {
  MLDSALevel,
  mldsaLevelToString,
  mldsaPrivateKeySize,
  mldsaGenerateKeypairUsing,
  mldsaSign,
  mldsaLevelFromCbor,
} from "./mldsa-level.js";
import { MLDSAPublicKey } from "./mldsa-public-key.js";
import { MLDSASignature } from "./mldsa-signature.js";
import { ComponentsError } from "../error.js";
import { guarded } from "../domain.js";
import { Reference } from "../reference.js";
import { Digest } from "../digest.js";

// The codec is built on first use so that an unused class tree-shakes away.
let M_L_D_S_A_PRIVATE_KEY_CODEC: ComponentCodec<MLDSAPrivateKey> | undefined;

/**
 * MLDSAPrivateKey - Post-quantum signing private key using ML-DSA.
 */
export class MLDSAPrivateKey implements ToCbor, ToUR {
  private readonly _level: MLDSALevel;
  private readonly _data: Uint8Array;

  private constructor(level: MLDSALevel, data: Uint8Array) {
    const expectedSize = mldsaPrivateKeySize(level);
    if (data.length !== expectedSize) {
      throw ComponentsError.postQuantum(
        `error: SecretKey expected ${expectedSize} bytes, got ${data.length}`,
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
    level: MLDSALevel = MLDSALevel.MLDSA65,
    { rng = secureRng() }: RngOptions = {},
  ): MLDSAPrivateKey {
    const keypair = mldsaGenerateKeypairUsing(level, rng);
    return new MLDSAPrivateKey(level, keypair.secretKey);
  }

  /**
   * Create an MLDSAPrivateKey from raw bytes.
   *
   * @param level - The ML-DSA security level
   * @param data - The private key bytes
   */
  static fromBytes(level: MLDSALevel, data: Uint8Array): MLDSAPrivateKey {
    return new MLDSAPrivateKey(level, data);
  }

  /** A fresh private key at `level` and its public key. */
  static keypair(
    level: MLDSALevel = MLDSALevel.MLDSA65,
    { rng = secureRng() }: RngOptions = {},
  ): [MLDSAPrivateKey, MLDSAPublicKey] {
    const keypairData = mldsaGenerateKeypairUsing(level, rng);
    const privateKey = new MLDSAPrivateKey(level, keypairData.secretKey);
    const publicKey = MLDSAPublicKey.fromBytes(level, keypairData.publicKey);
    return [privateKey, publicKey];
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
   * Sign a message with this private key.
   *
   * @param message - The message to sign
   * @returns The ML-DSA signature
   */
  sign(message: Uint8Array): MLDSASignature {
    const sigBytes = guarded("MLDSAPrivateKey.sign", () =>
      mldsaSign(this._level, this._data, message),
    );
    return MLDSASignature.fromBytes(this._level, sigBytes);
  }

  // ============================================================================
  // Equality and String Representation
  // ============================================================================

  /**
   * Compare with another MLDSAPrivateKey.
   */
  equals(other: MLDSAPrivateKey): boolean {
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
    return `${mldsaLevelToString(this._level)}PrivateKey(${this.refHexShort()})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<MLDSAPrivateKey> {
    return (M_L_D_S_A_PRIVATE_KEY_CODEC ??= defineCodec({
      tags: [TAG_MLDSA_PRIVATE_KEY],
      decodeUntagged: (cborValue) => {
        const elements = asArray(cborValue);
        if (elements === undefined) throw CborError.custom("MLDSAPrivateKey must be an array");
        if (elements.length !== 2) throw CborError.custom("MLDSAPrivateKey must have two elements");
        const level = mldsaLevelFromCbor(elements[0]);
        const data = expectBytes(elements[1]);
        return MLDSAPrivateKey.fromBytes(level, data);
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...MLDSAPrivateKey.codec.tags];
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
  static fromCbor(cborValue: Cbor): MLDSAPrivateKey {
    return MLDSAPrivateKey.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
