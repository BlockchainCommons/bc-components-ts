import { ecdsa } from "@blockchaincommons/crypto";
import {
  type Cbor,
  type CborInput,
  type Tag,
  cbor,
  expectMap,
  type ToCbor,
} from "@blockchaincommons/dcbor";
import {
  taggedCborOf,
  mapGetBoolean,
  mapGetBytes,
  type ComponentCodec,
  defineCodec,
} from "../codable.js";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { TAG_EC_KEY, LEGACY_TAGS } from "@blockchaincommons/tags";
const TAG_EC_KEY_V1 = LEGACY_TAGS.EC_KEY_V1;
import { ComponentsError } from "../error.js";
import { bytesToHex, toBase64 } from "../utils.js";
import { bytesFromHex, guarded } from "../domain.js";
import type { ECKeyBase } from "./ec-key-base.js";
import { Reference } from "../reference.js";
import { Digest } from "../digest.js";

// The codec is built on first use so that an unused class tree-shakes away.
let E_C_UNCOMPRESSED_PUBLIC_KEY_CODEC: ComponentCodec<ECUncompressedPublicKey> | undefined;

/**
 * EC uncompressed public key for ECDSA (secp256k1, 65 bytes)
 *
 * An `ECUncompressedPublicKey` is a 65-byte uncompressed representation of a
 * public key on the secp256k1 curve. The first byte is 0x04 (uncompressed prefix),
 * followed by the 32-byte x-coordinate and 32-byte y-coordinate.
 *
 * While compressed public keys (33 bytes) are preferred for space efficiency,
 * uncompressed keys are sometimes needed for compatibility with legacy systems.
 *
 * # CBOR Serialization
 *
 * `ECUncompressedPublicKey` is serialized to CBOR with tags 40306 (or legacy 306).
 *
 * The format is a map:
 * ```
 * #6.40306({
 *   3: h'<65-byte-uncompressed-public-key>' // key data
 * })
 * ```
 */
export class ECUncompressedPublicKey implements ECKeyBase, ToCbor, ToUR {
  /** The byte length of a `ECUncompressedPublicKey`. */
  static readonly KEY_SIZE: number = ecdsa.UNCOMPRESSED_PUBLIC_KEY_SIZE;

  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    if (data.length !== ecdsa.UNCOMPRESSED_PUBLIC_KEY_SIZE) {
      throw ComponentsError.invalidSize(ecdsa.UNCOMPRESSED_PUBLIC_KEY_SIZE, data.length);
    }
    if (data[0] !== 0x04) {
      throw ComponentsError.invalidDataForType("ECUncompressedPublicKey", "prefix must be 0x04");
    }
    // A point off the curve is rejected here, not at first use.
    guarded("ECUncompressedPublicKey", () => ecdsa.compressPublicKey(data));
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Restore an ECUncompressedPublicKey from a fixed-size array of bytes.
   */
  static from(data: Uint8Array): ECUncompressedPublicKey {
    return new ECUncompressedPublicKey(new Uint8Array(data));
  }

  /**
   * Restore an ECUncompressedPublicKey from a hex string.
   */
  static fromHex(hex: string): ECUncompressedPublicKey {
    return ECUncompressedPublicKey.from(bytesFromHex(hex, "ECUncompressedPublicKey"));
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /** The bytes (a view; do not mutate). */
  /** A copy of the bytes; mutating it does not touch this value. */
  get bytes(): Uint8Array {
    return new Uint8Array(this._data);
  }

  /**
   * Get hex string representation.
   */
  toHex(): string {
    return bytesToHex(this._data);
  }

  /**
   * Get base64 representation.
   */
  toBase64(): string {
    return toBase64(this._data);
  }

  /**
   * Convert to compressed public key format.
   * Note: Returns the compressed bytes. To get ECPublicKey, use the ec-public-key module.
   */
  compressedData(): Uint8Array {
    return ecdsa.compressPublicKey(this._data);
  }

  /**
   * Compare with another ECUncompressedPublicKey.
   */
  equals(other: ECUncompressedPublicKey): boolean {
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
    return `ECUncompressedPublicKey(${this.refHexShort()})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<ECUncompressedPublicKey> {
    return (E_C_UNCOMPRESSED_PUBLIC_KEY_CODEC ??= defineCodec({
      tags: [TAG_EC_KEY, TAG_EC_KEY_V1],
      decodeUntagged: (cborValue) => {
        const map = expectMap(cborValue);

        // Check that key 2 is not present (would indicate private key)
        const isPrivate = mapGetBoolean(map, 2);
        if (isPrivate === true) {
          throw ComponentsError.invalidData(
            "Expected ECUncompressedPublicKey but found private key",
          );
        }

        // Get key data from key 3
        // CborMap.extract() returns native types (Uint8Array for byte strings)
        const keyData = mapGetBytes(map, 3);
        if (keyData === undefined || keyData.length === 0) {
          throw ComponentsError.invalidData("ECUncompressedPublicKey CBOR must have key 3 (data)");
        }

        return ECUncompressedPublicKey.from(keyData);
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...ECUncompressedPublicKey.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: { 3: h'<65-byte-key>' }
   */
  untaggedCbor(): Cbor {
    const map = new Map<number, CborInput>();
    map.set(3, cbor(this._data));
    return cbor(map);
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
  static fromCbor(cborValue: Cbor): ECUncompressedPublicKey {
    return ECUncompressedPublicKey.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
