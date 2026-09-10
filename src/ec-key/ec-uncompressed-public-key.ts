/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
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
 *
 * Ported from bc-components-rust/src/ec_key/ec_uncompressed_public_key.rs
 */

import { ecdsa, ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE } from "@blockchaincommons/crypto";
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
import { EC_KEY as TAG_EC_KEY, LEGACY_TAGS } from "@blockchaincommons/tags";
const TAG_EC_KEY_V1 = LEGACY_TAGS.EC_KEY_V1;
import { ComponentsError } from "../error.js";
import { bytesToHex, hexToBytes, toBase64 } from "../utils.js";
import type { ECKeyBase } from "./ec-key-base.js";

export class ECUncompressedPublicKey implements ECKeyBase, ToCbor, ToUR {
  static readonly KEY_SIZE: number = ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE;

  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    if (data.length !== ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE) {
      throw ComponentsError.invalidSize(ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE, data.length);
    }
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Restore an ECUncompressedPublicKey from a fixed-size array of bytes.
   */
  static fromData(data: Uint8Array): ECUncompressedPublicKey {
    return new ECUncompressedPublicKey(new Uint8Array(data));
  }

  /**
   * Restore an ECUncompressedPublicKey from a reference to an array of bytes.
   * Validates the length.
   */
  static fromDataRef(data: Uint8Array): ECUncompressedPublicKey {
    if (data.length !== ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE) {
      throw ComponentsError.invalidSize(ECDSA_UNCOMPRESSED_PUBLIC_KEY_SIZE, data.length);
    }
    return ECUncompressedPublicKey.fromData(data);
  }

  /**
   * Create an ECUncompressedPublicKey from raw bytes (legacy alias).
   */
  static from(data: Uint8Array): ECUncompressedPublicKey {
    return ECUncompressedPublicKey.fromData(data);
  }

  /**
   * Restore an ECUncompressedPublicKey from a hex string.
   */
  static fromHex(hex: string): ECUncompressedPublicKey {
    return ECUncompressedPublicKey.fromData(hexToBytes(hex));
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /**
   * Get a reference to the fixed-size array of bytes.
   */
  data(): Uint8Array {
    return this._data;
  }

  /**
   * Get the raw public key bytes (copy).
   */
  toData(): Uint8Array {
    return new Uint8Array(this._data);
  }

  /**
   * Get hex string representation.
   */
  hex(): string {
    return bytesToHex(this._data);
  }

  /**
   * Get hex string representation (alias for hex()).
   */
  toHex(): string {
    return this.hex();
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
  toString(): string {
    return `ECUncompressedPublicKey(${this.toHex().substring(0, 16)}...)`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static readonly codec: ComponentCodec<ECUncompressedPublicKey> = defineCodec({
    tags: [TAG_EC_KEY, TAG_EC_KEY_V1],
    decodeUntagged: (cborValue) => {
      const map = expectMap(cborValue);

      // Check that key 2 is not present (would indicate private key)
      const isPrivate = mapGetBoolean(map, 2);
      if (isPrivate === true) {
        throw ComponentsError.invalidData("Expected ECUncompressedPublicKey but found private key");
      }

      // Get key data from key 3
      // CborMap.extract() returns native types (Uint8Array for byte strings)
      const keyData = mapGetBytes(map, 3);
      if (keyData === undefined || keyData.length === 0) {
        throw ComponentsError.invalidData("ECUncompressedPublicKey CBOR must have key 3 (data)");
      }

      return ECUncompressedPublicKey.fromDataRef(keyData);
    },
    encodeUntagged: (value) => value.untaggedCbor(),
  });

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
