/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * EC compressed public key for ECDSA verification (secp256k1, 33 bytes)
 *
 * An `ECPublicKey` is a 33-byte compressed representation of a public key on
 * the secp256k1 curve. The first byte is a prefix (0x02 or 0x03) that
 * indicates the parity of the y-coordinate, followed by the 32-byte
 * x-coordinate.
 *
 * These public keys are used to:
 * - Verify ECDSA signatures
 * - Identify the owner of a private key without revealing the private key
 *
 * # CBOR Serialization
 *
 * `ECPublicKey` is serialized to CBOR with tags 40306 (or legacy 306).
 *
 * The format is a map:
 * ```
 * #6.40306({
 *   3: h'<33-byte-public-key>' // key data (no key 2 means public key)
 * })
 * ```
 *
 * Ported from bc-components-rust/src/ec_key/ec_public_key.rs
 */

import { ecdsa, ECDSA_PUBLIC_KEY_SIZE } from "@blockchaincommons/crypto";
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
import { ECUncompressedPublicKey } from "./ec-uncompressed-public-key.js";
import { bytesToHex, hexToBytes, toBase64 } from "../utils.js";
import type { ECPublicKeyBase } from "./ec-key-base.js";

export class ECPublicKey implements ECPublicKeyBase, ToCbor, ToUR {
  static readonly KEY_SIZE: number = ECDSA_PUBLIC_KEY_SIZE;

  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    if (data.length !== ECDSA_PUBLIC_KEY_SIZE) {
      throw ComponentsError.invalidSize(ECDSA_PUBLIC_KEY_SIZE, data.length);
    }
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Restore an ECPublicKey from a fixed-size array of bytes.
   */
  static from(data: Uint8Array): ECPublicKey {
    return new ECPublicKey(new Uint8Array(data));
  }

  /**
   * Restore an ECPublicKey from a hex string.
   */
  static fromHex(hex: string): ECPublicKey {
    return ECPublicKey.from(hexToBytes(hex));
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /** The bytes (a view; do not mutate). */
  get bytes(): Uint8Array {
    return this._data;
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
   * Returns the compressed public key (self).
   *
   * This method implements the ECKey interface. Since ECPublicKey is already
   * a compressed public key, this returns itself.
   */
  publicKey(): ECPublicKey {
    return this;
  }

  /**
   * Convert this compressed public key to uncompressed format.
   */
  uncompressedPublicKey(): ECUncompressedPublicKey {
    const uncompressed = ecdsa.decompressPublicKey(this._data);
    return ECUncompressedPublicKey.from(uncompressed);
  }

  /**
   * Verify an ECDSA signature.
   *
   * @param signature - The 64-byte signature to verify
   * @param message - The message that was signed
   * @returns true if the signature is valid
   */
  verify(signature: Uint8Array, message: Uint8Array): boolean {
    try {
      return ecdsa.verify(this._data, signature, message);
    } catch {
      return false;
    }
  }

  /**
   * Compare with another ECPublicKey.
   */
  equals(other: ECPublicKey): boolean {
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
    return `ECPublicKey(${this.toHex().substring(0, 16)}...)`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static readonly codec: ComponentCodec<ECPublicKey> = defineCodec({
    tags: [TAG_EC_KEY, TAG_EC_KEY_V1],
    decodeUntagged: (cborValue) => {
      const map = expectMap(cborValue);

      // Check that key 2 is not present (would indicate private key)
      const isPrivate = mapGetBoolean(map, 2);
      if (isPrivate === true) {
        throw ComponentsError.invalidData(
          "Expected ECPublicKey but found private key (key 2 is true)",
        );
      }

      // Get key data from key 3
      // CborMap.extract() returns native types (Uint8Array for byte strings)
      const keyData = mapGetBytes(map, 3);
      if (keyData === undefined || keyData.length === 0) {
        throw ComponentsError.invalidData("ECPublicKey CBOR must have key 3 (data)");
      }

      return ECPublicKey.from(keyData);
    },
    encodeUntagged: (value) => value.untaggedCbor(),
  });

  cborTags(): Tag[] {
    return [...ECPublicKey.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: { 3: h'<33-byte-key>' }
   * Note: No key 2 indicates this is a public key
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
  static fromCbor(cborValue: Cbor): ECPublicKey {
    return ECPublicKey.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
