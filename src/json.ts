/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * A CBOR-tagged container for UTF-8 JSON text.
 *
 * Ported from bc-components-rust/src/json.rs
 *
 * The `JSON` type wraps UTF-8 JSON text as a CBOR byte string with tag 262.
 * This allows JSON data to be embedded within CBOR structures while
 * maintaining type information through the tag.
 *
 * This implementation does not validate that the contained data is well-formed
 * JSON. It simply provides a type-safe wrapper around byte data that is
 * intended to contain JSON text.
 *
 * # CBOR Serialization
 *
 * `JSON` implements the CBOR tagged encoding interfaces, which means it can be
 * serialized to and deserialized from CBOR with tag 262 (`TAG_JSON`).
 *
 * @example
 * ```typescript
 * import { JSON } from '@blockchaincommons/components';
 *
 * // Create JSON from a string
 * const json = JSON.fromString('{"key": "value"}');
 * console.log(json.asStr()); // {"key": "value"}
 *
 * // Create JSON from bytes
 * const json2 = JSON.from(new TextEncoder().encode('[1, 2, 3]'));
 * console.log(json2.byteLength); // 9
 * ```
 */

import { type Cbor, type Tag, cbor, expectBytes, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "./codable.js";
import { JSON as TAG_JSON } from "@blockchaincommons/tags";
import { bytesToHex, hexToBytes } from "./utils.js";
import { type UR, urFor } from "@blockchaincommons/uniform-resources";

/**
 * A CBOR-tagged container for UTF-8 JSON text.
 *
 * Wraps UTF-8 JSON text as a CBOR byte string with tag 262.
 * This allows JSON data to be embedded within CBOR structures while
 * maintaining type information through the tag.
 */
export class JSON implements ToCbor {
  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Create a new JSON instance from byte data.
   */
  static from(data: Uint8Array): JSON {
    return new JSON(data);
  }

  /**
   * Create a new JSON instance from a string.
   */
  static fromString(s: string): JSON {
    const encoder = new TextEncoder();
    return new JSON(encoder.encode(s));
  }

  /**
   * Create a new JSON instance from a hexadecimal string.
   */
  static fromHex(hex: string): JSON {
    return new JSON(hexToBytes(hex));
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /** Number of bytes. */
  get byteLength(): number {
    return this._data.length;
  }

  /**
   * Return true if the JSON data is empty.
   */
  isEmpty(): boolean {
    return this._data.length === 0;
  }

  /** The bytes (a view; do not mutate). */
  get bytes(): Uint8Array {
    return new Uint8Array(this._data);
  }

  /**
   * Return the data as a UTF-8 string slice.
   *
   * @throws Error if the data is not valid UTF-8.
   */
  asStr(): string {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    return decoder.decode(this._data);
  }

  /**
   * Return the data as a hexadecimal string.
   */
  toHex(): string {
    return bytesToHex(this._data);
  }

  /**
   * Compare with another JSON.
   */
  equals(other: JSON): boolean {
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
    return `JSON(${this.asStr()})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static readonly codec: ComponentCodec<JSON> = defineCodec({
    tags: [TAG_JSON],
    decodeUntagged: (cborValue) => {
      const data = expectBytes(cborValue);
      return JSON.from(data);
    },
    encodeUntagged: (value) => value.untaggedCbor(),
  });

  cborTags(): Tag[] {
    return [...JSON.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding (as a byte string).
   */
  untaggedCbor(): Cbor {
    return cbor(this._data);
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
  static fromCbor(cborValue: Cbor): JSON {
    return JSON.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================
}
