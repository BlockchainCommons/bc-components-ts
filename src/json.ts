/**
 * A CBOR-tagged container for UTF-8 CborJson text.
 *
 * The `CborJson` type wraps UTF-8 CborJson text as a CBOR byte string with tag 262.
 * This allows CborJson data to be embedded within CBOR structures while
 * maintaining type information through the tag.
 *
 * This implementation does not validate that the contained data is well-formed
 * CborJson. It simply provides a type-safe wrapper around byte data that is
 * intended to contain CborJson text.
 *
 * # CBOR Serialization
 *
 * `CborJson` implements the CBOR tagged encoding interfaces, which means it can be
 * serialized to and deserialized from CBOR with tag 262 (`TAG_JSON`).
 *
 * @example
 * ```typescript
 * import { CborJson } from '@blockchaincommons/components';
 *
 * // Create CborJson from a string
 * const json = CborJson.fromString('{"key": "value"}');
 * console.log(json.asStr()); // {"key": "value"}
 *
 * // Create CborJson from bytes
 * const json2 = CborJson.from(new TextEncoder().encode('[1, 2, 3]'));
 * console.log(json2.byteLength); // 9
 * ```
 */

import { type Cbor, type Tag, cbor, expectBytes, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "./codable.js";
import { TAG_JSON } from "@blockchaincommons/tags";
import { bytesToHex } from "./utils.js";
import { bytesFromHex } from "./domain.js";
import { type UR, urFor } from "@blockchaincommons/uniform-resources";
import { ComponentsError } from "./error.js";

// The codec is built on first use so that an unused class tree-shakes away.
let CBOR_JSON_CODEC: ComponentCodec<CborJson> | undefined;

/**
 * A CBOR-tagged container for UTF-8 CborJson text.
 *
 * Wraps UTF-8 CborJson text as a CBOR byte string with tag 262.
 * This allows CborJson data to be embedded within CBOR structures while
 * maintaining type information through the tag.
 */
export class CborJson implements ToCbor {
  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Create a new CborJson instance from byte data.
   */
  static from(data: Uint8Array): CborJson {
    return new CborJson(data);
  }

  /**
   * Create a new CborJson instance from a string.
   */
  static fromString(s: string): CborJson {
    const encoder = new TextEncoder();
    return new CborJson(encoder.encode(s));
  }

  /**
   * Create a new CborJson instance from a hexadecimal string.
   */
  static fromHex(hex: string): CborJson {
    return new CborJson(bytesFromHex(hex, "CborJson"));
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /** Number of bytes. */
  get byteLength(): number {
    return this._data.length;
  }

  /**
   * Return true if the CborJson data is empty.
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
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(this._data);
    } catch (e) {
      throw ComponentsError.utf8("CborJson bytes are not valid UTF-8", e);
    }
  }

  /**
   * Return the data as a hexadecimal string.
   */
  toHex(): string {
    return bytesToHex(this._data);
  }

  /**
   * Compare with another CborJson.
   */
  equals(other: CborJson): boolean {
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
    return `CborJson(${this.asStr()})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<CborJson> {
    return (CBOR_JSON_CODEC ??= defineCodec({
      tags: [TAG_JSON],
      decodeUntagged: (cborValue) => {
        const data = expectBytes(cborValue);
        return CborJson.from(data);
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...CborJson.codec.tags];
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
  static fromCbor(cborValue: Cbor): CborJson {
    return CborJson.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================
}
