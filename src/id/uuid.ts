import {
  type Cbor,
  type Tag,
  cbor,
  expectBytes,
  type ToCbor,
  CborError,
} from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "../codable.js";
import { TAG_UUID } from "@blockchaincommons/tags";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { ComponentsError } from "../error.js";
import { bytesFromHex, rustTrim } from "../domain.js";
import { bytesToHex, toBase64 } from "../utils.js";
import { randomBytes, secureRng, type RngOptions } from "@blockchaincommons/rand";

const UUID_SIZE = 16;

// The codec is built on first use so that an unused class tree-shakes away.
let U_U_I_D_CODEC: ComponentCodec<UUID> | undefined;

/**
 * Universally Unique Identifier (UUID) - 16-byte identifier
 *
 * UUIDs are 128-bit (16-byte) identifiers that are designed to be unique
 * across space and time. This implementation creates type 4 (random) UUIDs,
 * following the UUID specification:
 *
 * - Version field (bits 48-51) is set to 4, indicating a random UUID
 * - Variant field (bits 64-65) is set to 2, indicating RFC 4122/DCE 1.1 UUID
 *   variant
 *
 * Unlike ARIDs, UUIDs:
 * - Are shorter (128 bits vs 256 bits)
 * - Contain version and variant metadata within the identifier
 * - Have a canonical string representation with 5 groups separated by hyphens
 *
 * The canonical textual representation of a UUID takes the form:
 * `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` where each `x` is a hexadecimal digit.
 *
 * # CBOR Serialization
 *
 * `UUID` is serialized to CBOR with tag 37 (standard UUID tag).
 *
 * # UR Serialization
 *
 * When serialized as a Uniform Resource (UR), a `UUID` is represented with the
 * type "uuid".
 */
export class UUID implements ToCbor, ToUR {
  /** The byte length of a `UUID`. */
  static readonly UUID_SIZE: number = UUID_SIZE;

  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    if (data.length !== UUID_SIZE) {
      throw ComponentsError.invalidSize("UUID", UUID_SIZE, data.length);
    }
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Create a UUID from raw bytes.
   */
  static from(data: Uint8Array): UUID {
    return new UUID(new Uint8Array(data));
  }

  /**
   * Create a UUID from hex string (32 hex chars)
   */
  static fromHex(hex: string): UUID {
    return new UUID(bytesFromHex(hex));
  }

  /**
   * A UUID from its text, as the reference's `from_str`: Rust `str::trim`,
   * every `-` removed, strict hex (`Hex` on a malformed string), and 16
   * bytes (`InvalidSize` otherwise). Neither the dash positions nor the
   * digit count between them is checked.
   */
  static fromString(uuidString: string): UUID {
    return new UUID(bytesFromHex(rustTrim(uuidString).replaceAll("-", "")));
  }

  /**
   * Generate a random UUID (v4)
   */
  static random({ rng = secureRng() }: RngOptions = {}): UUID {
    const data = randomBytes(UUID_SIZE, { rng });

    // Set version to 4 (random)
    data[6] = (data[6] & 0x0f) | 0x40;
    // Set variant to RFC 4122
    data[8] = (data[8] & 0x3f) | 0x80;

    return new UUID(data);
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
   * Get hex string representation (lowercase, as the reference implementation does implementation).
   */
  toHex(): string {
    return bytesToHex(this._data);
  }

  /**
   * Get standard UUID string representation.
   * Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
   */
  toString(): string {
    const hex = this.toHex();
    return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
  }

  /**
   * Get base64 representation.
   */
  toBase64(): string {
    return toBase64(this._data);
  }

  /**
   * Compare with another UUID.
   */
  equals(other: UUID): boolean {
    if (this._data.length !== other._data.length) return false;
    for (let i = 0; i < this._data.length; i++) {
      if (this._data[i] !== other._data[i]) return false;
    }
    return true;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<UUID> {
    return (U_U_I_D_CODEC ??= defineCodec({
      tags: [TAG_UUID],
      decodeUntagged: (cbor) => {
        const data = expectBytes(cbor);
        if (data.length !== UUID_SIZE) throw CborError.custom("invalid UUID size");
        return UUID.from(data);
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...UUID.codec.tags];
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
  static fromCbor(cbor: Cbor): UUID {
    return UUID.codec.decode(cbor);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
