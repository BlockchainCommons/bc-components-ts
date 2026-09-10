/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * An "Apparently Random Identifier" (ARID)
 *
 * Ported from bc-components-rust/src/id/arid.rs
 *
 * An ARID is a cryptographically strong, universally unique identifier with
 * the following properties:
 * - Non-correlatability: The sequence of bits cannot be correlated with its
 *   referent or any other ARID
 * - Neutral semantics: Contains no inherent type information
 * - Open generation: Any method of generation is allowed as long as it
 *   produces statistically random bits
 * - Minimum strength: Must be 256 bits (32 bytes) in length
 * - Cryptographic suitability: Can be used as inputs to cryptographic
 *   constructs
 *
 * Unlike digests/hashes which identify a fixed, immutable state of data, ARIDs
 * can serve as stable identifiers for mutable data structures.
 *
 * ARIDs should not be confused with or cast to/from other identifier types
 * (like UUIDs), used as nonces, keys, or cryptographic seeds.
 *
 * As defined in [BCR-2022-002](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2022-002-arid.md).
 *
 * # CBOR Serialization
 *
 * `ARID` implements the CBOR tagged encoding interfaces, which means it can be
 * serialized to and deserialized from CBOR with a specific tag (TAG_ARID = 40012).
 *
 * # UR Serialization
 *
 * When serialized as a Uniform Resource (UR), an `ARID` is represented as a
 * binary blob with the type "arid".
 *
 * @example
 * ```typescript
 * import { ARID } from '@blockchaincommons/components';
 *
 * // Create a new random ARID
 * const arid = ARID.random();
 *
 * // Create an ARID from a hex string
 * const arid2 = ARID.fromHex("...");
 *
 * // Get the ARID as hex
 * console.log(arid.toHex());
 * ```
 */

import { secureRng, randomBytes, type RandomNumberGenerator } from "@blockchaincommons/rand";
import { type Cbor, type Tag, cbor, expectBytes, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "../codable.js";
import { ARID as TAG_ARID } from "@blockchaincommons/tags";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { ComponentsError } from "../error.js";
import { bytesToHex, hexToBytes, toBase64 } from "../utils.js";

export class ARID implements ToCbor, ToUR {
  static readonly ARID_SIZE = 32;

  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    if (data.length !== ARID.ARID_SIZE) {
      throw ComponentsError.invalidSize(ARID.ARID_SIZE, data.length);
    }
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /** A fresh random ARID; pass `rng` to make it deterministic. */
  static random({ rng = secureRng() }: { rng?: RandomNumberGenerator } = {}): ARID {
    return new ARID(randomBytes(ARID.ARID_SIZE, { rng }));
  }

  /**
   * Restore an ARID from a fixed-size array of bytes.
   */
  static from(data: Uint8Array): ARID {
    return new ARID(new Uint8Array(data));
  }

  /**
   * Create a new ARID from the given hexadecimal string.
   *
   * @throws Error if the string is not exactly 64 hexadecimal digits.
   */
  static fromHex(hex: string): ARID {
    return new ARID(hexToBytes(hex));
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /** The bytes (a view; do not mutate). */
  get bytes(): Uint8Array {
    return this._data;
  }

  /**
   * The data as a hexadecimal string.
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
   * The first four bytes of the ARID as a hexadecimal string.
   */
  shortDescription(): string {
    return bytesToHex(this._data.slice(0, 4));
  }

  /**
   * Compare with another ARID.
   */
  equals(other: ARID): boolean {
    if (this._data.length !== other._data.length) return false;
    for (let i = 0; i < this._data.length; i++) {
      if (this._data[i] !== other._data[i]) return false;
    }
    return true;
  }

  /**
   * Compare ARIDs lexicographically.
   */
  compare(other: ARID): number {
    for (let i = 0; i < this._data.length; i++) {
      const a = this._data[i];
      const b = other._data[i];
      if (a < b) return -1;
      if (a > b) return 1;
    }
    return 0;
  }

  /**
   * Get string representation.
   */
  toString(): string {
    return `ARID(${this.toHex()})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static readonly codec: ComponentCodec<ARID> = defineCodec({
    tags: [TAG_ARID],
    decodeUntagged: (cbor) => {
      const data = expectBytes(cbor);
      return ARID.from(data);
    },
    encodeUntagged: (value) => value.untaggedCbor(),
  });

  cborTags(): Tag[] {
    return [...ARID.codec.tags];
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
  static fromCbor(cbor: Cbor): ARID {
    return ARID.codec.decode(cbor);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
