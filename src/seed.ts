import { secureRng, randomBytes, type RngOptions } from "@blockchaincommons/rand";
import {
  type Cbor,
  type Tag,
  cbor,
  CborMap,
  CborDate,
  expectMap,
  type ToCbor,
  expectBytes,
  CborError,
} from "@blockchaincommons/dcbor";
import {
  taggedCborOf,
  forgetTaggedCbor,
  mapGetText,
  mapGetDate,
  type ComponentCodec,
  defineCodec,
} from "./codable.js";
import { TAG_SEED, LEGACY_TAGS } from "@blockchaincommons/tags";
const TAG_SEED_V1 = LEGACY_TAGS.SEED_V1;
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { ComponentsError } from "./error.js";
import { bytesToHex, toBase64 } from "./utils.js";
import { bytesFromHex, expectLength, expectString, expectDate } from "./domain.js";
import type { PrivateKeyDataProvider } from "./private-key-data-provider.js";

/** The optional metadata a `Seed` carries (CBOR map keys 3, 4 and 2). */
export interface SeedMetadata {
  /** A short label (map key 3). */
  name?: string | undefined;
  /** Free text (map key 4). */
  note?: string | undefined;
  /** When the seed was created (map key 2). */
  creationDate?: Date | undefined;
}

// The codec is built on first use so that an unused class tree-shakes away.
let SEED_CODEC: ComponentCodec<Seed> | undefined;

/**
 * Cryptographic seed with optional metadata (minimum 16 bytes)
 *
 * A `Seed` is a source of entropy used to generate cryptographic keys in a
 * deterministic manner. Unlike randomly generated keys, seed-derived keys can
 * be recreated if you have the original seed, making them useful for backup
 * and recovery scenarios.
 *
 * This implementation of `Seed` includes the random seed data as well as
 * optional metadata:
 * - A name (for identifying the seed)
 * - A note (for storing additional information)
 * - A creation date
 *
 * The minimum seed length is 16 bytes to ensure sufficient security and
 * entropy.
 *
 * # CBOR Serialization
 *
 * `Seed` implements the CBOR tagged encoding interfaces, which means it can be
 * serialized to and deserialized from CBOR with specific tags. The tags used
 * are `TAG_SEED` (40300) and the older `TAG_SEED_V1` (300) for backward compatibility.
 *
 * When serialized to CBOR, a `Seed` is represented as a map with the following
 * keys:
 * - 1: The seed data (required)
 * - 2: The creation date (optional)
 * - 3: The name (optional, omitted if empty)
 * - 4: The note (optional, omitted if empty)
 *
 * # UR Serialization
 *
 * When serialized as a Uniform Resource (UR), a `Seed` is represented with the
 * type "seed".
 */
export class Seed implements ToCbor, ToUR, PrivateKeyDataProvider {
  /**
   * Minimum seed length in bytes.
   */
  static readonly MIN_SEED_LENGTH = 16;

  // Defensive copy: internal data is never exposed directly to prevent external mutation
  private readonly _data: Uint8Array;
  private _name: string;
  private _note: string;
  /** The creation date as decoded or set (a `CborDate` keeps sub-millisecond precision on the wire). */
  private _creationDate: CborDate | undefined;

  private constructor(
    data: Uint8Array,
    name?: string,
    note?: string,
    creationDate?: Date | CborDate,
  ) {
    if (data.length < Seed.MIN_SEED_LENGTH) {
      throw ComponentsError.dataTooShort("seed", Seed.MIN_SEED_LENGTH, data.length);
    }
    // Defensive copy on construction to ensure immutability of internal state
    this._data = new Uint8Array(data);
    this._name = name === undefined ? "" : expectString(name, "name");
    this._note = note === undefined ? "" : expectString(note, "note");
    this._creationDate = Seed.cborDateOf(creationDate);
  }

  private static cborDateOf(creationDate: Date | CborDate | undefined): CborDate | undefined {
    if (creationDate === undefined) return undefined;
    if (creationDate instanceof CborDate) return creationDate;
    return CborDate.fromDate(expectDate(creationDate, "creationDate"));
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * A random seed of `length` bytes (16 by default), with optional metadata;
   * pass `rng` to make it deterministic.
   */
  static random({
    length = Seed.MIN_SEED_LENGTH,
    rng = secureRng(),
    ...metadata
  }: { length?: number } & RngOptions & SeedMetadata = {}): Seed {
    expectLength(length, Seed.MIN_SEED_LENGTH, "seed");
    return Seed.from(randomBytes(length, { rng }), metadata);
  }

  // ============================================================================
  // Static Factory Methods (TypeScript Convenience)
  // ============================================================================

  /**
   * Create a Seed from raw bytes with optional metadata.
   *
   * Note: The input data is copied to prevent external mutation of the seed's internal state.
   *
   * @param data - Seed bytes (must be >= 16 bytes)
   * @param metadata - Optional metadata object
   */
  static from(data: Uint8Array, metadata?: SeedMetadata): Seed {
    return new Seed(new Uint8Array(data), metadata?.name, metadata?.note, metadata?.creationDate);
  }

  /**
   * Create a Seed from hex string with optional metadata.
   *
   * @param hex - Hex string representing seed bytes
   * @param metadata - Optional metadata object
   */
  static fromHex(hex: string, metadata?: SeedMetadata): Seed {
    return Seed.from(bytesFromHex(hex), metadata);
  }

  // ============================================================================
  // Instance Methods - Data Access
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

  /** Number of bytes. */
  get byteLength(): number {
    return this._data.length;
  }

  // ============================================================================
  // Instance Methods - Metadata Access
  // ============================================================================

  /**
   * Return the name of the seed.
   *
   * returns empty string if not set.
   */
  /** The optional metadata as one object. */
  get metadata(): SeedMetadata {
    return { name: this._name, note: this._note, creationDate: this.creationDate };
  }

  /** The label, empty when none was given; set it to a string (`InvalidData` otherwise). */
  get name(): string {
    return this._name;
  }

  set name(name: string) {
    this._name = expectString(name, "name");
    forgetTaggedCbor(this);
  }

  /**
   * Return the note of the seed.
   *
   * returns empty string if not set.
   * Setting it requires a string (`InvalidData` otherwise).
   */
  get note(): string {
    return this._note;
  }

  set note(note: string) {
    this._note = expectString(note, "note");
    forgetTaggedCbor(this);
  }

  /**
   * Return the creation date of the seed.
   *
   * Setting it requires a valid `Date` or `undefined` (`InvalidData` otherwise).
   */
  get creationDate(): Date | undefined {
    return this._creationDate?.toDate();
  }

  set creationDate(creationDate: Date | undefined) {
    this._creationDate = Seed.cborDateOf(creationDate);
    forgetTaggedCbor(this);
  }

  /** The creation date as decoded, with the precision the wire carried. */
  get creationCborDate(): CborDate | undefined {
    return this._creationDate;
  }

  // ============================================================================
  // Instance Methods - Comparison and Display
  // ============================================================================

  /**
   * Compare with another Seed.
   */
  equals(other: Seed): boolean {
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
    return `Seed(${this.toHex().substring(0, 16)}..., ${this.byteLength} bytes)`;
  }

  // ============================================================================
  // PrivateKeyDataProvider Implementation
  // ============================================================================

  /**
   * Returns unique data from which cryptographic keys can be derived.
   *
   * This implementation returns a copy of the seed data, which can be used
   * as entropy for deriving private keys in various cryptographic schemes.
   *
   * @returns A Uint8Array containing the seed data
   */
  privateKeyData(): Uint8Array {
    return this.bytes;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<Seed> {
    return (SEED_CODEC ??= defineCodec({
      tags: [TAG_SEED, TAG_SEED_V1],
      decodeUntagged: (cborValue) => {
        const map = expectMap(cborValue);

        // Key 1: seed data (required)
        // CborMap.extract() returns native types (Uint8Array for byte strings)
        // `map.extract::<i32, CBOR>(1)?.try_into_byte_string()?`
        const dataValue = map.get(1);
        if (dataValue === undefined) throw CborError.missingMapKey();
        const data = expectBytes(dataValue);
        if (data.length === 0) throw CborError.custom("Seed data is empty");

        // Keys 2, 3 and 4, as the reference's `map.get::<i32, Date | String>`:
        // a value that does not convert is absent, not an error.
        const creationDate = mapGetDate(map, 2);
        const name = mapGetText(map, 3);
        const note = mapGetText(map, 4);

        return new Seed(new Uint8Array(data), name, note, creationDate);
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...Seed.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding (as a map).
   * Map keys:
   * - 1: seed data (required)
   * - 2: creation date (optional)
   * - 3: name (optional, omitted if empty)
   * - 4: note (optional, omitted if empty)
   */
  untaggedCbor(): Cbor {
    const map = new CborMap();
    map.set(1, cbor(this._data));
    if (this._creationDate !== undefined) {
      map.set(2, this._creationDate.toCbor());
    }
    if (this._name.length > 0) {
      map.set(3, this._name);
    }
    if (this._note.length > 0) {
      map.set(4, this._note);
    }
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
  static fromCbor(cborValue: Cbor): Seed {
    return Seed.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
