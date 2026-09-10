/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * Random salt used to decorrelate other information.
 *
 * Ported from bc-components-rust/src/salt.rs
 *
 * A `Salt` is a cryptographic primitive consisting of random data that is used
 * to modify the output of a cryptographic function. Salts are primarily used
 * in password hashing to defend against dictionary attacks, rainbow table
 * attacks, and pre-computation attacks. They are also used in other
 * cryptographic contexts to ensure uniqueness and prevent correlation between
 * different parts of a cryptosystem.
 *
 * Unlike a `Nonce` which has a fixed size, a `Salt` in this implementation can
 * have a variable length (minimum 8 bytes). Different salt creation methods
 * are provided to generate salts of appropriate sizes for different use cases.
 *
 * # Minimum Size Requirement
 *
 * For security reasons, salts must be at least 8 bytes long. Attempting to
 * create a salt with fewer than 8 bytes will result in an error.
 *
 * # CBOR Serialization
 *
 * `Salt` implements the CBOR tagged encoding interfaces, which means it can be
 * serialized to and deserialized from CBOR with a specific tag (TAG_SALT = 40018).
 *
 * # UR Serialization
 *
 * When serialized as a Uniform Resource (UR), a `Salt` is represented as a
 * binary blob with the type "salt".
 *
 * # Common Uses
 *
 * - Password hashing and key derivation functions
 * - Preventing correlation in cryptographic protocols
 * - Randomizing data before encryption to prevent pattern recognition
 * - Adding entropy to improve security in various cryptographic functions
 *
 * @example
 * ```typescript
 * import { Salt } from '@blockchaincommons/components';
 *
 * // Generate a salt with 16 bytes
 * const salt = Salt.random({ length: 16 });
 * console.log(salt.byteLength); // 16
 *
 * // Generate a salt proportional to 100 bytes of data
 * const salt2 = Salt.forSize(100);
 *
 * // Generate a salt with length between 16 and 32 bytes
 * const salt3 = Salt.randomInRange(16, 32);
 * ```
 */

import { type RandomNumberGenerator, secureRng, randomBytes } from "@blockchaincommons/rand";
import { nextInClosedRangeI32 } from "@blockchaincommons/rand/samplers";
import { type Cbor, type Tag, cbor, expectBytes, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "./codable.js";
import { SALT as TAG_SALT } from "@blockchaincommons/tags";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { ComponentsError } from "./error.js";
import { bytesToHex, hexToBytes, toBase64 } from "./utils.js";

const MIN_SALT_SIZE = 8;

export class Salt implements ToCbor, ToUR {
  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Create a new salt from data.
   * Note: Does not validate minimum size to allow for CBOR deserialization.
   */
  static from(data: Uint8Array): Salt {
    return new Salt(new Uint8Array(data));
  }

  /**
   * Create a new salt from the given hexadecimal string.
   */
  static fromHex(hex: string): Salt {
    return Salt.from(hexToBytes(hex));
  }

  /** A random salt of `length` bytes (16 by default); pass `rng` to make it deterministic. */
  static random({
    length = 16,
    rng = secureRng(),
  }: { length?: number; rng?: RandomNumberGenerator } = {}): Salt {
    if (length < MIN_SALT_SIZE) {
      throw ComponentsError.dataTooShort("salt", MIN_SALT_SIZE, length);
    }
    return new Salt(randomBytes(length, { rng }));
  }

  /** A random salt of a random length in `[minSize, maxSize]`. */
  static randomInRange(
    minSize: number,
    maxSize: number,
    { rng = secureRng() }: { rng?: RandomNumberGenerator } = {},
  ): Salt {
    if (minSize < MIN_SALT_SIZE) {
      throw ComponentsError.dataTooShort("salt", MIN_SALT_SIZE, minSize);
    }
    const count = nextInClosedRangeI32(rng, minSize, maxSize);
    return new Salt(randomBytes(count, { rng }));
  }

  /** A random salt sized for a payload of `size` bytes (5–25% of it, at least the minimum). */
  static forSize(size: number, { rng = secureRng() }: { rng?: RandomNumberGenerator } = {}): Salt {
    const minSize = Math.max(MIN_SALT_SIZE, Math.ceil(size * 0.05));
    const maxSize = Math.max(minSize + 8, Math.ceil(size * 0.25));
    return Salt.randomInRange(minSize, maxSize, { rng });
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /** Number of bytes. */
  get byteLength(): number {
    return this._data.length;
  }

  /**
   * Return true if the salt is empty (this is not recommended).
   */
  isEmpty(): boolean {
    return this._data.length === 0;
  }

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
   * Compare with another Salt.
   */
  equals(other: Salt): boolean {
    if (this._data.length !== other._data.length) return false;
    for (let i = 0; i < this._data.length; i++) {
      if (this._data[i] !== other._data[i]) return false;
    }
    return true;
  }

  /**
   * Get string representation showing the salt's length.
   */
  toString(): string {
    return `Salt(${this.byteLength})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static readonly codec: ComponentCodec<Salt> = defineCodec({
    tags: [TAG_SALT],
    decodeUntagged: (cbor) => {
      const data = expectBytes(cbor);
      return Salt.from(data);
    },
    encodeUntagged: (value) => value.untaggedCbor(),
  });

  cborTags(): Tag[] {
    return [...Salt.codec.tags];
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
  static fromCbor(cbor: Cbor): Salt {
    return Salt.codec.decode(cbor);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
