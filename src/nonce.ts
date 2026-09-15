import { secureRng, randomBytes, type RngOptions } from "@blockchaincommons/rand";
import { chacha20Poly1305 } from "@blockchaincommons/crypto";
import { type Cbor, type Tag, cbor, expectBytes, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "./codable.js";
import { TAG_NONCE } from "@blockchaincommons/tags";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { ComponentsError } from "./error.js";
import { bytesToHex, toBase64 } from "./utils.js";
import { bytesFromHex } from "./domain.js";

// The codec is built on first use so that an unused class tree-shakes away.
let NONCE_CODEC: ComponentCodec<Nonce> | undefined;

/**
 * A random nonce ("number used once").
 *
 * A `Nonce` is a cryptographic primitive consisting of a random or
 * pseudo-random number that is used only once in a cryptographic
 * communication. Nonces are often used in authentication protocols, encryption
 * algorithms, and digital signatures to prevent replay attacks and ensure
 * the uniqueness of encrypted messages.
 *
 * In this implementation, a `Nonce` is a 12-byte random value. The size is
 * chosen to be sufficiently large to prevent collisions while remaining
 * efficient for storage and transmission.
 *
 * # CBOR Serialization
 *
 * `Nonce` implements the CBOR tagged encoding interfaces, which means it can be
 * serialized to and deserialized from CBOR with a specific tag (TAG_NONCE = 40014).
 *
 * # UR Serialization
 *
 * When serialized as a Uniform Resource (UR), a `Nonce` is represented as a
 * binary blob with the type "nonce".
 *
 * # Common Uses
 *
 * - In authenticated encryption schemes like AES-GCM or ChaCha20-Poly1305
 * - For initializing counters in counter-mode block ciphers
 * - In challenge-response authentication protocols
 * - To prevent replay attacks in secure communications
 *
 * @example
 * ```typescript
 * import { Nonce } from '@blockchaincommons/components';
 *
 * // Generate a new random nonce
 * const nonce = Nonce.random();
 *
 * // Create a nonce from a byte array
 * const data = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
 * const nonce2 = Nonce.from(data);
 *
 * // Access the nonce data
 * const nonceData = nonce2.bytes;
 * ```
 */
export class Nonce implements ToCbor, ToUR {
  /** The byte length of a `Nonce`. */
  static readonly NONCE_SIZE: number = chacha20Poly1305.NONCE_SIZE;

  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    if (data.length !== Nonce.NONCE_SIZE) {
      throw ComponentsError.invalidSize("nonce", Nonce.NONCE_SIZE, data.length);
    }
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /** A fresh random value; pass `rng` to make it deterministic. */
  static random({ rng = secureRng() }: RngOptions = {}): Nonce {
    return new Nonce(randomBytes(Nonce.NONCE_SIZE, { rng: rng }));
  }

  /**
   * Restores a nonce from data.
   */
  static from(data: Uint8Array): Nonce {
    return new Nonce(new Uint8Array(data));
  }

  /**
   * Create a new nonce from the given hexadecimal string.
   *
   * @throws Error if the string is not exactly 24 hexadecimal digits.
   */
  static fromHex(hex: string): Nonce {
    return new Nonce(bytesFromHex(hex));
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
   * Compare with another Nonce.
   */
  equals(other: Nonce): boolean {
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
    return `Nonce(${this.toHex()})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<Nonce> {
    return (NONCE_CODEC ??= defineCodec({
      tags: [TAG_NONCE],
      decodeUntagged: (cbor) => {
        const data = expectBytes(cbor);
        return Nonce.from(data);
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...Nonce.codec.tags];
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
  static fromCbor(cbor: Cbor): Nonce {
    return Nonce.codec.decode(cbor);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
