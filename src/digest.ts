import { sha256, SHA256_SIZE } from "@blockchaincommons/crypto";
import { type Cbor, type Tag, cbor, expectBytes, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "./codable.js";
import { TAG_DIGEST } from "@blockchaincommons/tags";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { ComponentsError } from "./error.js";
import { bytesToHex, toBase64 } from "./utils.js";
import { bytesFromHex } from "./domain.js";
import type { DigestProvider } from "./digest-provider.js";

// The codec is built on first use so that an unused class tree-shakes away.
let DIGEST_CODEC: ComponentCodec<Digest> | undefined;

/**
 * SHA-256 cryptographic digest (32 bytes)
 *
 * A `Digest` represents the cryptographic hash of some data. In this
 * implementation, SHA-256 is used, which produces a 32-byte hash value.
 * Digests are used throughout the crate for data verification and as unique
 * identifiers derived from data.
 *
 * # CBOR Serialization
 *
 * `Digest` implements the CBOR tagged encoding interfaces, which means it can be
 * serialized to and deserialized from CBOR with a specific tag (TAG_DIGEST = 40001).
 *
 * # UR Serialization
 *
 * When serialized as a Uniform Resource (UR), a `Digest` is represented as a
 * binary blob with the type "digest".
 *
 * @example
 * ```typescript
 * import { Digest } from '@blockchaincommons/components';
 *
 * // Create a digest from a string
 * const data = new TextEncoder().encode("hello world");
 * const digest = Digest.fromImage(data);
 *
 * // Validate that the digest matches the original data
 * console.log(digest.validate(data)); // true
 *
 * // Create a digest from a hex string
 * const hexString = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
 * const digest2 = Digest.fromHex(hexString);
 *
 * // Retrieve the digest as hex
 * console.log(digest2.toHex()); // b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
 * ```
 */
export class Digest implements DigestProvider, ToCbor, ToUR {
  /** The byte length of a `Digest`. */
  static readonly DIGEST_SIZE: number = SHA256_SIZE;

  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    if (data.length !== Digest.DIGEST_SIZE) {
      throw ComponentsError.invalidSize(Digest.DIGEST_SIZE, data.length);
    }
    this._data = new Uint8Array(data);
  }

  /** The bytes (a view; do not mutate). */
  /** A copy of the bytes; mutating it does not touch this value. */
  get bytes(): Uint8Array {
    return new Uint8Array(this._data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Create a Digest from a 32-byte array.
   */
  static from(data: Uint8Array): Digest {
    return new Digest(new Uint8Array(data));
  }

  /**
   * Create a Digest from hex string.
   *
   * @throws Error if the hex string is not exactly 64 characters.
   */
  static fromHex(hex: string): Digest {
    return new Digest(bytesFromHex(hex, "Digest"));
  }

  /**
   * Compute SHA-256 digest of data (called "image" in the reference implementation).
   *
   * @param image - The data to hash
   */
  static fromImage(image: Uint8Array): Digest {
    const hashData = sha256(image);
    return new Digest(new Uint8Array(hashData));
  }

  /**
   * Compute SHA-256 digest from multiple data parts.
   *
   * The parts are concatenated and then hashed.
   *
   * @param imageParts - Array of byte arrays to concatenate and hash
   */
  static fromImageParts(imageParts: Uint8Array[]): Digest {
    const totalLength = imageParts.reduce((sum, part) => sum + part.length, 0);
    const buf = new Uint8Array(totalLength);
    let offset = 0;
    for (const part of imageParts) {
      buf.set(part, offset);
      offset += part.length;
    }
    return Digest.fromImage(buf);
  }

  /**
   * Compute SHA-256 digest from an array of Digests.
   *
   * The digest bytes are concatenated and then hashed.
   *
   * @param digests - Array of Digests to combine
   */
  static fromDigests(digests: Digest[]): Digest {
    const buf = new Uint8Array(digests.length * Digest.DIGEST_SIZE);
    let offset = 0;
    for (const digest of digests) {
      buf.set(digest._data, offset);
      offset += Digest.DIGEST_SIZE;
    }
    return Digest.fromImage(buf);
  }

  /**
   * Compute SHA-256 digest of data (legacy alias for fromImage).
   * @deprecated Use fromImage instead
   */
  static hash(data: Uint8Array): Digest {
    return Digest.fromImage(data);
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

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
   * Get the first four bytes of the digest as a hexadecimal string.
   * Useful for short descriptions.
   */
  shortDescription(): string {
    return bytesToHex(this._data.slice(0, 4));
  }

  /**
   * Validate the digest against the given image.
   *
   * The image is hashed with SHA-256 and compared to this digest.
   * @returns `true` if the digest matches the image.
   */
  validate(image: Uint8Array): boolean {
    return this.equals(Digest.fromImage(image));
  }

  /**
   * Compare with another Digest.
   */
  equals(other: Digest): boolean {
    if (this._data.length !== other._data.length) return false;
    for (let i = 0; i < this._data.length; i++) {
      if (this._data[i] !== other._data[i]) return false;
    }
    return true;
  }

  /**
   * Compare digests lexicographically.
   */
  compare(other: Digest): number {
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
    return `Digest(${this.toHex()})`;
  }

  // ============================================================================
  // DigestProvider Implementation
  // ============================================================================

  /**
   * A Digest is its own digest provider - returns itself.
   */
  digest(): Digest {
    return this;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<Digest> {
    return (DIGEST_CODEC ??= defineCodec({
      tags: [TAG_DIGEST],
      decodeUntagged: (cbor) => {
        const data = expectBytes(cbor);
        return Digest.from(data);
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...Digest.codec.tags];
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
  static fromCbor(cbor: Cbor): Digest {
    return Digest.codec.decode(cbor);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================

  // ============================================================================
  // Static Utility Methods
  // ============================================================================

  /**
   * Validate the given data against the digest, if any.
   *
   * Returns `true` if the digest is `undefined` or if the digest matches the
   * image's digest. Returns `false` if the digest does not match.
   */
  static validateOpt(image: Uint8Array, digest: Digest | undefined): boolean {
    if (digest === undefined) {
      return true;
    }
    return digest.validate(image);
  }
}
