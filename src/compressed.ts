/**
 * A compressed binary object with integrity verification.
 *
 * `Compressed` provides a way to efficiently store and transmit binary data
 * using the DEFLATE compression algorithm. It includes built-in integrity
 * verification through a CRC32 checksum and optional cryptographic digest.
 *
 * The compression is implemented using the raw DEFLATE format as described in
 * [IETF RFC 1951](https://www.ietf.org/rfc/rfc1951.txt), by an in-package
 * port of `miniz_oxide` 0.8.9 at level 6, the reference's compressor: the
 * same input gives the same bytes on both sides, and the inflater accepts
 * exactly the streams the reference accepts.
 *
 * Features:
 * - Compression at the reference's level (6)
 * - Integrity verification via CRC32 checksum
 * - Optional cryptographic digest for content identification
 * - Smart behavior for small data (stores decompressed if compression would
 *   increase size)
 * - CBOR serialization/deserialization support
 *
 * @example
 * ```typescript
 * import { Compressed } from '@blockchaincommons/components';
 *
 * // Compress a string
 * const data = new TextEncoder().encode(
 *   "This is a longer string that should compress well with repeated patterns."
 * );
 * const compressed = Compressed.fromDecompressedData(data);
 *
 * // The compressed size should be smaller than the original
 * console.log(compressed.compressionRatio); // < 1.0
 *
 * // We can recover the original data
 * const decompressed = compressed.decompress();
 * ```
 */

import { crc32 } from "@blockchaincommons/crypto";
import {
  type Cbor,
  type Tag,
  type CborInput,
  cbor,
  expectArray,
  expectUnsigned,
  expectBytes,
  type ToCbor,
  CborError,
} from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "./codable.js";
import { TAG_COMPRESSED } from "@blockchaincommons/tags";
import { Digest } from "./digest.js";
import type { DigestProvider } from "./digest-provider.js";
import { ComponentsError } from "./error.js";
import { bytesToHex } from "./utils.js";
import { U32_FIELD, USIZE_FIELD, expectU32 } from "./domain.js";
import { compressToVec } from "./internal/miniz-deflate.js";
import { decompressToVec } from "./internal/miniz-inflate.js";
import { type UR, urFor } from "@blockchaincommons/uniform-resources";

// The codec is built on first use so that an unused class tree-shakes away.
let COMPRESSED_CODEC: ComponentCodec<Compressed> | undefined;

/** The reference's compression level (`compress_to_vec(data, 6)`). */
const COMPRESSION_LEVEL = 6;
const USIZE_MAX = (1n << 64n) - 1n;

/** A `usize` field: an integer in `[0, 2^64 - 1]`, a `bigint` above `Number.MAX_SAFE_INTEGER`. */
function expectUsize(value: number | bigint, parameter: string): number | bigint {
  if (typeof value === "bigint") {
    if (value < 0n || value > USIZE_MAX) {
      throw ComponentsError.invalidDataForType(
        parameter,
        `must be an integer in [0, ${USIZE_MAX}], got ${value}`,
      );
    }
    return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value;
  }
  if (!Number.isInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
    throw ComponentsError.invalidDataForType(
      parameter,
      `must be an integer in [0, ${USIZE_MAX}], got ${String(value)}`,
    );
  }
  return value;
}

/**
 * A compressed binary object with integrity verification.
 *
 * Uses DEFLATE compression with CRC32 checksums for integrity verification.
 * Optionally includes a cryptographic digest for content identification.
 */
export class Compressed implements ToCbor, DigestProvider {
  /** CRC32 checksum of the decompressed data for integrity verification */
  private readonly _checksum: number;
  /** Size of the original decompressed data in bytes (a `usize`; a `bigint` above 2^53 − 1) */
  private readonly _decompressedSize: number | bigint;
  /** The compressed data (or original data if compression is ineffective) */
  private readonly _compressedData: Uint8Array;
  /** Optional cryptographic digest of the content */
  private readonly _digest: Digest | undefined;

  private constructor(
    checksum: number,
    decompressedSize: number | bigint,
    compressedData: Uint8Array,
    digest?: Digest,
  ) {
    if (BigInt(compressedData.length) > BigInt(decompressedSize)) {
      throw ComponentsError.compression("compressed data is larger than decompressed size");
    }
    this._checksum = checksum;
    this._decompressedSize = decompressedSize;
    this._compressedData = new Uint8Array(compressedData);
    this._digest = digest;
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Creates a new `Compressed` object with the specified parameters.
   *
   * This is a low-level constructor that allows direct creation of a
   * `Compressed` object without performing compression. It's primarily
   * intended for deserialization or when working with pre-compressed data.
   * `checksum` is a `u32` and `decompressedSize` a `usize` (a `bigint` is
   * accepted above `Number.MAX_SAFE_INTEGER`), as the reference's fields.
   *
   * @returns A new `Compressed` object
   * @throws ComponentsError `Compression` if the compressed data is larger than the decompressed size
   * @param parts - `checksum`, `decompressedSize`, `compressedData` and the optional `digest`
   */
  static fromParts({
    checksum,
    decompressedSize,
    compressedData,
    digest,
  }: {
    checksum: number;
    decompressedSize: number | bigint;
    compressedData: Uint8Array;
    digest?: Digest | undefined;
  }): Compressed {
    return new Compressed(
      expectU32(checksum, "checksum"),
      expectUsize(decompressedSize, "decompressedSize"),
      compressedData,
      digest,
    );
  }

  /**
   * Creates a new `Compressed` object by compressing the provided data.
   *
   * This is the primary method for creating compressed data. It compresses
   * with raw DEFLATE at level 6, the reference's `compress_to_vec(data, 6)`,
   * so the stream is byte-identical to the reference's for the same input.
   *
   * If the compressed data would be larger than the original data (which can
   * happen with small or already compressed inputs), the original data is
   * stored instead.
   *
   * @param decompressedData - The original data to compress
   * @param digest - Optional cryptographic digest of the content
   * @returns A new `Compressed` object containing the compressed (or original) data
   */
  static fromDecompressedData(decompressedData: Uint8Array, digest?: Digest): Compressed {
    const compressedData = compressToVec(decompressedData, COMPRESSION_LEVEL);
    const checksum = crc32(decompressedData);
    const decompressedSize = decompressedData.length;
    const compressedSize = compressedData.length;

    // If compression didn't help, store original data
    if (compressedSize !== 0 && compressedSize < decompressedSize) {
      return new Compressed(checksum, decompressedSize, compressedData, digest);
    } else {
      return new Compressed(checksum, decompressedSize, new Uint8Array(decompressedData), digest);
    }
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /**
   * Decompresses and returns the original decompressed data.
   *
   * This method performs the reverse of the compression process, restoring
   * the original data. It also verifies the integrity of the data using the
   * stored checksum.
   *
   * @returns The decompressed data
   * @throws ComponentsError `Compression` if the stream is corrupt (`corrupt compressed data`)
   *   or the checksum does not match (`compressed data checksum mismatch`)
   */
  decompress(): Uint8Array {
    const compressedSize = this._compressedData.length;

    // If data wasn't actually compressed (sizes equal), return as-is
    if (BigInt(compressedSize) >= BigInt(this._decompressedSize)) {
      return new Uint8Array(this._compressedData);
    }

    let decompressedData: Uint8Array;
    try {
      decompressedData = decompressToVec(this._compressedData);
    } catch (e) {
      throw ComponentsError.compression("corrupt compressed data", e);
    }
    if (crc32(decompressedData) !== this._checksum) {
      throw ComponentsError.compression("compressed data checksum mismatch");
    }
    return decompressedData;
  }

  /**
   * Returns the size of the compressed data in bytes.
   */
  get compressedSize(): number {
    return this._compressedData.length;
  }

  /**
   * Returns the size of the decompressed data in bytes, as decoded: a
   * `bigint` only when it exceeds `Number.MAX_SAFE_INTEGER`.
   */
  get decompressedSize(): number | bigint {
    return this._decompressedSize;
  }

  /**
   * Returns the CRC32 checksum of the decompressed data.
   */
  get checksum(): number {
    return this._checksum;
  }

  /**
   * Returns the compression ratio of the data.
   *
   * The compression ratio is calculated as (compressed size) / (decompressed size),
   * so lower values indicate better compression.
   *
   * @returns A floating-point value representing the compression ratio.
   * - Values less than 1.0 indicate effective compression
   * - Values equal to 1.0 indicate no compression was applied
   * - Values of NaN can occur if the decompressed size is zero
   */
  get compressionRatio(): number {
    return this._compressedData.length / Number(this._decompressedSize);
  }

  /**
   * Returns the digest of the compressed data, if available.
   *
   * @returns The `Digest` associated with this compressed data, or undefined if none.
   */
  digestOpt(): Digest | undefined {
    return this._digest;
  }

  /**
   * Returns whether this compressed data has an associated digest.
   */
  hasDigest(): boolean {
    return this._digest !== undefined;
  }

  // ============================================================================
  // DigestProvider implementation
  // ============================================================================

  /**
   * Returns the cryptographic digest associated with this compressed data.
   *
   * @returns A `Digest`
   * @throws ComponentsError `Compression` if there is no digest (the reference `unwrap`s it)
   */
  digest(): Digest {
    if (this._digest === undefined) {
      throw ComponentsError.compression("No digest associated with this compressed data");
    }
    return this._digest;
  }

  // ============================================================================
  // Comparison and String representation
  // ============================================================================

  /**
   * Compare with another Compressed: checksum, size, compressed bytes and
   * the digest, as the reference's derived `PartialEq`.
   */
  equals(other: Compressed): boolean {
    if (this._checksum !== other._checksum) return false;
    if (BigInt(this._decompressedSize) !== BigInt(other._decompressedSize)) return false;
    if (this._compressedData.length !== other._compressedData.length) return false;
    for (let i = 0; i < this._compressedData.length; i++) {
      if (this._compressedData[i] !== other._compressedData[i]) return false;
    }
    if (this._digest === undefined || other._digest === undefined) {
      return this._digest === other._digest;
    }
    return this._digest.equals(other._digest);
  }

  /**
   * Get string representation (the reference's `Debug`).
   */
  toString(): string {
    const checksumHex = bytesToHex(
      new Uint8Array([
        (this._checksum >>> 24) & 0xff,
        (this._checksum >>> 16) & 0xff,
        (this._checksum >>> 8) & 0xff,
        this._checksum & 0xff,
      ]),
    );
    const digestStr = this._digest?.shortDescription() ?? "None";
    return `Compressed(checksum: ${checksumHex}, size: ${this.compressedSize}/${this._decompressedSize}, ratio: ${this.compressionRatio.toFixed(2)}, digest: ${digestStr})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /**
   * Tagged-CBOR codec. The checksum decodes as a `u32` and the size as a
   * `usize`, each with dcbor's negative wrap (the reference's
   * `TryFrom<CBOR>` for those widths).
   */
  static get codec(): ComponentCodec<Compressed> {
    return (COMPRESSED_CODEC ??= defineCodec({
      tags: [TAG_COMPRESSED],
      decodeUntagged: (cborValue) => {
        const elements = expectArray(cborValue);
        if (elements.length < 3 || elements.length > 4) {
          throw CborError.custom("invalid number of elements in compressed");
        }

        const checksum = Number(expectUnsigned(elements[0], U32_FIELD));
        const decompressedSize = expectUnsigned(elements[1], USIZE_FIELD);
        const compressedData = expectBytes(elements[2]);

        let digest: Digest | undefined;
        if (elements.length === 4) {
          digest = Digest.fromCbor(elements[3]);
        }

        return new Compressed(checksum, decompressedSize, compressedData, digest);
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...Compressed.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding (as an array).
   *
   * Format:
   * ```
   * [
   *   checksum: uint,
   *   decompressed_size: uint,
   *   compressed_data: bytes,
   *   digest?: Digest  // Optional
   * ]
   * ```
   */
  untaggedCbor(): Cbor {
    const elements: CborInput[] = [
      this._checksum,
      this._decompressedSize,
      cbor(this._compressedData),
    ];
    if (this._digest !== undefined) {
      elements.push(this._digest.toCbor());
    }
    return cbor(elements);
  }

  /** The tagged CBOR form. */
  toCbor(): Cbor {
    return taggedCborOf(this);
  }

  /** As a UR, typed by the first tag's name. */
  toUR(): UR {
    return urFor(this);
  }

  /** Decode the tagged CBOR form. */
  static fromCbor(cborValue: Cbor): Compressed {
    return Compressed.codec.decode(cborValue);
  }
}
