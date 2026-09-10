/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * A globally unique reference to a globally unique object.
 *
 * Ported from bc-components-rust/src/reference.rs
 *
 * `Reference` is a 32-byte fixed-size identifier — typically derived from a
 * SHA-256 digest of an object's serialized form, but Rust also exposes
 * `Reference::from_data` for cases (like `XID`) where the underlying bytes
 * are themselves directly the reference identity.
 *
 * CDDL:
 * ```cddl
 * Reference = #6.40025(bytes .size 32)
 * ```
 */

import { type Cbor, type Tag, cbor, expectBytes, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "./codable.js";
import { REFERENCE as TAG_REFERENCE } from "@blockchaincommons/tags";
import { type UR, urFor } from "@blockchaincommons/uniform-resources";
import { shortIdentifier } from "@blockchaincommons/uniform-resources/bytewords";

import { Digest } from "./digest.js";
import type { DigestProvider } from "./digest-provider.js";
import { ComponentsError } from "./error.js";
import { bytesToHex, hexToBytes, toBase64 } from "./utils.js";

/** Encoding format for short Reference identifiers. */
export type ReferenceEncodingFormat = "hex" | "bytewords" | "bytemojis";

/**
 * Implementers of this interface provide a globally unique reference to themselves.
 *
 * Mirrors Rust's `ReferenceProvider` trait. The reference is derived from a
 * cryptographic digest of the object's serialized form, ensuring that it
 * uniquely identifies the object's contents.
 */
export interface ReferenceProvider {
  /** Returns a cryptographic reference that uniquely identifies this object. */
  reference(): Reference;
}

/**
 * Type guard to check if an object implements the ReferenceProvider interface.
 */
export function isReferenceProvider(obj: unknown): obj is ReferenceProvider {
  return (
    typeof obj === "object" &&
    obj !== null &&
    "reference" in obj &&
    typeof (obj as ReferenceProvider).reference === "function"
  );
}

/**
 * A globally unique reference to a globally unique object.
 *
 * Internally stores 32 raw bytes (matches Rust's `Reference([u8; 32])`).
 * Most callers obtain a `Reference` via `fromDigest`, but `XID` (and similar
 * content-addressable types whose bytes _are_ the reference) construct
 * via `fromData` directly.
 */
export class Reference implements ToCbor, DigestProvider, ReferenceProvider {
  /** Reference data size in bytes — matches Rust `Reference::REFERENCE_SIZE`. */
  static readonly REFERENCE_SIZE = 32;

  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    this._data = data;
  }

  // ============================================================================
  // Factories
  // ============================================================================

  /** Create a Reference from exactly 32 bytes. Mirrors Rust `Reference::from_data`. */
  static from(data: Uint8Array): Reference {
    if (data.length !== Reference.REFERENCE_SIZE) {
      throw ComponentsError.invalidSize(Reference.REFERENCE_SIZE, data.length);
    }
    return new Reference(new Uint8Array(data));
  }

  /** Alias of `fromData` for parity with Rust `from_data_ref`. */
  /** Create a Reference from a Digest's underlying bytes. */
  static fromDigest(digest: Digest): Reference {
    return new Reference(new Uint8Array(digest.bytes));
  }

  /** Backwards-compatible alias of `fromDigest`. */
  /** Create a Reference from a 64-character hex string. */
  static fromHex(hex: string): Reference {
    return Reference.from(hexToBytes(hex));
  }

  /**
   * Create a Reference whose bytes are the SHA-256 digest of the input.
   *
   * @deprecated Prefer `Reference.fromDigest(Digest.fromImage(data))` for
   *   clarity, or `Reference.from(data)` if `data` is already 32 bytes
   *   that should be wrapped without hashing (matches Rust `from_data`).
   */
  static hash(data: Uint8Array): Reference {
    return Reference.fromDigest(Digest.fromImage(data));
  }

  // ============================================================================
  // Accessors
  // ============================================================================

  /** Returns the 32 reference bytes (copy). */
  /** The bytes (a view; do not mutate). */
  get bytes(): Uint8Array {
    return new Uint8Array(this._data);
  }

  /** Alias of `data()`. */
  /** Returns a `Digest` constructed from these 32 bytes (no hashing). */
  /** The full 64-character lowercase hex of the reference. */
  refHex(): string {
    return bytesToHex(this._data);
  }

  /** The first 4 bytes of the reference. */
  refDataShort(): Uint8Array {
    return this._data.slice(0, 4);
  }

  /** The first 4 bytes of the reference, as 8 lowercase hex characters. */
  refHexShort(): string {
    return bytesToHex(this._data.slice(0, 4));
  }

  /**
   * The first 4 bytes as upper-case bytewords identifier.
   *
   * @param prefix - Optional prefix prepended with a single space.
   */
  bytewordsIdentifier(prefix?: string): string {
    const s = shortIdentifier(this.refDataShort()).toUpperCase();
    return prefix !== undefined ? `${prefix} ${s}` : s;
  }

  /**
   * The first 4 bytes as upper-case bytemojis identifier.
   *
   * @param prefix - Optional prefix prepended with a single space.
   */
  bytemojiIdentifier(prefix?: string): string {
    const s = shortIdentifier(this.refDataShort(), { style: "bytemoji" }).toUpperCase();
    return prefix !== undefined ? `${prefix} ${s}` : s;
  }

  // ============================================================================
  // Backwards-compatible accessors
  // ============================================================================

  /** Backwards-compatible alias of `refHex()`. */
  toHex(): string {
    return this.refHex();
  }

  /** Backwards-compatible alias of `refHex()`. */
  fullReference(): string {
    return this.refHex();
  }

  /** Returns the 32 raw bytes encoded as base64. */
  toBase64(): string {
    return toBase64(this._data);
  }

  /**
   * Returns a short representation of this reference in the requested format.
   *
   * Mirrors the legacy TS API; new code should prefer `refHexShort`,
   * `bytewordsIdentifier`, or `bytemojiIdentifier` directly.
   */
  shortReference(format: ReferenceEncodingFormat = "hex"): string {
    switch (format) {
      case "hex":
        return this.refHexShort();
      case "bytewords":
        return shortIdentifier(this.refDataShort());
      case "bytemojis":
        return shortIdentifier(this.refDataShort(), { style: "bytemoji" });
      default: {
        const _exhaustive: never = format;
        throw ComponentsError.invalidFormat(`Unknown reference format: ${String(_exhaustive)}`);
      }
    }
  }

  // ============================================================================
  // ReferenceProvider / DigestProvider
  // ============================================================================

  /** A Reference to this Reference (matches Rust's blanket `ReferenceProvider` impl). */
  reference(): Reference {
    return Reference.fromDigest(this.digest());
  }

  /**
   * SHA-256 of `taggedCbor().toCborData()`.
   *
   * Matches Rust's `DigestProvider for Reference` —
   * `Digest::from_image(self.tagged_cbor().to_cbor_data())`.
   */
  digest(): Digest {
    return Digest.fromImage(this.toCbor().toData());
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static readonly codec: ComponentCodec<Reference> = defineCodec({
    tags: [TAG_REFERENCE],
    decodeUntagged: (cbor) => {
      return Reference.from(expectBytes(cbor));
    },
    encodeUntagged: (value) => value.untaggedCbor(),
  });

  cborTags(): Tag[] {
    return [...Reference.codec.tags];
  }

  /** Untagged CBOR — a single byte string of the 32 raw bytes. */
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
  static fromCbor(cbor: Cbor): Reference {
    return Reference.codec.decode(cbor);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR
  // ============================================================================

  /** UR representation — `ur:reference/...`, untagged CBOR payload. */
  // ============================================================================
  // Equality / display
  // ============================================================================

  equals(other: Reference): boolean {
    if (this._data.length !== other._data.length) return false;
    for (let i = 0; i < this._data.length; i++) {
      if (this._data[i] !== other._data[i]) return false;
    }
    return true;
  }

  /** Debug-style representation: `Reference(<8-hex-prefix>)`. */
  toString(): string {
    return `Reference(${this.refHexShort()})`;
  }
}
