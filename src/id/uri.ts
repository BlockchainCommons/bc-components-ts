/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * Uniform Resource Identifier (URI) - String-based identifier
 *
 * A URI is a string of characters that unambiguously identifies a particular
 * resource. This implementation validates URIs using the URL API to ensure
 * conformance to RFC 3986.
 *
 * URIs are commonly used for:
 * - Web addresses (URLs like "https://example.com")
 * - Resource identifiers in various protocols
 * - Namespace identifiers
 * - References to resources in distributed systems
 *
 * # CBOR Serialization
 *
 * `URI` is serialized to CBOR with tag 32 (standard URI tag).
 *
 * # UR Serialization
 *
 * When serialized as a Uniform Resource (UR), a `URI` is represented with the
 * type "url".
 */

import { type Cbor, type Tag, cbor, expectText, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "../codable.js";
import { URI as TAG_URI } from "@blockchaincommons/tags";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { ComponentsError } from "../error.js";
import { toBase64 } from "../utils.js";

export class URI implements ToCbor, ToUR {
  private readonly _uri: string;

  private constructor(uri: string) {
    this._uri = uri;
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Creates a new `URI` from a string with validation.
   */
  static new(uri: string): URI {
    // Validate using URL API
    try {
      new URL(uri);
      return new URI(uri);
    } catch {
      throw ComponentsError.invalidData("URI: invalid URI format");
    }
  }

  /**
   * Create a URI from string (legacy alias).
   */
  static from(uri: string): URI {
    return URI.new(uri);
  }

  /**
   * Parse a URI string (alias for new()).
   */
  static parse(uriString: string): URI {
    return URI.new(uriString);
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /**
   * Get the URI as a string reference.
   */
  asRef(): string {
    return this._uri;
  }

  /**
   * Get the URI string.
   */
  toString(): string {
    return this._uri;
  }

  /**
   * Get the URI string (alias).
   */
  toURI(): string {
    return this._uri;
  }

  /**
   * Get the raw URI string.
   */
  getRaw(): string {
    return this._uri;
  }

  /**
   * Get scheme (e.g., "http", "https", "urn").
   */
  scheme(): string | null {
    const match = /^([a-z][a-z0-9+.-]*):\/?\/?/i.exec(this._uri);
    return match !== null ? match[1] : null;
  }

  /**
   * Get path component.
   */
  path(): string {
    try {
      const url = new URL(this._uri);
      return url.pathname;
    } catch {
      // For non-URL URIs, try to extract path after scheme
      const withoutScheme = this._uri.replace(/^[a-z][a-z0-9+.-]*:\/?\/?/i, "");
      return withoutScheme;
    }
  }

  /**
   * Check if URI is absolute (has a scheme).
   */
  isAbsolute(): boolean {
    return /^[a-z][a-z0-9+.-]*:/i.test(this._uri);
  }

  /**
   * Check if URI is relative.
   */
  isRelative(): boolean {
    return !this.isAbsolute();
  }

  /**
   * Compare with another URI.
   */
  equals(other: URI): boolean {
    return this._uri === other._uri;
  }

  /**
   * Check if URI starts with given prefix.
   */
  startsWith(prefix: string): boolean {
    return this._uri.startsWith(prefix);
  }

  /**
   * Get base64 representation of the URI string.
   */
  toBase64(): string {
    return toBase64(new TextEncoder().encode(this._uri));
  }

  /**
   * Get the length of the URI string.
   */
  length(): number {
    return this._uri.length;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static readonly codec: ComponentCodec<URI> = defineCodec({
    tags: [TAG_URI],
    decodeUntagged: (cborValue) => {
      const text = expectText(cborValue);
      return URI.new(text);
    },
    encodeUntagged: (value) => value.untaggedCbor(),
  });

  cborTags(): Tag[] {
    return [...URI.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding (as a text string).
   */
  untaggedCbor(): Cbor {
    return cbor(this._uri);
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
  static fromCbor(cborValue: Cbor): URI {
    return URI.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
