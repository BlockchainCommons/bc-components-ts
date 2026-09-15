import { type Cbor, cbor, expectBytes, decodeCbor } from "@blockchaincommons/dcbor";
import { decodeComponent } from "../codable.js";
import { ComponentsError } from "../error.js";
import { bytesToHex, toBase64 } from "../utils.js";
import { bytesFromHex } from "../domain.js";

const AUTHENTICATION_TAG_SIZE = 16;

/**
 * Authentication tag for AEAD encryption (16 bytes)
 *
 * An `AuthenticationTag` is a 16-byte value generated during ChaCha20-Poly1305
 * authenticated encryption. It serves as a message authentication code (MAC)
 * that verifies both the authenticity and integrity of the encrypted message.
 *
 * During decryption, the tag is verified to ensure:
 * - The message has not been tampered with (integrity)
 * - The message was encrypted by someone who possesses the encryption key
 *   (authenticity)
 *
 * This implementation follows the Poly1305 MAC algorithm as specified in
 * [RFC-8439](https://datatracker.ietf.org/doc/html/rfc8439).
 */
export class AuthenticationTag {
  /** The byte length of a `AuthenticationTag`. */
  static readonly AUTHENTICATION_TAG_SIZE: number = AUTHENTICATION_TAG_SIZE;

  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    if (data.length !== AUTHENTICATION_TAG_SIZE) {
      throw ComponentsError.invalidSize("authentication tag", AUTHENTICATION_TAG_SIZE, data.length);
    }
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Restore an AuthenticationTag from a fixed-size array of bytes.
   */
  static from(data: Uint8Array): AuthenticationTag {
    return new AuthenticationTag(new Uint8Array(data));
  }

  /**
   * Create an AuthenticationTag from hex string.
   */
  static fromHex(hex: string): AuthenticationTag {
    return AuthenticationTag.from(bytesFromHex(hex));
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
   * Compare with another AuthenticationTag.
   */
  equals(other: AuthenticationTag): boolean {
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
    return `AuthenticationTag("${this.toHex()}")`;
  }

  // ============================================================================
  // CBOR Serialization (untagged - no CBOR tag for AuthenticationTag)
  // ============================================================================

  /**
   * Returns the untagged CBOR encoding (as a byte string).
   * AuthenticationTag has no CBOR tag - it's serialized as a plain byte string.
   */
  toCbor(): Cbor {
    return cbor(this._data);
  }

  /**
   * Returns the CBOR binary representation.
   */
  toCborData(): Uint8Array {
    return this.toCbor().toData();
  }

  /**
   * Creates an AuthenticationTag from CBOR.
   */
  /**
   * From the untagged byte string, as the reference's `TryFrom<CBOR>`
   * (error type `Error`): a non-byte-string is `Cbor` (`CBOR error: …`), a
   * wrong length `InvalidSize`.
   */
  static fromCbor(cbor: Cbor): AuthenticationTag {
    return decodeComponent(() => AuthenticationTag.from(expectBytes(cbor)));
  }

  /**
   * Creates an AuthenticationTag from CBOR binary data.
   */
  static fromCborData(data: Uint8Array): AuthenticationTag {
    const cbor = decodeCbor(data);
    return AuthenticationTag.fromCbor(cbor);
  }
}
