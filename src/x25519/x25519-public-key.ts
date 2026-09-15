import { x25519 } from "@blockchaincommons/crypto";
import { type Cbor, type Tag, cbor, expectBytes, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "../codable.js";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { TAG_X25519_PUBLIC_KEY } from "@blockchaincommons/tags";
import { Digest } from "../digest.js";
import { ComponentsError } from "../error.js";
import { bytesToHex, toBase64 } from "../utils.js";
import { bytesFromHex } from "../domain.js";
import { Reference } from "../reference.js";

// The codec is built on first use so that an unused class tree-shakes away.
let X25519_PUBLIC_KEY_CODEC: ComponentCodec<X25519PublicKey> | undefined;

/**
 * X25519 public key for ECDH key exchange (32 bytes)
 *
 * X25519 is an elliptic-curve Diffie-Hellman key exchange protocol based on
 * Curve25519 as defined in RFC 7748. It allows two parties to establish a
 * shared secret key over an insecure channel.
 *
 * The X25519 public key is generated from a corresponding private key and is
 * designed to be:
 * - Compact (32 bytes)
 * - Fast to use in key agreement operations
 * - Resistant to various cryptographic attacks
 *
 * # CBOR Serialization
 *
 * `X25519PublicKey` is serialized to CBOR with tag 40011.
 *
 * ```
 * #6.40011(h'<32-byte-public-key>')
 * ```
 */
export class X25519PublicKey implements ToCbor, ToUR {
  /** The byte length of a `X25519PublicKey`. */
  static readonly KEY_SIZE: number = x25519.PUBLIC_KEY_SIZE;

  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    if (data.length !== x25519.PUBLIC_KEY_SIZE) {
      throw ComponentsError.invalidSize("X25519 public key", x25519.PUBLIC_KEY_SIZE, data.length);
    }
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Restore an X25519PublicKey from a fixed-size array of bytes.
   */
  static from(data: Uint8Array): X25519PublicKey {
    return new X25519PublicKey(new Uint8Array(data));
  }

  /**
   * Restore an X25519PublicKey from a hex string.
   */
  static fromHex(hex: string): X25519PublicKey {
    return X25519PublicKey.from(bytesFromHex(hex));
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
   * Compare with another X25519PublicKey.
   */
  equals(other: X25519PublicKey): boolean {
    if (this._data.length !== other._data.length) return false;
    for (let i = 0; i < this._data.length; i++) {
      if (this._data[i] !== other._data[i]) return false;
    }
    return true;
  }

  /**
   * Get string representation.
   *
   *   `X25519PublicKey(<ref_hex_short>)` where the reference is
   *   computed from the **tagged-CBOR** form of the key.
   */
  /** The reference: the digest of the tagged CBOR, as the reference computes it. */
  reference(): Reference {
    return Reference.fromDigest(Digest.fromImage(this.toCbor().toData()));
  }

  /** The first four bytes of `reference()` in hex, the reference's `ref_hex_short`. */
  refHexShort(): string {
    return this.reference().refHexShort();
  }

  /** The reference's `Display`: the type name over the short reference. */
  toString(): string {
    return `X25519PublicKey(${this.refHexShort()})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<X25519PublicKey> {
    return (X25519_PUBLIC_KEY_CODEC ??= defineCodec({
      tags: [TAG_X25519_PUBLIC_KEY],
      decodeUntagged: (cbor) => {
        const data = expectBytes(cbor);
        return X25519PublicKey.from(data);
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...X25519PublicKey.codec.tags];
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
  static fromCbor(cbor: Cbor): X25519PublicKey {
    return X25519PublicKey.codec.decode(cbor);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
