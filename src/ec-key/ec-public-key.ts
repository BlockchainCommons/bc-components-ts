import { ecdsa } from "@blockchaincommons/crypto";
import {
  type Cbor,
  type CborInput,
  type Tag,
  cbor,
  tagsForValues,
  type ToCbor,
} from "@blockchaincommons/dcbor";
import { taggedCborOf } from "../codable.js";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { TAG_EC_KEY, LEGACY_TAGS } from "@blockchaincommons/tags";
const TAG_EC_KEY_V1 = LEGACY_TAGS.EC_KEY_V1;
import { ComponentsError } from "../error.js";
import { ECUncompressedPublicKey } from "./ec-uncompressed-public-key.js";
import { bytesToHex, toBase64 } from "../utils.js";
import { bytesFromHex, guarded } from "../domain.js";
import type { ECPublicKeyBase } from "./ec-key-base.js";
import { Reference } from "../reference.js";
import { Digest } from "../digest.js";

/**
 * EC compressed public key for ECDSA verification (secp256k1, 33 bytes)
 *
 * An `ECPublicKey` is a 33-byte compressed representation of a public key on
 * the secp256k1 curve. The first byte is a prefix (0x02 or 0x03) that
 * indicates the parity of the y-coordinate, followed by the 32-byte
 * x-coordinate.
 *
 * These public keys are used to:
 * - Verify ECDSA signatures
 * - Identify the owner of a private key without revealing the private key
 *
 * # CBOR Serialization
 *
 * `ECPublicKey` is serialized to CBOR with tags 40306 (or legacy 306).
 *
 * The format is a map:
 * ```
 * #6.40306({
 *   3: h'<33-byte-public-key>' // key data (no key 2 means public key)
 * })
 * ```
 */
export class ECPublicKey implements ECPublicKeyBase, ToCbor, ToUR {
  /** The byte length of a `ECPublicKey`. */
  static readonly KEY_SIZE: number = ecdsa.PUBLIC_KEY_SIZE;

  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    if (data.length !== ecdsa.PUBLIC_KEY_SIZE) {
      throw ComponentsError.invalidSize("ECDSA public key", ecdsa.PUBLIC_KEY_SIZE, data.length);
    }
    // Any 33 bytes are accepted, as `ECPublicKey::from_data_ref`; a prefix
    // other than 02/03 or a point off the curve fails at `uncompressedPublicKey`
    // and `verify`, where the reference panics.
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Restore an ECPublicKey from a fixed-size array of bytes.
   */
  static from(data: Uint8Array): ECPublicKey {
    return new ECPublicKey(new Uint8Array(data));
  }

  /**
   * Restore an ECPublicKey from a hex string.
   */
  static fromHex(hex: string): ECPublicKey {
    return ECPublicKey.from(bytesFromHex(hex));
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
   * Returns the compressed public key (self).
   *
   * This method implements the ECKey interface. Since ECPublicKey is already
   * a compressed public key, this returns itself.
   */
  publicKey(): ECPublicKey {
    return this;
  }

  /**
   * Convert this compressed public key to uncompressed format.
   */
  uncompressedPublicKey(): ECUncompressedPublicKey {
    const uncompressed = guarded("ECPublicKey", () => ecdsa.decompressPublicKey(this._data));
    return ECUncompressedPublicKey.from(uncompressed);
  }

  /**
   * Verify an ECDSA signature.
   *
   * @param signature - The 64-byte signature to verify
   * @param message - The message that was signed
   * @returns true if the signature is valid
   */
  /**
   * Verify an ECDSA signature. A key that does not decode, or a signature
   * whose r or s is not below the curve order, is an `InvalidData` failure
   * (the reference's `ecdsa_verify` panics on them); any other pair is
   * `true` or `false`.
   */
  verify(signature: Uint8Array, message: Uint8Array): boolean {
    return guarded("ECPublicKey", () => ecdsa.verify(this._data, signature, message));
  }

  /**
   * Compare with another ECPublicKey.
   */
  equals(other: ECPublicKey): boolean {
    if (this._data.length !== other._data.length) return false;
    for (let i = 0; i < this._data.length; i++) {
      if (this._data[i] !== other._data[i]) return false;
    }
    return true;
  }

  /**
   * Get string representation.
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
    return `ECPublicKey(${this.refHexShort()})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /**
   * The CBOR tags of this type; the first one is used to encode. As the
   * reference, this type is only encoded: it has no `fromCbor`.
   */
  cborTags(): Tag[] {
    return tagsForValues([TAG_EC_KEY.value, TAG_EC_KEY_V1.value]);
  }

  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: { 3: h'<33-byte-key>' }
   * Note: No key 2 indicates this is a public key
   */
  untaggedCbor(): Cbor {
    const map = new Map<number, CborInput>();
    map.set(3, cbor(this._data));
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

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
