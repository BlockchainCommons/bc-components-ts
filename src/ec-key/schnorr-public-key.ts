import { schnorr } from "@blockchaincommons/crypto";
import { Digest } from "../digest.js";
import { ComponentsError } from "../error.js";
import { bytesToHex, toBase64 } from "../utils.js";
import { bytesFromHex, guarded } from "../domain.js";
import type { ECKeyBase } from "./ec-key-base.js";
import { Reference } from "../reference.js";

/**
 * Schnorr (x-only) public key for BIP-340 signatures (secp256k1, 32 bytes)
 *
 * A `SchnorrPublicKey` is a 32-byte "x-only" public key used with the BIP-340
 * Schnorr signature scheme. Unlike compressed ECDSA public keys (33 bytes)
 * that include a prefix byte indicating the parity of the y-coordinate,
 * Schnorr public keys only contain the x-coordinate of the elliptic curve
 * point.
 *
 * Schnorr signatures offer several advantages over traditional ECDSA
 * signatures:
 * - Linearity: Enables key and signature aggregation
 * - Non-malleability: Prevents third parties from modifying signatures
 * - Smaller size: Signatures are 64 bytes vs 70-72 bytes for ECDSA
 * - Better privacy: Makes different multisig policies indistinguishable
 *
 * Schnorr signatures were introduced to Bitcoin via the Taproot upgrade
 * (BIP-340).
 *
 * Note: SchnorrPublicKey does not have CBOR serialization in the reference
 * implementation, so we keep it simple here.
 */
export class SchnorrPublicKey implements ECKeyBase {
  /** The byte length of a `SchnorrPublicKey`. */
  static readonly KEY_SIZE: number = schnorr.PUBLIC_KEY_SIZE;

  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    if (data.length !== schnorr.PUBLIC_KEY_SIZE) {
      throw ComponentsError.invalidSize("Schnorr public key", schnorr.PUBLIC_KEY_SIZE, data.length);
    }
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Restore a SchnorrPublicKey from a fixed-size array of bytes.
   */
  static from(data: Uint8Array): SchnorrPublicKey {
    return new SchnorrPublicKey(new Uint8Array(data));
  }

  /**
   * Restore a SchnorrPublicKey from a hex string.
   */
  static fromHex(hex: string): SchnorrPublicKey {
    return SchnorrPublicKey.from(bytesFromHex(hex));
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
   * Verify a Schnorr signature (BIP-340).
   *
   * @param signature - The 64-byte signature to verify
   * @param message - The message that was signed
   * @returns true if the signature is valid
   */
  /**
   * Verify a BIP-340 signature. A key that is not an x-only point is an
   * `InvalidData` failure (the reference's `schnorr_verify` panics on it).
   */
  schnorrVerify(signature: Uint8Array, message: Uint8Array): boolean {
    return guarded("SchnorrPublicKey", () => schnorr.verify(this._data, signature, message));
  }

  /**
   * Compare with another SchnorrPublicKey.
   */
  equals(other: SchnorrPublicKey): boolean {
    if (this._data.length !== other._data.length) return false;
    for (let i = 0; i < this._data.length; i++) {
      if (this._data[i] !== other._data[i]) return false;
    }
    return true;
  }

  /**
   * Get string representation.
   *
   * — the reference is computed from the **raw 32-byte key data**
   * (not the tagged-CBOR form): `Reference::from_digest(Digest::from_image(self.bytes))`.
   * `ref_hex_short()` returns the first 8 hex chars of that
   * reference's binary form (= SHA-256(data)[0..4]).
   */
  /** The reference: the digest of the raw key bytes, as the reference computes it. */
  reference(): Reference {
    return Reference.fromDigest(Digest.fromImage(this.bytes));
  }

  /** The first four bytes of `reference()` in hex, the reference's `ref_hex_short`. */
  refHexShort(): string {
    return this.reference().refHexShort();
  }

  /** The reference's `Display`: the type name over the short reference. */
  toString(): string {
    return `SchnorrPublicKey(${this.refHexShort()})`;
  }
}
