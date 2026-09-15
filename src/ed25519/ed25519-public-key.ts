import { ed25519 } from "@blockchaincommons/crypto";
import { Digest } from "../digest.js";
import { ComponentsError } from "../error.js";
import { bytesToHex, toBase64 } from "../utils.js";
import { bytesFromHex, guarded } from "../domain.js";
import { Reference } from "../reference.js";

/**
 * Ed25519 public key for EdDSA signature verification (32 bytes)
 */
export class Ed25519PublicKey {
  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    if (data.length !== ed25519.PUBLIC_KEY_SIZE) {
      throw ComponentsError.invalidSize("Ed25519 public key", ed25519.PUBLIC_KEY_SIZE, data.length);
    }
    this._data = new Uint8Array(data);
  }

  /**
   * Create an Ed25519PublicKey from raw bytes (32 bytes).
   */
  static from(data: Uint8Array): Ed25519PublicKey {
    return new Ed25519PublicKey(data);
  }

  /**
   * Create an Ed25519PublicKey from hex string.
   */
  static fromHex(hex: string): Ed25519PublicKey {
    return new Ed25519PublicKey(bytesFromHex(hex));
  }

  /** Returns the 32 raw public key bytes (copy). */
  /** The bytes (a view; do not mutate). */
  get bytes(): Uint8Array {
    return new Uint8Array(this._data);
  }

  /** Alias of {@link Ed25519PublicKey.data}. */
  /** Backwards-compatible alias of {@link Ed25519PublicKey.data}. */
  /**
   * Get hex string representation
   */
  toHex(): string {
    return bytesToHex(this._data);
  }

  /**
   * Get base64 representation
   */
  toBase64(): string {
    return toBase64(this._data);
  }

  /**
   * Verify a signature using Ed25519
   */
  /**
   * Verify a signature (`verify_strict`). A key that does not decode is an
   * `InvalidData` failure (the reference `unwrap`s the decode); a wrong-size
   * signature is `InvalidSize`.
   */
  verify(message: Uint8Array, signature: Uint8Array): boolean {
    if (signature.length !== ed25519.SIGNATURE_SIZE) {
      throw ComponentsError.invalidSize(
        "Ed25519 signature",
        ed25519.SIGNATURE_SIZE,
        signature.length,
      );
    }
    return guarded("Ed25519PublicKey", () => ed25519.verify(this._data, signature, message));
  }

  /**
   * Compare with another Ed25519PublicKey
   */
  equals(other: Ed25519PublicKey): boolean {
    if (this._data.length !== other._data.length) return false;
    for (let i = 0; i < this._data.length; i++) {
      if (this._data[i] !== other._data[i]) return false;
    }
    return true;
  }

  /**
   * Get string representation.
   *
   *   `Ed25519PublicKey(<ref_hex_short>)`
   * where the reference is computed from the **raw 32-byte data**
   * (not tagged CBOR) — same pattern as SchnorrPublicKey.
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
    return `Ed25519PublicKey(${this.refHexShort()})`;
  }
}
