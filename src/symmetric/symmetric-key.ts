/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * Symmetric key for ChaCha20-Poly1305 AEAD encryption (32 bytes)
 *
 * A symmetric encryption key used for both encryption and decryption.
 *
 * `SymmetricKey` is a 32-byte cryptographic key used with ChaCha20-Poly1305
 * AEAD (Authenticated Encryption with Associated Data) encryption. This
 * implementation follows the IETF ChaCha20-Poly1305 specification as defined
 * in [RFC-8439](https://datatracker.ietf.org/doc/html/rfc8439).
 *
 * Symmetric encryption uses the same key for both encryption and decryption,
 * unlike asymmetric encryption where different keys are used for each
 * operation.
 *
 * # CBOR Serialization
 *
 * `SymmetricKey` is serialized to CBOR with tag 40023.
 *
 * Ported from bc-components-rust/src/symmetric/symmetric_key.rs
 */

import { type RandomNumberGenerator, secureRng, randomBytes } from "@blockchaincommons/rand";
import { chacha20Poly1305 } from "@blockchaincommons/crypto";
import {
  type Cbor,
  type Tag,
  cbor,
  expectBytes,
  validateTag,
  extractTaggedContent,
  decodeCbor,
  tagsForValues,
} from "@blockchaincommons/dcbor";
import { type CborTaggedEncodable, type CborTaggedDecodable, taggedCborOf } from "../codable.js";
import { SYMMETRIC_KEY as TAG_SYMMETRIC_KEY } from "@blockchaincommons/tags";
import { UR } from "@blockchaincommons/uniform-resources";
import { ComponentsError } from "../error.js";
import { bytesToHex, hexToBytes, toBase64 } from "../utils.js";
import { Nonce } from "../nonce.js";
import { EncryptedMessage } from "./encrypted-message.js";

const SYMMETRIC_KEY_SIZE = 32;

export class SymmetricKey implements CborTaggedEncodable, CborTaggedDecodable<SymmetricKey> {
  static readonly SYMMETRIC_KEY_SIZE: number = SYMMETRIC_KEY_SIZE;

  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    if (data.length !== SYMMETRIC_KEY_SIZE) {
      throw ComponentsError.invalidSize(SYMMETRIC_KEY_SIZE, data.length);
    }
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Create a new random symmetric key.
   */
  static new(): SymmetricKey {
    return SymmetricKey.random();
  }

  /**
   * Create a new symmetric key from data.
   */
  static fromData(data: Uint8Array): SymmetricKey {
    return new SymmetricKey(new Uint8Array(data));
  }

  /**
   * Create a new symmetric key from data (validates length).
   */
  static fromDataRef(data: Uint8Array): SymmetricKey {
    if (data.length !== SYMMETRIC_KEY_SIZE) {
      throw ComponentsError.invalidSize(SYMMETRIC_KEY_SIZE, data.length);
    }
    return SymmetricKey.fromData(data);
  }

  /**
   * Create a SymmetricKey from raw bytes (legacy alias).
   */
  static from(data: Uint8Array): SymmetricKey {
    return SymmetricKey.fromData(data);
  }

  /**
   * Create a SymmetricKey from hex string.
   */
  static fromHex(hex: string): SymmetricKey {
    return SymmetricKey.fromData(hexToBytes(hex));
  }

  /**
   * Generate a random symmetric key.
   */
  static random(): SymmetricKey {
    const rng = secureRng();
    return SymmetricKey.randomUsing(rng);
  }

  /**
   * Generate a random symmetric key using provided RNG.
   */
  static randomUsing(rng: RandomNumberGenerator): SymmetricKey {
    return new SymmetricKey(randomBytes(SYMMETRIC_KEY_SIZE, { rng: rng }));
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /**
   * Get the data of the symmetric key.
   */
  data(): Uint8Array {
    return this._data;
  }

  /**
   * Get the data of the symmetric key as a byte slice.
   */
  asBytes(): Uint8Array {
    return this._data;
  }

  /**
   * Get a copy of the raw key bytes.
   */
  toData(): Uint8Array {
    return new Uint8Array(this._data);
  }

  /**
   * Get hex string representation.
   */
  hex(): string {
    return bytesToHex(this._data);
  }

  /**
   * Get hex string representation (alias for hex()).
   */
  toHex(): string {
    return this.hex();
  }

  /**
   * Get base64 representation.
   */
  toBase64(): string {
    return toBase64(this._data);
  }

  /**
   * Compare with another SymmetricKey.
   */
  equals(other: SymmetricKey): boolean {
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
    return `SymmetricKey(${this.hex().substring(0, 8)}...)`;
  }

  // ============================================================================
  // Encryption/Decryption
  // ============================================================================

  /**
   * Encrypt the given plaintext with this key, and the given additional
   * authenticated data and nonce.
   */
  encrypt(plaintext: Uint8Array, aad?: Uint8Array, nonce?: Nonce): EncryptedMessage {
    const effectiveNonce = nonce ?? Nonce.new();
    const effectiveAad = aad ?? new Uint8Array(0);

    const sealed = chacha20Poly1305.encrypt(this._data, effectiveNonce.data(), plaintext, {
      aad: effectiveAad,
    });
    const ciphertext = sealed.subarray(0, sealed.length - chacha20Poly1305.TAG_SIZE);
    const authTag = sealed.subarray(sealed.length - chacha20Poly1305.TAG_SIZE);

    return EncryptedMessage.new(ciphertext, effectiveAad, effectiveNonce, authTag);
  }

  /**
   * Decrypt the given encrypted message with this key.
   */
  decrypt(message: EncryptedMessage): Uint8Array {
    const ct = message.ciphertext();
    const tag = message.authenticationTag().data();
    const sealed = new Uint8Array(ct.length + tag.length);
    sealed.set(ct);
    sealed.set(tag, ct.length);
    return chacha20Poly1305.decrypt(this._data, message.nonce().data(), sealed, {
      aad: message.aad(),
    });
  }

  // ============================================================================
  // CBOR Serialization (CborTaggedEncodable)
  // ============================================================================

  /**
   * Returns the CBOR tags associated with SymmetricKey.
   */
  cborTags(): Tag[] {
    return tagsForValues([TAG_SYMMETRIC_KEY.value]);
  }

  /**
   * Returns the untagged CBOR encoding (as a byte string).
   */
  untaggedCbor(): Cbor {
    return cbor(this._data);
  }

  /**
   * Returns the tagged CBOR encoding.
   */
  taggedCbor(): Cbor {
    return taggedCborOf(this);
  }

  /**
   * Returns the tagged value in CBOR binary representation.
   */
  taggedCborData(): Uint8Array {
    return this.taggedCbor().toData();
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  /**
   * Creates a SymmetricKey by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cbor: Cbor): SymmetricKey {
    const data = expectBytes(cbor);
    return SymmetricKey.fromDataRef(data);
  }

  /**
   * Creates a SymmetricKey by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cbor: Cbor): SymmetricKey {
    validateTag(cbor, this.cborTags());
    const content = extractTaggedContent(cbor);
    return this.fromUntaggedCbor(content);
  }

  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cbor: Cbor): SymmetricKey {
    const instance = new SymmetricKey(new Uint8Array(SYMMETRIC_KEY_SIZE));
    return instance.fromTaggedCbor(cbor);
  }

  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): SymmetricKey {
    const cbor = decodeCbor(data);
    return SymmetricKey.fromTaggedCbor(cbor);
  }

  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): SymmetricKey {
    const cbor = decodeCbor(data);
    const bytes = expectBytes(cbor);
    return SymmetricKey.fromDataRef(bytes);
  }

  // ============================================================================
  // UR (Uniform Resource) Serialization
  // ============================================================================

  /**
   * Get the UR type for symmetric keys.
   */
  static readonly UR_TYPE = "crypto-key";

  /**
   * Returns the UR representation of the symmetric key.
   *
   * The UR type prefix (`ur:crypto-key/...`) carries the CBOR tag, so the
   * inner CBOR must be untagged — matches Rust's `UREncodable` blanket impl.
   */
  ur(): UR {
    return UR.from(SymmetricKey.UR_TYPE, this.untaggedCbor());
  }

  /**
   * Returns the UR string representation of the symmetric key.
   */
  urString(): string {
    return this.ur().toString();
  }

  /**
   * Creates a SymmetricKey from a UR.
   */
  static fromUR(ur: UR): SymmetricKey {
    ur.expectType(SymmetricKey.UR_TYPE);
    const dummy = SymmetricKey.fromData(new Uint8Array(SymmetricKey.SYMMETRIC_KEY_SIZE));
    return dummy.fromUntaggedCbor(ur.cbor);
  }

  /**
   * Creates a SymmetricKey from a UR string.
   */
  static fromURString(urString: string): SymmetricKey {
    const ur = UR.parse(urString);
    return SymmetricKey.fromUR(ur);
  }

  /**
   * Alias for fromURString for Rust API compatibility.
   */
  static fromUrString(urString: string): SymmetricKey {
    return SymmetricKey.fromURString(urString);
  }
}
