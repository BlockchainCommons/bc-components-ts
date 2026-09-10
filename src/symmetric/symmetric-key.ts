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
import { type Cbor, type Tag, cbor, expectBytes, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "../codable.js";
import { SYMMETRIC_KEY as TAG_SYMMETRIC_KEY } from "@blockchaincommons/tags";
import { type UR, urFor } from "@blockchaincommons/uniform-resources";
import { ComponentsError } from "../error.js";
import { bytesToHex, hexToBytes, toBase64 } from "../utils.js";
import { Nonce } from "../nonce.js";
import { EncryptedMessage } from "./encrypted-message.js";

const SYMMETRIC_KEY_SIZE = 32;

export class SymmetricKey implements ToCbor {
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
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static readonly codec: ComponentCodec<SymmetricKey> = defineCodec({
    tags: [TAG_SYMMETRIC_KEY],
    decodeUntagged: (cbor) => {
      const data = expectBytes(cbor);
      return SymmetricKey.fromDataRef(data);
    },
    encodeUntagged: (value) => value.untaggedCbor(),
  });

  cborTags(): Tag[] {
    return [...SymmetricKey.codec.tags];
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
  static fromCbor(cbor: Cbor): SymmetricKey {
    return SymmetricKey.codec.decode(cbor);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR (Uniform Resource) Serialization
  // ============================================================================
}
