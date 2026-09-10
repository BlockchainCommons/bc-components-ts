/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * X25519 private key for ECDH key exchange (32 bytes seed)
 *
 * X25519 is an elliptic-curve Diffie-Hellman key exchange protocol based on
 * Curve25519 as defined in RFC 7748. It allows two parties to establish a
 * shared secret key over an insecure channel.
 *
 * Key features of X25519:
 * - High security (128-bit security level)
 * - High performance
 * - Small key sizes (32 bytes)
 * - Protection against various side-channel attacks
 *
 * # CBOR Serialization
 *
 * `X25519PrivateKey` is serialized to CBOR with tag 40010.
 *
 * ```
 * #6.40010(h'<32-byte-private-key>')
 * ```
 *
 * Ported from bc-components-rust/src/x25519/x25519_private_key.rs
 */

import { type RandomNumberGenerator, secureRng, randomBytes } from "@blockchaincommons/rand";
import { x25519, X25519_PRIVATE_KEY_SIZE } from "@blockchaincommons/crypto";
import { type Cbor, type Tag, cbor, expectBytes, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "../codable.js";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { X25519_PRIVATE_KEY as TAG_X25519_PRIVATE_KEY } from "@blockchaincommons/tags";
import { ComponentsError } from "../error.js";
import { X25519PublicKey } from "./x25519-public-key.js";
import { SymmetricKey } from "../symmetric/symmetric-key.js";
import { bytesToHex, hexToBytes, toBase64 } from "../utils.js";

export class X25519PrivateKey implements ToCbor, ToUR {
  static readonly KEY_SIZE: number = X25519_PRIVATE_KEY_SIZE;

  private readonly _data: Uint8Array;
  private _publicKey?: X25519PublicKey;

  private constructor(data: Uint8Array) {
    if (data.length !== X25519_PRIVATE_KEY_SIZE) {
      throw ComponentsError.invalidSize(X25519_PRIVATE_KEY_SIZE, data.length);
    }
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Generate a new random X25519PrivateKey.
   */
  static new(): X25519PrivateKey {
    return X25519PrivateKey.random();
  }

  /**
   * Generate a new random X25519PrivateKey.
   */
  static random(): X25519PrivateKey {
    const rng = secureRng();
    return X25519PrivateKey.newUsing(rng);
  }

  /**
   * Generate a new random X25519PrivateKey using provided RNG.
   */
  static newUsing(rng: RandomNumberGenerator): X25519PrivateKey {
    return new X25519PrivateKey(randomBytes(X25519_PRIVATE_KEY_SIZE, { rng: rng }));
  }

  /**
   * Generate a new random X25519PrivateKey and corresponding X25519PublicKey.
   */
  static keypair(): [X25519PrivateKey, X25519PublicKey] {
    const privateKey = X25519PrivateKey.new();
    const publicKey = privateKey.publicKey();
    return [privateKey, publicKey];
  }

  /**
   * Generate a new random X25519PrivateKey and corresponding X25519PublicKey
   * using the given random number generator.
   */
  static keypairUsing(rng: RandomNumberGenerator): [X25519PrivateKey, X25519PublicKey] {
    const privateKey = X25519PrivateKey.newUsing(rng);
    const publicKey = privateKey.publicKey();
    return [privateKey, publicKey];
  }

  /**
   * Derive an X25519PrivateKey from the given key material.
   *
   * @param keyMaterial - The key material to derive from
   * @returns A new X25519PrivateKey derived from the key material
   */
  static deriveFromKeyMaterial(keyMaterial: Uint8Array): X25519PrivateKey {
    return new X25519PrivateKey(x25519.deriveAgreementPrivateKey(keyMaterial));
  }

  /**
   * Restore an X25519PrivateKey from a fixed-size array of bytes.
   */
  static fromData(data: Uint8Array): X25519PrivateKey {
    return new X25519PrivateKey(new Uint8Array(data));
  }

  /**
   * Restore an X25519PrivateKey from a reference to an array of bytes.
   * Validates the length.
   */
  static fromDataRef(data: Uint8Array): X25519PrivateKey {
    if (data.length !== X25519_PRIVATE_KEY_SIZE) {
      throw ComponentsError.invalidSize(X25519_PRIVATE_KEY_SIZE, data.length);
    }
    return X25519PrivateKey.fromData(data);
  }

  /**
   * Create an X25519PrivateKey from raw bytes (legacy alias).
   */
  static from(data: Uint8Array): X25519PrivateKey {
    return X25519PrivateKey.fromData(data);
  }

  /**
   * Restore an X25519PrivateKey from a hex string.
   */
  static fromHex(hex: string): X25519PrivateKey {
    return X25519PrivateKey.fromData(hexToBytes(hex));
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /**
   * Get a reference to the fixed-size array of bytes.
   */
  data(): Uint8Array {
    return this._data;
  }

  /**
   * Get the raw private key bytes (copy).
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
   * Get the X25519PublicKey corresponding to this X25519PrivateKey.
   */
  publicKey(): X25519PublicKey {
    if (this._publicKey === undefined) {
      const publicKeyBytes = x25519.publicKey(this._data);
      this._publicKey = X25519PublicKey.fromData(publicKeyBytes);
    }
    return this._publicKey;
  }

  /**
   * Derive a shared symmetric key from this X25519PrivateKey and the given
   * X25519PublicKey.
   *
   * @param publicKey - The other party's public key
   * @returns A SymmetricKey derived from the shared secret
   */
  sharedKeyWith(publicKey: X25519PublicKey): SymmetricKey {
    const shared = x25519.sharedKey(this._data, publicKey.data());
    return SymmetricKey.fromData(shared);
  }

  /**
   * Perform ECDH key agreement with a public key (legacy method).
   *
   * @deprecated Use sharedKeyWith() instead which returns a SymmetricKey
   */
  sharedSecret(publicKey: X25519PublicKey): Uint8Array {
    try {
      const shared = x25519.sharedKey(this._data, publicKey.data());
      return new Uint8Array(shared);
    } catch (e: unknown) {
      throw ComponentsError.crypto(`ECDH key agreement failed: ${String(e)}`);
    }
  }

  /**
   * Compare with another X25519PrivateKey.
   */
  equals(other: X25519PrivateKey): boolean {
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
    return `X25519PrivateKey(${this.toHex().substring(0, 16)}...)`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static readonly codec: ComponentCodec<X25519PrivateKey> = defineCodec({
    tags: [TAG_X25519_PRIVATE_KEY],
    decodeUntagged: (cbor) => {
      const data = expectBytes(cbor);
      return X25519PrivateKey.fromDataRef(data);
    },
    encodeUntagged: (value) => value.untaggedCbor(),
  });

  cborTags(): Tag[] {
    return [...X25519PrivateKey.codec.tags];
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
  static fromCbor(cbor: Cbor): X25519PrivateKey {
    return X25519PrivateKey.codec.decode(cbor);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
