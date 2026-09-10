/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * EC private key for ECDSA and Schnorr signatures (secp256k1, 32 bytes)
 *
 * An `ECPrivateKey` is a 32-byte secret value that can be used to:
 * - Generate its corresponding public key
 * - Sign messages using the ECDSA signature scheme
 * - Sign messages using the Schnorr signature scheme (BIP-340)
 *
 * These keys use the secp256k1 curve, which is the same curve used in Bitcoin
 * and other cryptocurrencies.
 *
 * # CBOR Serialization
 *
 * `ECPrivateKey` is serialized to CBOR with tags 40306 (or legacy 306).
 *
 * The format is a map:
 * ```
 * #6.40306({
 *   2: true,                    // indicates private key
 *   3: h'<32-byte-private-key>' // key data
 * })
 * ```
 *
 * Ported from bc-components-rust/src/ec_key/ec_private_key.rs
 */

import { type RandomNumberGenerator, secureRng, randomBytes } from "@blockchaincommons/rand";
import { ecdsa, schnorr, ECDSA_PRIVATE_KEY_SIZE } from "@blockchaincommons/crypto";
import {
  type Cbor,
  type CborInput,
  type Tag,
  cbor,
  expectMap,
  type ToCbor,
} from "@blockchaincommons/dcbor";
import {
  taggedCborOf,
  mapGetBoolean,
  mapGetBytes,
  type ComponentCodec,
  defineCodec,
} from "../codable.js";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { EC_KEY as TAG_EC_KEY, LEGACY_TAGS } from "@blockchaincommons/tags";
const TAG_EC_KEY_V1 = LEGACY_TAGS.EC_KEY_V1;
import { ComponentsError } from "../error.js";
import { ECPublicKey } from "./ec-public-key.js";
import { SchnorrPublicKey } from "./schnorr-public-key.js";
import { bytesToHex, hexToBytes, toBase64 } from "../utils.js";
import type { ECKey } from "./ec-key-base.js";

export class ECPrivateKey implements ECKey, ToCbor, ToUR {
  static readonly KEY_SIZE: number = ECDSA_PRIVATE_KEY_SIZE;

  private readonly _data: Uint8Array;
  private _publicKey?: ECPublicKey;
  private _schnorrPublicKey?: SchnorrPublicKey;

  private constructor(data: Uint8Array) {
    if (data.length !== ECDSA_PRIVATE_KEY_SIZE) {
      throw ComponentsError.invalidSize(ECDSA_PRIVATE_KEY_SIZE, data.length);
    }
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /** A fresh random value; pass `rng` to make it deterministic. */
  static random({ rng = secureRng() }: { rng?: RandomNumberGenerator } = {}): ECPrivateKey {
    return new ECPrivateKey(randomBytes(ECDSA_PRIVATE_KEY_SIZE, { rng: rng }));
  }

  /** A fresh private key and its public key. */
  static keypair({ rng = secureRng() }: { rng?: RandomNumberGenerator } = {}): [
    ECPrivateKey,
    ECPublicKey,
  ] {
    const privateKey = ECPrivateKey.random({ rng });
    return [privateKey, privateKey.publicKey()];
  }

  /**
   * Derive an ECPrivateKey from the given key material.
   *
   * @param keyMaterial - The key material to derive from
   * @returns A new ECPrivateKey derived from the key material
   */
  static deriveFromKeyMaterial(keyMaterial: Uint8Array): ECPrivateKey {
    return new ECPrivateKey(ecdsa.derivePrivateKey(keyMaterial));
  }

  /**
   * Restore an ECPrivateKey from a fixed-size array of bytes.
   */
  static from(data: Uint8Array): ECPrivateKey {
    return new ECPrivateKey(new Uint8Array(data));
  }

  /**
   * Restore an ECPrivateKey from a hex string.
   */
  static fromHex(hex: string): ECPrivateKey {
    return ECPrivateKey.from(hexToBytes(hex));
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /** The bytes (a view; do not mutate). */
  get bytes(): Uint8Array {
    return this._data;
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
   * Get the ECPublicKey (compressed) corresponding to this ECPrivateKey.
   */
  publicKey(): ECPublicKey {
    if (this._publicKey === undefined) {
      const publicKeyBytes = ecdsa.publicKey(this._data);
      this._publicKey = ECPublicKey.from(publicKeyBytes);
    }
    return this._publicKey;
  }

  /**
   * Get the SchnorrPublicKey (x-only) corresponding to this ECPrivateKey.
   */
  schnorrPublicKey(): SchnorrPublicKey {
    if (this._schnorrPublicKey === undefined) {
      const publicKeyBytes = schnorr.publicKey(this._data);
      this._schnorrPublicKey = SchnorrPublicKey.from(publicKeyBytes);
    }
    return this._schnorrPublicKey;
  }

  /**
   * Sign a message using ECDSA.
   *
   * @param message - The message to sign
   * @returns A 64-byte signature
   */
  ecdsaSign(message: Uint8Array): Uint8Array {
    try {
      return ecdsa.sign(this._data, message);
    } catch (e) {
      throw ComponentsError.crypto(`ECDSA signing failed: ${String(e)}`);
    }
  }

  /**
   * Sign a message using Schnorr signature (BIP-340).
   *
   * @param message - The message to sign
   * @returns A 64-byte signature
   */
  schnorrSign(message: Uint8Array): Uint8Array {
    try {
      return schnorr.sign(this._data, message);
    } catch (e) {
      throw ComponentsError.crypto(`Schnorr signing failed: ${String(e)}`);
    }
  }

  /**
   * Sign a message using Schnorr signature with custom RNG.
   *
   * @param message - The message to sign
   * @param rng - Random number generator for auxiliary randomness
   * @returns A 64-byte signature
   */
  schnorrSignUsing(message: Uint8Array, rng: RandomNumberGenerator): Uint8Array {
    try {
      return schnorr.sign(this._data, message, { rng });
    } catch (e) {
      throw ComponentsError.crypto(`Schnorr signing failed: ${String(e)}`);
    }
  }

  /**
   * Compare with another ECPrivateKey.
   */
  equals(other: ECPrivateKey): boolean {
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
    return `ECPrivateKey(${this.toHex().substring(0, 16)}...)`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static readonly codec: ComponentCodec<ECPrivateKey> = defineCodec({
    tags: [TAG_EC_KEY, TAG_EC_KEY_V1],
    decodeUntagged: (cborValue) => {
      const map = expectMap(cborValue);

      // Check for key 2 (isPrivate = true)
      const isPrivate = mapGetBoolean(map, 2);
      if (isPrivate !== true) {
        throw ComponentsError.invalidData("ECPrivateKey CBOR must have key 2 set to true");
      }

      // Get key data from key 3
      // CborMap.extract() returns native types (Uint8Array for byte strings)
      const keyData = mapGetBytes(map, 3);
      if (keyData === undefined || keyData.length === 0) {
        throw ComponentsError.invalidData("ECPrivateKey CBOR must have key 3 (data)");
      }

      return ECPrivateKey.from(keyData);
    },
    encodeUntagged: (value) => value.untaggedCbor(),
  });

  cborTags(): Tag[] {
    return [...ECPrivateKey.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: { 2: true, 3: h'<32-byte-key>' }
   */
  untaggedCbor(): Cbor {
    const map = new Map<number, CborInput>();
    map.set(2, true);
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

  /** Decode tagged or untagged CBOR. */
  static fromCbor(cborValue: Cbor): ECPrivateKey {
    return ECPrivateKey.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
