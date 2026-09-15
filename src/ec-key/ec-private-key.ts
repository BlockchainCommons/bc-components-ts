import {
  type RandomNumberGenerator,
  secureRng,
  randomBytes,
  type RngOptions,
} from "@blockchaincommons/rand";
import { ecdsa, schnorr, deriveSigningPrivateKey } from "@blockchaincommons/crypto";
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
import { ECPublicKey } from "./ec-public-key.js";
import { SchnorrPublicKey } from "./schnorr-public-key.js";
import { bytesToHex, toBase64 } from "../utils.js";
import { bytesFromHex, guarded } from "../domain.js";
import type { ECKey } from "./ec-key-base.js";
import { Reference } from "../reference.js";
import { Digest } from "../digest.js";

/**
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
 */
export class ECPrivateKey implements ECKey, ToCbor, ToUR {
  /** The byte length of a `ECPrivateKey`. */
  static readonly KEY_SIZE: number = ecdsa.PRIVATE_KEY_SIZE;

  private readonly _data: Uint8Array;
  private _publicKey?: ECPublicKey;
  private _schnorrPublicKey?: SchnorrPublicKey;

  private constructor(data: Uint8Array) {
    if (data.length !== ecdsa.PRIVATE_KEY_SIZE) {
      throw ComponentsError.invalidSize("EC private key", ecdsa.PRIVATE_KEY_SIZE, data.length);
    }
    // Any 32 bytes are accepted, as `ECPrivateKey::from_data_ref`; a scalar
    // of 0 or ≥ n fails at `publicKey`, `schnorrPublicKey` and signing, where
    // the reference panics.
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /** A fresh random value; pass `rng` to make it deterministic. */
  static random({ rng = secureRng() }: RngOptions = {}): ECPrivateKey {
    return new ECPrivateKey(randomBytes(ecdsa.PRIVATE_KEY_SIZE, { rng: rng }));
  }

  /** A fresh private key and its public key. */
  static keypair({ rng = secureRng() }: RngOptions = {}): [ECPrivateKey, ECPublicKey] {
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
    return new ECPrivateKey(deriveSigningPrivateKey(keyMaterial));
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
    return ECPrivateKey.from(bytesFromHex(hex));
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
   * Get the ECPublicKey (compressed) corresponding to this ECPrivateKey.
   */
  publicKey(): ECPublicKey {
    if (this._publicKey === undefined) {
      const publicKeyBytes = guarded("ECPrivateKey", () => ecdsa.publicKey(this._data));
      this._publicKey = ECPublicKey.from(publicKeyBytes);
    }
    return this._publicKey;
  }

  /**
   * Get the SchnorrPublicKey (x-only) corresponding to this ECPrivateKey.
   */
  schnorrPublicKey(): SchnorrPublicKey {
    if (this._schnorrPublicKey === undefined) {
      const publicKeyBytes = guarded("ECPrivateKey", () => schnorr.publicKey(this._data));
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
    return guarded("ECPrivateKey", () => ecdsa.sign(this._data, message));
  }

  /**
   * Sign a message using Schnorr signature (BIP-340).
   *
   * @param message - The message to sign
   * @returns A 64-byte signature
   */
  schnorrSign(message: Uint8Array): Uint8Array {
    return guarded("ECPrivateKey", () => schnorr.sign(this._data, message));
  }

  /**
   * Sign a message using Schnorr signature with custom RNG.
   *
   * @param message - The message to sign
   * @param rng - Random number generator for auxiliary randomness
   * @returns A 64-byte signature
   */
  schnorrSignUsing(message: Uint8Array, rng: RandomNumberGenerator): Uint8Array {
    return guarded("ECPrivateKey", () => schnorr.sign(this._data, message, { rng }));
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
    return `ECPrivateKey(${this.refHexShort()})`;
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

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
