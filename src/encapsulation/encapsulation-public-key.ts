/**
 * Encapsulation public key for key encapsulation mechanisms
 *
 * This type represents a public key that can be used to encapsulate (encrypt)
 * a shared secret. The recipient can then use their corresponding private key
 * to decapsulate (decrypt) the shared secret.
 *
 * For X25519, encapsulation works by:
 * 1. Generating an ephemeral key pair
 * 2. Performing ECDH with the ephemeral private key and the recipient's public key
 * 3. Returning the shared secret and the ephemeral public key as "ciphertext"
 *
 * For MLKEM, encapsulation uses the ML-KEM algorithm to generate a shared secret
 * and ciphertext.
 *
 * # CBOR Serialization
 *
 * For X25519, the public key is serialized with tag 40011.
 * For MLKEM, the public key is serialized with tag 40101.
 */

import {
  type Cbor,
  type Tag,
  cbor,
  expectBytes,
  type ToCbor,
  asTaggedValue,
  CborError,
  tagsForValues,
} from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "../codable.js";
import { TAG_X25519_PUBLIC_KEY, TAG_MLKEM_PUBLIC_KEY } from "@blockchaincommons/tags";
import { X25519PrivateKey } from "../x25519/x25519-private-key.js";
import { X25519PublicKey } from "../x25519/x25519-public-key.js";
import { type SymmetricKey } from "../symmetric/symmetric-key.js";
import { EncapsulationScheme } from "./encapsulation-scheme.js";
import { EncapsulationCiphertext } from "./encapsulation-ciphertext.js";
import { MLKEMPublicKey } from "../mlkem/mlkem-public-key.js";
import { MLKEMLevel } from "../mlkem/mlkem-level.js";
import { Reference, type ReferenceProvider } from "../reference.js";
import { Digest } from "../digest.js";
import { ComponentsError } from "../error.js";
import type { RngOptions } from "@blockchaincommons/rand";

/**
 * Convert MLKEMLevel to EncapsulationScheme
 */
function mlkemLevelToScheme(level: MLKEMLevel): EncapsulationScheme {
  switch (level) {
    case MLKEMLevel.MLKEM512:
      return EncapsulationScheme.MLKEM512;
    case MLKEMLevel.MLKEM768:
      return EncapsulationScheme.MLKEM768;
    case MLKEMLevel.MLKEM1024:
      return EncapsulationScheme.MLKEM1024;
  }
}

/**
 * Check if a scheme is an MLKEM scheme
 */
function isMlkemScheme(scheme: EncapsulationScheme): boolean {
  return (
    scheme === EncapsulationScheme.MLKEM512 ||
    scheme === EncapsulationScheme.MLKEM768 ||
    scheme === EncapsulationScheme.MLKEM1024
  );
}

// The codec is built on first use so that an unused class tree-shakes away.
let ENCAPSULATION_PUBLIC_KEY_CODEC: ComponentCodec<EncapsulationPublicKey> | undefined;

/**
 * Represents a public key for key encapsulation.
 *
 * Use this to encapsulate a shared secret for a recipient.
 */
export class EncapsulationPublicKey implements ReferenceProvider, ToCbor {
  private readonly _scheme: EncapsulationScheme;
  private readonly _x25519PublicKey: X25519PublicKey | undefined;
  private readonly _mlkemPublicKey: MLKEMPublicKey | undefined;

  private constructor(
    scheme: EncapsulationScheme,
    x25519PublicKey?: X25519PublicKey,
    mlkemPublicKey?: MLKEMPublicKey,
  ) {
    this._scheme = scheme;
    this._x25519PublicKey = x25519PublicKey;
    this._mlkemPublicKey = mlkemPublicKey;
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Create an EncapsulationPublicKey from an X25519PublicKey.
   */
  static fromX25519PublicKey(publicKey: X25519PublicKey): EncapsulationPublicKey {
    return new EncapsulationPublicKey(EncapsulationScheme.X25519, publicKey, undefined);
  }

  /**
   * Create an EncapsulationPublicKey from raw X25519 public key bytes.
   */
  static fromX25519Data(data: Uint8Array): EncapsulationPublicKey {
    const publicKey = X25519PublicKey.from(data);
    return EncapsulationPublicKey.fromX25519PublicKey(publicKey);
  }

  /**
   * Create an EncapsulationPublicKey from an MLKEMPublicKey.
   */
  static fromMlkem(publicKey: MLKEMPublicKey): EncapsulationPublicKey {
    const scheme = mlkemLevelToScheme(publicKey.level);
    return new EncapsulationPublicKey(scheme, undefined, publicKey);
  }

  /**
   * Create an EncapsulationPublicKey from raw MLKEM public key bytes.
   */
  static fromMlkemData(level: MLKEMLevel, data: Uint8Array): EncapsulationPublicKey {
    const publicKey = MLKEMPublicKey.fromBytes(level, data);
    return EncapsulationPublicKey.fromMlkem(publicKey);
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /**
   * Returns the encapsulation scheme.
   */
  get encapsulationScheme(): EncapsulationScheme {
    return this._scheme;
  }

  /**
   * Returns true if this is an X25519 public key.
   */
  isX25519(): boolean {
    return this._scheme === EncapsulationScheme.X25519;
  }

  /**
   * Returns true if this is an MLKEM public key.
   */
  isMlkem(): boolean {
    return isMlkemScheme(this._scheme);
  }

  /**
   * Returns the X25519 public key if this is an X25519 encapsulation key.
   * @throws Error if this is not an X25519 key
   */
  x25519PublicKey(): X25519PublicKey {
    if (this._x25519PublicKey === undefined) {
      throw ComponentsError.invalidData("Not an X25519 public key");
    }
    return this._x25519PublicKey;
  }

  /**
   * Returns the MLKEM public key if this is an MLKEM encapsulation key.
   * @throws Error if this is not an MLKEM key
   */
  mlkemPublicKey(): MLKEMPublicKey {
    if (this._mlkemPublicKey === undefined) {
      throw ComponentsError.invalidData("Not an MLKEM public key");
    }
    return this._mlkemPublicKey;
  }

  /**
   * Returns the X25519 public key if available, or null.
   */
  asX25519(): X25519PublicKey | undefined {
    return this._x25519PublicKey ?? undefined;
  }

  /**
   * Returns the MLKEM public key if available, or null.
   */
  asMlkem(): MLKEMPublicKey | undefined {
    return this._mlkemPublicKey ?? undefined;
  }

  /** The bytes (a view; do not mutate). */
  get bytes(): Uint8Array {
    if (this._scheme === EncapsulationScheme.X25519) {
      const pk = this._x25519PublicKey;
      if (pk === undefined) throw ComponentsError.invalidData("X25519 public key not set");
      return pk.bytes;
    } else if (isMlkemScheme(this._scheme)) {
      const pk = this._mlkemPublicKey;
      if (pk === undefined) throw ComponentsError.invalidData("MLKEM public key not set");
      return pk.bytes;
    }
    throw ComponentsError.general(`Unsupported scheme: ${String(this._scheme)}`);
  }

  /**
   * Returns this object as an EncapsulationPublicKey.
   *
   * This method allows EncapsulationPublicKey to implement the Encrypter interface.
   * Since this class is itself an encapsulation public key, it returns `this`.
   *
   * @returns This encapsulation public key
   */
  encapsulationPublicKey(): EncapsulationPublicKey {
    return this;
  }

  /**
   * Encapsulate a new shared secret for this public key.
   *
   * This generates a random shared secret and encapsulates it so that only
   * the holder of the corresponding private key can recover it.
   *
   * @returns A tuple of [sharedSecret, ciphertext]
   */
  encapsulateNewSharedSecret({ rng }: RngOptions = {}): [SymmetricKey, EncapsulationCiphertext] {
    const opts = rng === undefined ? {} : { rng };
    if (this._scheme === EncapsulationScheme.X25519) {
      const pk = this._x25519PublicKey;
      if (pk === undefined) throw ComponentsError.invalidData("X25519 public key not set");
      // Generate ephemeral key pair
      const [ephemeralPrivate, ephemeralPublic] = X25519PrivateKey.keypair(opts);

      // Perform ECDH to get shared secret
      const sharedSecret = ephemeralPrivate.sharedKeyWith(pk);

      // The "ciphertext" is the ephemeral public key
      const ciphertext = EncapsulationCiphertext.fromX25519PublicKey(ephemeralPublic);

      return [sharedSecret, ciphertext];
    } else if (isMlkemScheme(this._scheme)) {
      const pk = this._mlkemPublicKey;
      if (pk === undefined) throw ComponentsError.invalidData("MLKEM public key not set");

      // Encapsulate using MLKEM
      const { sharedSecret, ciphertext: mlkemCiphertext } = pk.encapsulate(opts);

      // Wrap in EncapsulationCiphertext
      const ciphertext = EncapsulationCiphertext.fromMlkem(mlkemCiphertext);

      return [sharedSecret, ciphertext];
    }
    throw ComponentsError.general(`Unsupported scheme: ${String(this._scheme)}`);
  }

  /**
   * Compare with another EncapsulationPublicKey.
   */
  equals(other: EncapsulationPublicKey): boolean {
    if (this._scheme !== other._scheme) return false;
    if (this._scheme === EncapsulationScheme.X25519) {
      const thisPk = this._x25519PublicKey;
      const otherPk = other._x25519PublicKey;
      if (thisPk === undefined || otherPk === undefined) return false;
      return thisPk.equals(otherPk);
    } else if (isMlkemScheme(this._scheme)) {
      const thisPk = this._mlkemPublicKey;
      const otherPk = other._mlkemPublicKey;
      if (thisPk === undefined || otherPk === undefined) return false;
      return thisPk.equals(otherPk);
    }
    return false;
  }

  /**
   * Get string representation.
   *
   *   `EncapsulationPublicKey(<ref_hex_short>, <inner_key_display>)`
   * where ref_hex_short is computed from the tagged-CBOR form.
   */
  toString(): string {
    const refShort = this.reference().shortReference("hex");
    let innerDisplay: string;
    if (this._scheme === EncapsulationScheme.X25519 && this._x25519PublicKey !== undefined) {
      innerDisplay = this._x25519PublicKey.toString();
    } else if (isMlkemScheme(this._scheme) && this._mlkemPublicKey !== undefined) {
      innerDisplay = this._mlkemPublicKey.toString();
    } else {
      innerDisplay = String(this._scheme);
    }
    return `EncapsulationPublicKey(${refShort}, ${innerDisplay})`;
  }

  // ============================================================================
  // ReferenceProvider Interface
  // ============================================================================

  /**
   * Returns a unique reference to this EncapsulationPublicKey instance.
   *
   * The reference is derived from the SHA-256 hash of the tagged CBOR
   * representation, providing a unique, content-addressable identifier.
   */
  reference(): Reference {
    const digest = Digest.fromImage(this.toCbor().toData());
    return Reference.fromDigest(digest);
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; the tag value selects the scheme, as the reference's `TryFrom<CBOR>`. */
  static get codec(): ComponentCodec<EncapsulationPublicKey> {
    return (ENCAPSULATION_PUBLIC_KEY_CODEC ??= defineCodec({
      tags: [TAG_X25519_PUBLIC_KEY, TAG_MLKEM_PUBLIC_KEY],
      decodeUntagged: (cborValue) =>
        EncapsulationPublicKey.fromX25519PublicKey(X25519PublicKey.from(expectBytes(cborValue))),
      // The reference's `TryFrom<CBOR>`: the tag value selects the inner
      // decoder; anything else, an untagged value included, is its own text.
      decodeAny: (whole) => {
        const tag = asTaggedValue(whole)?.[0].value;
        if (tag === TAG_X25519_PUBLIC_KEY.value)
          return EncapsulationPublicKey.fromX25519PublicKey(X25519PublicKey.fromCbor(whole));
        if (tag === TAG_MLKEM_PUBLIC_KEY.value)
          return EncapsulationPublicKey.fromMlkem(MLKEMPublicKey.fromCbor(whole));
        throw CborError.custom("Invalid encapsulation public key");
      },
      encodeUntagged: (value) => value.untaggedCbor(),
      encode: (value) => value.toCbor(),
    }));
  }

  /**
   * Returns the CBOR tags associated with this public key.
   */
  cborTags(): Tag[] {
    if (this._scheme === EncapsulationScheme.X25519) {
      return tagsForValues([TAG_X25519_PUBLIC_KEY.value]);
    } else if (isMlkemScheme(this._scheme)) {
      return tagsForValues([TAG_MLKEM_PUBLIC_KEY.value]);
    }
    throw ComponentsError.general(`Unsupported scheme: ${String(this._scheme)}`);
  }

  /**
   * Returns the untagged CBOR encoding.
   */
  untaggedCbor(): Cbor {
    if (this._scheme === EncapsulationScheme.X25519) {
      const pk = this._x25519PublicKey;
      if (pk === undefined) throw ComponentsError.invalidData("X25519 public key not set");
      return cbor(pk.bytes);
    } else if (isMlkemScheme(this._scheme)) {
      const pk = this._mlkemPublicKey;
      if (pk === undefined) throw ComponentsError.invalidData("MLKEM public key not set");
      return pk.untaggedCbor();
    }
    throw ComponentsError.general(`Unsupported scheme: ${String(this._scheme)}`);
  }

  /** The tagged CBOR form; the tag follows the scheme. */
  toCbor(): Cbor {
    return taggedCborOf(this);
  }

  /** Decode tagged (X25519 or ML-KEM) or untagged (X25519) CBOR. */
  static fromCbor(cborValue: Cbor): EncapsulationPublicKey {
    return EncapsulationPublicKey.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================
}
