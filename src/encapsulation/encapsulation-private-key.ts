/**
 * Encapsulation private key for key encapsulation mechanisms
 *
 * This type represents a private key that can be used to decapsulate (decrypt)
 * a shared secret that was encapsulated using the corresponding public key.
 *
 * For X25519, decapsulation works by:
 * 1. Receiving the ephemeral public key (ciphertext)
 * 2. Performing ECDH with the private key and the ephemeral public key
 * 3. Returning the shared secret
 *
 * For MLKEM, decapsulation uses the ML-KEM algorithm to recover the shared secret.
 *
 * # CBOR Serialization
 *
 * For X25519, the private key is serialized with tag 40010.
 * For MLKEM, the private key is serialized with tag 40100.
 */

import { secureRng, type RngOptions } from "@blockchaincommons/rand";
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
import { TAG_X25519_PRIVATE_KEY, TAG_MLKEM_PRIVATE_KEY } from "@blockchaincommons/tags";
import { X25519PrivateKey } from "../x25519/x25519-private-key.js";
import { type SymmetricKey } from "../symmetric/symmetric-key.js";
import { EncapsulationScheme } from "./encapsulation-scheme.js";
import { type EncapsulationCiphertext } from "./encapsulation-ciphertext.js";
import { EncapsulationPublicKey } from "./encapsulation-public-key.js";
import { MLKEMPrivateKey } from "../mlkem/mlkem-private-key.js";
import { MLKEMLevel } from "../mlkem/mlkem-level.js";
import { ComponentsError } from "../error.js";
import { Reference, type ReferenceProvider } from "../reference.js";
import { Digest } from "../digest.js";

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
let ENCAPSULATION_PRIVATE_KEY_CODEC: ComponentCodec<EncapsulationPrivateKey> | undefined;

/**
 * Represents a private key for key encapsulation.
 *
 * Use this to decapsulate a shared secret from ciphertext.
 */
export class EncapsulationPrivateKey implements ReferenceProvider, ToCbor {
  private readonly _scheme: EncapsulationScheme;
  private readonly _x25519PrivateKey: X25519PrivateKey | undefined;
  private readonly _mlkemPrivateKey: MLKEMPrivateKey | undefined;

  private constructor(
    scheme: EncapsulationScheme,
    x25519PrivateKey?: X25519PrivateKey,
    mlkemPrivateKey?: MLKEMPrivateKey,
  ) {
    this._scheme = scheme;
    this._x25519PrivateKey = x25519PrivateKey;
    this._mlkemPrivateKey = mlkemPrivateKey;
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Create an EncapsulationPrivateKey from an X25519PrivateKey.
   */
  static fromX25519PrivateKey(privateKey: X25519PrivateKey): EncapsulationPrivateKey {
    return new EncapsulationPrivateKey(EncapsulationScheme.X25519, privateKey, undefined);
  }

  /**
   * Create an EncapsulationPrivateKey from raw X25519 private key bytes.
   */
  static fromX25519Data(data: Uint8Array): EncapsulationPrivateKey {
    const privateKey = X25519PrivateKey.from(data);
    return EncapsulationPrivateKey.fromX25519PrivateKey(privateKey);
  }

  /**
   * Create an EncapsulationPrivateKey from an MLKEMPrivateKey.
   */
  static fromMlkem(privateKey: MLKEMPrivateKey): EncapsulationPrivateKey {
    const scheme = mlkemLevelToScheme(privateKey.level);
    return new EncapsulationPrivateKey(scheme, undefined, privateKey);
  }

  /**
   * Create an EncapsulationPrivateKey from raw MLKEM private key bytes.
   */
  static fromMlkemData(level: MLKEMLevel, data: Uint8Array): EncapsulationPrivateKey {
    const privateKey = MLKEMPrivateKey.fromBytes(level, data);
    return EncapsulationPrivateKey.fromMlkem(privateKey);
  }

  /** A fresh random value; pass `rng` to make it deterministic. */
  static random({ rng = secureRng() }: RngOptions = {}): EncapsulationPrivateKey {
    const x25519Private = X25519PrivateKey.random({ rng: rng });
    return EncapsulationPrivateKey.fromX25519PrivateKey(x25519Private);
  }

  /** A fresh ML-KEM private key at `level`; pass `rng` to make it deterministic. */
  static randomMlkem(
    level: MLKEMLevel = MLKEMLevel.MLKEM768,
    { rng = secureRng() }: RngOptions = {},
  ): EncapsulationPrivateKey {
    const mlkemPrivate = MLKEMPrivateKey.random(level, { rng: rng });
    return EncapsulationPrivateKey.fromMlkem(mlkemPrivate);
  }

  /** A fresh private key and its public key. */
  static keypair({ rng = secureRng() }: RngOptions = {}): [
    EncapsulationPrivateKey,
    EncapsulationPublicKey,
  ] {
    const privateKey = EncapsulationPrivateKey.random({ rng });
    return [privateKey, privateKey.publicKey()];
  }

  /** A fresh ML-KEM private key at `level` and its public key. */
  static mlkemKeypair(
    level: MLKEMLevel = MLKEMLevel.MLKEM768,
    { rng = secureRng() }: RngOptions = {},
  ): [EncapsulationPrivateKey, EncapsulationPublicKey] {
    const [mlkemPrivate, mlkemPublic] = MLKEMPrivateKey.keypair(level, { rng });
    return [
      EncapsulationPrivateKey.fromMlkem(mlkemPrivate),
      EncapsulationPublicKey.fromMlkem(mlkemPublic),
    ];
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
   * Returns true if this is an X25519 private key.
   */
  isX25519(): boolean {
    return this._scheme === EncapsulationScheme.X25519;
  }

  /**
   * Returns true if this is an MLKEM private key.
   */
  isMlkem(): boolean {
    return isMlkemScheme(this._scheme);
  }

  /**
   * Returns the X25519 private key if this is an X25519 encapsulation key.
   * @throws Error if this is not an X25519 key
   */
  x25519PrivateKey(): X25519PrivateKey {
    if (this._x25519PrivateKey === undefined) {
      throw ComponentsError.invalidData("Not an X25519 private key");
    }
    return this._x25519PrivateKey;
  }

  /**
   * Returns the MLKEM private key if this is an MLKEM encapsulation key.
   * @throws Error if this is not an MLKEM key
   */
  mlkemPrivateKey(): MLKEMPrivateKey {
    if (this._mlkemPrivateKey === undefined) {
      throw ComponentsError.invalidData("Not an MLKEM private key");
    }
    return this._mlkemPrivateKey;
  }

  /**
   * Returns the X25519 private key if available, or null.
   */
  asX25519(): X25519PrivateKey | undefined {
    return this._x25519PrivateKey ?? undefined;
  }

  /**
   * Returns the MLKEM private key if available, or null.
   */
  asMlkem(): MLKEMPrivateKey | undefined {
    return this._mlkemPrivateKey ?? undefined;
  }

  /** The bytes (a view; do not mutate). */
  get bytes(): Uint8Array {
    if (this._scheme === EncapsulationScheme.X25519) {
      const pk = this._x25519PrivateKey;
      if (pk === undefined) throw ComponentsError.invalidData("X25519 private key not set");
      return pk.bytes;
    } else if (isMlkemScheme(this._scheme)) {
      const pk = this._mlkemPrivateKey;
      if (pk === undefined) throw ComponentsError.invalidData("MLKEM private key not set");
      return pk.bytes;
    }
    throw ComponentsError.general(`Unsupported scheme: ${String(this._scheme)}`);
  }

  /**
   * The public key corresponding to this private key.
   *
   * Only an X25519 key derives its public key. For an ML-KEM key this
   * throws `Crypto` (`Deriving ML-KEM public key not supported`), as the
   * reference does: keep the public key `mlkemKeypair` hands out.
   */
  publicKey(): EncapsulationPublicKey {
    if (this._scheme === EncapsulationScheme.X25519) {
      const pk = this._x25519PrivateKey;
      if (pk === undefined) throw ComponentsError.invalidData("X25519 private key not set");
      const x25519Public = pk.publicKey();
      return EncapsulationPublicKey.fromX25519PublicKey(x25519Public);
    } else if (isMlkemScheme(this._scheme)) {
      throw ComponentsError.crypto("Deriving ML-KEM public key not supported");
    }
    throw ComponentsError.general(`Unsupported scheme: ${String(this._scheme)}`);
  }

  /**
   * Decapsulate a shared secret from ciphertext.
   *
   * @param ciphertext - The ciphertext from encapsulation
   * @returns The decapsulated shared secret
   * @throws ComponentsError if the scheme doesn't match
   */
  decapsulateSharedSecret(ciphertext: EncapsulationCiphertext): SymmetricKey {
    // Verify scheme matches
    if (ciphertext.encapsulationScheme !== this._scheme) {
      throw ComponentsError.invalidData(
        `Scheme mismatch: expected ${String(this._scheme)}, got ${String(ciphertext.encapsulationScheme)}`,
      );
    }

    if (this._scheme === EncapsulationScheme.X25519) {
      const pk = this._x25519PrivateKey;
      if (pk === undefined) throw ComponentsError.invalidData("X25519 private key not set");
      // Get the ephemeral public key from ciphertext
      const ephemeralPublic = ciphertext.x25519PublicKey();

      // Perform ECDH to recover shared secret
      return pk.sharedKeyWith(ephemeralPublic);
    } else if (isMlkemScheme(this._scheme)) {
      const pk = this._mlkemPrivateKey;
      if (pk === undefined) throw ComponentsError.invalidData("MLKEM private key not set");
      // Get the MLKEM ciphertext and decapsulate
      const mlkemCiphertext = ciphertext.mlkemCiphertext();
      return pk.decapsulate(mlkemCiphertext);
    }

    throw ComponentsError.general(`Unsupported scheme: ${String(this._scheme)}`);
  }

  /**
   * Compare with another EncapsulationPrivateKey.
   */
  equals(other: EncapsulationPrivateKey): boolean {
    if (this._scheme !== other._scheme) return false;
    if (this._scheme === EncapsulationScheme.X25519) {
      const thisPk = this._x25519PrivateKey;
      const otherPk = other._x25519PrivateKey;
      if (thisPk === undefined || otherPk === undefined) return false;
      return thisPk.equals(otherPk);
    } else if (isMlkemScheme(this._scheme)) {
      const thisPk = this._mlkemPrivateKey;
      const otherPk = other._mlkemPrivateKey;
      if (thisPk === undefined || otherPk === undefined) return false;
      return thisPk.equals(otherPk);
    }
    return false;
  }

  /**
   * Get string representation.
   */
  /** The reference's `Display`: `EncapsulationPrivateKey(<short reference>, <inner key>)`. */
  toString(): string {
    const inner =
      this._x25519PrivateKey?.toString() ??
      this._mlkemPrivateKey?.toString() ??
      String(this._scheme);
    return `EncapsulationPrivateKey(${this.reference().refHexShort()}, ${inner})`;
  }

  // ============================================================================
  // ReferenceProvider Interface
  // ============================================================================

  /**
   * Returns a unique reference to this EncapsulationPrivateKey instance.
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
  static get codec(): ComponentCodec<EncapsulationPrivateKey> {
    return (ENCAPSULATION_PRIVATE_KEY_CODEC ??= defineCodec({
      tags: [TAG_X25519_PRIVATE_KEY, TAG_MLKEM_PRIVATE_KEY],
      decodeUntagged: (cborValue) =>
        EncapsulationPrivateKey.fromX25519PrivateKey(X25519PrivateKey.from(expectBytes(cborValue))),
      // The reference's `TryFrom<CBOR>`: the tag value selects the inner
      // decoder; anything else, an untagged value included, is its own text.
      decodeAny: (whole) => {
        const tag = asTaggedValue(whole)?.[0].value;
        if (tag === TAG_X25519_PRIVATE_KEY.value)
          return EncapsulationPrivateKey.fromX25519PrivateKey(X25519PrivateKey.fromCbor(whole));
        if (tag === TAG_MLKEM_PRIVATE_KEY.value)
          return EncapsulationPrivateKey.fromMlkem(MLKEMPrivateKey.fromCbor(whole));
        throw CborError.custom("Invalid encapsulation private key");
      },
      encodeUntagged: (value) => value.untaggedCbor(),
      encode: (value) => value.toCbor(),
    }));
  }

  /**
   * Returns the CBOR tags associated with this private key.
   */
  cborTags(): Tag[] {
    if (this._scheme === EncapsulationScheme.X25519) {
      return tagsForValues([TAG_X25519_PRIVATE_KEY.value]);
    } else if (isMlkemScheme(this._scheme)) {
      return tagsForValues([TAG_MLKEM_PRIVATE_KEY.value]);
    }
    throw ComponentsError.general(`Unsupported scheme: ${String(this._scheme)}`);
  }

  /**
   * Returns the untagged CBOR encoding.
   */
  untaggedCbor(): Cbor {
    if (this._scheme === EncapsulationScheme.X25519) {
      const pk = this._x25519PrivateKey;
      if (pk === undefined) throw ComponentsError.invalidData("X25519 private key not set");
      return cbor(pk.bytes);
    } else if (isMlkemScheme(this._scheme)) {
      const pk = this._mlkemPrivateKey;
      if (pk === undefined) throw ComponentsError.invalidData("MLKEM private key not set");
      return pk.untaggedCbor();
    }
    throw ComponentsError.general(`Unsupported scheme: ${String(this._scheme)}`);
  }

  /** The tagged CBOR form; the tag follows the scheme. */
  toCbor(): Cbor {
    return taggedCborOf(this);
  }

  /** Decode tagged (X25519 or ML-KEM) or untagged (X25519) CBOR. */
  static fromCbor(cborValue: Cbor): EncapsulationPrivateKey {
    return EncapsulationPrivateKey.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================
}
