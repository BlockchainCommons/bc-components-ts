/**
 * Encapsulation ciphertext for key encapsulation mechanisms
 *
 * This type represents the ciphertext produced during key encapsulation.
 * For X25519, this is actually an ephemeral public key used in ECDH.
 * For MLKEM, this is the ciphertext from the ML-KEM encapsulation.
 *
 * # CBOR Serialization
 *
 * For X25519, the ciphertext is serialized with the X25519 public key tag (40011).
 * For MLKEM, the ciphertext is serialized with tag 40102.
 */

import { type Cbor, type Tag, cbor, expectBytes, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "../codable.js";
import { TAG_X25519_PUBLIC_KEY, TAG_MLKEM_CIPHERTEXT } from "@blockchaincommons/tags";
import { X25519PublicKey } from "../x25519/x25519-public-key.js";
import { EncapsulationScheme } from "./encapsulation-scheme.js";
import { MLKEMCiphertext } from "../mlkem/mlkem-ciphertext.js";
import { MLKEMLevel } from "../mlkem/mlkem-level.js";
import { bytesToHex } from "../utils.js";
import { ComponentsError } from "../error.js";
import { type UR, urFor } from "@blockchaincommons/uniform-resources";

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
let ENCAPSULATION_CIPHERTEXT_CODEC: ComponentCodec<EncapsulationCiphertext> | undefined;

/**
 * Represents the ciphertext from a key encapsulation operation.
 *
 * For X25519, this wraps an ephemeral public key.
 * For MLKEM, this wraps an MLKEMCiphertext.
 */
export class EncapsulationCiphertext implements ToCbor {
  private readonly _scheme: EncapsulationScheme;
  private readonly _x25519PublicKey: X25519PublicKey | undefined;
  private readonly _mlkemCiphertext: MLKEMCiphertext | undefined;

  private constructor(
    scheme: EncapsulationScheme,
    x25519PublicKey?: X25519PublicKey,
    mlkemCiphertext?: MLKEMCiphertext,
  ) {
    this._scheme = scheme;
    this._x25519PublicKey = x25519PublicKey;
    this._mlkemCiphertext = mlkemCiphertext;
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Create an EncapsulationCiphertext from an X25519PublicKey.
   */
  static fromX25519PublicKey(publicKey: X25519PublicKey): EncapsulationCiphertext {
    return new EncapsulationCiphertext(EncapsulationScheme.X25519, publicKey, undefined);
  }

  /**
   * Create an EncapsulationCiphertext from raw X25519 data.
   */
  static fromX25519Data(data: Uint8Array): EncapsulationCiphertext {
    const publicKey = X25519PublicKey.from(data);
    return EncapsulationCiphertext.fromX25519PublicKey(publicKey);
  }

  /**
   * Create an EncapsulationCiphertext from an MLKEMCiphertext.
   */
  static fromMlkem(ciphertext: MLKEMCiphertext): EncapsulationCiphertext {
    const scheme = mlkemLevelToScheme(ciphertext.level);
    return new EncapsulationCiphertext(scheme, undefined, ciphertext);
  }

  /**
   * Create an EncapsulationCiphertext from raw MLKEM ciphertext bytes.
   */
  static fromMlkemData(level: MLKEMLevel, data: Uint8Array): EncapsulationCiphertext {
    const ciphertext = MLKEMCiphertext.fromBytes(level, data);
    return EncapsulationCiphertext.fromMlkem(ciphertext);
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
   * Returns true if this is an X25519 ciphertext.
   */
  isX25519(): boolean {
    return this._scheme === EncapsulationScheme.X25519;
  }

  /**
   * Returns true if this is an MLKEM ciphertext.
   */
  isMlkem(): boolean {
    return isMlkemScheme(this._scheme);
  }

  /**
   * Returns the X25519 public key if this is an X25519 ciphertext.
   * @throws Error if this is not an X25519 ciphertext
   */
  x25519PublicKey(): X25519PublicKey {
    if (this._x25519PublicKey === undefined) {
      throw ComponentsError.invalidData("Not an X25519 ciphertext");
    }
    return this._x25519PublicKey;
  }

  /**
   * Returns the MLKEM ciphertext if this is an MLKEM ciphertext.
   * @throws Error if this is not an MLKEM ciphertext
   */
  mlkemCiphertext(): MLKEMCiphertext {
    if (this._mlkemCiphertext === undefined) {
      throw ComponentsError.invalidData("Not an MLKEM ciphertext");
    }
    return this._mlkemCiphertext;
  }

  /**
   * Returns the X25519 public key if available, or null.
   */
  asX25519(): X25519PublicKey | undefined {
    return this._x25519PublicKey ?? undefined;
  }

  /**
   * Returns the MLKEM ciphertext if available, or null.
   */
  asMlkem(): MLKEMCiphertext | undefined {
    return this._mlkemCiphertext ?? undefined;
  }

  /** The bytes (a view; do not mutate). */
  get bytes(): Uint8Array {
    if (this._scheme === EncapsulationScheme.X25519) {
      const pk = this._x25519PublicKey;
      if (pk === undefined) throw ComponentsError.invalidData("X25519 public key not set");
      return pk.bytes;
    } else if (isMlkemScheme(this._scheme)) {
      const ct = this._mlkemCiphertext;
      if (ct === undefined) throw ComponentsError.invalidData("MLKEM ciphertext not set");
      return ct.bytes;
    }
    throw ComponentsError.general(`Unsupported scheme: ${String(this._scheme)}`);
  }

  /**
   * Compare with another EncapsulationCiphertext.
   */
  equals(other: EncapsulationCiphertext): boolean {
    if (this._scheme !== other._scheme) return false;
    if (this._scheme === EncapsulationScheme.X25519) {
      const thisPk = this._x25519PublicKey;
      const otherPk = other._x25519PublicKey;
      if (thisPk === undefined || otherPk === undefined) return false;
      return thisPk.equals(otherPk);
    } else if (isMlkemScheme(this._scheme)) {
      const thisCt = this._mlkemCiphertext;
      const otherCt = other._mlkemCiphertext;
      if (thisCt === undefined || otherCt === undefined) return false;
      return thisCt.equals(otherCt);
    }
    return false;
  }

  /**
   * Get string representation.
   */
  toString(): string {
    if (this._scheme === EncapsulationScheme.X25519) {
      return `EncapsulationCiphertext(X25519, ${bytesToHex(this.bytes).substring(0, 16)}...)`;
    } else if (isMlkemScheme(this._scheme)) {
      return `EncapsulationCiphertext(${String(this._scheme)}, ${bytesToHex(this.bytes).substring(0, 16)}...)`;
    }
    return `EncapsulationCiphertext(${String(this._scheme)})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; the tag selects the scheme, untagged bytes are X25519. */
  static get codec(): ComponentCodec<EncapsulationCiphertext> {
    return (ENCAPSULATION_CIPHERTEXT_CODEC ??= defineCodec({
      tags: [TAG_X25519_PUBLIC_KEY, TAG_MLKEM_CIPHERTEXT],
      decodeUntagged: (cborValue) =>
        EncapsulationCiphertext.fromX25519PublicKey(X25519PublicKey.from(expectBytes(cborValue))),
      decodeTagged: (tag, content, whole) =>
        tag.value === TAG_MLKEM_CIPHERTEXT.value
          ? EncapsulationCiphertext.fromMlkem(MLKEMCiphertext.fromCbor(whole))
          : EncapsulationCiphertext.codec.decodeUntagged(content),
      encodeUntagged: (value) => value.untaggedCbor(),
      encode: (value) => value.toCbor(),
    }));
  }

  /**
   * Returns the CBOR tags associated with this ciphertext.
   */
  cborTags(): Tag[] {
    if (this._scheme === EncapsulationScheme.X25519) {
      return [TAG_X25519_PUBLIC_KEY];
    } else if (isMlkemScheme(this._scheme)) {
      return [TAG_MLKEM_CIPHERTEXT];
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
      const ct = this._mlkemCiphertext;
      if (ct === undefined) throw ComponentsError.invalidData("MLKEM ciphertext not set");
      return ct.untaggedCbor();
    }
    throw ComponentsError.general(`Unsupported scheme: ${String(this._scheme)}`);
  }

  /** The tagged CBOR form; the tag follows the scheme. */
  toCbor(): Cbor {
    return taggedCborOf(this);
  }

  /** As a UR, typed by the scheme's tag name. */
  toUR(): UR {
    return urFor(this);
  }

  /** Decode tagged (X25519 or ML-KEM) or untagged (X25519) CBOR. */
  static fromCbor(cborValue: Cbor): EncapsulationCiphertext {
    return EncapsulationCiphertext.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================
}
