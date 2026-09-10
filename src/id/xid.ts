/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * eXtensible Identifier (XID) - 32-byte identifier bound to a public key
 *
 * A XID is a unique 32-byte identifier for a subject entity (person,
 * organization, device, or any other entity). XIDs have the following
 * characteristics:
 *
 * - They're cryptographically tied to a public key at inception (the
 *   "inception key")
 * - They remain stable throughout their lifecycle even as their keys and
 *   permissions change
 * - They can be extended to XID documents containing keys, endpoints,
 *   permissions, and delegation info
 * - They support key rotation and multiple verification schemes
 * - They allow for delegation of specific permissions to other entities
 * - They can include resolution methods to locate and verify the XID document
 *
 * A XID is created by taking the SHA-256 hash of the CBOR encoding of a public
 * signing key. This ensures the XID is cryptographically tied to the key.
 *
 * As defined in [BCR-2024-010](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2024-010-xid.md).
 *
 * # CBOR Serialization
 *
 * `XID` is serialized to CBOR with tag 40024 (standard XID tag).
 *
 * # UR Serialization
 *
 * When serialized as a Uniform Resource (UR), a `XID` is represented with the
 * type "xid".
 */

import { type Cbor, type Tag, cbor, expectBytes, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "../codable.js";
import { XID as TAG_XID } from "@blockchaincommons/tags";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { shortIdentifier } from "@blockchaincommons/uniform-resources/bytewords";
import { ComponentsError } from "../error.js";
import { bytesToHex, toBase64 } from "../utils.js";
import { Digest } from "../digest.js";
import { Reference, type ReferenceProvider } from "../reference.js";
import type { SigningPublicKey } from "../signing/signing-public-key.js";
import type { SigningPrivateKey } from "../signing/signing-private-key.js";
import type { PublicKeys } from "../public-keys.js";
import type { PrivateKeyBase } from "../private-key-base.js";
import { type RandomNumberGenerator, randomBytes, secureRng } from "@blockchaincommons/rand";

/**
 * XID prefix glyph for the upper-case bytewords/bytemoji identifier.
 *
 * Exported as the single source of truth so dependent packages (`@blockchaincommons/xid`,
 * `@blockchaincommons/envelope`, etc.) don't redefine the literal `"🅧"`.
 */
export const XID_PREFIX = "🅧";

const XID_SIZE = 32;

/**
 * Trait-style interface for objects that can produce a XID.
 *
 * other type that maps cleanly to a single XID (e.g. `SigningPublicKey`,
 * `PublicKeys`) may also implement it.
 */
export interface XIDProvider {
  /** Returns the XID for this object. */
  xid(): XID;
}

// The codec is built on first use so that an unused class tree-shakes away.
let X_I_D_CODEC: ComponentCodec<XID> | undefined;

/**
 * Type guard for {@link XIDProvider}.
 */
export function isXIDProvider(obj: unknown): obj is XIDProvider {
  return (
    typeof obj === "object" &&
    obj !== null &&
    "xid" in obj &&
    typeof (obj as XIDProvider).xid === "function"
  );
}

export class XID implements ToCbor, ToUR, XIDProvider, ReferenceProvider {
  static readonly XID_SIZE: number = XID_SIZE;

  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    if (data.length !== XID_SIZE) {
      throw ComponentsError.invalidSize(XID_SIZE, data.length);
    }
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Create a new XID from data.
   */
  static from(data: Uint8Array): XID {
    return new XID(new Uint8Array(data));
  }

  /**
   * Create an XID from hex string (64 hex characters).
   */
  static fromHex(hex: string): XID {
    if (hex.length !== 64) {
      throw ComponentsError.invalidFormat(`XID hex must be 64 characters, got ${hex.length}`);
    }
    const data = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      data[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return new XID(data);
  }

  /**
   * Generate a random XID (for testing purposes).
   *
   * Note: In practice, XIDs should be created from the SHA-256 hash of a
   * public signing key's CBOR encoding.
   */
  static random({ rng = secureRng() }: { rng?: RandomNumberGenerator } = {}): XID {
    return new XID(randomBytes(XID_SIZE, { rng }));
  }

  /**
   * Derived from the SHA-256 digest of the key's tagged CBOR.
   */
  static fromSigningPublicKey(signingPublicKey: SigningPublicKey): XID {
    return XID.from(Digest.fromImage(signingPublicKey.toCbor().toData()).bytes);
  }

  /**
   * The XID is derived from the bundle's signing public key.
   */
  static fromPublicKeys(publicKeys: PublicKeys): XID {
    return XID.fromSigningPublicKey(publicKeys.signingPublicKey);
  }

  /**
   * The XID is derived from the schnorr signing public key.
   */
  static fromPrivateKeyBase(base: PrivateKeyBase): XID {
    return XID.fromSigningPublicKey(base.schnorrSigningPrivateKey().publicKey());
  }

  /**
   * The XID is derived from the corresponding public key.
   */
  static tryFromSigningPrivateKey(signingPrivateKey: SigningPrivateKey): XID {
    return XID.fromSigningPublicKey(signingPrivateKey.publicKey());
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /**
   * Validate the XID against the given public key.
   *
   * Returns true if the SHA-256 hash of the key's CBOR encoding matches
   * the XID data. This matches the reference implementation's `XID::validate(&self, key: &SigningPublicKey)`.
   */
  validate(signingPublicKey: SigningPublicKey): boolean {
    const keyData = signingPublicKey.toCbor().toData();
    const digest = Digest.fromImage(keyData);
    return this.equals(XID.from(digest.bytes));
  }

  /** The bytes (a view; do not mutate). */
  get bytes(): Uint8Array {
    return this._data;
  }

  /**
   * Get hex string representation (lowercase, as the reference implementation does implementation).
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
   * Get short description (first 4 bytes) as hex.
   */
  shortDescription(): string {
    return bytesToHex(this._data.slice(0, 4));
  }

  /**
   * Get short reference (first 4 bytes) as hex (alias for shortDescription).
   */
  shortReference(): string {
    return this.shortDescription();
  }

  /**
   * Get the first four bytes of the XID as upper-case ByteWords.
   *
   * @param prefix - If true, prepends the XID prefix "🅧 "
   * @returns Space-separated uppercase bytewords, e.g., "🅧 URGE DICE GURU IRIS"
   */
  bytewordsIdentifier(prefix = false): string {
    const words = shortIdentifier(this._data.slice(0, 4)).toUpperCase();
    return prefix ? `${XID_PREFIX} ${words}` : words;
  }

  /**
   * Get the first four bytes of the XID as Bytemoji.
   *
   * @param prefix - If true, prepends the XID prefix "🅧 "
   * @returns Space-separated emojis, e.g., "🅧 🐻 😻 🍞 💐"
   */
  bytemojisIdentifier(prefix = false): string {
    const emojis = shortIdentifier(this._data.slice(0, 4), { style: "bytemoji" });
    return prefix ? `${XID_PREFIX} ${emojis}` : emojis;
  }

  /**
   * XIDProvider impl — returns this XID.
   *
   */
  xid(): XID {
    return this;
  }

  /**
   * ReferenceProvider impl — produces a Reference whose 32 bytes are the
   * raw XID data.
   *
   * Reference { Reference::from_data(*self.bytes) } }` — note this is a
   * direct wrap, not a SHA-256 hash of the XID.
   */
  reference(): Reference {
    return Reference.from(this._data);
  }

  /**
   * Compare with another XID.
   */
  equals(other: XID): boolean {
    if (this._data.length !== other._data.length) return false;
    for (let i = 0; i < this._data.length; i++) {
      if (this._data[i] !== other._data[i]) return false;
    }
    return true;
  }

  /**
   * Get string representation (short format, as the reference implementation does Display).
   * Uses first 4 bytes of the XID as hex, e.g., "XID(71274df1)".
   */
  toString(): string {
    return `XID(${this.shortDescription()})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<XID> {
    return (X_I_D_CODEC ??= defineCodec({
      tags: [TAG_XID],
      decodeUntagged: (cbor) => {
        const data = expectBytes(cbor);
        return XID.from(data);
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  cborTags(): Tag[] {
    return [...XID.codec.tags];
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
  static fromCbor(cbor: Cbor): XID {
    return XID.codec.decode(cbor);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
