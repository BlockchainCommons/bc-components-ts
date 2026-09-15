import {
  type Cbor,
  type Tag,
  cbor,
  expectBytes,
  decodeCbor,
  type ToCbor,
  asArray,
  CborError,
} from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "../codable.js";
import { TAG_ENCRYPTED } from "@blockchaincommons/tags";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { Nonce } from "../nonce.js";
import { Digest } from "../digest.js";
import { AuthenticationTag } from "./authentication-tag.js";
import { bytesToHex } from "../utils.js";

// The codec is built on first use so that an unused class tree-shakes away.
let ENCRYPTED_MESSAGE_CODEC: ComponentCodec<EncryptedMessage> | undefined;

/**
 * Encrypted message with ChaCha20-Poly1305 AEAD
 *
 * A secure encrypted message using IETF ChaCha20-Poly1305 authenticated
 * encryption.
 *
 * `EncryptedMessage` represents data that has been encrypted using a symmetric
 * key with the ChaCha20-Poly1305 AEAD (Authenticated Encryption with
 * Associated Data) construction as specified in [RFC-8439](https://datatracker.ietf.org/doc/html/rfc8439).
 *
 * An `EncryptedMessage` contains:
 * - `ciphertext`: The encrypted data (same length as the original plaintext)
 * - `aad`: Additional Authenticated Data that is not encrypted but is
 *   authenticated (optional)
 * - `nonce`: A 12-byte number used once for this specific encryption operation
 * - `auth`: A 16-byte authentication tag that verifies the integrity of the
 *   message
 *
 * The `aad` field is often used to include the `Digest` of the plaintext,
 * which allows verification of the plaintext after decryption and preserves
 * the unique identity of the data when used with structures like Gordian
 * Envelope.
 *
 * # CBOR Serialization
 *
 * `EncryptedMessage` is serialized to CBOR with tag 40002.
 *
 * CDDL:
 * ```text
 * EncryptedMessage =
 *     #6.40002([ ciphertext: bstr, nonce: bstr, auth: bstr, ? aad: bstr ])
 * ```
 *
 * # UR Serialization
 *
 * When serialized as a Uniform Resource (UR), an `EncryptedMessage` is
 * represented with the type "encrypted".
 */
export class EncryptedMessage implements ToCbor, ToUR {
  private readonly _ciphertext: Uint8Array;
  private readonly _aad: Uint8Array;
  private readonly _nonce: Nonce;
  private readonly _auth: AuthenticationTag;

  private constructor(
    ciphertext: Uint8Array,
    aad: Uint8Array,
    nonce: Nonce,
    auth: AuthenticationTag,
  ) {
    this._ciphertext = new Uint8Array(ciphertext);
    this._aad = new Uint8Array(aad);
    this._nonce = nonce;
    this._auth = auth;
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /** Assemble a message from its parts (no encryption happens here). */
  static from({
    ciphertext,
    nonce,
    authTag,
    aad = new Uint8Array(0),
  }: {
    ciphertext: Uint8Array;
    nonce: Nonce;
    authTag: AuthenticationTag | Uint8Array;
    aad?: Uint8Array;
  }): EncryptedMessage {
    const tag = authTag instanceof AuthenticationTag ? authTag : AuthenticationTag.from(authTag);
    return new EncryptedMessage(ciphertext, aad, nonce, tag);
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /**
   * Returns a reference to the ciphertext data.
   */
  /** A copy of the ciphertext. */
  get ciphertext(): Uint8Array {
    return new Uint8Array(this._ciphertext);
  }

  /**
   * Returns a reference to the additional authenticated data (AAD).
   */
  /** A copy of the additional authenticated data. */
  get aad(): Uint8Array {
    return new Uint8Array(this._aad);
  }

  /**
   * Returns a reference to the nonce value used for encryption.
   */
  get nonce(): Nonce {
    return this._nonce;
  }

  /**
   * Returns a reference to the authentication tag value used for encryption.
   */
  get authenticationTag(): AuthenticationTag {
    return this._auth;
  }

  /**
   * Returns a CBOR representation in the AAD field, if it exists.
   */
  aadCbor(): Cbor | null {
    if (this._aad.length === 0) {
      return null;
    }
    try {
      return decodeCbor(this._aad);
    } catch {
      return null;
    }
  }

  /**
   * Returns a Digest instance if the AAD data can be parsed as CBOR.
   */
  aadDigest(): Digest | null {
    const aadCbor = this.aadCbor();
    if (aadCbor === null) {
      return null;
    }
    try {
      return Digest.fromCbor(aadCbor);
    } catch {
      return null;
    }
  }

  /**
   * Returns true if the AAD data can be parsed as a Digest.
   */
  hasDigest(): boolean {
    return this.aadDigest() !== null;
  }

  /**
   * Compare with another EncryptedMessage.
   */
  equals(other: EncryptedMessage): boolean {
    if (this._ciphertext.length !== other._ciphertext.length) return false;
    for (let i = 0; i < this._ciphertext.length; i++) {
      if (this._ciphertext[i] !== other._ciphertext[i]) return false;
    }
    if (this._aad.length !== other._aad.length) return false;
    for (let i = 0; i < this._aad.length; i++) {
      if (this._aad[i] !== other._aad[i]) return false;
    }
    return this._nonce.equals(other._nonce) && this._auth.equals(other._auth);
  }

  /**
   * Get string representation.
   */
  toString(): string {
    return `EncryptedMessage(ciphertext: ${bytesToHex(this._ciphertext).substring(0, 16)}..., nonce: ${this._nonce.toHex()}, auth: ${this._auth.toHex()})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<EncryptedMessage> {
    return (ENCRYPTED_MESSAGE_CODEC ??= defineCodec({
      tags: [TAG_ENCRYPTED],
      decodeUntagged: (cborValue) => {
        const elements = asArray(cborValue);
        if (elements === undefined) throw CborError.custom("EncryptedMessage must be an array");
        if (elements.length < 3) {
          throw CborError.custom("EncryptedMessage must have at least 3 elements");
        }

        const ciphertext = expectBytes(elements[0]);
        const nonceData = expectBytes(elements[1]);
        const nonce = Nonce.from(nonceData);
        const authData = expectBytes(elements[2]);
        const auth = AuthenticationTag.from(authData);
        const aad = elements.length > 3 ? expectBytes(elements[3]) : new Uint8Array(0);

        return EncryptedMessage.from({
          ciphertext: ciphertext,
          aad: aad,
          nonce: nonce,
          authTag: auth,
        });
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...EncryptedMessage.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding (as an array).
   * Array format: [ciphertext, nonce, auth, ?aad]
   */
  untaggedCbor(): Cbor {
    const elements: Cbor[] = [
      cbor(this._ciphertext),
      cbor(this._nonce.bytes),
      cbor(this._auth.bytes),
    ];

    if (this._aad.length > 0) {
      elements.push(cbor(this._aad));
    }

    return cbor(elements);
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
  static fromCbor(cborValue: Cbor): EncryptedMessage {
    return EncryptedMessage.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
