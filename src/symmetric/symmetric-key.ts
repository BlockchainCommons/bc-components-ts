import { secureRng, randomBytes, type RngOptions } from "@blockchaincommons/rand";
import { chacha20Poly1305 } from "@blockchaincommons/crypto";
import { type Cbor, type Tag, cbor, expectBytes, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "../codable.js";
import { TAG_SYMMETRIC_KEY } from "@blockchaincommons/tags";
import { type UR, urFor } from "@blockchaincommons/uniform-resources";
import { ComponentsError } from "../error.js";
import { bytesToHex, toBase64 } from "../utils.js";
import { bytesFromHex, guarded } from "../domain.js";
import { Nonce } from "../nonce.js";
import { EncryptedMessage } from "./encrypted-message.js";
import { Reference } from "../reference.js";
import { Digest } from "../digest.js";

const SYMMETRIC_KEY_SIZE = 32;

// The codec is built on first use so that an unused class tree-shakes away.
let SYMMETRIC_KEY_CODEC: ComponentCodec<SymmetricKey> | undefined;

/**
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
 */
export class SymmetricKey implements ToCbor {
  /** The byte length of a `SymmetricKey`. */
  static readonly SYMMETRIC_KEY_SIZE: number = SYMMETRIC_KEY_SIZE;

  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    if (data.length !== SYMMETRIC_KEY_SIZE) {
      throw ComponentsError.invalidSize("symmetric key", SYMMETRIC_KEY_SIZE, data.length);
    }
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /** A fresh random value; pass `rng` to make it deterministic. */
  static random({ rng = secureRng() }: RngOptions = {}): SymmetricKey {
    return new SymmetricKey(randomBytes(SYMMETRIC_KEY_SIZE, { rng: rng }));
  }

  /**
   * Create a new symmetric key from data.
   */
  static from(data: Uint8Array): SymmetricKey {
    return new SymmetricKey(new Uint8Array(data));
  }

  /**
   * Create a SymmetricKey from hex string.
   */
  static fromHex(hex: string): SymmetricKey {
    return SymmetricKey.from(bytesFromHex(hex));
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
    return `SymmetricKey(${this.refHexShort()})`;
  }

  // ============================================================================
  // Encryption/Decryption
  // ============================================================================

  /**
   * Encrypt the given plaintext with this key, and the given additional
   * authenticated data and nonce.
   */
  encrypt(
    plaintext: Uint8Array,
    { aad = new Uint8Array(0), nonce = Nonce.random() }: { aad?: Uint8Array; nonce?: Nonce } = {},
  ): EncryptedMessage {
    const effectiveNonce = nonce;
    const effectiveAad = aad;

    const sealed = chacha20Poly1305.encrypt(this._data, effectiveNonce.bytes, plaintext, {
      aad: effectiveAad,
    });
    const ciphertext = sealed.subarray(0, sealed.length - chacha20Poly1305.TAG_SIZE);
    const authTag = sealed.subarray(sealed.length - chacha20Poly1305.TAG_SIZE);

    return EncryptedMessage.from({
      ciphertext: ciphertext,
      aad: effectiveAad,
      nonce: effectiveNonce,
      authTag: authTag,
    });
  }

  /**
   * Decrypt the given encrypted message with this key.
   */
  decrypt(message: EncryptedMessage): Uint8Array {
    const ct = message.ciphertext;
    const tag = message.authenticationTag.bytes;
    const sealed = new Uint8Array(ct.length + tag.length);
    sealed.set(ct);
    sealed.set(tag, ct.length);
    return guarded("SymmetricKey.decrypt", () =>
      chacha20Poly1305.decrypt(this._data, message.nonce.bytes, sealed, { aad: message.aad }),
    );
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<SymmetricKey> {
    return (SYMMETRIC_KEY_CODEC ??= defineCodec({
      tags: [TAG_SYMMETRIC_KEY],
      decodeUntagged: (cbor) => {
        const data = expectBytes(cbor);
        return SymmetricKey.from(data);
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
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
