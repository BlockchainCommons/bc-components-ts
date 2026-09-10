/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * Sealed message for anonymous authenticated encryption
 *
 * A `SealedMessage` combines key encapsulation with symmetric encryption to
 * provide anonymous authenticated encryption. The sender's identity is not
 * revealed, and only the intended recipient can decrypt the message.
 *
 * The sealing process:
 * 1. Encapsulate a new shared secret using the recipient's public key
 * 2. Use the shared secret to encrypt the plaintext with ChaCha20-Poly1305
 * 3. Return the encrypted message and the encapsulation ciphertext
 *
 * The unsealing process:
 * 1. Decapsulate the shared secret using the recipient's private key
 * 2. Use the shared secret to decrypt the ciphertext
 * 3. Return the plaintext
 *
 * Features:
 * - Anonymous sender (sender identity not revealed)
 * - Authenticated encryption
 * - Forward secrecy (each message uses different ephemeral key)
 *
 * # CBOR Serialization
 *
 * `SealedMessage` is serialized as a 2-element array with tag 40019:
 *
 * ```cddl
 * SealedMessage = #6.40019([
 *   message: EncryptedMessage,
 *   encapsulated_key: EncapsulationCiphertext
 * ])
 * ```
 *
 * # UR Serialization
 *
 * When serialized as a Uniform Resource (UR), a `SealedMessage` is
 * represented with the type "crypto-sealed".
 *
 * Ported from bc-components-rust/src/encapsulation/sealed_message.rs
 */

import { type Cbor, type Tag, cbor, expectArray, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "../codable.js";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { SEALED_MESSAGE as TAG_SEALED_MESSAGE } from "@blockchaincommons/tags";
import { Nonce } from "../nonce.js";
import { EncryptedMessage } from "../symmetric/encrypted-message.js";
import { type EncapsulationScheme } from "./encapsulation-scheme.js";
import { EncapsulationCiphertext } from "./encapsulation-ciphertext.js";
import { type EncapsulationPublicKey } from "./encapsulation-public-key.js";
import { type EncapsulationPrivateKey } from "./encapsulation-private-key.js";
import { bytesToHex } from "../utils.js";
import { ComponentsError } from "../error.js";

/**
 * A sealed message providing anonymous authenticated encryption.
 */
export class SealedMessage implements ToCbor, ToUR {
  private readonly _message: EncryptedMessage;
  private readonly _encapsulatedKey: EncapsulationCiphertext;

  private constructor(message: EncryptedMessage, encapsulatedKey: EncapsulationCiphertext) {
    this._message = message;
    this._encapsulatedKey = encapsulatedKey;
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Create a SealedMessage from its components.
   */
  static from(message: EncryptedMessage, encapsulatedKey: EncapsulationCiphertext): SealedMessage {
    return new SealedMessage(message, encapsulatedKey);
  }

  /**
   * Encrypt `plaintext` to `recipient`: a fresh shared secret is
   * encapsulated to the recipient's key and encrypts the plaintext.
   */
  static seal(
    plaintext: Uint8Array,
    recipient: EncapsulationPublicKey,
    { aad = new Uint8Array(0), nonce = Nonce.random() }: { aad?: Uint8Array; nonce?: Nonce } = {},
  ): SealedMessage {
    const [sharedSecret, ciphertext] = recipient.encapsulateNewSharedSecret();
    const encryptedMessage = sharedSecret.encrypt(plaintext, aad, nonce);
    return new SealedMessage(encryptedMessage, ciphertext);
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /**
   * Returns the encrypted message.
   */
  get message(): EncryptedMessage {
    return this._message;
  }

  /**
   * Returns the encapsulation ciphertext (ephemeral public key for X25519).
   */
  get encapsulatedKey(): EncapsulationCiphertext {
    return this._encapsulatedKey;
  }

  /**
   * Returns the encapsulation scheme used.
   */
  get encapsulationScheme(): EncapsulationScheme {
    return this._encapsulatedKey.encapsulationScheme;
  }

  /**
   * Decrypt the sealed message using the recipient's private key.
   *
   * @param privateKey - The recipient's private key
   * @returns The decrypted plaintext
   * @throws Error if decryption fails
   */
  decrypt(privateKey: EncapsulationPrivateKey): Uint8Array {
    // Decapsulate the shared secret
    const sharedSecret = privateKey.decapsulateSharedSecret(this._encapsulatedKey);

    // Decrypt the message
    return sharedSecret.decrypt(this._message);
  }

  /**
   * Compare with another SealedMessage.
   */
  equals(other: SealedMessage): boolean {
    return (
      this._message.equals(other._message) && this._encapsulatedKey.equals(other._encapsulatedKey)
    );
  }

  /**
   * Get string representation.
   */
  toString(): string {
    return `SealedMessage(${this._encapsulatedKey.encapsulationScheme}, ciphertext: ${bytesToHex(this._message.ciphertext).substring(0, 16)}...)`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static readonly codec: ComponentCodec<SealedMessage> = defineCodec({
    tags: [TAG_SEALED_MESSAGE],
    decodeUntagged: (cborValue) => {
      const elements = expectArray(cborValue);

      if (elements.length !== 2) {
        throw ComponentsError.invalidData(
          `SealedMessage must have 2 elements, got ${elements.length}`,
        );
      }

      // Decode the encrypted message (tagged)
      const message = EncryptedMessage.fromCbor(elements[0]);

      // Decode the encapsulation ciphertext (tagged)
      const encapsulatedKey = EncapsulationCiphertext.fromCbor(elements[1]);

      return new SealedMessage(message, encapsulatedKey);
    },
    encodeUntagged: (value) => value.untaggedCbor(),
  });

  cborTags(): Tag[] {
    return [...SealedMessage.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding.
   * Format: [EncryptedMessage (tagged), EncapsulationCiphertext (tagged)]
   */
  untaggedCbor(): Cbor {
    const elements: Cbor[] = [this._message.toCbor(), this._encapsulatedKey.toCbor()];
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
  static fromCbor(cborValue: Cbor): SealedMessage {
    return SealedMessage.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
