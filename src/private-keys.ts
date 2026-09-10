/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * PrivateKeys - Container for signing and encapsulation private keys
 *
 * PrivateKeys combines a SigningPrivateKey (for digital signatures) and an
 * EncapsulationPrivateKey (for key agreement/encryption) into a single unit.
 *
 * # CBOR Serialization
 *
 * PrivateKeys is serialized with tag 40013:
 * ```
 * #6.40013([<SigningPrivateKey>, <EncapsulationPrivateKey>])
 * ```
 *
 * # UR Serialization
 *
 * UR type: `crypto-prvkeys`
 *
 * Ported from bc-components-rust/src/private_keys.rs
 */

import { type Cbor, type Tag, cbor, expectArray, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "./codable.js";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { PRIVATE_KEYS as TAG_PRIVATE_KEYS } from "@blockchaincommons/tags";

import { SigningPrivateKey } from "./signing/signing-private-key.js";
import { EncapsulationPrivateKey } from "./encapsulation/encapsulation-private-key.js";
import { PublicKeys } from "./public-keys.js";
import type { SymmetricKey } from "./symmetric/symmetric-key.js";
import type { EncapsulationCiphertext } from "./encapsulation/encapsulation-ciphertext.js";
import type { Signature } from "./signing/signature.js";
import type { Signer } from "./signing/signer.js";
import type { SigningOptions } from "./signing/signature-scheme.js";
import type { Decrypter } from "./encrypter.js";
import { Reference, type ReferenceProvider } from "./reference.js";
import { Digest } from "./digest.js";
import { ComponentsError } from "./error.js";

/**
 * Trait for types that provide access to a PrivateKeys container.
 *
 * This is useful for types that wrap or contain private keys and need
 * to provide access to the underlying key material.
 */
export interface PrivateKeysProvider {
  /**
   * Returns the PrivateKeys container.
   */
  privateKeys(): PrivateKeys;
}

/**
 * PrivateKeys - Container for a signing key and an encapsulation key.
 *
 * This type provides a convenient way to manage a pair of private keys
 * for both signing and encryption operations.
 */
export class PrivateKeys implements Signer, Decrypter, ReferenceProvider, ToCbor, ToUR {
  private readonly _signingPrivateKey: SigningPrivateKey;
  private readonly _encapsulationPrivateKey: EncapsulationPrivateKey;

  private constructor(
    signingPrivateKey: SigningPrivateKey,
    encapsulationPrivateKey: EncapsulationPrivateKey,
  ) {
    this._signingPrivateKey = signingPrivateKey;
    this._encapsulationPrivateKey = encapsulationPrivateKey;
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Create a new PrivateKeys container with the given keys.
   */
  static withKeys(
    signingPrivateKey: SigningPrivateKey,
    encapsulationPrivateKey: EncapsulationPrivateKey,
  ): PrivateKeys {
    return new PrivateKeys(signingPrivateKey, encapsulationPrivateKey);
  }

  /**
   * Create a new PrivateKeys container with random Ed25519/X25519 keys.
   */
  static new(): PrivateKeys {
    const signingKey = SigningPrivateKey.random();
    const encapsulationKey = EncapsulationPrivateKey.random();
    return new PrivateKeys(signingKey, encapsulationKey);
  }

  /**
   * Generate a new PrivateKeys container with random Ed25519/X25519 keys.
   * This is an alias for new() for API compatibility.
   */
  static generate(): PrivateKeys {
    return PrivateKeys.new();
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /**
   * Returns the signing private key.
   */
  signingPrivateKey(): SigningPrivateKey {
    return this._signingPrivateKey;
  }

  /**
   * Returns the encapsulation private key.
   *
   * Note: Named to match Rust's API (which has a typo but we maintain compatibility)
   */
  encapsulationPrivateKey(): EncapsulationPrivateKey {
    return this._encapsulationPrivateKey;
  }

  /**
   * Derive the corresponding public keys.
   */
  publicKeys(): PublicKeys {
    const signingPublicKey = this._signingPrivateKey.publicKey();
    const encapsulationPublicKey = this._encapsulationPrivateKey.publicKey();
    return PublicKeys.new(signingPublicKey, encapsulationPublicKey);
  }

  // ============================================================================
  // Signer Interface
  // ============================================================================

  /**
   * Sign a message with optional signing options using the signing private key.
   */
  signWithOptions(message: Uint8Array, options?: SigningOptions): Signature {
    return this._signingPrivateKey.signWithOptions(message, options);
  }

  /**
   * Sign a message using the signing private key.
   */
  sign(message: Uint8Array): Signature {
    return this._signingPrivateKey.sign(message);
  }

  // ============================================================================
  // Decrypter Interface
  // ============================================================================

  /**
   * Decapsulate a shared secret from a ciphertext.
   *
   * This implements the Decrypter interface, allowing PrivateKeys to be used
   * in encryption contexts where a shared secret needs to be recovered.
   */
  decapsulateSharedSecret(ciphertext: EncapsulationCiphertext): SymmetricKey {
    return this._encapsulationPrivateKey.decapsulateSharedSecret(ciphertext);
  }

  // ============================================================================
  // ReferenceProvider Interface
  // ============================================================================

  /**
   * Returns a unique reference to this PrivateKeys instance.
   *
   * The reference is derived from the SHA-256 hash of the tagged CBOR
   * representation, providing a unique, content-addressable identifier.
   */
  reference(): Reference {
    const digest = Digest.fromImage(this.toCbor().toData());
    return Reference.from(digest);
  }

  // ============================================================================
  // Equality and String Representation
  // ============================================================================

  /**
   * Compare with another PrivateKeys.
   */
  equals(other: PrivateKeys): boolean {
    return (
      this._signingPrivateKey.equals(other._signingPrivateKey) &&
      this._encapsulationPrivateKey.equals(other._encapsulationPrivateKey)
    );
  }

  /**
   * Mirror of Rust `Display for PrivateKeys`
   * (`bc-components-rust/src/private_keys.rs:229-238`):
   *   `PrivateKeys(<refHexShort>, <signingPrivateKey>, <encapsulationPrivateKey>)`
   * The previous abbreviated form (`PrivateKeys(<short>)` only) was a
   * parity drift caught by the E1a summarizer audit.
   */
  toString(): string {
    return `PrivateKeys(${this.reference().shortReference(
      "hex",
    )}, ${this._signingPrivateKey.toString()}, ${this._encapsulationPrivateKey.toString()})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static readonly codec: ComponentCodec<PrivateKeys> = defineCodec({
    tags: [TAG_PRIVATE_KEYS],
    decodeUntagged: (cborValue) => {
      const elements = expectArray(cborValue);

      if (elements.length !== 2) {
        throw ComponentsError.invalidData(
          `PrivateKeys must have 2 elements, got ${elements.length}`,
        );
      }

      const signingPrivateKey = SigningPrivateKey.fromCbor(elements[0]);
      const encapsulationPrivateKey = EncapsulationPrivateKey.fromCbor(elements[1]);

      return new PrivateKeys(signingPrivateKey, encapsulationPrivateKey);
    },
    encodeUntagged: (value) => value.untaggedCbor(),
  });

  cborTags(): Tag[] {
    return [...PrivateKeys.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: [<SigningPrivateKey>, <EncapsulationPrivateKey>]
   */
  untaggedCbor(): Cbor {
    return cbor([this._signingPrivateKey.toCbor(), this._encapsulationPrivateKey.toCbor()]);
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
  static fromCbor(cborValue: Cbor): PrivateKeys {
    return PrivateKeys.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
