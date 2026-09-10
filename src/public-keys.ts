/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * PublicKeys - Container for signing and encapsulation public keys
 *
 * PublicKeys combines a SigningPublicKey (for signature verification) and an
 * EncapsulationPublicKey (for key agreement/encryption) into a single unit.
 *
 * This is the public counterpart to PrivateKeys.
 *
 * # CBOR Serialization
 *
 * PublicKeys is serialized with tag 40017:
 * ```
 * #6.40017([<SigningPublicKey>, <EncapsulationPublicKey>])
 * ```
 *
 * # UR Serialization
 *
 * UR type: `crypto-pubkeys`
 *
 * Ported from bc-components-rust/src/public_keys.rs
 */

import { type Cbor, type Tag, cbor, expectArray, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "./codable.js";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { PUBLIC_KEYS as TAG_PUBLIC_KEYS } from "@blockchaincommons/tags";

import { SigningPublicKey } from "./signing/signing-public-key.js";
import { EncapsulationPublicKey } from "./encapsulation/encapsulation-public-key.js";
import type { EncapsulationCiphertext } from "./encapsulation/encapsulation-ciphertext.js";
import type { SymmetricKey } from "./symmetric/symmetric-key.js";
import type { Signature } from "./signing/signature.js";
import type { Verifier } from "./signing/signer.js";
import type { Encrypter } from "./encrypter.js";
import { Reference, type ReferenceProvider } from "./reference.js";
import { Digest } from "./digest.js";
import { ComponentsError } from "./error.js";

/**
 * Trait for types that provide access to a PublicKeys container.
 *
 * This is useful for types that wrap or contain public keys and need
 * to provide access to the underlying key material.
 */
export interface PublicKeysProvider {
  /**
   * Returns the PublicKeys container.
   */
  publicKeys(): PublicKeys;
}

/**
 * PublicKeys - Container for a signing public key and an encapsulation public key.
 *
 * This type provides a convenient way to share public keys for both
 * signature verification and encryption operations.
 */
export class PublicKeys implements Verifier, Encrypter, ReferenceProvider, ToCbor, ToUR {
  private readonly _signingPublicKey: SigningPublicKey;
  private readonly _encapsulationPublicKey: EncapsulationPublicKey;

  private constructor(
    signingPublicKey: SigningPublicKey,
    encapsulationPublicKey: EncapsulationPublicKey,
  ) {
    this._signingPublicKey = signingPublicKey;
    this._encapsulationPublicKey = encapsulationPublicKey;
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Create a new PublicKeys container with the given keys.
   */
  static new(
    signingPublicKey: SigningPublicKey,
    encapsulationPublicKey: EncapsulationPublicKey,
  ): PublicKeys {
    return new PublicKeys(signingPublicKey, encapsulationPublicKey);
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /**
   * Returns the signing public key.
   */
  signingPublicKey(): SigningPublicKey {
    return this._signingPublicKey;
  }

  /**
   * Returns the encapsulation public key.
   *
   * Note: Named to match Rust's API (which has a typo but we maintain compatibility)
   */
  encapsulationPublicKey(): EncapsulationPublicKey {
    return this._encapsulationPublicKey;
  }

  // ============================================================================
  // Verifier Interface
  // ============================================================================

  /**
   * Verify a signature against a message.
   */
  verify(signature: Signature, message: Uint8Array): boolean {
    return this._signingPublicKey.verify(signature, message);
  }

  // ============================================================================
  // Encrypter Interface
  // ============================================================================

  /**
   * Encapsulate a new shared secret using the encapsulation public key.
   *
   * This implements the Encrypter interface, allowing PublicKeys to be used
   * in encryption contexts where a shared secret needs to be generated.
   *
   * @returns A tuple of [SymmetricKey, EncapsulationCiphertext]
   */
  encapsulateNewSharedSecret(): [SymmetricKey, EncapsulationCiphertext] {
    return this._encapsulationPublicKey.encapsulateNewSharedSecret();
  }

  // ============================================================================
  // ReferenceProvider Interface
  // ============================================================================

  /**
   * Returns a unique reference to this PublicKeys instance.
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
   * Compare with another PublicKeys.
   */
  equals(other: PublicKeys): boolean {
    return (
      this._signingPublicKey.equals(other._signingPublicKey) &&
      this._encapsulationPublicKey.equals(other._encapsulationPublicKey)
    );
  }

  /**
   * Get string representation.
   *
   * Mirrors Rust `Display for PublicKeys`
   * (`bc-components-rust/src/public_keys.rs:216-225`):
   *   `PublicKeys(<short_reference>, <signing_public_key>, <encapsulation_public_key>)`
   *
   * The earlier short form (`PublicKeys(<short_reference>)`) was
   * observable in envelope notation as a missing key fingerprint
   * trail in the GSTP `'sender': XID(...) [ 'key': PublicKeys(...) ]`
   * format-pin (G1 in `PARITY_OUTSTANDING.md`).
   */
  toString(): string {
    return `PublicKeys(${this.reference().shortReference(
      "hex",
    )}, ${this._signingPublicKey.toString()}, ${this._encapsulationPublicKey.toString()})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static readonly codec: ComponentCodec<PublicKeys> = defineCodec({
    tags: [TAG_PUBLIC_KEYS],
    decodeUntagged: (cborValue) => {
      const elements = expectArray(cborValue);

      if (elements.length !== 2) {
        throw ComponentsError.invalidData(
          `PublicKeys must have 2 elements, got ${elements.length}`,
        );
      }

      const signingPublicKey = SigningPublicKey.fromCbor(elements[0]);
      const encapsulationPublicKey = EncapsulationPublicKey.fromCbor(elements[1]);

      return new PublicKeys(signingPublicKey, encapsulationPublicKey);
    },
    encodeUntagged: (value) => value.untaggedCbor(),
  });

  cborTags(): Tag[] {
    return [...PublicKeys.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: [<SigningPublicKey>, <EncapsulationPublicKey>]
   */
  untaggedCbor(): Cbor {
    return cbor([this._signingPublicKey.toCbor(), this._encapsulationPublicKey.toCbor()]);
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
  static fromCbor(cborValue: Cbor): PublicKeys {
    return PublicKeys.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}
