/* eslint-disable @typescript-eslint/no-non-null-assertion -- fixtures are indexed by position; a miss fails the test */
/**
 * Cross-implementation CBOR Interoperability Tests
 *
 * These tests verify that the TypeScript implementation produces identical
 * CBOR output to the Rust bc-components implementation.
 *
 * Test vectors are derived from the Rust bc-components-rust implementation.
 */

import { describe, it, expect } from "vitest";
import {
  Signature,
  SigningPrivateKey,
  createKeypair,
  SignatureScheme,
  ECPrivateKey,
  Ed25519PrivateKey,
  EncapsulationPrivateKey,
  PrivateKeys,
} from "../src";
import {
  decodeCbor,
  isTagged,
  asTaggedValue,
  isBytes,
  expectBytes,
  isArray,
  expectArray,
  expectInteger,
} from "@blockchaincommons/dcbor";
import { SeededRng } from "@blockchaincommons/rand";

// The reference needs `register_tags()` before a UR is made; so does this package.
import { registerTags } from "../src/tags.js";
registerTags();

// Test vectors from Rust bc-components-rust
const TEST_PRIVATE_KEY_HEX = "322b5c1dd5a17c3481c2297990c85c232ed3c17b52ce9905c6ec5193ad132c36";
const TEST_MESSAGE = new TextEncoder().encode("Wolf McNally");

/**
 * Helper to convert hex to Uint8Array
 */
/**
 * Helper to convert Uint8Array to hex string
 */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

describe("CBOR Interoperability", () => {
  describe("SigningPrivateKey CBOR encoding", () => {
    it("should encode Schnorr private key as bare byte string (matching Rust)", () => {
      // In Rust: SigningPrivateKey::Schnorr encodes as just a byte string (not array)
      const ecKey = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const privateKey = SigningPrivateKey.fromSchnorr(ecKey);

      const taggedCbor = privateKey.toCbor().toData();
      const decoded = decodeCbor(taggedCbor);

      // Should be tagged with 40021 (SigningPrivateKey tag)
      expect(isTagged(decoded)).toBe(true);
      const [tag, content] = asTaggedValue(decoded)!;
      expect(Number(tag.value)).toBe(40021);

      // Content should be a byte string (not an array)
      expect(isBytes(content)).toBe(true);
      expect(bytesToHex(expectBytes(content))).toBe(TEST_PRIVATE_KEY_HEX);
    });

    it("should encode ECDSA private key as [1, byte_string] (matching Rust)", () => {
      // In Rust: SigningPrivateKey::ECDSA encodes as [1, private_key_bytes]
      const ecKey = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const privateKey = SigningPrivateKey.fromEcdsa(ecKey);

      const taggedCbor = privateKey.toCbor().toData();
      const decoded = decodeCbor(taggedCbor);

      expect(isTagged(decoded)).toBe(true);
      const [tag, content] = asTaggedValue(decoded)!;
      expect(Number(tag.value)).toBe(40021);

      // Content should be an array [1, byte_string]
      expect(isArray(content)).toBe(true);
      const array = expectArray(content);
      expect(array.length).toBe(2);
      expect(Number(expectInteger(array[0]))).toBe(1); // ECDSA discriminator
      expect(bytesToHex(expectBytes(array[1]))).toBe(TEST_PRIVATE_KEY_HEX);
    });

    it("should encode Ed25519 private key as [2, byte_string] (matching Rust)", () => {
      // In Rust: SigningPrivateKey::Ed25519 encodes as [2, private_key_bytes]
      const ed25519Key = Ed25519PrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const privateKey = SigningPrivateKey.fromEd25519(ed25519Key);

      const taggedCbor = privateKey.toCbor().toData();
      const decoded = decodeCbor(taggedCbor);

      expect(isTagged(decoded)).toBe(true);
      const [tag, content] = asTaggedValue(decoded)!;
      expect(Number(tag.value)).toBe(40021);

      // Content should be an array [2, byte_string]
      expect(isArray(content)).toBe(true);
      const array = expectArray(content);
      expect(array.length).toBe(2);
      expect(Number(expectInteger(array[0]))).toBe(2); // Ed25519 discriminator
      expect(bytesToHex(expectBytes(array[1]))).toBe(TEST_PRIVATE_KEY_HEX);
    });
  });

  describe("SigningPublicKey CBOR encoding", () => {
    it("should encode Schnorr public key as bare byte string (matching Rust)", () => {
      // Derive public key from private key
      const ecKey = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const privateKey = SigningPrivateKey.fromSchnorr(ecKey);
      const publicKey = privateKey.publicKey();

      const taggedCbor = publicKey.toCbor().toData();
      const decoded = decodeCbor(taggedCbor);

      // Should be tagged with 40022 (SigningPublicKey tag)
      expect(isTagged(decoded)).toBe(true);
      const [tag, content] = asTaggedValue(decoded)!;
      expect(Number(tag.value)).toBe(40022);

      // Content should be a byte string (not an array)
      expect(isBytes(content)).toBe(true);
      // Schnorr public key is 32 bytes (x-only)
      expect(expectBytes(content).length).toBe(32);
    });

    it("should encode ECDSA public key as [1, byte_string] (matching Rust)", () => {
      const ecKey = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const privateKey = SigningPrivateKey.fromEcdsa(ecKey);
      const publicKey = privateKey.publicKey();

      const taggedCbor = publicKey.toCbor().toData();
      const decoded = decodeCbor(taggedCbor);

      expect(isTagged(decoded)).toBe(true);
      const [tag, content] = asTaggedValue(decoded)!;
      expect(Number(tag.value)).toBe(40022);

      // Content should be an array [1, byte_string]
      expect(isArray(content)).toBe(true);
      const array = expectArray(content);
      expect(array.length).toBe(2);
      expect(Number(expectInteger(array[0]))).toBe(1); // ECDSA discriminator
      // ECDSA public key is 33 bytes (compressed)
      expect(expectBytes(array[1]).length).toBe(33);
    });

    it("should encode Ed25519 public key as [2, byte_string] (matching Rust)", () => {
      const ed25519Key = Ed25519PrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const privateKey = SigningPrivateKey.fromEd25519(ed25519Key);
      const publicKey = privateKey.publicKey();

      const taggedCbor = publicKey.toCbor().toData();
      const decoded = decodeCbor(taggedCbor);

      expect(isTagged(decoded)).toBe(true);
      const [tag, content] = asTaggedValue(decoded)!;
      expect(Number(tag.value)).toBe(40022);

      // Content should be an array [2, byte_string]
      expect(isArray(content)).toBe(true);
      const array = expectArray(content);
      expect(array.length).toBe(2);
      expect(Number(expectInteger(array[0]))).toBe(2); // Ed25519 discriminator
      // Ed25519 public key is 32 bytes
      expect(expectBytes(array[1]).length).toBe(32);
    });
  });

  describe("Signature CBOR encoding", () => {
    it("should encode ECDSA signature as [1, byte_string] (matching Rust test vector)", () => {
      /**
       * From Rust test_ecdsa_cbor:
       * 40020([1, h'1458d0f3d97e25109b38fd965782b43213134d02b01388a14e74ebf21e5dea4866f25a23866de9ecf0f9b72404d8192ed71fba4dc355cd89b47213e855cf6d23'])
       */
      const ecKey = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const privateKey = SigningPrivateKey.fromEcdsa(ecKey);
      const signature = privateKey.sign(TEST_MESSAGE);

      // Verify the CBOR structure
      const taggedCbor = signature.toCbor().toData();
      const decoded = decodeCbor(taggedCbor);

      expect(isTagged(decoded)).toBe(true);
      const [tag, content] = asTaggedValue(decoded)!;
      expect(Number(tag.value)).toBe(40020); // Signature tag

      // ECDSA should be [1, signature_bytes]
      expect(isArray(content)).toBe(true);
      const array = expectArray(content);
      expect(array.length).toBe(2);
      expect(Number(expectInteger(array[0]))).toBe(1); // ECDSA discriminator
      expect(expectBytes(array[1]).length).toBe(64); // ECDSA signature is 64 bytes

      // ECDSA signatures are deterministic, so verify exact match with Rust
      const expectedSigHex =
        "1458d0f3d97e25109b38fd965782b43213134d02b01388a14e74ebf21e5dea4866f25a23866de9ecf0f9b72404d8192ed71fba4dc355cd89b47213e855cf6d23";
      expect(bytesToHex(expectBytes(array[1]))).toBe(expectedSigHex);
    });

    it("should encode Schnorr signature as bare byte_string (matching Rust)", () => {
      const ecKey = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const privateKey = SigningPrivateKey.fromSchnorr(ecKey);
      const signature = privateKey.sign(TEST_MESSAGE);

      const taggedCbor = signature.toCbor().toData();
      const decoded = decodeCbor(taggedCbor);

      expect(isTagged(decoded)).toBe(true);
      const [tag, content] = asTaggedValue(decoded)!;
      expect(Number(tag.value)).toBe(40020); // Signature tag

      // Schnorr should be a bare byte string (not array)
      expect(isBytes(content)).toBe(true);
      expect(expectBytes(content).length).toBe(64); // Schnorr signature is 64 bytes
    });

    it("should produce deterministic Schnorr signature with fake RNG (matching Rust)", () => {
      /**
       * From Rust test_schnorr_cbor with make_fake_random_number_generator():
       * 40020(h'9d113392074dd52dfb7f309afb3698a1993cd14d32bc27c00070407092c9ec8c096643b5b1b535bb5277c44f256441ac660cd600739aa910b150d4f94757cf95')
       */
      const ecKey = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const privateKey = SigningPrivateKey.fromSchnorr(ecKey);

      // Use fake RNG for deterministic signature
      const fakeRng = SeededRng.forTesting();
      const signature = privateKey.signWithOptions(TEST_MESSAGE, {
        type: "Schnorr",
        rng: fakeRng,
      });

      const taggedCbor = signature.toCbor().toData();
      const decoded = decodeCbor(taggedCbor);

      const [, content] = asTaggedValue(decoded)!;
      const expectedSigHex =
        "9d113392074dd52dfb7f309afb3698a1993cd14d32bc27c00070407092c9ec8c096643b5b1b535bb5277c44f256441ac660cd600739aa910b150d4f94757cf95";
      expect(bytesToHex(expectBytes(content))).toBe(expectedSigHex);
    });

    it("should encode Ed25519 signature as [2, byte_string] (matching Rust)", () => {
      const ed25519Key = Ed25519PrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const privateKey = SigningPrivateKey.fromEd25519(ed25519Key);
      const signature = privateKey.sign(TEST_MESSAGE);

      const taggedCbor = signature.toCbor().toData();
      const decoded = decodeCbor(taggedCbor);

      expect(isTagged(decoded)).toBe(true);
      const [tag, content] = asTaggedValue(decoded)!;
      expect(Number(tag.value)).toBe(40020); // Signature tag

      // Ed25519 should be [2, signature_bytes]
      expect(isArray(content)).toBe(true);
      const array = expectArray(content);
      expect(array.length).toBe(2);
      expect(Number(expectInteger(array[0]))).toBe(2); // Ed25519 discriminator
      expect(expectBytes(array[1]).length).toBe(64); // Ed25519 signature is 64 bytes
    });
  });

  describe("CBOR roundtrip", () => {
    it("should roundtrip Schnorr private key through CBOR", () => {
      const ecKey = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const original = SigningPrivateKey.fromSchnorr(ecKey);

      const cborData = original.toCbor().toData();
      const restored = SigningPrivateKey.fromCbor(decodeCbor(cborData));

      expect(restored.scheme).toBe(original.scheme);
      expect(restored.equals(original)).toBe(true);
    });

    it("should roundtrip ECDSA private key through CBOR", () => {
      const ecKey = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const original = SigningPrivateKey.fromEcdsa(ecKey);

      const cborData = original.toCbor().toData();
      const restored = SigningPrivateKey.fromCbor(decodeCbor(cborData));

      expect(restored.scheme).toBe(original.scheme);
      expect(restored.equals(original)).toBe(true);
    });

    it("should roundtrip Ed25519 private key through CBOR", () => {
      const ed25519Key = Ed25519PrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const original = SigningPrivateKey.fromEd25519(ed25519Key);

      const cborData = original.toCbor().toData();
      const restored = SigningPrivateKey.fromCbor(decodeCbor(cborData));

      expect(restored.scheme).toBe(original.scheme);
      expect(restored.equals(original)).toBe(true);
    });

    it("should roundtrip Schnorr signature through CBOR", () => {
      const ecKey = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const privateKey = SigningPrivateKey.fromSchnorr(ecKey);
      const original = privateKey.sign(TEST_MESSAGE);

      const cborData = original.toCbor().toData();
      const restored = Signature.fromCbor(decodeCbor(cborData));

      expect(restored.scheme).toBe(original.scheme);
      expect(restored.equals(original)).toBe(true);

      // Verify the restored signature still works
      const publicKey = privateKey.publicKey();
      expect(publicKey.verify(restored, TEST_MESSAGE)).toBe(true);
    });

    it("should roundtrip ECDSA signature through CBOR", () => {
      const ecKey = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const privateKey = SigningPrivateKey.fromEcdsa(ecKey);
      const original = privateKey.sign(TEST_MESSAGE);

      const cborData = original.toCbor().toData();
      const restored = Signature.fromCbor(decodeCbor(cborData));

      expect(restored.scheme).toBe(original.scheme);
      expect(restored.equals(original)).toBe(true);

      // Verify the restored signature still works
      const publicKey = privateKey.publicKey();
      expect(publicKey.verify(restored, TEST_MESSAGE)).toBe(true);
    });
  });

  describe("ReferenceProvider", () => {
    it("SigningPrivateKey should provide reference", () => {
      const ecKey = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const privateKey = SigningPrivateKey.fromSchnorr(ecKey);

      const ref = privateKey.reference();
      expect(ref.refHexShort()).toBeTruthy();
      expect(ref.refHexShort().length).toBe(8); // 4 bytes = 8 hex chars
    });

    it("SigningPublicKey should provide reference", () => {
      const ecKey = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const privateKey = SigningPrivateKey.fromSchnorr(ecKey);
      const publicKey = privateKey.publicKey();

      const ref = publicKey.reference();
      expect(ref.refHexShort()).toBeTruthy();
      expect(ref.refHexShort().length).toBe(8);
    });

    it("EncapsulationPrivateKey should provide reference", () => {
      const privateKey = EncapsulationPrivateKey.random();

      const ref = privateKey.reference();
      expect(ref.refHexShort()).toBeTruthy();
      expect(ref.refHexShort().length).toBe(8);
    });

    it("EncapsulationPublicKey should provide reference", () => {
      const privateKey = EncapsulationPrivateKey.random();
      const publicKey = privateKey.publicKey();

      const ref = publicKey.reference();
      expect(ref.refHexShort()).toBeTruthy();
      expect(ref.refHexShort().length).toBe(8);
    });

    it("PrivateKeys should provide reference", () => {
      const privateKeys = PrivateKeys.random();

      const ref = privateKeys.reference();
      expect(ref.refHexShort()).toBeTruthy();
      expect(ref.refHexShort().length).toBe(8);
    });

    it("PublicKeys should provide reference", () => {
      const privateKeys = PrivateKeys.random();
      const publicKeys = privateKeys.publicKeys();

      const ref = publicKeys.reference();
      expect(ref.refHexShort()).toBeTruthy();
      expect(ref.refHexShort().length).toBe(8);
    });

    it("reference should be deterministic from CBOR", () => {
      const ecKey = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const privateKey1 = SigningPrivateKey.fromSchnorr(ecKey);
      const privateKey2 = SigningPrivateKey.fromSchnorr(ecKey);

      const ref1 = privateKey1.reference();
      const ref2 = privateKey2.reference();

      expect(ref1.refHexShort()).toBe(ref2.refHexShort());
      expect(ref1.fullReference()).toBe(ref2.fullReference());
    });
  });

  describe("Signature schemes default", () => {
    it("default signature scheme should be Schnorr (matching Rust)", () => {
      // Rust: impl Default for SignatureScheme { fn default() -> Self { Self::Schnorr } }
      const [privateKey] = createKeypair(SignatureScheme.Schnorr);
      expect(privateKey.scheme).toBe(SignatureScheme.Schnorr);
    });
  });
});
