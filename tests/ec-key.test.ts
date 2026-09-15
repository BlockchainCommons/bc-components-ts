/**
 * Tests for the EC key module
 *
 * Tests for:
 * - ECPrivateKey creation, signing, CBOR, UR serialization
 * - ECPublicKey creation, verification, CBOR, UR serialization
 * - ECUncompressedPublicKey creation, compression, CBOR, UR serialization
 * - SchnorrPublicKey creation, verification
 * - ECDSA and Schnorr signature integration
 */

import {
  ECPrivateKey,
  ECPublicKey,
  ECUncompressedPublicKey,
  SchnorrPublicKey,
  hexToBytes,
  bytesToHex,
  isECKeyBase,
  isECKey,
  isECPublicKeyBase,
} from "../src";
import type { ECKeyBase, ECKey, ECPublicKeyBase } from "../src";
import { SecureRng } from "@blockchaincommons/rand";

// The reference needs `register_tags()` before a UR is made; so does this package.
import { registerTags } from "../src/tags.js";
registerTags();

// Test vectors
const TEST_PRIVATE_KEY_HEX = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
const TEST_MESSAGE = new TextEncoder().encode("Hello, World!");

describe("ECPrivateKey", () => {
  describe("creation", () => {
    it("should create a new random key", () => {
      const key = ECPrivateKey.random();
      expect(key).toBeInstanceOf(ECPrivateKey);
      expect(key.bytes.length).toBe(32);
    });

    it("should create unique random keys", () => {
      const key1 = ECPrivateKey.random();
      const key2 = ECPrivateKey.random();
      expect(key1.equals(key2)).toBe(false);
    });

    it("should create from raw data", () => {
      const data = hexToBytes(TEST_PRIVATE_KEY_HEX);
      const key = ECPrivateKey.from(data);
      expect(key.toHex()).toBe(TEST_PRIVATE_KEY_HEX);
    });

    it("should create using fromDataRef", () => {
      const data = hexToBytes(TEST_PRIVATE_KEY_HEX);
      const key = ECPrivateKey.from(data);
      expect(key.toHex()).toBe(TEST_PRIVATE_KEY_HEX);
    });

    it("should throw on wrong size with fromDataRef", () => {
      const data = new Uint8Array(16);
      expect(() => ECPrivateKey.from(data)).toThrow();
    });

    it("should create using from (legacy alias)", () => {
      const data = hexToBytes(TEST_PRIVATE_KEY_HEX);
      const key = ECPrivateKey.from(data);
      expect(key.toHex()).toBe(TEST_PRIVATE_KEY_HEX);
    });

    it("should create from hex string", () => {
      const key = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      expect(key.toHex()).toBe(TEST_PRIVATE_KEY_HEX);
    });

    it("should create using provided RNG", () => {
      const rng = new SecureRng();
      const key = ECPrivateKey.random({ rng: rng });
      expect(key).toBeInstanceOf(ECPrivateKey);
      expect(key.bytes.length).toBe(32);
    });
  });

  describe("keypair", () => {
    it("should create keypair", () => {
      const [privateKey, publicKey] = ECPrivateKey.keypair();

      expect(privateKey).toBeInstanceOf(ECPrivateKey);
      expect(publicKey).toBeInstanceOf(ECPublicKey);
      expect(privateKey.publicKey().equals(publicKey)).toBe(true);
    });

    it("should create keypair using provided RNG", () => {
      const rng = new SecureRng();
      const [privateKey, publicKey] = ECPrivateKey.keypair({ rng: rng });

      expect(privateKey).toBeInstanceOf(ECPrivateKey);
      expect(publicKey).toBeInstanceOf(ECPublicKey);
      expect(privateKey.publicKey().equals(publicKey)).toBe(true);
    });
  });

  describe("deriveFromKeyMaterial", () => {
    it("should derive key from key material", () => {
      const keyMaterial = new TextEncoder().encode("test key material");
      const key = ECPrivateKey.deriveFromKeyMaterial(keyMaterial);
      expect(key).toBeInstanceOf(ECPrivateKey);
      expect(key.bytes.length).toBe(32);
    });

    it("should produce deterministic keys from same material", () => {
      const keyMaterial = new TextEncoder().encode("test key material");
      const key1 = ECPrivateKey.deriveFromKeyMaterial(keyMaterial);
      const key2 = ECPrivateKey.deriveFromKeyMaterial(keyMaterial);
      expect(key1.equals(key2)).toBe(true);
    });

    it("should produce different keys from different material", () => {
      const material1 = new TextEncoder().encode("material 1");
      const material2 = new TextEncoder().encode("material 2");
      const key1 = ECPrivateKey.deriveFromKeyMaterial(material1);
      const key2 = ECPrivateKey.deriveFromKeyMaterial(material2);
      expect(key1.equals(key2)).toBe(false);
    });
  });

  describe("accessors", () => {
    it("should return data as bytes", () => {
      const key = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      expect(key.bytes).toBeInstanceOf(Uint8Array);
      expect(key.bytes.length).toBe(32);
    });

    it("should return hex representation", () => {
      const key = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      expect(key.toHex()).toBe(TEST_PRIVATE_KEY_HEX);
      expect(key.toHex()).toBe(TEST_PRIVATE_KEY_HEX);
    });

    it("should return base64 representation", () => {
      const key = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      expect(key.toBase64()).toBeTruthy();
    });

    it("should return string representation", () => {
      const key = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      expect(key.toString()).toContain("ECPrivateKey");
    });
  });

  describe("publicKey", () => {
    it("should derive compressed public key", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey = privateKey.publicKey();
      expect(publicKey).toBeInstanceOf(ECPublicKey);
      expect(publicKey.bytes.length).toBe(33);
    });

    it("should cache derived public key", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey1 = privateKey.publicKey();
      const publicKey2 = privateKey.publicKey();
      expect(publicKey1).toBe(publicKey2); // Same instance
    });
  });

  describe("schnorrPublicKey", () => {
    it("should derive x-only (Schnorr) public key", () => {
      const privateKey = ECPrivateKey.random();
      const schnorrPubKey = privateKey.schnorrPublicKey();
      expect(schnorrPubKey).toBeInstanceOf(SchnorrPublicKey);
      expect(schnorrPubKey.bytes.length).toBe(32);
    });

    it("should cache derived Schnorr public key", () => {
      const privateKey = ECPrivateKey.random();
      const key1 = privateKey.schnorrPublicKey();
      const key2 = privateKey.schnorrPublicKey();
      expect(key1).toBe(key2); // Same instance
    });
  });

  describe("ECDSA signing", () => {
    it("should sign a message with ECDSA", () => {
      const privateKey = ECPrivateKey.random();
      const signature = privateKey.ecdsaSign(TEST_MESSAGE);
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64);
    });

    it("should produce verifiable ECDSA signatures", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey = privateKey.publicKey();
      const signature = privateKey.ecdsaSign(TEST_MESSAGE);
      expect(publicKey.verify(signature, TEST_MESSAGE)).toBe(true);
    });

    it("should fail verification with wrong message", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey = privateKey.publicKey();
      const signature = privateKey.ecdsaSign(TEST_MESSAGE);
      const wrongMessage = new TextEncoder().encode("Wrong message");
      expect(publicKey.verify(signature, wrongMessage)).toBe(false);
    });
  });

  describe("Schnorr signing", () => {
    it("should sign a message with Schnorr", () => {
      const privateKey = ECPrivateKey.random();
      const signature = privateKey.schnorrSign(TEST_MESSAGE);
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64);
    });

    it("should produce verifiable Schnorr signatures", () => {
      const privateKey = ECPrivateKey.random();
      const schnorrPubKey = privateKey.schnorrPublicKey();
      const signature = privateKey.schnorrSign(TEST_MESSAGE);
      expect(schnorrPubKey.schnorrVerify(signature, TEST_MESSAGE)).toBe(true);
    });

    it("should fail Schnorr verification with wrong message", () => {
      const privateKey = ECPrivateKey.random();
      const schnorrPubKey = privateKey.schnorrPublicKey();
      const signature = privateKey.schnorrSign(TEST_MESSAGE);
      const wrongMessage = new TextEncoder().encode("Wrong message");
      expect(schnorrPubKey.schnorrVerify(signature, wrongMessage)).toBe(false);
    });

    it("should sign with custom RNG", () => {
      const privateKey = ECPrivateKey.random();
      const rng = new SecureRng();
      const signature = privateKey.schnorrSignUsing(TEST_MESSAGE, rng);
      const schnorrPubKey = privateKey.schnorrPublicKey();
      expect(schnorrPubKey.schnorrVerify(signature, TEST_MESSAGE)).toBe(true);
    });
  });

  describe("equality", () => {
    it("should be equal to itself", () => {
      const key = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      expect(key.equals(key)).toBe(true);
    });

    it("should be equal to another key with same data", () => {
      const key1 = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const key2 = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      expect(key1.equals(key2)).toBe(true);
    });

    it("should not be equal to a key with different data", () => {
      const key1 = ECPrivateKey.random();
      const key2 = ECPrivateKey.random();
      expect(key1.equals(key2)).toBe(false);
    });
  });

  describe("CBOR serialization", () => {
    it("should return correct CBOR tags", () => {
      const key = ECPrivateKey.random();
      const tags = key.cborTags();
      expect(tags.length).toBe(2);
      expect(tags[0].value).toBe(40306);
      expect(tags[1].value).toBe(306);
    });

    it("should serialize to untagged CBOR", () => {
      const key = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const cbor = key.untaggedCbor();
      expect(cbor).toBeDefined();
    });

    it("should serialize to tagged CBOR", () => {
      const key = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const cbor = key.toCbor();
      expect(cbor).toBeDefined();
    });

    it("should serialize to tagged CBOR binary data", () => {
      const key = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const data = key.toCbor().toData();
      expect(data).toBeInstanceOf(Uint8Array);
    });
  });

  describe("UR serialization", () => {
    it("should serialize to UR", () => {
      const key = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const ur = key.toUR();
      expect(ur.type.name).toBe("eckey");
    });

    it("should serialize to UR string", () => {
      const key = ECPrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
      const urString = key.toUR().toString();
      expect(urString).toContain("ur:eckey");
    });
  });
});

describe("ECPublicKey", () => {
  describe("creation", () => {
    it("should create from raw data", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey = privateKey.publicKey();
      const data = publicKey.bytes;

      const restored = ECPublicKey.from(data);
      expect(restored.equals(publicKey)).toBe(true);
    });

    it("should create using fromDataRef", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey = privateKey.publicKey();
      const data = publicKey.bytes;

      const restored = ECPublicKey.from(data);
      expect(restored.equals(publicKey)).toBe(true);
    });

    it("should throw on wrong size with fromDataRef", () => {
      const data = new Uint8Array(16);
      expect(() => ECPublicKey.from(data)).toThrow();
    });

    it("should create using from (legacy alias)", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey = privateKey.publicKey();
      const data = publicKey.bytes;

      const restored = ECPublicKey.from(data);
      expect(restored.equals(publicKey)).toBe(true);
    });

    it("should create from hex string", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey = privateKey.publicKey();
      const hex = publicKey.toHex();

      const restored = ECPublicKey.fromHex(hex);
      expect(restored.equals(publicKey)).toBe(true);
    });
  });

  describe("accessors", () => {
    it("should return data as bytes", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey = privateKey.publicKey();
      expect(publicKey.bytes).toBeInstanceOf(Uint8Array);
      expect(publicKey.bytes.length).toBe(33);
    });

    it("should return hex representation", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey = privateKey.publicKey();
      expect(publicKey.toHex().length).toBe(66); // 33 bytes = 66 hex chars
      expect(publicKey.toHex()).toBe(publicKey.toHex());
    });

    it("should return base64 representation", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey = privateKey.publicKey();
      expect(publicKey.toBase64()).toBeTruthy();
    });

    it("should return string representation", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey = privateKey.publicKey();
      expect(publicKey.toString()).toContain("ECPublicKey");
    });
  });

  describe("uncompressedPublicKey", () => {
    it("should convert to uncompressed format", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey = privateKey.publicKey();
      const uncompressed = publicKey.uncompressedPublicKey();

      expect(uncompressed).toBeInstanceOf(ECUncompressedPublicKey);
      expect(uncompressed.bytes.length).toBe(65);
    });
  });

  describe("equality", () => {
    it("should be equal to itself", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey = privateKey.publicKey();
      expect(publicKey.equals(publicKey)).toBe(true);
    });

    it("should be equal to another key with same data", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey1 = privateKey.publicKey();
      const publicKey2 = ECPublicKey.from(publicKey1.bytes);
      expect(publicKey1.equals(publicKey2)).toBe(true);
    });

    it("should not be equal to a key with different data", () => {
      const key1 = ECPrivateKey.random().publicKey();
      const key2 = ECPrivateKey.random().publicKey();
      expect(key1.equals(key2)).toBe(false);
    });
  });

  describe("CBOR serialization", () => {
    it("should return correct CBOR tags", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey = privateKey.publicKey();
      const tags = publicKey.cborTags();
      expect(tags.length).toBe(2);
      expect(tags[0].value).toBe(40306);
      expect(tags[1].value).toBe(306);
    });
  });

  describe("UR serialization", () => {
    it("should serialize to UR", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey = privateKey.publicKey();
      const ur = publicKey.toUR();
      expect(ur.type.name).toBe("eckey");
    });
  });
});

describe("ECUncompressedPublicKey", () => {
  describe("creation", () => {
    it("should create from raw data", () => {
      const privateKey = ECPrivateKey.random();
      const uncompressed = privateKey.publicKey().uncompressedPublicKey();
      const data = uncompressed.bytes;

      const restored = ECUncompressedPublicKey.from(data);
      expect(restored.equals(uncompressed)).toBe(true);
    });

    it("should create using fromDataRef", () => {
      const privateKey = ECPrivateKey.random();
      const uncompressed = privateKey.publicKey().uncompressedPublicKey();
      const data = uncompressed.bytes;

      const restored = ECUncompressedPublicKey.from(data);
      expect(restored.equals(uncompressed)).toBe(true);
    });

    it("should throw on wrong size with fromDataRef", () => {
      const data = new Uint8Array(16);
      expect(() => ECUncompressedPublicKey.from(data)).toThrow();
    });

    it("should create from hex string", () => {
      const privateKey = ECPrivateKey.random();
      const uncompressed = privateKey.publicKey().uncompressedPublicKey();
      const hex = uncompressed.toHex();

      const restored = ECUncompressedPublicKey.fromHex(hex);
      expect(restored.equals(uncompressed)).toBe(true);
    });
  });

  describe("accessors", () => {
    it("should return data as bytes", () => {
      const privateKey = ECPrivateKey.random();
      const uncompressed = privateKey.publicKey().uncompressedPublicKey();
      expect(uncompressed.bytes).toBeInstanceOf(Uint8Array);
      expect(uncompressed.bytes.length).toBe(65);
    });

    it("should return hex representation", () => {
      const privateKey = ECPrivateKey.random();
      const uncompressed = privateKey.publicKey().uncompressedPublicKey();
      expect(uncompressed.toHex().length).toBe(130); // 65 bytes = 130 hex chars
    });
  });

  describe("compression", () => {
    it("should convert to compressed format", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey = privateKey.publicKey();
      const uncompressed = publicKey.uncompressedPublicKey();
      const compressedData = uncompressed.compressedData();

      expect(compressedData.length).toBe(33);
      expect(bytesToHex(compressedData)).toBe(publicKey.toHex());
    });
  });

  describe("equality", () => {
    it("should be equal to itself", () => {
      const privateKey = ECPrivateKey.random();
      const uncompressed = privateKey.publicKey().uncompressedPublicKey();
      expect(uncompressed.equals(uncompressed)).toBe(true);
    });

    it("should not be equal to different key", () => {
      const key1 = ECPrivateKey.random().publicKey().uncompressedPublicKey();
      const key2 = ECPrivateKey.random().publicKey().uncompressedPublicKey();
      expect(key1.equals(key2)).toBe(false);
    });
  });

  describe("CBOR serialization", () => {
    it("encodes under tag 40306 as a map with key 3; there is no decoder", () => {
      const original = ECPrivateKey.random().publicKey().uncompressedPublicKey();
      const data = original.toCbor().toData();
      expect(Buffer.from(data.subarray(0, 3)).toString("hex")).toBe("d99d72");
      expect(original.cborTags().map((t) => Number(t.value))).toEqual([40306, 306]);
      expect("fromCbor" in ECUncompressedPublicKey).toBe(false);
    });
  });

  describe("UR serialization", () => {
    it("has the eckey UR type", () => {
      const original = ECPrivateKey.random().publicKey().uncompressedPublicKey();
      expect(original.toUR().type.name).toBe("eckey");
    });
  });
});

describe("SchnorrPublicKey", () => {
  describe("creation", () => {
    it("should create from raw data", () => {
      const privateKey = ECPrivateKey.random();
      const schnorrPubKey = privateKey.schnorrPublicKey();
      const data = schnorrPubKey.bytes;

      const restored = SchnorrPublicKey.from(data);
      expect(restored.equals(schnorrPubKey)).toBe(true);
    });

    it("should create using fromDataRef", () => {
      const privateKey = ECPrivateKey.random();
      const schnorrPubKey = privateKey.schnorrPublicKey();
      const data = schnorrPubKey.bytes;

      const restored = SchnorrPublicKey.from(data);
      expect(restored.equals(schnorrPubKey)).toBe(true);
    });

    it("should throw on wrong size with fromDataRef", () => {
      const data = new Uint8Array(16);
      expect(() => SchnorrPublicKey.from(data)).toThrow();
    });

    it("should create from hex string", () => {
      const privateKey = ECPrivateKey.random();
      const schnorrPubKey = privateKey.schnorrPublicKey();
      const hex = schnorrPubKey.toHex();

      const restored = SchnorrPublicKey.fromHex(hex);
      expect(restored.equals(schnorrPubKey)).toBe(true);
    });
  });

  describe("accessors", () => {
    it("should return data as bytes", () => {
      const privateKey = ECPrivateKey.random();
      const schnorrPubKey = privateKey.schnorrPublicKey();
      expect(schnorrPubKey.bytes).toBeInstanceOf(Uint8Array);
      expect(schnorrPubKey.bytes.length).toBe(32);
    });

    it("should return hex representation", () => {
      const privateKey = ECPrivateKey.random();
      const schnorrPubKey = privateKey.schnorrPublicKey();
      expect(schnorrPubKey.toHex().length).toBe(64); // 32 bytes = 64 hex chars
      expect(schnorrPubKey.toHex()).toBe(schnorrPubKey.toHex());
    });

    it("should return base64 representation", () => {
      const privateKey = ECPrivateKey.random();
      const schnorrPubKey = privateKey.schnorrPublicKey();
      expect(schnorrPubKey.toBase64()).toBeTruthy();
    });

    it("should return string representation", () => {
      const privateKey = ECPrivateKey.random();
      const schnorrPubKey = privateKey.schnorrPublicKey();
      expect(schnorrPubKey.toString()).toContain("SchnorrPublicKey");
    });
  });

  describe("verification", () => {
    it("should verify valid Schnorr signature", () => {
      const privateKey = ECPrivateKey.random();
      const schnorrPubKey = privateKey.schnorrPublicKey();
      const signature = privateKey.schnorrSign(TEST_MESSAGE);
      expect(schnorrPubKey.schnorrVerify(signature, TEST_MESSAGE)).toBe(true);
    });

    it("should reject invalid signature", () => {
      const privateKey = ECPrivateKey.random();
      const schnorrPubKey = privateKey.schnorrPublicKey();
      const signature = privateKey.schnorrSign(TEST_MESSAGE);
      // Corrupt the signature
      signature[0] ^= 0xff;
      expect(schnorrPubKey.schnorrVerify(signature, TEST_MESSAGE)).toBe(false);
    });

    it("should reject signature for wrong message", () => {
      const privateKey = ECPrivateKey.random();
      const schnorrPubKey = privateKey.schnorrPublicKey();
      const signature = privateKey.schnorrSign(TEST_MESSAGE);
      const wrongMessage = new TextEncoder().encode("Wrong message");
      expect(schnorrPubKey.schnorrVerify(signature, wrongMessage)).toBe(false);
    });
  });

  describe("equality", () => {
    it("should be equal to itself", () => {
      const privateKey = ECPrivateKey.random();
      const schnorrPubKey = privateKey.schnorrPublicKey();
      expect(schnorrPubKey.equals(schnorrPubKey)).toBe(true);
    });

    it("should be equal to another key with same data", () => {
      const privateKey = ECPrivateKey.random();
      const key1 = privateKey.schnorrPublicKey();
      const key2 = SchnorrPublicKey.from(key1.bytes);
      expect(key1.equals(key2)).toBe(true);
    });

    it("should not be equal to a key with different data", () => {
      const key1 = ECPrivateKey.random().schnorrPublicKey();
      const key2 = ECPrivateKey.random().schnorrPublicKey();
      expect(key1.equals(key2)).toBe(false);
    });
  });
});

describe("EC key integration", () => {
  it("should sign with ECDSA and verify with compressed public key", () => {
    const [privateKey, publicKey] = ECPrivateKey.keypair();
    const message = new TextEncoder().encode("Test message for ECDSA");

    const signature = privateKey.ecdsaSign(message);
    expect(publicKey.verify(signature, message)).toBe(true);
  });

  it("should sign with Schnorr and verify with x-only public key", () => {
    const privateKey = ECPrivateKey.random();
    const schnorrPubKey = privateKey.schnorrPublicKey();
    const message = new TextEncoder().encode("Test message for Schnorr");

    const signature = privateKey.schnorrSign(message);
    expect(schnorrPubKey.schnorrVerify(signature, message)).toBe(true);
  });

  it("should convert between compressed and uncompressed formats", () => {
    const privateKey = ECPrivateKey.random();
    const compressed = privateKey.publicKey();
    const uncompressed = compressed.uncompressedPublicKey();
    const recompressed = uncompressed.compressedData();

    expect(bytesToHex(recompressed)).toBe(compressed.toHex());
  });

  it("should produce deterministic results with derived keys", () => {
    const keyMaterial = new TextEncoder().encode("shared key derivation material");

    // Both parties derive the same private key from shared material
    const alice = ECPrivateKey.deriveFromKeyMaterial(keyMaterial);
    const bob = ECPrivateKey.deriveFromKeyMaterial(keyMaterial);

    // Both keys should be identical
    expect(alice.equals(bob)).toBe(true);
    expect(alice.publicKey().equals(bob.publicKey())).toBe(true);
    expect(alice.schnorrPublicKey().equals(bob.schnorrPublicKey())).toBe(true);
  });
});

describe("EC Key Base Interfaces (Rust trait parity)", () => {
  describe("ECKeyBase interface", () => {
    it("ECPrivateKey implements ECKeyBase", () => {
      const key = ECPrivateKey.random();
      expect(isECKeyBase(key)).toBe(true);

      // Type assertion works
      const ecKeyBase: ECKeyBase = key;
      expect(ecKeyBase.bytes).toBeInstanceOf(Uint8Array);
      expect(typeof ecKeyBase.toHex()).toBe("string");
    });

    it("ECPublicKey implements ECKeyBase", () => {
      const [_, key] = ECPrivateKey.keypair();
      expect(isECKeyBase(key)).toBe(true);

      const ecKeyBase: ECKeyBase = key;
      expect(ecKeyBase.bytes).toBeInstanceOf(Uint8Array);
      expect(typeof ecKeyBase.toHex()).toBe("string");
    });

    it("ECUncompressedPublicKey implements ECKeyBase", () => {
      const [_, pubKey] = ECPrivateKey.keypair();
      const key = pubKey.uncompressedPublicKey();
      expect(isECKeyBase(key)).toBe(true);

      const ecKeyBase: ECKeyBase = key;
      expect(ecKeyBase.bytes).toBeInstanceOf(Uint8Array);
      expect(typeof ecKeyBase.toHex()).toBe("string");
    });

    it("SchnorrPublicKey implements ECKeyBase", () => {
      const privateKey = ECPrivateKey.random();
      const key = privateKey.schnorrPublicKey();
      expect(isECKeyBase(key)).toBe(true);

      const ecKeyBase: ECKeyBase = key;
      expect(ecKeyBase.bytes).toBeInstanceOf(Uint8Array);
      expect(typeof ecKeyBase.toHex()).toBe("string");
    });

    it("isECKeyBase returns false for non-EC objects", () => {
      expect(isECKeyBase(null)).toBe(false);
      expect(isECKeyBase(undefined)).toBe(false);
      expect(isECKeyBase({})).toBe(false);
      expect(isECKeyBase({ data: 123 })).toBe(false);
    });
  });

  describe("ECKey interface", () => {
    it("ECPrivateKey implements ECKey", () => {
      const key = ECPrivateKey.random();
      expect(isECKey(key)).toBe(true);

      const ecKey: ECKey = key;
      expect(ecKey.publicKey()).toBeInstanceOf(ECPublicKey);
    });

    it("ECPublicKey implements ECKey (returns self)", () => {
      const [_, key] = ECPrivateKey.keypair();
      expect(isECKey(key)).toBe(true);

      const ecKey: ECKey = key;
      const pubKey = ecKey.publicKey();
      expect(pubKey).toBe(key); // Same reference (self)
    });

    it("isECKey returns false for non-ECKey objects", () => {
      expect(isECKey(null)).toBe(false);
      expect(isECKey({ data: () => new Uint8Array(0), hex: () => "" })).toBe(false);
    });
  });

  describe("ECPublicKeyBase interface", () => {
    it("ECPublicKey implements ECPublicKeyBase", () => {
      const [_, key] = ECPrivateKey.keypair();
      expect(isECPublicKeyBase(key)).toBe(true);

      const ecPubKeyBase: ECPublicKeyBase = key;
      expect(ecPubKeyBase.uncompressedPublicKey()).toBeInstanceOf(ECUncompressedPublicKey);
    });

    it("isECPublicKeyBase returns false for ECPrivateKey", () => {
      const key = ECPrivateKey.random();
      expect(isECPublicKeyBase(key)).toBe(false);
    });

    it("isECPublicKeyBase returns false for SchnorrPublicKey", () => {
      const privateKey = ECPrivateKey.random();
      const key = privateKey.schnorrPublicKey();
      expect(isECPublicKeyBase(key)).toBe(false);
    });
  });

  describe("interface polymorphism", () => {
    it("can work with any ECKeyBase polymorphically", () => {
      const keys: ECKeyBase[] = [
        ECPrivateKey.random(),
        ECPrivateKey.random().publicKey(),
        ECPrivateKey.random().publicKey().uncompressedPublicKey(),
        ECPrivateKey.random().schnorrPublicKey(),
      ];

      for (const key of keys) {
        expect(key.bytes).toBeInstanceOf(Uint8Array);
        expect(key.bytes.length).toBeGreaterThan(0);
        expect(typeof key.toHex()).toBe("string");
        expect(key.toHex().length).toBeGreaterThan(0);
      }
    });

    it("can work with any ECKey polymorphically", () => {
      const privateKey = ECPrivateKey.random();
      const publicKey = privateKey.publicKey();

      const keys: ECKey[] = [privateKey, publicKey];

      for (const key of keys) {
        const pubKey = key.publicKey();
        expect(pubKey).toBeInstanceOf(ECPublicKey);
      }
    });
  });
});
