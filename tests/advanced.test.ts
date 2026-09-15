/* eslint-disable @typescript-eslint/no-non-null-assertion -- fixtures are indexed by position; a miss fails the test */
/**
 * Advanced feature tests
 *
 * Tests for:
 * - PrivateKeyBase
 * - PrivateKeys
 * - PublicKeys
 * - SskrShare
 */

import { describe, it, expect, beforeAll } from "vitest";
import { registerTags } from "@blockchaincommons/tags";
import {
  Secret,
  GroupSpec,
  Spec,
  generateShares,
  shareBytes,
  combineShares,
} from "@blockchaincommons/sskr";

import {
  PrivateKeyBase,
  PrivateKeys,
  PublicKeys,
  SigningPrivateKey,
  SigningPublicKey,
  EncapsulationPrivateKey,
  EncapsulationPublicKey,
} from "../src/index.js";
import { SskrShare } from "../src/sskr.js";
import { ComponentsError } from "../src/error.js";
import { UR, decodeURWith } from "@blockchaincommons/uniform-resources";
import { decodeCbor } from "@blockchaincommons/dcbor";

beforeAll(() => {
  registerTags();
});

// ============================================================================
// PrivateKeyBase Tests
// ============================================================================

describe("PrivateKeyBase", () => {
  describe("creation", () => {
    it("should create a random PrivateKeyBase", () => {
      const pkb = PrivateKeyBase.random();
      expect(pkb).toBeInstanceOf(PrivateKeyBase);
      expect(pkb.bytes).toHaveLength(32);
    });

    it("should create from data", () => {
      const data = new Uint8Array(32).fill(0x42);
      const pkb = PrivateKeyBase.from(data);
      expect(pkb.bytes).toEqual(data);
    });

    it("should accept variable data lengths (matching Rust)", () => {
      // Rust accepts any non-zero length
      const shortData = new Uint8Array(16).fill(0x42);
      expect(() => PrivateKeyBase.from(shortData)).not.toThrow();

      const longData = new Uint8Array(64).fill(0x42);
      expect(() => PrivateKeyBase.from(longData)).not.toThrow();

      // Empty data is accepted too, as the reference's `from_data`; keys derive from it.
      const emptyData = new Uint8Array(0);
      const empty = PrivateKeyBase.from(emptyData);
      expect(empty.bytes.length).toBe(0);
      expect(empty.ed25519SigningPrivateKey().publicKey().isEd25519()).toBe(true);
    });

    it("should return a copy of data", () => {
      const data = new Uint8Array(32).fill(0x42);
      const pkb = PrivateKeyBase.from(data);
      const retrieved = pkb.bytes;
      expect(retrieved).toEqual(data);
      // Ensure it's a copy
      retrieved[0] = 0xff;
      expect(pkb.bytes[0]).toBe(0x42);
    });
  });

  describe("key derivation", () => {
    it("should derive Ed25519 signing private key", () => {
      const pkb = PrivateKeyBase.random();
      const signingKey = pkb.ed25519SigningPrivateKey();
      expect(signingKey).toBeInstanceOf(SigningPrivateKey);
      expect(signingKey.isEd25519()).toBe(true);
    });

    it("should derive X25519 private key", () => {
      const pkb = PrivateKeyBase.random();
      const x25519Key = pkb.x25519PrivateKey();
      expect(x25519Key.bytes).toHaveLength(32);
    });

    it("should derive encapsulation private key", () => {
      const pkb = PrivateKeyBase.random();
      const encapKey = pkb.encapsulationPrivateKey();
      expect(encapKey).toBeInstanceOf(EncapsulationPrivateKey);
      expect(encapKey.isX25519()).toBe(true);
    });

    it("should derive PrivateKeys container", () => {
      const pkb = PrivateKeyBase.random();
      const privateKeys = pkb.ed25519PrivateKeys();
      expect(privateKeys).toBeInstanceOf(PrivateKeys);
    });

    it("should derive PublicKeys container", () => {
      const pkb = PrivateKeyBase.random();
      const publicKeys = pkb.ed25519PublicKeys();
      expect(publicKeys).toBeInstanceOf(PublicKeys);
    });

    it("should derive deterministic keys from same base", () => {
      const data = new Uint8Array(32).fill(0x42);
      const pkb1 = PrivateKeyBase.from(data);
      const pkb2 = PrivateKeyBase.from(new Uint8Array(data));

      const signing1 = pkb1.ed25519SigningPrivateKey();
      const signing2 = pkb2.ed25519SigningPrivateKey();
      expect(signing1.equals(signing2)).toBe(true);

      const x255191 = pkb1.x25519PrivateKey();
      const x255192 = pkb2.x25519PrivateKey();
      expect(x255191.equals(x255192)).toBe(true);
    });
  });

  describe("equality", () => {
    it("should be equal to itself", () => {
      const pkb = PrivateKeyBase.random();
      expect(pkb.equals(pkb)).toBe(true);
    });

    it("should be equal to another with same data", () => {
      const data = new Uint8Array(32).fill(0x42);
      const pkb1 = PrivateKeyBase.from(data);
      const pkb2 = PrivateKeyBase.from(new Uint8Array(data));
      expect(pkb1.equals(pkb2)).toBe(true);
    });

    it("should not be equal to another with different data", () => {
      const pkb1 = PrivateKeyBase.random();
      const pkb2 = PrivateKeyBase.random();
      expect(pkb1.equals(pkb2)).toBe(false);
    });
  });

  describe("CBOR serialization", () => {
    it("should return correct CBOR tags", () => {
      const pkb = PrivateKeyBase.random();
      const tags = pkb.cborTags();
      expect(tags).toHaveLength(1);
      expect(tags[0].value).toBe(40016);
    });

    it("should serialize to untagged CBOR", () => {
      const pkb = PrivateKeyBase.random();
      const cbor = pkb.untaggedCbor();
      expect(cbor).toBeDefined();
    });

    it("should serialize to tagged CBOR", () => {
      const pkb = PrivateKeyBase.random();
      const cbor = pkb.toCbor();
      expect(cbor).toBeDefined();
    });

    it("should roundtrip through tagged CBOR", () => {
      const pkb = PrivateKeyBase.random();
      const cborData = pkb.toCbor().toData();
      const recovered = PrivateKeyBase.fromCbor(decodeCbor(cborData));
      expect(recovered.equals(pkb)).toBe(true);
    });
  });

  describe("UR serialization", () => {
    it("should serialize to UR", () => {
      const pkb = PrivateKeyBase.random();
      const ur = pkb.toUR();
      expect(ur.type.name).toBe("crypto-prvkey-base");
    });

    it("should serialize to UR string", () => {
      const pkb = PrivateKeyBase.random();
      const urString = pkb.toUR().toString();
      expect(urString).toMatch(/^ur:crypto-prvkey-base\//);
    });

    it("should roundtrip through UR string", () => {
      const pkb = PrivateKeyBase.random();
      const urString = pkb.toUR().toString();
      const recovered = decodeURWith(UR.parse(urString), PrivateKeyBase.codec);
      expect(recovered.equals(pkb)).toBe(true);
    });
  });

  describe("signing roundtrip", () => {
    it("should sign and verify messages", () => {
      const pkb = PrivateKeyBase.random();
      const signingKey = pkb.ed25519SigningPrivateKey();
      const publicKey = signingKey.publicKey();

      const message = new Uint8Array([1, 2, 3, 4, 5]);
      const signature = signingKey.sign(message);

      expect(publicKey.verify(signature, message)).toBe(true);
      expect(publicKey.verify(signature, new Uint8Array([1, 2, 3]))).toBe(false);
    });
  });
});

// ============================================================================
// PrivateKeys Tests
// ============================================================================

describe("PrivateKeys", () => {
  describe("creation", () => {
    it("should create random PrivateKeys", () => {
      const pk = PrivateKeys.random();
      expect(pk).toBeInstanceOf(PrivateKeys);
    });

    it("should create with specific keys", () => {
      const signingKey = SigningPrivateKey.random();
      const encapKey = EncapsulationPrivateKey.random();
      const pk = PrivateKeys.from({ signing: signingKey, encapsulation: encapKey });

      expect(pk.signingPrivateKey.equals(signingKey)).toBe(true);
      expect(pk.encapsulationPrivateKey().equals(encapKey)).toBe(true);
    });
  });

  describe("accessors", () => {
    it("should return signing private key", () => {
      const pk = PrivateKeys.random();
      const signingKey = pk.signingPrivateKey;
      expect(signingKey).toBeInstanceOf(SigningPrivateKey);
    });

    it("should return encapsulation private key", () => {
      const pk = PrivateKeys.random();
      const encapKey = pk.encapsulationPrivateKey();
      expect(encapKey).toBeInstanceOf(EncapsulationPrivateKey);
    });

    it("should derive public keys", () => {
      const pk = PrivateKeys.random();
      const pubKeys = pk.publicKeys();
      expect(pubKeys).toBeInstanceOf(PublicKeys);
    });
  });

  describe("Signer interface", () => {
    it("should sign messages", () => {
      const pk = PrivateKeys.random();
      const message = new Uint8Array([1, 2, 3, 4, 5]);
      const signature = pk.sign(message);

      const pubKeys = pk.publicKeys();
      expect(pubKeys.verify(signature, message)).toBe(true);
    });
  });

  describe("Decrypter interface", () => {
    it("should decapsulate shared secrets", () => {
      const pk = PrivateKeys.random();
      const pubKeys = pk.publicKeys();

      // Encapsulate using public keys
      const [originalSecret, ciphertext] = pubKeys.encapsulateNewSharedSecret();

      // Decapsulate using private keys
      const recoveredSecret = pk.decapsulateSharedSecret(ciphertext);

      expect(recoveredSecret.equals(originalSecret)).toBe(true);
    });

    it("should implement encapsulationPrivateKey accessor", () => {
      const pk = PrivateKeys.random();
      const encapKey = pk.encapsulationPrivateKey();
      expect(encapKey).toBeInstanceOf(EncapsulationPrivateKey);
    });
  });

  describe("ReferenceProvider interface", () => {
    it("should return a unique reference", () => {
      const pk = PrivateKeys.random();
      const ref = pk.reference();
      expect(ref).toBeDefined();
      expect(ref.shortReference("hex")).toHaveLength(8);
    });

    it("should return consistent reference for same keys", () => {
      const pk = PrivateKeys.random();
      const ref1 = pk.reference();
      const ref2 = pk.reference();
      expect(ref1.equals(ref2)).toBe(true);
    });

    it("should return different references for different keys", () => {
      const pk1 = PrivateKeys.random();
      const pk2 = PrivateKeys.random();
      expect(pk1.reference().equals(pk2.reference())).toBe(false);
    });

    it("should include reference + inner keys in toString (Rust parity)", () => {
      // Mirrors Rust `Display for PrivateKeys`:
      //   `PrivateKeys(<refHexShort>, <signingPrivateKey>, <encapsulationPrivateKey>)`
      // The inner displays follow the same `KeyType(refOrInner)` shape as
      // their public counterparts. The previous abbreviated form was an
      // E1a parity drift from the audit pass.
      const pk = PrivateKeys.random();
      const str = pk.toString();
      expect(str).toMatch(/^PrivateKeys\([a-f0-9]{8}, /);
      expect(str).toContain(", SigningPrivateKey(");
      expect(str).toContain(", EncapsulationPrivateKey(");
      expect(str.endsWith("))")).toBe(true);
    });
  });

  describe("equality", () => {
    it("should be equal to itself", () => {
      const pk = PrivateKeys.random();
      expect(pk.equals(pk)).toBe(true);
    });

    it("should not be equal to another random instance", () => {
      const pk1 = PrivateKeys.random();
      const pk2 = PrivateKeys.random();
      expect(pk1.equals(pk2)).toBe(false);
    });
  });

  describe("CBOR serialization", () => {
    it("should return correct CBOR tags", () => {
      const pk = PrivateKeys.random();
      const tags = pk.cborTags();
      expect(tags).toHaveLength(1);
      expect(tags[0].value).toBe(40013);
    });

    it("should roundtrip through tagged CBOR", () => {
      const pk = PrivateKeys.random();
      const cborData = pk.toCbor().toData();
      const recovered = PrivateKeys.fromCbor(decodeCbor(cborData));
      expect(recovered.equals(pk)).toBe(true);
    });
  });

  describe("UR serialization", () => {
    it("should serialize to UR", () => {
      const pk = PrivateKeys.random();
      const ur = pk.toUR();
      expect(ur.type.name).toBe("crypto-prvkeys");
    });

    it("should roundtrip through UR string", () => {
      const pk = PrivateKeys.random();
      const urString = pk.toUR().toString();
      const recovered = decodeURWith(UR.parse(urString), PrivateKeys.codec);
      expect(recovered.equals(pk)).toBe(true);
    });
  });
});

// ============================================================================
// PublicKeys Tests
// ============================================================================

describe("PublicKeys", () => {
  describe("creation", () => {
    it("should create with specific keys", () => {
      const pk = PrivateKeys.random();
      const signingPublic = pk.signingPrivateKey.publicKey();
      const encapPublic = pk.encapsulationPrivateKey().publicKey();

      const pubKeys = PublicKeys.from({ signing: signingPublic, encapsulation: encapPublic });
      expect(pubKeys.signingPublicKey.equals(signingPublic)).toBe(true);
      expect(pubKeys.encapsulationPublicKey().equals(encapPublic)).toBe(true);
    });
  });

  describe("accessors", () => {
    it("should return signing public key", () => {
      const pk = PrivateKeys.random();
      const pubKeys = pk.publicKeys();
      expect(pubKeys.signingPublicKey).toBeInstanceOf(SigningPublicKey);
    });

    it("should return encapsulation public key", () => {
      const pk = PrivateKeys.random();
      const pubKeys = pk.publicKeys();
      expect(pubKeys.encapsulationPublicKey()).toBeInstanceOf(EncapsulationPublicKey);
    });
  });

  describe("Verifier interface", () => {
    it("should verify signatures", () => {
      const pk = PrivateKeys.random();
      const pubKeys = pk.publicKeys();

      const message = new Uint8Array([1, 2, 3, 4, 5]);
      const signature = pk.sign(message);

      expect(pubKeys.verify(signature, message)).toBe(true);
      expect(pubKeys.verify(signature, new Uint8Array([0]))).toBe(false);
    });
  });

  describe("Encrypter interface", () => {
    it("should encapsulate shared secrets", () => {
      const pk = PrivateKeys.random();
      const pubKeys = pk.publicKeys();

      // Encapsulate using public keys
      const [sharedSecret, ciphertext] = pubKeys.encapsulateNewSharedSecret();

      expect(sharedSecret).toBeDefined();
      expect(ciphertext).toBeDefined();
    });

    it("should implement encapsulationPublicKey accessor", () => {
      const pk = PrivateKeys.random();
      const pubKeys = pk.publicKeys();
      const encapKey = pubKeys.encapsulationPublicKey();
      expect(encapKey).toBeInstanceOf(EncapsulationPublicKey);
    });

    it("should generate secrets recoverable by matching private key", () => {
      const pk = PrivateKeys.random();
      const pubKeys = pk.publicKeys();

      const [originalSecret, ciphertext] = pubKeys.encapsulateNewSharedSecret();
      const recoveredSecret = pk.decapsulateSharedSecret(ciphertext);

      expect(recoveredSecret.equals(originalSecret)).toBe(true);
    });
  });

  describe("ReferenceProvider interface", () => {
    it("should return a unique reference", () => {
      const pk = PrivateKeys.random();
      const pubKeys = pk.publicKeys();
      const ref = pubKeys.reference();
      expect(ref).toBeDefined();
      expect(ref.shortReference("hex")).toHaveLength(8);
    });

    it("should return consistent reference for same keys", () => {
      const pk = PrivateKeys.random();
      const pubKeys = pk.publicKeys();
      const ref1 = pubKeys.reference();
      const ref2 = pubKeys.reference();
      expect(ref1.equals(ref2)).toBe(true);
    });

    it("should return different references for different keys", () => {
      const pk1 = PrivateKeys.random();
      const pk2 = PrivateKeys.random();
      expect(pk1.publicKeys().reference().equals(pk2.publicKeys().reference())).toBe(false);
    });

    it("should include reference in toString", () => {
      // Mirrors Rust `Display for PublicKeys`: full form with the
      // signing-public-key and encapsulation-public-key inner displays
      // (G1 fix). The earlier short form `PublicKeys(<short>)` was
      // observable in envelope notation as a missing fingerprint
      // trail.
      const pk = PrivateKeys.random();
      const pubKeys = pk.publicKeys();
      const str = pubKeys.toString();
      expect(str).toMatch(
        /^PublicKeys\([a-f0-9]{8}, SigningPublicKey\([a-f0-9]{8}, \w+\([a-f0-9]{8}\)\), EncapsulationPublicKey\([a-f0-9]{8}, \w+\([a-f0-9]{8}\)\)\)$/,
      );
    });
  });

  describe("equality", () => {
    it("should be equal when derived from same private keys", () => {
      const pk = PrivateKeys.random();
      const pubKeys1 = pk.publicKeys();
      const pubKeys2 = pk.publicKeys();
      expect(pubKeys1.equals(pubKeys2)).toBe(true);
    });

    it("should not be equal to another random instance", () => {
      const pk1 = PrivateKeys.random();
      const pk2 = PrivateKeys.random();
      expect(pk1.publicKeys().equals(pk2.publicKeys())).toBe(false);
    });
  });

  describe("CBOR serialization", () => {
    it("should return correct CBOR tags", () => {
      const pk = PrivateKeys.random();
      const pubKeys = pk.publicKeys();
      const tags = pubKeys.cborTags();
      expect(tags).toHaveLength(1);
      expect(tags[0].value).toBe(40017);
    });

    it("should roundtrip through tagged CBOR", () => {
      const pk = PrivateKeys.random();
      const pubKeys = pk.publicKeys();
      const cborData = pubKeys.toCbor().toData();
      const recovered = PublicKeys.fromCbor(decodeCbor(cborData));
      expect(recovered.equals(pubKeys)).toBe(true);
    });
  });

  describe("UR serialization", () => {
    it("should serialize to UR", () => {
      const pk = PrivateKeys.random();
      const pubKeys = pk.publicKeys();
      const ur = pubKeys.toUR();
      expect(ur.type.name).toBe("crypto-pubkeys");
    });

    it("should roundtrip through UR string", () => {
      const pk = PrivateKeys.random();
      const pubKeys = pk.publicKeys();
      const urString = pubKeys.toUR().toString();
      const recovered = decodeURWith(UR.parse(urString), PublicKeys.codec);
      expect(recovered.equals(pubKeys)).toBe(true);
    });
  });
});

// ============================================================================
// SskrShare Tests
// ============================================================================

describe("SskrShare", () => {
  // Generate a test share
  const testSecret = new Uint8Array(16).fill(0x42);
  let testShareData: Uint8Array;

  beforeAll(() => {
    const secret = Secret.from(testSecret);
    const group = GroupSpec.from({ memberThreshold: 2, memberCount: 3 }); // 2 of 3
    const spec = Spec.from({ groupThreshold: 1, groups: [group] }); // 1 of 1 group
    const groups = generateShares(spec, secret);
    testShareData = shareBytes(groups[0][0]!);
  });

  describe("creation", () => {
    it("should create from data", () => {
      const share = SskrShare.from(testShareData);
      expect(share).toBeInstanceOf(SskrShare);
    });

    it("should create from hex", () => {
      const hex = Array.from(testShareData)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      const share = SskrShare.fromHex(hex);
      expect(share.bytes).toEqual(testShareData);
    });

    it("holds any bytes; a header accessor on a short share is InvalidData", () => {
      const share = SskrShare.from(new Uint8Array(3));
      expect(share.bytes).toEqual(new Uint8Array(3));
      expect(share.identifier).toBe(0);
      expect(share.groupThreshold).toBe(1);
      let thrown: unknown;
      try {
        void share.groupIndex;
      } catch (e) {
        thrown = e;
      }
      expect(ComponentsError.isComponentsError(thrown)).toBe(true);
      expect((thrown as ComponentsError).code).toBe("InvalidData");
      expect(() => share.share).toThrow(ComponentsError);
      expect(() => SskrShare.combine([share])).toThrow();
    });
  });

  describe("metadata accessors", () => {
    it("should return identifier", () => {
      const share = SskrShare.from(testShareData);
      const id = share.identifier;
      expect(typeof id).toBe("number");
      expect(id).toBeGreaterThanOrEqual(0);
      expect(id).toBeLessThanOrEqual(0xffff);
    });

    it("should return identifier as hex", () => {
      const share = SskrShare.from(testShareData);
      const hex = share.identifierHex();
      expect(hex).toHaveLength(4);
    });

    it("should return group threshold", () => {
      const share = SskrShare.from(testShareData);
      expect(share.groupThreshold).toBe(1);
    });

    it("should return group count", () => {
      const share = SskrShare.from(testShareData);
      expect(share.groupCount).toBe(1);
    });

    it("should return group index", () => {
      const share = SskrShare.from(testShareData);
      expect(share.groupIndex).toBe(0);
    });

    it("should return member threshold", () => {
      const share = SskrShare.from(testShareData);
      expect(share.memberThreshold).toBe(2);
    });

    it("should return member index", () => {
      const share = SskrShare.from(testShareData);
      const idx = share.memberIndex;
      expect(idx).toBeGreaterThanOrEqual(0);
      expect(idx).toBeLessThanOrEqual(15);
    });

    it("should return share value", () => {
      const share = SskrShare.from(testShareData);
      const value = share.value;
      expect(value.length).toBeGreaterThan(0);
    });
  });

  describe("equality", () => {
    it("should be equal to itself", () => {
      const share = SskrShare.from(testShareData);
      expect(share.equals(share)).toBe(true);
    });

    it("should be equal to another with same data", () => {
      const share1 = SskrShare.from(testShareData);
      const share2 = SskrShare.from(new Uint8Array(testShareData));
      expect(share1.equals(share2)).toBe(true);
    });
  });

  describe("CBOR serialization", () => {
    it("should return correct CBOR tags", () => {
      const share = SskrShare.from(testShareData);
      const tags = share.cborTags();
      // Returns both current tag (40309) and legacy tag (309) for backward compatibility
      expect(tags).toHaveLength(2);
      expect(tags[0].value).toBe(40309); // TAG_SSKR_SHARE
      expect(tags[1].value).toBe(309); // TAG_SSKR_SHARE_V1 (legacy)
    });

    it("should roundtrip through tagged CBOR", () => {
      const share = SskrShare.from(testShareData);
      const cborData = share.toCbor().toData();
      const recovered = SskrShare.fromCbor(decodeCbor(cborData));
      expect(recovered.equals(share)).toBe(true);
    });
  });

  describe("string representation", () => {
    it("should provide meaningful toString", () => {
      const share = SskrShare.from(testShareData);
      const str = share.toString();
      expect(str).toContain("SskrShare");
      expect(str).toContain("group");
      expect(str).toContain("member");
    });
  });
});

// ============================================================================
// SSKR Integration Tests
// ============================================================================

describe("SSKR Integration", () => {
  describe("sskrGenerateShares and sskrCombineShares (Rust API parity)", () => {
    it("should generate and recover a secret (2 of 3)", () => {
      const secretData = new Uint8Array(16);
      for (let i = 0; i < 16; i++) {
        secretData[i] = i;
      }

      const secret = Secret.from(secretData);
      const group = GroupSpec.from({ memberThreshold: 2, memberCount: 3 }); // 2 of 3
      const spec = Spec.from({ groupThreshold: 1, groups: [group] }); // 1 of 1 group

      const groups = SskrShare.generate(spec, secret);
      expect(groups).toHaveLength(1);
      expect(groups[0]).toHaveLength(3);

      // Recover with first 2 shares
      const recoveredSecret = SskrShare.combine([groups[0][0], groups[0][1]]);
      expect(recoveredSecret.bytes).toEqual(secretData);

      // Recover with last 2 shares
      const recoveredSecret2 = SskrShare.combine([groups[0][1], groups[0][2]]);
      expect(recoveredSecret2.bytes).toEqual(secretData);
    });

    it("should work with multiple groups", () => {
      const secretData = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        secretData[i] = i;
      }

      const secret = Secret.from(secretData);
      const group1 = GroupSpec.from({ memberThreshold: 2, memberCount: 3 }); // 2 of 3
      const group2 = GroupSpec.from({ memberThreshold: 3, memberCount: 5 }); // 3 of 5
      const spec = Spec.from({ groupThreshold: 2, groups: [group1, group2] }); // 2 of 2 groups

      const groups = SskrShare.generate(spec, secret);
      expect(groups).toHaveLength(2);
      expect(groups[0]).toHaveLength(3);
      expect(groups[1]).toHaveLength(5);

      // All shares should be valid SskrShare instances
      for (const group of groups) {
        for (const share of group) {
          expect(share).toBeInstanceOf(SskrShare);
          expect(share.groupCount).toBe(2);
        }
      }

      // Recover with shares from both groups
      const recoveredSecret = SskrShare.combine([
        groups[0][0],
        groups[0][1],
        groups[1][0],
        groups[1][1],
        groups[1][2],
      ]);
      expect(recoveredSecret.bytes).toEqual(secretData);
    });

    it("should roundtrip shares through CBOR", () => {
      const secretData = new Uint8Array(16).fill(0x42);
      const secret = Secret.from(secretData);
      const group = GroupSpec.from({ memberThreshold: 2, memberCount: 3 });
      const spec = Spec.from({ groupThreshold: 1, groups: [group] });

      const groups = SskrShare.generate(spec, secret);

      // Serialize all shares to CBOR and back
      const recoveredShares = groups[0].map((share) => {
        const cborData = share.toCbor().toData();
        return SskrShare.fromCbor(decodeCbor(cborData));
      });

      // Should still recover the secret
      const recovered = SskrShare.combine([recoveredShares[0], recoveredShares[1]]);
      expect(recovered.bytes).toEqual(secretData);
    });
  });

  describe("raw sskr functions", () => {
    it("sskrGenerate and sskrCombine should work", () => {
      const secretData = new Uint8Array(16).fill(0xaa);
      const secret = Secret.from(secretData);
      const group = GroupSpec.from({ memberThreshold: 2, memberCount: 3 });
      const spec = Spec.from({ groupThreshold: 1, groups: [group] });

      const groups = generateShares(spec, secret);
      expect(groups).toHaveLength(1);
      expect(groups[0]).toHaveLength(3);

      // The sskr package's shares are parsed objects; the component wraps them.
      expect(shareBytes(groups[0][0]!)).toBeInstanceOf(Uint8Array);
      expect(SskrShare.from(groups[0][0]!).bytes).toEqual(shareBytes(groups[0][0]!));

      const recovered = combineShares([groups[0][0]!, groups[0][1]!]);
      expect(recovered.bytes).toEqual(secretData);
    });
  });
});

// ============================================================================
// Integration: PrivateKeyBase + SSKR
// ============================================================================

describe("PrivateKeyBase + SSKR Integration", () => {
  it("should split and recover PrivateKeyBase using SSKR", () => {
    // Create a PrivateKeyBase
    const pkb = PrivateKeyBase.random();
    const originalData = pkb.bytes;

    // Split it using SSKR
    const secret = Secret.from(originalData);
    const group = GroupSpec.from({ memberThreshold: 2, memberCount: 3 });
    const spec = Spec.from({ groupThreshold: 1, groups: [group] });

    const groups = SskrShare.generate(spec, secret);

    // Recover with 2 shares
    const recovered = SskrShare.combine([groups[0][0], groups[0][1]]);

    // Create new PrivateKeyBase from recovered data
    const recoveredPkb = PrivateKeyBase.from(recovered.bytes);

    // Should derive the same keys
    const originalSigning = pkb.ed25519SigningPrivateKey();
    const recoveredSigning = recoveredPkb.ed25519SigningPrivateKey();
    expect(originalSigning.equals(recoveredSigning)).toBe(true);

    const originalX25519 = pkb.x25519PrivateKey();
    const recoveredX25519 = recoveredPkb.x25519PrivateKey();
    expect(originalX25519.equals(recoveredX25519)).toBe(true);
  });
});
