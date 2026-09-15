/**
 * Tests for Digest class
 *
 * Ported from bc-components-rust/src/digest.rs
 */

import { describe, it, expect } from "vitest";
import { Digest } from "../src/digest.js";
import { hexToBytes } from "../src/utils.js";
import { UR, decodeURWith } from "@blockchaincommons/uniform-resources";
import { decodeCbor } from "@blockchaincommons/dcbor";

// The reference needs `register_tags()` before a UR is made; so does this package.
import { registerTags } from "../src/tags.js";
registerTags();

describe("Digest", () => {
  // Test data: SHA-256 hash of "hello world"
  const HELLO_WORLD_HASH = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

  describe("creation", () => {
    it("should create a digest from image data", () => {
      const data = new TextEncoder().encode("hello world");
      const digest = Digest.fromImage(data);

      expect(digest.bytes.length).toBe(Digest.DIGEST_SIZE);
      expect(digest.toHex()).toBe(HELLO_WORLD_HASH);
    });

    it("should create a digest from hex string", () => {
      const digest = Digest.fromHex(HELLO_WORLD_HASH);

      expect(digest.bytes.length).toBe(Digest.DIGEST_SIZE);
      expect(digest.toHex()).toBe(HELLO_WORLD_HASH);
    });

    it("should create a digest from raw data", () => {
      const rawData = hexToBytes(HELLO_WORLD_HASH);
      const digest = Digest.from(rawData);

      expect(digest.bytes.length).toBe(Digest.DIGEST_SIZE);
      expect(digest.toHex()).toBe(HELLO_WORLD_HASH);
    });

    it("should throw on invalid size", () => {
      const invalidData = new Uint8Array(16); // Wrong size
      expect(() => Digest.from(invalidData)).toThrow();
    });

    it("should throw on invalid hex string", () => {
      expect(() => Digest.fromHex("invalid_hex_string")).toThrow();
    });
  });

  describe("accessors", () => {
    it("should return data as bytes", () => {
      const digest = Digest.fromHex(HELLO_WORLD_HASH);

      expect(digest.bytes).toBeInstanceOf(Uint8Array);
      expect(digest.bytes).toBeInstanceOf(Uint8Array);
      expect(digest.bytes).toBeInstanceOf(Uint8Array);
    });

    it("should return hex representation", () => {
      const digest = Digest.fromHex(HELLO_WORLD_HASH);

      expect(digest.toHex()).toBe(HELLO_WORLD_HASH);
      expect(digest.toHex()).toBe(HELLO_WORLD_HASH);
    });

    it("should return base64 representation", () => {
      const digest = Digest.fromHex(HELLO_WORLD_HASH);

      expect(typeof digest.toBase64()).toBe("string");
    });

    it("should return short description", () => {
      const digest = Digest.fromHex(HELLO_WORLD_HASH);
      const shortDesc = digest.shortDescription();

      expect(shortDesc.length).toBe(8); // 4 bytes = 8 hex chars
      expect(shortDesc).toBe(HELLO_WORLD_HASH.slice(0, 8));
    });

    it("should return string representation", () => {
      const digest = Digest.fromHex(HELLO_WORLD_HASH);
      const str = digest.toString();

      expect(str).toContain("Digest");
      expect(str).toContain(HELLO_WORLD_HASH);
    });
  });

  describe("equality", () => {
    it("should be equal to itself", () => {
      const digest = Digest.fromHex(HELLO_WORLD_HASH);

      expect(digest.equals(digest)).toBe(true);
    });

    it("should be equal to another digest with the same data", () => {
      const digest1 = Digest.fromHex(HELLO_WORLD_HASH);
      const digest2 = Digest.fromHex(HELLO_WORLD_HASH);

      expect(digest1.equals(digest2)).toBe(true);
    });

    it("should not be equal to a digest with different data", () => {
      const digest1 = Digest.fromHex(HELLO_WORLD_HASH);
      // SHA-256 of empty string
      const digest2 = Digest.fromHex(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      );

      expect(digest1.equals(digest2)).toBe(false);
    });
  });

  describe("DigestProvider", () => {
    it("should return itself as digest", () => {
      const digest = Digest.fromHex(HELLO_WORLD_HASH);
      const providedDigest = digest.digest();

      expect(providedDigest.equals(digest)).toBe(true);
    });
  });

  describe("CBOR serialization", () => {
    it("should return correct CBOR tags", () => {
      const digest = Digest.fromHex(HELLO_WORLD_HASH);
      const tags = digest.cborTags();

      expect(tags.length).toBeGreaterThan(0);
    });

    it("should serialize to untagged CBOR", () => {
      const digest = Digest.fromHex(HELLO_WORLD_HASH);
      const untagged = digest.untaggedCbor();

      expect(untagged).toBeDefined();
    });

    it("should serialize to tagged CBOR", () => {
      const digest = Digest.fromHex(HELLO_WORLD_HASH);
      const tagged = digest.toCbor();

      expect(tagged).toBeDefined();
    });

    it("should serialize to tagged CBOR binary data", () => {
      const digest = Digest.fromHex(HELLO_WORLD_HASH);
      const data = digest.toCbor().toData();

      expect(data).toBeInstanceOf(Uint8Array);
      expect(data.length).toBeGreaterThan(0);
    });

    it("should roundtrip through tagged CBOR", () => {
      const digest = Digest.fromHex(HELLO_WORLD_HASH);
      const data = digest.toCbor().toData();
      const restored = Digest.fromCbor(decodeCbor(data));

      expect(restored.equals(digest)).toBe(true);
    });

    it("should roundtrip through untagged CBOR", () => {
      const digest = Digest.fromHex(HELLO_WORLD_HASH);
      const data = digest.untaggedCbor().toData();
      const restored = Digest.codec.decodeUntagged(decodeCbor(data));

      expect(restored.equals(digest)).toBe(true);
    });
  });

  describe("UR serialization", () => {
    it("should serialize to UR", () => {
      const digest = Digest.fromHex(HELLO_WORLD_HASH);
      const ur = digest.toUR();

      expect(ur).toBeDefined();
    });

    it("should serialize to UR string", () => {
      const data = new TextEncoder().encode("hello world");
      const digest = Digest.fromImage(data);
      const urString = digest.toUR().toString();

      expect(urString.startsWith("ur:digest/")).toBe(true);
    });

    it("should match expected UR string for 'hello world'", () => {
      const data = new TextEncoder().encode("hello world");
      const digest = Digest.fromImage(data);
      const urString = digest.toUR().toString();
      const expectedUrString =
        "ur:digest/hdcxrhgtdirhmugtfmayondmgmtstnkipyzssslrwsvlkngulawymhloylpsvowssnwlamnlatrs";

      expect(urString).toBe(expectedUrString);
    });

    it("should roundtrip through UR string", () => {
      const digest = Digest.fromHex(HELLO_WORLD_HASH);
      const urString = digest.toUR().toString();
      const restored = decodeURWith(UR.parse(urString), Digest.codec);

      expect(restored.equals(digest)).toBe(true);
    });

    it("should throw on invalid UR type", () => {
      const invalidUr = "ur:not_digest/invalid";

      expect(() => decodeURWith(UR.parse(invalidUr), Digest.codec)).toThrow();
    });
  });
});
