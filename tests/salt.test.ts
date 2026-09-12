/**
 * Tests for Salt class
 *
 * Ported from bc-components-rust/src/salt.rs
 */

import { describe, it, expect } from "vitest";
import { Salt } from "../src/salt.js";
import { UR, decodeURWith } from "@blockchaincommons/uniform-resources";
import { decodeCbor } from "@blockchaincommons/dcbor";

describe("Salt", () => {
  const MIN_SALT_SIZE = 8;

  describe("creation", () => {
    it("should create a salt with specific length", () => {
      const salt = Salt.random({ length: 16 });

      expect(salt.byteLength).toBe(16);
    });

    it("should throw when length is less than minimum", () => {
      expect(() => Salt.random({ length: 4 })).toThrow();
    });

    it("should create a salt from raw data", () => {
      const rawData = new Uint8Array(16);
      const salt = Salt.from(rawData);

      expect(salt.byteLength).toBe(16);
    });

    it("should create a salt using from (legacy alias)", () => {
      const rawData = new Uint8Array(16);
      const salt = Salt.from(rawData);

      expect(salt.byteLength).toBe(16);
    });

    it("should create a salt from hex string", () => {
      // 16 bytes = 32 hex chars
      const hex = "0102030405060708090a0b0c0d0e0f10";
      const salt = Salt.fromHex(hex);

      expect(salt.byteLength).toBe(16);
      expect(salt.toHex()).toBe(hex);
    });

    it("should create a salt using random (legacy alias)", () => {
      const salt = Salt.random();

      expect(salt.byteLength).toBe(16); // Default size
    });

    it("should create a salt using random with custom size", () => {
      const salt = Salt.random({ length: 32 });

      expect(salt.byteLength).toBe(32);
    });

    it("should create a salt using proportional (legacy alias)", () => {
      const salt = Salt.forSize(100);

      expect(salt.byteLength).toBeGreaterThanOrEqual(MIN_SALT_SIZE);
    });
  });

  describe("newInRange", () => {
    it("should create a salt within specified range", () => {
      const salt = Salt.randomInRange(16, 32);

      expect(salt.byteLength).toBeGreaterThanOrEqual(16);
      expect(salt.byteLength).toBeLessThanOrEqual(32);
    });

    it("should throw when minimum is less than 8", () => {
      expect(() => Salt.randomInRange(4, 32)).toThrow();
    });
  });

  describe("newForSize", () => {
    it("should create proportional salt for small size", () => {
      const salt = Salt.forSize(100);

      expect(salt.byteLength).toBeGreaterThanOrEqual(MIN_SALT_SIZE);
    });

    it("should create proportional salt for large size", () => {
      const salt = Salt.forSize(1000);

      expect(salt.byteLength).toBeGreaterThanOrEqual(MIN_SALT_SIZE);
    });

    it("should create larger salt for larger data", () => {
      // Multiple samples to get reasonable averages
      let smallTotal = 0;
      let largeTotal = 0;
      const samples = 10;

      for (let i = 0; i < samples; i++) {
        smallTotal += Salt.forSize(100).byteLength;
        largeTotal += Salt.forSize(1000).byteLength;
      }

      // Large should generally be bigger on average
      expect(largeTotal / samples).toBeGreaterThan(smallTotal / samples);
    });
  });

  describe("accessors", () => {
    it("should return correct length via len()", () => {
      const salt = Salt.random({ length: 20 });

      expect(salt.byteLength).toBe(20);
    });

    it("should return correct length via size()", () => {
      const salt = Salt.random({ length: 20 });

      expect(salt.byteLength).toBe(20);
    });

    it("should return isEmpty correctly", () => {
      const salt = Salt.random({ length: 16 });

      expect(salt.isEmpty()).toBe(false);
    });

    it("should return data as bytes", () => {
      const salt = Salt.random({ length: 16 });

      expect(salt.bytes).toBeInstanceOf(Uint8Array);
      expect(salt.bytes).toBeInstanceOf(Uint8Array);
    });

    it("should return hex representation", () => {
      const salt = Salt.random({ length: 16 });
      const hex = salt.toHex();

      expect(typeof hex).toBe("string");
      expect(hex.length).toBe(32); // 16 bytes * 2
    });

    it("should return same hex from hex() and toHex()", () => {
      const salt = Salt.random({ length: 16 });

      expect(salt.toHex()).toBe(salt.toHex());
    });

    it("should return base64 representation", () => {
      const salt = Salt.random({ length: 16 });

      expect(typeof salt.toBase64()).toBe("string");
    });

    it("should return string representation", () => {
      const salt = Salt.random({ length: 16 });
      const str = salt.toString();

      expect(str).toContain("Salt");
      expect(str).toContain("16");
    });
  });

  describe("equality", () => {
    it("should be equal to itself", () => {
      const salt = Salt.random({ length: 16 });

      expect(salt.equals(salt)).toBe(true);
    });

    it("should be equal to another salt with the same data", () => {
      const hex = "0102030405060708090a0b0c0d0e0f10";
      const salt1 = Salt.fromHex(hex);
      const salt2 = Salt.fromHex(hex);

      expect(salt1.equals(salt2)).toBe(true);
    });

    it("should not be equal to a salt with different data", () => {
      const salt1 = Salt.fromHex("0102030405060708090a0b0c0d0e0f10");
      const salt2 = Salt.fromHex("100f0e0d0c0b0a090807060504030201");

      expect(salt1.equals(salt2)).toBe(false);
    });

    it("should not be equal to salts of different length", () => {
      const salt1 = Salt.random({ length: 16 });
      const salt2 = Salt.random({ length: 32 });

      expect(salt1.equals(salt2)).toBe(false);
    });
  });

  describe("CBOR serialization", () => {
    it("should return correct CBOR tags", () => {
      const salt = Salt.random({ length: 16 });
      const tags = salt.cborTags();

      expect(tags.length).toBeGreaterThan(0);
    });

    it("should serialize to untagged CBOR", () => {
      const salt = Salt.random({ length: 16 });
      const untagged = salt.untaggedCbor();

      expect(untagged).toBeDefined();
    });

    it("should serialize to tagged CBOR", () => {
      const salt = Salt.random({ length: 16 });
      const tagged = salt.toCbor();

      expect(tagged).toBeDefined();
    });

    it("should serialize to tagged CBOR binary data", () => {
      const salt = Salt.random({ length: 16 });
      const data = salt.toCbor().toData();

      expect(data).toBeInstanceOf(Uint8Array);
      expect(data.length).toBeGreaterThan(0);
    });

    it("should roundtrip through tagged CBOR", () => {
      const salt = Salt.random({ length: 16 });
      const data = salt.toCbor().toData();
      const restored = Salt.fromCbor(decodeCbor(data));

      expect(restored.equals(salt)).toBe(true);
    });

    it("should roundtrip through untagged CBOR", () => {
      const salt = Salt.random({ length: 16 });
      const data = salt.untaggedCbor().toData();
      const restored = Salt.codec.decodeUntagged(decodeCbor(data));

      expect(restored.equals(salt)).toBe(true);
    });
  });

  describe("UR serialization", () => {
    it("should serialize to UR", () => {
      const salt = Salt.random({ length: 16 });
      const ur = salt.toUR();

      expect(ur).toBeDefined();
    });

    it("should serialize to UR string", () => {
      const salt = Salt.random({ length: 16 });
      const urString = salt.toUR().toString();

      expect(urString.startsWith("ur:salt/")).toBe(true);
    });

    it("should roundtrip through UR string", () => {
      const salt = Salt.random({ length: 16 });
      const urString = salt.toUR().toString();
      const restored = decodeURWith(UR.parse(urString), Salt.codec);

      expect(restored.equals(salt)).toBe(true);
    });

    it("should throw on invalid UR type", () => {
      const invalidUr = "ur:not_salt/invalid";

      expect(() => decodeURWith(UR.parse(invalidUr), Salt.codec)).toThrow();
    });
  });
});
