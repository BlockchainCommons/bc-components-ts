/**
 * Tests for Nonce class
 *
 * Ported from bc-components-rust/src/nonce.rs
 */

import { describe, it, expect } from "vitest";
import { Nonce } from "../src/nonce.js";
import { UR, decodeURWith } from "@blockchaincommons/uniform-resources";
import { decodeCbor } from "@blockchaincommons/dcbor";

describe("Nonce", () => {
  describe("creation", () => {
    it("should create a new random nonce", () => {
      const nonce = Nonce.random();

      expect(nonce.bytes.length).toBe(Nonce.NONCE_SIZE);
    });

    it("should create unique random nonces", () => {
      const nonce1 = Nonce.random();
      const nonce2 = Nonce.random();

      // While technically random, it's astronomically unlikely they'd be equal
      expect(nonce1.equals(nonce2)).toBe(false);
    });

    it("should create a nonce from raw data", () => {
      const rawData = new Uint8Array(Nonce.NONCE_SIZE);
      const nonce = Nonce.from(rawData);

      expect(nonce.bytes).toEqual(rawData);
    });

    it("should create a nonce using fromDataRef", () => {
      const rawData = new Uint8Array(Nonce.NONCE_SIZE);
      const nonce = Nonce.from(rawData);

      expect(nonce.bytes.length).toBe(Nonce.NONCE_SIZE);
    });

    it("should throw on wrong size with fromDataRef", () => {
      const wrongSizeData = new Uint8Array(Nonce.NONCE_SIZE + 1);

      expect(() => Nonce.from(wrongSizeData)).toThrow();
    });

    it("should create a nonce using from (legacy alias)", () => {
      const rawData = new Uint8Array(Nonce.NONCE_SIZE);
      const nonce = Nonce.from(rawData);

      expect(nonce.bytes.length).toBe(Nonce.NONCE_SIZE);
    });

    it("should create a nonce using random (alias)", () => {
      const nonce = Nonce.random();

      expect(nonce.bytes.length).toBe(Nonce.NONCE_SIZE);
    });

    it("should create a nonce from hex string", () => {
      // 12 bytes = 24 hex chars
      const hex = "0102030405060708090a0b0c";
      const nonce = Nonce.fromHex(hex);

      expect(nonce.bytes.length).toBe(Nonce.NONCE_SIZE);
      expect(nonce.toHex()).toBe(hex);
    });
  });

  describe("accessors", () => {
    it("should return data as bytes", () => {
      const nonce = Nonce.random();

      expect(nonce.bytes).toBeInstanceOf(Uint8Array);
      expect(nonce.bytes).toBeInstanceOf(Uint8Array);
      expect(nonce.bytes).toBeInstanceOf(Uint8Array);
    });

    it("should return hex representation", () => {
      const nonce = Nonce.random();
      const hex = nonce.toHex();

      expect(typeof hex).toBe("string");
      expect(hex.length).toBe(Nonce.NONCE_SIZE * 2);
    });

    it("should return same hex from hex() and toHex()", () => {
      const nonce = Nonce.random();

      expect(nonce.toHex()).toBe(nonce.toHex());
    });

    it("should return base64 representation", () => {
      const nonce = Nonce.random();

      expect(typeof nonce.toBase64()).toBe("string");
    });

    it("should return string representation", () => {
      const nonce = Nonce.random();
      const str = nonce.toString();

      expect(str).toContain("Nonce");
    });
  });

  describe("hex roundtrip", () => {
    it("should roundtrip through hex", () => {
      const nonce = Nonce.random();
      const hex = nonce.toHex();
      const restored = Nonce.fromHex(hex);

      expect(restored.equals(nonce)).toBe(true);
    });
  });

  describe("equality", () => {
    it("should be equal to itself", () => {
      const nonce = Nonce.random();

      expect(nonce.equals(nonce)).toBe(true);
    });

    it("should be equal to another nonce with the same data", () => {
      const hex = "0102030405060708090a0b0c";
      const nonce1 = Nonce.fromHex(hex);
      const nonce2 = Nonce.fromHex(hex);

      expect(nonce1.equals(nonce2)).toBe(true);
    });

    it("should not be equal to a nonce with different data", () => {
      const nonce1 = Nonce.fromHex("0102030405060708090a0b0c");
      const nonce2 = Nonce.fromHex("0c0b0a090807060504030201");

      expect(nonce1.equals(nonce2)).toBe(false);
    });
  });

  describe("CBOR serialization", () => {
    it("should return correct CBOR tags", () => {
      const nonce = Nonce.random();
      const tags = nonce.cborTags();

      expect(tags.length).toBeGreaterThan(0);
    });

    it("should serialize to untagged CBOR", () => {
      const nonce = Nonce.random();
      const untagged = nonce.untaggedCbor();

      expect(untagged).toBeDefined();
    });

    it("should serialize to tagged CBOR", () => {
      const nonce = Nonce.random();
      const tagged = nonce.toCbor();

      expect(tagged).toBeDefined();
    });

    it("should serialize to tagged CBOR binary data", () => {
      const nonce = Nonce.random();
      const data = nonce.toCbor().toData();

      expect(data).toBeInstanceOf(Uint8Array);
      expect(data.length).toBeGreaterThan(0);
    });

    it("should roundtrip through tagged CBOR", () => {
      const nonce = Nonce.random();
      const data = nonce.toCbor().toData();
      const restored = Nonce.fromCbor(decodeCbor(data));

      expect(restored.equals(nonce)).toBe(true);
    });

    it("should roundtrip through untagged CBOR", () => {
      const nonce = Nonce.random();
      const data = nonce.untaggedCbor().toData();
      const restored = Nonce.codec.decodeUntagged(decodeCbor(data));

      expect(restored.equals(nonce)).toBe(true);
    });
  });

  describe("UR serialization", () => {
    it("should serialize to UR", () => {
      const nonce = Nonce.random();
      const ur = nonce.toUR();

      expect(ur).toBeDefined();
    });

    it("should serialize to UR string", () => {
      const nonce = Nonce.random();
      const urString = nonce.toUR().toString();

      expect(urString.startsWith("ur:nonce/")).toBe(true);
    });

    it("should roundtrip through UR string", () => {
      const nonce = Nonce.random();
      const urString = nonce.toUR().toString();
      const restored = decodeURWith(UR.parse(urString), Nonce.codec);

      expect(restored.equals(nonce)).toBe(true);
    });

    it("should throw on invalid UR type", () => {
      const invalidUr = "ur:not_nonce/invalid";

      expect(() => decodeURWith(UR.parse(invalidUr), Nonce.codec)).toThrow();
    });
  });
});
