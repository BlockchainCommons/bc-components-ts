/**
 * Tests for the CborJson module
 * Ported from bc-components-rust/src/json.rs tests
 */

import { describe, it, expect } from "vitest";
import { CborJson } from "../src/index.js";
import { decodeCbor } from "@blockchaincommons/dcbor";

describe("CborJson", () => {
  describe("creation", () => {
    it("should create from string", () => {
      const json = CborJson.fromString('{"key": "value"}');
      expect(json.asStr()).toBe('{"key": "value"}');
      expect(json.byteLength).toBe(16);
      expect(json.isEmpty()).toBe(false);
    });

    it("should create from bytes", () => {
      const data = new TextEncoder().encode("[1, 2, 3]");
      const json = CborJson.from(data);
      expect(json.bytes).toEqual(data);
      expect(json.asStr()).toBe("[1, 2, 3]");
    });

    it("should handle empty CborJson", () => {
      const json = CborJson.fromString("");
      expect(json.isEmpty()).toBe(true);
      expect(json.byteLength).toBe(0);
    });
  });

  describe("hex encoding", () => {
    it("should convert to and from hex", () => {
      const json = CborJson.fromString("test");
      const hex = json.toHex();
      const json2 = CborJson.fromHex(hex);
      expect(json.equals(json2)).toBe(true);
    });
  });

  describe("CBOR serialization", () => {
    it("should roundtrip through tagged CBOR", () => {
      const json = CborJson.fromString('{"name":"Alice","age":30}');
      const cborData = json.toCbor().toData();
      const json2 = CborJson.fromCbor(decodeCbor(cborData));
      expect(json.equals(json2)).toBe(true);
      expect(json2.asStr()).toBe('{"name":"Alice","age":30}');
    });

    it("should roundtrip through untagged CBOR", () => {
      const json = CborJson.fromString('["array", "data"]');
      const cborData = json.untaggedCbor().toData();
      const json2 = CborJson.codec.decodeUntagged(decodeCbor(cborData));
      expect(json.equals(json2)).toBe(true);
    });
  });

  describe("equality", () => {
    it("should compare equal CborJson objects", () => {
      const json1 = CborJson.fromString('{"test": true}');
      const json2 = CborJson.fromString('{"test": true}');
      expect(json1.equals(json2)).toBe(true);
    });

    it("should detect different CborJson objects", () => {
      const json1 = CborJson.fromString('{"test": true}');
      const json2 = CborJson.fromString('{"test": false}');
      expect(json1.equals(json2)).toBe(false);
    });
  });

  describe("string representation", () => {
    it("should produce readable toString output", () => {
      const json = CborJson.fromString('{"test":true}');
      const str = json.toString();
      expect(str).toBe('JSON({"test":true})');
    });
  });

  describe("data access", () => {
    it("should return copy of data", () => {
      const json = CborJson.fromString("data");
      const bytes1 = json.bytes;
      const bytes2 = json.bytes;

      // Should be equal but different arrays
      expect(bytes1).toEqual(bytes2);
      expect(bytes1).not.toBe(bytes2);
    });
  });

  describe("complex CborJson", () => {
    it("should handle nested objects", () => {
      const complex = CborJson.fromString('{"outer":{"inner":"value","array":[1,2,3]}}');
      expect(complex.asStr()).toBe('{"outer":{"inner":"value","array":[1,2,3]}}');

      // Roundtrip through CBOR
      const cborData = complex.toCbor().toData();
      const recovered = CborJson.fromCbor(decodeCbor(cborData));
      expect(recovered.equals(complex)).toBe(true);
    });

    it("should handle unicode", () => {
      const unicode = CborJson.fromString('{"emoji":"🎉","japanese":"日本語"}');
      expect(unicode.asStr()).toBe('{"emoji":"🎉","japanese":"日本語"}');

      // Roundtrip through CBOR
      const cborData = unicode.toCbor().toData();
      const recovered = CborJson.fromCbor(decodeCbor(cborData));
      expect(recovered.asStr()).toBe('{"emoji":"🎉","japanese":"日本語"}');
    });
  });
});
