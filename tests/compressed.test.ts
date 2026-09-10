/**
 * Tests for the Compressed module
 * Ported from bc-components-rust/src/compressed.rs tests
 */

import { describe, it, expect } from "vitest";
import { Compressed, Digest } from "../src/index.js";
import { decodeCbor } from "@blockchaincommons/dcbor";

describe("Compressed", () => {
  describe("basic compression", () => {
    it("test_1 - should compress and decompress large text with good ratio", () => {
      const source = new TextEncoder().encode(
        "Lorem ipsum dolor sit amet consectetur adipiscing elit mi nibh ornare proin blandit diam ridiculus, faucibus mus dui eu vehicula nam donec dictumst sed vivamus bibendum aliquet efficitur. Felis imperdiet sodales dictum morbi vivamus augue dis duis aliquet velit ullamcorper porttitor, lobortis dapibus hac purus aliquam natoque iaculis blandit montes nunc pretium.",
      );
      const compressed = Compressed.fromDecompressedData(source);

      // Verify compression occurred
      expect(compressed.compressedSize()).toBeLessThan(source.length);
      expect(compressed.compressionRatio()).toBeLessThan(0.7);
      expect(compressed.decompressedSize()).toBe(source.length);

      // Verify decompression
      const decompressed = compressed.decompress();
      expect(decompressed).toEqual(source);
    });

    it("test_2 - should handle medium text correctly", () => {
      const source = new TextEncoder().encode("Lorem ipsum dolor sit amet consectetur adipiscing");
      const compressed = Compressed.fromDecompressedData(source);

      // Medium text may or may not compress depending on content
      // It should at least not be larger than original
      expect(compressed.compressedSize()).toBeLessThanOrEqual(source.length);
      expect(compressed.compressionRatio()).toBeLessThanOrEqual(1.0);
      expect(compressed.decompressedSize()).toBe(source.length);

      // Verify decompression
      const decompressed = compressed.decompress();
      expect(decompressed).toEqual(source);
    });

    it("test_3 - should store small data uncompressed when compression is ineffective", () => {
      const source = new TextEncoder().encode("Lorem");
      const compressed = Compressed.fromDecompressedData(source);

      // Small data shouldn't be compressed (compression would increase size)
      expect(compressed.compressedSize()).toBe(source.length);
      expect(compressed.compressionRatio()).toBe(1.0);
      expect(compressed.decompressedSize()).toBe(source.length);

      // Verify decompression
      const decompressed = compressed.decompress();
      expect(decompressed).toEqual(source);
    });

    it("test_4 - should handle empty data", () => {
      const source = new Uint8Array(0);
      const compressed = Compressed.fromDecompressedData(source);

      expect(compressed.compressedSize()).toBe(0);
      expect(compressed.decompressedSize()).toBe(0);
      expect(compressed.compressionRatio()).toBe(Number.NaN);

      // Verify decompression
      const decompressed = compressed.decompress();
      expect(decompressed).toEqual(source);
    });
  });

  describe("with digest", () => {
    it("should store and retrieve digest", () => {
      const source = new TextEncoder().encode("Hello world!");
      const digest = Digest.fromImage(source);
      const compressed = Compressed.fromDecompressedData(source, digest);

      expect(compressed.hasDigest()).toBe(true);
      expect(compressed.digestOpt()).toBeDefined();
      expect(compressed.digestOpt()?.equals(digest)).toBe(true);
      expect(compressed.digest().equals(digest)).toBe(true);
    });

    it("should handle missing digest", () => {
      const source = new TextEncoder().encode("Hello world!");
      const compressed = Compressed.fromDecompressedData(source);

      expect(compressed.hasDigest()).toBe(false);
      expect(compressed.digestOpt()).toBeUndefined();
      expect(() => compressed.digest()).toThrow();
    });
  });

  describe("CBOR serialization", () => {
    it("should roundtrip through tagged CBOR", () => {
      const source = new TextEncoder().encode(
        "This is a test string for CBOR roundtrip that should compress well with some repeated patterns patterns patterns.",
      );
      const compressed = Compressed.fromDecompressedData(source);

      const cborData = compressed.toCbor().toData();
      const recovered = Compressed.fromCbor(decodeCbor(cborData));

      expect(recovered.equals(compressed)).toBe(true);
      expect(recovered.decompress()).toEqual(source);
    });

    it("should roundtrip through untagged CBOR", () => {
      const source = new TextEncoder().encode(
        "Another test string for untagged CBOR roundtrip with repeated content content content.",
      );
      const compressed = Compressed.fromDecompressedData(source);

      const cborData = compressed.untaggedCbor().toData();
      const recovered = Compressed.fromCbor(decodeCbor(cborData));

      expect(recovered.equals(compressed)).toBe(true);
      expect(recovered.decompress()).toEqual(source);
    });

    it("should roundtrip with digest through CBOR", () => {
      const source = new TextEncoder().encode("Test data with digest");
      const digest = Digest.fromImage(source);
      const compressed = Compressed.fromDecompressedData(source, digest);

      const cborData = compressed.toCbor().toData();
      const recovered = Compressed.fromCbor(decodeCbor(cborData));

      expect(recovered.hasDigest()).toBe(true);
      expect(recovered.digestOpt()?.equals(digest)).toBe(true);
    });
  });

  describe("equality", () => {
    it("should compare equal compressed objects", () => {
      const source = new TextEncoder().encode("Test data for equality");
      const compressed1 = Compressed.fromDecompressedData(source);
      const compressed2 = Compressed.fromDecompressedData(source);

      expect(compressed1.equals(compressed2)).toBe(true);
    });

    it("should detect different compressed objects", () => {
      const source1 = new TextEncoder().encode("Test data one");
      const source2 = new TextEncoder().encode("Test data two");
      const compressed1 = Compressed.fromDecompressedData(source1);
      const compressed2 = Compressed.fromDecompressedData(source2);

      expect(compressed1.equals(compressed2)).toBe(false);
    });
  });

  describe("string representation", () => {
    it("should produce readable toString output", () => {
      const source = new TextEncoder().encode(
        "Test data for string representation with some repetition repetition repetition.",
      );
      const compressed = Compressed.fromDecompressedData(source);

      const str = compressed.toString();
      expect(str).toContain("Compressed");
      expect(str).toContain("checksum:");
      expect(str).toContain("size:");
      expect(str).toContain("ratio:");
    });
  });

  describe("highly compressible data", () => {
    it("should achieve very good compression ratio for repetitive data", () => {
      // 50 'A' characters should compress very well
      const source = new TextEncoder().encode("A".repeat(50));
      const compressed = Compressed.fromDecompressedData(source);

      // Should have very good compression
      expect(compressed.compressionRatio()).toBeLessThan(0.5);
    });
  });
});

describe("Compressed - miniz_oxide interop (RUST_DIVERGENCES D3)", () => {
  // Produced by tests/rust-validation/examples/dump_compressed.rs with
  // bc-components-rust 0.31.1 (miniz_oxide level 6). pako's level-6 stream
  // for the same input differs; both sides must decompress each other's.
  const RUST_TAGGED_HEX =
    "d99c43831a0eca22c618e4583cd5cb010dc0200c04402b2f6099124c90d22c9f504adae27f3a1070cd430ddc790cc3a70792856e5a0fc457aa94d609f4c1cd14ae0f3a592fda3df007";
  const TEXT = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(4);

  it("decompresses a stream produced by miniz_oxide", () => {
    const bytes = Uint8Array.from(RUST_TAGGED_HEX.match(/../g)!.map((b) => parseInt(b, 16)));
    const c = Compressed.fromCbor(decodeCbor(bytes));
    expect(new TextDecoder().decode(c.decompress())).toBe(TEXT);
    expect(c.decompressedSize()).toBe(TEXT.length);
  });

  it("produces a different but equivalent stream with pako", () => {
    const ours = Compressed.fromDecompressedData(new TextEncoder().encode(TEXT));
    const hex = Array.from(ours.toCbor().toData(), (b) => b.toString(16).padStart(2, "0")).join("");
    expect(hex).not.toBe(RUST_TAGGED_HEX);
    expect(ours.decompress()).toEqual(new TextEncoder().encode(TEXT));
  });
});
