/* eslint-disable @typescript-eslint/no-non-null-assertion -- fixtures are indexed by position; a miss fails the test */
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
      expect(compressed.compressedSize).toBeLessThan(source.length);
      expect(compressed.compressionRatio).toBeLessThan(0.7);
      expect(compressed.decompressedSize).toBe(source.length);

      // Verify decompression
      const decompressed = compressed.decompress();
      expect(decompressed).toEqual(source);
    });

    it("test_2 - should handle medium text correctly", () => {
      const source = new TextEncoder().encode("Lorem ipsum dolor sit amet consectetur adipiscing");
      const compressed = Compressed.fromDecompressedData(source);

      // Medium text may or may not compress depending on content
      // It should at least not be larger than original
      expect(compressed.compressedSize).toBeLessThanOrEqual(source.length);
      expect(compressed.compressionRatio).toBeLessThanOrEqual(1.0);
      expect(compressed.decompressedSize).toBe(source.length);

      // Verify decompression
      const decompressed = compressed.decompress();
      expect(decompressed).toEqual(source);
    });

    it("test_3 - should store small data uncompressed when compression is ineffective", () => {
      const source = new TextEncoder().encode("Lorem");
      const compressed = Compressed.fromDecompressedData(source);

      // Small data shouldn't be compressed (compression would increase size)
      expect(compressed.compressedSize).toBe(source.length);
      expect(compressed.compressionRatio).toBe(1.0);
      expect(compressed.decompressedSize).toBe(source.length);

      // Verify decompression
      const decompressed = compressed.decompress();
      expect(decompressed).toEqual(source);
    });

    it("test_4 - should handle empty data", () => {
      const source = new Uint8Array(0);
      const compressed = Compressed.fromDecompressedData(source);

      expect(compressed.compressedSize).toBe(0);
      expect(compressed.decompressedSize).toBe(0);
      expect(compressed.compressionRatio).toBe(Number.NaN);

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
      const recovered = Compressed.codec.decodeUntagged(decodeCbor(cborData));

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
      expect(compressed.compressionRatio).toBeLessThan(0.5);
    });
  });
});

describe("Compressed - the reference's bytes", () => {
  // The reference's tagged CBOR for this input (bc-components 0.31.1 over
  // miniz_oxide 0.8.9 at level 6); the in-package port produces the same
  // stream.
  const RUST_TAGGED_HEX =
    "d99c43831a0eca22c618e4583cd5cb010dc0200c04402b2f6099124c90d22c9f504adae27f3a1070cd430ddc790cc3a70792856e5a0fc457aa94d609f4c1cd14ae0f3a592fda3df007";
  const TEXT = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(4);

  it("decompresses a stream produced by miniz_oxide", () => {
    const bytes = Uint8Array.from(RUST_TAGGED_HEX.match(/../g)!.map((b) => parseInt(b, 16)));
    const c = Compressed.fromCbor(decodeCbor(bytes));
    expect(new TextDecoder().decode(c.decompress())).toBe(TEXT);
    expect(c.decompressedSize).toBe(TEXT.length);
  });

  it("produces the reference's stream byte for byte", () => {
    const ours = Compressed.fromDecompressedData(new TextEncoder().encode(TEXT));
    const hex = Array.from(ours.toCbor().toData(), (b) => b.toString(16).padStart(2, "0")).join("");
    expect(hex).toBe(RUST_TAGGED_HEX);
    expect(ours.decompress()).toEqual(new TextEncoder().encode(TEXT));
  });

  it("compares the digest in equals, as the reference's derived PartialEq", () => {
    const data = new TextEncoder().encode(TEXT);
    const a = Compressed.fromDecompressedData(data);
    const b = Compressed.fromDecompressedData(data, Digest.fromImage(data));
    const c = Compressed.fromDecompressedData(data, Digest.fromImage(data));
    expect(a.equals(b)).toBe(false);
    expect(b.equals(c)).toBe(true);
    expect(
      b.equals(Compressed.fromDecompressedData(data, Digest.fromImage(new Uint8Array(1)))),
    ).toBe(false);
  });

  it("decodes the checksum as a u32 and the size as a usize with the reference's negative wrap", () => {
    const decode = (hex: string) =>
      Compressed.fromCbor(decodeCbor(Uint8Array.from(Buffer.from(hex, "hex"))));
    // [-1, 10, h'00'] → checksum 4294967295
    expect(decode("d99c438320" + "0a" + "4100").checksum).toBe(0xffffffff);
    // [-4294967296, 10, h'00'] → checksum 0
    expect(decode("d99c43833affffffff" + "0a" + "4100").checksum).toBe(0);
    // [0, 2^53 + 1, h'00'] → the exact size, a bigint
    expect(decode("d99c438300" + "1b0020000000000001" + "4100").decompressedSize).toBe(
      9007199254740993n,
    );
    // [0, -1, h'00'] → 2^64 − 1
    expect(decode("d99c438300" + "20" + "4100").decompressedSize).toBe(18446744073709551615n);
    // above the widths: OutOfRange as `Cbor`
    for (const hex of [
      "d99c43831b0000000100000000" + "0a" + "4100",
      "d99c43833b0000000100000000" + "0a" + "4100",
    ]) {
      expect(() => decode(hex)).toThrow(
        "the CBOR numeric value could not be represented in the specified numeric type",
      );
    }
    // the size check is `Compression`
    let thrown: unknown;
    try {
      Compressed.fromParts({ checksum: 0, decompressedSize: 1, compressedData: new Uint8Array(2) });
    } catch (e) {
      thrown = e;
    }
    expect((thrown as { code: string }).code).toBe("Compression");
    expect((thrown as Error).message).toBe(
      "compression error: compressed data is larger than decompressed size",
    );
  });
});
