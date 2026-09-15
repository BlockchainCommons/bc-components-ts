/**
 * Tests for the HKDFRng module
 * Ported from bc-components-rust/src/hkdf_rng.rs tests
 */

import { describe, it, expect } from "vitest";
import { randomBytes } from "@blockchaincommons/rand";
import { bytesToHex, ComponentsError } from "../src/index.js";
import { HKDFRng } from "../src/kdf.js";

describe("HKDFRng", () => {
  const KEY_MATERIAL = new TextEncoder().encode("key_material");
  const SALT = "salt";

  describe("creation", () => {
    it("should create with default page length", () => {
      const rng = new HKDFRng(KEY_MATERIAL, SALT);
      expect(rng.keyMaterial).toEqual(KEY_MATERIAL);
      expect(rng.salt).toBe(SALT);
      expect(rng.pageLength).toBe(32);
      expect(rng.pageIndex).toBe(0);
    });

    it("should create with custom page length", () => {
      const rng = new HKDFRng(KEY_MATERIAL, SALT, { pageLength: 64 });
      expect(rng.pageLength).toBe(64);
    });

    it("accepts a page length of 0, as the reference, and serves empty draws", () => {
      const rng = new HKDFRng(KEY_MATERIAL, SALT, { pageLength: 0 });
      expect(rng.pageLength).toBe(0);
      expect(randomBytes(0, { rng })).toEqual(new Uint8Array(0));
      rng.fillBytes(new Uint8Array(0));
      expect(rng.pageIndex).toBe(0);
    });

    it("throws InvalidData on the first byte requested at page length 0 (the reference never returns)", () => {
      const rng = new HKDFRng(KEY_MATERIAL, SALT, { pageLength: 0 });
      for (const draw of [
        () => rng.nextU32(),
        () => rng.nextU64(),
        () => rng.fillBytes(new Uint8Array(1)),
        () => randomBytes(1, { rng }),
      ]) {
        let thrown: unknown;
        try {
          draw();
        } catch (e) {
          thrown = e;
        }
        expect(ComponentsError.isComponentsError(thrown)).toBe(true);
        expect((thrown as ComponentsError).code).toBe("InvalidData");
        expect((thrown as ComponentsError).message).toBe(
          "invalid HKDFRng: page length is 0; no bytes can be produced",
        );
      }
      expect(rng.pageIndex).toBe(0);
    });

    it("rejects a page length outside [0, 2^32 - 1] or not an integer", () => {
      for (const pageLength of [-1, 1.5, NaN, Infinity, 2 ** 32]) {
        expect(() => new HKDFRng(KEY_MATERIAL, SALT, { pageLength })).toThrow(ComponentsError);
      }
    });

    it("has no randomData, tryFillBytes or fillRandomData: bytes come through rand's helpers", () => {
      const rng = new HKDFRng(KEY_MATERIAL, SALT);
      expect("randomData" in rng).toBe(false);
      expect("tryFillBytes" in rng).toBe(false);
      expect("fillRandomData" in rng).toBe(false);
    });
  });

  describe("deterministic output", () => {
    it("should produce deterministic next_bytes", () => {
      const rng = new HKDFRng(KEY_MATERIAL, SALT);

      expect(bytesToHex(randomBytes(16, { rng: rng }))).toBe("1032ac8ffea232a27c79fe381d7eb7e4");
      expect(bytesToHex(randomBytes(16, { rng: rng }))).toBe("aeaaf727d35b6f338218391f9f8fa1f3");
      expect(bytesToHex(randomBytes(16, { rng: rng }))).toBe("4348a59427711deb1e7d8a6959c6adb4");
      expect(bytesToHex(randomBytes(16, { rng: rng }))).toBe("5d937a42cb5fb090fe1a1ec88f56e32b");
    });

    it("should produce deterministic nextU32 (unsigned, matches Rust)", () => {
      const rng = new HKDFRng(KEY_MATERIAL, SALT);
      expect(rng.nextU32()).toBe(2410426896);
    });

    it("should produce deterministic nextU64", () => {
      const rng = new HKDFRng(KEY_MATERIAL, SALT);
      const num = rng.nextU64();
      expect(num).toBe(BigInt("11687583197195678224"));
    });

    it("should produce deterministic fillBytes", () => {
      const rng = new HKDFRng(KEY_MATERIAL, SALT);
      const dest = new Uint8Array(16);
      rng.fillBytes(dest);
      expect(bytesToHex(dest)).toBe("1032ac8ffea232a27c79fe381d7eb7e4");
    });
  });

  describe("reproducibility", () => {
    it("should produce same sequence with same seed and salt", () => {
      const rng1 = new HKDFRng(KEY_MATERIAL, SALT);
      const rng2 = new HKDFRng(KEY_MATERIAL, SALT);

      const random1_1 = rng1.nextU32();
      const random1_2 = rng1.nextU32();

      const random2_1 = rng2.nextU32();
      const random2_2 = rng2.nextU32();

      expect(random1_1).toBe(random2_1);
      expect(random1_2).toBe(random2_2);
    });

    it("should produce different sequence with different salt", () => {
      const rng1 = new HKDFRng(KEY_MATERIAL, "salt1");
      const rng2 = new HKDFRng(KEY_MATERIAL, "salt2");

      const random1 = rng1.nextU32();
      const random2 = rng2.nextU32();

      expect(random1).not.toBe(random2);
    });

    it("should produce different sequence with different key material", () => {
      const keyMaterial1 = new TextEncoder().encode("key1");
      const keyMaterial2 = new TextEncoder().encode("key2");

      const rng1 = new HKDFRng(keyMaterial1, SALT);
      const rng2 = new HKDFRng(keyMaterial2, SALT);

      const random1 = rng1.nextU32();
      const random2 = rng2.nextU32();

      expect(random1).not.toBe(random2);
    });
  });

  describe("buffer management", () => {
    it("should handle requests larger than page length", () => {
      const rng = new HKDFRng(KEY_MATERIAL, SALT, { pageLength: 16 });

      // Request more bytes than page length
      const data = randomBytes(64, { rng: rng });
      expect(data.length).toBe(64);

      // Should have fetched multiple pages
      expect(rng.pageIndex).toBeGreaterThan(1);
    });

    it("should handle multiple small requests across page boundaries", () => {
      const rng = new HKDFRng(KEY_MATERIAL, SALT, { pageLength: 16 });

      // Make multiple small requests
      const chunks: Uint8Array[] = [];
      for (let i = 0; i < 10; i++) {
        chunks.push(randomBytes(8, { rng: rng }));
      }

      // All chunks should be different (statistically)
      const hexChunks = chunks.map(bytesToHex);
      const uniqueChunks = new Set(hexChunks);
      expect(uniqueChunks.size).toBe(10);
    });
  });

  describe("RandomNumberGenerator interface", () => {
    it("should implement fillBytes", () => {
      const rng = new HKDFRng(KEY_MATERIAL, SALT);
      const dest = new Uint8Array(32);
      rng.fillBytes(dest);

      // Should have data (not all zeros)
      const sum = dest.reduce((a, b) => a + b, 0);
      expect(sum).toBeGreaterThan(0);
    });
  });

  describe("page index progression", () => {
    it("should increment page index as buffer is consumed", () => {
      const rng = new HKDFRng(KEY_MATERIAL, SALT, { pageLength: 16 });

      expect(rng.pageIndex).toBe(0);

      // Consume first page
      randomBytes(16, { rng: rng });
      expect(rng.pageIndex).toBe(1);

      // Consume second page
      randomBytes(16, { rng: rng });
      expect(rng.pageIndex).toBe(2);
    });
  });
});
