/**
 * Hex parsing is dcbor's (Phase 2.2): one rule across the closure. The
 * observable change from the package's former helper is recorded here so a
 * consumer relying on the old behaviour finds it in the suite, not in
 * production: whitespace is now tolerated, and the error is a `CborError`.
 */
import { describe, it, expect } from "vitest";
import { CborError } from "@blockchaincommons/dcbor";
import { Digest, ARID } from "../src/index.js";
import { bytesToHex, hexToBytes } from "../src/utils.js";

describe("hex through dcbor", () => {
  const HEX = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

  it("round-trips and lowercases", () => {
    expect(bytesToHex(hexToBytes(HEX.toUpperCase()))).toBe(HEX);
    expect(Digest.fromHex(HEX.toUpperCase()).hex()).toBe(HEX);
  });

  it("tolerates ASCII whitespace (new)", () => {
    const spaced = HEX.replace(/(.{8})/g, "$1 ").trim();
    expect(ARID.fromHex(spaced).hex()).toBe(HEX);
  });

  it("rejects odd length and non-hex characters with CborError", () => {
    for (const bad of [
      "abc",
      "zz",
      "0x00",
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcdeg",
    ]) {
      expect(() => hexToBytes(bad)).toThrow(CborError);
    }
  });
});
