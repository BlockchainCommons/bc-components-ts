/**
 * Hex parsing is dcbor's: one rule across the closure. The
 * observable change from the package's former helper is recorded here so a
 * consumer relying on the old behaviour finds it in the suite, not in
 * production: whitespace is now tolerated, and the error is a `CborError`.
 */
import { describe, it, expect } from "vitest";
import { CborError } from "@blockchaincommons/dcbor";
import { Digest, ARID, ComponentsError } from "../src/index.js";
import { bytesToHex, hexToBytes } from "../src/utils.js";

describe("hex through dcbor", () => {
  const HEX = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

  it("round-trips and lowercases", () => {
    expect(bytesToHex(hexToBytes(HEX.toUpperCase()))).toBe(HEX);
    expect(Digest.fromHex(HEX.toUpperCase()).toHex()).toBe(HEX);
  });

  it("fromHex is strict, as the reference's hex::decode: whitespace is a Hex failure", () => {
    const spaced = HEX.replace(/(.{8})/g, "$1 ").trim();
    let thrown: unknown;
    try {
      ARID.fromHex(spaced);
    } catch (e) {
      thrown = e;
    }
    expect(ComponentsError.isComponentsError(thrown)).toBe(true);
    expect((thrown as ComponentsError).code).toBe("Hex");
    // 64 digits plus 7 spaces: an odd byte count is reported before the character.
    expect((thrown as ComponentsError).message).toBe("hex decoding error: Odd number of digits");
    expect(() => ARID.fromHex(`${HEX}  `)).toThrow(
      "hex decoding error: Invalid character ' ' at position 64",
    );
    expect(() => ARID.fromHex(`+1${HEX.slice(2)}`)).toThrow(
      "hex decoding error: Invalid character '+' at position 0",
    );
    // The utility keeps tolerating whitespace; it is not a `from_hex`.
    expect(bytesToHex(hexToBytes(spaced))).toBe(HEX);
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
