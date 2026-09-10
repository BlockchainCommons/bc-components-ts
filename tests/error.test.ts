import { describe, it, expect } from "vitest";
import { ComponentsError, COMPONENTS_ERROR_CODES, type ComponentsErrorCode } from "../src/index.js";

describe("ComponentsError", () => {
  it("carries a code and discriminated details", () => {
    const e = ComponentsError.invalidSizeForType("Digest", 32, 31);
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe("ComponentsError");
    expect(e.code).toBe("InvalidSize");
    expect(e.message).toBe("invalid Digest size: expected 32, got 31");
    if (e.details.code === "InvalidSize") {
      expect(e.details.dataType).toBe("Digest");
      expect(e.details.expected).toBe(32);
      expect(e.details.actual).toBe(31);
    } else {
      expect.unreachable();
    }
  });

  it("defaults the data type", () => {
    expect(ComponentsError.invalidSize(1, 2).message).toBe("invalid data size: expected 1, got 2");
    const d = ComponentsError.invalidData("bad");
    expect(d.message).toBe("invalid data: bad");
    expect(d.details).toEqual({ code: "InvalidData", dataType: "data", reason: "bad" });
    expect(ComponentsError.invalidFormat("x").details).toEqual({
      code: "InvalidData",
      dataType: "format",
      reason: "x",
    });
    const s = ComponentsError.dataTooShort("Seed", 16, 4);
    expect(s.message).toBe("data too short: Seed expected at least 16, got 4");
    expect(s.details).toEqual({ code: "DataTooShort", dataType: "Seed", minimum: 16, actual: 4 });
  });

  it("prefixes the message for every wrapped-dependency code", () => {
    const table: [ComponentsError, ComponentsErrorCode, string][] = [
      [ComponentsError.crypto("m"), "Crypto", "cryptographic operation failed: m"],
      [ComponentsError.cbor("m"), "Cbor", "CBOR error: m"],
      [ComponentsError.sskr("m"), "Sskr", "SSKR error: m"],
      [ComponentsError.ssh("m"), "Ssh", "SSH operation failed: m"],
      [ComponentsError.sshAgent("m"), "SshAgent", "SSH agent error: m"],
      [ComponentsError.uri("m"), "Uri", "invalid URI: m"],
      [ComponentsError.compression("m"), "Compression", "compression error: m"],
      [ComponentsError.postQuantum("m"), "PostQuantum", "post-quantum cryptography error: m"],
      [
        ComponentsError.levelMismatch(),
        "LevelMismatch",
        "signature level does not match key level",
      ],
      [ComponentsError.general("m"), "General", "m"],
    ];
    for (const [e, code, message] of table) {
      expect(e.code).toBe(code);
      expect(e.message).toBe(message);
      expect(e.is(code)).toBe(true);
      expect(e.details.code).toBe(code);
      expect("message" in e.details && e.details.message).toBe(
        code === "LevelMismatch" ? message : "m",
      );
    }
  });

  it("keeps the cause", () => {
    const inner = new RangeError("inner");
    const e = ComponentsError.crypto("outer", inner);
    expect(e.cause).toBe(inner);
    expect(ComponentsError.invalidData("x").cause).toBeUndefined();
  });

  it("is recognised structurally", () => {
    expect(ComponentsError.isComponentsError(ComponentsError.general("x"))).toBe(true);
    expect(ComponentsError.isComponentsError(new Error("x"))).toBe(false);
    expect(ComponentsError.isComponentsError(null)).toBe(false);
    expect(ComponentsError.isComponentsError({ code: "General" })).toBe(false);
  });

  it("lists every code once", () => {
    expect(new Set(COMPONENTS_ERROR_CODES).size).toBe(COMPONENTS_ERROR_CODES.length);
    expect(COMPONENTS_ERROR_CODES).toHaveLength(13);
  });

  it("narrows by code in a catch", () => {
    try {
      throw ComponentsError.invalidSizeForType("Nonce", 12, 3);
    } catch (e) {
      expect(ComponentsError.isComponentsError(e)).toBe(true);
      if (ComponentsError.isComponentsError(e) && e.details.code === "InvalidSize") {
        expect(e.details.expected - e.details.actual).toBe(9);
      } else {
        expect.unreachable();
      }
    }
  });
});
