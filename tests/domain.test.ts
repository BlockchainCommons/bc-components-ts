/**
 * The argument-domain predicates and the foreign-error boundary: every
 * check throws a `ComponentsError` naming the parameter,
 * and every wrapped dependency error keeps its original as `cause`.
 */
import { CborError } from "@blockchaincommons/dcbor";
import { CryptoError, chacha20Poly1305 } from "@blockchaincommons/crypto";
import { ComponentsError } from "../src/index.js";
import {
  expectInt,
  expectU8,
  expectU32,
  expectLength,
  expectString,
  expectDate,
  expectSecp256k1Scalar,
  bytesFromHex,
  wrapForeign,
  guarded,
  U32_MAX,
} from "../src/domain.js";

const code = (f: () => unknown): string => {
  try {
    f();
    return "ok";
  } catch (e) {
    if (!ComponentsError.isComponentsError(e)) throw e;
    return `${e.code}:${"dataType" in e.details ? e.details.dataType : ""}`;
  }
};

describe("domain predicates", () => {
  it("expectInt accepts integers in range and names the parameter otherwise", () => {
    expect(expectInt(5, 0, 10, "n")).toBe(5);
    expect(expectInt(0, 0, 10, "n")).toBe(0);
    expect(expectInt(10, 0, 10, "n")).toBe(10);
    for (const bad of [-1, 11, 1.5, NaN, Infinity, -Infinity, "5" as unknown as number]) {
      expect(code(() => expectInt(bad, 0, 10, "n"))).toBe("InvalidData:n");
    }
    expect(() => expectInt(1.5, 0, 10, "n")).toThrow(
      "invalid n: must be an integer in [0, 10], got 1.5",
    );
  });
  it("expectU8 / expectU32 cover the integer widths", () => {
    expect(expectU8(255, "b")).toBe(255);
    expect(code(() => expectU8(256, "b"))).toBe("InvalidData:b");
    expect(expectU32(U32_MAX, "w")).toBe(U32_MAX);
    expect(code(() => expectU32(U32_MAX + 1, "w"))).toBe("InvalidData:w");
    expect(code(() => expectU32(-1, "w"))).toBe("InvalidData:w");
  });
  it("expectLength distinguishes a non-integer from a short length", () => {
    expect(expectLength(16, 8, "salt")).toBe(16);
    expect(code(() => expectLength(1.5, 8, "salt"))).toBe("InvalidData:salt length");
    expect(code(() => expectLength(NaN, 8, "salt"))).toBe("InvalidData:salt length");
    expect(code(() => expectLength(-1, 8, "salt"))).toBe("InvalidData:salt length");
    expect(code(() => expectLength(7, 8, "salt"))).toBe("DataTooShort:salt");
  });
  it("expectString / expectDate", () => {
    expect(expectString("x", "name")).toBe("x");
    expect(code(() => expectString(42, "name"))).toBe("InvalidData:name");
    expect(code(() => expectString(null, "name"))).toBe("InvalidData:name");
    const d = new Date(0);
    expect(expectDate(d, "creationDate")).toBe(d);
    expect(code(() => expectDate("2020-01-01", "creationDate"))).toBe("InvalidData:creationDate");
    expect(code(() => expectDate(new Date(NaN), "creationDate"))).toBe("InvalidData:creationDate");
  });
  it("expectSecp256k1Scalar rejects 0 and n and above", () => {
    const one = new Uint8Array(32);
    one[31] = 1;
    expect(expectSecp256k1Scalar(one, "k")).toBe(one);
    const nMinus1 = Buffer.from(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
      "hex",
    );
    expect(code(() => expectSecp256k1Scalar(nMinus1, "k"))).toBe("ok");
    const n = Buffer.from(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
      "hex",
    );
    expect(code(() => expectSecp256k1Scalar(n, "k"))).toBe("InvalidData:k");
    expect(code(() => expectSecp256k1Scalar(new Uint8Array(32), "k"))).toBe("InvalidData:k");
    expect(code(() => expectSecp256k1Scalar(new Uint8Array(32).fill(0xff), "k"))).toBe(
      "InvalidData:k",
    );
  });
});

describe("foreign-error boundary", () => {
  it("bytesFromHex reports Hex with the dcbor error as cause", () => {
    expect(bytesFromHex("0aff", "Digest")).toEqual(new Uint8Array([0x0a, 0xff]));
    for (const bad of ["zz", "abc"]) {
      try {
        bytesFromHex(bad, "Digest");
        expect.unreachable();
      } catch (e) {
        expect(ComponentsError.isComponentsError(e) && e.code === "Hex").toBe(true);
        expect((e as ComponentsError).message).toContain("Digest");
        expect(CborError.isCborError((e as ComponentsError).cause)).toBe(true);
      }
    }
  });
  it("wrapForeign maps crypto, dcbor and other errors and passes ComponentsError through", () => {
    const own = ComponentsError.general("mine");
    expect(wrapForeign(own, "x")).toBe(own);
    const key = new Uint8Array(32);
    const nonce = new Uint8Array(12);
    const sealed = chacha20Poly1305.encrypt(key, nonce, new Uint8Array(4));
    sealed[sealed.length - 1] ^= 1;
    let auth: unknown;
    try {
      chacha20Poly1305.decrypt(key, nonce, sealed);
    } catch (e) {
      auth = e;
    }
    expect(CryptoError.isCryptoError(auth) && auth.is("AuthenticationFailed")).toBe(true);
    const wrapped = wrapForeign(auth, "SymmetricKey.decrypt");
    expect(wrapped.code).toBe("Crypto");
    expect(wrapped.cause).toBe(auth);
    let sizeErr: unknown;
    try {
      chacha20Poly1305.encrypt(new Uint8Array(3), nonce, new Uint8Array(4));
    } catch (e) {
      sizeErr = e;
    }
    expect(CryptoError.isCryptoError(sizeErr)).toBe(true);
    const w2 = wrapForeign(sizeErr, "SymmetricKey");
    expect(w2.code).toBe("InvalidData");
    expect(w2.details).toMatchObject({ code: "InvalidData", dataType: "SymmetricKey" });
    const cb = wrapForeign(CborError.underrun(), "decode");
    expect(cb.code).toBe("Cbor");
    const other = wrapForeign(new RangeError("r"), "op");
    expect(other.code).toBe("Crypto");
    expect(other.message).toBe("cryptographic operation failed: op: r");
    expect(wrapForeign("string", "op").code).toBe("Crypto");
  });
  it("guarded runs the thunk and wraps only on throw", () => {
    expect(guarded("op", () => 7)).toBe(7);
    expect(
      code(() =>
        guarded("op", () => {
          throw new TypeError("t");
        }),
      ),
    ).toBe("Crypto:");
  });
});
