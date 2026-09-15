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
});

describe("foreign-error boundary", () => {
  it("bytesFromHex is the hex crate's decode: odd length first, then the first bad byte", () => {
    expect(bytesFromHex("0aff")).toEqual(new Uint8Array([0x0a, 0xff]));
    expect(bytesFromHex("0AFF")).toEqual(new Uint8Array([0x0a, 0xff]));
    expect(bytesFromHex("")).toEqual(new Uint8Array(0));
    const message = (text: string): string => {
      try {
        bytesFromHex(text);
        return "ok";
      } catch (e) {
        expect(ComponentsError.isComponentsError(e) && e.code === "Hex").toBe(true);
        return (e as ComponentsError).message;
      }
    };
    expect(message("abc")).toBe("hex decoding error: Odd number of digits");
    expect(message("zz")).toBe("hex decoding error: Invalid character 'z' at position 0");
    expect(message("0aFg")).toBe("hex decoding error: Invalid character 'g' at position 3");
    // Over UTF-8 bytes, as Rust: `é` is two bytes, its first is C3 (`Ã`).
    expect(message("0é")).toBe("hex decoding error: Odd number of digits");
    expect(message("00é")).toBe("hex decoding error: Invalid character 'Ã' at position 2");
    expect(message("é0")).toBe("hex decoding error: Odd number of digits");
    expect(message("0aé0")).toBe("hex decoding error: Odd number of digits");
    // Rust's `char::escape_debug` for the byte.
    expect(message("0a\t0")).toBe("hex decoding error: Invalid character '\\t' at position 2");
    expect(message("0a\u00000")).toBe("hex decoding error: Invalid character '\\0' at position 2");
    expect(message("0a\u007f0")).toBe(
      "hex decoding error: Invalid character '\\u{7f}' at position 2",
    );
    expect(message("0a'0")).toBe("hex decoding error: Invalid character '\\'' at position 2");
    expect(message("0a 0")).toBe("hex decoding error: Invalid character ' ' at position 2");
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
    expect(wrapped.message).toBe("cryptographic operation failed: AEAD error");
    const other = wrapForeign(new RangeError("r"), "op");
    expect(other.code).toBe("Crypto");
    expect(other.message).toBe("cryptographic operation failed: r");
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
