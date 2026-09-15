/**
 * Argument-domain checks and the foreign-error boundary.
 *
 * TypeScript has no integer widths: a `u32` parameter is a `number` that
 * must be an integer in `[0, 4294967295]`. Every check here throws a
 * `ComponentsError` — `InvalidData` naming the parameter, or `DataTooShort`
 * for a length below a type's minimum — before any random draw or any
 * dependency call, so a caller never sees a `RandError` from rand, a
 * `CryptoError` from crypto or a `CborError` from dcbor through this
 * package. `wrapForeign` is the single place a dependency's error becomes a
 * `ComponentsError`; the original travels as `cause`.
 *
 * @module domain
 */
import type { ExpectUnsignedOptions } from "@blockchaincommons/dcbor";
import { ComponentsError } from "./error.js";

/** The inclusive maximum of a `u8`. */
export const U8_MAX = 0xff;
/** The inclusive maximum of a `u32`. */
export const U32_MAX = 0xffff_ffff;

/**
 * The fixed-width unsigned fields the reference decodes with
 * `u8`/`u32`/`usize: TryFrom<CBOR>`, which wrap a negative head (dcbor
 * 0.25.2 `int.rs`): pass one to dcbor's `expectUnsigned`.
 */
export const U8_FIELD: ExpectUnsignedOptions = Object.freeze({ width: 8, wrapNegative: true });
/** See {@link U8_FIELD}. */
export const U32_FIELD: ExpectUnsignedOptions = Object.freeze({ width: 32, wrapNegative: true });
/** See {@link U8_FIELD}; `usize` is 64 bits wide on the reference's targets. */
export const USIZE_FIELD: ExpectUnsignedOptions = Object.freeze({ width: 64, wrapNegative: true });

/** Throws `InvalidData` unless `value` is an integer `number` in `[min, max]`. Returns it. */
export function expectInt(value: number, min: number, max: number, parameter: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
    throw ComponentsError.invalidDataForType(
      parameter,
      `must be an integer in [${min}, ${max}], got ${String(value)}`,
    );
  }
  return value;
}

/** `expectInt` over `[0, 255]`. */
export function expectU8(value: number, parameter: string): number {
  return expectInt(value, 0, U8_MAX, parameter);
}

/** `expectInt` over `[0, 4294967295]`. */
export function expectU32(value: number, parameter: string): number {
  return expectInt(value, 0, U32_MAX, parameter);
}

/**
 * A byte length: an integer `≥ 0` (`InvalidData` otherwise) that is at
 * least `minimum` (`DataTooShort` otherwise). Returns it.
 */
export function expectLength(value: number, minimum: number, dataType: string): number {
  expectInt(value, 0, U32_MAX, `${dataType} length`);
  if (value < minimum) throw ComponentsError.dataTooShort(dataType, minimum, value);
  return value;
}

/** Throws `InvalidData` unless `value` is a string. Returns it. */
export function expectString(value: unknown, parameter: string): string {
  if (typeof value !== "string") {
    throw ComponentsError.invalidDataForType(parameter, `must be a string, got ${typeName(value)}`);
  }
  return value;
}

/** Throws `InvalidData` unless `value` is a valid `Date`. Returns it. */
export function expectDate(value: unknown, parameter: string): Date {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    throw ComponentsError.invalidDataForType(
      parameter,
      `must be a valid Date, got ${typeName(value)}`,
    );
  }
  return value;
}

// Hex ------------------------------------------------------------------------

const HEX_VALUE = new Int8Array(256).fill(-1);
for (let i = 0; i < 10; i++) HEX_VALUE[0x30 + i] = i;
for (let i = 0; i < 6; i++) {
  HEX_VALUE[0x41 + i] = 10 + i;
  HEX_VALUE[0x61 + i] = 10 + i;
}

/**
 * Rust's `char::escape_debug` for the Latin-1 range, the way `{:?}`
 * prints the offending byte of a hex string: `\0`, `\t`, `\n`, `\r`, `\'`
 * and `\\` by name, the other controls (U+0001–U+001F, U+007F–U+00A0) and
 * U+00AD as `\u{..}`, everything else as itself.
 */
function rustCharDebug(byte: number): string {
  switch (byte) {
    case 0x00:
      return "\\0";
    case 0x09:
      return "\\t";
    case 0x0a:
      return "\\n";
    case 0x0d:
      return "\\r";
    case 0x27:
      return "\\'";
    case 0x5c:
      return "\\\\";
    default:
      if (byte < 0x20 || (byte >= 0x7f && byte <= 0xa0) || byte === 0xad) {
        return `\\u{${byte.toString(16)}}`;
      }
      return String.fromCharCode(byte);
  }
}

/**
 * Bytes from a hex string, as the reference's `hex::decode` (hex 0.4.3)
 * reads it: over the UTF-8 bytes of `text`, an odd byte count first
 * (`Odd number of digits`), then the first byte outside `[0-9a-fA-F]`
 * (`Invalid character '<c>' at position <index>`), as `Hex` failures with
 * the crate's `Display`. Whitespace is not tolerated. The reference
 * `unwrap`s this in most `from_hex`s (a panic) and returns it for the
 * Ed25519 keys.
 */
export function decodeHexStrict(text: string): Uint8Array {
  const bytes = new TextEncoder().encode(text);
  if (bytes.length % 2 !== 0) throw ComponentsError.hex("Odd number of digits");
  const out = new Uint8Array(bytes.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const v = HEX_VALUE[bytes[i]];
    if (v < 0) {
      throw ComponentsError.hex(`Invalid character '${rustCharDebug(bytes[i])}' at position ${i}`);
    }
    if (i % 2 === 0) out[i >> 1] = v << 4;
    else out[i >> 1] |= v;
  }
  return out;
}

/** {@link decodeHexStrict}, the door every `fromHex` uses. */
export function bytesFromHex(hex: string): Uint8Array {
  return decodeHexStrict(hex);
}

/**
 * Rust's `str::trim`: the Unicode `White_Space` set (U+0009–U+000D,
 * U+0020, U+0085, U+00A0, U+1680, U+2000–U+200A, U+2028, U+2029, U+202F,
 * U+205F, U+3000), which is not `String.prototype.trim`'s set: U+FEFF is not
 * trimmed.
 */
export function rustTrim(text: string): string {
  const ws = (c: number): boolean =>
    (c >= 0x09 && c <= 0x0d) ||
    c === 0x20 ||
    c === 0x85 ||
    c === 0xa0 ||
    c === 0x1680 ||
    (c >= 0x2000 && c <= 0x200a) ||
    c === 0x2028 ||
    c === 0x2029 ||
    c === 0x202f ||
    c === 0x205f ||
    c === 0x3000;
  let start = 0;
  let end = text.length;
  while (start < end && ws(text.charCodeAt(start))) start++;
  while (end > start && ws(text.charCodeAt(end - 1))) end--;
  return text.slice(start, end);
}

/** `rustTrim` from the right only (`str::trim_end`). */
export function rustTrimEnd(text: string): string {
  const trimmed = rustTrim(`x${text}`);
  return trimmed.slice(1);
}

// The boundary -----------------------------------------------------------------

/**
 * The boundary: a dependency's error as a `ComponentsError` with `cause`.
 * A `ComponentsError` passes through unchanged. crypto's
 * `AuthenticationFailed` becomes `Crypto` with the reference's one
 * `bc_crypto::Error` text, `AEAD error`; its `InvalidData`, `InvalidSize`
 * and `InvalidParameter` become `InvalidData` for `dataType` (the input was
 * malformed, not the operation: the points where the reference panics);
 * dcbor's errors become `Cbor`; anything else becomes `Crypto` with its
 * own message.
 */
export function wrapForeign(e: unknown, dataType: string): ComponentsError {
  if (ComponentsError.isComponentsError(e)) return e;
  const name = e instanceof Error ? e.name : "";
  const code = (e as { code?: unknown }).code;
  if (name === "CryptoError") {
    if (code === "AuthenticationFailed") return ComponentsError.crypto("AEAD error", e);
    return ComponentsError.invalidDataForType(dataType, messageOf(e), e);
  }
  if (name === "CborError") return ComponentsError.cbor(messageOf(e), e);
  return ComponentsError.crypto(messageOf(e), e);
}

/** Runs `f`; a foreign throw becomes a `ComponentsError` for `dataType`. */
export function guarded<T>(dataType: string, f: () => T): T {
  try {
    return f();
  } catch (e) {
    throw wrapForeign(e, dataType);
  }
}

export function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function typeName(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "object") return value.constructor.name;
  return typeof value;
}
