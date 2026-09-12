/**
 * Argument-domain checks and the foreign-error boundary.
 *
 * TypeScript has no integer widths: a `u32` parameter is a `number` that
 * must be an integer in `[0, 4294967295]`. Every check here throws a
 * `ComponentsError` — `InvalidData` naming the parameter, or `DataTooShort`
 * for a length below a type's minimum — before any random draw or any
 * dependency call, so a caller never sees a `RangeError` from rand, a
 * `CryptoError` from crypto or a `CborError` from dcbor through this
 * package. `wrapForeign` is the single place a dependency's error becomes a
 * `ComponentsError`; the original travels as `cause`.
 *
 * @module domain
 */
import { hexToBytes } from "@blockchaincommons/dcbor";
import { ComponentsError } from "./error.js";

/** The inclusive maximum of a `u8`. */
export const U8_MAX = 0xff;
/** The inclusive maximum of a `u32`. */
export const U32_MAX = 0xffff_ffff;

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

/** The order of secp256k1's generator, `n`. */
const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/** Throws `InvalidData` unless the 32 big-endian bytes are a scalar in `[1, n - 1]`. Returns them. */
export function expectSecp256k1Scalar(bytes: Uint8Array, dataType: string): Uint8Array {
  let scalar = 0n;
  for (const b of bytes) scalar = (scalar << 8n) | BigInt(b);
  if (scalar === 0n || scalar >= SECP256K1_ORDER) {
    throw ComponentsError.invalidDataForType(dataType, "scalar must be in [1, n - 1]");
  }
  return bytes;
}

/** Bytes from a hex string; a malformed string is a `Hex` failure naming `dataType`. */
export function bytesFromHex(hex: string, dataType: string): Uint8Array {
  try {
    return hexToBytes(hex);
  } catch (e) {
    throw ComponentsError.hex(`${dataType}: ${messageOf(e)}`, e);
  }
}

/**
 * The boundary: a dependency's error as a `ComponentsError` with `cause`.
 * A `ComponentsError` passes through unchanged. crypto's
 * `AuthenticationFailed` becomes `Crypto`; its `InvalidData`,
 * `InvalidSize` and `InvalidParameter` become `InvalidData` for `dataType`
 * (the input was malformed, not the operation); dcbor's errors become
 * `Cbor`; anything else becomes `Crypto` when `dataType` names an
 * operation, which is the only other class of foreign throw left.
 */
export function wrapForeign(e: unknown, dataType: string): ComponentsError {
  if (ComponentsError.isComponentsError(e)) return e;
  const name = e instanceof Error ? e.name : "";
  const code = (e as { code?: unknown }).code;
  if (name === "CryptoError" && code !== "AuthenticationFailed") {
    return ComponentsError.invalidDataForType(dataType, messageOf(e), e);
  }
  if (name === "CborError") return ComponentsError.cbor(messageOf(e), e);
  return ComponentsError.crypto(`${dataType}: ${messageOf(e)}`, e);
}

/** Runs `f`; a foreign throw becomes a `ComponentsError` for `dataType`. */
export function guarded<T>(dataType: string, f: () => T): T {
  try {
    return f();
  } catch (e) {
    throw wrapForeign(e, dataType);
  }
}

function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function typeName(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "object") return value.constructor.name;
  return typeof value;
}
