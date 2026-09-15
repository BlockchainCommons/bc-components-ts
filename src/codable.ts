/**
 * The one codable mechanism of this package.
 *
 * Every value type exposes a `codec` (a dcbor `CborCodec` over its tagged
 * form; `decode` requires one of the type's tags), `toCbor()` (tagged),
 * `toUR()`, and `fromCbor(cbor)`. Bytes and UR strings compose with dcbor
 * and uniform-resources: `decodeWith(bytes, X.codec)`,
 * `decodeURWith(UR.parse(s), X.codec)`, `x.toCbor().toData()`,
 * `x.toUR().toString()`.
 *
 * Tags are held by value. Their names come from dcbor's global tags store
 * at the moment they are asked for (`codec.tags`, `cborTags()`, the
 * expected tag in a `WrongTag` message), as the reference's `cbor_tags()`
 * calls `tags_for_values`: call `registerTags()` (`/tags`) first to name
 * them, as the reference's `register_tags()`. A UR needs the name.
 *
 * Every decode failure is a `ComponentsError` with code `Cbor` whose
 * message is the dcbor `Display` and whose `cause` is the `CborError`, the
 * reference's `dcbor::Error` from `from_tagged_cbor`; see {@link decodeWith}.
 *
 * @module codable
 */
import {
  type Cbor,
  type CborCodec,
  type CborMap,
  type CborTagged,
  type Tag,
  type TagValue,
  type ToCbor,
  asBoolean,
  asBytes,
  asText,
  CborDate,
  extractTaggedContent,
  taggedValue,
  tagsForValues,
  validateTag,
  CborError,
} from "@blockchaincommons/dcbor";
import { ComponentsError } from "./error.js";

/**
 * A codec over a tagged type. `decode` requires one of `tags` (the
 * reference's `from_tagged_cbor`; an untagged or foreign-tagged value is a
 * `Cbor` failure); `decodeUntagged` is the explicit door for content whose
 * tag has already been consumed by the caller.
 */
export interface ComponentCodec<T> extends CborCodec<T> {
  /** The tag values this type is written and read with; the first is written. */
  readonly tagValues: readonly TagValue[];
  /**
   * `tagValues` resolved through dcbor's global tags store at each access
   * (the reference's `tags_for_values`): named once `registerTags()` ran,
   * numeric otherwise.
   */
  readonly tags: readonly Tag[];
  /** Decode a value tagged with any of `tags`; anything else is a `Cbor` failure. */
  decode: (cbor: Cbor) => T;
  /** Encode to the tagged form. */
  encode: (value: T) => Cbor;
  /** Decode the content inside the tag. */
  decodeUntagged: (cbor: Cbor) => T;
  /** Encode the content inside the tag. */
  encodeUntagged: (value: T) => Cbor;
}

/** What `defineCodec` needs from a type. */
export interface CodecSpec<T> {
  /** The type's tags (their values are kept; names come from the store). */
  tags: readonly Tag[];
  decodeUntagged: (cbor: Cbor) => T;
  encodeUntagged: (value: T) => Cbor;
  /**
   * For types whose tag selects the decoding (scheme-dispatching keys):
   * called with the matched tag and its content instead of `decodeUntagged`.
   */
  decodeTagged?: (tag: Tag, content: Cbor, whole: Cbor) => T;
  /**
   * For the `TryFrom<CBOR>` enums that dispatch on the tag value themselves
   * and report their own text for anything else: called with the whole
   * value instead of the tag check.
   */
  decodeAny?: (cbor: Cbor) => T;
  /** For types whose tag depends on the value: the full tagged encoding. */
  encode?: (value: T) => Cbor;
}

/**
 * Build a type's codec once. `decode` validates the tag against the store
 * (dcbor's `validateTag`: an untagged value is `WrongType`, a foreign tag
 * `WrongTag` naming the expected tag as the store names it) and hands the
 * content to `decodeTagged` or `decodeUntagged`; every failure inside goes
 * through {@link decodeWith}.
 */
export function defineCodec<T>(spec: CodecSpec<T>): ComponentCodec<T> {
  const tagValues: readonly TagValue[] = Object.freeze(spec.tags.map((t) => t.value));
  const first = tagValues[0];
  if (first === undefined) throw new Error("defineCodec: a codec needs at least one tag");
  const codec: ComponentCodec<T> = {
    tagValues,
    get tags(): readonly Tag[] {
      return tagsForValues([...tagValues]);
    },
    decodeUntagged: spec.decodeUntagged,
    encodeUntagged: spec.encodeUntagged,
    encode:
      spec.encode ??
      ((value) => taggedValue(tagsForValues([first])[0] ?? first, spec.encodeUntagged(value))),
    decode: (cbor) =>
      decodeWith(() => {
        if (spec.decodeAny !== undefined) return spec.decodeAny(cbor);
        const tag = validateTag(cbor, tagsForValues([...tagValues]));
        const content = extractTaggedContent(cbor);
        return spec.decodeTagged === undefined
          ? spec.decodeUntagged(content)
          : spec.decodeTagged(tag, content, cbor);
      }),
  };
  return codec;
}

/**
 * Runs a decoder under the reference's error rule for a `dcbor::Error`
 * result (`from_tagged_cbor`, and every `TryFrom<CBOR>` whose error type is
 * `dcbor::Error`): the failure is a `ComponentsError` with code `Cbor`, the
 * bare dcbor message and the `CborError` as `cause`.
 *
 * - a `CborError` is wrapped as is;
 * - a `ComponentsError` with code `Cbor` (a nested decoder, or a
 *   `CBOR error: …` from a component-typed site) contributes its
 *   `CborError` cause, as `From<Error> for dcbor::Error` unwraps
 *   `Error::Cbor`;
 * - any other `ComponentsError` (a size or format check inside the decoder)
 *   becomes `CborError.custom(<its message>)`, with the inner error kept as
 *   that cause's `cause`, as `dcbor::Error::msg(err.to_string())` does.
 *
 * Anything else (an engine error from a JS-only input) propagates.
 */
export function decodeWith<T>(f: () => T): T {
  try {
    return f();
  } catch (e) {
    if (CborError.isCborError(e)) throw ComponentsError.cborDecode(e);
    if (ComponentsError.isComponentsError(e)) {
      if (e.code === "Cbor") {
        const inner: unknown = e.cause;
        if (CborError.isCborError(inner)) throw ComponentsError.cborDecode(inner);
        throw e;
      }
      const custom = CborError.custom(e.message);
      custom.cause = e;
      throw ComponentsError.cborDecode(custom);
    }
    throw e;
  }
}

/**
 * Runs a decoder whose reference error type is the component `Error`
 * (`HashType`, `AuthenticationTag`, the ML-KEM and ML-DSA levels,
 * `KeyDerivationMethod`): a dcbor failure inside is `Cbor` with the
 * `CBOR error: ` prefix (`Error::Cbor`), a component failure keeps its code.
 */
export function decodeComponent<T>(f: () => T): T {
  try {
    return f();
  } catch (e) {
    if (CborError.isCborError(e)) throw ComponentsError.cbor(e.message, e);
    if (
      ComponentsError.isComponentsError(e) &&
      e.details.code === "Cbor" &&
      e.message === e.details.message
    ) {
      // A decoder's bare `Cbor` (a `dcbor::Error` result) met through `?`.
      const inner: unknown = e.cause;
      if (CborError.isCborError(inner)) throw ComponentsError.cbor(inner.message, inner);
    }
    throw e;
  }
}

/** What every value type implements: `toCbor()` plus `cborTags()`. */
export type Codable = ToCbor & CborTagged;

/**
 * Tagged CBOR memo, keyed by the value object. Every codable type here is an
 * immutable value (readonly fields, no setters) except `Seed`, whose setters
 * call `forgetTaggedCbor`. The memo makes repeated `toCbor().toData()` /
 * `Digest.fromImage(...)` calls on the same object (references, XIDs,
 * envelope leaf digests) free after the first.
 */
const TAGGED_CBOR = new WeakMap<object, Cbor>();

/** The value's untagged CBOR wrapped in its first tag; memoised per object. */
export function taggedCborOf(value: CborTagged & { untaggedCbor(): Cbor }): Cbor {
  const memo = TAGGED_CBOR.get(value);
  if (memo !== undefined) return memo;
  const tag: Tag | undefined = value.cborTags()[0];
  if (tag === undefined) throw new Error("No tags defined for this type");
  const out = taggedValue(tag, value.untaggedCbor());
  TAGGED_CBOR.set(value, out);
  return out;
}

/** Drop the memoised tagged CBOR of a value that has just been mutated. */
export function forgetTaggedCbor(value: object): void {
  TAGGED_CBOR.delete(value);
}

/**
 * dcbor's `Map::get::<K, T>`: the value at `key` converted to `T`, or
 * `undefined` when the key is absent or the value does not convert.
 */
export function mapGetBoolean(map: CborMap, key: number): boolean | undefined {
  const v = map.get(key);
  return v === undefined ? undefined : asBoolean(v);
}
/** See {@link mapGetBoolean}. */
export function mapGetText(map: CborMap, key: number): string | undefined {
  const v = map.get(key);
  return v === undefined ? undefined : asText(v);
}
/** See {@link mapGetBoolean}. */
export function mapGetBytes(map: CborMap, key: number): Uint8Array | undefined {
  const v = map.get(key);
  return v === undefined ? undefined : asBytes(v);
}
/** See {@link mapGetBoolean}: a value that is not a decodable tagged date is absent. */
export function mapGetDate(map: CborMap, key: number): CborDate | undefined {
  const v = map.get(key);
  if (v === undefined) return undefined;
  try {
    return CborDate.fromTaggedCbor(v);
  } catch {
    return undefined;
  }
}
