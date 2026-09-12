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
 * @module codable
 */
import {
  type Cbor,
  type CborCodec,
  type CborMap,
  type CborTagged,
  type Tag,
  type ToCbor,
  asBoolean,
  asBytes,
  asTaggedValue,
  asText,
  taggedValue,
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
  /** The tags this type is written and read with; the first is written. */
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
  tags: readonly Tag[];
  decodeUntagged: (cbor: Cbor) => T;
  encodeUntagged: (value: T) => Cbor;
  /**
   * For types whose tag selects the decoding (scheme-dispatching keys):
   * called with the matched tag and its content instead of `decodeUntagged`.
   */
  decodeTagged?: (tag: Tag, content: Cbor, whole: Cbor) => T;
  /** For types whose tag depends on the value: the full tagged encoding. */
  encode?: (value: T) => Cbor;
}

/**
 * Build a type's codec once. A tagged value whose tag is one of `tags` is
 * unwrapped (or handed to `decodeTagged`); anything else goes to
 * `decodeUntagged`, which rejects foreign tags itself.
 */
export function defineCodec<T>(spec: CodecSpec<T>): ComponentCodec<T> {
  const tags: readonly Tag[] = Object.freeze([...spec.tags]);
  const first = tags[0];
  if (first === undefined) throw new Error("defineCodec: a codec needs at least one tag");
  const byValue = new Map(tags.map((t) => [t.value, t] as const));
  const codec: ComponentCodec<T> = {
    tags,
    decodeUntagged: spec.decodeUntagged,
    encodeUntagged: spec.encodeUntagged,
    encode: spec.encode ?? ((value) => taggedValue(first, spec.encodeUntagged(value))),
    decode: (cbor) => {
      try {
        const tv = asTaggedValue(cbor);
        const tag = tv === undefined ? undefined : byValue.get(tv[0].value);
        if (tv === undefined || tag === undefined) {
          // The reference's `from_tagged_cbor`: the tag is part of the type.
          throw ComponentsError.cbor(
            `expected ${describeTags(tags)}, got ${tv === undefined ? "an untagged value" : `tag ${String(tv[0].value)}`}`,
          );
        }
        return spec.decodeTagged === undefined
          ? spec.decodeUntagged(tv[1])
          : spec.decodeTagged(tag, tv[1], cbor);
      } catch (e) {
        // dcbor's typed extraction failed: the boundary rule reports it as
        // `Cbor` with the original as `cause`.
        if (CborError.isCborError(e)) throw ComponentsError.cbor(e.message, e);
        throw e;
      }
    },
  };
  return codec;
}

/** A component value: tagged CBOR out, tags known. */
function describeTags(tags: readonly Tag[]): string {
  return tags
    .map((t) =>
      t.name === undefined ? `tag ${String(t.value)}` : `tag ${t.name} (${String(t.value)})`,
    )
    .join(" or ");
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

export function mapGetBoolean(map: CborMap, key: number): boolean | undefined {
  const v = map.get(key);
  return v === undefined ? undefined : asBoolean(v);
}
export function mapGetText(map: CborMap, key: number): string | undefined {
  const v = map.get(key);
  return v === undefined ? undefined : asText(v);
}
export function mapGetBytes(map: CborMap, key: number): Uint8Array | undefined {
  const v = map.get(key);
  return v === undefined ? undefined : asBytes(v);
}
