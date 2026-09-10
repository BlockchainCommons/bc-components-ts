/**
 * The one codable mechanism of this package.
 *
 * Every value type exposes a `codec` (a dcbor `CborCodec` over its tagged
 * form whose `decode` also accepts the untagged form), `toCbor()` (tagged),
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
} from "@blockchaincommons/dcbor";

/** A codec over a tagged type; `decode` also accepts the untagged form. */
export interface ComponentCodec<T> extends CborCodec<T> {
  /** The tags this type is written and read with; the first is written. */
  readonly tags: readonly Tag[];
  /** Decode tagged (any of `tags`) or untagged CBOR. */
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
      const tv = asTaggedValue(cbor);
      if (tv !== undefined) {
        const tag = byValue.get(tv[0].value);
        if (tag !== undefined) {
          return spec.decodeTagged === undefined
            ? spec.decodeUntagged(tv[1])
            : spec.decodeTagged(tag, tv[1], cbor);
        }
      }
      return spec.decodeUntagged(cbor);
    },
  };
  return codec;
}

/** A component value: tagged CBOR out, tags known. */
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
