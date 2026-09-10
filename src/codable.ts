/**
 * The tagged-CBOR and UR shape every value type in this package implements
 * today, plus the small helpers that build on canonical dcbor.
 *
 * @module codable
 */
import {
  type Cbor,
  type CborMap,
  type CborTagged,
  type Tag,
  asBoolean,
  asBytes,
  asText,
  taggedValue,
} from "@blockchaincommons/dcbor";
import type { UR } from "@blockchaincommons/uniform-resources";

/** Encodes to tagged CBOR; the first tag is the one written. */
export interface CborTaggedEncodable extends CborTagged {
  untaggedCbor(): Cbor;
  taggedCbor(): Cbor;
  taggedCborData?(): Uint8Array;
}

/** Decodes from tagged or untagged CBOR. */
export interface CborTaggedDecodable<T> extends CborTagged {
  fromUntaggedCbor(cbor: Cbor): T;
  fromTaggedCbor(cbor: Cbor): T;
  fromTaggedCborData?(data: Uint8Array): T;
  fromUntaggedCborData?(data: Uint8Array): T;
}

/** Presents itself as a UR. */
export interface UREncodable {
  ur(): UR;
  urString(): string;
}

/** The value wrapped in its first tag. */
export function taggedCborOf(value: CborTaggedEncodable): Cbor {
  const tag: Tag | undefined = value.cborTags()[0];
  if (tag === undefined) throw new Error("No tags defined for this type");
  return taggedValue(tag, value.untaggedCbor());
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
