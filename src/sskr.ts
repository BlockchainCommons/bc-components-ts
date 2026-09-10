/**
 * The CBOR-tagged SSKR share and the share-level generate/combine helpers.
 *
 * @module sskr
 */
import {
  type Cbor,
  type Tag,
  cbor,
  expectBytes,
  extractTaggedContent,
  decodeCbor,
  tagsForValues,
  tagValue,
} from "@blockchaincommons/dcbor";
import { SSKR_SHARE as TAG_SSKR_SHARE, LEGACY_TAGS } from "@blockchaincommons/tags";
import {
  generateShares,
  combineShares,
  shareBytes,
  Secret as SSKRSecret,
  GroupSpec as SSKRGroupSpec,
  Spec as SSKRSpec,
} from "@blockchaincommons/sskr";
import type { RandomNumberGenerator } from "@blockchaincommons/rand";
import { bytesToHex, hexToBytes } from "./utils.js";
import { type CborTaggedEncodable, type CborTaggedDecodable, taggedCborOf } from "./codable.js";
import { ComponentsError } from "./error.js";

const TAG_SSKR_SHARE_V1 = LEGACY_TAGS.SSKR_SHARE_V1;
export { SSKRSecret, SSKRGroupSpec, SSKRSpec };
const METADATA_SIZE_BYTES = 5;

export class SSKRShareCbor implements CborTaggedEncodable, CborTaggedDecodable<SSKRShareCbor> {
  private readonly _data: Uint8Array;
  private constructor(data: Uint8Array) {
    if (data.length < METADATA_SIZE_BYTES) {
      throw ComponentsError.sskr(
        `SSKRShare must be at least ${METADATA_SIZE_BYTES} bytes, got ${data.length}`,
      );
    }
    this._data = new Uint8Array(data);
  }
  static fromData(data: Uint8Array): SSKRShareCbor {
    return new SSKRShareCbor(data);
  }
  static fromHex(hex: string): SSKRShareCbor {
    return new SSKRShareCbor(hexToBytes(hex));
  }
  asBytes(): Uint8Array {
    return this._data;
  }
  data(): Uint8Array {
    return new Uint8Array(this._data);
  }
  hex(): string {
    return bytesToHex(this._data);
  }
  identifier(): number {
    return (this._data[0] << 8) | this._data[1];
  }
  identifierHex(): string {
    return bytesToHex(this._data.subarray(0, 2));
  }
  groupThreshold(): number {
    return (this._data[2] >> 4) + 1;
  }
  groupCount(): number {
    return (this._data[2] & 0x0f) + 1;
  }
  groupIndex(): number {
    return this._data[3] >> 4;
  }
  memberThreshold(): number {
    return (this._data[3] & 0x0f) + 1;
  }
  memberIndex(): number {
    return this._data[4] & 0x0f;
  }
  shareValue(): Uint8Array {
    return this._data.subarray(METADATA_SIZE_BYTES);
  }
  equals(other: SSKRShareCbor): boolean {
    if (this._data.length !== other._data.length) return false;
    for (let i = 0; i < this._data.length; i++) {
      if (this._data[i] !== other._data[i]) return false;
    }
    return true;
  }
  toString(): string {
    return `SSKRShare(${this.identifierHex()}, group ${this.groupIndex() + 1}/${this.groupCount()}, member ${this.memberIndex() + 1}/${this.memberThreshold()})`;
  }
  cborTags(): Tag[] {
    return tagsForValues([TAG_SSKR_SHARE.value, TAG_SSKR_SHARE_V1.value]);
  }
  untaggedCbor(): Cbor {
    return cbor(this._data);
  }
  taggedCbor(): Cbor {
    return taggedCborOf(this);
  }
  taggedCborData(): Uint8Array {
    return this.taggedCbor().toData();
  }
  fromUntaggedCbor(cborValue: Cbor): SSKRShareCbor {
    return SSKRShareCbor.fromData(expectBytes(cborValue));
  }
  fromTaggedCbor(cborValue: Cbor): SSKRShareCbor {
    const tag = tagValue(cborValue);
    if (tag !== TAG_SSKR_SHARE.value && tag !== TAG_SSKR_SHARE_V1.value) {
      throw ComponentsError.sskr(
        `Invalid SSKRShare tag: expected ${TAG_SSKR_SHARE.value} or ${TAG_SSKR_SHARE_V1.value}, got ${tag}`,
      );
    }
    return this.fromUntaggedCbor(extractTaggedContent(cborValue));
  }
  static fromTaggedCbor(cborValue: Cbor): SSKRShareCbor {
    const dummy = new SSKRShareCbor(new Uint8Array(METADATA_SIZE_BYTES + 16));
    return dummy.fromTaggedCbor(cborValue);
  }
  static fromTaggedCborData(data: Uint8Array): SSKRShareCbor {
    return SSKRShareCbor.fromTaggedCbor(decodeCbor(data));
  }
  static fromUntaggedCborData(data: Uint8Array): SSKRShareCbor {
    const dummy = new SSKRShareCbor(new Uint8Array(METADATA_SIZE_BYTES + 16));
    return dummy.fromUntaggedCbor(decodeCbor(data));
  }
}
export type SSKRShare = SSKRShareCbor;
export const SSKRShare = {
  fromData: (data: Uint8Array): SSKRShareCbor => SSKRShareCbor.fromData(data),
  fromHex: (hex: string): SSKRShareCbor => SSKRShareCbor.fromHex(hex),
  fromTaggedCbor: (cborValue: Cbor): SSKRShareCbor => SSKRShareCbor.fromTaggedCbor(cborValue),
  fromTaggedCborData: (data: Uint8Array): SSKRShareCbor => SSKRShareCbor.fromTaggedCborData(data),
  fromUntaggedCborData: (data: Uint8Array): SSKRShareCbor =>
    SSKRShareCbor.fromUntaggedCborData(data),
};

/** Raw share bytes per group, as sskr's `generateShares` + `shareBytes`. */
export function sskrGenerate(spec: SSKRSpec, masterSecret: SSKRSecret): Uint8Array[][] {
  return generateShares(spec, masterSecret).map((g) => g.map(shareBytes));
}
export function sskrGenerateUsing(
  spec: SSKRSpec,
  masterSecret: SSKRSecret,
  rng: RandomNumberGenerator,
): Uint8Array[][] {
  return generateShares(spec, masterSecret, { rng }).map((g) => g.map(shareBytes));
}
export function sskrCombine(shares: Uint8Array[]): SSKRSecret {
  return combineShares(shares);
}
export function sskrGenerateShares(spec: SSKRSpec, masterSecret: SSKRSecret): SSKRShare[][] {
  return sskrGenerate(spec, masterSecret).map((group) =>
    group.map((d) => SSKRShareCbor.fromData(d)),
  );
}
export interface SimpleRng {
  fillBytes(data: Uint8Array): void;
}
export function sskrGenerateSharesUsing(
  spec: SSKRSpec,
  masterSecret: SSKRSecret,
  rng: SimpleRng,
): SSKRShare[][] {
  return sskrGenerateUsing(spec, masterSecret, rng as RandomNumberGenerator).map((group) =>
    group.map((d) => SSKRShareCbor.fromData(d)),
  );
}
export function sskrCombineShares(shares: SSKRShare[]): SSKRSecret {
  return sskrCombine(shares.map((share) => share.data()));
}
