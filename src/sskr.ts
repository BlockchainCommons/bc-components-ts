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
  decodeCbor,
  type ToCbor,
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
import { taggedCborOf, type ComponentCodec, defineCodec } from "./codable.js";
import { ComponentsError } from "./error.js";
import { type UR, urFor } from "@blockchaincommons/uniform-resources";

const TAG_SSKR_SHARE_V1 = LEGACY_TAGS.SSKR_SHARE_V1;
export { SSKRSecret, SSKRGroupSpec, SSKRSpec };
const METADATA_SIZE_BYTES = 5;

export class SSKRShareCbor implements ToCbor {
  private readonly _data: Uint8Array;
  private constructor(data: Uint8Array) {
    if (data.length < METADATA_SIZE_BYTES) {
      throw ComponentsError.sskr(
        `SSKRShare must be at least ${METADATA_SIZE_BYTES} bytes, got ${data.length}`,
      );
    }
    this._data = new Uint8Array(data);
  }
  static from(data: Uint8Array): SSKRShareCbor {
    return new SSKRShareCbor(data);
  }
  static fromHex(hex: string): SSKRShareCbor {
    return new SSKRShareCbor(hexToBytes(hex));
  }
  /** The bytes (a view; do not mutate). */
  get bytes(): Uint8Array {
    return new Uint8Array(this._data);
  }
  toHex(): string {
    return bytesToHex(this._data);
  }
  get identifier(): number {
    return (this._data[0] << 8) | this._data[1];
  }
  identifierHex(): string {
    return bytesToHex(this._data.subarray(0, 2));
  }
  get groupThreshold(): number {
    return (this._data[2] >> 4) + 1;
  }
  get groupCount(): number {
    return (this._data[2] & 0x0f) + 1;
  }
  get groupIndex(): number {
    return this._data[3] >> 4;
  }
  get memberThreshold(): number {
    return (this._data[3] & 0x0f) + 1;
  }
  get memberIndex(): number {
    return this._data[4] & 0x0f;
  }
  get shareValue(): Uint8Array {
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
    return `SSKRShare(${this.identifierHex()}, group ${this.groupIndex + 1}/${this.groupCount}, member ${this.memberIndex + 1}/${this.memberThreshold})`;
  }
  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static readonly codec: ComponentCodec<SSKRShareCbor> = defineCodec({
    tags: [TAG_SSKR_SHARE, TAG_SSKR_SHARE_V1],
    decodeUntagged: (cborValue) => {
      return SSKRShareCbor.from(expectBytes(cborValue));
    },
    encodeUntagged: (value) => value.untaggedCbor(),
  });

  cborTags(): Tag[] {
    return [...SSKRShareCbor.codec.tags];
  }
  untaggedCbor(): Cbor {
    return cbor(this._data);
  }

  /** The tagged CBOR form. */
  toCbor(): Cbor {
    return taggedCborOf(this);
  }

  /** As a UR, typed by the first tag's name. */
  toUR(): UR {
    return urFor(this);
  }

  /** Decode tagged or untagged CBOR. */
  static fromCbor(cborValue: Cbor): SSKRShareCbor {
    return SSKRShareCbor.codec.decode(cborValue);
  }
}
export type SSKRShare = SSKRShareCbor;
export const SSKRShare = {
  fromData: (data: Uint8Array): SSKRShareCbor => SSKRShareCbor.from(data),
  fromHex: (hex: string): SSKRShareCbor => SSKRShareCbor.fromHex(hex),
  fromTaggedCbor: (cborValue: Cbor): SSKRShareCbor => SSKRShareCbor.fromCbor(cborValue),
  fromTaggedCborData: (data: Uint8Array): SSKRShareCbor => SSKRShareCbor.fromCbor(decodeCbor(data)),
  fromUntaggedCborData: (data: Uint8Array): SSKRShareCbor =>
    SSKRShareCbor.fromCbor(decodeCbor(data)),
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
  return sskrGenerate(spec, masterSecret).map((group) => group.map((d) => SSKRShareCbor.from(d)));
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
    group.map((d) => SSKRShareCbor.from(d)),
  );
}
export function sskrCombineShares(shares: SSKRShare[]): SSKRSecret {
  return sskrCombine(shares.map((share) => share.bytes));
}
