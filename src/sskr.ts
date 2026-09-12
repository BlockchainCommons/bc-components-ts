/**
 * An SSKR share as a component: the parsed share from
 * `@blockchaincommons/sskr` with the tagged CBOR (`#6.40309`, legacy
 * `#6.309`) and `ur:sskr` forms envelopes carry.
 *
 * Splitting and recovery are the sskr package's `generateShares` and
 * `combineShares`; `SskrShare.generate` and `SskrShare.combine` wrap them
 * for callers that want component shares directly.
 *
 * @module sskr
 */
import { type Cbor, type Tag, type ToCbor, cbor, expectBytes } from "@blockchaincommons/dcbor";
import { TAG_SSKR_SHARE, LEGACY_TAGS } from "@blockchaincommons/tags";
import {
  type SskrShare as ParsedShare,
  type Secret,
  type Spec,
  type GenerateOptions,
  generateShares,
  combineShares,
  shareBytes,
  parseShare,
  isSskrShare,
} from "@blockchaincommons/sskr";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { bytesToHex, bytesEqual } from "./utils.js";
import { bytesFromHex } from "./domain.js";
import { taggedCborOf, type ComponentCodec, defineCodec } from "./codable.js";
import { ComponentsError } from "./error.js";

const TAG_SSKR_SHARE_V1 = LEGACY_TAGS.SSKR_SHARE_V1;

// The codec is built on first use so that an unused class tree-shakes away.
let SSKR_SHARE_CODEC: ComponentCodec<SskrShare> | undefined;

/** One share of a Sharded Secret Key Reconstruction split. */
export class SskrShare implements ToCbor, ToUR {
  private readonly _share: ParsedShare;
  private readonly _bytes: Uint8Array;

  private constructor(share: ParsedShare) {
    this._share = share;
    this._bytes = shareBytes(share);
  }

  /** From the sskr package's parsed share, or from the wire bytes. */
  static from(share: ParsedShare | Uint8Array): SskrShare {
    if (isSskrShare(share)) return new SskrShare(share);
    try {
      return new SskrShare(parseShare(share));
    } catch (e) {
      throw ComponentsError.sskr(e instanceof Error ? e.message : String(e), e);
    }
  }

  /** A `SskrShare` from a hex string; malformed hex is a `Hex` failure. */
  static fromHex(hex: string): SskrShare {
    return SskrShare.from(bytesFromHex(hex, "SskrShare"));
  }

  /** Split `secret` per `spec`; every share wrapped as a component. */
  static generate(spec: Spec, secret: Secret, options?: GenerateOptions): SskrShare[][] {
    return generateShares(spec, secret, options).map((group) =>
      group.map((share) => new SskrShare(share)),
    );
  }

  /** Recover the secret from a quorum of shares. */
  static combine(shares: readonly SskrShare[]): Secret {
    return combineShares(shares.map((s) => s._share));
  }

  /** The parsed share. */
  get share(): ParsedShare {
    return this._share;
  }

  /** The wire bytes: five header bytes, then the share value. */
  /** A copy of the share bytes; mutating it does not touch this share. */
  get bytes(): Uint8Array {
    return new Uint8Array(this._bytes);
  }

  get identifier(): number {
    return this._share.identifier;
  }
  get groupThreshold(): number {
    return this._share.groupThreshold;
  }
  get groupCount(): number {
    return this._share.groupCount;
  }
  get groupIndex(): number {
    return this._share.groupIndex;
  }
  get memberThreshold(): number {
    return this._share.memberThreshold;
  }
  get memberIndex(): number {
    return this._share.memberIndex;
  }
  /** The share value (the secret-length payload after the header). */
  get value(): Uint8Array {
    return this._share.value.bytes;
  }

  /** The share bytes as hex. */
  toHex(): string {
    return bytesToHex(this._bytes);
  }

  /** The 16-bit identifier as four hex digits. */
  identifierHex(): string {
    return bytesToHex(this._bytes.subarray(0, 2));
  }

  /** `true` when the share bytes are equal. */
  equals(other: SskrShare): boolean {
    return bytesEqual(this._bytes, other._bytes);
  }

  toString(): string {
    return `SskrShare(${this.identifierHex()}, group ${this.groupIndex + 1}/${this.groupCount}, member ${this.memberIndex + 1}/${this.memberThreshold})`;
  }

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<SskrShare> {
    return (SSKR_SHARE_CODEC ??= defineCodec({
      tags: [TAG_SSKR_SHARE, TAG_SSKR_SHARE_V1],
      decodeUntagged: (cborValue) => SskrShare.from(expectBytes(cborValue)),
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...SskrShare.codec.tags];
  }

  /** The CBOR content without the tag. */
  untaggedCbor(): Cbor {
    return cbor(this._bytes);
  }

  /** The tagged CBOR (`sskr-share`, tag 40309). */
  toCbor(): Cbor {
    return taggedCborOf(this);
  }

  toUR(): UR {
    return urFor(this);
  }

  /** Decodes a tagged `SskrShare`; an untagged or foreign-tagged value is a `Cbor` failure. */
  static fromCbor(cborValue: Cbor): SskrShare {
    return SskrShare.codec.decode(cborValue);
  }
}
