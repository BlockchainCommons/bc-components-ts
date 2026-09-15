/**
 * `SskrShare`: one share of an SSKR split, as `@blockchaincommons/sskr`
 * produces it, wrapped for CBOR (tag 40309, legacy 309) and UR (`ur:sskr`).
 *
 * As the reference's `SSKRShare`, the value holds the share's raw bytes and
 * nothing else: `from(bytes)` copies them without parsing, the header
 * accessors read them by position (a share too short for the byte an
 * accessor reads is an `InvalidData` failure where the reference panics),
 * and `combine` hands the bytes to sskr's `combineShares`, whose `SskrError`
 * propagates as the reference's `SSKRError` does. A parsed view is
 * available through `share`.
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

/** An SSKR share: the raw share bytes, with a CBOR and UR form. */
export class SskrShare implements ToCbor, ToUR {
  private readonly _bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this._bytes = bytes;
  }

  /**
   * From the share's bytes (copied, never parsed: as `SSKRShare::from_data`)
   * or from a parsed share of the sskr package, whose bytes are those
   * `shareBytes` produces (a malformed parsed share is an `Sskr` failure).
   */
  static from(share: ParsedShare | Uint8Array): SskrShare {
    if (isSskrShare(share)) {
      try {
        return new SskrShare(shareBytes(share));
      } catch (e) {
        throw ComponentsError.sskr(e instanceof Error ? e.message : String(e), e);
      }
    }
    return new SskrShare(new Uint8Array(share));
  }

  /** From the share's bytes in hex. */
  static fromHex(hex: string): SskrShare {
    return SskrShare.from(bytesFromHex(hex));
  }

  /** `sskr_generate_using`: the groups of shares for `secret` under `spec`. */
  static generate(spec: Spec, secret: Secret, options?: GenerateOptions): SskrShare[][] {
    return generateShares(spec, secret, options).map((group) =>
      group.map((share) => new SskrShare(shareBytes(share))),
    );
  }

  /**
   * `sskr_combine`: the secret behind a quorum of shares. The bytes go to
   * sskr's `combineShares` as they are; its `SskrError` is not wrapped.
   */
  static combine(shares: readonly SskrShare[]): Secret {
    return combineShares(shares.map((s) => s._bytes));
  }

  /** The parsed share (sskr's `parseShare` over the bytes); a malformed share is an `Sskr` failure. */
  get share(): ParsedShare {
    try {
      return parseShare(this._bytes);
    } catch (e) {
      throw ComponentsError.sskr(e instanceof Error ? e.message : String(e), e);
    }
  }

  /** A copy of the share bytes. */
  get bytes(): Uint8Array {
    return new Uint8Array(this._bytes);
  }

  /** The byte at `index`; a share that short is an `InvalidData` failure (the reference indexes and panics). */
  private byteAt(index: number, field: string): number {
    const b = this._bytes[index];
    if (b === undefined) {
      throw ComponentsError.invalidDataForType(
        "SSKR share",
        `${field} needs ${index + 1} bytes, got ${this._bytes.length}`,
      );
    }
    return b;
  }

  /** The 16-bit identifier (`data[0..2]`). */
  get identifier(): number {
    return (this.byteAt(0, "identifier") << 8) | this.byteAt(1, "identifier");
  }
  /** The group threshold (`data[2] >> 4`, plus one). */
  get groupThreshold(): number {
    return (this.byteAt(2, "group threshold") >> 4) + 1;
  }
  /** The group count (`data[2] & 0xf`, plus one). */
  get groupCount(): number {
    return (this.byteAt(2, "group count") & 0xf) + 1;
  }
  /** The group index (`data[3] >> 4`). */
  get groupIndex(): number {
    return this.byteAt(3, "group index") >> 4;
  }
  /** The member threshold (`data[3] & 0xf`, plus one). */
  get memberThreshold(): number {
    return (this.byteAt(3, "member threshold") & 0xf) + 1;
  }
  /** The member index (`data[4] & 0xf`). */
  get memberIndex(): number {
    return this.byteAt(4, "member index") & 0xf;
  }
  /** The share value: the bytes after the five header bytes. */
  get value(): Uint8Array {
    return new Uint8Array(this._bytes.subarray(5));
  }

  /** The share bytes in hex. */
  toHex(): string {
    return bytesToHex(this._bytes);
  }

  /** The identifier's two bytes in hex. */
  identifierHex(): string {
    return bytesToHex(this._bytes.subarray(0, 2));
  }

  /** Byte equality. */
  equals(other: SskrShare): boolean {
    return bytesEqual(this._bytes, other._bytes);
  }

  /** A summary of the header; a share too short for it is an `InvalidData` failure. */
  toString(): string {
    return `SskrShare(${this.identifierHex()}, group ${this.groupIndex + 1}/${this.groupCount}, member ${this.memberIndex + 1}/${this.memberThreshold})`;
  }

  /** Tagged-CBOR codec: the share bytes under tag 40309 (legacy 309). */
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

  /** The untagged CBOR: the share bytes. */
  untaggedCbor(): Cbor {
    return cbor(this._bytes);
  }

  /** The tagged CBOR form. */
  toCbor(): Cbor {
    return taggedCborOf(this);
  }

  /** As `ur:sskr`. */
  toUR(): UR {
    return urFor(this);
  }

  /** Decode the tagged CBOR form. */
  static fromCbor(cborValue: Cbor): SskrShare {
    return SskrShare.codec.decode(cborValue);
  }
}
