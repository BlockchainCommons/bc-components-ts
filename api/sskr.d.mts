import { Cbor } from '@blockchaincommons/dcbor';
import { CborCodec } from '@blockchaincommons/dcbor';
import { GenerateOptions } from '@blockchaincommons/sskr';
import { Secret } from '@blockchaincommons/sskr';
import { Spec } from '@blockchaincommons/sskr';
import { SskrShare as SskrShare_2 } from '@blockchaincommons/sskr';
import { Tag } from '@blockchaincommons/dcbor';
import { TagValue } from '@blockchaincommons/dcbor';
import { ToCbor } from '@blockchaincommons/dcbor';
import { ToUR } from '@blockchaincommons/uniform-resources';
import { UR } from '@blockchaincommons/uniform-resources';

/**
 * A codec over a tagged type. `decode` requires one of `tags` (the
 * reference's `from_tagged_cbor`; an untagged or foreign-tagged value is a
 * `Cbor` failure); `decodeUntagged` is the explicit door for content whose
 * tag has already been consumed by the caller.
 */
declare interface ComponentCodec<T> extends CborCodec<T> {
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

/** An SSKR share: the raw share bytes, with a CBOR and UR form. */
export declare class SskrShare implements ToCbor, ToUR {
    private readonly _bytes;
    private constructor();
    /**
     * From the share's bytes (copied, never parsed: as `SSKRShare::from_data`)
     * or from a parsed share of the sskr package, whose bytes are those
     * `shareBytes` produces (a malformed parsed share is an `Sskr` failure).
     */
    static from(share: SskrShare_2 | Uint8Array): SskrShare;
    /** From the share's bytes in hex. */
    static fromHex(hex: string): SskrShare;
    /** `sskr_generate_using`: the groups of shares for `secret` under `spec`. */
    static generate(spec: Spec, secret: Secret, options?: GenerateOptions): SskrShare[][];
    /**
     * `sskr_combine`: the secret behind a quorum of shares. The bytes go to
     * sskr's `combineShares` as they are; its `SskrError` is not wrapped.
     */
    static combine(shares: readonly SskrShare[]): Secret;
    /** The parsed share (sskr's `parseShare` over the bytes); a malformed share is an `Sskr` failure. */
    get share(): SskrShare_2;
    /** A copy of the share bytes. */
    get bytes(): Uint8Array;
    /** The byte at `index`; a share that short is an `InvalidData` failure (the reference indexes and panics). */
    private byteAt;
    /** The 16-bit identifier (`data[0..2]`). */
    get identifier(): number;
    /** The group threshold (`data[2] >> 4`, plus one). */
    get groupThreshold(): number;
    /** The group count (`data[2] & 0xf`, plus one). */
    get groupCount(): number;
    /** The group index (`data[3] >> 4`). */
    get groupIndex(): number;
    /** The member threshold (`data[3] & 0xf`, plus one). */
    get memberThreshold(): number;
    /** The member index (`data[4] & 0xf`). */
    get memberIndex(): number;
    /** The share value: the bytes after the five header bytes. */
    get value(): Uint8Array;
    /** The share bytes in hex. */
    toHex(): string;
    /** The identifier's two bytes in hex. */
    identifierHex(): string;
    /** Byte equality. */
    equals(other: SskrShare): boolean;
    /** A summary of the header; a share too short for it is an `InvalidData` failure. */
    toString(): string;
    /** Tagged-CBOR codec: the share bytes under tag 40309 (legacy 309). */
    static get codec(): ComponentCodec<SskrShare>;
    /** The CBOR tags this type decodes from; the first one is used to encode. */
    cborTags(): Tag[];
    /** The untagged CBOR: the share bytes. */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As `ur:sskr`. */
    toUR(): UR;
    /** Decode the tagged CBOR form. */
    static fromCbor(cborValue: Cbor): SskrShare;
}

export { }
