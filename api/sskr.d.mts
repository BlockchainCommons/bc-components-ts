import { Cbor } from '@blockchaincommons/dcbor';
import { CborCodec } from '@blockchaincommons/dcbor';
import { GenerateOptions } from '@blockchaincommons/sskr';
import { Secret } from '@blockchaincommons/sskr';
import { Spec } from '@blockchaincommons/sskr';
import { SskrShare as SskrShare_2 } from '@blockchaincommons/sskr';
import { Tag } from '@blockchaincommons/dcbor';
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

/** One share of a Sharded Secret Key Reconstruction split. */
export declare class SskrShare implements ToCbor, ToUR {
    private readonly _share;
    private readonly _bytes;
    private constructor();
    /** From the sskr package's parsed share, or from the wire bytes. */
    static from(share: SskrShare_2 | Uint8Array): SskrShare;
    /** A `SskrShare` from a hex string; malformed hex is a `Hex` failure. */
    static fromHex(hex: string): SskrShare;
    /** Split `secret` per `spec`; every share wrapped as a component. */
    static generate(spec: Spec, secret: Secret, options?: GenerateOptions): SskrShare[][];
    /** Recover the secret from a quorum of shares. */
    static combine(shares: readonly SskrShare[]): Secret;
    /** The parsed share. */
    get share(): SskrShare_2;
    /** The wire bytes: five header bytes, then the share value. */
    /** A copy of the share bytes; mutating it does not touch this share. */
    get bytes(): Uint8Array;
    get identifier(): number;
    get groupThreshold(): number;
    get groupCount(): number;
    get groupIndex(): number;
    get memberThreshold(): number;
    get memberIndex(): number;
    /** The share value (the secret-length payload after the header). */
    get value(): Uint8Array;
    /** The share bytes as hex. */
    toHex(): string;
    /** The 16-bit identifier as four hex digits. */
    identifierHex(): string;
    /** `true` when the share bytes are equal. */
    equals(other: SskrShare): boolean;
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<SskrShare>;
    /** The CBOR tags this type decodes from; the first one is used to encode. */
    cborTags(): Tag[];
    /** The CBOR content without the tag. */
    untaggedCbor(): Cbor;
    /** The tagged CBOR (`sskr-share`, tag 40309). */
    toCbor(): Cbor;
    toUR(): UR;
    /** Decodes a tagged `SskrShare`; an untagged or foreign-tagged value is a `Cbor` failure. */
    static fromCbor(cborValue: Cbor): SskrShare;
}

export { }
