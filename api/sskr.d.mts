import { Cbor } from '@blockchaincommons/dcbor';
import { CborCodec } from '@blockchaincommons/dcbor';
import { RandomNumberGenerator } from '@blockchaincommons/rand';
import { GroupSpec as SSKRGroupSpec } from '@blockchaincommons/sskr';
import { Secret as SSKRSecret } from '@blockchaincommons/sskr';
import { Spec as SSKRSpec } from '@blockchaincommons/sskr';
import { Tag } from '@blockchaincommons/dcbor';
import { ToCbor } from '@blockchaincommons/dcbor';
import { UR } from '@blockchaincommons/uniform-resources';

/** A codec over a tagged type; `decode` also accepts the untagged form. */
declare interface ComponentCodec<T> extends CborCodec<T> {
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

export declare interface SimpleRng {
    fillBytes(data: Uint8Array): void;
}

export declare function sskrCombine(shares: Uint8Array[]): SSKRSecret;

export declare function sskrCombineShares(shares: SSKRShare[]): SSKRSecret;

/** Raw share bytes per group, as sskr's `generateShares` + `shareBytes`. */
export declare function sskrGenerate(spec: SSKRSpec, masterSecret: SSKRSecret): Uint8Array[][];

export declare function sskrGenerateShares(spec: SSKRSpec, masterSecret: SSKRSecret): SSKRShare[][];

export declare function sskrGenerateSharesUsing(spec: SSKRSpec, masterSecret: SSKRSecret, rng: SimpleRng): SSKRShare[][];

export declare function sskrGenerateUsing(spec: SSKRSpec, masterSecret: SSKRSecret, rng: RandomNumberGenerator): Uint8Array[][];

export { SSKRGroupSpec }

export { SSKRSecret }

export declare type SSKRShare = SSKRShareCbor;

export declare const SSKRShare: {
    fromData: (data: Uint8Array) => SSKRShareCbor;
    fromHex: (hex: string) => SSKRShareCbor;
    fromTaggedCbor: (cborValue: Cbor) => SSKRShareCbor;
    fromTaggedCborData: (data: Uint8Array) => SSKRShareCbor;
    fromUntaggedCborData: (data: Uint8Array) => SSKRShareCbor;
};

export declare class SSKRShareCbor implements ToCbor {
    private readonly _data;
    private constructor();
    static from(data: Uint8Array): SSKRShareCbor;
    static fromHex(hex: string): SSKRShareCbor;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    toHex(): string;
    get identifier(): number;
    identifierHex(): string;
    get groupThreshold(): number;
    get groupCount(): number;
    get groupIndex(): number;
    get memberThreshold(): number;
    get memberIndex(): number;
    get shareValue(): Uint8Array;
    equals(other: SSKRShareCbor): boolean;
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static readonly codec: ComponentCodec<SSKRShareCbor>;
    cborTags(): Tag[];
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): SSKRShareCbor;
}

export { SSKRSpec }

export { }
