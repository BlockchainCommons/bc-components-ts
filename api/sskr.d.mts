import { Cbor } from '@blockchaincommons/dcbor';
import { CborTagged } from '@blockchaincommons/dcbor';
import { RandomNumberGenerator } from '@blockchaincommons/rand';
import { GroupSpec as SSKRGroupSpec } from '@blockchaincommons/sskr';
import { Secret as SSKRSecret } from '@blockchaincommons/sskr';
import { Spec as SSKRSpec } from '@blockchaincommons/sskr';
import { Tag } from '@blockchaincommons/dcbor';

/** Decodes from tagged or untagged CBOR. */
declare interface CborTaggedDecodable<T> extends CborTagged {
    fromUntaggedCbor(cbor: Cbor): T;
    fromTaggedCbor(cbor: Cbor): T;
    fromTaggedCborData?(data: Uint8Array): T;
    fromUntaggedCborData?(data: Uint8Array): T;
}

/** Encodes to tagged CBOR; the first tag is the one written. */
declare interface CborTaggedEncodable extends CborTagged {
    untaggedCbor(): Cbor;
    taggedCbor(): Cbor;
    taggedCborData?(): Uint8Array;
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

export declare class SSKRShareCbor implements CborTaggedEncodable, CborTaggedDecodable<SSKRShareCbor> {
    private readonly _data;
    private constructor();
    static fromData(data: Uint8Array): SSKRShareCbor;
    static fromHex(hex: string): SSKRShareCbor;
    asBytes(): Uint8Array;
    data(): Uint8Array;
    hex(): string;
    identifier(): number;
    identifierHex(): string;
    groupThreshold(): number;
    groupCount(): number;
    groupIndex(): number;
    memberThreshold(): number;
    memberIndex(): number;
    shareValue(): Uint8Array;
    equals(other: SSKRShareCbor): boolean;
    toString(): string;
    cborTags(): Tag[];
    untaggedCbor(): Cbor;
    taggedCbor(): Cbor;
    taggedCborData(): Uint8Array;
    fromUntaggedCbor(cborValue: Cbor): SSKRShareCbor;
    fromTaggedCbor(cborValue: Cbor): SSKRShareCbor;
    static fromTaggedCbor(cborValue: Cbor): SSKRShareCbor;
    static fromTaggedCborData(data: Uint8Array): SSKRShareCbor;
    static fromUntaggedCborData(data: Uint8Array): SSKRShareCbor;
}

export { SSKRSpec }

export { }
