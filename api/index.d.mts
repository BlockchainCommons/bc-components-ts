import { bytesToHex } from '@blockchaincommons/dcbor';
import { Cbor } from '@blockchaincommons/dcbor';
import { CborCodec } from '@blockchaincommons/dcbor';
import { hexToBytes } from '@blockchaincommons/dcbor';
import { RandomNumberGenerator } from '@blockchaincommons/rand';
import { Tag } from '@blockchaincommons/dcbor';
import { ToCbor } from '@blockchaincommons/dcbor';
import { ToUR } from '@blockchaincommons/uniform-resources';
import { UR } from '@blockchaincommons/uniform-resources';

export declare class ARID implements ToCbor, ToUR {
    static readonly ARID_SIZE = 32;
    private readonly _data;
    private constructor();
    /** A fresh random ARID; pass `rng` to make it deterministic. */
    static random({ rng }?: {
        rng?: RandomNumberGenerator;
    }): ARID;
    /**
     * Restore an ARID from a fixed-size array of bytes.
     */
    static from(data: Uint8Array): ARID;
    /**
     * Create a new ARID from the given hexadecimal string.
     *
     * @throws Error if the string is not exactly 64 hexadecimal digits.
     */
    static fromHex(hex: string): ARID;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * The data as a hexadecimal string.
     */
    toHex(): string;
    /**
     * Get base64 representation.
     */
    toBase64(): string;
    /**
     * The first four bytes of the ARID as a hexadecimal string.
     */
    shortDescription(): string;
    /**
     * Compare with another ARID.
     */
    equals(other: ARID): boolean;
    /**
     * Compare ARIDs lexicographically.
     */
    compare(other: ARID): number;
    /**
     * Get string representation.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<ARID>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as a byte string).
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cbor: Cbor): ARID;
}

export declare class AuthenticationTag {
    static readonly AUTHENTICATION_TAG_SIZE: number;
    private readonly _data;
    private constructor();
    /**
     * Restore an AuthenticationTag from a fixed-size array of bytes.
     */
    static from(data: Uint8Array): AuthenticationTag;
    /**
     * Create an AuthenticationTag from hex string.
     */
    static fromHex(hex: string): AuthenticationTag;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Get hex string representation.
     */
    toHex(): string;
    /**
     * Get base64 representation.
     */
    toBase64(): string;
    /**
     * Compare with another AuthenticationTag.
     */
    equals(other: AuthenticationTag): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /**
     * Returns the untagged CBOR encoding (as a byte string).
     * AuthenticationTag has no CBOR tag - it's serialized as a plain byte string.
     */
    toCbor(): Cbor;
    /**
     * Returns the CBOR binary representation.
     */
    toCborData(): Uint8Array;
    /**
     * Creates an AuthenticationTag from CBOR.
     */
    static fromCbor(cbor: Cbor): AuthenticationTag;
    /**
     * Creates an AuthenticationTag from CBOR binary data.
     */
    static fromCborData(data: Uint8Array): AuthenticationTag;
}

/**
 * Compare two Uint8Arrays for equality using constant-time comparison.
 *
 * This function is designed to be resistant to timing attacks by always
 * comparing all bytes regardless of where a difference is found. The
 * comparison time depends only on the length of the arrays, not on where
 * they differ.
 *
 * **Security Note**: If the arrays have different lengths, this function
 * returns `false` immediately, which does leak length information. For
 * cryptographic uses where length should also be secret, ensure both
 * arrays are the same length before comparison.
 *
 * @param a - First byte array
 * @param b - Second byte array
 * @returns `true` if both arrays have the same length and identical contents
 *
 * @example
 * ```typescript
 * const key1 = new Uint8Array([1, 2, 3, 4]);
 * const key2 = new Uint8Array([1, 2, 3, 4]);
 * const key3 = new Uint8Array([1, 2, 3, 5]);
 *
 * bytesEqual(key1, key2); // true
 * bytesEqual(key1, key3); // false
 * ```
 */
export declare function bytesEqual(a: Uint8Array, b: Uint8Array): boolean;

export { bytesToHex }

/**
 * A CBOR-tagged container for UTF-8 CborJson text.
 *
 * Wraps UTF-8 CborJson text as a CBOR byte string with tag 262.
 * This allows CborJson data to be embedded within CBOR structures while
 * maintaining type information through the tag.
 */
export declare class CborJson implements ToCbor {
    private readonly _data;
    private constructor();
    /**
     * Create a new CborJson instance from byte data.
     */
    static from(data: Uint8Array): CborJson;
    /**
     * Create a new CborJson instance from a string.
     */
    static fromString(s: string): CborJson;
    /**
     * Create a new CborJson instance from a hexadecimal string.
     */
    static fromHex(hex: string): CborJson;
    /** Number of bytes. */
    get byteLength(): number;
    /**
     * Return true if the CborJson data is empty.
     */
    isEmpty(): boolean;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Return the data as a UTF-8 string slice.
     *
     * @throws Error if the data is not valid UTF-8.
     */
    asStr(): string;
    /**
     * Return the data as a hexadecimal string.
     */
    toHex(): string;
    /**
     * Compare with another CborJson.
     */
    equals(other: CborJson): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<CborJson>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as a byte string).
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): CborJson;
}

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

/** Every code, for exhaustive tables and tests. */
export declare const COMPONENTS_ERROR_CODES: readonly ComponentsErrorCode[];

/**
 * Error raised by every component operation.
 *
 * ```ts
 * try {
 *   Digest.from(bytes);
 * } catch (e) {
 *   if (ComponentsError.isComponentsError(e) && e.code === "InvalidSize") {
 *     console.log(e.details.expected, e.details.actual);
 *   }
 * }
 * ```
 */
export declare class ComponentsError extends Error {
    override readonly name = "ComponentsError";
    readonly code: ComponentsErrorCode;
    readonly details: ComponentsErrorDetails;
    private constructor();
    /** `true` for a `ComponentsError` from any copy of this package. */
    static isComponentsError(value: unknown): value is ComponentsError;
    /** `true` when this error carries `code`. */
    is(code: ComponentsErrorCode): boolean;
    static invalidSize(expected: number, actual: number): ComponentsError;
    static invalidSizeForType(dataType: string, expected: number, actual: number): ComponentsError;
    static invalidData(reason: string, cause?: unknown): ComponentsError;
    static invalidDataForType(dataType: string, reason: string, cause?: unknown): ComponentsError;
    static dataTooShort(dataType: string, minimum: number, actual: number): ComponentsError;
    static invalidFormat(reason: string, cause?: unknown): ComponentsError;
    static crypto(message: string, cause?: unknown): ComponentsError;
    static cbor(message: string, cause?: unknown): ComponentsError;
    static sskr(message: string, cause?: unknown): ComponentsError;
    static ssh(message: string, cause?: unknown): ComponentsError;
    static sshAgent(message: string, cause?: unknown): ComponentsError;
    static uri(message: string, cause?: unknown): ComponentsError;
    static compression(message: string, cause?: unknown): ComponentsError;
    static postQuantum(message: string, cause?: unknown): ComponentsError;
    static levelMismatch(): ComponentsError;
    static general(message: string, cause?: unknown): ComponentsError;
    private static of;
}

/**
 * The one error type of this package.
 *
 * Every failure a component can raise is a `ComponentsError` with a `code`
 * from a closed union, `details` discriminated by that code, and `cause`
 * carrying the wrapped error when the failure came from a dependency
 * (crypto, dcbor, sskr, an SSH parser).
 *
 * @module error
 */
/** The closed set of failure codes. */
export declare type ComponentsErrorCode = "InvalidSize" | "InvalidData" | "DataTooShort" | "Crypto" | "Cbor" | "Sskr" | "Ssh" | "Uri" | "Compression" | "PostQuantum" | "LevelMismatch" | "SshAgent" | "General";

/** `details` is discriminated by `code`. */
export declare type ComponentsErrorDetails = InvalidSizeDetails | InvalidDataDetails | DataTooShortDetails | MessageDetails;

/**
 * A compressed binary object with integrity verification.
 *
 * Uses DEFLATE compression with CRC32 checksums for integrity verification.
 * Optionally includes a cryptographic digest for content identification.
 */
export declare class Compressed implements ToCbor, DigestProvider {
    /** CRC32 checksum of the decompressed data for integrity verification */
    private readonly _checksum;
    /** Size of the original decompressed data in bytes */
    private readonly _decompressedSize;
    /** The compressed data (or original data if compression is ineffective) */
    private readonly _compressedData;
    /** Optional cryptographic digest of the content */
    private readonly _digest;
    private constructor();
    /**
     * Creates a new `Compressed` object with the specified parameters.
     *
     * This is a low-level constructor that allows direct creation of a
     * `Compressed` object without performing compression. It's primarily
     * intended for deserialization or when working with pre-compressed data.
     *
     * @param checksum - CRC32 checksum of the decompressed data
     * @param decompressedSize - Size of the original decompressed data in bytes
     * @param compressedData - The compressed data bytes
     * @param digest - Optional cryptographic digest of the content
     * @returns A new `Compressed` object
     * @throws ComponentsError if the compressed data is larger than the decompressed size
     */
    static fromParts({ checksum, decompressedSize, compressedData, digest }: {
        checksum: number;
        decompressedSize: number;
        compressedData: Uint8Array;
        digest?: Digest | undefined;
    }): Compressed;
    /**
     * Creates a new `Compressed` object by compressing the provided data.
     *
     * This is the primary method for creating compressed data. It automatically
     * handles compression using the DEFLATE algorithm with compression level 6.
     *
     * If the compressed data would be larger than the original data (which can
     * happen with small or already compressed inputs), the original data is
     * stored instead.
     *
     * @param decompressedData - The original data to compress
     * @param digest - Optional cryptographic digest of the content
     * @returns A new `Compressed` object containing the compressed (or original) data
     */
    static fromDecompressedData(decompressedData: Uint8Array, digest?: Digest): Compressed;
    /**
     * Decompresses and returns the original decompressed data.
     *
     * This method performs the reverse of the compression process, restoring
     * the original data. It also verifies the integrity of the data using the
     * stored checksum.
     *
     * @returns The decompressed data
     * @throws ComponentsError if the compressed data is corrupt or checksum doesn't match
     */
    decompress(): Uint8Array;
    /**
     * Returns the size of the compressed data in bytes.
     */
    get compressedSize(): number;
    /**
     * Returns the size of the decompressed data in bytes.
     */
    get decompressedSize(): number;
    /**
     * Returns the CRC32 checksum of the decompressed data.
     */
    get checksum(): number;
    /**
     * Returns the compression ratio of the data.
     *
     * The compression ratio is calculated as (compressed size) / (decompressed size),
     * so lower values indicate better compression.
     *
     * @returns A floating-point value representing the compression ratio.
     * - Values less than 1.0 indicate effective compression
     * - Values equal to 1.0 indicate no compression was applied
     * - Values of NaN can occur if the decompressed size is zero
     */
    get compressionRatio(): number;
    /**
     * Returns the digest of the compressed data, if available.
     *
     * @returns The `Digest` associated with this compressed data, or undefined if none.
     */
    digestOpt(): Digest | undefined;
    /**
     * Returns whether this compressed data has an associated digest.
     */
    hasDigest(): boolean;
    /**
     * Returns the cryptographic digest associated with this compressed data.
     *
     * @returns A `Digest`
     * @throws Error if there is no digest associated with this compressed data
     */
    digest(): Digest;
    /**
     * Compare with another Compressed.
     */
    equals(other: Compressed): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<Compressed>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as an array).
     *
     * Format:
     * ```
     * [
     *   checksum: uint,
     *   decompressed_size: uint,
     *   compressed_data: bytes,
     *   digest?: Digest  // Optional
     * ]
     * ```
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): Compressed;
}

/**
 * A fresh encapsulation key pair for `scheme` (X25519 by default). With
 * `rng` the ML-KEM schemes throw, because their key generation cannot be
 * seeded.
 */
export declare function createEncapsulationKeypair(scheme?: EncapsulationScheme, { rng }?: {
    rng?: RandomNumberGenerator;
}): [EncapsulationPrivateKey, EncapsulationPublicKey];

/**
 * A fresh signing key pair for `scheme`. Without `rng` every scheme draws
 * from the secure generator; with `rng` the ML-DSA schemes throw, because
 * their key generation cannot be seeded.
 */
export declare function createKeypair(scheme: SignatureScheme, { rng, comment }?: CreateKeypairOptions): [SigningPrivateKey, SigningPublicKey];

/** What `createKeypair` accepts. */
export declare interface CreateKeypairOptions {
    /** Randomness source; the ML-DSA schemes refuse a caller-supplied one. */
    rng?: RandomNumberGenerator;
    /** Comment stored in SSH keys (ignored by the other schemes). */
    comment?: string;
}

/** Details of a `DataTooShort` failure. */
export declare interface DataTooShortDetails {
    code: "DataTooShort";
    dataType: string;
    minimum: number;
    actual: number;
}

/**
 * A trait for types that can decapsulate shared secrets for public key decryption.
 *
 * The `Decrypter` interface defines an interface for decapsulating (recovering) a
 * shared secret using a private key. This is the counterpart to the
 * `Encrypter` interface and is used by the recipient of encapsulated messages.
 *
 * Types implementing this interface provide the ability to:
 * 1. Access their encapsulation private key
 * 2. Decapsulate shared secrets from ciphertexts
 *
 * This interface is typically implemented by:
 * - Encapsulation private keys
 * - Higher-level types that contain or can access encapsulation private keys
 *
 * @example
 * ```typescript
 * import { EncapsulationScheme, createEncapsulationKeypair } from '@blockchaincommons/components';
 *
 * // Generate a keypair
 * const [privateKey, publicKey] = createEncapsulationKeypair(EncapsulationScheme.X25519);
 *
 * // Encapsulate a new shared secret
 * const [originalSecret, ciphertext] = publicKey.encapsulateNewSharedSecret();
 *
 * // Decapsulate the shared secret
 * const recoveredSecret = privateKey.decapsulateSharedSecret(ciphertext);
 *
 * // The original and recovered secrets should match
 * ```
 */
export declare interface Decrypter {
    /**
     * Returns the encapsulation private key for this decrypter.
     *
     * @returns The encapsulation private key that should be used for decapsulation.
     */
    encapsulationPrivateKey(): EncapsulationPrivateKey;
    /**
     * Decapsulates a shared secret from a ciphertext.
     *
     * This method recovers the shared secret that was encapsulated in the
     * given ciphertext, using the private key from this decrypter.
     *
     * @param ciphertext - The encapsulation ciphertext containing the encapsulated shared secret
     * @returns The decapsulated `SymmetricKey`
     * @throws Error if the ciphertext type doesn't match the private key type or if decapsulation fails
     */
    decapsulateSharedSecret(ciphertext: EncapsulationCiphertext): SymmetricKey;
}

/**
 * Returns the default encapsulation scheme (X25519).
 */
export declare function defaultEncapsulationScheme(): EncapsulationScheme;

/**
 * Get the default signature scheme.
 * Defaults to Schnorr.
 */
export declare function defaultSignatureScheme(): SignatureScheme;

export declare class Digest implements DigestProvider, ToCbor, ToUR {
    static readonly DIGEST_SIZE: number;
    private readonly _data;
    private constructor();
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Create a Digest from a 32-byte array.
     */
    static from(data: Uint8Array): Digest;
    /**
     * Create a Digest from hex string.
     *
     * @throws Error if the hex string is not exactly 64 characters.
     */
    static fromHex(hex: string): Digest;
    /**
     * Compute SHA-256 digest of data (called "image" in the reference implementation).
     *
     * @param image - The data to hash
     */
    static fromImage(image: Uint8Array): Digest;
    /**
     * Compute SHA-256 digest from multiple data parts.
     *
     * The parts are concatenated and then hashed.
     *
     * @param imageParts - Array of byte arrays to concatenate and hash
     */
    static fromImageParts(imageParts: Uint8Array[]): Digest;
    /**
     * Compute SHA-256 digest from an array of Digests.
     *
     * The digest bytes are concatenated and then hashed.
     *
     * @param digests - Array of Digests to combine
     */
    static fromDigests(digests: Digest[]): Digest;
    /**
     * Compute SHA-256 digest of data (legacy alias for fromImage).
     * @deprecated Use fromImage instead
     */
    static hash(data: Uint8Array): Digest;
    /**
     * Get hex string representation.
     */
    toHex(): string;
    /**
     * Get base64 representation.
     */
    toBase64(): string;
    /**
     * Get the first four bytes of the digest as a hexadecimal string.
     * Useful for short descriptions.
     */
    shortDescription(): string;
    /**
     * Validate the digest against the given image.
     *
     * The image is hashed with SHA-256 and compared to this digest.
     * @returns `true` if the digest matches the image.
     */
    validate(image: Uint8Array): boolean;
    /**
     * Compare with another Digest.
     */
    equals(other: Digest): boolean;
    /**
     * Compare digests lexicographically.
     */
    compare(other: Digest): number;
    /**
     * Get string representation.
     */
    toString(): string;
    /**
     * A Digest is its own digest provider - returns itself.
     */
    digest(): Digest;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<Digest>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as a byte string).
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cbor: Cbor): Digest;
    /**
     * Validate the given data against the digest, if any.
     *
     * Returns `true` if the digest is `undefined` or if the digest matches the
     * image's digest. Returns `false` if the digest does not match.
     */
    static validateOpt(image: Uint8Array, digest: Digest | undefined): boolean;
}

/**
 * Helper function to get a digest from a byte array.
 * This provides DigestProvider-like functionality for raw bytes.
 *
 * @param data - The byte array to hash
 * @returns A Promise resolving to a Digest of the data
 */
export declare function digestFromBytes(data: Uint8Array): Promise<Digest>;

/**
 * A type that can provide a single unique digest that characterizes its contents.
 *
 * Use Cases:
 * - Data integrity verification
 * - Unique identifier for an object based on its content
 * - Content-addressable storage implementation
 * - Comparing objects by their content rather than identity
 */
export declare interface DigestProvider {
    /**
     * Returns a digest that uniquely characterizes the content of the
     * implementing type.
     */
    digest(): Digest;
}

/**
 * An interface for elliptic curve keys that can derive a public key.
 *
 * This interface extends `ECKeyBase` to provide a method for deriving
 * the corresponding compressed public key. It is implemented by both
 * private keys (where it generates the public key) and public keys
 * (where it may return self or convert between formats).
 */
export declare interface ECKey extends ECKeyBase {
    /**
     * Returns the compressed public key corresponding to this key.
     */
    publicKey(): ECPublicKey;
}

/**
 * A base interface for all elliptic curve keys.
 *
 * This interface defines common functionality for all elliptic curve keys,
 * including both private and public keys. It provides methods for key
 * construction from binary data and hexadecimal strings, as well as conversion
 * to hexadecimal format.
 *
 * All EC key types have a fixed size depending on their specific type:
 * - EC private keys: 32 bytes
 * - EC compressed public keys: 33 bytes
 * - EC uncompressed public keys: 65 bytes
 * - Schnorr public keys: 32 bytes
 */
export declare interface ECKeyBase {
    /**
     * Returns the key's binary data.
     */
    readonly bytes: Uint8Array;
    /**
     * Returns the key as a hexadecimal string.
     */
    toHex(): string;
}

export declare class ECPrivateKey implements ECKey, ToCbor, ToUR {
    static readonly KEY_SIZE: number;
    private readonly _data;
    private _publicKey?;
    private _schnorrPublicKey?;
    private constructor();
    /** A fresh random value; pass `rng` to make it deterministic. */
    static random({ rng }?: {
        rng?: RandomNumberGenerator;
    }): ECPrivateKey;
    /** A fresh private key and its public key. */
    static keypair({ rng }?: {
        rng?: RandomNumberGenerator;
    }): [ECPrivateKey, ECPublicKey];
    /**
     * Derive an ECPrivateKey from the given key material.
     *
     * @param keyMaterial - The key material to derive from
     * @returns A new ECPrivateKey derived from the key material
     */
    static deriveFromKeyMaterial(keyMaterial: Uint8Array): ECPrivateKey;
    /**
     * Restore an ECPrivateKey from a fixed-size array of bytes.
     */
    static from(data: Uint8Array): ECPrivateKey;
    /**
     * Restore an ECPrivateKey from a hex string.
     */
    static fromHex(hex: string): ECPrivateKey;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Get hex string representation.
     */
    toHex(): string;
    /**
     * Get base64 representation.
     */
    toBase64(): string;
    /**
     * Get the ECPublicKey (compressed) corresponding to this ECPrivateKey.
     */
    publicKey(): ECPublicKey;
    /**
     * Get the SchnorrPublicKey (x-only) corresponding to this ECPrivateKey.
     */
    schnorrPublicKey(): SchnorrPublicKey;
    /**
     * Sign a message using ECDSA.
     *
     * @param message - The message to sign
     * @returns A 64-byte signature
     */
    ecdsaSign(message: Uint8Array): Uint8Array;
    /**
     * Sign a message using Schnorr signature (BIP-340).
     *
     * @param message - The message to sign
     * @returns A 64-byte signature
     */
    schnorrSign(message: Uint8Array): Uint8Array;
    /**
     * Sign a message using Schnorr signature with custom RNG.
     *
     * @param message - The message to sign
     * @param rng - Random number generator for auxiliary randomness
     * @returns A 64-byte signature
     */
    schnorrSignUsing(message: Uint8Array, rng: RandomNumberGenerator): Uint8Array;
    /**
     * Compare with another ECPrivateKey.
     */
    equals(other: ECPrivateKey): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<ECPrivateKey>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     *
     * Format: { 2: true, 3: h'<32-byte-key>' }
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): ECPrivateKey;
}

export declare class ECPublicKey implements ECPublicKeyBase, ToCbor, ToUR {
    static readonly KEY_SIZE: number;
    private readonly _data;
    private constructor();
    /**
     * Restore an ECPublicKey from a fixed-size array of bytes.
     */
    static from(data: Uint8Array): ECPublicKey;
    /**
     * Restore an ECPublicKey from a hex string.
     */
    static fromHex(hex: string): ECPublicKey;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Get hex string representation.
     */
    toHex(): string;
    /**
     * Get base64 representation.
     */
    toBase64(): string;
    /**
     * Returns the compressed public key (self).
     *
     * This method implements the ECKey interface. Since ECPublicKey is already
     * a compressed public key, this returns itself.
     */
    publicKey(): ECPublicKey;
    /**
     * Convert this compressed public key to uncompressed format.
     */
    uncompressedPublicKey(): ECUncompressedPublicKey;
    /**
     * Verify an ECDSA signature.
     *
     * @param signature - The 64-byte signature to verify
     * @param message - The message that was signed
     * @returns true if the signature is valid
     */
    verify(signature: Uint8Array, message: Uint8Array): boolean;
    /**
     * Compare with another ECPublicKey.
     */
    equals(other: ECPublicKey): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<ECPublicKey>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     *
     * Format: { 3: h'<33-byte-key>' }
     * Note: No key 2 indicates this is a public key
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): ECPublicKey;
}

/**
 * An interface for elliptic curve public keys that can provide their
 * uncompressed form.
 *
 * This interface extends `ECKey` to provide a method for obtaining the
 * uncompressed representation of a public key. Elliptic curve public keys can
 * be represented in both compressed (33 bytes) and uncompressed (65 bytes)
 * formats:
 *
 * - Compressed format: Uses a single byte prefix (0x02 or 0x03) followed by
 *   the x-coordinate (32 bytes), with the prefix indicating the parity of the
 *   y-coordinate.
 *
 * - Uncompressed format: Uses a byte prefix (0x04) followed by both x and y
 *   coordinates (32 bytes each), for a total of 65 bytes.
 *
 * The compressed format is more space-efficient and is recommended for most
 * applications, but some legacy systems require the uncompressed format.
 */
export declare interface ECPublicKeyBase extends ECKey {
    /**
     * Returns the uncompressed public key representation.
     */
    uncompressedPublicKey(): ECUncompressedPublicKey;
}

export declare class ECUncompressedPublicKey implements ECKeyBase, ToCbor, ToUR {
    static readonly KEY_SIZE: number;
    private readonly _data;
    private constructor();
    /**
     * Restore an ECUncompressedPublicKey from a fixed-size array of bytes.
     */
    static from(data: Uint8Array): ECUncompressedPublicKey;
    /**
     * Restore an ECUncompressedPublicKey from a hex string.
     */
    static fromHex(hex: string): ECUncompressedPublicKey;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Get hex string representation.
     */
    toHex(): string;
    /**
     * Get base64 representation.
     */
    toBase64(): string;
    /**
     * Convert to compressed public key format.
     * Note: Returns the compressed bytes. To get ECPublicKey, use the ec-public-key module.
     */
    compressedData(): Uint8Array;
    /**
     * Compare with another ECUncompressedPublicKey.
     */
    equals(other: ECUncompressedPublicKey): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<ECUncompressedPublicKey>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     *
     * Format: { 3: h'<65-byte-key>' }
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): ECUncompressedPublicKey;
}

export declare class Ed25519PrivateKey {
    private readonly seed;
    private _publicKey?;
    private constructor();
    /**
     * Create an Ed25519PrivateKey from seed (32 bytes)
     */
    static from(seed: Uint8Array): Ed25519PrivateKey;
    /**
     * Create an Ed25519PrivateKey from hex string (64 hex characters)
     */
    static fromHex(hex: string): Ed25519PrivateKey;
    /** A fresh random value; pass `rng` to make it deterministic. */
    static random({ rng }?: {
        rng?: RandomNumberGenerator;
    }): Ed25519PrivateKey;
    /**
     * Derives an Ed25519 private key from the given key material via
     * HKDF-SHA-256 with salt `"signing"` and empty info (matches Rust
     * `bc_crypto::derive_signing_private_key`).
     */
    static deriveFromKeyMaterial(keyMaterial: Uint8Array): Ed25519PrivateKey;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /** Alias of {@link Ed25519PrivateKey.data}. */
    /** Backwards-compatible alias of {@link Ed25519PrivateKey.data}. */
    /**
     * Get hex string representation of the seed
     */
    toHex(): string;
    /**
     * Get base64 representation of the seed
     */
    toBase64(): string;
    /**
     * Derive the corresponding public key
     */
    publicKey(): Ed25519PublicKey;
    /**
     * Sign a message using Ed25519
     */
    sign(message: Uint8Array): Uint8Array;
    /**
     * Compare with another Ed25519PrivateKey
     */
    equals(other: Ed25519PrivateKey): boolean;
    /**
     * Get string representation
     */
    toString(): string;
}

export declare class Ed25519PublicKey {
    private readonly _data;
    private constructor();
    /**
     * Create an Ed25519PublicKey from raw bytes (32 bytes).
     */
    static from(data: Uint8Array): Ed25519PublicKey;
    /**
     * Create an Ed25519PublicKey from hex string.
     */
    static fromHex(hex: string): Ed25519PublicKey;
    /** Returns the 32 raw public key bytes (copy). */
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /** Alias of {@link Ed25519PublicKey.data}. */
    /** Backwards-compatible alias of {@link Ed25519PublicKey.data}. */
    /**
     * Get hex string representation
     */
    toHex(): string;
    /**
     * Get base64 representation
     */
    toBase64(): string;
    /**
     * Verify a signature using Ed25519
     */
    verify(message: Uint8Array, signature: Uint8Array): boolean;
    /**
     * Compare with another Ed25519PublicKey
     */
    equals(other: Ed25519PublicKey): boolean;
    /**
     * Get string representation.
     *
     *   `Ed25519PublicKey(<ref_hex_short>)`
     * where the reference is computed from the **raw 32-byte data**
     * (not tagged CBOR) — same pattern as SchnorrPublicKey.
     */
    toString(): string;
}

/**
 * Represents the ciphertext from a key encapsulation operation.
 *
 * For X25519, this wraps an ephemeral public key.
 * For MLKEM, this wraps an MLKEMCiphertext.
 */
export declare class EncapsulationCiphertext implements ToCbor {
    private readonly _scheme;
    private readonly _x25519PublicKey;
    private readonly _mlkemCiphertext;
    private constructor();
    /**
     * Create an EncapsulationCiphertext from an X25519PublicKey.
     */
    static fromX25519PublicKey(publicKey: X25519PublicKey): EncapsulationCiphertext;
    /**
     * Create an EncapsulationCiphertext from raw X25519 data.
     */
    static fromX25519Data(data: Uint8Array): EncapsulationCiphertext;
    /**
     * Create an EncapsulationCiphertext from an MLKEMCiphertext.
     */
    static fromMlkem(ciphertext: MLKEMCiphertext): EncapsulationCiphertext;
    /**
     * Create an EncapsulationCiphertext from raw MLKEM ciphertext bytes.
     */
    static fromMlkemData(level: MLKEMLevel, data: Uint8Array): EncapsulationCiphertext;
    /**
     * Returns the encapsulation scheme.
     */
    get encapsulationScheme(): EncapsulationScheme;
    /**
     * Returns true if this is an X25519 ciphertext.
     */
    isX25519(): boolean;
    /**
     * Returns true if this is an MLKEM ciphertext.
     */
    isMlkem(): boolean;
    /**
     * Returns the X25519 public key if this is an X25519 ciphertext.
     * @throws Error if this is not an X25519 ciphertext
     */
    x25519PublicKey(): X25519PublicKey;
    /**
     * Returns the MLKEM ciphertext if this is an MLKEM ciphertext.
     * @throws Error if this is not an MLKEM ciphertext
     */
    mlkemCiphertext(): MLKEMCiphertext;
    /**
     * Returns the X25519 public key if available, or null.
     */
    asX25519(): X25519PublicKey | undefined;
    /**
     * Returns the MLKEM ciphertext if available, or null.
     */
    asMlkem(): MLKEMCiphertext | undefined;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Compare with another EncapsulationCiphertext.
     */
    equals(other: EncapsulationCiphertext): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /** Tagged-CBOR codec; the tag selects the scheme, untagged bytes are X25519. */
    static get codec(): ComponentCodec<EncapsulationCiphertext>;
    /**
     * Returns the CBOR tags associated with this ciphertext.
     */
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form; the tag follows the scheme. */
    toCbor(): Cbor;
    /** As a UR, typed by the scheme's tag name. */
    toUR(): UR;
    /** Decode tagged (X25519 or ML-KEM) or untagged (X25519) CBOR. */
    static fromCbor(cborValue: Cbor): EncapsulationCiphertext;
}

/**
 * Represents a private key for key encapsulation.
 *
 * Use this to decapsulate a shared secret from ciphertext.
 */
export declare class EncapsulationPrivateKey implements ReferenceProvider, ToCbor, ToUR {
    private readonly _scheme;
    private readonly _x25519PrivateKey;
    private readonly _mlkemPrivateKey;
    private constructor();
    /**
     * Create an EncapsulationPrivateKey from an X25519PrivateKey.
     */
    static fromX25519PrivateKey(privateKey: X25519PrivateKey): EncapsulationPrivateKey;
    /**
     * Create an EncapsulationPrivateKey from raw X25519 private key bytes.
     */
    static fromX25519Data(data: Uint8Array): EncapsulationPrivateKey;
    /**
     * Create an EncapsulationPrivateKey from an MLKEMPrivateKey.
     */
    static fromMlkem(privateKey: MLKEMPrivateKey): EncapsulationPrivateKey;
    /**
     * Create an EncapsulationPrivateKey from raw MLKEM private key bytes.
     */
    static fromMlkemData(level: MLKEMLevel, data: Uint8Array): EncapsulationPrivateKey;
    /** A fresh random value; pass `rng` to make it deterministic. */
    static random({ rng }?: {
        rng?: RandomNumberGenerator;
    }): EncapsulationPrivateKey;
    /** A fresh ML-KEM private key at `level`; pass `rng` to make it deterministic. */
    static randomMlkem(level?: MLKEMLevel, { rng }?: {
        rng?: RandomNumberGenerator;
    }): EncapsulationPrivateKey;
    /** A fresh private key and its public key. */
    static keypair({ rng }?: {
        rng?: RandomNumberGenerator;
    }): [EncapsulationPrivateKey, EncapsulationPublicKey];
    /** A fresh ML-KEM private key at `level` and its public key. */
    static mlkemKeypair(level?: MLKEMLevel, { rng }?: {
        rng?: RandomNumberGenerator;
    }): [EncapsulationPrivateKey, EncapsulationPublicKey];
    /**
     * Returns the encapsulation scheme.
     */
    get encapsulationScheme(): EncapsulationScheme;
    /**
     * Returns true if this is an X25519 private key.
     */
    isX25519(): boolean;
    /**
     * Returns true if this is an MLKEM private key.
     */
    isMlkem(): boolean;
    /**
     * Returns the X25519 private key if this is an X25519 encapsulation key.
     * @throws Error if this is not an X25519 key
     */
    x25519PrivateKey(): X25519PrivateKey;
    /**
     * Returns the MLKEM private key if this is an MLKEM encapsulation key.
     * @throws Error if this is not an MLKEM key
     */
    mlkemPrivateKey(): MLKEMPrivateKey;
    /**
     * Returns the X25519 private key if available, or null.
     */
    asX25519(): X25519PrivateKey | undefined;
    /**
     * Returns the MLKEM private key if available, or null.
     */
    asMlkem(): MLKEMPrivateKey | undefined;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Get the public key corresponding to this private key.
     */
    publicKey(): EncapsulationPublicKey;
    /**
     * Decapsulate a shared secret from ciphertext.
     *
     * @param ciphertext - The ciphertext from encapsulation
     * @returns The decapsulated shared secret
     * @throws ComponentsError if the scheme doesn't match
     */
    decapsulateSharedSecret(ciphertext: EncapsulationCiphertext): SymmetricKey;
    /**
     * Compare with another EncapsulationPrivateKey.
     */
    equals(other: EncapsulationPrivateKey): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /**
     * Returns a unique reference to this EncapsulationPrivateKey instance.
     *
     * The reference is derived from the SHA-256 hash of the tagged CBOR
     * representation, providing a unique, content-addressable identifier.
     */
    reference(): Reference;
    /** Tagged-CBOR codec; the tag selects the scheme, untagged bytes are X25519. */
    static get codec(): ComponentCodec<EncapsulationPrivateKey>;
    /**
     * Returns the CBOR tags associated with this private key.
     */
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form; the tag follows the scheme. */
    toCbor(): Cbor;
    /** As a UR, typed by the scheme's tag name. */
    toUR(): UR;
    /** Decode tagged (X25519 or ML-KEM) or untagged (X25519) CBOR. */
    static fromCbor(cborValue: Cbor): EncapsulationPrivateKey;
}

/**
 * Represents a public key for key encapsulation.
 *
 * Use this to encapsulate a shared secret for a recipient.
 */
export declare class EncapsulationPublicKey implements ReferenceProvider, ToCbor, ToUR {
    private readonly _scheme;
    private readonly _x25519PublicKey;
    private readonly _mlkemPublicKey;
    private constructor();
    /**
     * Create an EncapsulationPublicKey from an X25519PublicKey.
     */
    static fromX25519PublicKey(publicKey: X25519PublicKey): EncapsulationPublicKey;
    /**
     * Create an EncapsulationPublicKey from raw X25519 public key bytes.
     */
    static fromX25519Data(data: Uint8Array): EncapsulationPublicKey;
    /**
     * Create an EncapsulationPublicKey from an MLKEMPublicKey.
     */
    static fromMlkem(publicKey: MLKEMPublicKey): EncapsulationPublicKey;
    /**
     * Create an EncapsulationPublicKey from raw MLKEM public key bytes.
     */
    static fromMlkemData(level: MLKEMLevel, data: Uint8Array): EncapsulationPublicKey;
    /**
     * Returns the encapsulation scheme.
     */
    get encapsulationScheme(): EncapsulationScheme;
    /**
     * Returns true if this is an X25519 public key.
     */
    isX25519(): boolean;
    /**
     * Returns true if this is an MLKEM public key.
     */
    isMlkem(): boolean;
    /**
     * Returns the X25519 public key if this is an X25519 encapsulation key.
     * @throws Error if this is not an X25519 key
     */
    x25519PublicKey(): X25519PublicKey;
    /**
     * Returns the MLKEM public key if this is an MLKEM encapsulation key.
     * @throws Error if this is not an MLKEM key
     */
    mlkemPublicKey(): MLKEMPublicKey;
    /**
     * Returns the X25519 public key if available, or null.
     */
    asX25519(): X25519PublicKey | undefined;
    /**
     * Returns the MLKEM public key if available, or null.
     */
    asMlkem(): MLKEMPublicKey | undefined;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Returns this object as an EncapsulationPublicKey.
     *
     * This method allows EncapsulationPublicKey to implement the Encrypter interface.
     * Since this class is itself an encapsulation public key, it returns `this`.
     *
     * @returns This encapsulation public key
     */
    encapsulationPublicKey(): EncapsulationPublicKey;
    /**
     * Encapsulate a new shared secret for this public key.
     *
     * This generates a random shared secret and encapsulates it so that only
     * the holder of the corresponding private key can recover it.
     *
     * @returns A tuple of [sharedSecret, ciphertext]
     */
    encapsulateNewSharedSecret(): [SymmetricKey, EncapsulationCiphertext];
    /**
     * Compare with another EncapsulationPublicKey.
     */
    equals(other: EncapsulationPublicKey): boolean;
    /**
     * Get string representation.
     *
     *   `EncapsulationPublicKey(<ref_hex_short>, <inner_key_display>)`
     * where ref_hex_short is computed from the tagged-CBOR form.
     */
    toString(): string;
    /**
     * Returns a unique reference to this EncapsulationPublicKey instance.
     *
     * The reference is derived from the SHA-256 hash of the tagged CBOR
     * representation, providing a unique, content-addressable identifier.
     */
    reference(): Reference;
    /** Tagged-CBOR codec; the tag selects the scheme, untagged bytes are X25519. */
    static get codec(): ComponentCodec<EncapsulationPublicKey>;
    /**
     * Returns the CBOR tags associated with this public key.
     */
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form; the tag follows the scheme. */
    toCbor(): Cbor;
    /** As a UR, typed by the scheme's tag name. */
    toUR(): UR;
    /** Decode tagged (X25519 or ML-KEM) or untagged (X25519) CBOR. */
    static fromCbor(cborValue: Cbor): EncapsulationPublicKey;
}

/**
 * Available key encapsulation schemes.
 */
export declare const EncapsulationScheme: {
    /**
     * X25519 Diffie-Hellman key exchange (default).
     * Based on Curve25519 as defined in RFC 7748.
     */
    readonly X25519: "x25519";
    /**
     * ML-KEM-512 post-quantum key encapsulation (NIST security level 1).
     */
    readonly MLKEM512: "mlkem512";
    /**
     * ML-KEM-768 post-quantum key encapsulation (NIST security level 3).
     */
    readonly MLKEM768: "mlkem768";
    /**
     * ML-KEM-1024 post-quantum key encapsulation (NIST security level 5).
     */
    readonly MLKEM1024: "mlkem1024";
};

/** One of the `EncapsulationScheme` values. */
export declare type EncapsulationScheme = (typeof EncapsulationScheme)[keyof typeof EncapsulationScheme];

export declare class EncryptedMessage implements ToCbor, ToUR {
    private readonly _ciphertext;
    private readonly _aad;
    private readonly _nonce;
    private readonly _auth;
    private constructor();
    /** Assemble a message from its parts (no encryption happens here). */
    static from({ ciphertext, nonce, authTag, aad }: {
        ciphertext: Uint8Array;
        nonce: Nonce;
        authTag: AuthenticationTag | Uint8Array;
        aad?: Uint8Array;
    }): EncryptedMessage;
    /**
     * Returns a reference to the ciphertext data.
     */
    get ciphertext(): Uint8Array;
    /**
     * Returns a reference to the additional authenticated data (AAD).
     */
    get aad(): Uint8Array;
    /**
     * Returns a reference to the nonce value used for encryption.
     */
    get nonce(): Nonce;
    /**
     * Returns a reference to the authentication tag value used for encryption.
     */
    get authenticationTag(): AuthenticationTag;
    /**
     * Returns a CBOR representation in the AAD field, if it exists.
     */
    aadCbor(): Cbor | null;
    /**
     * Returns a Digest instance if the AAD data can be parsed as CBOR.
     */
    aadDigest(): Digest | null;
    /**
     * Returns true if the AAD data can be parsed as a Digest.
     */
    hasDigest(): boolean;
    /**
     * Compare with another EncryptedMessage.
     */
    equals(other: EncryptedMessage): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<EncryptedMessage>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as an array).
     * Array format: [ciphertext, nonce, auth, ?aad]
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): EncryptedMessage;
}

/**
 * A trait for types that can encapsulate shared secrets for public key encryption.
 *
 * The `Encrypter` interface defines an interface for encapsulating a shared secret
 * using a public key. This is a key part of hybrid encryption schemes, where a
 * shared symmetric key is encapsulated with a public key, and the recipient
 * uses their private key to recover the symmetric key.
 *
 * Types implementing this interface provide the ability to:
 * 1. Access their encapsulation public key
 * 2. Generate and encapsulate new shared secrets
 *
 * This interface is typically implemented by:
 * - Encapsulation public keys
 * - Higher-level types that contain or can generate encapsulation public keys
 *
 * @example
 * ```typescript
 * import { EncapsulationScheme, createEncapsulationKeypair } from '@blockchaincommons/components';
 *
 * // Generate a recipient keypair
 * const [recipientPrivateKey, recipientPublicKey] = createEncapsulationKeypair(EncapsulationScheme.X25519);
 *
 * // Encapsulate a new shared secret
 * const [sharedSecret, ciphertext] = recipientPublicKey.encapsulateNewSharedSecret();
 * ```
 */
export declare interface Encrypter {
    /**
     * Returns the encapsulation public key for this encrypter.
     *
     * @returns The encapsulation public key that should be used for encapsulation.
     */
    encapsulationPublicKey(): EncapsulationPublicKey;
    /**
     * Encapsulates a new shared secret for the recipient.
     *
     * This method generates a new shared secret and encapsulates it using
     * the encapsulation public key from this encrypter.
     *
     * @returns A tuple containing:
     * - The generated shared secret as a `SymmetricKey`
     * - The encapsulation ciphertext that can be sent to the recipient
     */
    encapsulateNewSharedSecret(): [SymmetricKey, EncapsulationCiphertext];
}

/**
 * Convert a base64-encoded string to a Uint8Array.
 *
 * This function works in both browser and Node.js environments.
 * Uses atob which is available in browsers and Node.js 16+.
 *
 * @param base64 - A base64-encoded string
 * @returns The decoded byte array
 *
 * @example
 * ```typescript
 * fromBase64("SGVsbG8="); // Uint8Array([72, 101, 108, 108, 111])
 * ```
 */
export declare function fromBase64(base64: string): Uint8Array;

/**
 * A fresh `PrivateKeys`/`PublicKeys` pair: a signing key and an
 * encapsulation key in the chosen schemes.
 */
export declare function generateKeypair({ signing, encapsulation, rng }?: KeypairOptions): [PrivateKeys, PublicKeys];

export { hexToBytes }

/** Details of an `InvalidData` failure. */
export declare interface InvalidDataDetails {
    code: "InvalidData";
    dataType: string;
    reason: string;
}

/** Details of an `InvalidSize` failure. */
export declare interface InvalidSizeDetails {
    code: "InvalidSize";
    /** What was being constructed (`"data"`, `"Digest"`, …). */
    dataType: string;
    expected: number;
    actual: number;
}

/**
 * Type guard to check if an object implements the Decrypter interface.
 */
export declare function isDecrypter(obj: unknown): obj is Decrypter;

/**
 * Type guard to check if an object implements ECKey.
 */
export declare function isECKey(obj: unknown): obj is ECKey;

/**
 * Type guard to check if an object implements ECKeyBase.
 */
export declare function isECKeyBase(obj: unknown): obj is ECKeyBase;

/**
 * Type guard to check if an object implements ECPublicKeyBase.
 */
export declare function isECPublicKeyBase(obj: unknown): obj is ECPublicKeyBase;

/**
 * Type guard to check if an object implements the Encrypter interface.
 */
export declare function isEncrypter(obj: unknown): obj is Encrypter;

/**
 * Check if a signature scheme is a post-quantum ML-DSA scheme.
 *
 * @param scheme - The signature scheme to check
 * @returns true if the scheme is an ML-DSA scheme
 */
export declare function isMldsaScheme(scheme: SignatureScheme): boolean;

/**
 * Type guard to check if an object implements PrivateKeyDataProvider
 */
export declare function isPrivateKeyDataProvider(obj: unknown): obj is PrivateKeyDataProvider;

/**
 * Type guard to check if an object implements the ReferenceProvider interface.
 */
export declare function isReferenceProvider(obj: unknown): obj is ReferenceProvider;

/**
 * Check if a signature scheme requires SSH agent support.
 *
 * @param scheme - The signature scheme to check
 * @returns true if the scheme requires SSH agent
 */
export declare function isSshScheme(scheme: SignatureScheme): boolean;

/**
 * Type guard for {@link XIDProvider}.
 */
export declare function isXIDProvider(obj: unknown): obj is XIDProvider;

/**
 * Generates a key pair using the default signature and encapsulation schemes
 * (Schnorr + X25519).
 *
 */
/** What `generateKeypair` accepts; every field has a default. */
export declare interface KeypairOptions {
    /** Signature scheme (Schnorr by default). */
    signing?: SignatureScheme;
    /** Encapsulation scheme (X25519 by default). */
    encapsulation?: EncapsulationScheme;
    /** Randomness source; ML-DSA and ML-KEM keys refuse a caller-supplied one. */
    rng?: RandomNumberGenerator;
}

/** Details of every other failure: the unprefixed message. */
export declare interface MessageDetails {
    code: Exclude<ComponentsErrorCode, "InvalidSize" | "InvalidData" | "DataTooShort">;
    message: string;
}

/**
 * ML-DSA security levels.
 *
 * The numeric values correspond to NIST security levels:
 * - 2: NIST Level 2 (MLDSA44)
 * - 3: NIST Level 3 (MLDSA65)
 * - 5: NIST Level 5 (MLDSA87)
 */
export declare const MLDSALevel: {
    /** NIST Level 2 - AES-128 equivalent security */
    readonly MLDSA44: 2;
    /** NIST Level 3 - AES-192 equivalent security */
    readonly MLDSA65: 3;
    /** NIST Level 5 - AES-256 equivalent security */
    readonly MLDSA87: 5;
};

/** One of the `MLDSALevel` values. */
export declare type MLDSALevel = (typeof MLDSALevel)[keyof typeof MLDSALevel];

/**
 * MLDSAPrivateKey - Post-quantum signing private key using ML-DSA.
 */
declare class MLDSAPrivateKey implements ToCbor, ToUR {
    private readonly _level;
    private readonly _data;
    private constructor();
    /** A fresh private key at `level`; pass `rng` to make it deterministic. */
    static random(level?: MLDSALevel, { rng }?: {
        rng?: RandomNumberGenerator;
    }): MLDSAPrivateKey;
    /**
     * Create an MLDSAPrivateKey from raw bytes.
     *
     * @param level - The ML-DSA security level
     * @param data - The private key bytes
     */
    static fromBytes(level: MLDSALevel, data: Uint8Array): MLDSAPrivateKey;
    /** A fresh private key at `level` and its public key. */
    static keypair(level?: MLDSALevel, { rng }?: {
        rng?: RandomNumberGenerator;
    }): [MLDSAPrivateKey, MLDSAPublicKey];
    /**
     * Returns the security level of this key.
     */
    get level(): MLDSALevel;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /** Number of bytes. */
    get byteLength(): number;
    /**
     * Sign a message with this private key.
     *
     * @param message - The message to sign
     * @returns The ML-DSA signature
     */
    sign(message: Uint8Array): MLDSASignature;
    /**
     * Derive the public key from this private key.
     *
     * Note: ML-DSA doesn't have a direct derivation method, so we need to
     * regenerate the keypair from seed. For now, we extract from the secret key
     * structure (the public key is embedded in the secret key for ML-DSA).
     */
    publicKey(): MLDSAPublicKey;
    /**
     * Compare with another MLDSAPrivateKey.
     */
    equals(other: MLDSAPrivateKey): boolean;
    /**
     * Get string representation (truncated for security).
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<MLDSAPrivateKey>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     *
     * Format: [level, key_bytes]
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): MLDSAPrivateKey;
}

/**
 * MLDSAPublicKey - Post-quantum signature verification key using ML-DSA.
 */
declare class MLDSAPublicKey implements ToCbor, ToUR {
    private readonly _level;
    private readonly _data;
    private constructor();
    /**
     * Create an MLDSAPublicKey from raw bytes.
     *
     * @param level - The ML-DSA security level
     * @param data - The public key bytes
     */
    static fromBytes(level: MLDSALevel, data: Uint8Array): MLDSAPublicKey;
    /**
     * Returns the security level of this key.
     */
    get level(): MLDSALevel;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /** Number of bytes. */
    get byteLength(): number;
    /**
     * Verify a signature against a message.
     *
     * @param signature - The ML-DSA signature to verify
     * @param message - The message that was signed
     * @returns True if the signature is valid
     */
    verify(signature: MLDSASignature, message: Uint8Array): boolean;
    /**
     * Compare with another MLDSAPublicKey.
     */
    equals(other: MLDSAPublicKey): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<MLDSAPublicKey>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     *
     * Format: [level, key_bytes]
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): MLDSAPublicKey;
}

/**
 * MLDSASignature - Post-quantum digital signature using ML-DSA.
 */
declare class MLDSASignature implements ToCbor, ToUR {
    private readonly _level;
    private readonly _data;
    private constructor();
    /**
     * Create an MLDSASignature from raw bytes.
     *
     * @param level - The ML-DSA security level
     * @param data - The signature bytes
     */
    static fromBytes(level: MLDSALevel, data: Uint8Array): MLDSASignature;
    /**
     * Returns the security level of this signature.
     */
    get level(): MLDSALevel;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /** Number of bytes. */
    get byteLength(): number;
    /**
     * Compare with another MLDSASignature.
     */
    equals(other: MLDSASignature): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<MLDSASignature>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     *
     * Format: [level, signature_bytes]
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): MLDSASignature;
}

/**
 * MLKEMCiphertext - Post-quantum key encapsulation ciphertext using ML-KEM.
 */
declare class MLKEMCiphertext implements ToCbor, ToUR {
    private readonly _level;
    private readonly _data;
    private constructor();
    /**
     * Create an MLKEMCiphertext from raw bytes.
     *
     * @param level - The ML-KEM security level
     * @param data - The ciphertext bytes
     */
    static fromBytes(level: MLKEMLevel, data: Uint8Array): MLKEMCiphertext;
    /**
     * Returns the security level of this ciphertext.
     */
    get level(): MLKEMLevel;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /** Number of bytes. */
    get byteLength(): number;
    /**
     * Compare with another MLKEMCiphertext.
     */
    equals(other: MLKEMCiphertext): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<MLKEMCiphertext>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     *
     * Format: [level, ciphertext_bytes]
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): MLKEMCiphertext;
}

/**
 * Result of encapsulation operation.
 */
declare interface MLKEMEncapsulationPair {
    /** The shared secret as a SymmetricKey */
    sharedSecret: SymmetricKey;
    /** The ciphertext to send to the private key holder */
    ciphertext: MLKEMCiphertext;
}

/**
 * ML-KEM security levels.
 *
 * The numeric values correspond to the ML-KEM parameter set:
 * - 512: ML-KEM-512 (NIST Level 1)
 * - 768: ML-KEM-768 (NIST Level 3)
 * - 1024: ML-KEM-1024 (NIST Level 5)
 */
export declare const MLKEMLevel: {
    /** NIST Level 1 - AES-128 equivalent security */
    readonly MLKEM512: 512;
    /** NIST Level 3 - AES-192 equivalent security */
    readonly MLKEM768: 768;
    /** NIST Level 5 - AES-256 equivalent security */
    readonly MLKEM1024: 1024;
};

/** One of the `MLKEMLevel` values. */
export declare type MLKEMLevel = (typeof MLKEMLevel)[keyof typeof MLKEMLevel];

/**
 * MLKEMPrivateKey - Post-quantum key decapsulation private key using ML-KEM.
 */
declare class MLKEMPrivateKey implements ToCbor, ToUR {
    private readonly _level;
    private readonly _data;
    private constructor();
    /** A fresh private key at `level`; pass `rng` to make it deterministic. */
    static random(level?: MLKEMLevel, { rng }?: {
        rng?: RandomNumberGenerator;
    }): MLKEMPrivateKey;
    /**
     * Create an MLKEMPrivateKey from raw bytes.
     *
     * @param level - The ML-KEM security level
     * @param data - The private key bytes
     */
    static fromBytes(level: MLKEMLevel, data: Uint8Array): MLKEMPrivateKey;
    /** A fresh private key at `level` and its public key. */
    static keypair(level?: MLKEMLevel, { rng }?: {
        rng?: RandomNumberGenerator;
    }): [MLKEMPrivateKey, MLKEMPublicKey];
    /**
     * Returns the security level of this key.
     */
    get level(): MLKEMLevel;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /** Number of bytes. */
    get byteLength(): number;
    /**
     * Decapsulate a shared secret from a ciphertext.
     *
     * @param ciphertext - The ML-KEM ciphertext
     * @returns The decapsulated shared secret as a SymmetricKey
     */
    decapsulate(ciphertext: MLKEMCiphertext): SymmetricKey;
    /**
     * Derives and returns the corresponding public key.
     *
     * In ML-KEM (FIPS 203), the decapsulation key contains the encapsulation key (public key)
     * embedded within it. This method extracts that public key.
     *
     * @returns The corresponding MLKEMPublicKey
     */
    publicKey(): MLKEMPublicKey;
    /**
     * Compare with another MLKEMPrivateKey.
     */
    equals(other: MLKEMPrivateKey): boolean;
    /**
     * Get string representation (truncated for security).
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<MLKEMPrivateKey>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     *
     * Format: [level, key_bytes]
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): MLKEMPrivateKey;
}

/**
 * MLKEMPublicKey - Post-quantum key encapsulation public key using ML-KEM.
 */
declare class MLKEMPublicKey implements ToCbor, ToUR {
    private readonly _level;
    private readonly _data;
    private constructor();
    /**
     * Create an MLKEMPublicKey from raw bytes.
     *
     * @param level - The ML-KEM security level
     * @param data - The public key bytes
     */
    static fromBytes(level: MLKEMLevel, data: Uint8Array): MLKEMPublicKey;
    /**
     * Returns the security level of this key.
     */
    get level(): MLKEMLevel;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /** Number of bytes. */
    get byteLength(): number;
    /**
     * Encapsulate a new shared secret.
     *
     * This creates a random shared secret and encapsulates it, returning both
     * the shared secret (to be used as a symmetric key) and the ciphertext
     * (to be sent to the private key holder for decapsulation).
     *
     * @returns Object containing sharedSecret and ciphertext
     */
    encapsulate(): MLKEMEncapsulationPair;
    /**
     * Compare with another MLKEMPublicKey.
     */
    equals(other: MLKEMPublicKey): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<MLKEMPublicKey>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     *
     * Format: [level, key_bytes]
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): MLKEMPublicKey;
}

export declare class Nonce implements ToCbor, ToUR {
    static readonly NONCE_SIZE: number;
    private readonly _data;
    private constructor();
    /** A fresh random value; pass `rng` to make it deterministic. */
    static random({ rng }?: {
        rng?: RandomNumberGenerator;
    }): Nonce;
    /**
     * Restores a nonce from data.
     */
    static from(data: Uint8Array): Nonce;
    /**
     * Create a new nonce from the given hexadecimal string.
     *
     * @throws Error if the string is not exactly 24 hexadecimal digits.
     */
    static fromHex(hex: string): Nonce;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * The data as a hexadecimal string.
     */
    toHex(): string;
    /**
     * Get base64 representation.
     */
    toBase64(): string;
    /**
     * Compare with another Nonce.
     */
    equals(other: Nonce): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<Nonce>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as a byte string).
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cbor: Cbor): Nonce;
}

/**
 * PrivateKeyBase - Root cryptographic material for deterministic key derivation.
 *
 * This is the foundation from which signing keys and agreement keys can be
 * deterministically derived using HKDF.
 */
export declare class PrivateKeyBase implements ToCbor, ToUR, Decrypter {
    private readonly _data;
    private constructor();
    /** A fresh random value; pass `rng` to make it deterministic. */
    static random({ rng }?: {
        rng?: RandomNumberGenerator;
    }): PrivateKeyBase;
    /**
     * Create a PrivateKeyBase from raw bytes.
     *
     * @param data - 32 bytes of key material
     */
    static from(data: Uint8Array): PrivateKeyBase;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Derive an Ed25519 signing private key.
     *
     * Uses HKDF with salt "signing", as the reference implementation does's derive_signing_private_key().
     */
    ed25519SigningPrivateKey(): SigningPrivateKey;
    /**
     * Derive an X25519 agreement private key.
     *
     * Uses HKDF with salt "agreement", as the reference implementation does's derive_agreement_private_key().
     */
    x25519PrivateKey(): X25519PrivateKey;
    /**
     * Get EncapsulationPrivateKey for decryption.
     *
     * Returns the derived X25519 private key wrapped as EncapsulationPrivateKey.
     */
    encapsulationPrivateKey(): EncapsulationPrivateKey;
    /**
     * Decapsulate a shared secret from a ciphertext.
     *
     * Implements the `Decrypter` interface so a `PrivateKeyBase` can be used
     * directly as a recipient key,.
     */
    decapsulateSharedSecret(ciphertext: EncapsulationCiphertext): SymmetricKey;
    /**
     * Derive a PrivateKeys container with Ed25519 signing and X25519 agreement keys.
     *
     * @returns PrivateKeys containing the derived signing and encapsulation keys
     */
    ed25519PrivateKeys(): PrivateKeys;
    /**
     * Derive a PublicKeys container from the derived keys.
     *
     * @returns PublicKeys containing the derived public keys
     */
    ed25519PublicKeys(): PublicKeys;
    /**
     * Derive a Schnorr signing private key.
     *
     * Uses ECPrivateKey.deriveFromKeyMaterial() as the reference implementation does's
     * PrivateKeyBase::schnorr_signing_private_key().
     */
    schnorrSigningPrivateKey(): SigningPrivateKey;
    /**
     * Derive a PrivateKeys container with Schnorr signing and X25519 agreement keys.
     *
     */
    schnorrPrivateKeys(): PrivateKeys;
    /**
     * Derive a PublicKeys container from Schnorr derived keys.
     */
    schnorrPublicKeys(): PublicKeys;
    /**
     * Derive an ECDSA signing private key.
     *
     * Uses ECPrivateKey.deriveFromKeyMaterial() as the reference implementation does's
     * PrivateKeyBase::ecdsa_signing_private_key().
     */
    ecdsaSigningPrivateKey(): SigningPrivateKey;
    /**
     * Derive a PrivateKeys container with ECDSA signing and X25519 agreement keys.
     *
     */
    ecdsaPrivateKeys(): PrivateKeys;
    /**
     * Derive a PublicKeys container from ECDSA derived keys.
     */
    ecdsaPublicKeys(): PublicKeys;
    /**
     * Derive an SSH `SigningPrivateKey` from this `PrivateKeyBase`.
     *
     * builds an `HKDFRng` seeded by `this._data` with salt
     * `sshAlgorithmName(algorithm)`, then dispatches to the matching
     * `*Keypair::random` constructor.
     *
     * Supported algorithms (matching the four `SignatureScheme.SshXxx`
     * variants Rust ships in `signature_scheme.rs`):
     *   - Ed25519 (`ssh-ed25519`)
     *   - DSA (`ssh-dss`) — **throws**: byte-deterministic DSA-1024 prime
     *     generation requires porting the upstream `dsa` crate's
     *     FIPS 186-4 prime search, which is not yet implemented in TS.
     *   - ECDSA P-256 (`ecdsa-sha2-nistp256`)
     *   - ECDSA P-384 (`ecdsa-sha2-nistp384`)
     *
     * @param algorithm - The SSH key algorithm to derive
     * @param comment   - Optional comment carried through the OpenSSH PEM
     */
    sshSigningPrivateKey(algorithm: SshAlgorithm, comment?: string): SigningPrivateKey;
    /**
     * Derive a `PrivateKeys` container with an SSH signing key and an X25519
     * agreement key.
     */
    sshPrivateKeys(algorithm: SshAlgorithm, comment?: string): PrivateKeys;
    /**
     * Derive a `PublicKeys` container from `sshPrivateKeys`. Mirrors Rust
     * `PrivateKeyBase::ssh_public_keys`
     */
    sshPublicKeys(algorithm: SshAlgorithm, comment?: string): PublicKeys;
    /**
     * Internal key derivation using HKDF-SHA256.
     */
    private _deriveKey;
    /**
     * Compare with another PrivateKeyBase.
     */
    equals(other: PrivateKeyBase): boolean;
    /**
     * Get string representation (truncated for security).
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<PrivateKeyBase>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): PrivateKeyBase;
}

/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * A trait for types that can provide unique data for cryptographic key derivation.
 *
 *
 * Types implementing `PrivateKeyDataProvider` can be used as seed material for
 * cryptographic key derivation. The provided data should be sufficiently
 * random and unpredictable to ensure the security of the derived keys.
 *
 * This trait is particularly useful for:
 * - Deterministic key generation systems
 * - Key recovery mechanisms
 * - Key derivation hierarchies
 * - Hierarchical deterministic wallet implementations
 *
 * # Security Considerations
 *
 * Implementers of this trait should ensure that:
 * - The data they provide has sufficient entropy
 * - The data is properly protected in memory
 * - Any serialization or storage is done securely
 * - Appropriate zeroization occurs when data is no longer needed
 */
/**
 * Interface for types that can provide unique data for cryptographic key derivation.
 *
 * The provided data should be sufficiently random and have enough entropy
 * to serve as the basis for secure cryptographic key derivation.
 */
export declare interface PrivateKeyDataProvider {
    /**
     * Returns unique data from which cryptographic keys can be derived.
     *
     * The returned data should be sufficiently random and have enough entropy
     * to serve as the basis for secure cryptographic key derivation.
     *
     * @returns A Uint8Array containing the private key data.
     */
    privateKeyData(): Uint8Array;
}

/**
 * PrivateKeys - Container for a signing key and an encapsulation key.
 *
 * This type provides a convenient way to manage a pair of private keys
 * for both signing and encryption operations.
 */
export declare class PrivateKeys implements Signer, Decrypter, ReferenceProvider, ToCbor, ToUR {
    private readonly _signingPrivateKey;
    private readonly _encapsulationPrivateKey;
    private constructor();
    /** Bundle a signing key with an encapsulation key. */
    static from({ signing, encapsulation }: {
        signing: SigningPrivateKey;
        encapsulation: EncapsulationPrivateKey;
    }): PrivateKeys;
    /** Fresh Ed25519 signing and X25519 encapsulation keys. */
    static random({ rng }?: {
        rng?: RandomNumberGenerator;
    }): PrivateKeys;
    /**
     * Generate a new PrivateKeys container with random Ed25519/X25519 keys.
     * This is an alias for new() for API compatibility.
     */
    static generate(): PrivateKeys;
    /**
     * Returns the signing private key.
     */
    get signingPrivateKey(): SigningPrivateKey;
    /**
     * Returns the encapsulation private key.
     *
     * Note: Named to match the reference implementation's API (which has a typo but we maintain compatibility)
     */
    encapsulationPrivateKey(): EncapsulationPrivateKey;
    /**
     * Derive the corresponding public keys.
     */
    publicKeys(): PublicKeys;
    /**
     * Sign a message with optional signing options using the signing private key.
     */
    signWithOptions(message: Uint8Array, options?: SigningOptions): Signature;
    /**
     * Sign a message using the signing private key.
     */
    sign(message: Uint8Array): Signature;
    /**
     * Decapsulate a shared secret from a ciphertext.
     *
     * This implements the Decrypter interface, allowing PrivateKeys to be used
     * in encryption contexts where a shared secret needs to be recovered.
     */
    decapsulateSharedSecret(ciphertext: EncapsulationCiphertext): SymmetricKey;
    /**
     * Returns a unique reference to this PrivateKeys instance.
     *
     * The reference is derived from the SHA-256 hash of the tagged CBOR
     * representation, providing a unique, content-addressable identifier.
     */
    reference(): Reference;
    /**
     * Compare with another PrivateKeys.
     */
    equals(other: PrivateKeys): boolean;
    /**
     *   `PrivateKeys(<refHexShort>, <signingPrivateKey>, <encapsulationPrivateKey>)`
     * The previous abbreviated form (`PrivateKeys(<short>)` only) was a
     * parity drift caught by the E1a summarizer audit.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<PrivateKeys>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     *
     * Format: [<SigningPrivateKey>, <EncapsulationPrivateKey>]
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): PrivateKeys;
}

/**
 * Trait for types that provide access to a PrivateKeys container.
 *
 * This is useful for types that wrap or contain private keys and need
 * to provide access to the underlying key material.
 */
export declare interface PrivateKeysProvider {
    /**
     * Returns the PrivateKeys container.
     */
    privateKeys(): PrivateKeys;
}

/**
 * PublicKeys - Container for a signing public key and an encapsulation public key.
 *
 * This type provides a convenient way to share public keys for both
 * signature verification and encryption operations.
 */
export declare class PublicKeys implements Verifier, Encrypter, ReferenceProvider, ToCbor, ToUR {
    private readonly _signingPublicKey;
    private readonly _encapsulationPublicKey;
    private constructor();
    /**
     * Returns the signing public key.
     */
    get signingPublicKey(): SigningPublicKey;
    /**
     * Returns the encapsulation public key.
     *
     * Note: Named to match the reference implementation's API (which has a typo but we maintain compatibility)
     */
    encapsulationPublicKey(): EncapsulationPublicKey;
    /**
     * Verify a signature against a message.
     */
    verify(signature: Signature, message: Uint8Array): boolean;
    /**
     * Encapsulate a new shared secret using the encapsulation public key.
     *
     * This implements the Encrypter interface, allowing PublicKeys to be used
     * in encryption contexts where a shared secret needs to be generated.
     *
     * @returns A tuple of [SymmetricKey, EncapsulationCiphertext]
     */
    encapsulateNewSharedSecret(): [SymmetricKey, EncapsulationCiphertext];
    /**
     * Returns a unique reference to this PublicKeys instance.
     *
     * The reference is derived from the SHA-256 hash of the tagged CBOR
     * representation, providing a unique, content-addressable identifier.
     */
    reference(): Reference;
    /**
     * Compare with another PublicKeys.
     */
    equals(other: PublicKeys): boolean;
    /**
     * Get string representation.
     *
     *   `PublicKeys(<short_reference>, <signing_public_key>, <encapsulation_public_key>)`
     *
     * The earlier short form (`PublicKeys(<short_reference>)`) was
     * observable in envelope notation as a missing key fingerprint
     * trail in the GSTP `'sender': XID(...) [ 'key': PublicKeys(...) ]`
     * format-pin (G1 in `PARITY_OUTSTANDING.md`).
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<PublicKeys>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     *
     * Format: [<SigningPublicKey>, <EncapsulationPublicKey>]
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    /** Bundle a signing key with an encapsulation key. */
    static from({ signing, encapsulation }: {
        signing: SigningPublicKey;
        encapsulation: EncapsulationPublicKey;
    }): PublicKeys;
    static fromCbor(cborValue: Cbor): PublicKeys;
}

/**
 * Trait for types that provide access to a PublicKeys container.
 *
 * This is useful for types that wrap or contain public keys and need
 * to provide access to the underlying key material.
 */
export declare interface PublicKeysProvider {
    /**
     * Returns the PublicKeys container.
     */
    publicKeys(): PublicKeys;
}

/**
 * A globally unique reference to a globally unique object.
 *
 * Internally stores 32 raw bytes`).
 * Most callers obtain a `Reference` via `fromDigest`, but `XID` (and similar
 * content-addressable types whose bytes _are_ the reference) construct
 * via `fromData` directly.
 */
export declare class Reference implements ToCbor, DigestProvider, ReferenceProvider {
    /** Reference data size in bytes. */
    static readonly REFERENCE_SIZE = 32;
    private readonly _data;
    private constructor();
    /** Create a Reference from exactly 32 bytes. */
    static from(data: Uint8Array): Reference;
    /**  */
    /** Create a Reference from a Digest's underlying bytes. */
    static fromDigest(digest: Digest): Reference;
    /** Backwards-compatible alias of `fromDigest`. */
    /** Create a Reference from a 64-character hex string. */
    static fromHex(hex: string): Reference;
    /**
     * Create a Reference whose bytes are the SHA-256 digest of the input.
     *
     * @deprecated Prefer `Reference.fromDigest(Digest.fromImage(data))` for
     *   clarity, or `Reference.from(data)` if `data` is already 32 bytes
     *   that should be wrapped without hashing.
     */
    static hash(data: Uint8Array): Reference;
    /** Returns the 32 reference bytes (copy). */
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /** Alias of `data()`. */
    /** Returns a `Digest` constructed from these 32 bytes (no hashing). */
    /** The full 64-character lowercase hex of the reference. */
    refHex(): string;
    /** The first 4 bytes of the reference. */
    refDataShort(): Uint8Array;
    /** The first 4 bytes of the reference, as 8 lowercase hex characters. */
    refHexShort(): string;
    /**
     * The first 4 bytes as upper-case bytewords identifier.
     *
     * @param prefix - Optional prefix prepended with a single space.
     */
    bytewordsIdentifier(prefix?: string): string;
    /**
     * The first 4 bytes as upper-case bytemojis identifier.
     *
     * @param prefix - Optional prefix prepended with a single space.
     */
    bytemojiIdentifier(prefix?: string): string;
    /** Backwards-compatible alias of `refHex()`. */
    toHex(): string;
    /** Backwards-compatible alias of `refHex()`. */
    fullReference(): string;
    /** Returns the 32 raw bytes encoded as base64. */
    toBase64(): string;
    /**
     * Returns a short representation of this reference in the requested format.
     *
     * Mirrors the legacy TS API; new code should prefer `refHexShort`,
     * `bytewordsIdentifier`, or `bytemojiIdentifier` directly.
     */
    shortReference(format?: ReferenceEncodingFormat): string;
    /** A Reference to this Reference. */
    reference(): Reference;
    /**
     * SHA-256 of `taggedCbor().toCborData()`.
     *
     * `Digest::from_image(self.tagged_cbor().to_cbor_data())`.
     */
    digest(): Digest;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<Reference>;
    cborTags(): Tag[];
    /** Untagged CBOR — a single byte string of the 32 raw bytes. */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cbor: Cbor): Reference;
    /** UR representation — `ur:reference/...`, untagged CBOR payload. */
    equals(other: Reference): boolean;
    /** Debug-style representation: `Reference(<8-hex-prefix>)`. */
    toString(): string;
}

/** Encoding format for short Reference identifiers. */
export declare type ReferenceEncodingFormat = "hex" | "bytewords" | "bytemojis";

/**
 * Implementers of this interface provide a globally unique reference to themselves.
 *
 * cryptographic digest of the object's serialized form, ensuring that it
 * uniquely identifies the object's contents.
 */
export declare interface ReferenceProvider {
    /** Returns a cryptographic reference that uniquely identifies this object. */
    reference(): Reference;
}

export declare class Salt implements ToCbor, ToUR {
    private readonly _data;
    private constructor();
    /**
     * Create a new salt from data.
     * Note: Does not validate minimum size to allow for CBOR deserialization.
     */
    static from(data: Uint8Array): Salt;
    /**
     * Create a new salt from the given hexadecimal string.
     */
    static fromHex(hex: string): Salt;
    /** A random salt of `length` bytes (16 by default); pass `rng` to make it deterministic. */
    static random({ length, rng }?: {
        length?: number;
        rng?: RandomNumberGenerator;
    }): Salt;
    /** A random salt of a random length in `[minSize, maxSize]`. */
    static randomInRange(minSize: number, maxSize: number, { rng }?: {
        rng?: RandomNumberGenerator;
    }): Salt;
    /** A random salt sized for a payload of `size` bytes (5–25% of it, at least the minimum). */
    static forSize(size: number, { rng }?: {
        rng?: RandomNumberGenerator;
    }): Salt;
    /** Number of bytes. */
    get byteLength(): number;
    /**
     * Return true if the salt is empty (this is not recommended).
     */
    isEmpty(): boolean;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * The data as a hexadecimal string.
     */
    toHex(): string;
    /**
     * Get base64 representation.
     */
    toBase64(): string;
    /**
     * Compare with another Salt.
     */
    equals(other: Salt): boolean;
    /**
     * Get string representation showing the salt's length.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<Salt>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as a byte string).
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cbor: Cbor): Salt;
}

export declare class SchnorrPublicKey implements ECKeyBase {
    static readonly KEY_SIZE: number;
    private readonly _data;
    private constructor();
    /**
     * Restore a SchnorrPublicKey from a fixed-size array of bytes.
     */
    static from(data: Uint8Array): SchnorrPublicKey;
    /**
     * Restore a SchnorrPublicKey from a hex string.
     */
    static fromHex(hex: string): SchnorrPublicKey;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Get hex string representation.
     */
    toHex(): string;
    /**
     * Get base64 representation.
     */
    toBase64(): string;
    /**
     * Verify a Schnorr signature (BIP-340).
     *
     * @param signature - The 64-byte signature to verify
     * @param message - The message that was signed
     * @returns true if the signature is valid
     */
    schnorrVerify(signature: Uint8Array, message: Uint8Array): boolean;
    /**
     * Compare with another SchnorrPublicKey.
     */
    equals(other: SchnorrPublicKey): boolean;
    /**
     * Get string representation.
     *
     * — the reference is computed from the **raw 32-byte key data**
     * (not the tagged-CBOR form): `Reference::from_digest(Digest::from_image(self.bytes))`.
     * `ref_hex_short()` returns the first 8 hex chars of that
     * reference's binary form (= SHA-256(data)[0..4]).
     */
    toString(): string;
}

/**
 * A sealed message providing anonymous authenticated encryption.
 */
export declare class SealedMessage implements ToCbor, ToUR {
    private readonly _message;
    private readonly _encapsulatedKey;
    private constructor();
    /**
     * Create a SealedMessage from its components.
     */
    static from(message: EncryptedMessage, encapsulatedKey: EncapsulationCiphertext): SealedMessage;
    /**
     * Encrypt `plaintext` to `recipient`: a fresh shared secret is
     * encapsulated to the recipient's key and encrypts the plaintext.
     */
    static seal(plaintext: Uint8Array, recipient: EncapsulationPublicKey, { aad, nonce }?: {
        aad?: Uint8Array;
        nonce?: Nonce;
    }): SealedMessage;
    /**
     * Returns the encrypted message.
     */
    get message(): EncryptedMessage;
    /**
     * Returns the encapsulation ciphertext (ephemeral public key for X25519).
     */
    get encapsulatedKey(): EncapsulationCiphertext;
    /**
     * Returns the encapsulation scheme used.
     */
    get encapsulationScheme(): EncapsulationScheme;
    /**
     * Decrypt the sealed message using the recipient's private key.
     *
     * @param privateKey - The recipient's private key
     * @returns The decrypted plaintext
     * @throws Error if decryption fails
     */
    decrypt(privateKey: EncapsulationPrivateKey): Uint8Array;
    /**
     * Compare with another SealedMessage.
     */
    equals(other: SealedMessage): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<SealedMessage>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     * Format: [EncryptedMessage (tagged), EncapsulationCiphertext (tagged)]
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): SealedMessage;
}

export declare class Seed implements ToCbor, ToUR, PrivateKeyDataProvider {
    /**
     * Minimum seed length in bytes.
     */
    static readonly MIN_SEED_LENGTH = 16;
    private readonly _data;
    private _name;
    private _note;
    private _creationDate;
    private constructor();
    /**
     * A random seed of `length` bytes (16 by default), with optional metadata;
     * pass `rng` to make it deterministic.
     */
    static random({ length, rng, ...metadata }?: {
        length?: number;
        rng?: RandomNumberGenerator;
    } & SeedMetadata): Seed;
    /**
     * Create a Seed from raw bytes with optional metadata.
     *
     * Note: The input data is copied to prevent external mutation of the seed's internal state.
     *
     * @param data - Seed bytes (must be >= 16 bytes)
     * @param metadata - Optional metadata object
     */
    static from(data: Uint8Array, metadata?: SeedMetadata): Seed;
    /**
     * Create a Seed from hex string with optional metadata.
     *
     * @param hex - Hex string representing seed bytes
     * @param metadata - Optional metadata object
     */
    static fromHex(hex: string, metadata?: SeedMetadata): Seed;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Get hex string representation.
     */
    toHex(): string;
    /**
     * Get base64 representation.
     */
    toBase64(): string;
    /** Number of bytes. */
    get byteLength(): number;
    /**
     * Return the name of the seed.
     *
     * returns empty string if not set.
     */
    /** The optional metadata as one object. */
    get metadata(): SeedMetadata;
    get name(): string;
    set name(name: string);
    /**
     * Return the note of the seed.
     *
     * returns empty string if not set.
     */
    get note(): string;
    set note(note: string);
    /**
     * Return the creation date of the seed.
     *
     * */
    get creationDate(): Date | undefined;
    set creationDate(creationDate: Date | undefined);
    /**
     * Compare with another Seed.
     */
    equals(other: Seed): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /**
     * Returns unique data from which cryptographic keys can be derived.
     *
     * This implementation returns a copy of the seed data, which can be used
     * as entropy for deriving private keys in various cryptographic schemes.
     *
     * @returns A Uint8Array containing the seed data
     */
    privateKeyData(): Uint8Array;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<Seed>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as a map).
     * Map keys:
     * - 1: seed data (required)
     * - 2: creation date (optional)
     * - 3: name (optional, omitted if empty)
     * - 4: note (optional, omitted if empty)
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): Seed;
}

export declare interface SeedMetadata {
    name?: string | undefined;
    note?: string | undefined;
    creationDate?: Date | undefined;
}

/**
 * A digital signature created with various signature algorithms.
 *
 * Currently supports:
 * - Schnorr signatures (64 bytes) - bare byte string in CBOR
 * - ECDSA signatures (64 bytes) - discriminator 1
 * - Ed25519 signatures (64 bytes) - discriminator 2
 * - Sr25519 signatures (64 bytes) - discriminator 3
 * - MLDSA signatures (post-quantum) - tagged CBOR delegating to MLDSASignature
 */
export declare class Signature implements ToCbor {
    private readonly _type;
    private readonly _data;
    private readonly _mldsaSignature;
    private readonly _sshSig;
    private constructor();
    /**
     * Creates a Schnorr signature from a 64-byte array.
     *
     * @param data - The 64-byte signature data
     * @returns A new Schnorr signature
     */
    static schnorrFromData(data: Uint8Array): Signature;
    /**
     * Creates a Schnorr signature from a hex string.
     *
     * @param hex - The hex-encoded signature data
     * @returns A new Schnorr signature
     */
    static schnorrFromHex(hex: string): Signature;
    /**
     * Creates an ECDSA signature from a 64-byte array.
     *
     * @param data - The 64-byte signature data
     * @returns A new ECDSA signature
     */
    static ecdsaFromData(data: Uint8Array): Signature;
    /**
     * Creates an ECDSA signature from a hex string.
     *
     * @param hex - The hex-encoded signature data
     * @returns A new ECDSA signature
     */
    static ecdsaFromHex(hex: string): Signature;
    /**
     * Creates an Ed25519 signature from a 64-byte array.
     *
     * @param data - The 64-byte signature data
     * @returns A new Ed25519 signature
     */
    static ed25519FromData(data: Uint8Array): Signature;
    /**
     * Creates an Ed25519 signature from a hex string.
     *
     * @param hex - The hex-encoded signature data
     * @returns A new Ed25519 signature
     */
    static ed25519FromHex(hex: string): Signature;
    /**
     * Creates an Sr25519 signature from a 64-byte array.
     *
     * @param data - The 64-byte signature data
     * @returns A new Sr25519 signature
     */
    static sr25519FromData(data: Uint8Array): Signature;
    /**
     * Creates an Sr25519 signature from a hex string.
     *
     * @param hex - The hex-encoded signature data
     * @returns A new Sr25519 signature
     */
    static sr25519FromHex(hex: string): Signature;
    /**
     * Creates a Signature from an MLDSASignature.
     *
     * @param sig - The MLDSASignature
     * @returns A new Signature wrapping the MLDSA signature
     */
    static mldsaFromSignature(sig: MLDSASignature): Signature;
    /**
     * Creates a Signature from an SSHSignature.
     *
     *
     * The signature scheme is derived from the inner public-key algorithm,
     * as the reference implementation does `Signature::scheme()` at lines 506-519.
     *
     * @param sig - The SSHSignature
     * @returns A new SSH Signature
     */
    static fromSsh(sig: SSHSignature): Signature;
    /**
     * Returns the signature scheme used to create this signature.
     */
    get scheme(): SignatureScheme;
    /**
     * Returns a human-readable string identifying the signature type.
     * @returns A string like "Ed25519", "Schnorr", "ECDSA", "Sr25519", "MLDSA-44", etc.
     */
    get signatureType(): string;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Returns the Schnorr signature data if this is a Schnorr signature.
     *
     * @returns The 64-byte signature data if this is a Schnorr signature, undefined otherwise
     */
    asSchnorr(): Uint8Array | undefined;
    /**
     * Checks if this is a Schnorr signature.
     */
    isSchnorr(): boolean;
    /**
     * Returns the ECDSA signature data if this is an ECDSA signature.
     *
     * @returns The 64-byte signature data if this is an ECDSA signature, undefined otherwise
     */
    asEcdsa(): Uint8Array | undefined;
    /**
     * Checks if this is an ECDSA signature.
     */
    isEcdsa(): boolean;
    /**
     * Returns the Ed25519 signature data if this is an Ed25519 signature.
     *
     * @returns The 64-byte signature data if this is an Ed25519 signature, undefined otherwise
     */
    asEd25519(): Uint8Array | undefined;
    /**
     * Checks if this is an Ed25519 signature.
     */
    isEd25519(): boolean;
    /**
     * Returns the Sr25519 signature data if this is an Sr25519 signature.
     *
     * @returns The 64-byte signature data if this is an Sr25519 signature, undefined otherwise
     */
    asSr25519(): Uint8Array | undefined;
    /**
     * Checks if this is an Sr25519 signature.
     */
    isSr25519(): boolean;
    /**
     * Returns the MLDSASignature if this is an MLDSA signature.
     *
     * @returns The MLDSASignature if this is an MLDSA signature, undefined otherwise
     */
    asMldsa(): MLDSASignature | undefined;
    /**
     * Checks if this is an MLDSA signature.
     */
    isMldsa(): boolean;
    /**
     * Returns the underlying SSHSignature if this is an SSH signature.
     *
     *
     * @returns The SSHSignature if this is an SSH signature, undefined otherwise
     */
    asSsh(): SSHSignature | undefined;
    /**
     * Checks if this is an SSH signature.
     */
    isSsh(): boolean;
    /**
     * Get hex string representation of the signature data.
     */
    toHex(): string;
    /**
     * Compare with another Signature.
     */
    equals(other: Signature): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<Signature>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     *
     * Format:
     * - Schnorr: h'<64-byte-signature>' (bare byte string)
     * - ECDSA:   [1, h'<64-byte-signature>']
     * - Ed25519: [2, h'<64-byte-signature>']
     * - Sr25519: [3, h'<64-byte-signature>']
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): Signature;
}

/**
 * Supported digital signature schemes.
 *
 * This enum represents the various signature schemes supported in this package.
 * - Schnorr: BIP-340 Schnorr signature scheme (secp256k1) - DEFAULT
 * - ECDSA: ECDSA signature scheme (secp256k1)
 * - Ed25519: RFC 8032 signatures
 * - Sr25519: Schnorr over Ristretto25519, used by Polkadot/Substrate
 * - MLDSA44: ML-DSA44 post-quantum signature scheme (NIST level 2)
 * - MLDSA65: ML-DSA65 post-quantum signature scheme (NIST level 3)
 * - MLDSA87: ML-DSA87 post-quantum signature scheme (NIST level 5)
 * - SshEd25519: Ed25519 via SSH agent
 * - SshDsa: DSA via SSH agent
 * - SshEcdsaP256: ECDSA P-256 via SSH agent
 * - SshEcdsaP384: ECDSA P-384 via SSH agent
 *
 * Wire format note: Rust models `SignatureScheme` as a unit-only enum;
 * TypeScript uses string-typed values for ergonomic `switch`/`equals`
 * checks. The CBOR/UR wire format never includes the scheme name —
 * only the scheme's integer/byte-string discriminator on `Signature`,
 * `SigningPrivateKey`, `SigningPublicKey` — so this is a stylistic
 * difference, not a parity gap.
 */
export declare const SignatureScheme: {
    /**
     * BIP-340 Schnorr signature scheme (secp256k1)
     * Default scheme
     */
    readonly Schnorr: "Schnorr";
    /**
     * ECDSA signature scheme (secp256k1)
     */
    readonly Ecdsa: "Ecdsa";
    /**
     * Ed25519 signature scheme (RFC 8032)
     */
    readonly Ed25519: "Ed25519";
    /**
     * SR25519 signature scheme (Schnorr over Ristretto25519)
     * Used by Polkadot/Substrate
     */
    readonly Sr25519: "Sr25519";
    /**
     * ML-DSA44 post-quantum signature scheme (NIST level 2)
     */
    readonly MLDSA44: "MLDSA44";
    /**
     * ML-DSA65 post-quantum signature scheme (NIST level 3)
     */
    readonly MLDSA65: "MLDSA65";
    /**
     * ML-DSA87 post-quantum signature scheme (NIST level 5)
     */
    readonly MLDSA87: "MLDSA87";
    /**
     * Ed25519 signature via SSH agent.
     * Requires SSH agent daemon support.
     */
    readonly SshEd25519: "SshEd25519";
    /**
     * DSA signature via SSH agent.
     * Requires SSH agent daemon support.
     */
    readonly SshDsa: "SshDsa";
    /**
     * ECDSA P-256 signature via SSH agent.
     * Requires SSH agent daemon support.
     */
    readonly SshEcdsaP256: "SshEcdsaP256";
    /**
     * ECDSA P-384 signature via SSH agent.
     * Requires SSH agent daemon support.
     */
    readonly SshEcdsaP384: "SshEcdsaP384";
};

/** One of the `SignatureScheme` values. */
export declare type SignatureScheme = (typeof SignatureScheme)[keyof typeof SignatureScheme];

/**
 * A trait for types capable of creating digital signatures.
 *
 * The `Signer` interface provides methods for signing messages with various
 * cryptographic signature schemes. Implementations of this interface can sign
 * messages using different algorithms according to the specific signer type.
 */
export declare interface Signer {
    /**
     * Signs a message with optional signing options.
     *
     * Different signature schemes may use the options differently:
     * - Schnorr: Can accept a custom random number generator
     * - SSH: Requires namespace and hash algorithm (not yet implemented)
     * - Other schemes: Options are ignored
     *
     * @param message - The message to sign
     * @param options - Optional signing options
     * @returns The digital signature
     * @throws If signing fails
     */
    signWithOptions(message: Uint8Array, options?: SigningOptions): Signature;
    /**
     * Signs a message using default options.
     *
     * This is a convenience method that calls `signWithOptions` with no options.
     *
     * @param message - The message to sign
     * @returns The digital signature
     * @throws If signing fails
     */
    sign(message: Uint8Array): Signature;
}

/**
 * Options for configuring signature creation.
 *
 * Different signature schemes may require specific options:
 * - Schnorr: Optionally accepts a custom random number generator
 * - Ssh: Requires a namespace and hash algorithm
 *
 * Other signature types like ECDSA, Ed25519, Sr25519, and ML-DSA don't require options.
 */
export declare type SigningOptions = {
    type: "Schnorr";
    /** Custom random number generator for signature creation */
    rng: RandomNumberGenerator;
} | {
    type: "Ssh";
    /** The namespace used for SSH signatures */
    namespace: string;
    /** The hash algorithm used for SSH signatures */
    hashAlg: "sha256" | "sha512";
};

/**
 * A private key used for creating digital signatures.
 *
 * Currently supports:
 * - Schnorr private keys (32 bytes, secp256k1) - bare byte string in CBOR
 * - ECDSA private keys (32 bytes, secp256k1) - discriminator 1
 * - Ed25519 private keys (32 bytes) - discriminator 2
 * - SR25519 private keys (32-byte seed) - discriminator 3
 * - MLDSA private keys (post-quantum) - tagged CBOR delegating to MLDSAPrivateKey
 */
export declare class SigningPrivateKey implements Signer, Verifier, ReferenceProvider, ToCbor {
    private readonly _type;
    private readonly _ecKey;
    private readonly _ed25519Key;
    private readonly _sr25519Key;
    private readonly _mldsaKey;
    private readonly _sshKey;
    private constructor();
    /**
     * Creates a new Schnorr signing private key from an ECPrivateKey.
     *
     * @param key - The EC private key to use for Schnorr signing
     * @returns A new Schnorr signing private key
     */
    static fromSchnorr(key: ECPrivateKey): SigningPrivateKey;
    /**
     * Creates a new ECDSA signing private key from an ECPrivateKey.
     *
     * @param key - The EC private key to use for ECDSA signing
     * @returns A new ECDSA signing private key
     */
    static fromEcdsa(key: ECPrivateKey): SigningPrivateKey;
    /**
     * Creates a new Ed25519 signing private key from an Ed25519PrivateKey.
     *
     * @param key - The Ed25519 private key to use
     * @returns A new Ed25519 signing private key
     */
    static fromEd25519(key: Ed25519PrivateKey): SigningPrivateKey;
    /**
     * Creates a new SR25519 signing private key from an Sr25519PrivateKey.
     *
     * @param key - The SR25519 private key to use
     * @returns A new SR25519 signing private key
     */
    static fromSr25519(key: Sr25519PrivateKey): SigningPrivateKey;
    /**
     * Creates a new MLDSA signing private key from an MLDSAPrivateKey.
     *
     * @param key - The MLDSA private key to use
     * @returns A new MLDSA signing private key
     */
    static fromMldsa(key: MLDSAPrivateKey): SigningPrivateKey;
    /**
     * Creates a new SSH signing private key from an SSHPrivateKey.
     *
     *
     * @param key - The SSH private key to wrap
     * @returns A new SSH signing private key
     */
    static fromSsh(key: SSHPrivateKey): SigningPrivateKey;
    /**
     * A fresh signing key; Ed25519 unless `scheme` says otherwise. SSH schemes
     * derive from a `PrivateKeyBase` instead.
     */
    static random({ scheme, rng }?: {
        scheme?: SignatureScheme;
        rng?: RandomNumberGenerator;
    }): SigningPrivateKey;
    /**
     * Returns the signature scheme of this key.
     */
    get scheme(): SignatureScheme;
    /**
     * Returns a human-readable string identifying the key type.
     * @returns A string like "Ed25519", "Schnorr", "ECDSA", "Sr25519", "MLDSA-44", etc.
     */
    get keyType(): string;
    /**
     * Returns the underlying EC private key if this is a Schnorr or ECDSA key.
     *
     * @returns The EC private key if this is a Schnorr or ECDSA key, undefined otherwise
     */
    asEc(): ECPrivateKey | undefined;
    /**
     * Returns the underlying Schnorr private key if this is a Schnorr key.
     *
     * @returns The EC private key if this is a Schnorr key, undefined otherwise
     */
    asSchnorr(): ECPrivateKey | undefined;
    /**
     * Returns the underlying ECDSA private key if this is an ECDSA key.
     *
     * @returns The EC private key if this is an ECDSA key, undefined otherwise
     */
    asEcdsa(): ECPrivateKey | undefined;
    /**
     * Returns the underlying Ed25519 private key if this is an Ed25519 key.
     *
     * @returns The Ed25519 private key if this is an Ed25519 key, undefined otherwise
     */
    asEd25519(): Ed25519PrivateKey | undefined;
    /**
     * Returns the underlying Sr25519 private key if this is an Sr25519 key.
     *
     * @returns The Sr25519 private key if this is an Sr25519 key, undefined otherwise
     */
    asSr25519(): Sr25519PrivateKey | undefined;
    /**
     * Returns the underlying MLDSA private key if this is an MLDSA key.
     *
     * @returns The MLDSA private key if this is an MLDSA key, undefined otherwise
     */
    asMldsa(): MLDSAPrivateKey | undefined;
    /**
     * Checks if this is a Schnorr signing key.
     */
    isSchnorr(): boolean;
    /**
     * Checks if this is an ECDSA signing key.
     */
    isEcdsa(): boolean;
    /**
     * Checks if this is an Ed25519 signing key.
     */
    isEd25519(): boolean;
    /**
     * Checks if this is an Sr25519 signing key.
     */
    isSr25519(): boolean;
    /**
     * Checks if this is an MLDSA signing key.
     */
    isMldsa(): boolean;
    /**
     * Derives the corresponding public key for this private key.
     *
     * @returns The public key corresponding to this private key
     */
    publicKey(): SigningPublicKey;
    /**
     * Returns the underlying SSH private key if this is an SSH key.
     *
     *
     * @returns The SSHPrivateKey if this is an SSH key, undefined otherwise
     */
    asSsh(): SSHPrivateKey | undefined;
    /**
     * Checks if this is an SSH signing key.
     */
    isSsh(): boolean;
    /**
     * Compare with another SigningPrivateKey.
     */
    equals(other: SigningPrivateKey): boolean;
    /**
     *   `SigningPrivateKey(<refHexShort>, <inner>)`
     * where `<inner>` is:
     *   - `SchnorrPrivateKey(<refHexShort>)` / `ECDSAPrivateKey(<refHexShort>)`
     *     for the secp256k1 variants (Rust formats them inline by tag rather
     *     than delegating to the inner key's Display)
     *   - the inner key's Display for Ed25519 and MLDSA
     *   - `SSHPrivateKey(<refHexShort>)` for SSH
     * The previous abbreviated form (`SigningPrivateKey(<type>)` only) was
     * a parity drift caught by the E1a summarizer audit.
     */
    toString(): string;
    /**
     * Returns a unique reference to this SigningPrivateKey instance.
     *
     * The reference is derived from the SHA-256 hash of the tagged CBOR
     * representation, providing a unique, content-addressable identifier.
     */
    reference(): Reference;
    /**
     * Signs a message with optional signing options.
     *
     * Different signature schemes may use the options differently:
     * - Schnorr: Can accept a custom random number generator via SigningOptions.Schnorr
     * - SSH: Would require namespace and hash algorithm (not yet implemented)
     * - Other schemes (ECDSA, Ed25519, Sr25519, MLDSA): Options are ignored
     *
     * @param message - The message to sign
     * @param options - Optional signing options
     * @returns The digital signature
     */
    signWithOptions(message: Uint8Array, options?: SigningOptions): Signature;
    /**
     * Signs a message using default options.
     *
     * This is a convenience method that calls `signWithOptions` with no options.
     *
     * @param message - The message to sign
     * @returns The digital signature
     */
    sign(message: Uint8Array): Signature;
    /**
     * Verifies a signature against a message using the derived public key.
     *
     * actually verify; every other scheme returns `false`. Callers needing
     * verification for Ed25519 / ECDSA / Sr25519 / MLDSA should derive the
     * public key first via `publicKey().verify(...)`.
     *
     * @param signature - The signature to verify
     * @param message - The message that was allegedly signed
     * @returns `true` if the signature is a valid Schnorr signature
     */
    verify(signature: Signature, message: Uint8Array): boolean;
    /**
     * Signs a message using Schnorr with the provided random number generator.
     *
     * This method is only valid for Schnorr keys.
     *
     * @param message - The message to sign
     * @param rng - The random number generator to use for signature creation
     * @returns The Schnorr signature
     * @throws Error if this is not a Schnorr key
     */
    schnorrSign(message: Uint8Array, rng: RandomNumberGenerator): Signature;
    /**
     * Signs a message using ECDSA.
     *
     * This method is only valid for ECDSA keys.
     *
     * @param message - The message to sign
     * @returns The ECDSA signature
     * @throws Error if this is not an ECDSA key
     */
    ecdsaSign(message: Uint8Array): Signature;
    /**
     * Signs a message using Ed25519.
     *
     * This method is only valid for Ed25519 keys.
     *
     * @param message - The message to sign
     * @returns The Ed25519 signature
     * @throws Error if this is not an Ed25519 key
     */
    ed25519Sign(message: Uint8Array): Signature;
    /**
     * Signs a message using SR25519.
     *
     * This method is only valid for SR25519 keys.
     *
     * @param message - The message to sign
     * @returns The SR25519 signature
     * @throws Error if this is not an SR25519 key
     */
    sr25519Sign(message: Uint8Array): Signature;
    /**
     * Signs a message using ML-DSA.
     *
     * This method is only valid for MLDSA keys.
     *
     * @param message - The message to sign
     * @returns The ML-DSA signature
     * @throws Error if this is not an MLDSA key
     */
    mldsaSign(message: Uint8Array): Signature;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<SigningPrivateKey>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     *
     * Format:
     * - Schnorr: h'<32-byte-private-key>' (bare byte string)
     * - ECDSA:   [1, h'<32-byte-private-key>']
     * - Ed25519: [2, h'<32-byte-private-key>']
     * - Sr25519: [3, h'<32-byte-seed>']
     * - MLDSA:   delegates to MLDSAPrivateKey (tagged)
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): SigningPrivateKey;
    /**
     * Returns the canonical OpenSSH armored PEM for an SSH private key.
     *
     * Only valid when this `SigningPrivateKey` wraps an `SSHPrivateKey`
     * (i.e. one of the four `SignatureScheme.SshXxx` variants). Mirrors
     * the reference implementation's `SigningPrivateKey::SSH(key) => key.to_openssh(LineEnding::LF)`
     * usage at `signing_private_key.rs:896`.
     */
    toSshOpenssh(): string;
}

/**
 * A public key used for verifying digital signatures.
 *
 * Currently supports:
 * - Schnorr public keys (32 bytes, x-only) - bare byte string in CBOR
 * - ECDSA public keys (33 bytes, compressed) - discriminator 1
 * - Ed25519 public keys (32 bytes) - discriminator 2
 * - Sr25519 public keys (32 bytes) - discriminator 3
 * - MLDSA public keys (post-quantum) - tagged CBOR delegating to MLDSAPublicKey
 */
export declare class SigningPublicKey implements Verifier, ReferenceProvider, ToCbor {
    private readonly _type;
    private readonly _schnorrKey;
    private readonly _ecdsaKey;
    private readonly _ed25519Key;
    private readonly _sr25519Key;
    private readonly _mldsaKey;
    private readonly _sshKey;
    private constructor();
    /**
     * Creates a new signing public key from a Schnorr (x-only) public key.
     *
     * @param key - A SchnorrPublicKey
     * @returns A new signing public key containing the Schnorr key
     */
    static fromSchnorr(key: SchnorrPublicKey): SigningPublicKey;
    /**
     * Creates a new signing public key from an ECDSA (compressed) public key.
     *
     * @param key - An ECPublicKey
     * @returns A new signing public key containing the ECDSA key
     */
    static fromEcdsa(key: ECPublicKey): SigningPublicKey;
    /**
     * Creates a new signing public key from an Ed25519 public key.
     *
     * @param key - An Ed25519 public key
     * @returns A new signing public key containing the Ed25519 key
     */
    static fromEd25519(key: Ed25519PublicKey): SigningPublicKey;
    /**
     * Creates a new signing public key from an Sr25519 public key.
     *
     * @param key - An Sr25519 public key
     * @returns A new signing public key containing the Sr25519 key
     */
    static fromSr25519(key: Sr25519PublicKey): SigningPublicKey;
    /**
     * Creates a new signing public key from an MLDSAPublicKey.
     *
     * @param key - An MLDSAPublicKey
     * @returns A new signing public key containing the MLDSA key
     */
    static fromMldsa(key: MLDSAPublicKey): SigningPublicKey;
    /**
     * Creates a new signing public key from an SSHPublicKey.
     *
     *
     * @param key - An SSHPublicKey
     * @returns A new signing public key wrapping the SSH public key
     */
    static fromSsh(key: SSHPublicKey): SigningPublicKey;
    /**
     * Returns the signature scheme of this key.
     */
    get scheme(): SignatureScheme;
    /**
     * Returns a human-readable string identifying the key type.
     * @returns A string like "Ed25519", "Schnorr", "ECDSA", "Sr25519", "MLDSA-44", etc.
     */
    get keyType(): string;
    /**
     * Returns the underlying Schnorr public key if this is a Schnorr key.
     *
     * @returns The SchnorrPublicKey if this is a Schnorr key, undefined otherwise
     */
    asSchnorr(): SchnorrPublicKey | undefined;
    /**
     * Returns the underlying ECDSA public key if this is an ECDSA key.
     *
     * @returns The ECPublicKey if this is an ECDSA key, undefined otherwise
     */
    asEcdsa(): ECPublicKey | undefined;
    /**
     * Returns the underlying Ed25519 public key if this is an Ed25519 key.
     *
     * @returns The Ed25519 public key if this is an Ed25519 key, undefined otherwise
     */
    asEd25519(): Ed25519PublicKey | undefined;
    /**
     * Returns the underlying Sr25519 public key if this is an Sr25519 key.
     *
     * @returns The Sr25519 public key if this is an Sr25519 key, undefined otherwise
     */
    asSr25519(): Sr25519PublicKey | undefined;
    /**
     * Checks if this is a Schnorr signing key.
     */
    isSchnorr(): boolean;
    /**
     * Checks if this is an ECDSA signing key.
     */
    isEcdsa(): boolean;
    /**
     * Checks if this is an Ed25519 signing key.
     */
    isEd25519(): boolean;
    /**
     * Checks if this is an Sr25519 signing key.
     */
    isSr25519(): boolean;
    /**
     * Returns the underlying MLDSA public key if this is an MLDSA key.
     *
     * @returns The MLDSAPublicKey if this is an MLDSA key, undefined otherwise
     */
    asMldsa(): MLDSAPublicKey | undefined;
    /**
     * Checks if this is an MLDSA signing key.
     */
    isMldsa(): boolean;
    /**
     * Returns the underlying SSH public key if this is an SSH key.
     *
     *
     * @returns The SSHPublicKey if this is an SSH key, undefined otherwise
     */
    asSsh(): SSHPublicKey | undefined;
    /**
     * Checks if this is an SSH signing key.
     */
    isSsh(): boolean;
    /**
     * Returns a copy of this SSH public key with its comment replaced.
     * Throws if this is not an SSH key — mirrors the reference implementation's `set_comment`
     * which is only callable on `SigningPublicKey::SSH` variants.
     */
    withSshComment(comment: string): SigningPublicKey;
    /**
     * Compare with another SigningPublicKey.
     */
    equals(other: SigningPublicKey): boolean;
    /**
     * Get string representation.
     *
     *   `SigningPublicKey(<ref_hex_short>, <inner_key_display>)`
     * The reference is computed from the tagged-CBOR form.
     */
    toString(): string;
    /**
     * Returns a unique reference to this SigningPublicKey instance.
     *
     * The reference is derived from the SHA-256 hash of the tagged CBOR
     * representation, providing a unique, content-addressable identifier.
     */
    reference(): Reference;
    /**
     * Verifies a signature against a message.
     *
     * @param signature - The signature to verify
     * @param message - The message that was allegedly signed
     * @returns `true` if the signature is valid, `false` otherwise
     */
    verify(signature: Signature, message: Uint8Array): boolean;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<SigningPublicKey>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     *
     * Format:
     * - Schnorr: h'<32-byte-x-only-public-key>' (bare byte string)
     * - ECDSA:   [1, h'<33-byte-compressed-public-key>']
     * - Ed25519: [2, h'<32-byte-public-key>']
     * - Sr25519: [3, h'<32-byte-public-key>']
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): SigningPublicKey;
    /**
     * Returns the OpenSSH single-line public-key text for an SSH public key.
     *
     * Only valid when this `SigningPublicKey` wraps an `SSHPublicKey`
     * (i.e. one of the four `SignatureScheme.SshXxx` variants). Mirrors
     * the reference implementation's `SigningPublicKey::SSH(key) => key.to_openssh()` usage at
     * `signing_public_key.rs:442`.
     */
    toSshOpenssh(): string;
}

/** Default signing context (Substrate/Polkadot compatible) */
export declare const SR25519_DEFAULT_CONTEXT: Uint8Array;

/** Size of SR25519 private key (seed) in bytes */
export declare const SR25519_PRIVATE_KEY_SIZE = 32;

/** Size of SR25519 public key in bytes */
export declare const SR25519_PUBLIC_KEY_SIZE = 32;

/** Size of SR25519 signature in bytes */
export declare const SR25519_SIGNATURE_SIZE = 64;

/**
 * Sr25519PrivateKey - Private key for Schnorr signatures over Ristretto25519.
 *
 * This is the signature scheme used by Polkadot/Substrate.
 */
export declare class Sr25519PrivateKey {
    private readonly _seed;
    private _cachedPublicKey?;
    private constructor();
    /** A fresh random value; pass `rng` to make it deterministic. */
    static random({ rng }?: {
        rng?: RandomNumberGenerator;
    }): Sr25519PrivateKey;
    /**
     * Create an Sr25519 private key from a 32-byte seed.
     */
    static from(seed: Uint8Array): Sr25519PrivateKey;
    /**
     * Create an Sr25519 private key from a hex string.
     */
    static fromHex(hex: string): Sr25519PrivateKey;
    /**
     * Derive an Sr25519 private key from arbitrary key material using BLAKE2b.
     *
     * @param keyMaterial - Arbitrary bytes to derive the key from
     * @returns A new Sr25519 private key
     */
    static deriveFromKeyMaterial(keyMaterial: Uint8Array): Sr25519PrivateKey;
    /** A fresh private key and its public key. */
    static keypair({ rng }?: {
        rng?: RandomNumberGenerator;
    }): [Sr25519PrivateKey, Sr25519PublicKey];
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Returns the hex representation of the seed.
     */
    toHex(): string;
    /**
     * Derives the corresponding public key.
     */
    publicKey(): Sr25519PublicKey;
    /**
     * Sign a message using the default "substrate" context.
     *
     * @param message - The message to sign
     * @returns 64-byte signature
     */
    sign(message: Uint8Array): Uint8Array;
    /**
     * Sign a message using a custom context.
     *
     * The underlying `@scure/sr25519` library hard-codes the `"substrate"`
     * signing context. Calling with any other context byte-slice would
     * silently produce a non-cross-platform signature, so we fail loudly
     * instead — callers must use the substrate default until a
     * context-aware library is wired in.
     *
     * @param message - The message to sign
     * @param context - The signing context (must equal `SR25519_DEFAULT_CONTEXT`)
     * @returns 64-byte signature
     * @throws ComponentsError if `context` is not the substrate default
     */
    signWithContext(message: Uint8Array, context: Uint8Array): Uint8Array;
    /**
     * Compare with another Sr25519PrivateKey.
     */
    equals(other: Sr25519PrivateKey): boolean;
    /**
     * Get string representation (truncated for security).
     */
    toString(): string;
}

/**
 * Sr25519PublicKey - Public key for Schnorr signatures over Ristretto25519.
 *
 * This is the signature scheme used by Polkadot/Substrate.
 */
export declare class Sr25519PublicKey {
    private readonly _data;
    private constructor();
    /**
     * Create an Sr25519 public key from raw bytes.
     */
    static from(data: Uint8Array): Sr25519PublicKey;
    /**
     * Create an Sr25519 public key from a hex string.
     */
    static fromHex(hex: string): Sr25519PublicKey;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Returns the hex representation of the key.
     */
    toHex(): string;
    /**
     * Verify a signature using the default "substrate" context.
     *
     * @param signature - The 64-byte signature
     * @param message - The message that was signed
     * @returns true if the signature is valid
     */
    verify(signature: Uint8Array, message: Uint8Array): boolean;
    /**
     * Verify a signature using a custom context.
     *
     * The underlying `@scure/sr25519` library hard-codes the `"substrate"`
     * signing context. To avoid silently accepting/rejecting cross-platform
     * signatures, this method throws when called with any other context —
     * matching the symmetric guard in `Sr25519PrivateKey.signWithContext`.
     *
     * @param signature - The 64-byte signature
     * @param message - The message that was signed
     * @param context - The signing context (must equal `SR25519_DEFAULT_CONTEXT`)
     * @returns true if the signature is valid
     * @throws ComponentsError if `context` is not the substrate default
     */
    verifyWithContext(signature: Uint8Array, message: Uint8Array, context: Uint8Array): boolean;
    /**
     * Compare with another Sr25519PublicKey.
     */
    equals(other: Sr25519PublicKey): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
}

/**
 * Copyright © 2025-2026 Parity Technologies
 *
 * SSH key algorithm identifiers.
 *
 * `ssh-key` v0.6.7). v1.1 supports the four algorithms the reference implementation
 * actually wires through `SignatureScheme`:
 *
 *   - Ed25519 (`ssh-ed25519`)
 *   - DSA (`ssh-dss`) — 1024-bit p, 160-bit q, SHA-1
 *   - ECDSA P-256 (`ecdsa-sha2-nistp256`) — SHA-256
 *   - ECDSA P-384 (`ecdsa-sha2-nistp384`) — SHA-384
 *
 * Deferred (rust upstream blockers): RSA (commented out in
 * `signature_scheme.rs:80-81`), P-521 (`ssh-key` upstream bug
 * https://github.com/RustCrypto/SSH/issues/232), encrypted private
 * keys, `cert-v01@openssh.com`. See `SSH_PLAN.md` V2.A-V2.D.
 */
export declare type SshAlgorithm = {
    kind: "ed25519";
} | {
    kind: "dsa";
} | {
    kind: "ecdsa";
    curve: SshEcdsaCurve;
};

export declare type SshEcdsaCurve = "nistp256" | "nistp384";

export declare type SshHashAlgorithm = "sha256" | "sha512";

declare class SSHPrivateKey {
    readonly data: SshPrivateKeyData;
    readonly comment: string;
    /**
     * 32-bit checkint preserved on round-trip — `ssh-key` retains the parsed
     * value, so to round-trip byte-identically we do too.
     */
    readonly checkint: number;
    private constructor();
    /**
     * Construct an `SSHPrivateKey` from already-decoded parts. Used by
     * `PrivateKeyBase.sshSigningPrivateKey` after generating key material
     * from an HKDF-seeded RNG. The `checkint` should be derived
     * deterministically from the private bytes (as the reference implementation does's
     * `ssh-key` 0.6.7 `KeypairData::checkint`).
     */
    static fromParts(data: SshPrivateKeyData, comment: string, checkint: number): SSHPrivateKey;
    /** Algorithm tag for this key. */
    get algorithm(): SshAlgorithm;
    get publicBytes(): Uint8Array;
    get privateBytes(): Uint8Array;
    static fromOpenssh(text: string): SSHPrivateKey;
    static fromBlob(blob: Uint8Array): SSHPrivateKey;
    /**
     * Re-serialize to the canonical OpenSSH armored format.
     *
     */
    toOpenssh(): string;
    toBlob(): Uint8Array;
    publicKey(): SSHPublicKey;
    private publicBlob;
    private encryptedSection;
    digest(): Uint8Array;
    refHexShort(): string;
    toString(): string;
    sign(namespace: string, hashAlgorithm: SshHashAlgorithm, message: Uint8Array): SSHSignature;
}

/**
 * Algorithm-specific private-key data.
 *
 *   - ed25519: 32-byte seed.
 *   - ecdsa:   curve + canonical scalar (32 / 48 bytes, no sign byte).
 *   - dsa:     canonical positive p, q, g, y (re-stated from the public
 *              key blob), plus the secret exponent x.
 */
declare type SshPrivateKeyData = {
    kind: "ed25519";
    seed: Uint8Array;
    pubBytes: Uint8Array;
} | {
    kind: "ecdsa";
    curve: SshEcdsaCurve;
    scalar: Uint8Array;
    point: Uint8Array;
} | {
    kind: "dsa";
    p: Uint8Array;
    q: Uint8Array;
    g: Uint8Array;
    y: Uint8Array;
    x: Uint8Array;
};

declare class SSHPublicKey {
    readonly data: SshPublicKeyData;
    readonly comment: string;
    private constructor();
    /** Algorithm tag for this key. */
    get algorithm(): SshAlgorithm;
    static ed25519(keyBytes: Uint8Array, comment?: string): SSHPublicKey;
    static ecdsaP256(uncompressedPoint: Uint8Array, comment?: string): SSHPublicKey;
    static ecdsaP384(uncompressedPoint: Uint8Array, comment?: string): SSHPublicKey;
    static ecdsa(curve: SshEcdsaCurve, uncompressedPoint: Uint8Array, comment?: string): SSHPublicKey;
    /** DSA public key. p/q/g/y must already be canonical positive bytes (no sign byte). */
    static dsa(p: Uint8Array, q: Uint8Array, g: Uint8Array, y: Uint8Array, comment?: string): SSHPublicKey;
    /**
     * Returns a copy of this SSH public key with the comment replaced.
     *
     * return a new instance to keep the type immutable).
     */
    withComment(comment: string): SSHPublicKey;
    static fromOpenssh(text: string): SSHPublicKey;
    toOpenssh(): string;
    static fromBlob(blob: Uint8Array, comment?: string): SSHPublicKey;
    toBlob(): Uint8Array;
    digest(): Uint8Array;
    refHexShort(): string;
    toString(): string;
    equals(other: SSHPublicKey): boolean;
    /**
     * Comment-insensitive equality: matches when algorithm and key data
     * agree, ignoring the comment. Used by verify paths since SSH
     * wire-format pubkey blobs carry the key but not the comment.
     */
    keyEquals(other: SSHPublicKey): boolean;
    /**
     * Algorithm-specific raw payload bytes. Throws for DSA — DSA needs structured
     * access via `data.p/q/g/y`.
     */
    get keyBytes(): Uint8Array;
    verifySshSignature(namespace: string, message: Uint8Array, signature: {
        publicKey: SSHPublicKey;
        namespace: string;
        hashAlgorithm: "sha256" | "sha512";
        signatureBytes: Uint8Array;
    }): boolean;
}

/**
 * Internal discriminated union for the algorithm-specific public-key data.
 *
 *   - ed25519: the 32-byte raw public key.
 *   - ecdsa:   curve + 65/97-byte SEC1 uncompressed point.
 *   - dsa:     four canonical-positive mpint bytes (p, q, g, y) — sign
 *              byte already stripped on parse, re-added by the writer.
 */
declare type SshPublicKeyData = {
    kind: "ed25519";
    pubBytes: Uint8Array;
} | {
    kind: "ecdsa";
    curve: SshEcdsaCurve;
    point: Uint8Array;
} | {
    kind: "dsa";
    p: Uint8Array;
    q: Uint8Array;
    g: Uint8Array;
    y: Uint8Array;
};

declare class SSHSignature {
    readonly publicKey: SSHPublicKey;
    readonly namespace: string;
    readonly reserved: Uint8Array;
    readonly hashAlgorithm: SshHashAlgorithm;
    /**
     * Raw signature bytes specific to the algorithm:
     *   ed25519 → 64-byte concatenation `r || s`
     *   ecdsa-p256 → 64-byte concatenation `r || s` (we strip the SSH
     *     mpint sign bytes on parse and re-add them on serialize, so this
     *     stays a fixed 64-byte canonical form internally)
     */
    readonly signatureBytes: Uint8Array;
    private constructor();
    static fromPem(text: string): SSHSignature;
    static fromBlob(blob: Uint8Array): SSHSignature;
    toPem(): string;
    toBlob(): Uint8Array;
    /**
     * Build the message that gets signed/verified: the **signed-data** blob
     * defined by `PROTOCOL.sshsig` §3.1.
     *
     *     "SSHSIG" magic
     *     string  namespace
     *     string  reserved
     *     string  hash_algorithm
     *     string  H(message)        ← *digest*, not the raw message
     */
    static signedDataBlob(namespace: string, hashAlgorithm: SshHashAlgorithm, messageDigest: Uint8Array): Uint8Array;
    /** Construct from already-decoded parts (used by Phase 7 sign path). */
    static fromParts(publicKey: SSHPublicKey, namespace: string, hashAlgorithm: SshHashAlgorithm, signatureBytes: Uint8Array): SSHSignature;
    /** Fixed-string mirror of Rust summarizer for `TAG_SSH_TEXT_SIGNATURE`. */
    toString(): string;
    /** SHA-256 digest of canonical PEM bytes — kept for parity with key types. */
    digest(): Uint8Array;
}

export declare class SymmetricKey implements ToCbor {
    static readonly SYMMETRIC_KEY_SIZE: number;
    private readonly _data;
    private constructor();
    /** A fresh random value; pass `rng` to make it deterministic. */
    static random({ rng }?: {
        rng?: RandomNumberGenerator;
    }): SymmetricKey;
    /**
     * Create a new symmetric key from data.
     */
    static from(data: Uint8Array): SymmetricKey;
    /**
     * Create a SymmetricKey from hex string.
     */
    static fromHex(hex: string): SymmetricKey;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Get hex string representation.
     */
    toHex(): string;
    /**
     * Get base64 representation.
     */
    toBase64(): string;
    /**
     * Compare with another SymmetricKey.
     */
    equals(other: SymmetricKey): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /**
     * Encrypt the given plaintext with this key, and the given additional
     * authenticated data and nonce.
     */
    encrypt(plaintext: Uint8Array, aad?: Uint8Array, nonce?: Nonce): EncryptedMessage;
    /**
     * Decrypt the given encrypted message with this key.
     */
    decrypt(message: EncryptedMessage): Uint8Array;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<SymmetricKey>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as a byte string).
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cbor: Cbor): SymmetricKey;
}

/**
 * Convert a Uint8Array to a base64-encoded string.
 *
 * This function works in both browser and Node.js environments.
 * Uses btoa which is available in browsers and Node.js 16+.
 *
 * @param data - The byte array to encode
 * @returns A base64-encoded string
 *
 * @example
 * ```typescript
 * const bytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
 * toBase64(bytes); // "SGVsbG8="
 * ```
 */
export declare function toBase64(data: Uint8Array): string;

export declare class URI implements ToCbor, ToUR {
    private readonly _uri;
    private constructor();
    /**
     * Creates a new `URI` from a string with validation.
     */
    static from(uri: string): URI;
    /**
     * Get the URI as a string reference.
     */
    asRef(): string;
    /**
     * Get the URI string.
     */
    toString(): string;
    /**
     * Get the URI string (alias).
     */
    toURI(): string;
    /**
     * Get the raw URI string.
     */
    get raw(): string;
    /**
     * Get scheme (e.g., "http", "https", "urn").
     */
    get scheme(): string | null;
    /**
     * Get path component.
     */
    path(): string;
    /**
     * Check if URI is absolute (has a scheme).
     */
    isAbsolute(): boolean;
    /**
     * Check if URI is relative.
     */
    isRelative(): boolean;
    /**
     * Compare with another URI.
     */
    equals(other: URI): boolean;
    /**
     * Check if URI starts with given prefix.
     */
    startsWith(prefix: string): boolean;
    /**
     * Get base64 representation of the URI string.
     */
    toBase64(): string;
    /**
     * Get the length of the URI string.
     */
    get length(): number;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<URI>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as a text string).
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): URI;
}

export declare class UUID implements ToCbor, ToUR {
    static readonly UUID_SIZE: number;
    private readonly _data;
    private constructor();
    /**
     * Create a UUID from raw bytes.
     */
    static from(data: Uint8Array): UUID;
    /**
     * Create a UUID from hex string (32 hex chars)
     */
    static fromHex(hex: string): UUID;
    /**
     * Create a UUID from string representation (standard UUID format)
     * Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
     */
    static fromString(uuidString: string): UUID;
    /**
     * Generate a random UUID (v4)
     */
    static random({ rng }?: {
        rng?: RandomNumberGenerator;
    }): UUID;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Get hex string representation (lowercase, as the reference implementation does implementation).
     */
    toHex(): string;
    /**
     * Get standard UUID string representation.
     * Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
     */
    toString(): string;
    /**
     * Get base64 representation.
     */
    toBase64(): string;
    /**
     * Compare with another UUID.
     */
    equals(other: UUID): boolean;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<UUID>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as a byte string).
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cbor: Cbor): UUID;
}

/**
 * A trait for types capable of verifying digital signatures.
 *
 * The `Verifier` interface provides a method to verify that a signature was
 * created by a corresponding signer for a specific message.
 */
export declare interface Verifier {
    /**
     * Verifies a signature against a message.
     *
     * @param signature - The signature to verify
     * @param message - The message that was allegedly signed
     * @returns `true` if the signature is valid for the message, `false` otherwise
     */
    verify(signature: Signature, message: Uint8Array): boolean;
}

export declare class X25519PrivateKey implements ToCbor, ToUR {
    static readonly KEY_SIZE: number;
    private readonly _data;
    private _publicKey?;
    private constructor();
    /** A fresh random value; pass `rng` to make it deterministic. */
    static random({ rng }?: {
        rng?: RandomNumberGenerator;
    }): X25519PrivateKey;
    /** A fresh private key and its public key. */
    static keypair({ rng }?: {
        rng?: RandomNumberGenerator;
    }): [X25519PrivateKey, X25519PublicKey];
    /**
     * Derive an X25519PrivateKey from the given key material.
     *
     * @param keyMaterial - The key material to derive from
     * @returns A new X25519PrivateKey derived from the key material
     */
    static deriveFromKeyMaterial(keyMaterial: Uint8Array): X25519PrivateKey;
    /**
     * Restore an X25519PrivateKey from a fixed-size array of bytes.
     */
    static from(data: Uint8Array): X25519PrivateKey;
    /**
     * Restore an X25519PrivateKey from a hex string.
     */
    static fromHex(hex: string): X25519PrivateKey;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Get hex string representation.
     */
    toHex(): string;
    /**
     * Get base64 representation.
     */
    toBase64(): string;
    /**
     * Get the X25519PublicKey corresponding to this X25519PrivateKey.
     */
    publicKey(): X25519PublicKey;
    /**
     * Derive a shared symmetric key from this X25519PrivateKey and the given
     * X25519PublicKey.
     *
     * @param publicKey - The other party's public key
     * @returns A SymmetricKey derived from the shared secret
     */
    sharedKeyWith(publicKey: X25519PublicKey): SymmetricKey;
    /**
     * Perform ECDH key agreement with a public key (legacy method).
     *
     * @deprecated Use sharedKeyWith() instead which returns a SymmetricKey
     */
    sharedSecret(publicKey: X25519PublicKey): Uint8Array;
    /**
     * Compare with another X25519PrivateKey.
     */
    equals(other: X25519PrivateKey): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<X25519PrivateKey>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as a byte string).
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cbor: Cbor): X25519PrivateKey;
}

export declare class X25519PublicKey implements ToCbor, ToUR {
    static readonly KEY_SIZE: number;
    private readonly _data;
    private constructor();
    /**
     * Restore an X25519PublicKey from a fixed-size array of bytes.
     */
    static from(data: Uint8Array): X25519PublicKey;
    /**
     * Restore an X25519PublicKey from a hex string.
     */
    static fromHex(hex: string): X25519PublicKey;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Get hex string representation.
     */
    toHex(): string;
    /**
     * Get base64 representation.
     */
    toBase64(): string;
    /**
     * Compare with another X25519PublicKey.
     */
    equals(other: X25519PublicKey): boolean;
    /**
     * Get string representation.
     *
     *   `X25519PublicKey(<ref_hex_short>)` where the reference is
     *   computed from the **tagged-CBOR** form of the key.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<X25519PublicKey>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as a byte string).
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cbor: Cbor): X25519PublicKey;
}

export declare class XID implements ToCbor, ToUR, XIDProvider, ReferenceProvider {
    static readonly XID_SIZE: number;
    private readonly _data;
    private constructor();
    /**
     * Create a new XID from data.
     */
    static from(data: Uint8Array): XID;
    /**
     * Create an XID from hex string (64 hex characters).
     */
    static fromHex(hex: string): XID;
    /**
     * Generate a random XID (for testing purposes).
     *
     * Note: In practice, XIDs should be created from the SHA-256 hash of a
     * public signing key's CBOR encoding.
     */
    static random({ rng }?: {
        rng?: RandomNumberGenerator;
    }): XID;
    /**
     * Derived from the SHA-256 digest of the key's tagged CBOR.
     */
    static fromSigningPublicKey(signingPublicKey: SigningPublicKey): XID;
    /**
     * The XID is derived from the bundle's signing public key.
     */
    static fromPublicKeys(publicKeys: PublicKeys): XID;
    /**
     * The XID is derived from the schnorr signing public key.
     */
    static fromPrivateKeyBase(base: PrivateKeyBase): XID;
    /**
     * The XID is derived from the corresponding public key.
     */
    static tryFromSigningPrivateKey(signingPrivateKey: SigningPrivateKey): XID;
    /**
     * Validate the XID against the given public key.
     *
     * Returns true if the SHA-256 hash of the key's CBOR encoding matches
     * the XID data. This matches the reference implementation's `XID::validate(&self, key: &SigningPublicKey)`.
     */
    validate(signingPublicKey: SigningPublicKey): boolean;
    /** The bytes (a view; do not mutate). */
    get bytes(): Uint8Array;
    /**
     * Get hex string representation (lowercase, as the reference implementation does implementation).
     */
    toHex(): string;
    /**
     * Get base64 representation.
     */
    toBase64(): string;
    /**
     * Get short description (first 4 bytes) as hex.
     */
    shortDescription(): string;
    /**
     * Get short reference (first 4 bytes) as hex (alias for shortDescription).
     */
    shortReference(): string;
    /**
     * Get the first four bytes of the XID as upper-case ByteWords.
     *
     * @param prefix - If true, prepends the XID prefix "🅧 "
     * @returns Space-separated uppercase bytewords, e.g., "🅧 URGE DICE GURU IRIS"
     */
    bytewordsIdentifier(prefix?: boolean): string;
    /**
     * Get the first four bytes of the XID as Bytemoji.
     *
     * @param prefix - If true, prepends the XID prefix "🅧 "
     * @returns Space-separated emojis, e.g., "🅧 🐻 😻 🍞 💐"
     */
    bytemojisIdentifier(prefix?: boolean): string;
    /**
     * XIDProvider impl — returns this XID.
     *
     */
    xid(): XID;
    /**
     * ReferenceProvider impl — produces a Reference whose 32 bytes are the
     * raw XID data.
     *
     * Reference { Reference::from_data(*self.bytes) } }` — note this is a
     * direct wrap, not a SHA-256 hash of the XID.
     */
    reference(): Reference;
    /**
     * Compare with another XID.
     */
    equals(other: XID): boolean;
    /**
     * Get string representation (short format, as the reference implementation does Display).
     * Uses first 4 bytes of the XID as hex, e.g., "XID(71274df1)".
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<XID>;
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as a byte string).
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cbor: Cbor): XID;
}

/**
 * XID prefix glyph for the upper-case bytewords/bytemoji identifier.
 *
 * Exported as the single source of truth so dependent packages (`@blockchaincommons/xid`,
 * `@blockchaincommons/envelope`, etc.) don't redefine the literal `"🅧"`.
 */
export declare const XID_PREFIX = "🅧";

/**
 * Trait-style interface for objects that can produce a XID.
 *
 * other type that maps cleanly to a single XID (e.g. `SigningPublicKey`,
 * `PublicKeys`) may also implement it.
 */
export declare interface XIDProvider {
    /** Returns the XID for this object. */
    xid(): XID;
}

export { }
