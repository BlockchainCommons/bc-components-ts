import { Cbor } from '@blockchaincommons/dcbor';
import { CborTagged } from '@blockchaincommons/dcbor';
import { RandomNumberGenerator } from '@blockchaincommons/rand';
import { Tag } from '@blockchaincommons/dcbor';
import { UR } from '@blockchaincommons/uniform-resources';

/**
 * Argon2id parameters for password-based key derivation.
 *
 * This is the recommended method for password-based key derivation as it
 * provides the best protection against both GPU cracking and side-channel
 * attacks.
 */
export declare class Argon2idParams implements KeyDerivation {
    static readonly INDEX: KeyDerivationMethod;
    private readonly _salt;
    private constructor();
    /**
     * Create new Argon2id parameters with default settings.
     * Uses a random 16-byte salt.
     */
    static new(): Argon2idParams;
    /**
     * Create Argon2id parameters with a custom salt.
     */
    static newOpt(salt: Salt): Argon2idParams;
    /** Returns the salt. */
    salt(): Salt;
    /** Returns the method index for CBOR encoding. */
    index(): number;
    /**
     * Derive a key from the secret and encrypt the content key.
     */
    lock(contentKey: SymmetricKey, secret: Uint8Array): EncryptedMessage;
    /**
     * Derive a key from the secret and decrypt the content key.
     */
    unlock(encryptedMessage: EncryptedMessage, secret: Uint8Array): SymmetricKey;
    private _deriveKey;
    /**
     * Get string representation.
     */
    toString(): string;
    /**
     * Check equality with another Argon2idParams.
     */
    equals(other: Argon2idParams): boolean;
    /**
     * Convert to CBOR.
     * Format: [3, Salt]   (Salt is encoded as a tagged value — `#6.40018(bytes)`)
     */
    toCbor(): Cbor;
    /**
     * Convert to CBOR binary data.
     */
    toCborData(): Uint8Array;
    /**
     * Parse from CBOR.
     */
    static fromCbor(cborValue: Cbor): Argon2idParams;
}

/**
 * Create Argon2id derivation parameters.
 */
export declare function argon2idParams(params?: Argon2idParams): KeyDerivationParams;

declare class AuthenticationTag {
    static readonly AUTHENTICATION_TAG_SIZE: number;
    private readonly _data;
    private constructor();
    /**
     * Restore an AuthenticationTag from a fixed-size array of bytes.
     */
    static fromData(data: Uint8Array): AuthenticationTag;
    /**
     * Restore an AuthenticationTag from a reference to an array of bytes.
     */
    static fromDataRef(data: Uint8Array): AuthenticationTag;
    /**
     * Create an AuthenticationTag from raw bytes (legacy alias).
     */
    static from(data: Uint8Array): AuthenticationTag;
    /**
     * Create an AuthenticationTag from hex string.
     */
    static fromHex(hex: string): AuthenticationTag;
    /**
     * Get a reference to the fixed-size array of bytes.
     */
    data(): Uint8Array;
    /**
     * Get the reference as a byte slice.
     */
    asBytes(): Uint8Array;
    /**
     * Get the raw tag bytes as a copy.
     */
    toData(): Uint8Array;
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

/** Default number of iterations for PBKDF2 */
export declare const DEFAULT_PBKDF2_ITERATIONS = 1e5;

/** Default log_n parameter (2^15 = 32768 iterations) */
export declare const DEFAULT_SCRYPT_LOG_N = 15;

/** Default p parameter (parallelism) */
export declare const DEFAULT_SCRYPT_P = 1;

/** Default r parameter (block size) */
export declare const DEFAULT_SCRYPT_R = 8;

/**
 * Returns the default key derivation method (Argon2id).
 */
export declare function defaultKeyDerivationMethod(): KeyDerivationMethod;

/**
 * Create default key derivation parameters (Argon2id).
 */
export declare function defaultKeyDerivationParams(): KeyDerivationParams;

declare class Digest implements DigestProvider, CborTaggedEncodable, CborTaggedDecodable<Digest>, UREncodable {
    static readonly DIGEST_SIZE: number;
    private readonly _data;
    private constructor();
    /**
     * Get the digest data.
     */
    data(): Uint8Array;
    /**
     * Create a Digest from a 32-byte array.
     */
    static fromData(data: Uint8Array): Digest;
    /**
     * Create a Digest from data, validating the length.
     * Alias for fromData for compatibility with Rust API.
     */
    static fromDataRef(data: Uint8Array): Digest;
    /**
     * Create a Digest from hex string.
     *
     * @throws Error if the hex string is not exactly 64 characters.
     */
    static fromHex(hex: string): Digest;
    /**
     * Compute SHA-256 digest of data (called "image" in Rust).
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
     * Get the raw digest bytes as a copy.
     */
    toData(): Uint8Array;
    /**
     * Get a reference to the raw digest bytes.
     */
    asBytes(): Uint8Array;
    /**
     * Get hex string representation.
     */
    hex(): string;
    /**
     * Get hex string representation (alias for hex()).
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
    /**
     * Returns the CBOR tags associated with Digest.
     */
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as a byte string).
     */
    untaggedCbor(): Cbor;
    /**
     * Returns the tagged CBOR encoding.
     */
    taggedCbor(): Cbor;
    /**
     * Returns the tagged value in CBOR binary representation.
     */
    taggedCborData(): Uint8Array;
    /**
     * Creates a Digest by decoding it from untagged CBOR.
     */
    fromUntaggedCbor(cbor: Cbor): Digest;
    /**
     * Creates a Digest by decoding it from tagged CBOR.
     */
    fromTaggedCbor(cbor: Cbor): Digest;
    /**
     * Static method to decode from tagged CBOR.
     */
    static fromTaggedCbor(cbor: Cbor): Digest;
    /**
     * Static method to decode from tagged CBOR binary data.
     */
    static fromTaggedCborData(data: Uint8Array): Digest;
    /**
     * Static method to decode from untagged CBOR binary data.
     */
    static fromUntaggedCborData(data: Uint8Array): Digest;
    /**
     * Returns the UR representation of the Digest.
     * Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
     */
    ur(): UR;
    /**
     * Returns the UR string representation.
     */
    urString(): string;
    /**
     * Creates a Digest from a UR.
     */
    static fromUR(ur: UR): Digest;
    /**
     * Creates a Digest from a UR string.
     */
    static fromURString(urString: string): Digest;
    /**
     * Validate the given data against the digest, if any.
     *
     * Returns `true` if the digest is `undefined` or if the digest matches the
     * image's digest. Returns `false` if the digest does not match.
     */
    static validateOpt(image: Uint8Array, digest: Digest | undefined): boolean;
}

/**
 * A type that can provide a single unique digest that characterizes its contents.
 *
 * Use Cases:
 * - Data integrity verification
 * - Unique identifier for an object based on its content
 * - Content-addressable storage implementation
 * - Comparing objects by their content rather than identity
 */
declare interface DigestProvider {
    /**
     * Returns a digest that uniquely characterizes the content of the
     * implementing type.
     */
    digest(): Digest;
}

/**
 * Encrypted key providing secure storage of symmetric keys.
 *
 * Use `lock()` to encrypt a content key with a password or secret,
 * and `unlock()` to decrypt it.
 */
export declare class EncryptedKey implements CborTaggedEncodable, CborTaggedDecodable<EncryptedKey>, UREncodable {
    private readonly _params;
    private readonly _encryptedMessage;
    private constructor();
    /**
     * Lock (encrypt) a content key using custom derivation parameters.
     *
     * @param params - The key derivation parameters to use
     * @param secret - The secret (password or key material) to derive from
     * @param contentKey - The symmetric key to encrypt
     * @returns The encrypted key
     */
    static lockOpt(params: KeyDerivationParams, secret: Uint8Array, contentKey: SymmetricKey): EncryptedKey;
    /**
     * Lock (encrypt) a content key using a specific derivation method with defaults.
     *
     * @param method - The key derivation method to use
     * @param secret - The secret (password or key material) to derive from
     * @param contentKey - The symmetric key to encrypt
     * @returns The encrypted key
     */
    static lock(method: KeyDerivationMethod, secret: Uint8Array, contentKey: SymmetricKey): EncryptedKey;
    /**
     * Returns the encrypted message.
     */
    encryptedMessage(): EncryptedMessage;
    /**
     * Returns the key derivation parameters.
     */
    params(): KeyDerivationParams;
    /**
     * Returns the key derivation method.
     */
    method(): KeyDerivationMethod;
    /**
     * Check if this uses a password-based key derivation method.
     */
    isPasswordBased(): boolean;
    /**
     * Check if this uses SSH Agent for key derivation.
     *
     * Note: SSH Agent key derivation is not yet functional in TypeScript.
     * This method is useful for detecting envelopes locked by other
     * implementations (e.g., Rust).
     */
    isSshAgent(): boolean;
    /**
     * Unlock (decrypt) the content key.
     *
     * @param secret - The secret (password or key material) used to lock
     * @returns The decrypted symmetric key
     * @throws CryptoError if decryption fails (wrong password, tampered data, etc.)
     */
    unlock(secret: Uint8Array): SymmetricKey;
    /**
     * Check equality with another EncryptedKey.
     */
    equals(other: EncryptedKey): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /**
     * Returns the CBOR tags associated with EncryptedKey.
     */
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     * The EncryptedMessage is encoded with its own tag (40002).
     */
    untaggedCbor(): Cbor;
    /**
     * Returns the tagged CBOR encoding.
     */
    taggedCbor(): Cbor;
    /**
     * Returns the tagged value in CBOR binary representation.
     */
    taggedCborData(): Uint8Array;
    /**
     * Creates an EncryptedKey by decoding it from untagged CBOR.
     */
    fromUntaggedCbor(cborValue: Cbor): EncryptedKey;
    /**
     * Creates an EncryptedKey by decoding it from tagged CBOR.
     */
    fromTaggedCbor(cborValue: Cbor): EncryptedKey;
    /**
     * Static method to decode from tagged CBOR.
     */
    static fromTaggedCbor(cborValue: Cbor): EncryptedKey;
    /**
     * Static method to decode from tagged CBOR binary data.
     */
    static fromTaggedCborData(data: Uint8Array): EncryptedKey;
    /**
     * Static method to decode from untagged CBOR binary data.
     */
    static fromUntaggedCborData(data: Uint8Array): EncryptedKey;
    /**
     * Returns the UR representation.
     */
    ur(): UR;
    /**
     * Returns the UR string representation.
     */
    urString(): string;
    /**
     * Creates an EncryptedKey from a UR.
     */
    static fromUR(ur: UR): EncryptedKey;
    /**
     * Creates an EncryptedKey from a UR string.
     */
    static fromURString(urString: string): EncryptedKey;
}

declare class EncryptedMessage implements CborTaggedEncodable, CborTaggedDecodable<EncryptedMessage>, UREncodable {
    private readonly _ciphertext;
    private readonly _aad;
    private readonly _nonce;
    private readonly _auth;
    private constructor();
    /**
     * Restores an EncryptedMessage from its components.
     */
    static new(ciphertext: Uint8Array, aad: Uint8Array, nonce: Nonce, auth: Uint8Array | AuthenticationTag): EncryptedMessage;
    /**
     * Create an EncryptedMessage from components (legacy alias).
     */
    static from(nonce: Nonce, ciphertext: Uint8Array, tag: AuthenticationTag, aad?: Uint8Array): EncryptedMessage;
    /**
     * Returns a reference to the ciphertext data.
     */
    ciphertext(): Uint8Array;
    /**
     * Returns a reference to the additional authenticated data (AAD).
     */
    aad(): Uint8Array;
    /**
     * Returns a reference to the nonce value used for encryption.
     */
    nonce(): Nonce;
    /**
     * Returns a reference to the authentication tag value used for encryption.
     */
    authenticationTag(): AuthenticationTag;
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
    /**
     * Returns the CBOR tags associated with EncryptedMessage.
     */
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as an array).
     * Array format: [ciphertext, nonce, auth, ?aad]
     */
    untaggedCbor(): Cbor;
    /**
     * Returns the tagged CBOR encoding.
     */
    taggedCbor(): Cbor;
    /**
     * Returns the tagged value in CBOR binary representation.
     */
    taggedCborData(): Uint8Array;
    /**
     * Creates an EncryptedMessage by decoding it from untagged CBOR.
     */
    fromUntaggedCbor(cborValue: Cbor): EncryptedMessage;
    /**
     * Creates an EncryptedMessage by decoding it from tagged CBOR.
     */
    fromTaggedCbor(cborValue: Cbor): EncryptedMessage;
    /**
     * Static method to decode from tagged CBOR.
     */
    static fromTaggedCbor(cborValue: Cbor): EncryptedMessage;
    /**
     * Static method to decode from tagged CBOR binary data.
     */
    static fromTaggedCborData(data: Uint8Array): EncryptedMessage;
    /**
     * Static method to decode from untagged CBOR binary data.
     */
    static fromUntaggedCborData(data: Uint8Array): EncryptedMessage;
    /**
     * Returns the UR representation of the EncryptedMessage.
     * Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
     */
    ur(): UR;
    /**
     * Returns the UR string representation.
     */
    urString(): string;
    /**
     * Creates an EncryptedMessage from a UR.
     */
    static fromUR(ur: UR): EncryptedMessage;
    /**
     * Creates an EncryptedMessage from a UR string.
     */
    static fromURString(urString: string): EncryptedMessage;
}

/**
 * Enum representing supported hash types for key derivation.
 */
export declare enum HashType {
    /** SHA-256 hash algorithm */
    SHA256 = 0,
    /** SHA-512 hash algorithm */
    SHA512 = 1
}

/**
 * Parse HashType from CBOR.
 */
export declare function hashTypeFromCbor(cborValue: Cbor): HashType;

/**
 * Convert HashType to CBOR.
 */
export declare function hashTypeToCbor(hashType: HashType): Cbor;

/**
 * Convert HashType to its string representation.
 */
export declare function hashTypeToString(hashType: HashType): string;

/**
 * HKDF parameters for key derivation.
 *
 * HKDF is suitable for deriving keys from high-entropy inputs (like other keys),
 * but NOT for password-based key derivation.
 */
export declare class HKDFParams implements KeyDerivation {
    static readonly INDEX: KeyDerivationMethod;
    private readonly _salt;
    private readonly _hashType;
    private constructor();
    /**
     * Create new HKDF parameters with default settings.
     * Uses a random 16-byte salt and SHA-256.
     */
    static new(): HKDFParams;
    /**
     * Create HKDF parameters with custom settings.
     */
    static newOpt(salt: Salt, hashType: HashType): HKDFParams;
    /** Returns the salt. */
    salt(): Salt;
    /** Returns the hash type. */
    hashType(): HashType;
    /** Returns the method index for CBOR encoding. */
    index(): number;
    /**
     * Derive a key from the secret and encrypt the content key.
     */
    lock(contentKey: SymmetricKey, secret: Uint8Array): EncryptedMessage;
    /**
     * Derive a key from the secret and decrypt the content key.
     */
    unlock(encryptedMessage: EncryptedMessage, secret: Uint8Array): SymmetricKey;
    private _deriveKey;
    /**
     * Get string representation.
     */
    toString(): string;
    /**
     * Check equality with another HKDFParams.
     */
    equals(other: HKDFParams): boolean;
    /**
     * Convert to CBOR.
     * Format: [0, Salt, HashType]   (Salt is encoded as a tagged value — `#6.40018(bytes)`)
     */
    toCbor(): Cbor;
    /**
     * Convert to CBOR binary data.
     */
    toCborData(): Uint8Array;
    /**
     * Parse from CBOR.
     */
    static fromCbor(cborValue: Cbor): HKDFParams;
}

/**
 * Create HKDF derivation parameters.
 */
export declare function hkdfParams(params?: HKDFParams): KeyDerivationParams;

/**
 * A deterministic random number generator based on HKDF-HMAC-SHA256.
 *
 * Implements the RandomNumberGenerator interface from @blockchaincommons/rand.
 */
export declare class HKDFRng implements RandomNumberGenerator {
    /** Internal buffer of generated bytes */
    private _buffer;
    /** Current position in the buffer */
    private _position;
    /** Source key material (seed) */
    private readonly _keyMaterial;
    /** Salt value to combine with the key material */
    private readonly _salt;
    /** Length of each "page" of generated data */
    private readonly _pageLength;
    /** Current page index */
    private _pageIndex;
    private constructor();
    /**
     * Creates a new `HKDFRng` with a custom page length.
     *
     * @param keyMaterial - The seed material to derive random numbers from
     * @param salt - A salt value to mix with the key material
     * @param pageLength - The number of bytes to generate in each HKDF call
     * @returns A new `HKDFRng` instance configured with the specified parameters
     */
    static newWithPageLength(keyMaterial: Uint8Array, salt: string, pageLength: number): HKDFRng;
    /**
     * Creates a new `HKDFRng` with the default page length of 32 bytes.
     *
     * @param keyMaterial - The seed material to derive random numbers from
     * @param salt - A salt value to mix with the key material
     * @returns A new `HKDFRng` instance configured with the specified key material and salt
     */
    static new(keyMaterial: Uint8Array, salt: string): HKDFRng;
    /**
     * Refills the internal buffer with new deterministic random bytes.
     *
     * This method is called automatically when the internal buffer is exhausted.
     * It uses HKDF-HMAC-SHA256 to generate a new page of random bytes using the
     * key material, salt, and current page index.
     */
    private fillBuffer;
    /**
     * Generates the specified number of deterministic random bytes.
     *
     * @param length - The number of bytes to generate
     * @returns A Uint8Array containing the requested number of deterministic random bytes
     */
    private nextBytes;
    /**
     * Generates deterministic random bytes.
     *
     * @param length - The number of bytes to generate
     * @returns A Uint8Array of random bytes
     */
    randomData(length: number): Uint8Array;
    /**
     * Fills the provided buffer with deterministic random bytes.
     *
     * @param dest - The buffer to fill with random bytes
     */
    fillBytes(dest: Uint8Array): void;
    /**
     * Generates a random `u32` value.
     *
     * @returns A deterministic random 32-bit unsigned integer
     */
    nextU32(): number;
    /**
     * Generates a random `u64` value.
     *
     * Note: JavaScript numbers can only safely represent integers up to 2^53 - 1,
     * so this returns a BigInt for full 64-bit precision.
     *
     * @returns A deterministic random 64-bit unsigned integer as BigInt
     */
    nextU64(): bigint;
    /**
     * Attempts to fill the provided buffer with random bytes.
     * This implementation never fails.
     *
     * @param dest - The buffer to fill with random bytes
     */
    tryFillBytes(dest: Uint8Array): void;
    /**
     * Fills the provided buffer with deterministic random bytes.
     * Alias for fillBytes for interface compatibility.
     *
     * @param data - The buffer to fill with random bytes
     */
    fillRandomData(data: Uint8Array): void;
    /**
     * Returns the key material (for testing purposes).
     */
    getKeyMaterial(): Uint8Array;
    /**
     * Returns the salt (for testing purposes).
     */
    getSalt(): string;
    /**
     * Returns the page length (for testing purposes).
     */
    getPageLength(): number;
    /**
     * Returns the current page index (for testing purposes).
     */
    getPageIndex(): number;
}

/**
 * Check if the parameters use a password-based method.
 * Password-based methods (PBKDF2, Scrypt, Argon2id) are designed for
 * low-entropy secrets like passwords.
 */
export declare function isPasswordBased(kdp: KeyDerivationParams): boolean;

/**
 * Check if the parameters use SSH Agent for key derivation.
 *
 * Note: SSH Agent key derivation is not yet functional in TypeScript.
 * This function is useful for detecting envelopes locked by other
 * implementations (e.g., Rust).
 */
export declare function isSshAgent(kdp: KeyDerivationParams): boolean;

/**
 * Interface for key derivation implementations.
 *
 * All key derivation methods must implement this interface to provide
 * lock (encrypt) and unlock (decrypt) operations.
 */
export declare interface KeyDerivation {
    /**
     * Returns the method index for CBOR encoding.
     */
    index(): number;
    /**
     * Lock (encrypt) a content key using the derived key.
     *
     * @param contentKey - The symmetric key to encrypt
     * @param secret - The secret (password or key material) to derive from
     * @returns The encrypted message containing the locked key
     */
    lock(contentKey: SymmetricKey, secret: Uint8Array): EncryptedMessage;
    /**
     * Unlock (decrypt) a content key using the derived key.
     *
     * @param encryptedMessage - The encrypted message containing the locked key
     * @param secret - The secret (password or key material) to derive from
     * @returns The decrypted symmetric key
     */
    unlock(encryptedMessage: EncryptedMessage, secret: Uint8Array): SymmetricKey;
    /**
     * Convert to CBOR representation.
     */
    toCbor(): Cbor;
    /**
     * Convert to CBOR binary data.
     */
    toCborData(): Uint8Array;
    /**
     * Get string representation.
     */
    toString(): string;
}

/**
 * Enum representing supported key derivation methods.
 */
export declare enum KeyDerivationMethod {
    /** HKDF (HMAC-based Key Derivation Function) - RFC 5869 */
    HKDF = 0,
    /** PBKDF2 (Password-Based Key Derivation Function 2) - RFC 8018 */
    PBKDF2 = 1,
    /** Scrypt - RFC 7914 */
    Scrypt = 2,
    /** Argon2id - RFC 9106 (default, most secure for passwords) */
    Argon2id = 3,
    /** SSH Agent - Uses SSH agent for key derivation */
    SSHAgent = 4
}

/**
 * Parse KeyDerivationMethod from CBOR.
 */
export declare function keyDerivationMethodFromCbor(cborValue: Cbor): KeyDerivationMethod;

/**
 * Attempts to create a KeyDerivationMethod from a zero-based index.
 */
export declare function keyDerivationMethodFromIndex(index: number): KeyDerivationMethod | undefined;

/**
 * Returns the zero-based index of the key derivation method.
 */
export declare function keyDerivationMethodIndex(method: KeyDerivationMethod): number;

/**
 * Convert KeyDerivationMethod to its string representation.
 */
export declare function keyDerivationMethodToString(method: KeyDerivationMethod): string;

/**
 * Union type representing key derivation parameters.
 *
 * Use the `method()` function to get the derivation method, and
 * `lock()`/`unlock()` for key operations.
 */
export declare type KeyDerivationParams = {
    type: "hkdf";
    params: HKDFParams;
} | {
    type: "pbkdf2";
    params: PBKDF2Params;
} | {
    type: "scrypt";
    params: ScryptParams;
} | {
    type: "argon2id";
    params: Argon2idParams;
} | {
    type: "sshagent";
    params: SSHAgentParams;
};

/**
 * Parse KeyDerivationParams from CBOR.
 */
export declare function keyDerivationParamsFromCbor(cborValue: Cbor): KeyDerivationParams;

/**
 * Get the key derivation method for the given parameters.
 */
export declare function keyDerivationParamsMethod(kdp: KeyDerivationParams): KeyDerivationMethod;

/**
 * Convert KeyDerivationParams to CBOR.
 */
export declare function keyDerivationParamsToCbor(kdp: KeyDerivationParams): Cbor;

/**
 * Convert KeyDerivationParams to CBOR binary data.
 */
export declare function keyDerivationParamsToCborData(kdp: KeyDerivationParams): Uint8Array;

/**
 * Get string representation of KeyDerivationParams.
 */
export declare function keyDerivationParamsToString(kdp: KeyDerivationParams): string;

/**
 * Lock (encrypt) a content key using the derived key.
 */
export declare function lockWithParams(kdp: KeyDerivationParams, contentKey: SymmetricKey, secret: Uint8Array): EncryptedMessage;

declare class Nonce implements CborTaggedEncodable, CborTaggedDecodable<Nonce>, UREncodable {
    static readonly NONCE_SIZE: number;
    private readonly _data;
    private constructor();
    /**
     * Create a new random nonce.
     */
    static new(): Nonce;
    /**
     * Create a new random nonce (alias for compatibility).
     */
    static random(): Nonce;
    /**
     * Restores a nonce from data.
     */
    static fromData(data: Uint8Array): Nonce;
    /**
     * Restores a nonce from data (validates length).
     */
    static fromDataRef(data: Uint8Array): Nonce;
    /**
     * Create a Nonce from raw bytes (legacy alias).
     */
    static from(data: Uint8Array): Nonce;
    /**
     * Create a new nonce from the given hexadecimal string.
     *
     * @throws Error if the string is not exactly 24 hexadecimal digits.
     */
    static fromHex(hex: string): Nonce;
    /**
     * Generate a random nonce using provided RNG.
     */
    static randomUsing(rng: RandomNumberGenerator): Nonce;
    /**
     * Get the data of the nonce.
     */
    data(): Uint8Array;
    /**
     * Get the nonce as a byte slice.
     */
    asBytes(): Uint8Array;
    /**
     * Get the raw nonce bytes as a copy.
     */
    toData(): Uint8Array;
    /**
     * The data as a hexadecimal string.
     */
    hex(): string;
    /**
     * Get hex string representation (alias for hex()).
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
    /**
     * Returns the CBOR tags associated with Nonce.
     */
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as a byte string).
     */
    untaggedCbor(): Cbor;
    /**
     * Returns the tagged CBOR encoding.
     */
    taggedCbor(): Cbor;
    /**
     * Returns the tagged value in CBOR binary representation.
     */
    taggedCborData(): Uint8Array;
    /**
     * Creates a Nonce by decoding it from untagged CBOR.
     */
    fromUntaggedCbor(cbor: Cbor): Nonce;
    /**
     * Creates a Nonce by decoding it from tagged CBOR.
     */
    fromTaggedCbor(cbor: Cbor): Nonce;
    /**
     * Static method to decode from tagged CBOR.
     */
    static fromTaggedCbor(cbor: Cbor): Nonce;
    /**
     * Static method to decode from tagged CBOR binary data.
     */
    static fromTaggedCborData(data: Uint8Array): Nonce;
    /**
     * Static method to decode from untagged CBOR binary data.
     */
    static fromUntaggedCborData(data: Uint8Array): Nonce;
    /**
     * Returns the UR representation of the Nonce.
     * Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
     */
    ur(): UR;
    /**
     * Returns the UR string representation.
     */
    urString(): string;
    /**
     * Creates a Nonce from a UR.
     */
    static fromUR(ur: UR): Nonce;
    /**
     * Creates a Nonce from a UR string.
     */
    static fromURString(urString: string): Nonce;
}

/**
 * PBKDF2 parameters for password-based key derivation.
 */
export declare class PBKDF2Params implements KeyDerivation {
    static readonly INDEX: KeyDerivationMethod;
    private readonly _salt;
    private readonly _iterations;
    private readonly _hashType;
    private constructor();
    /**
     * Create new PBKDF2 parameters with default settings.
     * Uses a random 16-byte salt, 100,000 iterations, and SHA-256.
     */
    static new(): PBKDF2Params;
    /**
     * Create PBKDF2 parameters with custom settings.
     */
    static newOpt(salt: Salt, iterations: number, hashType: HashType): PBKDF2Params;
    /** Returns the salt. */
    salt(): Salt;
    /** Returns the number of iterations. */
    iterations(): number;
    /** Returns the hash type. */
    hashType(): HashType;
    /** Returns the method index for CBOR encoding. */
    index(): number;
    /**
     * Derive a key from the secret and encrypt the content key.
     */
    lock(contentKey: SymmetricKey, secret: Uint8Array): EncryptedMessage;
    /**
     * Derive a key from the secret and decrypt the content key.
     */
    unlock(encryptedMessage: EncryptedMessage, secret: Uint8Array): SymmetricKey;
    private _deriveKey;
    /**
     * Get string representation.
     */
    toString(): string;
    /**
     * Check equality with another PBKDF2Params.
     */
    equals(other: PBKDF2Params): boolean;
    /**
     * Convert to CBOR.
     * Format: [1, Salt, iterations, HashType]   (Salt is encoded as a tagged value — `#6.40018(bytes)`)
     */
    toCbor(): Cbor;
    /**
     * Convert to CBOR binary data.
     */
    toCborData(): Uint8Array;
    /**
     * Parse from CBOR.
     */
    static fromCbor(cborValue: Cbor): PBKDF2Params;
}

/**
 * Create PBKDF2 derivation parameters.
 */
export declare function pbkdf2Params(params?: PBKDF2Params): KeyDerivationParams;

declare class Salt implements CborTaggedEncodable, CborTaggedDecodable<Salt>, UREncodable {
    private readonly _data;
    private constructor();
    /**
     * Create a new salt from data.
     * Note: Does not validate minimum size to allow for CBOR deserialization.
     */
    static fromData(data: Uint8Array): Salt;
    /**
     * Create a Salt from raw bytes (legacy alias).
     */
    static from(data: Uint8Array): Salt;
    /**
     * Create a new salt from the given hexadecimal string.
     */
    static fromHex(hex: string): Salt;
    /**
     * Create a specific number of bytes of salt.
     *
     * @throws Error if the number of bytes is less than 8.
     */
    static newWithLen(count: number): Salt;
    /**
     * Create a specific number of bytes of salt using provided RNG.
     *
     * @throws Error if the number of bytes is less than 8.
     */
    static newWithLenUsing(count: number, rng: RandomNumberGenerator): Salt;
    /**
     * Create a number of bytes of salt chosen randomly from the given range.
     *
     * @throws Error if the minimum number of bytes is less than 8.
     */
    static newInRange(minSize: number, maxSize: number): Salt;
    /**
     * Create a number of bytes of salt chosen randomly from the given range using provided RNG.
     *
     * @throws Error if the minimum number of bytes is less than 8.
     */
    static newInRangeUsing(minSize: number, maxSize: number, rng: RandomNumberGenerator): Salt;
    /**
     * Create a number of bytes of salt generally proportionate to the size of
     * the object being salted.
     */
    static newForSize(size: number): Salt;
    /**
     * Create a number of bytes of salt generally proportionate to the size of
     * the object being salted using provided RNG.
     */
    static newForSizeUsing(size: number, rng: RandomNumberGenerator): Salt;
    /**
     * Generate a random salt with specified size (legacy alias for newWithLen).
     */
    static random(size?: number): Salt;
    /**
     * Generate a random salt with specified size using provided RNG (legacy alias).
     */
    static randomUsing(rng: RandomNumberGenerator, size?: number): Salt;
    /**
     * Generate a proportionally-sized salt (legacy alias for newForSize).
     */
    static proportional(dataSize: number): Salt;
    /**
     * Return the length of the salt.
     */
    len(): number;
    /**
     * Return the length of the salt (alias for len).
     */
    size(): number;
    /**
     * Return true if the salt is empty (this is not recommended).
     */
    isEmpty(): boolean;
    /**
     * Return the data of the salt.
     */
    asBytes(): Uint8Array;
    /**
     * Get the raw salt bytes as a copy.
     */
    toData(): Uint8Array;
    /**
     * The data as a hexadecimal string.
     */
    hex(): string;
    /**
     * Get hex string representation (alias for hex()).
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
    /**
     * Returns the CBOR tags associated with Salt.
     */
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as a byte string).
     */
    untaggedCbor(): Cbor;
    /**
     * Returns the tagged CBOR encoding.
     */
    taggedCbor(): Cbor;
    /**
     * Returns the tagged value in CBOR binary representation.
     */
    taggedCborData(): Uint8Array;
    /**
     * Creates a Salt by decoding it from untagged CBOR.
     */
    fromUntaggedCbor(cbor: Cbor): Salt;
    /**
     * Creates a Salt by decoding it from tagged CBOR.
     */
    fromTaggedCbor(cbor: Cbor): Salt;
    /**
     * Static method to decode from tagged CBOR.
     */
    static fromTaggedCbor(cbor: Cbor): Salt;
    /**
     * Static method to decode from tagged CBOR binary data.
     */
    static fromTaggedCborData(data: Uint8Array): Salt;
    /**
     * Static method to decode from untagged CBOR binary data.
     */
    static fromUntaggedCborData(data: Uint8Array): Salt;
    /**
     * Returns the UR representation of the Salt.
     * Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
     */
    ur(): UR;
    /**
     * Returns the UR string representation.
     */
    urString(): string;
    /**
     * Creates a Salt from a UR.
     */
    static fromUR(ur: UR): Salt;
    /**
     * Creates a Salt from a UR string.
     */
    static fromURString(urString: string): Salt;
}

/** Default salt length for key derivation */
export declare const SALT_LEN = 16;

/**
 * Scrypt parameters for password-based key derivation.
 *
 * Parameters:
 * - log_n: CPU/memory cost parameter (N = 2^log_n)
 * - r: Block size parameter
 * - p: Parallelization parameter
 */
export declare class ScryptParams implements KeyDerivation {
    static readonly INDEX: KeyDerivationMethod;
    private readonly _salt;
    private readonly _logN;
    private readonly _r;
    private readonly _p;
    private constructor();
    /**
     * Create new Scrypt parameters with default settings.
     * Uses a random 16-byte salt, log_n=15, r=8, p=1.
     */
    static new(): ScryptParams;
    /**
     * Create Scrypt parameters with custom settings.
     */
    static newOpt(salt: Salt, logN: number, r: number, p: number): ScryptParams;
    /** Returns the salt. */
    salt(): Salt;
    /** Returns the log_n parameter. */
    logN(): number;
    /** Returns the r parameter (block size). */
    r(): number;
    /** Returns the p parameter (parallelism). */
    p(): number;
    /** Returns the method index for CBOR encoding. */
    index(): number;
    /**
     * Derive a key from the secret and encrypt the content key.
     */
    lock(contentKey: SymmetricKey, secret: Uint8Array): EncryptedMessage;
    /**
     * Derive a key from the secret and decrypt the content key.
     */
    unlock(encryptedMessage: EncryptedMessage, secret: Uint8Array): SymmetricKey;
    private _deriveKey;
    /**
     * Get string representation.
     */
    toString(): string;
    /**
     * Check equality with another ScryptParams.
     */
    equals(other: ScryptParams): boolean;
    /**
     * Convert to CBOR.
     * Format: [2, Salt, log_n, r, p]   (Salt is encoded as a tagged value — `#6.40018(bytes)`)
     */
    toCbor(): Cbor;
    /**
     * Convert to CBOR binary data.
     */
    toCborData(): Uint8Array;
    /**
     * Parse from CBOR.
     */
    static fromCbor(cborValue: Cbor): ScryptParams;
}

/**
 * Create Scrypt derivation parameters.
 */
export declare function scryptParams(params?: ScryptParams): KeyDerivationParams;

/** Default salt length for SSH agent key derivation */
export declare const SSH_AGENT_SALT_LEN = 16;

/**
 * SSH Agent parameters for key derivation.
 *
 * This method uses an SSH agent daemon to derive encryption keys.
 * The agent signs a challenge derived from the salt using the specified
 * SSH key identity, and the signature is used to derive the encryption key.
 *
 * **Note:** SSH agent communication requires platform-specific support and
 * may not be available in all JavaScript environments. The lock/unlock
 * methods will throw an error if SSH agent support is not available.
 *
 * **Parity / portability note:** Rust gates SSH-agent support behind the
 * `ssh-agent` feature flag and links to OS-native libraries
 * (`ssh-agent-client-rs`). The TS port deliberately stubs the lock/unlock
 * paths because no portable browser-friendly SSH-agent transport exists.
 * The CBOR encoding of `SSHAgentParams` is still byte-identical, so a
 * payload produced in Rust can be inspected and parsed in TS — only the
 * actual key-derivation operation is unavailable.
 */
export declare class SSHAgentParams implements KeyDerivation {
    static readonly INDEX: KeyDerivationMethod;
    private readonly _salt;
    private readonly _id;
    private constructor();
    /**
     * Create new SSH agent parameters with default salt and specified key ID.
     *
     * @param id - The SSH key identity (usually the key comment or public key fingerprint)
     */
    static new(id: string): SSHAgentParams;
    /**
     * Create SSH agent parameters with custom salt and key ID.
     *
     * @param salt - The salt for key derivation
     * @param id - The SSH key identity
     */
    static newOpt(salt: Salt, id: string): SSHAgentParams;
    /** Returns the salt. */
    salt(): Salt;
    /** Returns the SSH key identity. */
    id(): string;
    /** Returns the method index for CBOR encoding. */
    index(): number;
    /**
     * Derive a key using SSH agent and encrypt the content key.
     *
     * **Note:** This method requires SSH agent support which is not yet
     * implemented in this TypeScript port. Use an alternative key derivation
     * method or implement SSH agent communication for your environment.
     *
     * @throws CryptoError - SSH agent support is not available
     */
    lock(_contentKey: SymmetricKey, _secret: Uint8Array): EncryptedMessage;
    /**
     * Derive a key using SSH agent and decrypt the content key.
     *
     * **Note:** This method requires SSH agent support which is not yet
     * implemented in this TypeScript port. Use an alternative key derivation
     * method or implement SSH agent communication for your environment.
     *
     * @throws CryptoError - SSH agent support is not available
     */
    unlock(_encryptedMessage: EncryptedMessage, _secret: Uint8Array): SymmetricKey;
    /**
     * Get string representation.
     */
    toString(): string;
    /**
     * Check equality with another SSHAgentParams.
     */
    equals(other: SSHAgentParams): boolean;
    /**
     * Convert to CBOR.
     * Format: [4, Salt, id: tstr]   (Salt is encoded as a tagged value — `#6.40018(bytes)`)
     */
    toCbor(): Cbor;
    /**
     * Convert to CBOR binary data.
     */
    toCborData(): Uint8Array;
    /**
     * Parse from CBOR.
     */
    static fromCbor(cborValue: Cbor): SSHAgentParams;
}

/**
 * Create SSH agent derivation parameters.
 *
 * @param idOrParams - Either an SSH key identity string or SSHAgentParams instance
 */
export declare function sshAgentParams(idOrParams: string | SSHAgentParams): KeyDerivationParams;

declare class SymmetricKey implements CborTaggedEncodable, CborTaggedDecodable<SymmetricKey> {
    static readonly SYMMETRIC_KEY_SIZE: number;
    private readonly _data;
    private constructor();
    /**
     * Create a new random symmetric key.
     */
    static new(): SymmetricKey;
    /**
     * Create a new symmetric key from data.
     */
    static fromData(data: Uint8Array): SymmetricKey;
    /**
     * Create a new symmetric key from data (validates length).
     */
    static fromDataRef(data: Uint8Array): SymmetricKey;
    /**
     * Create a SymmetricKey from raw bytes (legacy alias).
     */
    static from(data: Uint8Array): SymmetricKey;
    /**
     * Create a SymmetricKey from hex string.
     */
    static fromHex(hex: string): SymmetricKey;
    /**
     * Generate a random symmetric key.
     */
    static random(): SymmetricKey;
    /**
     * Generate a random symmetric key using provided RNG.
     */
    static randomUsing(rng: RandomNumberGenerator): SymmetricKey;
    /**
     * Get the data of the symmetric key.
     */
    data(): Uint8Array;
    /**
     * Get the data of the symmetric key as a byte slice.
     */
    asBytes(): Uint8Array;
    /**
     * Get a copy of the raw key bytes.
     */
    toData(): Uint8Array;
    /**
     * Get hex string representation.
     */
    hex(): string;
    /**
     * Get hex string representation (alias for hex()).
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
    /**
     * Returns the CBOR tags associated with SymmetricKey.
     */
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding (as a byte string).
     */
    untaggedCbor(): Cbor;
    /**
     * Returns the tagged CBOR encoding.
     */
    taggedCbor(): Cbor;
    /**
     * Returns the tagged value in CBOR binary representation.
     */
    taggedCborData(): Uint8Array;
    /**
     * Creates a SymmetricKey by decoding it from untagged CBOR.
     */
    fromUntaggedCbor(cbor: Cbor): SymmetricKey;
    /**
     * Creates a SymmetricKey by decoding it from tagged CBOR.
     */
    fromTaggedCbor(cbor: Cbor): SymmetricKey;
    /**
     * Static method to decode from tagged CBOR.
     */
    static fromTaggedCbor(cbor: Cbor): SymmetricKey;
    /**
     * Static method to decode from tagged CBOR binary data.
     */
    static fromTaggedCborData(data: Uint8Array): SymmetricKey;
    /**
     * Static method to decode from untagged CBOR binary data.
     */
    static fromUntaggedCborData(data: Uint8Array): SymmetricKey;
    /**
     * Get the UR type for symmetric keys.
     */
    static readonly UR_TYPE = "crypto-key";
    /**
     * Returns the UR representation of the symmetric key.
     *
     * The UR type prefix (`ur:crypto-key/...`) carries the CBOR tag, so the
     * inner CBOR must be untagged — matches Rust's `UREncodable` blanket impl.
     */
    ur(): UR;
    /**
     * Returns the UR string representation of the symmetric key.
     */
    urString(): string;
    /**
     * Creates a SymmetricKey from a UR.
     */
    static fromUR(ur: UR): SymmetricKey;
    /**
     * Creates a SymmetricKey from a UR string.
     */
    static fromURString(urString: string): SymmetricKey;
    /**
     * Alias for fromURString for Rust API compatibility.
     */
    static fromUrString(urString: string): SymmetricKey;
}

/** Presents itself as a UR. */
declare interface UREncodable {
    ur(): UR;
    urString(): string;
}

export { }
