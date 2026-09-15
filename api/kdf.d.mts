import { Cbor } from '@blockchaincommons/dcbor';
import { CborCodec } from '@blockchaincommons/dcbor';
import { RandomNumberGenerator } from '@blockchaincommons/rand';
import { RngOptions } from '@blockchaincommons/rand';
import { Tag } from '@blockchaincommons/dcbor';
import { TagValue } from '@blockchaincommons/dcbor';
import { ToCbor } from '@blockchaincommons/dcbor';
import { ToUR } from '@blockchaincommons/uniform-resources';
import { UR } from '@blockchaincommons/uniform-resources';

/**
 * Argon2id parameters for password-based key derivation.
 *
 * This is the recommended method for password-based key derivation as it
 * provides the best protection against both GPU cracking and side-channel
 * attacks.
 */
export declare class Argon2idParams implements KeyDerivation {
    /** The method discriminant that opens the Argon2id parameter array on the wire. */
    static readonly INDEX: KeyDerivationMethod;
    private readonly _salt;
    private constructor();
    /** Parameters with a fresh random salt unless one is given. */
    static from({ salt }?: {
        salt?: Salt;
    }): Argon2idParams;
    /** Returns the salt. */
    get salt(): Salt;
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
    private _deriveKeyRaw;
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
    /**
     * From the CBOR array, as the reference's `TryFrom<CBOR>` (a dcbor error):
     * every failure is `Cbor` with the bare message. The index element is
     * read as a `usize` (with dcbor's negative wrap) and its value ignored;
     * the fixed-width fields wrap the same way.
     */
    static fromCbor(cborValue: Cbor): Argon2idParams;
}

/**
 * Create Argon2id derivation parameters.
 */
export declare function argon2idParams(params?: Argon2idParams): KeyDerivationParams;

/**
 * Authentication tag for AEAD encryption (16 bytes)
 *
 * An `AuthenticationTag` is a 16-byte value generated during ChaCha20-Poly1305
 * authenticated encryption. It serves as a message authentication code (MAC)
 * that verifies both the authenticity and integrity of the encrypted message.
 *
 * During decryption, the tag is verified to ensure:
 * - The message has not been tampered with (integrity)
 * - The message was encrypted by someone who possesses the encryption key
 *   (authenticity)
 *
 * This implementation follows the Poly1305 MAC algorithm as specified in
 * [RFC-8439](https://datatracker.ietf.org/doc/html/rfc8439).
 */
declare class AuthenticationTag {
    /** The byte length of a `AuthenticationTag`. */
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
    /** A copy of the bytes; mutating it does not touch this value. */
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
    /**
     * From the untagged byte string, as the reference's `TryFrom<CBOR>`
     * (error type `Error`): a non-byte-string is `Cbor` (`CBOR error: …`), a
     * wrong length `InvalidSize`.
     */
    static fromCbor(cbor: Cbor): AuthenticationTag;
    /**
     * Creates an AuthenticationTag from CBOR binary data.
     */
    static fromCborData(data: Uint8Array): AuthenticationTag;
}

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

/**
 * SHA-256 cryptographic digest (32 bytes)
 *
 * A `Digest` represents the cryptographic hash of some data. In this
 * implementation, SHA-256 is used, which produces a 32-byte hash value.
 * Digests are used throughout the crate for data verification and as unique
 * identifiers derived from data.
 *
 * # CBOR Serialization
 *
 * `Digest` implements the CBOR tagged encoding interfaces, which means it can be
 * serialized to and deserialized from CBOR with a specific tag (TAG_DIGEST = 40001).
 *
 * # UR Serialization
 *
 * When serialized as a Uniform Resource (UR), a `Digest` is represented as a
 * binary blob with the type "digest".
 *
 * @example
 * ```typescript
 * import { Digest } from '@blockchaincommons/components';
 *
 * // Create a digest from a string
 * const data = new TextEncoder().encode("hello world");
 * const digest = Digest.fromImage(data);
 *
 * // Validate that the digest matches the original data
 * console.log(digest.validate(data)); // true
 *
 * // Create a digest from a hex string
 * const hexString = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
 * const digest2 = Digest.fromHex(hexString);
 *
 * // Retrieve the digest as hex
 * console.log(digest2.toHex()); // b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
 * ```
 */
declare class Digest implements DigestProvider, ToCbor, ToUR {
    /** The byte length of a `Digest`. */
    static readonly DIGEST_SIZE: number;
    private readonly _data;
    private constructor();
    /** The bytes (a view; do not mutate). */
    /** A copy of the bytes; mutating it does not touch this value. */
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
    /** The CBOR tags this type decodes from; the first one is used to encode. */
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
 * and `unlock()` to decrypt it. SSH-agent parameters need an `SshAgent`:
 * `lockWithAgent()` and `unlockWithAgent()`.
 */
export declare class EncryptedKey implements ToCbor, ToUR {
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
     * Lock (encrypt) a content key with an SSH agent, the asynchronous route
     * for SSH-agent parameters: `SSHAgentParams.lock` with `options`, so the
     * secret is the comment of the agent identity to use (empty for the only
     * one) and `options.agent` signs the salt.
     *
     * The other methods need no agent and take no nonce, so they have no
     * asynchronous route: use `lockOpt()` for them.
     *
     * @param params - SSH-agent parameters; `id` is set from the secret
     * @param secret - The identity's comment as UTF-8
     * @param contentKey - The symmetric key to encrypt
     * @param options - The agent, and the nonce to use instead of a random one
     * @returns The encrypted key
     * @throws `InvalidData` when `params` are not SSH-agent parameters; the
     * `SshAgent` failures of `SSHAgentParams.lock`
     */
    static lockWithAgent(params: KeyDerivationParams, secret: Uint8Array, contentKey: SymmetricKey, options: SshAgentLockOptions): Promise<EncryptedKey>;
    /**
     * Returns the encrypted message.
     */
    get encryptedMessage(): EncryptedMessage;
    /**
     * Returns the key derivation parameters.
     */
    get params(): KeyDerivationParams;
    /**
     * Returns the key derivation method.
     */
    get method(): KeyDerivationMethod;
    /**
     * Check if this uses a password-based key derivation method.
     */
    isPasswordBased(): boolean;
    /**
     * Check if this uses SSH Agent for key derivation.
     *
     * Such a key is unlocked with `unlockWithAgent()`, which needs an `SshAgent`.
     */
    isSshAgent(): boolean;
    /**
     * Unlock (decrypt) the content key.
     *
     * @param secret - The secret (password or key material) used to lock
     * @returns The decrypted symmetric key
     * @throws ComponentsError if decryption fails (wrong password, tampered data, etc.)
     */
    unlock(secret: Uint8Array): SymmetricKey;
    /**
     * Unlock (decrypt) the content key with an SSH agent: for SSH-agent
     * parameters `SSHAgentParams.unlock` with `options`, where the secret is
     * the comment of the agent identity to use, or empty for the stored id or
     * else the first identity; for every other method the same as
     * `unlock(secret)`, the agent unused.
     *
     * @param secret - The identity's comment as UTF-8, or the secret used to lock
     * @param options - The agent that signs the salt
     * @returns The decrypted symmetric key
     * @throws as `unlock`; the `SshAgent` and `Crypto` failures of
     * `SSHAgentParams.unlock`
     */
    unlockWithAgent(secret: Uint8Array, options: SshAgentUnlockOptions): Promise<SymmetricKey>;
    /** The derivation parameters, from the encrypted message's AAD. */
    private _paramsFromAad;
    /**
     * Check equality with another EncryptedKey.
     */
    equals(other: EncryptedKey): boolean;
    /**
     * Get string representation.
     */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<EncryptedKey>;
    /** The CBOR tags this type decodes from; the first one is used to encode. */
    cborTags(): Tag[];
    /**
     * Returns the untagged CBOR encoding.
     * The EncryptedMessage is encoded with its own tag (40002).
     */
    untaggedCbor(): Cbor;
    /** The tagged CBOR form. */
    toCbor(): Cbor;
    /** As a UR, typed by the first tag's name. */
    toUR(): UR;
    /** Decode tagged or untagged CBOR. */
    static fromCbor(cborValue: Cbor): EncryptedKey;
}

/**
 * Encrypted message with ChaCha20-Poly1305 AEAD
 *
 * A secure encrypted message using IETF ChaCha20-Poly1305 authenticated
 * encryption.
 *
 * `EncryptedMessage` represents data that has been encrypted using a symmetric
 * key with the ChaCha20-Poly1305 AEAD (Authenticated Encryption with
 * Associated Data) construction as specified in [RFC-8439](https://datatracker.ietf.org/doc/html/rfc8439).
 *
 * An `EncryptedMessage` contains:
 * - `ciphertext`: The encrypted data (same length as the original plaintext)
 * - `aad`: Additional Authenticated Data that is not encrypted but is
 *   authenticated (optional)
 * - `nonce`: A 12-byte number used once for this specific encryption operation
 * - `auth`: A 16-byte authentication tag that verifies the integrity of the
 *   message
 *
 * The `aad` field is often used to include the `Digest` of the plaintext,
 * which allows verification of the plaintext after decryption and preserves
 * the unique identity of the data when used with structures like Gordian
 * Envelope.
 *
 * # CBOR Serialization
 *
 * `EncryptedMessage` is serialized to CBOR with tag 40002.
 *
 * CDDL:
 * ```text
 * EncryptedMessage =
 *     #6.40002([ ciphertext: bstr, nonce: bstr, auth: bstr, ? aad: bstr ])
 * ```
 *
 * # UR Serialization
 *
 * When serialized as a Uniform Resource (UR), an `EncryptedMessage` is
 * represented with the type "encrypted".
 */
declare class EncryptedMessage implements ToCbor, ToUR {
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
    /** A copy of the ciphertext. */
    get ciphertext(): Uint8Array;
    /**
     * Returns a reference to the additional authenticated data (AAD).
     */
    /** A copy of the additional authenticated data. */
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
    /** The CBOR tags this type decodes from; the first one is used to encode. */
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
 * Enum representing supported hash types for key derivation.
 */
export declare const HashType: Readonly<{
    /** SHA-256; the CBOR discriminator is 0. */
    readonly SHA256: 0;
    /** SHA-512; the CBOR discriminator is 1. */
    readonly SHA512: 1;
}>;

/** One of the `HashType` values. */
export declare type HashType = (typeof HashType)[keyof typeof HashType];

/**
 * Parse HashType from CBOR.
 */
/**
 * As the reference's `TryFrom<CBOR>` (error type `Error`): a `u8` with
 * dcbor's negative wrap (`-256` reads as 0, SHA-256), then `General`
 * `Invalid HashType` for any other value; a non-integer or out-of-width
 * head is `Cbor` (`CBOR error: …`).
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
    /** The method discriminant that opens the HKDF parameter array on the wire. */
    static readonly INDEX: KeyDerivationMethod;
    private readonly _salt;
    private readonly _hashType;
    private constructor();
    /** Parameters with a fresh random salt unless one is given. */
    static from({ salt, hashType }?: {
        salt?: Salt;
        hashType?: HashType;
    }): HKDFParams;
    /** Returns the salt. */
    get salt(): Salt;
    /** Returns the hash type. */
    get hashType(): HashType;
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
    private _deriveKeyRaw;
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
    /**
     * From the CBOR array, as the reference's `TryFrom<CBOR>` (a dcbor error):
     * every failure is `Cbor` with the bare message. The index element is
     * read as a `usize` (with dcbor's negative wrap) and its value ignored;
     * the fixed-width fields wrap the same way.
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
 * Implements the RandomNumberGenerator interface from @blockchaincommons/rand
 * (`fillBytes`, `nextU32`, `nextU64`); draw bytes with rand's `randomBytes`
 * and `fillRandomBytes`.
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
    /**
     * @param keyMaterial - The input key material for HKDF
     * @param salt - The salt string; page `i` uses `"<salt>-<i>"`
     * @param pageLength - Bytes of output derived per page (32 by default). A
     *   page length of 0 is accepted, as the reference accepts it; the
     *   generator then serves only empty draws and throws `InvalidData` on
     *   the first request for a byte (where the reference never returns).
     */
    constructor(keyMaterial: Uint8Array, salt: string, { pageLength }?: {
        pageLength?: number;
    });
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
    get keyMaterial(): Uint8Array;
    get salt(): string;
    get pageLength(): number;
    get pageIndex(): number;
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
 * Such parameters lock and unlock with an `SshAgent` (see `SSHAgentParams.lock`).
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
export declare const KeyDerivationMethod: Readonly<{
    /** HKDF (RFC 5869); the CBOR discriminator is 0. */
    readonly HKDF: 0;
    /** PBKDF2 (RFC 8018); the CBOR discriminator is 1. */
    readonly PBKDF2: 1;
    /** scrypt (RFC 7914); the CBOR discriminator is 2. */
    readonly Scrypt: 2;
    /** Argon2id (RFC 9106); the CBOR discriminator is 3. */
    readonly Argon2id: 3;
    /** An SSH agent signature as key material; the CBOR discriminator is 4. */
    readonly SSHAgent: 4;
}>;

/** One of the `KeyDerivationMethod` values. */
export declare type KeyDerivationMethod = (typeof KeyDerivationMethod)[keyof typeof KeyDerivationMethod];

/**
 * Parse KeyDerivationMethod from CBOR.
 */
/**
 * As the reference's `TryFrom<CBOR>` (error type `Error`): the index as a
 * `usize` with dcbor's negative wrap, then `General`
 * `Invalid KeyDerivationMethod` for an unknown one; a non-integer or
 * out-of-width head is `Cbor` (`CBOR error: …`).
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
    /** HKDF. */
    type: "hkdf";
    /** The HKDF parameters. */
    params: HKDFParams;
} | {
    /** PBKDF2. */
    type: "pbkdf2";
    /** The PBKDF2 parameters. */
    params: PBKDF2Params;
} | {
    /** scrypt. */
    type: "scrypt";
    /** The scrypt parameters. */
    params: ScryptParams;
} | {
    /** Argon2id. */
    type: "argon2id";
    /** The Argon2id parameters. */
    params: Argon2idParams;
} | {
    /** SSH agent. */
    type: "sshagent";
    /** The SSH-agent parameters. */
    params: SSHAgentParams;
};

/**
 * Parse KeyDerivationParams from CBOR.
 */
/**
 * As the reference's `TryFrom<CBOR> for KeyDerivationParams` (a dcbor
 * error): the first element, a `usize` with dcbor's negative wrap, selects
 * the method, and that method's decoder reads the whole array.
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

/**
 * An `SshAgent` whose identities are private keys held in memory, the
 * analogue of the reference's test `MockSSHAgent`.
 *
 * Identities are keyed by comment: adding a key whose comment is already
 * present replaces that identity in place. `listIdentities` returns the
 * public keys in insertion order, so with an empty id a lock or unlock uses
 * the first key added.
 *
 * `sign` signs `data` the way the reference's mock does: an `sshsig`
 * signature in the namespace `test_namespace` over the SHA-256 digest of
 * `data`, of which the inner raw signature bytes are returned. A real agent
 * signs `data` itself, so a key locked with this agent cannot be unlocked
 * with a real agent holding the same key, and vice versa.
 */
export declare class MemorySshAgent implements SshAgent {
    private readonly _identities;
    private readonly _refuseToSign;
    /**
     * An agent holding `identities` (none by default). With `refuseToSign`
     * every `sign` call fails, the way an agent that declines a request does.
     */
    constructor({ identities, refuseToSign }?: {
        identities?: Iterable<SSHPrivateKey>;
        refuseToSign?: boolean;
    });
    /** Adds `key` under its comment, replacing any identity with that comment. */
    addIdentity(key: SSHPrivateKey): void;
    /** Removes the identity whose comment is `key`'s; nothing happens when there is none. */
    removeIdentity(key: SSHPrivateKey): void;
    /** Removes every identity. */
    removeAllIdentities(): void;
    /** The public keys of the identities, in insertion order, each with its comment. */
    listIdentities(): Promise<readonly SSHPublicKey[]>;
    /**
     * The raw signature bytes of the `sshsig` signature (namespace
     * `test_namespace`, SHA-256) over `data` by the private key whose comment
     * is `identity`'s.
     *
     * @throws `SshAgent` `Identity not found` when no identity has that
     * comment; `SshAgent` `Refused to sign` when the agent was built with
     * `refuseToSign`.
     */
    sign(identity: SSHPublicKey, data: Uint8Array): Promise<Uint8Array>;
}

/**
 * A random nonce ("number used once").
 *
 * A `Nonce` is a cryptographic primitive consisting of a random or
 * pseudo-random number that is used only once in a cryptographic
 * communication. Nonces are often used in authentication protocols, encryption
 * algorithms, and digital signatures to prevent replay attacks and ensure
 * the uniqueness of encrypted messages.
 *
 * In this implementation, a `Nonce` is a 12-byte random value. The size is
 * chosen to be sufficiently large to prevent collisions while remaining
 * efficient for storage and transmission.
 *
 * # CBOR Serialization
 *
 * `Nonce` implements the CBOR tagged encoding interfaces, which means it can be
 * serialized to and deserialized from CBOR with a specific tag (TAG_NONCE = 40014).
 *
 * # UR Serialization
 *
 * When serialized as a Uniform Resource (UR), a `Nonce` is represented as a
 * binary blob with the type "nonce".
 *
 * # Common Uses
 *
 * - In authenticated encryption schemes like AES-GCM or ChaCha20-Poly1305
 * - For initializing counters in counter-mode block ciphers
 * - In challenge-response authentication protocols
 * - To prevent replay attacks in secure communications
 *
 * @example
 * ```typescript
 * import { Nonce } from '@blockchaincommons/components';
 *
 * // Generate a new random nonce
 * const nonce = Nonce.random();
 *
 * // Create a nonce from a byte array
 * const data = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
 * const nonce2 = Nonce.from(data);
 *
 * // Access the nonce data
 * const nonceData = nonce2.bytes;
 * ```
 */
declare class Nonce implements ToCbor, ToUR {
    /** The byte length of a `Nonce`. */
    static readonly NONCE_SIZE: number;
    private readonly _data;
    private constructor();
    /** A fresh random value; pass `rng` to make it deterministic. */
    static random({ rng }?: RngOptions): Nonce;
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
    /** A copy of the bytes; mutating it does not touch this value. */
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
    /** The CBOR tags this type decodes from; the first one is used to encode. */
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
 * PBKDF2 parameters for password-based key derivation.
 */
export declare class PBKDF2Params implements KeyDerivation {
    /** The method discriminant that opens the PBKDF2 parameter array on the wire. */
    static readonly INDEX: KeyDerivationMethod;
    private readonly _salt;
    private readonly _iterations;
    private readonly _hashType;
    private constructor();
    /** Parameters with a fresh random salt unless one is given. */
    static from({ salt, iterations, hashType }?: {
        salt?: Salt;
        iterations?: number;
        hashType?: HashType;
    }): PBKDF2Params;
    /** Returns the salt. */
    get salt(): Salt;
    /** Returns the number of iterations. */
    get iterations(): number;
    /** Returns the hash type. */
    get hashType(): HashType;
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
    private _deriveKeyRaw;
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
    /**
     * From the CBOR array, as the reference's `TryFrom<CBOR>` (a dcbor error):
     * every failure is `Cbor` with the bare message. The index element is
     * read as a `usize` (with dcbor's negative wrap) and its value ignored;
     * the fixed-width fields wrap the same way.
     */
    static fromCbor(cborValue: Cbor): PBKDF2Params;
}

/**
 * Create PBKDF2 derivation parameters.
 */
export declare function pbkdf2Params(params?: PBKDF2Params): KeyDerivationParams;

/**
 * A globally unique reference to a globally unique object.
 *
 * Internally stores 32 raw bytes. Most callers obtain a `Reference` via
 * `fromDigest`, but `XID` (and similar content-addressable types whose
 * bytes _are_ the reference) construct via `fromData` directly.
 */
declare class Reference implements ToCbor, DigestProvider, ReferenceProvider {
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
    /** The CBOR tags this type decodes from; the first one is used to encode. */
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
declare type ReferenceEncodingFormat = "hex" | "bytewords" | "bytemojis";

/**
 * Implementers of this interface provide a globally unique reference to themselves.
 *
 * cryptographic digest of the object's serialized form, ensuring that it
 * uniquely identifies the object's contents.
 */
declare interface ReferenceProvider {
    /** Returns a cryptographic reference that uniquely identifies this object. */
    reference(): Reference;
}

/**
 * Random salt used to decorrelate other information.
 *
 * A `Salt` is a cryptographic primitive consisting of random data that is used
 * to modify the output of a cryptographic function. Salts are primarily used
 * in password hashing to defend against dictionary attacks, rainbow table
 * attacks, and pre-computation attacks. They are also used in other
 * cryptographic contexts to ensure uniqueness and prevent correlation between
 * different parts of a cryptosystem.
 *
 * Unlike a `Nonce` which has a fixed size, a `Salt` in this implementation can
 * have a variable length (minimum 8 bytes). Different salt creation methods
 * are provided to generate salts of appropriate sizes for different use cases.
 *
 * # Minimum Size Requirement
 *
 * For security reasons, salts must be at least 8 bytes long. Attempting to
 * create a salt with fewer than 8 bytes will result in an error.
 *
 * # CBOR Serialization
 *
 * `Salt` implements the CBOR tagged encoding interfaces, which means it can be
 * serialized to and deserialized from CBOR with a specific tag (TAG_SALT = 40018).
 *
 * # UR Serialization
 *
 * When serialized as a Uniform Resource (UR), a `Salt` is represented as a
 * binary blob with the type "salt".
 *
 * # Common Uses
 *
 * - Password hashing and key derivation functions
 * - Preventing correlation in cryptographic protocols
 * - Randomizing data before encryption to prevent pattern recognition
 * - Adding entropy to improve security in various cryptographic functions
 *
 * @example
 * ```typescript
 * import { Salt } from '@blockchaincommons/components';
 *
 * // Generate a salt with 16 bytes
 * const salt = Salt.random({ length: 16 });
 * console.log(salt.byteLength); // 16
 *
 * // Generate a salt proportional to 100 bytes of data
 * const salt2 = Salt.forSize(100);
 *
 * // Generate a salt with length between 16 and 32 bytes
 * const salt3 = Salt.randomInRange(16, 32);
 * ```
 */
declare class Salt implements ToCbor, ToUR {
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
    } & RngOptions): Salt;
    /** A random salt of a random length in `[minSize, maxSize]`. */
    static randomInRange(minSize: number, maxSize: number, { rng }?: RngOptions): Salt;
    /** A random salt sized for a payload of `size` bytes (5–25% of it, at least the minimum). */
    static forSize(size: number, { rng }?: RngOptions): Salt;
    /** Number of bytes. */
    get byteLength(): number;
    /**
     * Return true if the salt is empty (this is not recommended).
     */
    isEmpty(): boolean;
    /** The bytes (a view; do not mutate). */
    /** A copy of the bytes; mutating it does not touch this value. */
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
    /** The CBOR tags this type decodes from; the first one is used to encode. */
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
    /** The method discriminant that opens the scrypt parameter array on the wire. */
    static readonly INDEX: KeyDerivationMethod;
    private readonly _salt;
    private readonly _logN;
    private readonly _r;
    private readonly _p;
    private constructor();
    /** Parameters with a fresh random salt unless one is given. */
    static from({ salt, logN, r, p }?: {
        salt?: Salt;
        logN?: number;
        r?: number;
        p?: number;
    }): ScryptParams;
    /** Returns the salt. */
    get salt(): Salt;
    /** Returns the log_n parameter. */
    get logN(): number;
    /** Returns the r parameter (block size). */
    get r(): number;
    /** Returns the p parameter (parallelism). */
    get p(): number;
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
    private _deriveKeyRaw;
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
    /**
     * From the CBOR array, as the reference's `TryFrom<CBOR>` (a dcbor error):
     * every failure is `Cbor` with the bare message. The index element is
     * read as a `usize` (with dcbor's negative wrap) and its value ignored;
     * the fixed-width fields wrap the same way.
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
 * What a key-derivation lock/unlock needs from an SSH agent (the reference's
 * `SSHAgent` trait, asynchronous here).
 *
 * An implementation reports its own failures as a `ComponentsError`; a
 * failure to sign is reported by the caller as `SSH agent refused to sign`
 * whatever the implementation threw.
 */
export declare interface SshAgent {
    /** The public keys the agent holds, each with its comment. */
    listIdentities(): Promise<readonly SSHPublicKey[]>;
    /** The raw signature bytes (for Ed25519 the 64-byte signature) over `data`. */
    sign(identity: SSHPublicKey, data: Uint8Array): Promise<Uint8Array>;
}

/** The options of an agent-backed lock. */
export declare interface SshAgentLockOptions {
    /** The agent that signs the salt. */
    agent: SshAgent;
    /** The nonce to encrypt with; a random one unless given. */
    nonce?: Nonce;
}

/**
 * SSH Agent parameters for key derivation.
 *
 * This method uses an SSH agent to derive encryption keys: the agent signs
 * the salt with the Ed25519 identity `id` names (by comment), and the key
 * is HKDF-SHA256 of that signature with the salt. The agent is passed to
 * `lock` and `unlock` as an `SshAgent`: `MemorySshAgent` holds keys in
 * memory, and the `ssh-agent-node` subpath connects to the agent
 * `$SSH_AUTH_SOCK` names. Without an agent the synchronous `lock` and
 * `unlock` of `KeyDerivation` throw `SshAgent`, where the reference would
 * connect to `$SSH_AUTH_SOCK` itself.
 *
 * The CBOR encoding of `SSHAgentParams` is byte-identical to the reference's,
 * so a payload produced by either implementation is read by the other.
 */
export declare class SSHAgentParams implements KeyDerivation {
    /** The method discriminant that opens the SSH-agent parameter array on the wire. */
    static readonly INDEX: KeyDerivationMethod;
    private readonly _salt;
    private _id;
    private constructor();
    /** Parameters with a fresh random salt unless one is given, and an empty id unless one is given. */
    static from({ id, salt }?: {
        id?: string;
        salt?: Salt;
    }): SSHAgentParams;
    /** Returns the salt. */
    get salt(): Salt;
    /** Returns the SSH key identity: the comment of the agent identity; `lock` sets it from the secret. */
    get id(): string;
    /** Returns the method index for CBOR encoding. */
    index(): number;
    /**
     * Derive a key with an SSH agent and encrypt the content key, the
     * reference's `lock`.
     *
     * Without `options` there is no agent to ask, and the call throws
     * `SshAgent`. With `options.agent`:
     *
     * 1. `secret` is the id: the comment of the identity to use, as UTF-8
     *    (`SSH Agent secret must be a valid UTF-8 string` otherwise).
     * 2. The agent's identities are listed and reduced to the Ed25519 ones
     *    (`No Ed25519 identities available in SSH agent` when there is none).
     * 3. An empty id takes the only identity (`Multiple identities available
     *    in SSH agent, but no ID provided` when there are several); a
     *    non-empty id takes the identity with that comment (`No matching
     *    identity found`).
     * 4. The agent signs the salt (`SSH agent refused to sign` on any failure).
     * 5. The encryption key is HKDF-SHA256 of the signature with the salt.
     * 6. `id` is stored in these parameters, which are then the additional
     *    authenticated data; the content key is encrypted with
     *    `options.nonce` or a random nonce.
     *
     * @throws `SshAgent` as listed above.
     */
    lock(contentKey: SymmetricKey, secret: Uint8Array): EncryptedMessage;
    lock(contentKey: SymmetricKey, secret: Uint8Array, options: SshAgentLockOptions): Promise<EncryptedMessage>;
    /**
     * Derive a key with an SSH agent and decrypt the content key, the
     * reference's `unlock`.
     *
     * Without `options` there is no agent to ask, and the call throws
     * `SshAgent`. With `options.agent` the identity is chosen, among the
     * agent's Ed25519 identities, by the first of these that applies: the
     * secret's id when non-empty, the stored `id` when non-empty (each by
     * comment, `No matching identity found` otherwise), else the first
     * identity. The agent signs the stored salt, the key is derived as in
     * `lock`, and the message is decrypted.
     *
     * @throws `SshAgent` for the secret, identity and signing failures of
     * `lock`; `Crypto` `Failed to decrypt the encrypted key: <reason>` when
     * the message does not decrypt (a wrong identity, tampered data), and
     * `Crypto` `Failed to convert decrypted key to SymmetricKey: <reason>`
     * when the plaintext is not a symmetric key.
     */
    unlock(encryptedMessage: EncryptedMessage, secret: Uint8Array): SymmetricKey;
    unlock(encryptedMessage: EncryptedMessage, secret: Uint8Array, options: SshAgentUnlockOptions): Promise<SymmetricKey>;
    private _lockWithAgent;
    private _unlockWithAgent;
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
    /**
     * From the CBOR array, as the reference's `TryFrom<CBOR>` (a dcbor error):
     * every failure is `Cbor` with the bare message. The index element is
     * read as a `usize` (with dcbor's negative wrap) and its value ignored;
     * the fixed-width fields wrap the same way.
     */
    static fromCbor(cborValue: Cbor): SSHAgentParams;
}

/**
 * Create SSH agent derivation parameters.
 *
 * @param idOrParams - Either an SSH key identity string or SSHAgentParams instance
 */
export declare function sshAgentParams(idOrParams: string | SSHAgentParams): KeyDerivationParams;

/** The options of an agent-backed unlock. */
export declare interface SshAgentUnlockOptions {
    /** The agent that signs the salt. */
    agent: SshAgent;
}

/**
 * SSH key algorithm identifiers.
 *
 * The six key algorithms `ssh-key` 0.6.7 generates and parses, and that the
 * reference derives from a `PrivateKeyBase`:
 *
 *   - Ed25519 (`ssh-ed25519`)
 *   - DSA (`ssh-dss`) — 1024-bit p, 160-bit q, SHA-1
 *   - RSA (`ssh-rsa`) — 2048-bit keys; `sshsig` signatures name their hash
 *     as `rsa-sha2-256` / `rsa-sha2-512` (RFC 8332)
 *   - ECDSA P-256 (`ecdsa-sha2-nistp256`) — SHA-256
 *   - ECDSA P-384 (`ecdsa-sha2-nistp384`) — SHA-384
 *   - ECDSA P-521 (`ecdsa-sha2-nistp521`) — SHA-512
 *
 * Not supported: FIDO/U2F `sk-*` keys, opaque `name@domain` algorithms,
 * encrypted private keys and `*-cert-v01@openssh.com` certificates.
 */
declare type SshAlgorithm = {
    /** `ssh-ed25519`. */
    kind: "ed25519";
} | {
    /** `ssh-dss`. */
    kind: "dsa";
} | {
    /** `ssh-rsa`. */
    kind: "rsa";
} | {
    /** `ecdsa-sha2-nistp256` / `ecdsa-sha2-nistp384` / `ecdsa-sha2-nistp521`. */
    kind: "ecdsa";
    /** The NIST curve of an ECDSA key. */
    curve: SshEcdsaCurve;
};

/** The NIST curves an SSH ECDSA key can use. */
declare type SshEcdsaCurve = "nistp256" | "nistp384" | "nistp521";

/** The hash an `sshsig` signature is made over. */
declare type SshHashAlgorithm = "sha256" | "sha512";

/** An OpenSSH private key (`-----BEGIN OPENSSH PRIVATE KEY-----`), unencrypted, for the algorithms in `SshAlgorithm`. */
declare class SSHPrivateKey {
    /** The parsed key material by algorithm. */
    readonly data: SshPrivateKeyData;
    /** The comment stored in the private-key section (may be empty). */
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
     * deterministically from the private bytes (mirrors `ssh-key` 0.6.7's
     * `KeypairData::checkint`).
     */
    static fromParts(data: SshPrivateKeyData, comment: string, checkint: number): SSHPrivateKey;
    /** Algorithm tag for this key. */
    get algorithm(): SshAlgorithm;
    get publicBytes(): Uint8Array;
    get privateBytes(): Uint8Array;
    /** Parses the PEM-armoured OpenSSH private key text, as `ssh_key::PrivateKey::from_openssh`. */
    static fromOpenssh(text: string): SSHPrivateKey;
    /** Parses the binary `openssh-key-v1` blob (the base64 payload of the text form). */
    static fromBlob(blob: Uint8Array): SSHPrivateKey;
    /**
     * Re-serialize to the canonical OpenSSH armored format.
     *
     */
    toOpenssh(): string;
    /** The binary `openssh-key-v1` blob, byte for byte as OpenSSH writes it. */
    toBlob(): Uint8Array;
    /** The matching public key, with the same comment. */
    publicKey(): SSHPublicKey;
    private publicBlob;
    private encryptedSection;
    /** SHA-256 of the OpenSSH text form (the reference's `Reference` image). */
    digest(): Uint8Array;
    /** The first four bytes of `digest()` in hex, the reference's `ref_hex_short`. */
    refHexShort(): string;
    /** `SSHPrivateKey(<short reference>)`, the reference's `Display`. */
    toString(): string;
    /**
     * Signs `message` in `namespace` with `hashAlgorithm`, producing an
     * `sshsig` signature.
     *
     * RSA keys cannot sign: `ssh-key` 0.6.7 rebuilds the `rsa` private key
     * from `(p, p)` instead of `(p, q)`, so the reference's
     * `SigningPrivateKey::sign` fails with `cryptographic error` for every
     * RSA key, and so does this method.
     */
    sign(namespace: string, hashAlgorithm: SshHashAlgorithm, message: Uint8Array): SSHSignature;
}

/**
 * Algorithm-specific private-key data.
 *
 *   - ed25519: 32-byte seed.
 *   - ecdsa:   curve + canonical scalar (32 / 48 / 66 bytes, no sign byte).
 *   - dsa:     canonical positive p, q, g, y (re-stated from the public
 *              key blob), plus the secret exponent x.
 *   - rsa:     canonical positive n, e (re-stated), d, iqmp, p, q.
 */
declare type SshPrivateKeyData = {
    /** `ssh-ed25519`. */
    kind: "ed25519";
    /** The 32-byte seed. */
    seed: Uint8Array;
    /** The 32 raw public key bytes. */
    pubBytes: Uint8Array;
} | {
    /** `ecdsa-sha2-nistp256` / `ecdsa-sha2-nistp384` / `ecdsa-sha2-nistp521`. */
    kind: "ecdsa";
    /** The NIST curve. */
    curve: SshEcdsaCurve;
    /** The canonical scalar (32, 48 or 66 bytes, no sign byte). */
    scalar: Uint8Array;
    /** The SEC1 uncompressed public point. */
    point: Uint8Array;
} | {
    /** `ssh-dss`. */
    kind: "dsa";
    /** The prime modulus, canonical positive bytes. */
    p: Uint8Array;
    /** The subgroup order, canonical positive bytes. */
    q: Uint8Array;
    /** The generator, canonical positive bytes. */
    g: Uint8Array;
    /** The public value, canonical positive bytes. */
    y: Uint8Array;
    /** The secret exponent, canonical positive bytes. */
    x: Uint8Array;
} | {
    /** `ssh-rsa`. */
    kind: "rsa";
    /** The modulus, canonical positive bytes. */
    n: Uint8Array;
    /** The public exponent, canonical positive bytes. */
    e: Uint8Array;
    /** The private exponent, canonical positive bytes. */
    d: Uint8Array;
    /** The CRT coefficient `q^-1 mod p`, canonical positive bytes. */
    iqmp: Uint8Array;
    /** The first prime, canonical positive bytes. */
    p: Uint8Array;
    /** The second prime, canonical positive bytes. */
    q: Uint8Array;
};

declare class SSHPublicKey {
    /** The parsed key material by algorithm. */
    readonly data: SshPublicKeyData;
    /** The comment field of the OpenSSH text form (may be empty). */
    readonly comment: string;
    private constructor();
    /** Algorithm tag for this key. */
    get algorithm(): SshAlgorithm;
    /** An Ed25519 key from its 32 raw bytes. */
    static ed25519(keyBytes: Uint8Array, comment?: string): SSHPublicKey;
    /** A P-256 key from its 65-byte SEC1 uncompressed point. */
    static ecdsaP256(uncompressedPoint: Uint8Array, comment?: string): SSHPublicKey;
    /** A P-384 key from its 97-byte SEC1 uncompressed point. */
    static ecdsaP384(uncompressedPoint: Uint8Array, comment?: string): SSHPublicKey;
    /** A P-521 key from its 133-byte SEC1 uncompressed point. */
    static ecdsaP521(uncompressedPoint: Uint8Array, comment?: string): SSHPublicKey;
    /** An ECDSA key on `curve` from its SEC1 uncompressed point. */
    static ecdsa(curve: SshEcdsaCurve, uncompressedPoint: Uint8Array, comment?: string): SSHPublicKey;
    /** DSA public key. p/q/g/y must already be canonical positive bytes (no sign byte). */
    static dsa(p: Uint8Array, q: Uint8Array, g: Uint8Array, y: Uint8Array, comment?: string): SSHPublicKey;
    /** RSA public key. `e` and `n` must already be canonical positive bytes (no sign byte). */
    static rsa(e: Uint8Array, n: Uint8Array, comment?: string): SSHPublicKey;
    /**
     * Returns a copy of this SSH public key with the comment replaced,
     * leaving this instance untouched.
     */
    withComment(comment: string): SSHPublicKey;
    /**
     * Parses the single-line OpenSSH text form (`<algorithm> <base64 blob> [comment]`)
     * as `ssh-key` 0.6.7 `PublicKey::from_openssh`: trailing whitespace is
     * removed, the algorithm and Base64 segments end at a single space, the
     * Base64 is strict, and the text's algorithm name must equal the blob's
     * (`unknown algorithm` otherwise).
     */
    static fromOpenssh(text: string): SSHPublicKey;
    /** The single-line OpenSSH text form. */
    toOpenssh(): string;
    /** Parses the binary key blob (the base64 payload of the text form). */
    static fromBlob(blob: Uint8Array, comment?: string): SSHPublicKey;
    /** The binary key blob, byte for byte as OpenSSH writes it. */
    toBlob(): Uint8Array;
    /** SHA-256 of the OpenSSH text form (the reference's `Reference` image). */
    digest(): Uint8Array;
    /** The first four bytes of `digest()` in hex, the reference's `ref_hex_short`. */
    refHexShort(): string;
    /** `SSHPublicKey(<short reference>)`, the reference's `Display`. */
    toString(): string;
    /** `true` when algorithm, key material and comment are all equal. */
    equals(other: SSHPublicKey): boolean;
    /**
     * Comment-insensitive equality: matches when algorithm and key data
     * agree, ignoring the comment. Used by verify paths since SSH
     * wire-format pubkey blobs carry the key but not the comment.
     */
    keyEquals(other: SSHPublicKey): boolean;
    /**
     * Algorithm-specific raw payload bytes. Throws for DSA and RSA, whose
     * keys are several integers — use `data.p/q/g/y` or `data.e/n` instead.
     */
    get keyBytes(): Uint8Array;
    /**
     * Verifies an `sshsig` signature made over `message` in `namespace`, as
     * `ssh_key::PublicKey::verify`: the embedded key must be this key, the
     * namespace must match, and the algorithm-specific signature must verify
     * over the signed-data blob. Never throws on malformed input.
     */
    verifySshSignature(namespace: string, message: Uint8Array, signature: SshSignatureParts): boolean;
}

/**
 * Internal discriminated union for the algorithm-specific public-key data.
 *
 *   - ed25519: the 32-byte raw public key.
 *   - ecdsa:   curve + 65/97/133-byte SEC1 uncompressed point.
 *   - dsa:     four canonical-positive mpint bytes (p, q, g, y) — sign
 *              byte already stripped on parse, re-added by the writer.
 *   - rsa:     canonical-positive e and n.
 */
declare type SshPublicKeyData = {
    /** `ssh-ed25519`. */
    kind: "ed25519";
    /** The 32 raw public key bytes. */
    pubBytes: Uint8Array;
} | {
    /** `ecdsa-sha2-nistp256` / `ecdsa-sha2-nistp384` / `ecdsa-sha2-nistp521`. */
    kind: "ecdsa";
    /** The NIST curve. */
    curve: SshEcdsaCurve;
    /** The SEC1 uncompressed point (65, 97 or 133 bytes). */
    point: Uint8Array;
} | {
    /** `ssh-dss`. */
    kind: "dsa";
    /** The prime modulus, canonical positive bytes. */
    p: Uint8Array;
    /** The subgroup order, canonical positive bytes. */
    q: Uint8Array;
    /** The generator, canonical positive bytes. */
    g: Uint8Array;
    /** The public value, canonical positive bytes. */
    y: Uint8Array;
} | {
    /** `ssh-rsa`. */
    kind: "rsa";
    /** The public exponent, canonical positive bytes. */
    e: Uint8Array;
    /** The modulus, canonical positive bytes. */
    n: Uint8Array;
};

/** An OpenSSH `sshsig` signature (`-----BEGIN SSH SIGNATURE-----`), version 1. */
declare class SSHSignature {
    /** The signing key, embedded in the signature. */
    readonly publicKey: SSHPublicKey;
    /** The application namespace the signature was made in. */
    readonly namespace: string;
    /** The reserved field (empty in every signature OpenSSH writes). */
    readonly reserved: Uint8Array;
    /** The hash the message was digested with. */
    readonly hashAlgorithm: SshHashAlgorithm;
    /**
     * The algorithm name inside the signature blob: the key's wire name for
     * Ed25519, DSA and ECDSA keys, and `rsa-sha2-256` / `rsa-sha2-512` (the
     * hash the RSA signature was made with) for RSA keys.
     */
    readonly signatureAlgorithm: string;
    /**
     * Raw signature bytes specific to the algorithm:
     *   ed25519 → 64-byte concatenation `r || s`
     *   ecdsa   → fixed-width `r || s` (64 / 96 / 132 bytes; the SSH mpint
     *     sign bytes are stripped on parse and re-added on serialize)
     *   dsa     → 40-byte `r || s`
     *   rsa     → the RSASSA-PKCS1-v1_5 signature as stored
     */
    readonly signatureBytes: Uint8Array;
    private constructor();
    /** Parses the PEM-armoured `sshsig` text, as `ssh_key::SshSig::from_pem`. */
    static fromPem(text: string): SSHSignature;
    /** Parses the binary `sshsig` blob (the base64 payload of the text form). */
    static fromBlob(blob: Uint8Array): SSHSignature;
    /** The PEM-armoured text, wrapped at 70 columns like OpenSSH. */
    toPem(): string;
    /** The binary `sshsig` blob, byte for byte as OpenSSH writes it. */
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
    /**
     * Construct from already-decoded parts (used by the sign path).
     *
     * `signatureAlgorithm` defaults to the key's wire name; for an RSA key it
     * defaults to `rsa-sha2-512`, the algorithm `ssh-key`'s RSA signer names.
     */
    static fromParts(publicKey: SSHPublicKey, namespace: string, hashAlgorithm: SshHashAlgorithm, signatureBytes: Uint8Array, signatureAlgorithm?: string): SSHSignature;
    /** Fixed-string mirror of the reference's summarizer for `TAG_SSH_TEXT_SIGNATURE`. */
    toString(): string;
    /** SHA-256 digest of canonical PEM bytes — kept for parity with key types. */
    digest(): Uint8Array;
}

/** The parts of an `sshsig` signature `verifySshSignature` needs. */
declare interface SshSignatureParts {
    /** The key embedded in the signature. */
    publicKey: SSHPublicKey;
    /** The namespace the signature was made in. */
    namespace: string;
    /** The hash the message was digested with. */
    hashAlgorithm: "sha256" | "sha512";
    /** The algorithm name inside the signature blob (`rsa-sha2-256`, `ssh-ed25519`, …). */
    signatureAlgorithm: string;
    /** The raw algorithm-specific signature bytes. */
    signatureBytes: Uint8Array;
}

/**
 * Symmetric key for ChaCha20-Poly1305 AEAD encryption (32 bytes)
 *
 * A symmetric encryption key used for both encryption and decryption.
 *
 * `SymmetricKey` is a 32-byte cryptographic key used with ChaCha20-Poly1305
 * AEAD (Authenticated Encryption with Associated Data) encryption. This
 * implementation follows the IETF ChaCha20-Poly1305 specification as defined
 * in [RFC-8439](https://datatracker.ietf.org/doc/html/rfc8439).
 *
 * Symmetric encryption uses the same key for both encryption and decryption,
 * unlike asymmetric encryption where different keys are used for each
 * operation.
 *
 * # CBOR Serialization
 *
 * `SymmetricKey` is serialized to CBOR with tag 40023.
 */
declare class SymmetricKey implements ToCbor {
    /** The byte length of a `SymmetricKey`. */
    static readonly SYMMETRIC_KEY_SIZE: number;
    private readonly _data;
    private constructor();
    /** A fresh random value; pass `rng` to make it deterministic. */
    static random({ rng }?: RngOptions): SymmetricKey;
    /**
     * Create a new symmetric key from data.
     */
    static from(data: Uint8Array): SymmetricKey;
    /**
     * Create a SymmetricKey from hex string.
     */
    static fromHex(hex: string): SymmetricKey;
    /** The bytes (a view; do not mutate). */
    /** A copy of the bytes; mutating it does not touch this value. */
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
    /** The reference: the digest of the tagged CBOR, as the reference computes it. */
    reference(): Reference;
    /** The first four bytes of `reference()` in hex, the reference's `ref_hex_short`. */
    refHexShort(): string;
    /** The reference's `Display`: the type name over the short reference. */
    toString(): string;
    /**
     * Encrypt the given plaintext with this key, and the given additional
     * authenticated data and nonce.
     */
    encrypt(plaintext: Uint8Array, { aad, nonce }?: {
        aad?: Uint8Array;
        nonce?: Nonce;
    }): EncryptedMessage;
    /**
     * Decrypt the given encrypted message with this key.
     */
    decrypt(message: EncryptedMessage): Uint8Array;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<SymmetricKey>;
    /** The CBOR tags this type decodes from; the first one is used to encode. */
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

export { }
