import { Cbor } from '@blockchaincommons/dcbor';
import { CborCodec } from '@blockchaincommons/dcbor';
import { RandomNumberGenerator } from '@blockchaincommons/rand';
import { RngOptions } from '@blockchaincommons/rand';
import { Tag } from '@blockchaincommons/dcbor';
import { ToCbor } from '@blockchaincommons/dcbor';
import { ToUR } from '@blockchaincommons/uniform-resources';
import { UR } from '@blockchaincommons/uniform-resources';

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
 * Key sizes for each ML-DSA security level.
 */
export declare const MLDSA_KEY_SIZES: Readonly<Record<MLDSALevel, MLDSASizes>>;

/**
 * Generate an ML-DSA keypair for the given security level.
 *
 * @param level - The ML-DSA security level
 * @returns Object containing publicKey and secretKey bytes
 */
export declare function mldsaGenerateKeypair(level: MLDSALevel): MLDSAKeypairData;

/**
 * Generate an ML-DSA keypair using a provided RNG.
 *
 * @param level - The ML-DSA security level
 * @param rng - Random number generator
 * @returns Object containing publicKey and secretKey bytes
 */
export declare function mldsaGenerateKeypairUsing(level: MLDSALevel, rng: RandomNumberGenerator): MLDSAKeypairData;

/**
 * Internal type for ML-DSA keypair generation result.
 */
export declare interface MLDSAKeypairData {
    /** The public key bytes. */
    publicKey: Uint8Array;
    /** The secret key bytes. */
    secretKey: Uint8Array;
}

/**
 * ML-DSA security levels.
 *
 * The numeric values correspond to NIST security levels:
 * - 2: NIST Level 2 (MLDSA44)
 * - 3: NIST Level 3 (MLDSA65)
 * - 5: NIST Level 5 (MLDSA87)
 */
export declare const MLDSALevel: Readonly<{
    /** ML-DSA-44 (NIST security category 2); the CBOR discriminator is 2. */
    readonly MLDSA44: 2;
    /** ML-DSA-65 (category 3); the CBOR discriminator is 3. */
    readonly MLDSA65: 3;
    /** ML-DSA-87 (category 5); the CBOR discriminator is 5. */
    readonly MLDSA87: 5;
}>;

/** One of the `MLDSALevel` values. */
export declare type MLDSALevel = (typeof MLDSALevel)[keyof typeof MLDSALevel];

/**
 * Parse an ML-DSA level from its numeric value.
 */
export declare function mldsaLevelFromValue(value: number): MLDSALevel;

/**
 * Convert an ML-DSA level to its string representation.
 */
export declare function mldsaLevelToString(level: MLDSALevel): string;

/**
 * MLDSAPrivateKey - Post-quantum signing private key using ML-DSA.
 */
export declare class MLDSAPrivateKey implements ToCbor, ToUR {
    private readonly _level;
    private readonly _data;
    private constructor();
    /** A fresh private key at `level`; pass `rng` to make it deterministic. */
    static random(level?: MLDSALevel, { rng }?: RngOptions): MLDSAPrivateKey;
    /**
     * Create an MLDSAPrivateKey from raw bytes.
     *
     * @param level - The ML-DSA security level
     * @param data - The private key bytes
     */
    static fromBytes(level: MLDSALevel, data: Uint8Array): MLDSAPrivateKey;
    /** A fresh private key at `level` and its public key. */
    static keypair(level?: MLDSALevel, { rng }?: RngOptions): [MLDSAPrivateKey, MLDSAPublicKey];
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
    /** The reference: the digest of the tagged CBOR, as the reference computes it. */
    reference(): Reference;
    /** The first four bytes of `reference()` in hex, the reference's `ref_hex_short`. */
    refHexShort(): string;
    /** The reference's `Display`: the type name over the short reference. */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<MLDSAPrivateKey>;
    /** The CBOR tags this type decodes from; the first one is used to encode. */
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

export declare function mldsaPrivateKeySize(level: MLDSALevel): number;

/**
 * MLDSAPublicKey - Post-quantum signature verification key using ML-DSA.
 */
export declare class MLDSAPublicKey implements ToCbor, ToUR {
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
    /** The reference: the digest of the tagged CBOR, as the reference computes it. */
    reference(): Reference;
    /** The first four bytes of `reference()` in hex, the reference's `ref_hex_short`. */
    refHexShort(): string;
    /** The reference's `Display`: the type name over the short reference. */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<MLDSAPublicKey>;
    /** The CBOR tags this type decodes from; the first one is used to encode. */
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
 * Get the public key size for a given ML-DSA level.
 */
export declare function mldsaPublicKeySize(level: MLDSALevel): number;

/**
 * Sign a message using ML-DSA.
 *
 * @param level - The ML-DSA security level
 * @param secretKey - The secret key bytes
 * @param message - The message to sign
 * @returns The signature bytes
 */
export declare function mldsaSign(level: MLDSALevel, secretKey: Uint8Array, message: Uint8Array): Uint8Array;

/**
 * MLDSASignature - Post-quantum digital signature using ML-DSA.
 */
export declare class MLDSASignature implements ToCbor, ToUR {
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
    /** The CBOR tags this type decodes from; the first one is used to encode. */
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
 * Get the signature size for a given ML-DSA level.
 */
export declare function mldsaSignatureSize(level: MLDSALevel): number;

/** The byte lengths of an ML-DSA level's objects. */
export declare interface MLDSASizes {
    /** The private (secret) key length. */
    readonly privateKey: number;
    /** The public key length. */
    readonly publicKey: number;
    /** The signature length. */
    readonly signature: number;
}

/**
 * Verify a signature using ML-DSA.
 *
 * @param level - The ML-DSA security level
 * @param publicKey - The public key bytes
 * @param message - The message that was signed
 * @param signature - The signature to verify
 * @returns True if the signature is valid
 */
export declare function mldsaVerify(level: MLDSALevel, publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;

/**
 * Key sizes for each ML-KEM security level.
 */
export declare const MLKEM_KEY_SIZES: Readonly<Record<MLKEMLevel, MLKEMSizes>>;

/**
 * MLKEMCiphertext - Post-quantum key encapsulation ciphertext using ML-KEM.
 */
export declare class MLKEMCiphertext implements ToCbor, ToUR {
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
    /** The CBOR tags this type decodes from; the first one is used to encode. */
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
 * Get the ciphertext size for a given ML-KEM level.
 */
export declare function mlkemCiphertextSize(level: MLKEMLevel): number;

/**
 * Decapsulate a shared secret using a private key and ciphertext.
 *
 * @param level - The ML-KEM security level
 * @param secretKey - The secret key bytes
 * @param ciphertext - The ciphertext bytes
 * @returns The shared secret bytes
 */
export declare function mlkemDecapsulate(level: MLKEMLevel, secretKey: Uint8Array, ciphertext: Uint8Array): Uint8Array;

/**
 * Encapsulate a new shared secret using a public key.
 *
 * @param level - The ML-KEM security level
 * @param publicKey - The public key bytes
 * @returns Object containing sharedSecret and ciphertext bytes
 */
export declare function mlkemEncapsulate(level: MLKEMLevel, publicKey: Uint8Array, seed?: Uint8Array): MLKEMEncapsulationResult;

/**
 * Result of encapsulation operation.
 */
export declare interface MLKEMEncapsulationPair {
    /** The shared secret as a SymmetricKey */
    sharedSecret: SymmetricKey;
    /** The ciphertext to send to the private key holder */
    ciphertext: MLKEMCiphertext;
}

/**
 * Internal type for ML-KEM encapsulation result.
 */
export declare interface MLKEMEncapsulationResult {
    /** The 32-byte shared secret. */
    sharedSecret: Uint8Array;
    /** The ciphertext the recipient decapsulates. */
    ciphertext: Uint8Array;
}

/**
 * Generate an ML-KEM keypair for the given security level.
 *
 * @param level - The ML-KEM security level
 * @returns Object containing publicKey and secretKey bytes
 */
export declare function mlkemGenerateKeypair(level: MLKEMLevel): MLKEMKeypairData;

/**
 * Generate an ML-KEM keypair using a provided RNG.
 *
 * @param level - The ML-KEM security level
 * @param rng - Random number generator
 * @returns Object containing publicKey and secretKey bytes
 */
export declare function mlkemGenerateKeypairUsing(level: MLKEMLevel, rng: RandomNumberGenerator): MLKEMKeypairData;

/**
 * Internal type for ML-KEM keypair generation result.
 */
export declare interface MLKEMKeypairData {
    /** The public key bytes. */
    publicKey: Uint8Array;
    /** The secret key bytes. */
    secretKey: Uint8Array;
}

/**
 * ML-KEM security levels.
 *
 * The numeric values correspond to the ML-KEM parameter set:
 * - 512: ML-KEM-512 (NIST Level 1)
 * - 768: ML-KEM-768 (NIST Level 3)
 * - 1024: ML-KEM-1024 (NIST Level 5)
 */
export declare const MLKEMLevel: Readonly<{
    /** ML-KEM-512; the CBOR discriminator is 512. */
    readonly MLKEM512: 512;
    /** ML-KEM-768; the CBOR discriminator is 768. */
    readonly MLKEM768: 768;
    /** ML-KEM-1024; the CBOR discriminator is 1024. */
    readonly MLKEM1024: 1024;
}>;

/** One of the `MLKEMLevel` values. */
export declare type MLKEMLevel = (typeof MLKEMLevel)[keyof typeof MLKEMLevel];

/**
 * Parse an ML-KEM level from its numeric value.
 */
export declare function mlkemLevelFromValue(value: number): MLKEMLevel;

/**
 * Convert an ML-KEM level to its string representation.
 */
export declare function mlkemLevelToString(level: MLKEMLevel): string;

/**
 * MLKEMPrivateKey - Post-quantum key decapsulation private key using ML-KEM.
 */
export declare class MLKEMPrivateKey implements ToCbor, ToUR {
    private readonly _level;
    private readonly _data;
    private constructor();
    /** A fresh private key at `level`; pass `rng` to make it deterministic. */
    static random(level?: MLKEMLevel, { rng }?: RngOptions): MLKEMPrivateKey;
    /**
     * Create an MLKEMPrivateKey from raw bytes.
     *
     * @param level - The ML-KEM security level
     * @param data - The private key bytes
     */
    static fromBytes(level: MLKEMLevel, data: Uint8Array): MLKEMPrivateKey;
    /** A fresh private key at `level` and its public key. */
    static keypair(level?: MLKEMLevel, { rng }?: RngOptions): [MLKEMPrivateKey, MLKEMPublicKey];
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
    /** The reference: the digest of the tagged CBOR, as the reference computes it. */
    reference(): Reference;
    /** The first four bytes of `reference()` in hex, the reference's `ref_hex_short`. */
    refHexShort(): string;
    /** The reference's `Display`: the type name over the short reference. */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<MLKEMPrivateKey>;
    /** The CBOR tags this type decodes from; the first one is used to encode. */
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

export declare function mlkemPrivateKeySize(level: MLKEMLevel): number;

/**
 * MLKEMPublicKey - Post-quantum key encapsulation public key using ML-KEM.
 */
export declare class MLKEMPublicKey implements ToCbor, ToUR {
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
    encapsulate({ rng }?: RngOptions): MLKEMEncapsulationPair;
    /**
     * Compare with another MLKEMPublicKey.
     */
    equals(other: MLKEMPublicKey): boolean;
    /**
     * Get string representation.
     */
    /** The reference: the digest of the tagged CBOR, as the reference computes it. */
    reference(): Reference;
    /** The first four bytes of `reference()` in hex, the reference's `ref_hex_short`. */
    refHexShort(): string;
    /** The reference's `Display`: the type name over the short reference. */
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static get codec(): ComponentCodec<MLKEMPublicKey>;
    /** The CBOR tags this type decodes from; the first one is used to encode. */
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

/**
 * Get the public key size for a given ML-KEM level.
 */
export declare function mlkemPublicKeySize(level: MLKEMLevel): number;

/**
 * Get the shared secret size for a given ML-KEM level.
 * Note: This is always 32 bytes for all ML-KEM levels.
 */
export declare function mlkemSharedSecretSize(level: MLKEMLevel): number;

/** The byte lengths of an ML-KEM level's objects. */
export declare interface MLKEMSizes {
    /** The private (decapsulation) key length. */
    readonly privateKey: number;
    /** The public (encapsulation) key length. */
    readonly publicKey: number;
    /** The ciphertext length. */
    readonly ciphertext: number;
    /** The shared secret length (always 32). */
    readonly sharedSecret: number;
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
