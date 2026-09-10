import { Cbor } from '@blockchaincommons/dcbor';
import { CborCodec } from '@blockchaincommons/dcbor';
import { RandomNumberGenerator } from '@blockchaincommons/rand';
import { Tag } from '@blockchaincommons/dcbor';
import { ToCbor } from '@blockchaincommons/dcbor';
import { ToUR } from '@blockchaincommons/uniform-resources';
import { UR } from '@blockchaincommons/uniform-resources';

declare class AuthenticationTag {
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

declare class Digest implements DigestProvider, ToCbor, ToUR {
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
    static readonly codec: ComponentCodec<Digest>;
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
    static readonly codec: ComponentCodec<EncryptedMessage>;
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
export declare const MLDSA_KEY_SIZES: Readonly<Record<MLDSALevel, {
    privateKey: number;
    publicKey: number;
    signature: number;
}>>;

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
    publicKey: Uint8Array;
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
export declare enum MLDSALevel {
    /** NIST Level 2 - AES-128 equivalent security */
    MLDSA44 = 2,
    /** NIST Level 3 - AES-192 equivalent security */
    MLDSA65 = 3,
    /** NIST Level 5 - AES-256 equivalent security */
    MLDSA87 = 5
}

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
    static readonly codec: ComponentCodec<MLDSAPrivateKey>;
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
 * Get the private key size for a given ML-DSA level.
 */
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
    toString(): string;
    /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
    static readonly codec: ComponentCodec<MLDSAPublicKey>;
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
    static readonly codec: ComponentCodec<MLDSASignature>;
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
export declare const MLKEM_KEY_SIZES: Readonly<Record<MLKEMLevel, {
    privateKey: number;
    publicKey: number;
    ciphertext: number;
    sharedSecret: number;
}>>;

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
    static readonly codec: ComponentCodec<MLKEMCiphertext>;
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
export declare function mlkemEncapsulate(level: MLKEMLevel, publicKey: Uint8Array): MLKEMEncapsulationResult;

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
    sharedSecret: Uint8Array;
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
    publicKey: Uint8Array;
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
export declare enum MLKEMLevel {
    /** NIST Level 1 - AES-128 equivalent security */
    MLKEM512 = 512,
    /** NIST Level 3 - AES-192 equivalent security */
    MLKEM768 = 768,
    /** NIST Level 5 - AES-256 equivalent security */
    MLKEM1024 = 1024
}

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
    static readonly codec: ComponentCodec<MLKEMPrivateKey>;
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
 * Get the private key size for a given ML-KEM level.
 */
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
    static readonly codec: ComponentCodec<MLKEMPublicKey>;
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

declare class Nonce implements ToCbor, ToUR {
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
    static readonly codec: ComponentCodec<Nonce>;
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

declare class SymmetricKey implements ToCbor {
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
    static readonly codec: ComponentCodec<SymmetricKey>;
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
