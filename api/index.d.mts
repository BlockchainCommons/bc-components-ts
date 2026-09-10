import { Cbor, CborMap, CborTagged, Tag } from "@blockchaincommons/dcbor";
import { COMPRESSED, ENCRYPTED, ENVELOPE, KNOWN_VALUE, LEAF } from "@blockchaincommons/tags";
import { UR } from "@blockchaincommons/uniform-resources";
import { RandomNumberGenerator } from "@blockchaincommons/rand";
import { GroupSpec as SSKRGroupSpec, Secret as SSKRSecret, Spec as SSKRSpec } from "@blockchaincommons/sskr";
//#region src/error.d.ts
/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * Error types for cryptographic and component operations
 *
 * Ported from bc-components-rust/src/error.rs
 *
 * This module provides a unified error handling system that matches the Rust
 * implementation's error variants with full structural parity:
 *
 * - InvalidSize: Invalid data size for the specified type
 * - InvalidData: Invalid data format or content
 * - DataTooShort: Data too short for the expected type
 * - Crypto: Cryptographic operation failed
 * - Cbor: CBOR encoding or decoding error
 * - Sskr: SSKR error
 * - Ssh: SSH key operation failed
 * - Uri: URI parsing failed
 * - Compression: Data compression/decompression failed
 * - PostQuantum: Post-quantum cryptography library error
 * - LevelMismatch: Signature level mismatch
 * - SshAgent: SSH agent operation failed
 * - Hex: Hex decoding error
 * - Utf8: UTF-8 conversion error
 * - Env: Environment variable error
 * - SshAgentClient: SSH agent client error
 * - General: General error with custom message
 */
/**
 * Error kind enum matching Rust's Error variants.
 *
 * This enum allows programmatic checking of error types, matching the
 * Rust enum variants exactly.
 */
declare enum ErrorKind {
  /** Invalid data size for the specified type */
  InvalidSize = "InvalidSize",
  /** Invalid data format or content */
  InvalidData = "InvalidData",
  /** Data too short for the expected type */
  DataTooShort = "DataTooShort",
  /** Cryptographic operation failed */
  Crypto = "Crypto",
  /** CBOR encoding or decoding error */
  Cbor = "Cbor",
  /** SSKR error */
  Sskr = "Sskr",
  /** SSH key operation failed */
  Ssh = "Ssh",
  /** URI parsing failed */
  Uri = "Uri",
  /** Data compression/decompression failed */
  Compression = "Compression",
  /** Post-quantum cryptography library error */
  PostQuantum = "PostQuantum",
  /** Signature level mismatch */
  LevelMismatch = "LevelMismatch",
  /** SSH agent operation failed */
  SshAgent = "SshAgent",
  /** Hex decoding error */
  Hex = "Hex",
  /** UTF-8 conversion error */
  Utf8 = "Utf8",
  /** Environment variable error */
  Env = "Env",
  /** SSH agent client error */
  SshAgentClient = "SshAgentClient",
  /** General error with custom message */
  General = "General"
}
/**
 * Structured data for InvalidSize errors.
 */
interface InvalidSizeData {
  dataType: string;
  expected: number;
  actual: number;
}
/**
 * Structured data for InvalidData errors.
 */
interface InvalidDataData {
  dataType: string;
  reason: string;
}
/**
 * Structured data for DataTooShort errors.
 */
interface DataTooShortData {
  dataType: string;
  minimum: number;
  actual: number;
}
/**
 * Union type for all possible error data.
 */
type ErrorData = ({
  kind: ErrorKind.InvalidSize;
} & InvalidSizeData) | ({
  kind: ErrorKind.InvalidData;
} & InvalidDataData) | ({
  kind: ErrorKind.DataTooShort;
} & DataTooShortData) | {
  kind: ErrorKind.Crypto;
  message: string;
} | {
  kind: ErrorKind.Cbor;
  message: string;
} | {
  kind: ErrorKind.Sskr;
  message: string;
} | {
  kind: ErrorKind.Ssh;
  message: string;
} | {
  kind: ErrorKind.Uri;
  message: string;
} | {
  kind: ErrorKind.Compression;
  message: string;
} | {
  kind: ErrorKind.PostQuantum;
  message: string;
} | {
  kind: ErrorKind.LevelMismatch;
} | {
  kind: ErrorKind.SshAgent;
  message: string;
} | {
  kind: ErrorKind.Hex;
  message: string;
} | {
  kind: ErrorKind.Utf8;
  message: string;
} | {
  kind: ErrorKind.Env;
  message: string;
} | {
  kind: ErrorKind.SshAgentClient;
  message: string;
} | {
  kind: ErrorKind.General;
  message: string;
};
/**
 * Error type for cryptographic and component operations.
 *
 * This class provides full structural parity with the Rust Error enum,
 * including:
 * - An `errorKind` property for programmatic error type checking
 * - Structured `errorData` for accessing error-specific fields
 * - Factory methods matching Rust's impl block
 */
declare class CryptoError extends Error {
  /** The error kind for programmatic type checking */
  readonly errorKind: ErrorKind;
  /** Structured error data matching Rust's error variants */
  readonly errorData: ErrorData;
  private constructor();
  /**
   * Create an invalid size error.
   *
   * Rust equivalent: `Error::InvalidSize { data_type, expected, actual }`
   *
   * @param expected - The expected size
   * @param actual - The actual size received
   */
  static invalidSize(expected: number, actual: number): CryptoError;
  /**
   * Create an invalid size error with a data type name.
   *
   * Rust equivalent: `Error::invalid_size(data_type, expected, actual)`
   *
   * @param dataType - The name of the data type
   * @param expected - The expected size
   * @param actual - The actual size received
   */
  static invalidSizeForType(dataType: string, expected: number, actual: number): CryptoError;
  /**
   * Create an invalid data error.
   *
   * @param message - Description of what's invalid
   */
  static invalidData(message: string): CryptoError;
  /**
   * Create an invalid data error with a data type name.
   *
   * Rust equivalent: `Error::invalid_data(data_type, reason)`
   *
   * @param dataType - The name of the data type
   * @param reason - The reason the data is invalid
   */
  static invalidDataForType(dataType: string, reason: string): CryptoError;
  /**
   * Create a data too short error.
   *
   * Rust equivalent: `Error::data_too_short(data_type, minimum, actual)`
   *
   * @param dataType - The name of the data type
   * @param minimum - The minimum required size
   * @param actual - The actual size received
   */
  static dataTooShort(dataType: string, minimum: number, actual: number): CryptoError;
  /**
   * Create an invalid format error.
   *
   * @param message - Description of the format error
   */
  static invalidFormat(message: string): CryptoError;
  /**
   * Create an invalid input error.
   *
   * @param message - Description of the invalid input
   */
  static invalidInput(message: string): CryptoError;
  /**
   * Create a cryptographic operation failed error.
   *
   * Rust equivalent: `Error::crypto(msg)`
   *
   * @param message - Description of the failure
   */
  static cryptoOperation(message: string): CryptoError;
  /**
   * Create a crypto error.
   *
   * Rust equivalent: `Error::Crypto(msg)`
   *
   * @param message - Description of the failure
   */
  static crypto(message: string): CryptoError;
  /**
   * Create a post-quantum cryptography error.
   *
   * Rust equivalent: `Error::post_quantum(msg)`
   *
   * @param message - Description of the failure
   */
  static postQuantum(message: string): CryptoError;
  /**
   * Create a signature level mismatch error.
   *
   * Rust equivalent: `Error::LevelMismatch`
   */
  static levelMismatch(): CryptoError;
  /**
   * Create a CBOR error.
   *
   * Rust equivalent: `Error::Cbor(err)`
   *
   * @param message - Description of the CBOR error
   */
  static cbor(message: string): CryptoError;
  /**
   * Create a hex decoding error.
   *
   * Rust equivalent: `Error::Hex(err)`
   *
   * @param message - Description of the hex error
   */
  static hex(message: string): CryptoError;
  /**
   * Create a UTF-8 conversion error.
   *
   * Rust equivalent: `Error::Utf8(err)`
   *
   * @param message - Description of the UTF-8 error
   */
  static utf8(message: string): CryptoError;
  /**
   * Create a compression error.
   *
   * Rust equivalent: `Error::compression(msg)`
   *
   * @param message - Description of the compression error
   */
  static compression(message: string): CryptoError;
  /**
   * Create a URI parsing error.
   *
   * Rust equivalent: `Error::Uri(err)`
   *
   * @param message - Description of the URI error
   */
  static uri(message: string): CryptoError;
  /**
   * Create an SSKR error.
   *
   * Rust equivalent: `Error::Sskr(err)`
   *
   * @param message - Description of the SSKR error
   */
  static sskr(message: string): CryptoError;
  /**
   * Create an SSH operation error.
   *
   * Rust equivalent: `Error::ssh(msg)`
   *
   * @param message - Description of the SSH error
   */
  static ssh(message: string): CryptoError;
  /**
   * Create an SSH agent error.
   *
   * Rust equivalent: `Error::ssh_agent(msg)`
   *
   * @param message - Description of the SSH agent error
   */
  static sshAgent(message: string): CryptoError;
  /**
   * Create an SSH agent client error.
   *
   * Rust equivalent: `Error::ssh_agent_client(msg)`
   *
   * @param message - Description of the SSH agent client error
   */
  static sshAgentClient(message: string): CryptoError;
  /**
   * Create an environment variable error.
   *
   * Rust equivalent: `Error::Env(err)`
   *
   * @param message - Description of the environment error
   */
  static env(message: string): CryptoError;
  /**
   * Create a general error with a custom message.
   *
   * Rust equivalent: `Error::general(msg)` / `Error::General(msg)`
   *
   * @param message - The error message
   */
  static general(message: string): CryptoError;
  /**
   * Check if this error is of a specific kind.
   *
   * @param kind - The error kind to check
   */
  isKind(kind: ErrorKind): boolean;
  /**
   * Check if this is an InvalidSize error.
   */
  isInvalidSize(): this is CryptoError & {
    errorData: InvalidSizeData & {
      kind: ErrorKind.InvalidSize;
    };
  };
  /**
   * Check if this is an InvalidData error.
   */
  isInvalidData(): this is CryptoError & {
    errorData: InvalidDataData & {
      kind: ErrorKind.InvalidData;
    };
  };
  /**
   * Check if this is a DataTooShort error.
   */
  isDataTooShort(): this is CryptoError & {
    errorData: DataTooShortData & {
      kind: ErrorKind.DataTooShort;
    };
  };
  /**
   * Check if this is a Crypto error.
   */
  isCrypto(): boolean;
  /**
   * Check if this is a Cbor error.
   */
  isCbor(): boolean;
  /**
   * Check if this is an Sskr error.
   */
  isSskr(): boolean;
  /**
   * Check if this is an Ssh error.
   */
  isSsh(): boolean;
  /**
   * Check if this is a Uri error.
   */
  isUri(): boolean;
  /**
   * Check if this is a Compression error.
   */
  isCompression(): boolean;
  /**
   * Check if this is a PostQuantum error.
   */
  isPostQuantum(): boolean;
  /**
   * Check if this is a LevelMismatch error.
   */
  isLevelMismatch(): boolean;
  /**
   * Check if this is an SshAgent error.
   */
  isSshAgent(): boolean;
  /**
   * Check if this is a Hex error.
   */
  isHex(): boolean;
  /**
   * Check if this is a Utf8 error.
   */
  isUtf8(): boolean;
  /**
   * Check if this is an Env error.
   */
  isEnv(): boolean;
  /**
   * Check if this is an SshAgentClient error.
   */
  isSshAgentClient(): boolean;
  /**
   * Check if this is a General error.
   */
  isGeneral(): boolean;
}
/**
 * Result type that can be either a success value or an Error.
 */
type Result<T> = T | Error;
/**
 * Type guard to check if a result is an Error.
 */
declare function isError(result: unknown): result is Error;
/**
 * Type guard to check if a result is a CryptoError.
 */
declare function isCryptoError(result: unknown): result is CryptoError;
/**
 * Type guard to check if an error is a CryptoError of a specific kind.
 */
declare function isCryptoErrorKind(result: unknown, kind: ErrorKind): result is CryptoError;
//#endregion
//#region src/private-key-data-provider.d.ts
/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * A trait for types that can provide unique data for cryptographic key derivation.
 *
 * Ported from bc-components-rust/src/private_key_data_provider.rs
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
interface PrivateKeyDataProvider {
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
 * Type guard to check if an object implements PrivateKeyDataProvider
 */
declare function isPrivateKeyDataProvider(obj: unknown): obj is PrivateKeyDataProvider;
//#endregion
//#region src/codable.d.ts
/** Encodes to tagged CBOR; the first tag is the one written. */
interface CborTaggedEncodable extends CborTagged {
  untaggedCbor(): Cbor;
  taggedCbor(): Cbor;
  taggedCborData?(): Uint8Array;
}
/** Decodes from tagged or untagged CBOR. */
interface CborTaggedDecodable<T> extends CborTagged {
  fromUntaggedCbor(cbor: Cbor): T;
  fromTaggedCbor(cbor: Cbor): T;
  fromTaggedCborData?(data: Uint8Array): T;
  fromUntaggedCborData?(data: Uint8Array): T;
}
/** Presents itself as a UR. */
interface UREncodable {
  ur(): UR;
  urString(): string;
}
//#endregion
//#region src/x25519/x25519-public-key.d.ts
declare class X25519PublicKey implements CborTaggedEncodable, CborTaggedDecodable<X25519PublicKey>, UREncodable {
  static readonly KEY_SIZE: number;
  private readonly _data;
  private constructor();
  /**
   * Restore an X25519PublicKey from a fixed-size array of bytes.
   */
  static fromData(data: Uint8Array): X25519PublicKey;
  /**
   * Restore an X25519PublicKey from a reference to an array of bytes.
   * Validates the length.
   */
  static fromDataRef(data: Uint8Array): X25519PublicKey;
  /**
   * Create an X25519PublicKey from raw bytes (legacy alias).
   */
  static from(data: Uint8Array): X25519PublicKey;
  /**
   * Restore an X25519PublicKey from a hex string.
   */
  static fromHex(hex: string): X25519PublicKey;
  /**
   * Get a reference to the fixed-size array of bytes.
   */
  data(): Uint8Array;
  /**
   * Get the raw public key bytes (copy).
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
   * Compare with another X25519PublicKey.
   */
  equals(other: X25519PublicKey): boolean;
  /**
   * Get string representation.
   *
   * Mirrors Rust `Display for X25519PublicKey`
   * (`bc-components-rust/src/x25519/x25519_public_key.rs:166-168`):
   *   `X25519PublicKey(<ref_hex_short>)` where the reference is
   *   computed from the **tagged-CBOR** form of the key.
   */
  toString(): string;
  /**
   * Returns the CBOR tags associated with X25519PublicKey.
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
   * Creates an X25519PublicKey by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cbor: Cbor): X25519PublicKey;
  /**
   * Creates an X25519PublicKey by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cbor: Cbor): X25519PublicKey;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cbor: Cbor): X25519PublicKey;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): X25519PublicKey;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): X25519PublicKey;
  /**
   * Returns the UR representation of the X25519PublicKey.
   * Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates an X25519PublicKey from a UR.
   */
  static fromUR(ur: UR): X25519PublicKey;
  /**
   * Creates an X25519PublicKey from a UR string.
   */
  static fromURString(urString: string): X25519PublicKey;
}
//#endregion
//#region src/nonce.d.ts
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
//#endregion
//#region src/digest-provider.d.ts
/**
 * A type that can provide a single unique digest that characterizes its contents.
 *
 * Use Cases:
 * - Data integrity verification
 * - Unique identifier for an object based on its content
 * - Content-addressable storage implementation
 * - Comparing objects by their content rather than identity
 */
interface DigestProvider {
  /**
   * Returns a digest that uniquely characterizes the content of the
   * implementing type.
   */
  digest(): Digest;
}
/**
 * Helper function to get a digest from a byte array.
 * This provides DigestProvider-like functionality for raw bytes.
 *
 * @param data - The byte array to hash
 * @returns A Promise resolving to a Digest of the data
 */
declare function digestFromBytes(data: Uint8Array): Promise<Digest>;
//#endregion
//#region src/digest.d.ts
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
//#endregion
//#region src/symmetric/authentication-tag.d.ts
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
//#endregion
//#region src/symmetric/encrypted-message.d.ts
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
//#endregion
//#region src/symmetric/symmetric-key.d.ts
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
//#endregion
//#region src/x25519/x25519-private-key.d.ts
declare class X25519PrivateKey implements CborTaggedEncodable, CborTaggedDecodable<X25519PrivateKey>, UREncodable {
  static readonly KEY_SIZE: number;
  private readonly _data;
  private _publicKey?;
  private constructor();
  /**
   * Generate a new random X25519PrivateKey.
   */
  static new(): X25519PrivateKey;
  /**
   * Generate a new random X25519PrivateKey.
   */
  static random(): X25519PrivateKey;
  /**
   * Generate a new random X25519PrivateKey using provided RNG.
   */
  static newUsing(rng: RandomNumberGenerator): X25519PrivateKey;
  /**
   * Generate a new random X25519PrivateKey and corresponding X25519PublicKey.
   */
  static keypair(): [X25519PrivateKey, X25519PublicKey];
  /**
   * Generate a new random X25519PrivateKey and corresponding X25519PublicKey
   * using the given random number generator.
   */
  static keypairUsing(rng: RandomNumberGenerator): [X25519PrivateKey, X25519PublicKey];
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
  static fromData(data: Uint8Array): X25519PrivateKey;
  /**
   * Restore an X25519PrivateKey from a reference to an array of bytes.
   * Validates the length.
   */
  static fromDataRef(data: Uint8Array): X25519PrivateKey;
  /**
   * Create an X25519PrivateKey from raw bytes (legacy alias).
   */
  static from(data: Uint8Array): X25519PrivateKey;
  /**
   * Restore an X25519PrivateKey from a hex string.
   */
  static fromHex(hex: string): X25519PrivateKey;
  /**
   * Get a reference to the fixed-size array of bytes.
   */
  data(): Uint8Array;
  /**
   * Get the raw private key bytes (copy).
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
  /**
   * Returns the CBOR tags associated with X25519PrivateKey.
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
   * Creates an X25519PrivateKey by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cbor: Cbor): X25519PrivateKey;
  /**
   * Creates an X25519PrivateKey by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cbor: Cbor): X25519PrivateKey;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cbor: Cbor): X25519PrivateKey;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): X25519PrivateKey;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): X25519PrivateKey;
  /**
   * Returns the UR representation of the X25519PrivateKey.
   * Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates an X25519PrivateKey from a UR.
   */
  static fromUR(ur: UR): X25519PrivateKey;
  /**
   * Creates an X25519PrivateKey from a UR string.
   */
  static fromURString(urString: string): X25519PrivateKey;
}
//#endregion
//#region src/mlkem/mlkem-level.d.ts
/**
 * ML-KEM security levels.
 *
 * The numeric values correspond to the ML-KEM parameter set:
 * - 512: ML-KEM-512 (NIST Level 1)
 * - 768: ML-KEM-768 (NIST Level 3)
 * - 1024: ML-KEM-1024 (NIST Level 5)
 */
declare enum MLKEMLevel {
  /** NIST Level 1 - AES-128 equivalent security */
  MLKEM512 = 512,
  /** NIST Level 3 - AES-192 equivalent security */
  MLKEM768 = 768,
  /** NIST Level 5 - AES-256 equivalent security */
  MLKEM1024 = 1024
}
/**
 * Key sizes for each ML-KEM security level.
 */
declare const MLKEM_KEY_SIZES: Readonly<Record<MLKEMLevel, {
  privateKey: number;
  publicKey: number;
  ciphertext: number;
  sharedSecret: number;
}>>;
/**
 * Get the private key size for a given ML-KEM level.
 */
declare function mlkemPrivateKeySize(level: MLKEMLevel): number;
/**
 * Get the public key size for a given ML-KEM level.
 */
declare function mlkemPublicKeySize(level: MLKEMLevel): number;
/**
 * Get the ciphertext size for a given ML-KEM level.
 */
declare function mlkemCiphertextSize(level: MLKEMLevel): number;
/**
 * Get the shared secret size for a given ML-KEM level.
 * Note: This is always 32 bytes for all ML-KEM levels.
 */
declare function mlkemSharedSecretSize(level: MLKEMLevel): number;
/**
 * Convert an ML-KEM level to its string representation.
 */
declare function mlkemLevelToString(level: MLKEMLevel): string;
/**
 * Parse an ML-KEM level from its numeric value.
 */
declare function mlkemLevelFromValue(value: number): MLKEMLevel;
/**
 * Internal type for ML-KEM keypair generation result.
 */
interface MLKEMKeypairData {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}
/**
 * Internal type for ML-KEM encapsulation result.
 */
interface MLKEMEncapsulationResult {
  sharedSecret: Uint8Array;
  ciphertext: Uint8Array;
}
/**
 * Generate an ML-KEM keypair for the given security level.
 *
 * @param level - The ML-KEM security level
 * @returns Object containing publicKey and secretKey bytes
 */
declare function mlkemGenerateKeypair(level: MLKEMLevel): MLKEMKeypairData;
/**
 * Generate an ML-KEM keypair using a provided RNG.
 *
 * @param level - The ML-KEM security level
 * @param rng - Random number generator
 * @returns Object containing publicKey and secretKey bytes
 */
declare function mlkemGenerateKeypairUsing(level: MLKEMLevel, rng: RandomNumberGenerator): MLKEMKeypairData;
/**
 * Encapsulate a new shared secret using a public key.
 *
 * @param level - The ML-KEM security level
 * @param publicKey - The public key bytes
 * @returns Object containing sharedSecret and ciphertext bytes
 */
declare function mlkemEncapsulate(level: MLKEMLevel, publicKey: Uint8Array): MLKEMEncapsulationResult;
/**
 * Decapsulate a shared secret using a private key and ciphertext.
 *
 * @param level - The ML-KEM security level
 * @param secretKey - The secret key bytes
 * @param ciphertext - The ciphertext bytes
 * @returns The shared secret bytes
 */
declare function mlkemDecapsulate(level: MLKEMLevel, secretKey: Uint8Array, ciphertext: Uint8Array): Uint8Array;
//#endregion
//#region src/mlkem/mlkem-ciphertext.d.ts
/**
 * MLKEMCiphertext - Post-quantum key encapsulation ciphertext using ML-KEM.
 */
declare class MLKEMCiphertext implements CborTaggedEncodable, CborTaggedDecodable<MLKEMCiphertext>, UREncodable {
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
  level(): MLKEMLevel;
  /**
   * Returns the raw ciphertext bytes.
   */
  asBytes(): Uint8Array;
  /**
   * Returns a copy of the raw ciphertext bytes.
   */
  data(): Uint8Array;
  /**
   * Returns the size of the ciphertext in bytes.
   */
  size(): number;
  /**
   * Compare with another MLKEMCiphertext.
   */
  equals(other: MLKEMCiphertext): boolean;
  /**
   * Get string representation.
   */
  toString(): string;
  /**
   * Returns the CBOR tags associated with MLKEMCiphertext.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: [level, ciphertext_bytes]
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
   * Creates an MLKEMCiphertext by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cborValue: Cbor): MLKEMCiphertext;
  /**
   * Creates an MLKEMCiphertext by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): MLKEMCiphertext;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): MLKEMCiphertext;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): MLKEMCiphertext;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): MLKEMCiphertext;
  /**
   * Returns the UR representation.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates an MLKEMCiphertext from a UR.
   */
  static fromUR(ur: UR): MLKEMCiphertext;
  /**
   * Creates an MLKEMCiphertext from a UR string.
   */
  static fromURString(urString: string): MLKEMCiphertext;
}
//#endregion
//#region src/mlkem/mlkem-public-key.d.ts
/**
 * Result of encapsulation operation.
 */
interface MLKEMEncapsulationPair {
  /** The shared secret as a SymmetricKey */
  sharedSecret: SymmetricKey;
  /** The ciphertext to send to the private key holder */
  ciphertext: MLKEMCiphertext;
}
/**
 * MLKEMPublicKey - Post-quantum key encapsulation public key using ML-KEM.
 */
declare class MLKEMPublicKey implements CborTaggedEncodable, CborTaggedDecodable<MLKEMPublicKey>, UREncodable {
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
  level(): MLKEMLevel;
  /**
   * Returns the raw key bytes.
   */
  asBytes(): Uint8Array;
  /**
   * Returns a copy of the raw key bytes.
   */
  data(): Uint8Array;
  /**
   * Returns the size of the key in bytes.
   */
  size(): number;
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
  /**
   * Returns the CBOR tags associated with MLKEMPublicKey.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: [level, key_bytes]
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
   * Creates an MLKEMPublicKey by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cborValue: Cbor): MLKEMPublicKey;
  /**
   * Creates an MLKEMPublicKey by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): MLKEMPublicKey;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): MLKEMPublicKey;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): MLKEMPublicKey;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): MLKEMPublicKey;
  /**
   * Returns the UR representation.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates an MLKEMPublicKey from a UR.
   */
  static fromUR(ur: UR): MLKEMPublicKey;
  /**
   * Creates an MLKEMPublicKey from a UR string.
   */
  static fromURString(urString: string): MLKEMPublicKey;
}
//#endregion
//#region src/reference.d.ts
/** Encoding format for short Reference identifiers. */
type ReferenceEncodingFormat = "hex" | "bytewords" | "bytemojis";
/**
 * Implementers of this interface provide a globally unique reference to themselves.
 *
 * Mirrors Rust's `ReferenceProvider` trait. The reference is derived from a
 * cryptographic digest of the object's serialized form, ensuring that it
 * uniquely identifies the object's contents.
 */
interface ReferenceProvider {
  /** Returns a cryptographic reference that uniquely identifies this object. */
  reference(): Reference;
}
/**
 * Type guard to check if an object implements the ReferenceProvider interface.
 */
declare function isReferenceProvider(obj: unknown): obj is ReferenceProvider;
/**
 * A globally unique reference to a globally unique object.
 *
 * Internally stores 32 raw bytes (matches Rust's `Reference([u8; 32])`).
 * Most callers obtain a `Reference` via `fromDigest`, but `XID` (and similar
 * content-addressable types whose bytes _are_ the reference) construct
 * via `fromData` directly.
 */
declare class Reference implements CborTaggedEncodable, CborTaggedDecodable<Reference>, DigestProvider, ReferenceProvider {
  /** Reference data size in bytes — matches Rust `Reference::REFERENCE_SIZE`. */
  static readonly REFERENCE_SIZE = 32;
  private readonly _data;
  private constructor();
  /** Create a Reference from exactly 32 bytes. Mirrors Rust `Reference::from_data`. */
  static fromData(data: Uint8Array): Reference;
  /** Alias of `fromData` for parity with Rust `from_data_ref`. */
  static fromDataRef(data: Uint8Array): Reference;
  /** Create a Reference from a Digest's underlying bytes. */
  static fromDigest(digest: Digest): Reference;
  /** Backwards-compatible alias of `fromDigest`. */
  static from(digest: Digest): Reference;
  /** Create a Reference from a 64-character hex string. */
  static fromHex(hex: string): Reference;
  /**
   * Create a Reference whose bytes are the SHA-256 digest of the input.
   *
   * @deprecated Prefer `Reference.fromDigest(Digest.fromImage(data))` for
   *   clarity, or `Reference.fromData(data)` if `data` is already 32 bytes
   *   that should be wrapped without hashing (matches Rust `from_data`).
   */
  static hash(data: Uint8Array): Reference;
  /** Returns the 32 reference bytes (copy). */
  data(): Uint8Array;
  /** Alias of `data()`. */
  asBytes(): Uint8Array;
  /** Returns a `Digest` constructed from these 32 bytes (no hashing). */
  getDigest(): Digest;
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
  /** A Reference to this Reference (matches Rust's blanket `ReferenceProvider` impl). */
  reference(): Reference;
  /**
   * SHA-256 of `taggedCbor().toCborData()`.
   *
   * Matches Rust's `DigestProvider for Reference` —
   * `Digest::from_image(self.tagged_cbor().to_cbor_data())`.
   */
  digest(): Digest;
  cborTags(): Tag[];
  /** Untagged CBOR — a single byte string of the 32 raw bytes. */
  untaggedCbor(): Cbor;
  taggedCbor(): Cbor;
  taggedCborData(): Uint8Array;
  fromUntaggedCbor(cbor: Cbor): Reference;
  fromTaggedCbor(cbor: Cbor): Reference;
  static fromTaggedCbor(cbor: Cbor): Reference;
  static fromTaggedCborData(data: Uint8Array): Reference;
  static fromUntaggedCborData(data: Uint8Array): Reference;
  static readonly UR_TYPE = "reference";
  /** UR representation — `ur:reference/...`, untagged CBOR payload. */
  ur(): UR;
  urString(): string;
  static fromUR(ur: UR): Reference;
  static fromURString(s: string): Reference;
  equals(other: Reference): boolean;
  /** Debug-style representation: `Reference(<8-hex-prefix>)`. */
  toString(): string;
}
//#endregion
//#region src/encapsulation/encapsulation-public-key.d.ts
/**
 * Represents a public key for key encapsulation.
 *
 * Use this to encapsulate a shared secret for a recipient.
 */
declare class EncapsulationPublicKey implements ReferenceProvider, CborTaggedEncodable, CborTaggedDecodable<EncapsulationPublicKey>, UREncodable {
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
  encapsulationScheme(): EncapsulationScheme;
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
  toX25519(): X25519PublicKey | null;
  /**
   * Returns the MLKEM public key if available, or null.
   */
  toMlkem(): MLKEMPublicKey | null;
  /**
   * Returns the raw public key data.
   */
  data(): Uint8Array;
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
   * Mirrors Rust `Display for EncapsulationPublicKey`
   * (`bc-components-rust/src/encapsulation/encapsulation_public_key.rs:191-205`):
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
  /**
   * Returns the CBOR tags associated with this public key.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
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
   * Creates an EncapsulationPublicKey by decoding it from untagged CBOR.
   * Note: Without tags, we assume X25519 scheme.
   */
  fromUntaggedCbor(cborValue: Cbor): EncapsulationPublicKey;
  /**
   * Creates an EncapsulationPublicKey by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): EncapsulationPublicKey;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): EncapsulationPublicKey;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): EncapsulationPublicKey;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): EncapsulationPublicKey;
  /**
   * Returns the UR representation.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates an EncapsulationPublicKey from a UR.
   */
  static fromUR(ur: UR): EncapsulationPublicKey;
  /**
   * Creates an EncapsulationPublicKey from a UR string.
   */
  static fromURString(urString: string): EncapsulationPublicKey;
}
//#endregion
//#region src/mlkem/mlkem-private-key.d.ts
/**
 * MLKEMPrivateKey - Post-quantum key decapsulation private key using ML-KEM.
 */
declare class MLKEMPrivateKey implements CborTaggedEncodable, CborTaggedDecodable<MLKEMPrivateKey>, UREncodable {
  private readonly _level;
  private readonly _data;
  private constructor();
  /**
   * Generate a new random MLKEMPrivateKey with the specified security level.
   *
   * @param level - The ML-KEM security level (default: MLKEM768)
   */
  static new(level?: MLKEMLevel): MLKEMPrivateKey;
  /**
   * Generate a new random MLKEMPrivateKey using the provided RNG.
   *
   * @param level - The ML-KEM security level
   * @param rng - Random number generator
   */
  static newUsing(level: MLKEMLevel, rng: RandomNumberGenerator): MLKEMPrivateKey;
  /**
   * Create an MLKEMPrivateKey from raw bytes.
   *
   * @param level - The ML-KEM security level
   * @param data - The private key bytes
   */
  static fromBytes(level: MLKEMLevel, data: Uint8Array): MLKEMPrivateKey;
  /**
   * Generate a keypair and return both private and public keys.
   *
   * @param level - The ML-KEM security level (default: MLKEM768)
   * @returns Tuple of [privateKey, publicKey]
   */
  static keypair(level?: MLKEMLevel): [MLKEMPrivateKey, MLKEMPublicKey];
  /**
   * Generate a keypair using the provided RNG.
   *
   * @param level - The ML-KEM security level
   * @param rng - Random number generator
   * @returns Tuple of [privateKey, publicKey]
   */
  static keypairUsing(level: MLKEMLevel, rng: RandomNumberGenerator): [MLKEMPrivateKey, MLKEMPublicKey];
  /**
   * Returns the security level of this key.
   */
  level(): MLKEMLevel;
  /**
   * Returns the raw key bytes.
   */
  asBytes(): Uint8Array;
  /**
   * Returns a copy of the raw key bytes.
   */
  data(): Uint8Array;
  /**
   * Returns the size of the key in bytes.
   */
  size(): number;
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
  /**
   * Returns the CBOR tags associated with MLKEMPrivateKey.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: [level, key_bytes]
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
   * Creates an MLKEMPrivateKey by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cborValue: Cbor): MLKEMPrivateKey;
  /**
   * Creates an MLKEMPrivateKey by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): MLKEMPrivateKey;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): MLKEMPrivateKey;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): MLKEMPrivateKey;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): MLKEMPrivateKey;
  /**
   * Returns the UR representation.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates an MLKEMPrivateKey from a UR.
   */
  static fromUR(ur: UR): MLKEMPrivateKey;
  /**
   * Creates an MLKEMPrivateKey from a UR string.
   */
  static fromURString(urString: string): MLKEMPrivateKey;
}
//#endregion
//#region src/encapsulation/encapsulation-private-key.d.ts
/**
 * Represents a private key for key encapsulation.
 *
 * Use this to decapsulate a shared secret from ciphertext.
 */
declare class EncapsulationPrivateKey implements ReferenceProvider, CborTaggedEncodable, CborTaggedDecodable<EncapsulationPrivateKey>, UREncodable {
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
  /**
   * Generate a new random X25519 encapsulation private key.
   */
  static new(): EncapsulationPrivateKey;
  /**
   * Generate a new random X25519 encapsulation private key.
   */
  static random(): EncapsulationPrivateKey;
  /**
   * Generate a new random X25519 encapsulation private key using provided RNG.
   */
  static newUsing(rng: RandomNumberGenerator): EncapsulationPrivateKey;
  /**
   * Generate a new MLKEM encapsulation private key.
   */
  static newMlkem(level?: MLKEMLevel): EncapsulationPrivateKey;
  /**
   * Generate a new MLKEM encapsulation private key using provided RNG.
   */
  static newMlkemUsing(level: MLKEMLevel, rng: RandomNumberGenerator): EncapsulationPrivateKey;
  /**
   * Generate a new keypair for X25519.
   */
  static keypair(): [EncapsulationPrivateKey, EncapsulationPublicKey];
  /**
   * Generate a new keypair using the given RNG (X25519).
   */
  static keypairUsing(rng: RandomNumberGenerator): [EncapsulationPrivateKey, EncapsulationPublicKey];
  /**
   * Generate a new MLKEM keypair.
   */
  static mlkemKeypair(level?: MLKEMLevel): [EncapsulationPrivateKey, EncapsulationPublicKey];
  /**
   * Generate a new MLKEM keypair using the given RNG.
   */
  static mlkemKeypairUsing(level: MLKEMLevel, rng: RandomNumberGenerator): [EncapsulationPrivateKey, EncapsulationPublicKey];
  /**
   * Returns the encapsulation scheme.
   */
  encapsulationScheme(): EncapsulationScheme;
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
  toX25519(): X25519PrivateKey | null;
  /**
   * Returns the MLKEM private key if available, or null.
   */
  toMlkem(): MLKEMPrivateKey | null;
  /**
   * Returns the raw private key data.
   */
  data(): Uint8Array;
  /**
   * Get the public key corresponding to this private key.
   */
  publicKey(): EncapsulationPublicKey;
  /**
   * Decapsulate a shared secret from ciphertext.
   *
   * @param ciphertext - The ciphertext from encapsulation
   * @returns The decapsulated shared secret
   * @throws CryptoError if the scheme doesn't match
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
  /**
   * Returns the CBOR tags associated with this private key.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
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
   * Creates an EncapsulationPrivateKey by decoding it from untagged CBOR.
   * Note: Without tags, we assume X25519 scheme.
   */
  fromUntaggedCbor(cborValue: Cbor): EncapsulationPrivateKey;
  /**
   * Creates an EncapsulationPrivateKey by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): EncapsulationPrivateKey;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): EncapsulationPrivateKey;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): EncapsulationPrivateKey;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): EncapsulationPrivateKey;
  /**
   * Returns the UR representation.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates an EncapsulationPrivateKey from a UR.
   */
  static fromUR(ur: UR): EncapsulationPrivateKey;
  /**
   * Creates an EncapsulationPrivateKey from a UR string.
   */
  static fromURString(urString: string): EncapsulationPrivateKey;
}
//#endregion
//#region src/encapsulation/encapsulation-scheme.d.ts
/**
 * Available key encapsulation schemes.
 */
declare enum EncapsulationScheme {
  /**
   * X25519 Diffie-Hellman key exchange (default).
   * Based on Curve25519 as defined in RFC 7748.
   */
  X25519 = "x25519",
  /**
   * ML-KEM-512 post-quantum key encapsulation (NIST security level 1).
   */
  MLKEM512 = "mlkem512",
  /**
   * ML-KEM-768 post-quantum key encapsulation (NIST security level 3).
   */
  MLKEM768 = "mlkem768",
  /**
   * ML-KEM-1024 post-quantum key encapsulation (NIST security level 5).
   */
  MLKEM1024 = "mlkem1024"
}
/**
 * Returns the default encapsulation scheme (X25519).
 */
declare function defaultEncapsulationScheme(): EncapsulationScheme;
/**
 * Generate a new keypair for the given encapsulation scheme.
 *
 * @param scheme - The encapsulation scheme to use (defaults to X25519)
 * @returns A tuple of [privateKey, publicKey]
 */
declare function createEncapsulationKeypair(scheme?: EncapsulationScheme): [EncapsulationPrivateKey, EncapsulationPublicKey];
/**
 * Generate a new keypair for the given encapsulation scheme using a specific RNG.
 *
 * Note: Only X25519 supports deterministic keypair generation.
 * MLKEM schemes do not support deterministic generation (matching Rust behavior).
 *
 * @param rng - The random number generator to use
 * @param scheme - The encapsulation scheme to use (defaults to X25519)
 * @returns A tuple of [privateKey, publicKey]
 * @throws Error if the scheme doesn't support deterministic generation
 */
declare function createEncapsulationKeypairUsing(rng: RandomNumberGenerator, scheme?: EncapsulationScheme): [EncapsulationPrivateKey, EncapsulationPublicKey];
//#endregion
//#region src/encapsulation/encapsulation-ciphertext.d.ts
/**
 * Represents the ciphertext from a key encapsulation operation.
 *
 * For X25519, this wraps an ephemeral public key.
 * For MLKEM, this wraps an MLKEMCiphertext.
 */
declare class EncapsulationCiphertext implements CborTaggedEncodable, CborTaggedDecodable<EncapsulationCiphertext> {
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
  encapsulationScheme(): EncapsulationScheme;
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
  toX25519(): X25519PublicKey | null;
  /**
   * Returns the MLKEM ciphertext if available, or null.
   */
  toMlkem(): MLKEMCiphertext | null;
  /**
   * Returns the raw ciphertext data.
   */
  data(): Uint8Array;
  /**
   * Compare with another EncapsulationCiphertext.
   */
  equals(other: EncapsulationCiphertext): boolean;
  /**
   * Get string representation.
   */
  toString(): string;
  /**
   * Returns the CBOR tags associated with this ciphertext.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
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
   * Creates an EncapsulationCiphertext by decoding it from untagged CBOR.
   * Note: Without tags, we assume X25519 scheme.
   */
  fromUntaggedCbor(cborValue: Cbor): EncapsulationCiphertext;
  /**
   * Creates an EncapsulationCiphertext by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): EncapsulationCiphertext;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): EncapsulationCiphertext;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): EncapsulationCiphertext;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): EncapsulationCiphertext;
}
//#endregion
//#region src/encrypter.d.ts
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
interface Encrypter {
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
interface Decrypter {
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
 * Type guard to check if an object implements the Encrypter interface.
 */
declare function isEncrypter(obj: unknown): obj is Encrypter;
/**
 * Type guard to check if an object implements the Decrypter interface.
 */
declare function isDecrypter(obj: unknown): obj is Decrypter;
//#endregion
//#region src/json.d.ts
/**
 * A CBOR-tagged container for UTF-8 JSON text.
 *
 * Wraps UTF-8 JSON text as a CBOR byte string with tag 262.
 * This allows JSON data to be embedded within CBOR structures while
 * maintaining type information through the tag.
 */
declare class JSON implements CborTaggedEncodable, CborTaggedDecodable<JSON> {
  private readonly _data;
  private constructor();
  /**
   * Create a new JSON instance from byte data.
   */
  static fromData(data: Uint8Array): JSON;
  /**
   * Create a new JSON instance from a string.
   */
  static fromString(s: string): JSON;
  /**
   * Create a new JSON instance from a hexadecimal string.
   */
  static fromHex(hex: string): JSON;
  /**
   * Return the length of the JSON data in bytes.
   */
  len(): number;
  /**
   * Return true if the JSON data is empty.
   */
  isEmpty(): boolean;
  /**
   * Return the data as a byte slice.
   */
  asBytes(): Uint8Array;
  /**
   * Return the data as a UTF-8 string slice.
   *
   * @throws Error if the data is not valid UTF-8.
   */
  asStr(): string;
  /**
   * Return the data as a hexadecimal string.
   */
  hex(): string;
  /**
   * Return a copy of the underlying data.
   */
  toData(): Uint8Array;
  /**
   * Compare with another JSON.
   */
  equals(other: JSON): boolean;
  /**
   * Get string representation.
   */
  toString(): string;
  /**
   * Returns the CBOR tags associated with JSON.
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
   * Creates a JSON by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cborValue: Cbor): JSON;
  /**
   * Creates a JSON by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): JSON;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): JSON;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): JSON;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): JSON;
}
//#endregion
//#region src/compressed.d.ts
/**
 * A compressed binary object with integrity verification.
 *
 * Uses DEFLATE compression with CRC32 checksums for integrity verification.
 * Optionally includes a cryptographic digest for content identification.
 */
declare class Compressed implements CborTaggedEncodable, CborTaggedDecodable<Compressed>, DigestProvider {
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
   * @throws CryptoError if the compressed data is larger than the decompressed size
   */
  static new(checksum: number, decompressedSize: number, compressedData: Uint8Array, digest?: Digest): Compressed;
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
   * @throws CryptoError if the compressed data is corrupt or checksum doesn't match
   */
  decompress(): Uint8Array;
  /**
   * Returns the size of the compressed data in bytes.
   */
  compressedSize(): number;
  /**
   * Returns the size of the decompressed data in bytes.
   */
  decompressedSize(): number;
  /**
   * Returns the CRC32 checksum of the decompressed data.
   */
  checksum(): number;
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
  compressionRatio(): number;
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
  /**
   * Returns the CBOR tags associated with Compressed.
   */
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
  /**
   * Returns the tagged CBOR encoding.
   */
  taggedCbor(): Cbor;
  /**
   * Returns the tagged value in CBOR binary representation.
   */
  taggedCborData(): Uint8Array;
  /**
   * Creates a Compressed by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cborValue: Cbor): Compressed;
  /**
   * Creates a Compressed by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): Compressed;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): Compressed;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): Compressed;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): Compressed;
}
//#endregion
//#region src/hkdf-rng.d.ts
/**
 * A deterministic random number generator based on HKDF-HMAC-SHA256.
 *
 * Implements the RandomNumberGenerator interface from @blockchaincommons/rand.
 */
declare class HKDFRng implements RandomNumberGenerator {
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
//#endregion
//#region src/utils.d.ts
/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 * Utility functions for byte array conversions and comparisons.
 *
 * These functions provide cross-platform support for common byte manipulation
 * operations needed in cryptographic and encoding contexts.
 *
 */
/**
 * Convert a Uint8Array to a lowercase hexadecimal string.
 *
 * @param data - The byte array to convert
 * @returns A lowercase hex string representation (2 characters per byte)
 *
 * @example
 * ```typescript
 * const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
 * bytesToHex(bytes); // "deadbeef"
 * ```
 */
declare function bytesToHex(data: Uint8Array): string;
/**
 * Convert a hexadecimal string to a Uint8Array.
 *
 * @param hex - A hex string (must have even length, case-insensitive)
 * @returns The decoded byte array
 * @throws {Error} If the hex string has odd length or contains invalid characters
 *
 * @example
 * ```typescript
 * hexToBytes("deadbeef"); // Uint8Array([0xde, 0xad, 0xbe, 0xef])
 * hexToBytes("DEADBEEF"); // Uint8Array([0xde, 0xad, 0xbe, 0xef])
 * hexToBytes("xyz"); // throws Error: Invalid hex string
 * ```
 */
declare function hexToBytes(hex: string): Uint8Array;
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
declare function toBase64(data: Uint8Array): string;
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
declare function fromBase64(base64: string): Uint8Array;
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
declare function bytesEqual(a: Uint8Array, b: Uint8Array): boolean;
//#endregion
//#region src/salt.d.ts
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
//#endregion
//#region src/seed.d.ts
interface SeedMetadata {
  name?: string;
  note?: string;
  createdAt?: Date;
}
declare class Seed implements CborTaggedEncodable, CborTaggedDecodable<Seed>, UREncodable, PrivateKeyDataProvider {
  /**
   * Minimum seed length in bytes (matches Rust MIN_SEED_LENGTH).
   */
  static readonly MIN_SEED_LENGTH = 16;
  private readonly _data;
  private _name;
  private _note;
  private _creationDate;
  private constructor();
  /**
   * Create a new random seed with default length (16 bytes).
   *
   * Rust equivalent: `Seed::new()`
   */
  static new(): Seed;
  /**
   * Create a new random seed with a specified length.
   *
   * Rust equivalent: `Seed::new_with_len(count)`
   *
   * @param count - Number of bytes (must be >= 16)
   * @throws CryptoError if count < 16
   */
  static newWithLen(count: number): Seed;
  /**
   * Create a new random seed with a specified length using provided RNG.
   *
   * Rust equivalent: `Seed::new_with_len_using(count, rng)`
   *
   * @param count - Number of bytes (must be >= 16)
   * @param rng - Random number generator
   * @throws CryptoError if count < 16
   */
  static newWithLenUsing(count: number, rng: RandomNumberGenerator): Seed;
  /**
   * Create a new seed from data and optional metadata.
   *
   * Rust equivalent: `Seed::new_opt(data, name, note, creation_date)`
   *
   * @param data - Seed bytes (must be >= 16 bytes)
   * @param name - Optional name for the seed
   * @param note - Optional note for the seed
   * @param creationDate - Optional creation date
   * @throws CryptoError if data < 16 bytes
   */
  static newOpt(data: Uint8Array, name: string | undefined, note: string | undefined, creationDate: Date | undefined): Seed;
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
  /**
   * Generate a random seed with specified size (default 32 bytes).
   *
   * Convenience method that wraps `newWithLen()`.
   *
   * @param size - Number of bytes (must be >= 16, default 32)
   * @param metadata - Optional metadata object
   */
  static random(size?: number, metadata?: SeedMetadata): Seed;
  /**
   * Generate a random seed using provided RNG.
   *
   * Convenience method that wraps `newWithLenUsing()`.
   *
   * @param rng - Random number generator
   * @param size - Number of bytes (must be >= 16, default 32)
   * @param metadata - Optional metadata object
   */
  static randomUsing(rng: RandomNumberGenerator, size?: number, metadata?: SeedMetadata): Seed;
  /**
   * Return the data of the seed as a reference to the internal bytes.
   *
   * Rust equivalent: `seed.as_bytes()`
   *
   * Note: Returns a reference to internal data. For a copy, use `toData()`.
   */
  asBytes(): Uint8Array;
  /**
   * Get the raw seed bytes (copy).
   *
   * Note: Returns a copy to prevent external mutation of the seed's internal state.
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
   * Get seed size in bytes.
   */
  size(): number;
  /**
   * Return the name of the seed.
   *
   * Rust equivalent: `seed.name()` - returns empty string if not set.
   */
  name(): string;
  /**
   * Set the name of the seed.
   *
   * Rust equivalent: `seed.set_name(name)`
   */
  setName(name: string): void;
  /**
   * Return the note of the seed.
   *
   * Rust equivalent: `seed.note()` - returns empty string if not set.
   */
  note(): string;
  /**
   * Set the note of the seed.
   *
   * Rust equivalent: `seed.set_note(note)`
   */
  setNote(note: string): void;
  /**
   * Return the creation date of the seed.
   *
   * Rust equivalent: `seed.creation_date()`
   */
  creationDate(): Date | undefined;
  /**
   * Set the creation date of the seed.
   *
   * Rust equivalent: `seed.set_creation_date(date)`
   */
  setCreationDate(creationDate: Date | undefined): void;
  /**
   * Return the creation date of the seed (alias for creationDate).
   *
   * @deprecated Use `creationDate()` for Rust API parity.
   */
  createdAt(): Date | undefined;
  /**
   * Set the creation date of the seed (alias for setCreationDate).
   *
   * @deprecated Use `setCreationDate()` for Rust API parity.
   */
  setCreatedAt(date: Date): void;
  /**
   * Get metadata as an object.
   *
   * TypeScript convenience method - returns a snapshot of current metadata.
   */
  getMetadata(): SeedMetadata;
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
  /**
   * Returns the CBOR tags associated with Seed.
   * Includes TAG_SEED (40300) and TAG_SEED_V1 (300) for backward compatibility.
   */
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
  /**
   * Returns the tagged CBOR encoding.
   */
  taggedCbor(): Cbor;
  /**
   * Returns the tagged value in CBOR binary representation.
   */
  taggedCborData(): Uint8Array;
  /**
   * Creates a Seed by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cborValue: Cbor): Seed;
  /**
   * Creates a Seed by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cbor: Cbor): Seed;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): Seed;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): Seed;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): Seed;
  /**
   * Returns the UR representation of the Seed.
   * Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates a Seed from a UR.
   */
  static fromUR(ur: UR): Seed;
  /**
   * Creates a Seed from a UR string.
   */
  static fromURString(urString: string): Seed;
}
//#endregion
//#region src/id/arid.d.ts
declare class ARID implements CborTaggedEncodable, CborTaggedDecodable<ARID>, UREncodable {
  static readonly ARID_SIZE = 32;
  private readonly _data;
  private constructor();
  /**
   * Create a new random ARID.
   */
  static new(): ARID;
  /**
   * Create a new random ARID (alias for new()).
   */
  static random(): ARID;
  /**
   * Restore an ARID from a fixed-size array of bytes.
   */
  static fromData(data: Uint8Array): ARID;
  /**
   * Create a new ARID from a reference to an array of bytes.
   */
  static fromDataRef(data: Uint8Array): ARID;
  /**
   * Create an ARID from raw bytes (legacy alias).
   */
  static from(data: Uint8Array): ARID;
  /**
   * Create a new ARID from the given hexadecimal string.
   *
   * @throws Error if the string is not exactly 64 hexadecimal digits.
   */
  static fromHex(hex: string): ARID;
  /**
   * Get the data of the ARID as an array of bytes.
   */
  data(): Uint8Array;
  /**
   * Get the data of the ARID as a byte slice.
   */
  asBytes(): Uint8Array;
  /**
   * Get the raw ARID bytes as a copy.
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
  /**
   * Returns the CBOR tags associated with ARID.
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
   * Creates an ARID by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cbor: Cbor): ARID;
  /**
   * Creates an ARID by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cbor: Cbor): ARID;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cbor: Cbor): ARID;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): ARID;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): ARID;
  /**
   * Returns the UR representation of the ARID.
   * Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates an ARID from a UR.
   */
  static fromUR(ur: UR): ARID;
  /**
   * Creates an ARID from a UR string.
   */
  static fromURString(urString: string): ARID;
  /**
   * Alias for fromURString for Rust API compatibility.
   */
  static fromUrString(urString: string): ARID;
}
//#endregion
//#region src/id/uuid.d.ts
declare class UUID implements CborTaggedEncodable, CborTaggedDecodable<UUID>, UREncodable {
  static readonly UUID_SIZE: number;
  private readonly _data;
  private constructor();
  /**
   * Create a new random UUID (v4).
   */
  static new(): UUID;
  /**
   * Create a UUID from raw bytes.
   */
  static fromData(data: Uint8Array): UUID;
  /**
   * Restores a UUID from data (validates length).
   */
  static fromDataRef(data: Uint8Array): UUID;
  /**
   * Create a UUID from raw bytes (legacy alias).
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
  static random(): UUID;
  /**
   * Get the data of the UUID.
   */
  data(): Uint8Array;
  /**
   * Get the UUID as a byte slice.
   */
  asBytes(): Uint8Array;
  /**
   * Get the raw UUID bytes as a copy.
   */
  toData(): Uint8Array;
  /**
   * Get hex string representation (lowercase, matching Rust implementation).
   */
  hex(): string;
  /**
   * Get hex string representation (alias for hex()).
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
  /**
   * Returns the CBOR tags associated with UUID.
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
   * Creates a UUID by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cbor: Cbor): UUID;
  /**
   * Creates a UUID by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cbor: Cbor): UUID;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cbor: Cbor): UUID;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): UUID;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): UUID;
  /**
   * Returns the UR representation of the UUID.
   * Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates a UUID from a UR.
   */
  static fromUR(ur: UR): UUID;
  /**
   * Creates a UUID from a UR string.
   */
  static fromURString(urString: string): UUID;
}
//#endregion
//#region src/ed25519/ed25519-public-key.d.ts
declare class Ed25519PublicKey {
  private readonly _data;
  private constructor();
  /**
   * Create an Ed25519PublicKey from raw bytes (32 bytes).
   */
  static from(data: Uint8Array): Ed25519PublicKey;
  /**
   * Mirror of Rust `Ed25519PublicKey::from_data` — exact-length copy.
   */
  static fromData(data: Uint8Array): Ed25519PublicKey;
  /**
   * Mirror of Rust `Ed25519PublicKey::from_data_ref` — validates length.
   */
  static fromDataRef(data: Uint8Array): Ed25519PublicKey;
  /**
   * Create an Ed25519PublicKey from hex string.
   */
  static fromHex(hex: string): Ed25519PublicKey;
  /** Returns the 32 raw public key bytes (copy). */
  data(): Uint8Array;
  /** Alias of {@link Ed25519PublicKey.data}. */
  asBytes(): Uint8Array;
  /** Backwards-compatible alias of {@link Ed25519PublicKey.data}. */
  toData(): Uint8Array;
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
   * Mirrors Rust `Display for Ed25519PublicKey`
   * (`bc-components-rust/src/ed25519/ed25519_public_key.rs`):
   *   `Ed25519PublicKey(<ref_hex_short>)`
   * where the reference is computed from the **raw 32-byte data**
   * (not tagged CBOR) — same pattern as SchnorrPublicKey.
   */
  toString(): string;
}
//#endregion
//#region src/sr25519/sr25519-public-key.d.ts
/**
 * Sr25519PublicKey - Public key for Schnorr signatures over Ristretto25519.
 *
 * This is the signature scheme used by Polkadot/Substrate.
 */
declare class Sr25519PublicKey {
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
  /**
   * Returns the raw key bytes.
   */
  toData(): Uint8Array;
  /**
   * Returns the raw key bytes (alias for toData).
   */
  asBytes(): Uint8Array;
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
   * @throws CryptoError if `context` is not the substrate default
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
//#endregion
//#region src/ec-key/ec-key-base.d.ts
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
interface ECKeyBase {
  /**
   * Returns the key's binary data.
   */
  data(): Uint8Array;
  /**
   * Returns the key as a hexadecimal string.
   */
  hex(): string;
}
/**
 * Type guard to check if an object implements ECKeyBase.
 */
declare function isECKeyBase(obj: unknown): obj is ECKeyBase;
/**
 * An interface for elliptic curve keys that can derive a public key.
 *
 * This interface extends `ECKeyBase` to provide a method for deriving
 * the corresponding compressed public key. It is implemented by both
 * private keys (where it generates the public key) and public keys
 * (where it may return self or convert between formats).
 */
interface ECKey extends ECKeyBase {
  /**
   * Returns the compressed public key corresponding to this key.
   */
  publicKey(): ECPublicKey;
}
/**
 * Type guard to check if an object implements ECKey.
 */
declare function isECKey(obj: unknown): obj is ECKey;
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
interface ECPublicKeyBase extends ECKey {
  /**
   * Returns the uncompressed public key representation.
   */
  uncompressedPublicKey(): ECUncompressedPublicKey;
}
/**
 * Type guard to check if an object implements ECPublicKeyBase.
 */
declare function isECPublicKeyBase(obj: unknown): obj is ECPublicKeyBase;
//#endregion
//#region src/ec-key/ec-uncompressed-public-key.d.ts
declare class ECUncompressedPublicKey implements ECKeyBase, CborTaggedEncodable, CborTaggedDecodable<ECUncompressedPublicKey>, UREncodable {
  static readonly KEY_SIZE: number;
  private readonly _data;
  private constructor();
  /**
   * Restore an ECUncompressedPublicKey from a fixed-size array of bytes.
   */
  static fromData(data: Uint8Array): ECUncompressedPublicKey;
  /**
   * Restore an ECUncompressedPublicKey from a reference to an array of bytes.
   * Validates the length.
   */
  static fromDataRef(data: Uint8Array): ECUncompressedPublicKey;
  /**
   * Create an ECUncompressedPublicKey from raw bytes (legacy alias).
   */
  static from(data: Uint8Array): ECUncompressedPublicKey;
  /**
   * Restore an ECUncompressedPublicKey from a hex string.
   */
  static fromHex(hex: string): ECUncompressedPublicKey;
  /**
   * Get a reference to the fixed-size array of bytes.
   */
  data(): Uint8Array;
  /**
   * Get the raw public key bytes (copy).
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
  /**
   * Returns the CBOR tags associated with ECUncompressedPublicKey.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: { 3: h'<65-byte-key>' }
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
   * Creates an ECUncompressedPublicKey by decoding it from untagged CBOR.
   *
   * Format: { 3: h'<65-byte-key>' }
   */
  fromUntaggedCbor(cborValue: Cbor): ECUncompressedPublicKey;
  /**
   * Creates an ECUncompressedPublicKey by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): ECUncompressedPublicKey;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): ECUncompressedPublicKey;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): ECUncompressedPublicKey;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): ECUncompressedPublicKey;
  /**
   * Returns the UR representation of the ECUncompressedPublicKey.
   * Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates an ECUncompressedPublicKey from a UR.
   */
  static fromUR(ur: UR): ECUncompressedPublicKey;
  /**
   * Creates an ECUncompressedPublicKey from a UR string.
   */
  static fromURString(urString: string): ECUncompressedPublicKey;
}
//#endregion
//#region src/ec-key/ec-public-key.d.ts
declare class ECPublicKey implements ECPublicKeyBase, CborTaggedEncodable, CborTaggedDecodable<ECPublicKey>, UREncodable {
  static readonly KEY_SIZE: number;
  private readonly _data;
  private constructor();
  /**
   * Restore an ECPublicKey from a fixed-size array of bytes.
   */
  static fromData(data: Uint8Array): ECPublicKey;
  /**
   * Restore an ECPublicKey from a reference to an array of bytes.
   * Validates the length.
   */
  static fromDataRef(data: Uint8Array): ECPublicKey;
  /**
   * Create an ECPublicKey from raw bytes (legacy alias).
   */
  static from(data: Uint8Array): ECPublicKey;
  /**
   * Restore an ECPublicKey from a hex string.
   */
  static fromHex(hex: string): ECPublicKey;
  /**
   * Get a reference to the fixed-size array of bytes.
   */
  data(): Uint8Array;
  /**
   * Get the raw public key bytes (copy).
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
  /**
   * Returns the CBOR tags associated with ECPublicKey.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: { 3: h'<33-byte-key>' }
   * Note: No key 2 indicates this is a public key
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
   * Creates an ECPublicKey by decoding it from untagged CBOR.
   *
   * Format: { 3: h'<33-byte-key>' }
   */
  fromUntaggedCbor(cborValue: Cbor): ECPublicKey;
  /**
   * Creates an ECPublicKey by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): ECPublicKey;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): ECPublicKey;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): ECPublicKey;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): ECPublicKey;
  /**
   * Returns the UR representation of the ECPublicKey.
   * Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates an ECPublicKey from a UR.
   */
  static fromUR(ur: UR): ECPublicKey;
  /**
   * Creates an ECPublicKey from a UR string.
   */
  static fromURString(urString: string): ECPublicKey;
}
//#endregion
//#region src/ec-key/schnorr-public-key.d.ts
declare class SchnorrPublicKey implements ECKeyBase {
  static readonly KEY_SIZE: number;
  private readonly _data;
  private constructor();
  /**
   * Restore a SchnorrPublicKey from a fixed-size array of bytes.
   */
  static fromData(data: Uint8Array): SchnorrPublicKey;
  /**
   * Restore a SchnorrPublicKey from a reference to an array of bytes.
   * Validates the length.
   */
  static fromDataRef(data: Uint8Array): SchnorrPublicKey;
  /**
   * Create a SchnorrPublicKey from raw bytes (legacy alias).
   */
  static from(data: Uint8Array): SchnorrPublicKey;
  /**
   * Restore a SchnorrPublicKey from a hex string.
   */
  static fromHex(hex: string): SchnorrPublicKey;
  /**
   * Get a reference to the fixed-size array of bytes.
   */
  data(): Uint8Array;
  /**
   * Get the raw public key bytes (copy).
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
   * Mirrors Rust `Display for SchnorrPublicKey`
   * (`bc-components-rust/src/ec_key/schnorr_public_key.rs:116-120`)
   * — the reference is computed from the **raw 32-byte key data**
   * (not the tagged-CBOR form): `Reference::from_digest(Digest::from_image(self.data()))`.
   * `ref_hex_short()` returns the first 8 hex chars of that
   * reference's binary form (= SHA-256(data)[0..4]).
   */
  toString(): string;
}
//#endregion
//#region src/mldsa/mldsa-level.d.ts
/**
 * ML-DSA security levels.
 *
 * The numeric values correspond to NIST security levels:
 * - 2: NIST Level 2 (MLDSA44)
 * - 3: NIST Level 3 (MLDSA65)
 * - 5: NIST Level 5 (MLDSA87)
 */
declare enum MLDSALevel {
  /** NIST Level 2 - AES-128 equivalent security */
  MLDSA44 = 2,
  /** NIST Level 3 - AES-192 equivalent security */
  MLDSA65 = 3,
  /** NIST Level 5 - AES-256 equivalent security */
  MLDSA87 = 5
}
/**
 * Key sizes for each ML-DSA security level.
 */
declare const MLDSA_KEY_SIZES: Readonly<Record<MLDSALevel, {
  privateKey: number;
  publicKey: number;
  signature: number;
}>>;
/**
 * Get the private key size for a given ML-DSA level.
 */
declare function mldsaPrivateKeySize(level: MLDSALevel): number;
/**
 * Get the public key size for a given ML-DSA level.
 */
declare function mldsaPublicKeySize(level: MLDSALevel): number;
/**
 * Get the signature size for a given ML-DSA level.
 */
declare function mldsaSignatureSize(level: MLDSALevel): number;
/**
 * Convert an ML-DSA level to its string representation.
 */
declare function mldsaLevelToString(level: MLDSALevel): string;
/**
 * Parse an ML-DSA level from its numeric value.
 */
declare function mldsaLevelFromValue(value: number): MLDSALevel;
/**
 * Internal type for ML-DSA keypair generation result.
 */
interface MLDSAKeypairData {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}
/**
 * Generate an ML-DSA keypair for the given security level.
 *
 * @param level - The ML-DSA security level
 * @returns Object containing publicKey and secretKey bytes
 */
declare function mldsaGenerateKeypair(level: MLDSALevel): MLDSAKeypairData;
/**
 * Generate an ML-DSA keypair using a provided RNG.
 *
 * @param level - The ML-DSA security level
 * @param rng - Random number generator
 * @returns Object containing publicKey and secretKey bytes
 */
declare function mldsaGenerateKeypairUsing(level: MLDSALevel, rng: RandomNumberGenerator): MLDSAKeypairData;
/**
 * Sign a message using ML-DSA.
 *
 * @param level - The ML-DSA security level
 * @param secretKey - The secret key bytes
 * @param message - The message to sign
 * @returns The signature bytes
 */
declare function mldsaSign(level: MLDSALevel, secretKey: Uint8Array, message: Uint8Array): Uint8Array;
/**
 * Verify a signature using ML-DSA.
 *
 * @param level - The ML-DSA security level
 * @param publicKey - The public key bytes
 * @param message - The message that was signed
 * @param signature - The signature to verify
 * @returns True if the signature is valid
 */
declare function mldsaVerify(level: MLDSALevel, publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
//#endregion
//#region src/mldsa/mldsa-signature.d.ts
/**
 * MLDSASignature - Post-quantum digital signature using ML-DSA.
 */
declare class MLDSASignature implements CborTaggedEncodable, CborTaggedDecodable<MLDSASignature>, UREncodable {
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
  level(): MLDSALevel;
  /**
   * Returns the raw signature bytes.
   */
  asBytes(): Uint8Array;
  /**
   * Returns a copy of the raw signature bytes.
   */
  data(): Uint8Array;
  /**
   * Returns the size of the signature in bytes.
   */
  size(): number;
  /**
   * Compare with another MLDSASignature.
   */
  equals(other: MLDSASignature): boolean;
  /**
   * Get string representation.
   */
  toString(): string;
  /**
   * Returns the CBOR tags associated with MLDSASignature.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: [level, signature_bytes]
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
   * Creates an MLDSASignature by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cborValue: Cbor): MLDSASignature;
  /**
   * Creates an MLDSASignature by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): MLDSASignature;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): MLDSASignature;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): MLDSASignature;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): MLDSASignature;
  /**
   * Returns the UR representation.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates an MLDSASignature from a UR.
   */
  static fromUR(ur: UR): MLDSASignature;
  /**
   * Creates an MLDSASignature from a UR string.
   */
  static fromURString(urString: string): MLDSASignature;
}
//#endregion
//#region src/mldsa/mldsa-public-key.d.ts
/**
 * MLDSAPublicKey - Post-quantum signature verification key using ML-DSA.
 */
declare class MLDSAPublicKey implements CborTaggedEncodable, CborTaggedDecodable<MLDSAPublicKey>, UREncodable {
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
  level(): MLDSALevel;
  /**
   * Returns the raw key bytes.
   */
  asBytes(): Uint8Array;
  /**
   * Returns a copy of the raw key bytes.
   */
  data(): Uint8Array;
  /**
   * Returns the size of the key in bytes.
   */
  size(): number;
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
  /**
   * Returns the CBOR tags associated with MLDSAPublicKey.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: [level, key_bytes]
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
   * Creates an MLDSAPublicKey by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cborValue: Cbor): MLDSAPublicKey;
  /**
   * Creates an MLDSAPublicKey by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): MLDSAPublicKey;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): MLDSAPublicKey;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): MLDSAPublicKey;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): MLDSAPublicKey;
  /**
   * Returns the UR representation.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates an MLDSAPublicKey from a UR.
   */
  static fromUR(ur: UR): MLDSAPublicKey;
  /**
   * Creates an MLDSAPublicKey from a UR string.
   */
  static fromURString(urString: string): MLDSAPublicKey;
}
//#endregion
//#region src/ssh/ssh-algorithm.d.ts
/**
 * Copyright © 2025-2026 Parity Technologies
 *
 * SSH key algorithm identifiers.
 *
 * Mirrors the relevant subset of `ssh_key::Algorithm` (Rust crate
 * `ssh-key` v0.6.7). v1.1 supports the four algorithms `bc-components-rust`
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
type SshAlgorithm = {
  kind: "ed25519";
} | {
  kind: "dsa";
} | {
  kind: "ecdsa";
  curve: SshEcdsaCurve;
};
type SshEcdsaCurve = "nistp256" | "nistp384";
/** Wire-format algorithm name as it appears in OpenSSH text and in the key blob. */
declare const SSH_ALGO_ED25519 = "ssh-ed25519";
declare const SSH_ALGO_ECDSA_NISTP256 = "ecdsa-sha2-nistp256";
/** OpenSSH curve identifier embedded inside ECDSA key blobs. */
declare const SSH_CURVE_NISTP256 = "nistp256";
declare function sshAlgorithmName(algo: SshAlgorithm): string;
declare function parseSshAlgorithm(name: string): SshAlgorithm;
//#endregion
//#region src/ssh/ssh-public-key.d.ts
/**
 * Internal discriminated union for the algorithm-specific public-key data.
 *
 *   - ed25519: the 32-byte raw public key.
 *   - ecdsa:   curve + 65/97-byte SEC1 uncompressed point.
 *   - dsa:     four canonical-positive mpint bytes (p, q, g, y) — sign
 *              byte already stripped on parse, re-added by the writer.
 */
type SshPublicKeyData = {
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
   * Mirrors `ssh_key::PublicKey::set_comment` (mutating in Rust; we
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
//#endregion
//#region src/ed25519/ed25519-private-key.d.ts
declare class Ed25519PrivateKey {
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
  /**
   * Generate a random Ed25519PrivateKey
   */
  static random(): Ed25519PrivateKey;
  /**
   * Generate a random Ed25519PrivateKey using provided RNG
   */
  static randomUsing(rng: RandomNumberGenerator): Ed25519PrivateKey;
  /**
   * Derives an Ed25519 private key from the given key material via
   * HKDF-SHA-256 with salt `"signing"` and empty info (matches Rust
   * `bc_crypto::derive_signing_private_key`).
   */
  static deriveFromKeyMaterial(keyMaterial: Uint8Array): Ed25519PrivateKey;
  /**
   * Get the raw seed bytes (32 bytes).
   */
  data(): Uint8Array;
  /** Alias of {@link Ed25519PrivateKey.data}. */
  asBytes(): Uint8Array;
  /** Backwards-compatible alias of {@link Ed25519PrivateKey.data}. */
  toData(): Uint8Array;
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
//#endregion
//#region src/sr25519/sr25519-private-key.d.ts
/** Size of SR25519 private key (seed) in bytes */
declare const SR25519_PRIVATE_KEY_SIZE = 32;
/** Size of SR25519 public key in bytes */
declare const SR25519_PUBLIC_KEY_SIZE = 32;
/** Size of SR25519 signature in bytes */
declare const SR25519_SIGNATURE_SIZE = 64;
/** Default signing context (Substrate/Polkadot compatible) */
declare const SR25519_DEFAULT_CONTEXT: Uint8Array;
/**
 * Sr25519PrivateKey - Private key for Schnorr signatures over Ristretto25519.
 *
 * This is the signature scheme used by Polkadot/Substrate.
 */
declare class Sr25519PrivateKey {
  private readonly _seed;
  private _cachedPublicKey?;
  private constructor();
  /**
   * Create a new random Sr25519 private key.
   */
  static random(): Sr25519PrivateKey;
  /**
   * Create a new random Sr25519 private key using the provided RNG.
   */
  static randomUsing(rng: RandomNumberGenerator): Sr25519PrivateKey;
  /**
   * Create an Sr25519 private key from a 32-byte seed.
   */
  static fromSeed(seed: Uint8Array): Sr25519PrivateKey;
  /**
   * Create an Sr25519 private key from raw data.
   * Alias for fromSeed.
   */
  static from(data: Uint8Array): Sr25519PrivateKey;
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
  /**
   * Generate a keypair and return both private and public keys.
   *
   * @returns Tuple of [privateKey, publicKey]
   */
  static keypair(): [Sr25519PrivateKey, Sr25519PublicKey];
  /**
   * Generate a keypair using the provided RNG.
   *
   * @param rng - Random number generator
   * @returns Tuple of [privateKey, publicKey]
   */
  static keypairUsing(rng: RandomNumberGenerator): [Sr25519PrivateKey, Sr25519PublicKey];
  /**
   * Returns the raw seed bytes.
   */
  toData(): Uint8Array;
  /**
   * Returns the raw seed bytes (alias for toData).
   */
  asBytes(): Uint8Array;
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
   * @throws CryptoError if `context` is not the substrate default
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
//#endregion
//#region src/ec-key/ec-private-key.d.ts
declare class ECPrivateKey implements ECKey, CborTaggedEncodable, CborTaggedDecodable<ECPrivateKey>, UREncodable {
  static readonly KEY_SIZE: number;
  private readonly _data;
  private _publicKey?;
  private _schnorrPublicKey?;
  private constructor();
  /**
   * Generate a new random ECPrivateKey.
   */
  static new(): ECPrivateKey;
  /**
   * Generate a new random ECPrivateKey.
   */
  static random(): ECPrivateKey;
  /**
   * Generate a new random ECPrivateKey using provided RNG.
   */
  static newUsing(rng: RandomNumberGenerator): ECPrivateKey;
  /**
   * Generate a new random ECPrivateKey and corresponding ECPublicKey.
   */
  static keypair(): [ECPrivateKey, ECPublicKey];
  /**
   * Generate a new random ECPrivateKey and corresponding ECPublicKey
   * using the given random number generator.
   */
  static keypairUsing(rng: RandomNumberGenerator): [ECPrivateKey, ECPublicKey];
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
  static fromData(data: Uint8Array): ECPrivateKey;
  /**
   * Restore an ECPrivateKey from a reference to an array of bytes.
   * Validates the length.
   */
  static fromDataRef(data: Uint8Array): ECPrivateKey;
  /**
   * Create an ECPrivateKey from raw bytes (legacy alias).
   */
  static from(data: Uint8Array): ECPrivateKey;
  /**
   * Restore an ECPrivateKey from a hex string.
   */
  static fromHex(hex: string): ECPrivateKey;
  /**
   * Get a reference to the fixed-size array of bytes.
   */
  data(): Uint8Array;
  /**
   * Get the raw private key bytes (copy).
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
  /**
   * Returns the CBOR tags associated with ECPrivateKey.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: { 2: true, 3: h'<32-byte-key>' }
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
   * Creates an ECPrivateKey by decoding it from untagged CBOR.
   *
   * Format: { 2: true, 3: h'<32-byte-key>' }
   */
  fromUntaggedCbor(cborValue: Cbor): ECPrivateKey;
  /**
   * Creates an ECPrivateKey by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): ECPrivateKey;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): ECPrivateKey;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): ECPrivateKey;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): ECPrivateKey;
  /**
   * Returns the UR representation of the ECPrivateKey.
   * Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates an ECPrivateKey from a UR.
   */
  static fromUR(ur: UR): ECPrivateKey;
  /**
   * Creates an ECPrivateKey from a UR string.
   */
  static fromURString(urString: string): ECPrivateKey;
}
//#endregion
//#region src/mldsa/mldsa-private-key.d.ts
/**
 * MLDSAPrivateKey - Post-quantum signing private key using ML-DSA.
 */
declare class MLDSAPrivateKey implements CborTaggedEncodable, CborTaggedDecodable<MLDSAPrivateKey>, UREncodable {
  private readonly _level;
  private readonly _data;
  private constructor();
  /**
   * Generate a new random MLDSAPrivateKey with the specified security level.
   *
   * @param level - The ML-DSA security level (default: MLDSA65)
   */
  static new(level?: MLDSALevel): MLDSAPrivateKey;
  /**
   * Generate a new random MLDSAPrivateKey using the provided RNG.
   *
   * @param level - The ML-DSA security level
   * @param rng - Random number generator
   */
  static newUsing(level: MLDSALevel, rng: RandomNumberGenerator): MLDSAPrivateKey;
  /**
   * Create an MLDSAPrivateKey from raw bytes.
   *
   * @param level - The ML-DSA security level
   * @param data - The private key bytes
   */
  static fromBytes(level: MLDSALevel, data: Uint8Array): MLDSAPrivateKey;
  /**
   * Generate a keypair and return both private and public keys.
   *
   * @param level - The ML-DSA security level (default: MLDSA65)
   * @returns Tuple of [privateKey, publicKey]
   */
  static keypair(level?: MLDSALevel): [MLDSAPrivateKey, MLDSAPublicKey];
  /**
   * Generate a keypair using the provided RNG.
   *
   * @param level - The ML-DSA security level
   * @param rng - Random number generator
   * @returns Tuple of [privateKey, publicKey]
   */
  static keypairUsing(level: MLDSALevel, rng: RandomNumberGenerator): [MLDSAPrivateKey, MLDSAPublicKey];
  /**
   * Returns the security level of this key.
   */
  level(): MLDSALevel;
  /**
   * Returns the raw key bytes.
   */
  asBytes(): Uint8Array;
  /**
   * Returns a copy of the raw key bytes.
   */
  data(): Uint8Array;
  /**
   * Returns the size of the key in bytes.
   */
  size(): number;
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
  /**
   * Returns the CBOR tags associated with MLDSAPrivateKey.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: [level, key_bytes]
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
   * Creates an MLDSAPrivateKey by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cborValue: Cbor): MLDSAPrivateKey;
  /**
   * Creates an MLDSAPrivateKey by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): MLDSAPrivateKey;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): MLDSAPrivateKey;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): MLDSAPrivateKey;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): MLDSAPrivateKey;
  /**
   * Returns the UR representation.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates an MLDSAPrivateKey from a UR.
   */
  static fromUR(ur: UR): MLDSAPrivateKey;
  /**
   * Creates an MLDSAPrivateKey from a UR string.
   */
  static fromURString(urString: string): MLDSAPrivateKey;
}
//#endregion
//#region src/ssh/ssh-signature.d.ts
type SshHashAlgorithm = "sha256" | "sha512";
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
//#endregion
//#region src/ssh/ssh-private-key.d.ts
/**
 * Algorithm-specific private-key data.
 *
 *   - ed25519: 32-byte seed.
 *   - ecdsa:   curve + canonical scalar (32 / 48 bytes, no sign byte).
 *   - dsa:     canonical positive p, q, g, y (re-stated from the public
 *              key blob), plus the secret exponent x.
 */
type SshPrivateKeyData = {
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
   * deterministically from the private bytes (matching Rust's
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
   * Matches Rust `ssh_key::PrivateKey::to_openssh(LineEnding::LF)`.
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
//#endregion
//#region src/signing/signature.d.ts
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
declare class Signature implements CborTaggedEncodable, CborTaggedDecodable<Signature> {
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
   * Mirrors Rust `Signature::from_ssh`
   * (`bc-components-rust/src/signing/signature.rs:398`).
   *
   * The signature scheme is derived from the inner public-key algorithm,
   * matching Rust `Signature::scheme()` at lines 506-519.
   *
   * @param sig - The SSHSignature
   * @returns A new SSH Signature
   */
  static fromSsh(sig: SSHSignature): Signature;
  /**
   * Returns the signature scheme used to create this signature.
   */
  scheme(): SignatureScheme;
  /**
   * Returns a human-readable string identifying the signature type.
   * @returns A string like "Ed25519", "Schnorr", "ECDSA", "Sr25519", "MLDSA-44", etc.
   */
  signatureType(): string;
  /**
   * Returns the raw signature data.
   */
  data(): Uint8Array;
  /**
   * Returns the Schnorr signature data if this is a Schnorr signature.
   *
   * @returns The 64-byte signature data if this is a Schnorr signature, null otherwise
   */
  toSchnorr(): Uint8Array | null;
  /**
   * Checks if this is a Schnorr signature.
   */
  isSchnorr(): boolean;
  /**
   * Returns the ECDSA signature data if this is an ECDSA signature.
   *
   * @returns The 64-byte signature data if this is an ECDSA signature, null otherwise
   */
  toEcdsa(): Uint8Array | null;
  /**
   * Checks if this is an ECDSA signature.
   */
  isEcdsa(): boolean;
  /**
   * Returns the Ed25519 signature data if this is an Ed25519 signature.
   *
   * @returns The 64-byte signature data if this is an Ed25519 signature, null otherwise
   */
  toEd25519(): Uint8Array | null;
  /**
   * Checks if this is an Ed25519 signature.
   */
  isEd25519(): boolean;
  /**
   * Returns the Sr25519 signature data if this is an Sr25519 signature.
   *
   * @returns The 64-byte signature data if this is an Sr25519 signature, null otherwise
   */
  toSr25519(): Uint8Array | null;
  /**
   * Checks if this is an Sr25519 signature.
   */
  isSr25519(): boolean;
  /**
   * Returns the MLDSASignature if this is an MLDSA signature.
   *
   * @returns The MLDSASignature if this is an MLDSA signature, null otherwise
   */
  toMldsa(): MLDSASignature | null;
  /**
   * Checks if this is an MLDSA signature.
   */
  isMldsa(): boolean;
  /**
   * Returns the underlying SSHSignature if this is an SSH signature.
   *
   * Mirrors Rust `Signature::to_ssh`
   * (`bc-components-rust/src/signing/signature.rs:459`).
   *
   * @returns The SSHSignature if this is an SSH signature, null otherwise
   */
  toSsh(): SSHSignature | null;
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
  /**
   * Returns the CBOR tags associated with Signature.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
   *
   * Format (matching Rust bc-components):
   * - Schnorr: h'<64-byte-signature>' (bare byte string)
   * - ECDSA:   [1, h'<64-byte-signature>']
   * - Ed25519: [2, h'<64-byte-signature>']
   * - Sr25519: [3, h'<64-byte-signature>']
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
   * Creates a Signature by decoding it from untagged CBOR.
   *
   * Format (matching Rust bc-components):
   * - h'<64-byte-signature>' (bare byte string) for Schnorr
   * - [1, h'<64-byte-signature>'] for ECDSA
   * - [2, h'<64-byte-signature>'] for Ed25519
   * - [3, h'<64-byte-signature>'] for Sr25519
   */
  fromUntaggedCbor(cborValue: Cbor): Signature;
  /**
   * Creates a Signature by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): Signature;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): Signature;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): Signature;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): Signature;
  /**
   * Get the UR type for signatures.
   */
  static readonly UR_TYPE = "signature";
  /**
   * Returns the UR representation of the signature.
   *
   * The UR type prefix (`ur:signature/...`) carries the CBOR tag, so the
   * inner CBOR must be untagged — matches Rust's `UREncodable` blanket impl.
   */
  ur(): UR;
  /**
   * Returns the UR string representation of the signature.
   */
  urString(): string;
  /**
   * Creates a Signature from a UR.
   */
  static fromUR(ur: UR): Signature;
  /**
   * Creates a Signature from a UR string.
   */
  static fromURString(urString: string): Signature;
  /**
   * Alias for fromURString for Rust API compatibility.
   */
  static fromUrString(urString: string): Signature;
}
//#endregion
//#region src/signing/signer.d.ts
/**
 * A trait for types capable of creating digital signatures.
 *
 * The `Signer` interface provides methods for signing messages with various
 * cryptographic signature schemes. Implementations of this interface can sign
 * messages using different algorithms according to the specific signer type.
 */
interface Signer {
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
 * A trait for types capable of verifying digital signatures.
 *
 * The `Verifier` interface provides a method to verify that a signature was
 * created by a corresponding signer for a specific message.
 */
interface Verifier {
  /**
   * Verifies a signature against a message.
   *
   * @param signature - The signature to verify
   * @param message - The message that was allegedly signed
   * @returns `true` if the signature is valid for the message, `false` otherwise
   */
  verify(signature: Signature, message: Uint8Array): boolean;
}
//#endregion
//#region src/signing/signing-private-key.d.ts
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
declare class SigningPrivateKey implements Signer, Verifier, ReferenceProvider, CborTaggedEncodable, CborTaggedDecodable<SigningPrivateKey> {
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
  static newSchnorr(key: ECPrivateKey): SigningPrivateKey;
  /**
   * Creates a new ECDSA signing private key from an ECPrivateKey.
   *
   * @param key - The EC private key to use for ECDSA signing
   * @returns A new ECDSA signing private key
   */
  static newEcdsa(key: ECPrivateKey): SigningPrivateKey;
  /**
   * Creates a new Ed25519 signing private key from an Ed25519PrivateKey.
   *
   * @param key - The Ed25519 private key to use
   * @returns A new Ed25519 signing private key
   */
  static newEd25519(key: Ed25519PrivateKey): SigningPrivateKey;
  /**
   * Creates a new SR25519 signing private key from an Sr25519PrivateKey.
   *
   * @param key - The SR25519 private key to use
   * @returns A new SR25519 signing private key
   */
  static newSr25519(key: Sr25519PrivateKey): SigningPrivateKey;
  /**
   * Creates a new MLDSA signing private key from an MLDSAPrivateKey.
   *
   * @param key - The MLDSA private key to use
   * @returns A new MLDSA signing private key
   */
  static newMldsa(key: MLDSAPrivateKey): SigningPrivateKey;
  /**
   * Creates a new SSH signing private key from an SSHPrivateKey.
   *
   * Mirrors Rust `SigningPrivateKey::new_ssh`
   * (`bc-components-rust/src/signing/signing_private_key.rs:317`).
   *
   * @param key - The SSH private key to wrap
   * @returns A new SSH signing private key
   */
  static fromSsh(key: SSHPrivateKey): SigningPrivateKey;
  /**
   * Creates a new random Ed25519 signing private key.
   *
   * @returns A new random Ed25519 signing private key
   */
  static random(): SigningPrivateKey;
  /**
   * Creates a new random Schnorr signing private key.
   *
   * @returns A new random Schnorr signing private key
   */
  static randomSchnorr(): SigningPrivateKey;
  /**
   * Creates a new random ECDSA signing private key.
   *
   * @returns A new random ECDSA signing private key
   */
  static randomEcdsa(): SigningPrivateKey;
  /**
   * Creates a new random SR25519 signing private key.
   *
   * @returns A new random SR25519 signing private key
   */
  static randomSr25519(): SigningPrivateKey;
  /**
   * Returns the signature scheme of this key.
   */
  scheme(): SignatureScheme;
  /**
   * Returns a human-readable string identifying the key type.
   * @returns A string like "Ed25519", "Schnorr", "ECDSA", "Sr25519", "MLDSA-44", etc.
   */
  keyType(): string;
  /**
   * Returns the underlying EC private key if this is a Schnorr or ECDSA key.
   *
   * @returns The EC private key if this is a Schnorr or ECDSA key, null otherwise
   */
  toEc(): ECPrivateKey | null;
  /**
   * Returns the underlying Schnorr private key if this is a Schnorr key.
   *
   * @returns The EC private key if this is a Schnorr key, null otherwise
   */
  toSchnorr(): ECPrivateKey | null;
  /**
   * Returns the underlying ECDSA private key if this is an ECDSA key.
   *
   * @returns The EC private key if this is an ECDSA key, null otherwise
   */
  toEcdsa(): ECPrivateKey | null;
  /**
   * Returns the underlying Ed25519 private key if this is an Ed25519 key.
   *
   * @returns The Ed25519 private key if this is an Ed25519 key, null otherwise
   */
  toEd25519(): Ed25519PrivateKey | null;
  /**
   * Returns the underlying Sr25519 private key if this is an Sr25519 key.
   *
   * @returns The Sr25519 private key if this is an Sr25519 key, null otherwise
   */
  toSr25519(): Sr25519PrivateKey | null;
  /**
   * Returns the underlying MLDSA private key if this is an MLDSA key.
   *
   * @returns The MLDSA private key if this is an MLDSA key, null otherwise
   */
  toMldsa(): MLDSAPrivateKey | null;
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
   * Mirrors Rust `SigningPrivateKey::to_ssh`
   * (`bc-components-rust/src/signing/signing_private_key.rs:387`).
   *
   * @returns The SSHPrivateKey if this is an SSH key, null otherwise
   */
  toSsh(): SSHPrivateKey | null;
  /**
   * Checks if this is an SSH signing key.
   */
  isSsh(): boolean;
  /**
   * Compare with another SigningPrivateKey.
   */
  equals(other: SigningPrivateKey): boolean;
  /**
   * Mirror of Rust `Display for SigningPrivateKey`
   * (`bc-components-rust/src/signing/signing_private_key.rs:1048-1095`):
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
   * Mirrors Rust's `Verifier for SigningPrivateKey`: only Schnorr keys
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
  /**
   * Returns the CBOR tags associated with SigningPrivateKey.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
   *
   * Format (matching Rust bc-components):
   * - Schnorr: h'<32-byte-private-key>' (bare byte string)
   * - ECDSA:   [1, h'<32-byte-private-key>']
   * - Ed25519: [2, h'<32-byte-private-key>']
   * - Sr25519: [3, h'<32-byte-seed>']
   * - MLDSA:   delegates to MLDSAPrivateKey (tagged)
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
   * Creates a SigningPrivateKey by decoding it from untagged CBOR.
   *
   * Format (matching Rust bc-components):
   * - h'<32-byte-key>' (bare byte string) for Schnorr
   * - [1, h'<32-byte-key>'] for ECDSA
   * - [2, h'<32-byte-key>'] for Ed25519
   * - [3, h'<32-byte-seed>'] for Sr25519
   * - tagged MLDSA private key for MLDSA variants
   */
  fromUntaggedCbor(cborValue: Cbor): SigningPrivateKey;
  /**
   * Creates a SigningPrivateKey by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): SigningPrivateKey;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): SigningPrivateKey;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): SigningPrivateKey;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): SigningPrivateKey;
  /**
   * Static method to decode from untagged CBOR.
   */
  static fromUntaggedCbor(cborValue: Cbor): SigningPrivateKey;
  /**
   * Get the UR type for signing private keys.
   */
  static readonly UR_TYPE = "signing-private-key";
  /**
   * Returns the UR representation of the signing private key.
   */
  ur(): UR;
  /**
   * Returns the UR string representation of the signing private key.
   */
  urString(): string;
  /**
   * Creates a SigningPrivateKey from a UR.
   */
  static fromUR(ur: UR): SigningPrivateKey;
  /**
   * Creates a SigningPrivateKey from a UR string.
   */
  static fromURString(urString: string): SigningPrivateKey;
  /**
   * Alias for fromURString for Rust API compatibility.
   */
  static fromUrString(urString: string): SigningPrivateKey;
  /**
   * Returns the canonical OpenSSH armored PEM for an SSH private key.
   *
   * Only valid when this `SigningPrivateKey` wraps an `SSHPrivateKey`
   * (i.e. one of the four `SignatureScheme.SshXxx` variants). Mirrors
   * Rust's `SigningPrivateKey::SSH(key) => key.to_openssh(LineEnding::LF)`
   * usage at `signing_private_key.rs:896`.
   */
  toSshOpenssh(): string;
}
//#endregion
//#region src/signing/signature-scheme.d.ts
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
declare enum SignatureScheme {
  /**
   * BIP-340 Schnorr signature scheme (secp256k1)
   * Default scheme (matching Rust bc-components default when secp256k1 is enabled)
   */
  Schnorr = "Schnorr",
  /**
   * ECDSA signature scheme (secp256k1)
   */
  Ecdsa = "Ecdsa",
  /**
   * Ed25519 signature scheme (RFC 8032)
   */
  Ed25519 = "Ed25519",
  /**
   * SR25519 signature scheme (Schnorr over Ristretto25519)
   * Used by Polkadot/Substrate
   */
  Sr25519 = "Sr25519",
  /**
   * ML-DSA44 post-quantum signature scheme (NIST level 2)
   */
  MLDSA44 = "MLDSA44",
  /**
   * ML-DSA65 post-quantum signature scheme (NIST level 3)
   */
  MLDSA65 = "MLDSA65",
  /**
   * ML-DSA87 post-quantum signature scheme (NIST level 5)
   */
  MLDSA87 = "MLDSA87",
  /**
   * Ed25519 signature via SSH agent.
   * Requires SSH agent daemon support.
   */
  SshEd25519 = "SshEd25519",
  /**
   * DSA signature via SSH agent.
   * Requires SSH agent daemon support.
   */
  SshDsa = "SshDsa",
  /**
   * ECDSA P-256 signature via SSH agent.
   * Requires SSH agent daemon support.
   */
  SshEcdsaP256 = "SshEcdsaP256",
  /**
   * ECDSA P-384 signature via SSH agent.
   * Requires SSH agent daemon support.
   */
  SshEcdsaP384 = "SshEcdsaP384"
}
/**
 * Get the default signature scheme.
 * Defaults to Schnorr (matching Rust bc-components default when secp256k1 is enabled).
 */
declare function defaultSignatureScheme(): SignatureScheme;
/**
 * Check if a signature scheme requires SSH agent support.
 *
 * @param scheme - The signature scheme to check
 * @returns true if the scheme requires SSH agent
 */
declare function isSshScheme(scheme: SignatureScheme): boolean;
/**
 * Check if a signature scheme is a post-quantum ML-DSA scheme.
 *
 * @param scheme - The signature scheme to check
 * @returns true if the scheme is an ML-DSA scheme
 */
declare function isMldsaScheme(scheme: SignatureScheme): boolean;
/**
 * Options for configuring signature creation.
 *
 * Different signature schemes may require specific options:
 * - Schnorr: Optionally accepts a custom random number generator
 * - Ssh: Requires a namespace and hash algorithm
 *
 * Other signature types like ECDSA, Ed25519, Sr25519, and ML-DSA don't require options.
 */
type SigningOptions = {
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
 * Creates a new key pair for the signature scheme.
 *
 * @param scheme  - The signature scheme to use
 * @param comment - Optional comment for SSH keys (ignored for non-SSH schemes;
 *                  mirrors Rust `SignatureScheme::keypair_opt(comment)` at
 *                  `signature_scheme.rs:152`)
 * @returns A tuple containing a signing private key and its corresponding public key
 */
declare function createKeypair(scheme: SignatureScheme, comment?: string): [SigningPrivateKey, SigningPublicKey];
/**
 * Creates a new key pair for the signature scheme using a provided RNG.
 *
 * @param scheme  - The signature scheme to use
 * @param rng     - The random number generator to use
 * @param comment - Optional comment for SSH keys (ignored for non-SSH schemes;
 *                  mirrors Rust `SignatureScheme::keypair_using(rng, comment)`
 *                  at `signature_scheme.rs:316`)
 * @returns A tuple containing a signing private key and its corresponding public key
 * @throws CryptoError for MLDSA (which doesn't support deterministic generation)
 */
declare function createKeypairUsing(scheme: SignatureScheme, rng: RandomNumberGenerator, comment?: string): [SigningPrivateKey, SigningPublicKey];
//#endregion
//#region src/signing/signing-public-key.d.ts
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
declare class SigningPublicKey implements Verifier, ReferenceProvider, CborTaggedEncodable, CborTaggedDecodable<SigningPublicKey> {
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
   * Mirrors Rust `SigningPublicKey::from_ssh`
   * (`bc-components-rust/src/signing/signing_public_key.rs:214`).
   *
   * @param key - An SSHPublicKey
   * @returns A new signing public key wrapping the SSH public key
   */
  static fromSsh(key: SSHPublicKey): SigningPublicKey;
  /**
   * Returns the signature scheme of this key.
   */
  scheme(): SignatureScheme;
  /**
   * Returns a human-readable string identifying the key type.
   * @returns A string like "Ed25519", "Schnorr", "ECDSA", "Sr25519", "MLDSA-44", etc.
   */
  keyType(): string;
  /**
   * Returns the underlying Schnorr public key if this is a Schnorr key.
   *
   * @returns The SchnorrPublicKey if this is a Schnorr key, null otherwise
   */
  toSchnorr(): SchnorrPublicKey | null;
  /**
   * Returns the underlying ECDSA public key if this is an ECDSA key.
   *
   * @returns The ECPublicKey if this is an ECDSA key, null otherwise
   */
  toEcdsa(): ECPublicKey | null;
  /**
   * Returns the underlying Ed25519 public key if this is an Ed25519 key.
   *
   * @returns The Ed25519 public key if this is an Ed25519 key, null otherwise
   */
  toEd25519(): Ed25519PublicKey | null;
  /**
   * Returns the underlying Sr25519 public key if this is an Sr25519 key.
   *
   * @returns The Sr25519 public key if this is an Sr25519 key, null otherwise
   */
  toSr25519(): Sr25519PublicKey | null;
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
   * @returns The MLDSAPublicKey if this is an MLDSA key, null otherwise
   */
  toMldsa(): MLDSAPublicKey | null;
  /**
   * Checks if this is an MLDSA signing key.
   */
  isMldsa(): boolean;
  /**
   * Returns the underlying SSH public key if this is an SSH key.
   *
   * Mirrors Rust `SigningPublicKey::to_ssh`
   * (`bc-components-rust/src/signing/signing_public_key.rs:272`).
   *
   * @returns The SSHPublicKey if this is an SSH key, null otherwise
   */
  toSsh(): SSHPublicKey | null;
  /**
   * Checks if this is an SSH signing key.
   */
  isSsh(): boolean;
  /**
   * Returns a copy of this SSH public key with its comment replaced.
   * Throws if this is not an SSH key — mirrors Rust's `set_comment`
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
   * Mirrors Rust `Display for SigningPublicKey`
   * (`bc-components-rust/src/signing/signing_public_key.rs:573-606`):
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
  /**
   * Returns the CBOR tags associated with SigningPublicKey.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
   *
   * Format (matching Rust bc-components):
   * - Schnorr: h'<32-byte-x-only-public-key>' (bare byte string)
   * - ECDSA:   [1, h'<33-byte-compressed-public-key>']
   * - Ed25519: [2, h'<32-byte-public-key>']
   * - Sr25519: [3, h'<32-byte-public-key>']
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
   * Creates a SigningPublicKey by decoding it from untagged CBOR.
   *
   * Format (matching Rust bc-components):
   * - h'<32-byte-key>' (bare byte string) for Schnorr
   * - [1, h'<33-byte-key>'] for ECDSA
   * - [2, h'<32-byte-key>'] for Ed25519
   * - [3, h'<32-byte-key>'] for Sr25519
   */
  fromUntaggedCbor(cborValue: Cbor): SigningPublicKey;
  /**
   * Creates a SigningPublicKey by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): SigningPublicKey;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): SigningPublicKey;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): SigningPublicKey;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): SigningPublicKey;
  /**
   * Static method to decode from untagged CBOR.
   */
  static fromUntaggedCbor(cborValue: Cbor): SigningPublicKey;
  /**
   * Get the UR type for signing public keys.
   */
  static readonly UR_TYPE = "signing-public-key";
  /**
   * Returns the UR representation of the signing public key.
   */
  ur(): UR;
  /**
   * Returns the UR string representation of the signing public key.
   */
  urString(): string;
  /**
   * Creates a SigningPublicKey from a UR.
   */
  static fromUR(ur: UR): SigningPublicKey;
  /**
   * Creates a SigningPublicKey from a UR string.
   */
  static fromURString(urString: string): SigningPublicKey;
  /**
   * Alias for fromURString for Rust API compatibility.
   */
  static fromUrString(urString: string): SigningPublicKey;
  /**
   * Returns the OpenSSH single-line public-key text for an SSH public key.
   *
   * Only valid when this `SigningPublicKey` wraps an `SSHPublicKey`
   * (i.e. one of the four `SignatureScheme.SshXxx` variants). Mirrors
   * Rust's `SigningPublicKey::SSH(key) => key.to_openssh()` usage at
   * `signing_public_key.rs:442`.
   */
  toSshOpenssh(): string;
}
//#endregion
//#region src/public-keys.d.ts
/**
 * Trait for types that provide access to a PublicKeys container.
 *
 * This is useful for types that wrap or contain public keys and need
 * to provide access to the underlying key material.
 */
interface PublicKeysProvider {
  /**
   * Returns the PublicKeys container.
   */
  publicKeys(): PublicKeys;
}
/**
 * PublicKeys - Container for a signing public key and an encapsulation public key.
 *
 * This type provides a convenient way to share public keys for both
 * signature verification and encryption operations.
 */
declare class PublicKeys implements Verifier, Encrypter, ReferenceProvider, CborTaggedEncodable, CborTaggedDecodable<PublicKeys>, UREncodable {
  private readonly _signingPublicKey;
  private readonly _encapsulationPublicKey;
  private constructor();
  /**
   * Create a new PublicKeys container with the given keys.
   */
  static new(signingPublicKey: SigningPublicKey, encapsulationPublicKey: EncapsulationPublicKey): PublicKeys;
  /**
   * Returns the signing public key.
   */
  signingPublicKey(): SigningPublicKey;
  /**
   * Returns the encapsulation public key.
   *
   * Note: Named to match Rust's API (which has a typo but we maintain compatibility)
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
   * Mirrors Rust `Display for PublicKeys`
   * (`bc-components-rust/src/public_keys.rs:216-225`):
   *   `PublicKeys(<short_reference>, <signing_public_key>, <encapsulation_public_key>)`
   *
   * The earlier short form (`PublicKeys(<short_reference>)`) was
   * observable in envelope notation as a missing key fingerprint
   * trail in the GSTP `'sender': XID(...) [ 'key': PublicKeys(...) ]`
   * format-pin (G1 in `PARITY_OUTSTANDING.md`).
   */
  toString(): string;
  /**
   * Returns the CBOR tags associated with PublicKeys.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: [<SigningPublicKey>, <EncapsulationPublicKey>]
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
   * Creates a PublicKeys by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cborValue: Cbor): PublicKeys;
  /**
   * Creates a PublicKeys by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): PublicKeys;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): PublicKeys;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): PublicKeys;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): PublicKeys;
  /**
   * Returns the UR representation.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates a PublicKeys from a UR.
   */
  static fromUR(ur: UR): PublicKeys;
  /**
   * Creates a PublicKeys from a UR string.
   */
  static fromURString(urString: string): PublicKeys;
}
//#endregion
//#region src/private-keys.d.ts
/**
 * Trait for types that provide access to a PrivateKeys container.
 *
 * This is useful for types that wrap or contain private keys and need
 * to provide access to the underlying key material.
 */
interface PrivateKeysProvider {
  /**
   * Returns the PrivateKeys container.
   */
  privateKeys(): PrivateKeys;
}
/**
 * PrivateKeys - Container for a signing key and an encapsulation key.
 *
 * This type provides a convenient way to manage a pair of private keys
 * for both signing and encryption operations.
 */
declare class PrivateKeys implements Signer, Decrypter, ReferenceProvider, CborTaggedEncodable, CborTaggedDecodable<PrivateKeys>, UREncodable {
  private readonly _signingPrivateKey;
  private readonly _encapsulationPrivateKey;
  private constructor();
  /**
   * Create a new PrivateKeys container with the given keys.
   */
  static withKeys(signingPrivateKey: SigningPrivateKey, encapsulationPrivateKey: EncapsulationPrivateKey): PrivateKeys;
  /**
   * Create a new PrivateKeys container with random Ed25519/X25519 keys.
   */
  static new(): PrivateKeys;
  /**
   * Generate a new PrivateKeys container with random Ed25519/X25519 keys.
   * This is an alias for new() for API compatibility.
   */
  static generate(): PrivateKeys;
  /**
   * Returns the signing private key.
   */
  signingPrivateKey(): SigningPrivateKey;
  /**
   * Returns the encapsulation private key.
   *
   * Note: Named to match Rust's API (which has a typo but we maintain compatibility)
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
   * Mirror of Rust `Display for PrivateKeys`
   * (`bc-components-rust/src/private_keys.rs:229-238`):
   *   `PrivateKeys(<refHexShort>, <signingPrivateKey>, <encapsulationPrivateKey>)`
   * The previous abbreviated form (`PrivateKeys(<short>)` only) was a
   * parity drift caught by the E1a summarizer audit.
   */
  toString(): string;
  /**
   * Returns the CBOR tags associated with PrivateKeys.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
   *
   * Format: [<SigningPrivateKey>, <EncapsulationPrivateKey>]
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
   * Creates a PrivateKeys by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cborValue: Cbor): PrivateKeys;
  /**
   * Creates a PrivateKeys by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): PrivateKeys;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): PrivateKeys;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): PrivateKeys;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): PrivateKeys;
  /**
   * Returns the UR representation.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates a PrivateKeys from a UR.
   */
  static fromUR(ur: UR): PrivateKeys;
  /**
   * Creates a PrivateKeys from a UR string.
   */
  static fromURString(urString: string): PrivateKeys;
}
//#endregion
//#region src/private-key-base.d.ts
/**
 * PrivateKeyBase - Root cryptographic material for deterministic key derivation.
 *
 * This is the foundation from which signing keys and agreement keys can be
 * deterministically derived using HKDF.
 */
declare class PrivateKeyBase implements CborTaggedEncodable, CborTaggedDecodable<PrivateKeyBase>, UREncodable, Decrypter {
  private readonly _data;
  private constructor();
  /**
   * Create a new random PrivateKeyBase.
   */
  static new(): PrivateKeyBase;
  /**
   * Create a new random PrivateKeyBase using the provided RNG.
   */
  static newUsing(rng: RandomNumberGenerator): PrivateKeyBase;
  /**
   * Create a PrivateKeyBase from raw bytes.
   *
   * @param data - 32 bytes of key material
   */
  static fromData(data: Uint8Array): PrivateKeyBase;
  /**
   * Returns the raw key material.
   */
  asBytes(): Uint8Array;
  /**
   * Returns a copy of the raw key material.
   */
  data(): Uint8Array;
  /**
   * Derive an Ed25519 signing private key.
   *
   * Uses HKDF with salt "signing", matching Rust's derive_signing_private_key().
   */
  ed25519SigningPrivateKey(): SigningPrivateKey;
  /**
   * Derive an X25519 agreement private key.
   *
   * Uses HKDF with salt "agreement", matching Rust's derive_agreement_private_key().
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
   * directly as a recipient key, mirroring Rust `impl Decrypter for
   * PrivateKeyBase`.
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
   * Uses ECPrivateKey.deriveFromKeyMaterial() matching Rust's
   * PrivateKeyBase::schnorr_signing_private_key().
   */
  schnorrSigningPrivateKey(): SigningPrivateKey;
  /**
   * Derive a PrivateKeys container with Schnorr signing and X25519 agreement keys.
   *
   * Matches Rust's PrivateKeyBase::schnorr_private_keys().
   */
  schnorrPrivateKeys(): PrivateKeys;
  /**
   * Derive a PublicKeys container from Schnorr derived keys.
   */
  schnorrPublicKeys(): PublicKeys;
  /**
   * Derive an ECDSA signing private key.
   *
   * Uses ECPrivateKey.deriveFromKeyMaterial() matching Rust's
   * PrivateKeyBase::ecdsa_signing_private_key().
   */
  ecdsaSigningPrivateKey(): SigningPrivateKey;
  /**
   * Derive a PrivateKeys container with ECDSA signing and X25519 agreement keys.
   *
   * Matches Rust's PrivateKeyBase::ecdsa_private_keys().
   */
  ecdsaPrivateKeys(): PrivateKeys;
  /**
   * Derive a PublicKeys container from ECDSA derived keys.
   */
  ecdsaPublicKeys(): PublicKeys;
  /**
   * Derive an SSH `SigningPrivateKey` from this `PrivateKeyBase`.
   *
   * Mirrors Rust `PrivateKeyBase::ssh_signing_private_key`
   * (`bc-components-rust/src/private_key_base.rs:179-207`):
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
   * agreement key. Mirrors Rust `PrivateKeyBase::ssh_private_keys`
   * (`bc-components-rust/src/private_key_base.rs:273-283`).
   */
  sshPrivateKeys(algorithm: SshAlgorithm, comment?: string): PrivateKeys;
  /**
   * Derive a `PublicKeys` container from `sshPrivateKeys`. Mirrors Rust
   * `PrivateKeyBase::ssh_public_keys`
   * (`bc-components-rust/src/private_key_base.rs:289-300`).
   */
  sshPublicKeys(algorithm: SshAlgorithm, comment?: string): PublicKeys;
  /**
   * Internal key derivation using HKDF-SHA256.
   * Matches Rust's hkdf_hmac_sha256(key_material, salt, key_len) with empty info.
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
  /**
   * Returns the CBOR tags associated with PrivateKeyBase.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
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
   * Creates a PrivateKeyBase by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cborValue: Cbor): PrivateKeyBase;
  /**
   * Creates a PrivateKeyBase by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): PrivateKeyBase;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): PrivateKeyBase;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): PrivateKeyBase;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): PrivateKeyBase;
  /**
   * Returns the UR representation.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates a PrivateKeyBase from a UR.
   */
  static fromUR(ur: UR): PrivateKeyBase;
  /**
   * Creates a PrivateKeyBase from a UR string.
   */
  static fromURString(urString: string): PrivateKeyBase;
}
//#endregion
//#region src/id/xid.d.ts
/**
 * XID prefix glyph for the upper-case bytewords/bytemoji identifier.
 *
 * Exported as the single source of truth so dependent packages (`@blockchaincommons/xid`,
 * `@blockchaincommons/envelope`, etc.) don't redefine the literal `"🅧"`.
 */
declare const XID_PREFIX = "🅧";
/**
 * Trait-style interface for objects that can produce a XID.
 *
 * Mirrors Rust's `XIDProvider` trait. `XID` itself implements this; any
 * other type that maps cleanly to a single XID (e.g. `SigningPublicKey`,
 * `PublicKeys`) may also implement it.
 */
interface XIDProvider {
  /** Returns the XID for this object. */
  xid(): XID;
}
/**
 * Type guard for {@link XIDProvider}.
 */
declare function isXIDProvider(obj: unknown): obj is XIDProvider;
declare class XID implements CborTaggedEncodable, CborTaggedDecodable<XID>, UREncodable, XIDProvider, ReferenceProvider {
  static readonly XID_SIZE: number;
  private readonly _data;
  private constructor();
  /**
   * Create a new XID from data.
   */
  static fromData(data: Uint8Array): XID;
  /**
   * Create a new XID from data (validates length).
   *
   * Returns error if the data is not the correct length.
   */
  static fromDataRef(data: Uint8Array): XID;
  /**
   * Create an XID from raw bytes (legacy alias).
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
  static random(): XID;
  /**
   * Create a new XID from the given public key (the "genesis key").
   *
   * The XID is the SHA-256 digest of the CBOR encoding of the public key.
   * This matches Rust's `XID::new(genesis_key: impl AsRef<SigningPublicKey>)`.
   */
  static newFromSigningKey(signingPublicKey: SigningPublicKey): XID;
  /**
   * Mirror of Rust's `From<&SigningPublicKey> for XID`.
   * Equivalent to {@link XID.newFromSigningKey}; provided for API parity.
   */
  static fromSigningPublicKey(signingPublicKey: SigningPublicKey): XID;
  /**
   * Mirror of Rust's `From<&PublicKeys> for XID`.
   * The XID is derived from the bundle's signing public key.
   */
  static fromPublicKeys(publicKeys: PublicKeys): XID;
  /**
   * Mirror of Rust's `From<&PrivateKeyBase> for XID` (secp256k1 feature).
   * The XID is derived from the schnorr signing public key.
   */
  static fromPrivateKeyBase(base: PrivateKeyBase): XID;
  /**
   * Mirror of Rust's `TryFrom<&SigningPrivateKey> for XID`.
   * The XID is derived from the corresponding public key.
   */
  static tryFromSigningPrivateKey(signingPrivateKey: SigningPrivateKey): XID;
  /**
   * Validate the XID against the given public key.
   *
   * Returns true if the SHA-256 hash of the key's CBOR encoding matches
   * the XID data. This matches Rust's `XID::validate(&self, key: &SigningPublicKey)`.
   */
  validate(signingPublicKey: SigningPublicKey): boolean;
  /**
   * Return the data of the XID.
   */
  data(): Uint8Array;
  /**
   * Get the data of the XID as a byte slice.
   */
  asBytes(): Uint8Array;
  /**
   * Get a copy of the raw XID bytes.
   */
  toData(): Uint8Array;
  /**
   * Get hex string representation (lowercase, matching Rust implementation).
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
   * Mirrors Rust's blanket `impl XIDProvider for XID`.
   */
  xid(): XID;
  /**
   * ReferenceProvider impl — produces a Reference whose 32 bytes are the
   * raw XID data.
   *
   * Mirrors Rust's `impl ReferenceProvider for XID { fn reference(&self) ->
   * Reference { Reference::from_data(*self.data()) } }` — note this is a
   * direct wrap, not a SHA-256 hash of the XID.
   */
  reference(): Reference;
  /**
   * Compare with another XID.
   */
  equals(other: XID): boolean;
  /**
   * Get string representation (short format, matching Rust Display).
   * Uses first 4 bytes of the XID as hex, e.g., "XID(71274df1)".
   */
  toString(): string;
  /**
   * Returns the CBOR tags associated with XID.
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
   * Creates a XID by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cbor: Cbor): XID;
  /**
   * Creates a XID by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cbor: Cbor): XID;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cbor: Cbor): XID;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): XID;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): XID;
  /**
   * Returns the UR representation of the XID.
   * Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates a XID from a UR.
   */
  static fromUR(ur: UR): XID;
  /**
   * Creates a XID from a UR string.
   */
  static fromURString(urString: string): XID;
}
//#endregion
//#region src/id/uri.d.ts
declare class URI implements CborTaggedEncodable, CborTaggedDecodable<URI>, UREncodable {
  private readonly _uri;
  private constructor();
  /**
   * Creates a new `URI` from a string with validation.
   */
  static new(uri: string): URI;
  /**
   * Create a URI from string (legacy alias).
   */
  static from(uri: string): URI;
  /**
   * Parse a URI string (alias for new()).
   */
  static parse(uriString: string): URI;
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
  getRaw(): string;
  /**
   * Get scheme (e.g., "http", "https", "urn").
   */
  scheme(): string | null;
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
  length(): number;
  /**
   * Returns the CBOR tags associated with URI.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding (as a text string).
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
   * Creates a URI by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cborValue: Cbor): URI;
  /**
   * Creates a URI by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): URI;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): URI;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): URI;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): URI;
  /**
   * Returns the UR representation of the URI.
   * Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates a URI from a UR.
   */
  static fromUR(ur: UR): URI;
  /**
   * Creates a URI from a UR string.
   */
  static fromURString(urString: string): URI;
}
//#endregion
//#region src/keypair.d.ts
/**
 * Generates a key pair using the default signature and encapsulation schemes
 * (Schnorr + X25519).
 *
 * Mirrors Rust `pub fn keypair() -> (PrivateKeys, PublicKeys)`.
 */
declare function keypair(): [PrivateKeys, PublicKeys];
/**
 * Generates a key pair using the default schemes and a provided RNG.
 *
 * Mirrors Rust `pub fn keypair_using(rng) -> Result<(PrivateKeys, PublicKeys)>`.
 *
 * Note: ML-KEM does not support deterministic generation. This helper uses
 * the default encapsulation scheme (X25519), which does.
 */
declare function keypairUsing(rng: RandomNumberGenerator): [PrivateKeys, PublicKeys];
/**
 * Generates a key pair with explicit signature and encapsulation schemes.
 *
 * Mirrors Rust `pub fn keypair_opt(sig, enc) -> (PrivateKeys, PublicKeys)`.
 */
declare function keypairOpt(signatureScheme: SignatureScheme, encapsulationScheme: EncapsulationScheme): [PrivateKeys, PublicKeys];
/**
 * Generates a key pair with explicit schemes and a provided RNG.
 *
 * Mirrors Rust `pub fn keypair_opt_using(sig, enc, rng) ->
 *   Result<(PrivateKeys, PublicKeys)>`.
 *
 * Throws if either scheme does not support deterministic generation
 * (e.g. ML-DSA / ML-KEM, or any SSH-based signing scheme).
 */
declare function keypairOptUsing(signatureScheme: SignatureScheme, encapsulationScheme: EncapsulationScheme, rng: RandomNumberGenerator): [PrivateKeys, PublicKeys];
//#endregion
//#region src/encapsulation/sealed-message.d.ts
/**
 * A sealed message providing anonymous authenticated encryption.
 */
declare class SealedMessage implements CborTaggedEncodable, CborTaggedDecodable<SealedMessage>, UREncodable {
  private readonly _message;
  private readonly _encapsulatedKey;
  private constructor();
  /**
   * Create a SealedMessage from its components.
   */
  static from(message: EncryptedMessage, encapsulatedKey: EncapsulationCiphertext): SealedMessage;
  /**
   * Seal a message for a recipient (no additional authenticated data).
   *
   * @param plaintext - The message to encrypt
   * @param recipient - The recipient's public key
   * @returns A sealed message that only the recipient can decrypt
   */
  static new(plaintext: Uint8Array, recipient: EncapsulationPublicKey): SealedMessage;
  /**
   * Seal a message for a recipient with additional authenticated data.
   *
   * @param plaintext - The message to encrypt
   * @param recipient - The recipient's public key
   * @param aad - Additional authenticated data (not encrypted but authenticated)
   * @returns A sealed message that only the recipient can decrypt
   */
  static newWithAad(plaintext: Uint8Array, recipient: EncapsulationPublicKey, aad: Uint8Array): SealedMessage;
  /**
   * Seal a message with optional test nonce (for deterministic testing).
   *
   * @param plaintext - The message to encrypt
   * @param recipient - The recipient's public key
   * @param aad - Additional authenticated data
   * @param testNonce - Optional fixed nonce for testing (DO NOT use in production)
   * @returns A sealed message
   */
  static newOpt(plaintext: Uint8Array, recipient: EncapsulationPublicKey, aad: Uint8Array, testNonce?: Nonce): SealedMessage;
  /**
   * Returns the encrypted message.
   */
  message(): EncryptedMessage;
  /**
   * Returns the encapsulation ciphertext (ephemeral public key for X25519).
   */
  encapsulatedKey(): EncapsulationCiphertext;
  /**
   * Returns the encapsulation scheme used.
   */
  encapsulationScheme(): EncapsulationScheme;
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
  /**
   * Returns the CBOR tags associated with SealedMessage.
   */
  cborTags(): Tag[];
  /**
   * Returns the untagged CBOR encoding.
   * Format: [EncryptedMessage (tagged), EncapsulationCiphertext (tagged)]
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
   * Creates a SealedMessage by decoding it from untagged CBOR.
   */
  fromUntaggedCbor(cborValue: Cbor): SealedMessage;
  /**
   * Creates a SealedMessage by decoding it from tagged CBOR.
   */
  fromTaggedCbor(cborValue: Cbor): SealedMessage;
  /**
   * Static method to decode from tagged CBOR.
   */
  static fromTaggedCbor(cborValue: Cbor): SealedMessage;
  /**
   * Static method to decode from tagged CBOR binary data.
   */
  static fromTaggedCborData(data: Uint8Array): SealedMessage;
  /**
   * Static method to decode from untagged CBOR binary data.
   */
  static fromUntaggedCborData(data: Uint8Array): SealedMessage;
  /**
   * Returns the UR representation of the SealedMessage.
   * Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
   */
  ur(): UR;
  /**
   * Returns the UR string representation.
   */
  urString(): string;
  /**
   * Creates a SealedMessage from a UR.
   */
  static fromUR(ur: UR): SealedMessage;
  /**
   * Creates a SealedMessage from a UR string.
   */
  static fromURString(urString: string): SealedMessage;
}
//#endregion
//#region src/encrypted-key/hash-type.d.ts
/**
 * Enum representing supported hash types for key derivation.
 */
declare enum HashType {
  /** SHA-256 hash algorithm */
  SHA256 = 0,
  /** SHA-512 hash algorithm */
  SHA512 = 1
}
/**
 * Convert HashType to its string representation.
 */
declare function hashTypeToString(hashType: HashType): string;
/**
 * Convert HashType to CBOR.
 */
declare function hashTypeToCbor(hashType: HashType): Cbor;
/**
 * Parse HashType from CBOR.
 */
declare function hashTypeFromCbor(cborValue: Cbor): HashType;
//#endregion
//#region src/encrypted-key/key-derivation-method.d.ts
/**
 * Enum representing supported key derivation methods.
 */
declare enum KeyDerivationMethod {
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
 * Returns the default key derivation method (Argon2id).
 */
declare function defaultKeyDerivationMethod(): KeyDerivationMethod;
/**
 * Returns the zero-based index of the key derivation method.
 */
declare function keyDerivationMethodIndex(method: KeyDerivationMethod): number;
/**
 * Attempts to create a KeyDerivationMethod from a zero-based index.
 */
declare function keyDerivationMethodFromIndex(index: number): KeyDerivationMethod | undefined;
/**
 * Convert KeyDerivationMethod to its string representation.
 */
declare function keyDerivationMethodToString(method: KeyDerivationMethod): string;
/**
 * Parse KeyDerivationMethod from CBOR.
 */
declare function keyDerivationMethodFromCbor(cborValue: Cbor): KeyDerivationMethod;
//#endregion
//#region src/encrypted-key/key-derivation.d.ts
/**
 * Interface for key derivation implementations.
 *
 * All key derivation methods must implement this interface to provide
 * lock (encrypt) and unlock (decrypt) operations.
 */
interface KeyDerivation {
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
//#endregion
//#region src/encrypted-key/hkdf-params.d.ts
/** Default salt length for key derivation */
declare const SALT_LEN = 16;
/**
 * HKDF parameters for key derivation.
 *
 * HKDF is suitable for deriving keys from high-entropy inputs (like other keys),
 * but NOT for password-based key derivation.
 */
declare class HKDFParams implements KeyDerivation {
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
//#endregion
//#region src/encrypted-key/pbkdf2-params.d.ts
/** Default number of iterations for PBKDF2 */
declare const DEFAULT_PBKDF2_ITERATIONS = 1e5;
/**
 * PBKDF2 parameters for password-based key derivation.
 */
declare class PBKDF2Params implements KeyDerivation {
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
//#endregion
//#region src/encrypted-key/scrypt-params.d.ts
/** Default log_n parameter (2^15 = 32768 iterations) */
declare const DEFAULT_SCRYPT_LOG_N = 15;
/** Default r parameter (block size) */
declare const DEFAULT_SCRYPT_R = 8;
/** Default p parameter (parallelism) */
declare const DEFAULT_SCRYPT_P = 1;
/**
 * Scrypt parameters for password-based key derivation.
 *
 * Parameters:
 * - log_n: CPU/memory cost parameter (N = 2^log_n)
 * - r: Block size parameter
 * - p: Parallelization parameter
 */
declare class ScryptParams implements KeyDerivation {
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
//#endregion
//#region src/encrypted-key/argon2id-params.d.ts
/**
 * Argon2id parameters for password-based key derivation.
 *
 * This is the recommended method for password-based key derivation as it
 * provides the best protection against both GPU cracking and side-channel
 * attacks.
 */
declare class Argon2idParams implements KeyDerivation {
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
//#endregion
//#region src/encrypted-key/ssh-agent-params.d.ts
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
declare class SSHAgentParams implements KeyDerivation {
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
//#endregion
//#region src/encrypted-key/key-derivation-params.d.ts
/**
 * Union type representing key derivation parameters.
 *
 * Use the `method()` function to get the derivation method, and
 * `lock()`/`unlock()` for key operations.
 */
type KeyDerivationParams = {
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
 * Create HKDF derivation parameters.
 */
declare function hkdfParams(params?: HKDFParams): KeyDerivationParams;
/**
 * Create PBKDF2 derivation parameters.
 */
declare function pbkdf2Params(params?: PBKDF2Params): KeyDerivationParams;
/**
 * Create Scrypt derivation parameters.
 */
declare function scryptParams(params?: ScryptParams): KeyDerivationParams;
/**
 * Create Argon2id derivation parameters.
 */
declare function argon2idParams(params?: Argon2idParams): KeyDerivationParams;
/**
 * Create SSH agent derivation parameters.
 *
 * @param idOrParams - Either an SSH key identity string or SSHAgentParams instance
 */
declare function sshAgentParams(idOrParams: string | SSHAgentParams): KeyDerivationParams;
/**
 * Create default key derivation parameters (Argon2id).
 */
declare function defaultKeyDerivationParams(): KeyDerivationParams;
/**
 * Get the key derivation method for the given parameters.
 */
declare function keyDerivationParamsMethod(kdp: KeyDerivationParams): KeyDerivationMethod;
/**
 * Check if the parameters use a password-based method.
 * Password-based methods (PBKDF2, Scrypt, Argon2id) are designed for
 * low-entropy secrets like passwords.
 */
declare function isPasswordBased(kdp: KeyDerivationParams): boolean;
/**
 * Check if the parameters use SSH Agent for key derivation.
 *
 * Note: SSH Agent key derivation is not yet functional in TypeScript.
 * This function is useful for detecting envelopes locked by other
 * implementations (e.g., Rust).
 */
declare function isSshAgent(kdp: KeyDerivationParams): boolean;
/**
 * Lock (encrypt) a content key using the derived key.
 */
declare function lockWithParams(kdp: KeyDerivationParams, contentKey: SymmetricKey, secret: Uint8Array): EncryptedMessage;
/**
 * Convert KeyDerivationParams to CBOR.
 */
declare function keyDerivationParamsToCbor(kdp: KeyDerivationParams): Cbor;
/**
 * Convert KeyDerivationParams to CBOR binary data.
 */
declare function keyDerivationParamsToCborData(kdp: KeyDerivationParams): Uint8Array;
/**
 * Get string representation of KeyDerivationParams.
 */
declare function keyDerivationParamsToString(kdp: KeyDerivationParams): string;
/**
 * Parse KeyDerivationParams from CBOR.
 */
declare function keyDerivationParamsFromCbor(cborValue: Cbor): KeyDerivationParams;
//#endregion
//#region src/encrypted-key/encrypted-key.d.ts
/**
 * Encrypted key providing secure storage of symmetric keys.
 *
 * Use `lock()` to encrypt a content key with a password or secret,
 * and `unlock()` to decrypt it.
 */
declare class EncryptedKey implements CborTaggedEncodable, CborTaggedDecodable<EncryptedKey>, UREncodable {
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
//#endregion
//#region src/sskr.d.ts
declare class SSKRShareCbor implements CborTaggedEncodable, CborTaggedDecodable<SSKRShareCbor> {
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
type SSKRShare = SSKRShareCbor;
declare const SSKRShare: {
  fromData: (data: Uint8Array) => SSKRShareCbor;
  fromHex: (hex: string) => SSKRShareCbor;
  fromTaggedCbor: (cborValue: Cbor) => SSKRShareCbor;
  fromTaggedCborData: (data: Uint8Array) => SSKRShareCbor;
  fromUntaggedCborData: (data: Uint8Array) => SSKRShareCbor;
};
/** Raw share bytes per group, as sskr's `generateShares` + `shareBytes`. */
declare function sskrGenerate(spec: SSKRSpec, masterSecret: SSKRSecret): Uint8Array[][];
declare function sskrGenerateUsing(spec: SSKRSpec, masterSecret: SSKRSecret, rng: RandomNumberGenerator): Uint8Array[][];
declare function sskrCombine(shares: Uint8Array[]): SSKRSecret;
declare function sskrGenerateShares(spec: SSKRSpec, masterSecret: SSKRSecret): SSKRShare[][];
interface SimpleRng {
  fillBytes(data: Uint8Array): void;
}
declare function sskrGenerateSharesUsing(spec: SSKRSpec, masterSecret: SSKRSecret, rng: SimpleRng): SSKRShare[][];
declare function sskrCombineShares(shares: SSKRShare[]): SSKRSecret;
//#endregion
//#region src/ssh/ssh-certificate.d.ts
declare class SSHCertificate {
  /** The full single-line OpenSSH cert text, e.g.
   *  `ssh-ed25519-cert-v01@openssh.com AAAAI...== user@host`. */
  readonly text: string;
  private constructor();
  /** Construct from the canonical OpenSSH certificate text. */
  static fromText(text: string): SSHCertificate;
  /** The canonical OpenSSH text — round-trips byte-identically. */
  toText(): string;
  /** Fixed summarizer string — matches Rust `tags_registry.rs:236`. */
  toString(): string;
  digest(): Uint8Array;
}
//#endregion
export { ARID, Argon2idParams, AuthenticationTag, COMPRESSED, Compressed, CryptoError, DEFAULT_PBKDF2_ITERATIONS, DEFAULT_SCRYPT_LOG_N, DEFAULT_SCRYPT_P, DEFAULT_SCRYPT_R, type DataTooShortData, type Decrypter, Digest, type DigestProvider, type ECKey, type ECKeyBase, ECPrivateKey, ECPublicKey, type ECPublicKeyBase, ECUncompressedPublicKey, ENCRYPTED, ENVELOPE, Ed25519PrivateKey, Ed25519PublicKey, EncapsulationCiphertext, EncapsulationPrivateKey, EncapsulationPublicKey, EncapsulationScheme, EncryptedKey, EncryptedMessage, type Encrypter, type ErrorData, ErrorKind, HKDFParams, HKDFRng, HashType, type InvalidDataData, type InvalidSizeData, JSON, KNOWN_VALUE, type KeyDerivation, KeyDerivationMethod, type KeyDerivationParams, LEAF, type MLDSAKeypairData, MLDSALevel, MLDSAPrivateKey, MLDSAPublicKey, MLDSASignature, MLDSA_KEY_SIZES, MLKEMCiphertext, type MLKEMEncapsulationPair, type MLKEMEncapsulationResult, type MLKEMKeypairData, MLKEMLevel, MLKEMPrivateKey, MLKEMPublicKey, MLKEM_KEY_SIZES, Nonce, PBKDF2Params, PrivateKeyBase, type PrivateKeyDataProvider, PrivateKeys, type PrivateKeysProvider, PublicKeys, type PublicKeysProvider, Reference, type ReferenceEncodingFormat, type ReferenceProvider, type Result, SALT_LEN, SR25519_DEFAULT_CONTEXT, SR25519_PRIVATE_KEY_SIZE, SR25519_PUBLIC_KEY_SIZE, SR25519_SIGNATURE_SIZE, SSHAgentParams, SSHCertificate, SSHPrivateKey, SSHPublicKey, SSHSignature, SSH_ALGO_ECDSA_NISTP256, SSH_ALGO_ED25519, SSH_CURVE_NISTP256, SSKRGroupSpec, SSKRSecret, SSKRShare, SSKRShareCbor, SSKRSpec, Salt, SchnorrPublicKey, ScryptParams, SealedMessage, Seed, type SeedMetadata, Signature, SignatureScheme, type Signer, type SigningOptions, SigningPrivateKey, SigningPublicKey, type SimpleRng, Sr25519PrivateKey, Sr25519PublicKey, type SshAlgorithm, type SshEcdsaCurve, type SshHashAlgorithm, type SshPrivateKeyData, type SshPublicKeyData, SymmetricKey, URI, UUID, type Verifier, X25519PrivateKey, X25519PublicKey, XID, type XIDProvider, XID_PREFIX, argon2idParams, bytesEqual, bytesToHex, createEncapsulationKeypair, createEncapsulationKeypairUsing, createKeypair, createKeypairUsing, defaultEncapsulationScheme, defaultKeyDerivationMethod, defaultKeyDerivationParams, defaultSignatureScheme, digestFromBytes, fromBase64, hashTypeFromCbor, hashTypeToCbor, hashTypeToString, hexToBytes, hkdfParams, isCryptoError, isCryptoErrorKind, isDecrypter, isECKey, isECKeyBase, isECPublicKeyBase, isEncrypter, isError, isMldsaScheme, isPasswordBased, isPrivateKeyDataProvider, isReferenceProvider, isSshAgent, isSshScheme, isXIDProvider, keyDerivationMethodFromCbor, keyDerivationMethodFromIndex, keyDerivationMethodIndex, keyDerivationMethodToString, keyDerivationParamsFromCbor, keyDerivationParamsMethod, keyDerivationParamsToCbor, keyDerivationParamsToCborData, keyDerivationParamsToString, keypair, keypairOpt, keypairOptUsing, keypairUsing, lockWithParams, mldsaGenerateKeypair, mldsaGenerateKeypairUsing, mldsaLevelFromValue, mldsaLevelToString, mldsaPrivateKeySize, mldsaPublicKeySize, mldsaSign, mldsaSignatureSize, mldsaVerify, mlkemCiphertextSize, mlkemDecapsulate, mlkemEncapsulate, mlkemGenerateKeypair, mlkemGenerateKeypairUsing, mlkemLevelFromValue, mlkemLevelToString, mlkemPrivateKeySize, mlkemPublicKeySize, mlkemSharedSecretSize, parseSshAlgorithm, pbkdf2Params, scryptParams, sshAgentParams, sshAlgorithmName, sskrCombine, sskrCombineShares, sskrGenerate, sskrGenerateShares, sskrGenerateSharesUsing, sskrGenerateUsing, toBase64 };
//# sourceMappingURL=index.d.mts.map