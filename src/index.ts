/**
 * @blockchaincommons/components - Cryptographic components library
 * TypeScript implementation of Blockchain Commons' cryptographic components specification
 */

// Error handling
export { ComponentsError, COMPONENTS_ERROR_CODES } from "./error.js";
export type { ComponentCodec, Codable } from "./codable.js";
export type {
  ComponentsErrorCode,
  ComponentsErrorDetails,
  InvalidSizeDetails,
  InvalidDataDetails,
  DataTooShortDetails,
  MessageDetails,
} from "./error.js";

// PrivateKeyDataProvider interface
export type { PrivateKeyDataProvider } from "./private-key-data-provider.js";
export { isPrivateKeyDataProvider } from "./private-key-data-provider.js";

// Encrypter/Decrypter interfaces
export type { Encrypter, Decrypter } from "./encrypter.js";
export { isEncrypter, isDecrypter } from "./encrypter.js";

// JSON wrapper
export { CborJson } from "./json.js";

// Compressed data
export { Compressed } from "./compressed.js";

// Utility functions
export { bytesToHex, hexToBytes, toBase64, fromBase64, bytesEqual } from "./utils.js";

// DigestProvider interface
export type { DigestProvider } from "./digest-provider.js";
export { digestFromBytes } from "./digest-provider.js";

// Basic cryptographic primitives
export { Digest } from "./digest.js";
export { Nonce } from "./nonce.js";
export { Salt } from "./salt.js";
export { Seed } from "./seed.js";
export type { SeedMetadata } from "./seed.js";

// References
export { Reference, isReferenceProvider } from "./reference.js";
export type { ReferenceEncodingFormat, ReferenceProvider } from "./reference.js";

// Identifier types (from id/ module)
export { ARID, UUID, XID, XID_PREFIX, URI, isXIDProvider } from "./id/index.js";
export type { XIDProvider } from "./id/index.js";

// Top-level keypair helpers (PrivateKeys + PublicKeys bundle).
export { generateKeypair, type KeypairOptions } from "./keypair.js";

// Key agreement - X25519 (from x25519/ module)
export { X25519PrivateKey, X25519PublicKey } from "./x25519/index.js";

// Digital signatures - Ed25519 (from ed25519/ module)
export { Ed25519PrivateKey, Ed25519PublicKey } from "./ed25519/index.js";

// EC keys - secp256k1 (from ec-key/ module)
export type { ECKeyBase, ECKey, ECPublicKeyBase } from "./ec-key/index.js";
export {
  isECKeyBase,
  isECKey,
  isECPublicKeyBase,
  ECPrivateKey,
  ECPublicKey,
  ECUncompressedPublicKey,
  SchnorrPublicKey,
} from "./ec-key/index.js";

// Symmetric encryption (from symmetric/ module)
export { SymmetricKey, AuthenticationTag, EncryptedMessage } from "./symmetric/index.js";

// Digital signatures (from signing/ module)
export type { Signer, Verifier } from "./signing/index.js";
export {
  SignatureScheme,
  Signature,
  SigningPrivateKey,
  SigningPublicKey,
} from "./signing/index.js";
export { createKeypair, type CreateKeypairOptions } from "./signing/keypair.js";
export {
  defaultSignatureScheme,
  isSshScheme,
  isMldsaScheme,
  type SigningOptions,
} from "./signing/signature-scheme.js";

// Key encapsulation (from encapsulation/ module)
export {
  EncapsulationScheme,
  EncapsulationPrivateKey,
  EncapsulationPublicKey,
  EncapsulationCiphertext,
  SealedMessage,
  defaultEncapsulationScheme,
  createEncapsulationKeypair,
} from "./encapsulation/index.js";

// Key management containers
export { PrivateKeyBase } from "./private-key-base.js";
export { PrivateKeys } from "./private-keys.js";
export type { PrivateKeysProvider } from "./private-keys.js";
export { PublicKeys } from "./public-keys.js";
export type { PublicKeysProvider } from "./public-keys.js";

// Post-quantum cryptography - ML-DSA (from mldsa/ module)
export { MLDSALevel } from "./mldsa/index.js";

// SSH key/signature/certificate types — Ed25519 + ECDSA P-256 v1
// (mirrors the reference implementation feature `ssh`).
export type { SshAlgorithm, SshEcdsaCurve, SshHashAlgorithm } from "./ssh/index.js";

// Post-quantum cryptography - ML-KEM (from mlkem/ module)
export { MLKEMLevel } from "./mlkem/index.js";
