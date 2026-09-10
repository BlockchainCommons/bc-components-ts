/**
 * Sr25519 sizes and the default signing context.
 *
 * @module sr25519/constants
 */

/** Size of SR25519 private key (seed) in bytes */
export const SR25519_PRIVATE_KEY_SIZE = 32;

/** Size of SR25519 public key in bytes */
export const SR25519_PUBLIC_KEY_SIZE = 32;

/** Size of SR25519 signature in bytes */
export const SR25519_SIGNATURE_SIZE = 64;

/** Default signing context (Substrate/Polkadot compatible) */
export const SR25519_DEFAULT_CONTEXT: Uint8Array = new TextEncoder().encode("substrate");
