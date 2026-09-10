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

// Hex goes through dcbor: native `Uint8Array.toHex`/`fromHex` where the
// platform has them, and one validation rule across the closure.
export { bytesToHex, hexToBytes } from "@blockchaincommons/dcbor";

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
export function toBase64(data: Uint8Array): string {
  // Convert bytes to binary string without spread operator to avoid
  // call stack limits for large arrays (spread would fail at ~65k bytes)
  let binary = "";
  for (const byte of data) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
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
export function fromBase64(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
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
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}
