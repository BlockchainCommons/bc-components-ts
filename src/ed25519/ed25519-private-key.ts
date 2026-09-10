/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * Ed25519 private key for EdDSA signatures (32 bytes seed)
 * Ported from bc-components-rust/src/ed25519_private_key.rs
 */

import { type RandomNumberGenerator, secureRng, randomBytes } from "@blockchaincommons/rand";
import {
  ed25519,
  deriveSigningPrivateKey,
  ED25519_PRIVATE_KEY_SIZE,
} from "@blockchaincommons/crypto";
import { ComponentsError } from "../error.js";
import { Ed25519PublicKey } from "./ed25519-public-key.js";
import { bytesToHex, hexToBytes, toBase64 } from "../utils.js";

export class Ed25519PrivateKey {
  private readonly seed: Uint8Array;
  private _publicKey?: Ed25519PublicKey;

  private constructor(seed: Uint8Array) {
    if (seed.length !== ED25519_PRIVATE_KEY_SIZE) {
      throw ComponentsError.invalidSize(ED25519_PRIVATE_KEY_SIZE, seed.length);
    }
    this.seed = new Uint8Array(seed);
  }

  /**
   * Create an Ed25519PrivateKey from seed (32 bytes)
   */
  static from(seed: Uint8Array): Ed25519PrivateKey {
    return new Ed25519PrivateKey(new Uint8Array(seed));
  }

  /**
   * Create an Ed25519PrivateKey from hex string (64 hex characters)
   */
  static fromHex(hex: string): Ed25519PrivateKey {
    return new Ed25519PrivateKey(hexToBytes(hex));
  }

  /** A fresh random value; pass `rng` to make it deterministic. */
  static random({ rng = secureRng() }: { rng?: RandomNumberGenerator } = {}): Ed25519PrivateKey {
    return new Ed25519PrivateKey(randomBytes(ED25519_PRIVATE_KEY_SIZE, { rng: rng }));
  }

  /**
   * Derives an Ed25519 private key from the given key material via
   * HKDF-SHA-256 with salt `"signing"` and empty info (matches Rust
   * `bc_crypto::derive_signing_private_key`).
   */
  static deriveFromKeyMaterial(keyMaterial: Uint8Array): Ed25519PrivateKey {
    return new Ed25519PrivateKey(deriveSigningPrivateKey(keyMaterial));
  }

  /** The bytes (a view; do not mutate). */
  get bytes(): Uint8Array {
    return new Uint8Array(this.seed);
  }

  /** Alias of {@link Ed25519PrivateKey.data}. */
  /** Backwards-compatible alias of {@link Ed25519PrivateKey.data}. */
  /**
   * Get hex string representation of the seed
   */
  toHex(): string {
    return bytesToHex(this.seed);
  }

  /**
   * Get base64 representation of the seed
   */
  toBase64(): string {
    return toBase64(this.seed);
  }

  /**
   * Derive the corresponding public key
   */
  publicKey(): Ed25519PublicKey {
    if (this._publicKey === undefined) {
      const publicKeyBytes = ed25519.publicKey(this.seed);
      this._publicKey = Ed25519PublicKey.from(publicKeyBytes);
    }
    return this._publicKey;
  }

  /**
   * Sign a message using Ed25519
   */
  sign(message: Uint8Array): Uint8Array {
    try {
      const signature = ed25519.sign(this.seed, message);
      return new Uint8Array(signature);
    } catch (e) {
      throw ComponentsError.crypto(`Ed25519 signing failed: ${String(e)}`);
    }
  }

  /**
   * Compare with another Ed25519PrivateKey
   */
  equals(other: Ed25519PrivateKey): boolean {
    if (this.seed.length !== other.seed.length) return false;
    for (let i = 0; i < this.seed.length; i++) {
      if (this.seed[i] !== other.seed[i]) return false;
    }
    return true;
  }

  /**
   * Get string representation
   */
  toString(): string {
    return `Ed25519PrivateKey(${this.toHex().substring(0, 16)}...)`;
  }
}
