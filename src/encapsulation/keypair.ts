/**
 * Keypair generation per `EncapsulationScheme`.
 *
 * Lives apart from `encapsulation-scheme.ts` so the scheme enum (imported by
 * every encapsulation type) does not pull the key classes in and close an
 * import cycle.
 *
 * @module encapsulation/keypair
 */

import type { RandomNumberGenerator } from "@blockchaincommons/rand";
import { EncapsulationPrivateKey } from "./encapsulation-private-key.js";
import type { EncapsulationPublicKey } from "./encapsulation-public-key.js";
import { MLKEMLevel } from "../mlkem/mlkem-level.js";
import { EncapsulationScheme } from "./encapsulation-scheme.js";

/**
 * Generate a new keypair for the given encapsulation scheme.
 *
 * @param scheme - The encapsulation scheme to use (defaults to X25519)
 * @returns A tuple of [privateKey, publicKey]
 */
export function createEncapsulationKeypair(
  scheme: EncapsulationScheme = EncapsulationScheme.X25519,
): [EncapsulationPrivateKey, EncapsulationPublicKey] {
  switch (scheme) {
    case EncapsulationScheme.X25519:
      return EncapsulationPrivateKey.keypair();
    case EncapsulationScheme.MLKEM512:
      return EncapsulationPrivateKey.mlkemKeypair(MLKEMLevel.MLKEM512);
    case EncapsulationScheme.MLKEM768:
      return EncapsulationPrivateKey.mlkemKeypair(MLKEMLevel.MLKEM768);
    case EncapsulationScheme.MLKEM1024:
      return EncapsulationPrivateKey.mlkemKeypair(MLKEMLevel.MLKEM1024);
  }
}

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
export function createEncapsulationKeypairUsing(
  rng: RandomNumberGenerator,
  scheme: EncapsulationScheme = EncapsulationScheme.X25519,
): [EncapsulationPrivateKey, EncapsulationPublicKey] {
  switch (scheme) {
    case EncapsulationScheme.X25519:
      return EncapsulationPrivateKey.keypairUsing(rng);
    case EncapsulationScheme.MLKEM512:
    case EncapsulationScheme.MLKEM768:
    case EncapsulationScheme.MLKEM1024:
      // MLKEM doesn't support deterministic keypair generation (matching Rust behavior)
      throw new Error(
        "Deterministic keypair generation not supported for this encapsulation scheme",
      );
  }
}
