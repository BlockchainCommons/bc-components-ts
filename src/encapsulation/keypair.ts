/**
 * Keypair generation per `EncapsulationScheme`.
 *
 * Lives apart from `encapsulation-scheme.ts` so the scheme enum (imported by
 * every encapsulation type) does not pull the key classes in and close an
 * import cycle.
 *
 * @module encapsulation/keypair
 */

import type { RngOptions } from "@blockchaincommons/rand";
import { EncapsulationPrivateKey } from "./encapsulation-private-key.js";
import type { EncapsulationPublicKey } from "./encapsulation-public-key.js";
import { EncapsulationScheme, schemeToMlkemLevel } from "./encapsulation-scheme.js";
import { ComponentsError } from "../error.js";

/**
 * A fresh encapsulation key pair for `scheme` (X25519 by default). Without
 * `rng` every scheme draws from the secure generator (`keypair`). With
 * `rng` (`keypair_using`) the ML-KEM schemes throw `General` before drawing
 * anything, as the reference does: their key generation takes no
 * caller-supplied generator. Use `MLKEMPrivateKey.keypair(level, { rng })`
 * or `EncapsulationPrivateKey.mlkemKeypair(level, { rng })` for a seeded
 * ML-KEM pair.
 */
export function createEncapsulationKeypair(
  scheme: EncapsulationScheme = EncapsulationScheme.X25519,
  { rng }: RngOptions = {},
): [EncapsulationPrivateKey, EncapsulationPublicKey] {
  switch (scheme) {
    case EncapsulationScheme.X25519:
      return EncapsulationPrivateKey.keypair(rng === undefined ? {} : { rng });
    case EncapsulationScheme.MLKEM512:
    case EncapsulationScheme.MLKEM768:
    case EncapsulationScheme.MLKEM1024: {
      if (rng !== undefined) {
        throw ComponentsError.general(
          "Deterministic keypair generation not supported for this encapsulation scheme",
        );
      }
      return EncapsulationPrivateKey.mlkemKeypair(schemeToMlkemLevel(scheme));
    }
  }
}
