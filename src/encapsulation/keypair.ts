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

/**
 * A fresh encapsulation key pair for `scheme` (X25519 by default). With
 * `rng` the ML-KEM schemes throw, because their key generation cannot be
 * seeded.
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
      return EncapsulationPrivateKey.mlkemKeypair(
        schemeToMlkemLevel(scheme),
        rng === undefined ? {} : { rng },
      );
    }
  }
}
