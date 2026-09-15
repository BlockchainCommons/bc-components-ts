/**
 * Top-level keypair helpers — produce a `(PrivateKeys, PublicKeys)` bundle
 * spanning both signing and encapsulation schemes in one call.
 */

import { type RandomNumberGenerator } from "@blockchaincommons/rand";
import { PrivateKeys } from "./private-keys.js";
import { PublicKeys } from "./public-keys.js";
import { defaultSignatureScheme } from "./signing/signature-scheme.js";
import { createKeypair as createSigningKeypair } from "./signing/keypair.js";
import type { SignatureScheme } from "./signing/signature-scheme.js";
import { defaultEncapsulationScheme } from "./encapsulation/encapsulation-scheme.js";
import { createEncapsulationKeypair } from "./encapsulation/keypair.js";
import type { EncapsulationScheme } from "./encapsulation/encapsulation-scheme.js";

/**
 * Generates a key pair using the default signature and encapsulation schemes
 * (Schnorr + X25519).
 *
 */
/** What `generateKeypair` accepts; every field has a default. */
export interface KeypairOptions {
  /** Signature scheme (Schnorr by default). */
  signing?: SignatureScheme;
  /** Encapsulation scheme (X25519 by default). */
  encapsulation?: EncapsulationScheme;
  /** Randomness source; ML-DSA and ML-KEM keys refuse a caller-supplied one. */
  rng?: RandomNumberGenerator;
}

/**
 * A fresh `PrivateKeys`/`PublicKeys` pair: a signing key and an
 * encapsulation key in the chosen schemes (`keypair_opt`, or
 * `keypair_opt_using` with `rng`). The signing pair is made first, then the
 * encapsulation pair, drawing from `rng` in that order; a post-quantum
 * scheme with `rng` throws `General` at its turn, as the reference does.
 */
export function generateKeypair({
  signing = defaultSignatureScheme(),
  encapsulation = defaultEncapsulationScheme(),
  rng,
}: KeypairOptions = {}): [PrivateKeys, PublicKeys] {
  const opts = rng === undefined ? {} : { rng };
  const [signingPrivateKey, signingPublicKey] = createSigningKeypair(signing, opts);
  const [encapsulationPrivateKey, encapsulationPublicKey] = createEncapsulationKeypair(
    encapsulation,
    opts,
  );
  return [
    PrivateKeys.from({ signing: signingPrivateKey, encapsulation: encapsulationPrivateKey }),
    PublicKeys.from({ signing: signingPublicKey, encapsulation: encapsulationPublicKey }),
  ];
}
