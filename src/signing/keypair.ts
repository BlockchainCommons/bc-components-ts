/**
 * Keypair generation per `SignatureScheme`.
 *
 * Lives apart from `signature-scheme.ts` so the scheme enum (imported by
 * every signing type) does not pull the key classes in and close an import
 * cycle.
 *
 * @module signing/keypair
 */

import type { RandomNumberGenerator } from "@blockchaincommons/rand";
import { Ed25519PrivateKey } from "../ed25519/ed25519-private-key.js";
import { Sr25519PrivateKey } from "../sr25519/sr25519-private-key.js";
import { ECPrivateKey } from "../ec-key/ec-private-key.js";
import { MLDSAPrivateKey } from "../mldsa/mldsa-private-key.js";
import { MLDSALevel } from "../mldsa/mldsa-level.js";
import { PrivateKeyBase } from "../private-key-base.js";
import type { SshAlgorithm } from "../ssh/ssh-algorithm.js";
import { SigningPrivateKey } from "./signing-private-key.js";
import { SigningPublicKey } from "./signing-public-key.js";
import { ComponentsError } from "../error.js";
import { SignatureScheme } from "./signature-scheme.js";
import { secureRng } from "@blockchaincommons/rand";

/**
 * Map an `SshXxx` `SignatureScheme` value to its underlying
 * `SshAlgorithm`. Helper for `createKeypair`/`createKeypairUsing`.
 */
function sshSchemeToAlgorithm(scheme: SignatureScheme): SshAlgorithm {
  switch (scheme) {
    case SignatureScheme.SshEd25519:
      return { kind: "ed25519" };
    case SignatureScheme.SshDsa:
      return { kind: "dsa" };
    case SignatureScheme.SshEcdsaP256:
      return { kind: "ecdsa", curve: "nistp256" };
    case SignatureScheme.SshEcdsaP384:
      return { kind: "ecdsa", curve: "nistp384" };
    case SignatureScheme.Schnorr:
    case SignatureScheme.Ecdsa:
    case SignatureScheme.Ed25519:
    case SignatureScheme.Sr25519:
    case SignatureScheme.MLDSA44:
    case SignatureScheme.MLDSA65:
    case SignatureScheme.MLDSA87:
      throw ComponentsError.invalidData(`Not an SSH SignatureScheme: ${scheme}`);
  }
}

/** What `createKeypair` accepts. */
export interface CreateKeypairOptions {
  /** Randomness source; the ML-DSA schemes refuse a caller-supplied one. */
  rng?: RandomNumberGenerator;
  /** Comment stored in SSH keys (ignored by the other schemes). */
  comment?: string;
}

/**
 * A fresh signing key pair for `scheme`. Without `rng` every scheme draws
 * from the secure generator; with `rng` the ML-DSA schemes throw, because
 * their key generation cannot be seeded.
 */
export function createKeypair(
  scheme: SignatureScheme,
  { rng, comment = "" }: CreateKeypairOptions = {},
): [SigningPrivateKey, SigningPublicKey] {
  if (rng === undefined) {
    switch (scheme) {
      case SignatureScheme.MLDSA44:
      case SignatureScheme.MLDSA65:
      case SignatureScheme.MLDSA87: {
        const level = {
          MLDSA44: MLDSALevel.MLDSA44,
          MLDSA65: MLDSALevel.MLDSA65,
          MLDSA87: MLDSALevel.MLDSA87,
        }[scheme];
        const [mldsaKey, mldsaPub] = MLDSAPrivateKey.keypair(level);
        return [SigningPrivateKey.fromMldsa(mldsaKey), SigningPublicKey.fromMldsa(mldsaPub)];
      }
      default:
        return createKeypair(scheme, { rng: secureRng(), comment });
    }
  }
  switch (scheme) {
    case SignatureScheme.Schnorr: {
      const ecKey = ECPrivateKey.random({ rng: rng });
      const privateKey = SigningPrivateKey.fromSchnorr(ecKey);
      const publicKey = privateKey.publicKey();
      return [privateKey, publicKey];
    }
    case SignatureScheme.Ecdsa: {
      const ecKey = ECPrivateKey.random({ rng: rng });
      const privateKey = SigningPrivateKey.fromEcdsa(ecKey);
      const publicKey = privateKey.publicKey();
      return [privateKey, publicKey];
    }
    case SignatureScheme.Ed25519: {
      const ed25519Key = Ed25519PrivateKey.random({ rng: rng });
      const privateKey = SigningPrivateKey.fromEd25519(ed25519Key);
      const publicKey = privateKey.publicKey();
      return [privateKey, publicKey];
    }
    case SignatureScheme.Sr25519: {
      const sr25519Key = Sr25519PrivateKey.random({ rng: rng });
      const privateKey = SigningPrivateKey.fromSr25519(sr25519Key);
      const publicKey = privateKey.publicKey();
      return [privateKey, publicKey];
    }
    case SignatureScheme.MLDSA44:
    case SignatureScheme.MLDSA65:
    case SignatureScheme.MLDSA87:
      throw ComponentsError.general(
        `Deterministic keypair generation not supported for ${scheme}; omit rng.`,
      );
    case SignatureScheme.SshEd25519:
    case SignatureScheme.SshDsa:
    case SignatureScheme.SshEcdsaP256:
    case SignatureScheme.SshEcdsaP384: {
      // `PrivateKeyBase::new_using(rng)` and derive an SSH keypair.
      const base = PrivateKeyBase.random({ rng: rng });
      const privateKey = base.sshSigningPrivateKey(sshSchemeToAlgorithm(scheme), comment);
      const publicKey = privateKey.publicKey();
      return [privateKey, publicKey];
    }
  }
}
