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
import { ECPrivateKey } from "../ec-key/ec-private-key.js";
import { MLDSAPrivateKey } from "../mldsa/mldsa-private-key.js";
import { MLDSALevel } from "../mldsa/mldsa-level.js";
import { PrivateKeyBase } from "../private-key-base.js";
import type { SshAlgorithm } from "../ssh/ssh-algorithm.js";
import { SigningPrivateKey } from "./signing-private-key.js";
import { SigningPublicKey } from "./signing-public-key.js";
import { ComponentsError } from "../error.js";
import { SignatureScheme, defaultSignatureScheme } from "./signature-scheme.js";
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
 * from the secure generator (`keypair`). With `rng` (`keypair_using`) the
 * ML-DSA schemes throw `General` before drawing anything, as the reference
 * does: their key generation takes no caller-supplied generator. Use
 * `MLDSAPrivateKey.keypair(level, { rng })` for a seeded ML-DSA pair.
 */
export function createKeypair(
  scheme: SignatureScheme = defaultSignatureScheme(),
  { rng: given, comment = "" }: CreateKeypairOptions = {},
): [SigningPrivateKey, SigningPublicKey] {
  const rng = given ?? secureRng();
  switch (scheme) {
    case SignatureScheme.Schnorr: {
      const privateKey = SigningPrivateKey.fromSchnorr(ECPrivateKey.random({ rng }));
      return [privateKey, privateKey.publicKey()];
    }
    case SignatureScheme.Ecdsa: {
      const privateKey = SigningPrivateKey.fromEcdsa(ECPrivateKey.random({ rng }));
      return [privateKey, privateKey.publicKey()];
    }
    case SignatureScheme.Ed25519: {
      const privateKey = SigningPrivateKey.fromEd25519(Ed25519PrivateKey.random({ rng }));
      return [privateKey, privateKey.publicKey()];
    }
    case SignatureScheme.MLDSA44:
    case SignatureScheme.MLDSA65:
    case SignatureScheme.MLDSA87: {
      if (given !== undefined) {
        throw ComponentsError.general(
          "Deterministic keypair generation not supported for this signature scheme",
        );
      }
      const level = {
        MLDSA44: MLDSALevel.MLDSA44,
        MLDSA65: MLDSALevel.MLDSA65,
        MLDSA87: MLDSALevel.MLDSA87,
      }[scheme];
      const [mldsaKey, mldsaPub] = MLDSAPrivateKey.keypair(level);
      return [SigningPrivateKey.fromMldsa(mldsaKey), SigningPublicKey.fromMldsa(mldsaPub)];
    }
    case SignatureScheme.SshEd25519:
    case SignatureScheme.SshDsa:
    case SignatureScheme.SshEcdsaP256:
    case SignatureScheme.SshEcdsaP384: {
      // `PrivateKeyBase::new_using(rng)`, then the SSH keypair derived from it.
      const base = PrivateKeyBase.random({ rng });
      const privateKey = base.sshSigningPrivateKey(sshSchemeToAlgorithm(scheme), comment);
      return [privateKey, privateKey.publicKey()];
    }
  }
}
