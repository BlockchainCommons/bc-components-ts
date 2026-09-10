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

/**
 * Creates a new key pair for the signature scheme.
 *
 * @param scheme  - The signature scheme to use
 * @param comment - Optional comment for SSH keys (ignored for non-SSH schemes;
 *                  mirrors Rust `SignatureScheme::keypair_opt(comment)` at
 *                  `signature_scheme.rs:152`)
 * @returns A tuple containing a signing private key and its corresponding public key
 */
export function createKeypair(
  scheme: SignatureScheme,
  comment = "",
): [SigningPrivateKey, SigningPublicKey] {
  switch (scheme) {
    case SignatureScheme.Schnorr: {
      const ecKey = ECPrivateKey.random();
      const privateKey = SigningPrivateKey.newSchnorr(ecKey);
      const publicKey = privateKey.publicKey();
      return [privateKey, publicKey];
    }
    case SignatureScheme.Ecdsa: {
      const ecKey = ECPrivateKey.random();
      const privateKey = SigningPrivateKey.newEcdsa(ecKey);
      const publicKey = privateKey.publicKey();
      return [privateKey, publicKey];
    }
    case SignatureScheme.Ed25519: {
      const ed25519Key = Ed25519PrivateKey.random();
      const privateKey = SigningPrivateKey.newEd25519(ed25519Key);
      const publicKey = privateKey.publicKey();
      return [privateKey, publicKey];
    }
    case SignatureScheme.Sr25519: {
      const sr25519Key = Sr25519PrivateKey.random();
      const privateKey = SigningPrivateKey.newSr25519(sr25519Key);
      const publicKey = privateKey.publicKey();
      return [privateKey, publicKey];
    }
    case SignatureScheme.MLDSA44: {
      const [mldsaKey, mldsaPub] = MLDSAPrivateKey.keypair(MLDSALevel.MLDSA44);
      return [SigningPrivateKey.newMldsa(mldsaKey), SigningPublicKey.fromMldsa(mldsaPub)];
    }
    case SignatureScheme.MLDSA65: {
      const [mldsaKey, mldsaPub] = MLDSAPrivateKey.keypair(MLDSALevel.MLDSA65);
      return [SigningPrivateKey.newMldsa(mldsaKey), SigningPublicKey.fromMldsa(mldsaPub)];
    }
    case SignatureScheme.MLDSA87: {
      const [mldsaKey, mldsaPub] = MLDSAPrivateKey.keypair(MLDSALevel.MLDSA87);
      return [SigningPrivateKey.newMldsa(mldsaKey), SigningPublicKey.fromMldsa(mldsaPub)];
    }
    case SignatureScheme.SshEd25519:
    case SignatureScheme.SshDsa:
    case SignatureScheme.SshEcdsaP256:
    case SignatureScheme.SshEcdsaP384: {
      // Mirror Rust `signature_scheme.rs:209-276`: build an empty
      // `PrivateKeyBase` and derive an SSH keypair from it.
      const base = PrivateKeyBase.new();
      const privateKey = base.sshSigningPrivateKey(sshSchemeToAlgorithm(scheme), comment);
      const publicKey = privateKey.publicKey();
      return [privateKey, publicKey];
    }
  }
}

/**
 * Creates a new key pair for the signature scheme using a provided RNG.
 *
 * @param scheme  - The signature scheme to use
 * @param rng     - The random number generator to use
 * @param comment - Optional comment for SSH keys (ignored for non-SSH schemes;
 *                  mirrors Rust `SignatureScheme::keypair_using(rng, comment)`
 *                  at `signature_scheme.rs:316`)
 * @returns A tuple containing a signing private key and its corresponding public key
 * @throws ComponentsError for MLDSA (which doesn't support deterministic generation)
 */
export function createKeypairUsing(
  scheme: SignatureScheme,
  rng: RandomNumberGenerator,
  comment = "",
): [SigningPrivateKey, SigningPublicKey] {
  switch (scheme) {
    case SignatureScheme.Schnorr: {
      const ecKey = ECPrivateKey.newUsing(rng);
      const privateKey = SigningPrivateKey.newSchnorr(ecKey);
      const publicKey = privateKey.publicKey();
      return [privateKey, publicKey];
    }
    case SignatureScheme.Ecdsa: {
      const ecKey = ECPrivateKey.newUsing(rng);
      const privateKey = SigningPrivateKey.newEcdsa(ecKey);
      const publicKey = privateKey.publicKey();
      return [privateKey, publicKey];
    }
    case SignatureScheme.Ed25519: {
      const ed25519Key = Ed25519PrivateKey.randomUsing(rng);
      const privateKey = SigningPrivateKey.newEd25519(ed25519Key);
      const publicKey = privateKey.publicKey();
      return [privateKey, publicKey];
    }
    case SignatureScheme.Sr25519: {
      const sr25519Key = Sr25519PrivateKey.randomUsing(rng);
      const privateKey = SigningPrivateKey.newSr25519(sr25519Key);
      const publicKey = privateKey.publicKey();
      return [privateKey, publicKey];
    }
    case SignatureScheme.MLDSA44:
    case SignatureScheme.MLDSA65:
    case SignatureScheme.MLDSA87:
      // ML-DSA doesn't support deterministic generation with custom RNG (matching Rust behavior)
      throw ComponentsError.general(
        `Deterministic keypair generation not supported for ${scheme}. Use createKeypair() instead.`,
      );
    case SignatureScheme.SshEd25519:
    case SignatureScheme.SshDsa:
    case SignatureScheme.SshEcdsaP256:
    case SignatureScheme.SshEcdsaP384: {
      // Mirror Rust `signature_scheme.rs:316-413`: build a
      // `PrivateKeyBase::new_using(rng)` and derive an SSH keypair.
      const base = PrivateKeyBase.newUsing(rng);
      const privateKey = base.sshSigningPrivateKey(sshSchemeToAlgorithm(scheme), comment);
      const publicKey = privateKey.publicKey();
      return [privateKey, publicKey];
    }
  }
}
