/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * A private key used for creating digital signatures.
 *
 * `SigningPrivateKey` is a type representing different types of signing
 * private keys. Supports Schnorr, ECDSA, Ed25519, and SR25519.
 *
 * This type implements the `Signer` interface, allowing it to create signatures.
 *
 * # CBOR Serialization
 *
 * `SigningPrivateKey` is serialized to CBOR with tag 40021.
 *
 * The CBOR encoding:
 * - Schnorr: `#6.40021(h'<32-byte-private-key>')` (bare byte string)
 * - ECDSA:   `#6.40021([1, h'<32-byte-private-key>'])`
 * - Ed25519: `#6.40021([2, h'<32-byte-private-key>'])`
 * - SR25519: `#6.40021([3, h'<32-byte-seed>'])`
 *
 */

import type { RandomNumberGenerator } from "@blockchaincommons/rand";
import {
  type Cbor,
  type Tag,
  cbor,
  taggedValue,
  expectArray,
  expectBytes,
  expectText,
  expectUnsigned,
  isBytes,
  isArray,
  isTagged,
  asTaggedValue,
  type ToCbor,
} from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "../codable.js";
import {
  SIGNING_PRIVATE_KEY as TAG_SIGNING_PRIVATE_KEY,
  MLDSA_PRIVATE_KEY as TAG_MLDSA_PRIVATE_KEY,
  SSH_TEXT_PRIVATE_KEY as TAG_SSH_TEXT_PRIVATE_KEY,
} from "@blockchaincommons/tags";
import { Ed25519PrivateKey } from "../ed25519/ed25519-private-key.js";
import { Sr25519PrivateKey } from "../sr25519/sr25519-private-key.js";
import { ECPrivateKey } from "../ec-key/ec-private-key.js";
import { MLDSAPrivateKey } from "../mldsa/mldsa-private-key.js";
import { MLDSALevel } from "../mldsa/mldsa-level.js";
import { SSHPrivateKey } from "../ssh/ssh-private-key.js";
import { SignatureScheme, isMldsaScheme, type SigningOptions } from "./signature-scheme.js";
import { Signature } from "./signature.js";
import { SigningPublicKey } from "./signing-public-key.js";
import type { Signer, Verifier } from "./signer.js";
import { Reference, type ReferenceProvider } from "../reference.js";
import { Digest } from "../digest.js";
import { type UR, urFor } from "@blockchaincommons/uniform-resources";
import { ComponentsError } from "../error.js";
import { secureRng } from "@blockchaincommons/rand";

// The codec is built on first use so that an unused class tree-shakes away.
let SIGNING_PRIVATE_KEY_CODEC: ComponentCodec<SigningPrivateKey> | undefined;

/**
 * A private key used for creating digital signatures.
 *
 * Currently supports:
 * - Schnorr private keys (32 bytes, secp256k1) - bare byte string in CBOR
 * - ECDSA private keys (32 bytes, secp256k1) - discriminator 1
 * - Ed25519 private keys (32 bytes) - discriminator 2
 * - SR25519 private keys (32-byte seed) - discriminator 3
 * - MLDSA private keys (post-quantum) - tagged CBOR delegating to MLDSAPrivateKey
 */
export class SigningPrivateKey implements Signer, Verifier, ReferenceProvider, ToCbor {
  private readonly _type: SignatureScheme;
  private readonly _ecKey: ECPrivateKey | undefined;
  private readonly _ed25519Key: Ed25519PrivateKey | undefined;
  private readonly _sr25519Key: Sr25519PrivateKey | undefined;
  private readonly _mldsaKey: MLDSAPrivateKey | undefined;
  private readonly _sshKey: SSHPrivateKey | undefined;

  private constructor(
    type: SignatureScheme,
    ecKey?: ECPrivateKey,
    ed25519Key?: Ed25519PrivateKey,
    sr25519Key?: Sr25519PrivateKey,
    mldsaKey?: MLDSAPrivateKey,
    sshKey?: SSHPrivateKey,
  ) {
    this._type = type;
    this._ecKey = ecKey;
    this._ed25519Key = ed25519Key;
    this._sr25519Key = sr25519Key;
    this._mldsaKey = mldsaKey;
    this._sshKey = sshKey;
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Creates a new Schnorr signing private key from an ECPrivateKey.
   *
   * @param key - The EC private key to use for Schnorr signing
   * @returns A new Schnorr signing private key
   */
  static fromSchnorr(key: ECPrivateKey): SigningPrivateKey {
    return new SigningPrivateKey(SignatureScheme.Schnorr, key, undefined, undefined, undefined);
  }

  /**
   * Creates a new ECDSA signing private key from an ECPrivateKey.
   *
   * @param key - The EC private key to use for ECDSA signing
   * @returns A new ECDSA signing private key
   */
  static fromEcdsa(key: ECPrivateKey): SigningPrivateKey {
    return new SigningPrivateKey(SignatureScheme.Ecdsa, key, undefined, undefined, undefined);
  }

  /**
   * Creates a new Ed25519 signing private key from an Ed25519PrivateKey.
   *
   * @param key - The Ed25519 private key to use
   * @returns A new Ed25519 signing private key
   */
  static fromEd25519(key: Ed25519PrivateKey): SigningPrivateKey {
    return new SigningPrivateKey(SignatureScheme.Ed25519, undefined, key, undefined, undefined);
  }

  /**
   * Creates a new SR25519 signing private key from an Sr25519PrivateKey.
   *
   * @param key - The SR25519 private key to use
   * @returns A new SR25519 signing private key
   */
  static fromSr25519(key: Sr25519PrivateKey): SigningPrivateKey {
    return new SigningPrivateKey(SignatureScheme.Sr25519, undefined, undefined, key, undefined);
  }

  /**
   * Creates a new MLDSA signing private key from an MLDSAPrivateKey.
   *
   * @param key - The MLDSA private key to use
   * @returns A new MLDSA signing private key
   */
  static fromMldsa(key: MLDSAPrivateKey): SigningPrivateKey {
    // Determine the SignatureScheme based on the MLDSA level
    let scheme: SignatureScheme;
    switch (key.level) {
      case MLDSALevel.MLDSA44:
        scheme = SignatureScheme.MLDSA44;
        break;
      case MLDSALevel.MLDSA65:
        scheme = SignatureScheme.MLDSA65;
        break;
      case MLDSALevel.MLDSA87:
        scheme = SignatureScheme.MLDSA87;
        break;
      default:
        throw ComponentsError.invalidData(`Unknown MLDSA level: ${String(key.level)}`);
    }
    return new SigningPrivateKey(scheme, undefined, undefined, undefined, key);
  }

  /**
   * Creates a new SSH signing private key from an SSHPrivateKey.
   *
   *
   * @param key - The SSH private key to wrap
   * @returns A new SSH signing private key
   */
  static fromSsh(key: SSHPrivateKey): SigningPrivateKey {
    let scheme: SignatureScheme;
    switch (key.data.kind) {
      case "ed25519":
        scheme = SignatureScheme.SshEd25519;
        break;
      case "dsa":
        scheme = SignatureScheme.SshDsa;
        break;
      case "ecdsa":
        switch (key.data.curve) {
          case "nistp256":
            scheme = SignatureScheme.SshEcdsaP256;
            break;
          case "nistp384":
            scheme = SignatureScheme.SshEcdsaP384;
            break;
        }
        break;
    }
    return new SigningPrivateKey(scheme, undefined, undefined, undefined, undefined, key);
  }

  /**
   * A fresh signing key; Ed25519 unless `scheme` says otherwise. SSH schemes
   * derive from a `PrivateKeyBase` instead.
   */
  static random({
    scheme = SignatureScheme.Ed25519,
    rng = secureRng(),
  }: { scheme?: SignatureScheme; rng?: RandomNumberGenerator } = {}): SigningPrivateKey {
    switch (scheme) {
      case SignatureScheme.Schnorr:
        return SigningPrivateKey.fromSchnorr(ECPrivateKey.random({ rng }));
      case SignatureScheme.Ecdsa:
        return SigningPrivateKey.fromEcdsa(ECPrivateKey.random({ rng }));
      case SignatureScheme.Ed25519:
        return SigningPrivateKey.fromEd25519(Ed25519PrivateKey.random({ rng }));
      case SignatureScheme.Sr25519:
        return SigningPrivateKey.fromSr25519(Sr25519PrivateKey.random({ rng }));
      case SignatureScheme.MLDSA44:
        return SigningPrivateKey.fromMldsa(MLDSAPrivateKey.random(MLDSALevel.MLDSA44, { rng }));
      case SignatureScheme.MLDSA65:
        return SigningPrivateKey.fromMldsa(MLDSAPrivateKey.random(MLDSALevel.MLDSA65, { rng }));
      case SignatureScheme.MLDSA87:
        return SigningPrivateKey.fromMldsa(MLDSAPrivateKey.random(MLDSALevel.MLDSA87, { rng }));
      case SignatureScheme.SshEd25519:
      case SignatureScheme.SshDsa:
      case SignatureScheme.SshEcdsaP256:
      case SignatureScheme.SshEcdsaP384:
        throw ComponentsError.general(
          "SSH signing keys derive from a PrivateKeyBase: use base.sshSigningPrivateKey(algorithm)",
        );
    }
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /**
   * Returns the signature scheme of this key.
   */
  get scheme(): SignatureScheme {
    return this._type;
  }

  /**
   * Returns a human-readable string identifying the key type.
   * @returns A string like "Ed25519", "Schnorr", "ECDSA", "Sr25519", "MLDSA-44", etc.
   */
  get keyType(): string {
    switch (this._type) {
      case SignatureScheme.Ed25519:
        return "Ed25519";
      case SignatureScheme.Schnorr:
        return "Schnorr";
      case SignatureScheme.Ecdsa:
        return "ECDSA";
      case SignatureScheme.Sr25519:
        return "Sr25519";
      case SignatureScheme.MLDSA44:
        return "MLDSA-44";
      case SignatureScheme.MLDSA65:
        return "MLDSA-65";
      case SignatureScheme.MLDSA87:
        return "MLDSA-87";
      case SignatureScheme.SshEd25519:
        return "SSH-Ed25519";
      case SignatureScheme.SshDsa:
        return "SSH-DSA";
      case SignatureScheme.SshEcdsaP256:
        return "SSH-ECDSA-P256";
      case SignatureScheme.SshEcdsaP384:
        return "SSH-ECDSA-P384";
      default:
        return this._type;
    }
  }

  /**
   * Returns the underlying EC private key if this is a Schnorr or ECDSA key.
   *
   * @returns The EC private key if this is a Schnorr or ECDSA key, undefined otherwise
   */
  asEc(): ECPrivateKey | undefined {
    if (
      (this._type === SignatureScheme.Schnorr || this._type === SignatureScheme.Ecdsa) &&
      this._ecKey !== undefined
    ) {
      return this._ecKey;
    }
    return undefined;
  }

  /**
   * Returns the underlying Schnorr private key if this is a Schnorr key.
   *
   * @returns The EC private key if this is a Schnorr key, undefined otherwise
   */
  asSchnorr(): ECPrivateKey | undefined {
    if (this._type === SignatureScheme.Schnorr && this._ecKey !== undefined) {
      return this._ecKey;
    }
    return undefined;
  }

  /**
   * Returns the underlying ECDSA private key if this is an ECDSA key.
   *
   * @returns The EC private key if this is an ECDSA key, undefined otherwise
   */
  asEcdsa(): ECPrivateKey | undefined {
    if (this._type === SignatureScheme.Ecdsa && this._ecKey !== undefined) {
      return this._ecKey;
    }
    return undefined;
  }

  /**
   * Returns the underlying Ed25519 private key if this is an Ed25519 key.
   *
   * @returns The Ed25519 private key if this is an Ed25519 key, undefined otherwise
   */
  asEd25519(): Ed25519PrivateKey | undefined {
    if (this._type === SignatureScheme.Ed25519 && this._ed25519Key !== undefined) {
      return this._ed25519Key;
    }
    return undefined;
  }

  /**
   * Returns the underlying Sr25519 private key if this is an Sr25519 key.
   *
   * @returns The Sr25519 private key if this is an Sr25519 key, undefined otherwise
   */
  asSr25519(): Sr25519PrivateKey | undefined {
    if (this._type === SignatureScheme.Sr25519 && this._sr25519Key !== undefined) {
      return this._sr25519Key;
    }
    return undefined;
  }

  /**
   * Returns the underlying MLDSA private key if this is an MLDSA key.
   *
   * @returns The MLDSA private key if this is an MLDSA key, undefined otherwise
   */
  asMldsa(): MLDSAPrivateKey | undefined {
    if (isMldsaScheme(this._type) && this._mldsaKey !== undefined) {
      return this._mldsaKey;
    }
    return undefined;
  }

  /**
   * Checks if this is a Schnorr signing key.
   */
  isSchnorr(): boolean {
    return this._type === SignatureScheme.Schnorr;
  }

  /**
   * Checks if this is an ECDSA signing key.
   */
  isEcdsa(): boolean {
    return this._type === SignatureScheme.Ecdsa;
  }

  /**
   * Checks if this is an Ed25519 signing key.
   */
  isEd25519(): boolean {
    return this._type === SignatureScheme.Ed25519;
  }

  /**
   * Checks if this is an Sr25519 signing key.
   */
  isSr25519(): boolean {
    return this._type === SignatureScheme.Sr25519;
  }

  /**
   * Checks if this is an MLDSA signing key.
   */
  isMldsa(): boolean {
    return isMldsaScheme(this._type);
  }

  /**
   * Derives the corresponding public key for this private key.
   *
   * @returns The public key corresponding to this private key
   */
  publicKey(): SigningPublicKey {
    switch (this._type) {
      case SignatureScheme.Schnorr: {
        if (this._ecKey === undefined) {
          throw ComponentsError.invalidData("EC private key is missing");
        }
        return SigningPublicKey.fromSchnorr(this._ecKey.schnorrPublicKey());
      }
      case SignatureScheme.Ecdsa: {
        if (this._ecKey === undefined) {
          throw ComponentsError.invalidData("EC private key is missing");
        }
        return SigningPublicKey.fromEcdsa(this._ecKey.publicKey());
      }
      case SignatureScheme.Ed25519: {
        if (this._ed25519Key === undefined) {
          throw ComponentsError.invalidData("Ed25519 private key is missing");
        }
        return SigningPublicKey.fromEd25519(this._ed25519Key.publicKey());
      }
      case SignatureScheme.Sr25519: {
        if (this._sr25519Key === undefined) {
          throw ComponentsError.invalidData("Sr25519 private key is missing");
        }
        return SigningPublicKey.fromSr25519(this._sr25519Key.publicKey());
      }
      case SignatureScheme.MLDSA44:
      case SignatureScheme.MLDSA65:
      case SignatureScheme.MLDSA87: {
        if (this._mldsaKey === undefined) {
          throw ComponentsError.invalidData("MLDSA private key is missing");
        }
        return SigningPublicKey.fromMldsa(this._mldsaKey.publicKey());
      }
      case SignatureScheme.SshEd25519:
      case SignatureScheme.SshDsa:
      case SignatureScheme.SshEcdsaP256:
      case SignatureScheme.SshEcdsaP384: {
        if (this._sshKey === undefined) {
          throw ComponentsError.invalidData("SSH private key is missing");
        }
        return SigningPublicKey.fromSsh(this._sshKey.publicKey());
      }
    }
  }

  /**
   * Returns the underlying SSH private key if this is an SSH key.
   *
   *
   * @returns The SSHPrivateKey if this is an SSH key, undefined otherwise
   */
  asSsh(): SSHPrivateKey | undefined {
    return this._sshKey ?? undefined;
  }

  /**
   * Checks if this is an SSH signing key.
   */
  isSsh(): boolean {
    return this._sshKey !== undefined;
  }

  /**
   * Compare with another SigningPrivateKey.
   */
  equals(other: SigningPrivateKey): boolean {
    if (this._type !== other._type) return false;
    switch (this._type) {
      case SignatureScheme.Schnorr:
      case SignatureScheme.Ecdsa:
        if (this._ecKey === undefined || other._ecKey === undefined) return false;
        return this._ecKey.equals(other._ecKey);
      case SignatureScheme.Ed25519:
        if (this._ed25519Key === undefined || other._ed25519Key === undefined) return false;
        return this._ed25519Key.equals(other._ed25519Key);
      case SignatureScheme.Sr25519:
        if (this._sr25519Key === undefined || other._sr25519Key === undefined) return false;
        return this._sr25519Key.equals(other._sr25519Key);
      case SignatureScheme.MLDSA44:
      case SignatureScheme.MLDSA65:
      case SignatureScheme.MLDSA87:
        if (this._mldsaKey === undefined || other._mldsaKey === undefined) return false;
        return this._mldsaKey.equals(other._mldsaKey);
      case SignatureScheme.SshEd25519:
      case SignatureScheme.SshDsa:
      case SignatureScheme.SshEcdsaP256:
      case SignatureScheme.SshEcdsaP384: {
        if (this._sshKey === undefined || other._sshKey === undefined) return false;
        return this._sshKey.toOpenssh() === other._sshKey.toOpenssh();
      }
    }
  }

  /**
   *   `SigningPrivateKey(<refHexShort>, <inner>)`
   * where `<inner>` is:
   *   - `SchnorrPrivateKey(<refHexShort>)` / `ECDSAPrivateKey(<refHexShort>)`
   *     for the secp256k1 variants (Rust formats them inline by tag rather
   *     than delegating to the inner key's Display)
   *   - the inner key's Display for Ed25519 and MLDSA
   *   - `SSHPrivateKey(<refHexShort>)` for SSH
   * The previous abbreviated form (`SigningPrivateKey(<type>)` only) was
   * a parity drift caught by the E1a summarizer audit.
   */
  toString(): string {
    const refShort = this.reference().shortReference("hex");
    let innerDisplay: string;
    switch (this._type) {
      case SignatureScheme.Schnorr:
        innerDisplay = `SchnorrPrivateKey(${refShort})`;
        break;
      case SignatureScheme.Ecdsa:
        innerDisplay = `ECDSAPrivateKey(${refShort})`;
        break;
      case SignatureScheme.Ed25519:
        innerDisplay = this._ed25519Key?.toString() ?? String(this._type);
        break;
      case SignatureScheme.Sr25519:
        innerDisplay = this._sr25519Key?.toString() ?? String(this._type);
        break;
      case SignatureScheme.MLDSA44:
      case SignatureScheme.MLDSA65:
      case SignatureScheme.MLDSA87:
        innerDisplay = this._mldsaKey?.toString() ?? String(this._type);
        break;
      case SignatureScheme.SshEd25519:
      case SignatureScheme.SshDsa:
      case SignatureScheme.SshEcdsaP256:
      case SignatureScheme.SshEcdsaP384:
        innerDisplay = this._sshKey?.toString() ?? `SSHPrivateKey(${refShort})`;
        break;
    }
    return `SigningPrivateKey(${refShort}, ${innerDisplay})`;
  }

  // ============================================================================
  // ReferenceProvider Interface
  // ============================================================================

  /**
   * Returns a unique reference to this SigningPrivateKey instance.
   *
   * The reference is derived from the SHA-256 hash of the tagged CBOR
   * representation, providing a unique, content-addressable identifier.
   */
  reference(): Reference {
    const digest = Digest.fromImage(this.toCbor().toData());
    return Reference.fromDigest(digest);
  }

  // ============================================================================
  // Signer Interface
  // ============================================================================

  /**
   * Signs a message with optional signing options.
   *
   * Different signature schemes may use the options differently:
   * - Schnorr: Can accept a custom random number generator via SigningOptions.Schnorr
   * - SSH: Would require namespace and hash algorithm (not yet implemented)
   * - Other schemes (ECDSA, Ed25519, Sr25519, MLDSA): Options are ignored
   *
   * @param message - The message to sign
   * @param options - Optional signing options
   * @returns The digital signature
   */
  signWithOptions(message: Uint8Array, options?: SigningOptions): Signature {
    switch (this._type) {
      case SignatureScheme.Schnorr: {
        if (this._ecKey === undefined) {
          throw ComponentsError.invalidData("EC private key is missing");
        }
        // If Schnorr options with custom RNG are provided, use them
        if (options?.type === "Schnorr") {
          const sigData = this._ecKey.schnorrSignUsing(message, options.rng);
          return Signature.schnorrFromData(sigData);
        }
        // Otherwise use default RNG
        const sigData = this._ecKey.schnorrSign(message);
        return Signature.schnorrFromData(sigData);
      }
      case SignatureScheme.Ecdsa: {
        if (this._ecKey === undefined) {
          throw ComponentsError.invalidData("EC private key is missing");
        }
        const sigData = this._ecKey.ecdsaSign(message);
        return Signature.ecdsaFromData(sigData);
      }
      case SignatureScheme.Ed25519: {
        if (this._ed25519Key === undefined) {
          throw ComponentsError.invalidData("Ed25519 private key is missing");
        }
        const sigData = this._ed25519Key.sign(message);
        return Signature.ed25519FromData(sigData);
      }
      case SignatureScheme.Sr25519: {
        if (this._sr25519Key === undefined) {
          throw ComponentsError.invalidData("Sr25519 private key is missing");
        }
        const sigData = this._sr25519Key.sign(message);
        return Signature.sr25519FromData(sigData);
      }
      case SignatureScheme.MLDSA44:
      case SignatureScheme.MLDSA65:
      case SignatureScheme.MLDSA87: {
        if (this._mldsaKey === undefined) {
          throw ComponentsError.invalidData("MLDSA private key is missing");
        }
        const mldsaSig = this._mldsaKey.sign(message);
        return Signature.mldsaFromSignature(mldsaSig);
      }
      case SignatureScheme.SshEd25519:
      case SignatureScheme.SshDsa:
      case SignatureScheme.SshEcdsaP256:
      case SignatureScheme.SshEcdsaP384: {
        if (this._sshKey === undefined) {
          throw ComponentsError.invalidData("SSH private key is missing");
        }
        if (options?.type !== "Ssh") {
          // (`signing_private_key.rs:796`).
          throw ComponentsError.invalidData("Missing namespace and hash algorithm for SSH signing");
        }
        const sshSig = this._sshKey.sign(options.namespace, options.hashAlg, message);
        return Signature.fromSsh(sshSig);
      }
    }
  }

  /**
   * Signs a message using default options.
   *
   * This is a convenience method that calls `signWithOptions` with no options.
   *
   * @param message - The message to sign
   * @returns The digital signature
   */
  sign(message: Uint8Array): Signature {
    return this.signWithOptions(message);
  }

  // ============================================================================
  // Verifier Interface (Schnorr-only)
  // ============================================================================

  /**
   * Verifies a signature against a message using the derived public key.
   *
   * actually verify; every other scheme returns `false`. Callers needing
   * verification for Ed25519 / ECDSA / Sr25519 / MLDSA should derive the
   * public key first via `publicKey().verify(...)`.
   *
   * @param signature - The signature to verify
   * @param message - The message that was allegedly signed
   * @returns `true` if the signature is a valid Schnorr signature
   */
  verify(signature: Signature, message: Uint8Array): boolean {
    if (this._type !== SignatureScheme.Schnorr || this._ecKey === undefined) {
      return false;
    }
    const sigData = signature.asSchnorr();
    if (sigData === undefined) {
      return false;
    }
    return this._ecKey.schnorrPublicKey().schnorrVerify(sigData, message);
  }

  // ============================================================================
  // Scheme-Specific Sign Methods
  // ============================================================================

  /**
   * Signs a message using Schnorr with the provided random number generator.
   *
   * This method is only valid for Schnorr keys.
   *
   * @param message - The message to sign
   * @param rng - The random number generator to use for signature creation
   * @returns The Schnorr signature
   * @throws Error if this is not a Schnorr key
   */
  schnorrSign(message: Uint8Array, rng: RandomNumberGenerator): Signature {
    const privateKey = this.asSchnorr();
    if (privateKey === undefined) {
      throw ComponentsError.invalidData("Invalid key type for Schnorr signing");
    }
    const sigData = privateKey.schnorrSignUsing(message, rng);
    return Signature.schnorrFromData(sigData);
  }

  /**
   * Signs a message using ECDSA.
   *
   * This method is only valid for ECDSA keys.
   *
   * @param message - The message to sign
   * @returns The ECDSA signature
   * @throws Error if this is not an ECDSA key
   */
  ecdsaSign(message: Uint8Array): Signature {
    const privateKey = this.asEcdsa();
    if (privateKey === undefined) {
      throw ComponentsError.invalidData("Invalid key type for ECDSA signing");
    }
    const sigData = privateKey.ecdsaSign(message);
    return Signature.ecdsaFromData(sigData);
  }

  /**
   * Signs a message using Ed25519.
   *
   * This method is only valid for Ed25519 keys.
   *
   * @param message - The message to sign
   * @returns The Ed25519 signature
   * @throws Error if this is not an Ed25519 key
   */
  ed25519Sign(message: Uint8Array): Signature {
    const privateKey = this.asEd25519();
    if (privateKey === undefined) {
      throw ComponentsError.invalidData("Invalid key type for Ed25519 signing");
    }
    const sigData = privateKey.sign(message);
    return Signature.ed25519FromData(sigData);
  }

  /**
   * Signs a message using SR25519.
   *
   * This method is only valid for SR25519 keys.
   *
   * @param message - The message to sign
   * @returns The SR25519 signature
   * @throws Error if this is not an SR25519 key
   */
  sr25519Sign(message: Uint8Array): Signature {
    const privateKey = this.asSr25519();
    if (privateKey === undefined) {
      throw ComponentsError.invalidData("Invalid key type for SR25519 signing");
    }
    const sigData = privateKey.sign(message);
    return Signature.sr25519FromData(sigData);
  }

  /**
   * Signs a message using ML-DSA.
   *
   * This method is only valid for MLDSA keys.
   *
   * @param message - The message to sign
   * @returns The ML-DSA signature
   * @throws Error if this is not an MLDSA key
   */
  mldsaSign(message: Uint8Array): Signature {
    const privateKey = this.asMldsa();
    if (privateKey === undefined) {
      throw ComponentsError.invalidData("Invalid key type for MLDSA signing");
    }
    const mldsaSig = privateKey.sign(message);
    return Signature.mldsaFromSignature(mldsaSig);
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<SigningPrivateKey> {
    return (SIGNING_PRIVATE_KEY_CODEC ??= defineCodec({
      tags: [TAG_SIGNING_PRIVATE_KEY],
      decodeUntagged: (cborValue) => {
        // Wire format: Schnorr is a bare byte string
        if (isBytes(cborValue)) {
          const keyData = expectBytes(cborValue);
          return SigningPrivateKey.fromSchnorr(ECPrivateKey.from(keyData));
        }

        // Array format for ECDSA, Ed25519, Sr25519
        if (isArray(cborValue)) {
          const elements = expectArray(cborValue);

          if (elements.length !== 2) {
            throw ComponentsError.invalidData("SigningPrivateKey array must have 2 elements");
          }

          const discriminator = expectUnsigned(elements[0]);
          const keyData = expectBytes(elements[1]);

          switch (Number(discriminator)) {
            case 1: // ECDSA
              return SigningPrivateKey.fromEcdsa(ECPrivateKey.from(keyData));
            case 2: // Ed25519
              return SigningPrivateKey.fromEd25519(Ed25519PrivateKey.from(keyData));
            case 3: // Sr25519
              return SigningPrivateKey.fromSr25519(Sr25519PrivateKey.from(keyData));
            default:
              throw ComponentsError.invalidData(
                `Unknown SigningPrivateKey discriminator: ${discriminator}`,
              );
          }
        }

        // Tagged format for MLDSA / SSH
        if (isTagged(cborValue)) {
          const tagged = asTaggedValue(cborValue);
          if (tagged?.[0].value === TAG_MLDSA_PRIVATE_KEY.value) {
            const mldsaKey = MLDSAPrivateKey.fromCbor(cborValue);
            return SigningPrivateKey.fromMldsa(mldsaKey);
          }
          if (tagged?.[0].value === TAG_SSH_TEXT_PRIVATE_KEY.value) {
            const text = expectText(tagged[1]);
            const sshKey = SSHPrivateKey.fromOpenssh(text);
            return SigningPrivateKey.fromSsh(sshKey);
          }
        }

        throw ComponentsError.invalidData(
          "SigningPrivateKey must be a byte string (Schnorr), array (ECDSA/Ed25519/Sr25519), tagged MLDSA, or tagged SSH",
        );
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  cborTags(): Tag[] {
    return [...SigningPrivateKey.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding.
   *
   * Format:
   * - Schnorr: h'<32-byte-private-key>' (bare byte string)
   * - ECDSA:   [1, h'<32-byte-private-key>']
   * - Ed25519: [2, h'<32-byte-private-key>']
   * - Sr25519: [3, h'<32-byte-seed>']
   * - MLDSA:   delegates to MLDSAPrivateKey (tagged)
   */
  untaggedCbor(): Cbor {
    switch (this._type) {
      case SignatureScheme.Schnorr: {
        if (this._ecKey === undefined) {
          throw ComponentsError.invalidData("EC private key is missing");
        }
        // CBOR::to_byte_string(key.bytes) - bare byte string
        return cbor(this._ecKey.bytes);
      }
      case SignatureScheme.Ecdsa: {
        if (this._ecKey === undefined) {
          throw ComponentsError.invalidData("EC private key is missing");
        }
        return cbor([1, cbor(this._ecKey.bytes)]);
      }
      case SignatureScheme.Ed25519: {
        if (this._ed25519Key === undefined) {
          throw ComponentsError.invalidData("Ed25519 private key is missing");
        }
        return cbor([2, cbor(this._ed25519Key.bytes)]);
      }
      case SignatureScheme.Sr25519: {
        if (this._sr25519Key === undefined) {
          throw ComponentsError.invalidData("Sr25519 private key is missing");
        }
        return cbor([3, cbor(this._sr25519Key.bytes)]);
      }
      case SignatureScheme.MLDSA44:
      case SignatureScheme.MLDSA65:
      case SignatureScheme.MLDSA87: {
        if (this._mldsaKey === undefined) {
          throw ComponentsError.invalidData("MLDSA private key is missing");
        }
        // delegates to MLDSAPrivateKey (which produces tagged CBOR)
        return this._mldsaKey.toCbor();
      }
      case SignatureScheme.SshEd25519:
      case SignatureScheme.SshDsa:
      case SignatureScheme.SshEcdsaP256:
      case SignatureScheme.SshEcdsaP384: {
        if (this._sshKey === undefined) {
          throw ComponentsError.invalidData("SSH private key is missing");
        }
        // untagged CBOR encoding:
        // `CBOR::to_tagged_value(TAG_SSH_TEXT_PRIVATE_KEY, key.to_openssh())`.
        return taggedValue(TAG_SSH_TEXT_PRIVATE_KEY, this._sshKey.toOpenssh());
      }
    }
  }

  /** The tagged CBOR form. */
  toCbor(): Cbor {
    return taggedCborOf(this);
  }

  /** As a UR, typed by the first tag's name. */
  toUR(): UR {
    return urFor(this);
  }

  /** Decode tagged or untagged CBOR. */
  static fromCbor(cborValue: Cbor): SigningPrivateKey {
    return SigningPrivateKey.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR (Uniform Resource) Serialization
  // ============================================================================

  // ============================================================================
  // SSH Format
  // ============================================================================

  /**
   * Returns the canonical OpenSSH armored PEM for an SSH private key.
   *
   * Only valid when this `SigningPrivateKey` wraps an `SSHPrivateKey`
   * (i.e. one of the four `SignatureScheme.SshXxx` variants). Mirrors
   * the reference implementation's `SigningPrivateKey::SSH(key) => key.to_openssh(LineEnding::LF)`
   * usage at `signing_private_key.rs:896`.
   */
  toSshOpenssh(): string {
    if (this._sshKey === undefined) {
      throw ComponentsError.invalidData(
        `SigningPrivateKey is not an SSH key (scheme: ${this._type})`,
      );
    }
    return this._sshKey.toOpenssh();
  }
}
