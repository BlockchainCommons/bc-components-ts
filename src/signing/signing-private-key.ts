/**
 * A private key used for creating digital signatures.
 *
 * `SigningPrivateKey` is a type representing different types of signing
 * private keys. Supports Schnorr, ECDSA, Ed25519, ML-DSA and SSH keys.
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
  asTaggedValue,
  type ToCbor,
  CborError,
} from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "../codable.js";
import {
  TAG_SIGNING_PRIVATE_KEY,
  TAG_MLDSA_PRIVATE_KEY,
  TAG_SSH_TEXT_PRIVATE_KEY,
} from "@blockchaincommons/tags";
import { Ed25519PrivateKey } from "../ed25519/ed25519-private-key.js";
import { ECPrivateKey } from "../ec-key/ec-private-key.js";
import { MLDSAPrivateKey } from "../mldsa/mldsa-private-key.js";
import { MLDSALevel } from "../mldsa/mldsa-level.js";
import { SSHPrivateKey } from "../ssh/ssh-private-key.js";
import {
  sshKeyTypeName,
  sshSchemeUnsupportedError,
  sshSignatureScheme,
  type SshAlgorithm,
} from "../ssh/ssh-algorithm.js";
import {
  SignatureScheme,
  defaultSignatureScheme,
  isMldsaScheme,
  type SigningOptions,
} from "./signature-scheme.js";
import { Signature } from "./signature.js";
import { SigningPublicKey } from "./signing-public-key.js";
import type { Signer, Verifier } from "./signer.js";
import { Reference, type ReferenceProvider } from "../reference.js";
import { Digest } from "../digest.js";
import { type UR, urFor } from "@blockchaincommons/uniform-resources";
import { ComponentsError } from "../error.js";
import { USIZE_FIELD } from "../domain.js";
import { secureRng, type RngOptions } from "@blockchaincommons/rand";

// The codec is built on first use so that an unused class tree-shakes away.
let SIGNING_PRIVATE_KEY_CODEC: ComponentCodec<SigningPrivateKey> | undefined;

/**
 * A private key used for creating digital signatures.
 *
 * Currently supports:
 * - Schnorr private keys (32 bytes, secp256k1) - bare byte string in CBOR
 * - ECDSA private keys (32 bytes, secp256k1) - discriminator 1
 * - Ed25519 private keys (32 bytes) - discriminator 2
 * - MLDSA private keys (post-quantum) - tagged CBOR delegating to MLDSAPrivateKey
 */
export class SigningPrivateKey implements Signer, Verifier, ReferenceProvider, ToCbor {
  private readonly _type: SignatureScheme | undefined;
  private readonly _ecKey: ECPrivateKey | undefined;
  private readonly _ed25519Key: Ed25519PrivateKey | undefined;
  private readonly _mldsaKey: MLDSAPrivateKey | undefined;
  private readonly _sshKey: SSHPrivateKey | undefined;

  private constructor(
    type: SignatureScheme | undefined,
    ecKey?: ECPrivateKey,
    ed25519Key?: Ed25519PrivateKey,
    mldsaKey?: MLDSAPrivateKey,
    sshKey?: SSHPrivateKey,
  ) {
    this._type = type;
    this._ecKey = ecKey;
    this._ed25519Key = ed25519Key;
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
    return new SigningPrivateKey(SignatureScheme.Schnorr, key, undefined, undefined);
  }

  /**
   * Creates a new ECDSA signing private key from an ECPrivateKey.
   *
   * @param key - The EC private key to use for ECDSA signing
   * @returns A new ECDSA signing private key
   */
  static fromEcdsa(key: ECPrivateKey): SigningPrivateKey {
    return new SigningPrivateKey(SignatureScheme.Ecdsa, key, undefined, undefined);
  }

  /**
   * Creates a new Ed25519 signing private key from an Ed25519PrivateKey.
   *
   * @param key - The Ed25519 private key to use
   * @returns A new Ed25519 signing private key
   */
  static fromEd25519(key: Ed25519PrivateKey): SigningPrivateKey {
    return new SigningPrivateKey(SignatureScheme.Ed25519, undefined, key, undefined);
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
    return new SigningPrivateKey(scheme, undefined, undefined, key);
  }

  /**
   * Creates a new SSH signing private key from an SSHPrivateKey.
   *
   *
   * @param key - The SSH private key to wrap
   * @returns A new SSH signing private key
   */
  static fromSsh(key: SSHPrivateKey): SigningPrivateKey {
    return new SigningPrivateKey(
      sshSignatureScheme(key.algorithm),
      undefined,
      undefined,
      undefined,
      key,
    );
  }

  /**
   * A fresh signing key; Ed25519 unless `scheme` says otherwise. SSH schemes
   * derive from a `PrivateKeyBase` instead.
   */
  static random({
    scheme = defaultSignatureScheme(),
    rng = secureRng(),
  }: { scheme?: SignatureScheme } & RngOptions = {}): SigningPrivateKey {
    switch (scheme) {
      case SignatureScheme.Schnorr:
        return SigningPrivateKey.fromSchnorr(ECPrivateKey.random({ rng }));
      case SignatureScheme.Ecdsa:
        return SigningPrivateKey.fromEcdsa(ECPrivateKey.random({ rng }));
      case SignatureScheme.Ed25519:
        return SigningPrivateKey.fromEd25519(Ed25519PrivateKey.random({ rng }));
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
   *
   * SSH RSA and P-521 keys have no `SignatureScheme` (the reference defines
   * none for them) and throw `Ssh` with the reference's text for their
   * signatures: `Unsupported SSH signature algorithm` / `Unsupported SSH
   * ECDSA curve`.
   */
  get scheme(): SignatureScheme {
    if (this._type === undefined) throw sshSchemeUnsupportedError(this.sshAlgorithm());
    return this._type;
  }

  /** The SSH algorithm of an SSH key; `Ssh` failure for any other key. */
  private sshAlgorithm(): SshAlgorithm {
    if (this._sshKey === undefined) throw ComponentsError.ssh("not an SSH key");
    return this._sshKey.algorithm;
  }

  /**
   * Returns a human-readable string identifying the key type.
   * @returns A string like "Ed25519", "Schnorr", "ECDSA", "MLDSA-44", etc.
   */
  get keyType(): string {
    switch (this._type) {
      case SignatureScheme.Ed25519:
        return "Ed25519";
      case SignatureScheme.Schnorr:
        return "Schnorr";
      case SignatureScheme.Ecdsa:
        return "ECDSA";
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
      case undefined:
        return sshKeyTypeName(this.sshAlgorithm());
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
   * Returns the underlying MLDSA private key if this is an MLDSA key.
   *
   * @returns The MLDSA private key if this is an MLDSA key, undefined otherwise
   */
  asMldsa(): MLDSAPrivateKey | undefined {
    if (this._type !== undefined && isMldsaScheme(this._type) && this._mldsaKey !== undefined) {
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
   * Checks if this is an MLDSA signing key.
   */
  isMldsa(): boolean {
    return this._type !== undefined && isMldsaScheme(this._type);
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
      case SignatureScheme.MLDSA44:
      case SignatureScheme.MLDSA65:
      case SignatureScheme.MLDSA87:
        // As the reference: an ML-DSA public key is not derived from the
        // private key; keep the one `createKeypair` hands out.
        throw ComponentsError.general("Deriving ML-DSA public key not supported");
      case SignatureScheme.SshEd25519:
      case SignatureScheme.SshDsa:
      case SignatureScheme.SshEcdsaP256:
      case SignatureScheme.SshEcdsaP384:
      case undefined: {
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
      case SignatureScheme.MLDSA44:
      case SignatureScheme.MLDSA65:
      case SignatureScheme.MLDSA87:
        if (this._mldsaKey === undefined || other._mldsaKey === undefined) return false;
        return this._mldsaKey.equals(other._mldsaKey);
      case SignatureScheme.SshEd25519:
      case SignatureScheme.SshDsa:
      case SignatureScheme.SshEcdsaP256:
      case SignatureScheme.SshEcdsaP384:
      case undefined: {
        if (this._sshKey === undefined || other._sshKey === undefined) return false;
        return this._sshKey.toOpenssh() === other._sshKey.toOpenssh();
      }
    }
  }

  /**
   *   `SigningPrivateKey(<refHexShort>, <inner>)`
   * where `<inner>` is:
   *   - `SchnorrPrivateKey(<refHexShort>)` / `ECDSAPrivateKey(<refHexShort>)`
   *     for the secp256k1 variants (the reference formats them inline by tag rather
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
        innerDisplay = `SchnorrPrivateKey(${this._ecKey?.refHexShort() ?? refShort})`;
        break;
      case SignatureScheme.Ecdsa:
        innerDisplay = `ECDSAPrivateKey(${this._ecKey?.refHexShort() ?? refShort})`;
        break;
      case SignatureScheme.Ed25519:
        innerDisplay = this._ed25519Key?.toString() ?? String(this._type);
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
      case undefined:
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
   * - SSH: Requires namespace and hash algorithm via SigningOptions.Ssh
   * - Other schemes (ECDSA, Ed25519, MLDSA): Options are ignored
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
      case SignatureScheme.SshEcdsaP384:
      case undefined: {
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
   * verification for Ed25519 / ECDSA / MLDSA should derive the
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
      throw ComponentsError.crypto("Invalid key type for Schnorr signing");
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
      throw ComponentsError.crypto("Invalid key type for ECDSA signing");
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
      throw ComponentsError.crypto("Invalid key type for Ed25519 signing");
    }
    const sigData = privateKey.sign(message);
    return Signature.ed25519FromData(sigData);
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
      throw ComponentsError.postQuantum("Invalid key type for MLDSA signing");
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
      // The reference's `from_untagged_cbor`, branch for branch.
      decodeUntagged: (cborValue) => {
        // A byte string is a Schnorr key.
        if (isBytes(cborValue)) {
          return SigningPrivateKey.fromSchnorr(ECPrivateKey.from(expectBytes(cborValue)));
        }

        // An array: `elements.remove(0)` twice (the reference panics on a
        // missing element), the discriminator as a `usize` with dcbor's
        // negative wrap, and any further element ignored.
        if (isArray(cborValue)) {
          const elements = expectArray(cborValue);
          const head = elements[0];
          if (head === undefined) {
            throw CborError.custom("SigningPrivateKey array is empty");
          }
          const discriminator = expectUnsigned(head, USIZE_FIELD);
          if (discriminator === 1 || discriminator === 2) {
            const second = elements[1];
            if (second === undefined) {
              throw CborError.custom("SigningPrivateKey array has no key data");
            }
            const keyData = expectBytes(second);
            return discriminator === 1
              ? SigningPrivateKey.fromEcdsa(ECPrivateKey.from(keyData))
              : SigningPrivateKey.fromEd25519(Ed25519PrivateKey.from(keyData));
          }
          throw CborError.custom(`Invalid discriminator for SigningPrivateKey: ${discriminator}`);
        }

        // A tagged value: an SSH private key text or an ML-DSA key.
        const tagged = asTaggedValue(cborValue);
        if (tagged !== undefined) {
          if (tagged[0].value === TAG_SSH_TEXT_PRIVATE_KEY.value) {
            const text = expectText(tagged[1]);
            try {
              return SigningPrivateKey.fromSsh(SSHPrivateKey.fromOpenssh(text));
            } catch {
              throw CborError.custom("Invalid SSH private key");
            }
          }
          if (tagged[0].value === TAG_MLDSA_PRIVATE_KEY.value) {
            return SigningPrivateKey.fromMldsa(MLDSAPrivateKey.codec.decodeUntagged(tagged[1]));
          }
          throw CborError.custom(
            `Invalid CBOR tag for SigningPrivateKey: ${String(tagged[0].value)}`,
          );
        }

        throw CborError.custom("Invalid CBOR case for SigningPrivateKey");
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
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
      case SignatureScheme.SshEcdsaP384:
      case undefined: {
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
        `SigningPrivateKey is not an SSH key (scheme: ${String(this._type)})`,
      );
    }
    return this._sshKey.toOpenssh();
  }
}
