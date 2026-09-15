/**
 * A public key used for verifying digital signatures.
 *
 * `SigningPublicKey` is a type representing different types of signing public
 * keys. Supports Schnorr, ECDSA, Ed25519, ML-DSA and SSH keys.
 *
 * This type implements the `Verifier` interface, allowing it to verify signatures.
 *
 * # CBOR Serialization
 *
 * `SigningPublicKey` is serialized to CBOR with tag 40022.
 *
 * The CBOR encoding:
 * - Schnorr: `#6.40022(h'<32-byte-x-only-public-key>')` (bare byte string)
 * - ECDSA:   `#6.40022([1, h'<33-byte-compressed-public-key>'])`
 * - Ed25519: `#6.40022([2, h'<32-byte-public-key>'])`
 */

import {
  type Cbor,
  type Tag,
  cbor,
  taggedValue,
  expectArray,
  expectBytes,
  expectText,
  isBytes,
  isArray,
  asTaggedValue,
  type ToCbor,
  CborError,
  asUnsigned,
  asBytes,
} from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "../codable.js";
import {
  TAG_SIGNING_PUBLIC_KEY,
  TAG_MLDSA_PUBLIC_KEY,
  TAG_SSH_TEXT_PUBLIC_KEY,
} from "@blockchaincommons/tags";
import { Ed25519PublicKey } from "../ed25519/ed25519-public-key.js";
import { ECPublicKey } from "../ec-key/ec-public-key.js";
import { SchnorrPublicKey } from "../ec-key/schnorr-public-key.js";
import { MLDSAPublicKey } from "../mldsa/mldsa-public-key.js";
import { MLDSALevel } from "../mldsa/mldsa-level.js";
import { SSHPublicKey } from "../ssh/ssh-public-key.js";
import {
  sshKeyTypeName,
  sshSchemeUnsupportedError,
  sshSignatureScheme,
  type SshAlgorithm,
} from "../ssh/ssh-algorithm.js";
import { SignatureScheme, isMldsaScheme } from "./signature-scheme.js";
import type { Signature } from "./signature.js";
import type { Verifier } from "./signer.js";
import { Reference, type ReferenceProvider } from "../reference.js";
import { Digest } from "../digest.js";
import { type UR, urFor } from "@blockchaincommons/uniform-resources";
import { ComponentsError } from "../error.js";

// The codec is built on first use so that an unused class tree-shakes away.
let SIGNING_PUBLIC_KEY_CODEC: ComponentCodec<SigningPublicKey> | undefined;

/**
 * A public key used for verifying digital signatures.
 *
 * Currently supports:
 * - Schnorr public keys (32 bytes, x-only) - bare byte string in CBOR
 * - ECDSA public keys (33 bytes, compressed) - discriminator 1
 * - Ed25519 public keys (32 bytes) - discriminator 2
 * - MLDSA public keys (post-quantum) - tagged CBOR delegating to MLDSAPublicKey
 */
export class SigningPublicKey implements Verifier, ReferenceProvider, ToCbor {
  private readonly _type: SignatureScheme | undefined;
  private readonly _schnorrKey: SchnorrPublicKey | undefined;
  private readonly _ecdsaKey: ECPublicKey | undefined;
  private readonly _ed25519Key: Ed25519PublicKey | undefined;
  private readonly _mldsaKey: MLDSAPublicKey | undefined;
  private readonly _sshKey: SSHPublicKey | undefined;

  private constructor(
    type: SignatureScheme | undefined,
    schnorrKey?: SchnorrPublicKey,
    ecdsaKey?: ECPublicKey,
    ed25519Key?: Ed25519PublicKey,
    mldsaKey?: MLDSAPublicKey,
    sshKey?: SSHPublicKey,
  ) {
    this._type = type;
    this._schnorrKey = schnorrKey;
    this._ecdsaKey = ecdsaKey;
    this._ed25519Key = ed25519Key;
    this._mldsaKey = mldsaKey;
    this._sshKey = sshKey;
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Creates a new signing public key from a Schnorr (x-only) public key.
   *
   * @param key - A SchnorrPublicKey
   * @returns A new signing public key containing the Schnorr key
   */
  static fromSchnorr(key: SchnorrPublicKey): SigningPublicKey {
    return new SigningPublicKey(SignatureScheme.Schnorr, key, undefined, undefined, undefined);
  }

  /**
   * Creates a new signing public key from an ECDSA (compressed) public key.
   *
   * @param key - An ECPublicKey
   * @returns A new signing public key containing the ECDSA key
   */
  static fromEcdsa(key: ECPublicKey): SigningPublicKey {
    return new SigningPublicKey(SignatureScheme.Ecdsa, undefined, key, undefined, undefined);
  }

  /**
   * Creates a new signing public key from an Ed25519 public key.
   *
   * @param key - An Ed25519 public key
   * @returns A new signing public key containing the Ed25519 key
   */
  static fromEd25519(key: Ed25519PublicKey): SigningPublicKey {
    return new SigningPublicKey(SignatureScheme.Ed25519, undefined, undefined, key, undefined);
  }

  /**
   * Creates a new signing public key from an MLDSAPublicKey.
   *
   * @param key - An MLDSAPublicKey
   * @returns A new signing public key containing the MLDSA key
   */
  static fromMldsa(key: MLDSAPublicKey): SigningPublicKey {
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
    return new SigningPublicKey(scheme, undefined, undefined, undefined, key);
  }

  /**
   * Creates a new signing public key from an SSHPublicKey.
   *
   *
   * @param key - An SSHPublicKey
   * @returns A new signing public key wrapping the SSH public key
   */
  static fromSsh(key: SSHPublicKey): SigningPublicKey {
    return new SigningPublicKey(
      sshSignatureScheme(key.algorithm),
      undefined,
      undefined,
      undefined,
      undefined,
      key,
    );
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
   * Returns the underlying Schnorr public key if this is a Schnorr key.
   *
   * @returns The SchnorrPublicKey if this is a Schnorr key, undefined otherwise
   */
  asSchnorr(): SchnorrPublicKey | undefined {
    if (this._type === SignatureScheme.Schnorr && this._schnorrKey !== undefined) {
      return this._schnorrKey;
    }
    return undefined;
  }

  /**
   * Returns the underlying ECDSA public key if this is an ECDSA key.
   *
   * @returns The ECPublicKey if this is an ECDSA key, undefined otherwise
   */
  asEcdsa(): ECPublicKey | undefined {
    if (this._type === SignatureScheme.Ecdsa && this._ecdsaKey !== undefined) {
      return this._ecdsaKey;
    }
    return undefined;
  }

  /**
   * Returns the underlying Ed25519 public key if this is an Ed25519 key.
   *
   * @returns The Ed25519 public key if this is an Ed25519 key, undefined otherwise
   */
  asEd25519(): Ed25519PublicKey | undefined {
    if (this._type === SignatureScheme.Ed25519 && this._ed25519Key !== undefined) {
      return this._ed25519Key;
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
   * Returns the underlying MLDSA public key if this is an MLDSA key.
   *
   * @returns The MLDSAPublicKey if this is an MLDSA key, undefined otherwise
   */
  asMldsa(): MLDSAPublicKey | undefined {
    if (this._type !== undefined && isMldsaScheme(this._type) && this._mldsaKey !== undefined) {
      return this._mldsaKey;
    }
    return undefined;
  }

  /**
   * Checks if this is an MLDSA signing key.
   */
  isMldsa(): boolean {
    return this._type !== undefined && isMldsaScheme(this._type);
  }

  /**
   * Returns the underlying SSH public key if this is an SSH key.
   *
   *
   * @returns The SSHPublicKey if this is an SSH key, undefined otherwise
   */
  asSsh(): SSHPublicKey | undefined {
    return this._sshKey ?? undefined;
  }

  /**
   * Checks if this is an SSH signing key.
   */
  isSsh(): boolean {
    return this._sshKey !== undefined;
  }

  /**
   * Returns a copy of this SSH public key with its comment replaced.
   * Throws if this is not an SSH key — mirrors the reference implementation's `set_comment`
   * which is only callable on `SigningPublicKey::SSH` variants.
   */
  withSshComment(comment: string): SigningPublicKey {
    if (this._sshKey === undefined) {
      throw ComponentsError.invalidData(
        `SigningPublicKey.withSshComment: not an SSH key (scheme: ${String(this._type)})`,
      );
    }
    return SigningPublicKey.fromSsh(this._sshKey.withComment(comment));
  }

  /**
   * Compare with another SigningPublicKey.
   */
  equals(other: SigningPublicKey): boolean {
    if (this._type !== other._type) return false;
    switch (this._type) {
      case SignatureScheme.Schnorr:
        if (this._schnorrKey === undefined || other._schnorrKey === undefined) return false;
        return this._schnorrKey.equals(other._schnorrKey);
      case SignatureScheme.Ecdsa:
        if (this._ecdsaKey === undefined || other._ecdsaKey === undefined) return false;
        return this._ecdsaKey.equals(other._ecdsaKey);
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
        return this._sshKey.equals(other._sshKey);
      }
    }
  }

  /**
   * Get string representation.
   *
   *   `SigningPublicKey(<ref_hex_short>, <inner_key_display>)`
   * The reference is computed from the tagged-CBOR form.
   */
  toString(): string {
    const refShort = this.reference().shortReference("hex");
    let innerDisplay: string;
    switch (this._type) {
      case SignatureScheme.Schnorr:
        innerDisplay = this._schnorrKey?.toString() ?? String(this._type);
        break;
      case SignatureScheme.Ecdsa:
        innerDisplay = this._ecdsaKey?.toString() ?? String(this._type);
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
        innerDisplay = this._sshKey?.toString() ?? `SSHPublicKey(${refShort})`;
        break;
    }
    return `SigningPublicKey(${refShort}, ${innerDisplay})`;
  }

  // ============================================================================
  // ReferenceProvider Interface
  // ============================================================================

  /**
   * Returns a unique reference to this SigningPublicKey instance.
   *
   * The reference is derived from the SHA-256 hash of the tagged CBOR
   * representation, providing a unique, content-addressable identifier.
   */
  reference(): Reference {
    const digest = Digest.fromImage(this.toCbor().toData());
    return Reference.fromDigest(digest);
  }

  // ============================================================================
  // Verifier Interface
  // ============================================================================

  /**
   * Verifies a signature against a message.
   *
   * @param signature - The signature to verify
   * @param message - The message that was allegedly signed
   * @returns `true` if the signature is valid, `false` otherwise
   */
  verify(signature: Signature, message: Uint8Array): boolean {
    // An SSH key verifies only `sshsig` signatures: the embedded key,
    // namespace and algorithm-specific signature are checked by the SSH key.
    if (this._sshKey !== undefined) {
      const sshSig = signature.asSsh();
      if (sshSig === undefined) return false;
      try {
        return this._sshKey.verifySshSignature(sshSig.namespace, message, sshSig);
      } catch {
        return false;
      }
    }

    // Check that signature scheme matches
    if (signature.isSsh() || signature.scheme !== this._type) {
      return false;
    }

    switch (this._type) {
      case SignatureScheme.Schnorr: {
        if (this._schnorrKey === undefined) {
          return false;
        }
        const sigData = signature.asSchnorr();
        if (sigData === undefined) {
          return false;
        }
        return this._schnorrKey.schnorrVerify(sigData, message);
      }
      case SignatureScheme.Ecdsa: {
        if (this._ecdsaKey === undefined) {
          return false;
        }
        const sigData = signature.asEcdsa();
        if (sigData === undefined) {
          return false;
        }
        return this._ecdsaKey.verify(sigData, message);
      }
      case SignatureScheme.Ed25519: {
        if (this._ed25519Key === undefined) {
          return false;
        }
        const sigData = signature.asEd25519();
        if (sigData === undefined) {
          return false;
        }
        return this._ed25519Key.verify(message, sigData);
      }
      case SignatureScheme.MLDSA44:
      case SignatureScheme.MLDSA65:
      case SignatureScheme.MLDSA87: {
        if (this._mldsaKey === undefined) {
          return false;
        }
        const mldsaSig = signature.asMldsa();
        if (mldsaSig === undefined) {
          return false;
        }
        try {
          return this._mldsaKey.verify(mldsaSig, message);
        } catch {
          return false;
        }
      }
      case SignatureScheme.SshEd25519:
      case SignatureScheme.SshDsa:
      case SignatureScheme.SshEcdsaP256:
      case SignatureScheme.SshEcdsaP384:
      case undefined:
        return false;
    }
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<SigningPublicKey> {
    return (SIGNING_PUBLIC_KEY_CODEC ??= defineCodec({
      tags: [TAG_SIGNING_PUBLIC_KEY],
      // The reference's `from_untagged_cbor`, branch for branch.
      decodeUntagged: (cborValue) => {
        // A byte string is a Schnorr key.
        if (isBytes(cborValue)) {
          return SigningPublicKey.fromSchnorr(SchnorrPublicKey.from(expectBytes(cborValue)));
        }

        // An array of exactly two elements, `[1, bytes]` or `[2, bytes]`
        // (an exact `Unsigned(1)`/`Unsigned(2)` match: no wrap here).
        if (isArray(cborValue)) {
          const elements = expectArray(cborValue);
          if (elements.length === 2) {
            const head = asUnsigned(elements[0]);
            const keyData = asBytes(elements[1]);
            if (keyData !== undefined) {
              if (head === 1) return SigningPublicKey.fromEcdsa(ECPublicKey.from(keyData));
              if (head === 2) return SigningPublicKey.fromEd25519(Ed25519PublicKey.from(keyData));
            }
          }
          throw CborError.custom("invalid signing public key");
        }

        // A tagged value: an SSH public key text or an ML-DSA key.
        const tagged = asTaggedValue(cborValue);
        if (tagged !== undefined) {
          if (tagged[0].value === TAG_SSH_TEXT_PUBLIC_KEY.value) {
            const text = expectText(tagged[1]);
            try {
              return SigningPublicKey.fromSsh(SSHPublicKey.fromOpenssh(text));
            } catch {
              throw CborError.custom("invalid SSH public key");
            }
          }
          if (tagged[0].value === TAG_MLDSA_PUBLIC_KEY.value) {
            return SigningPublicKey.fromMldsa(MLDSAPublicKey.fromCbor(cborValue));
          }
        }

        throw CborError.custom("invalid signing public key");
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...SigningPublicKey.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding.
   *
   * Format:
   * - Schnorr: h'<32-byte-x-only-public-key>' (bare byte string)
   * - ECDSA:   [1, h'<33-byte-compressed-public-key>']
   * - Ed25519: [2, h'<32-byte-public-key>']
   */
  untaggedCbor(): Cbor {
    switch (this._type) {
      case SignatureScheme.Schnorr: {
        if (this._schnorrKey === undefined) {
          throw ComponentsError.invalidData("Schnorr public key is missing");
        }
        // CBOR::to_byte_string(key.bytes) - bare byte string
        return cbor(this._schnorrKey.bytes);
      }
      case SignatureScheme.Ecdsa: {
        if (this._ecdsaKey === undefined) {
          throw ComponentsError.invalidData("ECDSA public key is missing");
        }
        return cbor([1, cbor(this._ecdsaKey.bytes)]);
      }
      case SignatureScheme.Ed25519: {
        if (this._ed25519Key === undefined) {
          throw ComponentsError.invalidData("Ed25519 public key is missing");
        }
        return cbor([2, cbor(this._ed25519Key.bytes)]);
      }
      case SignatureScheme.MLDSA44:
      case SignatureScheme.MLDSA65:
      case SignatureScheme.MLDSA87: {
        if (this._mldsaKey === undefined) {
          throw ComponentsError.invalidData("MLDSA public key is missing");
        }
        // delegates to MLDSAPublicKey (which produces tagged CBOR)
        return this._mldsaKey.toCbor();
      }
      case SignatureScheme.SshEd25519:
      case SignatureScheme.SshDsa:
      case SignatureScheme.SshEcdsaP256:
      case SignatureScheme.SshEcdsaP384:
      case undefined: {
        if (this._sshKey === undefined) {
          throw ComponentsError.invalidData("SSH public key is missing");
        }
        // (`signing_public_key.rs:441-443`).
        return taggedValue(TAG_SSH_TEXT_PUBLIC_KEY, this._sshKey.toOpenssh());
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
  static fromCbor(cborValue: Cbor): SigningPublicKey {
    return SigningPublicKey.codec.decode(cborValue);
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
   * Returns the OpenSSH single-line public-key text for an SSH public key.
   *
   * Only valid when this `SigningPublicKey` wraps an `SSHPublicKey`
   * (i.e. one of the four `SignatureScheme.SshXxx` variants). Mirrors
   * the reference implementation's `SigningPublicKey::SSH(key) => key.to_openssh()` usage at
   * `signing_public_key.rs:442`.
   */
  toSshOpenssh(): string {
    if (this._sshKey === undefined) {
      throw ComponentsError.invalidData(
        `SigningPublicKey is not an SSH key (scheme: ${String(this._type)})`,
      );
    }
    return this._sshKey.toOpenssh();
  }
}
