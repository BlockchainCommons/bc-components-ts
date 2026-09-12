/**
 * A digital signature created with various signature algorithms.
 *
 * `Signature` represents different types of digital signatures.
 * Supports Schnorr, ECDSA, Ed25519, ML-DSA and SSH signatures.
 *
 * Signatures can be serialized to and from CBOR with tag 40020.
 *
 * # CBOR Serialization
 *
 * The CBOR encoding:
 * - Schnorr: `#6.40020(h'<64-byte-signature>')` (bare byte string)
 * - ECDSA:   `#6.40020([1, h'<64-byte-signature>'])`
 * - Ed25519: `#6.40020([2, h'<64-byte-signature>'])`
 */

import { ecdsa, schnorr, ed25519 } from "@blockchaincommons/crypto";
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
  TAG_SIGNATURE,
  TAG_MLDSA_SIGNATURE,
  TAG_SSH_TEXT_SIGNATURE,
} from "@blockchaincommons/tags";
import { ComponentsError } from "../error.js";
import { bytesToHex } from "../utils.js";
import { bytesFromHex } from "../domain.js";
import { SignatureScheme, isMldsaScheme } from "./signature-scheme.js";
import { MLDSASignature } from "../mldsa/mldsa-signature.js";
import { MLDSALevel } from "../mldsa/mldsa-level.js";
import { SSHSignature } from "../ssh/ssh-signature.js";
import { type UR, urFor } from "@blockchaincommons/uniform-resources";

// The codec is built on first use so that an unused class tree-shakes away.
let SIGNATURE_CODEC: ComponentCodec<Signature> | undefined;

/**
 * A digital signature created with various signature algorithms.
 *
 * Currently supports:
 * - Schnorr signatures (64 bytes) - bare byte string in CBOR
 * - ECDSA signatures (64 bytes) - discriminator 1
 * - Ed25519 signatures (64 bytes) - discriminator 2
 * - MLDSA signatures (post-quantum) - tagged CBOR delegating to MLDSASignature
 */
export class Signature implements ToCbor {
  private readonly _type: SignatureScheme;
  private readonly _data: Uint8Array;
  private readonly _mldsaSignature: MLDSASignature | undefined;
  private readonly _sshSig: SSHSignature | undefined;

  private constructor(
    type: SignatureScheme,
    data: Uint8Array,
    mldsaSignature?: MLDSASignature,
    sshSig?: SSHSignature,
  ) {
    this._type = type;
    this._data = new Uint8Array(data);
    this._mldsaSignature = mldsaSignature;
    this._sshSig = sshSig;
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /**
   * Creates a Schnorr signature from a 64-byte array.
   *
   * @param data - The 64-byte signature data
   * @returns A new Schnorr signature
   */
  static schnorrFromData(data: Uint8Array): Signature {
    if (data.length !== schnorr.SIGNATURE_SIZE) {
      throw ComponentsError.invalidSize(schnorr.SIGNATURE_SIZE, data.length);
    }
    return new Signature(SignatureScheme.Schnorr, data);
  }

  /**
   * Creates a Schnorr signature from a hex string.
   *
   * @param hex - The hex-encoded signature data
   * @returns A new Schnorr signature
   */
  static schnorrFromHex(hex: string): Signature {
    return Signature.schnorrFromData(bytesFromHex(hex, "Signature"));
  }

  /**
   * Creates an ECDSA signature from a 64-byte array.
   *
   * @param data - The 64-byte signature data
   * @returns A new ECDSA signature
   */
  static ecdsaFromData(data: Uint8Array): Signature {
    if (data.length !== ecdsa.SIGNATURE_SIZE) {
      throw ComponentsError.invalidSize(ecdsa.SIGNATURE_SIZE, data.length);
    }
    return new Signature(SignatureScheme.Ecdsa, data);
  }

  /**
   * Creates an ECDSA signature from a hex string.
   *
   * @param hex - The hex-encoded signature data
   * @returns A new ECDSA signature
   */
  static ecdsaFromHex(hex: string): Signature {
    return Signature.ecdsaFromData(bytesFromHex(hex, "Signature"));
  }

  /**
   * Creates an Ed25519 signature from a 64-byte array.
   *
   * @param data - The 64-byte signature data
   * @returns A new Ed25519 signature
   */
  static ed25519FromData(data: Uint8Array): Signature {
    if (data.length !== ed25519.SIGNATURE_SIZE) {
      throw ComponentsError.invalidSize(ed25519.SIGNATURE_SIZE, data.length);
    }
    return new Signature(SignatureScheme.Ed25519, data);
  }

  /**
   * Creates an Ed25519 signature from a hex string.
   *
   * @param hex - The hex-encoded signature data
   * @returns A new Ed25519 signature
   */
  static ed25519FromHex(hex: string): Signature {
    return Signature.ed25519FromData(bytesFromHex(hex, "Signature"));
  }

  /**
   * Creates a Signature from an MLDSASignature.
   *
   * @param sig - The MLDSASignature
   * @returns A new Signature wrapping the MLDSA signature
   */
  static mldsaFromSignature(sig: MLDSASignature): Signature {
    // Determine the SignatureScheme based on the MLDSA level
    let scheme: SignatureScheme;
    switch (sig.level) {
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
        throw ComponentsError.invalidData(`Unknown MLDSA level: ${String(sig.level)}`);
    }
    return new Signature(scheme, sig.bytes, sig);
  }

  /**
   * Creates a Signature from an SSHSignature.
   *
   *
   * The signature scheme is derived from the inner public-key algorithm,
   * as the reference implementation does `Signature::scheme()` at lines 506-519.
   *
   * @param sig - The SSHSignature
   * @returns A new SSH Signature
   */
  static fromSsh(sig: SSHSignature): Signature {
    let scheme: SignatureScheme;
    switch (sig.publicKey.data.kind) {
      case "ed25519":
        scheme = SignatureScheme.SshEd25519;
        break;
      case "dsa":
        scheme = SignatureScheme.SshDsa;
        break;
      case "ecdsa":
        switch (sig.publicKey.data.curve) {
          case "nistp256":
            scheme = SignatureScheme.SshEcdsaP256;
            break;
          case "nistp384":
            scheme = SignatureScheme.SshEcdsaP384;
            break;
        }
        break;
    }
    return new Signature(scheme, sig.signatureBytes, undefined, sig);
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /**
   * Returns the signature scheme used to create this signature.
   */
  get scheme(): SignatureScheme {
    return this._type;
  }

  /**
   * Returns a human-readable string identifying the signature type.
   * @returns A string like "Ed25519", "Schnorr", "ECDSA", "MLDSA-44", etc.
   */
  get signatureType(): string {
    switch (this._type) {
      case SignatureScheme.Ed25519:
        return "Ed25519";
      case SignatureScheme.Schnorr:
        return "Schnorr";
      case SignatureScheme.Ecdsa:
        return "Ecdsa";
      case SignatureScheme.MLDSA44:
        return "MLDSA-44";
      case SignatureScheme.MLDSA65:
        return "MLDSA-65";
      case SignatureScheme.MLDSA87:
        return "MLDSA-87";
      case SignatureScheme.SshEd25519:
        return "SshEd25519";
      case SignatureScheme.SshDsa:
        return "SshDsa";
      case SignatureScheme.SshEcdsaP256:
        return "SshEcdsaP256";
      case SignatureScheme.SshEcdsaP384:
        return "SshEcdsaP384";
      default:
        return this._type;
    }
  }

  /** The bytes (a view; do not mutate). */
  get bytes(): Uint8Array {
    return new Uint8Array(this._data);
  }

  /**
   * Returns the Schnorr signature data if this is a Schnorr signature.
   *
   * @returns The 64-byte signature data if this is a Schnorr signature, undefined otherwise
   */
  asSchnorr(): Uint8Array | undefined {
    if (this._type === SignatureScheme.Schnorr) {
      return new Uint8Array(this._data);
    }
    return undefined;
  }

  /**
   * Checks if this is a Schnorr signature.
   */
  isSchnorr(): boolean {
    return this._type === SignatureScheme.Schnorr;
  }

  /**
   * Returns the ECDSA signature data if this is an ECDSA signature.
   *
   * @returns The 64-byte signature data if this is an ECDSA signature, undefined otherwise
   */
  asEcdsa(): Uint8Array | undefined {
    if (this._type === SignatureScheme.Ecdsa) {
      return new Uint8Array(this._data);
    }
    return undefined;
  }

  /**
   * Checks if this is an ECDSA signature.
   */
  isEcdsa(): boolean {
    return this._type === SignatureScheme.Ecdsa;
  }

  /**
   * Returns the Ed25519 signature data if this is an Ed25519 signature.
   *
   * @returns The 64-byte signature data if this is an Ed25519 signature, undefined otherwise
   */
  asEd25519(): Uint8Array | undefined {
    if (this._type === SignatureScheme.Ed25519) {
      return new Uint8Array(this._data);
    }
    return undefined;
  }

  /**
   * Checks if this is an Ed25519 signature.
   */
  isEd25519(): boolean {
    return this._type === SignatureScheme.Ed25519;
  }

  /**
   * Returns the MLDSASignature if this is an MLDSA signature.
   *
   * @returns The MLDSASignature if this is an MLDSA signature, undefined otherwise
   */
  asMldsa(): MLDSASignature | undefined {
    if (isMldsaScheme(this._type) && this._mldsaSignature !== undefined) {
      return this._mldsaSignature;
    }
    return undefined;
  }

  /**
   * Checks if this is an MLDSA signature.
   */
  isMldsa(): boolean {
    return isMldsaScheme(this._type);
  }

  /**
   * Returns the underlying SSHSignature if this is an SSH signature.
   *
   *
   * @returns The SSHSignature if this is an SSH signature, undefined otherwise
   */
  asSsh(): SSHSignature | undefined {
    return this._sshSig ?? undefined;
  }

  /**
   * Checks if this is an SSH signature.
   */
  isSsh(): boolean {
    return this._sshSig !== undefined;
  }

  /**
   * Get hex string representation of the signature data.
   */
  toHex(): string {
    return bytesToHex(this._data);
  }

  /**
   * Compare with another Signature.
   */
  equals(other: Signature): boolean {
    if (this._type !== other._type) return false;
    if (this._sshSig !== undefined || other._sshSig !== undefined) {
      if (this._sshSig === undefined || other._sshSig === undefined) return false;
      return this._sshSig.toPem() === other._sshSig.toPem();
    }
    if (this._data.length !== other._data.length) return false;
    for (let i = 0; i < this._data.length; i++) {
      if (this._data[i] !== other._data[i]) return false;
    }
    return true;
  }

  /**
   * Get string representation.
   */
  toString(): string {
    return `Signature(${this._type}, ${this.toHex().substring(0, 16)}...)`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<Signature> {
    return (SIGNATURE_CODEC ??= defineCodec({
      tags: [TAG_SIGNATURE],
      decodeUntagged: (cborValue) => {
        // Wire format: Schnorr is a bare byte string
        if (isBytes(cborValue)) {
          const signatureData = expectBytes(cborValue);
          return Signature.schnorrFromData(signatureData);
        }

        // Array format for ECDSA, Ed25519
        if (isArray(cborValue)) {
          const elements = expectArray(cborValue);

          if (elements.length !== 2) {
            throw ComponentsError.invalidData("Signature array must have 2 elements");
          }

          const discriminator = expectUnsigned(elements[0]);
          const signatureData = expectBytes(elements[1]);

          switch (Number(discriminator)) {
            case 1: // ECDSA
              return Signature.ecdsaFromData(signatureData);
            case 2: // Ed25519
              return Signature.ed25519FromData(signatureData);
            default:
              throw ComponentsError.invalidData(
                `Unknown signature discriminator: ${discriminator}`,
              );
          }
        }

        // Tagged format for MLDSA / SSH
        if (isTagged(cborValue)) {
          const tagged = asTaggedValue(cborValue);
          if (tagged?.[0].value === TAG_MLDSA_SIGNATURE.value) {
            const mldsaSig = MLDSASignature.fromCbor(cborValue);
            return Signature.mldsaFromSignature(mldsaSig);
          }
          if (tagged?.[0].value === TAG_SSH_TEXT_SIGNATURE.value) {
            const text = expectText(tagged[1]);
            const sshSig = SSHSignature.fromPem(text);
            return Signature.fromSsh(sshSig);
          }
        }

        throw ComponentsError.invalidData(
          "Signature must be a byte string (Schnorr), array (ECDSA/Ed25519), tagged MLDSA, or tagged SSH",
        );
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...Signature.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding.
   *
   * Format:
   * - Schnorr: h'<64-byte-signature>' (bare byte string)
   * - ECDSA:   [1, h'<64-byte-signature>']
   * - Ed25519: [2, h'<64-byte-signature>']
   */
  untaggedCbor(): Cbor {
    switch (this._type) {
      case SignatureScheme.Schnorr:
        // CBOR::to_byte_string(data) - bare byte string
        return cbor(this._data);
      case SignatureScheme.Ecdsa:
        return cbor([1, cbor(this._data)]);
      case SignatureScheme.Ed25519:
        return cbor([2, cbor(this._data)]);
      case SignatureScheme.MLDSA44:
      case SignatureScheme.MLDSA65:
      case SignatureScheme.MLDSA87: {
        if (this._mldsaSignature === undefined) {
          throw ComponentsError.invalidData("MLDSA signature is missing");
        }
        // delegates to MLDSASignature (which produces tagged CBOR)
        return this._mldsaSignature.toCbor();
      }
      case SignatureScheme.SshEd25519:
      case SignatureScheme.SshDsa:
      case SignatureScheme.SshEcdsaP256:
      case SignatureScheme.SshEcdsaP384: {
        if (this._sshSig === undefined) {
          throw ComponentsError.invalidData("SSH signature is missing");
        }
        // (`signature.rs:643-646`).
        return taggedValue(TAG_SSH_TEXT_SIGNATURE, this._sshSig.toPem());
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
  static fromCbor(cborValue: Cbor): Signature {
    return Signature.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR (Uniform Resource) Serialization
  // ============================================================================
}
