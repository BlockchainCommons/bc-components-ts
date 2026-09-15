/**
 * PrivateKeyBase - Root cryptographic material for deterministic key derivation
 *
 * PrivateKeyBase is a 32-byte value that serves as the root of cryptographic
 * material from which various keys can be deterministically derived.
 *
 * # CBOR Serialization
 *
 * PrivateKeyBase is serialized with tag 40016:
 * ```
 * #6.40016(h'<32-byte-key-material>')
 * ```
 *
 * # UR Serialization
 *
 * UR type: `crypto-prvkey-base`
 */

import { secureRng, randomBytes, type RngOptions } from "@blockchaincommons/rand";
import { type Cbor, type Tag, cbor, expectBytes, type ToCbor } from "@blockchaincommons/dcbor";
import { taggedCborOf, type ComponentCodec, defineCodec } from "./codable.js";
import { type UR, type ToUR, urFor } from "@blockchaincommons/uniform-resources";
import { TAG_PRIVATE_KEY_BASE } from "@blockchaincommons/tags";
import { hkdfSha256 } from "@blockchaincommons/crypto";

import { X25519PrivateKey } from "./x25519/x25519-private-key.js";
import { Ed25519PrivateKey } from "./ed25519/ed25519-private-key.js";
import { ECPrivateKey } from "./ec-key/ec-private-key.js";
import { SigningPrivateKey } from "./signing/signing-private-key.js";
import { EncapsulationPrivateKey } from "./encapsulation/encapsulation-private-key.js";
import { PrivateKeys } from "./private-keys.js";
import type { PublicKeys } from "./public-keys.js";
import type { Decrypter } from "./encrypter.js";
import type { SymmetricKey } from "./symmetric/symmetric-key.js";
import type { EncapsulationCiphertext } from "./encapsulation/encapsulation-ciphertext.js";
import { HKDFRng } from "./hkdf-rng.js";
import { SSHPrivateKey, type SshPrivateKeyData } from "./ssh/ssh-private-key.js";
import {
  sshAlgorithmName,
  sshEcdsaPointLen,
  sshEcdsaScalarLen,
  validateSshAlgorithm,
  type SshAlgorithm,
} from "./ssh/ssh-algorithm.js";
import { generateDsaKeypair } from "./ssh/internal/dsa-keygen.js";
import { generateP521Keypair } from "./ssh/internal/p521-keygen.js";
import { generateRsaKeypair } from "./ssh/internal/rsa-keygen.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { p256, p384 } from "@noble/curves/nist.js";
import { ComponentsError } from "./error.js";
import { Reference } from "./reference.js";
import { Digest } from "./digest.js";

/** Default size of PrivateKeyBase key material in bytes (used for random generation) */
const PRIVATE_KEY_BASE_DEFAULT_SIZE = 32;

/** Key derivation salt string - must match the reference implementation's bc-crypto derive functions */
const SALT_SIGNING = "signing";

// The codec is built on first use so that an unused class tree-shakes away.
let PRIVATE_KEY_BASE_CODEC: ComponentCodec<PrivateKeyBase> | undefined;

/**
 * PrivateKeyBase - Root cryptographic material for deterministic key derivation.
 *
 * This is the foundation from which signing keys and agreement keys can be
 * deterministically derived using HKDF.
 */
export class PrivateKeyBase implements ToCbor, ToUR, Decrypter {
  private readonly _data: Uint8Array;

  private constructor(data: Uint8Array) {
    this._data = new Uint8Array(data);
  }

  // ============================================================================
  // Static Factory Methods
  // ============================================================================

  /** A fresh random value; pass `rng` to make it deterministic. */
  static random({ rng = secureRng() }: RngOptions = {}): PrivateKeyBase {
    const data = randomBytes(PRIVATE_KEY_BASE_DEFAULT_SIZE, { rng: rng });
    return new PrivateKeyBase(data);
  }

  /**
   * Create a PrivateKeyBase from raw bytes.
   *
   * @param data - 32 bytes of key material
   */
  static from(data: Uint8Array): PrivateKeyBase {
    return new PrivateKeyBase(data);
  }

  // ============================================================================
  // Instance Methods
  // ============================================================================

  /** The bytes (a view; do not mutate). */
  get bytes(): Uint8Array {
    return new Uint8Array(this._data);
  }

  // ============================================================================
  // Key Derivation Methods
  // ============================================================================

  /**
   * Derive an Ed25519 signing private key.
   *
   * Uses HKDF with salt "signing", as the reference implementation does's derive_signing_private_key().
   */
  ed25519SigningPrivateKey(): SigningPrivateKey {
    const derivedKey = this._deriveKey(SALT_SIGNING);
    const ed25519Key = Ed25519PrivateKey.from(derivedKey);
    return SigningPrivateKey.fromEd25519(ed25519Key);
  }

  /**
   * Derive an X25519 agreement private key.
   *
   * Uses HKDF with salt "agreement", as the reference implementation does's derive_agreement_private_key().
   */
  x25519PrivateKey(): X25519PrivateKey {
    return X25519PrivateKey.deriveFromKeyMaterial(this._data);
  }

  /**
   * Get EncapsulationPrivateKey for decryption.
   *
   * Returns the derived X25519 private key wrapped as EncapsulationPrivateKey.
   */
  encapsulationPrivateKey(): EncapsulationPrivateKey {
    return EncapsulationPrivateKey.fromX25519PrivateKey(this.x25519PrivateKey());
  }

  /**
   * Decapsulate a shared secret from a ciphertext.
   *
   * Implements the `Decrypter` interface so a `PrivateKeyBase` can be used
   * directly as a recipient key,.
   */
  decapsulateSharedSecret(ciphertext: EncapsulationCiphertext): SymmetricKey {
    return this.encapsulationPrivateKey().decapsulateSharedSecret(ciphertext);
  }

  /**
   * Derive a PrivateKeys container with Ed25519 signing and X25519 agreement keys.
   *
   * @returns PrivateKeys containing the derived signing and encapsulation keys
   */
  ed25519PrivateKeys(): PrivateKeys {
    return PrivateKeys.from({
      signing: this.ed25519SigningPrivateKey(),
      encapsulation: this.encapsulationPrivateKey(),
    });
  }

  /**
   * Derive a PublicKeys container from the derived keys.
   *
   * @returns PublicKeys containing the derived public keys
   */
  ed25519PublicKeys(): PublicKeys {
    const privateKeys = this.ed25519PrivateKeys();
    return privateKeys.publicKeys();
  }

  /**
   * Derive a Schnorr signing private key.
   *
   * Uses ECPrivateKey.deriveFromKeyMaterial() as the reference implementation does's
   * PrivateKeyBase::schnorr_signing_private_key().
   */
  schnorrSigningPrivateKey(): SigningPrivateKey {
    const ecKey = ECPrivateKey.deriveFromKeyMaterial(this._data);
    return SigningPrivateKey.fromSchnorr(ecKey);
  }

  /**
   * Derive a PrivateKeys container with Schnorr signing and X25519 agreement keys.
   *
   */
  schnorrPrivateKeys(): PrivateKeys {
    return PrivateKeys.from({
      signing: this.schnorrSigningPrivateKey(),
      encapsulation: this.encapsulationPrivateKey(),
    });
  }

  /**
   * Derive a PublicKeys container from Schnorr derived keys.
   */
  schnorrPublicKeys(): PublicKeys {
    return this.schnorrPrivateKeys().publicKeys();
  }

  /**
   * Derive an ECDSA signing private key.
   *
   * Uses ECPrivateKey.deriveFromKeyMaterial() as the reference implementation does's
   * PrivateKeyBase::ecdsa_signing_private_key().
   */
  ecdsaSigningPrivateKey(): SigningPrivateKey {
    const ecKey = ECPrivateKey.deriveFromKeyMaterial(this._data);
    return SigningPrivateKey.fromEcdsa(ecKey);
  }

  /**
   * Derive a PrivateKeys container with ECDSA signing and X25519 agreement keys.
   *
   */
  ecdsaPrivateKeys(): PrivateKeys {
    return PrivateKeys.from({
      signing: this.ecdsaSigningPrivateKey(),
      encapsulation: this.encapsulationPrivateKey(),
    });
  }

  /**
   * Derive a PublicKeys container from ECDSA derived keys.
   */
  ecdsaPublicKeys(): PublicKeys {
    return this.ecdsaPrivateKeys().publicKeys();
  }

  /**
   * Derive an SSH `SigningPrivateKey` from this `PrivateKeyBase`.
   *
   * Builds an `HKDFRng` seeded by `this._data` with salt
   * `sshAlgorithmName(algorithm)` (the wire name, as the reference's
   * `HKDFRng::new(seed, algorithm.as_str())`), then dispatches to the
   * matching `ssh-key` 0.6.7 `*Keypair::random` constructor, ported so the
   * RNG is consumed identically and the key is byte-for-byte the reference's:
   *   - Ed25519 (`ssh-ed25519`): `Ed25519Keypair::random` — 32 seed bytes.
   *   - DSA (`ssh-dss`): `DsaKeypair::random` — the `dsa` crate's
   *     FIPS 186-4 1024/160 parameter search (`generateDsaKeypair`).
   *   - RSA (`ssh-rsa`): `RsaKeypair::random(rng, 2048)` — the `rsa`
   *     crate's two-prime generation with e = 65537 (`generateRsaKeypair`).
   *   - ECDSA P-256 / P-384 / P-521: `p{256,384,521}::SecretKey::random`
   *     rejection sampling over the field-sized byte string.
   *
   * `algorithm` is validated before any bytes are drawn: an unknown kind or
   * curve is `InvalidData`.
   *
   * @param algorithm - The SSH key algorithm to derive
   * @param comment   - Optional comment carried through the OpenSSH PEM
   */
  sshSigningPrivateKey(algorithm: SshAlgorithm, comment = ""): SigningPrivateKey {
    const algo = validateSshAlgorithm(algorithm);
    const rng = new HKDFRng(this._data, sshAlgorithmName(algo));
    let data: SshPrivateKeyData;
    switch (algo.kind) {
      case "ed25519": {
        // Mirror `ssh-key` 0.6.7 `Ed25519PrivateKey::random`:
        // `rng.fill_bytes(&mut [0u8; 32])`. The 32 bytes are the seed.
        const seed = randomBytes(32, { rng: rng });
        const pubBytes = ed25519.getPublicKey(seed);
        data = { kind: "ed25519", seed, pubBytes: new Uint8Array(pubBytes) };
        break;
      }
      case "ecdsa": {
        if (algo.curve === "nistp521") {
          const { scalar, point } = generateP521Keypair(rng);
          data = { kind: "ecdsa", curve: algo.curve, point, scalar };
          break;
        }
        const scalarLen = sshEcdsaScalarLen(algo.curve);
        const pointLen = sshEcdsaPointLen(algo.curve);
        const curve = algo.curve === "nistp256" ? p256 : p384;
        // Mirror `p{256,384}::SecretKey::random` rejection sampling:
        // read `scalarLen` bytes; if the big-endian scalar is zero or
        // ≥ n, retry. We delegate the bounds check to noble's
        // `utils.isValidSecretKey` which performs exactly the same
        // `0 < scalar < n` predicate as the reference.
        let scalar: Uint8Array;
        for (;;) {
          const bytes = randomBytes(scalarLen, { rng: rng });
          if (curve.utils.isValidSecretKey(bytes)) {
            scalar = bytes;
            break;
          }
        }
        const point = curve.getPublicKey(scalar, false);
        if (point.length !== pointLen || point[0] !== 0x04) {
          throw ComponentsError.invalidData(
            `sshSigningPrivateKey ecdsa-${algo.curve}: noble returned non-uncompressed point`,
          );
        }
        data = {
          kind: "ecdsa",
          curve: algo.curve,
          point: new Uint8Array(point),
          scalar,
        };
        break;
      }
      case "dsa":
        data = { kind: "dsa", ...generateDsaKeypair(rng) };
        break;
      case "rsa":
        data = { kind: "rsa", ...generateRsaKeypair(rng, 2048) };
        break;
    }
    const checkint = sshCheckintFromPrivateBytes(data);
    const sshKey = SSHPrivateKey.fromParts(data, comment, checkint);
    return SigningPrivateKey.fromSsh(sshKey);
  }

  /**
   * Derive a `PrivateKeys` container with an SSH signing key and an X25519
   * agreement key.
   */
  sshPrivateKeys(algorithm: SshAlgorithm, comment = ""): PrivateKeys {
    return PrivateKeys.from({
      signing: this.sshSigningPrivateKey(algorithm, comment),
      encapsulation: this.encapsulationPrivateKey(),
    });
  }

  /**
   * Derive a `PublicKeys` container from `sshPrivateKeys`. Mirrors the reference's
   * `PrivateKeyBase::ssh_public_keys`
   */
  sshPublicKeys(algorithm: SshAlgorithm, comment = ""): PublicKeys {
    return this.sshPrivateKeys(algorithm, comment).publicKeys();
  }

  /**
   * Internal key derivation using HKDF-SHA256.
   */
  private _deriveKey(salt: string): Uint8Array {
    return hkdfSha256(this._data, new TextEncoder().encode(salt), { dkLen: 32 });
  }

  // ============================================================================
  // Equality and String Representation
  // ============================================================================

  /**
   * Compare with another PrivateKeyBase.
   */
  equals(other: PrivateKeyBase): boolean {
    if (this._data.length !== other._data.length) return false;
    for (let i = 0; i < this._data.length; i++) {
      if (this._data[i] !== other._data[i]) return false;
    }
    return true;
  }

  /**
   * Get string representation (truncated for security).
   */
  /** The reference: the digest of the tagged CBOR, as the reference computes it. */
  reference(): Reference {
    return Reference.fromDigest(Digest.fromImage(this.toCbor().toData()));
  }

  /** The first four bytes of `reference()` in hex, the reference's `ref_hex_short`. */
  refHexShort(): string {
    return this.reference().refHexShort();
  }

  /** The reference's `Display`: the type name over the short reference. */
  toString(): string {
    return `PrivateKeyBase(${this.refHexShort()})`;
  }

  // ============================================================================
  // CBOR Serialization (ToCbor)
  // ============================================================================

  /** Tagged-CBOR codec; `decode` also accepts the untagged form. */
  static get codec(): ComponentCodec<PrivateKeyBase> {
    return (PRIVATE_KEY_BASE_CODEC ??= defineCodec({
      tags: [TAG_PRIVATE_KEY_BASE],
      decodeUntagged: (cborValue) => {
        const data = expectBytes(cborValue);
        return PrivateKeyBase.from(data);
      },
      encodeUntagged: (value) => value.untaggedCbor(),
    }));
  }

  /** The CBOR tags this type decodes from; the first one is used to encode. */
  cborTags(): Tag[] {
    return [...PrivateKeyBase.codec.tags];
  }

  /**
   * Returns the untagged CBOR encoding.
   */
  untaggedCbor(): Cbor {
    return cbor(this._data);
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
  static fromCbor(cborValue: Cbor): PrivateKeyBase {
    return PrivateKeyBase.codec.decode(cborValue);
  }

  // ============================================================================
  // CBOR Deserialization (CborTaggedDecodable)
  // ============================================================================

  // ============================================================================
  // UR Serialization (ToUR)
  // ============================================================================
}

/**
 * Mirror of `ssh-key` 0.6.7 `KeypairData::checkint`
 * (`ssh-key/src/private/keypair.rs`): XOR successive 4-byte big-endian
 * chunks of the algorithm-specific private bytes, where those bytes are:
 *
 *   - Ed25519 → the 32-byte seed (`Ed25519PrivateKey::as_ref`)
 *   - ECDSA   → the fixed-width scalar (`EcdsaKeypair::private_key_bytes`,
 *               32 / 48 / 66 bytes, no sign byte)
 *   - DSA     → `DsaPrivateKey::as_bytes`, the `Mpint` encoding of x
 *   - RSA     → `RsaPrivateKey.d.as_bytes()`, the `Mpint` encoding of d
 *
 * An `Mpint`'s bytes carry a leading 0x00 when the top bit of the value
 * is set, so for DSA and RSA the XOR runs over the sign-padded form. The
 * `chunks_exact(4)` rule discards any trailing bytes whose count is not a
 * multiple of 4 — match it here.
 */
function sshCheckintFromPrivateBytes(data: SshPrivateKeyData): number {
  let bytes: Uint8Array;
  switch (data.kind) {
    case "ed25519":
      bytes = data.seed;
      break;
    case "ecdsa":
      bytes = data.scalar;
      break;
    case "dsa":
      bytes = mpintBytes(data.x);
      break;
    case "rsa":
      bytes = mpintBytes(data.d);
      break;
  }
  let n = 0;
  const fullChunks = Math.floor(bytes.length / 4);
  for (let i = 0; i < fullChunks; i++) {
    const off = i * 4;
    const chunk =
      ((bytes[off] << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3]) >>> 0;
    n = (n ^ chunk) >>> 0;
  }
  return n;
}

/**
 * `Mpint::from_positive_bytes` on canonical positive bytes: a 0x00 is
 * prefixed when the top bit is set so the value does not read as negative.
 */
function mpintBytes(canonical: Uint8Array): Uint8Array {
  if (canonical.length > 0 && (canonical[0] & 0x80) !== 0) {
    const out = new Uint8Array(canonical.length + 1);
    out.set(canonical, 1);
    return out;
  }
  return canonical;
}
