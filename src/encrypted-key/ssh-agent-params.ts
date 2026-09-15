/**
 * SSH Agent key derivation parameters
 *
 * SSH Agent uses an SSH agent daemon for key derivation. The agent signs
 * the salt with one of its Ed25519 identities, and the signature is the key
 * material the content key's encryption key is derived from.
 *
 * CDDL:
 * ```cddl
 * SSHAgentParams = [4, Salt, id: tstr]
 * ```
 */

import {
  type Cbor,
  cbor,
  expectArray,
  expectText,
  expectUnsigned,
  CborError,
} from "@blockchaincommons/dcbor";
import { hkdfSha256 } from "@blockchaincommons/crypto";

import { Salt } from "../salt.js";
import { Nonce } from "../nonce.js";
import { SymmetricKey } from "../symmetric/symmetric-key.js";
import type { EncryptedMessage } from "../symmetric/encrypted-message.js";
import type { SSHPublicKey } from "../ssh/ssh-public-key.js";
import type { SshAgent } from "../ssh-agent/ssh-agent.js";
import { KeyDerivationMethod } from "./key-derivation-method.js";
import type { KeyDerivation } from "./key-derivation.js";
import { ComponentsError } from "../error.js";
import { decodeWith } from "../codable.js";
import { messageOf, USIZE_FIELD } from "../domain.js";

/** Default salt length for SSH agent key derivation */
export const SALT_LEN = 16;

/** The options of an agent-backed lock. */
export interface SshAgentLockOptions {
  /** The agent that signs the salt. */
  agent: SshAgent;
  /** The nonce to encrypt with; a random one unless given. */
  nonce?: Nonce;
}

/** The options of an agent-backed unlock. */
export interface SshAgentUnlockOptions {
  /** The agent that signs the salt. */
  agent: SshAgent;
}

const NEEDS_AGENT =
  "SSH agent key derivation needs an agent; use lockWithAgent and unlockWithAgent with an SshAgent";

/**
 * SSH Agent parameters for key derivation.
 *
 * This method uses an SSH agent to derive encryption keys: the agent signs
 * the salt with the Ed25519 identity `id` names (by comment), and the key
 * is HKDF-SHA256 of that signature with the salt. The agent is passed to
 * `lock` and `unlock` as an `SshAgent`: `MemorySshAgent` holds keys in
 * memory, and the `ssh-agent-node` subpath connects to the agent
 * `$SSH_AUTH_SOCK` names. Without an agent the synchronous `lock` and
 * `unlock` of `KeyDerivation` throw `SshAgent`, where the reference would
 * connect to `$SSH_AUTH_SOCK` itself.
 *
 * The CBOR encoding of `SSHAgentParams` is byte-identical to the reference's,
 * so a payload produced by either implementation is read by the other.
 */
export class SSHAgentParams implements KeyDerivation {
  /** The method discriminant that opens the SSH-agent parameter array on the wire. */
  static readonly INDEX: KeyDerivationMethod = KeyDerivationMethod.SSHAgent;

  private readonly _salt: Salt;
  private _id: string;

  private constructor(salt: Salt, id: string) {
    this._salt = salt;
    this._id = id;
  }

  /** Parameters with a fresh random salt unless one is given, and an empty id unless one is given. */
  static from({
    id = "",
    salt = Salt.random({ length: SALT_LEN }),
  }: {
    id?: string;
    salt?: Salt;
  } = {}): SSHAgentParams {
    return new SSHAgentParams(salt, id);
  }

  /** Returns the salt. */
  get salt(): Salt {
    return this._salt;
  }

  /** Returns the SSH key identity: the comment of the agent identity; `lock` sets it from the secret. */
  get id(): string {
    return this._id;
  }

  /** Returns the method index for CBOR encoding. */
  index(): number {
    return SSHAgentParams.INDEX;
  }

  /**
   * Derive a key with an SSH agent and encrypt the content key, the
   * reference's `lock`.
   *
   * Without `options` there is no agent to ask, and the call throws
   * `SshAgent`. With `options.agent`:
   *
   * 1. `secret` is the id: the comment of the identity to use, as UTF-8
   *    (`SSH Agent secret must be a valid UTF-8 string` otherwise).
   * 2. The agent's identities are listed and reduced to the Ed25519 ones
   *    (`No Ed25519 identities available in SSH agent` when there is none).
   * 3. An empty id takes the only identity (`Multiple identities available
   *    in SSH agent, but no ID provided` when there are several); a
   *    non-empty id takes the identity with that comment (`No matching
   *    identity found`).
   * 4. The agent signs the salt (`SSH agent refused to sign` on any failure).
   * 5. The encryption key is HKDF-SHA256 of the signature with the salt.
   * 6. `id` is stored in these parameters, which are then the additional
   *    authenticated data; the content key is encrypted with
   *    `options.nonce` or a random nonce.
   *
   * @throws `SshAgent` as listed above.
   */
  lock(contentKey: SymmetricKey, secret: Uint8Array): EncryptedMessage;
  lock(
    contentKey: SymmetricKey,
    secret: Uint8Array,
    options: SshAgentLockOptions,
  ): Promise<EncryptedMessage>;
  lock(
    contentKey: SymmetricKey,
    secret: Uint8Array,
    options?: SshAgentLockOptions,
  ): EncryptedMessage | Promise<EncryptedMessage> {
    if (options === undefined) throw ComponentsError.sshAgent(NEEDS_AGENT);
    return this._lockWithAgent(contentKey, secret, options);
  }

  /**
   * Derive a key with an SSH agent and decrypt the content key, the
   * reference's `unlock`.
   *
   * Without `options` there is no agent to ask, and the call throws
   * `SshAgent`. With `options.agent` the identity is chosen, among the
   * agent's Ed25519 identities, by the first of these that applies: the
   * secret's id when non-empty, the stored `id` when non-empty (each by
   * comment, `No matching identity found` otherwise), else the first
   * identity. The agent signs the stored salt, the key is derived as in
   * `lock`, and the message is decrypted.
   *
   * @throws `SshAgent` for the secret, identity and signing failures of
   * `lock`; `Crypto` `Failed to decrypt the encrypted key: <reason>` when
   * the message does not decrypt (a wrong identity, tampered data), and
   * `Crypto` `Failed to convert decrypted key to SymmetricKey: <reason>`
   * when the plaintext is not a symmetric key.
   */
  unlock(encryptedMessage: EncryptedMessage, secret: Uint8Array): SymmetricKey;
  unlock(
    encryptedMessage: EncryptedMessage,
    secret: Uint8Array,
    options: SshAgentUnlockOptions,
  ): Promise<SymmetricKey>;
  unlock(
    encryptedMessage: EncryptedMessage,
    secret: Uint8Array,
    options?: SshAgentUnlockOptions,
  ): SymmetricKey | Promise<SymmetricKey> {
    if (options === undefined) throw ComponentsError.sshAgent(NEEDS_AGENT);
    return this._unlockWithAgent(encryptedMessage, secret, options);
  }

  private async _lockWithAgent(
    contentKey: SymmetricKey,
    secret: Uint8Array,
    { agent, nonce = Nonce.random() }: SshAgentLockOptions,
  ): Promise<EncryptedMessage> {
    // Convert `secret` to a string for the SSH ID.
    const id = idFromSecret(secret);

    // List all identities in the SSH agent, keeping the Ed25519 ones.
    const ids = ed25519Identities(await agent.listIdentities());

    // If `id` is empty, use the first available identity, otherwise find
    // the one matching `id`.
    let identity: SSHPublicKey;
    if (id.length === 0) {
      // If there is more than one identity, throw an error.
      if (ids.length > 1) {
        throw ComponentsError.sshAgent(
          "Multiple identities available in SSH agent, but no ID provided",
        );
      }
      identity = ids[0];
    } else {
      identity = identityWithComment(ids, id);
    }

    // Sign the salt with the identity, and derive the symmetric key from
    // the signature using HKDF with HMAC-SHA256.
    const salt = this._salt.bytes;
    const derivedKey = deriveKey(await signSalt(agent, identity, salt), salt);

    // Set the ID in the parameters.
    this._id = id;

    // Encrypt the content key with the derived key, using the encoded
    // method as additional authenticated data.
    return derivedKey.encrypt(contentKey.bytes, { aad: this.toCborData(), nonce });
  }

  private async _unlockWithAgent(
    encryptedMessage: EncryptedMessage,
    secret: Uint8Array,
    { agent }: SshAgentUnlockOptions,
  ): Promise<SymmetricKey> {
    // Convert `secret` to a string for the SSH ID.
    const id = idFromSecret(secret);

    // List all identities in the SSH agent, keeping the Ed25519 ones.
    const ids = ed25519Identities(await agent.listIdentities());

    // id priority:
    // 1. `id` passed in as secret if not empty,
    // 2. `this.id` if not empty,
    // 3. first available identity.
    let identity: SSHPublicKey;
    if (id.length > 0) {
      identity = identityWithComment(ids, id);
    } else if (this._id.length > 0) {
      identity = identityWithComment(ids, this._id);
    } else {
      identity = ids[0];
    }

    // Sign the salt with the identity, and derive the symmetric key from
    // the signature using HKDF with HMAC-SHA256.
    const salt = this._salt.bytes;
    const derivedKey = deriveKey(await signSalt(agent, identity, salt), salt);

    // Decrypt the encrypted key with the derived key.
    let decryptedKey: Uint8Array;
    try {
      decryptedKey = derivedKey.decrypt(encryptedMessage);
    } catch (e) {
      throw ComponentsError.crypto(`Failed to decrypt the encrypted key: ${messageOf(e)}`, e);
    }

    try {
      return SymmetricKey.from(decryptedKey);
    } catch (e) {
      throw ComponentsError.crypto(
        `Failed to convert decrypted key to SymmetricKey: ${messageOf(e)}`,
        e,
      );
    }
  }

  /**
   * Get string representation.
   */
  toString(): string {
    return `SSHAgent("${this._id}")`;
  }

  /**
   * Check equality with another SSHAgentParams.
   */
  equals(other: SSHAgentParams): boolean {
    return this._salt.equals(other._salt) && this._id === other._id;
  }

  // ============================================================================
  // CBOR Serialization
  // ============================================================================

  /**
   * Convert to CBOR.
   * Format: [4, Salt, id: tstr]   (Salt is encoded as a tagged value — `#6.40018(bytes)`)
   */
  toCbor(): Cbor {
    return cbor([cbor(SSHAgentParams.INDEX), this._salt.toCbor(), cbor(this._id)]);
  }

  /**
   * Convert to CBOR binary data.
   */
  toCborData(): Uint8Array {
    return this.toCbor().toData();
  }

  /**
   * Parse from CBOR.
   */
  /**
   * From the CBOR array, as the reference's `TryFrom<CBOR>` (a dcbor error):
   * every failure is `Cbor` with the bare message. The index element is
   * read as a `usize` (with dcbor's negative wrap) and its value ignored;
   * the fixed-width fields wrap the same way.
   */
  static fromCbor(cborValue: Cbor): SSHAgentParams {
    return decodeWith(() => {
      const array = expectArray(cborValue);
      if (array.length !== 3) throw CborError.custom("Invalid SSHAgentParams");
      expectUnsigned(array[0], USIZE_FIELD);
      const salt = Salt.fromCbor(array[1]);
      const id = expectText(array[2]);
      return new SSHAgentParams(salt, id);
    });
  }
}

/** The secret as the id string: it must be UTF-8 (a leading BOM is kept, as `String::from_utf8` keeps it). */
function idFromSecret(secret: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(secret);
  } catch {
    throw ComponentsError.sshAgent("SSH Agent secret must be a valid UTF-8 string");
  }
}

/** The Ed25519 identities among `identities`; there must be at least one. */
function ed25519Identities(identities: readonly SSHPublicKey[]): SSHPublicKey[] {
  const ids = identities.filter((k) => k.algorithm.kind === "ed25519");
  if (ids.length === 0) {
    throw ComponentsError.sshAgent("No Ed25519 identities available in SSH agent");
  }
  return ids;
}

/** The identity whose comment is `id`. */
function identityWithComment(identities: readonly SSHPublicKey[], id: string): SSHPublicKey {
  const identity = identities.find((k) => k.comment === id);
  if (identity === undefined) throw ComponentsError.sshAgent("No matching identity found");
  return identity;
}

/** The agent's raw signature over `salt`; any failure is `SSH agent refused to sign`. */
async function signSalt(
  agent: SshAgent,
  identity: SSHPublicKey,
  salt: Uint8Array,
): Promise<Uint8Array> {
  try {
    return await agent.sign(identity, salt);
  } catch (e) {
    throw ComponentsError.sshAgent("SSH agent refused to sign", e);
  }
}

/** HKDF-SHA256 of the signature with the salt, as a symmetric key. */
function deriveKey(signature: Uint8Array, salt: Uint8Array): SymmetricKey {
  return SymmetricKey.from(hkdfSha256(signature, salt, { dkLen: SymmetricKey.SYMMETRIC_KEY_SIZE }));
}
