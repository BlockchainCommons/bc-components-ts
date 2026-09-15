/**
 * The SSH agent an SSH-agent key derivation talks to.
 *
 * The reference's `SSHAgent` trait, reduced to what a lock or unlock needs
 * and made asynchronous: listing the agent's identities and asking it to
 * sign. Managing the agent's identities is left to each implementation
 * (`MemorySshAgent` has `addIdentity` and friends; a real agent is managed
 * with `ssh-add`).
 *
 * @module ssh-agent
 */

import type { SSHPublicKey } from "../ssh/ssh-public-key.js";

/**
 * What a key-derivation lock/unlock needs from an SSH agent (the reference's
 * `SSHAgent` trait, asynchronous here).
 *
 * An implementation reports its own failures as a `ComponentsError`; a
 * failure to sign is reported by the caller as `SSH agent refused to sign`
 * whatever the implementation threw.
 */
export interface SshAgent {
  /** The public keys the agent holds, each with its comment. */
  listIdentities(): Promise<readonly SSHPublicKey[]>;
  /** The raw signature bytes (for Ed25519 the 64-byte signature) over `data`. */
  sign(identity: SSHPublicKey, data: Uint8Array): Promise<Uint8Array>;
}
