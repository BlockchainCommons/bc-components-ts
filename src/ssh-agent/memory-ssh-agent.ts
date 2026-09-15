/**
 * An SSH agent held in memory, for tests and for environments without a
 * real agent.
 *
 * @module ssh-agent
 */

import type { SSHPrivateKey } from "../ssh/ssh-private-key.js";
import type { SSHPublicKey } from "../ssh/ssh-public-key.js";
import { ComponentsError } from "../error.js";
import type { SshAgent } from "./ssh-agent.js";

/** The `sshsig` namespace the in-memory agent signs in, as the reference's mock. */
const NAMESPACE = "test_namespace";

/**
 * An `SshAgent` whose identities are private keys held in memory, the
 * analogue of the reference's test `MockSSHAgent`.
 *
 * Identities are keyed by comment: adding a key whose comment is already
 * present replaces that identity in place. `listIdentities` returns the
 * public keys in insertion order, so with an empty id a lock or unlock uses
 * the first key added.
 *
 * `sign` signs `data` the way the reference's mock does: an `sshsig`
 * signature in the namespace `test_namespace` over the SHA-256 digest of
 * `data`, of which the inner raw signature bytes are returned. A real agent
 * signs `data` itself, so a key locked with this agent cannot be unlocked
 * with a real agent holding the same key, and vice versa.
 */
export class MemorySshAgent implements SshAgent {
  private readonly _identities = new Map<string, SSHPrivateKey>();
  private readonly _refuseToSign: boolean;

  /**
   * An agent holding `identities` (none by default). With `refuseToSign`
   * every `sign` call fails, the way an agent that declines a request does.
   */
  constructor({
    identities = [],
    refuseToSign = false,
  }: { identities?: Iterable<SSHPrivateKey>; refuseToSign?: boolean } = {}) {
    this._refuseToSign = refuseToSign;
    for (const key of identities) this.addIdentity(key);
  }

  /** Adds `key` under its comment, replacing any identity with that comment. */
  addIdentity(key: SSHPrivateKey): void {
    this._identities.set(key.comment, key);
  }

  /** Removes the identity whose comment is `key`'s; nothing happens when there is none. */
  removeIdentity(key: SSHPrivateKey): void {
    this._identities.delete(key.comment);
  }

  /** Removes every identity. */
  removeAllIdentities(): void {
    this._identities.clear();
  }

  /** The public keys of the identities, in insertion order, each with its comment. */
  listIdentities(): Promise<readonly SSHPublicKey[]> {
    return settled(() => [...this._identities.values()].map((key) => key.publicKey()));
  }

  /**
   * The raw signature bytes of the `sshsig` signature (namespace
   * `test_namespace`, SHA-256) over `data` by the private key whose comment
   * is `identity`'s.
   *
   * @throws `SshAgent` `Identity not found` when no identity has that
   * comment; `SshAgent` `Refused to sign` when the agent was built with
   * `refuseToSign`.
   */
  sign(identity: SSHPublicKey, data: Uint8Array): Promise<Uint8Array> {
    return settled(() => {
      if (this._refuseToSign) throw ComponentsError.sshAgent("Refused to sign");
      const privateKey = this._identities.get(identity.comment);
      if (privateKey === undefined) throw ComponentsError.sshAgent("Identity not found");
      return privateKey.sign(NAMESPACE, "sha256", data).signatureBytes;
    });
  }
}

/** `f()` as an already-settled promise: its value, or its throw as the rejection. */
function settled<T>(f: () => T): Promise<T> {
  return new Promise((resolve) => {
    resolve(f());
  });
}
