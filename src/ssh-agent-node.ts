/**
 * A connection to the SSH agent `$SSH_AUTH_SOCK` names, over the ssh-agent
 * protocol on a `node:net` Unix socket.
 *
 * Subpath entry `@blockchaincommons/components/ssh-agent-node`: the one
 * module of this package that imports from `node:`, kept off the root and
 * `/kdf` entries so that they stay browser-safe.
 *
 * ```ts
 * import { EncryptedKey, sshAgentParams } from "@blockchaincommons/components/kdf";
 * import { connectToSshAgent } from "@blockchaincommons/components/ssh-agent-node";
 *
 * const agent = await connectToSshAgent();
 * const locked = await EncryptedKey.lockWithAgent(sshAgentParams(""), secret, contentKey, { agent });
 * const contentKey2 = await locked.unlockWithAgent(secret, { agent });
 * ```
 *
 * @module ssh-agent-node
 */

import { createConnection } from "node:net";
import process from "node:process";

import { ComponentsError } from "./error.js";
import { messageOf } from "./domain.js";
import { SSHPublicKey } from "./ssh/ssh-public-key.js";
import { SshBufferReader, SshBufferWriter } from "./ssh/internal/ssh-buffer.js";
import type { SshAgent } from "./ssh-agent/ssh-agent.js";

export type { SshAgent } from "./ssh-agent/ssh-agent.js";

// The ssh-agent protocol (draft-miller-ssh-agent), message numbers.
const SSH_AGENT_FAILURE = 5;
const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENT_IDENTITIES_ANSWER = 12;
const SSH_AGENTC_SIGN_REQUEST = 13;
const SSH_AGENT_SIGN_RESPONSE = 14;

/**
 * Connects to whatever socket `$SSH_AUTH_SOCK` points at, the reference's
 * `connect_to_ssh_agent`.
 *
 * The agent returned opens one connection per request, so it holds no
 * resource between calls and needs no closing. Identities whose key blob
 * this package cannot parse (a certificate, a security key) are left out of
 * `listIdentities`. As the reference's `SSHAgent` for its client, a failure
 * once connected is an `SshAgent` error carrying the transport's message.
 *
 * @throws `SshAgent` `SSH_AUTH_SOCK env var not set` when the variable is
 * unset; `SshAgent` `no ssh-agent reachable` when the socket cannot be
 * connected.
 */
export async function connectToSshAgent(): Promise<SshAgent> {
  const socketPath = process.env["SSH_AUTH_SOCK"];
  if (socketPath === undefined) {
    throw ComponentsError.sshAgent("SSH_AUTH_SOCK env var not set");
  }
  await probe(socketPath);
  return new SocketSshAgent(socketPath);
}

/** The agent behind a Unix socket. */
class SocketSshAgent implements SshAgent {
  constructor(private readonly socketPath: string) {}

  async listIdentities(): Promise<readonly SSHPublicKey[]> {
    const reply = await request(
      this.socketPath,
      new Uint8Array([SSH_AGENTC_REQUEST_IDENTITIES]),
      SSH_AGENT_IDENTITIES_ANSWER,
    );
    return protocol(() => {
      const count = reply.readUint32();
      const identities: SSHPublicKey[] = [];
      for (let i = 0; i < count; i++) {
        const blob = reply.readString();
        const comment = reply.readStringUtf8();
        try {
          identities.push(SSHPublicKey.fromBlob(blob, comment));
        } catch {
          // A key type this package does not parse; not usable here anyway.
        }
      }
      return identities;
    });
  }

  async sign(identity: SSHPublicKey, data: Uint8Array): Promise<Uint8Array> {
    const message = new SshBufferWriter()
      .writeByte(SSH_AGENTC_SIGN_REQUEST)
      .writeString(identity.toBlob())
      .writeString(data)
      .writeUint32(0)
      .bytes();
    const reply = await request(this.socketPath, message, SSH_AGENT_SIGN_RESPONSE);
    return protocol(() => {
      // string signature, itself `string algorithm, string raw`.
      const signature = new SshBufferReader(reply.readString());
      signature.readString();
      return new Uint8Array(signature.readString());
    });
  }
}

/** A malformed reply is an `SshAgent` error with the parser's message. */
function protocol<T>(f: () => T): T {
  try {
    return f();
  } catch (e) {
    throw ComponentsError.sshAgent(messageOf(e), e);
  }
}

/** Resolves once the socket accepts a connection; the connection is closed again. */
function probe(socketPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    let done = false;
    const settle = (f: () => void): void => {
      if (done) return;
      done = true;
      socket.destroy();
      f();
    };
    socket.on("connect", () => settle(resolve));
    socket.on("error", (e: Error) =>
      settle(() => reject(ComponentsError.sshAgent("no ssh-agent reachable", e))),
    );
  });
}

/**
 * Sends one framed `message` over a fresh connection and returns a reader
 * over the reply's payload, positioned after its type byte, which must be
 * `expectedType`.
 */
function request(
  socketPath: string,
  message: Uint8Array,
  expectedType: number,
): Promise<SshBufferReader> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    const chunks: Uint8Array[] = [];
    let received = 0;
    let done = false;
    const settle = (f: () => void): void => {
      if (done) return;
      done = true;
      socket.destroy();
      f();
    };
    const fail = (text: string, cause?: unknown): void =>
      settle(() => reject(ComponentsError.sshAgent(text, cause)));

    socket.on("connect", () => {
      socket.write(new SshBufferWriter().writeString(message).bytes());
    });
    socket.on("data", (chunk: Uint8Array) => {
      chunks.push(chunk);
      received += chunk.length;
      if (received < 4) return;
      const all = concat(chunks, received);
      const length = new SshBufferReader(all).readUint32();
      if (received < 4 + length) return;
      const payload = all.subarray(4, 4 + length);
      if (payload.length === 0) {
        fail("empty reply from the agent");
        return;
      }
      const type = payload[0];
      if (type === SSH_AGENT_FAILURE) {
        fail("the agent returned SSH_AGENT_FAILURE");
        return;
      }
      if (type !== expectedType) {
        fail(`unexpected reply type ${String(type)} from the agent (expected ${expectedType})`);
        return;
      }
      settle(() => resolve(new SshBufferReader(payload.subarray(1))));
    });
    socket.on("error", (e: Error) => fail(e.message, e));
    socket.on("close", () => fail("connection closed before the agent replied"));
  });
}

function concat(chunks: readonly Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}
