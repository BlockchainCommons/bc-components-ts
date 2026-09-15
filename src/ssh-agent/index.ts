/**
 * The SSH agent interface a key derivation uses, and an in-memory agent.
 * The Node transport to a real agent is the `ssh-agent-node` subpath.
 */

export type { SshAgent } from "./ssh-agent.js";
export { MemorySshAgent } from "./memory-ssh-agent.js";
