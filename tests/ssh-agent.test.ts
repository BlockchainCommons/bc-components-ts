/**
 * SSH-agent key derivation: `SSHAgentParams.lock`/`unlock` with an
 * `SshAgent`, `MemorySshAgent`, `EncryptedKey.lockWithAgent`/
 * `unlockWithAgent`, and the Node transport `connectToSshAgent`.
 *
 * The lock/unlock steps and their error texts are the reference's
 * `impl KeyDerivation for SSHAgentParams`; `MemorySshAgent` is its test
 * `MockSSHAgent`, which signs as `sshsig` in `test_namespace` rather than
 * raw as a real agent does. `tests/fixtures/ssh-agent/vectors.json` pins,
 * for one key and salt, that signature, the key HKDF derives from it, and a
 * lock with a fixed nonce; the values were produced by this package.
 *
 * The real-agent tests run only when `ssh-agent`, `ssh-add` and
 * `ssh-keygen` are on the PATH; they start a private agent on a temporary
 * socket and stop it afterwards.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";
import process from "node:process";
import { decodeCbor } from "@blockchaincommons/dcbor";
import { hkdfSha256 } from "@blockchaincommons/crypto";
import { ed25519 } from "@noble/curves/ed25519.js";

// The reference needs `register_tags()` before a UR is made; so does this package.
import { registerTags } from "../src/tags.js";
registerTags();

import { ComponentsError, type ComponentsErrorCode } from "../src/error.js";
import { PrivateKeyBase } from "../src/private-key-base.js";
import { Salt } from "../src/salt.js";
import { Nonce } from "../src/nonce.js";
import { SymmetricKey } from "../src/symmetric/symmetric-key.js";
import { EncryptedMessage } from "../src/symmetric/encrypted-message.js";
import { SSHPrivateKey } from "../src/ssh/ssh-private-key.js";
import { SSHSignature } from "../src/ssh/ssh-signature.js";
import type { SshAlgorithm } from "../src/ssh/ssh-algorithm.js";
import { bytesToHex, hexToBytes } from "../src/utils.js";
import {
  EncryptedKey,
  SSHAgentParams,
  sshAgentParams,
  hkdfParams,
  MemorySshAgent,
  type SshAgent,
} from "../src/kdf.js";
import { connectToSshAgent } from "../src/ssh-agent-node.js";

interface Vectors {
  seedHex: string;
  comment: string;
  publicKeyOpenssh: string;
  privateKeyOpenssh: string;
  saltHex: string;
  signatureHex: string;
  derivedKeyHex: string;
  contentKeyHex: string;
  nonceHex: string;
  aadCborHex: string;
  encryptedKeyString: string;
  encryptedKeyCborHex: string;
}

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(join(here, "fixtures", "ssh-agent", "vectors.json"), "utf8"),
) as Vectors;

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

/** A deterministic SSH key: `PrivateKeyBase.from(seed).sshSigningPrivateKey`. */
function sshKey(
  seedByte: number,
  comment: string,
  algorithm: SshAlgorithm = { kind: "ed25519" },
): SSHPrivateKey {
  const key = PrivateKeyBase.from(new Uint8Array(32).fill(seedByte))
    .sshSigningPrivateKey(algorithm, comment)
    .asSsh();
  if (key === undefined) throw new Error("not an SSH key");
  return key;
}

async function rejection(promise: Promise<unknown>): Promise<ComponentsError> {
  try {
    await promise;
  } catch (e) {
    if (ComponentsError.isComponentsError(e)) return e;
    throw e;
  }
  throw new Error("expected a rejection");
}

function expectError(e: ComponentsError, code: ComponentsErrorCode, message: string): void {
  expect(e.code).toBe(code);
  expect(e.message).toBe(message);
}

const NEEDS_AGENT =
  "SSH agent error: SSH agent key derivation needs an agent; use lockWithAgent and unlockWithAgent with an SshAgent";
const DECRYPT_FAILED =
  "cryptographic operation failed: Failed to decrypt the encrypted key: cryptographic operation failed: AEAD error";

const alice = sshKey(1, "alice@example.com");
const bob = sshKey(2, "bob@example.com");
const p256 = sshKey(3, "p256@example.com", { kind: "ecdsa", curve: "nistp256" });

describe("MemorySshAgent", () => {
  it("lists the identities' public keys, with comments, in insertion order", async () => {
    const agent = new MemorySshAgent();
    expect(await agent.listIdentities()).toEqual([]);
    agent.addIdentity(bob);
    agent.addIdentity(alice);
    const ids = await agent.listIdentities();
    expect(ids.map((k) => k.comment)).toEqual(["bob@example.com", "alice@example.com"]);
    expect(ids[0].equals(bob.publicKey())).toBe(true);
    expect(ids[1].equals(alice.publicKey())).toBe(true);
  });

  it("keys identities by comment: a re-added comment replaces in place", async () => {
    const agent = new MemorySshAgent({ identities: [alice, bob] });
    const alice2 = sshKey(9, "alice@example.com");
    agent.addIdentity(alice2);
    const ids = await agent.listIdentities();
    expect(ids).toHaveLength(2);
    expect(ids[0].equals(alice2.publicKey())).toBe(true);
    expect(ids[0].equals(alice.publicKey())).toBe(false);
  });

  it("removes one identity or all", async () => {
    const agent = new MemorySshAgent({ identities: [alice, bob] });
    agent.removeIdentity(alice);
    expect((await agent.listIdentities()).map((k) => k.comment)).toEqual(["bob@example.com"]);
    agent.removeIdentity(alice);
    expect(await agent.listIdentities()).toHaveLength(1);
    agent.removeAllIdentities();
    expect(await agent.listIdentities()).toEqual([]);
  });

  it("signs as the reference's mock: sshsig in test_namespace over SHA-256, the raw bytes", async () => {
    const agent = new MemorySshAgent({ identities: [alice] });
    const data = utf8("test data");
    const sig1 = await agent.sign(alice.publicKey(), data);
    const sig2 = await agent.sign(alice.publicKey(), data);
    expect(sig1).toHaveLength(64);
    expect(sig1).toEqual(sig2);
    expect(sig1).toEqual(alice.sign("test_namespace", "sha256", data).signatureBytes);
    const sshsig = SSHSignature.fromParts(alice.publicKey(), "test_namespace", "sha256", sig1);
    expect(alice.publicKey().verifySshSignature("test_namespace", data, sshsig)).toBe(true);
    // Not a raw signature over the data, which is what a real agent returns.
    expect(ed25519.verify(sig1, data, alice.publicKey().keyBytes)).toBe(false);
  });

  it("signs with the identity the comment names, not the key bytes", async () => {
    const agent = new MemorySshAgent({ identities: [alice] });
    const data = utf8("test data");
    const impostor = alice.publicKey().withComment("bob@example.com");
    expectError(
      await rejection(agent.sign(impostor, data)),
      "SshAgent",
      "SSH agent error: Identity not found",
    );
    expectError(
      await rejection(agent.sign(bob.publicKey(), data)),
      "SshAgent",
      "SSH agent error: Identity not found",
    );
  });

  it("can refuse to sign", async () => {
    const agent = new MemorySshAgent({ identities: [alice], refuseToSign: true });
    expect(await agent.listIdentities()).toHaveLength(1);
    expectError(
      await rejection(agent.sign(alice.publicKey(), utf8("x"))),
      "SshAgent",
      "SSH agent error: Refused to sign",
    );
  });
});

describe("SSHAgentParams with an agent", () => {
  describe("lock/unlock round trip", () => {
    it.each(["", "alice@example.com", "bob@example.com", "ünïcödé ✓"])(
      "round-trips with id %j",
      async (id) => {
        const key = id === "" ? alice : sshKey(7, id);
        // An empty id needs the agent to hold exactly one identity.
        const agent = new MemorySshAgent({ identities: id === "" ? [key] : [alice, bob, key] });
        const params = SSHAgentParams.from();
        expect(params.id).toBe("");
        const contentKey = SymmetricKey.random();
        const message = await params.lock(contentKey, utf8(id), { agent });
        expect(params.id).toBe(id);
        expect(params.toString()).toBe(`SSHAgent("${id}")`);
        expect(message.aad).toEqual(params.toCborData());
        const unlocked = await params.unlock(message, utf8(id), { agent });
        expect(unlocked.equals(contentKey)).toBe(true);
      },
    );

    it("is byte-deterministic with an injected nonce", async () => {
      const agent = new MemorySshAgent({ identities: [alice] });
      const salt = Salt.random({ length: 16 });
      const nonce = Nonce.random();
      const contentKey = SymmetricKey.random();
      const one = await SSHAgentParams.from({ salt }).lock(contentKey, utf8(""), { agent, nonce });
      const two = await SSHAgentParams.from({ salt }).lock(contentKey, utf8(""), { agent, nonce });
      expect(one.toCbor().toData()).toEqual(two.toCbor().toData());
      expect(one.nonce.equals(nonce)).toBe(true);
      const three = await SSHAgentParams.from({ salt }).lock(contentKey, utf8(""), { agent });
      expect(three.toCbor().toData()).not.toEqual(one.toCbor().toData());
      expect(
        (await SSHAgentParams.from({ salt }).unlock(three, utf8(""), { agent })).equals(contentKey),
      ).toBe(true);
    });
  });

  describe("unlock identity priority", () => {
    const agent = new MemorySshAgent({ identities: [alice, bob] });
    const salt = Salt.random({ length: 16 });
    const contentKey = SymmetricKey.random();

    async function lockedByBob(): Promise<EncryptedMessage> {
      return SSHAgentParams.from({ salt }).lock(contentKey, utf8("bob@example.com"), { agent });
    }

    it("takes the secret's id first", async () => {
      const message = await lockedByBob();
      // The stored id names alice, the secret names bob: the secret wins.
      const params = SSHAgentParams.from({ salt, id: "alice@example.com" });
      const unlocked = await params.unlock(message, utf8("bob@example.com"), { agent });
      expect(unlocked.equals(contentKey)).toBe(true);
      // ... so the stored id alone (alice) does not decrypt bob's message.
      expectError(
        await rejection(params.unlock(message, utf8(""), { agent })),
        "Crypto",
        DECRYPT_FAILED,
      );
    });

    it("then the stored id", async () => {
      const message = await lockedByBob();
      const params = SSHAgentParams.fromCbor(decodeCbor(message.aad));
      expect(params.id).toBe("bob@example.com");
      const unlocked = await params.unlock(message, utf8(""), { agent });
      expect(unlocked.equals(contentKey)).toBe(true);
    });

    it("then the first identity", async () => {
      const message = await lockedByBob();
      const params = SSHAgentParams.from({ salt });
      // alice is first: her signature derives a different key.
      expectError(
        await rejection(params.unlock(message, utf8(""), { agent })),
        "Crypto",
        DECRYPT_FAILED,
      );
      // With bob first, the first identity is the right one.
      const bobFirst = new MemorySshAgent({ identities: [bob, alice] });
      const unlocked = await params.unlock(message, utf8(""), { agent: bobFirst });
      expect(unlocked.equals(contentKey)).toBe(true);
    });

    it("fails to decrypt with the wrong identity", async () => {
      const message = await lockedByBob();
      const params = SSHAgentParams.fromCbor(decodeCbor(message.aad));
      const e = await rejection(params.unlock(message, utf8("alice@example.com"), { agent }));
      expectError(e, "Crypto", DECRYPT_FAILED);
      expect(ComponentsError.isComponentsError(e.cause)).toBe(true);
    });
  });

  describe("errors, in the reference's words", () => {
    const contentKey = SymmetricKey.random();

    async function locked(agent: SshAgent, id: string): Promise<EncryptedMessage> {
      return SSHAgentParams.from().lock(contentKey, utf8(id), { agent });
    }

    it("SSH Agent secret must be a valid UTF-8 string", async () => {
      const agent = new MemorySshAgent({ identities: [alice] });
      const bad = new Uint8Array([0x61, 0xff, 0xfe]);
      const message = "SSH agent error: SSH Agent secret must be a valid UTF-8 string";
      const params = SSHAgentParams.from();
      expectError(await rejection(params.lock(contentKey, bad, { agent })), "SshAgent", message);
      expect(params.id).toBe("");
      const locked1 = await locked(agent, "");
      expectError(await rejection(params.unlock(locked1, bad, { agent })), "SshAgent", message);
    });

    it("keeps a leading BOM in the id, as String::from_utf8 does", async () => {
      const bom = "﻿alice@example.com";
      const agent = new MemorySshAgent({ identities: [sshKey(4, bom)] });
      const params = SSHAgentParams.from();
      await params.lock(contentKey, utf8(bom), { agent });
      expect(params.id).toBe(bom);
    });

    it("No Ed25519 identities available in SSH agent", async () => {
      const message = "SSH agent error: No Ed25519 identities available in SSH agent";
      for (const agent of [new MemorySshAgent(), new MemorySshAgent({ identities: [p256] })]) {
        expectError(
          await rejection(SSHAgentParams.from().lock(contentKey, utf8(""), { agent })),
          "SshAgent",
          message,
        );
        expectError(
          await rejection(
            SSHAgentParams.from().lock(contentKey, utf8("p256@example.com"), { agent }),
          ),
          "SshAgent",
          message,
        );
        const locked1 = await locked(new MemorySshAgent({ identities: [alice] }), "");
        expectError(
          await rejection(SSHAgentParams.from().unlock(locked1, utf8(""), { agent })),
          "SshAgent",
          message,
        );
      }
    });

    it("Multiple identities available in SSH agent, but no ID provided", async () => {
      // Non-Ed25519 identities do not count.
      const one = new MemorySshAgent({ identities: [alice, p256] });
      const message = await locked(one, "");
      const several = new MemorySshAgent({ identities: [alice, bob] });
      expectError(
        await rejection(SSHAgentParams.from().lock(contentKey, utf8(""), { agent: several })),
        "SshAgent",
        "SSH agent error: Multiple identities available in SSH agent, but no ID provided",
      );
      // Unlock has no such rule: an empty id and empty stored id take the first identity.
      const params = SSHAgentParams.fromCbor(decodeCbor(message.aad));
      expect(params.id).toBe("");
      const unlocked = await params.unlock(message, utf8(""), { agent: several });
      expect(unlocked.equals(contentKey)).toBe(true);
    });

    it("No matching identity found", async () => {
      const agent = new MemorySshAgent({ identities: [alice, bob] });
      const message = "SSH agent error: No matching identity found";
      const params = SSHAgentParams.from();
      expectError(
        await rejection(params.lock(contentKey, utf8("carol@example.com"), { agent })),
        "SshAgent",
        message,
      );
      expect(params.id).toBe("");
      const locked1 = await locked(agent, "alice@example.com");
      // The secret's id.
      expectError(
        await rejection(
          SSHAgentParams.fromCbor(decodeCbor(locked1.aad)).unlock(
            locked1,
            utf8("carol@example.com"),
            {
              agent,
            },
          ),
        ),
        "SshAgent",
        message,
      );
      // The stored id.
      expectError(
        await rejection(
          SSHAgentParams.from({ id: "carol@example.com" }).unlock(locked1, utf8(""), { agent }),
        ),
        "SshAgent",
        message,
      );
      // A comment match is exact.
      expectError(
        await rejection(params.lock(contentKey, utf8("alice@example.com "), { agent })),
        "SshAgent",
        message,
      );
    });

    it("SSH agent refused to sign", async () => {
      const refusing = new MemorySshAgent({ identities: [alice], refuseToSign: true });
      const message = "SSH agent error: SSH agent refused to sign";
      const params = SSHAgentParams.from();
      const e = await rejection(params.lock(contentKey, utf8(""), { agent: refusing }));
      expectError(e, "SshAgent", message);
      expect(ComponentsError.isComponentsError(e.cause) && e.cause.message).toBe(
        "SSH agent error: Refused to sign",
      );
      expect(params.id).toBe("");
      const locked1 = await locked(new MemorySshAgent({ identities: [alice] }), "");
      expectError(
        await rejection(params.unlock(locked1, utf8(""), { agent: refusing })),
        "SshAgent",
        message,
      );
      // Any throw counts, not only a ComponentsError.
      const throwing: SshAgent = {
        listIdentities: () => refusing.listIdentities(),
        sign: () => Promise.reject(new TypeError("socket closed")),
      };
      const e2 = await rejection(params.lock(contentKey, utf8(""), { agent: throwing }));
      expectError(e2, "SshAgent", message);
      expect(e2.cause).toBeInstanceOf(TypeError);
    });

    it("Failed to decrypt the encrypted key: tampered AAD and ciphertext", async () => {
      const agent = new MemorySshAgent({ identities: [alice] });
      const message = await locked(agent, "");
      const params = SSHAgentParams.fromCbor(decodeCbor(message.aad));

      const otherParams = SSHAgentParams.from({ salt: params.salt, id: "alice@example.com" });
      const tamperedAad = EncryptedMessage.from({
        ciphertext: message.ciphertext,
        aad: otherParams.toCborData(),
        nonce: message.nonce,
        authTag: message.authenticationTag.bytes,
      });
      expectError(
        await rejection(params.unlock(tamperedAad, utf8(""), { agent })),
        "Crypto",
        DECRYPT_FAILED,
      );

      const ciphertext = new Uint8Array(message.ciphertext);
      ciphertext[0] ^= 0x01;
      const tamperedCiphertext = EncryptedMessage.from({
        ciphertext,
        aad: message.aad,
        nonce: message.nonce,
        authTag: message.authenticationTag.bytes,
      });
      const e = await rejection(params.unlock(tamperedCiphertext, utf8(""), { agent }));
      expectError(e, "Crypto", DECRYPT_FAILED);
      expect(e.details).toEqual({
        code: "Crypto",
        message: "Failed to decrypt the encrypted key: cryptographic operation failed: AEAD error",
      });
    });

    it("Failed to convert decrypted key to SymmetricKey", async () => {
      const agent = new MemorySshAgent({ identities: [alice] });
      const params = SSHAgentParams.from({ id: "alice@example.com" });
      const signature = await agent.sign(alice.publicKey(), params.salt.bytes);
      const derived = SymmetricKey.from(hkdfSha256(signature, params.salt.bytes, { dkLen: 32 }));
      const notAKey = derived.encrypt(new Uint8Array(31), { aad: params.toCborData() });
      expectError(
        await rejection(params.unlock(notAKey, utf8(""), { agent })),
        "Crypto",
        "cryptographic operation failed: Failed to convert decrypted key to SymmetricKey: invalid symmetric key size: expected 32, got 31",
      );
    });

    it("SshAgent without an agent, the synchronous KeyDerivation route", () => {
      const params = SSHAgentParams.from({ id: "alice@example.com" });
      expect(() => params.lock(contentKey, utf8(""))).toThrow(NEEDS_AGENT);
      const message = contentKey.encrypt(new Uint8Array(32), { aad: params.toCborData() });
      expect(() => params.unlock(message, utf8(""))).toThrow(NEEDS_AGENT);
    });
  });

  describe("pinned vectors", () => {
    const key = PrivateKeyBase.from(hexToBytes(vectors.seedHex))
      .sshSigningPrivateKey({ kind: "ed25519" }, vectors.comment)
      .asSsh();
    if (key === undefined) throw new Error("not an SSH key");
    const salt = Salt.from(hexToBytes(vectors.saltHex));
    const agent = new MemorySshAgent({ identities: [key] });

    it("is the fixture's key", () => {
      expect(key.publicKey().toOpenssh()).toBe(vectors.publicKeyOpenssh);
      expect(key.toOpenssh()).toBe(vectors.privateKeyOpenssh);
      expect(
        SSHPrivateKey.fromOpenssh(vectors.privateKeyOpenssh).publicKey().equals(key.publicKey()),
      ).toBe(true);
    });

    it("signs the salt to the pinned 64 bytes, and HKDF derives the pinned key", async () => {
      const signature = await agent.sign(key.publicKey(), salt.bytes);
      expect(bytesToHex(signature)).toBe(vectors.signatureHex);
      expect(bytesToHex(hkdfSha256(signature, salt.bytes, { dkLen: 32 }))).toBe(
        vectors.derivedKeyHex,
      );
    });

    it("locks to the pinned bytes with the pinned nonce, and unlocks them", async () => {
      const params = SSHAgentParams.from({ salt });
      const contentKey = SymmetricKey.from(hexToBytes(vectors.contentKeyHex));
      const encrypted = await EncryptedKey.lockWithAgent(
        sshAgentParams(params),
        utf8(vectors.comment),
        contentKey,
        { agent, nonce: Nonce.from(hexToBytes(vectors.nonceHex)) },
      );
      expect(bytesToHex(params.toCborData())).toBe(vectors.aadCborHex);
      expect(encrypted.toString()).toBe(vectors.encryptedKeyString);
      expect(bytesToHex(encrypted.toCbor().toData())).toBe(vectors.encryptedKeyCborHex);

      // The pinned bytes decrypt with the derived key directly ...
      const derived = SymmetricKey.from(hexToBytes(vectors.derivedKeyHex));
      const pinned = EncryptedKey.fromCbor(decodeCbor(hexToBytes(vectors.encryptedKeyCborHex)));
      expect(derived.decrypt(pinned.encryptedMessage)).toEqual(contentKey.bytes);
      // ... and through the agent, by the stored id or the secret.
      expect((await pinned.unlockWithAgent(utf8(""), { agent })).equals(contentKey)).toBe(true);
      expect(
        (await pinned.unlockWithAgent(utf8(vectors.comment), { agent })).equals(contentKey),
      ).toBe(true);
    });
  });
});

describe("EncryptedKey with an agent", () => {
  const agent = new MemorySshAgent({ identities: [alice, bob] });
  const secret = utf8("alice@example.com");

  it("lockWithAgent, toCbor, fromCbor, unlockWithAgent", async () => {
    const contentKey = SymmetricKey.random();
    const params = SSHAgentParams.from();
    const encrypted = await EncryptedKey.lockWithAgent(sshAgentParams(params), secret, contentKey, {
      agent,
    });
    expect(encrypted.isSshAgent()).toBe(true);
    expect(encrypted.isPasswordBased()).toBe(false);
    expect(encrypted.toString()).toBe('EncryptedKey(SSHAgent("alice@example.com"))');
    expect(encrypted.params.type === "sshagent" && encrypted.params.params).toBe(params);
    expect(params.id).toBe("alice@example.com");

    const restored = EncryptedKey.fromCbor(decodeCbor(encrypted.toCbor().toData()));
    expect(restored.equals(encrypted)).toBe(true);
    expect(restored.isSshAgent()).toBe(true);
    expect((await restored.unlockWithAgent(secret, { agent })).equals(contentKey)).toBe(true);
    expect((await restored.unlockWithAgent(utf8(""), { agent })).equals(contentKey)).toBe(true);
    expect(restored.toUR().toString().startsWith("ur:encrypted-key/")).toBe(true);
  });

  it("follows the reference's test: the AAD's parameters unlock the message", async () => {
    // One identity, an empty secret.
    const one = new MemorySshAgent({ identities: [alice] });
    const contentKey = SymmetricKey.random();
    const encrypted = await EncryptedKey.lockWithAgent(
      sshAgentParams(SSHAgentParams.from()),
      utf8(""),
      contentKey,
      { agent: one },
    );
    const restored = EncryptedKey.fromCbor(decodeCbor(encrypted.toCbor().toData()));
    const params = SSHAgentParams.fromCbor(decodeCbor(restored.encryptedMessage.aad));
    expect(params.id).toBe("");
    const unlocked = await params.unlock(encrypted.encryptedMessage, utf8(""), { agent: one });
    expect(unlocked.equals(contentKey)).toBe(true);
  });

  it("unlockWithAgent on another method is unlock", async () => {
    const contentKey = SymmetricKey.random();
    const password = utf8("correct horse battery staple");
    const encrypted = EncryptedKey.lockOpt(hkdfParams(), password, contentKey);
    expect((await encrypted.unlockWithAgent(password, { agent })).equals(contentKey)).toBe(true);
    await expect(encrypted.unlockWithAgent(utf8("wrong"), { agent })).rejects.toThrow(
      "cryptographic operation failed: AEAD error",
    );
  });

  it("lockWithAgent needs SSH-agent parameters", async () => {
    const e = await rejection(
      EncryptedKey.lockWithAgent(hkdfParams(), secret, SymmetricKey.random(), { agent }),
    );
    expectError(
      e,
      "InvalidData",
      "invalid data: lockWithAgent() needs SSH Agent key derivation - use lockOpt() for HKDF, PBKDF2, Scrypt and Argon2id",
    );
  });

  it("the synchronous routes throw SshAgent for SSH-agent parameters", () => {
    const contentKey = SymmetricKey.random();
    let thrown: unknown;
    try {
      EncryptedKey.lockOpt(sshAgentParams("alice@example.com"), secret, contentKey);
    } catch (e) {
      thrown = e;
    }
    expect(ComponentsError.isComponentsError(thrown) && thrown.code).toBe("SshAgent");
    expect(ComponentsError.isComponentsError(thrown) && thrown.message).toBe(NEEDS_AGENT);
    expect(() => EncryptedKey.lock(4, secret, contentKey)).toThrow(
      "SSH Agent key derivation cannot be used with lock() - use lockOpt() with sshAgentParams() instead",
    );
  });

  it("the synchronous unlock throws SshAgent for a key locked with an agent", async () => {
    const encrypted = await EncryptedKey.lockWithAgent(
      sshAgentParams(SSHAgentParams.from()),
      secret,
      SymmetricKey.random(),
      { agent },
    );
    expect(() => encrypted.unlock(secret)).toThrow(NEEDS_AGENT);
  });
});

describe("connectToSshAgent", () => {
  const saved = process.env["SSH_AUTH_SOCK"];
  const restore = (): void => {
    if (saved === undefined) delete process.env["SSH_AUTH_SOCK"];
    else process.env["SSH_AUTH_SOCK"] = saved;
  };

  it("SSH_AUTH_SOCK env var not set", async () => {
    delete process.env["SSH_AUTH_SOCK"];
    try {
      expectError(
        await rejection(connectToSshAgent()),
        "SshAgent",
        "SSH agent error: SSH_AUTH_SOCK env var not set",
      );
    } finally {
      restore();
    }
  });

  it("no ssh-agent reachable", async () => {
    process.env["SSH_AUTH_SOCK"] = join(tmpdir(), "bc-components-no-such-agent.sock");
    try {
      const e = await rejection(connectToSshAgent());
      expectError(e, "SshAgent", "SSH agent error: no ssh-agent reachable");
      expect(e.cause).toBeInstanceOf(Error);
    } finally {
      restore();
    }
  });
});

function onPath(name: string): boolean {
  return (process.env["PATH"] ?? "")
    .split(delimiter)
    .some((dir) => dir.length > 0 && existsSync(join(dir, name)));
}

const haveSshTools = ["ssh-agent", "ssh-add", "ssh-keygen"].every(onPath);

describe.skipIf(!haveSshTools)("connectToSshAgent with a real ssh-agent", () => {
  const COMMENT = "your_email@example.com";
  const saved = process.env["SSH_AUTH_SOCK"];
  let dir = "";
  let socketPath = "";
  let agentProcess: ChildProcess | undefined;
  let key: SSHPrivateKey;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "bc-ssh-agent-"));
    socketPath = join(dir, "agent.sock");
    const keyPath = join(dir, "id_ed25519");
    execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", COMMENT, "-f", keyPath], {
      stdio: "pipe",
    });
    key = SSHPrivateKey.fromOpenssh(readFileSync(keyPath, "utf8"));
    agentProcess = spawn("ssh-agent", ["-D", "-a", socketPath], { stdio: "ignore" });
    for (let i = 0; i < 200 && !existsSync(socketPath); i++) {
      await sleep(50);
    }
    if (!existsSync(socketPath)) throw new Error("ssh-agent did not open its socket");
    execFileSync("ssh-add", [keyPath], {
      env: { ...process.env, SSH_AUTH_SOCK: socketPath },
      stdio: "pipe",
    });
    process.env["SSH_AUTH_SOCK"] = socketPath;
  }, 30_000);

  afterAll(() => {
    if (saved === undefined) delete process.env["SSH_AUTH_SOCK"];
    else process.env["SSH_AUTH_SOCK"] = saved;
    agentProcess?.kill();
    if (dir.length > 0) rmSync(dir, { recursive: true, force: true });
  });

  it("lists the added identity, the one the memory agent lists", async () => {
    const agent = await connectToSshAgent();
    const ids = await agent.listIdentities();
    expect(ids).toHaveLength(1);
    expect(ids[0].comment).toBe(COMMENT);
    expect(ids[0].equals(key.publicKey())).toBe(true);
    const memory = new MemorySshAgent({ identities: [key] });
    expect(ids[0].equals((await memory.listIdentities())[0])).toBe(true);
  });

  it("returns the raw Ed25519 signature over the data", async () => {
    const agent = await connectToSshAgent();
    const [identity] = await agent.listIdentities();
    const data = utf8("data to sign");
    const signature = await agent.sign(identity, data);
    expect(signature).toHaveLength(64);
    expect(ed25519.verify(signature, data, identity.keyBytes)).toBe(true);
    expect(signature).toEqual(await agent.sign(identity, data));
  });

  it("locks and unlocks through the agent, through CBOR", async () => {
    const agent = await connectToSshAgent();
    const contentKey = SymmetricKey.random();
    for (const id of ["", COMMENT]) {
      const params = SSHAgentParams.from();
      const encrypted = await EncryptedKey.lockWithAgent(
        sshAgentParams(params),
        utf8(id),
        contentKey,
        {
          agent,
        },
      );
      expect(params.id).toBe(id);
      expect(encrypted.toString()).toBe(`EncryptedKey(SSHAgent("${id}"))`);
      const restored = EncryptedKey.fromCbor(decodeCbor(encrypted.toCbor().toData()));
      expect((await restored.unlockWithAgent(utf8(id), { agent })).equals(contentKey)).toBe(true);
      expect((await restored.unlockWithAgent(utf8(""), { agent })).equals(contentKey)).toBe(true);
    }
  });

  it("derives the key from the raw signature, unlike the memory agent, which signs as the reference's mock", async () => {
    const agent = await connectToSshAgent();
    const memory = new MemorySshAgent({ identities: [key] });
    const salt = Salt.random({ length: 16 });
    const nonce = Nonce.random();
    const contentKey = SymmetricKey.random();
    const byAgent = await SSHAgentParams.from({ salt }).lock(contentKey, utf8(COMMENT), {
      agent,
      nonce,
    });
    const byMemory = await SSHAgentParams.from({ salt }).lock(contentKey, utf8(COMMENT), {
      agent: memory,
      nonce,
    });
    expect(byAgent.aad).toEqual(byMemory.aad);
    expect(byAgent.ciphertext).not.toEqual(byMemory.ciphertext);
    const params = SSHAgentParams.fromCbor(decodeCbor(byAgent.aad));
    expect((await params.unlock(byAgent, utf8(""), { agent })).equals(contentKey)).toBe(true);
    expect((await params.unlock(byMemory, utf8(""), { agent: memory })).equals(contentKey)).toBe(
      true,
    );
    expectError(
      await rejection(params.unlock(byMemory, utf8(""), { agent })),
      "Crypto",
      DECRYPT_FAILED,
    );
    expectError(
      await rejection(params.unlock(byAgent, utf8(""), { agent: memory })),
      "Crypto",
      DECRYPT_FAILED,
    );

    // The raw signature is what the derived key comes from.
    const signature = await agent.sign(key.publicKey(), salt.bytes);
    const derived = SymmetricKey.from(hkdfSha256(signature, salt.bytes, { dkLen: 32 }));
    expect(derived.decrypt(byAgent)).toEqual(contentKey.bytes);
  });

  it("names the identity by comment", async () => {
    const agent = await connectToSshAgent();
    expectError(
      await rejection(SSHAgentParams.from().lock(SymmetricKey.random(), utf8("nobody"), { agent })),
      "SshAgent",
      "SSH agent error: No matching identity found",
    );
  });
});
