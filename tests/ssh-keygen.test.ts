/**
 * Byte-identical parity tests for deterministic SSH key generation (DSA,
 * ECDSA P-521, RSA-2048) against fixtures produced by the Rust reference:
 * `bc-components` 0.31.1 `PrivateKeyBase::ssh_signing_private_key`, which
 * drives the `ssh-key` 0.6.7 `*Keypair::random` constructors with
 * `HKDFRng::new(seed, algorithm.as_str())`.
 *
 * Fixtures: `tests/fixtures/ssh-keygen/{dsa,p521,rsa}.json`, 22 seeds each:
 * the 16-byte seed the reference's own SSH tests use
 * (`59f2293a5bce7d4de59e71b4207ac5d2`), the 32-byte pattern `01 02 .. 20`,
 * and `[i; 32]` for i = 0..19. For every seed the Rust generator recorded
 * the OpenSSH private-key PEM, the public-key line, each key component as
 * `Mpint::as_positive_bytes()` hex (P-521: the raw 66-byte scalar and the
 * 133-byte SEC1 point), and the number of RNG requests it issued.
 *
 * Salts are the wire names exactly as `Algorithm::as_str()` returns them:
 * `ssh-dss`, `ecdsa-sha2-nistp521`, and `ssh-rsa` (the reference generates
 * RSA keys with `Algorithm::Rsa { hash: None }`).
 *
 * Measured generation time in TS, median of 3 runs on the first fixture
 * seed (Apple Silicon): Node 24 (vitest) — DSA 151 ms, P-521 1.3 ms,
 * RSA 158 ms; Bun 1.4 — DSA 55 ms, P-521 1.0 ms, RSA 44 ms. The Rust
 * release build took 179 ms, 0.4 ms and 165 ms for the same seed.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { HKDFRng } from "../src/hkdf-rng.js";
import type { KeygenRng } from "../src/ssh/internal/keygen-rng.js";
import { generateDsaKeypair } from "../src/ssh/internal/dsa-keygen.js";
import { generateP521Keypair } from "../src/ssh/internal/p521-keygen.js";
import { generateRsaKeypair } from "../src/ssh/internal/rsa-keygen.js";
import { SshBufferWriter } from "../src/ssh/internal/ssh-buffer.js";
import { SSHPrivateKey } from "../src/ssh/ssh-private-key.js";
import { fromBase64, toBase64 } from "../src/utils.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** DSA components as `Mpint::as_positive_bytes()` hex. */
interface DsaComponentsHex {
  p: string;
  q: string;
  g: string;
  y: string;
  x: string;
}

/** P-521 components: the raw 66-byte scalar and the 133-byte SEC1 point, hex. */
interface P521ComponentsHex {
  scalar: string;
  point: string;
}

/** RSA components as `Mpint::as_positive_bytes()` hex, in ssh-key's field meaning. */
interface RsaComponentsHex {
  n: string;
  e: string;
  d: string;
  iqmp: string;
  p: string;
  q: string;
}

interface FixtureRecord<C> {
  seed: string;
  salt: string;
  comment: string;
  privatePem: string;
  publicOpenssh: string;
  components: C;
  rngCalls: number;
  genMillis: number;
}

interface FixtureFile<C> {
  reference: string;
  algorithm: string;
  records: FixtureRecord<C>[];
}

const here = dirname(fileURLToPath(import.meta.url));

function loadFixture<C>(name: string): FixtureFile<C> {
  const text = readFileSync(join(here, "fixtures", "ssh-keygen", `${name}.json`), "utf8");
  return JSON.parse(text) as FixtureFile<C>;
}

const DSA = loadFixture<DsaComponentsHex>("dsa");
const P521 = loadFixture<P521ComponentsHex>("p521");
const RSA = loadFixture<RsaComponentsHex>("rsa");

const SALT_DSA = "ssh-dss";
const SALT_P521 = "ecdsa-sha2-nistp521";
const SALT_RSA = "ssh-rsa";
const COMMENT = "Key comment.";

/** The seed list the Rust generator used, in order. */
function expectedSeeds(): string[] {
  const seeds = ["59f2293a5bce7d4de59e71b4207ac5d2"];
  seeds.push(hex(Uint8Array.from({ length: 32 }, (_, i) => i + 1)));
  for (let i = 0; i < 20; i++) seeds.push(hex(new Uint8Array(32).fill(i)));
  return seeds;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function unhex(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function big(bytes: Uint8Array): bigint {
  return bytes.length === 0 ? 0n : BigInt(`0x${hex(bytes)}`);
}

/** Counts RNG requests so the tests can assert the same draw count as Rust. */
class CountingRng implements KeygenRng {
  calls = 0;
  constructor(private readonly inner: HKDFRng) {}
  fillBytes(dest: Uint8Array): void {
    this.calls += 1;
    this.inner.fillBytes(dest);
  }
  nextU32(): number {
    this.calls += 1;
    return this.inner.nextU32();
  }
  nextU64(): bigint {
    this.calls += 1;
    return this.inner.nextU64();
  }
}

/**
 * `ssh-key`'s `Mpint::as_bytes()` for a positive value: the canonical bytes
 * with a 0x00 prefix when the top bit is set.
 */
function mpintBytes(canonical: Uint8Array): Uint8Array {
  if (canonical.length > 0 && (canonical[0] & 0x80) !== 0) {
    const out = new Uint8Array(canonical.length + 1);
    out.set(canonical, 1);
    return out;
  }
  return canonical;
}

/** `ssh-key` 0.6.7 `KeypairData::checkint`: XOR of the 4-byte big-endian chunks (`chunks_exact`). */
function checkintOf(bytes: Uint8Array): number {
  let n = 0;
  for (let off = 0; off + 4 <= bytes.length; off += 4) {
    n ^=
      ((bytes[off] << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3]) >>> 0;
  }
  return n >>> 0;
}

/** The checkint stored in an unencrypted OpenSSH private-key PEM. */
function checkintFromPem(pem: string): number {
  const body = pem
    .split("\n")
    .filter((line) => line.length > 0 && !line.startsWith("-----"))
    .join("");
  const blob = fromBase64(body);
  const view = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  let off = 15; // "openssh-key-v1\0"
  const skipString = (): void => {
    off += 4 + view.getUint32(off, false);
  };
  skipString(); // ciphername
  skipString(); // kdfname
  skipString(); // kdfoptions
  off += 4; // nkeys
  skipString(); // public key blob
  off += 4; // length of the private section
  return view.getUint32(off, false);
}

const LONG_TEST_MS = 60_000;

function cases<C>(file: FixtureFile<C>): { idx: number; seed: string; rec: FixtureRecord<C> }[] {
  return file.records.map((rec, idx) => ({ idx, seed: rec.seed.slice(0, 8), rec }));
}

// ---------------------------------------------------------------------------
// Fixture sanity
// ---------------------------------------------------------------------------

describe("ssh keygen fixtures", () => {
  it("cover the documented seed list for every algorithm", () => {
    const seeds = expectedSeeds();
    expect(seeds).toHaveLength(22);
    for (const file of [DSA, P521, RSA]) {
      expect(file.records.map((r) => r.seed)).toEqual(seeds);
      expect(file.records.every((r) => r.comment === COMMENT)).toBe(true);
    }
  });

  it("record the wire-name salts the reference derives from `Algorithm::as_str()`", () => {
    expect(DSA.algorithm).toBe(SALT_DSA);
    expect(P521.algorithm).toBe(SALT_P521);
    expect(RSA.algorithm).toBe(SALT_RSA);
    expect(DSA.records.every((r) => r.salt === SALT_DSA)).toBe(true);
    expect(P521.records.every((r) => r.salt === SALT_P521)).toBe(true);
    expect(RSA.records.every((r) => r.salt === SALT_RSA)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// DSA (ssh-dss, 1024/160)
// ---------------------------------------------------------------------------

describe("generateDsaKeypair over HKDFRng(seed, 'ssh-dss') matches Rust", () => {
  it.each(cases(DSA))(
    "seed $idx ($seed…)",
    ({ rec }) => {
      const rng = new CountingRng(new HKDFRng(unhex(rec.seed), SALT_DSA));
      const key = generateDsaKeypair(rng);

      expect(hex(key.p)).toBe(rec.components.p);
      expect(hex(key.q)).toBe(rec.components.q);
      expect(hex(key.g)).toBe(rec.components.g);
      expect(hex(key.y)).toBe(rec.components.y);
      expect(hex(key.x)).toBe(rec.components.x);
      expect(rng.calls).toBe(rec.rngCalls);

      // The existing OpenSSH encoder reproduces the reference PEM when the
      // checkint is computed over the mpint encoding of x (with its sign
      // byte), as `KeypairData::checkint` does.
      const checkint = checkintOf(mpintBytes(key.x));
      expect(checkintFromPem(rec.privatePem)).toBe(checkint);
      const sshKey = SSHPrivateKey.fromParts({ kind: "dsa", ...key }, rec.comment, checkint);
      expect(sshKey.toOpenssh()).toBe(rec.privatePem);
      expect(sshKey.publicKey().toOpenssh()).toBe(rec.publicOpenssh);
    },
    LONG_TEST_MS,
  );

  it("produces a valid DSA group and keypair", () => {
    const key = generateDsaKeypair(new HKDFRng(unhex(DSA.records[0].seed), SALT_DSA));
    const p = big(key.p);
    const q = big(key.q);
    const g = big(key.g);
    const x = big(key.x);
    expect(key.p).toHaveLength(128);
    expect(key.q).toHaveLength(20);
    expect((p - 1n) % q).toBe(0n);
    expect(x > 0n && x < q).toBe(true);
    expect(g > 1n && g < p).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// ECDSA P-521 (ecdsa-sha2-nistp521)
// ---------------------------------------------------------------------------

describe("generateP521Keypair over HKDFRng(seed, 'ecdsa-sha2-nistp521') matches Rust", () => {
  it.each(cases(P521))("seed $idx ($seed…)", ({ rec }) => {
    const rng = new CountingRng(new HKDFRng(unhex(rec.seed), SALT_P521));
    const key = generateP521Keypair(rng);

    expect(key.scalar).toHaveLength(66);
    expect(key.point).toHaveLength(133);
    expect(hex(key.scalar)).toBe(rec.components.scalar);
    expect(hex(key.point)).toBe(rec.components.point);
    expect(rng.calls).toBe(rec.rngCalls);

    // Public-key line: string algorithm, string curve, string point.
    const blob = new SshBufferWriter()
      .writeStringUtf8(SALT_P521)
      .writeStringUtf8("nistp521")
      .writeString(key.point)
      .bytes();
    expect(`${SALT_P521} ${toBase64(blob)} ${rec.comment}`).toBe(rec.publicOpenssh);

    // The OpenSSH encoder reproduces the reference PEM; the checkint is
    // computed over the raw 66-byte scalar (`EcdsaKeypair::private_key_bytes`).
    const checkint = checkintOf(key.scalar);
    expect(checkintFromPem(rec.privatePem)).toBe(checkint);
    const sshKey = SSHPrivateKey.fromParts(
      { kind: "ecdsa", curve: "nistp521", scalar: key.scalar, point: key.point },
      rec.comment,
      checkint,
    );
    expect(sshKey.toOpenssh()).toBe(rec.privatePem);
    expect(sshKey.publicKey().toOpenssh()).toBe(rec.publicOpenssh);
  });
});

// ---------------------------------------------------------------------------
// RSA-2048 (ssh-rsa)
// ---------------------------------------------------------------------------

describe("generateRsaKeypair over HKDFRng(seed, 'ssh-rsa') matches Rust", () => {
  it.each(cases(RSA))(
    "seed $idx ($seed…)",
    ({ rec }) => {
      const rng = new CountingRng(new HKDFRng(unhex(rec.seed), SALT_RSA));
      const key = generateRsaKeypair(rng, 2048);

      expect(hex(key.n)).toBe(rec.components.n);
      expect(hex(key.e)).toBe(rec.components.e);
      expect(hex(key.d)).toBe(rec.components.d);
      expect(hex(key.iqmp)).toBe(rec.components.iqmp);
      expect(hex(key.p)).toBe(rec.components.p);
      expect(hex(key.q)).toBe(rec.components.q);
      expect(rng.calls).toBe(rec.rngCalls);

      // Public-key line: string algorithm, mpint e, mpint n.
      const blob = new SshBufferWriter()
        .writeStringUtf8(SALT_RSA)
        .writeMpintUnsigned(key.e)
        .writeMpintUnsigned(key.n)
        .bytes();
      expect(`${SALT_RSA} ${toBase64(blob)} ${rec.comment}`).toBe(rec.publicOpenssh);

      // The reference PEM's checkint is `KeypairData::checkint` over the
      // mpint encoding of d (with its sign byte); with it the OpenSSH
      // encoder reproduces the reference PEM.
      const checkint = checkintOf(mpintBytes(key.d));
      expect(checkintFromPem(rec.privatePem)).toBe(checkint);
      const sshKey = SSHPrivateKey.fromParts({ kind: "rsa", ...key }, rec.comment, checkint);
      expect(sshKey.toOpenssh()).toBe(rec.privatePem);
      expect(sshKey.publicKey().toOpenssh()).toBe(rec.publicOpenssh);
    },
    LONG_TEST_MS,
  );

  it("returns the fields with ssh-key's meaning: p = primes[0], q = primes[1], iqmp = q^-1 mod p", () => {
    const key = generateRsaKeypair(new HKDFRng(unhex(RSA.records[0].seed), SALT_RSA), 2048);
    const n = big(key.n);
    const e = big(key.e);
    const d = big(key.d);
    const p = big(key.p);
    const q = big(key.q);
    const iqmp = big(key.iqmp);
    expect(key.n).toHaveLength(256);
    expect(e).toBe(65537n);
    expect(p * q).toBe(n);
    expect((iqmp * q) % p).toBe(1n);
    expect((d * e) % ((p - 1n) * (q - 1n))).toBe(1n);
  });
});
