/* eslint-disable @typescript-eslint/no-non-null-assertion -- fixtures are indexed by position; a miss fails the test */
/**
 * Golden snapshots: one block per class over fixed inputs and the seeded
 * generator, plus the rejection table, plus freeze entries for every
 * behavioural finding (B1–B10).
 */
import { cbor, taggedValue } from "@blockchaincommons/dcbor";
import * as root from "../src/index.js";
import * as ssh from "../src/ssh/index.js";
import * as pq from "../src/pq.js";
import * as kdf from "../src/kdf.js";
import * as sskr from "../src/sskr.js";
import * as tagsMod from "../src/tags.js";

const src = { ...root, ...ssh, ...pq, ...kdf, ...sskr, ...tagsMod };
import * as rand from "@blockchaincommons/rand";
import { materialize, redesignedAdapterFor, type Recipe } from "./vectors/recipes";
import { categories, SEEDS, FAKE } from "./corpus/corpus";

const api = redesignedAdapterFor(src, rand);
const run = (r: Recipe) => materialize(api, r);

describe("golden: value types over fixed bytes", () => {
  const byType = new Map<string, Recipe[]>();
  for (const r of categories["values"]!()) {
    if (r.k !== "value") continue;
    byType.set(r.type, [...(byType.get(r.type) ?? []), r]);
  }
  for (const [type, recipes] of byType) {
    it(type, () => {
      expect(recipes.map((r) => run(r))).toMatchSnapshot();
    });
  }
});
describe("golden: seeded constructors", () => {
  for (const type of [
    "nonce",
    "salt",
    "arid",
    "uuid",
    "symmetricKey",
    "x25519Priv",
    "ecPriv",
    "ed25519Priv",
    "privateKeyBase",
    "seed",
  ] as const) {
    it(type, () => {
      expect([
        run({ k: "random", type, rng: SEEDS[0]! }),
        run({ k: "random", type, rng: FAKE }),
      ]).toMatchSnapshot();
    });
  }
});
for (const cat of [
  "derives",
  "digests",
  "compresseds",
  "seeds",
  "encrypts",
  "signings",
  "sshes",
  "pkbs",
  "kdfs",
  "sskrs",
  "decodes",
  "strictness",
  "untagged",
  "defaults",
  "kdfDomain",
  "domain",
  "summaries",
]) {
  describe(`golden: ${cat}`, () => {
    it("matches the snapshot", () => {
      const out: string[] = [];
      for (const r of categories[cat]!()) {
        const o = run(r);
        // outcomes that involve the secure generator are pinned by their stable tail
        out.push(r.k === "encryptedKey" ? o.replace(/\|aad=.*$/, "") : o);
      }
      expect(out).toMatchSnapshot();
    });
  });
}

/**
 * Freeze additions: every B-row's behavior, recorded verbatim so a
 * regression is a visible diff. `pageLength: 0` (B8) is not executed: it
 * loops forever on both sides.
 */
describe("golden: freeze additions", () => {
  const outcome = (f: () => unknown): string => {
    try {
      const r = f();
      return typeof r === "string" || typeof r === "boolean" ? String(r) : JSON.stringify(r);
    } catch (e) {
      const cls = (e as Error).constructor.name;
      const code = (e as { code?: string }).code;
      return `throw:${cls}${code === undefined ? "" : `:${code}`}:${(e as Error).message.slice(0, 60)}`;
    }
  };
  const hexOf = (b: Uint8Array): string => Buffer.from(b).toString("hex");
  const rng = () => rand.SeededRng.forTesting();
  const salt16 = () => src.Salt.from(new Uint8Array(16));
  const key = () => src.SymmetricKey.from(new Uint8Array(32).fill(7));
  const pw = new TextEncoder().encode("pw");

  it("B1: Ed25519 verification of a small-order key and a degenerate signature", () => {
    const identity = new Uint8Array(32);
    identity[0] = 1;
    const degenerate = new Uint8Array(64);
    degenerate[0] = 1;
    const verify = (pub: Uint8Array) =>
      outcome(() =>
        src.SigningPublicKey.fromEd25519(src.Ed25519PublicKey.from(pub)).verify(
          src.Signature.ed25519FromData(degenerate),
          new TextEncoder().encode("msg"),
        ),
      );
    expect([
      `identity key, (identity, 0) signature: ${verify(identity)}`,
      `non-canonical key (y ≥ p): ${verify(new Uint8Array(32).fill(0xff))}`,
    ]).toMatchSnapshot();
  });

  it("B2: untagged CBOR through fromCbor", () => {
    expect([
      `ARID.fromCbor(bytes32): ${outcome(() =>
        src.ARID.fromCbor(cbor(new Uint8Array(32)))
          .toHex()
          .slice(0, 8),
      )}`,
      `XID.fromCbor(bytes32): ${outcome(() =>
        src.XID.fromCbor(cbor(new Uint8Array(32)))
          .toHex()
          .slice(0, 8),
      )}`,
      `Nonce.fromCbor(bytes12): ${outcome(() => hexOf(src.Nonce.fromCbor(cbor(new Uint8Array(12))).bytes))}`,
      `SymmetricKey.fromCbor(bytes32): ${outcome(() => hexOf(src.SymmetricKey.fromCbor(cbor(new Uint8Array(32))).bytes).slice(0, 8))}`,
      `Salt.fromCbor(bytes8): ${outcome(() => hexOf(src.Salt.fromCbor(cbor(new Uint8Array(8))).bytes))}`,
      `Seed.fromCbor({1: bytes16}): ${outcome(() => `${src.Seed.fromCbor(cbor(new Map([[1, new Uint8Array(16)]]))).byteLength} bytes`)}`,
      `Digest.fromCbor(40001("x")): ${outcome(() => src.Digest.fromCbor(taggedValue(40001, cbor("x"))))}`,
    ]).toMatchSnapshot();
  });

  it("B3: the default signature scheme", () => {
    expect([
      `SigningPrivateKey.random({ rng }).scheme: ${outcome(() => src.SigningPrivateKey.random({ rng: rng() }).scheme)}`,
      `defaultSignatureScheme(): ${outcome(() => src.defaultSignatureScheme())}`,
      `generateKeypair({ rng }) signing scheme: ${outcome(() => src.generateKeypair({ rng: rng() })[0].signingPrivateKey.scheme)}`,
    ]).toMatchSnapshot();
  });

  it("B4: KDF parameter domains", () => {
    expect([
      `PBKDF2Params.from({ iterations: 0 }): ${outcome(() => `iterations=${src.PBKDF2Params.from({ salt: salt16(), iterations: 0 }).iterations}`)}`,
      `PBKDF2Params.from({ iterations: 1.5 }): ${outcome(() => `iterations=${src.PBKDF2Params.from({ salt: salt16(), iterations: 1.5 }).iterations}`)}`,
      `ScryptParams.from({ logN: 100 }): ${outcome(() => `logN=${src.ScryptParams.from({ salt: salt16(), logN: 100 }).logN}`)}`,
      `ScryptParams.from({ logN: 1.5 }): ${outcome(() => `logN=${src.ScryptParams.from({ salt: salt16(), logN: 1.5 }).logN}`)}`,
      `lockOpt scrypt logN 1.5: ${outcome(() =>
        hexOf(
          src.EncryptedKey.lockOpt(
            src.scryptParams(src.ScryptParams.from({ salt: salt16(), logN: 1.5 })),
            pw,
            key(),
          )
            .toCbor()
            .toData(),
        ).slice(0, 24),
      )}`,
      `lockOpt pbkdf2 iterations 0: ${outcome(() =>
        hexOf(
          src.EncryptedKey.lockOpt(
            src.pbkdf2Params(src.PBKDF2Params.from({ salt: salt16(), iterations: 0 })),
            pw,
            key(),
          )
            .toCbor()
            .toData(),
        ).slice(0, 24),
      )}`,
      `lockOpt scrypt logN 100: ${outcome(() =>
        hexOf(
          src.EncryptedKey.lockOpt(
            src.scryptParams(src.ScryptParams.from({ salt: salt16(), logN: 100 })),
            pw,
            key(),
          )
            .toCbor()
            .toData(),
        ).slice(0, 24),
      )}`,
      `unlock with the wrong password: ${outcome(() => src.EncryptedKey.lock(src.KeyDerivationMethod.HKDF, pw, key()).unlock(new TextEncoder().encode("no")))}`,
    ]).toMatchSnapshot();
  });

  it("B5: value objects alias their bytes", () => {
    const d = src.Digest.fromImage(new Uint8Array(3));
    const before = d.toHex();
    d.bytes[0] ^= 1;
    const sk = src.SymmetricKey.from(new Uint8Array(32));
    sk.bytes[0] = 9;
    const seed = src.Seed.from(new Uint8Array(16));
    seed.bytes[0] = 9;
    const xid = src.XID.from(new Uint8Array(32));
    xid.bytes[0] = 9;
    expect([
      `Digest: toHex changed=${d.toHex() !== before}, equals(original)=${src.Digest.fromHex(before).equals(d)}`,
      `SymmetricKey.bytes[0] = 9 → ${hexOf(sk.bytes).slice(0, 4)}`,
      `Seed.bytes[0] = 9 → ${hexOf(seed.bytes).slice(0, 4)}`,
      `XID.bytes[0] = 9 → ${xid.toHex().slice(0, 4)}`,
      `frozen: Digest=${Object.isFrozen(d)} ARID=${Object.isFrozen(src.ARID.from(new Uint8Array(32)))}`,
    ]).toMatchSnapshot();
  });

  it("B6/B7: foreign error classes past ComponentsError", () => {
    expect([
      `Digest.fromHex("zz"): ${outcome(() => src.Digest.fromHex("zz"))}`,
      `ECPublicKey.fromHex("zz"): ${outcome(() => src.ECPublicKey.fromHex("zz"))}`,
      `Salt.random({ length: NaN }): ${outcome(() => src.Salt.random({ length: NaN, rng: rng() }))}`,
      `Salt.random({ length: 1.5 }): ${outcome(() => src.Salt.random({ length: 1.5, rng: rng() }))}`,
      `Seed.random({ length: 1.5 }): ${outcome(() => src.Seed.random({ length: 1.5, rng: rng() }))}`,
      `ECPrivateKey.from(ff×32).publicKey(): ${outcome(() => src.ECPrivateKey.from(new Uint8Array(32).fill(0xff)).publicKey().toHex())}`,
      `X25519 sharedKeyWith(low-order point): ${outcome(() => src.X25519PrivateKey.random({ rng: rng() }).sharedKeyWith(src.X25519PublicKey.from(new Uint8Array(32))))}`,
      `SymmetricKey.decrypt(tampered tag): ${outcome(() => {
        const k = key();
        const m = k.encrypt(new Uint8Array(4), { nonce: src.Nonce.from(new Uint8Array(12)) });
        return k.decrypt(
          src.EncryptedMessage.from({
            ciphertext: m.ciphertext,
            nonce: m.nonce,
            authTag: src.AuthenticationTag.from(new Uint8Array(16)),
            aad: m.aad,
          }),
        );
      })}`,
      `new HKDFRng(km, salt, { pageLength: 1.5 }).nextU32(): ${outcome(() => new src.HKDFRng(new Uint8Array(16), "s", { pageLength: 1.5 }).nextU32())}`,
      `MLDSAPrivateKey.random(99): ${outcome(() => src.MLDSAPrivateKey.random(99 as never, { rng: rng() }))}`,
    ]).toMatchSnapshot();
  });

  it("B10: Seed metadata domain", () => {
    expect([
      `Seed.from(data, { name: 42 }).toCbor(): ${outcome(() =>
        hexOf(
          src.Seed.from(new Uint8Array(16), { name: 42 as never })
            .toCbor()
            .toData(),
        ),
      )}`,
      `Seed.fromCbor(map with a text at key 1): ${outcome(() => src.Seed.fromCbor(taggedValue(40300, cbor(new Map([[1, "abc"]])))))}`,
    ]).toMatchSnapshot();
  });
});
