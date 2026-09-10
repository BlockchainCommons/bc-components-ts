/**
 * Baseline vs working tree micro-benchmarks (Phase 2.3).
 *
 *   bun run build && bun bench/benchmark.mjs
 */
import * as baseline from "../tests/baseline/components-baseline.mjs";
import * as current from "../dist/index.mjs";

const seed = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);
const msg = Uint8Array.from({ length: 256 }, (_, i) => (i * 13 + 1) & 0xff);
const kib = Uint8Array.from({ length: 1024 }, (_, i) => (i * 31 + 5) & 0xff);
const rng = {
  fillRandomData(d) {
    for (let i = 0; i < d.length; i++) d[i] = (i * 31 + 11) & 0xff;
  },
  fillBytes(d) {
    this.fillRandomData(d);
  },
  randomData(n) {
    const d = new Uint8Array(n);
    this.fillRandomData(d);
    return d;
  },
  nextU32() {
    return 0x12345678;
  },
  nextU64() {
    return 0x12345678n;
  },
};

function time(fn, iters = 5) {
  fn();
  let best = Infinity;
  for (let i = 0; i < iters; i++) {
    const t0 = performance.now();
    fn();
    best = Math.min(best, performance.now() - t0);
  }
  return best;
}
const both = (make) => [make(baseline), make(current)];
const cases = {
  "PrivateKeyBase(seed) → schnorr keys + x25519 ×200": both((m) => () => {
    for (let i = 0; i < 200; i++) {
      const b = m.PrivateKeyBase.fromData(seed);
      b.schnorrPrivateKeys();
      b.schnorrPublicKeys();
      b.encapsulationPrivateKey();
    }
  }),
  "schnorr sign+verify ×200": both((m) => {
    const k = m.SigningPrivateKey.newSchnorr(m.ECPrivateKey.fromData(seed));
    const p = k.publicKey();
    return () => {
      for (let i = 0; i < 200; i++) p.verify(k.schnorrSign(msg, rng), msg);
    };
  }),
  "ecdsa sign+verify ×200": both((m) => {
    const k = m.SigningPrivateKey.newEcdsa(m.ECPrivateKey.fromData(seed));
    const p = k.publicKey();
    return () => {
      for (let i = 0; i < 200; i++) p.verify(k.sign(msg), msg);
    };
  }),
  "ed25519 sign+verify ×200": both((m) => {
    const k = m.SigningPrivateKey.newEd25519(m.Ed25519PrivateKey.from(seed));
    const p = k.publicKey();
    return () => {
      for (let i = 0; i < 200; i++) p.verify(k.sign(msg), msg);
    };
  }),
  "x25519 seal+open ×200": both((m) => {
    const b = m.PrivateKeyBase.fromData(seed);
    const priv = b.encapsulationPrivateKey();
    const pub = priv.publicKey();
    return () => {
      for (let i = 0; i < 200; i++) m.SealedMessage.new(msg, pub).decrypt(priv);
    };
  }),
  "Digest.fromImage(1 KiB) ×5000": both((m) => () => {
    for (let i = 0; i < 5000; i++) m.Digest.fromImage(kib);
  }),
  "Seed tagged CBOR encode (fresh) ×5000": both((m) => () => {
    for (let i = 0; i < 5000; i++)
      m.Seed.from(seed, { name: "bench", note: "note" }).taggedCborData();
  }),
  "XID.fromPublicKeys(same keys) ×5000": both((m) => {
    const pk = m.PrivateKeyBase.fromData(seed).schnorrPublicKeys();
    return () => {
      for (let i = 0; i < 5000; i++) m.XID.fromPublicKeys(pk);
    };
  }),
  "SigningPublicKey.taggedCborData (same key) ×20000": both((m) => {
    const pk = m.PrivateKeyBase.fromData(seed).schnorrPublicKeys().signingPublicKey();
    return () => {
      for (let i = 0; i < 20000; i++) pk.taggedCborData();
    };
  }),
};
console.log(
  `${"case".padEnd(52)} ${"baseline".padStart(10)} ${"current".padStart(10)} ${"speedup".padStart(8)}`,
);
for (const [name, [b, c]] of Object.entries(cases)) {
  const tb = time(b),
    tc = time(c);
  console.log(
    `${name.padEnd(52)} ${tb.toFixed(1).padStart(8)}ms ${tc.toFixed(1).padStart(8)}ms ${(tb / tc).toFixed(2).padStart(7)}×`,
  );
}
