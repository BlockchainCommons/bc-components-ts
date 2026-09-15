/**
 * Deterministic DSA-1024/160 key generation, byte-identical to
 * `ssh-key` 0.6.7 `DsaKeypair::random`, which runs
 * `dsa::Components::generate(rng, KeySize::DSA_1024_160)` followed by
 * `dsa::SigningKey::generate(rng, components)` (`dsa` 0.6.3,
 * `src/generate/components.rs` and `src/generate/keypair.rs`).
 *
 * RNG consumption, in order:
 *   1. `q`: `gen_prime(160)` draws 20 bytes per candidate until a prime
 *      with exactly 160 bits is found.
 *   2. `p`: up to 4096 attempts per `q`; each draws 128 bytes with
 *      `gen_biguint(1024)` (redrawn while `m <= 2^1023` or `m >= 2^1024`),
 *      sets `p = m - (m mod 2q) + 1` and tests `probably_prime(p, 64)`.
 *      If all 4096 attempts fail, a new `q` is drawn.
 *   3. `g`: no RNG; `h = 1, 2, ...` until `h^((p-1)/q) mod p != 1`
 *      (FIPS 186-4 Appendix A.2.1, unverifiable generation).
 *   4. `x`: `gen_biguint_range(1, q)` = `1 + gen_biguint_below(q - 1)`,
 *      20 bytes per attempt.
 *   5. `y = g^x mod p`.
 *
 * DSA with a 160-bit `q` is cryptographically obsolete; this exists only
 * for parity with the reference implementation.
 */

import type { KeygenRng } from "./keygen-rng.js";
import {
  bigintToBytes,
  genBiguint,
  genBiguintRange,
  genPrime,
  modPow,
  probablyPrime,
} from "./bigint-math.js";

/** Bit size of `p` (`KeySize::DSA_1024_160.l`). */
const DSA_L = 1024;
/** Bit size of `q` (`KeySize::DSA_1024_160.n`). */
const DSA_N = 160;
/** Miller-Rabin rounds the `dsa` crate uses when testing `p` (`MR_ROUNDS`). */
const DSA_P_MR_ROUNDS = 64;
/** Attempts at finding `p` for one `q` before drawing a new `q`. */
const DSA_P_ATTEMPTS_PER_Q = 4096;

/** The DSA key components as canonical positive big-endian bytes (no leading zero). */
export interface DsaKeypairComponents {
  /** Prime modulus (1024 bits). */
  p: Uint8Array;
  /** Prime subgroup order (160 bits). */
  q: Uint8Array;
  /** Generator of the order-`q` subgroup. */
  g: Uint8Array;
  /** Public value `g^x mod p`. */
  y: Uint8Array;
  /** Secret exponent in `[1, q-1]`. */
  x: Uint8Array;
}

/** `dsa::generate::calculate_bounds(size)`: `(2^(size-1), 2^size)`. */
function bounds(size: number): [bigint, bigint] {
  return [1n << BigInt(size - 1), 1n << BigInt(size)];
}

/** `dsa::generate::components::common` for L = 1024, N = 160: returns `(p, q)`. */
function generatePQ(rng: KeygenRng): { p: bigint; q: bigint } {
  const [pMin, pMax] = bounds(DSA_L);
  const [qMin, qMax] = bounds(DSA_N);
  for (;;) {
    const q = genPrime(rng, DSA_N);
    if (q < qMin || q > qMax) continue;
    const twoQ = 2n * q;
    for (let attempt = 0; attempt < DSA_P_ATTEMPTS_PER_Q; attempt++) {
      let m: bigint;
      for (;;) {
        m = genBiguint(rng, DSA_L);
        if (m > pMin && m < pMax) break;
      }
      const p = m - (m % twoQ) + 1n;
      if (probablyPrime(p, DSA_P_MR_ROUNDS)) return { p, q };
    }
  }
}

/**
 * Generate a DSA-1024/160 keypair from `rng`, consuming it exactly as the
 * reference does. With `new HKDFRng(seed, "ssh-dss")` this reproduces the
 * key `PrivateKeyBase::ssh_signing_private_key(SSHAlgorithm::Dsa, _)` derives.
 */
export function generateDsaKeypair(rng: KeygenRng): DsaKeypairComponents {
  const { p, q } = generatePQ(rng);

  const e = (p - 1n) / q;
  let h = 1n;
  let g: bigint;
  for (;;) {
    g = modPow(h, e, p);
    if (g !== 1n) break;
    h += 1n;
  }

  const x = genBiguintRange(rng, 1n, q);
  const y = modPow(g, x, p);

  return {
    p: bigintToBytes(p),
    q: bigintToBytes(q),
    g: bigintToBytes(g),
    y: bigintToBytes(y),
    x: bigintToBytes(x),
  };
}
