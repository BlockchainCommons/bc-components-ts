/**
 * Big-integer helpers for deterministic SSH key generation.
 *
 * Everything here is a port of the Rust code that `ssh-key` 0.6.7 runs when
 * it generates DSA and RSA keys, so that the same random source yields the
 * same primes:
 *
 *   - `num-bigint-dig` 0.8.6 `src/bigrand.rs`: `RandBigInt::gen_biguint`,
 *     `gen_biguint_below`, `gen_biguint_range` and `RandPrime::gen_prime`
 *     (candidate drawing, top-bit forcing, small-prime sieve).
 *   - `num-bigint-dig` 0.8.6 `src/prime.rs`: `probably_prime`
 *     (trial division + Miller-Rabin + "almost extra strong" Lucas), which
 *     is itself a port of Go's `big.Int.ProbablyPrime`.
 *   - `num-bigint-dig` 0.8.6 `src/algorithms/jacobi.rs` and
 *     `mod_inverse.rs`.
 *   - `rand` 0.8 `StdRng` = `rand_chacha` 0.3.1 `ChaCha12Rng`, seeded with
 *     `rand_core` 0.6.4 `SeedableRng::seed_from_u64`, which is the source of
 *     the Miller-Rabin bases. It is seeded from the candidate itself, not
 *     from the caller's RNG, so the caller's RNG is never touched by the
 *     primality test.
 *
 * `num-bigint-dig` is compiled without its `u64_digit` feature in the
 * reference build (`ssh-key` pulls `dsa` and `rsa` with default features
 * off), so limbs are 32 bits wide. That affects how many bytes
 * `gen_biguint` consumes for bit sizes that are not a multiple of 64 and
 * which bits seed the Miller-Rabin RNG; see `LIMB_BITS`.
 *
 * All arithmetic is plain JS `bigint` and is not constant-time, matching
 * the (also variable-time) reference crates.
 */

import { ComponentsError } from "../../error.js";

/** A byte source; both `KeygenRng` and the Miller-Rabin base RNG satisfy it. */
export interface ByteSource {
  fillBytes(dest: Uint8Array): void;
}

/** Width of a `num-bigint-dig` `BigDigit` in the reference build. */
export const LIMB_BITS: number = 32;

const LIMB_BYTES = LIMB_BITS / 8;
const LIMB_MASK = (1n << BigInt(LIMB_BITS)) - 1n;
const MASK32 = 0xffffffffn;
const MASK64 = 0xffffffffffffffffn;

// ---------------------------------------------------------------------------
// Byte conversion
// ---------------------------------------------------------------------------

/** Big-endian bytes to a non-negative bigint. */
export function bytesToBigint(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

/** Little-endian bytes to a non-negative bigint. */
export function bytesToBigintLE(bytes: Uint8Array): bigint {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

/**
 * Minimal big-endian encoding of a non-negative bigint (no leading zero
 * byte), the form `BigUint::to_bytes_be` produces and `Mpint::as_positive_bytes`
 * returns. Zero encodes as an empty array.
 */
export function bigintToBytes(v: bigint): Uint8Array {
  if (v < 0n) {
    throw ComponentsError.ssh("bigintToBytes: negative value");
  }
  if (v === 0n) return new Uint8Array(0);
  let hex = v.toString(16);
  if (hex.length % 2 === 1) hex = `0${hex}`;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Big-endian encoding padded on the left to exactly `len` bytes. */
export function bigintToBytesFixed(v: bigint, len: number): Uint8Array {
  const min = bigintToBytes(v);
  if (min.length > len) {
    throw ComponentsError.ssh(`bigintToBytesFixed: value needs ${min.length} bytes > ${len}`);
  }
  const out = new Uint8Array(len);
  out.set(min, len - min.length);
  return out;
}

// ---------------------------------------------------------------------------
// Elementary arithmetic
// ---------------------------------------------------------------------------

/** Number of significant bits (`BigUint::bits`); 0 for zero. */
export function bitLength(v: bigint): number {
  if (v === 0n) return 0;
  const hex = v.toString(16);
  return (hex.length - 1) * 4 + (32 - Math.clz32(parseInt(hex[0], 16)));
}

/** Number of trailing zero bits (`BigUint::trailing_zeros`); `v` must be non-zero. */
export function trailingZeros(v: bigint): number {
  if (v === 0n) {
    throw ComponentsError.ssh("trailingZeros: zero has no trailing-zero count");
  }
  let n = 0;
  let x = v;
  while ((x & 0xffffffffn) === 0n) {
    x >>= 32n;
    n += 32;
  }
  while ((x & 1n) === 0n) {
    x >>= 1n;
    n += 1;
  }
  return n;
}

/** `base ** exp mod mod` by 4-bit fixed-window exponentiation. */
export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod <= 0n) {
    throw ComponentsError.ssh("modPow: modulus must be positive");
  }
  if (mod === 1n) return 0n;
  if (exp < 0n) {
    throw ComponentsError.ssh("modPow: negative exponent");
  }
  let b = base % mod;
  if (b < 0n) b += mod;
  if (exp === 0n) return 1n;
  const table: bigint[] = [1n, b];
  for (let i = 2; i < 16; i++) table.push((table[i - 1] * b) % mod);
  let result = 1n;
  const nibbles = exp.toString(16);
  for (let i = 0; i < nibbles.length; i++) {
    if (i > 0) {
      result = (result * result) % mod;
      result = (result * result) % mod;
      result = (result * result) % mod;
      result = (result * result) % mod;
    }
    const nib = parseInt(nibbles[i], 16);
    if (nib !== 0) result = (result * table[nib]) % mod;
  }
  return result;
}

/**
 * Modular inverse of `a` modulo `m` in `[0, m)`, or `undefined` when
 * `gcd(a, m) != 1` (`num-bigint-dig` `mod_inverse` returns `None` then).
 */
export function modInverse(a: bigint, m: bigint): bigint | undefined {
  if (m <= 0n) {
    throw ComponentsError.ssh("modInverse: modulus must be positive");
  }
  let oldR = ((a % m) + m) % m;
  let r = m;
  let oldS = 1n;
  let s = 0n;
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) return undefined;
  return ((oldS % m) + m) % m;
}

/** Floor of the square root (`Roots::sqrt` for `BigUint`). */
export function isqrt(n: bigint): bigint {
  if (n < 0n) {
    throw ComponentsError.ssh("isqrt: negative value");
  }
  if (n < 2n) return n;
  let x = 1n << BigInt(Math.ceil(bitLength(n) / 2));
  for (;;) {
    const y = (x + n / x) >> 1n;
    if (y >= x) return x;
    x = y;
  }
}

/**
 * Jacobi symbol `(x / y)` for `x >= 0` and odd `y > 0`
 * (`num-bigint-dig` `algorithms::jacobi`).
 */
export function jacobi(x: bigint, y: bigint): number {
  if (x < 0n || y <= 0n || (y & 1n) === 0n) {
    throw ComponentsError.ssh("jacobi: requires x >= 0 and odd y > 0");
  }
  let a = x;
  let b = y;
  let j = 1;
  for (;;) {
    if (b === 1n) return j;
    if (a === 0n) return 0;
    a %= b;
    if (a === 0n) return 0;
    const s = trailingZeros(a);
    if ((s & 1) !== 0) {
      const bmod8 = Number(b & 7n);
      if (bmod8 === 3 || bmod8 === 5) j = -j;
    }
    const c = a >> BigInt(s);
    if ((b & 3n) === 3n && (c & 3n) === 3n) j = -j;
    a = b;
    b = c;
  }
}

// ---------------------------------------------------------------------------
// Miller-Rabin base RNG: rand 0.8 `StdRng` (`ChaCha12Rng`) via `seed_from_u64`
// ---------------------------------------------------------------------------

const CHACHA_CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
const CHACHA_DOUBLE_ROUNDS = 6; // ChaCha12
const CHACHA_WORDS_PER_REFILL = 64; // rand_chacha refills 4 blocks of 16 words
const PCG32_MUL = 6364136223846793005n;
const PCG32_INC = 11634580027462260723n;

function rotl32(v: number, c: number): number {
  return ((v << c) | (v >>> (32 - c))) >>> 0;
}

function quarterRound(x: Uint32Array, a: number, b: number, c: number, d: number): void {
  x[a] = x[a] + x[b];
  x[d] = rotl32(x[d] ^ x[a], 16);
  x[c] = x[c] + x[d];
  x[b] = rotl32(x[b] ^ x[c], 12);
  x[a] = x[a] + x[b];
  x[d] = rotl32(x[d] ^ x[a], 8);
  x[c] = x[c] + x[d];
  x[b] = rotl32(x[b] ^ x[c], 7);
}

/**
 * `rand_chacha` 0.3.1 `ChaCha12Rng` as driven by `rand_core` 0.6.4
 * `BlockRng::fill_bytes`: key = seed, 64-bit block counter starting at 0,
 * nonce 0, words emitted little-endian, and a partially consumed word is
 * discarded rather than resumed.
 */
export class MillerRabinBaseRng implements ByteSource {
  private readonly key = new Uint32Array(8);
  private blockPos = 0n;
  private readonly results = new Uint32Array(CHACHA_WORDS_PER_REFILL);
  private index = CHACHA_WORDS_PER_REFILL;

  /** `SeedableRng::from_seed` with a 32-byte seed. */
  constructor(seed: Uint8Array) {
    if (seed.length !== 32) {
      throw ComponentsError.ssh("MillerRabinBaseRng: seed must be 32 bytes");
    }
    for (let i = 0; i < 8; i++) {
      this.key[i] =
        (seed[i * 4] |
          (seed[i * 4 + 1] << 8) |
          (seed[i * 4 + 2] << 16) |
          (seed[i * 4 + 3] << 24)) >>>
        0;
    }
  }

  /** `rand_core` 0.6.4 `SeedableRng::seed_from_u64`: PCG32 expands the u64 into the seed. */
  static seedFromU64(state: bigint): MillerRabinBaseRng {
    const seed = new Uint8Array(32);
    let s = state & MASK64;
    for (let i = 0; i < 8; i++) {
      s = (s * PCG32_MUL + PCG32_INC) & MASK64;
      const xorshifted = Number((((s >> 18n) ^ s) >> 27n) & MASK32);
      const rot = Number(s >> 59n);
      const x = rot === 0 ? xorshifted : ((xorshifted >>> rot) | (xorshifted << (32 - rot))) >>> 0;
      seed[i * 4] = x & 0xff;
      seed[i * 4 + 1] = (x >>> 8) & 0xff;
      seed[i * 4 + 2] = (x >>> 16) & 0xff;
      seed[i * 4 + 3] = (x >>> 24) & 0xff;
    }
    return new MillerRabinBaseRng(seed);
  }

  private refill(): void {
    const input = new Uint32Array(16);
    const x = new Uint32Array(16);
    for (let blk = 0; blk < 4; blk++) {
      const ctr = this.blockPos + BigInt(blk);
      input.set(CHACHA_CONSTANTS, 0);
      input.set(this.key, 4);
      input[12] = Number(ctr & MASK32);
      input[13] = Number((ctr >> 32n) & MASK32);
      input[14] = 0;
      input[15] = 0;
      x.set(input);
      for (let r = 0; r < CHACHA_DOUBLE_ROUNDS; r++) {
        quarterRound(x, 0, 4, 8, 12);
        quarterRound(x, 1, 5, 9, 13);
        quarterRound(x, 2, 6, 10, 14);
        quarterRound(x, 3, 7, 11, 15);
        quarterRound(x, 0, 5, 10, 15);
        quarterRound(x, 1, 6, 11, 12);
        quarterRound(x, 2, 7, 8, 13);
        quarterRound(x, 3, 4, 9, 14);
      }
      for (let i = 0; i < 16; i++) this.results[blk * 16 + i] = x[i] + input[i];
    }
    this.blockPos = (this.blockPos + 4n) & MASK64;
    this.index = 0;
  }

  fillBytes(dest: Uint8Array): void {
    let readLen = 0;
    while (readLen < dest.length) {
      if (this.index >= CHACHA_WORDS_PER_REFILL) this.refill();
      const available = (CHACHA_WORDS_PER_REFILL - this.index) * 4;
      const byteLen = Math.min(available, dest.length - readLen);
      for (let i = 0; i < byteLen; i++) {
        const w = this.results[this.index + (i >> 2)];
        dest[readLen + i] = (w >>> ((i & 3) * 8)) & 0xff;
      }
      this.index += Math.ceil(byteLen / 4);
      readLen += byteLen;
    }
  }
}

// ---------------------------------------------------------------------------
// Random big integers: num-bigint-dig `RandBigInt`
// ---------------------------------------------------------------------------

/**
 * `RandBigInt::gen_biguint(bit_size)`: fill `ceil(bit_size / LIMB_BITS)`
 * little-endian limbs from the source, then shift the top limb right so
 * that only `bit_size` bits remain.
 */
export function genBiguint(src: ByteSource, bitSize: number): bigint {
  const digits = Math.floor(bitSize / LIMB_BITS);
  const rem = bitSize % LIMB_BITS;
  const limbs = digits + (rem > 0 ? 1 : 0);
  const bytes = new Uint8Array(limbs * LIMB_BYTES);
  src.fillBytes(bytes);
  let v = bytesToBigintLE(bytes);
  if (rem > 0) {
    const shift = BigInt(digits * LIMB_BITS);
    const low = v & ((1n << shift) - 1n);
    const top = (v >> shift) >> BigInt(LIMB_BITS - rem);
    v = low | (top << shift);
  }
  return v;
}

/** `RandBigInt::gen_biguint_below(bound)`: rejection sampling at `bound.bits()` bits. */
export function genBiguintBelow(src: ByteSource, bound: bigint): bigint {
  if (bound <= 0n) {
    throw ComponentsError.ssh("genBiguintBelow: bound must be positive");
  }
  const bits = bitLength(bound);
  for (;;) {
    const n = genBiguint(src, bits);
    if (n < bound) return n;
  }
}

/** `RandBigInt::gen_biguint_range(lbound, ubound)`: `[lbound, ubound)`. */
export function genBiguintRange(src: ByteSource, lbound: bigint, ubound: bigint): bigint {
  if (lbound >= ubound) {
    throw ComponentsError.ssh("genBiguintRange: empty range");
  }
  if (lbound === 0n) return genBiguintBelow(src, ubound);
  return lbound + genBiguintBelow(src, ubound - lbound);
}

// ---------------------------------------------------------------------------
// Primality: num-bigint-dig `prime::probably_prime`
// ---------------------------------------------------------------------------

const PRIMES_A = 3n * 5n * 7n * 11n * 13n * 17n * 19n * 23n * 37n;
const PRIMES_B = 29n * 31n * 41n * 43n * 47n * 53n;
const PRIMES_A_FACTORS = [3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 37n];
const PRIMES_B_FACTORS = [29n, 31n, 41n, 43n, 47n, 53n];

/** Bit `i` set iff `i` is a prime below 64. */
const PRIME_BIT_MASK =
  (1n << 2n) |
  (1n << 3n) |
  (1n << 5n) |
  (1n << 7n) |
  (1n << 11n) |
  (1n << 13n) |
  (1n << 17n) |
  (1n << 19n) |
  (1n << 23n) |
  (1n << 29n) |
  (1n << 31n) |
  (1n << 37n) |
  (1n << 41n) |
  (1n << 43n) |
  (1n << 47n) |
  (1n << 53n) |
  (1n << 59n) |
  (1n << 61n);

/**
 * `probably_prime(x, n)`: `n` pseudo-random Miller-Rabin rounds plus one
 * forced base-2 round, followed by the Lucas test (Baillie-PSW).
 */
export function probablyPrime(x: bigint, n: number): boolean {
  if (x === 0n) return false;
  if (x < 64n) return ((PRIME_BIT_MASK >> x) & 1n) === 1n;
  if ((x & 1n) === 0n) return false;
  const rA = x % PRIMES_A;
  const rB = x % PRIMES_B;
  for (const p of PRIMES_A_FACTORS) if (rA % p === 0n) return false;
  for (const p of PRIMES_B_FACTORS) if (rB % p === 0n) return false;
  return probablyPrimeMillerRabin(x, n + 1, true) && probablyPrimeLucas(x);
}

/**
 * `probably_prime_miller_rabin(n, reps, force2)`: bases are drawn from a
 * `StdRng` seeded with the lowest limb of `n`; the last round uses base 2
 * when `force2` is set.
 */
export function probablyPrimeMillerRabin(n: bigint, reps: number, force2: boolean): boolean {
  const nm1 = n - 1n;
  const k = trailingZeros(nm1);
  const q = nm1 >> BigInt(k);
  const nm3 = n - 2n;
  const rng = MillerRabinBaseRng.seedFromU64(n & LIMB_MASK);
  nextRandom: for (let i = 0; i < reps; i++) {
    const x = i === reps - 1 && force2 ? 2n : genBiguintBelow(rng, nm3) + 2n;
    let y = modPow(x, q, n);
    if (y === 1n || y === nm1) continue;
    for (let j = 1; j < k; j++) {
      y = (y * y) % n;
      if (y === nm1) continue nextRandom;
      if (y === 1n) return false;
    }
    return false;
  }
  return true;
}

/**
 * `probably_prime_lucas(n)`: the "almost extra strong" Lucas probable-prime
 * test with Baillie-OEIS method C parameter selection.
 */
export function probablyPrimeLucas(n: bigint): boolean {
  if (n === 0n || n === 1n) return false;
  if (n === 2n) return false;

  let p = 3n;
  for (;;) {
    if (p > 10000n) {
      throw ComponentsError.ssh(`probablyPrimeLucas: cannot find (D/n) = -1 for ${n.toString(16)}`);
    }
    const d = p * p - 4n;
    const j = jacobi(d, n);
    if (j === -1) break;
    if (j === 0) return n === p + 2n;
    if (p === 40n) {
      const t = isqrt(n);
      if (t * t === n) return false;
    }
    p += 1n;
  }

  let s = n + 1n;
  const r = trailingZeros(s);
  s >>= BigInt(r);
  const nm2 = n - 2n;

  let vk = 2n;
  let vk1 = p;
  for (let i = bitLength(s) - 1; i >= 0; i--) {
    if (((s >> BigInt(i)) & 1n) === 1n) {
      vk = (vk * vk1 + n - p) % n;
      vk1 = (vk1 * vk1 + nm2) % n;
    } else {
      vk1 = (vk * vk1 + n - p) % n;
      vk = (vk * vk + nm2) % n;
    }
  }

  if (vk === 2n || vk === nm2) {
    let t1 = vk * p;
    let t2 = vk1 << 1n;
    if (t1 < t2) [t1, t2] = [t2, t1];
    t1 -= t2;
    if (t1 % n === 0n) return true;
  }

  for (let t = 0; t < r - 1; t++) {
    if (vk === 0n) return true;
    if (vk === 2n) return false;
    vk = (((vk * vk - 2n) % n) + n) % n;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Random primes: num-bigint-dig `RandPrime::gen_prime`
// ---------------------------------------------------------------------------

const SMALL_PRIMES = [3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n, 53n];
const SMALL_PRIMES_PRODUCT = 16294579238595022365n;
const GEN_PRIME_DELTA_LIMIT = 1 << 20;

/**
 * `RandPrime::gen_prime(bit_size)`: draw `ceil(bit_size / 8)` bytes, force
 * the top two bits and the low bit, step the candidate forward by even
 * deltas until it is coprime to the small primes, then accept it if it
 * still has `bit_size` bits and passes `probably_prime(_, 20)`.
 */
export function genPrime(src: ByteSource, bitSize: number): bigint {
  if (bitSize < 2) {
    throw ComponentsError.ssh("genPrime: prime size must be at least 2 bits");
  }
  let b = bitSize % 8;
  if (b === 0) b = 8;
  const bytesLen = Math.ceil(bitSize / 8);
  const bytes = new Uint8Array(bytesLen);

  for (;;) {
    src.fillBytes(bytes);
    bytes[0] &= (1 << b) - 1;
    if (b >= 2) {
      bytes[0] |= (3 << (b - 2)) & 0xff;
    } else {
      bytes[0] |= 1;
      if (bytesLen > 1) bytes[1] |= 0x80;
    }
    bytes[bytesLen - 1] |= 1;

    let p = bytesToBigint(bytes);
    const rem = p % SMALL_PRIMES_PRODUCT;

    for (let delta = 0; delta < GEN_PRIME_DELTA_LIMIT; delta += 2) {
      const m = rem + BigInt(delta);
      let divisible = false;
      for (const prime of SMALL_PRIMES) {
        if (m % prime === 0n && (bitSize > 6 || m !== prime)) {
          divisible = true;
          break;
        }
      }
      if (divisible) continue;
      if (delta > 0) p += BigInt(delta);
      break;
    }

    if (bitLength(p) === bitSize && probablyPrime(p, 20)) return p;
  }
}
