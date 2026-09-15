/**
 * Deterministic RSA-2048 key generation, byte-identical to
 * `ssh-key` 0.6.7 `RsaKeypair::random(rng, 2048)`, which calls
 * `rsa::RsaPrivateKey::new(rng, 2048)` (`rsa` 0.9.10):
 *
 *   `RsaPrivateKey::new` -> `new_with_exp(rng, bits, 65537)` ->
 *   `algorithms::generate::generate_multi_prime_key_with_exp(rng, 2, bits, e)`
 *   -> `RsaPrivateKey::from_components(n, e, d, primes)` (validates and
 *   precomputes; the prime order is kept as generated).
 *
 * `generate_multi_prime_key_with_exp` for two primes:
 *   loop {
 *     p = rng.gen_prime(1024);            // 128 bytes per candidate
 *     q = rng.gen_prime(2048 - bits(p));  // = gen_prime(1024)
 *     if p == q            { continue }
 *     n = p * q; if bits(n) != 2048 { continue }
 *     d = e^-1 mod (p-1)(q-1); if none   { continue }   // Euler totient
 *     break
 *   }
 *
 * `ssh-key`'s `TryFrom<&rsa::RsaPrivateKey> for RsaKeypair` then stores
 * `n`, `e` (public) and `d`, `iqmp`, `p`, `q` (private) where
 * `p = primes()[0]`, `q = primes()[1]` and
 * `iqmp = crt_coefficient() = q^-1 mod p`. Each value is an `Mpint` built
 * with `Mpint::from_positive_bytes(BigUint::to_bytes_be())`, i.e. the
 * canonical positive big-endian bytes returned here.
 */

import type { KeygenRng } from "./keygen-rng.js";
import { bigintToBytes, bitLength, genPrime, modInverse } from "./bigint-math.js";
import { ComponentsError } from "../../error.js";

/** The public exponent `rsa::RsaPrivateKey::EXP`. */
export const RSA_PUBLIC_EXPONENT: bigint = 65537n;
/** Number of primes (`nprimes`) for a standard two-prime key. */
const RSA_NPRIMES = 2;

/** The RSA key components as canonical positive big-endian bytes (no leading zero). */
export interface RsaKeypairComponents {
  /** Modulus `p * q` (2048 bits). */
  n: Uint8Array;
  /** Public exponent (65537). */
  e: Uint8Array;
  /** Private exponent `e^-1 mod (p-1)(q-1)`. */
  d: Uint8Array;
  /** CRT coefficient `q^-1 mod p` (OpenSSH's `iqmp`). */
  iqmp: Uint8Array;
  /** First prime as generated (`primes()[0]`). */
  p: Uint8Array;
  /** Second prime as generated (`primes()[1]`). */
  q: Uint8Array;
}

/**
 * Generate an RSA keypair of `bits` bits from `rng`, consuming it exactly as
 * the reference does. With `new HKDFRng(seed, "ssh-rsa")` this reproduces
 * the key `PrivateKeyBase::ssh_signing_private_key(SSHAlgorithm::Rsa { hash:
 * None }, _)` derives.
 */
export function generateRsaKeypair(rng: KeygenRng, bits: 2048): RsaKeypairComponents {
  const e = RSA_PUBLIC_EXPONENT;
  for (;;) {
    let todo = bits;
    const primes: bigint[] = [];
    for (let i = 0; i < RSA_NPRIMES; i++) {
      const prime = genPrime(rng, Math.floor(todo / (RSA_NPRIMES - i)));
      todo -= bitLength(prime);
      primes.push(prime);
    }
    const [p, q] = primes;

    // Primes must be pairwise unequal.
    if (p === q) continue;

    const n = p * q;
    if (bitLength(n) !== bits) continue;

    // `compute_private_exponent_euler_totient`: d = e^-1 mod (p-1)(q-1).
    const d = modInverse(e, (p - 1n) * (q - 1n));
    if (d === undefined) continue;

    // `RsaPrivateKey::crt_coefficient`: primes[1]^-1 mod primes[0].
    const iqmp = modInverse(q, p);
    if (iqmp === undefined) {
      throw ComponentsError.ssh("generateRsaKeypair: q has no inverse modulo p");
    }

    return {
      n: bigintToBytes(n),
      e: bigintToBytes(e),
      d: bigintToBytes(d),
      iqmp: bigintToBytes(iqmp),
      p: bigintToBytes(p),
      q: bigintToBytes(q),
    };
  }
}
