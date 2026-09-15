/**
 * SSH-DSA digital signature algorithm (FIPS 186-4 §4) with the `dsa`
 * crate's deterministic k generation (RFC 6979 with the DRBG seeded by the
 * minimal encoding of the private key), so signatures are byte-identical to
 * the reference given the same key + message + hash.
 *
 * Used only for SSH-DSA (`ssh-dss`):
 *   - q is 160 bits
 *   - hash is SHA-1 (also used as HMAC hash for RFC 6979)
 *   - signature is fixed 40 bytes: r (20) || s (20)
 *
 * Note: DSA with q=160 / SHA-1 is cryptographically deprecated. We
 * support it only for parity with the reference implementation's SSH
 * keygen path, which itself is feature-gated and primarily used in
 * legacy-interop tests. Do NOT use this module for new keys.
 */

import { sha1 } from "@noble/hashes/legacy.js";
import { hmac } from "@noble/hashes/hmac.js";
import { ComponentsError } from "../../error.js";

// ----------------------------------------------------------------------------
// Modular-arithmetic helpers (BigInt — not constant-time, matches the reference's `dsa` crate)
// ----------------------------------------------------------------------------

function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  let result = 1n;
  let b = base % mod;
  if (b < 0n) b += mod;
  let e = exp;
  while (e > 0n) {
    if ((e & 1n) !== 0n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

/** The inverse of `a` modulo `m`, or `undefined` when `gcd(a, m) != 1` (`ModInverse`). */
function tryModinv(a: bigint, m: bigint): bigint | undefined {
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

function modinv(a: bigint, m: bigint): bigint {
  const inverse = tryModinv(a, m);
  if (inverse === undefined) throw ComponentsError.ssh("dsa: modular inverse does not exist");
  return inverse;
}

function bytesToBigint(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

function bigintToBytesFixed(v: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let n = v;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (n !== 0n) {
    throw ComponentsError.ssh(`dsa: integer does not fit in ${len} bytes`);
  }
  return out;
}

function concatBytes(...arrs: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let pos = 0;
  for (const a of arrs) {
    out.set(a, pos);
    pos += a.length;
  }
  return out;
}

// ----------------------------------------------------------------------------
// Deterministic k generation (the `dsa` crate's RFC 6979 variant)
// ----------------------------------------------------------------------------

/**
 * `bits2int` per RFC 6979 §2.3.2: interpret the input bits as a big-endian
 * integer, truncating the rightmost bits if the bit length exceeds qlen.
 */
function bits2int(input: Uint8Array, qlenBits: number): bigint {
  let v = bytesToBigint(input);
  const inputBits = input.length * 8;
  if (inputBits > qlenBits) {
    v >>= BigInt(inputBits - qlenBits);
  }
  return v;
}

/**
 * The per-signature nonce `k` and its inverse, as the `dsa` crate 0.6.3
 * computes them (`generate/secret_number.rs`, `secret_number_rfc6979`)
 * over `rfc6979` 0.4.0's `HmacDrbg` with HMAC-SHA-1:
 *
 * - the DRBG entropy is the **minimal** big-endian encoding of `x` (no
 *   leading zero bytes; `x = 1` seeds with the single byte `01`), which is
 *   where the crate departs from RFC 6979 §2.3.3's fixed-width `int2octets`;
 * - the DRBG nonce is `reduce_hash`: the first `floor(bits(q) / 8)` bytes of
 *   the digest, reduced modulo `q`, left-padded to that width;
 * - each candidate is `floor(bits(q) / 8)` DRBG bytes; it is accepted when it
 *   has an inverse modulo `q` and `0 < k < q`.
 *
 * Signatures over a private key whose top byte is zero therefore match the
 * reference only with this seeding.
 */
function rfc6979Nonce(q: bigint, x: bigint, hashedMessage: Uint8Array): [bigint, bigint] {
  const kSize = Math.floor(q.toString(2).length / 8);
  const entropy = minimalBigEndian(x);
  const nonce = reduceHash(q, hashedMessage, kSize);
  const drbg = new HmacDrbgSha1(entropy, nonce);
  const buffer = new Uint8Array(kSize);
  for (let iter = 0; iter < 1024; iter++) {
    drbg.fillBytes(buffer);
    const k = bytesToBigint(buffer);
    const inverse = tryModinv(k, q);
    if (inverse !== undefined && k > 0n && k < q) return [k, inverse];
  }
  throw ComponentsError.ssh("dsa: RFC 6979 failed to produce a valid k after 1024 iterations");
}

/** `dsa` 0.6.3 `reduce_hash`: the leading `qByteLen` digest bytes modulo `q`, left-padded. */
function reduceHash(q: bigint, hash: Uint8Array, qByteLen: number): Uint8Array {
  const head = hash.subarray(0, Math.min(hash.length, qByteLen));
  return bigintToBytesFixed(bytesToBigint(head) % q, qByteLen);
}

/** The shortest big-endian encoding of `v` (`BigUint::to_bytes_be`; zero is one `00` byte). */
function minimalBigEndian(v: bigint): Uint8Array {
  let hex = v.toString(16);
  if (hex.length % 2 === 1) hex = `0${hex}`;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return out;
}

/** `rfc6979` 0.4.0 `HmacDrbg<Sha1>`: `new(entropy, nonce, [])` and `fill_bytes`. */
class HmacDrbgSha1 {
  private k: Uint8Array;
  private v: Uint8Array;

  constructor(entropy: Uint8Array, nonce: Uint8Array) {
    this.k = new Uint8Array(20);
    this.v = new Uint8Array(20).fill(0x01);
    for (let i = 0; i <= 1; i++) {
      this.k = hmac(sha1, this.k, concatBytes(this.v, new Uint8Array([i]), entropy, nonce));
      this.v = hmac(sha1, this.k, this.v);
    }
  }

  fillBytes(out: Uint8Array): void {
    for (let offset = 0; offset < out.length; offset += this.v.length) {
      this.v = hmac(sha1, this.k, this.v);
      const take = Math.min(this.v.length, out.length - offset);
      out.set(this.v.subarray(0, take), offset);
    }
    this.k = hmac(sha1, this.k, concatBytes(this.v, new Uint8Array([0x00])));
    this.v = hmac(sha1, this.k, this.v);
  }
}

// ----------------------------------------------------------------------------
// Public API
// ----------------------------------------------------------------------------

export interface DsaPublicParams {
  p: Uint8Array;
  q: Uint8Array;
  g: Uint8Array;
  y: Uint8Array;
}

export interface DsaSignParams extends DsaPublicParams {
  /** Private exponent (canonical positive bytes, no sign byte). */
  x: Uint8Array;
  /** Hash digest of the message (SHA-1 for SSH-DSA). */
  messageDigest: Uint8Array;
}

export interface DsaVerifyParams extends DsaPublicParams {
  messageDigest: Uint8Array;
  /** 40-byte signature (r || s), each 20 bytes for q=160. */
  signature: Uint8Array;
}

/**
 * Sign `messageDigest` with the DSA private key, returning a fixed-length
 * `r || s` signature. Uses RFC 6979 deterministic `k` so signatures match
 * the reference implementation's `dsa` crate byte-for-byte.
 *
 * Output length is `2 * (qlen / 8)` = 40 bytes for SSH-DSA-1024.
 */
export function dsaSign(params: DsaSignParams): Uint8Array {
  const p = bytesToBigint(params.p);
  const q = bytesToBigint(params.q);
  const g = bytesToBigint(params.g);
  const x = bytesToBigint(params.x);
  const qlenBits = q.toString(2).length;
  const rolen = Math.ceil(qlenBits / 8);

  // Loop in case (r, s) hits the (rare) degenerate case where r=0 or s=0.
  // RFC 6979 §3.2 defines the next-k recovery as continuing the HMAC
  // chain — but for q=160 + SHA-1 the probability of this is ~2^-160, so
  // we treat it as fatal here.
  const [k, kInv] = rfc6979Nonce(q, x, params.messageDigest);
  const r = modpow(g, k, p) % q;
  if (r === 0n) {
    throw ComponentsError.ssh("dsa: degenerate signature with r=0");
  }
  const z = bits2int(params.messageDigest, qlenBits);
  const s = (kInv * (z + x * r)) % q;
  if (s === 0n) {
    throw ComponentsError.ssh("dsa: degenerate signature with s=0");
  }

  const out = new Uint8Array(rolen * 2);
  out.set(bigintToBytesFixed(r, rolen), 0);
  out.set(bigintToBytesFixed(s, rolen), rolen);
  return out;
}

/**
 * Verify a DSA `r || s` signature against the message digest and public key.
 * Returns `true` iff the signature is valid; never throws on bad input.
 */
export function dsaVerify(params: DsaVerifyParams): boolean {
  try {
    const p = bytesToBigint(params.p);
    const q = bytesToBigint(params.q);
    const g = bytesToBigint(params.g);
    const y = bytesToBigint(params.y);
    const qlenBits = q.toString(2).length;
    const rolen = Math.ceil(qlenBits / 8);
    if (params.signature.length !== rolen * 2) return false;
    const r = bytesToBigint(params.signature.subarray(0, rolen));
    const s = bytesToBigint(params.signature.subarray(rolen));
    if (r <= 0n || r >= q) return false;
    if (s <= 0n || s >= q) return false;
    const w = modinv(s, q);
    const z = bits2int(params.messageDigest, qlenBits);
    const u1 = (z * w) % q;
    const u2 = (r * w) % q;
    const v = ((modpow(g, u1, p) * modpow(y, u2, p)) % p) % q;
    return v === r;
  } catch {
    return false;
  }
}
