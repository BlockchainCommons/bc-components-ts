/**
 * RSASSA-PKCS1-v1_5 signature verification (RFC 8017 §8.2.2) over `bigint`,
 * used to verify RSA `sshsig` signatures (`rsa-sha2-256` / `rsa-sha2-512`,
 * RFC 8332).
 *
 * Mirrors `ssh-key` 0.6.7 `RsaPublicKey::verify` → `rsa` 0.9.10
 * `pkcs1v15::VerifyingKey::<Sha256 | Sha512>::verify`:
 *   - the public key must pass `RsaPublicKey::new` (`check_public`): the
 *     modulus is odd, at most 4096 bits and larger than `e`; `e` is odd,
 *     at least 2 and at most 2^33 - 1;
 *   - the signature must be exactly the modulus size and below `n`;
 *   - `EM = s^e mod n`, left-padded to the modulus size, must be
 *     `00 01 FF…FF 00 || DigestInfo || H(message)` with at least eight
 *     `FF` bytes.
 * Every failure is a plain `false`, as the reference maps any error to a
 * failed verification.
 */

import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { bigintToBytesFixed, bitLength, bytesToBigint, modPow } from "./bigint-math.js";
import type { SshRsaSignatureHash } from "../ssh-algorithm.js";

/** `rsa::RsaPublicKey::MAX_SIZE`. */
const RSA_MAX_MODULUS_BITS = 4096;
/** `rsa::RsaPublicKey::MIN_PUB_EXPONENT`. */
const RSA_MIN_PUB_EXPONENT = 2n;
/** `rsa::RsaPublicKey::MAX_PUB_EXPONENT`. */
const RSA_MAX_PUB_EXPONENT = (1n << 33n) - 1n;

/** DER `DigestInfo` prefixes (RFC 8017 §9.2 note 1). */
const DIGEST_INFO_PREFIX: Record<SshRsaSignatureHash, Uint8Array> = {
  sha256: Uint8Array.from([
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
  ]),
  sha512: Uint8Array.from([
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
  ]),
};

/** The inputs of an RSASSA-PKCS1-v1_5 verification. */
export interface RsaPkcs1v15VerifyParams {
  /** The modulus, canonical positive big-endian bytes. */
  n: Uint8Array;
  /** The public exponent, canonical positive big-endian bytes. */
  e: Uint8Array;
  /** The hash named by the signature algorithm. */
  hash: SshRsaSignatureHash;
  /** The message that was signed (hashed here). */
  message: Uint8Array;
  /** The signature, modulus-sized big-endian bytes. */
  signature: Uint8Array;
}

/** `true` iff `signature` is a valid PKCS#1 v1.5 signature of `message` under `(n, e)`. */
export function rsaPkcs1v15Verify(params: RsaPkcs1v15VerifyParams): boolean {
  const n = bytesToBigint(params.n);
  const e = bytesToBigint(params.e);

  // `check_public_with_max_size(.., Some(4096))`.
  if (bitLength(n) > RSA_MAX_MODULUS_BITS) return false;
  if (e > 0xffffffffffffffffn) return false;
  if (e >= n || (n & 1n) === 0n) return false;
  if ((e & 1n) === 0n) return false;
  if (e < RSA_MIN_PUB_EXPONENT || e > RSA_MAX_PUB_EXPONENT) return false;

  const k = Math.ceil(bitLength(n) / 8);
  const s = bytesToBigint(params.signature);
  if (s >= n || params.signature.length !== k) return false;

  const hashed = params.hash === "sha256" ? sha256(params.message) : sha512(params.message);
  const prefix = DIGEST_INFO_PREFIX[params.hash];
  const tLen = prefix.length + hashed.length;
  if (k < tLen + 11) return false;

  const em = bigintToBytesFixed(modPow(s, e, n), k);

  // EM = 0x00 || 0x01 || PS (0xff × (k - tLen - 3)) || 0x00 || T
  let ok = em[0] === 0x00 && em[1] === 0x01;
  for (let i = 2; i < k - tLen - 1; i++) ok = ok && em[i] === 0xff;
  ok = ok && em[k - tLen - 1] === 0x00;
  for (let i = 0; i < prefix.length; i++) ok = ok && em[k - tLen + i] === prefix[i];
  for (let i = 0; i < hashed.length; i++) ok = ok && em[k - hashed.length + i] === hashed[i];
  return ok;
}
