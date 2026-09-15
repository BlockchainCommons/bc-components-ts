/**
 * Deterministic ECDSA P-521 key generation, byte-identical to
 * `ssh-key` 0.6.7 `EcdsaKeypair::random(rng, EcdsaCurve::NistP521)`, which
 * calls `p521::SecretKey::random(rng)` (`p521` 0.13.3):
 *
 *   `SecretKey::random` -> `NonZeroScalar::random` -> loop over
 *   `<Scalar as ff::Field>::random`, which fills a 66-byte `FieldBytes` with
 *   `rng.fill_bytes` and accepts it when the big-endian value is below the
 *   group order; `NonZeroScalar::new` then rejects zero and the loop draws
 *   another 66 bytes.
 *
 * So the scalar is the first 66-byte draw `s` with `0 < s < n`; the public
 * key is the uncompressed SEC1 point `0x04 || X || Y` (133 bytes).
 */

import { p521 } from "@noble/curves/nist.js";
import type { KeygenRng } from "./keygen-rng.js";
import { bytesToBigint } from "./bigint-math.js";
import { ComponentsError } from "../../error.js";

/** Byte length of a P-521 scalar (`FieldBytes<NistP521>`). */
export const P521_SCALAR_LEN: number = 66;
/** Byte length of an uncompressed P-521 SEC1 point (`0x04 || X || Y`). */
export const P521_POINT_LEN: number = 133;

/** The P-521 group order `n` (`NistP521::ORDER`). */
const P521_ORDER = BigInt(
  "0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
);

/** A P-521 keypair in the fixed-width forms `ssh-key` stores. */
export interface P521KeypairComponents {
  /** The private scalar, 66 bytes big-endian. */
  scalar: Uint8Array;
  /** The public point, 133 bytes: `0x04 || X || Y`. */
  point: Uint8Array;
}

/**
 * Generate a P-521 keypair from `rng`, consuming it exactly as the reference
 * does. With `new HKDFRng(seed, "ecdsa-sha2-nistp521")` this reproduces the
 * key `PrivateKeyBase::ssh_signing_private_key(SSHAlgorithm::Ecdsa { curve:
 * EcdsaCurve::NistP521 }, _)` derives.
 */
export function generateP521Keypair(rng: KeygenRng): P521KeypairComponents {
  const scalar = new Uint8Array(P521_SCALAR_LEN);
  for (;;) {
    rng.fillBytes(scalar);
    const s = bytesToBigint(scalar);
    if (s !== 0n && s < P521_ORDER) break;
  }
  const point = new Uint8Array(p521.getPublicKey(scalar, false));
  if (point.length !== P521_POINT_LEN || point[0] !== 0x04) {
    throw ComponentsError.ssh("generateP521Keypair: expected an uncompressed SEC1 point");
  }
  return { scalar, point };
}
