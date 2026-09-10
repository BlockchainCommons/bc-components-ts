# Divergences from the Rust reference implementation

This library is a TypeScript port of
[`BlockchainCommons/bc-components-rust`](https://github.com/BlockchainCommons/bc-components-rust),
tracked at version **0.31.1**
([`cc4d402`](https://github.com/BlockchainCommons/bc-components-rust/commit/cc4d40218810319e286dc2d4e588731a3a70d0f5)).

The tracked version and commit are recorded in
[`.github/versions.yml`](./.github/versions.yml), and the `upstream.yml`
workflow opens a tracking issue whenever the reference implementation moves
ahead of it.

Every entry below is checked by `tests/rust-validation`, a Rust program that
pins `bc-components = 0.31.1` (features `ssh`, `pqcrypto`) and replays
`tests/vectors/vectors.json` through the reference. A vector either matches
byte for byte, is listed here as an expected divergence, or fails the run.
The current run: **386 vectors — 290 match, 96 expected divergences, 0
mismatches.**

This document has three kinds of entry:

1. **True behavioral divergences** - the same input produces a different outcome.
2. **JS-only input domain** - inputs that have no Rust analog, so there is nothing to diverge from.
3. **Mapping equivalences** - JS-specific inputs that are validated through the bytes they produce.

## 1. True behavioral divergences

### D3. `Compressed` bytes (24 vectors)

`Compressed.fromDecompressedData` uses pako raw DEFLATE at level 6; the
reference uses `miniz_oxide::compress_to_vec(data, 6)`. The two encoders
produce different DEFLATE streams for the same input (block boundaries and
match choices differ). The harness verifies that every TypeScript stream
decompresses in Rust to the original bytes; `tests/compressed.test.ts`
verifies the reverse direction on a miniz_oxide stream dumped by
`tests/rust-validation/examples/dump_compressed.rs`.

The wire is unaffected in practice: the `Compressed` CBOR carries the digest
of the *uncompressed* content, so envelopes and their digests are identical on
both sides; only the compressed payload bytes differ. Decided in ADR 0006; the
TypeScript bytes are the frozen behaviour.

### D4. ECDSA SSH signatures are low-s normalised (1 vector)

`SSHPrivateKey.sign` for `ecdsa-sha2-nistp256` produces a low-s signature
(noble's default); the reference (via `ssh-key`/`p256`) does not normalise.
Both signatures verify on both sides, and every other field of the signature
(the namespace, the `sshsig` framing, the public key) matches.

### T2. `sshsig` PEM line width (6 vectors) — **pending fix**

The TypeScript `SSHSignature` text form wraps its base64 body at 76 columns;
the reference and OpenSSH wrap at 70. The base64 bodies are identical and both
sides parse either width. This is a bug on the TypeScript side and is fixed in
Phase 3; the harness records it as a tombstone until then.

## 2. JS-only input domain

The following surfaces have no counterpart in `bc-components-rust` 0.31.1 and
are exercised only by the TypeScript golden vectors (55 vectors, class `D2` in
the harness):

- **Sr25519** keys, signatures, and `PrivateKeyBase` derivation (`@scure/sr25519`).
- **EC key CBOR decoding.** The reference implements only the encoding
  direction for `ECPrivateKey`, `ECPublicKey`, `ECUncompressedPublicKey`, and
  `SchnorrPublicKey`; the TypeScript classes also decode.
- **`URI` as a UR** (`ur:uri/…`); the reference has no `UREncodable` for URI.
- **`SSHAgentParams` / `KeyDerivationMethod.SSHAgent`** — the reference needs
  the optional `ssh-agent` feature, which the harness does not enable.
- **Seeded post-quantum and SSH-ECDSA key generation.** TypeScript draws
  ML-DSA, ML-KEM and SSH ECDSA key material from the caller's RNG; the
  reference's `new_keypair` for these schemes uses its own entropy source and
  cannot be seeded, so the harness compares only the deterministic parts
  (signature verification, decapsulation, the sealed-message structure).

## 3. Mapping equivalences

- **Error taxonomy (`E1`, 19 vectors).** Where both sides reject an input
  the codes differ: the reference reports size mismatches as dcbor errors
  when they occur inside `TryFrom<CBOR>`, while TypeScript reports
  `InvalidSize`/`InvalidData` from the constructor. The harness requires both
  sides to reject; the TypeScript code is pinned by the golden vectors.
- **KDF parameter display.** `*Params.toString()` is not the reference's
  `Display`; the harness compares the parameters structurally (method index,
  salt bytes, hash type, iteration and cost fields) rather than by string.
- **RNG consumption.** `bc_rand::RandomNumberGenerator::random_data` in the
  reference fills eight bytes per `u64`; the seeded TypeScript RNG fills one
  byte per call. The harness delegates `random_data` per byte so both sides
  draw the same sequence from the same seed; TypeScript's byte order is the
  frozen behaviour (it matches `bc-rand-ts`).
- **Randomised outputs** (X25519 ephemeral keys in `SealedMessage`, Schnorr
  aux randomness, ML-KEM encapsulation) are compared by round trip: the
  TypeScript ciphertext or signature is opened or verified in Rust, and the
  fixed parts (recipient key, plaintext, AAD) must match.

## Maintenance

When the upstream reference moves:

1. Review the diff via the link in the `upstream.yml` tracking issue.
2. Port the relevant changes.
3. Update `.github/versions.yml` with the new version and commit.
4. Update the tracked version at the top of this file.
5. Re-run `tests/rust-validation` (see its README) and add, amend, or remove
   divergence entries as the port requires.
