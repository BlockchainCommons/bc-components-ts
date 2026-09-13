# Divergences from the Rust reference implementation

This library is a TypeScript port of
[`BlockchainCommons/bc-components-rust`](https://github.com/BlockchainCommons/bc-components-rust),
tracked at version **0.31.1**
([`d843f5d`](https://github.com/BlockchainCommons/bc-components-rust/commit/d843f5d8f66330eaa4471662d57f5c1bebfd0c7c), the commit the crates.io release was cut from per its `.cargo_vcs_info.json`).

The tracked version and commit are recorded in
[`.github/versions.yml`](./.github/versions.yml), and the `upstream.yml`
workflow opens a tracking issue whenever the reference implementation moves
ahead of it.

Every entry below is checked by `tests/rust-validation`, a Rust program that
pins `bc-components = 0.31.1` (features `ssh`, `pqcrypto`) and replays
`tests/vectors/vectors.json` through the reference. A vector either matches
byte for byte, is listed here as an expected divergence, or fails the run.
The current run: **509 vectors — 405 match, 48 expected divergences (D2 7,
D3 24, D5 1, D6 3, E1 13), 56 JS-only, 0 mismatches.** A JS-only vector is
one the reference cannot express (a non-integer length, an unknown level, a
seeded post-quantum key) or a surface the harness adapter does not run; it
is counted, never compared.

This document has three kinds of entry:

1. **True behavioral divergences** - the same input produces a different outcome.
2. **JS-only input domain** - inputs that have no Rust analog, so there is nothing to diverge from.
3. **Mapping equivalences** - JS-specific inputs that are validated through the bytes they produce.

## 1. True behavioral divergences

Harness on the current tree (`tests/rust-validation`, `bc-components =
0.31.1`, 2026-09-12): **509 vectors — 405 match, 48 expected divergence (D2
7, D3 24, D5 1, D6 3, E1 13), 56 JS-only, 0 mismatch.** The E1 table, D5
type list and D6 rule are explicit in `tests/rust-validation/src/main.rs`;
any other pair is a mismatch.

### D3. `Compressed` bytes (24 vectors)

`Compressed.fromDecompressedData` uses pako raw DEFLATE at level 6; the
reference uses `miniz_oxide::compress_to_vec(data, 6)`. The two encoders
produce different DEFLATE streams for the same input (block boundaries and
match choices differ). The harness verifies that every TypeScript stream
decompresses in Rust to the original bytes; `tests/compressed.test.ts`
verifies the reverse direction on a miniz_oxide stream dumped by
`tests/rust-validation/examples/dump_compressed.rs`.

What differs on the wire, stated precisely: the `Compressed` CBOR is
`[checksum, decompressedSize, compressedData, digest?]`, so the element's
bytes — and therefore a compressed envelope's CBOR and UR — differ between
the two implementations (executed on a 53-byte input: 16-byte stream here,
28-byte stream there). The envelope digest is the digest of the
*uncompressed* subject and is identical, so nothing signed or compared by
digest is affected. Matching would mean porting miniz_oxide's compressor
(or loading it as WASM); the TypeScript bytes are the frozen behaviour.

### D6. A zero scalar or an off-curve point is rejected at decode (3 vectors)

`ECPrivateKey` requires a scalar in `[1, n − 1]` and `ECPublicKey` /
`ECUncompressedPublicKey` a point on the curve **when the key is
constructed** (`ComponentsError` `InvalidData`), so a `SigningPrivateKey`,
`SigningPublicKey` or `PrivateKeys` CBOR carrying such a key fails to decode
here. The reference copies the bytes unchecked and panics at first use
(executed: `ECPrivateKey::from_data_ref([0; 32])` is `Ok` and
`.public_key()` panics in `bc-crypto` `ecdsa_keys.rs:31`, `expect("32
bytes, within curve order")`; `ECPublicKey::from_data_ref` of a non-point
is `Ok` and `.uncompressed_public_key()` panics), so no reference program
can use such a key either. **Upstream fix:** validate in `from_data_ref`
and return `Err`. The three corpus rows that carry the all-zero key record the
rejection; their valid-key twins (scalar `2^248`, the generator `G`) decode
identically on both sides.

### Was: divergences since fixed

These were true divergences before the redesign and are now identical to
the reference, each pinned by vectors:

- **Untagged CBOR was accepted by every `fromCbor`** (B2); `fromCbor`
  requires the type's tag now, as `from_tagged_cbor` does, and reports
  anything else as `Cbor` (16 `decodeUntagged` vectors).
- **`SigningPrivateKey.random()` defaulted to Ed25519** (B3); it is Schnorr,
  `SignatureScheme::default()` (3 `signingDefault` vectors).
- **KDF numbers reached the wire unchecked** (B4); `iterations`, `r`, `p`
  are `u32` and `logN` is `u8` at construction, the reference's widths (30
  `kdfDomain` vectors; the out-of-width ones are JS-only).
- **Foreign error classes leaked** (B6, B7): dcbor, crypto and rand errors
  are `ComponentsError`s with `Cbor`, `Crypto`, `InvalidData`, `Hex` or
  `Utf8` codes and the original as `cause`; the low-order X25519 point is
  `InvalidData` here where the reference derives an all-zero secret (B7 —
  the port stays the safer side, and this is the one place it does not
  follow the reference; a `domain` vector pins it).
- **`HKDFRng` with `pageLength: 0` looped forever** (B8); it is
  `InvalidData` before any HKDF call (the reference still loops, U3).
- **`toString()` of the key types printed key bytes**; every key type has
  `reference()` / `refHexShort()` and prints the reference's `Display`
  form, checked string for string through the tag summarisers (25 `summary`
  vectors, `/tags`).
- **ECDSA SSH signatures were low-s normalised, and a high-s one was
  rejected** (D4, 1.0.0-beta.1). The reference (`ssh-key` over RustCrypto
  `ecdsa`, RFC 6979, no normalisation) and OpenSSH produce `s > n/2` half
  the time; noble's defaults normalised on signing and refused on
  verification, so the port could not verify the reference's signatures.
  Signing and verification pass `lowS: false` now: with the same nonce the
  bytes are identical to the reference's (the `sshFromSeed … +sign` vector
  matches byte for byte) and both forms verify on both sides; a fixture
  test verifies a signature the reference produced.
- **Lax Ed25519 verification** (B1) was fixed at its source in
  `@blockchaincommons/crypto` (`verify_strict` semantics); eight
  `verifyStrict` vectors pin the strict outcome against the reference here
  too.

## 2. JS-only input domain

The following surfaces have no counterpart in `bc-components-rust` 0.31.1 and
are exercised only by the TypeScript golden vectors (7 vectors in class `D2`
and 56 counted as JS-only in the harness):

- **`toUR()` on `EncapsulationCiphertext`.** The reference has `From<_> for
  CBOR` but no `CBORTagged` for it (two tags), so no `UREncodable`; the
  TypeScript type produces `ur:agreement-public-key/…` (X25519) or
  `ur:mlkem-ciphertext/…` from its tag names (class `D5`, this type only,
  1 vector). `JSON`, `SSKRShare` and `URI` are `CBORTaggedEncodable` in the
  reference, so bc-ur's blanket `UREncodable` gives them `ur_string()` —
  executed, `ur:json/…`, `ur:sskr/…` and `ur:url/…` are identical to the
  port's (the harness adapter had typed a `-` for them until 1.0.0-beta.2);
  `AuthenticationTag` has no UR on either side.
- **EC key CBOR decoding.** The reference implements only the encoding
  direction for `ECPrivateKey`, `ECPublicKey`, `ECUncompressedPublicKey`, and
  `SchnorrPublicKey`; the TypeScript classes also decode.
- **`SSHAgentParams` / `KeyDerivationMethod.SSHAgent`** — the reference has
  them behind the optional `ssh-agent` feature, which the harness does not
  enable (2 vectors in `D2`: harness scope, not a divergence; the
  `encryptedKey` row would need a running agent).
- **Seeded post-quantum and SSH-ECDSA key generation.** TypeScript draws
  ML-DSA, ML-KEM and SSH ECDSA key material from the caller's RNG
  (`createKeypair` / `createEncapsulationKeypair` / `generateKeypair` with
  `rng`, and `MLKEMPublicKey.encapsulate({ rng })` for the encapsulation
  randomness); the reference's `keypair_using` returns
  `General("Deterministic keypair generation not supported for this
  encapsulation scheme" / "… signature scheme")` for every post-quantum
  scheme (executed; 5 `D2` vectors) and its `keypair()` draws from the OS
  through `pqcrypto`, so the harness compares only the deterministic parts
  (signature verification, decapsulation, the sealed-message structure).
  Matching would remove a capability for no wire benefit.
- **The JS input domain** (`domain` and out-of-width `kdfDomain` vectors,
  42 of the 56 JS-only rows): `NaN`, `Infinity`, negative or fractional
  lengths and parameters, a number where a string is expected, an unknown
  level number — unrepresentable in the reference's types; each is
  `ComponentsError` `InvalidData` or `PostQuantum` here, pinned by the
  golden snapshots.

## 3. Mapping equivalences

- **Error taxonomy (`E1`, 13 vectors, an explicit table).** Where both sides
  reject an input the codes differ in exactly these pairs (reference →
  TypeScript): a wrong shape, length or PQ level inside a tag `Cbor` →
  `InvalidData` / `InvalidSize` / `PostQuantum`; a UR of another type or an
  unparsable bytewords body `Cbor` → `UnexpectedType` / `Bytewords`; a bad
  SSKR share `Error` → `Sskr` (the harness answers for the reference here:
  `SSKRShare::from_data` on fewer than 5 bytes panics on an index); a
  non-point `ECPublicKey` panics there and is `InvalidData` here. Every
  other both-reject pair is a mismatch. A dcbor failure that reaches the
  caller is `Cbor` on both sides (the reference's `Error::Cbor`).
- **The low-order X25519 point** (B7 in the list above). Executed:
  `shared_key_with(&X25519PublicKey::from_data([0; 32]))` returns a key
  (`6ddeb1af…`) in the reference — `bc-crypto` HKDFs the all-zero
  Diffie–Hellman output, so it does not look zero — where the port raises
  `InvalidData` ("low-order point"). A predictable shared key is what the
  check prevents; the port stays the safer side. **Upstream fix:** a
  contributory check in `x25519_shared_key`.
- **`MLDSAPrivateKey.publicKey()`.** Neither side derives the public key from
  the private key: the reference's `MLDSAPrivateKey` has `sign`, `level`,
  `size`, `as_bytes`, `from_bytes` and no `public_key()`; both hand out the
  pair from `keypair()` / `createKeypair()`. The port's `publicKey()` stub
  throws `General` and exists for the shape only.
- **KDF parameter display** matches the reference (`PBKDF2(SHA256)`,
  `Scrypt`, `Argon2id`, `HKDF(SHA256)`); the structural rule the harness
  keeps for `params` / `encryptedKey` is never exercised.
- **RNG consumption.** `bc_rand::RandomNumberGenerator::random_data` in the
  reference fills eight bytes per `u64`; the seeded TypeScript RNG fills one
  byte per call. The harness delegates `random_data` per byte so both sides
  draw the same sequence from the same seed; TypeScript's byte order is the
  frozen behaviour (it matches `bc-rand-ts`).
- **Randomised outputs** (X25519 ephemeral keys in `SealedMessage`, Schnorr
  aux randomness, ML-KEM encapsulation) are compared by round trip: the
  TypeScript ciphertext or signature is opened or verified in Rust, and the
  fixed parts (recipient key, plaintext, AAD) must match.

## 4. Known gaps (the reference has it, TypeScript does not)

- **SSH DSA key generation.** `createKeypair("SshDsa")` and
  `PrivateKeyBase.sshSigningPrivateKey({ kind: "dsa" })` throw; the
  reference's byte-deterministic DSA-1024 generation (FIPS 186-4 prime
  search) is not ported. DSA keys parsed from PEM sign, verify and round-trip.

## Maintenance

When the upstream reference moves:

1. Review the diff via the link in the `upstream.yml` tracking issue.
2. Port the relevant changes.
3. Update `.github/versions.yml` with the new version and commit.
4. Update the tracked version at the top of this file.
5. Re-run `tests/rust-validation` (see its README) and add, amend, or remove
   divergence entries as the port requires.
