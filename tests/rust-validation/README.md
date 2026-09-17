# Rust reference cross-validation

Replays vector files against the `bc-components` reference: the published
`bc-components` 0.31.1 crate from crates.io (sources `bc-components-rust`
commit `d843f5d`, tag 0.31.1) over the published `bc-crypto` 0.14.0,
`bc-ur` 0.19.2, `dcbor` 0.25.2, `bc-rand` 0.5.0, `sskr` 0.12.0, `ssh-key`
0.6.7 and `miniz_oxide` 0.8.9. Nothing is patched. Two builds: the default
one, and `--features agent`, which turns on `bc-components/ssh-agent` and
compares the SSH-agent key-derivation rows.

```sh
cd tests/rust-validation
cargo run --release --offline -- ../vectors/vectors.json                    # the golden file
bun run vectors:full                                                          # writes target/corpus.json
cargo run --release --offline -- target/corpus.json                          # the whole corpus
cargo run --release --offline --features agent -- ../vectors/vectors.json    # the ssh-agent build
cargo run --release --offline --features agent -- target/corpus.json
```

Result lines on 2026-09-15:

```
5701 vectors - 5230 match, 323 panic-mapped (hang 3, none 2, panic 318), 148 js-only (J1 35, J2 21, J3 91, J4 1), 0 MISMATCH
10334 vectors - 9747 match, 331 panic-mapped (hang 3, none 2, panic 326), 256 js-only (J1 35, J2 21, J3 199, J4 1), 0 MISMATCH
5701 vectors - 5321 match, 323 panic-mapped (hang 3, none 2, panic 318), 57 js-only (J1 35, J2 21, J4 1), 0 MISMATCH [agent]
10334 vectors - 9946 match, 331 panic-mapped (hang 3, none 2, panic 326), 57 js-only (J1 35, J2 21, J4 1), 0 MISMATCH [agent]
```

## What is compared

Every recipe yields one outcome string on each side and the two are
compared textually. The TypeScript outcome is the vector's `expect`
(`scripts/generate-vectors.ts` materialises it with the working tree, error
messages included); the reference's is computed by `src/main.rs`.

- A failure is `throw:<code>:<message>`: the reference's error variant
  followed by its `Display`. A dcbor error from a decoder is `Cbor` with
  dcbor's own message; a `bc_components::Error::Cbor` (the `TryFrom<CBOR>`
  types: `HashType`, `AuthenticationTag`, the levels, `KeyDerivationMethod`)
  keeps its `CBOR error: ` prefix; a bc-ur error is its variant with `UR`
  printed as `Decoder`; an sskr error is `SskrError:<variant>` with the
  Shamir wrapper printed as `Shamir`; an ssh-key error is `Ssh` with the
  reference's `SSH operation failed: ` prefix.
- `urParse` runs the reference's `from_ur_string` in its two steps: the UR
  grammar (`UR::from_ur_string`), then the type check against the tag's
  registered name and the untagged decoder.
- Rows whose artefact is drawn from the secure generator are verified rather
  than reproduced: the reference opens the TypeScript sealed message with the
  recipient key the row carries (`seal`), unlocks the TypeScript encrypted key
  and checks its AAD is the reference's encoding of the same parameters
  (`encryptedKey`), decapsulates the TypeScript ML-KEM ciphertext (`mlkem`),
  verifies the TypeScript ML-DSA keys and signature (`mldsa`), and verifies
  the TypeScript ECDSA P-521 SSH signature, which p521 0.13.3 makes with fresh
  randomness (`sshFromSeed`, `sshFromPem`). Every other SSH algorithm signs
  deterministically and compares byte for byte.
- `agentLock` (the `agent` build) runs the reference's SSH-agent key
  derivation over an in-memory agent built from the row's OpenSSH keys (the
  reference's test agent: identities by comment, `test_namespace`, SHA-256):
  the reference locks and unlocks on its own, unlocks the TypeScript locked
  key, checks its parameters equal the reference's after the id update, and
  runs the row's unlock (another secret, a stored-id override, a flipped AAD
  or ciphertext byte) so the error rows compare code and message. The
  default build reports these rows as J3.
- Integers are read exactly: a recipe field that is not an integer of the
  reference's width makes the row `unparsable`, which fails the run. The
  program asserts a 64-bit `usize`.

## Panic-mapped rows

Where the reference has no error object at the call the port reports one, the
row is `panic-mapped` and only the TypeScript code is compared. `PANIC_MAPPED`
in `src/main.rs` lists every such site as (recipe kind, a substring of the
panic message or the class `none`/`hang`, the TypeScript code):

- a panic: `from_hex` unwrapping the hex decode or the size check, `UUID`'s
  `FromStr`, the SSKR share accessors indexing fewer than 5 bytes, bc-crypto
  unwrapping a secp256k1 scalar or point conversion (key derivation and
  `verify` under the published bc-crypto 0.14.0), `JSON::as_str` on non-UTF-8
  content, `Compressed::digest()` without a digest,
  `SigningPrivateKey::from_untagged_cbor` on an empty array, and `ur_string()`
  before `register_tags()`;
- `none`: `UUID::from_data_ref` returns an `Option`;
- `hang`: `HKDFRng` with page length 0 never returns from a non-empty draw.
  Each vector runs on its own thread; these rows time out after two seconds
  and the thread is abandoned.

A panic outside the table, or one whose TypeScript code differs, is a
MISMATCH.

## JS-only rows

`js-only` rows are the recipes the reference cannot run, in four classes:

- **J1** the input is outside the reference's types: the `domain` rows
  (`NaN`, fractional or negative lengths, a number where a string goes, an
  unknown level) and the `kdfDomain` numbers outside `u32`/`u8`;
- **J2** the reference type has no such operation: `UUID::from_hex`, the SSKR
  share's payload accessor, the private `ecdsa_sign`/`mldsa_sign`, and
  `cbor_tags()` on the encapsulation enums;
- **J3** the operation needs the `ssh-agent` feature and the default build
  lacks it: the `SSHAgentParams` rows, the `agentLock` rows and every decode
  that reaches method index 4 (the reference stops at `Invalid
  KeyDerivationMethod`; the agent build compares these rows in full, which is
  why its J3 count is zero);
- **J4** the operation needs a live SSH agent socket: `encryptedKey` with
  SSH-agent parameters and no injected agent.

## Order

Rows under `noreg` run before `bc_components::register_tags()` and must come
first in the file; the generator writes them first and the program fails a
file that has one after a registered row.

## Self-check and fixtures

- `mismatch.json`: one digest row with its last hex digit flipped; the run
  must exit 1 with `1 MISMATCH`.
- `fixtures/classes.json`: one row per outcome class of the default build:
  `8 vectors - 1 match, 3 panic-mapped (hang 1, none 1, panic 1), 4 js-only (J1 1, J2 1, J3 1, J4 1), 0 MISMATCH`.
- `fixtures/malformed.json`: a fractional cycle length is `unparsable` (exit 1).
- `fixtures/noreg-order.json`: a `noreg` row after a registered row is a MISMATCH.
- `fixtures/panic-code.json`: a mapped panic whose TypeScript code differs is a MISMATCH.

## CI

The `rust-validation` job in `.github/workflows/ci.yml` checks the golden
file against the working tree (`bun run test:golden`), materialises the full
corpus, builds the harness against the pinned crates (`cargo run --locked
--offline` after `cargo fetch --locked`), runs the golden file and the corpus
in both builds, then the mismatch fixture and the four harness fixtures. A
MISMATCH anywhere fails the job.

## Maintenance

When the reference moves: update the pins in `Cargo.toml`, run
`cargo update -p bc-components`, update `.github/versions.yml`, regenerate
the vectors (`bun run vectors:generate`), run the four replays and copy the
result lines above. A new difference is a bug on one side: fix it, or add the
panic-mapped or js-only row with its reason in `src/main.rs` and here.
