# Rust reference cross-validation (Phase 1.4)

Replays `tests/vectors/vectors.json` against `bc-components = 0.31.1`
(features `ssh`, `pqcrypto`).

```sh
cd tests/rust-validation
cargo run --release -- ../vectors/vectors.json
```

Seeded recipes drive `bc-rand`'s `SeededRandomNumberGenerator` from the same
xoshiro state, the counter "fake" generator, or `HKDFRng`. Tagged CBOR, UR
strings, derivations, signatures and OpenSSH text compare exactly. Outcomes
the reference cannot reproduce (sr25519, which it lacks; ML-DSA/ML-KEM key
generation, which pqcrypto seeds differently; SSH ECDSA key generation from
a seed; the reference's own `Display` strings) are allowlisted in
`expected_divergence()`, the machine-readable twin of `RUST_DIVERGENCES.md`.
Exit 0 iff every vector matches or is allowlisted. Not wired into CI (needs
a Rust toolchain and a long first build); a mandatory manual gate at phase
boundaries.
