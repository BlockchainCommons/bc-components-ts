# Rust reference cross-validation

Replays `tests/vectors/vectors.json` against `bc-components = 0.31.1`
(features `ssh`, `pqcrypto`).

```sh
cd tests/rust-validation
cargo run --release -- ../vectors/vectors.json
```

Seeded recipes drive `bc-rand`'s `SeededRandomNumberGenerator` from the same
xoshiro state, the counter "fake" generator, or `HKDFRng`. Tagged CBOR, UR
strings, derivations, signatures and OpenSSH text compare exactly. Outcomes
the reference cannot reproduce (ML-DSA/ML-KEM key
generation, which pqcrypto seeds differently; SSH ECDSA key generation from
a seed) are allowlisted in
`expected_divergence()`, the machine-readable twin of `RUST_DIVERGENCES.md`.
Exit 0 iff every vector matches or is allowlisted. Not wired into CI (needs
a Rust toolchain and a long first build); run manually before any release.

Adapter rule: a `-` printed for a field (a UR, a name) must be an *observed*
absence — the reference type has no such method — never a typed
placeholder. Three "TypeScript-only UR" rows (JSON, SSKR share, URI) were
placeholders until 1.0.0-beta.2; the reference has those URs through bc-ur's
blanket `UREncodable`.

Skipped rows include adapter coverage gaps as well as JavaScript-only inputs.
See `RUST_DIVERGENCES.md` for the distinction and remaining behavioral differences.
