# Frozen baseline build

`components-baseline.mjs` is the self-contained ESM bundle of `@blockchaincommons/components` built from
commit `7418977ffe5079f77008c6682af0fa6f1848f8f7`, the pre-redesign wire-format reference. Sibling
`@blockchaincommons/*` packages are INLINED from their own frozen baseline
bundles (@blockchaincommons/crypto, @blockchaincommons/rand, @blockchaincommons/sskr, @blockchaincommons/tags, @blockchaincommons/uniform-resources, @blockchaincommons/shamir), so this bundle keeps the
pre-redesign behaviour of its dependencies after they change.
`components-baseline.d.mts` is the public surface at that commit (Phase 0.5).

`tests/differential.test.ts` runs every corpus recipe through this bundle and
the working tree and asserts identical outcomes; it pins the sha256 below so
an accidental rebuild cannot turn the differential into a self-comparison.

Baseline commit: 7418977ffe5079f77008c6682af0fa6f1848f8f7
Baseline sha256: e586b600317b4e2acdd9853bea449e641fefabe6f6049e90cc0b1087af9946b9
