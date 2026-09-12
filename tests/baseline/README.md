# Frozen baseline build

`components-baseline.mjs` is the self-contained ESM bundle of `@blockchaincommons/components` built from
commit `7418977ffe5079f77008c6682af0fa6f1848f8f7`, the pre-redesign wire-format reference. Siblings
`@blockchaincommons/crypto`, `@blockchaincommons/rand`, `@blockchaincommons/sskr`,
`@blockchaincommons/tags` and `@blockchaincommons/uniform-resources` are INLINED from their own
frozen baseline bundles, and the pre-redesign `@blockchaincommons/dcbor-compat` is INLINED
directly, so this bundle keeps the pre-redesign behaviour of its dependencies after they change.
`components-baseline.d.mts` is the public surface at that commit.

`tests/differential.test.ts` runs every corpus recipe through this bundle and
the working tree and asserts identical outcomes; it pins the sha256 below so
an accidental rebuild cannot turn the differential into a self-comparison.

Baseline commit: 7418977ffe5079f77008c6682af0fa6f1848f8f7
Baseline sha256: e60c13533397a3caaecfad9e632008de6920b86b88391311eec86983d16cab66

The pre-redesign source carried an sr25519 scheme that this package does not
support (the reference has none). Its `import * as sr25519 from
"@scure/sr25519"` line is replaced in the bundle by a stub whose every
member throws, so the bundle loads without that package and the dead
sr25519 paths stay dead; nothing the differential corpus exercises reaches
them. The sha256 above pins the stubbed bundle.
