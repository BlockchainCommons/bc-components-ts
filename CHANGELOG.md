# Changelog

## 1.0.0-beta.1

### Changed

- **One codable mechanism.** Every value type has `static codec` (a dcbor `CborCodec` over the tagged form whose `decode` also accepts the untagged form), `toCbor()`, `toUR()` and `static fromCbor(cbor)`. The thirteen-method ladder (`taggedCbor`, `taggedCborData`, instance and static `fromTaggedCbor`, `fromTaggedCborData`, `fromUntaggedCborData`, `ur`, `urString`, `fromUR`, `fromURString`, `fromUrString`, `UR_TYPE`) is gone: bytes and UR strings compose with dcbor's `decodeCbor`/`decodeWith` and uniform-resources' `decodeURWith`. Tag names come from the tag constants, so URs no longer need the global tag registry.
- **Names.** `from(bytes)` replaces `fromData`/`fromDataRef`; `random({ rng? })` replaces `new()`/`newUsing(rng)`/`random()`/`randomUsing(rng)` everywhere (`Salt.random({ length, rng })`, `Salt.randomInRange`, `Salt.forSize`, `Seed.random({ length, rng, name, note, creationDate })`, `MLDSAPrivateKey.random(level, { rng })`, `EncapsulationPrivateKey.randomMlkem(level, { rng })`, `keypair({ rng })`); the `bytes` getter replaces `data()`/`asBytes()`/`toData()`; `toHex()` replaces `hex()`; `byteLength` replaces `len()`/`size()`; `asSchnorr()`/`asEcdsa()`/… return `undefined` instead of `null` where `toSchnorr()`/… did; stored properties are getters (`scheme`, `level`, `salt`, `nonce`, `aad`, `name`, …) and `Seed` has setters; KDF parameter types use `from({ salt?, … })`; `SealedMessage.seal(plaintext, recipient, { aad?, nonce? })`; `EncryptedMessage.from({ ciphertext, nonce, authTag, aad? })`; `new HKDFRng(keyMaterial, salt, { pageLength? })`; `PrivateKeys.from({ signing, encapsulation })` and `PublicKeys.from(...)`; `SigningPrivateKey.fromSchnorr/fromEcdsa/fromEd25519/fromSr25519/fromMldsa`; `Compressed.fromParts({ ... })`; `URI.from(text)`.
- **`ComponentsError`** replaces `CryptoError`/`ErrorKind`: `code` (string union), `details` discriminated by code, `cause`; four unused kinds dropped; every bare `Error` thrown by the package now carries a code.
- Ported to the canonical `@blockchaincommons/dcbor` (the `dcbor-compat` shim is gone) and to the redesigned `crypto`, `rand`, `sskr`, `tags` and `uniform-resources` siblings. Every wire byte is unchanged; the port is verified against a frozen pre-port baseline (`tests/differential.test.ts`) and against `bc-components-rust` 0.31.1 (`tests/rust-validation`, see `RUST_DIVERGENCES.md`).
- `hexToBytes` is dcbor's: whitespace inside a hex string is tolerated, and malformed hex throws `CborError`.
- Tagged CBOR of a value object is memoised; repeated `taggedCborData()`, references and XIDs over the same object no longer re-encode.
- A `Seed` map value of the wrong CBOR type is now rejected with `InvalidData` (was an incidental `DataTooShort`).

- **Enums are `as const` objects** with literal-union types (`SignatureScheme`, `EncapsulationScheme`, `KeyDerivationMethod`, `HashType`, `MLDSALevel`, `MLKEMLevel`); member names and values unchanged.
- **Options objects** for key generation: `generateKeypair({ signing?, encapsulation?, rng? })` replaces `keypair`/`keypairUsing`/`keypairOpt`/`keypairOptUsing`; `createKeypair(scheme, { rng?, comment? })` and `createEncapsulationKeypair(scheme, { rng? })` absorb their `Using` variants.
- **SSKR**: one `SskrShare` class (on `/sskr`) over the sskr package's parsed share replaces `SSKRShareCbor`, the `SSKRShare` alias object, `sskrGenerate*`, `sskrCombine*` and the re-exported sskr types.
- **Subpaths**: the root entry no longer exports the SSH, post-quantum, KDF and SSKR families; codecs are built lazily so an import of `Digest` + `SymmetricKey` + `EncryptedMessage` tree-shakes to about 6.5 kB.
- `JSON` is `CborJson`; the tag constants are no longer re-exported (import `@blockchaincommons/tags`).
- Comments no longer frame the code as a port; the reference implementation is cited where a wire choice needs it.

### Fixed

- `SSHSignature` text wraps at 70 columns like OpenSSH and the reference (was 76).
- `createKeypair` for the ML-DSA schemes threw (it asked the private key for a public key it cannot derive); it now generates both keys together.

### Added

- Subpath entries `@blockchaincommons/components/ssh`, `/pq`, `/kdf` and `/sskr` (the root entry still exports everything for now).
- Golden vectors (`tests/vectors/vectors.json`), a differential corpus, property tests, and ADRs 0001–0006 under `docs/adr/`.

Extracted from the [`paritytech/bcts`](https://github.com/paritytech/bcts) monorepo, where this library was published as `@bcts/components`, and redesigned as an idiomatic TypeScript library; see [MIGRATION.md](./MIGRATION.md). Every wire byte is unchanged.

---

## History as `@bcts/components`

## [1.0.0-beta.6] - 2026-07-29

### Changed

- Workspace version bump

## [1.0.0-beta.5] - 2026-07-01

### Changed

- Workspace version bump

## [1.0.0-beta.4] - 2026-06-28

### Changed

- Dependency sync

## [1.0.0-beta.3] - 2026-06-22

### Changed

- Dependencies bump

## [1.0.0-beta.2] - 2026-06-16

### Changed

- Dependencies bump

## [1.0.0-beta.1] - 2026-05-27

### Fixed

- `SigningPublicKey`/`SigningPrivateKey` UR encoding now carries the **untagged** CBOR content (the `ur:signing-public-key` / `ur:signing-private-key` type already implies the tag). Previously `ur()` embedded the tagged form, double-tagging the content (`tag(40022, …)` inside the UR), which diverged from Rust.

### Added

- `PrivateKeyBase` now implements the `Decrypter` interface (`decapsulateSharedSecret`), so it can be used directly as a recipient key for public-key decryption.

## [1.0.0-beta.0] - 2026-04-27

### Added

- Initial SSH key support: OpenSSH-format private keys, public keys, certificates, and signatures (`SSHPrivateKey`, `SSHPublicKey`, `SSHCertificate`, `SSHSignature`, `SSHAlgorithm`) with sign/verify and PEM round-trip.
- `toSsh()` / `isSsh()` accessors on `SigningPrivateKey` / `SigningPublicKey` to bridge BC envelopes and OpenSSH artifacts.
- Sr25519 keypair surface and tests; sr25519 / mldsa / mlkem level helpers exposed for parity.
- Comprehensive SSH test suite (buffer, certificate, private key, public key, sign/verify, signature).

### Changed

- Refined signing scheme, signature, and signing-private/public-key APIs to align with `bc-components-rust`.
- Subpath exports added (`@bcts/components/ssh`, etc.); typedoc and bundler config tightened.
- Misc cleanups in `private-key-base`, `keypair`, `private-keys`, `public-keys`, `reference`, encrypted-key parameter types.

## [1.0.0-alpha.23] - 2026-04-24

### Changed

- Workspace version bump

## [1.0.0-alpha.22] - 2026-03-01

### Changed

- Workspace version bump

## [1.0.0-alpha.21] - 2026-02-27

### Changed

- Workspace version bump

## [1.0.0-alpha.20] - 2026-02-12

### Changed

- Workspace version bump

## [1.0.0-alpha.19] - 2026-02-05

### Fixed

- **Compatibility**: Removed insecure `Math.random()` fallback in `UUID.random()`. UUID generation now uses `globalThis.crypto.getRandomValues()` exclusively, which is available in all browsers and Node.js 18+.

## [1.0.0-alpha.18] - 2025-01-31

### Changed

- **PrivateKeyBase**: Major refactor for Rust parity
  - Key derivation now uses HKDF with salt strings matching Rust's `bc-crypto` (`"signing"` for signing keys, `"agreement"` handled internally by `X25519PrivateKey.deriveFromKeyMaterial()`)
  - Relaxed constructor validation from fixed 32-byte requirement to non-zero length, matching Rust's flexible `PrivateKeyBase::new(data)`
  - Renamed internal constant `PRIVATE_KEY_BASE_SIZE` to `PRIVATE_KEY_BASE_DEFAULT_SIZE` (32 bytes, used only for random generation)
  - `x25519PrivateKey()` now delegates to `X25519PrivateKey.deriveFromKeyMaterial()` instead of manual HKDF derivation
- **PrivateKeyBase key derivation**: Added `schnorrPrivateKeys()` and `ecdsaPrivateKeys()` methods for Schnorr and ECDSA key pair derivation
- **XID**: Enhanced `XID` type with additional methods for Rust parity
- **Signature**: Minor improvements to signature handling
