# Changelog

## 1.0.0-beta.2 - 2026-09-12

Review against `bc-components-rust` 0.31.1 found one
interoperability bug fixed, one recorded divergence closed by it, and
three "TypeScript-only" surfaces found to exist in the reference too.

### Fixed

- **A high-s ECDSA `sshsig` signature was rejected.** `SSHPublicKey.verify`
  (and so `SigningPublicKey.verify` for SSH ECDSA keys) used noble's default
  `lowS: true`, which refuses a signature whose `s` is above n/2. The
  reference (`ssh-key` over RustCrypto `ecdsa`, RFC 6979 with no low-s
  normalisation) and OpenSSH produce such signatures half the time, so they
  failed to verify here. Verification now accepts either form, as SSH
  requires; a fixture test verifies a signature the reference produced.

### Changed

- `SSHPrivateKey.sign` for `ecdsa-sha2-nistp256` / `-nistp384` no longer
  low-s normalises `s`. With the same RFC 6979 nonce the signature bytes are
  now identical to the reference's (the one `sshFromSeed … +sign` vector
  changed from the low-s form to the reference's bytes); both forms of a
  signature verify on both sides.
- `SignatureScheme.Schnorr` / `Ecdsa` / `Ed25519` carry doc comments
  (typedoc warnings gone).

## 1.0.0-beta.1 - 2026-09-09

Initial beta implementation.