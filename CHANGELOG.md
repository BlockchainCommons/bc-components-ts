# Changelog

## 1.0.0-beta.3 - 2026-09-15

### Added

- **SSH-agent key derivation.** `SSHAgentParams.lock(contentKey, secret, { agent, nonce? })`
  and `unlock(encryptedMessage, secret, { agent })` implement the reference's
  algorithm over an injectable `SshAgent` (`listIdentities`, `sign`);
  `EncryptedKey.lockWithAgent` / `unlockWithAgent` route through it;
  `MemorySshAgent` is an in-memory agent for tests and embedded use; the
  Node-only subpath `@blockchaincommons/components/ssh-agent-node` exports
  `connectToSshAgent()` over `SSH_AUTH_SOCK`. Errors carry the reference's
  texts under `SshAgent` (`SSH Agent secret must be a valid UTF-8 string`,
  `No Ed25519 identities available in SSH agent`, `Multiple identities
  available in SSH agent, but no ID provided`, `No matching identity found`,
  `SSH agent refused to sign`, `SSH_AUTH_SOCK env var not set`, `no
  ssh-agent reachable`) and `Crypto` (`Failed to decrypt the encrypted key: …`,
  `Failed to convert decrypted key to SymmetricKey: …`).
- SSH keys of every algorithm the reference generates: `sshSigningPrivateKey`
  accepts `{ kind: "dsa" }`, `{ kind: "rsa" }` (2048 bits) and
  `{ kind: "ecdsa", curve: "nistp521" }`, and OpenSSH private keys, public
  keys and `sshsig` texts of those algorithms parse and re-encode byte for
  byte with the reference (`ssh-key` 0.6.7 and `pem-rfc7468`).
- `HKDFRng` accepts `pageLength: 0` (a non-empty draw throws `InvalidData`
  instead of looping, which is where the reference hangs).
- `ComponentsError` codes `Env` and `SshAgentClient`, completing the
  reference's error enum (no operation produces them: the reference maps
  every agent failure to `SshAgent`); `ComponentsError.cborDecode`.
- `Seed.creationCborDate` (the stored `CborDate`, sub-second precision kept).
- The DEFLATE implementation is a port of `miniz_oxide` 0.8.9 (`src/internal`),
  so `Compressed` bytes equal the reference's;

### Changed (breaking)

- **Decode errors.** Every `fromCbor` / `codec.decode` failure is a
  `ComponentsError` with code `Cbor` and the reference's message: dcbor's
  own text for a tag or type mismatch, the reference's text for a shape
  error (`Invalid signature format`, `invalid signing public key`,
  `SealedMessage must be an array`, `Invalid HKDFParams`, …), and the leaf
  error's text (`invalid nonce size: expected 12, got 11`) for a size error
  inside a tag. `HashType`, `AuthenticationTag`, `MLKEMLevel`, `MLDSALevel`
  and `KeyDerivationMethod` keep their own codes, with dcbor failures under
  `Cbor` prefixed `CBOR error: `. Unsigned fields decode with dcbor's
  negative wrap (`u8` / `u32` / `usize` widths).
- **Tags follow the process-wide store.** `X.codec.tags` and `X.cborTags()`
  resolve names through the dcbor tags store at call time; `toUR()` throws
  `URError` `TagUnnamed` until `registerTags()`.
- **Removed surfaces that have no reference counterpart:** `toUR()` on
  `EncapsulationPrivateKey`, `EncapsulationPublicKey` and
  `EncapsulationCiphertext`; `fromCbor` / `codec` on `ECPrivateKey`,
  `ECPublicKey`, `ECUncompressedPublicKey` and `SchnorrPublicKey` (they
  encode only); `MLKEMPrivateKey.publicKey()`, `MLDSAPrivateKey.publicKey()`
  and `mlkemExtractPublicKey`; `HKDFRng.randomData` / `tryFillBytes` /
  `fillRandomData`; `ComponentsError.invalidSizeForType` (use
  `invalidSize(dataType, expected, actual)`); the second argument of
  `bytesFromHex`.
- **Post-quantum key derivation and seeding.** `EncapsulationPrivateKey.publicKey()`
  throws `Crypto` for ML-KEM and `SigningPrivateKey.publicKey()` throws
  `General` for ML-DSA (`Deriving ML-KEM/ML-DSA public key not supported`);
  `PrivateKeys.publicKeys()` fails the same way for such keys. The
  reference-mapped keypair factories refuse a seeded generator for the
  post-quantum schemes (`Deterministic keypair generation not supported for
  this signature/encapsulation scheme`) before drawing anything;
  `MLKEMPrivateKey.keypair` / `MLDSAPrivateKey.keypair` keep seeding.
- **EC keys construct by size only** (`ECPrivateKey`, `ECPublicKey`,
  `ECUncompressedPublicKey`, `SchnorrPublicKey`); a zero or out-of-range
  scalar and an off-curve or wrong-parity point throw `InvalidData` at first
  use (`publicKey()`, `sign`, `uncompressedPublicKey()`, `compressedData()`),
  where the reference panics. A hybrid `06` prefix with the right parity is
  accepted.
- **Verification throws where the reference panics.** `verify` with an
  undecodable Ed25519, Schnorr or ECDSA public key, or an ECDSA signature
  with `r` or `s` outside `[0, n - 1]`, throws `InvalidData` (the released
  bc-crypto 0.14.0 panics there); a decodable key with a wrong signature
  returns `false`.
- `X25519PrivateKey.sharedKeyWith` a low-order point derives the reference's
  fixed key instead of throwing; PBKDF2 with 0 iterations and scrypt with
  `logN` 0 derive.
- **Compressed.** `checksum` is a `u32` and `decompressedSize` a `usize`
  (a `bigint` above 2⁵³), both exact on the wire; `fromParts` and decode
  reject compressed data larger than the decompressed size with
  `Compression` (`compressed data is larger than decompressed size`);
  `decompress` reports `corrupt compressed data` and `compressed data
  checksum mismatch`; `equals` compares by digest, as the reference.
- **Seed.** `creationDate` is stored as the decoded `CborDate`; a value of
  the wrong type at the date, name or note key is dropped (the reference's
  `Map::get`), a missing or empty data entry is `Cbor`.
- **SskrShare** stores raw bytes: `from(bytes)` never throws; the header
  accessors throw `InvalidData` naming the field when the share is shorter
  than five bytes; `combine` passes the bytes to sskr and its `SskrError`
  propagates unwrapped. An empty `PrivateKeyBase` is accepted.
- **Strict text parsers.** `X.fromHex` rejects whitespace, odd lengths and
  non-hex characters with `Hex` (`hex decoding error: Odd number of digits`,
  `Invalid character 'z' at position 0`); `UUID.fromString` trims, removes
  `-` and requires 16 bytes (`InvalidSize`); `URI.from` rejects with
  `InvalidData` (`invalid URI: invalid URI format`); `CborJson.asStr` keeps a
  leading BOM and throws `Utf8` on invalid UTF-8.
- **Texts and `toString()`.** Size errors name the reference's data types
  (`digest`, `nonce`, `symmetric key`, `authentication tag`, `Schnorr
  signature`, `EC private key`, `ECDSA public key`, `X25519 public key`, …);
  `AuthenticationTag` prints `AuthenticationTag("<hex>")`, `CborJson`
  `JSON(<text>)`, `SSHAgentParams` `SSHAgent("<id>")`; the `Signature`
  summariser prints `Signature(Unknown)` for an SSH algorithm the scheme
  enum has no name for; the SSH certificate summariser no longer validates
  its content.
- SSH: `SSHSignature.scheme` throws `Ssh` for ECDSA P-521 and RSA
  (`Unsupported SSH ECDSA curve` / `Unsupported SSH signature algorithm`);
  RSA `sshsig` signing throws `Ssh` (`cryptographic error`), as the
  reference's; SSH-DSA signing seeds RFC 6979 with the minimal big-endian
  private key, as the `dsa` crate; the OpenSSH and `sshsig` parsers report
  the reference's grammar errors (`PEM Base64 error: invalid Base64
  encoding`, `unexpected PEM type label: expecting "OPENSSH PRIVATE KEY"`,
  `unknown algorithm`, …) and `sshSigningPrivateKey` validates its algorithm
  argument.

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