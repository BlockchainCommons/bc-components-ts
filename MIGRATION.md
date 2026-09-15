# Migrating from `@bcts/components` to `@blockchaincommons/components`

`@blockchaincommons/components` is the successor to `@bcts/components`.

## TL;DR checklist

- [ ] Replace the `@bcts/components` dependency with `@blockchaincommons/components`.
- [ ] Rewrite import specifiers: `@bcts/components` becomes `@blockchaincommons/components`.
- [ ] Raise your Node floor to **22.12**.
- [ ] Ensure TypeScript **>= 5.7** to consume the published types.
- [ ] If you relied on the `browser` field or a global-script build, switch to the ESM or CJS entry point.

## 1. Package name and imports

```diff
- import { /* ... */ } from "@bcts/components";
+ import { /* ... */ } from "@blockchaincommons/components";
```

```diff
  "dependencies": {
-   "@bcts/components": "^1.0.0-beta.6"
+   "@blockchaincommons/components": "^1.0.0-beta.1"
  }
```

## 2. Version numbering restarts

`@bcts/components` versions moved in lockstep with every other `@bcts`
package, which is why it reached `1.0.0-beta.6`. Each extracted package now
versions independently and starts again at `1.0.0-beta.1`. A lower version
number here does **not** mean older code.

## 3. Node and TypeScript floors moved up

| | `@bcts/components` | `@blockchaincommons/components` |
|---|---|---|
| Node | `>= 18` | `>= 22.12` |
| TypeScript (consumers) | 6.x | `>= 5.7` |

## 4. The IIFE / global-script build is gone

`@bcts/components` shipped an additional IIFE bundle exposed through the `browser`
field. That build is dropped: IIFE entry points cannot share chunks, which forks
module-level singletons across entry points. Use the ESM entry (`import`) or the
CJS entry (`require`); both are declared in `exports` and validated in CI by
`publint` and `@arethetypeswrong/cli`.

## 5. Peer packages renamed too

Every sibling library moved from the `@bcts` scope to `@blockchaincommons`. If
you depend on more than one, rename them together so a single copy of each
shared type is resolved:

| Old | New |
|---|---|
| `@bcts/dcbor` | `@blockchaincommons/dcbor` |
| `@bcts/<name>` | `@blockchaincommons/<name>` |

## 6. What did not change

- The public API: every exported name, signature and type is identical.
- The wire format. Encodings produced by `@bcts/components` decode here, and the reverse.
- Parity with the Rust reference implementation, replayed against the published crate by [`tests/rust-validation`](./tests/rust-validation/README.md).

---

# Migrating to 1.0.0-beta.3

`1.0.0-beta.3` aligns the package with `bc-components-rust` 0.31.1 point by
point (see the CHANGELOG for the full list). What a caller has to change:

- **Register the tags before `toUR()`.** Call `registerTags()` from
  `@blockchaincommons/components/tags` once at start-up, as the reference
  calls `register_tags()`; `toUR()` throws `URError` `TagUnnamed` until then,
  and `codec.tags` / `cborTags()` names follow the process-wide store.
- **Catch `Cbor` for every decode failure.** `fromCbor`, `codec.decode` and
  `decodeWith` throw `ComponentsError` with code `Cbor` and the reference's
  message; the leaf codes (`InvalidSize`, `InvalidData`, `PostQuantum`, …)
  no longer surface from a decoder (the `cause` chain keeps the leaf error).
  `HashType`, `AuthenticationTag`, the ML-KEM/ML-DSA levels and
  `KeyDerivationMethod` keep their own codes.
- **Removed:** `toUR()` on the three encapsulation enums; `fromCbor`/`codec`
  on `ECPrivateKey`, `ECPublicKey`, `ECUncompressedPublicKey`,
  `SchnorrPublicKey` (encode only, as the reference); `MLKEMPrivateKey.publicKey()`,
  `MLDSAPrivateKey.publicKey()`, `mlkemExtractPublicKey`; `HKDFRng.randomData`,
  `tryFillBytes`, `fillRandomData` (use `fillBytes`); `ComponentsError.invalidSizeForType`
  (use `invalidSize(dataType, expected, actual)`); `bytesFromHex(hex, what)`
  is `bytesFromHex(hex)`.
- **Post-quantum keys:** `EncapsulationPrivateKey.publicKey()` throws for
  ML-KEM and `SigningPrivateKey.publicKey()` for ML-DSA; keep the public key
  the keypair factory hands out. `generateKeypair` / `createKeypair` with a
  post-quantum scheme and an `rng` throw `General`; use
  `MLKEMPrivateKey.keypair(level, { rng })` / `MLDSAPrivateKey.keypair(level, { rng })`
  for seeded post-quantum keys.
- **EC keys are validated at first use**, not at construction: `ECPrivateKey.from`
  accepts any 32 bytes and `publicKey()` / `sign` throw `InvalidData` for a
  zero or out-of-range scalar; the same for the public-key classes.
- **`verify` can throw.** An undecodable Ed25519, Schnorr or ECDSA public key,
  or an ECDSA signature with `r` or `s` ≥ n, throws `InvalidData` (the
  reference panics there); wrap `verify` where untrusted keys reach it.
- `X25519PrivateKey.sharedKeyWith` a low-order point returns the reference's
  fixed key instead of throwing; PBKDF2 `iterations: 0` and scrypt `logN: 0`
  derive.
- `Compressed.decompressedSize` is a `number | bigint` (exact `usize`);
  `Compressed.equals` compares digests; `SskrShare.from` never throws and the
  header accessors throw `InvalidData` on a short share; `Seed.creationDate`
  round-trips through `CborDate` (`creationCborDate` keeps the precision).
- `X.fromHex` is strict (no whitespace); `UUID.fromString` trims and drops
  `-` only; `URI.from` rejects with `InvalidData`; `CborJson.asStr` keeps a
  leading BOM.
-  DEFLATE is a port of `miniz_oxide`, so `Compressed` bytes are the reference's.
- **New:** SSH-agent lock/unlock (`SSHAgentParams.lock`/`unlock`,
  `EncryptedKey.lockWithAgent`/`unlockWithAgent`, `MemorySshAgent`, and the
  Node transport `@blockchaincommons/components/ssh-agent-node`); SSH DSA,
  RSA and ECDSA P-521 keys; `HKDFRng` page length 0; error codes `Env` and
  `SshAgentClient`.

---

# Migrating to the 1.0.0-beta.1 API

`1.0.0-beta.1` also reshapes the TypeScript surface; **every wire byte is
unchanged** (tagged CBOR, URs, derivations, signatures, encryption are
verified against a frozen `@bcts/components` baseline and against
`bc-components-rust` 0.31.1 by `tests/rust-validation`). What changed is
how you spell things.

## 0. Rust-parity checklist (2026-09)

These behaviours changed to match the Rust reference; all are in this
first release:

- [ ] `X.fromCbor(cbor)` requires the type's tag, as the reference's `from_tagged_cbor` does; decode tag-stripped content with `X.codec.decodeUntagged(cbor)`.
- [ ] `SigningPrivateKey.random()` and `createKeypair()` default to **Schnorr** (the reference's default and `defaultSignatureScheme()`); pass `{ scheme: SignatureScheme.Ed25519 }` for Ed25519.
- [ ] `key.encrypt(plaintext, { aad?, nonce? })`: the two trailing positionals became an options object.
- [ ] `SealedMessage.seal(pt, recipient, { aad?, nonce?, rng? })` and `encapsulateNewSharedSecret({ rng? })` take a generator, so sealing is reproducible; every `random` / `keypair` option object is rand's `RngOptions`; `createKeypair` and `createEncapsulationKeypair` honour `rng` for ML-DSA and ML-KEM too.
- [ ] Every failure is a `ComponentsError`: `Hex` (`X.fromHex`) and `Utf8` (`CborJson.asStr`) codes exist; dcbor failures surface as `Cbor`; crypto failures as `Crypto` (authentication) or `InvalidData` (a malformed key or parameter); a non-integer or out-of-width number (`length`, `pageLength`, `iterations`, `logN`, `r`, `p`) is `InvalidData` naming the parameter; an unknown ML-DSA / ML-KEM level is `PostQuantum`; a zero secp256k1 scalar or an off-curve point is `InvalidData` when the key is constructed; a corrupt DEFLATE stream is `Compression`. The original error is the `cause`.
- [ ] `bytes` (and `ciphertext`, `aad`, `asSchnorr()`, …) return copies; the enum objects and size tables are frozen.
- [ ] `toString()` of every key type prints the reference's `Display` form, `Type(<short reference>)`; `reference()` and `refHexShort()` exist on every key type.
- [ ] The tag summarisers live on `@blockchaincommons/components/tags` (`registerTags`, `registerTagsIn`, `registerComponentSummarizers`).
- [ ] There is no sr25519 anywhere: the reference has no such scheme.

## 1. One codable mechanism

| Before | After |
|---|---|
| `x.taggedCbor()` | `x.toCbor()` |
| `x.taggedCborData()` | `x.toCbor().toData()` |
| `x.untaggedCbor()` | unchanged |
| `x.ur()` / `x.urString()` | `x.toUR()` / `x.toUR().toString()` |
| `X.fromTaggedCbor(cbor)` | `X.fromCbor(cbor)` (tagged only) |
| `X.fromTaggedCborData(bytes)` / `X.fromUntaggedCborData(bytes)` | `X.fromCbor(decodeCbor(bytes))` or `decodeWith(bytes, X.codec)` |
| `X.fromUR(ur)` / `X.fromURString(s)` | `decodeURWith(ur, X.codec)` / `decodeURWith(UR.parse(s), X.codec)` |
| instance `fromUntaggedCbor` / `fromTaggedCbor` | `X.codec.decodeUntagged(cbor)` / `X.codec.decode(cbor)` |
| `X.UR_TYPE` | `X.codec.tags[0].name` |

`decodeCbor`/`decodeWith` come from `@blockchaincommons/dcbor`,
`UR`/`decodeURWith` from `@blockchaincommons/uniform-resources`. URs no
longer need the global tag registry: the UR type comes from the tag constant.

## 2. Names

| Before | After |
|---|---|
| `X.fromData(bytes)`, `X.fromDataRef(bytes)` | `X.from(bytes)` |
| `X.new()`, `X.newUsing(rng)`, `X.random()`, `X.randomUsing(rng)` | `X.random({ rng? })` |
| `X.keypair()`, `X.keypairUsing(rng)` | `X.keypair({ rng? })` |
| `MLDSAPrivateKey.new(level)` / `newUsing(level, rng)` | `MLDSAPrivateKey.random(level, { rng? })` (ML-KEM alike) |
| `EncapsulationPrivateKey.newMlkem(level)` / `newMlkemUsing` | `EncapsulationPrivateKey.randomMlkem(level, { rng? })` |
| `SigningPrivateKey.random()`, `randomSchnorr()`, … | `SigningPrivateKey.random({ scheme?, rng? })` |
| `SigningPrivateKey.newSchnorr(k)`, `newEcdsa`, `newEd25519`, `newMldsa` | `SigningPrivateKey.fromSchnorr(k)`, `fromEcdsa`, … |
| `Salt.newWithLen(n)`, `newInRange(a, b)`, `newForSize(n)`, `proportional(n)` (+ `Using`) | `Salt.random({ length?, rng? })`, `Salt.randomInRange(a, b, { rng? })`, `Salt.forSize(n, { rng? })` |
| `Seed.new()`, `newWithLen(n)`, `newOpt(data, name, note, date)`, `random(size, meta)` | `Seed.random({ length?, rng?, name?, note?, creationDate? })`, `Seed.from(data, { name?, note?, creationDate? })` |
| `seed.setName(n)`, `createdAt()`, `getMetadata()` | `seed.name = n`, `seed.creationDate`, `seed.metadata` |
| `x.data()`, `x.asBytes()`, `x.toData()` | `x.bytes` |
| `x.hex()` | `x.toHex()` |
| `x.len()`, `x.size()` | `x.byteLength` |
| `x.toSchnorr()`, `toEcdsa()`, `toEd25519()`, `toMldsa()`, `toSsh()`, `toEc()`, `toX25519()`, `toMlkem()` (`X | null`) | `x.asSchnorr()`, … (`X | undefined`) |
| `x.scheme()`, `encapsulationScheme()`, `level()`, `salt()`, `nonce()`, `aad()`, `ciphertext()`, `authenticationTag()`, `name()`, `note()`, `identifier()`, `groupIndex()`, … | getters: `x.scheme`, `x.level`, … |
| `hkdfRng.getKeyMaterial()`, `getSalt()`, `getPageLength()`, `getPageIndex()` | `keyMaterial`, `salt`, `pageLength`, `pageIndex` |
| `HKDFParams.new()` / `newOpt(salt, hash)` (and the other params) | `HKDFParams.from({ salt?, hashType? })`, `PBKDF2Params.from({ salt?, iterations?, hashType? })`, `ScryptParams.from({ salt?, logN?, r?, p? })`, `Argon2idParams.from({ salt? })`, `SSHAgentParams.from({ id, salt? })` |
| `SealedMessage.new(pt, r)`, `newWithAad(pt, r, aad)`, `newOpt(pt, r, aad, nonce)` | `SealedMessage.seal(pt, r, { aad?, nonce?, rng? })` |
| `key.encrypt(pt, aad, nonce)` | `key.encrypt(pt, { aad?, nonce? })` |
| `EncryptedMessage.new(ct, aad, nonce, tag)`, `from(nonce, ct, tag, aad)` | `EncryptedMessage.from({ ciphertext, nonce, authTag, aad? })` |
| `HKDFRng.new(km, salt)`, `newWithPageLength(km, salt, n)` | `new HKDFRng(km, salt, { pageLength? })` |
| `PrivateKeys.withKeys(s, e)`, `PrivateKeys.new()`, `PublicKeys.new(s, e)` | `PrivateKeys.from({ signing, encapsulation })`, `PrivateKeys.random({ rng? })`, `PublicKeys.from({ signing, encapsulation })` |
| `keypair()`, `keypairUsing(rng)`, `keypairOpt(s, e)`, `keypairOptUsing(s, e, rng)` | `generateKeypair({ signing?, encapsulation?, rng? })` |
| `createKeypair(scheme, comment)`, `createKeypairUsing(scheme, rng, comment)` | `createKeypair(scheme, { rng?, comment? })` |
| `createEncapsulationKeypair(scheme)`, `createEncapsulationKeypairUsing(rng, scheme)` | `createEncapsulationKeypair(scheme, { rng? })` |
| `Compressed.new(checksum, size, data, digest)` | `Compressed.fromParts({ checksum, decompressedSize, compressedData, digest })` |
| `URI.new(s)`, `URI.parse(s)` | `URI.from(s)` |
| `Reference.from(digest)` | `Reference.fromDigest(digest)` (`Reference.from` takes bytes) |
| `JSON` | `CborJson` |
| `XID.newFromSigningKey(k)` | `XID.fromSigningPublicKey(k)` |
| `hexToBytes` | dcbor's: whitespace inside hex is tolerated; malformed hex throws `CborError` from the utility and `ComponentsError` `Hex` from every `X.fromHex` |

## 3. Enums are `as const` objects

`SignatureScheme`, `EncapsulationScheme`, `KeyDerivationMethod`, `HashType`,
`MLDSALevel` and `MLKEMLevel` are plain objects plus string/number-literal
union types with the same member names and values. `SignatureScheme.Schnorr`
still works; so does the literal `"Schnorr"`.

## 4. Errors

`CryptoError` and `ErrorKind` become `ComponentsError` with `code` (a string
union), `details` discriminated by code, and `cause`. `isError`,
`isCryptoError`, `isCryptoErrorKind`, `errorKind`, `errorData`, `isKind()`
and the `isInvalidSize()`-style predicates are gone:

```diff
- if (isCryptoErrorKind(e, ErrorKind.InvalidSize)) console.log(e.errorData.expected);
+ if (ComponentsError.isComponentsError(e) && e.details.code === "InvalidSize")
+   console.log(e.details.expected);
```

`Hex` and `Utf8` are raised by `X.fromHex` and `CborJson.asStr`; `Env` and
`SshAgentClient` belong to the reference's `ssh-agent` feature, which is not
ported. Errors the package used to throw as bare `Error`, and every error a
dependency used to leak (`CborError`, `CryptoError`, `RangeError`), now carry
a code, with the original as `cause`.

## 5. Subpaths

The root entry no longer exports the SSH, post-quantum, KDF and SSKR
families. Import them from `@blockchaincommons/components/ssh`, `/pq`, `/kdf`
and `/sskr`; the tag summarisers are on `/tags`. `MLDSALevel`, `MLKEMLevel` and the `SshAlgorithm` types stay on
the root because root signatures use them.

## 6. SSKR

`SSKRShareCbor`, the `SSKRShare` alias object, `sskrGenerate*`,
`sskrCombine*`, `SimpleRng`, and the re-exported `SSKRSecret`/`SSKRSpec`/
`SSKRGroupSpec` are replaced by one `SskrShare` class on
`@blockchaincommons/components/sskr`, built on the sskr package's parsed
share (`SskrShare.from(share | bytes)`, `SskrShare.generate(spec, secret,
{ rng? })`, `SskrShare.combine(shares)`, `share.share`, `share.value`).
Splitting and recovery themselves are `generateShares`/`combineShares` from
`@blockchaincommons/sskr`.

## 7. Tags

`KNOWN_VALUE`, `ENVELOPE`, `LEAF`, `ENCRYPTED` and `COMPRESSED` are no longer
re-exported; import them from `@blockchaincommons/tags`.

## 8. Behaviour

- `SSHSignature` text wraps its base64 body at 70 columns (what OpenSSH and
  the reference emit) instead of 76; parsing accepts either.
- `createKeypair` for the ML-DSA schemes works (it used to throw).
- `hexToBytes` tolerates whitespace and throws `CborError`.
