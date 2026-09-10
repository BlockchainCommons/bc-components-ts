# Migrating from `@bcts/components` to `@blockchaincommons/components`

`@blockchaincommons/components` is the canonical home of this library. It was extracted from the
[`paritytech/bcts`](https://github.com/paritytech/bcts) monorepo, where it was
published as `@bcts/components`, into its own Blockchain Commons repository at
[`BlockchainCommons/bc-components-ts`](https://github.com/BlockchainCommons/bc-components-ts).

For the extraction release, **`1.0.0-beta.1`, the public API is unchanged.** The
migration is a rename. `@bcts/components` remains published for one beta cycle as a
thin re-export of this package, so nothing breaks the moment you update.

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

`@bcts/components` versions moved in lockstep with every other package in the
monorepo, which is why it reached `1.0.0-beta.6`. Each extracted package now
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
- Parity with the Rust reference implementation. See [`RUST_DIVERGENCES.md`](./RUST_DIVERGENCES.md).

---

# Migrating to the redesigned API (`1.0.0-beta.2`)

`1.0.0-beta.2` redesigns the TypeScript surface; **every wire byte is
unchanged** (tagged CBOR, URs, derivations, signatures, encryption are
verified against a frozen pre-redesign baseline and against
`bc-components-rust` 0.31.1 by `tests/rust-validation`). What changed is
how you spell things.

## 1. One codable mechanism

| Before | After |
|---|---|
| `x.taggedCbor()` | `x.toCbor()` |
| `x.taggedCborData()` | `x.toCbor().toData()` |
| `x.untaggedCbor()` | unchanged |
| `x.ur()` / `x.urString()` | `x.toUR()` / `x.toUR().toString()` |
| `X.fromTaggedCbor(cbor)` | `X.fromCbor(cbor)` (accepts tagged or untagged) |
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
| `SigningPrivateKey.newSchnorr(k)`, `newEcdsa`, `newEd25519`, `newSr25519`, `newMldsa` | `SigningPrivateKey.fromSchnorr(k)`, `fromEcdsa`, … |
| `Salt.newWithLen(n)`, `newInRange(a, b)`, `newForSize(n)`, `proportional(n)` (+ `Using`) | `Salt.random({ length?, rng? })`, `Salt.randomInRange(a, b, { rng? })`, `Salt.forSize(n, { rng? })` |
| `Seed.new()`, `newWithLen(n)`, `newOpt(data, name, note, date)`, `random(size, meta)` | `Seed.random({ length?, rng?, name?, note?, creationDate? })`, `Seed.from(data, { name?, note?, creationDate? })` |
| `seed.setName(n)`, `createdAt()`, `getMetadata()` | `seed.name = n`, `seed.creationDate`, `seed.metadata` |
| `x.data()`, `x.asBytes()`, `x.toData()` | `x.bytes` |
| `x.hex()` | `x.toHex()` |
| `x.len()`, `x.size()` | `x.byteLength` |
| `x.toSchnorr()`, `toEcdsa()`, `toEd25519()`, `toSr25519()`, `toMldsa()`, `toSsh()`, `toEc()`, `toX25519()`, `toMlkem()` (`X | null`) | `x.asSchnorr()`, … (`X | undefined`) |
| `x.scheme()`, `encapsulationScheme()`, `level()`, `salt()`, `nonce()`, `aad()`, `ciphertext()`, `authenticationTag()`, `name()`, `note()`, `identifier()`, `groupIndex()`, … | getters: `x.scheme`, `x.level`, … |
| `hkdfRng.getKeyMaterial()`, `getSalt()`, `getPageLength()`, `getPageIndex()` | `keyMaterial`, `salt`, `pageLength`, `pageIndex` |
| `HKDFParams.new()` / `newOpt(salt, hash)` (and the other params) | `HKDFParams.from({ salt?, hashType? })`, `PBKDF2Params.from({ salt?, iterations?, hashType? })`, `ScryptParams.from({ salt?, logN?, r?, p? })`, `Argon2idParams.from({ salt? })`, `SSHAgentParams.from({ id, salt? })` |
| `SealedMessage.new(pt, r)`, `newWithAad(pt, r, aad)`, `newOpt(pt, r, aad, nonce)` | `SealedMessage.seal(pt, r, { aad?, nonce? })` |
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
| `hexToBytes` | dcbor's: whitespace inside hex is tolerated; malformed hex throws `CborError` |

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

The `Hex`, `Utf8`, `Env` and `SshAgentClient` kinds (never raised) are gone.
Errors the package used to throw as bare `Error` now carry a code.

## 5. Subpaths

The root entry no longer exports the SSH, post-quantum, KDF and SSKR
families. Import them from `@blockchaincommons/components/ssh`, `/pq`, `/kdf`
and `/sskr`. `MLDSALevel`, `MLKEMLevel` and the `SshAlgorithm` types stay on
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
