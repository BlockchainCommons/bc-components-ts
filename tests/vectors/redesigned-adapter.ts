/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion */
/**
 * The adapter over the working tree. Edited by the mechanical API passes
 * together with the rest of the tests.
 */
import {
  type VectorApi,
  type RngSpec,
  type ValueType,
  type Scheme,
  type SshAlg,
  type ParamsSpec,
  type DecodeType,
  type Recipe,
  toBytes,
  hex,
  num,
  FAKE_FILL,
} from "./recipes";
import { decodeCbor, asTaggedValue, TagsStore } from "@blockchaincommons/dcbor";
import { Spec, GroupSpec, Secret } from "@blockchaincommons/sskr";
import { UR, decodeURWith } from "@blockchaincommons/uniform-resources";

/**
 * The pre-redesign (Rust-shaped) surface: `X.fromData`, `taggedCborData()`,
 * `urString()`, `sskrGenerateSharesUsing`, … `rand` is whichever rand module
 * pairs with `m` (the frozen rand baseline for the frozen bundle, the
 * redesigned rand for the working tree).
 */
export function redesignedShapedAdapterFor(
  m: any,
  rand: any,
  opts: { newRand: boolean },
): VectorApi {
  // A generator object that satisfies both rand interfaces.
  const gen = (fill: (d: Uint8Array) => void): any => ({
    fillRandomData: fill,
    fillBytes: fill,
    randomData: (n: number) => {
      const d = new Uint8Array(n);
      fill(d);
      return d;
    },
    nextU32: () => {
      throw new Error("unused");
    },
    nextU64: () => {
      throw new Error("unused");
    },
  });
  const rngOf = (spec: RngSpec): any => {
    if ("fake" in spec) return gen(FAKE_FILL);
    if ("hkdf" in spec) {
      const h = new m.HKDFRng(toBytes(spec.hkdf.km), spec.hkdf.salt);
      return gen((d) => h.fillBytes(d));
    }
    const seed = spec.seed.map(BigInt);
    const g = opts.newRand ? new rand.SeededRng(seed) : new rand.SeededRandomNumberGenerator(seed);
    return gen((d) => (opts.newRand ? g.fillBytes(d) : g.fillRandomData(d)));
  };
  const tagged = (v: any): string => hex(v.toCbor().toData());
  const urOf = (v: any): string => (typeof v.toUR === "function" ? v.toUR().toString() : "-");
  const codable = (v: any): string => `${tagged(v)}|${urOf(v)}`;
  const B = toBytes;
  const valueOf = (type: ValueType, data: Uint8Array): any => {
    switch (type) {
      case "digest":
        return m.Digest.from(data);
      case "nonce":
        return m.Nonce.from(data);
      case "salt":
        return m.Salt.from(data);
      case "arid":
        return m.ARID.from(data);
      case "uuid":
        return m.UUID.from(data);
      case "xid":
        return m.XID.from(data);
      case "reference":
        return m.Reference.from(data);
      case "symmetricKey":
        return m.SymmetricKey.from(data);
      case "json":
        return m.CborJson.from(data);
      case "uri":
        return m.URI.from(new TextDecoder().decode(data));
      case "authTag":
        return m.AuthenticationTag.from(data);
      case "x25519Priv":
        return m.X25519PrivateKey.from(data);
      case "x25519Pub":
        return m.X25519PublicKey.from(data);
      case "ecPriv":
        return m.ECPrivateKey.from(data);
      case "ecPub":
        return m.ECPublicKey.from(data);
      case "ecUncompressed":
        return m.ECUncompressedPublicKey.from(data);
      case "schnorrPub":
        return m.SchnorrPublicKey.from(data);
      case "ed25519Priv":
        return m.Ed25519PrivateKey.from(data);
      case "ed25519Pub":
        return m.Ed25519PublicKey.from(data);
      case "privateKeyBase":
        return m.PrivateKeyBase.from(data);
      case "sskrShare":
        return m.SskrShare.from(data);
    }
  };
  const describe = (v: any): string => {
    if (typeof v.toCbor === "function") return codable(v);
    if (typeof v.toCborData === "function") return hex(v.toCborData());
    if (typeof v.toData === "function") return hex(v.bytes);
    return hex(v.bytes);
  };
  const signingPriv = (scheme: Scheme, key: Uint8Array): any => {
    switch (scheme) {
      case "schnorr":
        return m.SigningPrivateKey.fromSchnorr(m.ECPrivateKey.from(key));
      case "ecdsa":
        return m.SigningPrivateKey.fromEcdsa(m.ECPrivateKey.from(key));
      case "ed25519":
        return m.SigningPrivateKey.fromEd25519(m.Ed25519PrivateKey.from(key));
    }
  };
  const schemeEnum = (s: Scheme): any =>
    ({ schnorr: "Schnorr", ecdsa: "Ecdsa", ed25519: "Ed25519" })[s];
  const sshAlgOf = (a: SshAlg): any =>
    a === "ed25519"
      ? { kind: "ed25519" }
      : { kind: "ecdsa", curve: a === "ecdsa-p256" ? "nistp256" : "nistp384" };
  const paramsOf = (p: ParamsSpec): any => {
    const salt = m.Salt.from(B(p.salt));
    const hash = p.hash === "sha512" ? m.HashType.SHA512 : m.HashType.SHA256;
    switch (p.method) {
      case "hkdf":
        return m.hkdfParams(m.HKDFParams.from({ salt: salt, hashType: hash }));
      case "pbkdf2":
        return m.pbkdf2Params(
          m.PBKDF2Params.from({
            salt: salt,
            iterations: p.iterations ?? m.DEFAULT_PBKDF2_ITERATIONS,
            hashType: hash,
          }),
        );
      case "scrypt":
        return m.scryptParams(
          m.ScryptParams.from({
            salt: salt,
            logN: p.logN ?? m.DEFAULT_SCRYPT_LOG_N,
            r: p.r ?? m.DEFAULT_SCRYPT_R,
            p: p.p ?? m.DEFAULT_SCRYPT_P,
          }),
        );
      case "argon2id":
        return m.argon2idParams(m.Argon2idParams.from({ salt: salt }));
      case "sshAgent":
        return m.sshAgentParams(m.SSHAgentParams.from({ salt: salt, id: p.id ?? "id" }));
    }
  };
  const decoder = (type: DecodeType): any =>
    ({
      digest: m.Digest,
      nonce: m.Nonce,
      salt: m.Salt,
      arid: m.ARID,
      uuid: m.UUID,
      xid: m.XID,
      reference: m.Reference,
      symmetricKey: m.SymmetricKey,
      json: m.CborJson,
      uri: m.URI,
      x25519Priv: m.X25519PrivateKey,
      x25519Pub: m.X25519PublicKey,
      ecPriv: m.ECPrivateKey,
      ecPub: m.ECPublicKey,
      ecUncompressed: m.ECUncompressedPublicKey,
      privateKeyBase: m.PrivateKeyBase,
      sskrShare: m.SskrShare,
      seed: m.Seed,
      compressed: m.Compressed,
      encryptedMessage: m.EncryptedMessage,
      signature: m.Signature,
      signingPriv: m.SigningPrivateKey,
      signingPub: m.SigningPublicKey,
      encapPriv: m.EncapsulationPrivateKey,
      encapPub: m.EncapsulationPublicKey,
      encapCiphertext: m.EncapsulationCiphertext,
      sealedMessage: m.SealedMessage,
      privateKeys: m.PrivateKeys,
      publicKeys: m.PublicKeys,
      encryptedKey: m.EncryptedKey,
      mldsaPriv: m.MLDSAPrivateKey,
      mldsaPub: m.MLDSAPublicKey,
      mldsaSig: m.MLDSASignature,
      mlkemPriv: m.MLKEMPrivateKey,
      mlkemPub: m.MLKEMPublicKey,
      mlkemCiphertext: m.MLKEMCiphertext,
    })[type as string];
  const mldsaLevel = (l: 44 | 65 | 87): any => m.MLDSALevel[`MLDSA${l}`];
  /**
   * The JS-only input domain, one closure per named case; the outcome
   * records the thrown class AND code so a foreign class (dcbor, rand,
   * crypto, noble) leaking unwrapped would still be visible.
   */
  const fakeRng = (): any => gen(FAKE_FILL);
  const ff32 = new Uint8Array(32).fill(0xff);
  const domainCases: Record<string, () => unknown> = {
    "salt.random.length.NaN": () => m.Salt.random({ length: NaN, rng: fakeRng() }),
    "salt.random.length.1.5": () => m.Salt.random({ length: 1.5, rng: fakeRng() }),
    "salt.random.length.-1": () => m.Salt.random({ length: -1, rng: fakeRng() }),
    "salt.random.length.Infinity": () => m.Salt.random({ length: Infinity, rng: fakeRng() }),
    "seed.random.length.1.5": () => m.Seed.random({ length: 1.5, rng: fakeRng() }),
    "seed.random.length.NaN": () => m.Seed.random({ length: NaN, rng: fakeRng() }),
    "nonce.random.rng.missingFill": () => m.Nonce.random({ rng: {} }),
    "hkdfRng.pageLength.1.5": () =>
      new m.HKDFRng(new Uint8Array(16), "s", { pageLength: 1.5 }).nextU32(),
    "hkdfRng.pageLength.-1": () =>
      new m.HKDFRng(new Uint8Array(16), "s", { pageLength: -1 }).nextU32(),
    "seed.name.number": () => m.Seed.from(new Uint8Array(16), { name: 42 }),
    "seed.note.object": () => m.Seed.from(new Uint8Array(16), { note: {} }),
    "seed.creationDate.string": () =>
      m.Seed.from(new Uint8Array(16), { creationDate: "2020-01-01" }),
    "mldsa.level.99": () => m.MLDSAPrivateKey.random(99, { rng: fakeRng() }),
    "mlkem.level.99": () => m.MLKEMPrivateKey.random(99, { rng: fakeRng() }),
    "digest.fromHex.zz": () => m.Digest.fromHex("zz"),
    "digest.fromHex.odd": () => m.Digest.fromHex("abc"),
    "ecPub.fromHex.zz": () => m.ECPublicKey.fromHex("zz"),
    "symmetricKey.fromHex.short": () => m.SymmetricKey.fromHex("00"),
    "ecPriv.invalidScalar.publicKey": () => m.ECPrivateKey.from(ff32).publicKey(),
    "ecPriv.zeroScalar.publicKey": () => m.ECPrivateKey.from(new Uint8Array(32)).publicKey(),
    "x25519.lowOrder.sharedKey": () =>
      m.X25519PrivateKey.from(new Uint8Array(32).fill(1)).sharedKeyWith(
        m.X25519PublicKey.from(new Uint8Array(32)),
      ),
    "symmetricKey.decrypt.tamperedTag": () => {
      const k = m.SymmetricKey.from(new Uint8Array(32).fill(7));
      const msg = k.encrypt(new Uint8Array(4), { nonce: m.Nonce.from(new Uint8Array(12)) });
      return k.decrypt(
        m.EncryptedMessage.from({
          ciphertext: msg.ciphertext,
          nonce: msg.nonce,
          authTag: m.AuthenticationTag.from(new Uint8Array(16)),
          aad: msg.aad,
        }),
      );
    },
    "encryptedKey.unlock.wrongPassword": () =>
      m.EncryptedKey.lock(
        m.KeyDerivationMethod.HKDF,
        new Uint8Array([1]),
        m.SymmetricKey.from(new Uint8Array(32).fill(7)),
      ).unlock(new Uint8Array([2])),
    "kdf.pbkdf2.iterations.0.lock": () =>
      m.EncryptedKey.lockOpt(
        m.pbkdf2Params(
          m.PBKDF2Params.from({ salt: m.Salt.from(new Uint8Array(16)), iterations: 0 }),
        ),
        new Uint8Array([1]),
        m.SymmetricKey.from(new Uint8Array(32).fill(7)),
      ),
    "kdf.scrypt.logN.100.lock": () =>
      m.EncryptedKey.lockOpt(
        m.scryptParams(m.ScryptParams.from({ salt: m.Salt.from(new Uint8Array(16)), logN: 100 })),
        new Uint8Array([1]),
        m.SymmetricKey.from(new Uint8Array(32).fill(7)),
      ),
    "digest.from.undefined": () => m.Digest.from(undefined),
    "arid.from.null": () => m.ARID.from(null),
  };
  const mlkemLevel = (l: 512 | 768 | 1024): any => m.MLKEMLevel[`MLKEM${l}`];

  return {
    errorCode: (e) => {
      const x = e as any;
      const name = String(x?.name ?? "Error");
      // dcbor's own class: reported under the reference's `Error::Cbor` name
      // — the tree wraps every dcbor failure that crosses its boundary as
      // `Cbor`, and this adapter's own `decodeCbor` parse step is the twin
      // of the reference's `CBOR::try_from_data`.
      if (name === "CborError") return "Cbor";
      // uniform-resources: nine classes before the redesign, one `URError`
      // with a code after it; both sides report the code name.
      const UR: Record<string, string> = {
        InvalidSchemeError: "InvalidScheme",
        TypeUnspecifiedError: "TypeUnspecified",
        InvalidTypeError: "InvalidType",
        NotSinglePartError: "NotSinglePart",
        UnexpectedTypeError: "UnexpectedType",
        BytewordsError: "Bytewords",
        CBORError: "Cbor",
        URDecodeError: "Decoder",
      };
      if (name in UR) return UR[name] as string;
      if (name === "URError" && typeof x?.code === "string") return x.code as string;
      return String(x?.errorKind ?? x?.code ?? x?.type ?? name);
    },
    run(r) {
      switch (r.k) {
        case "value": {
          const v = valueOf(r.type, B(r.data));
          const extras: string[] = [];
          if (r.type === "ecPriv")
            extras.push(hex(v.publicKey().bytes), hex(v.schnorrPublicKey().bytes));
          if (r.type === "ed25519Priv" || r.type === "x25519Priv")
            extras.push(hex(v.publicKey().bytes));
          if (r.type === "ecPub") extras.push(hex(v.uncompressedPublicKey().bytes));
          if (r.type === "ecUncompressed") extras.push(hex(v.compressedData()));
          if (r.type === "xid")
            extras.push(
              v.bytewordsIdentifier(true),
              v.bytemojisIdentifier(true),
              v.shortDescription(),
            );
          if (r.type === "reference")
            extras.push(v.refHexShort(), v.bytewordsIdentifier(), v.bytemojiIdentifier());
          if (r.type === "uuid") extras.push(v.toString());
          if (r.type === "sskrShare")
            extras.push(
              `${v.identifier},${v.groupThreshold},${v.groupCount},${v.groupIndex},${v.memberThreshold},${v.memberIndex}`,
            );
          return [describe(v), ...extras].join("|");
        }
        case "saltInRange":
        case "saltForSize": {
          // A real generator (the `gen()` wrapper has no integer draws): the
          // length is a sampler draw and must consume the generator as the
          // reference's `rng_next_in_closed_range::<usize>` does.
          if (!opts.newRand || "fake" in r.rng) return "js-only";
          const g =
            "hkdf" in r.rng
              ? new m.HKDFRng(toBytes(r.rng.hkdf.km), r.rng.hkdf.salt)
              : new rand.SeededRng(r.rng.seed.map(BigInt));
          const salt =
            r.k === "saltInRange"
              ? m.Salt.randomInRange(r.min, r.max, { rng: g })
              : m.Salt.forSize(r.size, { rng: g });
          return hex(salt.bytes);
        }
        case "random": {
          const rng = rngOf(r.rng);
          switch (r.type) {
            case "nonce":
              return hex(m.Nonce.random({ rng: rng }).bytes);
            case "salt":
              return hex(m.Salt.random({ length: r.len ?? 16, rng: rng }).bytes);
            case "arid":
              return hex(m.ARID.from(rng.randomData(32)).bytes);
            case "uuid":
              return hex(m.UUID.from(rng.randomData(16)).bytes);
            case "symmetricKey":
              return hex(m.SymmetricKey.random({ rng: rng }).bytes);
            case "x25519Priv":
              return hex(m.X25519PrivateKey.random({ rng: rng }).bytes);
            case "ecPriv":
              return hex(m.ECPrivateKey.random({ rng: rng }).bytes);
            case "ed25519Priv":
              return hex(m.Ed25519PrivateKey.random({ rng: rng }).bytes);
            case "privateKeyBase":
              return hex(m.PrivateKeyBase.random({ rng: rng }).bytes);
            case "seed":
              return hex(m.Seed.random({ length: r.len ?? 32, rng: rng }).bytes);
          }
          break;
        }
        case "derive": {
          const km = B(r.km);
          switch (r.type) {
            case "x25519": {
              const k = m.X25519PrivateKey.deriveFromKeyMaterial(km);
              return `${hex(k.bytes)}|${hex(k.publicKey().bytes)}`;
            }
            case "ec": {
              const k = m.ECPrivateKey.deriveFromKeyMaterial(km);
              return `${hex(k.bytes)}|${hex(k.publicKey().bytes)}|${hex(k.schnorrPublicKey().bytes)}`;
            }
            case "ed25519": {
              const k = m.Ed25519PrivateKey.deriveFromKeyMaterial(km);
              return `${hex(k.bytes)}|${hex(k.publicKey().bytes)}`;
            }
          }
          break;
        }
        case "digest": {
          const d = m.Digest.fromImage(B(r.image));
          return `${hex(d.bytes)}|${d.toUR().toString()}|${d.shortDescription()}`;
        }
        case "compressed": {
          const data = B(r.data);
          const c = m.Compressed.fromDecompressedData(
            data,
            r.digest ? m.Digest.fromImage(data) : undefined,
          );
          const back = c.decompress();
          return `${tagged(c)}|${hex(back) === hex(data) ? "roundtrip" : "MISMATCH"}`;
        }
        case "seed": {
          const s = m.Seed.from(B(r.data), {
            name: r.name,
            note: r.note,
            creationDate: r.date === undefined ? undefined : new Date(r.date),
          });
          return codable(s);
        }
        case "encrypt": {
          const key = m.SymmetricKey.from(B(r.key));
          const msg = key.encrypt(B(r.plaintext), {
            ...(r.aad ? { aad: B(r.aad) } : {}),
            nonce: m.Nonce.from(B(r.nonce)),
          });
          const back = key.decrypt(msg);
          return `${codable(msg)}|${hex(back) === hex(B(r.plaintext)) ? "roundtrip" : "MISMATCH"}`;
        }
        case "x25519Shared": {
          const priv = m.X25519PrivateKey.from(B(r.priv));
          return hex(priv.sharedKeyWith(m.X25519PublicKey.from(B(r.pub))).bytes);
        }
        case "signingKeys": {
          const priv = signingPriv(r.scheme, B(r.key));
          const pub = priv.publicKey();
          return `${codable(priv)}|${codable(pub)}|${hex(m.XID.fromSigningPublicKey(pub).bytes)}|${hex(pub.reference().bytes)}`;
        }
        case "sign": {
          const priv = signingPriv(r.scheme, B(r.key));
          const msg = B(r.message);
          const sig = r.rng
            ? priv.signWithOptions(msg, { type: "Schnorr", rng: rngOf(r.rng) })
            : priv.sign(msg);
          const ok = priv.publicKey().verify(sig, msg);
          return `${codable(sig)}|${ok ? "verified" : "INVALID"}`;
        }
        case "sshFromSeed": {
          const pkb = m.PrivateKeyBase.from(B(r.seed));
          const priv = pkb.sshSigningPrivateKey(sshAlgOf(r.alg), r.comment);
          const pub = priv.publicKey();
          const parts = [priv.toSshOpenssh(), pub.toSshOpenssh(), tagged(priv), tagged(pub)];
          if (r.message) {
            const sig = priv.signWithOptions(B(r.message), {
              type: "Ssh",
              namespace: r.namespace ?? "test",
              hashAlg: "sha256",
            });
            parts.push(tagged(sig), pub.verify(sig, B(r.message)) ? "verified" : "INVALID");
          }
          return parts.join("|");
        }
        case "sshFromPem": {
          const key = m.SSHPrivateKey.fromOpenssh(r.pem);
          const priv = m.SigningPrivateKey.fromSsh(key);
          const pub = priv.publicKey();
          const parts = [
            key.toOpenssh() === r.pem ? "pem-roundtrip" : "PEM-DIFF",
            pub.toSshOpenssh(),
            tagged(pub),
          ];
          if (r.message) {
            const sig = priv.signWithOptions(B(r.message), {
              type: "Ssh",
              namespace: r.namespace ?? "test",
              hashAlg: "sha256",
            });
            parts.push(tagged(sig), pub.verify(sig, B(r.message)) ? "verified" : "INVALID");
          }
          return parts.join("|");
        }
        case "pkb": {
          const pkb = m.PrivateKeyBase.from(B(r.seed));
          const ed = pkb.ed25519SigningPrivateKey();
          const sch = pkb.schnorrSigningPrivateKey();
          const ec = pkb.ecdsaSigningPrivateKey();
          const x = pkb.x25519PrivateKey();
          return [
            codable(pkb),
            tagged(ed),
            tagged(sch.publicKey()),
            tagged(ec),
            hex(x.bytes),
            hex(x.publicKey().bytes),
            tagged(pkb.ed25519PublicKeys()),
            tagged(pkb.schnorrPublicKeys()),
            tagged(pkb.ecdsaPrivateKeys()),
          ].join("|");
        }
        case "keypair": {
          const encEnum = {
            x25519: m.EncapsulationScheme.X25519,
            mlkem512: m.EncapsulationScheme.MLKEM512,
            mlkem768: m.EncapsulationScheme.MLKEM768,
            mlkem1024: m.EncapsulationScheme.MLKEM1024,
          }[r.encScheme];
          const [priv, pub] = m.generateKeypair({
            signing: m.SignatureScheme[schemeEnum(r.sigScheme)],
            encapsulation: encEnum,
            rng: rngOf(r.rng),
          });
          return `${codable(priv)}|${codable(pub)}|${hex(pub.reference().bytes)}|${pub.equals(priv.publicKeys()) ? "consistent" : "INCONSISTENT"}`;
        }
        case "seal": {
          let priv: any;
          if ("x25519" in r.recipient)
            priv = m.EncapsulationPrivateKey.fromX25519PrivateKey(
              m.X25519PrivateKey.from(B(r.recipient.x25519)),
            );
          else
            priv = m.EncapsulationPrivateKey.randomMlkem(mlkemLevel(r.recipient.mlkem), {
              rng: rngOf(r.recipient.rng),
            });
          const pub = priv.publicKey();
          const pt = B(r.plaintext);
          const opts: Record<string, unknown> = {};
          if (r.aad) opts["aad"] = B(r.aad);
          if (r.nonce) opts["nonce"] = m.Nonce.from(B(r.nonce));
          const sealed = m.SealedMessage.seal(pt, pub, opts);
          const back = sealed.decrypt(priv);
          const bytes = sealed.toCbor().toData();
          const re = m.SealedMessage.fromCbor(decodeCbor(bytes));
          return `${sealed.encapsulationScheme}|len=${bytes.length}|${hex(back) === hex(pt) ? "roundtrip" : "MISMATCH"}|${hex(re.decrypt(priv)) === hex(pt) ? "cbor-roundtrip" : "CBOR-MISMATCH"}|${"x25519" in r.recipient ? tagged(pub) : `pubLen=${pub.toCbor().toData().length}`}`;
        }
        case "params": {
          const kdp = paramsOf(r);
          const methodName = ["hkdf", "pbkdf2", "scrypt", "argon2id", "sshAgent"][
            Number(m.keyDerivationParamsMethod(kdp))
          ];
          return `${hex(m.keyDerivationParamsToCborData(kdp))}|${m.keyDerivationParamsToString(kdp)}|${methodName}`;
        }
        case "encryptedKey": {
          if (r.method === "sshAgent") {
            try {
              m.EncryptedKey.lockOpt(paramsOf(r), B(r.secret), m.SymmetricKey.from(B(r.key)));
              return "locked";
            } catch (e) {
              return `unsupported:${this.errorCode(e)}`;
            }
          }
          const key = m.SymmetricKey.from(B(r.key));
          const ek = m.EncryptedKey.lockOpt(paramsOf(r), B(r.secret), key);
          const bytes = ek.toCbor().toData();
          const re = m.EncryptedKey.fromCbor(decodeCbor(bytes));
          const back = re.unlock(B(r.secret));
          let wrong = "wrong-secret-rejected";
          try {
            re.unlock(new Uint8Array([1, 2, 3]));
            wrong = "WRONG-SECRET-ACCEPTED";
          } catch {
            /* expected */
          }
          return `${m.keyDerivationParamsToString(re.params)}|len=${bytes.length}|${back.equals(key) ? "unlocked" : "MISMATCH"}|${wrong}|aad=${hex(ek.encryptedMessage.aad)}`;
        }
        case "hkdfRng": {
          const g = r.pageLen
            ? new m.HKDFRng(B(r.km), r.salt, { pageLength: r.pageLen })
            : new m.HKDFRng(B(r.km), r.salt);
          return (
            r.draws.map((n) => hex(g.randomData(n))).join("|") +
            `|u32=${g.nextU32()}|u64=${g.nextU64()}`
          );
        }
        case "mldsa": {
          const priv = m.MLDSAPrivateKey.random(mldsaLevel(r.level), { rng: rngOf(r.rng) });
          const pub = priv.publicKey();
          const parts = [codable(priv), codable(pub)];
          if (r.message) {
            const sig = priv.sign(B(r.message));
            parts.push(
              `sigLen=${sig.toCbor().toData().length}`,
              pub.verify(sig, B(r.message)) ? "verified" : "INVALID",
            );
          }
          return parts.join("|");
        }
        case "mlkem": {
          const priv = m.MLKEMPrivateKey.random(mlkemLevel(r.level), { rng: rngOf(r.rng) });
          const pub = priv.publicKey();
          const { sharedSecret, ciphertext } = pub.encapsulate();
          const back = priv.decapsulate(ciphertext);
          return `${codable(priv)}|${codable(pub)}|ctLen=${ciphertext.toCbor().toData().length}|${back.equals(sharedSecret) ? "decapsulated" : "MISMATCH"}`;
        }
        case "sskr": {
          const spec = Spec.from({
            groupThreshold: r.spec.gt,
            groups: r.spec.groups.map((g) =>
              GroupSpec.from({ memberThreshold: g.mt, memberCount: g.mc }),
            ),
          });
          const groups = m.SskrShare.generate(spec, Secret.from(B(r.secret)), {
            rng: rngOf(r.rng),
          });
          const quorum: any[] = [];
          for (let gi = 0; gi < r.spec.gt; gi++)
            for (let mi = 0; mi < r.spec.groups[gi]!.mt; mi++) quorum.push(groups[gi][mi]);
          const back = m.SskrShare.combine(quorum);
          return (
            groups.map((g: any[]) => g.map(tagged).join(",")).join(";") +
            `|${hex(back.bytes) === hex(B(r.secret)) ? "combined" : "MISMATCH"}`
          );
        }
        case "decode": {
          const v = decoder(r.type).fromCbor(
            decodeCbor(Uint8Array.from(Buffer.from(r.hex, "hex"))),
          );
          return describe(v);
        }
        case "urParse": {
          const v = decodeURWith(UR.parse(r.s), decoder(r.type).codec);
          return describe(v);
        }
        case "verifyStrict": {
          const pub = m.SigningPublicKey.fromEd25519(m.Ed25519PublicKey.from(B(r.pub)));
          return pub.verify(m.Signature.ed25519FromData(B(r.sig)), B(r.message))
            ? "valid"
            : "invalid";
        }
        case "decodeUntagged": {
          const v = decoder(r.type).fromCbor(
            decodeCbor(Uint8Array.from(Buffer.from(r.hex, "hex"))),
          );
          return describe(v);
        }
        case "signingDefault": {
          const a = m.SigningPrivateKey.random({ rng: rngOf(r.rng) }).scheme;
          const b = m.generateKeypair({ rng: rngOf(r.rng) })[0].signingPrivateKey.scheme;
          return `${a}|${b}`;
        }
        case "kdfDomain": {
          const salt = m.Salt.from(new Uint8Array(16));
          if (r.method === "pbkdf2") {
            const p = m.PBKDF2Params.from({
              salt,
              iterations: r.iterations === undefined ? undefined : num(r.iterations),
            });
            return `ok:${p.iterations}`;
          }
          const p = m.ScryptParams.from({
            salt,
            logN: r.logN === undefined ? undefined : num(r.logN),
            r: r.r === undefined ? undefined : num(r.r),
            p: r.p === undefined ? undefined : num(r.p),
          });
          return `ok:${p.logN},${p.r},${p.p}`;
        }
        case "summary": {
          const store = new TagsStore();
          m.registerComponentSummarizers(store);
          const tv = asTaggedValue(decodeCbor(Uint8Array.from(Buffer.from(r.hex, "hex"))));
          if (tv === undefined) return "untagged";
          const s = store.summarizer(tv[0].value);
          if (s === undefined) return "none";
          const out = s(tv[1], false);
          return out.ok ? out.value : "error";
        }
        case "domain": {
          const f = domainCases[r.case];
          if (f === undefined) throw new Error(`unknown domain case ${r.case}`);
          try {
            const v = f();
            return `ok:${typeof v === "string" ? v : typeof v === "number" ? String(v) : describe(v)}`;
          } catch (e) {
            const x = e as { constructor: { name: string }; code?: string };
            return `throw:${x.constructor.name}${x.code === undefined ? "" : `:${x.code}`}`;
          }
        }
      }
      throw new Error(`unhandled recipe ${(r as Recipe).k}`);
    },
  };
}
