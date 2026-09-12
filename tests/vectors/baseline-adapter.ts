/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion */
/**
 * FROZEN: the adapter over the pre-redesign bundle. Never edited by the
 * mechanical API passes; `redesigned-adapter.ts` is the working-tree twin.
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
  FAKE_FILL,
} from "./recipes";

/**
 * The pre-redesign (Rust-shaped) surface: `X.fromData`, `taggedCborData()`,
 * `urString()`, `sskrGenerateSharesUsing`, … `rand` is whichever rand module
 * pairs with `m` (the frozen rand baseline for the frozen bundle, the
 * redesigned rand for the working tree).
 */
export function rustShapedAdapterFor(m: any, rand: any, opts: { newRand: boolean }): VectorApi {
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
      const h = m.HKDFRng.new(toBytes(spec.hkdf.km), spec.hkdf.salt);
      return gen((d) => h.fillBytes(d));
    }
    const seed = spec.seed.map(BigInt);
    const g = opts.newRand ? new rand.SeededRng(seed) : new rand.SeededRandomNumberGenerator(seed);
    return gen((d) => (opts.newRand ? g.fillBytes(d) : g.fillRandomData(d)));
  };
  const tagged = (v: any): string => hex(v.taggedCborData());
  const urOf = (v: any): string => (typeof v.urString === "function" ? v.urString() : "-");
  const codable = (v: any): string => `${tagged(v)}|${urOf(v)}`;
  const B = toBytes;
  const valueOf = (type: ValueType, data: Uint8Array): any => {
    switch (type) {
      case "digest":
        return m.Digest.fromData(data);
      case "nonce":
        return m.Nonce.fromData(data);
      case "salt":
        return m.Salt.fromData(data);
      case "arid":
        return m.ARID.fromData(data);
      case "uuid":
        return m.UUID.fromData(data);
      case "xid":
        return m.XID.fromData(data);
      case "reference":
        return m.Reference.fromData(data);
      case "symmetricKey":
        return m.SymmetricKey.fromData(data);
      case "json":
        return m.JSON.fromData(data);
      case "uri":
        return m.URI.new(new TextDecoder().decode(data));
      case "authTag":
        return m.AuthenticationTag.fromData(data);
      case "x25519Priv":
        return m.X25519PrivateKey.fromData(data);
      case "x25519Pub":
        return m.X25519PublicKey.fromData(data);
      case "ecPriv":
        return m.ECPrivateKey.fromData(data);
      case "ecPub":
        return m.ECPublicKey.fromData(data);
      case "ecUncompressed":
        return m.ECUncompressedPublicKey.fromData(data);
      case "schnorrPub":
        return m.SchnorrPublicKey.fromData(data);
      case "ed25519Priv":
        return m.Ed25519PrivateKey.from(data);
      case "ed25519Pub":
        return m.Ed25519PublicKey.from(data);
      case "privateKeyBase":
        return m.PrivateKeyBase.fromData(data);
      case "sskrShare":
        return m.SSKRShareCbor.fromData(data);
    }
  };
  const describe = (v: any): string => {
    if (typeof v.taggedCborData === "function") return codable(v);
    if (typeof v.toCborData === "function") return hex(v.toCborData());
    if (typeof v.toData === "function") return hex(v.toData());
    return hex(v.asBytes());
  };
  const signingPriv = (scheme: Scheme, key: Uint8Array): any => {
    switch (scheme) {
      case "schnorr":
        return m.SigningPrivateKey.newSchnorr(m.ECPrivateKey.fromData(key));
      case "ecdsa":
        return m.SigningPrivateKey.newEcdsa(m.ECPrivateKey.fromData(key));
      case "ed25519":
        return m.SigningPrivateKey.newEd25519(m.Ed25519PrivateKey.from(key));
    }
  };
  const schemeEnum = (s: Scheme): any =>
    ({ schnorr: "Schnorr", ecdsa: "Ecdsa", ed25519: "Ed25519" })[s];
  const sshAlgOf = (a: SshAlg): any =>
    a === "ed25519"
      ? { kind: "ed25519" }
      : { kind: "ecdsa", curve: a === "ecdsa-p256" ? "nistp256" : "nistp384" };
  const paramsOf = (p: ParamsSpec): any => {
    const salt = m.Salt.fromData(B(p.salt));
    const hash = p.hash === "sha512" ? m.HashType.SHA512 : m.HashType.SHA256;
    switch (p.method) {
      case "hkdf":
        return m.hkdfParams(m.HKDFParams.newOpt(salt, hash));
      case "pbkdf2":
        return m.pbkdf2Params(
          m.PBKDF2Params.newOpt(salt, p.iterations ?? m.DEFAULT_PBKDF2_ITERATIONS, hash),
        );
      case "scrypt":
        return m.scryptParams(
          m.ScryptParams.newOpt(
            salt,
            p.logN ?? m.DEFAULT_SCRYPT_LOG_N,
            p.r ?? m.DEFAULT_SCRYPT_R,
            p.p ?? m.DEFAULT_SCRYPT_P,
          ),
        );
      case "argon2id":
        return m.argon2idParams(m.Argon2idParams.newOpt(salt));
      case "sshAgent":
        return m.sshAgentParams(m.SSHAgentParams.newOpt(salt, p.id ?? "id"));
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
      json: m.JSON,
      uri: m.URI,
      x25519Priv: m.X25519PrivateKey,
      x25519Pub: m.X25519PublicKey,
      ecPriv: m.ECPrivateKey,
      ecPub: m.ECPublicKey,
      ecUncompressed: m.ECUncompressedPublicKey,
      privateKeyBase: m.PrivateKeyBase,
      sskrShare: m.SSKRShareCbor,
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
  const mlkemLevel = (l: 512 | 768 | 1024): any => m.MLKEMLevel[`MLKEM${l}`];

  return {
    errorCode: (e) => {
      const x = e as any;
      const name = String(x?.name ?? "Error");
      // dcbor errors: the compat class carries no code, the canonical one
      // does; both sides report the class.
      if (name === "CborError") return "CborError";
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
            extras.push(hex(v.publicKey().toData()), hex(v.schnorrPublicKey().toData()));
          if (r.type === "ed25519Priv" || r.type === "x25519Priv")
            extras.push(hex(v.publicKey().toData()));
          if (r.type === "ecPub") extras.push(hex(v.uncompressedPublicKey().toData()));
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
              `${v.identifier()},${v.groupThreshold()},${v.groupCount()},${v.groupIndex()},${v.memberThreshold()},${v.memberIndex()}`,
            );
          return [describe(v), ...extras].join("|");
        }
        case "random": {
          const rng = rngOf(r.rng);
          switch (r.type) {
            case "nonce":
              return hex(m.Nonce.randomUsing(rng).data());
            case "salt":
              return hex(m.Salt.newWithLenUsing(r.len ?? 16, rng).asBytes());
            case "arid":
              return hex(m.ARID.fromData(rng.randomData(32)).data());
            case "uuid":
              return hex(m.UUID.fromData(rng.randomData(16)).data());
            case "symmetricKey":
              return hex(m.SymmetricKey.randomUsing(rng).data());
            case "x25519Priv":
              return hex(m.X25519PrivateKey.newUsing(rng).data());
            case "ecPriv":
              return hex(m.ECPrivateKey.newUsing(rng).data());
            case "ed25519Priv":
              return hex(m.Ed25519PrivateKey.randomUsing(rng).data());
            case "privateKeyBase":
              return hex(m.PrivateKeyBase.newUsing(rng).data());
            case "seed":
              return hex(m.Seed.newWithLenUsing(r.len ?? 32, rng).asBytes());
          }
          break;
        }
        case "derive": {
          const km = B(r.km);
          switch (r.type) {
            case "x25519": {
              const k = m.X25519PrivateKey.deriveFromKeyMaterial(km);
              return `${hex(k.data())}|${hex(k.publicKey().data())}`;
            }
            case "ec": {
              const k = m.ECPrivateKey.deriveFromKeyMaterial(km);
              return `${hex(k.data())}|${hex(k.publicKey().data())}|${hex(k.schnorrPublicKey().data())}`;
            }
            case "ed25519": {
              const k = m.Ed25519PrivateKey.deriveFromKeyMaterial(km);
              return `${hex(k.data())}|${hex(k.publicKey().data())}`;
            }
          }
          break;
        }
        case "digest": {
          const d = m.Digest.fromImage(B(r.image));
          return `${hex(d.data())}|${d.urString()}|${d.shortDescription()}`;
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
          const s = m.Seed.newOpt(
            B(r.data),
            r.name,
            r.note,
            r.date === undefined ? undefined : new Date(r.date),
          );
          return codable(s);
        }
        case "encrypt": {
          const key = m.SymmetricKey.fromData(B(r.key));
          const msg = key.encrypt(
            B(r.plaintext),
            r.aad ? B(r.aad) : undefined,
            m.Nonce.fromData(B(r.nonce)),
          );
          const back = key.decrypt(msg);
          return `${codable(msg)}|${hex(back) === hex(B(r.plaintext)) ? "roundtrip" : "MISMATCH"}`;
        }
        case "x25519Shared": {
          const priv = m.X25519PrivateKey.fromData(B(r.priv));
          return hex(priv.sharedKeyWith(m.X25519PublicKey.fromData(B(r.pub))).data());
        }
        case "signingKeys": {
          const priv = signingPriv(r.scheme, B(r.key));
          const pub = priv.publicKey();
          return `${codable(priv)}|${codable(pub)}|${hex(m.XID.fromSigningPublicKey(pub).data())}|${hex(pub.reference().data())}`;
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
          const pkb = m.PrivateKeyBase.fromData(B(r.seed));
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
          const pkb = m.PrivateKeyBase.fromData(B(r.seed));
          const ed = pkb.ed25519SigningPrivateKey();
          const sch = pkb.schnorrSigningPrivateKey();
          const ec = pkb.ecdsaSigningPrivateKey();
          const x = pkb.x25519PrivateKey();
          return [
            codable(pkb),
            tagged(ed),
            tagged(sch.publicKey()),
            tagged(ec),
            hex(x.data()),
            hex(x.publicKey().data()),
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
          const [priv, pub] = m.keypairOptUsing(
            m.SignatureScheme[schemeEnum(r.sigScheme)],
            encEnum,
            rngOf(r.rng),
          );
          return `${codable(priv)}|${codable(pub)}|${hex(pub.reference().data())}|${pub.equals(priv.publicKeys()) ? "consistent" : "INCONSISTENT"}`;
        }
        case "seal": {
          let priv: any;
          if ("x25519" in r.recipient)
            priv = m.EncapsulationPrivateKey.fromX25519PrivateKey(
              m.X25519PrivateKey.fromData(B(r.recipient.x25519)),
            );
          else
            priv = m.EncapsulationPrivateKey.newMlkemUsing(
              mlkemLevel(r.recipient.mlkem),
              rngOf(r.recipient.rng),
            );
          const pub = priv.publicKey();
          const pt = B(r.plaintext);
          const sealed = r.aad
            ? m.SealedMessage.newOpt(pt, pub, B(r.aad), undefined)
            : m.SealedMessage.new(pt, pub);
          const back = sealed.decrypt(priv);
          const bytes = sealed.taggedCborData();
          const re = m.SealedMessage.fromTaggedCborData(bytes);
          return `${sealed.encapsulationScheme()}|len=${bytes.length}|${hex(back) === hex(pt) ? "roundtrip" : "MISMATCH"}|${hex(re.decrypt(priv)) === hex(pt) ? "cbor-roundtrip" : "CBOR-MISMATCH"}|${"x25519" in r.recipient ? tagged(pub) : `pubLen=${pub.taggedCborData().length}`}`;
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
              m.EncryptedKey.lockOpt(paramsOf(r), B(r.secret), m.SymmetricKey.fromData(B(r.key)));
              return "locked";
            } catch (e) {
              return `unsupported:${this.errorCode(e)}`;
            }
          }
          const key = m.SymmetricKey.fromData(B(r.key));
          const ek = m.EncryptedKey.lockOpt(paramsOf(r), B(r.secret), key);
          const bytes = ek.taggedCborData();
          const re = m.EncryptedKey.fromTaggedCborData(bytes);
          const back = re.unlock(B(r.secret));
          let wrong = "wrong-secret-rejected";
          try {
            re.unlock(new Uint8Array([1, 2, 3]));
            wrong = "WRONG-SECRET-ACCEPTED";
          } catch {
            /* expected */
          }
          return `${m.keyDerivationParamsToString(re.params())}|len=${bytes.length}|${back.equals(key) ? "unlocked" : "MISMATCH"}|${wrong}|aad=${hex(ek.encryptedMessage().aad())}`;
        }
        case "hkdfRng": {
          const g = r.pageLen
            ? m.HKDFRng.newWithPageLength(B(r.km), r.salt, r.pageLen)
            : m.HKDFRng.new(B(r.km), r.salt);
          return (
            r.draws.map((n) => hex(g.randomData(n))).join("|") +
            `|u32=${g.nextU32()}|u64=${g.nextU64()}`
          );
        }
        case "mldsa": {
          const priv = m.MLDSAPrivateKey.newUsing(mldsaLevel(r.level), rngOf(r.rng));
          const pub = priv.publicKey();
          const parts = [codable(priv), codable(pub)];
          if (r.message) {
            const sig = priv.sign(B(r.message));
            parts.push(
              `sigLen=${sig.taggedCborData().length}`,
              pub.verify(sig, B(r.message)) ? "verified" : "INVALID",
            );
          }
          return parts.join("|");
        }
        case "mlkem": {
          const priv = m.MLKEMPrivateKey.newUsing(mlkemLevel(r.level), rngOf(r.rng));
          const pub = priv.publicKey();
          const { sharedSecret, ciphertext } = pub.encapsulate();
          const back = priv.decapsulate(ciphertext);
          return `${codable(priv)}|${codable(pub)}|ctLen=${ciphertext.taggedCborData().length}|${back.equals(sharedSecret) ? "decapsulated" : "MISMATCH"}`;
        }
        case "sskr": {
          const spec = m.SSKRSpec.new
            ? m.SSKRSpec.new(
                r.spec.gt,
                r.spec.groups.map((g) => m.SSKRGroupSpec.new(g.mt, g.mc)),
              )
            : m.SSKRSpec.from({
                groupThreshold: r.spec.gt,
                groups: r.spec.groups.map((g) =>
                  m.SSKRGroupSpec.from({ memberThreshold: g.mt, memberCount: g.mc }),
                ),
              });
          const secret = m.SSKRSecret.new
            ? m.SSKRSecret.new(B(r.secret))
            : m.SSKRSecret.from(B(r.secret));
          const groups = m.sskrGenerateSharesUsing(spec, secret, rngOf(r.rng));
          const quorum: any[] = [];
          for (let gi = 0; gi < r.spec.gt; gi++)
            for (let mi = 0; mi < r.spec.groups[gi]!.mt; mi++) quorum.push(groups[gi][mi]);
          const back = m.sskrCombineShares(quorum);
          const bytes = typeof back.getData === "function" ? back.getData() : back.bytes;
          return (
            groups.map((g: any[]) => g.map(tagged).join(",")).join(";") +
            `|${hex(bytes) === hex(B(r.secret)) ? "combined" : "MISMATCH"}`
          );
        }
        case "decode": {
          const v = decoder(r.type).fromTaggedCborData(Uint8Array.from(Buffer.from(r.hex, "hex")));
          return describe(v);
        }
        case "verifyStrict": {
          const pub = m.SigningPublicKey.fromEd25519(m.Ed25519PublicKey.from(B(r.pub)));
          return pub.verify(m.Signature.ed25519FromData(B(r.sig)), B(r.message))
            ? "valid"
            : "invalid";
        }
        case "decodeUntagged": {
          // the strict twin of the tree's `fromCbor`: Rust's `from_tagged_cbor`
          const v = decoder(r.type).fromTaggedCborData(Uint8Array.from(Buffer.from(r.hex, "hex")));
          return describe(v);
        }
        case "signingDefault":
        case "kdfDomain":
        case "domain":
        case "summary":
          throw new Error("baseline: unsupported recipe kind");
        case "urParse": {
          const v = decoder(r.type).fromURString(r.s);
          return describe(v);
        }
      }
      throw new Error(`unhandled recipe ${(r as Recipe).k}`);
    },
  };
}
