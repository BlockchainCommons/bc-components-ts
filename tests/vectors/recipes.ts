/**
 * Vector recipes (Phase 1.1). A recipe names an operation and its inputs;
 * `materialize` runs it through a `VectorApi` and returns one outcome
 * string, so the same recipe drives the golden file, the differential and
 * the Rust harness. Adapters bridge the pre- and post-redesign surfaces.
 *
 * Outcomes are wire: tagged CBOR hex, UR strings, key/derivation hex,
 * OpenSSH text. Where a constructor draws from the secure generator with no
 * way to seed it (sealing, key locking, ML-KEM encapsulation) the outcome is
 * structural: lengths, scheme, and a round-trip check.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

export type Bytes = { hex: string } | { cycle: number; start?: number } | { text: string };
export type RngSpec =
  | { seed: [string, string, string, string] }
  | { fake: true }
  | { hkdf: { km: Bytes; salt: string } };
export type ValueType =
  | "digest"
  | "nonce"
  | "salt"
  | "arid"
  | "uuid"
  | "xid"
  | "reference"
  | "symmetricKey"
  | "json"
  | "uri"
  | "authTag"
  | "x25519Priv"
  | "x25519Pub"
  | "ecPriv"
  | "ecPub"
  | "ecUncompressed"
  | "schnorrPub"
  | "ed25519Priv"
  | "ed25519Pub"
  | "sr25519Priv"
  | "sr25519Pub"
  | "privateKeyBase"
  | "sskrShare";
export type RandomType =
  | "nonce"
  | "salt"
  | "arid"
  | "uuid"
  | "symmetricKey"
  | "x25519Priv"
  | "ecPriv"
  | "ed25519Priv"
  | "sr25519Priv"
  | "privateKeyBase"
  | "seed";
export type Scheme = "schnorr" | "ecdsa" | "ed25519" | "sr25519";
export type EncScheme = "x25519" | "mlkem512" | "mlkem768" | "mlkem1024";
export type SshAlg = "ed25519" | "ecdsa-p256" | "ecdsa-p384";
export type KdfMethod = "hkdf" | "pbkdf2" | "scrypt" | "argon2id" | "sshAgent";
export type DecodeType =
  | ValueType
  | "seed"
  | "compressed"
  | "encryptedMessage"
  | "signature"
  | "signingPriv"
  | "signingPub"
  | "encapPriv"
  | "encapPub"
  | "encapCiphertext"
  | "sealedMessage"
  | "privateKeys"
  | "publicKeys"
  | "encryptedKey"
  | "mldsaPriv"
  | "mldsaPub"
  | "mldsaSig"
  | "mlkemPriv"
  | "mlkemPub"
  | "mlkemCiphertext";
export interface ParamsSpec {
  method: KdfMethod;
  salt: Bytes;
  hash?: "sha256" | "sha512";
  iterations?: number;
  logN?: number;
  r?: number;
  p?: number;
  id?: string;
}
export type Recipe =
  | { k: "value"; type: ValueType; data: Bytes }
  | { k: "random"; type: RandomType; rng: RngSpec; len?: number }
  | { k: "derive"; type: "x25519" | "ec" | "ed25519" | "sr25519"; km: Bytes }
  | { k: "digest"; image: Bytes }
  | { k: "compressed"; data: Bytes; digest?: boolean }
  | { k: "seed"; data: Bytes; name?: string; note?: string; date?: number }
  | { k: "encrypt"; key: Bytes; nonce: Bytes; plaintext: Bytes; aad?: Bytes }
  | { k: "x25519Shared"; priv: Bytes; pub: Bytes }
  | { k: "signingKeys"; scheme: Scheme; key: Bytes }
  | { k: "sign"; scheme: Scheme; key: Bytes; message: Bytes; rng?: RngSpec }
  | {
      k: "sshFromSeed";
      seed: Bytes;
      alg: SshAlg;
      comment: string;
      message?: Bytes;
      namespace?: string;
    }
  | { k: "sshFromPem"; pem: string; message?: Bytes; namespace?: string }
  | { k: "pkb"; seed: Bytes }
  | { k: "keypair"; sigScheme: Scheme; encScheme: EncScheme; rng: RngSpec }
  | {
      k: "seal";
      plaintext: Bytes;
      recipient: { x25519: Bytes } | { mlkem: 512 | 768 | 1024; rng: RngSpec };
      aad?: Bytes;
    }
  | ({ k: "params" } & ParamsSpec)
  | ({ k: "encryptedKey"; secret: Bytes; key: Bytes } & ParamsSpec)
  | { k: "hkdfRng"; km: Bytes; salt: string; draws: number[]; pageLen?: number }
  | { k: "mldsa"; level: 44 | 65 | 87; rng: RngSpec; message?: Bytes }
  | { k: "mlkem"; level: 512 | 768 | 1024; rng: RngSpec }
  | {
      k: "sskr";
      spec: { gt: number; groups: { mt: number; mc: number }[] };
      secret: Bytes;
      rng: RngSpec;
    }
  | { k: "decode"; type: DecodeType; hex: string }
  | { k: "urParse"; type: ValueType | "seed" | "encryptedMessage" | "signature"; s: string };
export type Outcome = string;

export interface VectorApi {
  run(recipe: Recipe): string;
  errorCode(e: unknown): string;
}

export function toBytes(b: Bytes): Uint8Array {
  if ("hex" in b) return Uint8Array.from(Buffer.from(b.hex, "hex"));
  if ("text" in b) return new TextEncoder().encode(b.text);
  const start = b.start ?? 0;
  return Uint8Array.from({ length: b.cycle }, (_, i) => (start + i) & 0xff);
}
export const hex = (u: Uint8Array): string => Buffer.from(u).toString("hex");
const short = (b: Bytes): string =>
  "hex" in b
    ? `hex:${b.hex.slice(0, 12)}`
    : "text" in b
      ? `text:${b.text.slice(0, 12)}`
      : `cyc:${b.cycle}`;
const rngName = (r: RngSpec): string =>
  "fake" in r ? "fake" : "seed" in r ? `seed=${r.seed[0].slice(0, 6)}` : `hkdf:${r.hkdf.salt}`;

export function recipeName(r: Recipe): string {
  switch (r.k) {
    case "value":
      return `value ${r.type} ${short(r.data)} (${toBytes(r.data).length}B)`;
    case "random":
      return `random ${r.type} ${rngName(r.rng)}${r.len ? ` len=${r.len}` : ""}`;
    case "derive":
      return `derive ${r.type} ${short(r.km)}`;
    case "digest":
      return `digest ${short(r.image)} (${toBytes(r.image).length}B)`;
    case "compressed":
      return `compressed ${short(r.data)} (${toBytes(r.data).length}B)${r.digest ? " +digest" : ""}`;
    case "seed":
      return `seed ${short(r.data)} name=${r.name ?? "-"} note=${r.note ?? "-"} date=${r.date ?? "-"}`;
    case "encrypt":
      return `encrypt ${short(r.plaintext)} (${toBytes(r.plaintext).length}B)${r.aad ? " +aad" : ""}`;
    case "x25519Shared":
      return `x25519Shared ${short(r.priv)}`;
    case "signingKeys":
      return `signingKeys ${r.scheme} ${short(r.key)}`;
    case "sign":
      return `sign ${r.scheme} ${short(r.key)} msg=${short(r.message)}${r.rng ? ` ${rngName(r.rng)}` : ""}`;
    case "sshFromSeed":
      return `sshFromSeed ${r.alg} ${short(r.seed)} "${r.comment}"${r.message ? " +sign" : ""}`;
    case "sshFromPem":
      return `sshFromPem ${r.pem.slice(36, 60)}${r.message ? " +sign" : ""}`;
    case "pkb":
      return `pkb ${short(r.seed)}`;
    case "keypair":
      return `keypair ${r.sigScheme}/${r.encScheme} ${rngName(r.rng)}`;
    case "seal":
      return `seal ${short(r.plaintext)} → ${"x25519" in r.recipient ? "x25519" : `mlkem${r.recipient.mlkem}`}${r.aad ? " +aad" : ""}`;
    case "params":
      return `params ${r.method} salt=${toBytes(r.salt).length}B ${r.hash ?? ""}${r.iterations ?? ""}${r.logN ?? ""}${r.id ?? ""}`;
    case "encryptedKey":
      return `encryptedKey ${r.method} ${short(r.secret)}`;
    case "hkdfRng":
      return `hkdfRng ${short(r.km)} "${r.salt}" ${r.draws.join(",")}${r.pageLen ? ` page=${r.pageLen}` : ""}`;
    case "mldsa":
      return `mldsa${r.level} ${rngName(r.rng)}${r.message ? " +sign" : ""}`;
    case "mlkem":
      return `mlkem${r.level} ${rngName(r.rng)}`;
    case "sskr":
      return `sskr ${r.spec.gt}/[${r.spec.groups.map((g) => `${g.mt}-of-${g.mc}`).join(",")}] ${rngName(r.rng)}`;
    case "decode":
      return `decode ${r.type} ${r.hex.slice(0, 20)}… (${r.hex.length / 2}B)`;
    case "urParse":
      return `urParse ${r.type} ${r.s.slice(0, 28)}…`;
  }
}

export function materialize(api: VectorApi, r: Recipe): Outcome {
  try {
    return api.run(r);
  } catch (e) {
    return `throw:${api.errorCode(e)}`;
  }
}

const FAKE_FILL = (dest: Uint8Array): void => {
  let b = 0;
  for (let i = 0; i < dest.length; i++) {
    dest[i] = b;
    b = (b + 17) & 0xff;
  }
};

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
      case "sr25519Priv":
        return m.Sr25519PrivateKey.fromSeed(data);
      case "sr25519Pub":
        return m.Sr25519PublicKey.from(data);
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
      case "sr25519":
        return m.SigningPrivateKey.newSr25519(m.Sr25519PrivateKey.fromSeed(key));
    }
  };
  const schemeEnum = (s: Scheme): any =>
    ({ schnorr: "Schnorr", ecdsa: "Ecdsa", ed25519: "Ed25519", sr25519: "Sr25519" })[s];
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
          if (r.type === "ed25519Priv" || r.type === "x25519Priv" || r.type === "sr25519Priv")
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
            case "sr25519Priv":
              return hex(m.Sr25519PrivateKey.randomUsing(rng).toData());
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
            case "sr25519": {
              const k = m.Sr25519PrivateKey.deriveFromKeyMaterial(km);
              return `${hex(k.toData())}|${hex(k.publicKey().toData())}`;
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
        case "urParse": {
          const v = decoder(r.type).fromURString(r.s);
          return describe(v);
        }
      }
      throw new Error(`unhandled recipe ${(r as Recipe).k}`);
    },
  };
}

export function baselineAdapterFor(m: any, randBaseline: any): VectorApi {
  return rustShapedAdapterFor(m, randBaseline, { newRand: false });
}
/** The working tree; grows a redesigned branch in Phase 3. */
export function redesignedAdapterFor(m: any, rand: any): VectorApi {
  return rustShapedAdapterFor(m, rand, { newRand: true });
}
