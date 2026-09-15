/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion */
/**
 * The adapter over the working tree: one function per recipe kind, each
 * returning the outcome string the Rust harness prints for the same recipe.
 * Outcomes that involve the secure generator carry the artefact (sealed
 * message, locked key, signature, ciphertext) so the harness can open or
 * verify it with the recipient's or signer's key.
 */
import {
  type VectorApi,
  type RngSpec,
  type ValueType,
  type Scheme,
  type KeypairScheme,
  type SshAlg,
  type ParamsSpec,
  type DecodeType,
  type HexType,
  type Recipe,
  toBytes,
  hex,
  num,
  FAKE_FILL,
} from "./recipes";
import { decodeCbor, asTaggedValue, TagsStore, cbor } from "@blockchaincommons/dcbor";
import { Spec, GroupSpec, Secret } from "@blockchaincommons/sskr";
import { UR, decodeURWith } from "@blockchaincommons/uniform-resources";
import { crc32 } from "@blockchaincommons/crypto";
import { decompressToVec, InflateError } from "../../src/internal/miniz-inflate.js";
import { hashTypeFromCbor, hashTypeToString } from "../../src/encrypted-key/hash-type.js";
import {
  keyDerivationMethodFromCbor,
  keyDerivationMethodToString,
} from "../../src/encrypted-key/key-derivation-method.js";
import { mlkemLevelFromCbor, mlkemLevelToString } from "../../src/mlkem/mlkem-level.js";
import { mldsaLevelFromCbor, mldsaLevelToString } from "../../src/mldsa/mldsa-level.js";

/** The reference's enum variant names for the encapsulation schemes. */
const ENC_VARIANT: Record<string, string> = {
  x25519: "X25519",
  mlkem512: "MLKEM512",
  mlkem768: "MLKEM768",
  mlkem1024: "MLKEM1024",
};

export function workingTreeAdapterOver(m: any, rand: any, opts: { newRand: boolean }): VectorApi {
  // A generator object over a fill function; the integer draws are unused.
  const gen = (fill: (d: Uint8Array) => void): any => ({
    fillBytes: fill,
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
  const B = toBytes;
  const bytesOf = (v: any): Uint8Array => (v.bytes ?? v.toData()) as Uint8Array;
  const tagged = (v: any): string => hex(v.toCbor().toData());
  const urOf = (v: any): string => (typeof v.toUR === "function" ? v.toUR().toString() : "-");
  const codable = (v: any): string => `${tagged(v)}|${urOf(v)}`;
  const decoded = (bytes: Uint8Array): any => decodeCbor(bytes);
  const fromHex = (s: string): any => decoded(Uint8Array.from(Buffer.from(s, "hex")));
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
    return hex(bytesOf(v));
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
  const signingPub = (scheme: Scheme, key: Uint8Array): any => {
    switch (scheme) {
      case "schnorr":
        return m.SigningPublicKey.fromSchnorr(m.SchnorrPublicKey.from(key));
      case "ecdsa":
        return m.SigningPublicKey.fromEcdsa(m.ECPublicKey.from(key));
      case "ed25519":
        return m.SigningPublicKey.fromEd25519(m.Ed25519PublicKey.from(key));
    }
  };
  const signatureOf = (scheme: Scheme, sig: Uint8Array): any => {
    switch (scheme) {
      case "schnorr":
        return m.Signature.schnorrFromData(sig);
      case "ecdsa":
        return m.Signature.ecdsaFromData(sig);
      case "ed25519":
        return m.Signature.ed25519FromData(sig);
    }
  };
  const SCHEME_NAME: Record<KeypairScheme, string> = {
    schnorr: "Schnorr",
    ecdsa: "Ecdsa",
    ed25519: "Ed25519",
    mldsa44: "MLDSA44",
    mldsa65: "MLDSA65",
    mldsa87: "MLDSA87",
    sshEd25519: "SshEd25519",
    sshDsa: "SshDsa",
    sshEcdsaP256: "SshEcdsaP256",
    sshEcdsaP384: "SshEcdsaP384",
  };
  const sshAlgOf = (a: SshAlg): any => {
    switch (a) {
      case "ed25519":
        return { kind: "ed25519" };
      case "dsa":
        return { kind: "dsa" };
      case "rsa":
        return { kind: "rsa" };
      case "ecdsa-p256":
        return { kind: "ecdsa", curve: "nistp256" };
      case "ecdsa-p384":
        return { kind: "ecdsa", curve: "nistp384" };
      case "ecdsa-p521":
        return { kind: "ecdsa", curve: "nistp521" };
    }
  };
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
  /** The class behind a decode type, or `undefined` for the `TryFrom` functions below. */
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
      authTag: m.AuthenticationTag,
      hkdfParams: m.HKDFParams,
      pbkdf2Params: m.PBKDF2Params,
      scryptParams: m.ScryptParams,
      argon2idParams: m.Argon2idParams,
      sshAgentParams: m.SSHAgentParams,
    })[type as string];
  /** `fromCbor` for every decode type, with the outcome rendered the way the harness renders it. */
  const decode = (type: DecodeType, c: any): string => {
    switch (type) {
      case "kdp": {
        const v = m.keyDerivationParamsFromCbor(c);
        return `${hex(m.keyDerivationParamsToCborData(v))}|${m.keyDerivationParamsToString(v)}`;
      }
      case "hashType":
        return hashTypeToString(hashTypeFromCbor(c));
      case "kdMethod":
        return keyDerivationMethodToString(keyDerivationMethodFromCbor(c));
      case "mlkemLevel":
        return mlkemLevelToString(mlkemLevelFromCbor(c));
      case "mldsaLevel":
        return mldsaLevelToString(mldsaLevelFromCbor(c));
      case "hkdfParams":
      case "pbkdf2Params":
      case "scryptParams":
      case "argon2idParams":
      case "sshAgentParams": {
        const v = decoder(type).fromCbor(c);
        return `${hex(v.toCborData())}|${v.toString()}`;
      }
      case "authTag":
        return hex(m.AuthenticationTag.fromCbor(c).toCborData());
      case "encapPriv":
      case "encapPub":
      case "encapCiphertext":
        return `${tagged(decoder(type).fromCbor(c))}|-`;
      default:
        return describe(decoder(type).fromCbor(c));
    }
  };
  const hexType = (type: HexType, text: string): Uint8Array => {
    const cls = {
      digest: m.Digest,
      nonce: m.Nonce,
      salt: m.Salt,
      arid: m.ARID,
      xid: m.XID,
      reference: m.Reference,
      symmetricKey: m.SymmetricKey,
      json: m.CborJson,
      sskrShare: m.SskrShare,
      x25519Priv: m.X25519PrivateKey,
      x25519Pub: m.X25519PublicKey,
      ed25519Priv: m.Ed25519PrivateKey,
      ed25519Pub: m.Ed25519PublicKey,
      uuid: m.UUID,
    }[type];
    return bytesOf(cls.fromHex(text));
  };
  const mldsaLevel = (l: 44 | 65 | 87): any => m.MLDSALevel[`MLDSA${l}`];
  const mlkemLevel = (l: 512 | 768 | 1024): any => m.MLKEMLevel[`MLKEM${l}`];
  const fakeRng = (): any => gen(FAKE_FILL);
  const escapeUnicode = (s: string): string =>
    [...s].map((c) => `\\u{${c.codePointAt(0)!.toString(16)}}`).join("");
  const ecOne = new Uint8Array(32);
  ecOne[31] = 1;
  const secpN = Uint8Array.from(
    Buffer.from("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", "hex"),
  );
  const gUncompressedXY =
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
  const key7 = (): any => m.SymmetricKey.from(new Uint8Array(32).fill(7));
  const msgM = new TextEncoder().encode("m");
  const good = (): any => m.ECPrivateKey.from(ecOne);
  const short4 = (): any => m.SskrShare.from(new Uint8Array([0, 1, 2, 3]));
  const lockUnlock = (params: any): string => {
    const key = key7();
    const ek = m.EncryptedKey.lockOpt(params, new Uint8Array([1]), key);
    return ek.unlock(new Uint8Array([1])).equals(key) ? "unlocked" : "MISMATCH";
  };
  const resultOf = (f: () => string): string => `ok:${f()}`;
  /**
   * The named API cases: the same operations, in the same words, as the
   * harness's table. A `throw:` outcome is produced by `materialize`.
   */
  const apiCases: Record<string, () => string> = {
    "json/invalid-utf8-decode": () =>
      resultOf(() =>
        tagged(m.CborJson.fromCbor(m.CborJson.from(new Uint8Array([0xff, 0xfe])).toCbor())),
      ),
    "json/invalid-utf8-as-str": () => m.CborJson.from(new Uint8Array([0xff, 0xfe])).asStr(),
    "json/bom-as-str": () =>
      escapeUnicode(m.CborJson.from(new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d])).asStr()),
    "sskr/short4-identifier": () => String(short4().identifier),
    "sskr/short4-group-threshold": () => String(short4().groupThreshold),
    "sskr/short4-group-count": () => String(short4().groupCount),
    "sskr/short4-group-index": () => String(short4().groupIndex),
    "sskr/short4-member-threshold": () => String(short4().memberThreshold),
    "sskr/short4-member-index": () => String(short4().memberIndex),
    "sskr/short4-value": () => hex(short4().value),
    "sskr/empty-identifier": () => String(m.SskrShare.from(new Uint8Array(0)).identifier),
    "sskr/combine-short": () => {
      m.SskrShare.combine([short4()]);
      return "ok";
    },
    "sskr/combine-empty": () => {
      m.SskrShare.combine([]);
      return "ok";
    },
    "sskr/combine-one-of-two": () => {
      const spec = Spec.from({
        groupThreshold: 1,
        groups: [GroupSpec.from({ memberThreshold: 2, memberCount: 3 })],
      });
      const groups = m.SskrShare.generate(spec, Secret.from(new Uint8Array(16).fill(7)), {
        rng: fakeRng(),
      });
      m.SskrShare.combine([groups[0][0]]);
      return "ok";
    },
    "mldsa/signing-public-key": () =>
      resultOf(() => {
        const [k] = m.MLDSAPrivateKey.keypair(m.MLDSALevel.MLDSA44, { rng: fakeRng() });
        return m.SigningPrivateKey.fromMldsa(k).publicKey().toString();
      }),
    "mlkem/encap-public-key": () =>
      resultOf(() => {
        const [k] = m.MLKEMPrivateKey.keypair(m.MLKEMLevel.MLKEM512, { rng: fakeRng() });
        return m.EncapsulationPrivateKey.fromMlkem(k).publicKey().toString();
      }),
    "privateKeys/mldsa-public-keys": () =>
      resultOf(() => {
        const [k] = m.MLDSAPrivateKey.keypair(m.MLDSALevel.MLDSA44, { rng: fakeRng() });
        return m.PrivateKeys.from({
          signing: m.SigningPrivateKey.fromMldsa(k),
          encapsulation: m.EncapsulationPrivateKey.fromX25519PrivateKey(
            m.X25519PrivateKey.from(ecOne),
          ),
        })
          .publicKeys()
          .toString();
      }),
    "privateKeys/mlkem-public-keys": () =>
      resultOf(() => {
        const [k] = m.MLKEMPrivateKey.keypair(m.MLKEMLevel.MLKEM512, { rng: fakeRng() });
        return m.PrivateKeys.from({
          signing: m.SigningPrivateKey.fromSchnorr(good()),
          encapsulation: m.EncapsulationPrivateKey.fromMlkem(k),
        })
          .publicKeys()
          .toString();
      }),
    "compressed/new-larger": () =>
      resultOf(() => {
        m.Compressed.fromParts({
          checksum: 0,
          decompressedSize: 1,
          compressedData: new Uint8Array(2),
        });
        return "ok";
      }),
    "compressed/digest-none": () =>
      hex(m.Compressed.fromDecompressedData(new Uint8Array(3)).digest().bytes),
    "ec/zero-public-key": () => hex(m.ECPrivateKey.from(new Uint8Array(32)).publicKey().bytes),
    "ec/zero-schnorr-public-key": () =>
      hex(m.ECPrivateKey.from(new Uint8Array(32)).schnorrPublicKey().bytes),
    "ec/zero-signing-public-key": () =>
      resultOf(() =>
        m.SigningPrivateKey.fromSchnorr(m.ECPrivateKey.from(new Uint8Array(32)))
          .publicKey()
          .toString(),
      ),
    "ec/zero-schnorr-sign": () =>
      resultOf(() => {
        m.SigningPrivateKey.fromSchnorr(m.ECPrivateKey.from(new Uint8Array(32))).signWithOptions(
          msgM,
          { type: "Schnorr", rng: fakeRng() },
        );
        return "signed";
      }),
    "ec/zero-ecdsa-sign": () =>
      resultOf(() => {
        m.SigningPrivateKey.fromEcdsa(m.ECPrivateKey.from(new Uint8Array(32))).sign(msgM);
        return "signed";
      }),
    "ec/n-public-key": () => hex(m.ECPrivateKey.from(secpN).publicKey().bytes),
    "ec/one-public-key": () => hex(good().publicKey().bytes),
    "ecpub/zeros33-uncompressed": () =>
      hex(m.ECPublicKey.from(new Uint8Array(33)).uncompressedPublicKey().bytes),
    "ecpub/02zeros-uncompressed": () =>
      hex(
        m.ECPublicKey.from(Uint8Array.from([2, ...new Uint8Array(32)])).uncompressedPublicKey()
          .bytes,
      ),
    "ecpub/05ff-uncompressed": () =>
      hex(
        m.ECPublicKey.from(
          Uint8Array.from([5, ...new Uint8Array(32).fill(0xff)]),
        ).uncompressedPublicKey().bytes,
      ),
    "ecpub/G-uncompressed": () => hex(good().publicKey().uncompressedPublicKey().bytes),
    "ecuncomp/04-public-key": () =>
      hex(m.ECUncompressedPublicKey.fromHex(`04${gUncompressedXY}`).compressedData()),
    "ecuncomp/06-public-key": () =>
      hex(m.ECUncompressedPublicKey.fromHex(`06${gUncompressedXY}`).compressedData()),
    "ecuncomp/07-public-key": () =>
      hex(m.ECUncompressedPublicKey.fromHex(`07${gUncompressedXY}`).compressedData()),
    "ecuncomp/00-public-key": () =>
      hex(m.ECUncompressedPublicKey.fromHex(`00${gUncompressedXY}`).compressedData()),
    "sym/decrypt-tampered": () =>
      resultOf(() => {
        const k = key7();
        const msg = k.encrypt(new Uint8Array([0x61, 0x62, 0x63, 0x64]), {
          nonce: m.Nonce.from(new Uint8Array(12)),
        });
        return hex(
          k.decrypt(
            m.EncryptedMessage.from({
              ciphertext: msg.ciphertext,
              nonce: msg.nonce,
              authTag: m.AuthenticationTag.from(new Uint8Array(16)),
              aad: msg.aad,
            }),
          ),
        );
      }),
    "sym/decrypt-wrong-key": () =>
      resultOf(() => {
        const msg = key7().encrypt(new Uint8Array([1, 2, 3]), {
          nonce: m.Nonce.from(new Uint8Array(12)),
        });
        return hex(m.SymmetricKey.from(new Uint8Array(32).fill(8)).decrypt(msg));
      }),
    "ek/unlock-wrong": () =>
      resultOf(() =>
        hex(
          m.EncryptedKey.lock(m.KeyDerivationMethod.HKDF, new Uint8Array([1]), key7()).unlock(
            new Uint8Array([2]),
          ).bytes,
        ),
      ),
    "sealed/wrong-key": () =>
      resultOf(() => {
        const [, pub] = m.EncapsulationPrivateKey.keypair({ rng: fakeRng() });
        const other = m.EncapsulationPrivateKey.fromX25519PrivateKey(
          m.X25519PrivateKey.from(new Uint8Array(32).fill(9)),
        );
        return hex(m.SealedMessage.seal(new Uint8Array([0x78]), pub).decrypt(other));
      }),
    "salt/len7": () => resultOf(() => hex(m.Salt.random({ length: 7, rng: fakeRng() }).bytes)),
    "salt/len8": () => resultOf(() => hex(m.Salt.random({ length: 8, rng: fakeRng() }).bytes)),
    "seed/len15": () =>
      resultOf(() => {
        m.Seed.from(new Uint8Array(15));
        return "ok";
      }),
    "seed/len16": () =>
      resultOf(() => {
        m.Seed.from(new Uint8Array(16));
        return "ok";
      }),
    "sign/ed25519-with-schnorr-opts": () =>
      resultOf(() =>
        tagged(
          m.SigningPrivateKey.fromEd25519(
            m.Ed25519PrivateKey.from(new Uint8Array(32).fill(7)),
          ).signWithOptions(msgM, { type: "Schnorr", rng: fakeRng() }),
        ),
      ),
    // Schnorr ignores SSH options and draws its own randomness: pinned by verification.
    "sign/schnorr-with-ssh-opts": () =>
      resultOf(() => {
        const priv = m.SigningPrivateKey.fromSchnorr(good());
        const sig = priv.signWithOptions(msgM, { type: "Ssh", namespace: "n", hashAlg: "sha256" });
        return priv.publicKey().verify(sig, msgM) ? "verified" : "INVALID";
      }),
    "sign/schnorr-key-ecdsa-sign": () =>
      resultOf(() => tagged(m.SigningPrivateKey.fromSchnorr(good()).ecdsaSign(msgM))),
    "sign/ecdsa-key-schnorr-sign": () =>
      resultOf(() => tagged(m.SigningPrivateKey.fromEcdsa(good()).schnorrSign(msgM, fakeRng()))),
    "sign/ed25519-key-ecdsa-sign": () =>
      resultOf(() =>
        tagged(
          m.SigningPrivateKey.fromEd25519(
            m.Ed25519PrivateKey.from(new Uint8Array(32).fill(7)),
          ).ecdsaSign(msgM),
        ),
      ),
    "sign/schnorr-key-ed25519-sign": () =>
      resultOf(() => tagged(m.SigningPrivateKey.fromSchnorr(good()).ed25519Sign(msgM))),
    "sign/schnorr-key-mldsa-sign": () =>
      resultOf(() => tagged(m.SigningPrivateKey.fromSchnorr(good()).mldsaSign(msgM))),
    "pkb/empty": () => {
      const p = m.PrivateKeyBase.from(new Uint8Array(0));
      return `${tagged(p)}|${hex(p.x25519PrivateKey().bytes)}`;
    },
    "mldsa/short-sig-verify": () => {
      const [pk, pub] = m.MLDSAPrivateKey.keypair(m.MLDSALevel.MLDSA44, { rng: fakeRng() });
      const s = pk.sign(msgM);
      const short = m.MLDSASignature.fromBytes(m.MLDSALevel.MLDSA44, s.bytes.subarray(0, 100));
      return `from-ok|${String(pub.verify(short, msgM))}`;
    },
    "mldsa/long-sig-from": () =>
      resultOf(() => {
        m.MLDSASignature.fromBytes(m.MLDSALevel.MLDSA44, new Uint8Array(2421));
        return "ok";
      }),
    "scheme/default-sig": () => String(m.defaultSignatureScheme()),
    "scheme/default-enc": () => ENC_VARIANT[String(m.defaultEncapsulationScheme())]!,
    "hkdf/page0-fill0": () => {
      new m.HKDFRng(new TextEncoder().encode("km"), "salt", { pageLength: 0 }).fillBytes(
        new Uint8Array(0),
      );
      return "ok";
    },
    "hkdf/page0-fill1": () => {
      new m.HKDFRng(new TextEncoder().encode("km"), "salt", { pageLength: 0 }).fillBytes(
        new Uint8Array(1),
      );
      return "ok";
    },
    "hkdf/page0-u32": () =>
      resultOf(() =>
        String(new m.HKDFRng(new TextEncoder().encode("km"), "salt", { pageLength: 0 }).nextU32()),
      ),
    "kdf/pbkdf2-iter0-unlock": () =>
      lockUnlock(
        m.pbkdf2Params(
          m.PBKDF2Params.from({ salt: m.Salt.from(new Uint8Array(16)), iterations: 0 }),
        ),
      ),
    "kdf/scrypt-logn0-unlock": () =>
      lockUnlock(
        m.scryptParams(m.ScryptParams.from({ salt: m.Salt.from(new Uint8Array(16)), logN: 0 })),
      ),
    "authTag/from-cbor-bytes": () =>
      hex(m.AuthenticationTag.fromCbor(cbor(new Uint8Array(16))).bytes),
    "authTag/from-cbor-uint": () => hex(m.AuthenticationTag.fromCbor(cbor(1)).bytes),
    "authTag/from-cbor-short": () =>
      hex(m.AuthenticationTag.fromCbor(cbor(new Uint8Array(15))).bytes),
    "uuid/to-string": () =>
      m.UUID.from(Uint8Array.from({ length: 16 }, (_, i) => (0x60 + i) & 0xff)).toString(),
    "ssh/rsa-sign": () =>
      resultOf(() =>
        tagged(
          m.PrivateKeyBase.from(new Uint8Array(32).fill(1))
            .sshSigningPrivateKey({ kind: "rsa" }, "c")
            .signWithOptions(msgM, { type: "Ssh", namespace: "test", hashAlg: "sha256" }),
        ),
      ),
  };
  /**
   * The JS-only input domain, one closure per named case; the outcome
   * records the thrown class AND code so a foreign class (dcbor, rand,
   * crypto, noble) leaking unwrapped would still be visible.
   */
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
    "mldsa.level.99": () => m.MLDSAPrivateKey.keypair(99, { rng: fakeRng() }),
    "mlkem.level.99": () => m.MLKEMPrivateKey.keypair(99, { rng: fakeRng() }),
    "digest.from.undefined": () => m.Digest.from(undefined),
    "arid.from.null": () => m.ARID.from(null),
    "sshSigningPrivateKey.algorithm.unknown": () =>
      m.PrivateKeyBase.from(new Uint8Array(32)).sshSigningPrivateKey({ kind: "gost" }, ""),
    "sshSigningPrivateKey.algorithm.curve.unknown": () =>
      m.PrivateKeyBase.from(new Uint8Array(32)).sshSigningPrivateKey(
        { kind: "ecdsa", curve: "nistp999" },
        "",
      ),
    "compressed.fromParts.size.1.5": () =>
      m.Compressed.fromParts({
        checksum: 0,
        decompressedSize: 1.5,
        compressedData: new Uint8Array(0),
      }),
    "compressed.fromParts.checksum.-1": () =>
      m.Compressed.fromParts({
        checksum: -1,
        decompressedSize: 1,
        compressedData: new Uint8Array(0),
      }),
  };

  const api: VectorApi = {
    errorCode: (e) => {
      const x = e as any;
      const name = String(x?.name ?? "Error");
      if (name === "CborError") return "Cbor";
      if (name === "URError" || name === "ComponentsError") return String(x.code);
      if (name === "SskrError" || name === "RandError") return `${name}:${String(x.code)}`;
      return name;
    },
    errorMessage: (e) => (e instanceof Error ? e.message : String(e)),
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
          const draw = (n: number): Uint8Array => {
            const d = new Uint8Array(n);
            rng.fillBytes(d);
            return d;
          };
          switch (r.type) {
            case "nonce":
              return hex(m.Nonce.random({ rng: rng }).bytes);
            case "salt":
              return hex(m.Salt.random({ length: r.len ?? 16, rng: rng }).bytes);
            case "arid":
              return hex(m.ARID.from(draw(32)).bytes);
            case "uuid":
              return hex(m.UUID.from(draw(16)).bytes);
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
        case "inflate": {
          const bytes = Uint8Array.from(Buffer.from(r.hex, "hex"));
          let raw: string;
          let crc = 0;
          try {
            const out = decompressToVec(bytes);
            raw = `ok:${hex(out)}`;
            crc = crc32(out);
          } catch (e) {
            if (!(e instanceof InflateError)) throw e;
            raw = `err:${e.status}`;
          }
          let through: string;
          try {
            through = `ok:${hex(
              m.Compressed.fromParts({
                checksum: crc,
                decompressedSize: 1 << 20,
                compressedData: bytes,
              }).decompress(),
            )}`;
          } catch (e) {
            through = `throw:${this.errorCode(e)}:${this.errorMessage!(e)}`;
          }
          return `raw=${raw}|compressed=${through}`;
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
        case "verify":
          return String(
            signingPub(r.scheme, B(r.pub)).verify(signatureOf(r.scheme, B(r.sig)), B(r.message)),
          );
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
            parts.push(
              `sig=${tagged(sig)}`,
              pub.verify(sig, B(r.message)) ? "verified" : "INVALID",
            );
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
            parts.push(
              `sig=${tagged(sig)}`,
              pub.verify(sig, B(r.message)) ? "verified" : "INVALID",
            );
          }
          return parts.join("|");
        }
        case "sshText": {
          switch (r.kind) {
            case "priv": {
              const key = m.SSHPrivateKey.fromOpenssh(r.text);
              return `ok:${key.toOpenssh()}|comment=${key.comment}|pub=${key.publicKey().toOpenssh()}`;
            }
            case "pub": {
              const key = m.SSHPublicKey.fromOpenssh(r.text);
              return `ok:${key.toOpenssh()}|comment=${key.comment}`;
            }
            case "sig":
              return `ok:${m.SSHSignature.fromPem(r.text).toPem()}`;
          }
          break;
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
            tagged(pkb.schnorrPrivateKeys()),
            tagged(pkb.schnorrPublicKeys()),
            tagged(pkb.ecdsaPrivateKeys()),
            tagged(pkb.ecdsaPublicKeys()),
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
            signing: m.SignatureScheme[SCHEME_NAME[r.sigScheme]],
            encapsulation: encEnum,
            rng: rngOf(r.rng),
          });
          return `${codable(priv)}|${codable(pub)}|${hex(pub.reference().bytes)}|${pub.equals(priv.publicKeys()) ? "consistent" : "INCONSISTENT"}`;
        }
        case "seal": {
          let priv: any;
          let pub: any;
          let scheme: string;
          if ("x25519" in r.recipient) {
            priv = m.EncapsulationPrivateKey.fromX25519PrivateKey(
              m.X25519PrivateKey.from(B(r.recipient.x25519)),
            );
            pub = priv.publicKey();
            scheme = "x25519";
          } else {
            [priv, pub] = m.EncapsulationPrivateKey.mlkemKeypair(mlkemLevel(r.recipient.mlkem), {
              rng: rngOf(r.recipient.rng),
            });
            scheme = `mlkem${r.recipient.mlkem}`;
          }
          const pt = B(r.plaintext);
          const aad = r.aad ? B(r.aad) : new Uint8Array(0);
          const sealOpts: Record<string, unknown> = {};
          if (r.aad) sealOpts["aad"] = aad;
          if (r.nonce) sealOpts["nonce"] = m.Nonce.from(B(r.nonce));
          const sealed = m.SealedMessage.seal(pt, pub, sealOpts);
          const bytes = sealed.toCbor().toData();
          const back = sealed.decrypt(priv);
          const re = m.SealedMessage.fromCbor(decoded(bytes)).decrypt(priv);
          if (hex(back) !== hex(pt) || hex(re) !== hex(pt)) return "SEAL-MISMATCH";
          return `${scheme}|priv=${tagged(priv)}|pub=${tagged(pub)}|sealed=${hex(bytes)}|pt=${hex(pt)}|aad=${hex(aad)}`;
        }
        case "params": {
          const kdp = paramsOf(r);
          const methodName = ["hkdf", "pbkdf2", "scrypt", "argon2id", "sshAgent"][
            Number(m.keyDerivationParamsMethod(kdp))
          ];
          return `${hex(m.keyDerivationParamsToCborData(kdp))}|${m.keyDerivationParamsToString(kdp)}|${methodName}`;
        }
        case "encryptedKey": {
          const key = m.SymmetricKey.from(B(r.key));
          const secret = B(r.secret);
          const ek = m.EncryptedKey.lockOpt(paramsOf(r), secret, key);
          const bytes = ek.toCbor().toData();
          const re = m.EncryptedKey.fromCbor(decoded(bytes));
          if (!re.unlock(secret).equals(key)) return "UNLOCK-MISMATCH";
          return `${m.keyDerivationParamsToString(re.params)}|ek=${hex(bytes)}|key=${hex(B(r.key))}|secret=${hex(secret)}`;
        }
        case "hkdfRng": {
          const g =
            r.pageLen === undefined
              ? new m.HKDFRng(B(r.km), r.salt)
              : new m.HKDFRng(B(r.km), r.salt, { pageLength: r.pageLen });
          const draw = (n: number): Uint8Array => {
            const d = new Uint8Array(n);
            g.fillBytes(d);
            return d;
          };
          return (
            r.draws.map((n) => hex(draw(n))).join("|") + `|u32=${g.nextU32()}|u64=${g.nextU64()}`
          );
        }
        case "mldsa": {
          const [priv, pub] = m.MLDSAPrivateKey.keypair(mldsaLevel(r.level), {
            rng: rngOf(r.rng),
          });
          const parts = [codable(priv), codable(pub)];
          if (r.message) {
            const sig = priv.sign(B(r.message));
            if (!pub.verify(sig, B(r.message))) return "SIGN-MISMATCH";
            parts.push(`sig=${tagged(sig)}`, `msg=${hex(B(r.message))}`);
          }
          return parts.join("|");
        }
        case "mlkem": {
          const [priv, pub] = m.MLKEMPrivateKey.keypair(mlkemLevel(r.level), {
            rng: rngOf(r.rng),
          });
          const { sharedSecret, ciphertext } = pub.encapsulate();
          const back = priv.decapsulate(ciphertext);
          if (!back.equals(sharedSecret)) return "DECAPSULATE-MISMATCH";
          return `${codable(priv)}|${codable(pub)}|ct=${tagged(ciphertext)}|ss=${hex(sharedSecret.bytes)}`;
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
        case "decode":
          return decode(r.type, fromHex(r.hex));
        case "urParse":
          return describe(decodeURWith(UR.parse(r.s), decoder(r.type).codec));
        case "verifyStrict": {
          const pub = m.SigningPublicKey.fromEd25519(m.Ed25519PublicKey.from(B(r.pub)));
          return pub.verify(m.Signature.ed25519FromData(B(r.sig)), B(r.message))
            ? "valid"
            : "invalid";
        }
        case "decodeUntagged":
          return decode(r.type, fromHex(r.hex));
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
          const tv = asTaggedValue(fromHex(r.hex));
          if (tv === undefined) return "untagged";
          const s = store.summarizer(tv[0].value);
          if (s === undefined) return "none";
          const out = s(tv[1], false);
          return out.ok ? `ok:${out.value}` : `error:${out.error.message}`;
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
        case "uri":
          return m.URI.from(r.text).toString();
        case "uuidParse":
          return m.UUID.fromString(r.text).toString();
        case "hex":
          return hex(hexType(r.type, r.text));
        case "api": {
          const f = apiCases[r.case];
          if (f === undefined) throw new Error(`unknown api case ${r.case}`);
          return f();
        }
        case "cborTags":
          return decoder(r.type)
            .codec.tags.map((t: any) => t.name ?? String(t.value))
            .join(",");
        case "noreg":
          return this.run(r.inner);
        case "agentLock":
          throw new Error("agentLock is asynchronous: materialise it with materializeAsync");
      }
      throw new Error(`unhandled recipe ${(r as Recipe).k}`);
    },
    async runAsync(r) {
      if (r.k !== "agentLock") return this.run(r);
      // The in-memory agent over the listed OpenSSH keys; the lock under the
      // injected nonce is byte-deterministic (Ed25519 signs deterministically),
      // and the reference unlocks it.
      const identities = r.identities.map((i) =>
        m.PrivateKeyBase.from(B(i.seed))
          .sshSigningPrivateKey(sshAlgOf(i.alg ?? "ed25519"), i.comment)
          .asSsh(),
      );
      const agent = new m.MemorySshAgent({ identities, refuseToSign: r.refuse ?? false });
      const salt = m.Salt.from(B(r.salt));
      const key = m.SymmetricKey.from(B(r.key));
      const secret = B(r.secret);
      const ek = await m.EncryptedKey.lockWithAgent(
        m.sshAgentParams(m.SSHAgentParams.from({ salt })),
        secret,
        key,
        { agent, nonce: m.Nonce.from(B(r.nonce)) },
      );
      const bytes = ek.toCbor().toData();
      const re = m.EncryptedKey.fromCbor(decoded(bytes));
      if (!(await re.unlockWithAgent(secret, { agent })).equals(key)) return "UNLOCK-MISMATCH";
      let out = `lock=${m.keyDerivationParamsToString(re.params)}|ek=${hex(bytes)}|key=${hex(B(r.key))}|secret=${hex(secret)}`;
      if (r.unlock) {
        const original = re.encryptedMessage;
        const ciphertext = Uint8Array.from(original.ciphertext);
        const aad = Uint8Array.from(original.aad);
        if (r.unlock.tamper === "aad" && aad.length > 0) aad[aad.length - 1]! ^= 1;
        if (r.unlock.tamper === "ciphertext" && ciphertext.length > 0) ciphertext[0]! ^= 1;
        const message = m.EncryptedMessage.from({
          ciphertext,
          aad,
          nonce: original.nonce,
          authTag: original.authenticationTag,
        });
        // The stored id is the secret's text, as the lock left it.
        const stored = r.unlock.storedId ?? new TextDecoder().decode(secret);
        const params = m.SSHAgentParams.from({ salt, id: stored });
        let result: string;
        try {
          result = `ok:${hex((await params.unlock(message, B(r.unlock.secret), { agent })).bytes)}`;
        } catch (e) {
          result = `throw:${this.errorCode(e)}:${this.errorMessage!(e)}`;
        }
        out += `|unlock=${result}`;
      }
      return out;
    },
  };
  return api;
}
