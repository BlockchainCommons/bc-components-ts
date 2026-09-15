/* eslint-disable @typescript-eslint/no-non-null-assertion -- fixtures are indexed by position; a miss fails the test */
/**
 * The scheme-dispatching types (`SigningPrivateKey`, `SigningPublicKey`,
 * `Signature`, `Encapsulation*`) over every scheme: predicates, accessors,
 * equality, display, references, and the tagged-CBOR / UR round trips.
 */
import { describe, it, expect } from "vitest";
import { decodeCbor } from "@blockchaincommons/dcbor";
import { UR, decodeURWith } from "@blockchaincommons/uniform-resources";
import { SeededRng } from "@blockchaincommons/rand";
import {
  ComponentsError,
  ECPrivateKey,
  Ed25519PrivateKey,
  MLKEMLevel,
  PrivateKeyBase,
  SigningPrivateKey,
  SigningPublicKey,
  Signature,
  SignatureScheme,
  defaultSignatureScheme,
  EncapsulationPrivateKey,
  EncapsulationPublicKey,
  EncapsulationCiphertext,
  EncapsulationScheme,
  X25519PrivateKey,
  createKeypair,
  createEncapsulationKeypair,
  generateKeypair,
  defaultEncapsulationScheme,
} from "../src/index.js";
import { MLDSAPrivateKey, MLDSALevel } from "../src/pq.js";
import { MLKEMPrivateKey } from "../src/pq.js";
import {
  isMlkemScheme,
  schemeToMlkemLevel,
  mlkemLevelToScheme,
} from "../src/encapsulation/encapsulation-scheme.js";

// The reference needs `register_tags()` before a UR is made; so does this package.
import { registerTags } from "../src/tags.js";
registerTags();

const seed = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);
const msg = new TextEncoder().encode("scheme dispatch");
const rng = (): SeededRng => new SeededRng([1n, 2n, 3n, 4n]);

type SigningCase = {
  name: string;
  scheme: SignatureScheme;
  key: SigningPrivateKey;
  own: "Schnorr" | "Ecdsa" | "Ed25519" | "Mldsa" | "Ssh";
};
const signingCases: SigningCase[] = [
  {
    name: "schnorr",
    scheme: SignatureScheme.Schnorr,
    key: SigningPrivateKey.fromSchnorr(ECPrivateKey.from(seed)),
    own: "Schnorr",
  },
  {
    name: "ecdsa",
    scheme: SignatureScheme.Ecdsa,
    key: SigningPrivateKey.fromEcdsa(ECPrivateKey.from(seed)),
    own: "Ecdsa",
  },
  {
    name: "ed25519",
    scheme: SignatureScheme.Ed25519,
    key: SigningPrivateKey.fromEd25519(Ed25519PrivateKey.from(seed)),
    own: "Ed25519",
  },
  {
    name: "mldsa44",
    scheme: SignatureScheme.MLDSA44,
    key: createKeypair(SignatureScheme.MLDSA44)[0],
    own: "Mldsa",
  },
  {
    name: "ssh-ed25519",
    scheme: SignatureScheme.SshEd25519,
    key: PrivateKeyBase.from(seed).sshSigningPrivateKey({ kind: "ed25519" }, "c"),
    own: "Ssh",
  },
];
const PREDICATES = ["Schnorr", "Ecdsa", "Ed25519", "Mldsa", "Ssh"] as const;

describe("SigningPrivateKey over every scheme", () => {
  for (const c of signingCases) {
    it(c.name, () => {
      const k = c.key;
      expect(k.scheme).toBe(c.scheme);
      expect(typeof k.keyType).toBe("string");
      for (const p of PREDICATES) {
        const is = (k as unknown as Record<string, () => boolean>)[`is${p}`]!();
        expect(is, p).toBe(p === c.own);
        const to = (k as unknown as Record<string, () => unknown>)[`as${p}`]!();
        expect(to !== undefined, `as${p}`).toBe(p === c.own);
      }
      expect(k.asEc() !== undefined).toBe(c.own === "Schnorr" || c.own === "Ecdsa");
      // ML-DSA cannot derive its public key from the private key alone.
      if (c.own === "Mldsa") {
        expect(() => k.publicKey()).toThrow(ComponentsError);
        return;
      }
      const pub = k.publicKey();
      expect(pub.scheme).toBe(c.scheme);
      const sig =
        c.own === "Ssh"
          ? k.signWithOptions(msg, { type: "Ssh", namespace: "t", hashAlg: "sha256" })
          : k.sign(msg);
      expect(pub.verify(sig, msg)).toBe(true);
      // The private key verifies only Schnorr (the reference does the same).
      expect(k.verify(sig, msg)).toBe(c.own === "Schnorr");
      expect(pub.verify(sig, new Uint8Array([1]))).toBe(false);
      expect(k.equals(k)).toBe(true);
      expect(k.toString()).toContain("SigningPrivateKey");
      expect(k.reference().toCbor().toData().length).toBeGreaterThan(0);
      const back = SigningPrivateKey.fromCbor(decodeCbor(k.toCbor().toData()));
      expect(back.equals(k)).toBe(true);
      expect(back.scheme).toBe(c.scheme);
      const viaUr = decodeURWith(UR.parse(k.toUR().toString()), SigningPrivateKey.codec);
      expect(viaUr.equals(k)).toBe(true);
      expect(k.toUR().type.name).toBe("signing-private-key");
      // the scheme-specific signers refuse the wrong scheme
      const own: string = c.own;
      if (own !== "Ecdsa") expect(() => k.ecdsaSign(msg)).toThrow(ComponentsError);
      if (own !== "Ed25519") expect(() => k.ed25519Sign(msg)).toThrow(ComponentsError);
      if (own !== "Mldsa") expect(() => k.mldsaSign(msg)).toThrow(ComponentsError);
      if (own !== "Schnorr") expect(() => k.schnorrSign(msg, rng())).toThrow(ComponentsError);
    });
  }

  it("random constructors produce the named scheme", () => {
    expect(SigningPrivateKey.random().isSchnorr()).toBe(true);
    expect(SigningPrivateKey.random({ scheme: SignatureScheme.Ed25519 }).isEd25519()).toBe(true);
    expect(SigningPrivateKey.random({ scheme: SignatureScheme.Schnorr }).isSchnorr()).toBe(true);
    expect(SigningPrivateKey.random({ scheme: SignatureScheme.Ecdsa }).isEcdsa()).toBe(true);
  });

  it("keys of different schemes are not equal", () => {
    const [a, b] = signingCases;
    expect(a!.key.equals(b!.key)).toBe(false);
  });
});

describe("SigningPublicKey and Signature over every scheme", () => {
  for (const c of signingCases) {
    it(c.name, () => {
      const pub = c.own === "Mldsa" ? createKeypair(SignatureScheme.MLDSA44)[1] : c.key.publicKey();
      for (const p of PREDICATES) {
        expect((pub as unknown as Record<string, () => boolean>)[`is${p}`]!(), p).toBe(p === c.own);
        expect(
          (pub as unknown as Record<string, () => unknown>)[`as${p}`]!() !== undefined,
          `as${p}`,
        ).toBe(p === c.own);
      }
      expect(typeof pub.keyType).toBe("string");
      expect(pub.toString()).toContain("SigningPublicKey");
      expect(pub.equals(pub)).toBe(true);
      const back = SigningPublicKey.fromCbor(decodeCbor(pub.toCbor().toData()));
      expect(back.equals(pub)).toBe(true);
      expect(
        decodeURWith(UR.parse(pub.toUR().toString()), SigningPublicKey.codec).equals(pub),
      ).toBe(true);
      expect(pub.reference().equals(c.key.reference())).toBe(false);
      if (c.own === "Ssh") {
        expect(pub.toSshOpenssh()).toContain("ssh-ed25519");
        expect(pub.withSshComment("other").toSshOpenssh()).toContain("other");
      } else {
        expect(() => pub.toSshOpenssh()).toThrow(ComponentsError);
      }

      if (c.own === "Mldsa") return;
      const sig =
        c.own === "Ssh"
          ? c.key.signWithOptions(msg, { type: "Ssh", namespace: "t", hashAlg: "sha256" })
          : c.key.sign(msg);
      expect(sig.scheme).toBe(c.scheme);
      expect(typeof sig.signatureType).toBe("string");
      for (const p of PREDICATES) {
        expect((sig as unknown as Record<string, () => boolean>)[`is${p}`]!(), p).toBe(p === c.own);
        expect(
          (sig as unknown as Record<string, () => unknown>)[`as${p}`]!() !== undefined,
          `as${p}`,
        ).toBe(p === c.own);
      }
      expect(sig.toHex().length).toBeGreaterThan(0);
      expect(sig.equals(sig)).toBe(true);
      expect(sig.toString()).toContain("Signature");
      const sback = Signature.fromCbor(decodeCbor(sig.toCbor().toData()));
      expect(sback.equals(sig)).toBe(true);
      expect(pub.verify(sback, msg)).toBe(true);
      expect(decodeURWith(UR.parse(sig.toUR().toString()), Signature.codec).equals(sig)).toBe(true);
    });
  }

  it("ML-DSA public key and signature round trips", () => {
    const [priv, pub] = createKeypair(SignatureScheme.MLDSA44);
    const sig = priv.sign(msg);
    expect(sig.isMldsa()).toBe(true);
    expect(sig.asMldsa()).toBeDefined();
    expect(pub.isMldsa()).toBe(true);
    expect(pub.asMldsa()).toBeDefined();
    expect(pub.verify(sig, msg)).toBe(true);
    expect(Signature.fromCbor(decodeCbor(sig.toCbor().toData())).equals(sig)).toBe(true);
    expect(SigningPublicKey.fromCbor(decodeCbor(pub.toCbor().toData())).equals(pub)).toBe(true);
    expect(decodeURWith(UR.parse(pub.toUR().toString()), SigningPublicKey.codec).equals(pub)).toBe(
      true,
    );
    expect(decodeURWith(UR.parse(sig.toUR().toString()), Signature.codec).equals(sig)).toBe(true);
    expect(SigningPrivateKey.fromCbor(decodeCbor(priv.toCbor().toData())).equals(priv)).toBe(true);
  });

  it("hex constructors round-trip the raw signature bytes", () => {
    const ec = ECPrivateKey.from(seed);
    const e = SigningPrivateKey.fromEcdsa(ec).sign(msg);
    expect(Signature.ecdsaFromHex(e.toHex()).equals(e)).toBe(true);
    const s = SigningPrivateKey.fromSchnorr(ec).sign(msg);
    expect(Signature.schnorrFromHex(s.toHex()).equals(s)).toBe(true);
    const d = SigningPrivateKey.fromEd25519(Ed25519PrivateKey.from(seed)).sign(msg);
    expect(Signature.ed25519FromHex(d.toHex()).equals(d)).toBe(true);
    expect(() => Signature.ecdsaFromData(new Uint8Array(3))).toThrow(ComponentsError);
  });
});

describe("keypair factories", () => {
  it("createKeypair covers every scheme", () => {
    for (const scheme of Object.values(SignatureScheme)) {
      const [priv, pub] = createKeypair(scheme, { comment: "comment" });
      expect(priv.scheme).toBe(scheme);
      expect(pub.scheme).toBe(scheme);
      if (!priv.isMldsa()) expect(pub.equals(priv.publicKey())).toBe(true);
      const sig = priv.isSsh()
        ? priv.signWithOptions(msg, { type: "Ssh", namespace: "t", hashAlg: "sha256" })
        : priv.sign(msg);
      expect(pub.verify(sig, msg)).toBe(true);
    }
  });
  it("createKeypair with an rng is seeded for every scheme the reference seeds", () => {
    for (const scheme of [
      SignatureScheme.Schnorr,
      SignatureScheme.Ecdsa,
      SignatureScheme.Ed25519,
      SignatureScheme.SshEd25519,
      SignatureScheme.SshEcdsaP256,
      SignatureScheme.SshDsa,
    ]) {
      const [a] = createKeypair(scheme, { rng: rng() });
      const [b] = createKeypair(scheme, { rng: rng() });
      expect(a.equals(b), scheme).toBe(true);
    }
  });
  it("createKeypair refuses an rng for the ML-DSA schemes before drawing, as keypair_using", () => {
    for (const scheme of [
      SignatureScheme.MLDSA44,
      SignatureScheme.MLDSA65,
      SignatureScheme.MLDSA87,
    ]) {
      let draws = 0;
      const counting = {
        nextU32: () => {
          draws++;
          return 0;
        },
        nextU64: () => {
          draws++;
          return 0n;
        },
        fillBytes: () => {
          draws++;
        },
      };
      let thrown: unknown;
      try {
        createKeypair(scheme, { rng: counting });
      } catch (e) {
        thrown = e;
      }
      expect(ComponentsError.isComponentsError(thrown)).toBe(true);
      expect((thrown as ComponentsError).code).toBe("General");
      expect((thrown as ComponentsError).message).toBe(
        "Deterministic keypair generation not supported for this signature scheme",
      );
      expect(draws).toBe(0);
      // Without an rng the pair comes from the secure generator.
      const [priv, pub] = createKeypair(scheme);
      expect(priv.scheme).toBe(scheme);
      expect(pub.verify(priv.sign(msg), msg)).toBe(true);
    }
    // The seeded route is the level's own factory.
    const [a] = MLDSAPrivateKey.keypair(MLDSALevel.MLDSA65, { rng: rng() });
    const [b] = MLDSAPrivateKey.keypair(MLDSALevel.MLDSA65, { rng: rng() });
    expect(a.equals(b)).toBe(true);
  });
  it("createEncapsulationKeypair and generateKeypair refuse an rng for ML-KEM, as keypair_opt_using", () => {
    for (const scheme of [
      EncapsulationScheme.MLKEM512,
      EncapsulationScheme.MLKEM768,
      EncapsulationScheme.MLKEM1024,
    ]) {
      let thrown: unknown;
      try {
        createEncapsulationKeypair(scheme, { rng: rng() });
      } catch (e) {
        thrown = e;
      }
      expect((thrown as ComponentsError).code).toBe("General");
      expect((thrown as ComponentsError).message).toBe(
        "Deterministic keypair generation not supported for this encapsulation scheme",
      );
      const [priv, pub] = createEncapsulationKeypair(scheme);
      expect(priv.encapsulationScheme).toBe(scheme);
      expect(pub.encapsulationScheme).toBe(scheme);
    }
    // The signing pair is made first and draws; the refusal comes at the encapsulation turn.
    let draws = 0;
    const counting = {
      nextU32: () => {
        draws++;
        return 0;
      },
      nextU64: () => {
        draws++;
        return 0n;
      },
      fillBytes: (d: Uint8Array) => {
        draws++;
        d.fill(7);
      },
    };
    expect(() =>
      generateKeypair({
        signing: SignatureScheme.Ed25519,
        encapsulation: EncapsulationScheme.MLKEM768,
        rng: counting,
      }),
    ).toThrow("Deterministic keypair generation not supported for this encapsulation scheme");
    expect(draws).toBeGreaterThan(0);
    draws = 0;
    expect(() =>
      generateKeypair({
        signing: SignatureScheme.MLDSA44,
        encapsulation: EncapsulationScheme.X25519,
        rng: counting,
      }),
    ).toThrow("Deterministic keypair generation not supported for this signature scheme");
    expect(draws).toBe(0);
  });
  it("createKeypair defaults to the reference's default scheme", () => {
    const [priv, pub] = createKeypair();
    expect(priv.scheme).toBe(defaultSignatureScheme());
    expect(priv.isSchnorr()).toBe(true);
    expect(pub.equals(priv.publicKey())).toBe(true);
  });
});

describe("Encapsulation types over both schemes", () => {
  const x = EncapsulationPrivateKey.fromX25519PrivateKey(X25519PrivateKey.from(seed));
  const [mPriv, mPub] = MLKEMPrivateKey.keypair(MLKEMLevel.MLKEM512, { rng: rng() });
  const m = EncapsulationPrivateKey.fromMlkem(mPriv);
  const cases: [string, EncapsulationPrivateKey, EncapsulationPublicKey, EncapsulationScheme][] = [
    ["x25519", x, x.publicKey(), EncapsulationScheme.X25519],
    ["mlkem512", m, EncapsulationPublicKey.fromMlkem(mPub), EncapsulationScheme.MLKEM512],
  ];
  for (const [name, priv, pub, scheme] of cases) {
    it(name, () => {
      const isX = scheme === EncapsulationScheme.X25519;
      expect(priv.encapsulationScheme).toBe(scheme);
      expect(priv.isX25519()).toBe(isX);
      expect(priv.isMlkem()).toBe(!isX);
      expect(priv.asX25519() !== undefined).toBe(isX);
      expect(priv.asMlkem() !== undefined).toBe(!isX);
      if (isX) expect(() => priv.mlkemPrivateKey()).toThrow(ComponentsError);
      else expect(() => priv.x25519PrivateKey()).toThrow(ComponentsError);
      expect(priv.bytes.length).toBeGreaterThan(0);
      expect(priv.equals(priv)).toBe(true);
      expect(priv.toString()).toContain("EncapsulationPrivateKey");
      expect(priv.reference().toCbor().toData().length).toBeGreaterThan(0);
      const back = EncapsulationPrivateKey.fromCbor(decodeCbor(priv.toCbor().toData()));
      expect(back.equals(priv)).toBe(true);
      expect("toUR" in priv).toBe(false);

      if (isX) expect(priv.publicKey().equals(pub)).toBe(true);
      else expect(() => priv.publicKey()).toThrow(ComponentsError);
      expect(pub.encapsulationScheme).toBe(scheme);
      expect(pub.isX25519()).toBe(isX);
      expect(pub.isMlkem()).toBe(!isX);
      expect(pub.asX25519() !== undefined).toBe(isX);
      expect(pub.asMlkem() !== undefined).toBe(!isX);
      if (isX) expect(() => pub.mlkemPublicKey()).toThrow(ComponentsError);
      else expect(() => pub.x25519PublicKey()).toThrow(ComponentsError);
      expect(pub.bytes.length).toBeGreaterThan(0);
      expect(pub.encapsulationPublicKey().equals(pub)).toBe(true);
      expect(pub.toString()).toContain("EncapsulationPublicKey");
      expect(pub.reference().equals(priv.reference())).toBe(false);
      expect(EncapsulationPublicKey.fromCbor(decodeCbor(pub.toCbor().toData())).equals(pub)).toBe(
        true,
      );
      expect("toUR" in pub).toBe(false);

      const [shared, ct] = pub.encapsulateNewSharedSecret();
      expect(ct.encapsulationScheme).toBe(scheme);
      expect(ct.isX25519()).toBe(isX);
      expect(ct.isMlkem()).toBe(!isX);
      expect(ct.asX25519() !== undefined).toBe(isX);
      expect(ct.asMlkem() !== undefined).toBe(!isX);
      if (isX) expect(() => ct.mlkemCiphertext()).toThrow(ComponentsError);
      else expect(() => ct.x25519PublicKey()).toThrow(ComponentsError);
      expect(ct.bytes.length).toBeGreaterThan(0);
      expect(ct.equals(ct)).toBe(true);
      expect(ct.toString()).toContain("EncapsulationCiphertext");
      const ctBack = EncapsulationCiphertext.fromCbor(decodeCbor(ct.toCbor().toData()));
      expect(ctBack.equals(ct)).toBe(true);
      expect("toUR" in ct).toBe(false);
      expect(priv.decapsulateSharedSecret(ctBack).equals(shared)).toBe(true);
    });
  }

  it("data constructors and random constructors", () => {
    expect(EncapsulationPrivateKey.fromX25519Data(seed).equals(x)).toBe(true);
    expect(EncapsulationPublicKey.fromX25519Data(x.publicKey().bytes).equals(x.publicKey())).toBe(
      true,
    );
    expect(EncapsulationCiphertext.fromX25519Data(seed).isX25519()).toBe(true);
    const mp = EncapsulationPrivateKey.fromMlkemData(MLKEMLevel.MLKEM512, m.bytes);
    expect(mp.equals(m)).toBe(true);
    const mPublic = EncapsulationPublicKey.fromMlkem(mPub);
    expect(
      EncapsulationPublicKey.fromMlkemData(MLKEMLevel.MLKEM512, mPublic.bytes).equals(mPublic),
    ).toBe(true);
    const [, ct] = mPublic.encapsulateNewSharedSecret();
    expect(EncapsulationCiphertext.fromMlkemData(MLKEMLevel.MLKEM512, ct.bytes).equals(ct)).toBe(
      true,
    );
    expect(EncapsulationPrivateKey.random().isX25519()).toBe(true);
    expect(EncapsulationPrivateKey.random().isX25519()).toBe(true);
    expect(
      EncapsulationPrivateKey.random({ rng: rng() }).equals(
        EncapsulationPrivateKey.random({ rng: rng() }),
      ),
    ).toBe(true);
    expect(EncapsulationPrivateKey.randomMlkem().isMlkem()).toBe(true);
    const [kp, kpub] = EncapsulationPrivateKey.keypair();
    expect(kp.publicKey().equals(kpub)).toBe(true);
    expect(x.equals(m)).toBe(false);
  });

  it("scheme helpers and keypair factories", () => {
    expect(defaultEncapsulationScheme()).toBe(EncapsulationScheme.X25519);
    expect(isMlkemScheme(EncapsulationScheme.X25519)).toBe(false);
    for (const [scheme, level] of [
      [EncapsulationScheme.MLKEM512, MLKEMLevel.MLKEM512],
      [EncapsulationScheme.MLKEM768, MLKEMLevel.MLKEM768],
      [EncapsulationScheme.MLKEM1024, MLKEMLevel.MLKEM1024],
    ] as const) {
      expect(isMlkemScheme(scheme)).toBe(true);
      expect(schemeToMlkemLevel(scheme)).toBe(level);
      expect(mlkemLevelToScheme(level)).toBe(scheme);
      const [priv, pub] = createEncapsulationKeypair(scheme);
      expect(priv.encapsulationScheme).toBe(scheme);
      expect(pub.encapsulationScheme).toBe(scheme);
      // The public key is not derived from an ML-KEM private key (the reference refuses).
      expect(() => priv.publicKey()).toThrow(ComponentsError);
      // Seeded ML-KEM pairs come from the level's own factory.
      const [s1] = EncapsulationPrivateKey.mlkemKeypair(level, { rng: rng() });
      const [s2] = EncapsulationPrivateKey.mlkemKeypair(level, { rng: rng() });
      expect(s1.equals(s2), scheme).toBe(true);
    }
    expect(() => schemeToMlkemLevel(EncapsulationScheme.X25519)).toThrow();
    const [a] = createEncapsulationKeypair(EncapsulationScheme.X25519, { rng: rng() });
    const [b] = createEncapsulationKeypair(EncapsulationScheme.X25519, { rng: rng() });
    expect(a.equals(b)).toBe(true);
    expect(createEncapsulationKeypair()[0].isX25519()).toBe(true);
  });
});
