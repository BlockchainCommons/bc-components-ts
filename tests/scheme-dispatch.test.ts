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
  Sr25519PrivateKey,
  MLKEMLevel,
  MLKEMPrivateKey,
  PrivateKeyBase,
  SigningPrivateKey,
  SigningPublicKey,
  Signature,
  SignatureScheme,
  EncapsulationPrivateKey,
  EncapsulationPublicKey,
  EncapsulationCiphertext,
  EncapsulationScheme,
  X25519PrivateKey,
  createKeypair,
  createKeypairUsing,
  createEncapsulationKeypair,
  createEncapsulationKeypairUsing,
  defaultEncapsulationScheme,
} from "../src/index.js";
import {
  isMlkemScheme,
  schemeToMlkemLevel,
  mlkemLevelToScheme,
} from "../src/encapsulation/encapsulation-scheme.js";

const seed = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);
const msg = new TextEncoder().encode("scheme dispatch");
const rng = (): SeededRng => new SeededRng([1n, 2n, 3n, 4n]);

type SigningCase = {
  name: string;
  scheme: SignatureScheme;
  key: SigningPrivateKey;
  own: "Schnorr" | "Ecdsa" | "Ed25519" | "Sr25519" | "Mldsa" | "Ssh";
};
const signingCases: SigningCase[] = [
  {
    name: "schnorr",
    scheme: SignatureScheme.Schnorr,
    key: SigningPrivateKey.newSchnorr(ECPrivateKey.fromData(seed)),
    own: "Schnorr",
  },
  {
    name: "ecdsa",
    scheme: SignatureScheme.Ecdsa,
    key: SigningPrivateKey.newEcdsa(ECPrivateKey.fromData(seed)),
    own: "Ecdsa",
  },
  {
    name: "ed25519",
    scheme: SignatureScheme.Ed25519,
    key: SigningPrivateKey.newEd25519(Ed25519PrivateKey.from(seed)),
    own: "Ed25519",
  },
  {
    name: "sr25519",
    scheme: SignatureScheme.Sr25519,
    key: SigningPrivateKey.newSr25519(Sr25519PrivateKey.from(seed)),
    own: "Sr25519",
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
    key: PrivateKeyBase.fromData(seed).sshSigningPrivateKey({ kind: "ed25519" }, "c"),
    own: "Ssh",
  },
];
const PREDICATES = ["Schnorr", "Ecdsa", "Ed25519", "Sr25519", "Mldsa", "Ssh"] as const;

describe("SigningPrivateKey over every scheme", () => {
  for (const c of signingCases) {
    it(c.name, () => {
      const k = c.key;
      expect(k.scheme()).toBe(c.scheme);
      expect(typeof k.keyType()).toBe("string");
      for (const p of PREDICATES) {
        const is = (k as unknown as Record<string, () => boolean>)[`is${p}`]!();
        expect(is, p).toBe(p === c.own);
        const to = (k as unknown as Record<string, () => unknown>)[`to${p}`]!();
        expect(to !== null, `to${p}`).toBe(p === c.own);
      }
      expect(k.toEc() !== null).toBe(c.own === "Schnorr" || c.own === "Ecdsa");
      // ML-DSA cannot derive its public key from the private key alone.
      if (c.own === "Mldsa") {
        expect(() => k.publicKey()).toThrow(ComponentsError);
        return;
      }
      const pub = k.publicKey();
      expect(pub.scheme()).toBe(c.scheme);
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
      expect(back.scheme()).toBe(c.scheme);
      const viaUr = decodeURWith(UR.parse(k.toUR().toString()), SigningPrivateKey.codec);
      expect(viaUr.equals(k)).toBe(true);
      expect(k.toUR().type.name).toBe("signing-private-key");
      // the scheme-specific signers refuse the wrong scheme
      const own: string = c.own;
      if (own !== "Ecdsa") expect(() => k.ecdsaSign(msg)).toThrow(ComponentsError);
      if (own !== "Ed25519") expect(() => k.ed25519Sign(msg)).toThrow(ComponentsError);
      if (own !== "Sr25519") expect(() => k.sr25519Sign(msg)).toThrow(ComponentsError);
      if (own !== "Mldsa") expect(() => k.mldsaSign(msg)).toThrow(ComponentsError);
      if (own !== "Schnorr") expect(() => k.schnorrSign(msg, rng())).toThrow(ComponentsError);
    });
  }

  it("random constructors produce the named scheme", () => {
    expect(SigningPrivateKey.random().isEd25519()).toBe(true);
    expect(SigningPrivateKey.randomSchnorr().isSchnorr()).toBe(true);
    expect(SigningPrivateKey.randomEcdsa().isEcdsa()).toBe(true);
    expect(SigningPrivateKey.randomSr25519().isSr25519()).toBe(true);
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
          (pub as unknown as Record<string, () => unknown>)[`to${p}`]!() !== null,
          `to${p}`,
        ).toBe(p === c.own);
      }
      expect(typeof pub.keyType()).toBe("string");
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
      expect(sig.scheme()).toBe(c.scheme);
      expect(typeof sig.signatureType()).toBe("string");
      for (const p of PREDICATES) {
        expect((sig as unknown as Record<string, () => boolean>)[`is${p}`]!(), p).toBe(p === c.own);
        expect(
          (sig as unknown as Record<string, () => unknown>)[`to${p}`]!() !== null,
          `to${p}`,
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
    expect(sig.toMldsa()).not.toBeNull();
    expect(pub.isMldsa()).toBe(true);
    expect(pub.toMldsa()).not.toBeNull();
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
    const ec = ECPrivateKey.fromData(seed);
    const e = SigningPrivateKey.newEcdsa(ec).sign(msg);
    expect(Signature.ecdsaFromHex(e.toHex()).equals(e)).toBe(true);
    const s = SigningPrivateKey.newSchnorr(ec).sign(msg);
    expect(Signature.schnorrFromHex(s.toHex()).equals(s)).toBe(true);
    const d = SigningPrivateKey.newEd25519(Ed25519PrivateKey.from(seed)).sign(msg);
    expect(Signature.ed25519FromHex(d.toHex()).equals(d)).toBe(true);
    const r = SigningPrivateKey.newSr25519(Sr25519PrivateKey.from(seed)).sign(msg);
    expect(Signature.sr25519FromHex(r.toHex()).equals(r)).toBe(true);
    expect(() => Signature.ecdsaFromData(new Uint8Array(3))).toThrow(ComponentsError);
  });
});

describe("keypair factories", () => {
  it("createKeypair covers every scheme", () => {
    for (const scheme of Object.values(SignatureScheme)) {
      if (scheme === SignatureScheme.SshDsa) {
        // DSA-1024 key generation is not ported (RUST_DIVERGENCES.md §2).
        expect(() => createKeypair(scheme)).toThrow(ComponentsError);
        continue;
      }
      const [priv, pub] = createKeypair(scheme, "comment");
      expect(priv.scheme()).toBe(scheme);
      expect(pub.scheme()).toBe(scheme);
      if (!priv.isMldsa()) expect(pub.equals(priv.publicKey())).toBe(true);
      const sig = priv.isSsh()
        ? priv.signWithOptions(msg, { type: "Ssh", namespace: "t", hashAlg: "sha256" })
        : priv.sign(msg);
      expect(pub.verify(sig, msg)).toBe(true);
    }
  });
  it("createKeypairUsing is seeded except for ML-DSA", () => {
    for (const scheme of [
      SignatureScheme.Schnorr,
      SignatureScheme.Ecdsa,
      SignatureScheme.Ed25519,
      SignatureScheme.Sr25519,
      SignatureScheme.SshEd25519,
      SignatureScheme.SshEcdsaP256,
    ]) {
      const [a] = createKeypairUsing(scheme, rng());
      const [b] = createKeypairUsing(scheme, rng());
      expect(a.equals(b), scheme).toBe(true);
    }
    expect(() => createKeypairUsing(SignatureScheme.MLDSA65, rng())).toThrow(ComponentsError);
  });
});

describe("Encapsulation types over both schemes", () => {
  const x = EncapsulationPrivateKey.fromX25519PrivateKey(X25519PrivateKey.fromData(seed));
  const m = EncapsulationPrivateKey.fromMlkem(MLKEMPrivateKey.newUsing(MLKEMLevel.MLKEM512, rng()));
  const cases: [string, EncapsulationPrivateKey, EncapsulationScheme][] = [
    ["x25519", x, EncapsulationScheme.X25519],
    ["mlkem512", m, EncapsulationScheme.MLKEM512],
  ];
  for (const [name, priv, scheme] of cases) {
    it(name, () => {
      const isX = scheme === EncapsulationScheme.X25519;
      expect(priv.encapsulationScheme()).toBe(scheme);
      expect(priv.isX25519()).toBe(isX);
      expect(priv.isMlkem()).toBe(!isX);
      expect(priv.toX25519() !== null).toBe(isX);
      expect(priv.toMlkem() !== null).toBe(!isX);
      if (isX) expect(() => priv.mlkemPrivateKey()).toThrow(ComponentsError);
      else expect(() => priv.x25519PrivateKey()).toThrow(ComponentsError);
      expect(priv.data().length).toBeGreaterThan(0);
      expect(priv.equals(priv)).toBe(true);
      expect(priv.toString()).toContain("EncapsulationPrivateKey");
      expect(priv.reference().toCbor().toData().length).toBeGreaterThan(0);
      const back = EncapsulationPrivateKey.fromCbor(decodeCbor(priv.toCbor().toData()));
      expect(back.equals(priv)).toBe(true);
      expect(
        decodeURWith(UR.parse(priv.toUR().toString()), EncapsulationPrivateKey.codec).equals(priv),
      ).toBe(true);
      expect(priv.toUR().type.name).toBe(isX ? "agreement-private-key" : "mlkem-private-key");

      const pub = priv.publicKey();
      expect(pub.encapsulationScheme()).toBe(scheme);
      expect(pub.isX25519()).toBe(isX);
      expect(pub.isMlkem()).toBe(!isX);
      expect(pub.toX25519() !== null).toBe(isX);
      expect(pub.toMlkem() !== null).toBe(!isX);
      if (isX) expect(() => pub.mlkemPublicKey()).toThrow(ComponentsError);
      else expect(() => pub.x25519PublicKey()).toThrow(ComponentsError);
      expect(pub.data().length).toBeGreaterThan(0);
      expect(pub.encapsulationPublicKey().equals(pub)).toBe(true);
      expect(pub.toString()).toContain("EncapsulationPublicKey");
      expect(pub.reference().equals(priv.reference())).toBe(false);
      expect(EncapsulationPublicKey.fromCbor(decodeCbor(pub.toCbor().toData())).equals(pub)).toBe(
        true,
      );
      expect(
        decodeURWith(UR.parse(pub.toUR().toString()), EncapsulationPublicKey.codec).equals(pub),
      ).toBe(true);

      const [shared, ct] = pub.encapsulateNewSharedSecret();
      expect(ct.encapsulationScheme()).toBe(scheme);
      expect(ct.isX25519()).toBe(isX);
      expect(ct.isMlkem()).toBe(!isX);
      expect(ct.toX25519() !== null).toBe(isX);
      expect(ct.toMlkem() !== null).toBe(!isX);
      if (isX) expect(() => ct.mlkemCiphertext()).toThrow(ComponentsError);
      else expect(() => ct.x25519PublicKey()).toThrow(ComponentsError);
      expect(ct.data().length).toBeGreaterThan(0);
      expect(ct.equals(ct)).toBe(true);
      expect(ct.toString()).toContain("EncapsulationCiphertext");
      const ctBack = EncapsulationCiphertext.fromCbor(decodeCbor(ct.toCbor().toData()));
      expect(ctBack.equals(ct)).toBe(true);
      expect(
        decodeURWith(UR.parse(ct.toUR().toString()), EncapsulationCiphertext.codec).equals(ct),
      ).toBe(true);
      expect(priv.decapsulateSharedSecret(ctBack).equals(shared)).toBe(true);
    });
  }

  it("data constructors and random constructors", () => {
    expect(EncapsulationPrivateKey.fromX25519Data(seed).equals(x)).toBe(true);
    expect(EncapsulationPublicKey.fromX25519Data(x.publicKey().data()).equals(x.publicKey())).toBe(
      true,
    );
    expect(EncapsulationCiphertext.fromX25519Data(seed).isX25519()).toBe(true);
    const mp = EncapsulationPrivateKey.fromMlkemData(MLKEMLevel.MLKEM512, m.data());
    expect(mp.equals(m)).toBe(true);
    expect(
      EncapsulationPublicKey.fromMlkemData(MLKEMLevel.MLKEM512, m.publicKey().data()).equals(
        m.publicKey(),
      ),
    ).toBe(true);
    const [, ct] = m.publicKey().encapsulateNewSharedSecret();
    expect(EncapsulationCiphertext.fromMlkemData(MLKEMLevel.MLKEM512, ct.data()).equals(ct)).toBe(
      true,
    );
    expect(EncapsulationPrivateKey.new().isX25519()).toBe(true);
    expect(EncapsulationPrivateKey.random().isX25519()).toBe(true);
    expect(
      EncapsulationPrivateKey.newUsing(rng()).equals(EncapsulationPrivateKey.newUsing(rng())),
    ).toBe(true);
    expect(EncapsulationPrivateKey.newMlkem().isMlkem()).toBe(true);
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
      expect(priv.encapsulationScheme()).toBe(scheme);
      expect(priv.publicKey().equals(pub)).toBe(true);
      expect(() => createEncapsulationKeypairUsing(rng(), scheme)).toThrow(ComponentsError);
    }
    expect(() => schemeToMlkemLevel(EncapsulationScheme.X25519)).toThrow();
    const [a] = createEncapsulationKeypairUsing(rng());
    const [b] = createEncapsulationKeypairUsing(rng(), EncapsulationScheme.X25519);
    expect(a.equals(b)).toBe(true);
    expect(createEncapsulationKeypair()[0].isX25519()).toBe(true);
  });
});
