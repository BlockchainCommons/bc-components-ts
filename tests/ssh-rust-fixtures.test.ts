/**
 *
 * Byte-identical parity tests against the Rust reference
 * (`bc-components` 0.31.1 over `ssh-key` 0.6.7) SSH fixtures.
 *
 * The reference derives every SSH key as
 *   `PrivateKeyBase::from_data(hex!("59f2293a5bce7d4de59e71b4207ac5d2"))`
 *   `.ssh_signing_private_key(algorithm, "Key comment.")`
 * and the OpenSSH PEM, public-key text and `sshsig` signatures it produced
 * are asserted here byte for byte:
 *   - Ed25519, DSA, ECDSA P-256 / P-384 / P-521 and RSA key generation
 *     (`tests/fixtures/ssh-keygen/*.json` for the 22-seed sets);
 *   - `sshsig` signatures over `hello` in namespace `test`
 *     (`tests/fixtures/ssh-sign/vectors.json`): byte-identical for DSA
 *     and P-256 (RFC 6979); the reference signs P-521 with a random nonce
 *     (`p521` 0.13.3 draws `k` from `OsRng`), so its P-521 signatures are
 *     verified rather than reproduced; RSA signing fails in the reference
 *     and RSA signatures made with the `rsa` crate directly verify;
 *   - the `SignatureScheme` mapping, including the reference's failure for
 *     RSA and P-521, which have no scheme.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import {
  PrivateKeyBase,
  SignatureScheme,
  SigningPrivateKey,
  SigningPublicKey,
} from "../src/index.js";
import { Signature } from "../src/signing/signature.js";
import { SSHPrivateKey, SSHSignature } from "../src/ssh/index.js";
import { ComponentsError } from "../src/error.js";
import { decodeCbor } from "@blockchaincommons/dcbor";

const here = dirname(fileURLToPath(import.meta.url));

interface KeygenRecord {
  seed: string;
  privatePem: string;
  publicOpenssh: string;
}

function keygenRecords(name: string): KeygenRecord[] {
  const text = readFileSync(join(here, "fixtures", "ssh-keygen", `${name}.json`), "utf8");
  return (JSON.parse(text) as { records: KeygenRecord[] }).records;
}

interface SignVector {
  hashAlgorithm: "sha256" | "sha512";
  signatureAlgorithm: string;
  sshsigPem: string;
  verified: boolean;
  bcScheme: string;
}

interface RsaSignVector extends SignVector {
  bcVerified: boolean;
  wrongMessageVerified: boolean;
  wrongNamespaceVerified: boolean;
}

interface SignVectors {
  rsaSign: { bcComponentsDisplay: string; sshKeyDirectDisplay: string };
  rsaPlainSshRsaSig: { sshsigPem: string; parseOutcome: string };
  rsaVectors: RsaSignVector[];
  p521Vectors: SignVector[];
  dsaVectors: SignVector[];
  p256Vectors: SignVector[];
}

const SIGN_VECTORS = JSON.parse(
  readFileSync(join(here, "fixtures", "ssh-sign", "vectors.json"), "utf8"),
) as SignVectors;

const VECTOR_MESSAGE = new TextEncoder().encode("hello");
const VECTOR_NAMESPACE = "test";

function unhex(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function sshOf(sig: Signature): SSHSignature {
  const ssh = sig.asSsh();
  if (ssh === undefined) throw new Error("not an SSH signature");
  return ssh;
}

// Mirror `bc-components-rust/src/lib.rs:268` — `SEED = hex!("59f2293a5bce7d4de59e71b4207ac5d2")`.
const RUST_SEED = new Uint8Array([
  0x59, 0xf2, 0x29, 0x3a, 0x5b, 0xce, 0x7d, 0x4d, 0xe5, 0x9e, 0x71, 0xb4, 0x20, 0x7a, 0xc5, 0xd2,
]);

const RUST_COMMENT = "Key comment.";

const RUST_MESSAGE = new TextEncoder().encode(
  "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
);

const RUST_NAMESPACE = "test";

// --- Ed25519 fixture (Rust `lib.rs:464-470, 473`) -----------------------------

const RUST_ED25519_PRIVATE_PEM = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBUe4FDGyGIgHf75yVdE4hYl9guj02FdsIadgLC04zObQAAAJA+TyZiPk8m
YgAAAAtzc2gtZWQyNTUxOQAAACBUe4FDGyGIgHf75yVdE4hYl9guj02FdsIadgLC04zObQ
AAAECsX3CKi3hm5VrrU26ffa2FB2YrFogg45ucOVbIz4FQo1R7gUMbIYiAd/vnJV0TiFiX
2C6PTYV2whp2AsLTjM5tAAAADEtleSBjb21tZW50LgE=
-----END OPENSSH PRIVATE KEY-----
`;

const RUST_ED25519_PUBLIC_OPENSSH =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFR7gUMbIYiAd/vnJV0TiFiX2C6PTYV2whp2AsLTjM5t Key comment.";

// --- DSA fixture (Rust `lib.rs:310-330, 334`) ---------------------------------

/** A reference-generated DSA key whose private exponent x is 1 (comment `small-x-fixture`). */
const RUST_DSA_SMALL_X_PEM = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsQAAAAdzc2gtZH
NzAAAAgQC/7asaHYbbX7CUlzKoKpntY8zNkkYuG/qkRzqyvDNzbefnKasi1epmAhrCWnTH
5qYtwzup62vucUlfvs3mvCD72Q+cGaCooWdqUyYFxIgE4ZCN6EBtywGaYUbvTMKQfMTMnM
gCpmrmcN6MfEd7i5TWYlYhD9HMVXR67Bg9f9ZkGQAAABUAxWqN2dXOPvdlH3lBIGdYzWca
uGUAAACAKepvsejOCO+dil9sK0tzmUvn7P2OLtijHZ7Am/Eamr6R3xXfKmWFmjVqJIuw8V
G+P0hNbIPAsYjCnXXVZEwgsENObYMj0bBTVpPu75cMtRaGKOVGBIUqKltFr2uASdKyB2dJ
yMkGjS10orxOqeVaPxSKpsp26tfTNIZhEOgrQ1IAAACAKepvsejOCO+dil9sK0tzmUvn7P
2OLtijHZ7Am/Eamr6R3xXfKmWFmjVqJIuw8VG+P0hNbIPAsYjCnXXVZEwgsENObYMj0bBT
VpPu75cMtRaGKOVGBIUqKltFr2uASdKyB2dJyMkGjS10orxOqeVaPxSKpsp26tfTNIZhEO
grQ1IAAAHYAAAAAAAAAAAAAAAHc3NoLWRzcwAAAIEAv+2rGh2G21+wlJcyqCqZ7WPMzZJG
Lhv6pEc6srwzc23n5ymrItXqZgIawlp0x+amLcM7qetr7nFJX77N5rwg+9kPnBmgqKFnal
MmBcSIBOGQjehAbcsBmmFG70zCkHzEzJzIAqZq5nDejHxHe4uU1mJWIQ/RzFV0euwYPX/W
ZBkAAAAVAMVqjdnVzj73ZR95QSBnWM1nGrhlAAAAgCnqb7HozgjvnYpfbCtLc5lL5+z9ji
7Yox2ewJvxGpq+kd8V3yplhZo1aiSLsPFRvj9ITWyDwLGIwp111WRMILBDTm2DI9GwU1aT
7u+XDLUWhijlRgSFKipbRa9rgEnSsgdnScjJBo0tdKK8TqnlWj8UiqbKdurX0zSGYRDoK0
NSAAAAgCnqb7HozgjvnYpfbCtLc5lL5+z9ji7Yox2ewJvxGpq+kd8V3yplhZo1aiSLsPFR
vj9ITWyDwLGIwp111WRMILBDTm2DI9GwU1aT7u+XDLUWhijlRgSFKipbRa9rgEnSsgdnSc
jJBo0tdKK8TqnlWj8UiqbKdurX0zSGYRDoK0NSAAAAAQEAAAAPc21hbGwteC1maXh0dXJl
AQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
`;
const RUST_DSA_PRIVATE_PEM = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsgAAAAdzc2gtZH
NzAAAAgQCWG4f7r8FAMT/IL11w9OfM/ZduIQ8vEq1Ub+uMdyJS8wS/jXL5OB2/dPnXCNSt
L4vjSqpDzMs+Dtd5wJy6baSQ3zGEbYv71mkIRJB/AtSVmd8FZe5AEjLFvHxYMSlO0jpi1Y
/1nLM7vLQu4QByDCLhYYjPxgrZKXB3cLxtjvly5wAAABUA4fIZLivnDVcg9PXzwcb5m07H
9k0AAACBAJK5Vm6t1Sg7n+C63wrNgDA6LTNyGzxqRVM2unI16jisCOzuC98Dgs+IbAkLhT
qWSY+nI+U9HBHc7sr+KKdWCzR76NLK5eSilXvtt8g+LfHIXvCjD4Q2puowtjDoXSEQAJYd
c1gtef21KZ2eoKoyAwzQIehCbvLpwYbxnhap5usVAAAAgGCrsbfReaDZo1Cw4/dFlJWBDP
sMGeG04/2hCThNmU+zLiKCwsEg0X6onOTMTonCXve3fVb5lNjIU92iTmt5QkmOj2hjsbgo
q/0sa0lALHp7UcK/W4IdU4Abtc4m0SUflgJcds1nsy2rKUNEtAfRa/WwtDResWOa4T7L+3
FEUdavAAAB6F0RJ3hdESd4AAAAB3NzaC1kc3MAAACBAJYbh/uvwUAxP8gvXXD058z9l24h
Dy8SrVRv64x3IlLzBL+Ncvk4Hb90+dcI1K0vi+NKqkPMyz4O13nAnLptpJDfMYRti/vWaQ
hEkH8C1JWZ3wVl7kASMsW8fFgxKU7SOmLVj/Wcszu8tC7hAHIMIuFhiM/GCtkpcHdwvG2O
+XLnAAAAFQDh8hkuK+cNVyD09fPBxvmbTsf2TQAAAIEAkrlWbq3VKDuf4LrfCs2AMDotM3
IbPGpFUza6cjXqOKwI7O4L3wOCz4hsCQuFOpZJj6cj5T0cEdzuyv4op1YLNHvo0srl5KKV
e+23yD4t8che8KMPhDam6jC2MOhdIRAAlh1zWC15/bUpnZ6gqjIDDNAh6EJu8unBhvGeFq
nm6xUAAACAYKuxt9F5oNmjULDj90WUlYEM+wwZ4bTj/aEJOE2ZT7MuIoLCwSDRfqic5MxO
icJe97d9VvmU2MhT3aJOa3lCSY6PaGOxuCir/SxrSUAsentRwr9bgh1TgBu1zibRJR+WAl
x2zWezLaspQ0S0B9Fr9bC0NF6xY5rhPsv7cURR1q8AAAAVANWljfuxQcmJ/T7wSmAUXmXo
6ZI0AAAADEtleSBjb21tZW50LgECAwQF
-----END OPENSSH PRIVATE KEY-----
`;

const RUST_DSA_PUBLIC_OPENSSH =
  "ssh-dss AAAAB3NzaC1kc3MAAACBAJYbh/uvwUAxP8gvXXD058z9l24hDy8SrVRv64x3IlLzBL+Ncvk4Hb90+dcI1K0vi+NKqkPMyz4O13nAnLptpJDfMYRti/vWaQhEkH8C1JWZ3wVl7kASMsW8fFgxKU7SOmLVj/Wcszu8tC7hAHIMIuFhiM/GCtkpcHdwvG2O+XLnAAAAFQDh8hkuK+cNVyD09fPBxvmbTsf2TQAAAIEAkrlWbq3VKDuf4LrfCs2AMDotM3IbPGpFUza6cjXqOKwI7O4L3wOCz4hsCQuFOpZJj6cj5T0cEdzuyv4op1YLNHvo0srl5KKVe+23yD4t8che8KMPhDam6jC2MOhdIRAAlh1zWC15/bUpnZ6gqjIDDNAh6EJu8unBhvGeFqnm6xUAAACAYKuxt9F5oNmjULDj90WUlYEM+wwZ4bTj/aEJOE2ZT7MuIoLCwSDRfqic5MxOicJe97d9VvmU2MhT3aJOa3lCSY6PaGOxuCir/SxrSUAsentRwr9bgh1TgBu1zibRJR+WAlx2zWezLaspQ0S0B9Fr9bC0NF6xY5rhPsv7cURR1q8= Key comment.";

describe("SSH fixture parity with Rust `bc-components-rust v0.31.1`", () => {
  describe("Ed25519 — byte-identical keygen + sign/verify round-trip", () => {
    it("derives the Rust Ed25519 fixture byte-for-byte from SEED", () => {
      const base = PrivateKeyBase.from(RUST_SEED);
      const privateKey = base.sshSigningPrivateKey({ kind: "ed25519" }, RUST_COMMENT);

      expect(privateKey).toBeInstanceOf(SigningPrivateKey);
      expect(privateKey.scheme).toBe(SignatureScheme.SshEd25519);

      // Byte-identical with Rust's `to_openssh(LineEnding::LF)`.
      expect(privateKey.toSshOpenssh()).toBe(RUST_ED25519_PRIVATE_PEM);

      const publicKey = privateKey.publicKey();
      expect(publicKey.scheme).toBe(SignatureScheme.SshEd25519);
      expect(publicKey.toSshOpenssh()).toBe(RUST_ED25519_PUBLIC_OPENSSH);
    });

    it("signs and verifies via SignatureScheme dispatch", () => {
      const base = PrivateKeyBase.from(RUST_SEED);
      const privateKey = base.sshSigningPrivateKey({ kind: "ed25519" }, RUST_COMMENT);
      const publicKey = privateKey.publicKey();
      const sig = privateKey.signWithOptions(RUST_MESSAGE, {
        type: "Ssh",
        namespace: RUST_NAMESPACE,
        hashAlg: "sha256",
      });
      expect(publicKey.verify(sig, RUST_MESSAGE)).toBe(true);
    });
  });

  describe("DSA — byte-identical keygen from SEED, sign/verify, PEM round-trip", () => {
    it("derives the Rust DSA fixture byte-for-byte from SEED", () => {
      const base = PrivateKeyBase.from(RUST_SEED);
      const privateKey = base.sshSigningPrivateKey({ kind: "dsa" }, RUST_COMMENT);
      expect(privateKey.scheme).toBe(SignatureScheme.SshDsa);
      expect(privateKey.keyType).toBe("SSH-DSA");
      expect(privateKey.toSshOpenssh()).toBe(RUST_DSA_PRIVATE_PEM);
      expect(privateKey.publicKey().toSshOpenssh()).toBe(RUST_DSA_PUBLIC_OPENSSH);
    });

    it("signs byte-identically to the reference (RFC 6979 over SHA-1)", () => {
      const privateKey = PrivateKeyBase.from(RUST_SEED).sshSigningPrivateKey(
        { kind: "dsa" },
        RUST_COMMENT,
      );
      for (const v of SIGN_VECTORS.dsaVectors) {
        const sig = privateKey.signWithOptions(VECTOR_MESSAGE, {
          type: "Ssh",
          namespace: VECTOR_NAMESPACE,
          hashAlg: v.hashAlgorithm,
        });
        expect(sshOf(sig).toPem()).toBe(v.sshsigPem);
        expect(sig.scheme).toBe(SignatureScheme.SshDsa);
        expect(privateKey.publicKey().verify(sig, VECTOR_MESSAGE)).toBe(v.verified);
      }
    });

    it("round-trips the Rust DSA fixture PEM byte-for-byte", () => {
      const sshKey = SSHPrivateKey.fromOpenssh(RUST_DSA_PRIVATE_PEM);
      expect(sshKey.toOpenssh()).toBe(RUST_DSA_PRIVATE_PEM);
      const privateKey = SigningPrivateKey.fromSsh(sshKey);
      expect(privateKey.scheme).toBe(SignatureScheme.SshDsa);
      expect(privateKey.toSshOpenssh()).toBe(RUST_DSA_PRIVATE_PEM);
    });

    it("derives the Rust DSA public-key fixture byte-for-byte from the loaded private key", () => {
      const sshKey = SSHPrivateKey.fromOpenssh(RUST_DSA_PRIVATE_PEM);
      const privateKey = SigningPrivateKey.fromSsh(sshKey);
      const publicKey = privateKey.publicKey();
      expect(publicKey.scheme).toBe(SignatureScheme.SshDsa);
      expect(publicKey.toSshOpenssh()).toBe(RUST_DSA_PUBLIC_OPENSSH);
    });

    it("signs and verifies a message via SignatureScheme dispatch", () => {
      const sshKey = SSHPrivateKey.fromOpenssh(RUST_DSA_PRIVATE_PEM);
      const privateKey = SigningPrivateKey.fromSsh(sshKey);
      const publicKey = privateKey.publicKey();
      const sig = privateKey.signWithOptions(RUST_MESSAGE, {
        type: "Ssh",
        namespace: RUST_NAMESPACE,
        hashAlg: "sha256",
      });
      expect(publicKey.verify(sig, RUST_MESSAGE)).toBe(true);
    });

    it("seeds RFC 6979 with the minimal encoding of x, as the dsa crate: x = 1 signs as the reference", () => {
      // A key whose private exponent is 1 (the reference generated the PEM;
      // its signature over "hello" in namespace "fixture" is pinned). RFC 6979
      // §2.3.3 would seed the DRBG with a fixed 20-byte x and give
      // 879e836e…d832047 instead.
      const key = SSHPrivateKey.fromOpenssh(RUST_DSA_SMALL_X_PEM);
      expect(key.data.kind).toBe("dsa");
      if (key.data.kind === "dsa") expect(Buffer.from(key.data.x).toString("hex")).toBe("01");
      const sig = key.sign("fixture", "sha256", new TextEncoder().encode("hello"));
      expect(Buffer.from(sig.signatureBytes).toString("hex")).toBe(
        "093b8a2ce2d48acfc29354649e8665969957ce199f60e428477528638aee046e89e45cfb667863ab",
      );
      expect(
        key.publicKey().verifySshSignature("fixture", new TextEncoder().encode("hello"), sig),
      ).toBe(true);
    });
  });

  describe("ECDSA P-256 — keygen + sign/verify", () => {
    it("signs byte-identically to the reference (RFC 6979, no low-s)", () => {
      const privateKey = PrivateKeyBase.from(RUST_SEED).sshSigningPrivateKey(
        { kind: "ecdsa", curve: "nistp256" },
        RUST_COMMENT,
      );
      for (const v of SIGN_VECTORS.p256Vectors) {
        const sig = privateKey.signWithOptions(VECTOR_MESSAGE, {
          type: "Ssh",
          namespace: VECTOR_NAMESPACE,
          hashAlg: v.hashAlgorithm,
        });
        expect(sshOf(sig).toPem()).toBe(v.sshsigPem);
        expect(privateKey.publicKey().verify(sig, VECTOR_MESSAGE)).toBe(true);
      }
    });

    it("derives a P-256 SSH key from SEED and round-trips through OpenSSH", () => {
      const base = PrivateKeyBase.from(RUST_SEED);
      const privateKey = base.sshSigningPrivateKey(
        { kind: "ecdsa", curve: "nistp256" },
        RUST_COMMENT,
      );
      expect(privateKey.scheme).toBe(SignatureScheme.SshEcdsaP256);
      const pem = privateKey.toSshOpenssh();
      const reloaded = SigningPrivateKey.fromSsh(SSHPrivateKey.fromOpenssh(pem));
      expect(reloaded.toSshOpenssh()).toBe(pem);
    });

    it("signs and verifies via SignatureScheme dispatch", () => {
      const base = PrivateKeyBase.from(RUST_SEED);
      const privateKey = base.sshSigningPrivateKey(
        { kind: "ecdsa", curve: "nistp256" },
        RUST_COMMENT,
      );
      const publicKey = privateKey.publicKey();
      const sig = privateKey.signWithOptions(RUST_MESSAGE, {
        type: "Ssh",
        namespace: RUST_NAMESPACE,
        hashAlg: "sha256",
      });
      expect(publicKey.verify(sig, RUST_MESSAGE)).toBe(true);
    });
  });

  describe("ECDSA P-384 — keygen + sign/verify", () => {
    it("derives a P-384 SSH key from SEED and round-trips through OpenSSH", () => {
      const base = PrivateKeyBase.from(RUST_SEED);
      const privateKey = base.sshSigningPrivateKey(
        { kind: "ecdsa", curve: "nistp384" },
        RUST_COMMENT,
      );
      expect(privateKey.scheme).toBe(SignatureScheme.SshEcdsaP384);
      const pem = privateKey.toSshOpenssh();
      const reloaded = SigningPrivateKey.fromSsh(SSHPrivateKey.fromOpenssh(pem));
      expect(reloaded.toSshOpenssh()).toBe(pem);
    });

    it("signs and verifies via SignatureScheme dispatch", () => {
      const base = PrivateKeyBase.from(RUST_SEED);
      const privateKey = base.sshSigningPrivateKey(
        { kind: "ecdsa", curve: "nistp384" },
        RUST_COMMENT,
      );
      const publicKey = privateKey.publicKey();
      const sig = privateKey.signWithOptions(RUST_MESSAGE, {
        type: "Ssh",
        namespace: RUST_NAMESPACE,
        hashAlg: "sha512",
      });
      expect(publicKey.verify(sig, RUST_MESSAGE)).toBe(true);
    });
  });

  describe("CBOR round-trip for SSH SigningPrivateKey / SigningPublicKey / Signature", () => {
    it("Ed25519: SigningPrivateKey CBOR round-trip", () => {
      const base = PrivateKeyBase.from(RUST_SEED);
      const sk = base.sshSigningPrivateKey({ kind: "ed25519" }, RUST_COMMENT);
      const data = sk.toCbor().toData();
      const decoded = SigningPrivateKey.fromCbor(decodeCbor(data));
      expect(decoded.scheme).toBe(SignatureScheme.SshEd25519);
      expect(decoded.toSshOpenssh()).toBe(sk.toSshOpenssh());
    });

    it("Ed25519: SigningPublicKey CBOR round-trip", () => {
      const base = PrivateKeyBase.from(RUST_SEED);
      const sk = base.sshSigningPrivateKey({ kind: "ed25519" }, RUST_COMMENT);
      const pk = sk.publicKey();
      const data = pk.toCbor().toData();
      const decoded = SigningPublicKey.fromCbor(decodeCbor(data));
      expect(decoded.scheme).toBe(SignatureScheme.SshEd25519);
      expect(decoded.toSshOpenssh()).toBe(pk.toSshOpenssh());
    });
  });
});

describe("ECDSA P-521 — byte-identical keygen, sign/verify, no SignatureScheme", () => {
  const P521 = { kind: "ecdsa", curve: "nistp521" } as const;

  it.each(keygenRecords("p521").map((rec, idx) => ({ idx, rec })))(
    "derives the reference key for seed $idx",
    ({ rec }) => {
      const privateKey = PrivateKeyBase.from(unhex(rec.seed)).sshSigningPrivateKey(
        P521,
        RUST_COMMENT,
      );
      expect(privateKey.toSshOpenssh()).toBe(rec.privatePem);
      expect(privateKey.publicKey().toSshOpenssh()).toBe(rec.publicOpenssh);
      const reloaded = SigningPrivateKey.fromSsh(SSHPrivateKey.fromOpenssh(rec.privatePem));
      expect(reloaded.toSshOpenssh()).toBe(rec.privatePem);
    },
  );

  it("verifies the reference's (randomised-nonce) signatures and signs verifiably itself", () => {
    // `p521` 0.13.3 has no RFC 6979 path for SHA-512 (its output is shorter
    // than the 66-byte field), so the reference draws `k` from `OsRng`; the
    // vectors can be verified but not reproduced. TS signs with RFC 6979
    // (SHA-512), which the reference verifies like any other valid signature.
    const privateKey = PrivateKeyBase.from(RUST_SEED).sshSigningPrivateKey(P521, RUST_COMMENT);
    const publicKey = privateKey.publicKey();
    expect(SIGN_VECTORS.p521Vectors).toHaveLength(2);
    for (const v of SIGN_VECTORS.p521Vectors) {
      const reference = SSHSignature.fromPem(v.sshsigPem);
      expect(reference.toPem()).toBe(v.sshsigPem);
      expect(reference.signatureAlgorithm).toBe("ecdsa-sha2-nistp521");
      expect(reference.signatureBytes).toHaveLength(132);
      expect(publicKey.verify(Signature.fromSsh(reference), VECTOR_MESSAGE)).toBe(v.verified);
      expect(
        publicKey.verify(Signature.fromSsh(reference), new TextEncoder().encode("hellp")),
      ).toBe(false);

      const sig = privateKey.signWithOptions(VECTOR_MESSAGE, {
        type: "Ssh",
        namespace: VECTOR_NAMESPACE,
        hashAlg: v.hashAlgorithm,
      });
      expect(sshOf(sig).signatureBytes).toHaveLength(132);
      expect(publicKey.verify(sig, VECTOR_MESSAGE)).toBe(true);
      expect(publicKey.verify(sig, new TextEncoder().encode("hellp"))).toBe(false);
      const reparsed = Signature.fromSsh(SSHSignature.fromPem(sshOf(sig).toPem()));
      expect(publicKey.verify(reparsed, VECTOR_MESSAGE)).toBe(true);
      expect(reparsed.equals(sig)).toBe(true);
    }
  });

  it("has no SignatureScheme: `scheme` fails as the reference's Signature::scheme()", () => {
    const privateKey = PrivateKeyBase.from(RUST_SEED).sshSigningPrivateKey(P521, RUST_COMMENT);
    const publicKey = privateKey.publicKey();
    const sig = privateKey.signWithOptions(VECTOR_MESSAGE, {
      type: "Ssh",
      namespace: VECTOR_NAMESPACE,
      hashAlg: "sha256",
    });
    for (const subject of [() => privateKey.scheme, () => publicKey.scheme, () => sig.scheme]) {
      let caught: unknown;
      try {
        subject();
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ComponentsError);
      expect((caught as ComponentsError).code).toBe("Ssh");
      expect((caught as ComponentsError).message).toBe(
        "SSH operation failed: Unsupported SSH ECDSA curve",
      );
    }
    expect(privateKey.keyType).toBe("SSH-ECDSA-P521");
    expect(publicKey.keyType).toBe("SSH-ECDSA-P521");
    expect(sig.signatureType).toBe("SshEcdsaP521");
    expect(privateKey.isSsh()).toBe(true);
    expect(privateKey.isMldsa()).toBe(false);
  });

  it("round-trips through CBOR and compares equal", () => {
    const sk = PrivateKeyBase.from(RUST_SEED).sshSigningPrivateKey(P521, RUST_COMMENT);
    const decoded = SigningPrivateKey.fromCbor(decodeCbor(sk.toCbor().toData()));
    expect(decoded.toSshOpenssh()).toBe(sk.toSshOpenssh());
    expect(decoded.equals(sk)).toBe(true);
    const pk = sk.publicKey();
    const decodedPk = SigningPublicKey.fromCbor(decodeCbor(pk.toCbor().toData()));
    expect(decodedPk.equals(pk)).toBe(true);
    expect(decodedPk.toSshOpenssh()).toBe(pk.toSshOpenssh());
    expect(sk.toString()).toMatch(
      /^SigningPrivateKey\([0-9a-f]{8}, SSHPrivateKey\([0-9a-f]{8}\)\)$/,
    );
  });
});

describe("RSA — byte-identical keygen, reference sign failure, verification", () => {
  const RSA = { kind: "rsa" } as const;

  it.each(keygenRecords("rsa").map((rec, idx) => ({ idx, rec })))(
    "derives the reference key for seed $idx",
    ({ rec }) => {
      const privateKey = PrivateKeyBase.from(unhex(rec.seed)).sshSigningPrivateKey(
        RSA,
        RUST_COMMENT,
      );
      expect(privateKey.toSshOpenssh()).toBe(rec.privatePem);
      expect(privateKey.publicKey().toSshOpenssh()).toBe(rec.publicOpenssh);
      const reloaded = SigningPrivateKey.fromSsh(SSHPrivateKey.fromOpenssh(rec.privatePem));
      expect(reloaded.toSshOpenssh()).toBe(rec.privatePem);
    },
    60_000,
  );

  it("cannot sign: the reference fails with `cryptographic error`", () => {
    expect(SIGN_VECTORS.rsaSign.bcComponentsDisplay).toBe(
      "SSH operation failed: cryptographic error",
    );
    expect(SIGN_VECTORS.rsaSign.sshKeyDirectDisplay).toBe("cryptographic error");
    const privateKey = PrivateKeyBase.from(RUST_SEED).sshSigningPrivateKey(RSA, RUST_COMMENT);
    let caught: unknown;
    try {
      privateKey.signWithOptions(VECTOR_MESSAGE, {
        type: "Ssh",
        namespace: VECTOR_NAMESPACE,
        hashAlg: "sha256",
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ComponentsError);
    expect((caught as ComponentsError).code).toBe("Ssh");
    expect((caught as ComponentsError).message).toBe(SIGN_VECTORS.rsaSign.bcComponentsDisplay);
    const sshKey = privateKey.asSsh();
    expect(sshKey).toBeDefined();
    expect(() => sshKey?.sign(VECTOR_NAMESPACE, "sha512", VECTOR_MESSAGE)).toThrow(
      "SSH operation failed: cryptographic error",
    );
  });

  it("verifies rsa-sha2-256 / rsa-sha2-512 signatures made with the reference's rsa crate", () => {
    const privateKey = PrivateKeyBase.from(RUST_SEED).sshSigningPrivateKey(RSA, RUST_COMMENT);
    const publicKey = privateKey.publicKey();
    expect(SIGN_VECTORS.rsaVectors).toHaveLength(4);
    for (const v of SIGN_VECTORS.rsaVectors) {
      const sshSig = SSHSignature.fromPem(v.sshsigPem);
      expect(sshSig.signatureAlgorithm).toBe(v.signatureAlgorithm);
      expect(sshSig.hashAlgorithm).toBe(v.hashAlgorithm);
      expect(sshSig.signatureBytes).toHaveLength(256);
      expect(sshSig.toPem()).toBe(v.sshsigPem);
      const sig = Signature.fromSsh(sshSig);
      expect(publicKey.verify(sig, VECTOR_MESSAGE)).toBe(v.bcVerified);
      expect(publicKey.verify(sig, new TextEncoder().encode("hellp"))).toBe(v.wrongMessageVerified);
      expect(sshSig.publicKey.verifySshSignature("tesu", VECTOR_MESSAGE, sshSig)).toBe(
        v.wrongNamespaceVerified,
      );
      // The signature also decodes through the tagged-CBOR form.
      const decoded = Signature.fromCbor(decodeCbor(sig.toCbor().toData()));
      expect(publicKey.verify(decoded, VECTOR_MESSAGE)).toBe(true);
      expect(decoded.equals(sig)).toBe(true);
    }
  });

  it("rejects an sshsig whose signature blob names plain ssh-rsa, as ssh-key does", () => {
    expect(SIGN_VECTORS.rsaPlainSshRsaSig.parseOutcome).toBe("length invalid");
    expect(() => SSHSignature.fromPem(SIGN_VECTORS.rsaPlainSshRsaSig.sshsigPem)).toThrow(
      "SSH operation failed: length invalid",
    );
  });

  it("has no SignatureScheme: `scheme` fails as the reference's Signature::scheme()", () => {
    const privateKey = PrivateKeyBase.from(RUST_SEED).sshSigningPrivateKey(RSA, RUST_COMMENT);
    const publicKey = privateKey.publicKey();
    const sig = Signature.fromSsh(SSHSignature.fromPem(SIGN_VECTORS.rsaVectors[0].sshsigPem));
    expect(SIGN_VECTORS.rsaVectors[0].bcScheme).toBe(
      "Err: SSH operation failed: Unsupported SSH signature algorithm",
    );
    for (const subject of [() => privateKey.scheme, () => publicKey.scheme, () => sig.scheme]) {
      let caught: unknown;
      try {
        subject();
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ComponentsError);
      expect((caught as ComponentsError).code).toBe("Ssh");
      expect((caught as ComponentsError).message).toBe(
        "SSH operation failed: Unsupported SSH signature algorithm",
      );
    }
    expect(privateKey.keyType).toBe("SSH-RSA");
    expect(publicKey.keyType).toBe("SSH-RSA");
    expect(sig.signatureType).toBe("SshRsa");
  });

  it("round-trips through CBOR and compares equal", () => {
    const sk = PrivateKeyBase.from(RUST_SEED).sshSigningPrivateKey(RSA, RUST_COMMENT);
    const decoded = SigningPrivateKey.fromCbor(decodeCbor(sk.toCbor().toData()));
    expect(decoded.equals(sk)).toBe(true);
    const pk = sk.publicKey();
    expect(SigningPublicKey.fromCbor(decodeCbor(pk.toCbor().toData())).equals(pk)).toBe(true);
    expect(pk.withSshComment("other").toSshOpenssh().endsWith(" other")).toBe(true);
  });
});

describe("sshSigningPrivateKey validates the algorithm before drawing", () => {
  const base = PrivateKeyBase.from(RUST_SEED);
  it.each([
    ["a string", "ssh-ed25519"],
    ["null", null],
    ["an unknown kind", { kind: "nope" }],
    ["an unknown curve", { kind: "ecdsa", curve: "nistp999" }],
    ["a missing curve", { kind: "ecdsa" }],
  ])("rejects %s as InvalidData", (_label, algorithm) => {
    let caught: unknown;
    try {
      base.sshSigningPrivateKey(algorithm as never, RUST_COMMENT);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ComponentsError);
    expect((caught as ComponentsError).code).toBe("InvalidData");
    expect((caught as ComponentsError).message).toMatch(/^invalid algorithm: /);
  });
});
