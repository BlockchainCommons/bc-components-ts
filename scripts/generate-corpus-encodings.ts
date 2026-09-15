/**
 * Writes tests/corpus/encodings.json: one valid tagged encoding per decode
 * type (and a few variants), the seeds of the decode corpus's mutations.
 * Every key is derived from a fixed seed, so the file is reproducible; it is
 * regenerated only when a wire format changes, and the change is reviewed.
 *
 *   bun scripts/generate-corpus-encodings.ts
 */
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SeededRng } from "@blockchaincommons/rand";
import { cbor, taggedValue } from "@blockchaincommons/dcbor";
import * as root from "../src/index.ts";
import * as pq from "../src/pq.ts";
import * as kdf from "../src/kdf.ts";
import * as sskrMod from "../src/sskr.ts";
import { registerTags } from "../src/tags.ts";
import { Spec, GroupSpec, Secret } from "@blockchaincommons/sskr";

registerTags();
const out = join(dirname(fileURLToPath(import.meta.url)), "../tests/corpus/encodings.json");
const h = (u: Uint8Array): string => Buffer.from(u).toString("hex");
const tagged = (v: { toCbor(): { toData(): Uint8Array } }): string => h(v.toCbor().toData());
const rng = () => new SeededRng([1n, 2n, 3n, 4n]);
const cyc = (n: number, start = 0): Uint8Array =>
  Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);

const ec = root.ECPrivateKey.from(
  Uint8Array.from(Buffer.from("322b5c1dd5a17c3481c2297990c85c232ed3c17b52ce9905c6ec5193ad132c36", "hex")),
);
const ed = root.Ed25519PrivateKey.from(cyc(32, 1));
const x = root.X25519PrivateKey.from(cyc(32, 1));
const key = root.SymmetricKey.from(cyc(32, 0x10));
const msg = key.encrypt(cyc(20, 5), { aad: cyc(8, 0x30), nonce: root.Nonce.from(cyc(12, 0xa0)) });
const salt16 = root.Salt.from(cyc(16, 0x50));
const [mldsaPriv, mldsaPub] = pq.MLDSAPrivateKey.keypair(pq.MLDSALevel.MLDSA44, { rng: rng() });
const [mlkemPriv, mlkemPub] = pq.MLKEMPrivateKey.keypair(pq.MLKEMLevel.MLKEM512, { rng: rng() });
const mlkemEncap = root.EncapsulationPublicKey.fromMlkem(mlkemPub);
const [, mlkemCt] = mlkemEncap.encapsulateNewSharedSecret({ rng: rng() });
const schnorrPriv = root.SigningPrivateKey.fromSchnorr(ec);
const ecdsaPriv = root.SigningPrivateKey.fromEcdsa(ec);
const edPriv = root.SigningPrivateKey.fromEd25519(ed);
const mldsaSigning = root.SigningPrivateKey.fromMldsa(mldsaPriv);
const sshPriv = root.PrivateKeyBase.from(cyc(32, 1)).sshSigningPrivateKey(
  { kind: "ed25519" },
  "Key comment.",
);
const m = new TextEncoder().encode("Wolf McNally");
const encap = root.EncapsulationPrivateKey.fromX25519PrivateKey(x);
const pkeys = root.PrivateKeys.from({ signing: schnorrPriv, encapsulation: encap });
const shares = sskrMod.SskrShare.generate(
  Spec.from({
    groupThreshold: 1,
    groups: [GroupSpec.from({ memberThreshold: 2, memberCount: 3 })],
  }),
  Secret.from(cyc(16, 7)),
  { rng: rng() },
);
const share = shares[0]?.[0];
if (share === undefined) throw new Error("no share");
// An EncryptedKey's wire form: tag 40027 over the tagged EncryptedMessage
// whose AAD is the parameters' CBOR. The content key is any 32 bytes: a
// decode never derives it.
const encryptedKey = (params: Uint8Array): string =>
  h(
    taggedValue(
      40027,
      key.encrypt(cyc(32, 0x77), { aad: params, nonce: root.Nonce.from(cyc(12, 0xb0)) }).toCbor(),
    ).toData(),
  );

const encodings: Record<string, string> = {
  "digest/img": tagged(root.Digest.fromImage(new TextEncoder().encode("hello world"))),
  "nonce/12": tagged(root.Nonce.from(cyc(12, 0xa0))),
  "salt/16": tagged(salt16),
  "arid/32": tagged(root.ARID.from(cyc(32, 0x20))),
  "uuid/16": tagged(root.UUID.from(cyc(16, 0x60))),
  "xid/32": tagged(root.XID.from(cyc(32, 0x40))),
  "reference/32": tagged(root.Reference.from(cyc(32, 0x70))),
  "symmetricKey/32": tagged(key),
  "json/obj": tagged(root.CborJson.fromString('{"a":1}')),
  "uri/https": tagged(root.URI.from("https://example.com/x")),
  "authTag/16": h(root.AuthenticationTag.from(cyc(16, 0x90)).toCborData()),
  "x25519Priv/k": tagged(x),
  "x25519Pub/k": tagged(x.publicKey()),
  "privateKeyBase/32": tagged(root.PrivateKeyBase.from(cyc(32, 1))),
  "sskrShare/2of3": tagged(share),
  "seed/plain": tagged(root.Seed.from(cyc(16))),
  "seed/meta": tagged(
    root.Seed.from(cyc(16), {
      name: "n",
      note: "t",
      creationDate: new Date(Date.UTC(2023, 5, 15, 10, 30, 0)),
    }),
  ),
  "compressed/d": tagged(
    root.Compressed.fromDecompressedData(
      new TextEncoder().encode("Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(2)),
      root.Digest.fromImage(cyc(3)),
    ),
  ),
  "compressed/nod": tagged(root.Compressed.fromDecompressedData(cyc(300, 7))),
  "encryptedMessage/aad": tagged(msg),
  "encryptedMessage/noaad": tagged(
    key.encrypt(cyc(20, 5), { nonce: root.Nonce.from(cyc(12, 0xa0)) }),
  ),
  "signature/schnorr": tagged(schnorrPriv.signWithOptions(m, { type: "Schnorr", rng: rng() })),
  "signature/ecdsa": tagged(ecdsaPriv.sign(m)),
  "signature/ed25519": tagged(edPriv.sign(m)),
  "signature/mldsa44": tagged(mldsaSigning.sign(m)),
  "signature/ssh-ed25519": tagged(
    sshPriv.signWithOptions(m, { type: "Ssh", namespace: "test", hashAlg: "sha256" }),
  ),
  "signingPriv/schnorr": tagged(schnorrPriv),
  "signingPriv/ecdsa": tagged(ecdsaPriv),
  "signingPriv/ed25519": tagged(edPriv),
  "signingPriv/mldsa44": tagged(mldsaSigning),
  "signingPriv/ssh-ed25519": tagged(sshPriv),
  "signingPub/schnorr": tagged(schnorrPriv.publicKey()),
  "signingPub/ecdsa": tagged(ecdsaPriv.publicKey()),
  "signingPub/ed25519": tagged(edPriv.publicKey()),
  "signingPub/mldsa44": tagged(root.SigningPublicKey.fromMldsa(mldsaPub)),
  "signingPub/ssh-ed25519": tagged(sshPriv.publicKey()),
  "encapPriv/x25519": tagged(encap),
  "encapPriv/mlkem512": tagged(root.EncapsulationPrivateKey.fromMlkem(mlkemPriv)),
  "encapPub/x25519": tagged(encap.publicKey()),
  "encapPub/mlkem512": tagged(mlkemEncap),
  "encapCiphertext/x25519": tagged(root.EncapsulationCiphertext.fromX25519PublicKey(x.publicKey())),
  "encapCiphertext/mlkem512": tagged(mlkemCt),
  "sealedMessage/x25519": tagged(
    root.SealedMessage.seal(cyc(10), encap.publicKey(), {
      nonce: root.Nonce.from(cyc(12, 0x60)),
      rng: rng(),
    }),
  ),
  "privateKeys/default": tagged(pkeys),
  "publicKeys/default": tagged(pkeys.publicKeys()),
  "encryptedKey/hkdf": encryptedKey(kdf.HKDFParams.from({ salt: salt16 }).toCborData()),
  "encryptedKey/pbkdf2": encryptedKey(
    kdf.PBKDF2Params.from({ salt: salt16, iterations: 10 }).toCborData(),
  ),
  "encryptedKey/scrypt": encryptedKey(kdf.ScryptParams.from({ salt: salt16, logN: 4 }).toCborData()),
  "encryptedKey/argon2id": encryptedKey(kdf.Argon2idParams.from({ salt: salt16 }).toCborData()),
  "mldsaPriv/44": tagged(mldsaPriv),
  "mldsaPub/44": tagged(mldsaPub),
  "mldsaSig/44": tagged(mldsaPriv.sign(m)),
  "mlkemPriv/512": tagged(mlkemPriv),
  "mlkemPub/512": tagged(mlkemPub),
  "mlkemCiphertext/512": h(mlkemCt.toCbor().toData()),
  "hkdfParams/hkdf": h(kdf.HKDFParams.from({ salt: salt16 }).toCborData()),
  "pbkdf2Params/pbkdf2": h(kdf.PBKDF2Params.from({ salt: salt16, iterations: 10 }).toCborData()),
  "scryptParams/scrypt": h(kdf.ScryptParams.from({ salt: salt16, logN: 4 }).toCborData()),
  "argon2idParams/argon2id": h(kdf.Argon2idParams.from({ salt: salt16 }).toCborData()),
  "sshAgentParams/sshAgent": h(kdf.SSHAgentParams.from({ salt: salt16, id: "my-key" }).toCborData()),
  "kdp/hkdf": h(kdf.HKDFParams.from({ salt: salt16 }).toCborData()),
  "kdp/pbkdf2": h(kdf.PBKDF2Params.from({ salt: salt16, iterations: 10 }).toCborData()),
  "kdp/scrypt": h(kdf.ScryptParams.from({ salt: salt16, logN: 4 }).toCborData()),
  "kdp/argon2id": h(kdf.Argon2idParams.from({ salt: salt16 }).toCborData()),
  "kdp/sshAgent": h(kdf.SSHAgentParams.from({ salt: salt16, id: "my-key" }).toCborData()),
  "hashType/sha256": h(cbor(0).toData()),
  "hashType/sha512": h(cbor(1).toData()),
  "kdMethod/hkdf": h(cbor(0).toData()),
  "kdMethod/sshAgent": h(cbor(4).toData()),
  "mlkemLevel/512": h(cbor(512).toData()),
  "mldsaLevel/44": h(cbor(2).toData()),
};
// One deliberately legacy-tagged encoding each for the two-tag types.
encodings["seed/legacy"] = h(
  taggedValue(300, root.Seed.codec.encodeUntagged(root.Seed.from(cyc(16)))).toData(),
);
encodings["sskrShare/legacy"] = h(
  taggedValue(309, sskrMod.SskrShare.codec.encodeUntagged(share)).toData(),
);

writeFileSync(out, JSON.stringify(encodings, null, 1) + "\n");
console.log(`wrote ${Object.keys(encodings).length} encodings to ${out}`);
