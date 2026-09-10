/**
 * Property tests (Phase 0.3): every codable type round-trips through tagged
 * CBOR and UR; sign/verify per scheme; encrypt/decrypt; compress/decompress;
 * PrivateKeyBase(seed).publicKeys() equals privateKeys().publicKeys().
 */
import type { ComponentCodec } from "../src/codable.js";
import fc from "fast-check";
import { SeededRng } from "@blockchaincommons/rand";
import * as c from "../src";
import { decodeCbor, type Cbor } from "@blockchaincommons/dcbor";
import { UR, decodeURWith } from "@blockchaincommons/uniform-resources";

const bytes32 = fc.uint8Array({ minLength: 32, maxLength: 32 });
const hexOf = (b: Uint8Array): string => Buffer.from(b).toString("hex");

describe("codable round-trips", () => {
  it("byte-value types survive tagged CBOR and UR", () => {
    fc.assert(
      fc.property(
        bytes32,
        fc.uint8Array({ minLength: 12, maxLength: 12 }),
        fc.uint8Array({ minLength: 16, maxLength: 16 }),
        (b, n, u) => {
          const items: { toCbor(): Cbor; toUR(): UR }[] = [
            c.Digest.fromData(b),
            c.ARID.fromData(b),
            c.XID.fromData(b),
            c.Reference.fromData(b),
            c.SymmetricKey.fromData(b),
            c.X25519PrivateKey.fromData(b),
            c.Nonce.fromData(n),
            c.UUID.fromData(u),
            c.Salt.fromData(u),
            c.PrivateKeyBase.fromData(b),
          ];
          const ctors = [
            c.Digest,
            c.ARID,
            c.XID,
            c.Reference,
            c.SymmetricKey,
            c.X25519PrivateKey,
            c.Nonce,
            c.UUID,
            c.Salt,
            c.PrivateKeyBase,
          ];
          return items.every((v, i) => {
            const ctor = ctors[i] as unknown as {
              codec: ComponentCodec<{ toCbor(): Cbor }>;
              fromCbor(c: Cbor): { toCbor(): Cbor };
            };
            const t = v.toCbor().toData();
            return (
              hexOf(ctor.fromCbor(decodeCbor(t)).toCbor().toData()) === hexOf(t) &&
              hexOf(decodeURWith(UR.parse(v.toUR().toString()), ctor.codec).toCbor().toData()) ===
                hexOf(t)
            );
          });
        },
      ),
      { numRuns: 60 },
    );
  });
  it("seed with metadata round-trips", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 16, maxLength: 32 }),
        fc.string({ maxLength: 20 }),
        fc.string({ maxLength: 40 }),
        fc.integer({ min: 0, max: 4102444800 }),
        (d, name, note, secs) => {
          const seed = c.Seed.newOpt(
            d,
            name || undefined,
            note || undefined,
            new Date(secs * 1000),
          );
          const back = c.Seed.fromCbor(decodeCbor(seed.toCbor().toData()));
          return (
            back.equals(seed) && hexOf(back.toCbor().toData()) === hexOf(seed.toCbor().toData())
          );
        },
      ),
      { numRuns: 60 },
    );
  });
});

describe("crypto round-trips", () => {
  const seed = fc.tuple(
    fc.bigInt({ min: 1n, max: (1n << 64n) - 1n }),
    fc.bigInt({ min: 0n, max: (1n << 64n) - 1n }),
    fc.bigInt({ min: 0n, max: (1n << 64n) - 1n }),
    fc.bigInt({ min: 0n, max: (1n << 64n) - 1n }),
  );
  it("every signature scheme signs and verifies; CBOR round-trips", () => {
    fc.assert(
      fc.property(bytes32, fc.uint8Array({ maxLength: 200 }), seed, (k, msg, sd) => {
        const rng = new SeededRng(sd);
        const keys = [
          c.SigningPrivateKey.newSchnorr(c.ECPrivateKey.fromData(k)),
          c.SigningPrivateKey.newEcdsa(c.ECPrivateKey.fromData(k)),
          c.SigningPrivateKey.newEd25519(c.Ed25519PrivateKey.from(k)),
          c.SigningPrivateKey.newSr25519(c.Sr25519PrivateKey.fromSeed(k)),
        ];
        return keys.every((priv, i) => {
          const sig =
            i === 0 ? priv.signWithOptions(msg, { type: "Schnorr", rng }) : priv.sign(msg);
          const pub = priv.publicKey();
          const sig2 = c.Signature.fromCbor(decodeCbor(sig.toCbor().toData()));
          const pub2 = c.SigningPublicKey.fromCbor(decodeCbor(pub.toCbor().toData()));
          return (
            pub.verify(sig, msg) &&
            pub2.verify(sig2, msg) &&
            !pub.verify(sig, new Uint8Array([...msg, 1]))
          );
        });
      }),
      { numRuns: 30 },
    );
  });
  it("symmetric encrypt/decrypt with and without aad", () => {
    fc.assert(
      fc.property(
        bytes32,
        fc.uint8Array({ minLength: 12, maxLength: 12 }),
        fc.uint8Array({ maxLength: 300 }),
        fc.uint8Array({ maxLength: 40 }),
        (k, n, pt, aad) => {
          const key = c.SymmetricKey.fromData(k);
          const msg = key.encrypt(pt, aad.length ? aad : undefined, c.Nonce.fromData(n));
          const back = c.EncryptedMessage.fromCbor(decodeCbor(msg.toCbor().toData()));
          return hexOf(key.decrypt(msg)) === hexOf(pt) && hexOf(key.decrypt(back)) === hexOf(pt);
        },
      ),
      { numRuns: 60 },
    );
  });
  it("seal/open with x25519 and ML-KEM", () => {
    fc.assert(
      fc.property(bytes32, fc.uint8Array({ maxLength: 200 }), seed, (k, pt, sd) => {
        const x = c.EncapsulationPrivateKey.fromX25519PrivateKey(c.X25519PrivateKey.fromData(k));
        const kem = c.EncapsulationPrivateKey.newMlkemUsing(
          c.MLKEMLevel.MLKEM512,
          new SeededRng(sd),
        );
        return [x, kem].every((priv) => {
          const sealed = c.SealedMessage.new(pt, priv.publicKey());
          const back = c.SealedMessage.fromCbor(decodeCbor(sealed.toCbor().toData()));
          return (
            hexOf(sealed.decrypt(priv)) === hexOf(pt) && hexOf(back.decrypt(priv)) === hexOf(pt)
          );
        });
      }),
      { numRuns: 15 },
    );
  });
  it("compress/decompress", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 2048 }), (d) => {
        const cmp = c.Compressed.fromDecompressedData(d, c.Digest.fromImage(d));
        const back = c.Compressed.fromCbor(decodeCbor(cmp.toCbor().toData()));
        return (
          hexOf(cmp.decompress()) === hexOf(d) &&
          hexOf(back.decompress()) === hexOf(d) &&
          back.digest().equals(c.Digest.fromImage(d))
        );
      }),
      { numRuns: 60 },
    );
  });
  it("PrivateKeyBase(seed): publicKeys equals privateKeys().publicKeys()", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 16, maxLength: 64 }), (s) => {
        const pkb = c.PrivateKeyBase.fromData(s);
        return (
          pkb.ed25519PublicKeys().equals(pkb.ed25519PrivateKeys().publicKeys()) &&
          pkb.schnorrPublicKeys().equals(pkb.schnorrPrivateKeys().publicKeys()) &&
          pkb.ecdsaPublicKeys().equals(pkb.ecdsaPrivateKeys().publicKeys())
        );
      }),
      { numRuns: 30 },
    );
  });
});
