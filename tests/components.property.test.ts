/**
 * Property tests: every codable type round-trips through tagged
 * CBOR and UR; sign/verify per scheme; encrypt/decrypt; compress/decompress;
 * PrivateKeyBase(seed).publicKeys() equals privateKeys().publicKeys().
 */
import type { ComponentCodec } from "../src/codable.js";
import fc from "fast-check";
import { SeededRng } from "@blockchaincommons/rand";
import * as c from "../src";
import * as kdf from "../src/kdf.js";
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
            c.Digest.from(b),
            c.ARID.from(b),
            c.XID.from(b),
            c.Reference.from(b),
            c.SymmetricKey.from(b),
            c.X25519PrivateKey.from(b),
            c.Nonce.from(n),
            c.UUID.from(u),
            c.Salt.from(u),
            c.PrivateKeyBase.from(b),
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
          const seed = c.Seed.from(d, {
            name: name || undefined,
            note: note || undefined,
            creationDate: new Date(secs * 1000),
          });
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
          c.SigningPrivateKey.fromSchnorr(c.ECPrivateKey.from(k)),
          c.SigningPrivateKey.fromEcdsa(c.ECPrivateKey.from(k)),
          c.SigningPrivateKey.fromEd25519(c.Ed25519PrivateKey.from(k)),
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
          const key = c.SymmetricKey.from(k);
          const msg = key.encrypt(pt, { ...(aad.length ? { aad } : {}), nonce: c.Nonce.from(n) });
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
        const x = c.EncapsulationPrivateKey.fromX25519PrivateKey(c.X25519PrivateKey.from(k));
        const kem = c.EncapsulationPrivateKey.randomMlkem(c.MLKEMLevel.MLKEM512, {
          rng: new SeededRng(sd),
        });
        return [x, kem].every((priv) => {
          const sealed = c.SealedMessage.seal(pt, priv.publicKey());
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
        const pkb = c.PrivateKeyBase.from(s);
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

describe("properties", () => {
  it("bytes getters are copies: mutating the view never changes the value (B5)", () => {
    fc.assert(
      fc.property(bytes32, fc.nat({ max: 31 }), fc.integer({ min: 1, max: 255 }), (b, i, m) => {
        const items = [
          c.Digest.from(b),
          c.ARID.from(b),
          c.XID.from(b),
          c.SymmetricKey.from(b),
          c.X25519PrivateKey.from(b),
          c.X25519PublicKey.from(b),
          c.SchnorrPublicKey.from(b),
          c.Ed25519PublicKey.from(b),
          c.Salt.from(b),
        ];
        for (const item of items) {
          const before = hexOf(item.bytes);
          const view = item.bytes;
          view[i] ^= m;
          if (hexOf(item.bytes) !== before) return false;
        }
        return true;
      }),
      { numRuns: 60 },
    );
  });
  it("every non-u32 / non-u8 KDF number is InvalidData at construction (B4)", () => {
    const salt = c.Salt.from(new Uint8Array(16));
    const nonU32 = fc.oneof(
      fc.constantFrom(NaN, Infinity, -Infinity, 4294967296, -1),
      fc.double({ noInteger: true, noNaN: true }),
    );
    const nonU8 = fc.oneof(fc.constantFrom(NaN, 256, -1, 1.5), fc.integer({ min: 256, max: 1e6 }));
    const isInvalid = (f: () => unknown, parameter: string): boolean => {
      try {
        f();
        return false;
      } catch (e) {
        return (
          c.ComponentsError.isComponentsError(e) &&
          e.code === "InvalidData" &&
          "dataType" in e.details &&
          e.details.dataType === parameter
        );
      }
    };
    fc.assert(
      fc.property(
        nonU32,
        nonU8,
        (v, l) =>
          isInvalid(() => kdf.PBKDF2Params.from({ salt, iterations: v }), "iterations") &&
          isInvalid(() => kdf.ScryptParams.from({ salt, logN: l }), "logN") &&
          isInvalid(() => kdf.ScryptParams.from({ salt, r: v }), "r") &&
          isInvalid(() => kdf.ScryptParams.from({ salt, p: v }), "p"),
      ),
    );
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 4294967295 }),
        fc.integer({ min: 0, max: 255 }),
        (v, l) => {
          return (
            kdf.PBKDF2Params.from({ salt, iterations: v }).iterations === v &&
            kdf.ScryptParams.from({ salt, logN: l, r: v, p: v }).logN === l
          );
        },
      ),
    );
  });
  it("Salt.random / Seed.random / HKDFRng reject every non-integer length up front", () => {
    const bad = fc.oneof(
      fc.constantFrom(NaN, Infinity, -Infinity, -1, 1.5),
      fc.double({ noInteger: true, noNaN: true }),
    );
    fc.assert(
      fc.property(bad, (v) => {
        const rng = SeededRng.forTesting();
        const invalid = (f: () => unknown) => {
          try {
            f();
            return false;
          } catch (e) {
            return c.ComponentsError.isComponentsError(e) && e.code === "InvalidData";
          }
        };
        return (
          invalid(() => c.Salt.random({ length: v, rng })) &&
          invalid(() => c.Seed.random({ length: v, rng })) &&
          invalid(() => new kdf.HKDFRng(new Uint8Array(16), "s", { pageLength: v }))
        );
      }),
    );
  });
});
