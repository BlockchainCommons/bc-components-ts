/* eslint-disable @typescript-eslint/no-non-null-assertion -- fixtures are indexed by position; a miss fails the test */
/**
 * The `/tags` subpath: the reference's
 * `tags_registry.rs` summarisers, byte for byte, on a private store and on
 * the global one. The Rust harness compares the same strings through the
 * `summary` recipes.
 */
import { TagsStore, getGlobalTagsStore, asTaggedValue, type Cbor } from "@blockchaincommons/dcbor";
import { TAG_DIGEST, TAG_SEED } from "@blockchaincommons/tags";
import { SeededRng } from "@blockchaincommons/rand";
import * as c from "../src/index.js";
import { EncryptedKey, KeyDerivationMethod } from "../src/kdf.js";
import { SskrShare } from "../src/sskr.js";
import { Spec, GroupSpec, Secret } from "@blockchaincommons/sskr";
import { registerComponentSummarizers, registerTagsIn, registerTags } from "../src/tags.js";

const store = new TagsStore();
registerComponentSummarizers(store);

const summarize = (value: { toCbor(): Cbor }): string => {
  const tv = asTaggedValue(value.toCbor());
  if (tv === undefined) throw new Error("not tagged");
  const s = store.summarizer(tv[0].value);
  if (s === undefined) return "none";
  const out = s(tv[1], false);
  return out.ok ? out.value : `error:${out.error.message}`;
};

describe("component tag summarisers", () => {
  const rng = () => SeededRng.forTesting();
  it("value types", () => {
    const d = c.Digest.fromImage(new Uint8Array([1, 2, 3]));
    expect(summarize(d)).toBe(`Digest(${d.shortDescription()})`);
    const a = c.ARID.from(new Uint8Array(32).fill(7));
    expect(summarize(a)).toBe(`ARID(${a.shortDescription()})`);
    const x = c.XID.from(new Uint8Array(32).fill(9));
    expect(summarize(x)).toBe(`XID(${x.shortDescription()})`);
    expect(summarize(c.URI.from("https://example.com/"))).toBe("URI(https://example.com/)");
    const u = c.UUID.from(new Uint8Array(16));
    expect(summarize(u)).toBe(`UUID(${u.toString()})`);
    expect(summarize(c.Nonce.from(new Uint8Array(12)))).toBe("Nonce");
    expect(summarize(c.Salt.from(new Uint8Array(16)))).toBe("Salt");
    expect(summarize(c.Seed.from(new Uint8Array(16)))).toBe("Seed");
    expect(summarize(c.CborJson.fromString('{"a":1}'))).toBe('JSON({"a":1})');
    const ref = c.Reference.from(new Uint8Array(32).fill(1));
    expect(summarize(ref)).toBe(ref.toString());
  });
  it("keys, signatures and sealed messages", () => {
    const pkb = c.PrivateKeyBase.from(new Uint8Array(32).fill(3));
    expect(summarize(pkb)).toBe(pkb.toString());
    const [priv, pub] = c.generateKeypair({ rng: rng() });
    expect(summarize(priv)).toBe(priv.toString());
    expect(summarize(pub)).toBe(pub.toString());
    expect(summarize(priv.signingPrivateKey)).toBe(priv.signingPrivateKey.toString());
    expect(summarize(pub.signingPublicKey)).toBe(pub.signingPublicKey.toString());
    const msg = new Uint8Array([1]);
    expect(summarize(priv.signingPrivateKey.sign(msg))).toBe("Signature");
    const ed = c.SigningPrivateKey.random({ scheme: c.SignatureScheme.Ed25519, rng: rng() });
    expect(summarize(ed.sign(msg))).toBe("Signature(Ed25519)");
    const ec = c.SigningPrivateKey.random({ scheme: c.SignatureScheme.Ecdsa, rng: rng() });
    expect(summarize(ec.sign(msg))).toBe("Signature(Ecdsa)");
    expect(summarize(c.SealedMessage.seal(msg, pub.encapsulationPublicKey(), { rng: rng() }))).toBe(
      "SealedMessage",
    );
    const [, mlkemPub] = c.EncapsulationPrivateKey.mlkemKeypair(c.MLKEMLevel.MLKEM768, {
      rng: rng(),
    });
    expect(summarize(c.SealedMessage.seal(msg, mlkemPub, { rng: rng() }))).toBe(
      "SealedMessage(MLKEM768)",
    );
  });
  it("kdf, sskr and ssh families", () => {
    const ek = EncryptedKey.lock(
      KeyDerivationMethod.HKDF,
      new Uint8Array([1]),
      c.SymmetricKey.from(new Uint8Array(32).fill(5)),
    );
    expect(summarize(ek)).toBe(ek.toString());
    const share = SskrShare.generate(
      Spec.from({
        groupThreshold: 1,
        groups: [GroupSpec.from({ memberThreshold: 1, memberCount: 1 })],
      }),
      Secret.from(new Uint8Array(16)),
      { rng: rng() },
    )[0]![0]!;
    expect(summarize(share)).toBe("SSKRShare");
    const [sshPriv, sshPub] = c.createKeypair(c.SignatureScheme.SshEd25519, { rng: rng() });
    expect(summarize(sshPriv)).toBe(sshPriv.toString());
    expect(summarize(sshPub)).toBe(sshPub.toString());
  });
  it("reports a malformed content as an error result, never a throw", () => {
    const s = store.summarizer(TAG_DIGEST.value);
    expect(s).toBeDefined();
    const out = s!(c.Nonce.from(new Uint8Array(12)).untaggedCbor(), false);
    expect(out.ok).toBe(false);
  });
  it("registerTagsIn names the tags too; registerTags targets the global store", () => {
    const fresh = new TagsStore();
    registerTagsIn(fresh);
    expect(fresh.nameForTag(TAG_SEED)).toBe("seed");
    expect(fresh.summarizer(TAG_SEED.value)).toBeDefined();
    registerTags();
    expect(getGlobalTagsStore().summarizer(TAG_DIGEST.value)).toBeDefined();
  });
});
