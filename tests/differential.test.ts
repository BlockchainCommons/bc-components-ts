/**
 * Differential harness: every corpus recipe the frozen baseline bundle can
 * run (the `@bcts/components` wire-format reference with its siblings
 * inlined) is materialised with it AND with the working tree; outcomes,
 * error codes included, must be identical except for the allowed
 * differences listed below, each of which must be hit exactly as many times
 * per category as it says. `stable()` drops the fields drawn from the
 * secure generator; `baselineSupports()` (recipes.ts) names what the bundle
 * never had.
 */
import { createHash } from "node:crypto";
import process from "node:process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as baselineMod from "./baseline/components-baseline.mjs";
import * as randBaseline from "./baseline/rand-baseline.mjs";
import * as root from "../src/index.js";
import * as ssh from "../src/ssh/index.js";
import * as pq from "../src/pq.js";
import * as kdf from "../src/kdf.js";
import * as sskr from "../src/sskr.js";
import * as tagsMod from "../src/tags.js";

const src = { ...root, ...ssh, ...pq, ...kdf, ...sskr, ...tagsMod };
// The working tree names its tags through the process-wide store, as the
// reference does through `register_tags()`; the frozen bundle carries its own.
tagsMod.registerTags();
import * as rand from "@blockchaincommons/rand";
import {
  materialize,
  baselineAdapterFor,
  workingTreeAdapterFor,
  recipeName,
  baselineSupports,
  type Recipe,
} from "./vectors/recipes";
import { categories } from "./corpus/corpus";

const here = dirname(fileURLToPath(import.meta.url));
const BASELINE_SHA256 = "e60c13533397a3caaecfad9e632008de6920b86b88391311eec86983d16cab66";

const DECODE_KINDS: ReadonlySet<Recipe["k"]> = new Set<Recipe["k"]>([
  "decode",
  "decodeUntagged",
  "urParse",
]);
const throws = (o: string): boolean => o.startsWith("throw:");
/** The decode type of a decode-kind recipe, `undefined` for any other kind. */
const decodeType = (r: Recipe): string | undefined =>
  r.k === "decode" || r.k === "decodeUntagged" || r.k === "urParse" ? r.type : undefined;

/**
 * The allowed differences between the baseline and the working tree. Each
 * names the recipes it covers and, per category, the number of rows it must
 * cover; a difference no entry covers, or a count that moves, fails.
 */
interface AllowedDifference {
  readonly id: string;
  readonly hits: Readonly<Record<string, number>>;
  readonly matches: (r: Recipe, baselineOutcome: string, currentOutcome: string) => boolean;
}
const ALLOWED_DIFFERENCES: readonly AllowedDifference[] = [
  {
    // Every decode failure is `Cbor` with the reference's message, where the
    // baseline reported a leaf code, a dcbor class, or crashed on the input.
    id: "decode-errors-are-Cbor",
    hits: { decodes: 42, untagged: 16, decodeCorpus: 4185 },
    matches: (r, a, b) =>
      DECODE_KINDS.has(r.k) && throws(a) && a !== "throw:Cbor" && b === "throw:Cbor",
  },
  {
    // The decoders accept what the reference accepts: the `[bytes, _]`
    // Schnorr signature form, a negative discriminator wrapped as `usize`,
    // extra array elements, a Seed whose date or metadata is dropped, a raw
    // SSKR share of any length, an ML-DSA signature up to its size, an empty
    // PrivateKeyBase, and a 64-bit Compressed size.
    id: "decoder-accepts",
    hits: { decodes: 12, decodeCorpus: 42 },
    matches: (r, a, b) => DECODE_KINDS.has(r.k) && throws(a) && !throws(b),
  },
  {
    // The decoders reject what the reference rejects: a checksum outside
    // `u32` after dcbor's negative wrap, a float where an integer goes.
    id: "decoder-rejects",
    hits: { decodes: 2, decodeCorpus: 8 },
    matches: (r, a, b) => DECODE_KINDS.has(r.k) && !throws(a) && b === "throw:Cbor",
  },
  {
    // Compressed integers are exact (`u32` checksum, `usize` size as a
    // bigint) and the type has a UR; the baseline went through `number`.
    id: "compressed-integers",
    hits: { decodes: 4, decodeCorpus: 53 },
    matches: (r, a, b) => decodeType(r) === "compressed" && !throws(a) && !throws(b) && a !== b,
  },
  {
    // An SSH signature re-encodes through the reference's PEM grammar.
    id: "ssh-signature-text",
    hits: { decodeCorpus: 1 },
    matches: (r, a, b) => decodeType(r) === "signature" && !throws(a) && !throws(b) && a !== b,
  },
  {
    // DEFLATE bytes come from the miniz_oxide level-6 port, not pako; both
    // sides decompress each other's output (the miniz suite checks it).
    id: "miniz-oxide-level-6",
    hits: { compresseds: 25 },
    matches: (r, a, b) => r.k === "compressed" && !throws(a) && !throws(b) && a !== b,
  },
  {
    // An empty PrivateKeyBase is accepted, as `PrivateKeyBase::from_data`.
    id: "empty-private-key-base",
    hits: { values: 2, pkbs: 1 },
    matches: (r, a, b) =>
      ((r.k === "value" && r.type === "privateKeyBase") || r.k === "pkb") &&
      a === "throw:Error" &&
      !throws(b),
  },
  {
    // EC keys are constructed by size only; the curve check happens at first
    // use, where the reference's does.
    id: "ec-key-size-only",
    hits: { values: 1 },
    matches: (r, a, b) =>
      r.k === "value" &&
      ["ecPriv", "ecPub", "ecUncompressed", "schnorrPub"].includes(r.type) &&
      a === "throw:Error" &&
      !throws(b),
  },
  {
    // A low-order X25519 peer derives the reference's fixed shared key.
    id: "x25519-low-order-derives",
    hits: { encrypts: 3 },
    matches: (r, a, b) => r.k === "x25519Shared" && a === "throw:Error" && !throws(b),
  },
  {
    // PBKDF2 with 0 iterations and scrypt with log N 0 derive, as the reference's do.
    id: "zero-cost-kdf-derives",
    hits: { kdfs: 2 },
    matches: (r, a, b) => r.k === "encryptedKey" && a === "throw:Error" && !throws(b),
  },
  {
    // The sskr package names its Shamir wrapper `Shamir`.
    id: "sskr-shamir-code",
    hits: { sskrs: 1 },
    matches: (r, a, b) =>
      r.k === "sskr" && a === "throw:SskrError:ShamirError" && b === "throw:SskrError:Shamir",
  },
  {
    // The `mldsa` recipe runs on the working tree (`MLDSAPrivateKey.keypair`
    // hands out both keys) where the baseline's private key could not
    // derive its public key.
    id: "mldsa-keypair",
    hits: { pqs: 4 },
    matches: (r, a, b) => r.k === "mldsa" && a === "throw:Error" && !throws(b),
  },
  {
    // `sshFromSeed`/`sshFromPem` recipes are exempt from comparison
    // outright: the baseline's SSH module predates the reference's formats.
    id: "ssh-recipes",
    hits: { sshes: 8 },
    matches: (r) => r.k === "sshFromSeed" || r.k === "sshFromPem",
  },
  {
    // Every bare `Error` throw became a `ComponentsError` with a code: the
    // secp256k1 checks at first use, the seeded post-quantum keypair refusal.
    id: "typed-errors",
    hits: { values: 10, pkbs: 5 },
    matches: (_r, a, b) => a === "throw:Error" && throws(b) && b !== a,
  },
  {
    // The UR surface follows the reference: CborJson, SskrShare and
    // AuthenticationTag print through `toCbor()`/`toUR()` where the baseline
    // printed a placeholder, and the three encapsulation enums no longer
    // have `toUR()`.
    id: "ur-surface",
    hits: { values: 9, decodes: 5, decodeCorpus: 39 },
    matches: (_r, a, b) => {
      const strip = (o: string): string => o.replace(/\|ur:[^|]*/g, "").replace(/\|-/g, "");
      return !throws(a) && !throws(b) && strip(a) === strip(b);
    },
  },
  {
    // `SSHAgentParams` prints the reference's `SSHAgent("<id>")`.
    id: "ssh-agent-display",
    hits: { kdfs: 2 },
    matches: (r, a, b) =>
      r.k === "params" && r.method === "sshAgent" && a.includes("(id: ") && !b.includes("(id: "),
  },
  {
    // `UR.parse` reports a bad checksum under its own `Decoder` code where
    // the baseline's uniform-resources reported `Bytewords`.
    id: "ur-parse-codes",
    hits: { decodes: 1 },
    matches: (r, a, b) => r.k === "urParse" && a === "throw:Bytewords" && b === "throw:Decoder",
  },
  {
    // The baseline's inlined Ed25519 accepts the identity key with the
    // `(identity, 0)` signature; the strict verifier rejects it.
    id: "ed25519-strict",
    hits: { strictness: 1 },
    matches: (r, a, b) => r.k === "verifyStrict" && a === "valid" && b === "invalid",
  },
];

/**
 * The artefacts drawn from the secure generator (a sealed message, a locked
 * key, an encapsulation, an ML-DSA signature) differ per run on both sides;
 * the Rust harness verifies them, this suite compares the rest of the row.
 */
const stable = (r: Recipe, o: string): string => {
  const drop = (names: string[]): string =>
    o
      .split("|")
      .filter((f) => !names.some((n) => f.startsWith(`${n}=`)))
      .join("|");
  switch (r.k) {
    case "seal":
      return drop(["sealed"]);
    case "encryptedKey":
      return drop(["ek"]);
    case "mlkem":
      return drop(["ct", "ss"]);
    case "mldsa":
      return drop(["sig"]);
    default:
      return o;
  }
};
const baseline = baselineAdapterFor(baselineMod, randBaseline);
const current = workingTreeAdapterFor(src, rand);
/**
 * `DIFFERENTIAL_MEASURE=<path>` writes the observed hits per difference and
 * category, and the unallowed rows, to that file instead of asserting them.
 */
const measure = process.env["DIFFERENTIAL_MEASURE"];
const observed: Record<string, Record<string, number>> = {};
const unallowed: Record<string, string[]> = {};

describe("differential: baseline vs working tree", () => {
  it("baseline bundle integrity", () => {
    const sha = createHash("sha256")
      .update(readFileSync(join(here, "baseline/components-baseline.mjs")))
      .digest("hex");
    expect(sha).toBe(BASELINE_SHA256);
  });
  for (const [name, gen] of Object.entries(categories)) {
    it(`category ${name}`, { timeout: 600_000 }, () => {
      let n = 0;
      let skipped = 0;
      const diffs: string[] = [];
      const hits: Record<string, number> = {};
      for (const recipe of gen()) {
        if (!baselineSupports(recipe)) {
          skipped++;
          continue;
        }
        n++;
        const a = stable(recipe, materialize(baseline, recipe));
        const b = stable(recipe, materialize(current, recipe));
        if (a === b) continue;
        const allowed = ALLOWED_DIFFERENCES.find((d) => d.matches(recipe, a, b));
        if (allowed === undefined)
          diffs.push(`${recipeName(recipe)}: ${a.slice(0, 90)} !== ${b.slice(0, 90)}`);
        else hits[allowed.id] = (hits[allowed.id] ?? 0) + 1;
      }
      expect(n + skipped).toBeGreaterThan(0);
      if (measure !== undefined) {
        for (const [id, count] of Object.entries(hits)) (observed[id] ??= {})[name] = count;
        if (diffs.length > 0) unallowed[name] = diffs;
        return;
      }
      expect(diffs).toEqual([]);
      for (const d of ALLOWED_DIFFERENCES)
        expect(hits[d.id] ?? 0, `${d.id} in ${name}`).toBe(d.hits[name] ?? 0);
    });
  }
  it("every allowed difference is hit", () => {
    if (measure !== undefined) {
      writeFileSync(measure, JSON.stringify({ observed, unallowed }, null, 1));
      return;
    }
    for (const d of ALLOWED_DIFFERENCES)
      expect(
        Object.values(d.hits).reduce((s, x) => s + x, 0),
        d.id,
      ).toBeGreaterThan(0);
  });
});
