/**
 * Differential harness: every corpus recipe is materialised with the frozen
 * baseline bundle (every pre-redesign sibling and dcbor-compat inlined) AND
 * the working tree; outcomes, including error codes, must be identical
 * except for the enumerated tombstones and the structural outcomes that
 * involve the secure generator.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
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
import * as rand from "@blockchaincommons/rand";
import {
  materialize,
  baselineAdapterFor,
  redesignedAdapterFor,
  recipeName,
  BASELINE_UNSUPPORTED,
  type Recipe,
} from "./vectors/recipes";
import { categories } from "./corpus/corpus";

const here = dirname(fileURLToPath(import.meta.url));
const BASELINE_SHA256 = "e60c13533397a3caaecfad9e632008de6920b86b88391311eec86983d16cab66";

/**
 * Tombstones: the only allowed differences.
 * T1: a map value of the wrong CBOR type is rejected by typed extraction
 *    (`InvalidData`) where the compat bundle's untyped `extract` produced
 *    an incidental `DataTooShort`.
 * T2: every bare `Error` throw became a `ComponentsError` with a code; the
 *    baseline's `throw:Error` is any `throw:<code>` now.
 * T3: every codable type has `toUR()`; the adapter's `-` placeholder for
 *    "no UR" became a UR string for CborJson and SSKR shares, and
 *    `AuthenticationTag` reports through `toCbor()` now.
 * T4: `sshFromSeed`/`sshFromPem` recipes are exempt from comparison
 *    outright, whatever the outcomes are.
 * T5: `decodeUntagged` — the tree's `fromCbor` used to accept the untagged
 *    form (or report a size error from inside it) where the baseline's
 *    tagged door rejected the missing tag; both reject now, the tree with
 *    `Cbor` where the baseline's raw `CborError` is reported by class (16
 *    rows, also covered by T7).
 * T6: the baseline's inlined Ed25519 accepts the identity key with the
 *    `(identity, 0)` signature (one strictness row) that the tree's strict
 *    verifier rejects (B1).
 * T7: a dcbor `CborError` that used to escape `fromCbor` is a
 *    `ComponentsError` with code `Cbor` now (the boundary rule).
 * T8: a zero secp256k1 scalar or an off-curve point is rejected when the
 *    key is constructed (`InvalidData`), where the baseline copied the
 *    bytes and failed at first use.
 * T9: `generateKeypair` / `createEncapsulationKeypair` with an `rng` and an
 *    ML-KEM scheme produce keys (the baseline threw a bare `Error`: "omit
 *    rng").
 * Recipe kinds in `BASELINE_UNSUPPORTED` (`signingDefault`, `kdfDomain`,
 * `domain`) have no baseline twin and are skipped here; the golden
 * snapshots and the Rust harness cover them.
 */
const TOMBSTONES: {
  id: string;
  landed: boolean;
  /** For a pending tombstone: the exact number of rows it must cover today. */
  rowsBeforeLanding?: number;
  category?: string;
  matches: (r: Recipe, baselineOutcome: string, currentOutcome: string) => boolean;
}[] = [
  {
    id: "T5",
    landed: true,
    matches: (r, a, b) => r.k === "decodeUntagged" && a.startsWith("throw:") && b === "throw:Cbor",
  },
  {
    id: "T6",
    landed: true,
    matches: (r, a, b) => r.k === "verifyStrict" && a === "valid" && b === "invalid",
  },
  {
    id: "T9",
    landed: true,
    matches: (r, a, b) =>
      r.k === "keypair" &&
      r.encScheme.startsWith("mlkem") &&
      a.startsWith("throw:") &&
      !b.startsWith("throw:"),
  },
  {
    id: "T7",
    landed: true,
    matches: (_r, a, b) => a === "throw:CborError" && b === "throw:Cbor",
  },
  {
    id: "T8",
    landed: true,
    matches: (r, a, b) =>
      (r.k === "decode" || r.k === "decodeUntagged") &&
      ["signingPriv", "signingPub", "privateKeys", "publicKeys", "ecPriv", "ecPub"].includes(
        r.type,
      ) &&
      !a.startsWith("throw:") &&
      b === "throw:InvalidData",
  },
  {
    id: "T1",
    landed: true,
    matches: (r) => r.k === "decode" && r.type === "seed" && r.hex.includes("a10161"),
  },
  {
    id: "T4",
    landed: true,
    matches: (r) => r.k === "sshFromSeed" || r.k === "sshFromPem",
  },
  {
    id: "T3",
    landed: true,
    matches: (_r, a, b) => {
      const strip = (o: string): string => o.replace(/\|ur:[^|]*/g, "").replace(/\|-/g, "");
      return strip(a) === strip(b);
    },
  },
  {
    id: "T2",
    landed: true,
    matches: (_r, a, b) => a === "throw:Error" && b.startsWith("throw:") && b !== "throw:Error",
  },
];

const stable = (r: Recipe, o: string): string => {
  if (r.k === "seal" || r.k === "encryptedKey" || r.k === "mlkem")
    return o.replace(/\|aad=.*$/, "");
  if (r.k === "mldsa") return o.split("|").slice(-2).join("|");
  return o;
};
const baseline = baselineAdapterFor(baselineMod, randBaseline);
const current = redesignedAdapterFor(src, rand);

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
      const pendingHits: Record<string, number> = {};
      for (const recipe of gen()) {
        if (BASELINE_UNSUPPORTED.has(recipe.k)) {
          skipped++;
          continue;
        }
        n++;
        const a = stable(recipe, materialize(baseline, recipe));
        const b = stable(recipe, materialize(current, recipe));
        if (a === b) continue;
        const tomb = TOMBSTONES.find((t) => t.matches(recipe, a, b));
        if (tomb === undefined)
          diffs.push(`${recipeName(recipe)}: ${a.slice(0, 90)} !== ${b.slice(0, 90)}`);
        else if (!tomb.landed) pendingHits[tomb.id] = (pendingHits[tomb.id] ?? 0) + 1;
      }
      expect(n + skipped).toBeGreaterThan(0);
      expect(diffs).toEqual([]);
      for (const t of TOMBSTONES)
        if (!t.landed && t.category === name)
          expect(pendingHits[t.id] ?? 0).toBe(t.rowsBeforeLanding);
    });
  }
});
