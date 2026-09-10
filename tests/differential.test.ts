/**
 * Differential harness (Phase 1.3): every corpus recipe is materialised with
 * the frozen baseline bundle (every pre-redesign sibling and dcbor-compat
 * inlined) AND the working tree; outcomes, including error codes, must be
 * identical except for the enumerated tombstones and the structural
 * outcomes that involve the secure generator.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as baselineMod from "./baseline/components-baseline.mjs";
import * as randBaseline from "../../bc-rand-ts/tests/baseline/rand-baseline.mjs";
import * as src from "../src";
import * as rand from "@blockchaincommons/rand";
import {
  materialize,
  baselineAdapterFor,
  redesignedAdapterFor,
  recipeName,
  type Recipe,
} from "./vectors/recipes";
import { categories } from "./corpus/corpus";

const here = dirname(fileURLToPath(import.meta.url));
const BASELINE_SHA256 = "e586b600317b4e2acdd9853bea449e641fefabe6f6049e90cc0b1087af9946b9";

/**
 * Tombstones: the only allowed differences.
 * T1 (landed with the dcbor port): a map value of the wrong CBOR type is
 *    rejected by typed extraction (`InvalidData`) where the compat bundle's
 *    untyped `extract` produced an incidental `DataTooShort`.
 * T2 (landed with W1): every bare `Error` throw became a `ComponentsError`
 *    with a code; the baseline's `throw:Error` is any `throw:<code>` now.
 * T3 (landed with W2): every codable type has `toUR()`; the adapter's `-`
 *    placeholder for "no UR" became a UR string for JSON and SSKR shares,
 *    and `AuthenticationTag` reports through `toCbor()` now.
 */
const TOMBSTONES: {
  id: string;
  landed: boolean;
  matches: (r: Recipe, baselineOutcome: string, currentOutcome: string) => boolean;
}[] = [
  {
    id: "T1",
    landed: true,
    matches: (r) => r.k === "decode" && r.type === "seed" && r.hex.includes("a10161"),
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
  if (r.k === "sign" && r.scheme === "sr25519") return o.split("|").at(-1) ?? o;
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
      const diffs: string[] = [];
      for (const recipe of gen()) {
        n++;
        const a = stable(recipe, materialize(baseline, recipe));
        const b = stable(recipe, materialize(current, recipe));
        const tomb = TOMBSTONES.find((t) => t.matches(recipe, a, b));
        if (a !== b && tomb?.landed !== true)
          diffs.push(`${recipeName(recipe)}: ${a.slice(0, 90)} !== ${b.slice(0, 90)}`);
      }
      expect(n).toBeGreaterThan(0);
      expect(diffs).toEqual([]);
    });
  }
});
