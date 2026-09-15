/**
 * Golden vector suite: the committed freeze of every outcome the working
 * tree produces for the golden recipe subset, error messages included.
 * Changes only through `bun run vectors:generate`. The rows under `noreg`
 * run in `golden-vectors-noreg.test.ts`, before any tag is registered.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
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
  materializeAsync,
  workingTreeAdapterFor,
  type Recipe,
  type Outcome,
} from "./vectors/recipes";

tagsMod.registerTags();
const here = dirname(fileURLToPath(import.meta.url));
const { count, vectors } = JSON.parse(readFileSync(join(here, "vectors/vectors.json"), "utf8")) as {
  count: number;
  vectors: { name: string; recipe: Recipe; expect: Outcome }[];
};
const api = workingTreeAdapterFor(src, rand);
/**
 * The artefacts drawn from the secure generator (a sealed message, a locked
 * key, an encapsulation, an ML-DSA signature) differ per run; the Rust
 * harness verifies them, this suite pins the rest of the row.
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

describe("golden vectors (frozen)", () => {
  it("fixture is self-consistent and non-trivial", () => {
    expect(vectors.length).toBe(count);
    expect(vectors.length).toBeGreaterThanOrEqual(5000);
    expect(vectors.findIndex((v) => v.recipe.k !== "noreg")).toBeGreaterThan(0);
    // every noreg row precedes every registered row
    const firstRegistered = vectors.findIndex((v) => v.recipe.k !== "noreg");
    expect(vectors.slice(firstRegistered).every((v) => v.recipe.k !== "noreg")).toBe(true);
  });
  vectors.forEach((v, i) => {
    if (v.recipe.k === "noreg") return;
    it(`#${i} ${v.name}`, async () => {
      const outcome =
        v.recipe.k === "agentLock"
          ? await materializeAsync(api, v.recipe, { messages: true })
          : materialize(api, v.recipe, { messages: true });
      expect(stable(v.recipe, outcome)).toBe(stable(v.recipe, v.expect));
    });
  });
});
