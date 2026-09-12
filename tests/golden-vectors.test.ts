/**
 * Golden vector suite: the committed, hand-pinned freeze of every
 * tagged CBOR, UR, derivation and signature. Changes only through
 * `bun run vectors:generate`.
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
import { materialize, redesignedAdapterFor, type Recipe, type Outcome } from "./vectors/recipes";

const here = dirname(fileURLToPath(import.meta.url));
const { count, vectors } = JSON.parse(readFileSync(join(here, "vectors/vectors.json"), "utf8")) as {
  count: number;
  vectors: { name: string; recipe: Recipe; expect: Outcome }[];
};
const api = redesignedAdapterFor(src, rand);
// Structural outcomes vary per run where the secure generator is involved
// (sealing, key locking, ML-KEM encapsulation); the
// stable prefix is what is pinned.
const stable = (r: Recipe, o: string): string => {
  if (r.k === "seal" || r.k === "encryptedKey" || r.k === "mlkem")
    return o.replace(/\|aad=.*$/, "");
  if (r.k === "mldsa") return o.split("|").slice(-2).join("|");
  return o;
};

describe("golden vectors (frozen)", () => {
  it("fixture is self-consistent and non-trivial", () => {
    expect(vectors.length).toBe(count);
    expect(vectors.length).toBeGreaterThanOrEqual(300);
  });
  vectors.forEach((v, i) => {
    it(`#${i} ${v.name}`, () => {
      expect(stable(v.recipe, materialize(api, v.recipe))).toBe(stable(v.recipe, v.expect));
    });
  });
});
