/**
 * Golden vector suite (Phase 1.2): the committed, hand-pinned freeze of every
 * tagged CBOR, UR, derivation and signature. Changes only through
 * `bun run vectors:generate`.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as src from "../src";
import * as rand from "@blockchaincommons/rand";
import { materialize, redesignedAdapterFor, type Recipe, type Outcome } from "./vectors/recipes";

const here = dirname(fileURLToPath(import.meta.url));
const { count, vectors } = JSON.parse(readFileSync(join(here, "vectors/vectors.json"), "utf8")) as {
  count: number;
  vectors: { name: string; recipe: Recipe; expect: Outcome }[];
};
const api = redesignedAdapterFor(src, rand);
// Structural outcomes vary per run where the secure generator is involved
// (sealing, key locking, ML-KEM encapsulation, sr25519 signatures); the
// stable prefix is what is pinned.
const stable = (r: Recipe, o: string): string => {
  if (r.k === "seal" || r.k === "encryptedKey" || r.k === "mlkem")
    return o.replace(/\|aad=.*$/, "");
  if (r.k === "sign" && r.scheme === "sr25519") return o.split("|").at(-1) ?? o;
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
