/**
 * The golden rows that run before any tag is registered: what `toUR()`,
 * `fromCbor` and `cborTags()` do in a process that never called
 * `registerTags()`. This file must not register tags, and vitest runs it in
 * its own module context so no other suite's registration leaks in.
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
import { materialize, workingTreeAdapterFor, type Recipe, type Outcome } from "./vectors/recipes";

const here = dirname(fileURLToPath(import.meta.url));
const { vectors } = JSON.parse(readFileSync(join(here, "vectors/vectors.json"), "utf8")) as {
  vectors: { name: string; recipe: Recipe; expect: Outcome }[];
};
const api = workingTreeAdapterFor(src, rand);
const noreg = vectors.filter((v) => v.recipe.k === "noreg");

describe("golden vectors before registerTags()", () => {
  it("has the unregistered rows", () => {
    expect(noreg.length).toBeGreaterThan(0);
  });
  noreg.forEach((v, i) => {
    it(`#${i} ${v.name}`, () => {
      expect(materialize(api, v.recipe, { messages: true })).toBe(v.expect);
    });
  });
});
