/**
 * Vector generator. Materialises recipes with the WORKING TREE, error
 * messages included, in the order the Rust harness replays them: the rows
 * under `noreg` first, before the tags are registered, then everything else.
 *
 *   bun scripts/generate-vectors.ts                 # the golden subset → tests/vectors/vectors.json
 *   bun scripts/generate-vectors.ts --full <path>   # the whole corpus → <path> (not committed)
 *
 * Regenerating the golden file is a deliberate, reviewed act.
 */
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  materializeAsync,
  recipeName,
  workingTreeAdapterFor,
  type Recipe,
} from "../tests/vectors/recipes.ts";
import { allRecipes, goldenRecipes } from "../tests/corpus/corpus.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const fullIndex = process.argv.indexOf("--full");
const full = fullIndex !== -1;
const out = full ? process.argv[fullIndex + 1] : join(root, "tests/vectors/vectors.json");
if (out === undefined) throw new Error("--full needs an output path");

const m = {
  ...(await import("../src/index.ts")),
  ...(await import("../src/ssh/index.ts")),
  ...(await import("../src/pq.ts")),
  ...(await import("../src/kdf.ts")),
  ...(await import("../src/sskr.ts")),
  ...(await import("../src/tags.ts")),
};
const rand = await import("@blockchaincommons/rand");
const api = workingTreeAdapterFor(m, rand);

const recipes = [...(full ? allRecipes() : goldenRecipes())];
const noreg = recipes.filter((r) => r.k === "noreg");
const registered = recipes.filter((r) => r.k !== "noreg");
const row = async (recipe: Recipe) => ({
  name: recipeName(recipe),
  recipe,
  expect: await materializeAsync(api, recipe, { messages: true }),
});
// The unregistered rows see the store as a fresh process does.
const vectors = [];
for (const recipe of noreg) vectors.push(await row(recipe));
m.registerTags();
for (const recipe of registered) vectors.push(await row(recipe));

writeFileSync(out, JSON.stringify({ count: vectors.length, vectors }, null, 1) + "\n");
console.log(`wrote ${vectors.length} ${full ? "corpus" : "golden"} vectors to ${out}`);
