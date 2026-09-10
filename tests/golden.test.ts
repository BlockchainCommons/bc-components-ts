/**
 * Golden snapshots (Phase 0.2): one block per class over fixed inputs and
 * the seeded generator, plus the rejection table.
 */
import * as src from "../src";
import * as rand from "@blockchaincommons/rand";
import { materialize, redesignedAdapterFor, type Recipe } from "./vectors/recipes";
import { categories, SEEDS, FAKE } from "./corpus/corpus";

const api = redesignedAdapterFor(src, rand);
const run = (r: Recipe) => materialize(api, r);

describe("golden: value types over fixed bytes", () => {
  const byType = new Map<string, Recipe[]>();
  for (const r of categories["values"]!()) {
    if (r.k !== "value") continue;
    byType.set(r.type, [...(byType.get(r.type) ?? []), r]);
  }
  for (const [type, recipes] of byType) {
    it(type, () => {
      expect(recipes.map((r) => run(r))).toMatchSnapshot();
    });
  }
});
describe("golden: seeded constructors", () => {
  for (const type of [
    "nonce",
    "salt",
    "arid",
    "uuid",
    "symmetricKey",
    "x25519Priv",
    "ecPriv",
    "ed25519Priv",
    "sr25519Priv",
    "privateKeyBase",
    "seed",
  ] as const) {
    it(type, () => {
      expect([
        run({ k: "random", type, rng: SEEDS[0]! }),
        run({ k: "random", type, rng: FAKE }),
      ]).toMatchSnapshot();
    });
  }
});
for (const cat of [
  "derives",
  "digests",
  "compresseds",
  "seeds",
  "encrypts",
  "signings",
  "sshes",
  "pkbs",
  "kdfs",
  "sskrs",
  "decodes",
]) {
  describe(`golden: ${cat}`, () => {
    it("matches the snapshot", () => {
      const out: string[] = [];
      for (const r of categories[cat]!()) {
        const o = run(r);
        // outcomes that involve the secure generator are pinned by their stable tail
        out.push(
          r.k === "encryptedKey"
            ? o.replace(/\|aad=.*$/, "")
            : r.k === "sign" && r.scheme === "sr25519"
              ? (o.split("|").at(-1) ?? o)
              : o,
        );
      }
      expect(out).toMatchSnapshot();
    });
  });
}
