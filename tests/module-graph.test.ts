/**
 * The source module graph must be a DAG. Only value imports
 * count: a `import type` edge is erased at compile time and cannot cause a
 * temporal-dead-zone failure at load.
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, normalize, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

function* walk(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else if (p.endsWith(".ts") && !p.endsWith(".d.ts")) yield p;
  }
}

const IMPORT = /^import\s+(type\s+)?([^;]*?)\s+from\s+"(\.[^"]+)"/gms;

function valueImports(file: string): string[] {
  const src = readFileSync(file, "utf8");
  const out: string[] = [];
  for (const m of src.matchAll(IMPORT)) {
    if (m[1] !== undefined) continue;
    const spec = m[2] ?? "";
    const named = /\{([^}]*)\}/.exec(spec)?.[1];
    const defaultImport = /^\s*\w+\s*,/.test(spec) || /^\s*\w+\s*$/.test(spec);
    if (
      named !== undefined &&
      !defaultImport &&
      named
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
        .every((s) => s.startsWith("type "))
    )
      continue;
    let target = normalize(join(dirname(file), m[3] ?? ""));
    if (target.endsWith(".js")) target = target.slice(0, -3);
    try {
      if (statSync(target).isDirectory()) target = join(target, "index");
    } catch {
      /* a file */
    }
    out.push(`${target}.ts`);
  }
  return out;
}

describe("module graph", () => {
  const graph = new Map<string, string[]>();
  for (const f of walk(root)) graph.set(f, valueImports(f));

  it("has no value-import cycles", () => {
    const state = new Map<string, 1 | 2>();
    const stack: string[] = [];
    const cycles: string[] = [];
    const visit = (u: string): void => {
      state.set(u, 1);
      stack.push(u);
      for (const v of graph.get(u) ?? []) {
        const s = state.get(v);
        if (s === 1)
          cycles.push(
            [...stack.slice(stack.indexOf(v)), v].map((p) => relative(root, p)).join(" -> "),
          );
        else if (s === undefined) visit(v);
      }
      stack.pop();
      state.set(u, 2);
    };
    for (const u of graph.keys()) if (!state.has(u)) visit(u);
    expect(cycles).toEqual([]);
  });

  it("every relative import resolves to a source file", () => {
    for (const [from, deps] of graph)
      for (const d of deps) expect(graph.has(d), `${relative(root, from)} -> ${d}`).toBe(true);
  });
});
