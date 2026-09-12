import { defineConfig } from "vitest/config";

import { fileURLToPath } from "node:url";

const src = (p: string): string => fileURLToPath(new URL(`./src/${p}`, import.meta.url));

export default defineConfig({
  // `src/tags.ts` imports the package by its own name; in the repo those are the sources.
  resolve: {
    alias: [
      { find: "@blockchaincommons/components/kdf", replacement: src("kdf.ts") },
      { find: "@blockchaincommons/components/ssh", replacement: src("ssh/index.ts") },
      { find: "@blockchaincommons/components/sskr", replacement: src("sskr.ts") },
      { find: "@blockchaincommons/components/pq", replacement: src("pq.ts") },
      { find: "@blockchaincommons/components", replacement: src("index.ts") },
    ],
  },
  test: {
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text-summary", "json-summary", "html"],
      reportsDirectory: "coverage",
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.d.ts", "src/index.ts"],
      // Raise-only floors. Seed from the first measured run; never lower.
      thresholds: {
        statements: 85,
        branches: 76,
        functions: 91,
        lines: 87,
      },
    },
  },
});
