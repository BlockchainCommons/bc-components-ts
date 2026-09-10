import { defineConfig } from "tsdown";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    ssh: "src/ssh/index.ts",
    pq: "src/pq.ts",
    kdf: "src/kdf.ts",
    sskr: "src/sskr.ts",
  },
  outDir: "dist",
  format: ["cjs", "esm"],
  dts: true,
  inputOptions: {
    // The rolldown-plugin-dts "fake-js" pass transforms .d.ts content without
    // emitting a sourcemap, producing a spurious SOURCEMAP_BROKEN warning even
    // though the real JS sourcemaps are correct. Filter only that case.
    onwarn(warning, defaultHandler) {
      if (warning.code === "SOURCEMAP_BROKEN") return;
      defaultHandler(warning);
    },
  },
  sourcemap: true,
  clean: true,
  target: "es2022",
  // Keep @noble/* and @scure/* as external - don't bundle them
  deps: {
    neverBundle: [/@noble\/.*/, /@scure\/.*/],
  },
});
