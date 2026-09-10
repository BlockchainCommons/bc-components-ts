/**
 * Public-API snapshot.
 *
 * Snapshots the public type declarations of EVERY entry point to
 * api/<entry>.d.mts so any change to the public surface is a reviewable diff.
 * With several entry points the bundler splits shared declarations into
 * hashed chunk files, so each entry is first rolled up into one
 * self-contained file by api-extractor (dist/api-temp/<entry>.d.mts) and
 * that is what gets snapshotted.
 *
 *   bun run api:snapshot   # write/update the snapshots from the current build
 *   bun run api:check      # fail if any rolled-up entry differs from its snapshot
 *
 * Run `bun run build` first (the script reads dist/).
 */

import { copyFileSync, existsSync, readFileSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Extractor, ExtractorConfig } from "@microsoft/api-extractor";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const check = process.argv.includes("--check");

const ENTRIES = ["index", "ssh", "pq", "kdf", "sskr"];

const base = JSON.parse(readFileSync(join(root, "api-extractor.json"), "utf8"));

/** Roll dist/<entry>.d.mts (and its chunks) up into one declaration file. */
function rollup(entry) {
  const dmts = join(root, "dist", `${entry}.d.mts`);
  const dts = join(root, "dist", `${entry}.d.ts`);
  const out = join(root, "dist", "api-temp", `${entry}.d.mts`);
  if (!existsSync(dmts)) {
    console.error(`Missing ${dmts}. Run \`bun run build\` first.`);
    process.exit(1);
  }
  copyFileSync(dmts, dts);
  try {
    const config = ExtractorConfig.prepare({
      configObject: {
        ...base,
        projectFolder: root,
        mainEntryPointFilePath: `<projectFolder>/dist/${entry}.d.ts`,
        apiReport: { enabled: false },
        docModel: { enabled: false },
        tsdocMetadata: { enabled: false },
        dtsRollup: { enabled: true, untrimmedFilePath: out },
        messages: {
          extractorMessageReporting: { default: { logLevel: "none" } },
          tsdocMessageReporting: { default: { logLevel: "none" } },
        },
      },
      configObjectFullPath: join(root, "api-extractor.json"),
      packageJsonFullPath: join(root, "package.json"),
    });
    const result = Extractor.invoke(config, { localBuild: true, showVerboseMessages: false });
    if (!result.succeeded) {
      console.error(`api-extractor rollup of "${entry}" failed with ${result.errorCount} error(s).`);
      process.exit(1);
    }
  } finally {
    rmSync(dts, { force: true });
  }
  return readFileSync(out, "utf8");
}

let failed = false;
for (const entry of ENTRIES) {
  const snapshot = resolve(root, `api/${entry}.d.mts`);
  const current = rollup(entry);

  if (check) {
    if (!existsSync(snapshot)) {
      console.error(`No API snapshot for "${entry}". Run \`bun run api:snapshot\`.`);
      failed = true;
      continue;
    }
    if (readFileSync(snapshot, "utf8") !== current) {
      console.error(
        `Public API changed vs api/${entry}.d.mts.\n` +
          "Review the change; if intended, run `bun run api:snapshot` to update it.",
      );
      failed = true;
    }
  } else {
    mkdirSync(dirname(snapshot), { recursive: true });
    writeFileSync(snapshot, current);
    console.log(`Wrote API snapshot to api/${entry}.d.mts (${current.length} bytes).`);
  }
}
rmSync(join(root, "dist", "api-temp"), { recursive: true, force: true });

if (check) {
  if (failed) process.exit(1);
  console.log("All API snapshots match the current build.");
}
