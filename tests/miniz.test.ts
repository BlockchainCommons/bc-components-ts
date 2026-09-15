/**
 * Parity tests for the miniz_oxide 0.8.9 port (`src/internal/miniz-deflate.ts`
 * and `src/internal/miniz-inflate.ts`).
 *
 * Every expectation in `tests/fixtures/miniz/` was produced by the Rust crate
 * itself (`miniz_oxide = "=0.8.9"`), never by the port:
 *
 * - `compress-level6.json`: `compress_to_vec(input, 6)` for every corpus input
 *   defined below (full hex for inputs of at most 100 000 bytes, SHA-256 and
 *   length of the output above that) and the fact that Rust round-trips it.
 * - `compress-levels.json`: the same for a corpus subset at levels 2-5 and
 *   7-10.
 * - `inflate.json`: `decompress_to_vec(stream)` outcomes for hand-built
 *   streams (stored blocks, single-symbol tables, invalid code-length codes,
 *   block type 3, distances before the start of the output, trailing garbage,
 *   empty input), every prefix of a 40-byte stream, every single-bit flip of
 *   a 30-byte stream and a few level-6 outputs, as `ok:<hex>`,
 *   `ok-sha256:<sha256>:<len>` (outputs over 100 000 bytes) or
 *   `err:<TINFLStatus>`.
 *
 * The corpus inputs are regenerated here from the same definitions the Rust
 * generator uses (lengths, seeds and PRNG), so only names and expectations are
 * stored.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { compressToVec } from "../src/internal/miniz-deflate.js";
import {
  decompressToVec,
  InflateError,
  type InflateStatus,
} from "../src/internal/miniz-inflate.js";

// ---------------------------------------------------------------------------
// Corpus (mirrored in the Rust fixture generator)
// ---------------------------------------------------------------------------

/** xorshift32; each step contributes its low byte to the stream. */
class Xorshift32 {
  private s: number;

  constructor(seed: number) {
    if (seed === 0) throw new Error("seed must be non-zero");
    this.s = seed >>> 0;
  }

  nextU32(): number {
    let x = this.s;
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    this.s = x;
    return x;
  }

  bytes(n: number): Uint8Array {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) out[i] = this.nextU32() & 0xff;
    return out;
  }
}

const PRNG_SEED = 2_463_534_242;
const LOREM = new TextEncoder().encode("Lorem ipsum dolor sit amet, consectetur adipiscing elit. ");

function lorem(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = LOREM[i % LOREM.length];
  return out;
}

function cyclic(start: number, n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (start + i) & 0xff;
  return out;
}

function repeatPattern(pat: Uint8Array, n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = pat[i % pat.length];
  return out;
}

function runs(spec: [byte: number, count: number][]): Uint8Array {
  const total = spec.reduce((acc, [, n]) => acc + n, 0);
  const out = new Uint8Array(total);
  let p = 0;
  for (const [b, n] of spec) {
    out.fill(b, p, p + n);
    p += n;
  }
  return out;
}

function corpus(): Map<string, Uint8Array> {
  const c = new Map<string, Uint8Array>();
  const ascii = (s: string): Uint8Array => new TextEncoder().encode(s);
  c.set("empty", new Uint8Array(0));
  c.set("one-byte", new Uint8Array([0x61]));
  c.set("two-bytes", new Uint8Array([0x61, 0x62]));
  for (const n of [0, 1, 10, 57, 100, 114, 256, 500, 1000, 1024, 2048, 4096, 10000, 40000, 70000]) {
    c.set(`lorem-${n}`, lorem(n));
  }
  for (let n = 0; n <= 300; n++) c.set(`cyclic-${n}`, cyclic((n * 7) & 0xff, n));
  for (const n of [1000, 32768, 32769, 65535, 65536, 65537, 100_000, 200_000]) {
    c.set(`cyclic0-${n}`, cyclic(0, n));
  }
  for (const n of [100, 1000, 5000, 33000, 100_000, 1_048_576]) {
    c.set(`prng-${n}`, new Xorshift32(PRNG_SEED).bytes(n));
  }
  c.set("run-300x00", runs([[0x00, 300]]));
  c.set("run-300xff", runs([[0xff, 300]]));
  c.set(
    "runs-300x00-300xff",
    runs([
      [0x00, 300],
      [0xff, 300],
    ]),
  );
  c.set("alt01-1000", repeatPattern(new Uint8Array([0, 1]), 1000));
  c.set("run-258", runs([[0x41, 258]]));
  c.set("run-259", runs([[0x41, 259]]));
  c.set(
    "runs-258x3",
    runs([
      [0x41, 258],
      [0x42, 258],
      [0x43, 258],
    ]),
  );
  c.set(
    "runs-259x3",
    runs([
      [0x41, 259],
      [0x42, 259],
      [0x43, 259],
    ]),
  );
  c.set("run-65536x41", runs([[0x41, 65536]]));
  c.set("abc-5000", repeatPattern(ascii("abc"), 5000));
  c.set("ab-6000", repeatPattern(ascii("ab"), 6000));
  for (let i = 0; i < 200; i++) {
    const rng = new Xorshift32((1_000_003 * (i + 1)) >>> 0);
    const len = rng.nextU32() % 3001;
    c.set(`rand-${i}`, rng.bytes(len));
  }
  return c;
}

// ---------------------------------------------------------------------------
// Fixtures and helpers
// ---------------------------------------------------------------------------

interface CompressCase {
  level?: number;
  name: string;
  inputLen: number;
  hex?: string;
  sha256?: string;
  compressedLen?: number;
  roundTrip: boolean;
}

interface InflateCase {
  name: string;
  hex: string;
  expect: string;
}

interface Fixture<T> {
  crate: string;
  version: string;
  cases: T[];
}

const here = dirname(fileURLToPath(import.meta.url));

function loadFixture<T>(name: string): Fixture<T> {
  const text = readFileSync(join(here, "fixtures", "miniz", name), "utf8");
  const fixture = JSON.parse(text) as Fixture<T>;
  expect(fixture.crate).toBe("miniz_oxide");
  expect(fixture.version).toBe("0.8.9");
  return fixture;
}

const HEX_BYTES: string[] = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));

function toHex(bytes: Uint8Array): string {
  const parts = new Array<string>(bytes.length);
  for (let i = 0; i < bytes.length; i++) parts[i] = HEX_BYTES[bytes[i]];
  return parts.join("");
}

function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) {
    throw new Error("fixture hex is not well formed");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** Index of the first differing byte, or -1 when both arrays are identical. */
function firstDifference(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return i;
  return a.length === b.length ? -1 : n;
}

function expectSameBytes(actual: Uint8Array, expected: Uint8Array, what: string): void {
  const diff = firstDifference(actual, expected);
  expect(
    diff,
    `${what}: first difference at byte ${diff} (got ${actual.length} bytes, want ${expected.length})`,
  ).toBe(-1);
}

function checkCompressCase(c: CompressCase, input: Uint8Array, level: number): void {
  expect(input.length, `${c.name}: corpus length`).toBe(c.inputLen);
  expect(c.roundTrip, `${c.name}: Rust round trip`).toBe(true);

  const out = compressToVec(input, level);
  if (c.hex !== undefined) {
    expectSameBytes(out, fromHex(c.hex), `${c.name} level ${level}`);
  } else {
    expect(out.length, `${c.name} level ${level}: compressed length`).toBe(c.compressedLen);
    expect(sha256Hex(out), `${c.name} level ${level}: compressed sha256`).toBe(c.sha256);
  }

  expectSameBytes(decompressToVec(out), input, `${c.name} level ${level}: round trip`);
}

/** Mirrors the generator's `inflate_outcome`. */
function inflateOutcome(input: Uint8Array): string {
  try {
    const out = decompressToVec(input);
    if (out.length > 100_000) return `ok-sha256:${sha256Hex(out)}:${out.length}`;
    return `ok:${toHex(out)}`;
  } catch (e) {
    if (e instanceof InflateError) return `err:${e.status}`;
    throw e;
  }
}

const INFLATE_STATUSES: readonly InflateStatus[] = [
  "FailedCannotMakeProgress",
  "BadParam",
  "Adler32Mismatch",
  "Failed",
  "Done",
  "NeedsMoreInput",
  "HasMoreOutput",
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const inputs = corpus();

describe("miniz corpus", () => {
  it("has unique names and the expected shape", () => {
    expect(inputs.size).toBe(3 + 15 + 301 + 8 + 6 + 11 + 200);
    expect(inputs.get("prng-100")?.subarray(0, 4)).toEqual(new Xorshift32(PRNG_SEED).bytes(4));
    expect(inputs.get("cyclic-10")).toEqual(
      new Uint8Array([70, 71, 72, 73, 74, 75, 76, 77, 78, 79]),
    );
  });
});

describe("compressToVec level 6 matches miniz_oxide 0.8.9", () => {
  const fixture = loadFixture<CompressCase>("compress-level6.json");
  const names = new Set(fixture.cases.map((c) => c.name));

  it("covers exactly the corpus", () => {
    expect(fixture.cases.length).toBe(names.size);
    expect([...names].sort()).toEqual([...inputs.keys()].sort());
  });

  for (const c of fixture.cases) {
    it(`${c.name} (${c.inputLen} bytes)`, () => {
      const input = inputs.get(c.name);
      if (input === undefined) throw new Error(`no corpus input named ${c.name}`);
      checkCompressCase(c, input, 6);
    });
  }
});

describe("compressToVec other levels match miniz_oxide 0.8.9", () => {
  const fixture = loadFixture<CompressCase>("compress-levels.json");

  it("covers levels 2-5 and 7-10", () => {
    const levels = new Set(fixture.cases.map((c) => c.level));
    expect([...levels].sort((a, b) => (a ?? 0) - (b ?? 0))).toEqual([2, 3, 4, 5, 7, 8, 9, 10]);
  });

  for (const c of fixture.cases) {
    it(`${c.name} level ${c.level} (${c.inputLen} bytes)`, () => {
      const input = inputs.get(c.name);
      if (input === undefined) throw new Error(`no corpus input named ${c.name}`);
      if (c.level === undefined) throw new Error(`no level recorded for ${c.name}`);
      checkCompressCase(c, input, c.level);
    });
  }

  it("rejects the levels that use other compressors", () => {
    for (const level of [-1, 0, 1, 11, 2.5, Number.NaN]) {
      expect(() => compressToVec(new Uint8Array(10), level)).toThrow(RangeError);
    }
  });
});

describe("decompressToVec matches miniz_oxide 0.8.9", () => {
  const fixture = loadFixture<InflateCase>("inflate.json");

  it("covers the required stream families", () => {
    const names = fixture.cases.map((c) => c.name);
    expect(names.filter((n) => n.startsWith("stream-")).length).toBeGreaterThan(0);
    expect(names.filter((n) => n.startsWith("trunc-")).length).toBe(41);
    expect(names.filter((n) => n.startsWith("flip-")).length).toBe(30 * 8 + 1);
    for (const required of [
      "hand-empty",
      "hand-btype3-final",
      "hand-stored-hello",
      "hand-stored-bad-nlen",
      "hand-fixed-dist-too-far",
      "hand-trailing-garbage",
      "hand-dyn-hufflen-single",
      "hand-dyn-hufflen-oversubscribed",
      "hand-dyn-litlen-single-eob",
    ]) {
      expect(names, required).toContain(required);
    }
  });

  it("only records TINFLStatus names the port can report", () => {
    for (const c of fixture.cases) {
      if (c.expect.startsWith("err:")) {
        expect(INFLATE_STATUSES, c.name).toContain(c.expect.slice(4));
      }
    }
  });

  for (const c of fixture.cases) {
    it(`${c.name} -> ${c.expect.slice(0, 40)}`, () => {
      const input = fromHex(c.hex);
      expect(inflateOutcome(input)).toBe(c.expect);

      if (c.expect.startsWith("err:")) {
        let thrown: unknown;
        try {
          decompressToVec(input);
        } catch (e) {
          thrown = e;
        }
        expect(thrown).toBeInstanceOf(InflateError);
        const error = thrown as InflateError;
        expect(error.status).toBe(c.expect.slice(4));
        expect(error.output).toBeInstanceOf(Uint8Array);
        expect(error.message.length).toBeGreaterThan(0);
      }
    });
  }
});
