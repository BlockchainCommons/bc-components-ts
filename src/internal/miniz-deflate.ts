/**
 * Raw DEFLATE compressor.
 *
 * This is a literal port of the compressor in `miniz_oxide` 0.8.9
 * (`deflate/core.rs`, `deflate/buffer.rs` and `compress_to_vec` in
 * `deflate/mod.rs`), restricted to what `compress_to_vec(input, level)` uses
 * for a raw stream with the default strategy: the `compress_normal` parser
 * (greedy for levels 2-3, lazy for 4-10), the hash chains, `flush_block` with
 * its static/dynamic/stored block choice and the Huffman table construction.
 * The goal is byte-for-byte identical output to the Rust crate, so the
 * structure and every output-affecting branch follow the Rust source; names
 * in comments refer to the Rust functions.
 *
 * Not ported (never reached by `compress_to_vec` with the default strategy):
 * level 0 (`compress_stored`), level 1 (`compress_fast`), the zlib wrapper,
 * adler32 and the RLE/filtered/fixed/huffman-only strategies.
 */

// ---------------------------------------------------------------------------
// Constants (deflate/core.rs, deflate/buffer.rs)
// ---------------------------------------------------------------------------

const MAX_SUPPORTED_HUFF_CODESIZE = 15;
const LEN_SYM_OFFSET = 256;
const MAX_HUFF_SYMBOLS = 288;
const MAX_HUFF_TABLES = 3;
/** Literal/length codes. */
const MAX_HUFF_SYMBOLS_0 = 288;
/** Distance codes. */
const MAX_HUFF_SYMBOLS_1 = 32;
/** Huffman length values. */
const MAX_HUFF_SYMBOLS_2 = 19;
const LZ_DICT_SIZE = 32768;
const LZ_DICT_SIZE_MASK = LZ_DICT_SIZE - 1;
const MIN_MATCH_LEN = 3;
const MAX_MATCH_LEN = 258;
const LZ_CODE_BUF_SIZE = 64 * 1024;
const LZ_CODE_BUF_MASK = LZ_CODE_BUF_SIZE - 1;
const OUT_BUF_SIZE = Math.floor((LZ_CODE_BUF_SIZE * 13) / 10);
const LZ_DICT_FULL_SIZE = LZ_DICT_SIZE + MAX_MATCH_LEN - 1 + 1;
const LZ_HASH_BITS = 15;
const LZ_HASH_SHIFT = Math.floor((LZ_HASH_BITS + 2) / 3);
const LZ_HASH_SIZE = 1 << LZ_HASH_BITS;
const MAX_PROBES_MASK = 0xfff;

const LITLEN_TABLE = 0;
const DIST_TABLE = 1;
const HUFF_CODES_TABLE = 2;

/** `deflate_flags` */
const TDEFL_WRITE_ZLIB_HEADER = 0x0000_1000;
const TDEFL_GREEDY_PARSING_FLAG = 0x0000_4000;
const TDEFL_RLE_MATCHES = 0x0001_0000;
const TDEFL_FILTER_MATCHES = 0x0002_0000;
const TDEFL_FORCE_ALL_STATIC_BLOCKS = 0x0004_0000;
const TDEFL_FORCE_ALL_RAW_BLOCKS = 0x0008_0000;

/** Maximum hash chain probes per compression level (`NUM_PROBES`). */
const NUM_PROBES: readonly number[] = [0, 1, 6, 32, 16, 32, 128, 256, 512, 768, 1500];

const HUFFMAN_LENGTH_ORDER: Uint8Array = new Uint8Array([
  16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
]);

// Lookup tables copied verbatim from deflate/core.rs.

/** Length code for length values - 256 (indexed by `match_len - 3`). */
const LEN_SYM: Uint8Array = new Uint8Array([
  1, 2, 3, 4, 5, 6, 7, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15,
  15, 16, 16, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 18, 18, 19, 19, 19,
  19, 19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 20, 20, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21,
  21, 21, 21, 21, 21, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23,
  23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
  24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
  25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
  26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 27, 27, 27,
  27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
  27, 27, 27, 27, 27, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
  28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 29,
]);

/** Number of extra bits for length values. */
const LEN_EXTRA: Uint8Array = new Uint8Array([
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3,
  3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4,
  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5,
  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 0,
]);

/** Distance codes for distances smaller than 512. */
const SMALL_DIST_SYM: Uint8Array = new Uint8Array([
  0, 1, 2, 3, 4, 4, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9,
  10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11,
  11, 11, 11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
  12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13, 13, 13, 13, 13,
  13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
  14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
  14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
  14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 15, 15, 15, 15, 15, 15, 15, 15,
  15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
  15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
  15, 15, 15, 15, 15, 15, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
  16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
  16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
  16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
  16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
  16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17,
  17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
  17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
  17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
  17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
  17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
]);

/** Number of extra bits for distances smaller than 512. */
const SMALL_DIST_EXTRA: Uint8Array = new Uint8Array([
  0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4,
  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5,
  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6,
  6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
  6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
  6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
  6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
]);

/** Distance codes for distances of 512 and above (indexed by `dist >> 8`). */
const LARGE_DIST_SYM: Uint8Array = new Uint8Array([
  0, 0, 18, 19, 20, 20, 21, 21, 22, 22, 22, 22, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 25,
  25, 25, 25, 25, 25, 25, 25, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 27,
  27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 28, 28, 28, 28, 28, 28, 28, 28, 28,
  28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 29,
  29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
  29, 29, 29, 29, 29, 29, 29,
]);

/** Number of extra bits for distances of 512 and above. */
const LARGE_DIST_EXTRA: Uint8Array = new Uint8Array([
  0, 0, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
  11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
  12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
  13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
  13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
  13, 13, 13, 13, 13, 13,
]);

const BITMASKS: Uint32Array = new Uint32Array([
  0, 1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 4095, 8191, 16383, 32767, 65535,
]);

/** Bit reversal of a byte, used to build `u16::reverse_bits`. */
const REV8: Uint8Array = (() => {
  const t = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    let r = 0;
    for (let b = 0; b < 8; b++) r |= ((i >> b) & 1) << (7 - b);
    t[i] = r;
  }
  return t;
})();

function reverseBits16(v: number): number {
  return (REV8[v & 0xff] << 8) | REV8[(v >> 8) & 0xff];
}

/**
 * `create_comp_flags_from_zip_params`.
 * `windowBits > 0` selects the zlib wrapper, `level == 0` stored blocks and
 * `strategy` one of the special strategies; `compressToVec` only ever calls
 * this with `(level, 0, 0)`.
 */
function createCompFlagsFromZipParams(level: number, windowBits: number, strategy: number): number {
  const numProbes = level >= 0 ? Math.min(10, level) : 6;
  const greedy = level <= 3 ? TDEFL_GREEDY_PARSING_FLAG : 0;
  let compFlags = NUM_PROBES[numProbes] | greedy;
  if (windowBits > 0) compFlags |= TDEFL_WRITE_ZLIB_HEADER;
  if (level === 0) {
    compFlags |= TDEFL_FORCE_ALL_RAW_BLOCKS;
  } else if (strategy === 1) {
    compFlags |= TDEFL_FILTER_MATCHES;
  } else if (strategy === 2) {
    compFlags &= ~MAX_PROBES_MASK;
  } else if (strategy === 4) {
    compFlags |= TDEFL_FORCE_ALL_STATIC_BLOCKS;
  } else if (strategy === 3) {
    compFlags |= TDEFL_RLE_MATCHES;
  }
  return compFlags;
}

/** Flags whose code paths this port does not include. */
const UNSUPPORTED_FLAGS =
  TDEFL_WRITE_ZLIB_HEADER |
  TDEFL_RLE_MATCHES |
  TDEFL_FILTER_MATCHES |
  TDEFL_FORCE_ALL_STATIC_BLOCKS |
  TDEFL_FORCE_ALL_RAW_BLOCKS;

// ---------------------------------------------------------------------------
// Compressor state (CompressorOxide = LZOxide + ParamsOxide + HuffmanOxide + DictOxide)
// ---------------------------------------------------------------------------

class Deflater {
  // ParamsOxide
  private readonly greedyParsing: boolean;
  private savedMatchDist = 0;
  private savedMatchLen = 0;
  private savedLit = 0;
  private srcPos = 0;
  private savedBitBuffer = 0;
  private savedBitsIn = 0;
  private blockIndex = 0;

  // DictOxide / HashBuffers
  private readonly maxProbes0: number;
  private readonly maxProbes1: number;
  private readonly dict: Uint8Array = new Uint8Array(LZ_DICT_FULL_SIZE);
  private readonly next: Uint16Array = new Uint16Array(LZ_DICT_SIZE);
  private readonly hash: Uint16Array = new Uint16Array(LZ_DICT_SIZE);
  private codeBufDictPos = 0;
  private lookaheadSize = 0;
  private lookaheadPos = 0;
  private dictSize = 0;

  // LZOxide
  private readonly lzCodes: Uint8Array = new Uint8Array(LZ_CODE_BUF_SIZE);
  private codePosition = 1;
  private flagPosition = 0;
  private totalBytes = 0;
  private numFlagsLeft = 8;

  // HuffmanOxide
  private readonly count: Uint16Array[] = [];
  private readonly codes: Uint16Array[] = [];
  private readonly codeSizes: Uint8Array[] = [];

  // Scratch buffers for optimize_table / start_dynamic_block.
  private readonly symKeys0: Uint16Array = new Uint16Array(MAX_HUFF_SYMBOLS);
  private readonly symIdx0: Uint16Array = new Uint16Array(MAX_HUFF_SYMBOLS);
  private readonly symKeys1: Uint16Array = new Uint16Array(MAX_HUFF_SYMBOLS);
  private readonly symIdx1: Uint16Array = new Uint16Array(MAX_HUFF_SYMBOLS);
  private readonly hist0: Uint32Array = new Uint32Array(256);
  private readonly hist1: Uint32Array = new Uint32Array(256);
  private readonly offsets: Uint32Array = new Uint32Array(256);
  private readonly numCodes: Int32Array = new Int32Array(32 + 1);
  private readonly nextCode: Uint32Array = new Uint32Array(MAX_SUPPORTED_HUFF_CODESIZE + 1);
  private readonly codeSizesToPack: Uint8Array = new Uint8Array(
    MAX_HUFF_SYMBOLS_0 + MAX_HUFF_SYMBOLS_1,
  );
  private readonly packedCodeSizes: Uint8Array = new Uint8Array(
    MAX_HUFF_SYMBOLS_0 + MAX_HUFF_SYMBOLS_1,
  );

  // Output (OutputBufferOxide, written straight into the result vector).
  private out: Uint8Array;
  private outPos = 0;
  private bitBuffer = 0;
  private bitsIn = 0;

  // Results of find_match.
  private matchDist = 0;
  private matchLen = 0;

  constructor(flags: number, inputLen: number) {
    this.greedyParsing = (flags & TDEFL_GREEDY_PARSING_FLAG) !== 0;
    // probes_from_flags
    this.maxProbes0 = 1 + Math.floor(((flags & 0xfff) + 2) / 3);
    this.maxProbes1 = 1 + Math.floor((((flags & 0xfff) >> 2) + 2) / 3);
    for (let t = 0; t < MAX_HUFF_TABLES; t++) {
      this.count.push(new Uint16Array(MAX_HUFF_SYMBOLS));
      this.codes.push(new Uint16Array(MAX_HUFF_SYMBOLS));
      this.codeSizes.push(new Uint8Array(MAX_HUFF_SYMBOLS));
    }
    this.out = new Uint8Array(Math.max(inputLen >> 1, 1024) + 2 * OUT_BUF_SIZE);
  }

  /** `compress_to_vec_inner` with `TDEFLFlush::Finish` on a raw stream. */
  compress(input: Uint8Array): Uint8Array {
    this.compressNormal(input);
    // compress_inner: with a Finish flush and no input left the final block is
    // written once the lookahead is empty.
    if (this.lookaheadSize !== 0 || this.srcPos !== input.length) {
      throw new Error("miniz deflate: compressor did not consume the whole input");
    }
    this.flushBlock(true);
    return this.out.slice(0, this.outPos);
  }

  // -- OutputBufferOxide -----------------------------------------------------

  /**
   * `put_bits`: appends `len` bits and writes out every whole byte. Flushing
   * after every call yields the same byte stream as the batched 64-bit
   * `BitBuffer` used by `compress_lz_codes`, so a single writer serves both.
   */
  private putBits(bits: number, len: number): void {
    this.bitBuffer = (this.bitBuffer | (bits << this.bitsIn)) >>> 0;
    this.bitsIn += len;
    while (this.bitsIn >= 8) {
      this.out[this.outPos++] = this.bitBuffer & 0xff;
      this.bitBuffer >>>= 8;
      this.bitsIn -= 8;
    }
  }

  /** `pad_to_bytes` */
  private padToBytes(): void {
    if (this.bitsIn !== 0) this.putBits(0, 8 - this.bitsIn);
  }

  private ensureOutCapacity(needed: number): void {
    if (needed <= this.out.length) return;
    let cap = this.out.length * 2;
    while (cap < needed) cap *= 2;
    const grown = new Uint8Array(cap);
    grown.set(this.out.subarray(0, this.outPos));
    this.out = grown;
  }

  // -- LZOxide -----------------------------------------------------------------

  private writeCode(val: number): void {
    this.lzCodes[this.codePosition & 0xffff] = val;
    this.codePosition += 1;
  }

  private initFlag(): void {
    if (this.numFlagsLeft === 8) {
      this.lzCodes[this.flagPosition & 0xffff] = 0;
      this.codePosition -= 1;
    } else {
      this.lzCodes[this.flagPosition & 0xffff] >>= this.numFlagsLeft;
    }
  }

  private consumeFlag(): void {
    this.numFlagsLeft -= 1;
    if (this.numFlagsLeft === 0) {
      this.numFlagsLeft = 8;
      // plant_flag
      this.flagPosition = this.codePosition;
      this.codePosition += 1;
    }
  }

  /** `record_literal` */
  private recordLiteral(lit: number): void {
    this.totalBytes += 1;
    this.writeCode(lit);
    this.lzCodes[this.flagPosition & 0xffff] >>= 1;
    this.consumeFlag();
    this.count[LITLEN_TABLE][lit] += 1;
  }

  /** `record_match` */
  private recordMatch(matchLen: number, matchDist: number): void {
    this.totalBytes += matchLen;
    matchDist -= 1;
    const len = matchLen - MIN_MATCH_LEN;
    this.writeCode(len);
    this.writeCode(matchDist & 0xff);
    this.writeCode((matchDist >> 8) & 0xff);
    const fp = this.flagPosition & 0xffff;
    this.lzCodes[fp] >>= 1;
    this.lzCodes[fp] |= 0x80;
    this.consumeFlag();
    const symbol =
      matchDist < 512 ? SMALL_DIST_SYM[matchDist] : LARGE_DIST_SYM[(matchDist >> 8) & 127];
    this.count[DIST_TABLE][symbol] += 1;
    this.count[LITLEN_TABLE][(LEN_SYM[len] & 31) + LEN_SYM_OFFSET] += 1;
  }

  // -- DictOxide ---------------------------------------------------------------

  /**
   * `DictOxide::find_match`: look for a match at `lookaheadPos` longer than
   * `matchLen`. Results are left in `this.matchDist` / `this.matchLen`
   * (unchanged if nothing better was found).
   */
  private findMatch(
    lookaheadPos: number,
    maxDist: number,
    maxMatchLenIn: number,
    matchDist: number,
    matchLen: number,
  ): void {
    const dict = this.dict;
    const next = this.next;
    const maxMatchLen = Math.min(MAX_MATCH_LEN, maxMatchLenIn);
    matchLen = Math.max(matchLen, 1);

    if (maxMatchLen <= matchLen) {
      this.matchDist = matchDist;
      this.matchLen = matchLen;
      return;
    }

    const pos = lookaheadPos & LZ_DICT_SIZE_MASK;
    let probePos = pos;
    let numProbesLeft = matchLen < 32 ? this.maxProbes0 : this.maxProbes1;

    // Last byte of the current match and the one after it.
    let c01 = dict[pos + matchLen - 1] | (dict[pos + matchLen] << 8);
    // The two first bytes at the current position.
    const s01 = dict[pos] | (dict[pos + 1] << 8);

    let dist: number;
    outer: for (;;) {
      found: for (;;) {
        numProbesLeft -= 1;
        if (numProbesLeft === 0) {
          this.matchDist = matchDist;
          this.matchLen = matchLen;
          return;
        }
        for (let k = 0; k < 3; k++) {
          const nextProbePos = next[probePos];
          dist = (lookaheadPos - nextProbePos) & 0xffff;
          if (nextProbePos === 0 || dist > maxDist || matchLen - 1 >= MAX_MATCH_LEN) {
            this.matchDist = matchDist;
            this.matchLen = matchLen;
            return;
          }
          probePos = nextProbePos & LZ_DICT_SIZE_MASK;
          if ((dict[probePos + matchLen - 1] | (dict[probePos + matchLen] << 8)) === c01) {
            break found;
          }
        }
      }

      if (dist === 0) {
        this.matchDist = matchDist;
        this.matchLen = matchLen;
        return;
      }

      if ((dict[probePos] | (dict[probePos + 1] << 8)) !== s01) continue;

      // The first two bytes matched; compare the rest 8 bytes at a time
      // (read_unaligned_u64 masks the position, the dictionary tail mirrors
      // the first MAX_MATCH_LEN - 1 bytes).
      let p = pos + 2;
      let q = probePos + 2;
      for (let round = 0; round < 32; round++) {
        const pb = p & LZ_DICT_SIZE_MASK;
        const qb = q & LZ_DICT_SIZE_MASK;
        let k = 0;
        while (k < 8 && dict[pb + k] === dict[qb + k]) k++;
        if (k === 8) {
          p += 8;
          q += 8;
          continue;
        }
        const probeLen = p - pos + k;
        if (probeLen > matchLen) {
          matchDist = dist;
          matchLen = Math.min(maxMatchLen, probeLen);
          if (matchLen >= maxMatchLen) {
            this.matchDist = matchDist;
            this.matchLen = matchLen;
            return;
          }
          c01 = dict[pos + matchLen - 1] | (dict[pos + matchLen] << 8);
        }
        continue outer;
      }

      this.matchDist = dist;
      this.matchLen = Math.min(maxMatchLen, MAX_MATCH_LEN);
      return;
    }
  }

  // -- compress_normal -----------------------------------------------------------

  /** `compress_normal` with `TDEFLFlush::Finish`. */
  private compressNormal(inBuf: Uint8Array): void {
    const dict = this.dict;
    const next = this.next;
    const hashTable = this.hash;

    let srcPos = this.srcPos;
    let lookaheadSize = this.lookaheadSize;
    let lookaheadPos = this.lookaheadPos;
    let savedLit = this.savedLit;
    let savedMatchDist = this.savedMatchDist;
    let savedMatchLen = this.savedMatchLen;

    while (srcPos < inBuf.length || lookaheadSize !== 0) {
      const srcBufLeft = inBuf.length - srcPos;
      const numBytesToProcess = Math.min(srcBufLeft, MAX_MATCH_LEN - lookaheadSize);

      if (lookaheadSize + this.dictSize >= MIN_MATCH_LEN - 1 && numBytesToProcess > 0) {
        let dstPos = (lookaheadPos + lookaheadSize) & LZ_DICT_SIZE_MASK;
        let insPos = lookaheadPos + lookaheadSize - 2;
        // update_hash on the first two bytes.
        let hash =
          ((dict[insPos & LZ_DICT_SIZE_MASK] << LZ_HASH_SHIFT) ^
            dict[(insPos + 1) & LZ_DICT_SIZE_MASK]) &
          (LZ_HASH_SIZE - 1);

        lookaheadSize += numBytesToProcess;

        const end = srcPos + numBytesToProcess;
        for (let i = srcPos; i < end; i++) {
          const c = inBuf[i];
          dict[dstPos] = c;
          if (dstPos < MAX_MATCH_LEN - 1) dict[LZ_DICT_SIZE + dstPos] = c;

          hash = ((hash << LZ_HASH_SHIFT) ^ c) & (LZ_HASH_SIZE - 1);
          next[insPos & LZ_DICT_SIZE_MASK] = hashTable[hash];
          hashTable[hash] = insPos & 0xffff;
          dstPos = (dstPos + 1) & LZ_DICT_SIZE_MASK;
          insPos += 1;
        }

        srcPos += numBytesToProcess;
      } else {
        const end = srcPos + numBytesToProcess;
        for (let i = srcPos; i < end; i++) {
          const c = inBuf[i];
          const dstPos = (lookaheadPos + lookaheadSize) & LZ_DICT_SIZE_MASK;
          dict[dstPos] = c;
          if (dstPos < MAX_MATCH_LEN - 1) dict[LZ_DICT_SIZE + dstPos] = c;

          lookaheadSize += 1;
          if (lookaheadSize + this.dictSize >= MIN_MATCH_LEN) {
            const insPos = lookaheadPos + lookaheadSize - 3;
            const hash =
              ((dict[insPos & LZ_DICT_SIZE_MASK] << (LZ_HASH_SHIFT * 2)) ^
                ((dict[(insPos + 1) & LZ_DICT_SIZE_MASK] << LZ_HASH_SHIFT) ^ c)) &
              (LZ_HASH_SIZE - 1);

            next[insPos & LZ_DICT_SIZE_MASK] = hashTable[hash];
            hashTable[hash] = insPos & 0xffff;
          }
        }

        srcPos += numBytesToProcess;
      }

      this.dictSize = Math.min(LZ_DICT_SIZE - lookaheadSize, this.dictSize);
      // (With TDEFLFlush::None the loop would stop here until the lookahead is
      // full; Finish always continues.)

      let lenToMove = 1;
      let curMatchDist = 0;
      let curMatchLen = savedMatchLen !== 0 ? savedMatchLen : MIN_MATCH_LEN - 1;
      const curPos = lookaheadPos & LZ_DICT_SIZE_MASK;

      this.findMatch(lookaheadPos, this.dictSize, lookaheadSize, curMatchDist, curMatchLen);
      curMatchDist = this.matchDist;
      curMatchLen = this.matchLen;

      const farAndSmall = curMatchLen === MIN_MATCH_LEN && curMatchDist >= 8 * 1024;
      if (farAndSmall || curPos === curMatchDist) {
        curMatchDist = 0;
        curMatchLen = 0;
      }

      if (savedMatchLen !== 0) {
        if (curMatchLen > savedMatchLen) {
          this.recordLiteral(savedLit);
          if (curMatchLen >= 128) {
            this.recordMatch(curMatchLen, curMatchDist);
            savedMatchLen = 0;
            lenToMove = curMatchLen;
          } else {
            savedLit = dict[curPos];
            savedMatchDist = curMatchDist;
            savedMatchLen = curMatchLen;
          }
        } else {
          this.recordMatch(savedMatchLen, savedMatchDist);
          lenToMove = savedMatchLen - 1;
          savedMatchLen = 0;
        }
      } else if (curMatchDist === 0) {
        this.recordLiteral(dict[curPos]);
      } else if (this.greedyParsing || curMatchLen >= 128) {
        // Lazy matching defers matches shorter than 128 bytes by one byte.
        this.recordMatch(curMatchLen, curMatchDist);
        lenToMove = curMatchLen;
      } else {
        savedLit = dict[curPos];
        savedMatchDist = curMatchDist;
        savedMatchLen = curMatchLen;
      }

      lookaheadPos += lenToMove;
      if (lookaheadSize < lenToMove) {
        throw new Error("miniz deflate: lookahead underflow");
      }
      lookaheadSize -= lenToMove;
      this.dictSize = Math.min(this.dictSize + lenToMove, LZ_DICT_SIZE);

      const lzBufTight = this.codePosition > LZ_CODE_BUF_SIZE - 8;
      const fat = (this.codePosition * 115) >> 7 >= this.totalBytes;
      const bufFat = this.totalBytes > 31 * 1024 && fat;

      if (lzBufTight || bufFat) {
        this.srcPos = srcPos;
        this.lookaheadSize = lookaheadSize;
        this.lookaheadPos = lookaheadPos;
        this.flushBlock(false);
      }
    }

    this.srcPos = srcPos;
    this.lookaheadSize = lookaheadSize;
    this.lookaheadPos = lookaheadPos;
    this.savedLit = savedLit;
    this.savedMatchDist = savedMatchDist;
    this.savedMatchLen = savedMatchLen;
  }

  // -- flush_block -----------------------------------------------------------------

  /** `flush_block` with `TDEFLFlush::None` (mid-stream) or `Finish`. */
  private flushBlock(finish: boolean): void {
    // A block can need more than OUT_BUF_SIZE bytes only for inputs on which
    // the Rust crate fails as well; reserve enough to detect that afterwards.
    this.ensureOutCapacity(this.outPos + 2 * OUT_BUF_SIZE);
    const blockStart = this.outPos;

    this.bitBuffer = this.savedBitBuffer;
    this.bitsIn = this.savedBitsIn;

    this.initFlag();

    // Block header: BFINAL.
    this.putBits(finish ? 1 : 0, 1);

    const savedPos = this.outPos;
    const savedBitBuffer = this.bitBuffer;
    const savedBitsIn = this.bitsIn;

    const useStatic = this.totalBytes < 48;
    this.compressBlock(useStatic);

    // If the compressed block is not smaller than the input, emit a stored
    // block instead.
    const expanded =
      this.totalBytes > 32 &&
      this.outPos - savedPos + 1 >= this.totalBytes &&
      this.lookaheadPos - this.codeBufDictPos <= this.dictSize;

    if (expanded) {
      this.outPos = savedPos;
      this.bitBuffer = savedBitBuffer;
      this.bitsIn = savedBitsIn;

      this.putBits(0, 2);
      this.padToBytes();
      this.putBits(this.totalBytes & 0xffff, 16);
      this.putBits(~this.totalBytes & 0xffff, 16);

      const start = this.codeBufDictPos & LZ_DICT_SIZE_MASK;
      const end = (this.codeBufDictPos + this.totalBytes) & LZ_DICT_SIZE_MASK;
      if (start < end) {
        this.out.set(this.dict.subarray(start, end), this.outPos);
        this.outPos += end - start;
      } else if (this.totalBytes > 0) {
        this.out.set(this.dict.subarray(start, LZ_DICT_SIZE), this.outPos);
        this.outPos += LZ_DICT_SIZE - start;
        this.out.set(this.dict.subarray(0, end), this.outPos);
        this.outPos += end;
      }
    }

    if (finish) this.padToBytes();

    this.count[LITLEN_TABLE].fill(0, 0, MAX_HUFF_SYMBOLS_0);
    this.count[DIST_TABLE].fill(0, 0, MAX_HUFF_SYMBOLS_1);

    // Clear the LZ buffer for the next block.
    this.codePosition = 1;
    this.flagPosition = 0;
    this.numFlagsLeft = 8;
    this.codeBufDictPos += this.totalBytes;
    this.totalBytes = 0;
    this.blockIndex += 1;

    this.savedBitBuffer = this.bitBuffer;
    this.savedBitsIn = this.bitsIn;

    if (this.outPos - blockStart > OUT_BUF_SIZE - 16) {
      // The Rust crate's per-block output buffer would have overflowed here.
      throw new Error("miniz deflate: block output exceeds the output buffer");
    }
  }

  /** `compress_block` */
  private compressBlock(staticBlock: boolean): void {
    if (staticBlock) {
      this.startStaticBlock();
    } else {
      this.startDynamicBlock();
    }
    this.compressLzCodes();
  }

  /** `compress_lz_codes`: Huffman-code the LZ buffer and the end-of-block symbol. */
  private compressLzCodes(): void {
    const lz = this.lzCodes;
    const codes0 = this.codes[LITLEN_TABLE];
    const sizes0 = this.codeSizes[LITLEN_TABLE];
    const codes1 = this.codes[DIST_TABLE];
    const sizes1 = this.codeSizes[DIST_TABLE];
    const usedLen = Math.min(LZ_CODE_BUF_SIZE, this.codePosition);

    let flags = 1;
    let i = 0;
    while (i < usedLen) {
      if (flags === 1) {
        flags = lz[i] | 0x100;
        i += 1;
      }

      if ((flags & 1) === 1) {
        // A match.
        flags >>= 1;

        const matchLen = lz[i & LZ_CODE_BUF_MASK];
        const matchDist = lz[(i + 1) & LZ_CODE_BUF_MASK] | (lz[(i + 2) & LZ_CODE_BUF_MASK] << 8);
        i += 3;

        const lenSym = (LEN_SYM[matchLen] & 31) + LEN_SYM_OFFSET;
        this.putBits(codes0[lenSym], sizes0[lenSym]);
        this.putBits(matchLen & BITMASKS[LEN_EXTRA[matchLen] & 7], LEN_EXTRA[matchLen]);

        let sym: number;
        let numExtraBits: number;
        if (matchDist < 512) {
          sym = SMALL_DIST_SYM[matchDist];
          numExtraBits = SMALL_DIST_EXTRA[matchDist];
        } else {
          sym = LARGE_DIST_SYM[matchDist >> 8];
          numExtraBits = LARGE_DIST_EXTRA[matchDist >> 8];
        }
        this.putBits(codes1[sym], sizes1[sym]);
        this.putBits(matchDist & BITMASKS[numExtraBits & 15], numExtraBits);
      } else {
        // Up to three literals.
        for (let k = 0; k < 3; k++) {
          flags >>= 1;
          const lit = lz[i & LZ_CODE_BUF_MASK];
          i += 1;
          this.putBits(codes0[lit], sizes0[lit]);
          if ((flags & 1) === 1 || i >= usedLen) break;
        }
      }
    }

    // End of block.
    this.putBits(codes0[256], sizes0[256]);
  }

  // -- HuffmanOxide ------------------------------------------------------------------

  /** `start_static_block` */
  private startStaticBlock(): void {
    const lit = this.codeSizes[LITLEN_TABLE];
    lit.fill(8, 0, 144);
    lit.fill(9, 144, 256);
    lit.fill(7, 256, 280);
    lit.fill(8, 280, 288);
    this.codeSizes[DIST_TABLE].fill(5, 0, 32);

    this.optimizeTable(LITLEN_TABLE, 288, 15, true);
    this.optimizeTable(DIST_TABLE, 32, 15, true);

    this.putBits(0b01, 2);
  }

  /** `start_dynamic_block` */
  private startDynamicBlock(): void {
    // There is always exactly one end-of-block code.
    this.count[LITLEN_TABLE][256] = 1;

    this.optimizeTable(LITLEN_TABLE, MAX_HUFF_SYMBOLS_0, 15, false);
    this.optimizeTable(DIST_TABLE, MAX_HUFF_SYMBOLS_1, 15, false);

    const litSizes = this.codeSizes[LITLEN_TABLE];
    const distSizes = this.codeSizes[DIST_TABLE];

    let numLitCodes = 286;
    while (numLitCodes > 257 && litSizes[numLitCodes - 1] === 0) numLitCodes -= 1;
    let numDistCodes = 30;
    while (numDistCodes > 1 && distSizes[numDistCodes - 1] === 0) numDistCodes -= 1;

    const codeSizesToPack = this.codeSizesToPack;
    const packed = this.packedCodeSizes;
    const totalCodeSizesToPack = numLitCodes + numDistCodes;
    codeSizesToPack.set(litSizes.subarray(0, numLitCodes), 0);
    codeSizesToPack.set(distSizes.subarray(0, numDistCodes), numLitCodes);

    const counts = this.count[HUFF_CODES_TABLE];
    counts.fill(0, 0, MAX_HUFF_SYMBOLS_2);

    // Run-length encode the code sizes (struct Rle).
    let packedPos = 0;
    let zCount = 0;
    let repeatCount = 0;
    let prevCodeSize = 0xff;

    const rlePrevCodeSize = (): void => {
      if (repeatCount !== 0) {
        if (repeatCount < 3) {
          counts[prevCodeSize] += repeatCount;
          for (let k = 0; k < repeatCount; k++) packed[packedPos++] = prevCodeSize;
        } else {
          counts[16] += 1;
          packed[packedPos++] = 16;
          packed[packedPos++] = repeatCount - 3;
        }
        repeatCount = 0;
      }
    };
    const rleZeroCodeSize = (): void => {
      if (zCount !== 0) {
        if (zCount < 3) {
          counts[0] += zCount;
          for (let k = 0; k < zCount; k++) packed[packedPos++] = 0;
        } else if (zCount <= 10) {
          counts[17] += 1;
          packed[packedPos++] = 17;
          packed[packedPos++] = zCount - 3;
        } else {
          counts[18] += 1;
          packed[packedPos++] = 18;
          packed[packedPos++] = zCount - 11;
        }
        zCount = 0;
      }
    };

    for (let i = 0; i < totalCodeSizesToPack; i++) {
      const codeSize = codeSizesToPack[i];
      if (codeSize === 0) {
        rlePrevCodeSize();
        zCount += 1;
        if (zCount === 138) rleZeroCodeSize();
      } else {
        rleZeroCodeSize();
        if (codeSize !== prevCodeSize) {
          rlePrevCodeSize();
          counts[codeSize] += 1;
          packed[packedPos++] = codeSize;
        } else {
          repeatCount += 1;
          if (repeatCount === 6) rlePrevCodeSize();
        }
      }
      prevCodeSize = codeSize;
    }

    if (repeatCount !== 0) {
      rlePrevCodeSize();
    } else {
      rleZeroCodeSize();
    }

    this.optimizeTable(HUFF_CODES_TABLE, MAX_HUFF_SYMBOLS_2, 7, false);

    this.putBits(2, 2);
    this.putBits(numLitCodes - 257, 5);
    this.putBits(numDistCodes - 1, 5);

    const hcSizes = this.codeSizes[HUFF_CODES_TABLE];
    let trailingZero = 0;
    for (let k = HUFFMAN_LENGTH_ORDER.length - 1; k >= 0; k--) {
      if (hcSizes[HUFFMAN_LENGTH_ORDER[k]] !== 0) break;
      trailingZero += 1;
    }
    let numBitLengths = 18 - trailingZero;
    numBitLengths = Math.max(4, numBitLengths + 1);
    this.putBits(numBitLengths - 4, 4);
    for (let k = 0; k < numBitLengths; k++) {
      this.putBits(hcSizes[HUFFMAN_LENGTH_ORDER[k]], 3);
    }

    const hcCodes = this.codes[HUFF_CODES_TABLE];
    let packedCodeSizeIndex = 0;
    while (packedCodeSizeIndex < packedPos) {
      const code = packed[packedCodeSizeIndex];
      packedCodeSizeIndex += 1;
      this.putBits(hcCodes[code], hcSizes[code]);
      if (code >= 16) {
        this.putBits(packed[packedCodeSizeIndex], code === 16 ? 2 : code === 17 ? 3 : 7);
        packedCodeSizeIndex += 1;
      }
    }
  }

  /**
   * `optimize_table`: derive code sizes (unless `staticTable`) and canonical
   * codes for one table.
   */
  private optimizeTable(
    tableNum: number,
    tableLen: number,
    codeSizeLimit: number,
    staticTable: boolean,
  ): void {
    const numCodes = this.numCodes;
    const nextCode = this.nextCode;
    const codeSizes = this.codeSizes[tableNum];
    const codes = this.codes[tableNum];
    numCodes.fill(0);
    nextCode.fill(0);

    if (staticTable) {
      for (let i = 0; i < tableLen; i++) numCodes[codeSizes[i]] += 1;
    } else {
      const count = this.count[tableNum];
      let numUsedSymbols = 0;
      for (let i = 0; i < tableLen; i++) {
        if (count[i] !== 0) {
          this.symKeys0[numUsedSymbols] = count[i];
          this.symIdx0[numUsedSymbols] = i;
          numUsedSymbols += 1;
        }
      }

      const inSecond = this.radixSortSymbols(numUsedSymbols);
      const keys = inSecond ? this.symKeys1 : this.symKeys0;
      const idx = inSecond ? this.symIdx1 : this.symIdx0;
      calculateMinimumRedundancy(keys, numUsedSymbols);

      for (let i = 0; i < numUsedSymbols; i++) numCodes[keys[i]] += 1;

      enforceMaxCodeSize(numCodes, numUsedSymbols, codeSizeLimit);

      codeSizes.fill(0);
      codes.fill(0);

      let last = numUsedSymbols;
      for (let i = 1; i <= codeSizeLimit; i++) {
        const first = last - numCodes[i];
        for (let s = first; s < last; s++) codeSizes[idx[s]] = i;
        last = first;
      }
    }

    let j = 0;
    nextCode[1] = 0;
    for (let i = 2; i <= codeSizeLimit; i++) {
      j = (j + numCodes[i - 1]) << 1;
      nextCode[i] = j;
    }

    for (let i = 0; i < tableLen; i++) {
      const codeSize = codeSizes[i];
      if (codeSize === 0) continue;
      const code = nextCode[codeSize];
      nextCode[codeSize] += 1;
      codes[i] = reverseBits16(code & 0xffff) >>> (16 - codeSize);
    }
  }

  /**
   * `radix_sort_symbols`: stable sort of the `numUsedSymbols` (key, index)
   * pairs in buffer 0 by key. Returns whether the result ended up in buffer 1.
   */
  private radixSortSymbols(numUsedSymbols: number): boolean {
    const hist0 = this.hist0;
    const hist1 = this.hist1;
    const offsets = this.offsets;
    hist0.fill(0);
    hist1.fill(0);

    for (let i = 0; i < numUsedSymbols; i++) {
      const key = this.symKeys0[i];
      hist0[key & 0xff] += 1;
      hist1[(key >> 8) & 0xff] += 1;
    }

    let nPasses = 2;
    if (numUsedSymbols === hist1[0]) nPasses -= 1;

    let curKeys = this.symKeys0;
    let curIdx = this.symIdx0;
    let newKeys = this.symKeys1;
    let newIdx = this.symIdx1;
    let inSecond = false;

    for (let pass = 0; pass < nPasses; pass++) {
      const hist = pass === 0 ? hist0 : hist1;
      let offset = 0;
      for (let i = 0; i < 256; i++) {
        offsets[i] = offset;
        offset += hist[i];
      }
      const shift = pass * 8;
      for (let i = 0; i < numUsedSymbols; i++) {
        const key = curKeys[i];
        const j = (key >> shift) & 0xff;
        const o = offsets[j];
        offsets[j] = o + 1;
        newKeys[o] = key;
        newIdx[o] = curIdx[i];
      }
      const tk = curKeys;
      curKeys = newKeys;
      newKeys = tk;
      const ti = curIdx;
      curIdx = newIdx;
      newIdx = ti;
      inSecond = !inSecond;
    }

    return inSecond;
  }
}

/**
 * `calculate_minimum_redundancy` (Moffat & Katajainen in-place algorithm):
 * turns the sorted frequencies in `keys[0..n]` into code lengths.
 */
function calculateMinimumRedundancy(keys: Uint16Array, n: number): void {
  if (n === 0) return;
  if (n === 1) {
    keys[0] = 1;
    return;
  }

  keys[0] += keys[1];
  let root = 0;
  let leaf = 2;
  for (let next = 1; next < n - 1; next++) {
    if (leaf >= n || keys[root] < keys[leaf]) {
      keys[next] = keys[root];
      keys[root] = next;
      root += 1;
    } else {
      keys[next] = keys[leaf];
      leaf += 1;
    }

    if (leaf >= n || (root < next && keys[root] < keys[leaf])) {
      keys[next] = keys[next] + keys[root];
      keys[root] = next;
      root += 1;
    } else {
      keys[next] = keys[next] + keys[leaf];
      leaf += 1;
    }
  }

  keys[n - 2] = 0;
  for (let next = n - 3; next >= 0; next--) {
    keys[next] = keys[keys[next]] + 1;
  }

  let avbl = 1;
  let used = 0;
  let dpth = 0;
  let root2 = n - 2;
  let next2 = n - 1;
  while (avbl > 0) {
    while (root2 >= 0 && keys[root2] === dpth) {
      used += 1;
      root2 -= 1;
    }
    while (avbl > used) {
      keys[next2] = dpth;
      next2 -= 1;
      avbl -= 1;
    }
    avbl = 2 * used;
    dpth += 1;
    used = 0;
  }
}

/** `enforce_max_code_size`: limit code lengths to `maxCodeSize` bits. */
function enforceMaxCodeSize(numCodes: Int32Array, codeListLen: number, maxCodeSize: number): void {
  if (codeListLen <= 1) return;

  let overflow = 0;
  for (let i = maxCodeSize + 1; i < numCodes.length; i++) overflow += numCodes[i];
  numCodes[maxCodeSize] += overflow;

  let total = 0;
  for (let i = 1; i <= maxCodeSize; i++) total += numCodes[i] << (maxCodeSize - i);

  for (let t = 1 << maxCodeSize; t < total; t++) {
    numCodes[maxCodeSize] -= 1;
    for (let i = maxCodeSize - 1; i >= 1; i--) {
      if (numCodes[i] !== 0) {
        numCodes[i] -= 1;
        numCodes[i + 1] += 2;
        break;
      }
    }
  }
}

/**
 * Compresses `input` into a raw DEFLATE stream (RFC 1951, no zlib header),
 * producing exactly the bytes `miniz_oxide::deflate::compress_to_vec(input,
 * level)` produces.
 *
 * Supported levels are 2 through 10 (the `compress_normal` code path). Level 0
 * (stored blocks) and level 1 (`compress_fast`) use different compressors that
 * are not part of this port and are rejected with a `RangeError`.
 */
export function compressToVec(input: Uint8Array, level: number): Uint8Array {
  if (!Number.isInteger(level) || level < 2 || level > 10) {
    throw new RangeError(`unsupported compression level ${level}; supported levels are 2 to 10`);
  }
  const flags = createCompFlagsFromZipParams(level, 0, 0);
  if ((flags & UNSUPPORTED_FLAGS) !== 0 || (flags & MAX_PROBES_MASK) === 1) {
    throw new RangeError(`unsupported compression level ${level}; supported levels are 2 to 10`);
  }
  return new Deflater(flags, input.length).compress(input);
}
