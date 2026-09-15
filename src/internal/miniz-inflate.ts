/**
 * Raw DEFLATE decompressor.
 *
 * This is a literal port of the decompressor in `miniz_oxide` 0.8.9
 * (`inflate/core.rs` and `decompress_to_vec` in `inflate/mod.rs`): the same
 * state machine, the same Huffman table construction (`init_tree`, including
 * its acceptance of single-symbol literal/length and distance tables), the
 * same fast and slow decoding paths and the same 64-bit bit buffer, so that a
 * stream is accepted or rejected exactly where the Rust crate accepts or
 * rejects it, with the same `TINFLStatus`. Names in comments refer to the Rust
 * functions and states.
 *
 * Only raw streams are handled (no zlib header, no adler32) and the output
 * buffer is always used in the non-wrapping mode, which is what
 * `decompress_to_vec` does.
 */

// ---------------------------------------------------------------------------
// Status codes (TINFLStatus)
// ---------------------------------------------------------------------------

const TINFL_STATUS_FAILED_CANNOT_MAKE_PROGRESS = -4;
const TINFL_STATUS_BAD_PARAM = -3;
const TINFL_STATUS_ADLER32_MISMATCH = -2;
const TINFL_STATUS_FAILED = -1;
const TINFL_STATUS_DONE = 0;
const TINFL_STATUS_NEEDS_MORE_INPUT = 1;
const TINFL_STATUS_HAS_MORE_OUTPUT = 2;

/** Names of the `TINFLStatus` variants of miniz_oxide. */
export type InflateStatus =
  | "FailedCannotMakeProgress"
  | "BadParam"
  | "Adler32Mismatch"
  | "Failed"
  | "Done"
  | "NeedsMoreInput"
  | "HasMoreOutput";

function statusName(status: number): InflateStatus {
  switch (status) {
    case TINFL_STATUS_FAILED_CANNOT_MAKE_PROGRESS:
      return "FailedCannotMakeProgress";
    case TINFL_STATUS_BAD_PARAM:
      return "BadParam";
    case TINFL_STATUS_ADLER32_MISMATCH:
      return "Adler32Mismatch";
    case TINFL_STATUS_FAILED:
      return "Failed";
    case TINFL_STATUS_DONE:
      return "Done";
    case TINFL_STATUS_NEEDS_MORE_INPUT:
      return "NeedsMoreInput";
    default:
      return "HasMoreOutput";
  }
}

function statusMessage(status: InflateStatus): string {
  switch (status) {
    case "FailedCannotMakeProgress":
    case "NeedsMoreInput":
      return "Truncated input stream";
    case "BadParam":
      return "Invalid output buffer size";
    case "Adler32Mismatch":
      return "Adler32 checksum mismatch";
    case "Failed":
      return "Invalid input data";
    case "HasMoreOutput":
      return "Output size exceeded the specified limit";
    case "Done":
      return "";
  }
}

/**
 * Error thrown by {@link decompressToVec}, the counterpart of
 * `miniz_oxide::inflate::DecompressError`.
 */
export class InflateError extends Error {
  /** The `TINFLStatus` the Rust crate reports for this stream. */
  readonly status: InflateStatus;
  /** The data decompressed before the failure. */
  readonly output: Uint8Array;

  constructor(status: InflateStatus, output: Uint8Array) {
    super(statusMessage(status));
    this.name = "InflateError";
    this.status = status;
    this.output = output;
  }
}

// ---------------------------------------------------------------------------
// Constants (inflate/core.rs)
// ---------------------------------------------------------------------------

const MAX_HUFF_TABLES = 3;
const MAX_HUFF_SYMBOLS_0 = 288;
const MAX_HUFF_SYMBOLS_1 = 32;
const MAX_HUFF_SYMBOLS_2 = 19;
const FAST_LOOKUP_BITS = 10;
const FAST_LOOKUP_SIZE = 1 << FAST_LOOKUP_BITS;
const MAX_HUFF_TREE_SIZE = MAX_HUFF_SYMBOLS_0 * 2;
const LITLEN_TABLE = 0;
const DIST_TABLE = 1;
const HUFFLEN_TABLE = 2;
const LEN_CODES_SIZE = 512;
const LEN_CODES_MASK = LEN_CODES_SIZE - 1;
/** `INVALID_CODE` in init_tree: a non-zero length with an invalid symbol. */
const INVALID_CODE = (1 << 9) | 286;

/** `inflate_flags` */
const TINFL_FLAG_HAS_MORE_INPUT = 2;
const TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF = 4;

const MIN_TABLE_SIZES: Uint16Array = new Uint16Array([257, 1, 4]);

const HUFFMAN_LENGTH_ORDER: Uint8Array = new Uint8Array([
  16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
]);

/** Base length for each length code (padded to 32 entries for masking). */
const LENGTH_BASE: Uint16Array = new Uint16Array([
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
  163, 195, 227, 258, 512, 512, 512,
]);

/** Number of extra bits for each length code. */
const LENGTH_EXTRA: Uint8Array = new Uint8Array([
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 0, 0, 0,
]);

/** Base value for each distance code. */
const DIST_BASE: Uint16Array = new Uint16Array([
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049,
  3073, 4097, 6145, 8193, 12289, 16385, 24577,
]);

const BASE_EXTRA_MASK = 32 - 1;

/** `num_extra_bits_for_distance_code` */
function numExtraBitsForDistanceCode(code: number): number {
  const c = code >> 1;
  return c > 1 ? c - 1 : 0;
}

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

// ---------------------------------------------------------------------------
// States (enum State)
// ---------------------------------------------------------------------------

const S_START = 0;
const S_READ_BLOCK_HEADER = 3;
const S_BLOCK_TYPE_NO_COMPRESSION = 4;
const S_RAW_HEADER = 5;
const S_RAW_MEMCPY1 = 6;
const S_RAW_MEMCPY2 = 7;
const S_READ_TABLE_SIZES = 8;
const S_READ_HUFFLEN_TABLE_CODE_SIZE = 9;
const S_READ_LITLEN_DIST_TABLES_CODE_SIZE = 10;
const S_READ_EXTRA_BITS_CODE_SIZE = 11;
const S_DECODE_LITLEN = 12;
const S_WRITE_SYMBOL = 13;
const S_READ_EXTRA_BITS_LITLEN = 14;
const S_DECODE_DISTANCE = 15;
const S_READ_EXTRA_BITS_DISTANCE = 16;
const S_RAW_READ_FIRST_BYTE = 17;
const S_RAW_STORE_FIRST_BYTE = 18;
const S_WRITE_LEN_BYTES_TO_END = 19;
const S_BLOCK_DONE = 20;
const S_HUFF_DECODE_OUTER_LOOP1 = 21;
const S_HUFF_DECODE_OUTER_LOOP2 = 22;
const S_DONE_FOREVER = 24;
// Failure states.
const S_BLOCK_TYPE_UNEXPECTED = 25;
const S_BAD_CODE_SIZE_SUM = 26;
const S_BAD_DIST_OR_LITERAL_TABLE_LENGTH = 27;
const S_BAD_TOTAL_SYMBOLS = 28;
const S_DISTANCE_OUT_OF_BOUNDS = 30;
const S_BAD_RAW_LENGTH = 31;
const S_BAD_CODE_SIZE_DIST_PREV_LOOKUP = 32;
const S_INVALID_LITLEN = 33;
const S_INVALID_DIST = 34;

/** Marker returned by `initTree` where the Rust function returns `None`. */
const INIT_TREE_FAILED = -1;

// ---------------------------------------------------------------------------
// Decompressor state (DecompressorOxide)
// ---------------------------------------------------------------------------

/** `HuffmanTable`: fast lookup table plus the tree for longer codes. */
class HuffmanTable {
  /** Symbol in the low 9 bits, code length in the next 6; negative = tree. */
  readonly lookUp: Int16Array = new Int16Array(FAST_LOOKUP_SIZE);
  /** Positive values are symbols, negative values reference other nodes. */
  readonly tree: Int16Array = new Int16Array(MAX_HUFF_TREE_SIZE);
}

class Decompressor {
  state = S_START;
  numBits = 0;
  /** Low and high halves of the 64-bit bit buffer. */
  bitLo = 0;
  bitHi = 0;
  finish = 0;
  blockType = 0;
  dist = 0;
  counter = 0;
  numExtra = 0;
  readonly tableSizes: Uint16Array = new Uint16Array(MAX_HUFF_TABLES);
  readonly tables: HuffmanTable[] = [new HuffmanTable(), new HuffmanTable(), new HuffmanTable()];
  readonly codeSizeLiteral: Uint8Array = new Uint8Array(MAX_HUFF_SYMBOLS_0);
  readonly codeSizeDist: Uint8Array = new Uint8Array(MAX_HUFF_SYMBOLS_1);
  readonly codeSizeHuffman: Uint8Array = new Uint8Array(MAX_HUFF_SYMBOLS_2);
  readonly rawHeader: Uint8Array = new Uint8Array(4);
  readonly lenCodes: Uint8Array = new Uint8Array(LEN_CODES_SIZE);
  // Scratch for init_tree.
  readonly totalSymbols: Uint16Array = new Uint16Array(16);
  readonly nextCode: Uint32Array = new Uint32Array(17);
}

/**
 * Working variables of one `decompress` call (`LocalVars` plus the input and
 * output cursors).
 */
class Ctx {
  bitLo = 0;
  bitHi = 0;
  numBits = 0;
  dist = 0;
  counter = 0;
  numExtra = 0;
  inPos = 0;
  outPos = 0;

  constructor(
    readonly inBuf: Uint8Array,
    readonly out: Uint8Array,
    readonly flags: number,
  ) {}
}

// ---------------------------------------------------------------------------
// 64-bit bit buffer helpers
// ---------------------------------------------------------------------------

/** `bit_buf |= value << num_bits` for a value of at most 32 bits. */
function addBits(c: Ctx, value: number, at: number): void {
  if (at < 32) {
    c.bitLo = (c.bitLo | (value << at)) >>> 0;
    if (at !== 0) c.bitHi = (c.bitHi | (value >>> (32 - at))) >>> 0;
  } else {
    c.bitHi = (c.bitHi | (value << (at - 32))) >>> 0;
  }
}

/** `bit_buf >>= n` for 0 <= n <= 32. */
function shiftRight(c: Ctx, n: number): void {
  if (n === 0) return;
  if (n >= 32) {
    c.bitLo = c.bitHi >>> (n - 32);
    c.bitHi = 0;
  } else {
    c.bitLo = ((c.bitLo >>> n) | (c.bitHi << (32 - n))) >>> 0;
    c.bitHi >>>= n;
  }
}

/** `bit_buf & ((1 << n) - 1)` for 0 <= n <= 32. */
function lowBits(c: Ctx, n: number): number {
  if (n >= 32) return c.bitLo;
  return (c.bitLo & ((1 << n) - 1)) >>> 0;
}

/** `bit_buf &= (1 << num_bits) - 1` */
function maskToNumBits(c: Ctx): void {
  const n = c.numBits;
  if (n >= 64) return;
  if (n >= 32) {
    c.bitHi = n === 32 ? 0 : (c.bitHi & ((1 << (n - 32)) - 1)) >>> 0;
  } else {
    c.bitHi = 0;
    c.bitLo = n === 0 ? 0 : (c.bitLo & ((1 << n) - 1)) >>> 0;
  }
}

/**
 * `fill_bit_buffer` (64-bit variant): reads four bytes at once when fewer
 * than 30 bits are buffered. Assumes at least 4 input bytes are left.
 */
function fillBitBuffer(c: Ctx): void {
  if (c.numBits < 30) {
    const b = c.inBuf;
    const p = c.inPos;
    const v = (b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24)) >>> 0;
    c.inPos = p + 4;
    addBits(c, v, c.numBits);
    c.numBits += 32;
  }
}

/** `end_of_input` */
function endOfInput(flags: number): number {
  return (flags & TINFL_FLAG_HAS_MORE_INPUT) !== 0
    ? TINFL_STATUS_NEEDS_MORE_INPUT
    : TINFL_STATUS_FAILED_CANNOT_MAKE_PROGRESS;
}

/**
 * `read_bits`: returns the bits, or -1 when the input ran out (the status is
 * then `endOfInput(flags)`).
 */
function readBits(c: Ctx, amount: number): number {
  while (c.numBits < amount) {
    if (c.inPos >= c.inBuf.length) return -1;
    addBits(c, c.inBuf[c.inPos], c.numBits);
    c.inPos += 1;
    c.numBits += 8;
  }
  const bits = lowBits(c, amount);
  shiftRight(c, amount);
  c.numBits -= amount;
  return bits;
}

/** `pad_to_bytes` */
function padToBytes(c: Ctx): number {
  return readBits(c, c.numBits & 7);
}

// ---------------------------------------------------------------------------
// Huffman lookup
// ---------------------------------------------------------------------------

/** Code length of the symbol returned by the last `lookup`. */
let lookupLen = 0;

/**
 * `HuffmanTable::lookup`: returns the symbol (still carrying the length bits
 * when it came from the fast table, as in Rust) and stores the code length in
 * `lookupLen`.
 */
function lookup(table: HuffmanTable, bitLo: number): number {
  let symbol = table.lookUp[bitLo & (FAST_LOOKUP_SIZE - 1)];
  if (symbol >= 0) {
    lookupLen = symbol >> 9;
    return symbol;
  }
  // tree_lookup
  const tree = table.tree;
  let codeLen = FAST_LOOKUP_BITS;
  do {
    const treeIndex = ~symbol + ((bitLo >>> codeLen) & 1);
    symbol = treeIndex < tree.length ? tree[treeIndex] : 32767;
    codeLen += 1;
  } while (symbol < 0);
  lookupLen = codeLen;
  return symbol;
}

/**
 * `decode_huffman_code`: returns the decoded symbol, or -1 when the input ran
 * out.
 */
function decodeHuffmanCode(r: Decompressor, c: Ctx, tableIndex: number): number {
  const table = r.tables[tableIndex];
  if (c.numBits < 15) {
    if (c.inBuf.length - c.inPos < 2) {
      // Fewer than two bytes left: read only as many bytes as needed to
      // decode the next code.
      for (;;) {
        let temp = table.lookUp[c.bitLo & (FAST_LOOKUP_SIZE - 1)];
        if (temp >= 0) {
          const codeLen = temp >> 9;
          if (codeLen !== 0 && c.numBits >= codeLen) break;
        } else if (c.numBits > FAST_LOOKUP_BITS) {
          let codeLen = FAST_LOOKUP_BITS;
          do {
            const treeIndex = ~temp + ((c.bitLo >>> codeLen) & 1);
            temp = treeIndex < table.tree.length ? table.tree[treeIndex] : 32767;
            codeLen += 1;
          } while (!(temp >= 0 || c.numBits < codeLen + 1));
          if (temp >= 0) break;
        }

        if (c.inPos >= c.inBuf.length) return -1;
        addBits(c, c.inBuf[c.inPos], c.numBits);
        c.inPos += 1;
        c.numBits += 8;

        if (c.numBits >= 15) break;
      }
    } else {
      const b = c.inBuf;
      const p = c.inPos;
      addBits(c, b[p] | (b[p + 1] << 8), c.numBits);
      c.inPos = p + 2;
      c.numBits += 16;
    }
  }

  let symbol = table.lookUp[c.bitLo & (FAST_LOOKUP_SIZE - 1)];
  let codeLen: number;
  if (symbol >= 0) {
    codeLen = symbol >> 9;
    symbol &= 511;
  } else {
    symbol = lookup(table, c.bitLo);
    codeLen = lookupLen;
  }

  shiftRight(c, codeLen);
  c.numBits -= codeLen;
  return symbol;
}

// ---------------------------------------------------------------------------
// Table construction
// ---------------------------------------------------------------------------

/** `start_static_table` */
function startStaticTable(r: Decompressor): void {
  r.tableSizes[LITLEN_TABLE] = 288;
  r.tableSizes[DIST_TABLE] = 32;
  r.codeSizeLiteral.fill(8, 0, 144);
  r.codeSizeLiteral.fill(9, 144, 256);
  r.codeSizeLiteral.fill(7, 256, 280);
  r.codeSizeLiteral.fill(8, 280, 288);
  r.codeSizeDist.fill(5, 0, 32);
}

/**
 * `init_tree`: builds the lookup table and tree for the table selected by
 * `r.blockType` (and the ones below it). Returns the next state, or
 * `INIT_TREE_FAILED` where the Rust function returns `None`.
 */
function initTree(r: Decompressor, c: Ctx): number {
  for (;;) {
    const bt = r.blockType;
    let codeSizes: Uint8Array;
    if (bt === LITLEN_TABLE) {
      codeSizes = r.codeSizeLiteral;
    } else if (bt === DIST_TABLE) {
      codeSizes = r.codeSizeDist;
    } else if (bt === HUFFLEN_TABLE) {
      codeSizes = r.codeSizeHuffman;
    } else {
      return INIT_TREE_FAILED;
    }
    const table = r.tables[bt];
    const totalSymbols = r.totalSymbols;
    const nextCode = r.nextCode;
    totalSymbols.fill(0);
    nextCode.fill(0);

    table.lookUp.fill(INVALID_CODE);
    // The code length table never needs the tree (codes are at most 7 bits).
    if (bt !== HUFFLEN_TABLE) table.tree.fill(0);

    const tableSize = r.tableSizes[bt];
    if (tableSize > codeSizes.length) return INIT_TREE_FAILED;

    for (let i = 0; i < tableSize; i++) {
      const cs = codeSizes[i];
      if (cs >= totalSymbols.length) return INIT_TREE_FAILED;
      totalSymbols[cs] += 1;
    }

    let usedSymbols = 0;
    let total = 0;
    for (let k = 1; k < 16; k++) {
      const ts = totalSymbols[k];
      usedSymbols += ts;
      total = (total + ts) * 2;
      nextCode[k + 1] = total;
    }

    // A table must be complete, except that the literal/length and distance
    // tables may hold a single symbol (or none); the code length table may not.
    if (total !== 65536 && (usedSymbols > 1 || bt === HUFFLEN_TABLE)) {
      return S_BAD_TOTAL_SYMBOLS;
    }

    let treeNext = -1;
    for (let symbolIndex = 0; symbolIndex < tableSize; symbolIndex++) {
      const codeSize = codeSizes[symbolIndex] & 15;
      if (codeSize === 0) continue;

      const curCode = nextCode[codeSize];
      nextCode[codeSize] += 1;

      const n = curCode & ((1 << codeSize) - 1) & 0xffff;
      let revCode = reverseBits16(n) >>> (16 - codeSize);

      if (codeSize <= FAST_LOOKUP_BITS) {
        const k = (codeSize << 9) | symbolIndex;
        while (revCode < FAST_LOOKUP_SIZE) {
          table.lookUp[revCode] = k;
          revCode += 1 << codeSize;
        }
        continue;
      }

      let treeCur = table.lookUp[revCode & (FAST_LOOKUP_SIZE - 1)];
      if (treeCur === INVALID_CODE) {
        table.lookUp[revCode & (FAST_LOOKUP_SIZE - 1)] = treeNext;
        treeCur = treeNext;
        treeNext -= 2;
      }

      revCode >>= FAST_LOOKUP_BITS - 1;
      for (let j = FAST_LOOKUP_BITS + 1; j < codeSize; j++) {
        revCode >>= 1;
        treeCur -= revCode & 1;
        const treeIndex = -treeCur - 1;
        if (treeIndex >= table.tree.length) return INIT_TREE_FAILED;
        if (table.tree[treeIndex] === 0) {
          table.tree[treeIndex] = treeNext;
          treeCur = treeNext;
          treeNext -= 2;
        } else {
          treeCur = table.tree[treeIndex];
        }
      }

      revCode >>= 1;
      treeCur -= revCode & 1;
      const treeIndex = -treeCur - 1;
      if (treeIndex >= table.tree.length) return INIT_TREE_FAILED;
      table.tree[treeIndex] = symbolIndex;
    }

    if (r.blockType === HUFFLEN_TABLE) {
      c.counter = 0;
      return S_READ_LITLEN_DIST_TABLES_CODE_SIZE;
    }

    if (r.blockType === LITLEN_TABLE) break;
    r.blockType -= 1;
  }

  c.counter = 0;
  return S_DECODE_LITLEN;
}

// ---------------------------------------------------------------------------
// Match copying (apply_match / transfer, non-wrapping output)
// ---------------------------------------------------------------------------

/**
 * Copies `matchLen` bytes from `dist` bytes back, replicating the source when
 * it overlaps the destination (the LZ77 semantics `transfer` implements).
 */
function applyMatch(out: Uint8Array, outPos: number, dist: number, matchLen: number): void {
  const src = outPos - dist;
  if (dist >= matchLen) {
    out.copyWithin(outPos, src, src + matchLen);
  } else if (dist === 1) {
    out.fill(out[src], outPos, outPos + matchLen);
  } else {
    for (let i = 0; i < matchLen; i++) out[outPos + i] = out[src + i];
  }
}

// ---------------------------------------------------------------------------
// Fast path (decompress_fast)
// ---------------------------------------------------------------------------

/**
 * `decompress_fast`: inner loop run while at least 259 output bytes and 14
 * input bytes are available. Returns the status and leaves the next state in
 * `r.state`.
 */
function decompressFast(r: Decompressor, c: Ctx): number {
  const inBuf = c.inBuf;
  const inLen = inBuf.length;
  const out = c.out;
  const outLen = out.length;
  const litTable = r.tables[LITLEN_TABLE];
  const distTable = r.tables[DIST_TABLE];

  let lo = c.bitLo;
  let hi = c.bitHi;
  let numBits = c.numBits;
  let counter = c.counter;
  let dist = c.dist;
  let numExtra = c.numExtra;
  let inPos = c.inPos;
  let outPos = c.outPos;

  let state: number;
  let status: number;

  o: for (;;) {
    for (;;) {
      if (outLen - outPos < 259 || inLen - inPos < 14) {
        state = S_DECODE_LITLEN;
        status = TINFL_STATUS_DONE;
        break o;
      }

      // fill_bit_buffer
      if (numBits < 30) {
        const v =
          (inBuf[inPos] |
            (inBuf[inPos + 1] << 8) |
            (inBuf[inPos + 2] << 16) |
            (inBuf[inPos + 3] << 24)) >>>
          0;
        inPos += 4;
        if (numBits === 0) {
          lo = v;
        } else {
          lo = (lo | (v << numBits)) >>> 0;
          hi = (hi | (v >>> (32 - numBits))) >>> 0;
        }
        numBits += 32;
      }

      let symbol = lookup(litTable, lo);
      let codeLen = lookupLen;
      counter = symbol;
      lo = ((lo >>> codeLen) | (hi << (32 - codeLen))) >>> 0;
      hi >>>= codeLen;
      numBits -= codeLen;

      if ((counter & 256) !== 0) {
        // Not a literal.
        break;
      }

      symbol = lookup(litTable, lo);
      codeLen = lookupLen;
      lo = ((lo >>> codeLen) | (hi << (32 - codeLen))) >>> 0;
      hi >>>= codeLen;
      numBits -= codeLen;
      // The previous symbol was a literal: write it and check the next one.
      out[outPos++] = counter & 0xff;
      if ((symbol & 256) !== 0) {
        counter = symbol;
        break;
      }
      out[outPos++] = symbol & 0xff;
    }

    counter &= 511;
    if (counter === 256) {
      state = S_BLOCK_DONE;
      status = TINFL_STATUS_DONE;
      break o;
    } else if (counter > 285) {
      state = S_INVALID_LITLEN;
      status = TINFL_STATUS_FAILED;
      break o;
    }

    numExtra = LENGTH_EXTRA[(counter - 257) & BASE_EXTRA_MASK];
    counter = LENGTH_BASE[(counter - 257) & BASE_EXTRA_MASK];

    if (numBits < 30) {
      const v =
        (inBuf[inPos] |
          (inBuf[inPos + 1] << 8) |
          (inBuf[inPos + 2] << 16) |
          (inBuf[inPos + 3] << 24)) >>>
        0;
      inPos += 4;
      if (numBits === 0) {
        lo = v;
      } else {
        lo = (lo | (v << numBits)) >>> 0;
        hi = (hi | (v >>> (32 - numBits))) >>> 0;
      }
      numBits += 32;
    }
    if (numExtra !== 0) {
      const extraBits = lo & ((1 << numExtra) - 1);
      lo = ((lo >>> numExtra) | (hi << (32 - numExtra))) >>> 0;
      hi >>>= numExtra;
      numBits -= numExtra;
      counter += extraBits;
    }

    const distSym = lookup(distTable, lo) & 511;
    const distCodeLen = lookupLen;
    lo = ((lo >>> distCodeLen) | (hi << (32 - distCodeLen))) >>> 0;
    hi >>>= distCodeLen;
    numBits -= distCodeLen;
    if (distSym > 29) {
      state = S_INVALID_DIST;
      status = TINFL_STATUS_FAILED;
      break o;
    }

    numExtra = numExtraBitsForDistanceCode(distSym);
    dist = DIST_BASE[distSym];

    if (numExtra !== 0) {
      if (numBits < 30) {
        const v =
          (inBuf[inPos] |
            (inBuf[inPos + 1] << 8) |
            (inBuf[inPos + 2] << 16) |
            (inBuf[inPos + 3] << 24)) >>>
          0;
        inPos += 4;
        if (numBits === 0) {
          lo = v;
        } else {
          lo = (lo | (v << numBits)) >>> 0;
          hi = (hi | (v >>> (32 - numBits))) >>> 0;
        }
        numBits += 32;
      }
      const extraBits = lo & ((1 << numExtra) - 1);
      lo = ((lo >>> numExtra) | (hi << (32 - numExtra))) >>> 0;
      hi >>>= numExtra;
      numBits -= numExtra;
      dist += extraBits;
    }

    if (dist > outPos || dist > outLen) {
      // The match refers to data before the start of the output.
      state = S_DISTANCE_OUT_OF_BOUNDS;
      status = TINFL_STATUS_FAILED;
      break o;
    }

    applyMatch(out, outPos, dist, counter);
    outPos += counter;
  }

  c.bitLo = lo;
  c.bitHi = hi;
  c.numBits = numBits;
  c.counter = counter;
  c.dist = dist;
  c.numExtra = numExtra;
  c.inPos = inPos;
  c.outPos = outPos;
  r.state = state;
  return status;
}

// ---------------------------------------------------------------------------
// Main state machine (decompress)
// ---------------------------------------------------------------------------

/**
 * `decompress`: decodes from `inBuf` into `out` starting at `outPos` until the
 * input is exhausted, the output is full, the stream ends or an error is
 * found. Returns the status; `c.inPos` and `c.outPos` hold the consumed input
 * and the output position (after the same "undo whole bytes" adjustment the
 * Rust function applies to its returned input count).
 */
function decompress(r: Decompressor, c: Ctx): number {
  const inBuf = c.inBuf;
  const out = c.out;
  const flags = c.flags;
  const outLen = out.length;
  const startOutPos = c.outPos;

  if ((flags & TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF) === 0) {
    throw new Error("miniz inflate: only the non-wrapping output buffer mode is implemented");
  }
  if (c.outPos > outLen) {
    return TINFL_STATUS_BAD_PARAM;
  }

  let state = r.state;
  c.bitLo = r.bitLo;
  c.bitHi = r.bitHi;
  c.numBits = r.numBits;
  c.dist = r.dist;
  c.counter = r.counter;
  c.numExtra = r.numExtra;

  let status: number;

  machine: for (;;) {
    switch (state) {
      case S_START: {
        c.bitLo = 0;
        c.bitHi = 0;
        c.numBits = 0;
        c.dist = 0;
        c.counter = 0;
        c.numExtra = 0;
        state = S_READ_BLOCK_HEADER;
        continue machine;
      }

      case S_READ_BLOCK_HEADER: {
        const bits = readBits(c, 3);
        if (bits < 0) {
          status = endOfInput(flags);
          break machine;
        }
        r.finish = bits & 1;
        r.blockType = (bits >> 1) & 3;
        switch (r.blockType) {
          case 0:
            state = S_BLOCK_TYPE_NO_COMPRESSION;
            continue machine;
          case 1: {
            startStaticTable(r);
            const next = initTree(r, c);
            if (next === INIT_TREE_FAILED) {
              status = TINFL_STATUS_FAILED;
              break machine;
            }
            state = next;
            continue machine;
          }
          case 2:
            c.counter = 0;
            state = S_READ_TABLE_SIZES;
            continue machine;
          default:
            state = S_BLOCK_TYPE_UNEXPECTED;
            continue machine;
        }
      }

      // Stored block.
      case S_BLOCK_TYPE_NO_COMPRESSION: {
        if (padToBytes(c) < 0) {
          status = endOfInput(flags);
          break machine;
        }
        c.counter = 0;
        state = S_RAW_HEADER;
        continue machine;
      }

      case S_RAW_HEADER: {
        if (c.counter < 4) {
          // Read the block length and its ones' complement.
          if (c.numBits !== 0) {
            const bits = readBits(c, 8);
            if (bits < 0) {
              status = endOfInput(flags);
              break machine;
            }
            r.rawHeader[c.counter] = bits;
          } else {
            if (c.inPos >= inBuf.length) {
              status = endOfInput(flags);
              break machine;
            }
            r.rawHeader[c.counter] = inBuf[c.inPos];
            c.inPos += 1;
          }
          c.counter += 1;
          continue machine;
        }
        const length = r.rawHeader[0] | (r.rawHeader[1] << 8);
        const check = r.rawHeader[2] | (r.rawHeader[3] << 8);
        const valid = length === (~check & 0xffff);
        c.counter = length;

        if (!valid) {
          state = S_BAD_RAW_LENGTH;
        } else if (c.counter === 0) {
          // Empty stored block (used for synchronization).
          state = S_BLOCK_DONE;
        } else if (c.numBits !== 0) {
          // Bytes still sitting in the bit buffer come first.
          state = S_RAW_READ_FIRST_BYTE;
        } else {
          state = S_RAW_MEMCPY1;
        }
        continue machine;
      }

      case S_RAW_READ_FIRST_BYTE: {
        const bits = readBits(c, 8);
        if (bits < 0) {
          status = endOfInput(flags);
          break machine;
        }
        c.dist = bits;
        state = S_RAW_STORE_FIRST_BYTE;
        continue machine;
      }

      case S_RAW_STORE_FIRST_BYTE: {
        if (outLen - c.outPos === 0) {
          status = TINFL_STATUS_HAS_MORE_OUTPUT;
          break machine;
        }
        out[c.outPos++] = c.dist & 0xff;
        c.counter -= 1;
        state = c.counter === 0 || c.numBits === 0 ? S_RAW_MEMCPY1 : S_RAW_READ_FIRST_BYTE;
        continue machine;
      }

      case S_RAW_MEMCPY1: {
        if (c.counter === 0) {
          state = S_BLOCK_DONE;
        } else if (outLen - c.outPos === 0) {
          status = TINFL_STATUS_HAS_MORE_OUTPUT;
          break machine;
        } else {
          state = S_RAW_MEMCPY2;
        }
        continue machine;
      }

      case S_RAW_MEMCPY2: {
        const inLeft = inBuf.length - c.inPos;
        if (inLeft > 0) {
          const spaceLeft = outLen - c.outPos;
          const bytesToCopy = Math.min(Math.min(spaceLeft, inLeft), c.counter);
          out.set(inBuf.subarray(c.inPos, c.inPos + bytesToCopy), c.outPos);
          c.outPos += bytesToCopy;
          c.inPos += bytesToCopy;
          c.counter -= bytesToCopy;
          state = S_RAW_MEMCPY1;
          continue machine;
        }
        status = endOfInput(flags);
        break machine;
      }

      // Dynamic block: number of codes in each table.
      case S_READ_TABLE_SIZES: {
        if (c.counter < 3) {
          const numBits = c.counter === 2 ? 4 : 5;
          const bits = readBits(c, numBits);
          if (bits < 0) {
            status = endOfInput(flags);
            break machine;
          }
          r.tableSizes[c.counter] = bits + MIN_TABLE_SIZES[c.counter];
          c.counter += 1;
          continue machine;
        }
        r.codeSizeHuffman.fill(0);
        c.counter = 0;
        // At most 286 literal/length and 30 distance codes.
        state =
          r.tableSizes[LITLEN_TABLE] <= 286 && r.tableSizes[DIST_TABLE] <= 30
            ? S_READ_HUFFLEN_TABLE_CODE_SIZE
            : S_BAD_DIST_OR_LITERAL_TABLE_LENGTH;
        continue machine;
      }

      // 3-bit lengths of the code length code.
      case S_READ_HUFFLEN_TABLE_CODE_SIZE: {
        if (c.counter < r.tableSizes[HUFFLEN_TABLE]) {
          const bits = readBits(c, 3);
          if (bits < 0) {
            status = endOfInput(flags);
            break machine;
          }
          r.codeSizeHuffman[HUFFMAN_LENGTH_ORDER[c.counter]] = bits;
          c.counter += 1;
          continue machine;
        }
        r.tableSizes[HUFFLEN_TABLE] = MAX_HUFF_SYMBOLS_2;
        const next = initTree(r, c);
        if (next === INIT_TREE_FAILED) {
          status = TINFL_STATUS_FAILED;
          break machine;
        }
        state = next;
        continue machine;
      }

      case S_READ_LITLEN_DIST_TABLES_CODE_SIZE: {
        const total = r.tableSizes[LITLEN_TABLE] + r.tableSizes[DIST_TABLE];
        if (c.counter < total) {
          const symbol = decodeHuffmanCode(r, c, HUFFLEN_TABLE);
          if (symbol < 0) {
            status = endOfInput(flags);
            break machine;
          }
          c.dist = symbol;
          if (c.dist < 16) {
            r.lenCodes[c.counter & LEN_CODES_MASK] = c.dist;
            c.counter += 1;
          } else if (c.dist === 16 && c.counter === 0) {
            state = S_BAD_CODE_SIZE_DIST_PREV_LOOKUP;
          } else {
            const idx = (c.dist - 16) & 3;
            c.numExtra = idx === 0 ? 2 : idx === 1 ? 3 : idx === 2 ? 7 : 0;
            state = S_READ_EXTRA_BITS_CODE_SIZE;
          }
          continue machine;
        }
        if (c.counter !== total) {
          state = S_BAD_CODE_SIZE_SUM;
          continue machine;
        }
        const litLen = r.tableSizes[LITLEN_TABLE];
        const distLen = r.tableSizes[DIST_TABLE];
        r.codeSizeLiteral.set(r.lenCodes.subarray(0, litLen & LEN_CODES_MASK), 0);
        const distStart = litLen & LEN_CODES_MASK;
        const distEnd = (litLen + distLen) & LEN_CODES_MASK;
        r.codeSizeDist.set(r.lenCodes.subarray(distStart, distEnd), 0);

        r.blockType -= 1;
        const next = initTree(r, c);
        if (next === INIT_TREE_FAILED) {
          status = TINFL_STATUS_FAILED;
          break machine;
        }
        state = next;
        continue machine;
      }

      case S_READ_EXTRA_BITS_CODE_SIZE: {
        const bits = readBits(c, c.numExtra);
        if (bits < 0) {
          status = endOfInput(flags);
          break machine;
        }
        // 16 and 17 add 3, 18 adds 11.
        const extraBits = bits + (((c.dist - 16) & 2) === 0 ? 3 : 11);
        const val = c.dist === 16 ? r.lenCodes[(c.counter - 1) & LEN_CODES_MASK] : 0;
        r.lenCodes.fill(val, c.counter & LEN_CODES_MASK, (c.counter + extraBits) & LEN_CODES_MASK);
        c.counter += extraBits;
        state = S_READ_LITLEN_DIST_TABLES_CODE_SIZE;
        continue machine;
      }

      case S_DECODE_LITLEN: {
        const inLeft = inBuf.length - c.inPos;
        const outLeft = outLen - c.outPos;
        if (inLeft < 4 || outLeft < 2) {
          // Decode one symbol with whatever is left.
          const symbol = decodeHuffmanCode(r, c, LITLEN_TABLE);
          if (symbol < 0) {
            status = endOfInput(flags);
            break machine;
          }
          c.counter = symbol;
          state = S_WRITE_SYMBOL;
          continue machine;
        }
        if (outLeft >= 259 && inLeft >= 14) {
          const fastStatus = decompressFast(r, c);
          state = r.state;
          if (fastStatus === TINFL_STATUS_DONE) continue machine;
          status = fastStatus;
          break machine;
        }

        fillBitBuffer(c);

        let symbol = lookup(r.tables[LITLEN_TABLE], c.bitLo);
        let codeLen = lookupLen;
        c.counter = symbol;
        shiftRight(c, codeLen);
        c.numBits -= codeLen;

        if ((c.counter & 256) !== 0) {
          state = S_HUFF_DECODE_OUTER_LOOP1;
          continue machine;
        }

        symbol = lookup(r.tables[LITLEN_TABLE], c.bitLo);
        codeLen = lookupLen;
        shiftRight(c, codeLen);
        c.numBits -= codeLen;
        out[c.outPos++] = c.counter & 0xff;
        if ((symbol & 256) !== 0) {
          c.counter = symbol;
          state = S_HUFF_DECODE_OUTER_LOOP1;
          continue machine;
        }
        out[c.outPos++] = symbol & 0xff;
        continue machine;
      }

      case S_WRITE_SYMBOL: {
        if (c.counter >= 256) {
          state = S_HUFF_DECODE_OUTER_LOOP1;
        } else if (outLen - c.outPos > 0) {
          out[c.outPos++] = c.counter & 0xff;
          state = S_DECODE_LITLEN;
        } else {
          status = TINFL_STATUS_HAS_MORE_OUTPUT;
          break machine;
        }
        continue machine;
      }

      case S_HUFF_DECODE_OUTER_LOOP1: {
        c.counter &= 511;
        if (c.counter === 256) {
          state = S_BLOCK_DONE;
        } else if (c.counter > 285) {
          state = S_INVALID_LITLEN;
        } else {
          c.numExtra = LENGTH_EXTRA[(c.counter - 257) & BASE_EXTRA_MASK];
          c.counter = LENGTH_BASE[(c.counter - 257) & BASE_EXTRA_MASK];
          state = c.numExtra !== 0 ? S_READ_EXTRA_BITS_LITLEN : S_DECODE_DISTANCE;
        }
        continue machine;
      }

      case S_READ_EXTRA_BITS_LITLEN: {
        const bits = readBits(c, c.numExtra);
        if (bits < 0) {
          status = endOfInput(flags);
          break machine;
        }
        c.counter += bits;
        state = S_DECODE_DISTANCE;
        continue machine;
      }

      case S_DECODE_DISTANCE: {
        const symbol = decodeHuffmanCode(r, c, DIST_TABLE);
        if (symbol < 0) {
          status = endOfInput(flags);
          break machine;
        }
        if (symbol > 29) {
          state = S_INVALID_DIST;
          continue machine;
        }
        c.numExtra = numExtraBitsForDistanceCode(symbol);
        c.dist = DIST_BASE[symbol];
        state = c.numExtra !== 0 ? S_READ_EXTRA_BITS_DISTANCE : S_HUFF_DECODE_OUTER_LOOP2;
        continue machine;
      }

      case S_READ_EXTRA_BITS_DISTANCE: {
        const bits = readBits(c, c.numExtra);
        if (bits < 0) {
          status = endOfInput(flags);
          break machine;
        }
        c.dist += bits;
        state = S_HUFF_DECODE_OUTER_LOOP2;
        continue machine;
      }

      case S_HUFF_DECODE_OUTER_LOOP2: {
        if (c.dist > c.outPos || c.dist > outLen) {
          state = S_DISTANCE_OUT_OF_BOUNDS;
          continue machine;
        }
        const outPos = c.outPos;
        const sourcePos = outPos - c.dist;
        const matchEndPos = outPos + c.counter;
        if (matchEndPos > outLen || (sourcePos >= outPos && sourcePos - outPos < c.counter)) {
          // Not enough room for the whole match: copy what fits.
          state = c.counter === 0 ? S_DECODE_LITLEN : S_WRITE_LEN_BYTES_TO_END;
          continue machine;
        }
        applyMatch(out, outPos, c.dist, c.counter);
        c.outPos = outPos + c.counter;
        state = S_DECODE_LITLEN;
        continue machine;
      }

      case S_WRITE_LEN_BYTES_TO_END: {
        const outLeft = outLen - c.outPos;
        if (outLeft > 0) {
          const len = Math.min(outLeft, c.counter);
          applyMatch(out, c.outPos, c.dist, len);
          c.outPos += len;
          c.counter -= len;
          if (c.counter === 0) state = S_DECODE_LITLEN;
          continue machine;
        }
        status = TINFL_STATUS_HAS_MORE_OUTPUT;
        break machine;
      }

      case S_BLOCK_DONE: {
        if (r.finish !== 0) {
          padToBytes(c);
          // Whole bytes still in the bit buffer are given back to the input.
          const inConsumed = c.inPos;
          const undo = Math.min(c.numBits >> 3, inConsumed);
          c.numBits -= undo << 3;
          c.inPos = inConsumed - undo;
          maskToNumBits(c);
          state = S_DONE_FOREVER;
        } else {
          state = S_READ_BLOCK_HEADER;
        }
        continue machine;
      }

      case S_DONE_FOREVER:
        status = TINFL_STATUS_DONE;
        break machine;

      // Every remaining state is a failure state.
      default:
        status = TINFL_STATUS_FAILED;
        break machine;
    }
  }

  // Return whole unread bytes from the bit buffer to the input so the caller
  // can resume from them.
  let inUndo = 0;
  if (
    status !== TINFL_STATUS_NEEDS_MORE_INPUT &&
    status !== TINFL_STATUS_FAILED_CANNOT_MAKE_PROGRESS
  ) {
    inUndo = Math.min(c.numBits >> 3, c.inPos);
    c.numBits -= inUndo << 3;
  }

  // HasMoreOutput overrides NeedsMoreInput when the output buffer is full.
  if (status === TINFL_STATUS_NEEDS_MORE_INPUT && outLen - c.outPos === 0) {
    status = TINFL_STATUS_HAS_MORE_OUTPUT;
  }

  maskToNumBits(c);
  r.state = state;
  r.bitLo = c.bitLo;
  r.bitHi = c.bitHi;
  r.numBits = c.numBits;
  r.dist = c.dist;
  r.counter = c.counter;
  r.numExtra = c.numExtra;

  c.inPos -= inUndo;
  if (c.outPos < startOutPos) {
    throw new Error("miniz inflate: output position moved backwards");
  }
  return status;
}

// ---------------------------------------------------------------------------
// decompress_to_vec
// ---------------------------------------------------------------------------

/**
 * Decompresses a raw DEFLATE stream (RFC 1951, no zlib header) exactly as
 * `miniz_oxide::inflate::decompress_to_vec` does: the output buffer starts at
 * twice the input size and doubles when full, and any bytes after the final
 * block are ignored.
 *
 * Throws {@link InflateError} with the `TINFLStatus` name the Rust crate
 * reports (`"Failed"` for corrupt data, `"FailedCannotMakeProgress"` for a
 * truncated stream).
 */
export function decompressToVec(input: Uint8Array): Uint8Array {
  const flags = TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
  let ret = new Uint8Array(input.length * 2);
  const r = new Decompressor();
  let remaining = input;
  let outPos = 0;

  for (;;) {
    const c = new Ctx(remaining, ret, flags);
    c.outPos = outPos;
    const status = decompress(r, c);
    const inConsumed = c.inPos;
    outPos = c.outPos;

    if (status === TINFL_STATUS_DONE) {
      return ret.slice(0, outPos);
    }
    if (status === TINFL_STATUS_HAS_MORE_OUTPUT) {
      if (inConsumed > remaining.length) {
        throw new InflateError("HasMoreOutput", ret.slice(0, outPos));
      }
      remaining = remaining.subarray(inConsumed);
      const grown = new Uint8Array(ret.length * 2);
      grown.set(ret);
      ret = grown;
      continue;
    }
    throw new InflateError(statusName(status), ret.slice(0, outPos));
  }
}
