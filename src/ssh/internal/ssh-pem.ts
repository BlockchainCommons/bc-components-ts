/**
 * The text encodings around OpenSSH binary blobs, ported so that every input
 * is accepted or rejected exactly as `ssh-key` 0.6.7 does, with the same
 * error text:
 *
 *   - PEM (`-----BEGIN <LABEL>-----`), a port of `pem-rfc7468` 0.7.0
 *     (`grammar.rs`, `decoder.rs`, `encoder.rs`) as `ssh-encoding` 0.2.0
 *     drives it: `Decoder::new_wrapped(pem, 70)` followed by
 *     `PemLabel::validate_pem_label`. The Base64 body follows `base64ct`
 *     1.8's line-wrapped decoder: every line except the last is exactly 70
 *     columns, lines end in CR, LF or CRLF, there are no blank lines or
 *     stray whitespace, and the final block must be canonically padded.
 *   - The single-line public-key form (`<algorithm> <base64> [comment]`),
 *     a port of `ssh-key` 0.6.7 `public/ssh_format.rs` `SshFormat::decode`
 *     with `base64ct`'s strict (unwrapped) decoder for the key data.
 *
 * Every failure is `ComponentsError.ssh(<the crate's Display text>)`.
 */

import { ComponentsError } from "../../error.js";
import { rustTrimEnd } from "../../domain.js";

const PRE_ENCAPSULATION_BOUNDARY = "-----BEGIN ";
const POST_ENCAPSULATION_BOUNDARY = "-----END ";
const ENCAPSULATION_BOUNDARY_DELIMITER = "-----";

const CHAR_NUL = 0x00;
const CHAR_HT = 0x09;
const CHAR_LF = 0x0a;
const CHAR_CR = 0x0d;
const CHAR_SP = 0x20;
const CHAR_HYPHEN = 0x2d;
const CHAR_PAD = 0x3d; // '='

/** `pem-rfc7468` line width `ssh-encoding` uses for every OpenSSH document. */
export const SSH_PEM_LINE_WIDTH: number = 70;

// ---------------------------------------------------------------------------
// Error texts (`pem-rfc7468` 0.7.0 `Error`, `base64ct` 1.8 `Error`,
// `ssh-encoding` 0.2.0 `Error`)
// ---------------------------------------------------------------------------

const PEM_LABEL_INVALID = "PEM type label invalid";
const PEM_PREAMBLE = "PEM preamble contains invalid data (NUL byte)";
const PEM_PRE_ENCAPSULATION = "PEM error in pre-encapsulation boundary";
const PEM_POST_ENCAPSULATION = "PEM error in post-encapsulation boundary";
const BASE64_INVALID_ENCODING = "invalid Base64 encoding";
const BASE64_INVALID_LENGTH = "invalid Base64 length";
const ENCODING_CHARACTER = "character encoding invalid";
const ENCODING_LENGTH = "length invalid";

function pemBase64Error(text: string): ComponentsError {
  return ComponentsError.ssh(`PEM Base64 error: ${text}`);
}

function base64Error(text: string): ComponentsError {
  return ComponentsError.ssh(`Base64 encoding error: ${text}`);
}

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

const ASCII = new TextEncoder();
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function startsWithBytes(bytes: Uint8Array, offset: number, prefix: Uint8Array): boolean {
  if (offset + prefix.length > bytes.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (bytes[offset + i] !== prefix[i]) return false;
  }
  return true;
}

function endsWithBytes(bytes: Uint8Array, suffix: Uint8Array): boolean {
  return startsWithBytes(bytes, bytes.length - suffix.length, suffix);
}

/** `grammar::strip_leading_eol`: one CRLF, CR or LF at `offset`, or -1. */
function leadingEolLength(bytes: Uint8Array, offset: number): number {
  if (bytes[offset] === CHAR_LF) return 1;
  if (bytes[offset] === CHAR_CR) return bytes[offset + 1] === CHAR_LF ? 2 : 1;
  return -1;
}

/** `grammar::strip_trailing_eol`: the length of one trailing CRLF, LF or CR, or -1. */
function trailingEolLength(bytes: Uint8Array): number {
  const n = bytes.length;
  if (n >= 2 && bytes[n - 2] === CHAR_CR && bytes[n - 1] === CHAR_LF) return 2;
  if (n >= 1 && (bytes[n - 1] === CHAR_LF || bytes[n - 1] === CHAR_CR)) return 1;
  return -1;
}

/** `grammar::is_labelchar`: printable ASCII except hyphen-minus. */
function isLabelChar(c: number): boolean {
  return (c >= 0x21 && c <= 0x2c) || (c >= 0x2e && c <= 0x7e);
}

function isWsp(c: number): boolean {
  return c === CHAR_HT || c === CHAR_SP;
}

// ---------------------------------------------------------------------------
// Strict Base64 (`base64ct` 1.8 `Base64`, the padded alphabet)
// ---------------------------------------------------------------------------

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_VALUES = new Int16Array(256).fill(-1);
for (let i = 0; i < BASE64_ALPHABET.length; i++) {
  BASE64_VALUES[BASE64_ALPHABET.charCodeAt(i)] = i;
}

/**
 * `Base64::decode` on a complete (unwrapped) buffer: the length is a
 * multiple of four, padding is only `=` or `==` at the very end, every other
 * byte is in the alphabet, and the final block round-trips (no non-zero
 * trailing bits). Returns `undefined` on any violation — the caller picks
 * the error text of the layer it is in.
 */
function decodeBase64Block(src: Uint8Array): Uint8Array | undefined {
  if (src.length % 4 !== 0) return undefined;
  if (src.length === 0) return new Uint8Array(0);
  let padding = 0;
  if (src[src.length - 1] === CHAR_PAD) {
    padding = src[src.length - 2] === CHAR_PAD ? 2 : 1;
  } else if (src[src.length - 2] === CHAR_PAD) {
    return undefined;
  }
  const unpaddedLen = src.length - padding;
  const out = new Uint8Array(Math.floor((unpaddedLen * 3) / 4));
  let o = 0;
  for (let i = 0; i + 4 <= unpaddedLen; i += 4) {
    const a = BASE64_VALUES[src[i]];
    const b = BASE64_VALUES[src[i + 1]];
    const c = BASE64_VALUES[src[i + 2]];
    const d = BASE64_VALUES[src[i + 3]];
    if (a < 0 || b < 0 || c < 0 || d < 0) return undefined;
    const n = (a << 18) | (b << 12) | (c << 6) | d;
    out[o++] = (n >>> 16) & 0xff;
    out[o++] = (n >>> 8) & 0xff;
    out[o++] = n & 0xff;
  }
  const rem = unpaddedLen % 4;
  if (rem !== 0) {
    if (rem < 2) return undefined;
    const base = unpaddedLen - rem;
    const a = BASE64_VALUES[src[base]];
    const b = BASE64_VALUES[src[base + 1]];
    const c = rem > 2 ? BASE64_VALUES[src[base + 2]] : 0;
    if (a < 0 || b < 0 || c < 0) return undefined;
    const n = (a << 18) | (b << 12) | (c << 6);
    out[o++] = (n >>> 16) & 0xff;
    if (rem > 2) out[o] = (n >>> 8) & 0xff;
  }
  // `validate_last_block`: re-encode the last decoded block and compare.
  const encStart = Math.floor((src.length - 1) / 4) * 4;
  const decStart = Math.floor((out.length - 1) / 3) * 3;
  const reencoded = encodeBase64(out.subarray(decStart));
  for (let i = 0; i < reencoded.length && encStart + i < src.length; i++) {
    if (reencoded.charCodeAt(i) !== src[encStart + i]) return undefined;
  }
  return out;
}

/** Standard padded Base64 of `data`. */
export function encodeBase64(data: Uint8Array): string {
  let out = "";
  for (let i = 0; i < data.length; i += 3) {
    const b0 = data[i];
    const b1 = i + 1 < data.length ? data[i + 1] : 0;
    const b2 = i + 2 < data.length ? data[i + 2] : 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    out += BASE64_ALPHABET[(n >>> 18) & 63];
    out += BASE64_ALPHABET[(n >>> 12) & 63];
    out += i + 1 < data.length ? BASE64_ALPHABET[(n >>> 6) & 63] : "=";
    out += i + 2 < data.length ? BASE64_ALPHABET[n & 63] : "=";
  }
  return out;
}

/**
 * `ssh-encoding` `Base64Reader::new` + a full read: strict padded Base64 of
 * a single unwrapped segment. Failures carry `ssh-encoding`'s
 * `Base64 encoding error: …` text.
 */
export function decodeBase64Strict(bytes: Uint8Array): Uint8Array {
  if (bytes.length === 0) throw base64Error(BASE64_INVALID_LENGTH);
  const out = decodeBase64Block(bytes);
  if (out === undefined) throw base64Error(BASE64_INVALID_ENCODING);
  return out;
}

// ---------------------------------------------------------------------------
// PEM decoding (`pem-rfc7468` `Encapsulation::parse` + `Decoder::new_wrapped`)
// ---------------------------------------------------------------------------

/**
 * Decodes one PEM document with the label `expectedLabel`, as
 * `ssh-key` 0.6.7 `PrivateKey::from_openssh` / `SshSig::from_pem` do.
 */
export function decodePem(text: string, expectedLabel: string): Uint8Array {
  const input = ASCII.encode(text);
  const begin = ASCII.encode(PRE_ENCAPSULATION_BOUNDARY);
  const delimiter = ASCII.encode(ENCAPSULATION_BOUNDARY_DELIMITER);

  // `grammar::strip_preamble`: anything but NUL may precede the boundary,
  // which must then start the input or directly follow a LF.
  let pos = 0;
  if (!startsWithBytes(input, 0, begin)) {
    for (;;) {
      if (pos >= input.length) throw ComponentsError.ssh(PEM_PREAMBLE);
      const byte = input[pos];
      pos += 1;
      if (byte === CHAR_NUL) throw ComponentsError.ssh(PEM_PREAMBLE);
      if (byte === CHAR_LF && startsWithBytes(input, pos, begin)) break;
    }
  }
  pos += begin.length;

  // `grammar::split_label`: label characters and single blanks up to the
  // first hyphen, then `-----` and a mandatory newline.
  const labelStart = pos;
  let lastWasWsp = false;
  for (; pos < input.length; pos++) {
    const c = input[pos];
    if (isLabelChar(c)) {
      lastWasWsp = false;
    } else if (c === CHAR_HYPHEN) {
      break;
    } else if (pos !== labelStart && isWsp(c)) {
      if (lastWasWsp) throw ComponentsError.ssh(PEM_LABEL_INVALID);
      lastWasWsp = true;
    } else {
      throw ComponentsError.ssh(PEM_LABEL_INVALID);
    }
  }
  const label = UTF8.decode(input.subarray(labelStart, pos));
  if (!startsWithBytes(input, pos, delimiter)) throw ComponentsError.ssh(PEM_LABEL_INVALID);
  pos += delimiter.length;
  const eol = leadingEolLength(input, pos);
  if (eol < 0) throw ComponentsError.ssh(PEM_LABEL_INVALID);
  pos += eol;

  // The body must end with `-----` after at most one newline …
  let body = input.subarray(pos);
  const trailing = trailingEolLength(body);
  if (trailing > 0) body = body.subarray(0, body.length - trailing);
  if (!endsWithBytes(body, delimiter)) throw ComponentsError.ssh(PEM_PRE_ENCAPSULATION);
  body = body.subarray(0, body.length - delimiter.length);

  // … preceded by `-----END <same label>` …
  for (const suffix of [ASCII.encode(label), ASCII.encode(POST_ENCAPSULATION_BOUNDARY)]) {
    if (!endsWithBytes(body, suffix)) throw ComponentsError.ssh(PEM_POST_ENCAPSULATION);
    body = body.subarray(0, body.length - suffix.length);
  }

  // … and a mandatory newline before the post-encapsulation boundary.
  const bodyEol = trailingEolLength(body);
  if (bodyEol < 0) throw ComponentsError.ssh(PEM_POST_ENCAPSULATION);
  const encapsulated = body.subarray(0, body.length - bodyEol);

  const lines = splitWrappedLines(encapsulated);
  const joined = concatLines(lines);

  // `LineReader::decoded_len` decodes the final block up front …
  if (
    joined.length % 4 !== 0 ||
    decodeBase64Block(joined.subarray(joined.length - 4)) === undefined
  ) {
    throw pemBase64Error(BASE64_INVALID_ENCODING);
  }

  // … `PemLabel::validate_pem_label` runs before the body is read …
  if (label !== expectedLabel) {
    throw ComponentsError.ssh(`unexpected PEM type label: expecting "${expectedLabel}"`);
  }

  // … and the body is decoded as it is consumed.
  const decoded = decodeBase64Block(joined);
  if (decoded === undefined) throw pemBase64Error(BASE64_INVALID_ENCODING);
  return decoded;
}

/**
 * `base64ct` `LineReader` at width 70: every line but the last is exactly
 * 70 bytes followed by CRLF, CR or LF; the last line loses one trailing
 * newline. Empty input is a length error.
 */
function splitWrappedLines(bytes: Uint8Array): Uint8Array[] {
  if (bytes.length === 0) throw pemBase64Error(BASE64_INVALID_LENGTH);
  const lines: Uint8Array[] = [];
  let rest = bytes;
  for (;;) {
    if (rest.length <= SSH_PEM_LINE_WIDTH) {
      const eol = trailingEolLength(rest);
      lines.push(eol > 0 ? rest.subarray(0, rest.length - eol) : rest);
      return lines;
    }
    const eol = leadingEolLength(rest, SSH_PEM_LINE_WIDTH);
    if (eol < 0) throw pemBase64Error(BASE64_INVALID_ENCODING);
    lines.push(rest.subarray(0, SSH_PEM_LINE_WIDTH));
    rest = rest.subarray(SSH_PEM_LINE_WIDTH + eol);
    if (rest.length === 0) return lines;
  }
}

function concatLines(lines: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const line of lines) total += line.length;
  const out = new Uint8Array(total);
  let pos = 0;
  for (const line of lines) {
    out.set(line, pos);
    pos += line.length;
  }
  return out;
}

/**
 * Encodes a PEM document as `pem-rfc7468` `Encoder::new_wrapped(label,
 * width, LineEnding::LF)`: the Base64 body wrapped at `width` columns, LF
 * line endings and a trailing newline after the post-encapsulation boundary.
 */
export function encodePem(label: string, data: Uint8Array, width: number): string {
  const b64 = encodeBase64(data);
  const lines: string[] = [];
  lines.push(`${PRE_ENCAPSULATION_BOUNDARY}${label}${ENCAPSULATION_BOUNDARY_DELIMITER}`);
  for (let i = 0; i < b64.length; i += width) {
    lines.push(b64.slice(i, i + width));
  }
  lines.push(`${POST_ENCAPSULATION_BOUNDARY}${label}${ENCAPSULATION_BOUNDARY_DELIMITER}`);
  return `${lines.join("\n")}\n`;
}

// ---------------------------------------------------------------------------
// OpenSSH public-key text (`ssh-key` 0.6.7 `SshFormat::decode`)
// ---------------------------------------------------------------------------

/** The three parts of an OpenSSH public-key line. */
export interface SshFormatParts {
  /** The algorithm identifier before the first space. */
  algorithmId: string;
  /** The Base64 key data, still encoded. */
  base64Data: Uint8Array;
  /** The comment with trailing whitespace removed (may be empty). */
  comment: string;
}

/** `decode_segment`: the bytes allowed in the algorithm and Base64 segments. */
function isSegmentByte(c: number): boolean {
  return (
    (c >= 0x41 && c <= 0x5a) || // A-Z
    (c >= 0x61 && c <= 0x7a) || // a-z
    (c >= 0x30 && c <= 0x39) || // 0-9
    c === 0x2b || // +
    c === 0x2d || // -
    c === 0x2f || // /
    c === 0x3d || // =
    c === 0x40 || // @
    c === 0x2e // .
  );
}

/**
 * Splits `<algorithm> <base64> [comment]` as `PublicKey::from_openssh`:
 * the text is `trim_end`ed first, a segment ends at a space or at the end
 * of input, any other byte outside the segment alphabet is
 * `character encoding invalid`, and an empty algorithm or key segment is
 * `length invalid`.
 */
export function decodeSshFormat(text: string): SshFormatParts {
  const bytes = ASCII.encode(rustTrimEnd(text));
  let pos = 0;
  const segment = (): Uint8Array => {
    const start = pos;
    for (;;) {
      if (pos >= bytes.length) return bytes.subarray(start, pos);
      const c = bytes[pos];
      if (isSegmentByte(c)) {
        pos += 1;
      } else if (c === CHAR_SP) {
        const out = bytes.subarray(start, pos);
        pos += 1;
        return out;
      } else {
        throw ComponentsError.ssh(ENCODING_CHARACTER);
      }
    }
  };
  const algorithm = segment();
  const base64Data = segment();
  const comment = rustTrimEnd(UTF8.decode(bytes.subarray(pos)));
  if (algorithm.length === 0 || base64Data.length === 0) {
    throw ComponentsError.ssh(ENCODING_LENGTH);
  }
  return { algorithmId: UTF8.decode(algorithm), base64Data, comment };
}
