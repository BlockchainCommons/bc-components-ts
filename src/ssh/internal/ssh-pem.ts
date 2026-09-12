/**
 * Minimal PEM (RFC 7468 §3) reader/writer with the byte-shape conventions
 * used by the reference's `ssh-key` 0.6.7:
 *
 *   - Wrap base64 at **70 columns** for OpenSSH private keys
 *     (`pem-rfc7468` default for that format).
 *   - Wrap base64 at **70 columns** for SSHSIG too (what OpenSSH emits).
 *   - LF newlines (matches `LineEnding::LF`, used for all parity fixtures
 *     in the reference implementation).
 *   - Trailing newline after the END line.
 */

import { base64 } from "@scure/base";
import { ComponentsError } from "../../error.js";

const BEGIN = "-----BEGIN ";
const END = "-----END ";
const SUFFIX = "-----";

export interface PemBlock {
  label: string;
  data: Uint8Array;
}

/**
 * Parse a single PEM block. Tolerant of CRLF, trailing whitespace, leading
 * whitespace lines and `Proc-Type` / `DEK-Info` headers (the SSHSIG/OpenSSH
 * formats don't use those, but we ignore them to be robust).
 */
export function parsePem(text: string, expectedLabel?: string): PemBlock {
  const lines = text.split(/\r?\n/);
  let i = 0;
  while (i < lines.length && lines[i].trim() === "") i++;
  if (i >= lines.length) {
    throw ComponentsError.ssh("PEM: empty input");
  }
  const beginLine = lines[i];
  if (!beginLine.startsWith(BEGIN) || !beginLine.endsWith(SUFFIX)) {
    throw ComponentsError.ssh(`PEM: expected '-----BEGIN <label>-----' header, got '${beginLine}'`);
  }
  const label = beginLine.slice(BEGIN.length, beginLine.length - SUFFIX.length);
  if (expectedLabel !== undefined && label !== expectedLabel) {
    throw ComponentsError.ssh(`PEM: expected label '${expectedLabel}', got '${label}'`);
  }
  i++;
  // Skip any RFC 1421 headers (`Key:` lines before the blank-line separator).
  while (i < lines.length && /^[A-Za-z][A-Za-z0-9-]*:/.test(lines[i].trim())) {
    i++;
  }
  if (i < lines.length && lines[i].trim() === "") i++;

  const bodyLines: string[] = [];
  let endLine: string | undefined;
  for (; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith(END)) {
      endLine = line;
      break;
    }
    bodyLines.push(line);
  }
  if (endLine === undefined) {
    throw ComponentsError.ssh("PEM: missing '-----END <label>-----' footer");
  }
  if (!endLine.endsWith(SUFFIX)) {
    throw ComponentsError.ssh(`PEM: malformed END line '${endLine}'`);
  }
  const endLabel = endLine.slice(END.length, endLine.length - SUFFIX.length);
  if (endLabel !== label) {
    throw ComponentsError.ssh(`PEM: BEGIN/END label mismatch ('${label}' vs '${endLabel}')`);
  }

  const body = bodyLines.join("").replace(/\s+/g, "");
  return { label, data: base64.decode(body) };
}

/**
 * Encode a PEM block. `width` is the base64 column width (70 for OpenSSH
 * private keys and SSHSIG signatures alike). Trailing newline is included
 * to match the reference fixtures.
 */
export function encodePem(label: string, data: Uint8Array, width: number): string {
  const b64 = base64.encode(data);
  const lines: string[] = [];
  lines.push(`${BEGIN}${label}${SUFFIX}`);
  for (let i = 0; i < b64.length; i += width) {
    lines.push(b64.slice(i, i + width));
  }
  lines.push(`${END}${label}${SUFFIX}`);
  return `${lines.join("\n")}\n`;
}
