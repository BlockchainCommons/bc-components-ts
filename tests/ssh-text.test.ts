/**
 * SSH text-grammar parity with `ssh-key` 0.6.7.
 *
 * `tests/fixtures/ssh-text/cases.json` holds 191 OpenSSH texts — private
 * keys (PEM), public-key lines and `sshsig` signatures for Ed25519, P-256,
 * P-384, P-521, DSA and RSA, each in a dozen spellings (CRLF, missing or
 * doubled final newline, leading whitespace or newline, 64/76/one-line
 * wrapping, blank lines, lower-case or wrong labels, tabs, option prefixes,
 * unpadded Base64, mismatched algorithm names, trailing comment
 * whitespace, and comments starting with U+FEFF or containing U+00A0) —
 * together with the outcome the reference produced for each:
 * `PrivateKey::from_openssh` / `PublicKey::from_openssh` /
 * `SshSig::from_pem`, re-encoded with `LineEnding::LF` on success, or the
 * error's `Display` text on failure.
 *
 * The TS decoders must accept and reject exactly the same texts, reproduce
 * the same re-encoding, comment and public key, and report every failure
 * as `Ssh` with `SSH operation failed: <the crate's text>`.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ComponentsError } from "../src/error.js";
import { SSHPrivateKey } from "../src/ssh/ssh-private-key.js";
import { SSHPublicKey } from "../src/ssh/ssh-public-key.js";
import { SSHSignature } from "../src/ssh/ssh-signature.js";
import { SshBufferReader, SshBufferWriter } from "../src/ssh/internal/ssh-buffer.js";

type CaseKind = "priv" | "pub" | "sig";

interface OkOutcome {
  ok: true;
  /** The reference's re-encoding (`to_openssh(LF)` / `to_pem(LF)` / `to_openssh()`). */
  text: string;
  /** The parsed comment (private and public keys). */
  comment?: string;
  /** `public_key().to_openssh()` (private keys). */
  publicKey?: string;
}

interface ErrOutcome {
  ok: false;
  /** The `Display` text of the `ssh_key::Error`. */
  error: string;
}

interface TextCase {
  id: string;
  kind: CaseKind;
  text: string;
  expect: OkOutcome | ErrOutcome;
}

interface CasesFile {
  reference: string;
  cases: TextCase[];
}

const here = dirname(fileURLToPath(import.meta.url));
const CASES = (
  JSON.parse(readFileSync(join(here, "fixtures", "ssh-text", "cases.json"), "utf8")) as CasesFile
).cases;

interface Parsed {
  text: string;
  comment?: string;
  publicKey?: string;
}

function parse(kind: CaseKind, text: string): Parsed {
  switch (kind) {
    case "priv": {
      const key = SSHPrivateKey.fromOpenssh(text);
      return {
        text: key.toOpenssh(),
        comment: key.comment,
        publicKey: key.publicKey().toOpenssh(),
      };
    }
    case "pub": {
      const key = SSHPublicKey.fromOpenssh(text);
      return { text: key.toOpenssh(), comment: key.comment };
    }
    case "sig":
      return { text: SSHSignature.fromPem(text).toPem() };
  }
}

function byKind(kind: CaseKind): TextCase[] {
  return CASES.filter((c) => c.kind === kind);
}

describe("ssh text fixtures", () => {
  it("cover every kind and outcome", () => {
    expect(CASES).toHaveLength(191);
    expect(byKind("priv")).toHaveLength(81);
    expect(byKind("pub")).toHaveLength(75);
    expect(byKind("sig")).toHaveLength(35);
    expect(CASES.filter((c) => c.expect.ok)).toHaveLength(78);
    const errors = new Set(CASES.flatMap((c) => (c.expect.ok ? [] : [c.expect.error])));
    expect([...errors].sort()).toEqual(
      [
        "Base64 encoding error: invalid Base64 encoding",
        "PEM Base64 error: invalid Base64 encoding",
        "PEM error in pre-encapsulation boundary",
        "PEM preamble contains invalid data (NUL byte)",
        "PEM type label invalid",
        "character encoding invalid",
        "length invalid",
        'unexpected PEM type label: expecting "OPENSSH PRIVATE KEY"',
        "unknown algorithm",
      ].sort(),
    );
  });
});

for (const kind of ["priv", "pub", "sig"] as const) {
  const label = { priv: "OpenSSH private keys", pub: "OpenSSH public-key lines", sig: "sshsig" }[
    kind
  ];
  describe(`${label} parse as ssh-key 0.6.7`, () => {
    it.each(byKind(kind))("$id", ({ text, expect: expected }) => {
      if (expected.ok) {
        const got = parse(kind, text);
        expect(got.text).toBe(expected.text);
        if (expected.comment !== undefined) expect(got.comment).toBe(expected.comment);
        if (expected.publicKey !== undefined) expect(got.publicKey).toBe(expected.publicKey);
        return;
      }
      let caught: unknown;
      try {
        parse(kind, text);
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ComponentsError);
      const err = caught as ComponentsError;
      expect(err.code).toBe("Ssh");
      expect(err.message).toBe(`SSH operation failed: ${expected.error}`);
    });
  });
}

describe("UTF-8 text fields keep a leading U+FEFF", () => {
  const BOM_COMMENT = "﻿c";

  it("SshBufferReader.readStringUtf8 does not strip a BOM", () => {
    const blob = new SshBufferWriter().writeStringUtf8(BOM_COMMENT).bytes();
    expect(new SshBufferReader(blob).readStringUtf8()).toBe(BOM_COMMENT);
  });

  it("an SSH private key whose comment starts with U+FEFF round-trips byte for byte", () => {
    const base = CASES.find((c) => c.id === "comment/plain/priv");
    if (base === undefined) throw new Error("fixture missing");
    const plain = SSHPrivateKey.fromOpenssh(base.text);
    const withBom = SSHPrivateKey.fromParts(plain.data, BOM_COMMENT, plain.checkint);
    const pem = withBom.toOpenssh();
    const reparsed = SSHPrivateKey.fromOpenssh(pem);
    expect(reparsed.comment).toBe(BOM_COMMENT);
    expect(reparsed.toOpenssh()).toBe(pem);
    expect(reparsed.publicKey().comment).toBe(BOM_COMMENT);
    // The reference's own rendering of the same key and comment.
    const bomCase = CASES.find((c) => c.id === "comment/bom/priv");
    if (bomCase === undefined || !bomCase.expect.ok) throw new Error("fixture missing");
    expect(pem).toBe(bomCase.expect.text);
  });

  it("an SSH public-key line keeps a U+FEFF at the start of its comment", () => {
    const line =
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIELWZo92J4kWoWbPxNwQVJ4fV6saNXldROPJDNuJLeht ﻿c";
    const key = SSHPublicKey.fromOpenssh(line);
    expect(key.comment).toBe(BOM_COMMENT);
    expect(key.toOpenssh()).toBe(line);
  });
});
