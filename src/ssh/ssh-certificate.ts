/**
 * SSH certificate (`cert-v01@openssh.com`) placeholder — parity with the
 * reference implementation, which registers a fixed `"SSHCertificate"`
 * summarizer for `TAG_SSH_TEXT_CERTIFICATE` (40803) with a
 * `// todo: validation` comment. The reference does *not* parse certificate
 * fields either — it only round-trips the text.
 *
 * This class therefore stores the OpenSSH certificate text verbatim and
 * defers real `cert-v01@openssh.com` parsing, contingent on the reference
 * gaining a real parser upstream.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { ComponentsError } from "../error.js";

/** An OpenSSH certificate (`*-cert-v01@openssh.com`), carried as its single-line text; fields are not parsed, as in the reference. */
export class SSHCertificate {
  /** The full single-line OpenSSH cert text, e.g.
   *  `ssh-ed25519-cert-v01@openssh.com AAAAI...== user@host`. */
  readonly text: string;

  private constructor(text: string) {
    this.text = text;
  }

  /** Construct from the canonical OpenSSH certificate text. */
  static fromText(text: string): SSHCertificate {
    const trimmed = text.trim();
    if (trimmed.length === 0) {
      throw ComponentsError.ssh("SSHCertificate: empty input");
    }
    return new SSHCertificate(trimmed);
  }

  /** The canonical OpenSSH text — round-trips byte-identically. */
  toText(): string {
    return this.text;
  }

  /** Fixed summarizer string. */
  toString(): string {
    return "SSHCertificate";
  }

  /** SHA-256 of the certificate text. */
  digest(): Uint8Array {
    return sha256(new TextEncoder().encode(this.text));
  }
}
