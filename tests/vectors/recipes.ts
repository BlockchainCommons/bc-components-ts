/**
 * Vector recipes. A recipe names an operation and its inputs;
 * `materialize` runs it through a `VectorApi` and returns one outcome
 * string, so the same recipe drives the golden file, the differential and
 * the Rust harness. Adapters bridge the pre- and post-redesign surfaces.
 *
 * Outcomes are wire: tagged CBOR hex, UR strings, key/derivation hex,
 * OpenSSH text. Where a constructor draws from the secure generator with no
 * way to seed it (sealing, key locking, ML-KEM encapsulation) the outcome is
 * structural: lengths, scheme, and a round-trip check.
 */

import { rustShapedAdapterFor } from "./baseline-adapter";
import { redesignedShapedAdapterFor } from "./redesigned-adapter";
/* eslint-disable @typescript-eslint/no-explicit-any */

export type Bytes = { hex: string } | { cycle: number; start?: number } | { text: string };
/**
 * A JavaScript `number` that must survive JSON: `NaN` and the infinities
 * have no JSON form, so they travel as strings.
 */
export type Num = number | "NaN" | "Infinity" | "-Infinity";
export const num = (v: Num): number => (typeof v === "number" ? v : Number(v));
export type RngSpec =
  | { seed: [string, string, string, string] }
  | { fake: true }
  | { hkdf: { km: Bytes; salt: string } };
export type ValueType =
  | "digest"
  | "nonce"
  | "salt"
  | "arid"
  | "uuid"
  | "xid"
  | "reference"
  | "symmetricKey"
  | "json"
  | "uri"
  | "authTag"
  | "x25519Priv"
  | "x25519Pub"
  | "ecPriv"
  | "ecPub"
  | "ecUncompressed"
  | "schnorrPub"
  | "ed25519Priv"
  | "ed25519Pub"
  | "privateKeyBase"
  | "sskrShare";
export type RandomType =
  | "nonce"
  | "salt"
  | "arid"
  | "uuid"
  | "symmetricKey"
  | "x25519Priv"
  | "ecPriv"
  | "ed25519Priv"
  | "privateKeyBase"
  | "seed";
export type Scheme = "schnorr" | "ecdsa" | "ed25519";
export type EncScheme = "x25519" | "mlkem512" | "mlkem768" | "mlkem1024";
export type SshAlg = "ed25519" | "ecdsa-p256" | "ecdsa-p384";
export type KdfMethod = "hkdf" | "pbkdf2" | "scrypt" | "argon2id" | "sshAgent";
export type DecodeType =
  | ValueType
  | "seed"
  | "compressed"
  | "encryptedMessage"
  | "signature"
  | "signingPriv"
  | "signingPub"
  | "encapPriv"
  | "encapPub"
  | "encapCiphertext"
  | "sealedMessage"
  | "privateKeys"
  | "publicKeys"
  | "encryptedKey"
  | "mldsaPriv"
  | "mldsaPub"
  | "mldsaSig"
  | "mlkemPriv"
  | "mlkemPub"
  | "mlkemCiphertext";
export interface ParamsSpec {
  method: KdfMethod;
  salt: Bytes;
  hash?: "sha256" | "sha512";
  iterations?: number;
  logN?: number;
  r?: number;
  p?: number;
  id?: string;
}
export type Recipe =
  | { k: "value"; type: ValueType; data: Bytes }
  | { k: "random"; type: RandomType; rng: RngSpec; len?: number }
  | { k: "derive"; type: "x25519" | "ec" | "ed25519"; km: Bytes }
  | { k: "digest"; image: Bytes }
  | { k: "compressed"; data: Bytes; digest?: boolean }
  | { k: "seed"; data: Bytes; name?: string; note?: string; date?: number }
  | { k: "encrypt"; key: Bytes; nonce: Bytes; plaintext: Bytes; aad?: Bytes }
  | { k: "x25519Shared"; priv: Bytes; pub: Bytes }
  | { k: "signingKeys"; scheme: Scheme; key: Bytes }
  | { k: "sign"; scheme: Scheme; key: Bytes; message: Bytes; rng?: RngSpec }
  | {
      k: "sshFromSeed";
      seed: Bytes;
      alg: SshAlg;
      comment: string;
      message?: Bytes;
      namespace?: string;
    }
  | { k: "sshFromPem"; pem: string; message?: Bytes; namespace?: string }
  | { k: "pkb"; seed: Bytes }
  | { k: "keypair"; sigScheme: Scheme; encScheme: EncScheme; rng: RngSpec }
  | {
      k: "seal";
      plaintext: Bytes;
      recipient: { x25519: Bytes } | { mlkem: 512 | 768 | 1024; rng: RngSpec };
      aad?: Bytes;
      /** Fixed nonce; the ephemeral key stays random on both sides (U5). */
      nonce?: Bytes;
    }
  | ({ k: "params" } & ParamsSpec)
  | ({ k: "encryptedKey"; secret: Bytes; key: Bytes } & ParamsSpec)
  | { k: "hkdfRng"; km: Bytes; salt: string; draws: number[]; pageLen?: number }
  | { k: "mldsa"; level: 44 | 65 | 87; rng: RngSpec; message?: Bytes }
  | { k: "mlkem"; level: 512 | 768 | 1024; rng: RngSpec }
  | {
      k: "sskr";
      spec: { gt: number; groups: { mt: number; mc: number }[] };
      secret: Bytes;
      rng: RngSpec;
    }
  | { k: "decode"; type: DecodeType; hex: string }
  | { k: "urParse"; type: ValueType | "seed" | "encryptedMessage" | "signature"; s: string }
  /** Ed25519 verification of raw key/signature bytes (V2): `valid` / `invalid`. */
  | { k: "verifyStrict"; pub: Bytes; sig: Bytes; message: Bytes; note: string }
  /** `fromCbor` over the UNTAGGED encoding (B2). */
  | { k: "decodeUntagged"; type: DecodeType; hex: string }
  /** `SigningPrivateKey.random().scheme | generateKeypair() signing scheme` (B3). */
  | { k: "signingDefault"; rng: RngSpec }
  /** KDF parameter construction with out-of-domain numbers (B4): `ok:…` or a throw. */
  | { k: "kdfDomain"; method: "pbkdf2" | "scrypt"; iterations?: Num; logN?: Num; r?: Num; p?: Num }
  /** A named JS-only input case from the adapter's table: `ok:…` or `throw:<class>:<code>`. */
  | { k: "domain"; case: string }
  /** The tag summariser applied to tagged CBOR: the summary, `error`, or `none`. */
  | { k: "summary"; hex: string; note: string }
  /** `Salt.randomInRange(min, max, { rng })`: the length is a `usize` draw (N1). */
  | { k: "saltInRange"; min: number; max: number; rng: RngSpec }
  /** `Salt.forSize(size, { rng })`: proportional bounds, then the `usize` draw (N1). */
  | { k: "saltForSize"; size: number; rng: RngSpec };
export type Outcome = string;

export interface VectorApi {
  run(recipe: Recipe): string;
  errorCode(e: unknown): string;
}

export function toBytes(b: Bytes): Uint8Array {
  if ("hex" in b) return Uint8Array.from(Buffer.from(b.hex, "hex"));
  if ("text" in b) return new TextEncoder().encode(b.text);
  const start = b.start ?? 0;
  return Uint8Array.from({ length: b.cycle }, (_, i) => (start + i) & 0xff);
}
export const hex = (u: Uint8Array): string => Buffer.from(u).toString("hex");
const short = (b: Bytes): string =>
  "hex" in b
    ? `hex:${b.hex.slice(0, 12)}`
    : "text" in b
      ? `text:${b.text.slice(0, 12)}`
      : `cyc:${b.cycle}`;
const rngName = (r: RngSpec): string =>
  "fake" in r ? "fake" : "seed" in r ? `seed=${r.seed[0].slice(0, 6)}` : `hkdf:${r.hkdf.salt}`;

export function recipeName(r: Recipe): string {
  switch (r.k) {
    case "value":
      return `value ${r.type} ${short(r.data)} (${toBytes(r.data).length}B)`;
    case "random":
      return `random ${r.type} ${rngName(r.rng)}${r.len ? ` len=${r.len}` : ""}`;
    case "derive":
      return `derive ${r.type} ${short(r.km)}`;
    case "digest":
      return `digest ${short(r.image)} (${toBytes(r.image).length}B)`;
    case "compressed":
      return `compressed ${short(r.data)} (${toBytes(r.data).length}B)${r.digest ? " +digest" : ""}`;
    case "seed":
      return `seed ${short(r.data)} name=${r.name ?? "-"} note=${r.note ?? "-"} date=${r.date ?? "-"}`;
    case "encrypt":
      return `encrypt ${short(r.plaintext)} (${toBytes(r.plaintext).length}B)${r.aad ? " +aad" : ""}`;
    case "x25519Shared":
      return `x25519Shared ${short(r.priv)}`;
    case "signingKeys":
      return `signingKeys ${r.scheme} ${short(r.key)}`;
    case "sign":
      return `sign ${r.scheme} ${short(r.key)} msg=${short(r.message)}${r.rng ? ` ${rngName(r.rng)}` : ""}`;
    case "sshFromSeed":
      return `sshFromSeed ${r.alg} ${short(r.seed)} "${r.comment}"${r.message ? " +sign" : ""}`;
    case "sshFromPem":
      return `sshFromPem ${r.pem.slice(36, 60)}${r.message ? " +sign" : ""}`;
    case "pkb":
      return `pkb ${short(r.seed)}`;
    case "keypair":
      return `keypair ${r.sigScheme}/${r.encScheme} ${rngName(r.rng)}`;
    case "seal":
      return `seal ${short(r.plaintext)} → ${"x25519" in r.recipient ? "x25519" : `mlkem${r.recipient.mlkem}`}${r.aad ? " +aad" : ""}`;
    case "params":
      return `params ${r.method} salt=${toBytes(r.salt).length}B ${r.hash ?? ""}${r.iterations ?? ""}${r.logN ?? ""}${r.id ?? ""}`;
    case "encryptedKey":
      return `encryptedKey ${r.method} ${short(r.secret)}`;
    case "hkdfRng":
      return `hkdfRng ${short(r.km)} "${r.salt}" ${r.draws.join(",")}${r.pageLen ? ` page=${r.pageLen}` : ""}`;
    case "mldsa":
      return `mldsa${r.level} ${rngName(r.rng)}${r.message ? " +sign" : ""}`;
    case "mlkem":
      return `mlkem${r.level} ${rngName(r.rng)}`;
    case "sskr":
      return `sskr ${r.spec.gt}/[${r.spec.groups.map((g) => `${g.mt}-of-${g.mc}`).join(",")}] ${rngName(r.rng)}`;
    case "decode":
      return `decode ${r.type} ${r.hex.slice(0, 20)}… (${r.hex.length / 2}B)`;
    case "urParse":
      return `urParse ${r.type} ${r.s.slice(0, 28)}…`;
    case "verifyStrict":
      return `verifyStrict ${r.note}`;
    case "decodeUntagged":
      return `decodeUntagged ${r.type} ${r.hex.slice(0, 16)}…`;
    case "signingDefault":
      return `signingDefault ${rngName(r.rng)}`;
    case "kdfDomain":
      return `kdfDomain ${r.method} ${[r.iterations, r.logN, r.r, r.p].filter((x) => x !== undefined).join(",")}`;
    case "domain":
      return `domain ${r.case}`;
    case "summary":
      return `summary ${r.note}`;
    case "saltInRange":
      return `saltInRange ${r.min}..=${r.max} ${rngName(r.rng)}`;
    case "saltForSize":
      return `saltForSize ${r.size} ${rngName(r.rng)}`;
  }
}

/** Recipe kinds the frozen baseline bundle cannot run (its surface has no equivalent). */
export const BASELINE_UNSUPPORTED: ReadonlySet<Recipe["k"]> = new Set<Recipe["k"]>([
  "signingDefault",
  "kdfDomain",
  "domain",
  "summary",
  // The baseline drew salt lengths through the 32-bit sampler (a different
  // draw from the reference's `usize`); no twin to compare.
  "saltInRange",
  "saltForSize",
]);

export function materialize(api: VectorApi, r: Recipe): Outcome {
  try {
    return api.run(r);
  } catch (e) {
    return `throw:${api.errorCode(e)}`;
  }
}

export const FAKE_FILL = (dest: Uint8Array): void => {
  let b = 0;
  for (let i = 0; i < dest.length; i++) {
    dest[i] = b;
    b = (b + 17) & 0xff;
  }
};

export function baselineAdapterFor(m: any, randBaseline: any): VectorApi {
  return rustShapedAdapterFor(m, randBaseline, { newRand: false });
}
/** The working tree. */
export function redesignedAdapterFor(m: any, rand: any): VectorApi {
  return redesignedShapedAdapterFor(m, rand, { newRand: true });
}
