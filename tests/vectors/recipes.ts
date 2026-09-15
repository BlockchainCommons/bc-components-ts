/**
 * Vector recipes. A recipe names an operation and its inputs;
 * `materialize` runs it through a `VectorApi` and returns one outcome
 * string, so the same recipe drives the golden file, the differential and
 * the Rust harness. Adapters bridge the frozen baseline and the working
 * tree.
 *
 * Outcomes are wire: tagged CBOR hex, UR strings, key/derivation hex,
 * OpenSSH text. Where a constructor draws from the secure generator with no
 * way to seed it (sealing, key locking, ML-KEM encapsulation) the outcome
 * carries the artefact itself (the sealed message, the locked key, the
 * ciphertext) next to the deterministic parts, so the Rust harness can open
 * it with the recipient's key instead of comparing a structure.
 *
 * A failure is `throw:<code>` or, with `messages`, `throw:<code>:<message>`:
 * a `ComponentsError`'s code and message, a `CborError` as `Cbor`, a
 * `URError`'s code, sskr's `SskrError` code, and any other error's class
 * name (a foreign class leaking would show).
 */

import { rustShapedAdapterFor } from "./baseline-adapter";
import { workingTreeAdapterOver } from "./working-tree-adapter";
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
/** `keypair_opt_using` signature schemes, the reference's `SignatureScheme` names in lower case. */
export type KeypairScheme =
  | Scheme
  | "mldsa44"
  | "mldsa65"
  | "mldsa87"
  | "sshEd25519"
  | "sshDsa"
  | "sshEcdsaP256"
  | "sshEcdsaP384";
export type EncScheme = "x25519" | "mlkem512" | "mlkem768" | "mlkem1024";
export type SshAlg = "ed25519" | "dsa" | "ecdsa-p256" | "ecdsa-p384" | "ecdsa-p521" | "rsa";
export type KdfMethod = "hkdf" | "pbkdf2" | "scrypt" | "argon2id" | "sshAgent";
/**
 * The types with a decoder on both sides. The EC key classes only encode, as
 * the reference; `authTag`, the KDF parameter types, `kdp`, `hashType`,
 * `kdMethod` and the levels are the `TryFrom<CBOR>` impls (no tag of their
 * own).
 */
export type DecodeType =
  | Exclude<
      ValueType,
      "ecPriv" | "ecPub" | "ecUncompressed" | "schnorrPub" | "ed25519Priv" | "ed25519Pub"
    >
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
  | "mlkemCiphertext"
  | "hkdfParams"
  | "pbkdf2Params"
  | "scryptParams"
  | "argon2idParams"
  | "sshAgentParams"
  | "kdp"
  | "hashType"
  | "kdMethod"
  | "mlkemLevel"
  | "mldsaLevel";
/** The types with a `from_hex` in the reference (plus the Ed25519 pair, which returns a `Result`). */
export type HexType =
  | "digest"
  | "nonce"
  | "salt"
  | "arid"
  | "xid"
  | "reference"
  | "symmetricKey"
  | "json"
  | "sskrShare"
  | "x25519Priv"
  | "x25519Pub"
  | "ed25519Priv"
  | "ed25519Pub"
  | "uuid";
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
  /** Raw DEFLATE bytes through the inflater, then through `Compressed.decompress`. */
  | { k: "inflate"; hex: string }
  | { k: "seed"; data: Bytes; name?: string; note?: string; date?: number }
  | { k: "encrypt"; key: Bytes; nonce: Bytes; plaintext: Bytes; aad?: Bytes }
  | { k: "x25519Shared"; priv: Bytes; pub: Bytes }
  | { k: "signingKeys"; scheme: Scheme; key: Bytes }
  | { k: "sign"; scheme: Scheme; key: Bytes; message: Bytes; rng?: RngSpec }
  /** `SigningPublicKey.verify` over raw key and signature bytes: `true`, `false`, or a throw. */
  | { k: "verify"; scheme: Scheme; pub: Bytes; sig: Bytes; message: Bytes; note: string }
  | {
      k: "sshFromSeed";
      seed: Bytes;
      alg: SshAlg;
      comment: string;
      message?: Bytes;
      namespace?: string;
    }
  | { k: "sshFromPem"; pem: string; message?: Bytes; namespace?: string }
  /** An OpenSSH private key, public key or SSHSIG text through the parser: the re-encoded text or a throw. */
  | { k: "sshText"; kind: "priv" | "pub" | "sig"; text: string; note: string }
  | { k: "pkb"; seed: Bytes }
  | { k: "keypair"; sigScheme: KeypairScheme; encScheme: EncScheme; rng: RngSpec }
  | {
      k: "seal";
      plaintext: Bytes;
      recipient: { x25519: Bytes } | { mlkem: 512 | 768 | 1024; rng: RngSpec };
      aad?: Bytes;
      /** Fixed nonce; the ephemeral key stays random on both sides. */
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
  /** `UR.parse`, then the codec: the reference's `from_ur_string` in its two steps. */
  | { k: "urParse"; type: DecodeType; s: string }
  /** Ed25519 verification of raw key/signature bytes: `valid` / `invalid`. */
  | { k: "verifyStrict"; pub: Bytes; sig: Bytes; message: Bytes; note: string }
  /** `fromCbor` over the UNTAGGED encoding. */
  | { k: "decodeUntagged"; type: DecodeType; hex: string }
  /** `SigningPrivateKey.random().scheme | generateKeypair() signing scheme`. */
  | { k: "signingDefault"; rng: RngSpec }
  /** KDF parameter construction with out-of-domain numbers: `ok:…` or a throw. */
  | { k: "kdfDomain"; method: "pbkdf2" | "scrypt"; iterations?: Num; logN?: Num; r?: Num; p?: Num }
  /** A named JS-only input case from the adapter's table: `ok:…` or `throw:<class>:<code>`. */
  | { k: "domain"; case: string }
  /** The tag summariser applied to tagged CBOR: the summary, `error:<message>`, or `none`. */
  | { k: "summary"; hex: string; note: string }
  /** `Salt.randomInRange(min, max, { rng })`: the length is a `usize` draw. */
  | { k: "saltInRange"; min: number; max: number; rng: RngSpec }
  /** `Salt.forSize(size, { rng })`: proportional bounds, then the `usize` draw. */
  | { k: "saltForSize"; size: number; rng: RngSpec }
  /** `URI.from(text)`: the text back, or a throw. */
  | { k: "uri"; text: string }
  /** `UUID.fromString(text)`: the canonical text back, or a throw. */
  | { k: "uuidParse"; text: string }
  /** `X.fromHex(text)`: the bytes, or a throw. */
  | { k: "hex"; type: HexType; text: string }
  /** A named API case both sides implement (see the adapters' tables). */
  | { k: "api"; case: string }
  /** `cborTags()` of a type, as the tags store names them at the time. */
  | { k: "cborTags"; type: DecodeType }
  /** `inner` run with no tags registered (the harness runs these rows before `register_tags()`). */
  | { k: "noreg"; inner: Recipe }
  /**
   * SSH-agent key derivation over an in-memory agent holding the listed
   * identities: the lock under an injected nonce (the locked key, the
   * content key and the secret; the reference unlocks it), then optionally
   * the unlock of that message with another secret, a stored id override
   * and one byte of the AAD or ciphertext flipped.
   */
  | {
      k: "agentLock";
      identities: { seed: Bytes; comment: string; alg?: SshAlg }[];
      refuse?: boolean;
      salt: Bytes;
      secret: Bytes;
      key: Bytes;
      nonce: Bytes;
      unlock?: { secret: Bytes; storedId?: string; tamper?: "aad" | "ciphertext" };
    };
export type Outcome = string;

export interface VectorApi {
  run(recipe: Recipe): string;
  /** The recipes whose operation is asynchronous (`agentLock`); absent on the frozen baseline. */
  runAsync?(recipe: Recipe): Promise<string>;
  errorCode(e: unknown): string;
  /** The error's message; absent on the frozen baseline (messages are not compared there). */
  errorMessage?(e: unknown): string;
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
const clip = (s: string, n: number): string =>
  (s.length > n ? `${s.slice(0, n)}…` : s).replace(/\r/g, "\\r").replace(/\n/g, "\\n");

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
    case "inflate":
      return `inflate ${r.hex.slice(0, 24)} (${r.hex.length / 2}B)`;
    case "seed":
      return `seed ${short(r.data)} name=${r.name ?? "-"} note=${r.note ?? "-"} date=${r.date ?? "-"}`;
    case "encrypt":
      return `encrypt ${short(r.plaintext)} (${toBytes(r.plaintext).length}B)${r.aad ? " +aad" : ""}`;
    case "x25519Shared":
      return `x25519Shared ${short(r.priv)} ${short(r.pub)}`;
    case "signingKeys":
      return `signingKeys ${r.scheme} ${short(r.key)}`;
    case "sign":
      return `sign ${r.scheme} ${short(r.key)} msg=${short(r.message)}${r.rng ? ` ${rngName(r.rng)}` : ""}`;
    case "verify":
      return `verify ${r.scheme} ${r.note}`;
    case "sshFromSeed":
      return `sshFromSeed ${r.alg} ${short(r.seed)} "${r.comment}"${r.message ? " +sign" : ""}`;
    case "sshFromPem":
      return `sshFromPem ${r.pem.slice(36, 60)}${r.message ? " +sign" : ""}`;
    case "sshText":
      return `sshText ${r.kind} ${r.note}`;
    case "pkb":
      return `pkb ${short(r.seed)}`;
    case "keypair":
      return `keypair ${r.sigScheme}/${r.encScheme} ${rngName(r.rng)}`;
    case "seal":
      return `seal ${short(r.plaintext)} → ${"x25519" in r.recipient ? "x25519" : `mlkem${r.recipient.mlkem}`}${r.aad ? " +aad" : ""}${r.nonce ? " +nonce" : ""}`;
    case "params":
      return `params ${r.method} salt=${toBytes(r.salt).length}B ${r.hash ?? ""}${r.iterations ?? ""}${r.logN ?? ""}${r.id ?? ""}`;
    case "encryptedKey":
      return `encryptedKey ${r.method} ${short(r.secret)}${r.iterations !== undefined ? ` iter=${r.iterations}` : ""}${r.logN !== undefined ? ` logN=${r.logN}` : ""}`;
    case "hkdfRng":
      return `hkdfRng ${short(r.km)} "${r.salt}" ${r.draws.join(",")}${r.pageLen !== undefined ? ` page=${r.pageLen}` : ""}`;
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
    case "uri":
      return `uri ${clip(JSON.stringify(r.text), 40)}`;
    case "uuidParse":
      return `uuidParse ${clip(JSON.stringify(r.text), 48)}`;
    case "hex":
      return `hex ${r.type} ${clip(JSON.stringify(r.text), 40)}`;
    case "api":
      return `api ${r.case}`;
    case "cborTags":
      return `cborTags ${r.type}`;
    case "noreg":
      return `noreg ${recipeName(r.inner)}`;
    case "agentLock":
      return `agentLock [${r.identities.map((i) => `${i.comment}${i.alg ? `:${i.alg}` : ""}`).join(",")}]${r.refuse ? " refuse" : ""} secret=${short(r.secret)}${r.unlock ? ` +unlock secret=${short(r.unlock.secret)}${r.unlock.storedId !== undefined ? ` stored=${JSON.stringify(r.unlock.storedId)}` : ""}${r.unlock.tamper ? ` tamper=${r.unlock.tamper}` : ""}` : ""}`;
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
  // Surfaces the baseline never had: the inflater, the SSH text grammar and
  // algorithms, the verify rows, the hex and text parsers, the named API
  // cases, `cborTags()` through the store and the unregistered-store rows.
  "inflate",
  "sshText",
  "verify",
  "uri",
  "uuidParse",
  "hex",
  "api",
  "cborTags",
  "noreg",
  "agentLock",
]);

/** Decode types the frozen bundle never had a class for. */
const BASELINE_UNSUPPORTED_DECODE_TYPES: ReadonlySet<string> = new Set([
  "authTag",
  "hkdfParams",
  "pbkdf2Params",
  "scryptParams",
  "argon2idParams",
  "sshAgentParams",
  "kdp",
  "hashType",
  "kdMethod",
  "mlkemLevel",
  "mldsaLevel",
]);
/**
 * Whether the frozen bundle can run a recipe: its kind is supported and,
 * within a kind, the decode type, keypair scheme, SSH algorithm or page
 * length is one the bundle had (a zero HKDF page length loops forever there).
 */
export function baselineSupports(r: Recipe): boolean {
  if (BASELINE_UNSUPPORTED.has(r.k)) return false;
  if (
    (r.k === "decode" || r.k === "decodeUntagged" || r.k === "urParse") &&
    BASELINE_UNSUPPORTED_DECODE_TYPES.has(r.type)
  )
    return false;
  if (r.k === "keypair" && !["schnorr", "ecdsa", "ed25519"].includes(r.sigScheme)) return false;
  if (r.k === "sshFromSeed" && !["ed25519", "ecdsa-p256", "ecdsa-p384"].includes(r.alg))
    return false;
  if (r.k === "hkdfRng" && r.pageLen === 0) return false;
  return true;
}

export interface MaterializeOptions {
  /** Append the error message to a `throw:` outcome (the Rust harness compares it). */
  messages?: boolean;
}

export function materialize(
  api: VectorApi,
  r: Recipe,
  { messages = false }: MaterializeOptions = {},
): Outcome {
  try {
    return api.run(r);
  } catch (e) {
    return thrown(api, e, messages);
  }
}
/** `materialize` for a recipe whose operation may be asynchronous. */
export async function materializeAsync(
  api: VectorApi,
  r: Recipe,
  { messages = false }: MaterializeOptions = {},
): Promise<Outcome> {
  try {
    return api.runAsync === undefined ? api.run(r) : await api.runAsync(r);
  } catch (e) {
    return thrown(api, e, messages);
  }
}
function thrown(api: VectorApi, e: unknown, messages: boolean): Outcome {
  const code = api.errorCode(e);
  if (!messages || api.errorMessage === undefined) return `throw:${code}`;
  return `throw:${code}:${api.errorMessage(e)}`;
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
export function workingTreeAdapterFor(m: any, rand: any): VectorApi {
  return workingTreeAdapterOver(m, rand, { newRand: true });
}
