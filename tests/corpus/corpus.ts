/**
 * Deterministic differential corpus. Every input is a literal, a cyclic
 * byte pattern, a fixture file under `tests/fixtures`, or a CBOR mutation of
 * one of the pinned encodings in `encodings.json`; no package code runs
 * here (dcbor is used only to build the mutated CBOR).
 *
 * Categories are yielded in the order below; `noreg` comes first because
 * its rows must run before the tags are registered, on both sides.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  type Cbor,
  CborMap,
  MajorType,
  asArray,
  asBytes,
  asMap,
  asTaggedValue,
  asUnsigned,
  cbor,
  decodeCbor,
  taggedValue,
} from "@blockchaincommons/dcbor";
import type {
  Recipe,
  Bytes,
  RngSpec,
  ValueType,
  RandomType,
  Scheme,
  KeypairScheme,
  EncScheme,
  DecodeType,
  HexType,
} from "../vectors/recipes";

const here = dirname(fileURLToPath(import.meta.url));
const cyc = (n: number, start = 0): Bytes => ({ cycle: n, start });
const h = (hex: string): Bytes => ({ hex });
const t = (text: string): Bytes => ({ text });
const cycHex = (n: number, start = 0): string =>
  Array.from({ length: n }, (_, i) => ((start + i) & 0xff).toString(16).padStart(2, "0")).join("");
export const SEEDS: readonly [RngSpec, RngSpec, RngSpec] = [
  {
    seed: [
      "17295166580085024720",
      "422929670265678780",
      "5577237070365765850",
      "7953171132032326923",
    ],
  },
  { seed: ["1", "1", "1", "1"] },
  { seed: ["81985529216486895", "18364758544493064720", "3735928559", "14627333968358932480"] },
];
export const FAKE: RngSpec = { fake: true };
export const HKDF: RngSpec = { hkdf: { km: t("key material"), salt: "salt" } };

// Sizes each value type accepts; wrong sizes are the rejection table.
export const VALUE_SIZES: Record<ValueType, number[]> = {
  digest: [32],
  nonce: [12],
  salt: [8, 9, 16, 32, 64],
  arid: [32],
  uuid: [16],
  xid: [32],
  reference: [32],
  symmetricKey: [32],
  json: [2, 20, 200],
  uri: [8, 30],
  authTag: [16],
  x25519Priv: [32],
  x25519Pub: [32],
  ecPriv: [32],
  ecPub: [33],
  ecUncompressed: [65],
  schnorrPub: [32],
  ed25519Priv: [32],
  ed25519Pub: [32],
  privateKeyBase: [0, 16, 32, 64],
  sskrShare: [21, 37],
};
const WRONG_SIZES: Record<ValueType, number[]> = {
  digest: [0, 31, 33],
  nonce: [11, 13],
  salt: [0, 7],
  arid: [31],
  uuid: [15, 17],
  xid: [31],
  reference: [31],
  symmetricKey: [31, 33],
  json: [],
  uri: [],
  authTag: [15, 17],
  x25519Priv: [31],
  x25519Pub: [31],
  ecPriv: [31, 33],
  ecPub: [32, 65],
  ecUncompressed: [33],
  schnorrPub: [31],
  ed25519Priv: [31],
  ed25519Pub: [33],
  privateKeyBase: [],
  sskrShare: [],
};
// Real curve points where random bytes would not do.
const EC_PRIV = h("322b5c1dd5a17c3481c2297990c85c232ed3c17b52ce9905c6ec5193ad132c36");
const EC_PUB = h("02e8251dc3a17e0f2c07865ed191139ecbcddcbdd070ec1ff65df5148c7ef4005a");
const EC_PUB_INVALID = h("02d43099fe444807c46921a4f33a2a798b0d8cf5f6ec337bc764d1866b5d07ca42");
/** secp256k1 G, compressed and uncompressed. */
const G_COMPRESSED = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const G_UNCOMPRESSED_XY =
  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
  "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
/** The order of secp256k1, n. */
const SECP_N = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
const JSON_TEXT = t('{"a":1,"b":[true,null],"c":"x"}');
const URI_TEXT = t("https://example.com/path?q=1#frag");
const SSKR_SHARE = h("001100020000112233445566778899aabbccddeeff");

function* values(): Generator<Recipe> {
  for (const type of Object.keys(VALUE_SIZES) as ValueType[]) {
    if (type === "ecPub") {
      yield { k: "value", type, data: EC_PUB };
      yield { k: "value", type, data: EC_PUB_INVALID };
      // Prefixes the reference accepts at construction (decompression decides).
      yield { k: "value", type, data: h("00" + "00".repeat(32)) };
      yield { k: "value", type, data: h("05" + "ff".repeat(32)) };
      yield { k: "value", type, data: h("02" + "00".repeat(32)) };
    } else if (type === "ecUncompressed") {
      yield { k: "value", type, data: h("04" + G_UNCOMPRESSED_XY) };
      // Hybrid prefixes (libsecp256k1 accepts 06/07 when the parity matches y).
      yield { k: "value", type, data: h("06" + G_UNCOMPRESSED_XY) };
      yield { k: "value", type, data: h("07" + G_UNCOMPRESSED_XY) };
      yield { k: "value", type, data: h("00" + G_UNCOMPRESSED_XY) };
    } else if (type === "json") {
      yield { k: "value", type, data: JSON_TEXT };
      yield { k: "value", type, data: t("[]") };
      yield { k: "value", type, data: h("efbbbf7b7d") }; // U+FEFF {}
      yield { k: "value", type, data: h("fffe") }; // not UTF-8
    } else if (type === "uri") {
      yield { k: "value", type, data: URI_TEXT };
      yield { k: "value", type, data: t("ur:test/aeae") };
    } else if (type === "sskrShare") {
      yield { k: "value", type, data: SSKR_SHARE };
      yield {
        k: "value",
        type,
        data: h("0011110100ce5cce1ad9fe9cefa4707449576e8eadfc7d107c5a9e812b21f80aeca635cacd"),
      };
      // Short shares: held as bytes; the header accessors fail where the reference panics.
      yield { k: "value", type, data: cyc(4) };
      yield { k: "value", type, data: cyc(0) };
      yield { k: "value", type, data: cyc(5, 0x11) };
    } else if (type === "ecPriv") {
      yield { k: "value", type, data: EC_PRIV };
      yield { k: "value", type, data: cyc(32, 1) };
      // A zero scalar, n and ff…: accepted at construction, derivation panics in the reference.
      yield { k: "value", type, data: cyc(32, 0) };
      yield { k: "value", type, data: h(SECP_N) };
      yield { k: "value", type, data: h("ff".repeat(32)) };
    } else if (type === "ed25519Pub") {
      for (const n of VALUE_SIZES[type])
        for (const start of [0, 0x80]) yield { k: "value", type, data: cyc(n, start) };
      yield { k: "value", type, data: h("ff".repeat(31) + "7f") };
    } else {
      for (const n of VALUE_SIZES[type])
        for (const start of [0, 0x80]) yield { k: "value", type, data: cyc(n, start) };
    }
    for (const n of WRONG_SIZES[type]) yield { k: "value", type, data: cyc(n, 3) };
  }
  yield { k: "value", type: "uri", data: t("not a uri") };
  yield { k: "value", type: "uri", data: t("") };
}
function* randoms(): Generator<Recipe> {
  const types: RandomType[] = [
    "nonce",
    "salt",
    "arid",
    "uuid",
    "symmetricKey",
    "x25519Priv",
    "ecPriv",
    "ed25519Priv",
    "privateKeyBase",
    "seed",
  ];
  for (const type of types)
    for (const rng of [...SEEDS, FAKE, HKDF]) yield { k: "random", type, rng };
  for (const len of [8, 16, 24, 64]) yield { k: "random", type: "salt", rng: SEEDS[0], len };
  for (const len of [16, 24, 32]) yield { k: "random", type: "seed", rng: SEEDS[1], len };
}
/**
 * Salt lengths drawn from a seeded generator: the reference samples a
 * `RangeInclusive<usize>` (a 64-bit draw).
 */
function* saltLengths(): Generator<Recipe> {
  for (const rng of [...SEEDS, HKDF]) {
    for (const [min, max] of [
      [8, 32],
      [8, 17],
      [16, 64],
      [100, 4000],
      [8, 8],
    ] as [number, number][])
      yield { k: "saltInRange", min, max, rng };
    for (const size of [20, 65, 1000, 20000]) yield { k: "saltForSize", size, rng };
  }
}
function* derives(): Generator<Recipe> {
  for (const km of [
    t("test key material"),
    t("material 1"),
    h("59f2293a5bce7d4de59e71b4207ac5d2"),
    cyc(0),
    cyc(64, 9),
  ])
    for (const type of ["x25519", "ec", "ed25519"] as const) yield { k: "derive", type, km };
}
function* digests(): Generator<Recipe> {
  for (const image of [t("hello world"), cyc(0), cyc(1), cyc(63), cyc(64), cyc(65), cyc(1024, 5)])
    yield { k: "digest", image };
}
const LOREM = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ";
/** A small xorshift32 stream, defined here and nowhere else. */
function prng(length: number, seed: number): Bytes {
  let s = seed >>> 0;
  const out: string[] = [];
  for (let i = 0; i < length; i++) {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;
    out.push((s & 0xff).toString(16).padStart(2, "0"));
  }
  return h(out.join(""));
}
function* compresseds(): Generator<Recipe> {
  for (const n of [0, 1, 10, 53, 57, 100, 114, 256, 500, 1000, 1024, 2048, 4096, 10000, 40000]) {
    yield { k: "compressed", data: t(LOREM.repeat(Math.ceil(n / LOREM.length)).slice(0, n)) };
    yield { k: "compressed", data: cyc(n, (n * 7) & 0xff), digest: n % 2 === 0 };
  }
  yield { k: "compressed", data: t(LOREM.repeat(2)), digest: true };
  yield {
    k: "compressed",
    data: h(
      Array.from({ length: 300 }, (_, i) =>
        ((i * 131 + 7) & 0xff).toString(16).padStart(2, "0"),
      ).join(""),
    ),
  };
  // Runs, repeats and incompressible bytes exercise the match finder.
  yield { k: "compressed", data: h("00".repeat(300)) };
  yield { k: "compressed", data: h("41".repeat(70000)) };
  yield { k: "compressed", data: t("abc".repeat(2000)) };
  yield { k: "compressed", data: h("0001".repeat(600)) };
  for (const [n, seed] of [
    [100, 1],
    [1000, 2],
    [5000, 3],
    [33000, 4],
    [70000, 5],
  ] as const)
    yield { k: "compressed", data: prng(n, seed) };
}
/** Raw DEFLATE streams through the inflater: the inputs of the miniz fixtures. */
const INFLATE_FIXTURE = join(here, "../fixtures/miniz/inflate.json");
function inflateCases(): { name: string; hex: string }[] {
  const file = JSON.parse(readFileSync(INFLATE_FIXTURE, "utf8")) as {
    cases: { name: string; hex: string }[];
  };
  return file.cases;
}
function* inflates(): Generator<Recipe> {
  for (const c of inflateCases()) yield { k: "inflate", hex: c.hex };
}
function* seeds(): Generator<Recipe> {
  for (const data of [cyc(16, 1), cyc(32, 0x40), h("59f2293a5bce7d4de59e71b4207ac5d2")]) {
    yield { k: "seed", data };
    yield { k: "seed", data, name: "Test Seed" };
    yield {
      k: "seed",
      data,
      name: "Test Seed",
      note: "A test note",
      date: Date.UTC(2023, 5, 15, 10, 30, 0),
    };
    yield { k: "seed", data, note: "only note" };
    yield { k: "seed", data, date: 0 };
    yield { k: "seed", data, name: "", note: "" };
  }
  yield { k: "seed", data: cyc(16, 1), date: 1700000000123 };
  yield { k: "seed", data: cyc(16, 1), date: -86400000 };
}
const RFC_KEY = h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
const RFC_NONCE = h("070000004041424344454647");
const RFC_PT = t(
  "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
);
const RFC_AAD = h("50515253c0c1c2c3c4c5c6c7");
function* encrypts(): Generator<Recipe> {
  yield { k: "encrypt", key: RFC_KEY, nonce: RFC_NONCE, plaintext: RFC_PT, aad: RFC_AAD };
  yield { k: "encrypt", key: RFC_KEY, nonce: RFC_NONCE, plaintext: RFC_PT };
  for (const n of [0, 1, 16, 17, 100, 1024]) {
    yield { k: "encrypt", key: cyc(32, 0x10), nonce: cyc(12, 0xa0), plaintext: cyc(n, 5) };
    yield {
      k: "encrypt",
      key: cyc(32, 0x10),
      nonce: cyc(12, 0xa0),
      plaintext: cyc(n, 5),
      aad: cyc(20, 0x30),
    };
  }
  // AAD that is a tagged digest (the envelope convention) - d99c41 5820 …
  yield {
    k: "encrypt",
    key: cyc(32, 0x10),
    nonce: cyc(12, 0xa0),
    plaintext: cyc(40),
    aad: h("d99c415820" + "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"),
  };
  yield {
    k: "x25519Shared",
    priv: cyc(32, 1),
    pub: h("863cf3facee3ba45dc54e5eedecb21d791d64adfb0a1c63bfb6fea366c1ee62b"),
  };
  yield {
    k: "x25519Shared",
    priv: h("77ff838285a0403d3618aa8c30491f99f55221be0b944f50bfb371f43b897485"),
    pub: cyc(32, 9),
  };
  // Low-order peers (RFC 7748 §6.1): the reference derives from the all-zero secret.
  yield { k: "x25519Shared", priv: h("01".repeat(32)), pub: h("00".repeat(32)) };
  yield { k: "x25519Shared", priv: h("01".repeat(32)), pub: h("01" + "00".repeat(31)) };
  yield {
    k: "x25519Shared",
    priv: cyc(32, 1),
    pub: h("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
  };
  yield { k: "x25519Shared", priv: cyc(32, 1), pub: h("ff".repeat(31) + "7f") };
}
const WOLF = t("Wolf McNally");
function* signings(): Generator<Recipe> {
  const keys = [EC_PRIV, cyc(32, 1), h("59f2293a5bce7d4de59e71b4207ac5d2".repeat(2))];
  for (const scheme of ["schnorr", "ecdsa", "ed25519"] as Scheme[]) {
    for (const key of keys) {
      yield { k: "signingKeys", scheme, key };
      for (const message of [WOLF, cyc(0), cyc(100, 7)]) {
        if (scheme === "schnorr") {
          yield { k: "sign", scheme, key, message, rng: FAKE };
          yield { k: "sign", scheme, key, message, rng: SEEDS[0] };
        } else yield { k: "sign", scheme, key, message };
      }
    }
  }
}
/**
 * `verify` over raw key and signature bytes: `true`, `false`, or the typed
 * failure where the reference's `bc-crypto` panics on a key or signature it
 * cannot parse.
 */
function* verifies(): Generator<Recipe> {
  const message = t("abc");
  const zeroSig = h("00".repeat(64));
  for (let i = 0; i < 256; i++) {
    yield {
      k: "verify",
      scheme: "ed25519",
      pub: h(i.toString(16).padStart(2, "0") + "00".repeat(31)),
      sig: zeroSig,
      message,
      note: `ed25519 key [${i}, 0×31] zero signature`,
    };
  }
  yield {
    k: "verify",
    scheme: "ed25519",
    pub: h("ff".repeat(31) + "7f"),
    sig: zeroSig,
    message,
    note: "ed25519 undecodable key ff…7f",
  };
  const one = "00".repeat(31) + "01";
  for (const [r, s, note] of [
    [SECP_N, one, "r = n, s = 1"],
    [one, SECP_N, "r = 1, s = n"],
    ["00".repeat(32), one, "r = 0, s = 1"],
    [one, "00".repeat(32), "r = 1, s = 0"],
    [one, one, "r = 1, s = 1"],
  ] as const) {
    yield { k: "verify", scheme: "ecdsa", pub: h(G_COMPRESSED), sig: h(r + s), message, note };
  }
  for (const [pub, note] of [
    ["00".repeat(33), "ecdsa key zeros33"],
    ["02" + "00".repeat(32), "ecdsa key 02 zeros"],
    ["05" + "ff".repeat(32), "ecdsa key 05 ff"],
  ] as const) {
    yield { k: "verify", scheme: "ecdsa", pub: h(pub), sig: h(one + one), message, note };
  }
  yield {
    k: "verify",
    scheme: "schnorr",
    pub: h("05".repeat(32)),
    sig: zeroSig,
    message,
    note: "schnorr key 05×32 (not a point)",
  };
  yield {
    k: "verify",
    scheme: "schnorr",
    pub: h("ff".repeat(32)),
    sig: zeroSig,
    message,
    note: "schnorr key ff×32",
  };
  yield {
    k: "verify",
    scheme: "schnorr",
    pub: h(G_COMPRESSED.slice(2)),
    sig: zeroSig,
    message,
    note: "schnorr key G.x zero signature",
  };
}
const RUST_SEED = h("59f2293a5bce7d4de59e71b4207ac5d2");
export const RUST_DSA_PEM = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsgAAAAdzc2gtZH
NzAAAAgQCWG4f7r8FAMT/IL11w9OfM/ZduIQ8vEq1Ub+uMdyJS8wS/jXL5OB2/dPnXCNSt
L4vjSqpDzMs+Dtd5wJy6baSQ3zGEbYv71mkIRJB/AtSVmd8FZe5AEjLFvHxYMSlO0jpi1Y
/1nLM7vLQu4QByDCLhYYjPxgrZKXB3cLxtjvly5wAAABUA4fIZLivnDVcg9PXzwcb5m07H
9k0AAACBAJK5Vm6t1Sg7n+C63wrNgDA6LTNyGzxqRVM2unI16jisCOzuC98Dgs+IbAkLhT
qWSY+nI+U9HBHc7sr+KKdWCzR76NLK5eSilXvtt8g+LfHIXvCjD4Q2puowtjDoXSEQAJYd
c1gtef21KZ2eoKoyAwzQIehCbvLpwYbxnhap5usVAAAAgGCrsbfReaDZo1Cw4/dFlJWBDP
sMGeG04/2hCThNmU+zLiKCwsEg0X6onOTMTonCXve3fVb5lNjIU92iTmt5QkmOj2hjsbgo
q/0sa0lALHp7UcK/W4IdU4Abtc4m0SUflgJcds1nsy2rKUNEtAfRa/WwtDResWOa4T7L+3
FEUdavAAAB6F0RJ3hdESd4AAAAB3NzaC1kc3MAAACBAJYbh/uvwUAxP8gvXXD058z9l24h
Dy8SrVRv64x3IlLzBL+Ncvk4Hb90+dcI1K0vi+NKqkPMyz4O13nAnLptpJDfMYRti/vWaQ
hEkH8C1JWZ3wVl7kASMsW8fFgxKU7SOmLVj/Wcszu8tC7hAHIMIuFhiM/GCtkpcHdwvG2O
+XLnAAAAFQDh8hkuK+cNVyD09fPBxvmbTsf2TQAAAIEAkrlWbq3VKDuf4LrfCs2AMDotM3
IbPGpFUza6cjXqOKwI7O4L3wOCz4hsCQuFOpZJj6cj5T0cEdzuyv4op1YLNHvo0srl5KKV
e+23yD4t8che8KMPhDam6jC2MOhdIRAAlh1zWC15/bUpnZ6gqjIDDNAh6EJu8unBhvGeFq
nm6xUAAACAYKuxt9F5oNmjULDj90WUlYEM+wwZ4bTj/aEJOE2ZT7MuIoLCwSDRfqic5MxO
icJe97d9VvmU2MhT3aJOa3lCSY6PaGOxuCir/SxrSUAsentRwr9bgh1TgBu1zibRJR+WAl
x2zWezLaspQ0S0B9Fr9bC0NF6xY5rhPsv7cURR1q8AAAAVANWljfuxQcmJ/T7wSmAUXmXo
6ZI0AAAADEtleSBjb21tZW50LgECAwQF
-----END OPENSSH PRIVATE KEY-----
`;
/** A reference-generated DSA key whose private exponent x is 1 (comment `small-x-fixture`). */
export const RUST_DSA_SMALL_X_PEM = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsQAAAAdzc2gtZH
NzAAAAgQC/7asaHYbbX7CUlzKoKpntY8zNkkYuG/qkRzqyvDNzbefnKasi1epmAhrCWnTH
5qYtwzup62vucUlfvs3mvCD72Q+cGaCooWdqUyYFxIgE4ZCN6EBtywGaYUbvTMKQfMTMnM
gCpmrmcN6MfEd7i5TWYlYhD9HMVXR67Bg9f9ZkGQAAABUAxWqN2dXOPvdlH3lBIGdYzWca
uGUAAACAKepvsejOCO+dil9sK0tzmUvn7P2OLtijHZ7Am/Eamr6R3xXfKmWFmjVqJIuw8V
G+P0hNbIPAsYjCnXXVZEwgsENObYMj0bBTVpPu75cMtRaGKOVGBIUqKltFr2uASdKyB2dJ
yMkGjS10orxOqeVaPxSKpsp26tfTNIZhEOgrQ1IAAACAKepvsejOCO+dil9sK0tzmUvn7P
2OLtijHZ7Am/Eamr6R3xXfKmWFmjVqJIuw8VG+P0hNbIPAsYjCnXXVZEwgsENObYMj0bBT
VpPu75cMtRaGKOVGBIUqKltFr2uASdKyB2dJyMkGjS10orxOqeVaPxSKpsp26tfTNIZhEO
grQ1IAAAHYAAAAAAAAAAAAAAAHc3NoLWRzcwAAAIEAv+2rGh2G21+wlJcyqCqZ7WPMzZJG
Lhv6pEc6srwzc23n5ymrItXqZgIawlp0x+amLcM7qetr7nFJX77N5rwg+9kPnBmgqKFnal
MmBcSIBOGQjehAbcsBmmFG70zCkHzEzJzIAqZq5nDejHxHe4uU1mJWIQ/RzFV0euwYPX/W
ZBkAAAAVAMVqjdnVzj73ZR95QSBnWM1nGrhlAAAAgCnqb7HozgjvnYpfbCtLc5lL5+z9ji
7Yox2ewJvxGpq+kd8V3yplhZo1aiSLsPFRvj9ITWyDwLGIwp111WRMILBDTm2DI9GwU1aT
7u+XDLUWhijlRgSFKipbRa9rgEnSsgdnScjJBo0tdKK8TqnlWj8UiqbKdurX0zSGYRDoK0
NSAAAAgCnqb7HozgjvnYpfbCtLc5lL5+z9ji7Yox2ewJvxGpq+kd8V3yplhZo1aiSLsPFR
vj9ITWyDwLGIwp111WRMILBDTm2DI9GwU1aT7u+XDLUWhijlRgSFKipbRa9rgEnSsgdnSc
jJBo0tdKK8TqnlWj8UiqbKdurX0zSGYRDoK0NSAAAAAQEAAAAPc21hbGwteC1maXh0dXJl
AQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
`;
function* sshes(): Generator<Recipe> {
  for (const seed of [RUST_SEED, cyc(32, 1)]) {
    for (const alg of [
      "ed25519",
      "ecdsa-p256",
      "ecdsa-p384",
      "ecdsa-p521",
      "dsa",
      "rsa",
    ] as const) {
      yield { k: "sshFromSeed", seed, alg, comment: "Key comment." };
      yield { k: "sshFromSeed", seed, alg, comment: "", message: RFC_PT, namespace: "test" };
    }
  }
  yield { k: "sshFromPem", pem: RUST_DSA_PEM };
  yield { k: "sshFromPem", pem: RUST_DSA_PEM, message: RFC_PT, namespace: "test" };
  yield { k: "sshFromPem", pem: RUST_DSA_SMALL_X_PEM };
  yield { k: "sshFromPem", pem: RUST_DSA_SMALL_X_PEM, message: t("hello"), namespace: "fixture" };
}
/** The SSH text grammar fixtures: OpenSSH private keys, public keys and SSHSIG texts. */
const SSH_TEXT_FIXTURE = join(here, "../fixtures/ssh-text/cases.json");
interface SshTextCase {
  id: string;
  kind: "priv" | "pub" | "sig";
  text: string;
}
function sshTextCases(): SshTextCase[] {
  const file = JSON.parse(readFileSync(SSH_TEXT_FIXTURE, "utf8")) as
    SshTextCase[] | { cases: SshTextCase[] };
  return Array.isArray(file) ? file : file.cases;
}
function* sshTexts(): Generator<Recipe> {
  for (const c of sshTextCases()) yield { k: "sshText", kind: c.kind, text: c.text, note: c.id };
}
function* pkbs(): Generator<Recipe> {
  for (const seed of [RUST_SEED, cyc(32, 1), cyc(16, 0x99), cyc(64, 0x21), cyc(0)])
    yield { k: "pkb", seed };
  for (const sigScheme of ["schnorr", "ecdsa", "ed25519"] as Scheme[])
    for (const encScheme of ["x25519", "mlkem768"] as EncScheme[])
      yield { k: "keypair", sigScheme, encScheme, rng: SEEDS[0] };
  yield { k: "keypair", sigScheme: "schnorr", encScheme: "mlkem512", rng: FAKE };
  yield { k: "keypair", sigScheme: "ed25519", encScheme: "mlkem1024", rng: SEEDS[2] };
  // The post-quantum signature schemes and the SSH schemes through `keypair_opt_using`.
  for (const sigScheme of ["mldsa44", "mldsa65", "mldsa87"] as KeypairScheme[])
    yield { k: "keypair", sigScheme, encScheme: "x25519", rng: SEEDS[1] };
  for (const sigScheme of ["sshEd25519", "sshDsa", "sshEcdsaP256", "sshEcdsaP384"] as const)
    yield { k: "keypair", sigScheme, encScheme: "x25519", rng: SEEDS[1] };
}
function* seals(): Generator<Recipe> {
  for (const plaintext of [cyc(0), t("hello"), cyc(1000, 3)]) {
    yield { k: "seal", plaintext, recipient: { x25519: cyc(32, 1) } };
    yield { k: "seal", plaintext, recipient: { x25519: cyc(32, 1) }, aad: cyc(16, 0x50) };
  }
  for (const level of [512, 768, 1024] as const)
    yield { k: "seal", plaintext: t("pq"), recipient: { mlkem: level, rng: SEEDS[0] } };
  yield {
    k: "seal",
    plaintext: t("hello"),
    recipient: { x25519: cyc(32, 1) },
    nonce: cyc(12, 0x60),
  };
  yield {
    k: "seal",
    plaintext: t("hello"),
    recipient: { x25519: cyc(32, 1) },
    aad: cyc(16, 0x50),
    nonce: cyc(12, 0x60),
  };
}
function* kdfs(): Generator<Recipe> {
  const salt = cyc(16, 0x50);
  yield { k: "params", method: "hkdf", salt };
  yield { k: "params", method: "hkdf", salt, hash: "sha512" };
  yield { k: "params", method: "pbkdf2", salt };
  yield { k: "params", method: "pbkdf2", salt, iterations: 10, hash: "sha512" };
  yield { k: "params", method: "pbkdf2", salt, iterations: 0 };
  yield { k: "params", method: "scrypt", salt };
  yield { k: "params", method: "scrypt", salt, logN: 4, r: 8, p: 1 };
  yield { k: "params", method: "scrypt", salt, logN: 0, r: 8, p: 1 };
  yield { k: "params", method: "argon2id", salt };
  yield { k: "params", method: "sshAgent", salt, id: "my-key" };
  yield { k: "params", method: "sshAgent", salt, id: "" };
  yield { k: "params", method: "hkdf", salt: cyc(32, 0xaa) };
  const secret = t("password");
  const key = cyc(32, 0x10);
  yield { k: "encryptedKey", method: "hkdf", salt, secret, key };
  yield { k: "encryptedKey", method: "pbkdf2", salt, secret, key, iterations: 10 };
  yield { k: "encryptedKey", method: "pbkdf2", salt, secret, key, iterations: 0 };
  yield { k: "encryptedKey", method: "scrypt", salt, secret, key, logN: 4 };
  yield { k: "encryptedKey", method: "scrypt", salt, secret, key, logN: 0 };
  yield { k: "encryptedKey", method: "argon2id", salt, secret, key };
  yield { k: "encryptedKey", method: "sshAgent", salt, secret, key, id: "my-key" };
  yield { k: "hkdfRng", km: t("key_material"), salt: "salt", draws: [16, 16, 16, 16] };
  yield {
    k: "hkdfRng",
    km: t("key_material"),
    salt: "salt",
    draws: [1, 31, 33, 64, 100],
    pageLen: 64,
  };
  yield { k: "hkdfRng", km: cyc(32, 1), salt: "ssh-ed25519", draws: [32, 32] };
  for (const pageLen of [1, 3, 5, 33])
    yield { k: "hkdfRng", km: t("km"), salt: "salt", draws: [7], pageLen };
  // Page length 0: an empty draw returns; the reference never returns from a non-empty one.
  yield { k: "hkdfRng", km: t("km"), salt: "salt", draws: [0], pageLen: 0 };
}
function* pqs(): Generator<Recipe> {
  for (const level of [44, 65, 87] as const)
    yield { k: "mldsa", level, rng: SEEDS[0], message: WOLF };
  yield { k: "mldsa", level: 65, rng: FAKE };
  for (const level of [512, 768, 1024] as const) yield { k: "mlkem", level, rng: SEEDS[0] };
  yield { k: "mlkem", level: 768, rng: FAKE };
}
function* sskrs(): Generator<Recipe> {
  const g = (mt: number, mc: number) => ({ mt, mc });
  yield {
    k: "sskr",
    spec: { gt: 1, groups: [g(3, 5)] },
    secret: h("0ff784df000c4380a5ed683f7e6e3dcf"),
    rng: FAKE,
  };
  yield {
    k: "sskr",
    spec: { gt: 2, groups: [g(2, 3), g(2, 3)] },
    secret: cyc(32, 0x40),
    rng: FAKE,
  };
  yield { k: "sskr", spec: { gt: 2, groups: [g(2, 3), g(3, 5)] }, secret: cyc(16), rng: SEEDS[0] };
  yield { k: "sskr", spec: { gt: 1, groups: [g(1, 1)] }, secret: cyc(16, 7), rng: SEEDS[1] };
  // A zero member threshold: the spec builds, generation fails in the split.
  yield { k: "sskr", spec: { gt: 1, groups: [g(0, 3)] }, secret: cyc(16, 7), rng: SEEDS[0] };
  yield { k: "sskr", spec: { gt: 1, groups: [g(2, 1)] }, secret: cyc(16, 7), rng: SEEDS[0] };
  yield { k: "sskr", spec: { gt: 1, groups: [g(2, 3)] }, secret: cyc(15, 7), rng: SEEDS[0] };
}
function* decodes(): Generator<Recipe> {
  // hand-built tagged CBOR: d9 9c XX = tag 40000+; sizes from the tables
  const bstr32 = "5820" + "00".repeat(32);
  const salt16 = "d99c525000" + "00".repeat(15);
  const cases: [DecodeType, string][] = [
    ["digest", "d99c41" + bstr32],
    ["digest", "d99c41" + "581f" + "00".repeat(31)], // wrong size
    ["digest", "d99c42" + bstr32], // wrong tag (encrypted)
    ["digest", "d99c41" + "01"], // wrong type
    ["nonce", "d99c4e4c" + "00".repeat(12)],
    ["nonce", "d99c4e4b" + "00".repeat(11)],
    ["nonce", "d99c4e40"], // empty
    ["salt", salt16],
    ["arid", "d99c4c" + bstr32],
    ["xid", "d99c58" + bstr32],
    ["reference", "d99c59" + bstr32],
    ["symmetricKey", "d99c57" + bstr32],
    ["uuid", "d82550" + "00".repeat(16)],
    ["uuid", "d8254f" + "00".repeat(15)],
    ["json", "d90106" + "42" + "7b7d"],
    ["uri", "d820" + "68" + "687474703a2f2f78"],
    ["uri", "d820" + "01"],
    ["x25519Priv", "d99c4a" + bstr32],
    ["x25519Pub", "d99c4b" + bstr32],
    ["privateKeyBase", "d99c50" + bstr32],
    ["privateKeyBase", "d99c5040"],
    ["sskrShare", "d99d75" + "55" + "001100020000112233445566778899aabbccddeeff"],
    ["sskrShare", "d90135" + "55" + "001100020000112233445566778899aabbccddeeff"], // legacy tag 309
    ["sskrShare", "d99d75" + "44" + "00010203"], // four bytes: held, not parsed
    ["seed", "d99d6c" + "a10150" + "00".repeat(16)],
    ["seed", "d9012c" + "a10150" + "00".repeat(16)], // legacy 300
    ["seed", "d99d6c" + "a10161" + "78"], // data is text
    ["seed", "d99d6c" + "a2" + "0150" + "00".repeat(16) + "03" + "6161"],
    ["seed", "d99d6c" + "a2" + "0150" + "00".repeat(16) + "02" + "c1f97e00"], // 1(NaN)
    ["seed", "d99d6c" + "a2" + "0150" + "00".repeat(16) + "02" + "c1fb41d8f37a5f8f5c29"], // sub-millisecond
    ["seed", "d99d6c" + "a2" + "0150" + "00".repeat(16) + "02" + "00"], // date not tagged: dropped
    ["seed", "d99d6c" + "a2" + "0150" + "00".repeat(16) + "03" + "01"], // name not text: dropped
    ["seed", "d99d6c" + "a10140"], // empty data
    ["compressed", "d99c43" + "83" + "1a00000000" + "00" + "40"],
    ["compressed", "d99c43" + "82" + "00" + "40"],
    ["compressed", "d99c43" + "83" + "20" + "0a" + "4100"], // checksum -1 → u32 wrap
    ["compressed", "d99c43" + "83" + "3affffffff" + "0a" + "4100"], // checksum -2^32 → 0
    ["compressed", "d99c43" + "83" + "3b0000000100000000" + "0a" + "4100"], // -2^32-1: out of range
    ["compressed", "d99c43" + "83" + "1b0000000100000000" + "0a" + "4100"], // 2^32: out of range
    ["compressed", "d99c43" + "83" + "00" + "1b0020000000000001" + "4100"], // size 2^53+1
    ["compressed", "d99c43" + "83" + "00" + "20" + "4100"], // size -1 → 2^64-1
    ["compressed", "d99c43" + "83" + "00" + "1bffffffffffffffff" + "4100"], // size 2^64-1
    ["compressed", "d99c43" + "83" + "00" + "01" + "420000"], // data larger than size
    ["encryptedMessage", "d99c42" + "83" + "40" + "4c" + "00".repeat(12) + "50" + "00".repeat(16)],
    ["encryptedMessage", "d99c42" + "82" + "40" + "4c" + "00".repeat(12)],
    ["signature", "d99c54" + "5840" + "00".repeat(64)],
    ["signature", "d99c54" + "82" + "01" + "5840" + "00".repeat(64)],
    ["signature", "d99c54" + "82" + "09" + "5840" + "00".repeat(64)], // unknown discriminator
    ["signature", "d99c54" + "82" + "5840" + "00".repeat(64) + "00"], // [bytes, any] is Schnorr
    ["signature", "d99c54" + "82" + "5840" + "00".repeat(64) + "6178"], // [bytes, "x"]
    ["signature", "d99c54" + "82" + "40" + "5840" + "00".repeat(64)], // [h'', bytes]: Schnorr size
    ["signature", "d99c54" + "82" + "01" + "00"], // [1, not bytes]
    ["signingPriv", "d99c55" + bstr32], // zero scalar: accepted, fails at use
    ["signingPriv", "d99c55" + "5820" + "01" + "00".repeat(31)], // valid scalar 2^248
    ["signingPriv", "d99c55" + "82" + "02" + bstr32],
    ["signingPriv", "d99c55" + "80"], // []: the reference panics
    ["signingPriv", "d99c55" + "81" + "01"], // [1]: the reference panics
    ["signingPriv", "d99c55" + "81" + "03"], // [3]
    ["signingPriv", "d99c55" + "81" + "00"], // [0]
    ["signingPriv", "d99c55" + "83" + "01" + bstr32 + "07"], // extra element ignored
    ["signingPriv", "d99c55" + "82" + "20" + bstr32], // [-1, bytes]: usize wrap
    ["signingPriv", "d99c55" + "82" + "3bfffffffffffffffe" + bstr32], // [-2^64+1, bytes] → 1
    ["signingPriv", "d99c55" + "82" + "3bfffffffffffffffd" + bstr32], // [-2^64+2, bytes] → 2
    ["signingPriv", "d99c55" + "82" + "01" + "6178"], // [1, "x"]
    ["signingPriv", "d99c55" + "d99c46" + "01"], // unknown tag inside
    ["signingPriv", "d99c55" + "f6"], // null
    ["signingPub", "d99c56" + bstr32],
    ["signingPub", "d99c56" + "82" + "01" + "5821" + "02" + "00".repeat(32)], // x = 0: accepted
    ["signingPub", "d99c56" + "82" + "01" + "5821" + G_COMPRESSED], // the generator
    ["signingPub", "d99c56" + "83" + "01" + "5821" + G_COMPRESSED + "00"], // three elements
    ["signingPub", "d99c56" + "82" + "20" + "5821" + G_COMPRESSED], // [-1, bytes]
    ["signingPub", "d99c56" + "81" + "01"],
    ["encapPriv", "d99c4a" + bstr32],
    ["encapPriv", bstr32], // untagged: the enum's own text
    ["encapPriv", "d99c41" + bstr32], // another tag
    ["encapPub", "d99c4b" + bstr32],
    ["encapPub", "d99c4b" + "00"],
    ["encapCiphertext", "d99c4b" + bstr32],
    ["encapCiphertext", "d99c4a" + bstr32],
    ["mldsaPriv", "d99ca7" + "82" + "03" + "40"],
    ["mldsaPriv", "d99ca7" + "82" + "07" + "40"],
    ["mldsaPriv", "d99ca7" + "82" + "20" + "40"], // level -1: u32 wrap in the text
    ["mldsaPriv", "d99ca7" + "82" + "3affffffff" + "40"], // level -2^32 → 0
    ["mldsaPriv", "d99ca7" + "82" + "3b0000000100000000" + "40"], // -2^32-1: out of range
    ["mldsaSig", "d99ca9" + "82" + "02" + "5864" + "00".repeat(100)], // 100 bytes: accepted
    ["mldsaSig", "d99ca9" + "82" + "02" + "40"], // empty: accepted
    ["mlkemCiphertext", "d99ca6" + "82" + "190300" + "40"],
    ["mlkemCiphertext", "d99ca6" + "82" + "190200" + "40"],
    ["privateKeys", "d99c4d" + "82" + "d99c55" + bstr32 + "d99c4a" + bstr32], // zero scalar inside
    [
      "privateKeys",
      "d99c4d" + "82" + "d99c55" + "5820" + "01" + "00".repeat(31) + "d99c4a" + bstr32,
    ],
    ["publicKeys", "d99c51" + "82" + "d99c56" + bstr32 + "d99c4b" + bstr32],
    ["authTag", "50" + "00".repeat(16)],
    ["authTag", "4f" + "00".repeat(15)],
    ["authTag", "01"], // not bytes: `CBOR error: …`
    ["hashType", "00"],
    ["hashType", "01"],
    ["hashType", "02"],
    ["hashType", "20"], // -1
    ["hashType", "38fe"], // -255 → 1: SHA-512
    ["hashType", "38ff"], // -256 → 0: SHA-256
    ["hashType", "390100"], // -257: out of range
    ["hashType", "18ff"], // 255
    ["hashType", "190100"], // 256: out of range
    ["hashType", "6178"], // text
    ["kdMethod", "00"],
    ["kdMethod", "04"],
    ["kdMethod", "05"],
    ["kdMethod", "3bffffffffffffffff"], // -2^64 → 0: HKDF
    ["kdMethod", "20"], // -1 → 2^64-1: invalid
    ["mlkemLevel", "190200"],
    ["mlkemLevel", "190201"],
    ["mlkemLevel", "20"],
    ["mlkemLevel", "3affffffff"],
    ["mlkemLevel", "3b0000000100000000"],
    ["mldsaLevel", "02"],
    ["mldsaLevel", "04"],
    ["mldsaLevel", "20"],
    ["hkdfParams", "83" + "00" + salt16 + "00"],
    ["hkdfParams", "83" + "07" + salt16 + "00"], // index ignored
    ["hkdfParams", "83" + "20" + salt16 + "00"], // index -1: wraps, ignored
    ["hkdfParams", "82" + "00" + salt16], // two elements
    ["pbkdf2Params", "84" + "01" + salt16 + "1903e8" + "38ff"], // hash -256
    ["pbkdf2Params", "84" + "01" + salt16 + "20" + "00"], // iterations -1
    ["pbkdf2Params", "84" + "01" + salt16 + "1b0000000100000000" + "00"], // 2^32
    ["scryptParams", "85" + "02" + salt16 + "20" + "08" + "01"], // log_n -1 → 255
    ["scryptParams", "85" + "02" + salt16 + "38ff" + "08" + "01"], // -256 → 0
    ["scryptParams", "85" + "02" + salt16 + "390100" + "08" + "01"], // -257
    ["argon2idParams", "82" + "03" + salt16],
    ["argon2idParams", "82" + "03" + "00"],
    ["kdp", "83" + "00" + salt16 + "00"],
    ["kdp", "83" + "05" + salt16 + "00"], // unknown method
    ["kdp", "80"], // empty
    ["kdp", "8304d99c5250505152535455565758595a5b5c5d5e5f666d792d6b6579"], // SSH agent
    ["sshAgentParams", "8304d99c5250505152535455565758595a5b5c5d5e5f666d792d6b6579"],
  ];
  for (const [type, hex] of cases) yield { k: "decode", type, hex };
  yield {
    k: "urParse",
    type: "digest",
    s: "ur:digest/hdcxrhgtdirhmugtfmayondmgmtstnkipyzssslrwsvlkngulawymhloylpsvowssnwlamnlatrs",
  };
  yield {
    k: "urParse",
    type: "xid",
    s: "ur:xid/hdcxuedeguisgevwhdaxnbluenutlbglhfiygamsamadmojkdydtneteeowffhwprtemcaatledk",
  };
  yield {
    k: "urParse",
    type: "digest",
    s: "ur:xid/hdcxuedeguisgevwhdaxnbluenutlbglhfiygamsamadmojkdydtneteeowffhwprtemcaatledk",
  }; // wrong type
  yield { k: "urParse", type: "digest", s: "ur:digest/aeae" };
  yield { k: "urParse", type: "digest", s: "ur:digest/fwadaokggetitt" }; // 2 bytes: size error
  yield {
    k: "urParse",
    type: "seed",
    s: "ur:crypto-seed/oyadgdaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaebbftpmcw",
  }; // legacy type name
  yield {
    k: "urParse",
    type: "sskrShare",
    s: "ur:crypto-sskr/goaebyaeaoaeaebycpeofygoiyktlonlpkrksfutwyzmistiwdlo",
  };
  yield {
    k: "urParse",
    type: "digest",
    s: "UR:DIGEST/HDCXRHGTDIRHMUGTFMAYONDMGMTSTNKIPYZSSSLRWSVLKNGULAWYMHLOYLPSVOWSSNWLAMNLATRS",
  };
}

/**
 * Ed25519 verification over raw bytes. The valid pair is the key `01..20`
 * signing "abc" (checked against noble); every other row is a strictness
 * probe that a permissive verifier could accept.
 */
const ED_PUB = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
const ED_SIG =
  "71dcb65f01d32556134ca44d130715adb02210919a8a47e016773d742b421895ebf1df3d9bf447b857adec983f055855c9a4260ad9a1f96da4c82f50bec7ce01";
const ED_SIG_HIGH_S =
  "71dcb65f01d32556134ca44d130715adb02210919a8a47e016773d742b421895" +
  // s + L (non-canonical scalar); L = 2^252 + 27742317777372353535851937790883648493
  "d8ecd5b23ddcd93c92ba8a2b3f0ff0d2c9a4260ad9a1f96da4c82f50bec7ce11";
function* strictness(): Generator<Recipe> {
  const message = t("abc");
  const sig = h(ED_SIG);
  yield { k: "verifyStrict", pub: h(ED_PUB), sig, message, note: "valid pair" };
  yield { k: "verifyStrict", pub: h(ED_PUB), sig, message: t("abd"), note: "wrong message" };
  yield { k: "verifyStrict", pub: h(ED_PUB), sig: h(ED_SIG_HIGH_S), message, note: "s ≥ L" };
  yield {
    k: "verifyStrict",
    pub: h(ED_PUB),
    sig: h("00".repeat(64)),
    message,
    note: "zero signature",
  };
  yield {
    k: "verifyStrict",
    pub: h("01" + "00".repeat(31)),
    sig: h("01" + "00".repeat(63)),
    message,
    note: "identity key, identity R, s = 0",
  };
  yield {
    k: "verifyStrict",
    pub: h("ff".repeat(32)),
    sig,
    message,
    note: "non-canonical key y ≥ p",
  };
  yield {
    k: "verifyStrict",
    pub: h("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    sig,
    message,
    note: "key y = p - 1 (small order)",
  };
  yield { k: "verifyStrict", pub: h("00".repeat(32)), sig, message, note: "zero key" };
}
/** The untagged encodings of the tagged `decodes()` rows. */
function* untagged(): Generator<Recipe> {
  const bstr32 = "5820" + "00".repeat(32);
  const cases: [DecodeType, string][] = [
    ["digest", bstr32],
    ["nonce", "4c" + "00".repeat(12)],
    ["salt", "5000" + "00".repeat(15)],
    ["arid", bstr32],
    ["xid", bstr32],
    ["reference", bstr32],
    ["symmetricKey", bstr32],
    ["uuid", "50" + "00".repeat(16)],
    ["x25519Priv", bstr32],
    ["x25519Pub", bstr32],
    ["privateKeyBase", bstr32],
    ["seed", "a10150" + "00".repeat(16)],
    ["signature", "5840" + "00".repeat(64)],
    ["signingPriv", bstr32],
    ["encryptedMessage", "83" + "40" + "4c" + "00".repeat(12) + "50" + "00".repeat(16)],
    ["digest", "d99c41" + bstr32], // tagged input through the same door
    ["digest", "581f" + "00".repeat(31)], // untagged AND wrong size
  ];
  for (const [type, hex] of cases) yield { k: "decodeUntagged", type, hex };
}
/** The scheme `random()` and `generateKeypair()` pick. */
function* defaults(): Generator<Recipe> {
  for (const rng of [...SEEDS.slice(0, 2), FAKE]) yield { k: "signingDefault", rng };
}
/** KDF parameter construction over the integer edges and the JS-only numbers. */
function* kdfDomain(): Generator<Recipe> {
  for (const iterations of [1, 10, 4294967295, 0, 4294967296, 1.5, -1, "NaN", "Infinity"] as const)
    yield { k: "kdfDomain", method: "pbkdf2", iterations };
  for (const logN of [1, 4, 255, 0, 256, 1.5, -1, "NaN"] as const)
    yield { k: "kdfDomain", method: "scrypt", logN };
  for (const r of [1, 8, 4294967295, 0, 4294967296, 1.5, "NaN"] as const)
    yield { k: "kdfDomain", method: "scrypt", logN: 4, r };
  for (const p of [1, 4294967295, 0, 4294967296, 2.5, "-Infinity"] as const)
    yield { k: "kdfDomain", method: "scrypt", logN: 4, r: 8, p };
}
/** Named JS-only input cases (see the adapter's table): values the reference's types cannot hold. */
function* domain(): Generator<Recipe> {
  for (const c of [
    "salt.random.length.NaN",
    "salt.random.length.1.5",
    "salt.random.length.-1",
    "salt.random.length.Infinity",
    "seed.random.length.1.5",
    "seed.random.length.NaN",
    "nonce.random.rng.missingFill",
    "hkdfRng.pageLength.1.5",
    "hkdfRng.pageLength.-1",
    "seed.name.number",
    "seed.note.object",
    "seed.creationDate.string",
    "mldsa.level.99",
    "mlkem.level.99",
    "digest.from.undefined",
    "arid.from.null",
    "sshSigningPrivateKey.algorithm.unknown",
    "sshSigningPrivateKey.algorithm.curve.unknown",
    "compressed.fromParts.size.1.5",
    "compressed.fromParts.checksum.-1",
  ])
    yield { k: "domain", case: c };
}

/** The tag summarisers over tagged CBOR, compared with the reference's registry. */
function* summaries(): Generator<Recipe> {
  const bstr32 = "5820" + "00".repeat(32);
  const cases: [string, string][] = [
    ["digest zeros", "d99c41" + bstr32],
    ["digest wrong size", "d99c41" + "581f" + "00".repeat(31)],
    ["arid zeros", "d99c4c" + bstr32],
    ["xid zeros", "d99c58" + bstr32],
    ["uri http://x", "d820" + "68" + "687474703a2f2f78"],
    ["uuid zeros", "d82550" + "00".repeat(16)],
    ["nonce zeros", "d99c4e4c" + "00".repeat(12)],
    ["nonce short", "d99c4e4b" + "00".repeat(11)],
    ["salt 16", "d99c525000" + "00".repeat(15)],
    ["json {}", "d90106" + "42" + "7b7d"],
    ["json BOM {}", "d90106" + "45" + "efbbbf7b7d"],
    ["json not UTF-8", "d90106" + "42" + "fffe"],
    ["seed 16", "d99d6c" + "a10150" + "00".repeat(16)],
    ["reference zeros", "d99c59" + bstr32],
    ["privateKeyBase zeros", "d99c50" + bstr32],
    ["signature schnorr", "d99c54" + "5840" + "00".repeat(64)],
    ["signature ecdsa", "d99c54" + "82" + "01" + "5840" + "00".repeat(64)],
    ["signature ed25519", "d99c54" + "82" + "02" + "5840" + "00".repeat(64)],
    ["signingPriv schnorr", "d99c55" + "5820" + "01" + "00".repeat(31)],
    ["signingPriv ed25519", "d99c55" + "82" + "02" + bstr32],
    ["signingPub schnorr", "d99c56" + bstr32],
    ["signingPub ecdsa G", "d99c56" + "82" + "01" + "5821" + G_COMPRESSED],
    [
      "privateKeys",
      "d99c4d" + "82" + "d99c55" + "5820" + "01" + "00".repeat(31) + "d99c4a" + bstr32,
    ],
    ["publicKeys", "d99c51" + "82" + "d99c56" + bstr32 + "d99c4b" + bstr32],
    ["sskrShare", "d99d75" + "55" + "001100020000112233445566778899aabbccddeeff"],
    ["sskrShare short", "d99d75" + "42" + "0001"],
    ["ssh certificate uint", "d99f6300"],
    ["ssh certificate text", "d99f636178"],
    ["ssh certificate bytes", "d99f634100"],
    ["ssh private key not text", "d99f6000"],
    ["unknown tag 40999", "d9a027" + "00"],
    ["untagged", "00"],
  ];
  for (const [note, hex] of cases) yield { k: "summary", hex, note };
}

// ---------------------------------------------------------------------------
// The text and hex parsers
// ---------------------------------------------------------------------------

const URIS = [
  "https://example.com",
  "http://a b",
  "http://a",
  "urn:isbn:0451450523",
  "mailto:a@b.c",
  "a:b",
  "ur:test/aeae",
  "/relative",
  "relative",
  "",
  " http://a",
  "http://a ",
  "HTTP://A/",
  "http://[::1]/",
  "http://[::1",
  "http://example.com:99999",
  "http://exa mple.com",
  "file:///tmp/x",
  "data:text/plain,hi",
  "javascript:alert(1)",
  "http://é.com",
  "﻿http://a",
  "http://a\tb",
  "http://a\nb",
  "https://example.com/%zz",
  "foo://bar",
  "1http://a",
  "h:",
  "http://",
  "http:///a",
  "http:a",
  "http://a:b@c/",
  "http://256.256.256.256/",
  "http://0x7f.1/",
  "https://ex ample.com",
  "http://a/ ",
  "sc:\\\\x",
];
function* uris(): Generator<Recipe> {
  for (const text of URIS) yield { k: "uri", text };
}
const UUID_GOOD = "01234567-89ab-cdef-0123-456789abcdef";
const UUIDS = [
  UUID_GOOD,
  UUID_GOOD.toUpperCase(),
  UUID_GOOD.replaceAll("-", ""),
  ` ${UUID_GOOD} `,
  "0123456789abcdef-0123456789abcdef",
  "01234567-89ab-cdef-0123-456789abcd",
  "zz234567-89ab-cdef-0123-456789abcdef",
  `{${UUID_GOOD}}`,
  "0-1-2-3-4-5-6-7-8-9-a-b-c-d-e-f-0-1-2-3-4-5-6-7-8-9-a-b-c-d-e-f",
  `\u{85}${UUID_GOOD}`,
  `\u{3000}${UUID_GOOD}\u{3000}`,
  `\u{feff}${UUID_GOOD}`,
  `${UUID_GOOD.replaceAll("-", "").slice(0, 31)}é`,
  `${UUID_GOOD.replaceAll("-", "").slice(0, 30)}é`,
  UUID_GOOD.replaceAll("-", "").slice(0, 30),
  "",
  "-",
  `\t${UUID_GOOD}\n`,
];
function* uuids(): Generator<Recipe> {
  for (const text of UUIDS) yield { k: "uuidParse", text };
}
const HEX_SIZES: Record<HexType, number> = {
  digest: 32,
  nonce: 12,
  salt: 16,
  arid: 32,
  xid: 32,
  reference: 32,
  symmetricKey: 32,
  json: 2,
  sskrShare: 21,
  x25519Priv: 32,
  x25519Pub: 32,
  ed25519Priv: 32,
  ed25519Pub: 32,
  uuid: 16,
};
function* hexes(): Generator<Recipe> {
  for (const type of Object.keys(HEX_SIZES) as HexType[]) {
    const n = HEX_SIZES[type];
    const good = cycHex(n, 0x21);
    for (const text of [
      good,
      good.toUpperCase(),
      "",
      "zz",
      "abc",
      "+1",
      ` ${good}`,
      `${good} `,
      `${good}  `,
      good.replace(/(.{8})/g, "$1 ").trim(),
      good.slice(0, -2),
      `${good}00`,
      "00",
      `${good.slice(0, -2)}0g`,
      `é${good.slice(2)}`,
      `${good}\n`,
    ])
      yield { k: "hex", type, text };
  }
  // Every byte value at position 0 of an Ed25519 public key: the crate's character rendering.
  const good = cycHex(32, 0x21);
  for (let b = 0; b < 256; b++) {
    const ch = String.fromCharCode(b);
    yield { k: "hex", type: "ed25519Pub", text: ch + good.slice(1) };
    if (b >= 0x80) yield { k: "hex", type: "ed25519Pub", text: ch + good.slice(2) };
  }
}

/** Named API cases both adapters and the harness implement in the same words. */
export const API_CASES: readonly string[] = [
  "json/invalid-utf8-decode",
  "json/invalid-utf8-as-str",
  "json/bom-as-str",
  "sskr/short4-identifier",
  "sskr/short4-group-threshold",
  "sskr/short4-group-count",
  "sskr/short4-group-index",
  "sskr/short4-member-threshold",
  "sskr/short4-member-index",
  "sskr/short4-value",
  "sskr/empty-identifier",
  "sskr/combine-short",
  "sskr/combine-empty",
  "sskr/combine-one-of-two",
  "mldsa/signing-public-key",
  "mlkem/encap-public-key",
  "privateKeys/mldsa-public-keys",
  "privateKeys/mlkem-public-keys",
  "compressed/new-larger",
  "compressed/digest-none",
  "ec/zero-public-key",
  "ec/zero-schnorr-public-key",
  "ec/zero-signing-public-key",
  "ec/zero-schnorr-sign",
  "ec/zero-ecdsa-sign",
  "ec/n-public-key",
  "ec/one-public-key",
  "ecpub/zeros33-uncompressed",
  "ecpub/02zeros-uncompressed",
  "ecpub/05ff-uncompressed",
  "ecpub/G-uncompressed",
  "ecuncomp/04-public-key",
  "ecuncomp/06-public-key",
  "ecuncomp/07-public-key",
  "ecuncomp/00-public-key",
  "sym/decrypt-tampered",
  "sym/decrypt-wrong-key",
  "ek/unlock-wrong",
  "sealed/wrong-key",
  "salt/len7",
  "salt/len8",
  "seed/len15",
  "seed/len16",
  "sign/ed25519-with-schnorr-opts",
  "sign/schnorr-with-ssh-opts",
  "sign/schnorr-key-ecdsa-sign",
  "sign/ecdsa-key-schnorr-sign",
  "sign/ed25519-key-ecdsa-sign",
  "sign/schnorr-key-ed25519-sign",
  "sign/schnorr-key-mldsa-sign",
  "pkb/empty",
  "mldsa/short-sig-verify",
  "mldsa/long-sig-from",
  "scheme/default-sig",
  "scheme/default-enc",
  "hkdf/page0-fill0",
  "hkdf/page0-fill1",
  "hkdf/page0-u32",
  "kdf/pbkdf2-iter0-unlock",
  "kdf/scrypt-logn0-unlock",
  "authTag/from-cbor-bytes",
  "authTag/from-cbor-uint",
  "authTag/from-cbor-short",
  "uuid/to-string",
  "ssh/rsa-sign",
];
function* apis(): Generator<Recipe> {
  for (const c of API_CASES) yield { k: "api", case: c };
}

// ---------------------------------------------------------------------------
// The generated decode and summary corpora
// ---------------------------------------------------------------------------

const ENCODINGS = JSON.parse(readFileSync(join(here, "encodings.json"), "utf8")) as Record<
  string,
  string
>;
/** The `TryFrom<CBOR>` types: their encodings carry no tag. */
const UNTAGGED_TYPES: ReadonlySet<DecodeType> = new Set<DecodeType>([
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
export const DECODE_TYPES: readonly DecodeType[] = [
  "digest",
  "nonce",
  "salt",
  "arid",
  "uuid",
  "xid",
  "reference",
  "symmetricKey",
  "json",
  "uri",
  "authTag",
  "x25519Priv",
  "x25519Pub",
  "privateKeyBase",
  "sskrShare",
  "seed",
  "compressed",
  "encryptedMessage",
  "signature",
  "signingPriv",
  "signingPub",
  "encapPriv",
  "encapPub",
  "encapCiphertext",
  "sealedMessage",
  "privateKeys",
  "publicKeys",
  "encryptedKey",
  "mldsaPriv",
  "mldsaPub",
  "mldsaSig",
  "mlkemPriv",
  "mlkemPub",
  "mlkemCiphertext",
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
];
interface Encoding {
  id: string;
  type: DecodeType;
  hex: string;
}
const SEED_ENCODINGS: Encoding[] = Object.entries(ENCODINGS).map(([id, hex]) => ({
  id,
  type: id.slice(0, id.indexOf("/")) as DecodeType,
  hex,
}));
const hexOf = (c: Cbor): string => Buffer.from(c.toData()).toString("hex");
const fromHex = (hex: string): Cbor => decodeCbor(Uint8Array.from(Buffer.from(hex, "hex")));
const RETAG = 99999;
/** The replacement atoms: one CBOR value of each shape. */
const ATOMS: readonly [string, Cbor][] = [
  ["u0", cbor(0)],
  ["u1", cbor(1)],
  ["neg", cbor(-1)],
  ["f", cbor(1.5)],
  ["b0", cbor(new Uint8Array(0))],
  ["t0", cbor("")],
  ["a0", cbor([])],
  ["m0", cbor(new CborMap())],
  ["true", cbor(true)],
  ["null", cbor(null)],
  ["umax", cbor(18446744073709551615n)],
];
/** Integer heads at the width boundaries the reference's `u8`/`u32`/`usize` decoders wrap or reject. */
const INTS: readonly [string, Cbor][] = [
  ["u2", cbor(2)],
  ["u255", cbor(255)],
  ["u256", cbor(256)],
  ["u32max", cbor(4294967295)],
  ["u32over", cbor(4294967296)],
  ["neg255", cbor(-255)],
  ["neg256", cbor(-256)],
  ["neg257", cbor(-257)],
  ["neg32max", cbor(-4294967296)],
  ["neg32over", cbor(-4294967297)],
  ["negmin", cbor(-18446744073709551616n)],
];
const bytesVariants = (b: Uint8Array): [string, Cbor][] => [
  ["bm1", cbor(b.subarray(0, Math.max(0, b.length - 1)))],
  ["bp1", cbor(Uint8Array.from([...b, 0]))],
  ["b64", cbor(Uint8Array.from({ length: 64 }, (_, i) => i))],
  ["b33z", cbor(new Uint8Array(33))],
  ["b32z", cbor(new Uint8Array(32))],
  ["b32ff", cbor(new Uint8Array(32).fill(0xff))],
  ["b4", cbor(Uint8Array.from([0, 1, 2, 3]))],
  ["b5", cbor(Uint8Array.from([0, 1, 2, 3, 4]))],
];
const isInteger = (c: Cbor): boolean =>
  c.type === MajorType.Unsigned || c.type === MajorType.Negative;
const mapWith = (entries: readonly (readonly [Cbor, Cbor])[]): Cbor => {
  const m = new CborMap();
  for (const [k, v] of entries) m.set(k, v);
  return cbor(m);
};
/**
 * Structural mutants of a node, one level deep, each with a path label:
 * arrays by element (every atom, the byte-string and integer variants where
 * they apply, one nested level for tagged, array or map elements), plus a
 * dropped and an appended element; maps by key, plus a dropped and an added
 * key; byte strings by length; integers by the width boundaries.
 */
function* mutants(node: Cbor, depth: number): Generator<[string, Cbor]> {
  const arr = asArray(node);
  if (arr !== undefined) {
    for (let i = 0; i < arr.length; i++) {
      const replace = (c: Cbor): Cbor => cbor(arr.map((e, j) => (j === i ? c : e)));
      for (const [name, atom] of ATOMS) yield [`a${i}.${name}`, replace(atom)];
      const el = arr[i];
      if (el === undefined) continue;
      const bytes = asBytes(el);
      if (bytes !== undefined)
        for (const [name, v] of bytesVariants(bytes)) yield [`a${i}.${name}`, replace(v)];
      if (isInteger(el)) for (const [name, v] of INTS) yield [`a${i}.${name}`, replace(v)];
      const tagged = asTaggedValue(el);
      if (tagged !== undefined) {
        yield [`a${i}.untag`, replace(tagged[1])];
        yield [`a${i}.retag`, replace(taggedValue(RETAG, tagged[1]))];
        if (depth > 0)
          for (const [name, v] of mutants(tagged[1], depth - 1))
            yield [`a${i}.t.${name}`, replace(taggedValue(tagged[0], v))];
      } else if (depth > 0 && (asArray(el) !== undefined || asMap(el) !== undefined)) {
        for (const [name, v] of mutants(el, depth - 1)) yield [`a${i}.${name}`, replace(v)];
      }
    }
    if (arr.length > 0) yield ["adrop", cbor(arr.slice(0, -1))];
    yield ["aext0", cbor([...arr, cbor(0)])];
    yield ["aextb", cbor([...arr, cbor(new Uint8Array(0))])];
    return;
  }
  const map = asMap(node);
  if (map !== undefined) {
    const entries = [...map.entries()];
    for (const [k, v] of entries) {
      const label = `m${String(asUnsigned(k) ?? hexOf(k))}`;
      const replace = (c: Cbor): Cbor =>
        mapWith(entries.map(([kk, vv]) => [kk, kk === k ? c : vv]));
      for (const [name, atom] of ATOMS) yield [`${label}.${name}`, replace(atom)];
      const tagged = asTaggedValue(v);
      if (tagged !== undefined) {
        yield [`${label}.untag`, replace(tagged[1])];
        yield [`${label}.retag`, replace(taggedValue(RETAG, tagged[1]))];
      }
      const bytes = asBytes(v);
      if (bytes !== undefined)
        for (const [name, bv] of bytesVariants(bytes)) yield [`${label}.${name}`, replace(bv)];
      yield [`${label}.drop`, mapWith(entries.filter(([kk]) => kk !== k))];
    }
    yield ["madd9", mapWith([...entries, [cbor(9), cbor(0)]])];
    return;
  }
  const bytes = asBytes(node);
  if (bytes !== undefined) {
    for (const [name, v] of bytesVariants(bytes)) yield [name, v];
    return;
  }
  if (isInteger(node)) for (const [name, v] of INTS) yield [name, v];
}
interface CorpusRow {
  id: string;
  type: DecodeType;
  hex: string;
  /** Rows on the golden subset. */
  golden: boolean;
  /** Rows the summariser corpus also runs (tagged inputs only). */
  tagged: boolean;
}
function* decodeRows(): Generator<CorpusRow> {
  const firstOfType = new Set<DecodeType>();
  for (const seed of SEED_ENCODINGS) {
    const golden = !firstOfType.has(seed.type);
    firstOfType.add(seed.type);
    const node = fromHex(seed.hex);
    const row = (suffix: string, c: Cbor, g = golden): CorpusRow => ({
      id: `${seed.id}/${suffix}`,
      type: seed.type,
      hex: hexOf(c),
      golden: g,
      tagged: c.type === MajorType.Tagged,
    });
    yield row("orig", node, true);
    const tagged = asTaggedValue(node);
    if (tagged !== undefined) {
      const [tag, content] = tagged;
      yield row("untag", content, true);
      yield row("retag", taggedValue(RETAG, content), true);
      for (const [name, atom] of ATOMS) yield row(name, taggedValue(tag, atom));
      for (const [name, v] of mutants(content, 1)) yield row(`t.${name}`, taggedValue(tag, v));
    } else {
      yield row("tag", taggedValue(RETAG, node), true);
      for (const [name, atom] of ATOMS) yield row(name, atom);
      for (const [name, v] of mutants(node, 1)) yield row(`t.${name}`, v);
    }
  }
  // Cross-type: every seed encoding through every other decoder.
  const CORE: ReadonlySet<DecodeType> = new Set<DecodeType>([
    "digest",
    "seed",
    "compressed",
    "encryptedMessage",
    "signature",
    "signingPriv",
    "signingPub",
    "encapPub",
    "sealedMessage",
    "privateKeys",
    "encryptedKey",
    "hkdfParams",
    "kdp",
    "hashType",
    "mldsaSig",
    "mlkemPub",
    "sskrShare",
  ]);
  for (const seed of SEED_ENCODINGS) {
    for (const type of DECODE_TYPES) {
      if (type === seed.type) continue;
      yield {
        id: `${type}/x-${seed.id.replace("/", "-")}`,
        type,
        hex: seed.hex,
        golden: CORE.has(type) && CORE.has(seed.type),
        tagged: !UNTAGGED_TYPES.has(seed.type),
      };
    }
  }
}
function* decodeCorpus(): Generator<Recipe> {
  for (const r of decodeRows()) yield { k: "decode", type: r.type, hex: r.hex };
}
function* decodeCorpusGolden(): Generator<Recipe> {
  for (const r of decodeRows()) if (r.golden) yield { k: "decode", type: r.type, hex: r.hex };
}
/** The tagged decode-corpus inputs through the summariser registry. */
function* summaryRows(): Generator<CorpusRow> {
  const seen = new Set<string>();
  for (const r of decodeRows()) {
    if (!r.tagged || r.id.includes("/x-") || seen.has(r.hex)) continue;
    seen.add(r.hex);
    yield r;
  }
}
function* summaryCorpus(): Generator<Recipe> {
  for (const r of summaryRows()) yield { k: "summary", hex: r.hex, note: `corpus ${r.id}` };
}
function* summaryCorpusGolden(): Generator<Recipe> {
  for (const r of summaryRows())
    if (r.golden) yield { k: "summary", hex: r.hex, note: `corpus ${r.id}` };
}

/** Rows run before the tags are registered: numbers where names would be. */
function* noreg(): Generator<Recipe> {
  const bstr32 = "5820" + "00".repeat(32);
  const rows: Recipe[] = [
    { k: "decode", type: "seed", hex: "d99d6c" + "a10150" + "00".repeat(16) },
    { k: "decode", type: "seed", hex: "d9012c" + "a10150" + "00".repeat(16) },
    { k: "decode", type: "seed", hex: "da0001869f" + "a10150" + "00".repeat(16) }, // 99999(...)
    { k: "decode", type: "seed", hex: "a10150" + "00".repeat(16) },
    { k: "decode", type: "digest", hex: "d99c41" + bstr32 },
    { k: "decode", type: "digest", hex: "da0001869f" + bstr32 },
    { k: "decode", type: "digest", hex: bstr32 },
    {
      k: "decode",
      type: "sealedMessage",
      hex:
        "d99c53" +
        "82" +
        "d99c4283404c" +
        "00".repeat(12) +
        "50" +
        "00".repeat(16) +
        "d99c4b" +
        bstr32,
    },
    { k: "decode", type: "sealedMessage", hex: "da0001869f" + "82" + "00" + "00" },
    {
      k: "decode",
      type: "sskrShare",
      hex: "da0001869f" + "55" + "001100020000112233445566778899aabbccddeeff",
    },
    { k: "decode", type: "encapPub", hex: "da0001869f" + bstr32 },
    { k: "cborTags", type: "seed" },
    { k: "cborTags", type: "digest" },
    { k: "cborTags", type: "sealedMessage" },
    { k: "cborTags", type: "sskrShare" },
    { k: "cborTags", type: "signingPriv" },
    { k: "cborTags", type: "encapPub" },
    // A UR needs the tag's name: the reference panics without it.
    { k: "value", type: "digest", data: cyc(32) },
    {
      k: "urParse",
      type: "digest",
      s: "ur:digest/hdcxrhgtdirhmugtfmayondmgmtstnkipyzssslrwsvlkngulawymhloylpsvowssnwlamnlatrs",
    },
  ];
  for (const inner of rows) yield { k: "noreg", inner };
}

/** SSH-agent key derivation over the in-memory agent: the reference's lock/unlock algorithm and every error row. */
function* agents(): Generator<Recipe> {
  const alice = { seed: { cycle: 32, start: 1 }, comment: "alice" };
  const bob = { seed: { cycle: 32, start: 2 }, comment: "bob" };
  const carol = { seed: { cycle: 32, start: 3 }, comment: "carol", alg: "ecdsa-p256" as const };
  const base = {
    k: "agentLock" as const,
    salt: { cycle: 16, start: 0x50 },
    key: { cycle: 32, start: 0x10 },
    nonce: { cycle: 12, start: 0xb0 },
  };
  const t = (text: string) => ({ text });
  // the round trip, by the secret's id, by the stored id and by the first identity
  yield { ...base, identities: [alice], secret: t("alice"), unlock: { secret: t("alice") } };
  yield { ...base, identities: [alice], secret: t(""), unlock: { secret: t("") } };
  yield { ...base, identities: [alice, bob], secret: t("bob"), unlock: { secret: t("") } };
  yield {
    ...base,
    identities: [alice, bob],
    secret: t("bob"),
    unlock: { secret: t(""), storedId: "" },
  };
  // unlock under another identity, an unknown identity, a flipped AAD, a flipped ciphertext
  yield { ...base, identities: [alice, bob], secret: t("bob"), unlock: { secret: t("alice") } };
  yield { ...base, identities: [alice, bob], secret: t("bob"), unlock: { secret: t("carol") } };
  yield {
    ...base,
    identities: [alice],
    secret: t("alice"),
    unlock: { secret: t("alice"), tamper: "aad" },
  };
  yield {
    ...base,
    identities: [alice],
    secret: t("alice"),
    unlock: { secret: t("alice"), tamper: "ciphertext" },
  };
  // the lock's own refusals
  yield { ...base, identities: [alice, bob], secret: t("") };
  yield { ...base, identities: [carol], secret: t("") };
  yield { ...base, identities: [], secret: t("") };
  yield { ...base, identities: [alice], secret: t("zed") };
  yield { ...base, identities: [alice], refuse: true, secret: t("") };
  yield { ...base, identities: [alice], secret: { hex: "fffe" } };
}

export const categories: Record<string, () => Generator<Recipe>> = {
  noreg,
  values,
  randoms,
  saltLengths,
  derives,
  digests,
  compresseds,
  inflates,
  seeds,
  encrypts,
  signings,
  verifies,
  sshes,
  sshTexts,
  pkbs,
  seals,
  kdfs,
  pqs,
  sskrs,
  decodes,
  strictness,
  untagged,
  defaults,
  kdfDomain,
  domain,
  summaries,
  uris,
  uuids,
  hexes,
  apis,
  decodeCorpus,
  summaryCorpus,
  agents,
};
/** Categories with their own golden sample; the others keep every row but the second cyclic start. */
const GOLDEN_SAMPLE: Record<string, () => Generator<Recipe>> = {
  decodeCorpus: decodeCorpusGolden,
  summaryCorpus: summaryCorpusGolden,
  inflates: function* () {
    let i = 0;
    for (const c of inflateCases()) {
      // every stream and hand-built case; one in eight of the truncations and bit flips
      if (!c.name.startsWith("trunc") && !c.name.startsWith("flip"))
        yield { k: "inflate", hex: c.hex };
      else if (i++ % 8 === 0) yield { k: "inflate", hex: c.hex };
    }
  },
};
export function* allRecipes(): Generator<Recipe> {
  for (const g of Object.values(categories)) yield* g();
}
/** Golden subset: the sampled categories, and everything else except the second cyclic start of each value size. */
export function* goldenRecipes(): Generator<Recipe> {
  for (const [name, g] of Object.entries(categories)) {
    const sample = GOLDEN_SAMPLE[name];
    if (sample !== undefined) {
      yield* sample();
      continue;
    }
    for (const r of g()) {
      if (r.k === "value" && "cycle" in r.data && r.data.start === 0x80) continue;
      yield r;
    }
  }
}
