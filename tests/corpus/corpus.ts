/**
 * Deterministic differential corpus. Pure: every input is a
 * literal or a cyclic byte pattern; no package code runs here.
 */
import type {
  Recipe,
  Bytes,
  RngSpec,
  ValueType,
  RandomType,
  Scheme,
  EncScheme,
  DecodeType,
} from "../vectors/recipes";

const cyc = (n: number, start = 0): Bytes => ({ cycle: n, start });
const h = (hex: string): Bytes => ({ hex });
const t = (text: string): Bytes => ({ text });
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
  privateKeyBase: [16, 32, 64],
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
  sskrShare: [4],
};
// Real curve points where random bytes would not do.
const EC_PRIV = h("322b5c1dd5a17c3481c2297990c85c232ed3c17b52ce9905c6ec5193ad132c36");
const EC_PUB = h("02e8251dc3a17e0f2c07865ed191139ecbcddcbdd070ec1ff65df5148c7ef4005a");
const EC_PUB_INVALID = h("02d43099fe444807c46921a4f33a2a798b0d8cf5f6ec337bc764d1866b5d07ca42");
const JSON_TEXT = t('{"a":1,"b":[true,null],"c":"x"}');
const URI_TEXT = t("https://example.com/path?q=1#frag");
const SSKR_SHARE = h("001100020000112233445566778899aabbccddeeff");

function* values(): Generator<Recipe> {
  for (const type of Object.keys(VALUE_SIZES) as ValueType[]) {
    if (type === "ecPub") {
      yield { k: "value", type, data: EC_PUB };
      yield { k: "value", type, data: EC_PUB_INVALID };
    } else if (type === "ecUncompressed") {
      yield {
        k: "value",
        type,
        data: h(
          "04" +
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        ),
      };
    } else if (type === "json") {
      yield { k: "value", type, data: JSON_TEXT };
      yield { k: "value", type, data: t("[]") };
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
    } else if (type === "ecPriv") {
      yield { k: "value", type, data: EC_PRIV };
      yield { k: "value", type, data: cyc(32, 1) };
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
 * `RangeInclusive<usize>` (a 64-bit draw); the 32-bit sampler gives a
 * different length from the same seed (N1 in the rand divergence review).
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
function* compresseds(): Generator<Recipe> {
  for (const n of [0, 1, 10, 57, 100, 114, 256, 500, 1000, 1024, 2048]) {
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
function* sshes(): Generator<Recipe> {
  for (const seed of [RUST_SEED, cyc(32, 1)]) {
    for (const alg of ["ed25519", "ecdsa-p256", "ecdsa-p384"] as const) {
      yield { k: "sshFromSeed", seed, alg, comment: "Key comment." };
      yield { k: "sshFromSeed", seed, alg, comment: "", message: RFC_PT, namespace: "test" };
    }
  }
  yield { k: "sshFromPem", pem: RUST_DSA_PEM };
  yield { k: "sshFromPem", pem: RUST_DSA_PEM, message: RFC_PT, namespace: "test" };
}
function* pkbs(): Generator<Recipe> {
  for (const seed of [RUST_SEED, cyc(32, 1), cyc(16, 0x99), cyc(64, 0x21)])
    yield { k: "pkb", seed };
  for (const sigScheme of ["schnorr", "ecdsa", "ed25519"] as Scheme[])
    for (const encScheme of ["x25519", "mlkem768"] as EncScheme[])
      yield { k: "keypair", sigScheme, encScheme, rng: SEEDS[0] };
  yield { k: "keypair", sigScheme: "schnorr", encScheme: "mlkem512", rng: FAKE };
  yield { k: "keypair", sigScheme: "ed25519", encScheme: "mlkem1024", rng: SEEDS[2] };
}
function* seals(): Generator<Recipe> {
  for (const plaintext of [cyc(0), t("hello"), cyc(1000, 3)]) {
    yield { k: "seal", plaintext, recipient: { x25519: cyc(32, 1) } };
    yield { k: "seal", plaintext, recipient: { x25519: cyc(32, 1) }, aad: cyc(16, 0x50) };
  }
  for (const level of [512, 768, 1024] as const)
    yield { k: "seal", plaintext: t("pq"), recipient: { mlkem: level, rng: SEEDS[0] } };
  // fixed nonce: the ephemeral key still differs per side (U5)
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
  yield { k: "params", method: "scrypt", salt };
  yield { k: "params", method: "scrypt", salt, logN: 4, r: 8, p: 1 };
  yield { k: "params", method: "argon2id", salt };
  yield { k: "params", method: "sshAgent", salt, id: "my-key" };
  yield { k: "params", method: "hkdf", salt: cyc(32, 0xaa) };
  const secret = t("password");
  const key = cyc(32, 0x10);
  yield { k: "encryptedKey", method: "hkdf", salt, secret, key };
  yield { k: "encryptedKey", method: "pbkdf2", salt, secret, key, iterations: 10 };
  yield { k: "encryptedKey", method: "scrypt", salt, secret, key, logN: 4 };
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
}
/** secp256k1 G, compressed: a point that is on the curve. */
const G_COMPRESSED = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
function* decodes(): Generator<Recipe> {
  // hand-built tagged CBOR: d9 9c XX = tag 40000+; sizes from the tables
  const bstr32 = "5820" + "00".repeat(32);
  const cases: [DecodeType, string][] = [
    ["digest", "d99c41" + bstr32],
    ["digest", "d99c41" + "581f" + "00".repeat(31)], // wrong size
    ["digest", "d99c42" + bstr32], // wrong tag (encrypted)
    ["digest", "d99c41" + "01"], // wrong type
    ["nonce", "d99c4e4c" + "00".repeat(12)],
    ["nonce", "d99c4e4b" + "00".repeat(11)],
    ["salt", "d99c525000" + "00".repeat(15)],
    ["arid", "d99c4c" + bstr32],
    ["xid", "d99c58" + bstr32],
    ["reference", "d99c59" + bstr32],
    ["symmetricKey", "d99c57" + bstr32],
    ["uuid", "d82550" + "00".repeat(16)],
    ["json", "d90106" + "42" + "7b7d"],
    ["uri", "d820" + "68" + "687474703a2f2f78"],
    ["uri", "d820" + "01"],
    ["x25519Priv", "d99c4a" + bstr32],
    ["x25519Pub", "d99c4b" + bstr32],
    ["ecPriv", "d99d62a2" + "02f5" + "03" + bstr32], // map {2: true, 3: bytes}
    ["ecPriv", "d99d62a2" + "02f4" + "03" + bstr32], // isPrivate false
    ["ecPub", "d99d62a2" + "02f4" + "03" + "5821" + "02" + "00".repeat(32)],
    ["privateKeyBase", "d99c50" + bstr32],
    ["sskrShare", "d99d65" + "55" + "001100020000112233445566778899aabbccddeeff"],
    ["sskrShare", "d90135" + "55" + "001100020000112233445566778899aabbccddeeff"], // legacy tag 309
    ["seed", "d99d6c" + "a10150" + "00".repeat(16)],
    ["seed", "d9012c" + "a10150" + "00".repeat(16)], // legacy 300
    ["seed", "d99d6c" + "a10161" + "78"], // data is text
    ["seed", "d99d6c" + "a2" + "0150" + "00".repeat(16) + "03" + "6161"],
    ["compressed", "d99c43" + "83" + "1a00000000" + "00" + "40"],
    ["compressed", "d99c43" + "82" + "00" + "40"],
    ["encryptedMessage", "d99c42" + "83" + "40" + "4c" + "00".repeat(12) + "50" + "00".repeat(16)],
    ["encryptedMessage", "d99c42" + "82" + "40" + "4c" + "00".repeat(12)],
    ["signature", "d99c54" + "5840" + "00".repeat(64)],
    ["signature", "d99c54" + "82" + "01" + "5840" + "00".repeat(64)],
    ["signature", "d99c54" + "82" + "09" + "5840" + "00".repeat(64)], // unknown discriminator
    ["signingPriv", "d99c55" + bstr32], // zero scalar: rejected (U2)
    ["signingPriv", "d99c55" + "5820" + "01" + "00".repeat(31)], // valid scalar 2^248
    ["signingPriv", "d99c55" + "82" + "02" + bstr32],
    ["signingPub", "d99c56" + bstr32],
    ["signingPub", "d99c56" + "82" + "01" + "5821" + "02" + "00".repeat(32)], // x = 0 is off the curve: rejected (U7)
    ["signingPub", "d99c56" + "82" + "01" + "5821" + G_COMPRESSED], // the generator
    ["encapPriv", "d99c4a" + bstr32],
    ["encapPub", "d99c4b" + bstr32],
    ["encapCiphertext", "d99c4b" + bstr32],
    ["mldsaPriv", "d99ca7" + "82" + "03" + "40"],
    ["mldsaPriv", "d99ca7" + "82" + "07" + "40"],
    ["mlkemCiphertext", "d99ca6" + "82" + "190300" + "40"],
    ["privateKeys", "d99c4d" + "82" + "d99c55" + bstr32 + "d99c4a" + bstr32], // zero scalar inside
    [
      "privateKeys",
      "d99c4d" + "82" + "d99c55" + "5820" + "01" + "00".repeat(31) + "d99c4a" + bstr32,
    ],
    ["publicKeys", "d99c51" + "82" + "d99c56" + bstr32 + "d99c4b" + bstr32],
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
}

/**
 * V2: Ed25519 verification over raw bytes. The valid pair is the
 * key `01..20` signing "abc" (checked against noble); every other row is a
 * strictness probe that a permissive verifier could accept.
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
/** B2: the untagged encodings of the tagged `decodes()` rows. */
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
/** B3: the scheme `random()` and `generateKeypair()` pick. */
function* defaults(): Generator<Recipe> {
  for (const rng of [...SEEDS.slice(0, 2), FAKE]) yield { k: "signingDefault", rng };
}
/** B4: KDF parameter construction over the integer edges and the JS-only numbers. */
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
/** B6 / B7 / B10: named JS-only input cases (see the adapter's table). */
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
    "digest.fromHex.zz",
    "digest.fromHex.odd",
    "ecPub.fromHex.zz",
    "symmetricKey.fromHex.short",
    "ecPriv.invalidScalar.publicKey",
    "ecPriv.zeroScalar.publicKey",
    "x25519.lowOrder.sharedKey",
    "symmetricKey.decrypt.tamperedTag",
    "encryptedKey.unlock.wrongPassword",
    "kdf.pbkdf2.iterations.0.lock",
    "kdf.scrypt.logN.100.lock",
    "digest.from.undefined",
    "arid.from.null",
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
    ["sskrShare", "d99d65" + "55" + "001100020000112233445566778899aabbccddeeff"],
    ["unknown tag 40999", "d9a027" + "00"],
    ["untagged", "00"],
  ];
  for (const [note, hex] of cases) yield { k: "summary", hex, note };
}

export const categories: Record<string, () => Generator<Recipe>> = {
  values,
  randoms,
  saltLengths,
  derives,
  digests,
  compresseds,
  seeds,
  encrypts,
  signings,
  sshes,
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
};
export function* allRecipes(): Generator<Recipe> {
  for (const g of Object.values(categories)) yield* g();
}
/** Golden subset: everything except the second cyclic start of each value size. */
export function* goldenRecipes(): Generator<Recipe> {
  for (const r of allRecipes()) {
    if (r.k === "value" && "cycle" in r.data && r.data.start === 0x80) continue;
    yield r;
  }
}
