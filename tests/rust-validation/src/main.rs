//! Replays a vector file against bc-components 0.31.1 from crates.io, with the
//! published bc-crypto 0.14.0 underneath it.
//!
//!   cargo run --release -- ../vectors/vectors.json        # the golden file
//!   cargo run --release -- <file>                         # any file `bun run vectors:full` wrote
//!   cargo run --release --features agent -- <file>        # with bc-components/ssh-agent
//!
//! Every recipe yields one outcome string on each side and the two are
//! compared textually: the TypeScript outcome is the vector's `expect`, the
//! reference's is computed here. A failure is `throw:<code>:<message>`: the
//! reference's error variant (a dcbor error is `Cbor` with dcbor's own
//! message, a `bc_components::Error::Cbor` keeps its `CBOR error: ` prefix, a
//! bc-ur error is its variant with `UR` printed as `Decoder`, an sskr error is
//! `SskrError:<variant>`) followed by its `Display`.
//!
//! Where the reference has no error object at the call the port reports one
//! (a panic, an `Option::None`, an infinite loop), the row is `panic-mapped`:
//! `PANIC_MAPPED` names the TypeScript code thrown there and only the code is
//! compared. Where the reference cannot run the recipe the row is `js-only`,
//! in one of four named classes:
//!
//!   J1  the input is outside the reference's types (a fractional length, a
//!       number where a string goes, `NaN`);
//!   J2  the reference type has no such operation (`UUID::from_hex`, an SSKR
//!       share's payload accessor);
//!   J3  the operation needs the `ssh-agent` feature and this build lacks it;
//!   J4  the operation needs a live SSH agent socket.
//!
//! Anything else that differs is a MISMATCH; a vector this program cannot
//! parse is `unparsable`. Both make the process exit 1. Rows under `noreg`
//! run before `register_tags()` and must come first in the file.
use bc_components::*;
use bc_rand::{RandomNumberGenerator, SeededRandomNumberGenerator};
use bc_ur::prelude::*;
use rand_core::RngCore;
use serde::Deserialize;
use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;
use std::sync::mpsc;
use std::time::Duration;

const DEFAULT_PBKDF2_ITERATIONS: u64 = 100_000;
const DEFAULT_SCRYPT_LOG_N: u64 = 15;
const DEFAULT_SCRYPT_R: u64 = 8;
const DEFAULT_SCRYPT_P: u64 = 1;

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/// The counter generator: 0, 17, 34, … (wrapping). Its integer draws are
/// little-endian reads of the same stream.
struct Fake;
impl RngCore for Fake {
    fn next_u32(&mut self) -> u32 { let mut b = [0u8; 4]; self.fill_bytes(&mut b); u32::from_le_bytes(b) }
    fn next_u64(&mut self) -> u64 { let mut b = [0u8; 8]; self.fill_bytes(&mut b); u64::from_le_bytes(b) }
    fn fill_bytes(&mut self, dest: &mut [u8]) { let mut b: u8 = 0; for x in dest.iter_mut() { *x = b; b = b.wrapping_add(17); } }
}
impl rand_core::CryptoRng for Fake {}
impl RandomNumberGenerator for Fake {}

/// Any of the three seedable generators behind one type.
enum Rng { Seeded(SeededRandomNumberGenerator), Fake(Fake), Hkdf(HKDFRng) }
impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 { match self { Rng::Seeded(r) => r.next_u32(), Rng::Fake(r) => r.next_u32(), Rng::Hkdf(r) => ssh_key::rand_core::RngCore::next_u32(r) } }
    fn next_u64(&mut self) -> u64 { match self { Rng::Seeded(r) => r.next_u64(), Rng::Fake(r) => r.next_u64(), Rng::Hkdf(r) => ssh_key::rand_core::RngCore::next_u64(r) } }
    fn fill_bytes(&mut self, dest: &mut [u8]) { match self { Rng::Seeded(r) => r.fill_bytes(dest), Rng::Fake(r) => r.fill_bytes(dest), Rng::Hkdf(r) => ssh_key::rand_core::RngCore::fill_bytes(r, dest) } }
}
impl rand_core::CryptoRng for Rng {}
// bc-rand's seeded generator draws one u64 per byte in `random_data`, which
// is not what rand_core's default `fill_bytes` does; delegate explicitly.
impl RandomNumberGenerator for Rng {
    fn random_data(&mut self, size: usize) -> Vec<u8> {
        match self {
            Rng::Seeded(r) => r.random_data(size),
            Rng::Fake(r) => r.random_data(size),
            Rng::Hkdf(r) => { let mut d = vec![0u8; size]; ssh_key::rand_core::RngCore::fill_bytes(r, &mut d); d }
        }
    }
    fn fill_random_data(&mut self, data: &mut [u8]) {
        match self {
            Rng::Seeded(r) => r.fill_random_data(data),
            Rng::Fake(r) => r.fill_random_data(data),
            Rng::Hkdf(r) => ssh_key::rand_core::RngCore::fill_bytes(r, data),
        }
    }
}

/// An in-memory SSH agent over OpenSSH private keys, the reference's test
/// agent: identities are keyed by comment and sign under namespace
/// `test_namespace` with SHA-256, returning the inner signature bytes.
#[cfg(feature = "agent")]
struct MemoryAgent { keys: Vec<ssh_key::PrivateKey>, refuse: bool }
#[cfg(feature = "agent")]
impl SSHAgent for MemoryAgent {
    fn list_identities(&mut self) -> Result<Vec<ssh_key::PublicKey>> { Ok(self.keys.iter().map(|k| k.public_key().clone()).collect()) }
    fn add_identity(&mut self, key: &ssh_key::PrivateKey) -> Result<()> { self.keys.push(key.clone()); Ok(()) }
    fn remove_identity(&mut self, key: &ssh_key::PrivateKey) -> Result<()> { self.keys.retain(|k| k.comment() != key.comment()); Ok(()) }
    fn remove_all_identities(&mut self) -> Result<()> { self.keys.clear(); Ok(()) }
    fn sign(&mut self, key: &ssh_key::PublicKey, data: &[u8]) -> Result<ssh_key::Signature> {
        if self.refuse { return Err(Error::ssh_agent("refused")); }
        let k = self.keys.iter().find(|k| k.comment() == key.comment()).ok_or_else(|| Error::ssh_agent("Identity not found"))?;
        let sig = k.sign("test_namespace", ssh_key::HashAlg::Sha256, data).map_err(|e| Error::ssh_agent(format!("Failed to sign data: {}", e)))?;
        Ok(sig.signature().clone())
    }
}
/// The message with one byte of its AAD or ciphertext flipped.
#[cfg(feature = "agent")]
fn tampered(m: &EncryptedMessage, how: &str) -> EncryptedMessage {
    let (mut ct, mut aad) = (m.ciphertext().to_vec(), m.aad().to_vec());
    match how {
        "aad" => { if let Some(b) = aad.last_mut() { *b ^= 1; } }
        "ciphertext" => { if let Some(b) = ct.first_mut() { *b ^= 1; } }
        _ => {}
    }
    EncryptedMessage::new(ct, aad, m.nonce().clone(), m.authentication_tag().clone())
}

// ---------------------------------------------------------------------------
// Outcome rendering
// ---------------------------------------------------------------------------

/// The first token of a `Debug` rendering: the enum variant name.
fn variant<E: std::fmt::Debug>(e: &E) -> String {
    let d = format!("{e:?}");
    d.split(|c: char| c == '(' || c == '{' || c == ' ').next().unwrap_or(&d).to_string()
}
/// One error class rendered the way the port renders it.
trait Render { fn render(&self) -> String; }
impl Render for bc_components::Error { fn render(&self) -> String { format!("throw:{}:{}", variant(self), self) } }
impl Render for dcbor::Error { fn render(&self) -> String { format!("throw:Cbor:{self}") } }
impl Render for bc_ur::Error {
    fn render(&self) -> String {
        let v = variant(self);
        let code = if v == "UR" { "Decoder".to_string() } else { v };
        format!("throw:{code}:{self}")
    }
}
impl Render for sskr::Error {
    fn render(&self) -> String {
        let v = variant(self);
        let code = if v == "ShamirError" { "Shamir".to_string() } else { v };
        format!("throw:SskrError:{code}:{self}")
    }
}
// The reference wraps every ssh-key error as `Error::Ssh(e.to_string())`.
impl Render for ssh_key::Error { fn render(&self) -> String { format!("throw:Ssh:SSH operation failed: {self}") } }
macro_rules! tri { ($e:expr) => { match $e { Ok(v) => v, Err(e) => return e.render() } } }

const J1: &str = "js-only:J1";
const J2: &str = "js-only:J2";
#[allow(dead_code)]
const J3: &str = "js-only:J3";
#[allow(dead_code)]
const J4: &str = "js-only:J4";

fn h(b: impl AsRef<[u8]>) -> String { hex::encode(b) }
/// IEEE CRC-32, the checksum `Compressed` stores over the decompressed bytes.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 { crc = if crc & 1 == 1 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 }; }
    }
    !crc
}
/// `tagged_cbor_data()|ur_string()` of a codable value.
fn cod<T: CBORTaggedEncodable + UREncodable>(v: &T) -> String { format!("{}|{}", h(v.tagged_cbor_data()), v.ur_string()) }
fn tagged<T: CBORTaggedEncodable>(v: &T) -> String { h(v.tagged_cbor_data()) }
/// Tagged CBOR of a value that only offers `Into<CBOR>` (the encapsulation enums).
fn tagged_any<T: Clone + Into<CBOR>>(v: &T) -> String { h(CBOR::from(v.clone().into()).to_cbor_data()) }

// ---------------------------------------------------------------------------
// The vector file
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct File { count: usize, vectors: Vec<Vector> }
#[derive(Deserialize, Clone)]
struct Vector { name: String, recipe: serde_json::Value, expect: String }
type J = serde_json::Value;

/// A recipe field this program cannot read exactly is an `unparsable` row.
macro_rules! need { ($e:expr, $what:expr) => { match $e { Some(v) => v, None => return format!("unparsable:{}", $what) } } }

fn bytes(v: &J) -> Option<Vec<u8>> {
    if let Some(x) = v.get("hex") { return hex::decode(x.as_str()?).ok(); }
    if let Some(t) = v.get("text") { return Some(t.as_str()?.as_bytes().to_vec()); }
    let n = v.get("cycle")?.as_u64()? as usize;
    let start = match v.get("start") { Some(s) => s.as_u64()? as usize, None => 0 };
    Some((0..n).map(|i| ((start + i) & 0xff) as u8).collect())
}
fn s(v: &J, k: &str) -> Option<String> { v.get(k)?.as_str().map(|x| x.to_string()) }
/// An exact unsigned integer: a float or a string is `None`.
fn u(v: &J, k: &str) -> Option<u64> { v.get(k)?.as_u64() }
fn rng_of(v: &J) -> Option<Rng> {
    if v.get("fake").is_some() { return Some(Rng::Fake(Fake)); }
    if let Some(x) = v.get("hkdf") { return Some(Rng::Hkdf(HKDFRng::new(bytes(x.get("km")?)?, x.get("salt")?.as_str()?))); }
    let a = v.get("seed")?.as_array()?;
    let mut seed = [0u64; 4];
    for (i, x) in a.iter().enumerate().take(4) { seed[i] = x.as_str()?.parse().ok()?; }
    Some(Rng::Seeded(SeededRandomNumberGenerator::new(seed)))
}
/// The `name=value` field of a TypeScript outcome, for the rows the reference
/// verifies rather than reproduces.
fn field<'a>(want: &'a str, name: &str) -> Option<&'a str> {
    want.split('|').find_map(|f| f.strip_prefix(name).and_then(|r| r.strip_prefix('=')))
}
fn unhex(x: &str) -> Option<Vec<u8>> { hex::decode(x).ok() }

// ---------------------------------------------------------------------------
// Recipe helpers
// ---------------------------------------------------------------------------

fn signing_priv(scheme: &str, key: &[u8]) -> Option<Result<SigningPrivateKey>> {
    Some(match scheme {
        "schnorr" => ECPrivateKey::from_data_ref(key).map(SigningPrivateKey::Schnorr),
        "ecdsa" => ECPrivateKey::from_data_ref(key).map(SigningPrivateKey::ECDSA),
        "ed25519" => Ed25519PrivateKey::from_data_ref(key).map(SigningPrivateKey::Ed25519),
        _ => return None,
    })
}
fn signing_pub(scheme: &str, key: &[u8]) -> Option<Result<SigningPublicKey>> {
    Some(match scheme {
        "schnorr" => SchnorrPublicKey::from_data_ref(key).map(SigningPublicKey::Schnorr),
        "ecdsa" => ECPublicKey::from_data_ref(key).map(SigningPublicKey::ECDSA),
        "ed25519" => Ed25519PublicKey::from_data_ref(key).map(SigningPublicKey::Ed25519),
        _ => return None,
    })
}
fn signature_of(scheme: &str, sig: &[u8]) -> Option<Result<Signature>> {
    Some(match scheme {
        "schnorr" => Signature::schnorr_from_data_ref(sig),
        "ecdsa" => Signature::ecdsa_from_data_ref(sig),
        "ed25519" => Signature::ed25519_from_data_ref(sig),
        _ => return None,
    })
}
fn ssh_alg(a: &str) -> Option<ssh_key::Algorithm> {
    use ssh_key::{Algorithm, EcdsaCurve};
    Some(match a {
        "ed25519" => Algorithm::Ed25519,
        "dsa" => Algorithm::Dsa,
        "rsa" => Algorithm::Rsa { hash: None },
        "ecdsa-p256" => Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 },
        "ecdsa-p384" => Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 },
        "ecdsa-p521" => Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 },
        _ => return None,
    })
}
fn is_p521(a: &ssh_key::Algorithm) -> bool {
    matches!(a, ssh_key::Algorithm::Ecdsa { curve: ssh_key::EcdsaCurve::NistP521 })
}
/// The signature field of an SSH signing row. Ed25519, DSA, P-256, P-384 and
/// RSA sign deterministically in the reference and compare byte for byte;
/// p521 0.13.3 signs with fresh randomness, so for P-521 the reference
/// verifies the TypeScript signature instead and the field is re-emitted.
fn ssh_sign_fields(p: &SigningPrivateKey, q: &SigningPublicKey, alg: &ssh_key::Algorithm, msg: &Vec<u8>, namespace: String, want: &str) -> String {
    let sig = match p.sign_with_options(msg, Some(SigningOptions::Ssh { namespace, hash_alg: ssh_key::HashAlg::Sha256 })) {
        Ok(sig) => sig,
        Err(e) => return e.render(),
    };
    if is_p521(alg) {
        if let Some(ts) = field(want, "sig").and_then(unhex) {
            if let Ok(ts_sig) = Signature::from_tagged_cbor_data(&ts) {
                if q.verify(&ts_sig, &msg) { return format!("sig={}|verified", h(ts)); }
                return format!("sig={}|TS-SIGNATURE-INVALID", h(ts));
            }
        }
    }
    format!("sig={}|{}", tagged(&sig), if q.verify(&sig, &msg) { "verified" } else { "INVALID" })
}
/// `KeyDerivationParams` for a params spec; `None` for a method this build has no type for.
fn params_of(r: &J) -> Option<Result<KeyDerivationParams>> {
    let salt = Salt::from_data(bytes(r.get("salt")?)?);
    let hash = if s(r, "hash").as_deref() == Some("sha512") { HashType::SHA512 } else { HashType::SHA256 };
    let n = |k: &str, d: u64| -> Option<u64> { match r.get(k) { None => Some(d), Some(v) => v.as_u64() } };
    Some(Ok(match s(r, "method")?.as_str() {
        "hkdf" => KeyDerivationParams::HKDF(HKDFParams::new_opt(salt, hash)),
        "pbkdf2" => KeyDerivationParams::PBKDF2(PBKDF2Params::new_opt(salt, u32::try_from(n("iterations", DEFAULT_PBKDF2_ITERATIONS)?).ok()?, hash)),
        "scrypt" => KeyDerivationParams::Scrypt(ScryptParams::new_opt(
            salt,
            u8::try_from(n("logN", DEFAULT_SCRYPT_LOG_N)?).ok()?,
            u32::try_from(n("r", DEFAULT_SCRYPT_R)?).ok()?,
            u32::try_from(n("p", DEFAULT_SCRYPT_P)?).ok()?,
        )),
        "argon2id" => KeyDerivationParams::Argon2id(Argon2idParams::new_opt(salt)),
        #[cfg(feature = "agent")]
        "sshAgent" => KeyDerivationParams::SSHAgent(SSHAgentParams::new_opt(salt, s(r, "id").unwrap_or_default(), None)),
        _ => return None,
    }))
}
fn method_name(m: KeyDerivationMethod) -> &'static str {
    match m {
        KeyDerivationMethod::HKDF => "hkdf",
        KeyDerivationMethod::PBKDF2 => "pbkdf2",
        KeyDerivationMethod::Scrypt => "scrypt",
        KeyDerivationMethod::Argon2id => "argon2id",
        #[cfg(feature = "agent")]
        KeyDerivationMethod::SSHAgent => "sshAgent",
    }
}
fn scheme_of(sig: &str) -> Option<SignatureScheme> {
    Some(match sig {
        "schnorr" => SignatureScheme::Schnorr,
        "ecdsa" => SignatureScheme::Ecdsa,
        "ed25519" => SignatureScheme::Ed25519,
        "mldsa44" => SignatureScheme::MLDSA44,
        "mldsa65" => SignatureScheme::MLDSA65,
        "mldsa87" => SignatureScheme::MLDSA87,
        "sshEd25519" => SignatureScheme::SshEd25519,
        "sshDsa" => SignatureScheme::SshDsa,
        "sshEcdsaP256" => SignatureScheme::SshEcdsaP256,
        "sshEcdsaP384" => SignatureScheme::SshEcdsaP384,
        _ => return None,
    })
}
fn enc_of(e: &str) -> Option<EncapsulationScheme> {
    Some(match e {
        "x25519" => EncapsulationScheme::X25519,
        "mlkem512" => EncapsulationScheme::MLKEM512,
        "mlkem768" => EncapsulationScheme::MLKEM768,
        "mlkem1024" => EncapsulationScheme::MLKEM1024,
        _ => return None,
    })
}
fn enc_name(e: EncapsulationScheme) -> &'static str {
    match e { EncapsulationScheme::X25519 => "x25519", EncapsulationScheme::MLKEM512 => "mlkem512", EncapsulationScheme::MLKEM768 => "mlkem768", EncapsulationScheme::MLKEM1024 => "mlkem1024" }
}
fn mldsa_level(l: u64) -> Option<MLDSA> { Some(match l { 44 => MLDSA::MLDSA44, 65 => MLDSA::MLDSA65, 87 => MLDSA::MLDSA87, _ => return None }) }
fn mlkem_level(l: u64) -> Option<MLKEM> { Some(match l { 512 => MLKEM::MLKEM512, 768 => MLKEM::MLKEM768, 1024 => MLKEM::MLKEM1024, _ => return None }) }
fn tag_names<T: CBORTagged>() -> String {
    T::cbor_tags().iter().map(|t| t.name().unwrap_or_else(|| t.value().to_string())).collect::<Vec<_>>().join(",")
}
fn escape_unicode(s: &str) -> String { s.chars().map(|c| format!("\\u{{{:x}}}", c as u32)).collect() }

// ---------------------------------------------------------------------------
// Recipe kinds
// ---------------------------------------------------------------------------

fn value(t: &str, d: &[u8]) -> String {
    match t {
        "digest" => cod(&tri!(Digest::from_data_ref(d))),
        "nonce" => cod(&tri!(Nonce::from_data_ref(d))),
        "salt" => cod(&Salt::from_data(d)),
        "arid" => cod(&tri!(ARID::from_data_ref(d))),
        // `from_data_ref` returns an `Option`: no error object (panic-mapped).
        "uuid" => match UUID::from_data_ref(d) { Some(v) => format!("{}|{}", cod(&v), v), None => "none:UUID::from_data_ref".into() },
        "xid" => { let v = tri!(XID::from_data_ref(d)); format!("{}|{}|{}|{}", cod(&v), v.bytewords_identifier(true), v.bytemoji_identifier(true), v.short_description()) }
        "reference" => { let v = tri!(Reference::from_data_ref(d)); format!("{}|{}|{}|{}", cod(&v), v.ref_hex_short(), v.bytewords_identifier(None), v.bytemoji_identifier(None)) }
        "symmetricKey" => cod(&tri!(SymmetricKey::from_data_ref(d))),
        "json" => cod(&JSON::from_data(d)),
        "uri" => match std::str::from_utf8(d) { Ok(t) => cod(&tri!(URI::new(t))), Err(_) => J1.into() },
        // `AuthenticationTag` has no `CBORTagged` impl: no UR on either side.
        "authTag" => format!("{}|-", h(CBOR::from(tri!(AuthenticationTag::from_data_ref(d))).to_cbor_data())),
        "x25519Priv" => { let v = tri!(X25519PrivateKey::from_data_ref(d)); format!("{}|{}", cod(&v), h(v.public_key().data())) }
        "x25519Pub" => cod(&tri!(X25519PublicKey::from_data_ref(d))),
        "ecPriv" => { let v = tri!(ECPrivateKey::from_data_ref(d)); format!("{}|{}|{}", cod(&v), h(v.public_key().data()), h(v.schnorr_public_key().data())) }
        "ecPub" => { let v = tri!(ECPublicKey::from_data_ref(d)); format!("{}|{}", cod(&v), h(v.uncompressed_public_key().data())) }
        "ecUncompressed" => { let v = tri!(ECUncompressedPublicKey::from_data_ref(d)); format!("{}|{}", cod(&v), h(v.public_key().data())) }
        "schnorrPub" => h(tri!(SchnorrPublicKey::from_data_ref(d)).data()),
        "ed25519Priv" => { let v = tri!(Ed25519PrivateKey::from_data_ref(d)); format!("{}|{}", h(v.data()), h(v.public_key().data())) }
        "ed25519Pub" => h(tri!(Ed25519PublicKey::from_data_ref(d)).data()),
        "privateKeyBase" => cod(&PrivateKeyBase::from_data(d)),
        // `from_data` copies the bytes; the accessors index into them.
        "sskrShare" => { let v = SSKRShare::from_data(d); format!("{}|{},{},{},{},{},{}", cod(&v), v.identifier(), v.group_threshold(), v.group_count(), v.group_index(), v.member_threshold(), v.member_index()) }
        _ => format!("unhandled:value type {t}"),
    }
}

/// `X::from_hex(text)`: the bytes. Most of the reference's `from_hex` unwrap,
/// so a bad text or size is a panic (panic-mapped); the Ed25519 pair returns
/// a `Result`.
fn from_hex(t: &str, text: &str) -> String {
    match t {
        "digest" => h(Digest::from_hex(text).data()),
        "nonce" => h(Nonce::from_hex(text).data()),
        "salt" => h(Salt::from_hex(text).as_bytes()),
        "arid" => h(ARID::from_hex(text).as_bytes()),
        "xid" => h(XID::from_hex(text).data()),
        "reference" => h(Reference::from_hex(text).data()),
        "symmetricKey" => h(tri!(SymmetricKey::from_hex(text)).data()),
        "json" => h(JSON::from_hex(text).as_bytes()),
        "sskrShare" => h(SSKRShare::from_hex(text).as_bytes()),
        "x25519Priv" => h(X25519PrivateKey::from_hex(text).data()),
        "x25519Pub" => h(X25519PublicKey::from_hex(text).data()),
        "ed25519Priv" => h(tri!(Ed25519PrivateKey::from_hex(text)).data()),
        "ed25519Pub" => h(tri!(Ed25519PublicKey::from_hex(text)).data()),
        // The reference `UUID` has no `from_hex`.
        "uuid" => J2.into(),
        _ => format!("unhandled:hex type {t}"),
    }
}

/// The decoders. Tagged types go through `from_tagged_cbor_data` (a dcbor
/// error, rendered bare); the `TryFrom<CBOR>` types parse the CBOR first and
/// then convert (a `bc_components::Error` keeps its `CBOR error: ` prefix).
fn decode(t: &str, data: &[u8]) -> String {
    macro_rules! decu { ($t:ty) => { { let v = tri!(<$t>::from_tagged_cbor_data(data)); cod(&v) } } }
    macro_rules! parsed { () => { tri!(CBOR::try_from_data(data)) } }
    match t {
        "digest" => decu!(Digest), "nonce" => decu!(Nonce), "salt" => decu!(Salt), "arid" => decu!(ARID), "xid" => decu!(XID),
        "reference" => decu!(Reference), "symmetricKey" => decu!(SymmetricKey), "uuid" => decu!(UUID),
        "json" => decu!(JSON), "uri" => decu!(URI), "x25519Priv" => decu!(X25519PrivateKey), "x25519Pub" => decu!(X25519PublicKey),
        "privateKeyBase" => decu!(PrivateKeyBase), "sskrShare" => decu!(SSKRShare), "seed" => decu!(Seed), "compressed" => decu!(Compressed),
        "encryptedMessage" => decu!(EncryptedMessage), "signature" => decu!(Signature), "signingPriv" => decu!(SigningPrivateKey),
        "signingPub" => decu!(SigningPublicKey), "sealedMessage" => decu!(SealedMessage), "privateKeys" => decu!(PrivateKeys),
        "publicKeys" => decu!(PublicKeys), "encryptedKey" => decu!(EncryptedKey), "mldsaPriv" => decu!(MLDSAPrivateKey),
        "mldsaPub" => decu!(MLDSAPublicKey), "mldsaSig" => decu!(MLDSASignature), "mlkemPriv" => decu!(MLKEMPrivateKey),
        "mlkemPub" => decu!(MLKEMPublicKey), "mlkemCiphertext" => decu!(MLKEMCiphertext),
        "encapPriv" => { let v = tri!(EncapsulationPrivateKey::try_from(parsed!())); format!("{}|-", tagged_any(&v)) }
        "encapPub" => { let v = tri!(EncapsulationPublicKey::try_from(parsed!())); format!("{}|-", tagged_any(&v)) }
        "encapCiphertext" => { let v = tri!(EncapsulationCiphertext::try_from(parsed!())); format!("{}|-", tagged_any(&v)) }
        "authTag" => h(CBOR::from(tri!(AuthenticationTag::try_from(parsed!()))).to_cbor_data()),
        "hkdfParams" => { let v = tri!(HKDFParams::try_from(parsed!())); format!("{}|{}", h(CBOR::from(v.clone()).to_cbor_data()), v) }
        "pbkdf2Params" => { let v = tri!(PBKDF2Params::try_from(parsed!())); format!("{}|{}", h(CBOR::from(v.clone()).to_cbor_data()), v) }
        "scryptParams" => { let v = tri!(ScryptParams::try_from(parsed!())); format!("{}|{}", h(CBOR::from(v.clone()).to_cbor_data()), v) }
        "argon2idParams" => { let v = tri!(Argon2idParams::try_from(parsed!())); format!("{}|{}", h(CBOR::from(v.clone()).to_cbor_data()), v) }
        #[cfg(feature = "agent")]
        "sshAgentParams" => { let v = tri!(SSHAgentParams::try_from(parsed!())); format!("{}|{}", h(CBOR::from(v.clone()).to_cbor_data()), v) }
        #[cfg(not(feature = "agent"))]
        "sshAgentParams" => J3.into(),
        "kdp" => { let v = tri!(KeyDerivationParams::try_from(parsed!())); format!("{}|{}", h(CBOR::from(v.clone()).to_cbor_data()), v) }
        "hashType" => tri!(HashType::try_from(parsed!())).to_string(),
        "kdMethod" => tri!(KeyDerivationMethod::try_from(&parsed!())).to_string(),
        "mlkemLevel" => format!("{:?}", tri!(MLKEM::try_from(parsed!()))),
        "mldsaLevel" => format!("{:?}", tri!(MLDSA::try_from(parsed!()))),
        _ => format!("unhandled:decode type {t}"),
    }
}

/// `from_ur_string` in its two steps: the UR grammar, then the type check and
/// the untagged decoder (the type name comes from the tags store, as in
/// `URDecodable::from_ur`).
fn ur_parse(t: &str, st: &str) -> String {
    let ur = tri!(UR::from_ur_string(st));
    macro_rules! dec { ($t:ty) => { {
        let name = <$t>::cbor_tags()[0].name().unwrap();
        tri!(ur.check_type(name).map_err(dcbor::Error::from));
        cod(&tri!(<$t>::from_untagged_cbor(ur.cbor())))
    } } }
    match t {
        "digest" => dec!(Digest), "nonce" => dec!(Nonce), "salt" => dec!(Salt), "arid" => dec!(ARID), "xid" => dec!(XID),
        "reference" => dec!(Reference), "symmetricKey" => dec!(SymmetricKey), "uuid" => dec!(UUID), "json" => dec!(JSON), "uri" => dec!(URI),
        "x25519Priv" => dec!(X25519PrivateKey), "x25519Pub" => dec!(X25519PublicKey), "privateKeyBase" => dec!(PrivateKeyBase),
        "sskrShare" => dec!(SSKRShare), "seed" => dec!(Seed), "compressed" => dec!(Compressed), "encryptedMessage" => dec!(EncryptedMessage),
        "signature" => dec!(Signature), "signingPriv" => dec!(SigningPrivateKey), "signingPub" => dec!(SigningPublicKey),
        "sealedMessage" => dec!(SealedMessage), "privateKeys" => dec!(PrivateKeys), "publicKeys" => dec!(PublicKeys),
        "encryptedKey" => dec!(EncryptedKey), "mldsaPriv" => dec!(MLDSAPrivateKey), "mldsaPub" => dec!(MLDSAPublicKey),
        "mldsaSig" => dec!(MLDSASignature), "mlkemPriv" => dec!(MLKEMPrivateKey), "mlkemPub" => dec!(MLKEMPublicKey), "mlkemCiphertext" => dec!(MLKEMCiphertext),
        _ => format!("unhandled:urParse type {t}"),
    }
}

fn cbor_tags(t: &str) -> String {
    match t {
        "digest" => tag_names::<Digest>(), "nonce" => tag_names::<Nonce>(), "salt" => tag_names::<Salt>(), "arid" => tag_names::<ARID>(),
        "xid" => tag_names::<XID>(), "reference" => tag_names::<Reference>(), "symmetricKey" => tag_names::<SymmetricKey>(), "uuid" => tag_names::<UUID>(),
        "json" => tag_names::<JSON>(), "uri" => tag_names::<URI>(), "x25519Priv" => tag_names::<X25519PrivateKey>(), "x25519Pub" => tag_names::<X25519PublicKey>(),
        "privateKeyBase" => tag_names::<PrivateKeyBase>(), "sskrShare" => tag_names::<SSKRShare>(), "seed" => tag_names::<Seed>(), "compressed" => tag_names::<Compressed>(),
        "encryptedMessage" => tag_names::<EncryptedMessage>(), "signature" => tag_names::<Signature>(), "signingPriv" => tag_names::<SigningPrivateKey>(),
        "signingPub" => tag_names::<SigningPublicKey>(), "sealedMessage" => tag_names::<SealedMessage>(), "privateKeys" => tag_names::<PrivateKeys>(),
        "publicKeys" => tag_names::<PublicKeys>(), "encryptedKey" => tag_names::<EncryptedKey>(), "mldsaPriv" => tag_names::<MLDSAPrivateKey>(),
        "mldsaPub" => tag_names::<MLDSAPublicKey>(), "mldsaSig" => tag_names::<MLDSASignature>(), "mlkemPriv" => tag_names::<MLKEMPrivateKey>(),
        "mlkemPub" => tag_names::<MLKEMPublicKey>(), "mlkemCiphertext" => tag_names::<MLKEMCiphertext>(),
        // The encapsulation enums are not `CBORTagged` in the reference.
        "encapPriv" | "encapPub" | "encapCiphertext" => J2.into(),
        _ => format!("unhandled:cborTags type {t}"),
    }
}

/// The named API cases, one closure each, in the words of the port's table.
fn api(case: &str) -> String {
    let msg = b"m".to_vec();
    let one = { let mut k = [0u8; 32]; k[31] = 1; k };
    let good = || ECPrivateKey::from_data_ref(one).unwrap();
    let key7 = || SymmetricKey::from_data_ref([7u8; 32]).unwrap();
    let short4 = || SSKRShare::from_data([0u8, 1, 2, 3]);
    let g_xy = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    let fake = || Rc::new(RefCell::new(Fake)) as Rc<RefCell<dyn RandomNumberGenerator>>;
    let lock_unlock = |params: KeyDerivationParams| -> String {
        let key = key7();
        let ek = tri!(EncryptedKey::lock_opt(params, [1u8], &key));
        if tri!(ek.unlock([1u8])) == key { "unlocked".into() } else { "MISMATCH".into() }
    };
    match case {
        "json/invalid-utf8-decode" => format!("ok:{}", tagged(&tri!(JSON::from_tagged_cbor_data(JSON::from_data([0xffu8, 0xfe]).tagged_cbor_data())))),
        "json/invalid-utf8-as-str" => JSON::from_data([0xffu8, 0xfe]).as_str().to_string(),
        "json/bom-as-str" => escape_unicode(JSON::from_data([0xefu8, 0xbb, 0xbf, 0x7b, 0x7d]).as_str()),
        "sskr/short4-identifier" => short4().identifier().to_string(),
        "sskr/short4-group-threshold" => short4().group_threshold().to_string(),
        "sskr/short4-group-count" => short4().group_count().to_string(),
        "sskr/short4-group-index" => short4().group_index().to_string(),
        "sskr/short4-member-threshold" => short4().member_threshold().to_string(),
        "sskr/short4-member-index" => short4().member_index().to_string(),
        // The reference share has no payload accessor.
        "sskr/short4-value" => J2.into(),
        "sskr/empty-identifier" => SSKRShare::from_data([0u8; 0]).identifier().to_string(),
        "sskr/combine-short" => { tri!(sskr_combine(&[short4()])); "ok".into() }
        "sskr/combine-empty" => { tri!(sskr_combine(&[])); "ok".into() }
        "sskr/combine-one-of-two" => {
            let spec = tri!(SSKRSpec::new(1, vec![tri!(SSKRGroupSpec::new(2, 3))]));
            let groups = tri!(sskr_generate_using(&spec, &tri!(SSKRSecret::new([7u8; 16])), &mut Fake));
            tri!(sskr_combine(&[groups[0][0].clone()]));
            "ok".into()
        }
        "mldsa/signing-public-key" => { let (k, _) = MLDSA::MLDSA44.keypair(); format!("ok:{}", tri!(SigningPrivateKey::MLDSA(k).public_key())) }
        "mlkem/encap-public-key" => { let (k, _) = MLKEM::MLKEM512.keypair(); format!("ok:{}", tri!(EncapsulationPrivateKey::MLKEM(k).public_key())) }
        "privateKeys/mldsa-public-keys" => {
            let (k, _) = MLDSA::MLDSA44.keypair();
            let x = tri!(X25519PrivateKey::from_data_ref(one));
            format!("ok:{}", tri!(PrivateKeys::with_keys(SigningPrivateKey::MLDSA(k), EncapsulationPrivateKey::X25519(x)).public_keys()))
        }
        "privateKeys/mlkem-public-keys" => {
            let (k, _) = MLKEM::MLKEM512.keypair();
            format!("ok:{}", tri!(PrivateKeys::with_keys(SigningPrivateKey::Schnorr(good()), EncapsulationPrivateKey::MLKEM(k)).public_keys()))
        }
        "compressed/new-larger" => { tri!(Compressed::new(0, 1, vec![0u8; 2], None)); "ok:ok".into() }
        "compressed/digest-none" => h(Compressed::from_decompressed_data([0u8; 3], None).digest().data()),
        "ec/zero-public-key" => h(tri!(ECPrivateKey::from_data_ref([0u8; 32])).public_key().data()),
        "ec/zero-schnorr-public-key" => h(tri!(ECPrivateKey::from_data_ref([0u8; 32])).schnorr_public_key().data()),
        "ec/zero-signing-public-key" => format!("ok:{}", tri!(SigningPrivateKey::Schnorr(tri!(ECPrivateKey::from_data_ref([0u8; 32]))).public_key())),
        "ec/zero-schnorr-sign" => {
            tri!(SigningPrivateKey::Schnorr(tri!(ECPrivateKey::from_data_ref([0u8; 32]))).sign_with_options(&msg, Some(SigningOptions::Schnorr { rng: fake() })));
            "ok:signed".into()
        }
        "ec/zero-ecdsa-sign" => { tri!(SigningPrivateKey::ECDSA(tri!(ECPrivateKey::from_data_ref([0u8; 32]))).sign(&msg)); "ok:signed".into() }
        "ec/n-public-key" => h(tri!(ECPrivateKey::from_data_ref(hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap())).public_key().data()),
        "ec/one-public-key" => h(good().public_key().data()),
        "ecpub/zeros33-uncompressed" => h(tri!(ECPublicKey::from_data_ref([0u8; 33])).uncompressed_public_key().data()),
        "ecpub/02zeros-uncompressed" => { let mut k = [0u8; 33]; k[0] = 2; h(tri!(ECPublicKey::from_data_ref(k)).uncompressed_public_key().data()) }
        "ecpub/05ff-uncompressed" => { let mut k = [0xffu8; 33]; k[0] = 5; h(tri!(ECPublicKey::from_data_ref(k)).uncompressed_public_key().data()) }
        "ecpub/G-uncompressed" => h(good().public_key().uncompressed_public_key().data()),
        "ecuncomp/04-public-key" => h(tri!(ECUncompressedPublicKey::from_data_ref(hex::decode(format!("04{g_xy}")).unwrap())).public_key().data()),
        "ecuncomp/06-public-key" => h(tri!(ECUncompressedPublicKey::from_data_ref(hex::decode(format!("06{g_xy}")).unwrap())).public_key().data()),
        "ecuncomp/07-public-key" => h(tri!(ECUncompressedPublicKey::from_data_ref(hex::decode(format!("07{g_xy}")).unwrap())).public_key().data()),
        "ecuncomp/00-public-key" => h(tri!(ECUncompressedPublicKey::from_data_ref(hex::decode(format!("00{g_xy}")).unwrap())).public_key().data()),
        "sym/decrypt-tampered" => {
            let k = key7();
            let m = k.encrypt([0x61u8, 0x62, 0x63, 0x64], None::<Vec<u8>>, Some(tri!(Nonce::from_data_ref([0u8; 12]))));
            let tampered = EncryptedMessage::new(m.ciphertext(), m.aad(), m.nonce().clone(), tri!(AuthenticationTag::from_data_ref([0u8; 16])));
            format!("ok:{}", h(tri!(k.decrypt(&tampered))))
        }
        "sym/decrypt-wrong-key" => {
            let m = key7().encrypt([1u8, 2, 3], None::<Vec<u8>>, Some(tri!(Nonce::from_data_ref([0u8; 12]))));
            format!("ok:{}", h(tri!(tri!(SymmetricKey::from_data_ref([8u8; 32])).decrypt(&m))))
        }
        "ek/unlock-wrong" => format!("ok:{}", h(tri!(tri!(EncryptedKey::lock(KeyDerivationMethod::HKDF, [1u8], &key7())).unlock([2u8])).data())),
        "sealed/wrong-key" => {
            let (_, pubk) = tri!(EncapsulationScheme::X25519.keypair_using(&mut Fake));
            let other = EncapsulationPrivateKey::X25519(tri!(X25519PrivateKey::from_data_ref([9u8; 32])));
            format!("ok:{}", h(tri!(SealedMessage::new([0x78u8], &pubk).decrypt(&other))))
        }
        "salt/len7" => format!("ok:{}", h(tri!(Salt::new_with_len_using(7, &mut Fake)).as_bytes())),
        "salt/len8" => format!("ok:{}", h(tri!(Salt::new_with_len_using(8, &mut Fake)).as_bytes())),
        "seed/len15" => { tri!(Seed::new_opt(vec![0u8; 15], None, None, None)); "ok:ok".into() }
        "seed/len16" => { tri!(Seed::new_opt(vec![0u8; 16], None, None, None)); "ok:ok".into() }
        "sign/ed25519-with-schnorr-opts" => format!("ok:{}", tagged(&tri!(SigningPrivateKey::Ed25519(tri!(Ed25519PrivateKey::from_data_ref([7u8; 32]))).sign_with_options(&msg, Some(SigningOptions::Schnorr { rng: fake() }))))),
        "sign/schnorr-with-ssh-opts" => {
            let p = SigningPrivateKey::Schnorr(good());
            let sig = tri!(p.sign_with_options(&msg, Some(SigningOptions::Ssh { namespace: "n".into(), hash_alg: ssh_key::HashAlg::Sha256 })));
            format!("ok:{}", if tri!(p.public_key()).verify(&sig, &msg) { "verified" } else { "INVALID" })
        }
        // The reference's `ecdsa_sign` and `mldsa_sign` are private: no counterpart.
        "sign/schnorr-key-ecdsa-sign" | "sign/ed25519-key-ecdsa-sign" | "sign/schnorr-key-mldsa-sign" => J2.into(),
        "sign/ecdsa-key-schnorr-sign" => format!("ok:{}", tagged(&tri!(SigningPrivateKey::ECDSA(good()).schnorr_sign(&msg, fake())))),
        "sign/schnorr-key-ed25519-sign" => format!("ok:{}", tagged(&tri!(SigningPrivateKey::Schnorr(good()).ed25519_sign(&msg)))),
        "pkb/empty" => { let p = PrivateKeyBase::from_data([0u8; 0]); format!("{}|{}", tagged(&p), h(p.x25519_private_key().data())) }
        "mldsa/short-sig-verify" => {
            let (pk, pubk) = MLDSA::MLDSA44.keypair();
            let sig = pk.sign(&msg);
            let short = tri!(MLDSASignature::from_bytes(MLDSA::MLDSA44, &sig.as_bytes()[..100]));
            format!("from-ok|{}", tri!(pubk.verify(&short, &msg)))
        }
        "mldsa/long-sig-from" => { tri!(MLDSASignature::from_bytes(MLDSA::MLDSA44, &[0u8; 2421])); "ok:ok".into() }
        "scheme/default-sig" => format!("{:?}", SignatureScheme::default()),
        "scheme/default-enc" => format!("{:?}", EncapsulationScheme::default()),
        "hkdf/page0-fill0" => { let mut g = HKDFRng::new_with_page_length(b"km", "salt", 0); ssh_key::rand_core::RngCore::fill_bytes(&mut g, &mut []); "ok".into() }
        "hkdf/page0-fill1" => { let mut g = HKDFRng::new_with_page_length(b"km", "salt", 0); ssh_key::rand_core::RngCore::fill_bytes(&mut g, &mut [0u8; 1]); "ok".into() }
        "hkdf/page0-u32" => { let mut g = HKDFRng::new_with_page_length(b"km", "salt", 0); format!("ok:{}", ssh_key::rand_core::RngCore::next_u32(&mut g)) }
        "kdf/pbkdf2-iter0-unlock" => lock_unlock(KeyDerivationParams::PBKDF2(PBKDF2Params::new_opt(Salt::from_data([0u8; 16]), 0, HashType::SHA256))),
        "kdf/scrypt-logn0-unlock" => lock_unlock(KeyDerivationParams::Scrypt(ScryptParams::new_opt(Salt::from_data([0u8; 16]), 0, DEFAULT_SCRYPT_R as u32, DEFAULT_SCRYPT_P as u32))),
        "authTag/from-cbor-bytes" => h(tri!(AuthenticationTag::try_from(CBOR::to_byte_string([0u8; 16]))).data()),
        "authTag/from-cbor-uint" => h(tri!(AuthenticationTag::try_from(CBOR::from(1))).data()),
        "authTag/from-cbor-short" => h(tri!(AuthenticationTag::try_from(CBOR::to_byte_string([0u8; 15]))).data()),
        "uuid/to-string" => { let mut d = [0u8; 16]; for (i, b) in d.iter_mut().enumerate() { *b = 0x60 + i as u8; } UUID::from_data(d).to_string() }
        "ssh/rsa-sign" => {
            let p = tri!(PrivateKeyBase::from_data([1u8; 32]).ssh_signing_private_key(ssh_key::Algorithm::Rsa { hash: None }, "c"));
            format!("ok:{}", tagged(&tri!(p.sign_with_options(&msg, Some(SigningOptions::Ssh { namespace: "test".into(), hash_alg: ssh_key::HashAlg::Sha256 })))))
        }
        _ => format!("unhandled:api case {case}"),
    }
}

fn run(r: &J, want: &str) -> String {
    let k = need!(s(r, "k"), "k");
    match k.as_str() {
        "value" => value(&need!(s(r, "type"), "type"), &need!(r.get("data").and_then(bytes), "data")),
        "saltInRange" => {
            let mut g = need!(r.get("rng").and_then(rng_of), "rng");
            let (min, max) = (need!(u(r, "min"), "min") as usize, need!(u(r, "max"), "max") as usize);
            h(tri!(Salt::new_in_range_using(&(min..=max), &mut g)).as_bytes())
        }
        "saltForSize" => {
            let mut g = need!(r.get("rng").and_then(rng_of), "rng");
            h(Salt::new_for_size_using(need!(u(r, "size"), "size") as usize, &mut g).as_bytes())
        }
        "random" => {
            let mut g = need!(r.get("rng").and_then(rng_of), "rng");
            let len = match r.get("len") { None => None, Some(v) => Some(need!(v.as_u64(), "len")) };
            match need!(s(r, "type"), "type").as_str() {
                "nonce" => h(g.random_data(12)),
                "salt" => h(tri!(Salt::new_with_len_using(len.unwrap_or(16) as usize, &mut g)).as_bytes()),
                "arid" => h(g.random_data(32)),
                "uuid" => h(g.random_data(16)),
                "symmetricKey" => h(SymmetricKey::new_using(&mut g).data()),
                "x25519Priv" => h(X25519PrivateKey::new_using(&mut g).data()),
                "ecPriv" => h(ECPrivateKey::new_using(&mut g).data()),
                "ed25519Priv" => h(Ed25519PrivateKey::new_using(&mut g).data()),
                "privateKeyBase" => h(PrivateKeyBase::new_using(&mut g).as_bytes()),
                "seed" => h(tri!(Seed::new_with_len_using(len.unwrap_or(32) as usize, &mut g)).as_bytes()),
                t => format!("unhandled:random type {t}"),
            }
        }
        "derive" => {
            let km = need!(r.get("km").and_then(bytes), "km");
            match need!(s(r, "type"), "type").as_str() {
                "x25519" => { let k = X25519PrivateKey::derive_from_key_material(&km); format!("{}|{}", h(k.data()), h(k.public_key().data())) }
                "ec" => { let k = ECPrivateKey::derive_from_key_material(&km); format!("{}|{}|{}", h(k.data()), h(k.public_key().data()), h(k.schnorr_public_key().data())) }
                "ed25519" => { let k = Ed25519PrivateKey::derive_from_key_material(&km); format!("{}|{}", h(k.data()), h(k.public_key().data())) }
                t => format!("unhandled:derive type {t}"),
            }
        }
        "digest" => { let d = Digest::from_image(need!(r.get("image").and_then(bytes), "image")); format!("{}|{}|{}", h(d.data()), d.ur_string(), d.short_description()) }
        "compressed" => {
            let data = need!(r.get("data").and_then(bytes), "data");
            let digest = if r.get("digest").and_then(|x| x.as_bool()).unwrap_or(false) { Some(Digest::from_image(&data)) } else { None };
            let c = Compressed::from_decompressed_data(&data, digest);
            let back = tri!(c.decompress());
            format!("{}|{}", tagged(&c), if back == data { "roundtrip" } else { "MISMATCH" })
        }
        "inflate" => {
            let data = need!(s(r, "hex").and_then(|x| unhex(&x)), "hex");
            let (raw, crc) = match miniz_oxide::inflate::decompress_to_vec(&data) {
                Ok(out) => (format!("ok:{}", h(&out)), crc32(&out)),
                Err(e) => (format!("err:{:?}", e.status), 0),
            };
            let through = (|| -> String {
                let c = tri!(Compressed::new(crc, 1 << 20, data.clone(), None));
                format!("ok:{}", h(tri!(c.decompress())))
            })();
            format!("raw={raw}|compressed={through}")
        }
        "seed" => {
            let date = match r.get("date") { None => None, Some(v) => Some(Date::from_timestamp(need!(v.as_f64(), "date") / 1000.0)) };
            cod(&tri!(Seed::new_opt(need!(r.get("data").and_then(bytes), "data"), s(r, "name"), s(r, "note"), date)))
        }
        "encrypt" => {
            let key = tri!(SymmetricKey::from_data_ref(need!(r.get("key").and_then(bytes), "key")));
            let nonce = tri!(Nonce::from_data_ref(need!(r.get("nonce").and_then(bytes), "nonce")));
            let pt = need!(r.get("plaintext").and_then(bytes), "plaintext");
            let aad = match r.get("aad") { None => None, Some(v) => Some(need!(bytes(v), "aad")) };
            let msg = key.encrypt(&pt, aad, Some(nonce));
            let back = tri!(key.decrypt(&msg));
            format!("{}|{}", cod(&msg), if back == pt { "roundtrip" } else { "MISMATCH" })
        }
        "x25519Shared" => {
            let p = tri!(X25519PrivateKey::from_data_ref(need!(r.get("priv").and_then(bytes), "priv")));
            let q = tri!(X25519PublicKey::from_data_ref(need!(r.get("pub").and_then(bytes), "pub")));
            h(p.shared_key_with(&q).data())
        }
        "signingKeys" => {
            let p = tri!(need!(signing_priv(&need!(s(r, "scheme"), "scheme"), &need!(r.get("key").and_then(bytes), "key")), "scheme"));
            let q = tri!(p.public_key());
            format!("{}|{}|{}|{}", cod(&p), cod(&q), h(XID::new(&q).data()), h(q.reference().data()))
        }
        "sign" => {
            let p = tri!(need!(signing_priv(&need!(s(r, "scheme"), "scheme"), &need!(r.get("key").and_then(bytes), "key")), "scheme"));
            let msg = need!(r.get("message").and_then(bytes), "message");
            let sig = if let Some(rv) = r.get("rng") {
                let rng: Rc<RefCell<dyn RandomNumberGenerator>> = Rc::new(RefCell::new(need!(rng_of(rv), "rng")));
                tri!(p.sign_with_options(&msg, Some(SigningOptions::Schnorr { rng })))
            } else { tri!(p.sign(&msg)) };
            let ok = tri!(p.public_key()).verify(&sig, &msg);
            format!("{}|{}", cod(&sig), if ok { "verified" } else { "INVALID" })
        }
        "verify" => {
            let scheme = need!(s(r, "scheme"), "scheme");
            let q = tri!(need!(signing_pub(&scheme, &need!(r.get("pub").and_then(bytes), "pub")), "scheme"));
            let sig = tri!(need!(signature_of(&scheme, &need!(r.get("sig").and_then(bytes), "sig")), "scheme"));
            let msg = need!(r.get("message").and_then(bytes), "message");
            q.verify(&sig, &msg).to_string()
        }
        "sshFromSeed" => {
            let pkb = PrivateKeyBase::from_data(need!(r.get("seed").and_then(bytes), "seed"));
            let alg = need!(ssh_alg(&need!(s(r, "alg"), "alg")), "alg");
            let p = tri!(pkb.ssh_signing_private_key(alg.clone(), need!(s(r, "comment"), "comment")));
            let q = tri!(p.public_key());
            let pem = tri!(tri!(p.to_ssh().unwrap().to_openssh(ssh_key::LineEnding::LF)).to_string().parse::<String>().map_err(|_| Error::general("pem")));
            let pubtxt = tri!(q.to_ssh().unwrap().to_openssh());
            let mut parts = vec![pem, pubtxt, tagged(&p), tagged(&q)];
            if let Some(m) = r.get("message") {
                let msg = need!(bytes(m), "message");
                let f = ssh_sign_fields(&p, &q, &alg, &msg, s(r, "namespace").unwrap_or_else(|| "test".into()), want);
                if f.starts_with("throw:") { return f; }
                parts.push(f);
            }
            parts.join("|")
        }
        "sshFromPem" => {
            let pem = need!(s(r, "pem"), "pem");
            let key = tri!(ssh_key::PrivateKey::from_openssh(&pem));
            let alg = key.algorithm();
            let p = SigningPrivateKey::new_ssh(key.clone());
            let q = tri!(p.public_key());
            let mut parts = vec![
                if tri!(key.to_openssh(ssh_key::LineEnding::LF)).to_string() == pem { "pem-roundtrip".to_string() } else { "PEM-DIFF".to_string() },
                tri!(q.to_ssh().unwrap().to_openssh()),
                tagged(&q),
            ];
            if let Some(m) = r.get("message") {
                let msg = need!(bytes(m), "message");
                let f = ssh_sign_fields(&p, &q, &alg, &msg, s(r, "namespace").unwrap_or_else(|| "test".into()), want);
                if f.starts_with("throw:") { return f; }
                parts.push(f);
            }
            parts.join("|")
        }
        "sshText" => {
            let text = need!(s(r, "text"), "text");
            match need!(s(r, "kind"), "kind").as_str() {
                "priv" => {
                    let key = tri!(ssh_key::PrivateKey::from_openssh(&text));
                    format!("ok:{}|comment={}|pub={}", tri!(key.to_openssh(ssh_key::LineEnding::LF)).to_string(), key.comment(), tri!(key.public_key().to_openssh()))
                }
                "pub" => { let key = tri!(ssh_key::PublicKey::from_openssh(&text)); format!("ok:{}|comment={}", tri!(key.to_openssh()), key.comment()) }
                "sig" => { let sig = tri!(ssh_key::SshSig::from_pem(&text)); format!("ok:{}", tri!(sig.to_pem(ssh_key::LineEnding::LF))) }
                kind => format!("unhandled:sshText kind {kind}"),
            }
        }
        "pkb" => {
            let pkb = PrivateKeyBase::from_data(need!(r.get("seed").and_then(bytes), "seed"));
            let x = pkb.x25519_private_key();
            [
                cod(&pkb), tagged(&pkb.ed25519_signing_private_key()), tagged(&tri!(pkb.schnorr_signing_private_key().public_key())),
                tagged(&pkb.ecdsa_signing_private_key()), h(x.data()), h(x.public_key().data()),
                tagged(&pkb.schnorr_private_keys()), tagged(&pkb.schnorr_public_keys()), tagged(&pkb.ecdsa_private_keys()), tagged(&pkb.ecdsa_public_keys()),
            ].join("|")
        }
        "keypair" => {
            let mut g = need!(r.get("rng").and_then(rng_of), "rng");
            let sig = need!(scheme_of(&need!(s(r, "sigScheme"), "sigScheme")), "sigScheme");
            let enc = need!(enc_of(&need!(s(r, "encScheme"), "encScheme")), "encScheme");
            let (p, q) = tri!(keypair_opt_using(sig, enc, &mut g));
            let consistent = q == tri!(p.public_keys());
            format!("{}|{}|{}|{}", cod(&p), cod(&q), h(q.reference().data()), if consistent { "consistent" } else { "INCONSISTENT" })
        }
        "seal" => {
            // The ephemeral key is drawn from the secure generator on both sides,
            // so the reference opens the TypeScript artefact: it decrypts the
            // sealed message with the recipient key the row carries and checks
            // the plaintext and AAD, then re-emits the row.
            let pt = need!(r.get("plaintext").and_then(bytes), "plaintext");
            let aad = match r.get("aad") { None => Vec::new(), Some(v) => need!(bytes(v), "aad") };
            let (Some(priv_hex), Some(pub_hex), Some(sealed_hex), Some(pt_hex), Some(aad_hex)) = (field(want, "priv"), field(want, "pub"), field(want, "sealed"), field(want, "pt"), field(want, "aad")) else {
                return format!("unverifiable:the TypeScript row carries no sealed message ({want})");
            };
            if pt_hex != h(&pt) || aad_hex != h(&aad) { return "unverifiable:the row's plaintext or AAD is not the recipe's".into(); }
            let priv_key = tri!(EncapsulationPrivateKey::try_from(tri!(CBOR::try_from_data(need!(unhex(priv_hex), "priv")))));
            let sealed = tri!(SealedMessage::from_tagged_cbor_data(need!(unhex(sealed_hex), "sealed")));
            let scheme = want.split('|').next().unwrap_or("");
            if enc_name(sealed.encapsulation_scheme()) != scheme { return format!("SCHEME-DIFF:{}", enc_name(sealed.encapsulation_scheme())); }
            let back = tri!(sealed.decrypt(&priv_key));
            if back != pt { return "PLAINTEXT-DIFF".into(); }
            // The row's public key is the private key's (X25519 derives it; the
            // reference cannot derive an ML-KEM public key) and the reference's
            // own sealing to it must open with the private key.
            let pubk = tri!(EncapsulationPublicKey::try_from(tri!(CBOR::try_from_data(need!(unhex(pub_hex), "pub")))));
            if let EncapsulationPrivateKey::X25519(_) = priv_key {
                if tri!(priv_key.public_key()) != pubk { return "PUBLIC-KEY-DIFF".into(); }
            }
            let own = SealedMessage::new_opt(&pt, &pubk, if aad.is_empty() { None } else { Some(aad.clone()) }, None);
            if tri!(own.decrypt(&priv_key)) != pt { return "OWN-SEAL-DIFF".into(); }
            want.to_string()
        }
        "params" => {
            let p = match params_of(r) {
                Some(p) => tri!(p),
                None if s(r, "method").as_deref() == Some("sshAgent") => return J3.into(),
                None => return "unparsable:method".into(),
            };
            format!("{}|{}|{}", h(CBOR::from(p.clone()).to_cbor_data()), p, method_name(p.method()))
        }
        "encryptedKey" => {
            // The content key is locked under a fresh nonce on both sides, so
            // the reference unlocks the TypeScript artefact with the secret,
            // checks its AAD is the reference's encoding of the same parameters,
            // locks and unlocks on its own, and re-emits the row.
            if s(r, "method").as_deref() == Some("sshAgent") { return J4.into(); }
            let params = tri!(need!(params_of(r), "method"));
            let key = tri!(SymmetricKey::from_data_ref(need!(r.get("key").and_then(bytes), "key")));
            let secret = need!(r.get("secret").and_then(bytes), "secret");
            let Some(ek_hex) = field(want, "ek") else { return format!("unverifiable:the TypeScript row carries no encrypted key ({want})"); };
            let ek = tri!(EncryptedKey::from_tagged_cbor_data(need!(unhex(ek_hex), "ek")));
            if tri!(ek.unlock(&secret)) != key { return "UNLOCK-DIFF".into(); }
            if ek.encrypted_message().aad() != CBOR::from(params.clone()).to_cbor_data() { return "AAD-DIFF".into(); }
            let own = tri!(EncryptedKey::lock_opt(params.clone(), &secret, &key));
            if tri!(tri!(EncryptedKey::from_tagged_cbor_data(own.tagged_cbor_data())).unlock(&secret)) != key { return "OWN-LOCK-DIFF".into(); }
            format!("{}|ek={}|key={}|secret={}", params, ek_hex, h(key.data()), h(&secret))
        }
        "hkdfRng" => {
            let km = need!(r.get("km").and_then(bytes), "km");
            let salt = need!(s(r, "salt"), "salt");
            let mut g = match r.get("pageLen") { Some(p) => HKDFRng::new_with_page_length(km, &salt, need!(p.as_u64(), "pageLen") as usize), None => HKDFRng::new(km, &salt) };
            let draws = need!(r.get("draws").and_then(|d| d.as_array()), "draws");
            let mut parts: Vec<String> = Vec::new();
            for n in draws {
                let mut d = vec![0u8; need!(n.as_u64(), "draw") as usize];
                ssh_key::rand_core::RngCore::fill_bytes(&mut g, &mut d);
                parts.push(h(d));
            }
            parts.push(format!("u32={}", ssh_key::rand_core::RngCore::next_u32(&mut g)));
            parts.push(format!("u64={}", ssh_key::rand_core::RngCore::next_u64(&mut g)));
            parts.join("|")
        }
        "mldsa" => {
            // The reference seeds ML-DSA key generation from the OS only, so it
            // verifies the TypeScript keys: both parse and re-encode, a fresh
            // signature under the private key verifies under the public key,
            // and the row's own signature verifies too.
            let level = need!(u(r, "level").and_then(mldsa_level), "level");
            let f: Vec<&str> = want.split('|').collect();
            if f.len() < 4 || want.starts_with("throw:") { return format!("unverifiable:the TypeScript row carries no keys ({want})"); }
            let priv_key = tri!(MLDSAPrivateKey::from_tagged_cbor_data(need!(unhex(f[0]), "priv")));
            let pubk = tri!(MLDSAPublicKey::from_tagged_cbor_data(need!(unhex(f[2]), "pub")));
            if priv_key.level() != level || pubk.level() != level { return "LEVEL-DIFF".into(); }
            if cod(&priv_key) != format!("{}|{}", f[0], f[1]) || cod(&pubk) != format!("{}|{}", f[2], f[3]) { return "REENCODE-DIFF".into(); }
            let probe = b"probe".to_vec();
            if !tri!(pubk.verify(&priv_key.sign(&probe), &probe)) { return "KEYPAIR-INCONSISTENT".into(); }
            if let Some(m) = r.get("message") {
                let msg = need!(bytes(m), "message");
                let sig = tri!(MLDSASignature::from_tagged_cbor_data(need!(field(want, "sig").and_then(unhex), "sig")));
                if field(want, "msg") != Some(h(&msg).as_str()) { return "MESSAGE-DIFF".into(); }
                if !tri!(pubk.verify(&sig, &msg)) { return "TS-SIGNATURE-INVALID".into(); }
            }
            want.to_string()
        }
        "mlkem" => {
            // As `mldsa`: the reference decapsulates the row's ciphertext with
            // the row's private key and checks the shared secret, and
            // encapsulates to the row's public key on its own.
            let level = need!(u(r, "level").and_then(mlkem_level), "level");
            let f: Vec<&str> = want.split('|').collect();
            if f.len() < 6 || want.starts_with("throw:") { return format!("unverifiable:the TypeScript row carries no keys ({want})"); }
            let priv_key = tri!(MLKEMPrivateKey::from_tagged_cbor_data(need!(unhex(f[0]), "priv")));
            let pubk = tri!(MLKEMPublicKey::from_tagged_cbor_data(need!(unhex(f[2]), "pub")));
            if priv_key.level() != level || pubk.level() != level { return "LEVEL-DIFF".into(); }
            if cod(&priv_key) != format!("{}|{}", f[0], f[1]) || cod(&pubk) != format!("{}|{}", f[2], f[3]) { return "REENCODE-DIFF".into(); }
            let ct = tri!(MLKEMCiphertext::from_tagged_cbor_data(need!(field(want, "ct").and_then(unhex), "ct")));
            let ss = tri!(priv_key.decapsulate_shared_secret(&ct));
            if Some(h(ss.data()).as_str()) != field(want, "ss") { return "SHARED-SECRET-DIFF".into(); }
            let (own_ss, own_ct) = pubk.encapsulate_new_shared_secret();
            if tri!(priv_key.decapsulate_shared_secret(&own_ct)) != own_ss { return "KEYPAIR-INCONSISTENT".into(); }
            want.to_string()
        }
        "sskr" => {
            let spec = need!(r.get("spec"), "spec");
            let gt = need!(u(spec, "gt"), "gt") as usize;
            let groups_j = need!(spec.get("groups").and_then(|g| g.as_array()), "groups");
            let mut groups = Vec::new();
            for g in groups_j { groups.push(tri!(SSKRGroupSpec::new(need!(u(g, "mt"), "mt") as usize, need!(u(g, "mc"), "mc") as usize))); }
            let spec_v = tri!(SSKRSpec::new(gt, groups));
            let secret_bytes = need!(r.get("secret").and_then(bytes), "secret");
            let secret = tri!(SSKRSecret::new(&secret_bytes));
            let mut g = need!(r.get("rng").and_then(rng_of), "rng");
            let shares = tri!(sskr_generate_using(&spec_v, &secret, &mut g));
            let mut quorum = vec![];
            for gi in 0..gt { let mt = need!(u(&groups_j[gi], "mt"), "mt") as usize; for mi in 0..mt { quorum.push(shares[gi][mi].clone()); } }
            let back = tri!(sskr_combine(&quorum));
            let out: Vec<String> = shares.iter().map(|g| g.iter().map(tagged).collect::<Vec<_>>().join(",")).collect();
            format!("{}|{}", out.join(";"), if back.data() == secret_bytes.as_slice() { "combined" } else { "MISMATCH" })
        }
        "agentLock" => {
            // SSH-agent key derivation over the in-memory agent. The
            // reference locks on its own (a fresh nonce) and unlocks that,
            // then unlocks the port's artefact and checks its parameters
            // are the reference's after the id update; an `unlock` spec runs
            // the reference's unlock over the port's message with the same
            // secret, stored id and tampering.
            #[cfg(not(feature = "agent"))]
            { let _ = want; J3.into() }
            #[cfg(feature = "agent")]
            {
                let ids = need!(r.get("identities").and_then(|x| x.as_array()), "identities");
                let mut keys = Vec::new();
                for id in ids {
                    let alg = need!(ssh_alg(&s(id, "alg").unwrap_or_else(|| "ed25519".into())), "alg");
                    let p = tri!(PrivateKeyBase::from_data(need!(id.get("seed").and_then(bytes), "seed")).ssh_signing_private_key(alg, need!(s(id, "comment"), "comment")));
                    keys.push(p.to_ssh().unwrap().clone());
                }
                let refuse = r.get("refuse").and_then(|x| x.as_bool()).unwrap_or(false);
                let agent: Rc<RefCell<dyn SSHAgent>> = Rc::new(RefCell::new(MemoryAgent { keys, refuse }));
                let salt = Salt::from_data(need!(r.get("salt").and_then(bytes), "salt"));
                let secret = need!(r.get("secret").and_then(bytes), "secret");
                let key = tri!(SymmetricKey::from_data_ref(need!(r.get("key").and_then(bytes), "key")));
                let mut own_params = SSHAgentParams::new_opt(salt.clone(), "", Some(agent.clone()));
                let own = tri!(KeyDerivation::lock(&mut own_params, &key, &secret));
                if tri!(KeyDerivation::unlock(&own_params, &own, &secret)) != key { return "OWN-UNLOCK-DIFF".into(); }
                let Some(ek_hex) = field(want, "ek") else { return format!("unverifiable:the TypeScript row carries no encrypted key ({want})"); };
                let ek = tri!(EncryptedKey::from_tagged_cbor_data(need!(unhex(ek_hex), "ek")));
                let KeyDerivationParams::SSHAgent(ts_params) = tri!(KeyDerivationParams::try_from(tri!(ek.aad_cbor()))) else { return "NOT-SSH-AGENT-PARAMS".into(); };
                if ts_params != own_params { return format!("PARAMS-DIFF:{ts_params}"); }
                let with_agent = |id: &str| SSHAgentParams::new_opt(salt.clone(), id, Some(agent.clone()));
                if tri!(KeyDerivation::unlock(&with_agent(ts_params.id()), ek.encrypted_message(), &secret)) != key { return "UNLOCK-DIFF".into(); }
                let mut out = format!("lock={own_params}|ek={ek_hex}|key={}|secret={}", h(key.data()), h(&secret));
                if let Some(u) = r.get("unlock") {
                    let usecret = need!(u.get("secret").and_then(bytes), "secret");
                    let stored = s(u, "storedId").unwrap_or_else(|| ts_params.id().clone());
                    let msg = tampered(ek.encrypted_message(), &s(u, "tamper").unwrap_or_default());
                    let res = match KeyDerivation::unlock(&with_agent(&stored), &msg, &usecret) { Ok(k) => format!("ok:{}", h(k.data())), Err(e) => e.render() };
                    out.push_str(&format!("|unlock={res}"));
                }
                out
            }
        }
        "decode" | "decodeUntagged" => decode(&need!(s(r, "type"), "type"), &need!(s(r, "hex").and_then(|x| unhex(&x)), "hex")),
        "urParse" => ur_parse(&need!(s(r, "type"), "type"), &need!(s(r, "s"), "s")),
        "verifyStrict" => {
            let pubk = SigningPublicKey::Ed25519(tri!(Ed25519PublicKey::from_data_ref(need!(r.get("pub").and_then(bytes), "pub"))));
            let sig = tri!(Signature::ed25519_from_data_ref(need!(r.get("sig").and_then(bytes), "sig")));
            let msg = need!(r.get("message").and_then(bytes), "message");
            if pubk.verify(&sig, &msg) { "valid".into() } else { "invalid".into() }
        }
        "signingDefault" => {
            // `SignatureScheme::default()` is what `keypair_using` picks; the
            // reference has no `SigningPrivateKey::random`.
            let mut g = need!(r.get("rng").and_then(rng_of), "rng");
            let (p, _) = tri!(keypair_using(&mut g));
            let name = match p.signing_private_key() { SigningPrivateKey::Schnorr(_) => "Schnorr", SigningPrivateKey::ECDSA(_) => "Ecdsa", SigningPrivateKey::Ed25519(_) => "Ed25519", _ => "other" };
            format!("{:?}|{}", SignatureScheme::default(), name)
        }
        "kdfDomain" => {
            // A number that is not an integer in the field's width cannot reach the reference (J1).
            let salt = Salt::from_data(vec![0u8; 16]);
            let int = |key: &str, max: u64| -> Option<Option<u64>> { match r.get(key) { None => Some(None), Some(v) => match v.as_u64() { Some(n) if n <= max => Some(Some(n)), _ => None } } };
            match need!(s(r, "method"), "method").as_str() {
                "pbkdf2" => match int("iterations", u32::MAX as u64) {
                    Some(n) => format!("ok:{}", PBKDF2Params::new_opt(salt, n.unwrap_or(DEFAULT_PBKDF2_ITERATIONS) as u32, HashType::SHA256).iterations()),
                    None => J1.into(),
                },
                "scrypt" => match (int("logN", u8::MAX as u64), int("r", u32::MAX as u64), int("p", u32::MAX as u64)) {
                    (Some(ln), Some(rr), Some(pp)) => {
                        let p = ScryptParams::new_opt(salt, ln.unwrap_or(DEFAULT_SCRYPT_LOG_N) as u8, rr.unwrap_or(DEFAULT_SCRYPT_R) as u32, pp.unwrap_or(DEFAULT_SCRYPT_P) as u32);
                        format!("ok:{},{},{}", p.log_n(), p.r(), p.p())
                    }
                    _ => J1.into(),
                },
                m => format!("unhandled:kdfDomain method {m}"),
            }
        }
        "summary" => {
            // The reference's registry, applied the way dcbor's diagnostic
            // printer applies it: to the untagged content, non-flat.
            let data = need!(s(r, "hex").and_then(|x| unhex(&x)), "hex");
            let cbor = tri!(CBOR::try_from_data(&data));
            let (tag, content) = match cbor.try_into_tagged_value() { Ok(x) => x, Err(_) => return "untagged".into() };
            // Clone the summarizer out of the store first: the global store is a
            // lock, and a summarizer that prints a tag name takes it again.
            let f = dcbor::with_tags!(|t: &TagsStore| t.summarizer(tag.value()).cloned());
            match f.map(|f| f(content, false)) { None => "none".into(), Some(Ok(v)) => format!("ok:{v}"), Some(Err(e)) => format!("error:{e}") }
        }
        // Named JavaScript-only inputs: nothing to run here.
        "domain" => J1.into(),
        "uri" => tri!(URI::new(need!(s(r, "text"), "text"))).to_string(),
        "uuidParse" => tri!(need!(s(r, "text"), "text").parse::<UUID>()).to_string(),
        "hex" => from_hex(&need!(s(r, "type"), "type"), &need!(s(r, "text"), "text")),
        "api" => api(&need!(s(r, "case"), "case")),
        "cborTags" => cbor_tags(&need!(s(r, "type"), "type")),
        "noreg" => run(need!(r.get("inner"), "inner"), want),
        k => format!("unhandled:kind {k}"),
    }
}

// ---------------------------------------------------------------------------
// Panics the port reports as typed errors
// ---------------------------------------------------------------------------

/// (recipe kind, a substring of the panic message or the class `none`/`hang`,
/// the TypeScript code thrown at the same call). Compared by code only; a
/// panic outside this table is a MISMATCH.
const PANIC_MAPPED: &[(&str, &str, &str)] = &[
    // SSKRShare accessors index into fewer than 5 bytes
    ("value", "index out of bounds", "InvalidData"),
    ("api", "index out of bounds", "InvalidData"),
    // bc-crypto unwraps a secp256k1 scalar or point conversion
    ("value", "InvalidSecretKey", "InvalidData"),
    ("value", "InvalidPublicKey", "InvalidData"),
    ("api", "InvalidSecretKey", "InvalidData"),
    ("api", "InvalidPublicKey", "InvalidData"),
    // bc-crypto 0.14.0 unwraps the key and signature parses inside `verify`
    ("verify", "InvalidPublicKey", "InvalidData"),
    ("verify", "InvalidSignature", "InvalidData"),
    ("verify", "signature::Error", "InvalidData"),
    ("verify", "InvalidPoint", "InvalidData"),
    // `UUID::from_data_ref` returns `None`
    ("value", "none", "InvalidSize"),
    // `ur_string()` and `from_ur` need the tag's name: before `register_tags()`
    // bc-ur panics, and this program's `from_ur` step unwraps the same `None`
    ("value", "must have a name", "TagUnnamed"),
    ("digest", "must have a name", "TagUnnamed"),
    ("decode", "must have a name", "TagUnnamed"),
    ("urParse", "must have a name", "TagUnnamed"),
    ("urParse", "Option::unwrap()", "TagUnnamed"),
    // `SigningPrivateKey::from_untagged_cbor` removes element 0 of an empty array
    ("decode", "removal index", "Cbor"),
    ("summary", "removal index", "error"),
    // the JSON summariser calls `as_str` on non-UTF-8 content
    ("summary", "Invalid UTF-8 in JSON data", "error"),
    // `JSON::as_str` expects UTF-8
    ("api", "Invalid UTF-8 in JSON data", "Utf8"),
    // `Compressed::digest()` unwraps the optional digest
    ("api", "Option::unwrap()", "Compression"),
    // `HKDFRng` with page length 0 extends its buffer by nothing, forever
    ("hkdfRng", "hang", "InvalidData"),
    ("api", "hang", "InvalidData"),
    // `from_hex` unwraps the hex decode and the size check
    ("hex", "OddLength", "Hex"),
    ("hex", "InvalidHexCharacter", "Hex"),
    ("hex", "InvalidStringLength", "Hex"),
    ("hex", "InvalidSize", "InvalidSize"),
    // `UUID::from_str` unwraps the hex decode and copies into 16 bytes
    ("uuidParse", "OddLength", "Hex"),
    ("uuidParse", "InvalidHexCharacter", "Hex"),
    ("uuidParse", "destination slice length", "InvalidSize"),
];
fn panic_mapped(kind: &str, text: &str) -> Option<&'static str> {
    PANIC_MAPPED.iter().find(|(k, needle, _)| *k == kind && text.contains(needle)).map(|(_, _, code)| *code)
}
/// The code of a TypeScript throw; a summariser failure (`error:<message>`) is the class `error`.
fn ts_code(want: &str) -> Option<&str> {
    if want.starts_with("error:") { return Some("error"); }
    want.strip_prefix("throw:").map(|r| r.split(':').next().unwrap_or(r))
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

enum Got { Value(String), Panic(String), Hang }
fn payload(p: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<&str>() { return s.to_string(); }
    if let Some(s) = p.downcast_ref::<String>() { return s.clone(); }
    "non-string panic payload".into()
}
/// Runs one vector on its own thread so a reference loop cannot stall the run.
fn run_guarded(v: &Vector, timeout: Duration) -> Got {
    let (tx, rx) = mpsc::channel();
    let (recipe, want) = (v.recipe.clone(), v.expect.clone());
    std::thread::spawn(move || {
        let got = match catch_unwind(AssertUnwindSafe(|| run(&recipe, &want))) { Ok(s) => Got::Value(s), Err(p) => Got::Panic(payload(p)) };
        let _ = tx.send(got);
    });
    rx.recv_timeout(timeout).unwrap_or(Got::Hang)
}
fn kind_of(r: &J) -> String {
    let k = r.get("k").and_then(|x| x.as_str()).unwrap_or("");
    if k == "noreg" { return r.get("inner").map(kind_of).unwrap_or_default(); }
    k.to_string()
}
/// A `HKDFRng` with page length 0 never returns from a non-empty draw.
fn may_hang(r: &J) -> bool {
    let k = kind_of(r);
    (k == "hkdfRng" && r.get("pageLen").and_then(|x| x.as_u64()) == Some(0))
        || (k == "api" && r.get("case").and_then(|x| x.as_str()).map(|c| c.starts_with("hkdf/page0")).unwrap_or(false))
}

fn main() {
    assert_eq!(usize::BITS, 64, "the reference's usize fields are compared as 64-bit integers");
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: components-validation <vectors.json> [--verbose]");
    let verbose = args.iter().any(|a| a == "--verbose") || std::env::var("VERBOSE").is_ok();
    let file: File = serde_json::from_str(&std::fs::read_to_string(path).expect("read vectors")).expect("parse vectors");
    assert_eq!(file.count, file.vectors.len(), "the file's count must equal its vectors");
    std::panic::set_hook(Box::new(|_| {}));

    let (mut ok, mut mapped, mut js_only, mut mismatch, mut unparsable) = (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut mapped_by: std::collections::BTreeMap<&'static str, usize> = Default::default();
    let mut js_by: std::collections::BTreeMap<String, usize> = Default::default();
    let mut registered = false;
    let cut = |x: &str| if verbose { x.to_string() } else { x.chars().take(160).collect::<String>() };
    let report = |name: &str, detail: String| eprintln!("MISMATCH {name}\n  {detail}");

    for v in &file.vectors {
        let is_noreg = v.recipe.get("k").and_then(|x| x.as_str()) == Some("noreg");
        if is_noreg && registered {
            mismatch += 1;
            report(&v.name, "a noreg row after the first registered row; the file must list noreg rows first".into());
            continue;
        }
        if !is_noreg && !registered { bc_components::register_tags(); registered = true; }
        let kind = kind_of(&v.recipe);
        let want = v.expect.as_str();
        let timeout = if may_hang(&v.recipe) { Duration::from_secs(2) } else { Duration::from_secs(120) };
        match run_guarded(v, timeout) {
            Got::Value(got) => {
                if got == want { ok += 1; continue; }
                if let Some(class) = got.strip_prefix("js-only:") { js_only += 1; *js_by.entry(class.to_string()).or_default() += 1; continue; }
                if let Some(what) = got.strip_prefix("unparsable:") { unparsable += 1; eprintln!("UNPARSABLE {} ({what})", v.name); continue; }
                // J3: without the `ssh-agent` feature the reference rejects the
                // method index the port decodes, wherever the port got with it;
                // the agent build compares these rows in full.
                if cfg!(not(feature = "agent")) && got.ends_with(":Invalid KeyDerivationMethod") {
                    js_only += 1; *js_by.entry("J3".into()).or_default() += 1; continue;
                }
                if let Some(rest) = got.strip_prefix("none:") {
                    match panic_mapped(&kind, "none") {
                        Some(code) if ts_code(want) == Some(code) => { mapped += 1; *mapped_by.entry("none").or_default() += 1; }
                        _ => { mismatch += 1; report(&v.name, format!("reference: None from {rest}\n  ts:        {}", cut(want))) },
                    }
                    continue;
                }
                let (g, w): (Vec<&str>, Vec<&str>) = (got.split('|').collect(), want.split('|').collect());
                let field = (0..g.len().max(w.len())).find(|&i| g.get(i) != w.get(i)).unwrap_or(0);
                mismatch += 1;
                report(&v.name, format!("[field {field}/{}]\n  rust: {}\n  ts:   {}", w.len(), cut(g.get(field).unwrap_or(&"")), cut(w.get(field).unwrap_or(&""))));
            }
            Got::Panic(text) => match panic_mapped(&kind, &text) {
                Some(code) if ts_code(want) == Some(code) => { mapped += 1; *mapped_by.entry("panic").or_default() += 1; }
                Some(code) => { mismatch += 1; report(&v.name, format!("reference panicked ({}) mapped to {code}\n  ts: {}", cut(&text), cut(want))) },
                None => { mismatch += 1; report(&v.name, format!("unhandled reference panic: {}\n  ts: {}", cut(&text), cut(want))) },
            },
            Got::Hang => match panic_mapped(&kind, "hang") {
                Some(code) if ts_code(want) == Some(code) => { mapped += 1; *mapped_by.entry("hang").or_default() += 1; }
                _ => { mismatch += 1; report(&v.name, format!("reference did not return within {timeout:?}\n  ts: {}", cut(want))) },
            },
        }
    }
    let mapped_detail: Vec<String> = mapped_by.iter().map(|(k, n)| format!("{k} {n}")).collect();
    let js_detail: Vec<String> = js_by.iter().map(|(k, n)| format!("{k} {n}")).collect();
    let build = if cfg!(feature = "agent") { " [agent]" } else { "" };
    let mut line = format!(
        "{} vectors - {ok} match, {mapped} panic-mapped ({}), {js_only} js-only ({}), {mismatch} MISMATCH",
        file.vectors.len(), mapped_detail.join(", "), js_detail.join(", ")
    );
    if unparsable > 0 { line.push_str(&format!(", {unparsable} unparsable")); }
    println!("{line}{build}");
    std::process::exit(if mismatch == 0 && unparsable == 0 { 0 } else { 1 });
}
