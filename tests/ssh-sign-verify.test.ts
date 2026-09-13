import { describe, it, expect } from "vitest";
import { SSHPrivateKey } from "../src/ssh/ssh-private-key.js";
import { SSHPublicKey } from "../src/ssh/ssh-public-key.js";
import { SSHSignature } from "../src/ssh/ssh-signature.js";

/**
 * End-to-end SSHSIG sign+verify round-trip — mirrors the assertions in
 * `bc-envelope-rust/tests/ssh_tests.rs::test_ssh_signed_plaintext`:
 *   1. Alice signs a message with her SSH key.
 *   2. The signature verifies against her public key.
 *   3. The signature does NOT verify against an unrelated public key.
 *
 * For Ed25519 we use the deterministic Rust fixture (same seed →
 * same signing key on both sides), so the signature bytes themselves
 * are deterministic too.
 */

const RUST_ED25519_PRIVATE = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBUe4FDGyGIgHf75yVdE4hYl9guj02FdsIadgLC04zObQAAAJA+TyZiPk8m
YgAAAAtzc2gtZWQyNTUxOQAAACBUe4FDGyGIgHf75yVdE4hYl9guj02FdsIadgLC04zObQ
AAAECsX3CKi3hm5VrrU26ffa2FB2YrFogg45ucOVbIz4FQo1R7gUMbIYiAd/vnJV0TiFiX
2C6PTYV2whp2AsLTjM5tAAAADEtleSBjb21tZW50LgE=
-----END OPENSSH PRIVATE KEY-----
`;

const RUST_ECDSA_P256_PRIVATE = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTtBE6+WTueAierXl/c/f83JAmoxm0k
YlGMVMofLOUFeKx3FqUW0VRVljx1wHL03faFhiTPVR9CNG5iZCUqa4eLAAAAqPC+XgXwvl
4FAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO0ETr5ZO54CJ6te
X9z9/zckCajGbSRiUYxUyh8s5QV4rHcWpRbRVFWWPHXAcvTd9oWGJM9VH0I0bmJkJSprh4
sAAAAgAVk1Bq0ILFsF/ADaUq8G5Tow0Xv+Qs8V21gfOBSWQDEAAAAMS2V5IGNvbW1lbnQu
AQIDBA==
-----END OPENSSH PRIVATE KEY-----
`;

const MESSAGE = new TextEncoder().encode(
  "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
);
const NAMESPACE = "test";

describe("SSHSIG sign + verify — Rust round-trip parity", () => {
  it("ed25519: sign + verify round-trip succeeds", () => {
    const priv = SSHPrivateKey.fromOpenssh(RUST_ED25519_PRIVATE);
    const pub = priv.publicKey();
    const sig = priv.sign(NAMESPACE, "sha256", MESSAGE);
    expect(sig.namespace).toBe(NAMESPACE);
    expect(sig.hashAlgorithm).toBe("sha256");
    expect(sig.signatureBytes.length).toBe(64);
    expect(pub.verifySshSignature(NAMESPACE, MESSAGE, sig)).toBe(true);
  });

  it("ed25519: signature is deterministic for the same key/message", () => {
    const priv = SSHPrivateKey.fromOpenssh(RUST_ED25519_PRIVATE);
    const a = priv.sign(NAMESPACE, "sha256", MESSAGE);
    const b = priv.sign(NAMESPACE, "sha256", MESSAGE);
    expect(a.signatureBytes).toEqual(b.signatureBytes);
    expect(a.toPem()).toBe(b.toPem());
  });

  it("ed25519: verify rejects with wrong namespace", () => {
    const priv = SSHPrivateKey.fromOpenssh(RUST_ED25519_PRIVATE);
    const pub = priv.publicKey();
    const sig = priv.sign(NAMESPACE, "sha256", MESSAGE);
    expect(pub.verifySshSignature("other", MESSAGE, sig)).toBe(false);
  });

  it("ed25519: verify rejects with wrong message", () => {
    const priv = SSHPrivateKey.fromOpenssh(RUST_ED25519_PRIVATE);
    const pub = priv.publicKey();
    const sig = priv.sign(NAMESPACE, "sha256", MESSAGE);
    const tampered = new Uint8Array(MESSAGE);
    tampered[0] ^= 0x01;
    expect(pub.verifySshSignature(NAMESPACE, tampered, sig)).toBe(false);
  });

  it("ed25519: verify rejects when key doesn't match the signed-by key", () => {
    const priv = SSHPrivateKey.fromOpenssh(RUST_ED25519_PRIVATE);
    const sig = priv.sign(NAMESPACE, "sha256", MESSAGE);

    // A second, unrelated Ed25519 keypair. We just tweak one byte of the
    // public bytes to manufacture a non-matching key. `verifySshSignature`
    // compares OpenSSH text, so this returns false on the public-key
    // mismatch check before ever touching the curve verifier.
    const pubOther = priv.publicKey();
    const otherKeyBytes = new Uint8Array(pubOther.keyBytes);
    otherKeyBytes[0] ^= 0xff;
    const aliasedPub = SSHPublicKey.ed25519(otherKeyBytes);
    expect(aliasedPub.verifySshSignature(NAMESPACE, MESSAGE, sig)).toBe(false);
  });

  it("ed25519: SSHSignature parsed back from PEM also verifies", () => {
    const priv = SSHPrivateKey.fromOpenssh(RUST_ED25519_PRIVATE);
    const pub = priv.publicKey();
    const sig = priv.sign(NAMESPACE, "sha256", MESSAGE);
    const round = SSHSignature.fromPem(sig.toPem());
    expect(pub.verifySshSignature(NAMESPACE, MESSAGE, round)).toBe(true);
  });

  it("ecdsa-p256: sign + verify round-trip succeeds", () => {
    const priv = SSHPrivateKey.fromOpenssh(RUST_ECDSA_P256_PRIVATE);
    const pub = priv.publicKey();
    const sig = priv.sign(NAMESPACE, "sha256", MESSAGE);
    expect(sig.signatureBytes.length).toBe(64);
    expect(pub.verifySshSignature(NAMESPACE, MESSAGE, sig)).toBe(true);
    // Re-parse PEM and verify still works
    const round = SSHSignature.fromPem(sig.toPem());
    expect(pub.verifySshSignature(NAMESPACE, MESSAGE, round)).toBe(true);
  });

  it("ecdsa-p256: tampered signature fails verification", () => {
    const priv = SSHPrivateKey.fromOpenssh(RUST_ECDSA_P256_PRIVATE);
    const pub = priv.publicKey();
    const sig = priv.sign(NAMESPACE, "sha256", MESSAGE);
    const tampered = new Uint8Array(sig.signatureBytes);
    tampered[0] ^= 0x01;
    const tamperedSig = SSHSignature.fromParts(pub, NAMESPACE, "sha256", tampered);
    expect(pub.verifySshSignature(NAMESPACE, MESSAGE, tamperedSig)).toBe(false);
  });
});

/**
 * A signature the reference produced (`bc-components-rust` 0.31.1 over
 * `ssh-key` 0.6.7 / RustCrypto `ecdsa` 0.16.9) for the key above, the
 * message above and namespace "test": RFC 6979, and — as OpenSSH — with no
 * low-s normalisation, so its `s` is above n/2. Tagged CBOR of the
 * `Signature` (tag 40020 over tag 40802).
 */
const RUST_ECDSA_P256_SIGNATURE_HEX =
  "d99c54d99f627901872d2d2d2d2d424547494e20535348205349474e41545552452d2d2d2d2d0a55314e4955306c48414141414151414141476741414141545a574e6b63324574633268684d69317561584e30634449314e6741414141687561584e30634449314e67414141450a45453751524f766c6b376e67496e713135663350332f4e79514a714d5a744a474a526a46544b48797a6c425869736478616c46744655565a593864634279394e33326859596b0a7a315566516a5275596d516c4b6d754869774141414152305a584e30414141414141414141415a7a614745794e5459414141426c414141414532566a5a484e684c584e6f59540a4974626d6c7a644841794e5459414141424b41414141495144394a67305678714d724f49507835484845756c6d366b4f466b6139523341374b4e37306661707262386f7741410a414345416a656e42395445664b54445a3477786d7a5052364f5673692f363471503877465a677545646865443538633d0a2d2d2d2d2d454e4420535348205349474e41545552452d2d2d2d2d0a";

describe("SSHSIG ECDSA parity with the reference (D4 closed)", () => {
  const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const sOf = (sig: Uint8Array): bigint =>
    BigInt("0x" + Array.from(sig.slice(32, 64), (b) => b.toString(16).padStart(2, "0")).join(""));
  const sshOf = (sig: { asSsh(): SSHSignature | undefined }): SSHSignature => {
    const ssh = sig.asSsh();
    if (ssh === undefined) throw new Error("not an SSH signature");
    return ssh;
  };

  it("verifies the reference's high-s signature", async () => {
    const { decodeCbor, hexToBytes } = await import("@blockchaincommons/dcbor");
    const { Signature } = await import("../src/signing/signature.js");
    const rustSig = sshOf(
      Signature.fromCbor(decodeCbor(hexToBytes(RUST_ECDSA_P256_SIGNATURE_HEX))),
    );
    expect(sOf(rustSig.signatureBytes) > P256_N / 2n).toBe(true);
    const pub = SSHPrivateKey.fromOpenssh(RUST_ECDSA_P256_PRIVATE).publicKey();
    expect(pub.verifySshSignature(NAMESPACE, MESSAGE, rustSig)).toBe(true);
  });

  it("produces the reference's bytes (same RFC 6979 nonce, no low-s normalisation)", async () => {
    const { decodeCbor, hexToBytes } = await import("@blockchaincommons/dcbor");
    const { Signature } = await import("../src/signing/signature.js");
    const rustSig = sshOf(
      Signature.fromCbor(decodeCbor(hexToBytes(RUST_ECDSA_P256_SIGNATURE_HEX))),
    );
    const priv = SSHPrivateKey.fromOpenssh(RUST_ECDSA_P256_PRIVATE);
    const sig = priv.sign(NAMESPACE, "sha256", MESSAGE);
    expect(sig.signatureBytes).toEqual(rustSig.signatureBytes);
    // Both forms of the same signature verify: SSH has no low-s rule.
    const pub = priv.publicKey();
    const lowS = new Uint8Array(sig.signatureBytes);
    const s = sOf(lowS);
    const flipped = (P256_N - s).toString(16).padStart(64, "0");
    for (let i = 0; i < 32; i++) lowS[32 + i] = parseInt(flipped.slice(i * 2, i * 2 + 2), 16);
    expect(
      pub.verifySshSignature(
        NAMESPACE,
        MESSAGE,
        SSHSignature.fromParts(pub, NAMESPACE, "sha256", lowS),
      ),
    ).toBe(true);
  });
});
