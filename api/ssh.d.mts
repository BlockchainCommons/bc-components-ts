/**
 * The algorithm for a wire-format name.
 *
 * As `ssh-key` 0.6.7 `Algorithm::from_str`, the RFC 8332 names
 * `rsa-sha2-256` / `rsa-sha2-512` also denote an RSA key. A name the
 * package does not support is an `Ssh` failure: `ssh-key` accepts any
 * `name@domain` identifier as an opaque algorithm, which this package does
 * not implement (`unsupported algorithm: <name>`); every other unknown name
 * fails its label parser (`invalid label: '<name>'`).
 */
export declare function parseSshAlgorithm(name: string): SshAlgorithm;

/** Wire-format name of DSA keys. */
export declare const SSH_ALGO_DSA = "ssh-dss";

/** Wire-format name of ECDSA P-256 keys. */
export declare const SSH_ALGO_ECDSA_NISTP256 = "ecdsa-sha2-nistp256";

/** Wire-format name of ECDSA P-384 keys. */
export declare const SSH_ALGO_ECDSA_NISTP384 = "ecdsa-sha2-nistp384";

/** Wire-format name of ECDSA P-521 keys. */
export declare const SSH_ALGO_ECDSA_NISTP521 = "ecdsa-sha2-nistp521";

/** Wire-format algorithm name as it appears in OpenSSH text and in the key blob. */
export declare const SSH_ALGO_ED25519 = "ssh-ed25519";

/** Wire-format name of RSA keys. */
export declare const SSH_ALGO_RSA = "ssh-rsa";

/** RFC 8332 name of an RSA signature made with SHA-256 (`sshsig` signature blobs). */
export declare const SSH_ALGO_RSA_SHA2_256 = "rsa-sha2-256";

/** RFC 8332 name of an RSA signature made with SHA-512 (`sshsig` signature blobs). */
export declare const SSH_ALGO_RSA_SHA2_512 = "rsa-sha2-512";

/** OpenSSH curve identifier embedded inside ECDSA key blobs. */
export declare const SSH_CURVE_NISTP256 = "nistp256";

/** OpenSSH curve identifier for P-384. */
export declare const SSH_CURVE_NISTP384 = "nistp384";

/** OpenSSH curve identifier for P-521. */
export declare const SSH_CURVE_NISTP521 = "nistp521";

/**
 * SSH key algorithm identifiers.
 *
 * The six key algorithms `ssh-key` 0.6.7 generates and parses, and that the
 * reference derives from a `PrivateKeyBase`:
 *
 *   - Ed25519 (`ssh-ed25519`)
 *   - DSA (`ssh-dss`) — 1024-bit p, 160-bit q, SHA-1
 *   - RSA (`ssh-rsa`) — 2048-bit keys; `sshsig` signatures name their hash
 *     as `rsa-sha2-256` / `rsa-sha2-512` (RFC 8332)
 *   - ECDSA P-256 (`ecdsa-sha2-nistp256`) — SHA-256
 *   - ECDSA P-384 (`ecdsa-sha2-nistp384`) — SHA-384
 *   - ECDSA P-521 (`ecdsa-sha2-nistp521`) — SHA-512
 *
 * Not supported: FIDO/U2F `sk-*` keys, opaque `name@domain` algorithms,
 * encrypted private keys and `*-cert-v01@openssh.com` certificates.
 */
export declare type SshAlgorithm = {
    /** `ssh-ed25519`. */
    kind: "ed25519";
} | {
    /** `ssh-dss`. */
    kind: "dsa";
} | {
    /** `ssh-rsa`. */
    kind: "rsa";
} | {
    /** `ecdsa-sha2-nistp256` / `ecdsa-sha2-nistp384` / `ecdsa-sha2-nistp521`. */
    kind: "ecdsa";
    /** The NIST curve of an ECDSA key. */
    curve: SshEcdsaCurve;
};

/** The wire-format name of `algo` (`ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`, …). */
export declare function sshAlgorithmName(algo: SshAlgorithm): string;

/** An OpenSSH certificate (`*-cert-v01@openssh.com`), carried as its single-line text; fields are not parsed, as in the reference. */
export declare class SSHCertificate {
    /** The full single-line OpenSSH cert text, e.g.
     *  `ssh-ed25519-cert-v01@openssh.com AAAAI...== user@host`. */
    readonly text: string;
    private constructor();
    /** Construct from the canonical OpenSSH certificate text. */
    static fromText(text: string): SSHCertificate;
    /** The canonical OpenSSH text — round-trips byte-identically. */
    toText(): string;
    /** Fixed summarizer string. */
    toString(): string;
    /** SHA-256 of the certificate text. */
    digest(): Uint8Array;
}

/** The NIST curves an SSH ECDSA key can use. */
export declare type SshEcdsaCurve = "nistp256" | "nistp384" | "nistp521";

/** The hash an `sshsig` signature is made over. */
export declare type SshHashAlgorithm = "sha256" | "sha512";

/** An OpenSSH private key (`-----BEGIN OPENSSH PRIVATE KEY-----`), unencrypted, for the algorithms in `SshAlgorithm`. */
export declare class SSHPrivateKey {
    /** The parsed key material by algorithm. */
    readonly data: SshPrivateKeyData;
    /** The comment stored in the private-key section (may be empty). */
    readonly comment: string;
    /**
     * 32-bit checkint preserved on round-trip — `ssh-key` retains the parsed
     * value, so to round-trip byte-identically we do too.
     */
    readonly checkint: number;
    private constructor();
    /**
     * Construct an `SSHPrivateKey` from already-decoded parts. Used by
     * `PrivateKeyBase.sshSigningPrivateKey` after generating key material
     * from an HKDF-seeded RNG. The `checkint` should be derived
     * deterministically from the private bytes (mirrors `ssh-key` 0.6.7's
     * `KeypairData::checkint`).
     */
    static fromParts(data: SshPrivateKeyData, comment: string, checkint: number): SSHPrivateKey;
    /** Algorithm tag for this key. */
    get algorithm(): SshAlgorithm;
    get publicBytes(): Uint8Array;
    get privateBytes(): Uint8Array;
    /** Parses the PEM-armoured OpenSSH private key text, as `ssh_key::PrivateKey::from_openssh`. */
    static fromOpenssh(text: string): SSHPrivateKey;
    /** Parses the binary `openssh-key-v1` blob (the base64 payload of the text form). */
    static fromBlob(blob: Uint8Array): SSHPrivateKey;
    /**
     * Re-serialize to the canonical OpenSSH armored format.
     *
     */
    toOpenssh(): string;
    /** The binary `openssh-key-v1` blob, byte for byte as OpenSSH writes it. */
    toBlob(): Uint8Array;
    /** The matching public key, with the same comment. */
    publicKey(): SSHPublicKey;
    private publicBlob;
    private encryptedSection;
    /** SHA-256 of the OpenSSH text form (the reference's `Reference` image). */
    digest(): Uint8Array;
    /** The first four bytes of `digest()` in hex, the reference's `ref_hex_short`. */
    refHexShort(): string;
    /** `SSHPrivateKey(<short reference>)`, the reference's `Display`. */
    toString(): string;
    /**
     * Signs `message` in `namespace` with `hashAlgorithm`, producing an
     * `sshsig` signature.
     *
     * RSA keys cannot sign: `ssh-key` 0.6.7 rebuilds the `rsa` private key
     * from `(p, p)` instead of `(p, q)`, so the reference's
     * `SigningPrivateKey::sign` fails with `cryptographic error` for every
     * RSA key, and so does this method.
     */
    sign(namespace: string, hashAlgorithm: SshHashAlgorithm, message: Uint8Array): SSHSignature;
}

/**
 * Algorithm-specific private-key data.
 *
 *   - ed25519: 32-byte seed.
 *   - ecdsa:   curve + canonical scalar (32 / 48 / 66 bytes, no sign byte).
 *   - dsa:     canonical positive p, q, g, y (re-stated from the public
 *              key blob), plus the secret exponent x.
 *   - rsa:     canonical positive n, e (re-stated), d, iqmp, p, q.
 */
export declare type SshPrivateKeyData = {
    /** `ssh-ed25519`. */
    kind: "ed25519";
    /** The 32-byte seed. */
    seed: Uint8Array;
    /** The 32 raw public key bytes. */
    pubBytes: Uint8Array;
} | {
    /** `ecdsa-sha2-nistp256` / `ecdsa-sha2-nistp384` / `ecdsa-sha2-nistp521`. */
    kind: "ecdsa";
    /** The NIST curve. */
    curve: SshEcdsaCurve;
    /** The canonical scalar (32, 48 or 66 bytes, no sign byte). */
    scalar: Uint8Array;
    /** The SEC1 uncompressed public point. */
    point: Uint8Array;
} | {
    /** `ssh-dss`. */
    kind: "dsa";
    /** The prime modulus, canonical positive bytes. */
    p: Uint8Array;
    /** The subgroup order, canonical positive bytes. */
    q: Uint8Array;
    /** The generator, canonical positive bytes. */
    g: Uint8Array;
    /** The public value, canonical positive bytes. */
    y: Uint8Array;
    /** The secret exponent, canonical positive bytes. */
    x: Uint8Array;
} | {
    /** `ssh-rsa`. */
    kind: "rsa";
    /** The modulus, canonical positive bytes. */
    n: Uint8Array;
    /** The public exponent, canonical positive bytes. */
    e: Uint8Array;
    /** The private exponent, canonical positive bytes. */
    d: Uint8Array;
    /** The CRT coefficient `q^-1 mod p`, canonical positive bytes. */
    iqmp: Uint8Array;
    /** The first prime, canonical positive bytes. */
    p: Uint8Array;
    /** The second prime, canonical positive bytes. */
    q: Uint8Array;
};

export declare class SSHPublicKey {
    /** The parsed key material by algorithm. */
    readonly data: SshPublicKeyData;
    /** The comment field of the OpenSSH text form (may be empty). */
    readonly comment: string;
    private constructor();
    /** Algorithm tag for this key. */
    get algorithm(): SshAlgorithm;
    /** An Ed25519 key from its 32 raw bytes. */
    static ed25519(keyBytes: Uint8Array, comment?: string): SSHPublicKey;
    /** A P-256 key from its 65-byte SEC1 uncompressed point. */
    static ecdsaP256(uncompressedPoint: Uint8Array, comment?: string): SSHPublicKey;
    /** A P-384 key from its 97-byte SEC1 uncompressed point. */
    static ecdsaP384(uncompressedPoint: Uint8Array, comment?: string): SSHPublicKey;
    /** A P-521 key from its 133-byte SEC1 uncompressed point. */
    static ecdsaP521(uncompressedPoint: Uint8Array, comment?: string): SSHPublicKey;
    /** An ECDSA key on `curve` from its SEC1 uncompressed point. */
    static ecdsa(curve: SshEcdsaCurve, uncompressedPoint: Uint8Array, comment?: string): SSHPublicKey;
    /** DSA public key. p/q/g/y must already be canonical positive bytes (no sign byte). */
    static dsa(p: Uint8Array, q: Uint8Array, g: Uint8Array, y: Uint8Array, comment?: string): SSHPublicKey;
    /** RSA public key. `e` and `n` must already be canonical positive bytes (no sign byte). */
    static rsa(e: Uint8Array, n: Uint8Array, comment?: string): SSHPublicKey;
    /**
     * Returns a copy of this SSH public key with the comment replaced,
     * leaving this instance untouched.
     */
    withComment(comment: string): SSHPublicKey;
    /**
     * Parses the single-line OpenSSH text form (`<algorithm> <base64 blob> [comment]`)
     * as `ssh-key` 0.6.7 `PublicKey::from_openssh`: trailing whitespace is
     * removed, the algorithm and Base64 segments end at a single space, the
     * Base64 is strict, and the text's algorithm name must equal the blob's
     * (`unknown algorithm` otherwise).
     */
    static fromOpenssh(text: string): SSHPublicKey;
    /** The single-line OpenSSH text form. */
    toOpenssh(): string;
    /** Parses the binary key blob (the base64 payload of the text form). */
    static fromBlob(blob: Uint8Array, comment?: string): SSHPublicKey;
    /** The binary key blob, byte for byte as OpenSSH writes it. */
    toBlob(): Uint8Array;
    /** SHA-256 of the OpenSSH text form (the reference's `Reference` image). */
    digest(): Uint8Array;
    /** The first four bytes of `digest()` in hex, the reference's `ref_hex_short`. */
    refHexShort(): string;
    /** `SSHPublicKey(<short reference>)`, the reference's `Display`. */
    toString(): string;
    /** `true` when algorithm, key material and comment are all equal. */
    equals(other: SSHPublicKey): boolean;
    /**
     * Comment-insensitive equality: matches when algorithm and key data
     * agree, ignoring the comment. Used by verify paths since SSH
     * wire-format pubkey blobs carry the key but not the comment.
     */
    keyEquals(other: SSHPublicKey): boolean;
    /**
     * Algorithm-specific raw payload bytes. Throws for DSA and RSA, whose
     * keys are several integers — use `data.p/q/g/y` or `data.e/n` instead.
     */
    get keyBytes(): Uint8Array;
    /**
     * Verifies an `sshsig` signature made over `message` in `namespace`, as
     * `ssh_key::PublicKey::verify`: the embedded key must be this key, the
     * namespace must match, and the algorithm-specific signature must verify
     * over the signed-data blob. Never throws on malformed input.
     */
    verifySshSignature(namespace: string, message: Uint8Array, signature: SshSignatureParts): boolean;
}

/**
 * Internal discriminated union for the algorithm-specific public-key data.
 *
 *   - ed25519: the 32-byte raw public key.
 *   - ecdsa:   curve + 65/97/133-byte SEC1 uncompressed point.
 *   - dsa:     four canonical-positive mpint bytes (p, q, g, y) — sign
 *              byte already stripped on parse, re-added by the writer.
 *   - rsa:     canonical-positive e and n.
 */
export declare type SshPublicKeyData = {
    /** `ssh-ed25519`. */
    kind: "ed25519";
    /** The 32 raw public key bytes. */
    pubBytes: Uint8Array;
} | {
    /** `ecdsa-sha2-nistp256` / `ecdsa-sha2-nistp384` / `ecdsa-sha2-nistp521`. */
    kind: "ecdsa";
    /** The NIST curve. */
    curve: SshEcdsaCurve;
    /** The SEC1 uncompressed point (65, 97 or 133 bytes). */
    point: Uint8Array;
} | {
    /** `ssh-dss`. */
    kind: "dsa";
    /** The prime modulus, canonical positive bytes. */
    p: Uint8Array;
    /** The subgroup order, canonical positive bytes. */
    q: Uint8Array;
    /** The generator, canonical positive bytes. */
    g: Uint8Array;
    /** The public value, canonical positive bytes. */
    y: Uint8Array;
} | {
    /** `ssh-rsa`. */
    kind: "rsa";
    /** The public exponent, canonical positive bytes. */
    e: Uint8Array;
    /** The modulus, canonical positive bytes. */
    n: Uint8Array;
};

/** The hash an RSA `sshsig` signature was made with. */
export declare type SshRsaSignatureHash = "sha256" | "sha512";

/** An OpenSSH `sshsig` signature (`-----BEGIN SSH SIGNATURE-----`), version 1. */
export declare class SSHSignature {
    /** The signing key, embedded in the signature. */
    readonly publicKey: SSHPublicKey;
    /** The application namespace the signature was made in. */
    readonly namespace: string;
    /** The reserved field (empty in every signature OpenSSH writes). */
    readonly reserved: Uint8Array;
    /** The hash the message was digested with. */
    readonly hashAlgorithm: SshHashAlgorithm;
    /**
     * The algorithm name inside the signature blob: the key's wire name for
     * Ed25519, DSA and ECDSA keys, and `rsa-sha2-256` / `rsa-sha2-512` (the
     * hash the RSA signature was made with) for RSA keys.
     */
    readonly signatureAlgorithm: string;
    /**
     * Raw signature bytes specific to the algorithm:
     *   ed25519 → 64-byte concatenation `r || s`
     *   ecdsa   → fixed-width `r || s` (64 / 96 / 132 bytes; the SSH mpint
     *     sign bytes are stripped on parse and re-added on serialize)
     *   dsa     → 40-byte `r || s`
     *   rsa     → the RSASSA-PKCS1-v1_5 signature as stored
     */
    readonly signatureBytes: Uint8Array;
    private constructor();
    /** Parses the PEM-armoured `sshsig` text, as `ssh_key::SshSig::from_pem`. */
    static fromPem(text: string): SSHSignature;
    /** Parses the binary `sshsig` blob (the base64 payload of the text form). */
    static fromBlob(blob: Uint8Array): SSHSignature;
    /** The PEM-armoured text, wrapped at 70 columns like OpenSSH. */
    toPem(): string;
    /** The binary `sshsig` blob, byte for byte as OpenSSH writes it. */
    toBlob(): Uint8Array;
    /**
     * Build the message that gets signed/verified: the **signed-data** blob
     * defined by `PROTOCOL.sshsig` §3.1.
     *
     *     "SSHSIG" magic
     *     string  namespace
     *     string  reserved
     *     string  hash_algorithm
     *     string  H(message)        ← *digest*, not the raw message
     */
    static signedDataBlob(namespace: string, hashAlgorithm: SshHashAlgorithm, messageDigest: Uint8Array): Uint8Array;
    /**
     * Construct from already-decoded parts (used by the sign path).
     *
     * `signatureAlgorithm` defaults to the key's wire name; for an RSA key it
     * defaults to `rsa-sha2-512`, the algorithm `ssh-key`'s RSA signer names.
     */
    static fromParts(publicKey: SSHPublicKey, namespace: string, hashAlgorithm: SshHashAlgorithm, signatureBytes: Uint8Array, signatureAlgorithm?: string): SSHSignature;
    /** Fixed-string mirror of the reference's summarizer for `TAG_SSH_TEXT_SIGNATURE`. */
    toString(): string;
    /** SHA-256 digest of canonical PEM bytes — kept for parity with key types. */
    digest(): Uint8Array;
}

/** The parts of an `sshsig` signature `verifySshSignature` needs. */
export declare interface SshSignatureParts {
    /** The key embedded in the signature. */
    publicKey: SSHPublicKey;
    /** The namespace the signature was made in. */
    namespace: string;
    /** The hash the message was digested with. */
    hashAlgorithm: "sha256" | "sha512";
    /** The algorithm name inside the signature blob (`rsa-sha2-256`, `ssh-ed25519`, …). */
    signatureAlgorithm: string;
    /** The raw algorithm-specific signature bytes. */
    signatureBytes: Uint8Array;
}

/**
 * Checks that `value` is a well-formed `SshAlgorithm` object and returns it.
 * Anything else — a non-object, an unknown `kind` or an unknown `curve` — is
 * `InvalidData` for `algorithm`.
 */
export declare function validateSshAlgorithm(value: unknown): SshAlgorithm;

export { }
