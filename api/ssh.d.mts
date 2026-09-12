/** The algorithm for a wire-format name; an unknown name is an `Ssh` failure. */
export declare function parseSshAlgorithm(name: string): SshAlgorithm;

/** Wire-format name of ECDSA P-256 keys. */
export declare const SSH_ALGO_ECDSA_NISTP256 = "ecdsa-sha2-nistp256";

/** Wire-format algorithm name as it appears in OpenSSH text and in the key blob. */
export declare const SSH_ALGO_ED25519 = "ssh-ed25519";

/** OpenSSH curve identifier embedded inside ECDSA key blobs. */
export declare const SSH_CURVE_NISTP256 = "nistp256";

/**
 * SSH key algorithm identifiers.
 *
 * Supports the four algorithms the reference implementation actually wires
 * through `SignatureScheme`:
 *
 *   - Ed25519 (`ssh-ed25519`)
 *   - DSA (`ssh-dss`) — 1024-bit p, 160-bit q, SHA-1
 *   - ECDSA P-256 (`ecdsa-sha2-nistp256`) — SHA-256
 *   - ECDSA P-384 (`ecdsa-sha2-nistp384`) — SHA-384
 *
 * Deferred (blocked upstream in the reference's dependencies): RSA (commented out in
 * `signature_scheme.rs:80-81`), P-521 (`ssh-key` upstream bug
 * https://github.com/RustCrypto/SSH/issues/232), encrypted private
 * keys, `cert-v01@openssh.com`.
 */
export declare type SshAlgorithm = {
    /** `ssh-ed25519`. */
    kind: "ed25519";
} | {
    /** `ssh-dss` (parse only). */
    kind: "dsa";
} | {
    /** `ecdsa-sha2-nistp256` / `ecdsa-sha2-nistp384`. */
    kind: "ecdsa";
    /** The NIST curve of an ECDSA key. */
    curve: SshEcdsaCurve;
};

/** The wire-format name of `algo` (`ssh-ed25519`, `ecdsa-sha2-nistp256`, …). */
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
export declare type SshEcdsaCurve = "nistp256" | "nistp384";

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
    /** Parses the PEM-armoured OpenSSH private key text. */
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
    /** Signs `message` in `namespace` with `hashAlgorithm`, producing an `sshsig` signature. */
    sign(namespace: string, hashAlgorithm: SshHashAlgorithm, message: Uint8Array): SSHSignature;
}

/**
 * Algorithm-specific private-key data.
 *
 *   - ed25519: 32-byte seed.
 *   - ecdsa:   curve + canonical scalar (32 / 48 bytes, no sign byte).
 *   - dsa:     canonical positive p, q, g, y (re-stated from the public
 *              key blob), plus the secret exponent x.
 */
export declare type SshPrivateKeyData = {
    /** `ssh-ed25519`. */
    kind: "ed25519";
    /** The 32-byte seed. */
    seed: Uint8Array;
    /** The 32 raw public key bytes. */
    pubBytes: Uint8Array;
} | {
    /** `ecdsa-sha2-nistp256` / `ecdsa-sha2-nistp384`. */
    kind: "ecdsa";
    /** The NIST curve. */
    curve: SshEcdsaCurve;
    /** The canonical scalar (32 or 48 bytes, no sign byte). */
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
    /** An ECDSA key on `curve` from its SEC1 uncompressed point. */
    static ecdsa(curve: SshEcdsaCurve, uncompressedPoint: Uint8Array, comment?: string): SSHPublicKey;
    /** DSA public key. p/q/g/y must already be canonical positive bytes (no sign byte). */
    static dsa(p: Uint8Array, q: Uint8Array, g: Uint8Array, y: Uint8Array, comment?: string): SSHPublicKey;
    /**
     * Returns a copy of this SSH public key with the comment replaced,
     * leaving this instance untouched.
     */
    withComment(comment: string): SSHPublicKey;
    /** Parses the single-line OpenSSH text form (`<algorithm> <base64 blob> [comment]`). */
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
     * Algorithm-specific raw payload bytes. Throws for DSA — DSA needs structured
     * access via `data.p/q/g/y`.
     */
    get keyBytes(): Uint8Array;
    /** Verifies an `sshsig` signature made over `message` in `namespace`. */
    verifySshSignature(namespace: string, message: Uint8Array, signature: {
        publicKey: SSHPublicKey;
        namespace: string;
        hashAlgorithm: "sha256" | "sha512";
        signatureBytes: Uint8Array;
    }): boolean;
}

/**
 * Internal discriminated union for the algorithm-specific public-key data.
 *
 *   - ed25519: the 32-byte raw public key.
 *   - ecdsa:   curve + 65/97-byte SEC1 uncompressed point.
 *   - dsa:     four canonical-positive mpint bytes (p, q, g, y) — sign
 *              byte already stripped on parse, re-added by the writer.
 */
export declare type SshPublicKeyData = {
    /** `ssh-ed25519`. */
    kind: "ed25519";
    /** The 32 raw public key bytes. */
    pubBytes: Uint8Array;
} | {
    /** `ecdsa-sha2-nistp256` / `ecdsa-sha2-nistp384`. */
    kind: "ecdsa";
    /** The NIST curve. */
    curve: SshEcdsaCurve;
    /** The SEC1 uncompressed point (65 or 97 bytes). */
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
};

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
     * Raw signature bytes specific to the algorithm:
     *   ed25519 → 64-byte concatenation `r || s`
     *   ecdsa-p256 → 64-byte concatenation `r || s` (we strip the SSH
     *     mpint sign bytes on parse and re-add them on serialize, so this
     *     stays a fixed 64-byte canonical form internally)
     */
    readonly signatureBytes: Uint8Array;
    private constructor();
    /** Parses the PEM-armoured `sshsig` text. */
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
    /** Construct from already-decoded parts (used by the sign path). */
    static fromParts(publicKey: SSHPublicKey, namespace: string, hashAlgorithm: SshHashAlgorithm, signatureBytes: Uint8Array): SSHSignature;
    /** Fixed-string mirror of the reference's summarizer for `TAG_SSH_TEXT_SIGNATURE`. */
    toString(): string;
    /** SHA-256 digest of canonical PEM bytes — kept for parity with key types. */
    digest(): Uint8Array;
}

export { }
