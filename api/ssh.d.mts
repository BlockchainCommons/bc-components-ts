export declare function parseSshAlgorithm(name: string): SshAlgorithm;

export declare const SSH_ALGO_ECDSA_NISTP256 = "ecdsa-sha2-nistp256";

/** Wire-format algorithm name as it appears in OpenSSH text and in the key blob. */
export declare const SSH_ALGO_ED25519 = "ssh-ed25519";

/** OpenSSH curve identifier embedded inside ECDSA key blobs. */
export declare const SSH_CURVE_NISTP256 = "nistp256";

/**
 * Copyright © 2025-2026 Parity Technologies
 *
 * SSH key algorithm identifiers.
 *
 * `ssh-key` v0.6.7). v1.1 supports the four algorithms the reference implementation
 * actually wires through `SignatureScheme`:
 *
 *   - Ed25519 (`ssh-ed25519`)
 *   - DSA (`ssh-dss`) — 1024-bit p, 160-bit q, SHA-1
 *   - ECDSA P-256 (`ecdsa-sha2-nistp256`) — SHA-256
 *   - ECDSA P-384 (`ecdsa-sha2-nistp384`) — SHA-384
 *
 * Deferred (rust upstream blockers): RSA (commented out in
 * `signature_scheme.rs:80-81`), P-521 (`ssh-key` upstream bug
 * https://github.com/RustCrypto/SSH/issues/232), encrypted private
 * keys, `cert-v01@openssh.com`. See `SSH_PLAN.md` V2.A-V2.D.
 */
export declare type SshAlgorithm = {
    kind: "ed25519";
} | {
    kind: "dsa";
} | {
    kind: "ecdsa";
    curve: SshEcdsaCurve;
};

export declare function sshAlgorithmName(algo: SshAlgorithm): string;

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
    digest(): Uint8Array;
}

export declare type SshEcdsaCurve = "nistp256" | "nistp384";

export declare type SshHashAlgorithm = "sha256" | "sha512";

export declare class SSHPrivateKey {
    readonly data: SshPrivateKeyData;
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
     * deterministically from the private bytes (as the reference implementation does's
     * `ssh-key` 0.6.7 `KeypairData::checkint`).
     */
    static fromParts(data: SshPrivateKeyData, comment: string, checkint: number): SSHPrivateKey;
    /** Algorithm tag for this key. */
    get algorithm(): SshAlgorithm;
    get publicBytes(): Uint8Array;
    get privateBytes(): Uint8Array;
    static fromOpenssh(text: string): SSHPrivateKey;
    static fromBlob(blob: Uint8Array): SSHPrivateKey;
    /**
     * Re-serialize to the canonical OpenSSH armored format.
     *
     */
    toOpenssh(): string;
    toBlob(): Uint8Array;
    publicKey(): SSHPublicKey;
    private publicBlob;
    private encryptedSection;
    digest(): Uint8Array;
    refHexShort(): string;
    toString(): string;
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
    kind: "ed25519";
    seed: Uint8Array;
    pubBytes: Uint8Array;
} | {
    kind: "ecdsa";
    curve: SshEcdsaCurve;
    scalar: Uint8Array;
    point: Uint8Array;
} | {
    kind: "dsa";
    p: Uint8Array;
    q: Uint8Array;
    g: Uint8Array;
    y: Uint8Array;
    x: Uint8Array;
};

export declare class SSHPublicKey {
    readonly data: SshPublicKeyData;
    readonly comment: string;
    private constructor();
    /** Algorithm tag for this key. */
    get algorithm(): SshAlgorithm;
    static ed25519(keyBytes: Uint8Array, comment?: string): SSHPublicKey;
    static ecdsaP256(uncompressedPoint: Uint8Array, comment?: string): SSHPublicKey;
    static ecdsaP384(uncompressedPoint: Uint8Array, comment?: string): SSHPublicKey;
    static ecdsa(curve: SshEcdsaCurve, uncompressedPoint: Uint8Array, comment?: string): SSHPublicKey;
    /** DSA public key. p/q/g/y must already be canonical positive bytes (no sign byte). */
    static dsa(p: Uint8Array, q: Uint8Array, g: Uint8Array, y: Uint8Array, comment?: string): SSHPublicKey;
    /**
     * Returns a copy of this SSH public key with the comment replaced.
     *
     * return a new instance to keep the type immutable).
     */
    withComment(comment: string): SSHPublicKey;
    static fromOpenssh(text: string): SSHPublicKey;
    toOpenssh(): string;
    static fromBlob(blob: Uint8Array, comment?: string): SSHPublicKey;
    toBlob(): Uint8Array;
    digest(): Uint8Array;
    refHexShort(): string;
    toString(): string;
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
    kind: "ed25519";
    pubBytes: Uint8Array;
} | {
    kind: "ecdsa";
    curve: SshEcdsaCurve;
    point: Uint8Array;
} | {
    kind: "dsa";
    p: Uint8Array;
    q: Uint8Array;
    g: Uint8Array;
    y: Uint8Array;
};

export declare class SSHSignature {
    readonly publicKey: SSHPublicKey;
    readonly namespace: string;
    readonly reserved: Uint8Array;
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
    static fromPem(text: string): SSHSignature;
    static fromBlob(blob: Uint8Array): SSHSignature;
    toPem(): string;
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
    /** Construct from already-decoded parts (used by Phase 7 sign path). */
    static fromParts(publicKey: SSHPublicKey, namespace: string, hashAlgorithm: SshHashAlgorithm, signatureBytes: Uint8Array): SSHSignature;
    /** Fixed-string mirror of Rust summarizer for `TAG_SSH_TEXT_SIGNATURE`. */
    toString(): string;
    /** SHA-256 digest of canonical PEM bytes — kept for parity with key types. */
    digest(): Uint8Array;
}

export { }
