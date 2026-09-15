/**
 * Connects to whatever socket `$SSH_AUTH_SOCK` points at, the reference's
 * `connect_to_ssh_agent`.
 *
 * The agent returned opens one connection per request, so it holds no
 * resource between calls and needs no closing. Identities whose key blob
 * this package cannot parse (a certificate, a security key) are left out of
 * `listIdentities`. As the reference's `SSHAgent` for its client, a failure
 * once connected is an `SshAgent` error carrying the transport's message.
 *
 * @throws `SshAgent` `SSH_AUTH_SOCK env var not set` when the variable is
 * unset; `SshAgent` `no ssh-agent reachable` when the socket cannot be
 * connected.
 */
export declare function connectToSshAgent(): Promise<SshAgent>;

/**
 * What a key-derivation lock/unlock needs from an SSH agent (the reference's
 * `SSHAgent` trait, asynchronous here).
 *
 * An implementation reports its own failures as a `ComponentsError`; a
 * failure to sign is reported by the caller as `SSH agent refused to sign`
 * whatever the implementation threw.
 */
export declare interface SshAgent {
    /** The public keys the agent holds, each with its comment. */
    listIdentities(): Promise<readonly SSHPublicKey[]>;
    /** The raw signature bytes (for Ed25519 the 64-byte signature) over `data`. */
    sign(identity: SSHPublicKey, data: Uint8Array): Promise<Uint8Array>;
}

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
declare type SshAlgorithm = {
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

/** The NIST curves an SSH ECDSA key can use. */
declare type SshEcdsaCurve = "nistp256" | "nistp384" | "nistp521";

declare class SSHPublicKey {
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
declare type SshPublicKeyData = {
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

/** The parts of an `sshsig` signature `verifySshSignature` needs. */
declare interface SshSignatureParts {
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

export { }
