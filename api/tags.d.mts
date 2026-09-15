import { TagsStore } from '@blockchaincommons/dcbor';

/**
 * Installs the summariser of every components tag in `store`, one line per
 * type and the same strings as the reference:
 *
 * - `Digest(…)`, `ARID(…)`, `XID(…)` over the short description; `URI(…)`,
 *   `UUID(…)`, `JSON(…)` over the text
 * - `Nonce`, `Salt`, `Seed`, `SSKRShare`, `SSHSignature` as fixed words
 *   once the content parses; `SSHCertificate` for any content
 * - `Signature` for the default scheme, `Signature(Ed25519)` and so on
 *   otherwise; `SealedMessage` for X25519, `SealedMessage(MLKEM768)` …
 * - `toString()` of `PrivateKeys`, `PublicKeys`, `Reference`,
 *   `EncryptedKey`, `PrivateKeyBase`, `SigningPrivateKey`,
 *   `SigningPublicKey`
 * - `SSHPrivateKey(…)` / `SSHPublicKey(…)` over the short reference hex
 */
export declare function registerComponentSummarizers(store: TagsStore): void;

/** `registerTagsIn` on dcbor's global tags store. */
export declare function registerTags(): void;

/** Registers every Blockchain Commons tag name and the components summarisers in `store`. */
export declare function registerTagsIn(store: TagsStore): void;

export { }
