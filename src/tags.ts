/**
 * Tag summarisers for every components type, the port of the reference's
 * `tags_registry.rs`. On its own subpath because it reaches
 * every family (root, `/kdf`, `/ssh`, `/sskr`): importing it costs the whole
 * package, which the root entry must not. It is built as a consumer of the
 * package's own public entries (see `tsdown.config.ts`), so adding it did
 * not change how the other entries are chunked.
 *
 * ```ts
 * import { registerTags } from "@blockchaincommons/components/tags";
 * registerTags(); // dcbor's diagnostics now print `Digest(4d3e…)` for tag 40001
 * ```
 *
 * @module tags
 */
import {
  type Cbor,
  type CborSummarizer,
  type TagsStore,
  CborError,
  expectText,
  getGlobalTagsStore,
} from "@blockchaincommons/dcbor";
import {
  registerTags as registerBcTags,
  TAG_ARID,
  TAG_DIGEST,
  TAG_ENCRYPTED_KEY,
  TAG_JSON,
  TAG_NONCE,
  TAG_PRIVATE_KEY_BASE,
  TAG_PRIVATE_KEYS,
  TAG_PUBLIC_KEYS,
  TAG_REFERENCE,
  TAG_SALT,
  TAG_SEALED_MESSAGE,
  TAG_SEED,
  TAG_SIGNATURE,
  TAG_SIGNING_PRIVATE_KEY,
  TAG_SIGNING_PUBLIC_KEY,
  TAG_SSH_TEXT_CERTIFICATE,
  TAG_SSH_TEXT_PRIVATE_KEY,
  TAG_SSH_TEXT_PUBLIC_KEY,
  TAG_SSH_TEXT_SIGNATURE,
  TAG_SSKR_SHARE,
  TAG_URI,
  TAG_UUID,
  TAG_XID,
} from "@blockchaincommons/tags";
import {
  ARID,
  CborJson,
  ComponentsError,
  Digest,
  Nonce,
  PrivateKeyBase,
  PrivateKeys,
  PublicKeys,
  Reference,
  Salt,
  SealedMessage,
  Seed,
  Signature,
  SigningPrivateKey,
  SigningPublicKey,
  URI,
  UUID,
  XID,
  defaultEncapsulationScheme,
  defaultSignatureScheme,
} from "@blockchaincommons/components";
import { EncryptedKey } from "@blockchaincommons/components/kdf";
import { SSHPrivateKey, SSHPublicKey, SSHSignature } from "@blockchaincommons/components/ssh";
import { SskrShare } from "@blockchaincommons/components/sskr";

/** A summariser from a function over the untagged content; any throw becomes a dcbor error result. */
const summary =
  (f: (untagged: Cbor) => string): CborSummarizer =>
  (cbor, _flat) => {
    try {
      return { ok: true, value: f(cbor) };
    } catch (e) {
      // A decoder failure carries its dcbor error as `cause`; report it as
      // the reference's summarisers return the `dcbor::Error`.
      const cause: unknown = e instanceof Error ? e.cause : undefined;
      return {
        ok: false,
        error: CborError.isCborError(e)
          ? e
          : CborError.isCborError(cause)
            ? cause
            : CborError.custom(e instanceof Error ? e.message : String(e)),
      };
    }
  };

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
export function registerComponentSummarizers(store: TagsStore): void {
  store.setSummarizer(
    TAG_DIGEST.value,
    summary((c) => `Digest(${Digest.codec.decodeUntagged(c).shortDescription()})`),
  );
  store.setSummarizer(
    TAG_ARID.value,
    summary((c) => `ARID(${ARID.codec.decodeUntagged(c).shortDescription()})`),
  );
  store.setSummarizer(
    TAG_XID.value,
    summary((c) => `XID(${XID.codec.decodeUntagged(c).shortDescription()})`),
  );
  store.setSummarizer(
    TAG_URI.value,
    summary((c) => `URI(${URI.codec.decodeUntagged(c).toString()})`),
  );
  store.setSummarizer(
    TAG_UUID.value,
    summary((c) => `UUID(${UUID.codec.decodeUntagged(c).toString()})`),
  );
  store.setSummarizer(
    TAG_NONCE.value,
    summary((c) => {
      Nonce.codec.decodeUntagged(c);
      return "Nonce";
    }),
  );
  store.setSummarizer(
    TAG_SALT.value,
    summary((c) => {
      Salt.codec.decodeUntagged(c);
      return "Salt";
    }),
  );
  store.setSummarizer(
    TAG_JSON.value,
    summary((c) => `JSON(${CborJson.codec.decodeUntagged(c).asStr()})`),
  );
  store.setSummarizer(
    TAG_SEED.value,
    summary((c) => {
      Seed.codec.decodeUntagged(c);
      return "Seed";
    }),
  );
  store.setSummarizer(
    TAG_PRIVATE_KEYS.value,
    summary((c) => PrivateKeys.codec.decodeUntagged(c).toString()),
  );
  store.setSummarizer(
    TAG_PUBLIC_KEYS.value,
    summary((c) => PublicKeys.codec.decodeUntagged(c).toString()),
  );
  store.setSummarizer(
    TAG_REFERENCE.value,
    summary((c) => Reference.codec.decodeUntagged(c).toString()),
  );
  store.setSummarizer(
    TAG_ENCRYPTED_KEY.value,
    summary((c) => EncryptedKey.codec.decodeUntagged(c).toString()),
  );
  store.setSummarizer(
    TAG_PRIVATE_KEY_BASE.value,
    summary((c) => PrivateKeyBase.codec.decodeUntagged(c).toString()),
  );
  store.setSummarizer(
    TAG_SIGNING_PRIVATE_KEY.value,
    summary((c) => SigningPrivateKey.codec.decodeUntagged(c).toString()),
  );
  store.setSummarizer(
    TAG_SIGNING_PUBLIC_KEY.value,
    summary((c) => SigningPublicKey.codec.decodeUntagged(c).toString()),
  );
  store.setSummarizer(
    TAG_SIGNATURE.value,
    summary((c) => {
      const signature = Signature.codec.decodeUntagged(c);
      // An SSH signature with no `SignatureScheme` (RSA, P-521) prints
      // `Signature(Unknown)`, as the reference's summariser does.
      let scheme: string;
      try {
        scheme = signature.scheme;
      } catch {
        return "Signature(Unknown)";
      }
      return scheme === defaultSignatureScheme() ? "Signature" : `Signature(${scheme})`;
    }),
  );
  store.setSummarizer(
    TAG_SEALED_MESSAGE.value,
    summary((c) => {
      const scheme = SealedMessage.codec.decodeUntagged(c).encapsulationScheme;
      // The reference prints the enum variant, which is upper-case (`MLKEM768`).
      return scheme === defaultEncapsulationScheme()
        ? "SealedMessage"
        : `SealedMessage(${scheme.toUpperCase()})`;
    }),
  );
  store.setSummarizer(
    TAG_SSKR_SHARE.value,
    summary((c) => {
      SskrShare.codec.decodeUntagged(c);
      return "SSKRShare";
    }),
  );
  store.setSummarizer(
    TAG_SSH_TEXT_PRIVATE_KEY.value,
    summary((c) => `SSHPrivateKey(${SSHPrivateKey.fromOpenssh(expectText(c)).refHexShort()})`),
  );
  store.setSummarizer(
    TAG_SSH_TEXT_PUBLIC_KEY.value,
    summary((c) => `SSHPublicKey(${SSHPublicKey.fromOpenssh(expectText(c)).refHexShort()})`),
  );
  store.setSummarizer(
    TAG_SSH_TEXT_SIGNATURE.value,
    summary((c) => {
      // The reference maps the ssh-key error's own text into the dcbor
      // error (`SSHSignature::from_pem(...).map_err(|e| dcbor::Error::msg(e.to_string()))`),
      // without the `SSH operation failed: ` wrapper `Ssh` carries.
      try {
        SSHSignature.fromPem(expectText(c));
      } catch (e) {
        if (ComponentsError.isComponentsError(e) && e.code === "Ssh" && "message" in e.details) {
          throw CborError.custom(e.details.message);
        }
        throw e;
      }
      return "SSHSignature";
    }),
  );
  // The reference's summariser does not look at the content.
  store.setSummarizer(
    TAG_SSH_TEXT_CERTIFICATE.value,
    summary(() => "SSHCertificate"),
  );
}

/** Registers every Blockchain Commons tag name and the components summarisers in `store`. */
export function registerTagsIn(store: TagsStore): void {
  registerBcTags(store);
  registerComponentSummarizers(store);
}

/** `registerTagsIn` on dcbor's global tags store. */
export function registerTags(): void {
  registerTagsIn(getGlobalTagsStore());
}
