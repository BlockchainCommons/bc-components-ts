/**
 * Mutation checks. Each entry names one single-site change to `src/` and
 * the gate that must go red for it. They are executed by hand (apply the
 * mutation, run `bun test`, revert); the `it.todo`s keep the list in the
 * suite so it is reviewed with the code.
 */
describe("mutation checks (by hand)", () => {
  it.todo(
    "Ed25519 verify returns true for a zero signature → strictness golden rows + Rust harness (verifyStrict)",
  );
  it.todo(
    "defineCodec.decode keeps the untagged fallback → untagged golden rows + differential T5 count",
  );
  it.todo(
    "SigningPrivateKey.random defaults to Ed25519 → defaults golden rows + harness P-B3 stays non-zero",
  );
  it.todo(
    "Salt.random drops the MIN_SALT_SIZE check → domain rows salt.random.length.* + randoms category",
  );
  it.todo("PBKDF2Params.from accepts iterations 1.5 → kdfDomain rows + property test");
  it.todo("SealedMessage.seal ignores the aad option → seals rows with aad (decrypt must fail)");
  it.todo("SealedMessage.seal ignores the nonce option → seals rows with a fixed nonce");
  it.todo("Digest.bytes returns the internal buffer → aliasing property test (B5)");
  it.todo("Seed.from silently drops a non-string name → domain row seed.name.number (B10)");
  it.todo(
    "errorCode of a foreign class is not wrapped → domain rows report CryptoError/CborError/RangeError",
  );
});
