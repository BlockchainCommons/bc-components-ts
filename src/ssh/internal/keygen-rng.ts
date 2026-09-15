/**
 * The random source consumed by the deterministic SSH key generators.
 *
 * Mirrors the subset of `rand_core` 0.6 `RngCore` that the reference crates
 * (`dsa` 0.6.3, `rsa` 0.9.10, `p521` 0.13.3 via `ssh-key` 0.6.7) call while
 * generating keys. `HKDFRng` satisfies it structurally, so
 * `new HKDFRng(seed, algorithmName)` can be passed straight in.
 *
 * The generators consume the source in exactly the order the Rust crates
 * do (`fill_bytes` sizes, rejection-sampling retries), which is what makes
 * the produced keys byte-identical to the reference for the same seed.
 */
export interface KeygenRng {
  /** Fill `dest` with the next `dest.length` bytes (`RngCore::fill_bytes`). */
  fillBytes(dest: Uint8Array): void;
  /** The next little-endian u32 (`RngCore::next_u32`). */
  nextU32(): number;
  /** The next little-endian u64 (`RngCore::next_u64`). */
  nextU64(): bigint;
}
