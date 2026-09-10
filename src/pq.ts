/**
 * Post-quantum primitives: ML-DSA signatures and ML-KEM encapsulation.
 *
 * Subpath entry `@blockchaincommons/components/pq`. The root entry's
 * `SigningPrivateKey` and `EncapsulationPrivateKey` dispatch to these types;
 * import this entry to use them directly.
 *
 * @module pq
 */
export * from "./mldsa/index.js";
export * from "./mlkem/index.js";
