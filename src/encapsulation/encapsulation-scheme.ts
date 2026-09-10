/**
 * Copyright © 2023-2026 Blockchain Commons, LLC
 * Copyright © 2025-2026 Parity Technologies
 *
 *
 * Encapsulation scheme enum for key encapsulation mechanisms
 *
 * This enum represents the available key encapsulation mechanisms (KEMs)
 * for establishing shared secrets between parties.
 *
 * Supported schemes:
 * - X25519: Curve25519-based Diffie-Hellman key exchange (default)
 * - MLKEM512, MLKEM768, MLKEM1024: ML-KEM at various security levels
 *
 */

import { MLKEMLevel } from "../mlkem/mlkem-level.js";
import { ComponentsError } from "../error.js";

/**
 * Available key encapsulation schemes.
 */
export const EncapsulationScheme = {
  /**
   * X25519 Diffie-Hellman key exchange (default).
   * Based on Curve25519 as defined in RFC 7748.
   */
  X25519: "x25519",

  /**
   * ML-KEM-512 post-quantum key encapsulation (NIST security level 1).
   */
  MLKEM512: "mlkem512",

  /**
   * ML-KEM-768 post-quantum key encapsulation (NIST security level 3).
   */
  MLKEM768: "mlkem768",

  /**
   * ML-KEM-1024 post-quantum key encapsulation (NIST security level 5).
   */
  MLKEM1024: "mlkem1024",
} as const;

/** One of the `EncapsulationScheme` values. */
export type EncapsulationScheme = (typeof EncapsulationScheme)[keyof typeof EncapsulationScheme];

/**
 * Returns the default encapsulation scheme (X25519).
 */
export function defaultEncapsulationScheme(): EncapsulationScheme {
  return EncapsulationScheme.X25519;
}

/**
 * Check if a scheme is an MLKEM scheme.
 */
export function isMlkemScheme(scheme: EncapsulationScheme): boolean {
  return (
    scheme === EncapsulationScheme.MLKEM512 ||
    scheme === EncapsulationScheme.MLKEM768 ||
    scheme === EncapsulationScheme.MLKEM1024
  );
}

/**
 * Convert EncapsulationScheme to MLKEMLevel.
 * @throws Error if scheme is not an MLKEM scheme
 */
export function schemeToMlkemLevel(scheme: EncapsulationScheme): MLKEMLevel {
  switch (scheme) {
    case EncapsulationScheme.X25519:
      throw ComponentsError.invalidData(`Not an MLKEM scheme: ${String(scheme)}`);
    case EncapsulationScheme.MLKEM512:
      return MLKEMLevel.MLKEM512;
    case EncapsulationScheme.MLKEM768:
      return MLKEMLevel.MLKEM768;
    case EncapsulationScheme.MLKEM1024:
      return MLKEMLevel.MLKEM1024;
  }
}

/**
 * Convert MLKEMLevel to EncapsulationScheme.
 */
export function mlkemLevelToScheme(level: MLKEMLevel): EncapsulationScheme {
  switch (level) {
    case MLKEMLevel.MLKEM512:
      return EncapsulationScheme.MLKEM512;
    case MLKEMLevel.MLKEM768:
      return EncapsulationScheme.MLKEM768;
    case MLKEMLevel.MLKEM1024:
      return EncapsulationScheme.MLKEM1024;
  }
}
