/**
 * The one error type of this package.
 *
 * Every failure a component can raise is a `ComponentsError` with a `code`
 * from a closed union, `details` discriminated by that code, and `cause`
 * carrying the wrapped error when the failure came from a dependency
 * (crypto, dcbor, sskr, an SSH parser).
 *
 * @module error
 */

/** The closed set of failure codes. */
export type ComponentsErrorCode =
  | "InvalidSize"
  | "InvalidData"
  | "DataTooShort"
  | "Crypto"
  | "Cbor"
  | "Sskr"
  | "Ssh"
  | "Uri"
  | "Compression"
  | "PostQuantum"
  | "LevelMismatch"
  | "SshAgent"
  | "General";

/** Every code, for exhaustive tables and tests. */
export const COMPONENTS_ERROR_CODES: readonly ComponentsErrorCode[] = [
  "InvalidSize",
  "InvalidData",
  "DataTooShort",
  "Crypto",
  "Cbor",
  "Sskr",
  "Ssh",
  "Uri",
  "Compression",
  "PostQuantum",
  "LevelMismatch",
  "SshAgent",
  "General",
];

/** Details of an `InvalidSize` failure. */
export interface InvalidSizeDetails {
  code: "InvalidSize";
  /** What was being constructed (`"data"`, `"Digest"`, …). */
  dataType: string;
  expected: number;
  actual: number;
}

/** Details of an `InvalidData` failure. */
export interface InvalidDataDetails {
  code: "InvalidData";
  dataType: string;
  reason: string;
}

/** Details of a `DataTooShort` failure. */
export interface DataTooShortDetails {
  code: "DataTooShort";
  dataType: string;
  minimum: number;
  actual: number;
}

/** Details of every other failure: the unprefixed message. */
export interface MessageDetails {
  code: Exclude<ComponentsErrorCode, "InvalidSize" | "InvalidData" | "DataTooShort">;
  message: string;
}

/** `details` is discriminated by `code`. */
export type ComponentsErrorDetails =
  InvalidSizeDetails | InvalidDataDetails | DataTooShortDetails | MessageDetails;

/**
 * Error raised by every component operation.
 *
 * ```ts
 * try {
 *   Digest.from(bytes);
 * } catch (e) {
 *   if (ComponentsError.isComponentsError(e) && e.code === "InvalidSize") {
 *     console.log(e.details.expected, e.details.actual);
 *   }
 * }
 * ```
 */
export class ComponentsError extends Error {
  override readonly name = "ComponentsError";
  readonly code: ComponentsErrorCode;
  readonly details: ComponentsErrorDetails;

  private constructor(message: string, details: ComponentsErrorDetails, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.code = details.code;
    this.details = details;
  }

  /** `true` for a `ComponentsError` from any copy of this package. */
  static isComponentsError(value: unknown): value is ComponentsError {
    return value instanceof Error && value.name === "ComponentsError" && "code" in value;
  }

  /** `true` when this error carries `code`. */
  is(code: ComponentsErrorCode): boolean {
    return this.code === code;
  }

  // Size and shape ------------------------------------------------------------

  static invalidSize(expected: number, actual: number): ComponentsError {
    return ComponentsError.invalidSizeForType("data", expected, actual);
  }

  static invalidSizeForType(dataType: string, expected: number, actual: number): ComponentsError {
    return new ComponentsError(`invalid ${dataType} size: expected ${expected}, got ${actual}`, {
      code: "InvalidSize",
      dataType,
      expected,
      actual,
    });
  }

  static invalidData(reason: string, cause?: unknown): ComponentsError {
    return ComponentsError.invalidDataForType("data", reason, cause);
  }

  static invalidDataForType(dataType: string, reason: string, cause?: unknown): ComponentsError {
    return new ComponentsError(
      `invalid ${dataType}: ${reason}`,
      { code: "InvalidData", dataType, reason },
      cause,
    );
  }

  static dataTooShort(dataType: string, minimum: number, actual: number): ComponentsError {
    return new ComponentsError(
      `data too short: ${dataType} expected at least ${minimum}, got ${actual}`,
      { code: "DataTooShort", dataType, minimum, actual },
    );
  }

  static invalidFormat(reason: string, cause?: unknown): ComponentsError {
    return ComponentsError.invalidDataForType("format", reason, cause);
  }

  // Wrapped dependencies ------------------------------------------------------

  static crypto(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of(
      "Crypto",
      `cryptographic operation failed: ${message}`,
      message,
      cause,
    );
  }

  static cbor(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of("Cbor", `CBOR error: ${message}`, message, cause);
  }

  static sskr(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of("Sskr", `SSKR error: ${message}`, message, cause);
  }

  static ssh(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of("Ssh", `SSH operation failed: ${message}`, message, cause);
  }

  static sshAgent(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of("SshAgent", `SSH agent error: ${message}`, message, cause);
  }

  static uri(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of("Uri", `invalid URI: ${message}`, message, cause);
  }

  static compression(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of("Compression", `compression error: ${message}`, message, cause);
  }

  static postQuantum(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of(
      "PostQuantum",
      `post-quantum cryptography error: ${message}`,
      message,
      cause,
    );
  }

  static levelMismatch(): ComponentsError {
    const message = "signature level does not match key level";
    return ComponentsError.of("LevelMismatch", message, message);
  }

  static general(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of("General", message, message, cause);
  }

  private static of(
    code: MessageDetails["code"],
    fullMessage: string,
    message: string,
    cause?: unknown,
  ): ComponentsError {
    return new ComponentsError(fullMessage, { code, message }, cause);
  }
}
