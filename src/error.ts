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

/**
 * The closed set of failure codes. `Hex` and `Utf8` mirror the reference's
 * `Error::Hex` / `Error::Utf8`; its `Env` and `SshAgentClient` belong to
 * the `ssh-agent` feature, which this package does not port.
 */
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
  | "Hex"
  | "Utf8"
  | "General";

/** Every code, for exhaustive tables and tests. */
export const COMPONENTS_ERROR_CODES: readonly ComponentsErrorCode[] = /*#__PURE__*/ Object.freeze([
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
  "Hex",
  "Utf8",
  "General",
]);

/** Details of an `InvalidSize` failure. */
export interface InvalidSizeDetails {
  /** The discriminant. */
  code: "InvalidSize";
  /** What was being constructed (`"data"`, `"Digest"`, …). */
  dataType: string;
  /** The byte length the type requires. */
  expected: number;
  /** The byte length that was given. */
  actual: number;
}

/** Details of an `InvalidData` failure. */
export interface InvalidDataDetails {
  /** The discriminant. */
  code: "InvalidData";
  /** What was being constructed or which parameter was checked. */
  dataType: string;
  /** Why the input was rejected. */
  reason: string;
}

/** Details of a `DataTooShort` failure. */
export interface DataTooShortDetails {
  /** The discriminant. */
  code: "DataTooShort";
  /** What was being constructed. */
  dataType: string;
  /** The smallest byte length the type accepts. */
  minimum: number;
  /** The byte length that was given. */
  actual: number;
}

/** Details of every other failure: the unprefixed message. */
export interface MessageDetails {
  /** The discriminant: every code without structured details. */
  code: Exclude<ComponentsErrorCode, "InvalidSize" | "InvalidData" | "DataTooShort">;
  /** The message without the code's prefix. */
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
  /** Always `"ComponentsError"`; the cross-copy identity `isComponentsError` checks. */
  override readonly name = "ComponentsError";
  /** The failure code. */
  readonly code: ComponentsErrorCode;
  /** Structured details, discriminated by `code`. */
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

  /** `InvalidSize` for unnamed data. */
  static invalidSize(expected: number, actual: number): ComponentsError {
    return ComponentsError.invalidSizeForType("data", expected, actual);
  }

  /** `InvalidSize` naming the type being constructed. */
  static invalidSizeForType(dataType: string, expected: number, actual: number): ComponentsError {
    return new ComponentsError(`invalid ${dataType} size: expected ${expected}, got ${actual}`, {
      code: "InvalidSize",
      dataType,
      expected,
      actual,
    });
  }

  /** `InvalidData` for unnamed data. */
  static invalidData(reason: string, cause?: unknown): ComponentsError {
    return ComponentsError.invalidDataForType("data", reason, cause);
  }

  /** `InvalidData` naming the type or parameter. */
  static invalidDataForType(dataType: string, reason: string, cause?: unknown): ComponentsError {
    return new ComponentsError(
      `invalid ${dataType}: ${reason}`,
      { code: "InvalidData", dataType, reason },
      cause,
    );
  }

  /** `DataTooShort`: fewer bytes than the type's minimum. */
  static dataTooShort(dataType: string, minimum: number, actual: number): ComponentsError {
    return new ComponentsError(
      `data too short: ${dataType} expected at least ${minimum}, got ${actual}`,
      { code: "DataTooShort", dataType, minimum, actual },
    );
  }

  /** `InvalidData` for a malformed text form (an SSH PEM, a URI). */
  static invalidFormat(reason: string, cause?: unknown): ComponentsError {
    return ComponentsError.invalidDataForType("format", reason, cause);
  }

  // Wrapped dependencies ------------------------------------------------------

  /** `Crypto`: a cryptographic operation failed (authentication, signing). */
  static crypto(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of(
      "Crypto",
      `cryptographic operation failed: ${message}`,
      message,
      cause,
    );
  }

  /** `Cbor`: a dcbor failure at the package boundary. */
  static cbor(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of("Cbor", `CBOR error: ${message}`, message, cause);
  }

  /** `Sskr`: a failure from the sskr package. */
  static sskr(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of("Sskr", `SSKR error: ${message}`, message, cause);
  }

  /** `Ssh`: an SSH key, signature or certificate could not be parsed or used. */
  static ssh(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of("Ssh", `SSH operation failed: ${message}`, message, cause);
  }

  /** `SshAgent`: an SSH-agent operation is not available. */
  static sshAgent(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of("SshAgent", `SSH agent error: ${message}`, message, cause);
  }

  /** `Uri`: not a valid URI. */
  static uri(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of("Uri", `invalid URI: ${message}`, message, cause);
  }

  /** `Compression`: a DEFLATE stream or its checksum is corrupt. */
  static compression(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of("Compression", `compression error: ${message}`, message, cause);
  }

  /** `PostQuantum`: an ML-DSA / ML-KEM level or key is invalid. */
  static postQuantum(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of(
      "PostQuantum",
      `post-quantum cryptography error: ${message}`,
      message,
      cause,
    );
  }

  /** `LevelMismatch`: an ML-DSA signature and key of different levels. */
  static levelMismatch(): ComponentsError {
    const message = "signature level does not match key level";
    return ComponentsError.of("LevelMismatch", message, message);
  }

  /** `Hex`: a malformed hex string. */
  static hex(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of("Hex", `invalid hex: ${message}`, message, cause);
  }

  /** `Utf8`: bytes that are not valid UTF-8. */
  static utf8(message: string, cause?: unknown): ComponentsError {
    return ComponentsError.of("Utf8", `invalid UTF-8: ${message}`, message, cause);
  }

  /** `General`: anything the other codes do not name. */
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
