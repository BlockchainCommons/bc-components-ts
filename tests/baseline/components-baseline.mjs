import { deflateRaw, inflateRaw } from "pako";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { scrypt } from "@noble/hashes/scrypt.js";
import { argon2id } from "@noble/hashes/argon2.js";
import * as sr25519 from "@scure/sr25519";
import { blake2b } from "@noble/hashes/blake2.js";
import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { sha1 } from "@noble/hashes/legacy.js";
import { p256, p384 } from "@noble/curves/nist.js";
import { base64 } from "@scure/base";
import { ml_kem1024, ml_kem512, ml_kem768 } from "@noble/post-quantum/ml-kem.js";
//#region src/error.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Error types for cryptographic and component operations
*
* Ported from bc-components-rust/src/error.rs
*
* This module provides a unified error handling system that matches the Rust
* implementation's error variants with full structural parity:
*
* - InvalidSize: Invalid data size for the specified type
* - InvalidData: Invalid data format or content
* - DataTooShort: Data too short for the expected type
* - Crypto: Cryptographic operation failed
* - Cbor: CBOR encoding or decoding error
* - Sskr: SSKR error
* - Ssh: SSH key operation failed
* - Uri: URI parsing failed
* - Compression: Data compression/decompression failed
* - PostQuantum: Post-quantum cryptography library error
* - LevelMismatch: Signature level mismatch
* - SshAgent: SSH agent operation failed
* - Hex: Hex decoding error
* - Utf8: UTF-8 conversion error
* - Env: Environment variable error
* - SshAgentClient: SSH agent client error
* - General: General error with custom message
*/
/**
* Error kind enum matching Rust's Error variants.
*
* This enum allows programmatic checking of error types, matching the
* Rust enum variants exactly.
*/
let ErrorKind = /* @__PURE__ */ function(ErrorKind) {
	/** Invalid data size for the specified type */
	ErrorKind["InvalidSize"] = "InvalidSize";
	/** Invalid data format or content */
	ErrorKind["InvalidData"] = "InvalidData";
	/** Data too short for the expected type */
	ErrorKind["DataTooShort"] = "DataTooShort";
	/** Cryptographic operation failed */
	ErrorKind["Crypto"] = "Crypto";
	/** CBOR encoding or decoding error */
	ErrorKind["Cbor"] = "Cbor";
	/** SSKR error */
	ErrorKind["Sskr"] = "Sskr";
	/** SSH key operation failed */
	ErrorKind["Ssh"] = "Ssh";
	/** URI parsing failed */
	ErrorKind["Uri"] = "Uri";
	/** Data compression/decompression failed */
	ErrorKind["Compression"] = "Compression";
	/** Post-quantum cryptography library error */
	ErrorKind["PostQuantum"] = "PostQuantum";
	/** Signature level mismatch */
	ErrorKind["LevelMismatch"] = "LevelMismatch";
	/** SSH agent operation failed */
	ErrorKind["SshAgent"] = "SshAgent";
	/** Hex decoding error */
	ErrorKind["Hex"] = "Hex";
	/** UTF-8 conversion error */
	ErrorKind["Utf8"] = "Utf8";
	/** Environment variable error */
	ErrorKind["Env"] = "Env";
	/** SSH agent client error */
	ErrorKind["SshAgentClient"] = "SshAgentClient";
	/** General error with custom message */
	ErrorKind["General"] = "General";
	return ErrorKind;
}({});
/**
* Error type for cryptographic and component operations.
*
* This class provides full structural parity with the Rust Error enum,
* including:
* - An `errorKind` property for programmatic error type checking
* - Structured `errorData` for accessing error-specific fields
* - Factory methods matching Rust's impl block
*/
var CryptoError = class CryptoError extends Error {
	/** The error kind for programmatic type checking */
	errorKind;
	/** Structured error data matching Rust's error variants */
	errorData;
	constructor(message, errorData) {
		super(message);
		this.name = "CryptoError";
		this.errorKind = errorData.kind;
		this.errorData = errorData;
		const ErrorWithStackTrace = Error;
		if (typeof ErrorWithStackTrace.captureStackTrace === "function") ErrorWithStackTrace.captureStackTrace(this, CryptoError);
	}
	/**
	* Create an invalid size error.
	*
	* Rust equivalent: `Error::InvalidSize { data_type, expected, actual }`
	*
	* @param expected - The expected size
	* @param actual - The actual size received
	*/
	static invalidSize(expected, actual) {
		return CryptoError.invalidSizeForType("data", expected, actual);
	}
	/**
	* Create an invalid size error with a data type name.
	*
	* Rust equivalent: `Error::invalid_size(data_type, expected, actual)`
	*
	* @param dataType - The name of the data type
	* @param expected - The expected size
	* @param actual - The actual size received
	*/
	static invalidSizeForType(dataType, expected, actual) {
		return new CryptoError(`invalid ${dataType} size: expected ${expected}, got ${actual}`, {
			kind: "InvalidSize",
			dataType,
			expected,
			actual
		});
	}
	/**
	* Create an invalid data error.
	*
	* @param message - Description of what's invalid
	*/
	static invalidData(message) {
		return CryptoError.invalidDataForType("data", message);
	}
	/**
	* Create an invalid data error with a data type name.
	*
	* Rust equivalent: `Error::invalid_data(data_type, reason)`
	*
	* @param dataType - The name of the data type
	* @param reason - The reason the data is invalid
	*/
	static invalidDataForType(dataType, reason) {
		return new CryptoError(`invalid ${dataType}: ${reason}`, {
			kind: "InvalidData",
			dataType,
			reason
		});
	}
	/**
	* Create a data too short error.
	*
	* Rust equivalent: `Error::data_too_short(data_type, minimum, actual)`
	*
	* @param dataType - The name of the data type
	* @param minimum - The minimum required size
	* @param actual - The actual size received
	*/
	static dataTooShort(dataType, minimum, actual) {
		return new CryptoError(`data too short: ${dataType} expected at least ${minimum}, got ${actual}`, {
			kind: "DataTooShort",
			dataType,
			minimum,
			actual
		});
	}
	/**
	* Create an invalid format error.
	*
	* @param message - Description of the format error
	*/
	static invalidFormat(message) {
		return CryptoError.invalidDataForType("format", message);
	}
	/**
	* Create an invalid input error.
	*
	* @param message - Description of the invalid input
	*/
	static invalidInput(message) {
		return CryptoError.invalidDataForType("input", message);
	}
	/**
	* Create a cryptographic operation failed error.
	*
	* Rust equivalent: `Error::crypto(msg)`
	*
	* @param message - Description of the failure
	*/
	static cryptoOperation(message) {
		return CryptoError.crypto(message);
	}
	/**
	* Create a crypto error.
	*
	* Rust equivalent: `Error::Crypto(msg)`
	*
	* @param message - Description of the failure
	*/
	static crypto(message) {
		return new CryptoError(`cryptographic operation failed: ${message}`, {
			kind: "Crypto",
			message
		});
	}
	/**
	* Create a post-quantum cryptography error.
	*
	* Rust equivalent: `Error::post_quantum(msg)`
	*
	* @param message - Description of the failure
	*/
	static postQuantum(message) {
		return new CryptoError(`post-quantum cryptography error: ${message}`, {
			kind: "PostQuantum",
			message
		});
	}
	/**
	* Create a signature level mismatch error.
	*
	* Rust equivalent: `Error::LevelMismatch`
	*/
	static levelMismatch() {
		return new CryptoError("signature level does not match key level", { kind: "LevelMismatch" });
	}
	/**
	* Create a CBOR error.
	*
	* Rust equivalent: `Error::Cbor(err)`
	*
	* @param message - Description of the CBOR error
	*/
	static cbor(message) {
		return new CryptoError(`CBOR error: ${message}`, {
			kind: "Cbor",
			message
		});
	}
	/**
	* Create a hex decoding error.
	*
	* Rust equivalent: `Error::Hex(err)`
	*
	* @param message - Description of the hex error
	*/
	static hex(message) {
		return new CryptoError(`hex decoding error: ${message}`, {
			kind: "Hex",
			message
		});
	}
	/**
	* Create a UTF-8 conversion error.
	*
	* Rust equivalent: `Error::Utf8(err)`
	*
	* @param message - Description of the UTF-8 error
	*/
	static utf8(message) {
		return new CryptoError(`UTF-8 conversion error: ${message}`, {
			kind: "Utf8",
			message
		});
	}
	/**
	* Create a compression error.
	*
	* Rust equivalent: `Error::compression(msg)`
	*
	* @param message - Description of the compression error
	*/
	static compression(message) {
		return new CryptoError(`compression error: ${message}`, {
			kind: "Compression",
			message
		});
	}
	/**
	* Create a URI parsing error.
	*
	* Rust equivalent: `Error::Uri(err)`
	*
	* @param message - Description of the URI error
	*/
	static uri(message) {
		return new CryptoError(`invalid URI: ${message}`, {
			kind: "Uri",
			message
		});
	}
	/**
	* Create an SSKR error.
	*
	* Rust equivalent: `Error::Sskr(err)`
	*
	* @param message - Description of the SSKR error
	*/
	static sskr(message) {
		return new CryptoError(`SSKR error: ${message}`, {
			kind: "Sskr",
			message
		});
	}
	/**
	* Create an SSH operation error.
	*
	* Rust equivalent: `Error::ssh(msg)`
	*
	* @param message - Description of the SSH error
	*/
	static ssh(message) {
		return new CryptoError(`SSH operation failed: ${message}`, {
			kind: "Ssh",
			message
		});
	}
	/**
	* Create an SSH agent error.
	*
	* Rust equivalent: `Error::ssh_agent(msg)`
	*
	* @param message - Description of the SSH agent error
	*/
	static sshAgent(message) {
		return new CryptoError(`SSH agent error: ${message}`, {
			kind: "SshAgent",
			message
		});
	}
	/**
	* Create an SSH agent client error.
	*
	* Rust equivalent: `Error::ssh_agent_client(msg)`
	*
	* @param message - Description of the SSH agent client error
	*/
	static sshAgentClient(message) {
		return new CryptoError(`SSH agent client error: ${message}`, {
			kind: "SshAgentClient",
			message
		});
	}
	/**
	* Create an environment variable error.
	*
	* Rust equivalent: `Error::Env(err)`
	*
	* @param message - Description of the environment error
	*/
	static env(message) {
		return new CryptoError(`environment variable error: ${message}`, {
			kind: "Env",
			message
		});
	}
	/**
	* Create a general error with a custom message.
	*
	* Rust equivalent: `Error::general(msg)` / `Error::General(msg)`
	*
	* @param message - The error message
	*/
	static general(message) {
		return new CryptoError(message, {
			kind: "General",
			message
		});
	}
	/**
	* Check if this error is of a specific kind.
	*
	* @param kind - The error kind to check
	*/
	isKind(kind) {
		return this.errorKind === kind;
	}
	/**
	* Check if this is an InvalidSize error.
	*/
	isInvalidSize() {
		return this.errorKind === "InvalidSize";
	}
	/**
	* Check if this is an InvalidData error.
	*/
	isInvalidData() {
		return this.errorKind === "InvalidData";
	}
	/**
	* Check if this is a DataTooShort error.
	*/
	isDataTooShort() {
		return this.errorKind === "DataTooShort";
	}
	/**
	* Check if this is a Crypto error.
	*/
	isCrypto() {
		return this.errorKind === "Crypto";
	}
	/**
	* Check if this is a Cbor error.
	*/
	isCbor() {
		return this.errorKind === "Cbor";
	}
	/**
	* Check if this is an Sskr error.
	*/
	isSskr() {
		return this.errorKind === "Sskr";
	}
	/**
	* Check if this is an Ssh error.
	*/
	isSsh() {
		return this.errorKind === "Ssh";
	}
	/**
	* Check if this is a Uri error.
	*/
	isUri() {
		return this.errorKind === "Uri";
	}
	/**
	* Check if this is a Compression error.
	*/
	isCompression() {
		return this.errorKind === "Compression";
	}
	/**
	* Check if this is a PostQuantum error.
	*/
	isPostQuantum() {
		return this.errorKind === "PostQuantum";
	}
	/**
	* Check if this is a LevelMismatch error.
	*/
	isLevelMismatch() {
		return this.errorKind === "LevelMismatch";
	}
	/**
	* Check if this is an SshAgent error.
	*/
	isSshAgent() {
		return this.errorKind === "SshAgent";
	}
	/**
	* Check if this is a Hex error.
	*/
	isHex() {
		return this.errorKind === "Hex";
	}
	/**
	* Check if this is a Utf8 error.
	*/
	isUtf8() {
		return this.errorKind === "Utf8";
	}
	/**
	* Check if this is an Env error.
	*/
	isEnv() {
		return this.errorKind === "Env";
	}
	/**
	* Check if this is an SshAgentClient error.
	*/
	isSshAgentClient() {
		return this.errorKind === "SshAgentClient";
	}
	/**
	* Check if this is a General error.
	*/
	isGeneral() {
		return this.errorKind === "General";
	}
};
/**
* Type guard to check if a result is an Error.
*/
function isError(result) {
	return result instanceof Error;
}
/**
* Type guard to check if a result is a CryptoError.
*/
function isCryptoError(result) {
	return result instanceof CryptoError;
}
/**
* Type guard to check if an error is a CryptoError of a specific kind.
*/
function isCryptoErrorKind(result, kind) {
	return isCryptoError(result) && result.errorKind === kind;
}
//#endregion
//#region src/private-key-data-provider.ts
/**
* Type guard to check if an object implements PrivateKeyDataProvider
*/
function isPrivateKeyDataProvider(obj) {
	return typeof obj === "object" && obj !== null && "privateKeyData" in obj && typeof obj.privateKeyData === "function";
}
//#endregion
//#region src/encrypter.ts
/**
* Type guard to check if an object implements the Encrypter interface.
*/
function isEncrypter(obj) {
	return typeof obj === "object" && obj !== null && "encapsulationPublicKey" in obj && typeof obj.encapsulationPublicKey === "function" && "encapsulateNewSharedSecret" in obj && typeof obj.encapsulateNewSharedSecret === "function";
}
/**
* Type guard to check if an object implements the Decrypter interface.
*/
function isDecrypter(obj) {
	return typeof obj === "object" && obj !== null && "encapsulationPrivateKey" in obj && typeof obj.encapsulationPrivateKey === "function" && "decapsulateSharedSecret" in obj && typeof obj.decapsulateSharedSecret === "function";
}
//#endregion
//#region ../bc-dcbor-compat-ts/node_modules/@blockchaincommons/dcbor/dist/error-BXLcx8Bl.mjs
const MajorType$4 = {
	Unsigned: 0,
	Negative: 1,
	ByteString: 2,
	Text: 3,
	Array: 4,
	Map: 5,
	Tagged: 6,
	Simple: 7
};
const isCborNumber$4 = (value) => {
	return typeof value === "number" || typeof value === "bigint";
};
const isCbor$4 = (value) => {
	return value !== null && typeof value === "object" && "isCbor" in value && value.isCbor === true;
};
/**
* Compare two tag values for equality, normalizing `number` vs `bigint`.
* A raw `===` would treat `100n` and `100` as unequal, so a large tag that
* decoded to a `bigint` wouldn't match the same value written as a `number`.
*
* @internal Exported for cross-module use; not part of the public surface -
* use `Tag.equals` instead.
*/
const tagValuesEqual$4 = (a, b) => {
	if (typeof a === "bigint" || typeof b === "bigint") return BigInt(a) === BigInt(b);
	return a === b;
};
/**
* Value-type companion for the `Tag` interface: an interface plus a merged
* `const` with a handful of members. It stays small and must not import the
* encode/format graph.
*/
const Tag$2 = {
	/**
	* Create a Tag from its numeric value, optionally with a name.
	*
	* ```typescript
	* Tag.from(1, "date");
	* Tag.from(12345);
	* ```
	*/
	from(value, name) {
		if (name !== void 0) return {
			value,
			name
		};
		return { value };
	},
	/**
	* Compare two tags for equality: compares by `value` only (normalizing
	* `number` vs `bigint`) and ignores the optional `name`.
	*/
	equals(a, b) {
		return tagValuesEqual$4(a.value, b.value);
	}
};
/**
* Get the string representation of a tag.
* Internal function used for error messages.
*
* @param tag - The tag to represent
* @returns String representation (name if available, otherwise value)
*
* @internal
*/
const tagToString$4 = (tag) => tag.name ?? tag.value.toString();
const captureStackTrace$2 = Error.captureStackTrace;
/**
* The single error type thrown by dCBOR encoding, decoding, and extraction.
*
* @example
* ```typescript
* try {
*   decodeCbor(bytes);
* } catch (e) {
*   if (CborError.isCborError(e) && e.code === "WrongTag") {
*     console.log(e.details.expectedTag, e.details.actualTag);
*   }
* }
* ```
*/
var CborError$4 = class CborError extends Error {
	/** Machine-readable discriminant; switch on this to handle errors. */
	code;
	/** Structured, code-specific data (see {@link CborErrorDetails}). */
	details;
	constructor(code, message, details = {}) {
		super(message);
		this.name = "CborError";
		this.code = code;
		this.details = details;
		Object.setPrototypeOf(this, new.target.prototype);
		if (typeof captureStackTrace$2 === "function") captureStackTrace$2(this, CborError);
	}
	/** Type guard: is `value` a {@link CborError}? Narrows to the
	* code-discriminated {@link CborErrorTyped} union. */
	static isCborError(value) {
		return value instanceof CborError;
	}
	/** The CBOR data ended before a complete item could be decoded. */
	static underrun() {
		return new CborError("Underrun", "early end of CBOR data");
	}
	/** An unsupported/invalid value was found in a CBOR header byte. */
	static unsupportedHeaderValue(headerValue) {
		return new CborError("UnsupportedHeaderValue", "unsupported value in CBOR header", { headerValue });
	}
	/** A numeric value was not in its shortest/canonical dCBOR form. */
	static nonCanonicalNumeric() {
		return new CborError("NonCanonicalNumeric", "a CBOR numeric value was encoded in non-canonical form");
	}
	/** A major-type-7 simple value other than false/true/null/float. */
	static invalidSimpleValue() {
		return new CborError("InvalidSimpleValue", "an invalid CBOR simple value was encountered");
	}
	/** A text string was not valid UTF-8 (with the underlying reason). */
	static invalidString(cause) {
		return new CborError("InvalidString", `an invalidly-encoded UTF-8 string was encountered in the CBOR (${cause})`, { cause });
	}
	/** A text string was not in Unicode NFC. */
	static nonCanonicalString() {
		return new CborError("NonCanonicalString", "a CBOR string was not encoded in Unicode Canonical Normalization Form C");
	}
	/** The decoded item left `count` trailing bytes unconsumed. */
	static unusedData(count) {
		return new CborError("UnusedData", `the decoded CBOR had ${count} extra bytes at the end`, { count });
	}
	/** Map keys were not in canonical ascending byte order. */
	static misorderedMapKey() {
		return new CborError("MisorderedMapKey", "the decoded CBOR map has keys that are not in canonical order");
	}
	/** A map contained a duplicate key. */
	static duplicateMapKey() {
		return new CborError("DuplicateMapKey", "the decoded CBOR map has a duplicate key");
	}
	/** A requested map key was not present. */
	static missingMapKey() {
		return new CborError("MissingMapKey", "missing CBOR map key");
	}
	/** A numeric value could not be represented in the target type. */
	static outOfRange() {
		return new CborError("OutOfRange", "the CBOR numeric value could not be represented in the specified numeric type");
	}
	/** The CBOR value was not the type expected by a conversion. */
	static wrongType() {
		return new CborError("WrongType", "the decoded CBOR value was not the expected type");
	}
	/** A tagged value had a tag other than the one expected. */
	static wrongTag(expected, actual) {
		return new CborError("WrongTag", `expected CBOR tag ${tagToString$4(expected)}, but got ${tagToString$4(actual)}`, {
			expectedTag: expected,
			actualTag: actual
		});
	}
	/** Invalid UTF-8 in a text string (with the underlying reason). */
	static invalidUtf8(cause) {
		return new CborError("InvalidUtf8", `invalid UTF‑8 string: ${cause}`, { cause });
	}
	/** Invalid ISO 8601 / RFC 3339 date string (with the underlying reason). */
	static invalidDate(cause) {
		return new CborError("InvalidDate", `invalid ISO 8601 date string: ${cause}`, { cause });
	}
	/** An arbitrary error carrying a custom message. */
	static custom(message) {
		return new CborError("Custom", message);
	}
};
//#endregion
//#region ../bc-dcbor-compat-ts/node_modules/@blockchaincommons/dcbor/dist/tags-store-BZjfminT.mjs
/**
* Byte-array utilities shared across the library.
*
* @module stdlib
*/
/**
* Check if two byte arrays are equal.
*/
const areBytesEqual$2 = (a, b) => {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
};
/**
* Lexicographically compare two byte arrays.
* Returns: -1 if a < b, 0 if a == b, 1 if a > b
*/
const lexicographicallyCompareBytes$2 = (a, b) => {
	const minLen = Math.min(a.length, b.length);
	for (let i = 0; i < minLen; i++) {
		const aVal = a[i];
		const bVal = b[i];
		if (aVal === void 0 || bVal === void 0) throw CborError$4.custom("Unexpected undefined byte in array");
		if (aVal < bVal) return -1;
		if (aVal > bVal) return 1;
	}
	if (a.length < b.length) return -1;
	if (a.length > b.length) return 1;
	return 0;
};
/**
* A map keyed by encoded CBOR key bytes, kept in canonical (lexicographic)
* byte order.
*
* dCBOR needs exactly one specialised container: keys are the encoded bytes of
* a CBOR value, and the map must iterate in ascending lexicographic byte order
* (that ordering is the deterministic wire contract). This is a thin,
* dependency-free structure over a sorted array with binary-search insertion -
* it gives the exact ordering dCBOR requires, and lets the decode hot path
* append in O(1) since canonical input already arrives sorted.
*
* @module sorted-byte-map
*/
var SortedByteMap$2 = class {
	items = [];
	/** Number of entries. */
	get size() {
		return this.items.length;
	}
	/**
	* Binary search for `key`. Returns the index of an exact match, or the
	* negative value `-(insertionPoint) - 1` when absent, so a single search both
	* tests membership and locates where an insert would go (Java
	* `Arrays.binarySearch` convention).
	*/
	indexOf(key) {
		let lo = 0;
		let hi = this.items.length - 1;
		while (lo <= hi) {
			const mid = lo + hi >>> 1;
			const cmp = lexicographicallyCompareBytes$2(this.items[mid].key, key);
			if (cmp < 0) lo = mid + 1;
			else if (cmp > 0) hi = mid - 1;
			else return mid;
		}
		return -(lo + 1);
	}
	/** Insert or replace the entry for `key`. */
	set(key, value) {
		const i = this.indexOf(key);
		if (i >= 0) this.items[i] = {
			key,
			value
		};
		else this.items.splice(-i - 1, 0, {
			key,
			value
		});
	}
	/**
	* Append an entry whose key is strictly greater than every existing key.
	* Used by canonical decode, where keys arrive already sorted; the caller must
	* guarantee the ordering (this skips the search + shift that {@link set} does).
	*/
	appendGreatest(key, value) {
		this.items.push({
			key,
			value
		});
	}
	/** The value for `key`, or `undefined` if absent. */
	get(key) {
		const i = this.indexOf(key);
		return i >= 0 ? this.items[i].value : void 0;
	}
	/** Whether `key` is present. */
	has(key) {
		return this.indexOf(key) >= 0;
	}
	/** Remove `key`; returns whether it was present. */
	delete(key) {
		const i = this.indexOf(key);
		if (i < 0) return false;
		this.items.splice(i, 1);
		return true;
	}
	/** The greatest key currently stored (ascending order), or `undefined`. */
	maxKey() {
		const n = this.items.length;
		return n > 0 ? this.items[n - 1].key : void 0;
	}
	/** Map over each value (with its key) in ascending key order. */
	map(fn) {
		return this.items.map((e) => fn(e.value, e.key));
	}
};
/**
* Numeric boundary contract and helpers.
*
* ## The `number` / `bigint` contract
*
* dCBOR integers span `[-(2^64), 2^64)`, which exceeds JavaScript's safe
* integer range (`±(2^53 − 1)`). The single, repo-wide rule is:
*
* - An integer that fits in the IEEE-754 **safe** range is represented as a
*   `number`; anything larger (in magnitude) is a `bigint`.
* - Decoding returns the **narrowest exact** representation via
*   {@link narrowInteger}, so small values are ergonomic `number`s and large
*   ones remain lossless `bigint`s.
* - Encoding accepts either at the public edge and normalises once.
*
* Every module funnels its boundary logic through this file - nothing else
* should hard-code `Number.MAX_SAFE_INTEGER`, `2^64`, etc.
*
* @module numeric
*/
/** `BigInt(Number.MAX_SAFE_INTEGER)` - largest integer exact as a `number`. */
const SAFE_MAX_BIG$2 = BigInt(Number.MAX_SAFE_INTEGER);
/** `BigInt(Number.MIN_SAFE_INTEGER)`. */
const SAFE_MIN_BIG$2 = BigInt(Number.MIN_SAFE_INTEGER);
/** Smallest dCBOR-encodable integer: −(2^64). */
const CBOR_INT_MIN$2 = -(1n << 64n);
/**
* Return the narrowest exact representation of an integer: a `number` when it
* fits the safe-integer range, otherwise the `bigint` unchanged. This is the
* canonical way to hand an integer back to callers.
*/
const narrowInteger$2 = (value) => value >= SAFE_MIN_BIG$2 && value <= SAFE_MAX_BIG$2 ? Number(value) : value;
/**
* A growable output buffer for encoding.
*
* The encoder writes a whole CBOR tree into a single `BufWriter` rather than
* allocating a fresh `Uint8Array` per node and concatenating them (which
* re-copies every subtree at every level): one buffer, geometric growth, one
* final right-sized copy.
*
* @module buf-writer
*/
var BufWriter$2 = class {
	buf;
	view;
	pos = 0;
	constructor(initialCapacity = 64) {
		this.buf = new Uint8Array(initialCapacity);
		this.view = new DataView(this.buf.buffer);
	}
	/** Number of bytes written so far. */
	get length() {
		return this.pos;
	}
	/** Grow the backing store so at least `extra` more bytes fit. */
	ensure(extra) {
		const needed = this.pos + extra;
		if (needed <= this.buf.length) return;
		let capacity = this.buf.length * 2;
		while (capacity < needed) capacity *= 2;
		const next = new Uint8Array(capacity);
		next.set(this.buf.subarray(0, this.pos));
		this.buf = next;
		this.view = new DataView(next.buffer);
	}
	writeByte(byte) {
		this.ensure(1);
		this.buf[this.pos] = byte;
		this.pos += 1;
	}
	writeUint16(value) {
		this.ensure(2);
		this.view.setUint16(this.pos, value, false);
		this.pos += 2;
	}
	writeUint32(value) {
		this.ensure(4);
		this.view.setUint32(this.pos, value, false);
		this.pos += 4;
	}
	writeBigUint64(value) {
		this.ensure(8);
		this.view.setBigUint64(this.pos, value, false);
		this.pos += 8;
	}
	writeBytes(bytes) {
		this.ensure(bytes.length);
		this.buf.set(bytes, this.pos);
		this.pos += bytes.length;
	}
	/** Return the written region as a right-sized copy. */
	toBytes() {
		return this.buf.slice(0, this.pos);
	}
};
const typeBits$2 = (t) => {
	return t << 5;
};
/**
* Write a CBOR head (major type + argument) straight into `writer`, avoiding
* the intermediate `Uint8Array` that {@link encodeVarInt} allocates. This is
* the encoder hot path (every node emits a head). It MUST stay byte-identical
* to {@link encodeVarInt}; the golden vectors cover both.
*/
const writeVarInt$2 = (writer, value, majorType) => {
	if (value < 0) throw CborError$4.outOfRange();
	if (typeof value === "number" && hasFractionalPart$2(value)) throw CborError$4.outOfRange();
	const type = typeBits$2(majorType);
	if (isCborNumber$4(value) && value <= Number.MAX_SAFE_INTEGER) {
		const n = Number(value);
		if (n <= 23) writer.writeByte(n | type);
		else if (n <= 255) {
			writer.writeByte(24 | type);
			writer.writeByte(n);
		} else if (n <= 65535) {
			writer.writeByte(25 | type);
			writer.writeUint16(n);
		} else if (n <= 4294967295) {
			writer.writeByte(26 | type);
			writer.writeUint32(n);
		} else {
			writer.writeByte(27 | type);
			writer.writeBigUint64(BigInt(n));
		}
	} else {
		const big = BigInt(value);
		if (big > 18446744073709551615n) throw CborError$4.outOfRange();
		writer.writeByte(27 | type);
		writer.writeBigUint64(big);
	}
};
const encodeVarInt$2 = (value, majorType) => {
	if (value < 0) throw CborError$4.outOfRange();
	if (typeof value === "number" && hasFractionalPart$2(value)) throw CborError$4.outOfRange();
	const type = typeBits$2(majorType);
	if (isCborNumber$4(value) && value <= Number.MAX_SAFE_INTEGER) {
		value = Number(value);
		if (value <= 23) return new Uint8Array([value | type]);
		else if (value <= 255) return new Uint8Array([24 | type, value]);
		else if (value <= 65535) {
			const buffer = /* @__PURE__ */ new ArrayBuffer(3);
			const view = new DataView(buffer);
			view.setUint8(0, 25 | type);
			view.setUint16(1, value);
			return new Uint8Array(buffer);
		} else if (value <= 4294967295) {
			const buffer = /* @__PURE__ */ new ArrayBuffer(5);
			const view = new DataView(buffer);
			view.setUint8(0, 26 | type);
			view.setUint32(1, value);
			return new Uint8Array(buffer);
		} else {
			const buffer = /* @__PURE__ */ new ArrayBuffer(9);
			const view = new DataView(buffer);
			view.setUint8(0, 27 | type);
			view.setBigUint64(1, BigInt(value));
			return new Uint8Array(buffer);
		}
	} else {
		const big = BigInt(value);
		if (big > 18446744073709551615n) throw CborError$4.outOfRange();
		const buffer = /* @__PURE__ */ new ArrayBuffer(9);
		const view = new DataView(buffer);
		view.setUint8(0, 27 | type);
		view.setBigUint64(1, big);
		return new Uint8Array(buffer);
	}
};
const hasFract$2 = (n) => {
	return n % 1 !== 0;
};
/**
* Shared float→integer exactness gate for every `Exact<Int>.exactFromF*`. A
* float is an exact integer of a width iff it is finite, whole, and inside that
* width's exclusive `(loEx, hiEx)` bounds (use ±Infinity to skip a side). The
* bounds encode the per-width / per-source-precision limits. The three typed
* wrappers below shape the truncated result.
*/
const isExactIntFloat$2 = (source, loEx, hiEx) => Number.isFinite(source) && source > loEx && source < hiEx && !hasFract$2(source);
/** float → small integer (`number`). */
const intFromFloatNum$2 = (source, loEx, hiEx) => isExactIntFloat$2(source, loEx, hiEx) ? Math.trunc(source) : void 0;
/** float → 64-bit integer (`number` if safe, else `bigint`). */
const intFromFloatNarrow$2 = (source, loEx, hiEx) => isExactIntFloat$2(source, loEx, hiEx) ? narrowInteger$2(BigInt(Math.trunc(source))) : void 0;
/** float → 128-bit integer (`bigint`). */
const intFromFloatBig$2 = (source, loEx, hiEx) => isExactIntFloat$2(source, loEx, hiEx) ? BigInt(Math.trunc(source)) : void 0;
/**
* Exact conversions for i128 (JavaScript bigint).
*/
var ExactI128$2 = class {
	static MIN = -(2n ** 127n);
	static MAX = 2n ** 127n - 1n;
	static exactFromF16(source) {
		return intFromFloatBig$2(source, -Infinity, Infinity);
	}
	static exactFromF32(source) {
		return intFromFloatBig$2(source, -Infinity, Infinity);
	}
	static exactFromF64(source) {
		return intFromFloatBig$2(source, -Infinity, Infinity);
	}
	static exactFromU64(source) {
		return BigInt(source);
	}
	static exactFromI64(source) {
		return BigInt(source);
	}
	static exactFromU128(source) {
		if (source > 2n ** 127n - 1n) return void 0;
		return source;
	}
	static exactFromI128(source) {
		return source;
	}
};
/**
* Exact conversions for u16 (0 to 65535).
*/
var ExactU16$2 = class {
	static MIN = 0;
	static MAX = 65535;
	static exactFromF16(source) {
		return intFromFloatNum$2(source, -1, Infinity);
	}
	static exactFromF32(source) {
		return intFromFloatNum$2(source, -1, 65536);
	}
	static exactFromF64(source) {
		return intFromFloatNum$2(source, -1, 65536);
	}
	static exactFromU64(source) {
		const n = typeof source === "bigint" ? Number(source) : source;
		if (n > 65535) return void 0;
		return n;
	}
	static exactFromI64(source) {
		const n = typeof source === "bigint" ? Number(source) : source;
		if (n < 0 || n > 65535) return void 0;
		return n;
	}
	static exactFromU128(source) {
		if (source > 65535n) return void 0;
		return Number(source);
	}
	static exactFromI128(source) {
		if (source < 0n || source > 65535n) return void 0;
		return Number(source);
	}
};
/**
* Exact conversions for u32 (0 to 4294967295).
*/
var ExactU32$2 = class {
	static MIN = 0;
	static MAX = 4294967295;
	static exactFromF16(source) {
		return intFromFloatNum$2(source, -1, Infinity);
	}
	static exactFromF32(source) {
		return intFromFloatNum$2(source, -1, 4294967296);
	}
	static exactFromF64(source) {
		return intFromFloatNum$2(source, -1, 4294967296);
	}
	static exactFromU64(source) {
		const n = typeof source === "bigint" ? Number(source) : source;
		if (n > 4294967295) return void 0;
		return n;
	}
	static exactFromI64(source) {
		const n = typeof source === "bigint" ? Number(source) : source;
		if (n < 0 || n > 4294967295) return void 0;
		return n;
	}
	static exactFromU128(source) {
		if (source > 4294967295n) return void 0;
		return Number(source);
	}
	static exactFromI128(source) {
		if (source < 0n || source > 4294967295n) return void 0;
		return Number(source);
	}
};
/**
* Exact conversions for u64 (0 to 18446744073709551615).
*/
var ExactU64$2 = class {
	static MIN = 0n;
	static MAX = 18446744073709551615n;
	static exactFromF16(source) {
		return intFromFloatNarrow$2(source, -1, Infinity);
	}
	static exactFromF32(source) {
		return intFromFloatNarrow$2(source, -1, 0x10000000000000000);
	}
	static exactFromF64(source) {
		return intFromFloatNarrow$2(source, -1, 0x10000000000000000);
	}
	static exactFromU64(source) {
		return source;
	}
	static exactFromI64(source) {
		if ((typeof source === "bigint" ? source : BigInt(source)) < 0n) return void 0;
		return source;
	}
	static exactFromU128(source) {
		if (source > 18446744073709551615n) return void 0;
		return narrowInteger$2(source);
	}
	static exactFromI128(source) {
		if (source < 0n || source > 18446744073709551615n) return void 0;
		return narrowInteger$2(source);
	}
};
/**
* Float encoding and conversion utilities for dCBOR.
*
* # Floating Point Number Support in dCBOR
*
* dCBOR provides canonical encoding for floating point values.
*
* Per the dCBOR specification, the canonical encoding rules ensure
* deterministic representation:
*
* - Numeric reduction: Floating point values with zero fractional part in
*   range [-2^63, 2^64-1] are automatically encoded as integers (e.g., 42.0
*   becomes 42)
* - Values are encoded in the smallest possible representation that preserves
*   their value
* - All NaN values are canonicalized to a single representation: 0xf97e00
* - Positive/negative infinity are canonicalized to half-precision
*   representations
*
* @module float
*/
/**
* Canonical NaN representation in CBOR: 0xf97e00
*/
const CBOR_NAN$2 = new Uint8Array([
	249,
	126,
	0
]);
/**
* Check if a number has a fractional part.
*/
const hasFractionalPart$2 = (n) => n !== Math.floor(n);
/**
* Read a big-endian IEEE-754 double from the first 8 bytes of `data`.
* @internal
*/
const binary64ToNumber$2 = (data) => new DataView(data.buffer, data.byteOffset, data.byteLength).getFloat64(0, false);
/**
* Encode a number as 4 big-endian bytes of an IEEE-754 single (f32).
*/
const numberToBinary32$2 = (n) => {
	const data = /* @__PURE__ */ new Uint8Array(4);
	new DataView(data.buffer).setFloat32(0, n, false);
	return data;
};
/**
* Read a big-endian IEEE-754 single (f32) from the first 4 bytes of `data`.
*/
const binary32ToNumber$2 = (data) => new DataView(data.buffer, data.byteOffset, data.byteLength).getFloat32(0, false);
const f32ScratchView$2 = /* @__PURE__ */ new DataView(/* @__PURE__ */ new ArrayBuffer(4));
/**
* Compute the 16-bit pattern of the IEEE-754 half-precision value nearest `n`,
* rounding ties to even.
*
* All call sites pass values already exactly representable in binary16 (the
* reduction gates in {@link f16CborData} ensure this), so no rounding occurs on
* a value that is actually stored; the rounding path exists only so the
* reduction round-trip probe (`binary16ToNumber(numberToBinary16(n)) === n`)
* answers correctly for non-representable inputs.
*/
const float16Bits$2 = (n) => {
	f32ScratchView$2.setFloat32(0, n, false);
	const f = f32ScratchView$2.getUint32(0, false);
	const sign = f >>> 16 & 32768;
	const exp = f >>> 23 & 255;
	const mant = f & 8388607;
	if (exp === 255) return sign | (mant !== 0 ? 32256 : 31744);
	const e = exp - 127 + 15;
	if (e >= 31) return sign | 31744;
	if (e <= 0) {
		if (e < -10) return sign;
		const significand = mant | 8388608;
		const shift = 14 - e;
		let result = significand >>> shift;
		const remainder = significand & (1 << shift) - 1;
		const halfway = 1 << shift - 1;
		if (remainder > halfway || remainder === halfway && (result & 1) === 1) result += 1;
		return sign | result;
	}
	let fraction = mant >>> 13;
	const remainder = mant & 8191;
	let exponent = e;
	if (remainder > 4096 || remainder === 4096 && (fraction & 1) === 1) {
		fraction += 1;
		if (fraction === 1024) {
			fraction = 0;
			exponent += 1;
			if (exponent >= 31) return sign | 31744;
		}
	}
	return sign | exponent << 10 | fraction;
};
/**
* Encode a number as 2 big-endian bytes of an IEEE-754 half (f16).
*/
const numberToBinary16$2 = (n) => {
	const bits = float16Bits$2(n);
	return new Uint8Array([bits >> 8 & 255, bits & 255]);
};
/**
* Read a big-endian IEEE-754 half (f16) from the first 2 bytes of `data`.
*/
const binary16ToNumber$2 = (data) => {
	const bits = data[0] << 8 | data[1];
	const sign = (bits & 32768) !== 0 ? -1 : 1;
	const exponent = bits >> 10 & 31;
	const fraction = bits & 1023;
	if (exponent === 0) return sign * fraction * 2 ** -24;
	if (exponent === 31) return fraction !== 0 ? NaN : sign * Infinity;
	return sign * (1 + fraction / 1024) * 2 ** (exponent - 15);
};
/**
* Encode f64 value to CBOR data bytes.
* Implements numeric reduction and canonical encoding rules.
* @internal
*/
const f64CborData$2 = (value) => {
	const n = value;
	const f32Bytes = numberToBinary32$2(n);
	const f = binary32ToNumber$2(f32Bytes);
	if (f === n) return f32CborData$2(f);
	if (n < 0) {
		const i128 = ExactI128$2.exactFromF64(n);
		if (i128 !== void 0) {
			const i = ExactU64$2.exactFromI128(-1n - i128);
			if (i !== void 0) return encodeVarInt$2(i, MajorType$4.Negative);
		}
	}
	const u = ExactU64$2.exactFromF64(n);
	if (u !== void 0) return encodeVarInt$2(u, MajorType$4.Unsigned);
	if (Number.isNaN(value)) return CBOR_NAN$2;
	const buffer = /* @__PURE__ */ new ArrayBuffer(8);
	new DataView(buffer).setFloat64(0, n, false);
	const bytes = new Uint8Array(buffer);
	return new Uint8Array([251, ...bytes]);
};
/**
* Encode f32 value to CBOR data bytes.
* Implements numeric reduction and canonical encoding rules.
* @internal
*/
const f32CborData$2 = (value) => {
	const n = value;
	const f16Bytes = numberToBinary16$2(n);
	const f = binary16ToNumber$2(f16Bytes);
	if (f === n) return f16CborData$2(f);
	if (n < 0) {
		const u = ExactU64$2.exactFromF32(Math.fround(-1 - n));
		if (u !== void 0) return encodeVarInt$2(u, MajorType$4.Negative);
	}
	const u = ExactU32$2.exactFromF32(n);
	if (u !== void 0) return encodeVarInt$2(u, MajorType$4.Unsigned);
	if (Number.isNaN(value)) return CBOR_NAN$2;
	const bytes = numberToBinary32$2(n);
	return new Uint8Array([250, ...bytes]);
};
/**
* Encode f16 value to CBOR data bytes.
* Implements numeric reduction and canonical encoding rules.
* @internal
*/
const f16CborData$2 = (value) => {
	const n = value;
	if (n < 0) {
		const u = ExactU64$2.exactFromF64(-1 - n);
		if (u !== void 0) return encodeVarInt$2(u, MajorType$4.Negative);
	}
	const u = ExactU16$2.exactFromF64(n);
	if (u !== void 0) return encodeVarInt$2(u, MajorType$4.Unsigned);
	if (Number.isNaN(value)) return CBOR_NAN$2;
	const bytes = numberToBinary16$2(value);
	return new Uint8Array([249, ...bytes]);
};
/**
* Render a float to its diagnostic string.
*
* Finite non-zero values with magnitude in [1e-4, 1e16) print in decimal with
* at least one fractional digit (whole values get a trailing `.0`); everything
* else prints in exponential form. Zero prints as `0.0`/`-0.0`.
*
* JS already produces the same shortest round-tripping digits; we only fix up
* the notation threshold, the `e+` → `e` exponent, and the `.0` suffix.
*
* @param value - The float value
* @returns The diagnostic string
*/
const floatDisplayString$2 = (value) => {
	if (Number.isNaN(value)) return "NaN";
	if (!Number.isFinite(value)) return value > 0 ? "Infinity" : "-Infinity";
	if (value === 0) return Object.is(value, -0) ? "-0.0" : "0.0";
	const abs = Math.abs(value);
	if (abs >= 1e-4 && abs < 0x2386f26fc10000) {
		let str = String(value);
		if (!str.includes(".")) str = `${str}.0`;
		return str;
	}
	return value.toExponential().replace("e+", "e");
};
/**
* A forward-only cursor over the input bytes.
*
* Decoding advances a single `pos` through one shared `DataView` rather than
* slicing a fresh sub-view per nested item and threading a consumed-length back
* up the recursion. Every read is bounds-checked against the remaining bytes.
*/
var ByteReader$2 = class {
	view;
	pos = 0;
	constructor(data) {
		this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
	}
	get byteLength() {
		return this.view.byteLength;
	}
	get remaining() {
		return this.view.byteLength - this.pos;
	}
	/** Read the byte at `offset` relative to the current position (no advance). */
	peek(offset) {
		return this.view.getUint8(this.pos + offset);
	}
	/** Advance the cursor by `count` bytes. */
	advance(count) {
		this.pos += count;
	}
	/** A zero-copy view of `len` bytes at the given absolute offset. */
	bytesAt(offset, len) {
		return new Uint8Array(this.view.buffer, this.view.byteOffset + offset, len);
	}
};
/**
* Decode a single dCBOR item from `data`, enforcing every deterministic
* encoding rule (canonical numeric forms, NFC text, map-key order, no
* trailing bytes). Throws {@link CborError} on any violation.
*
* @example
* ```typescript
* const value = decodeCbor(hexToBytes("a1616101")); // {"a": 1}
* expectMap(value).size; // 1
* ```
*
* @throws {CborError} `Underrun` | `UnsupportedHeaderValue` |
*   `NonCanonicalNumeric` | `InvalidSimpleValue` | `InvalidUtf8` |
*   `NonCanonicalString` | `UnusedData` | `MisorderedMapKey` |
*   `DuplicateMapKey` - see {@link CborErrorDetailsByCode}.
* @public
*
* @remarks Decoded byte strings are zero-copy views aliasing the input
* buffer - mutating the input after decoding (or mutating the returned
* bytes) changes the other side. Call `.slice()` first if you need an
* independent copy. This is deliberate: the zero-copy decode performance
* profile is part of the library's contract.
*/
function decodeCbor$4(data) {
	const reader = new ByteReader$2(data);
	const cbor = readCbor$2(reader);
	const remaining = reader.byteLength - reader.pos;
	if (remaining !== 0) throw CborError$4.unusedData(remaining);
	return cbor;
}
function parseHeader$2(header) {
	return {
		majorType: header >> 5,
		headerValue: header & 31
	};
}
/**
* Read a CBOR head (major type + argument) at the cursor, advancing past it.
* `varIntLen` is the head length (1/2/3/5/9); the argument value is validated
* for canonical minimal-length encoding.
*/
function readHeaderVarint$2(reader) {
	if (reader.remaining < 1) throw CborError$4.underrun();
	const header = reader.peek(0);
	const { majorType, headerValue } = parseHeader$2(header);
	const dataRemaining = reader.remaining - 1;
	let value;
	let varIntLen;
	if (headerValue <= 23) {
		value = headerValue;
		varIntLen = 1;
	} else if (headerValue === 24) {
		if (dataRemaining < 1) throw CborError$4.underrun();
		value = reader.peek(1);
		if (value < 24) throw CborError$4.nonCanonicalNumeric();
		varIntLen = 2;
	} else if (headerValue === 25) {
		if (dataRemaining < 2) throw CborError$4.underrun();
		value = (reader.peek(1) << 8 | reader.peek(2)) >>> 0;
		if (value <= 255 && header !== 249) throw CborError$4.nonCanonicalNumeric();
		varIntLen = 3;
	} else if (headerValue === 26) {
		if (dataRemaining < 4) throw CborError$4.underrun();
		value = (reader.peek(1) << 24 | reader.peek(2) << 16 | reader.peek(3) << 8 | reader.peek(4)) >>> 0;
		if (value <= 65535 && header !== 250) throw CborError$4.nonCanonicalNumeric();
		varIntLen = 5;
	} else if (headerValue === 27) {
		if (dataRemaining < 8) throw CborError$4.underrun();
		const a = BigInt(reader.peek(1)) << 56n;
		const b = BigInt(reader.peek(2)) << 48n;
		const c = BigInt(reader.peek(3)) << 40n;
		const d = BigInt(reader.peek(4)) << 32n;
		const e = BigInt(reader.peek(5)) << 24n;
		const f = BigInt(reader.peek(6)) << 16n;
		const g = BigInt(reader.peek(7)) << 8n;
		const h = BigInt(reader.peek(8));
		value = narrowInteger$2(a | b | c | d | e | f | g | h);
		if (value <= 4294967295 && header !== 251) throw CborError$4.nonCanonicalNumeric();
		varIntLen = 9;
	} else throw CborError$4.unsupportedHeaderValue(headerValue);
	reader.advance(varIntLen);
	return {
		majorType,
		value,
		varIntLen
	};
}
function readCbor$2(reader) {
	if (reader.remaining < 1) throw CborError$4.underrun();
	const headStart = reader.pos;
	const { majorType, value, varIntLen } = readHeaderVarint$2(reader);
	switch (majorType) {
		case MajorType$4.Unsigned: {
			const cbor = attachMethods$4({
				isCbor: true,
				type: MajorType$4.Unsigned,
				value
			});
			checkCanonicalEncoding$2(cbor, reader.bytesAt(headStart, varIntLen));
			return cbor;
		}
		case MajorType$4.Negative: {
			const cbor = attachMethods$4({
				isCbor: true,
				type: MajorType$4.Negative,
				value
			});
			checkCanonicalEncoding$2(cbor, reader.bytesAt(headStart, varIntLen));
			return cbor;
		}
		case MajorType$4.ByteString: {
			if (typeof value === "bigint") throw CborError$4.underrun();
			if (reader.remaining < value) throw CborError$4.underrun();
			const bytes = reader.bytesAt(reader.pos, value);
			reader.advance(value);
			return attachMethods$4({
				isCbor: true,
				type: MajorType$4.ByteString,
				value: bytes
			});
		}
		case MajorType$4.Text: {
			if (typeof value === "bigint") throw CborError$4.underrun();
			if (reader.remaining < value) throw CborError$4.underrun();
			const textBytes = reader.bytesAt(reader.pos, value);
			reader.advance(value);
			let text;
			try {
				text = new TextDecoder("utf-8", { fatal: true }).decode(textBytes);
			} catch (e) {
				throw CborError$4.invalidUtf8(e instanceof Error ? e.message : String(e));
			}
			if (text.normalize("NFC") !== text) throw CborError$4.nonCanonicalString();
			return attachMethods$4({
				isCbor: true,
				type: MajorType$4.Text,
				value: text
			});
		}
		case MajorType$4.Array: {
			const items = [];
			for (let i = 0; i < value; i++) items.push(readCbor$2(reader));
			return attachMethods$4({
				isCbor: true,
				type: MajorType$4.Array,
				value: items
			});
		}
		case MajorType$4.Map: {
			const map = new CborMap$4();
			for (let i = 0; i < value; i++) {
				const key = readCbor$2(reader);
				const val = readCbor$2(reader);
				map.setNext(key, val);
			}
			return attachMethods$4({
				isCbor: true,
				type: MajorType$4.Map,
				value: map
			});
		}
		case MajorType$4.Tagged: {
			const item = readCbor$2(reader);
			return attachMethods$4({
				isCbor: true,
				type: MajorType$4.Tagged,
				tag: value,
				value: item
			});
		}
		case MajorType$4.Simple: switch (varIntLen) {
			case 3: {
				const f = binary16ToNumber$2(reader.bytesAt(headStart + 1, 2));
				checkCanonicalEncoding$2(f, reader.bytesAt(headStart, varIntLen));
				return attachMethods$4({
					isCbor: true,
					type: MajorType$4.Simple,
					value: {
						type: "Float",
						value: f
					}
				});
			}
			case 5: {
				const f = binary32ToNumber$2(reader.bytesAt(headStart + 1, 4));
				checkCanonicalEncoding$2(f, reader.bytesAt(headStart, varIntLen));
				return attachMethods$4({
					isCbor: true,
					type: MajorType$4.Simple,
					value: {
						type: "Float",
						value: f
					}
				});
			}
			case 9: {
				const f = binary64ToNumber$2(reader.bytesAt(headStart + 1, 8));
				checkCanonicalEncoding$2(f, reader.bytesAt(headStart, varIntLen));
				return attachMethods$4({
					isCbor: true,
					type: MajorType$4.Simple,
					value: {
						type: "Float",
						value: f
					}
				});
			}
			default: switch (value) {
				case 20: return attachMethods$4({
					isCbor: true,
					type: MajorType$4.Simple,
					value: { type: "False" }
				});
				case 21: return attachMethods$4({
					isCbor: true,
					type: MajorType$4.Simple,
					value: { type: "True" }
				});
				case 22: return attachMethods$4({
					isCbor: true,
					type: MajorType$4.Simple,
					value: { type: "Null" }
				});
				default: throw CborError$4.invalidSimpleValue();
			}
		}
	}
}
function checkCanonicalEncoding$2(cbor, buf) {
	if (!areBytesEqual$2(buf, encodeCbor$5(cbor))) throw CborError$4.nonCanonicalNumeric();
}
/**
* Extract native JavaScript value from CBOR.
* Converts CBOR types to their JavaScript equivalents.
*
* Returns the closed union {@link CborNative}. Note the two asymmetries
* documented there: maps come back as `CborMap` and tagged values as `Cbor`.
*/
const extractCbor$4 = (cbor) => {
	let c;
	if (cbor instanceof Uint8Array) c = decodeCbor$4(cbor);
	else c = cbor;
	switch (c.type) {
		case MajorType$4.Unsigned: return c.value;
		case MajorType$4.Negative: if (typeof c.value === "bigint") return -c.value - 1n;
		else return -c.value - 1;
		case MajorType$4.ByteString: return c.value;
		case MajorType$4.Text: return c.value;
		case MajorType$4.Array: return c.value.map(extractCbor$4);
		case MajorType$4.Map: return c.value;
		case MajorType$4.Tagged: return c;
		case MajorType$4.Simple: {
			const simple = c.value;
			switch (simple.type) {
				case "True": return true;
				case "False": return false;
				case "Null": return null;
				case "Float": return simple.value;
				default: return simple;
			}
		}
		default: return c;
	}
};
/**
* Map Support in dCBOR
*
* A deterministic CBOR map implementation that ensures maps with the same
* content always produce identical binary encodings, regardless of insertion
* order.
*
* ## Deterministic Map Representation
*
* The `CborMap` type follows strict deterministic encoding rules as specified by
* dCBOR:
*
* - Map keys are always sorted in lexicographic order of their encoded CBOR bytes
* - Duplicate keys are not allowed (enforced by the implementation)
* - Keys and values can be any type that can be converted to CBOR
* - Numeric reduction is applied (e.g., 3.0 is stored as integer 3)
*
* ## Vocabulary
*
* `CborMap` mirrors the JS `Map` protocol: `set`, `get`, `getOrThrow`, `has`,
* `delete`, `clear`, `size`, `keys()`, `values()`, `entries()`, `forEach`,
* iteration. `get` returns the STORED `Cbor` node (symmetric with
* `entries()`); extract natives explicitly with `extractCbor(map.get(k))`.
*
* @module map
*/
/**
* A deterministic CBOR map implementation.
*
* Maps are always encoded with keys sorted lexicographically by their
* encoded CBOR representation, ensuring deterministic encoding.
*/
var CborMap$4 = class {
	/** Debug label: `Object.prototype.toString` reports `[object CborMap]`. */
	get [Symbol.toStringTag]() {
		return "CborMap";
	}
	_dict;
	/**
	* Creates a new, empty CBOR Map.
	* Optionally initializes from a JavaScript Map (every key and value must
	* itself be encodable).
	*/
	constructor(map) {
		this._dict = new SortedByteMap$2();
		if (map !== void 0) for (const [key, value] of map.entries()) this.set(key, value);
	}
	/**
	* Inserts a key-value pair into the map (replacing any entry whose key has
	* the same canonical encoding). Any insertion order is accepted - entries
	* are kept in canonical ascending encoded-key order.
	*
	* @example
	* ```typescript
	* const m = new CborMap();
	* m.set("z", 1);
	* m.set(10, "ten"); // sorts before "z" in the encoding
	* encodeCbor(m);    // deterministic regardless of insertion order
	* ```
	* @public
	*/
	set(key, value) {
		const keyCbor = cbor$4(key);
		const valueCbor = cbor$4(value);
		const keyData = encodeCbor$5(keyCbor);
		this._dict.set(keyData, {
			key: keyCbor,
			value: valueCbor
		});
	}
	_makeKey(key) {
		return encodeCbor$5(cbor$4(key));
	}
	/**
	* Get the STORED `Cbor` node for a key, or `undefined` if absent.
	*
	* This is symmetric with `entries()` - no hidden native extraction, no
	* unwitnessed generics. To read a native value, compose explicitly:
	*
	* ```typescript
	* asNumber(map.get("age"));          // number | undefined, checked
	* extractCbor(map.getOrThrow("age")); // CborNative, throws if absent
	* ```
	* @public
	*/
	get(key) {
		return this._dict.get(this._makeKey(key))?.value;
	}
	/**
	* Get the stored `Cbor` node for a key.
	*
	* @throws {CborError} `MissingMapKey` - the key is not present.
	*/
	getOrThrow(key) {
		const value = this.get(key);
		if (value === void 0) throw CborError$4.missingMapKey();
		return value;
	}
	delete(key) {
		const keyData = this._makeKey(key);
		const existed = this._dict.has(keyData);
		this._dict.delete(keyData);
		return existed;
	}
	has(key) {
		return this._dict.has(this._makeKey(key));
	}
	clear() {
		this._dict = new SortedByteMap$2();
	}
	/** The number of entries in the map. */
	get size() {
		return this._dict.size;
	}
	/**
	* Get the entries of the map as an array, sorted in canonical ascending
	* encoded-key order.
	*
	* @internal Public because the encoder, diagnostic formatter, and hex
	* annotator consume it cross-module; not part of the supported surface.
	*/
	get entriesArray() {
		return this._dict.map((value, _key) => ({
			key: value.key,
			value: value.value
		}));
	}
	/** Iterate keys in canonical (sorted encoded-key) order. */
	*keys() {
		for (const entry of this.entriesArray) yield entry.key;
	}
	/** Iterate values in canonical key order. */
	*values() {
		for (const entry of this.entriesArray) yield entry.value;
	}
	/**
	* Iterate `[key, value]` tuples in canonical key order (the JS
	* `Map.entries()` shape).
	*/
	*entries() {
		for (const entry of this.entriesArray) yield [entry.key, entry.value];
	}
	/** JS `Map.forEach` mirror (value first, then key, then the map). */
	forEach(callback, thisArg) {
		for (const entry of this.entriesArray) callback.call(thisArg, entry.value, entry.key, this);
	}
	*[Symbol.iterator]() {
		for (const entry of this.entriesArray) yield [entry.key, entry.value];
	}
	/**
	* Inserts the next key-value pair into the map during decoding.
	* This is used for efficient map building during CBOR decoding.
	* Throws if the key is not in ascending order or is a duplicate.
	*
	* @internal The decoder's append path; not part of the supported surface.
	*/
	setNext(key, value) {
		const keyCbor = cbor$4(key);
		const newKey = encodeCbor$5(keyCbor);
		if (this._dict.has(newKey)) throw CborError$4.duplicateMapKey();
		const greatest = this._dict.maxKey();
		if (greatest !== void 0) {
			if (lexicographicallyCompareBytes$2(newKey, greatest) <= 0) throw CborError$4.misorderedMapKey();
		}
		this._dict.appendGreatest(newKey, {
			key: keyCbor,
			value: cbor$4(value)
		});
	}
	/**
	* Convert to a plain JavaScript `Map` of extracted native values.
	* Tagged values come back as `Cbor` nodes and nested maps as `CborMap`
	* (the {@link CborNative} asymmetries).
	*/
	toMap() {
		const map = /* @__PURE__ */ new Map();
		for (const entry of this.entriesArray) map.set(extractCbor$4(entry.key), extractCbor$4(entry.value));
		return map;
	}
};
/**
* Encodes the simple value to its raw CBOR byte representation.
*
* Returns the CBOR bytes that represent this simple value according to the
* dCBOR deterministic encoding rules:
* - `False` encodes as `0xf4`
* - `True` encodes as `0xf5`
* - `Null` encodes as `0xf6`
* - `Float` values encode according to the IEEE 754 floating point rules,
*   using the shortest representation that preserves precision.
*/
const simpleCborData$2 = (simple) => {
	switch (simple.type) {
		case "False": return encodeVarInt$2(20, MajorType$4.Simple);
		case "True": return encodeVarInt$2(21, MajorType$4.Simple);
		case "Null": return encodeVarInt$2(22, MajorType$4.Simple);
		case "Float": return f64CborData$2(simple.value);
	}
};
Uint8Array.fromHex;
/**
* Convert bytes to a lowercase hex string.
*
* Delegates to the native `Uint8Array.prototype.toHex` where available.
*/
const bytesToHex$5 = (bytes) => {
	const native = bytes.toHex;
	if (typeof native === "function") return native.call(bytes);
	let out = "";
	for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
	return out;
};
/**
* The dCBOR value core: the `Cbor` union type, the polymorphic constructor
* `cbor()`, the encoder entry `encodeCbor()`, and the tagged-value
* constructor `taggedValue()`.
*
* ## The API in one paragraph
*
* Construct with `cbor(input)` (the single polymorphic constructor) or
* `taggedValue(tag, content)` (the only explicit tagged-value constructor);
* custom types participate by implementing the one structural protocol
* `ToCbor { toCbor(): Cbor }`. Encode with `encodeCbor(value)`. Decode with
* `decodeCbor(bytes)` (throws) or `tryDecode(bytes)` (returns `Result`).
* Read with the free `isX`/`asX`/`expectX` accessor functions. The only
* instance conveniences on a `Cbor` value are `toData()`, `toHex()`, and a
* cheap `toString()`.
*
* @module cbor
*/
/**
* The instance methods shared by every `Cbor` value: exactly three cheap
* conveniences (plus debug symbols below). Everything else is a free function
* so decode-only bundles never carry the diagnostic formatter, hex annotator,
* tag store, or walker.
*
* `String(c)`/template literals/`console.log` produce `Cbor(0x…)`. Diagnostic
* rendering lives in `@blockchaincommons/dcbor/diagnostic`; opt-in diag-flavored debug
* output lives in `@blockchaincommons/dcbor/debug` (`installDebugHooks()`).
*/
const CBOR_METHODS$2 = {
	toData() {
		return encodeCbor$5(this);
	},
	toHex() {
		return bytesToHex$5(encodeCbor$5(this));
	},
	toString() {
		return `Cbor(0x${bytesToHex$5(encodeCbor$5(this))})`;
	},
	[Symbol.toStringTag]: "Cbor",
	[Symbol.for("nodejs.util.inspect.custom")]() {
		return this.toString();
	}
};
/**
* Decorate a bare CBOR value (`{ isCbor, type, value[, tag] }`) with the shared
* instance methods. The methods live on {@link CBOR_METHODS} and are installed
* via the prototype - constructed with `Object.create` (not `setPrototypeOf`,
* which would drop the object off V8's fast path). Only the handful of data
* properties are own-properties; the methods are shared, not per-object.
*
* @internal
*/
const attachMethods$4 = (obj) => {
	const decorated = Object.create(CBOR_METHODS$2);
	return Object.assign(decorated, obj);
};
const CBOR_FALSE$2 = attachMethods$4({
	isCbor: true,
	type: MajorType$4.Simple,
	value: { type: "False" }
});
const CBOR_TRUE$2 = attachMethods$4({
	isCbor: true,
	type: MajorType$4.Simple,
	value: { type: "True" }
});
const CBOR_NULL$2 = attachMethods$4({
	isCbor: true,
	type: MajorType$4.Simple,
	value: { type: "Null" }
});
const hasTaggedCbor$4 = (value) => {
	return typeof value === "object" && value !== null && "taggedCbor" in value && typeof value.taggedCbor === "function";
};
const hasToCbor$4 = (value) => {
	return typeof value === "object" && value !== null && "toCbor" in value && typeof value.toCbor === "function";
};
/**
* Convert any supported value to its CBOR representation - the single
* polymorphic constructor.
*
* Custom types participate by implementing {@link ToCbor}
* (`toCbor(): Cbor` - the `toJSON` precedent). Tagged values are built with
* {@link taggedValue}.
*
* @example
* ```typescript
* cbor(42);                          // integer
* cbor("héllo");                     // NFC-normalized text
* cbor([1, "two", true, null]);      // array
* cbor(new Map([["k", 1]]));         // map (canonical key order)
* cbor({ name: "Alice", age: 30 });  // plain object -> map
* ```
*
* @throws {CborError} `OutOfRange` - bigint outside `[-(2^64), 2^64 - 1]`.
* @throws {CborError} `Custom` - unsupported input type, or one of the two
*   directive errors below.
* @public
*
* ## Directive errors
*
* Two input shapes throw a directive `CborError` because encoding them
* silently would produce ambiguous or divergent bytes:
*
* - plain objects shaped exactly `{tag, value}`: use
*   `taggedValue(tag, content)` for a tagged value, or add/rename a key for
*   a map;
* - objects implementing `taggedCbor()` but not `toCbor()`: add
*   `toCbor() { return this.taggedCbor(); }`.
*/
const cbor$4 = (value) => {
	if (isCbor$4(value) && "toData" in value) return value;
	if (isCbor$4(value)) return attachMethods$4(value);
	let result;
	if (isCborNumber$4(value)) if (typeof value === "number" && Number.isNaN(value)) result = {
		isCbor: true,
		type: MajorType$4.Simple,
		value: {
			type: "Float",
			value: NaN
		}
	};
	else if (typeof value === "number" && hasFractionalPart$2(value)) result = {
		isCbor: true,
		type: MajorType$4.Simple,
		value: {
			type: "Float",
			value
		}
	};
	else if (value == Infinity) result = {
		isCbor: true,
		type: MajorType$4.Simple,
		value: {
			type: "Float",
			value: Infinity
		}
	};
	else if (value == -Infinity) result = {
		isCbor: true,
		type: MajorType$4.Simple,
		value: {
			type: "Float",
			value: -Infinity
		}
	};
	else if (typeof value === "number" && !Number.isSafeInteger(value)) {
		const big = BigInt(value);
		if (big >= 0n && big <= 18446744073709551615n) result = {
			isCbor: true,
			type: MajorType$4.Unsigned,
			value: big
		};
		else if (big < 0n && big >= CBOR_INT_MIN$2) result = {
			isCbor: true,
			type: MajorType$4.Negative,
			value: -big - 1n
		};
		else result = {
			isCbor: true,
			type: MajorType$4.Simple,
			value: {
				type: "Float",
				value
			}
		};
	} else if (typeof value === "bigint" && (value > 18446744073709551615n || value < CBOR_INT_MIN$2)) throw CborError$4.outOfRange();
	else if (value < 0) if (typeof value === "bigint") result = {
		isCbor: true,
		type: MajorType$4.Negative,
		value: -value - 1n
	};
	else result = {
		isCbor: true,
		type: MajorType$4.Negative,
		value: -value - 1
	};
	else result = {
		isCbor: true,
		type: MajorType$4.Unsigned,
		value
	};
	else if (typeof value === "string") {
		const normalized = value.normalize("NFC");
		result = {
			isCbor: true,
			type: MajorType$4.Text,
			value: normalized
		};
	} else if (value === null || value === void 0) return CBOR_NULL$2;
	else if (value === true) return CBOR_TRUE$2;
	else if (value === false) return CBOR_FALSE$2;
	else if (Array.isArray(value)) result = {
		isCbor: true,
		type: MajorType$4.Array,
		value: value.map(cbor$4)
	};
	else if (value instanceof Uint8Array) result = {
		isCbor: true,
		type: MajorType$4.ByteString,
		value
	};
	else if (value instanceof CborMap$4) result = {
		isCbor: true,
		type: MajorType$4.Map,
		value
	};
	else if (value instanceof Map) result = {
		isCbor: true,
		type: MajorType$4.Map,
		value: new CborMap$4(value)
	};
	else if (value instanceof Set) result = {
		isCbor: true,
		type: MajorType$4.Array,
		value: Array.from(value).map(cbor$4)
	};
	else if (hasToCbor$4(value)) return value.toCbor();
	else if (hasTaggedCbor$4(value)) throw CborError$4.custom("objects implementing taggedCbor() are no longer auto-wrapped by cbor(); implement toCbor() (e.g. `toCbor() { return this.taggedCbor(); }`)");
	else if (typeof value === "object" && "tag" in value && "value" in value) {
		const keys = Object.keys(value);
		if (keys.length === 2 && keys.includes("tag") && keys.includes("value")) throw CborError$4.custom("plain { tag, value } objects are ambiguous and no longer encode as tagged values; use taggedValue(tag, content) for a tagged value, or add/rename a key to encode a map");
		const map = new CborMap$4();
		for (const [key, val] of Object.entries(value)) map.set(cbor$4(key), cbor$4(val));
		result = {
			isCbor: true,
			type: MajorType$4.Map,
			value: map
		};
	} else if (typeof value === "object") {
		const map = new CborMap$4();
		for (const [key, val] of Object.entries(value)) map.set(cbor$4(key), cbor$4(val));
		result = {
			isCbor: true,
			type: MajorType$4.Map,
			value: map
		};
	} else throw CborError$4.custom("Unsupported type for CBOR encoding");
	return attachMethods$4(result);
};
const textEncoder$2 = new TextEncoder();
/**
* Write a CBOR value into `writer`. The whole tree encodes into one growable
* buffer, so nested containers don't allocate-and-concatenate a fresh array
* per level.
*/
const writeCborInto$2 = (writer, value) => {
	const c = cbor$4(value);
	switch (c.type) {
		case MajorType$4.Unsigned:
			writeVarInt$2(writer, c.value, MajorType$4.Unsigned);
			return;
		case MajorType$4.Negative:
			writeVarInt$2(writer, c.value, MajorType$4.Negative);
			return;
		case MajorType$4.ByteString:
			if (c.value instanceof Uint8Array) {
				writeVarInt$2(writer, c.value.length, MajorType$4.ByteString);
				writer.writeBytes(c.value);
				return;
			}
			break;
		case MajorType$4.Text:
			if (typeof c.value === "string") {
				const utf8Bytes = textEncoder$2.encode(c.value);
				writeVarInt$2(writer, utf8Bytes.length, MajorType$4.Text);
				writer.writeBytes(utf8Bytes);
				return;
			}
			break;
		case MajorType$4.Tagged:
			if (typeof c.tag === "bigint" || typeof c.tag === "number") {
				writeVarInt$2(writer, c.tag, MajorType$4.Tagged);
				writeCborInto$2(writer, c.value);
				return;
			}
			break;
		case MajorType$4.Simple:
			writer.writeBytes(simpleCborData$2(c.value));
			return;
		case MajorType$4.Array:
			writeVarInt$2(writer, c.value.length, MajorType$4.Array);
			for (const item of c.value) writeCborInto$2(writer, item);
			return;
		case MajorType$4.Map: {
			const entries = c.value.entriesArray;
			writeVarInt$2(writer, entries.length, MajorType$4.Map);
			for (const { key, value: entryValue } of entries) {
				writeCborInto$2(writer, key);
				writeCborInto$2(writer, entryValue);
			}
			return;
		}
	}
	throw CborError$4.wrongType();
};
/**
* Encode a value to deterministic CBOR bytes. Accepts anything `cbor()`
* accepts; equal values always produce identical bytes (dCBOR determinism).
*
* @example
* ```typescript
* encodeCbor({ a: 1 });            // Uint8Array [0xa1, 0x61, 0x61, 0x01]
* bytesToHex(encodeCbor("Hello")); // "6548656c6c6f"
* ```
*
* @throws {CborError} Whatever `cbor(value)` throws for unsupported inputs
*   (`OutOfRange`, `Custom`).
* @remarks The decoder's canonicality check re-encodes every decoded value
*   through this function, so it is wire-critical.
* @public
*/
const encodeCbor$5 = (value) => {
	const c = cbor$4(value);
	switch (c.type) {
		case MajorType$4.Unsigned: return encodeVarInt$2(c.value, MajorType$4.Unsigned);
		case MajorType$4.Negative: return encodeVarInt$2(c.value, MajorType$4.Negative);
		case MajorType$4.Simple: return simpleCborData$2(c.value);
		default: {
			const writer = new BufWriter$2();
			writeCborInto$2(writer, c);
			return writer.toBytes();
		}
	}
};
/**
* Construct a tagged value - the ONLY explicit tagged-value constructor.
*
* @example
* ```typescript
* taggedValue(1, 1675854714);        // epoch date, tag 1
* taggedValue(Tag.from(32), "https://example.com/"); // URI, tag 32
* ```
*
* @param tag - The tag number (`number | bigint`) or a `Tag` object (its
*   `.value` is used; names never reach the wire).
* @param content - Anything `cbor()` accepts.
* @public
*/
const taggedValue = (tag, content) => {
	const tagVal = typeof tag === "object" && "value" in tag ? tag.value : tag;
	return attachMethods$4({
		isCbor: true,
		type: MajorType$4.Tagged,
		tag: tagVal,
		value: cbor$4(content)
	});
};
/**
* Tag registry implementation.
*
* Stores tags with their names and optional summarizer functions.
*/
var TagsStore$4 = class {
	/** Debug label: `Object.prototype.toString` reports `[object TagsStore]`. */
	get [Symbol.toStringTag]() {
		return "TagsStore";
	}
	_tagsByValue = /* @__PURE__ */ new Map();
	_tagsByName = /* @__PURE__ */ new Map();
	_summarizers = /* @__PURE__ */ new Map();
	constructor() {}
	/**
	* Insert a tag into the registry.
	*
	* - Throws if the tag name is undefined or empty
	* - Throws if a tag with the same value exists with a different name
	* - Allows re-registering the same tag value with the same name
	*
	* @param tag - The tag to register (must have a non-empty name)
	* @throws Error if tag has no name, empty name, or conflicts with existing registration
	*
	* @example
	* ```typescript
	* const store = new TagsStore();
	* store.register(Tag.from(12345, 'myCustomTag'));
	* ```
	*/
	register(tag) {
		const name = tag.name;
		if (name === void 0 || name === "") throw new Error(`Tag ${tag.value} must have a non-empty name`);
		const key = this._valueKey(tag.value);
		const existing = this._tagsByValue.get(key);
		if (existing?.name !== void 0 && existing.name !== name) throw new Error(`Attempt to register tag: ${tag.value} '${existing.name}' with different name: '${name}'`);
		this._tagsByValue.set(key, tag);
		this._tagsByName.set(name, tag);
	}
	/**
	* Register multiple tags; the conflict-throwing validation in `register()`
	* applies per tag.
	*/
	registerAll(tags) {
		for (const tag of tags) this.register(tag);
	}
	/**
	* Register a custom summarizer function for a tag.
	*
	* @param tagValue - The numeric tag value
	* @param summarizer - The summarizer function
	*
	* @example
	* ```typescript
	* store.setSummarizer(1, (cbor, flat) => {
	*   // Custom date formatting
	*   return `Date(${extractCbor(cbor)})`;
	* });
	* ```
	*/
	setSummarizer(tagValue, summarizer) {
		const key = this._valueKey(tagValue);
		this._summarizers.set(key, summarizer);
	}
	assignedNameForTag(tag) {
		const key = this._valueKey(tag.value);
		return this._tagsByValue.get(key)?.name;
	}
	nameForTag(tag) {
		return this.assignedNameForTag(tag) ?? tag.value.toString();
	}
	tagForValue(value) {
		const key = this._valueKey(value);
		return this._tagsByValue.get(key);
	}
	tagForName(name) {
		return this._tagsByName.get(name);
	}
	nameForValue(value) {
		const tag = this.tagForValue(value);
		return tag !== void 0 ? this.nameForTag(tag) : value.toString();
	}
	summarizer(tag) {
		const key = this._valueKey(tag);
		return this._summarizers.get(key);
	}
	/**
	* Create a string key for a numeric tag value.
	* Handles both number and bigint types.
	*
	* @private
	*/
	_valueKey(value) {
		return value.toString();
	}
};
/**
* Global singleton instance of the tags store.
*/
let globalTagsStore$4;
/**
* Get the global tags store instance.
*
* Creates the instance on first access.
*
* @returns The global TagsStore instance
*
* @example
* ```typescript
* const store = getGlobalTagsStore();
* store.register(Tag.from(999, 'myTag'));
* ```
*/
const getGlobalTagsStore$4 = () => {
	globalTagsStore$4 ??= new TagsStore$4();
	return globalTagsStore$4;
};
//#endregion
//#region ../bc-dcbor-compat-ts/node_modules/@blockchaincommons/dcbor/dist/index.mjs
/**
* Helper function to validate that a CBOR value has one of the expected tags.
*
* @param cbor - CBOR value to validate
* @param expectedTags - Array of valid tags
* @returns The matching tag
* @throws {CborError} `WrongType` if the value is not tagged; `WrongTag` if
*   the tag matches none of `expectedTags`.
*/
const validateTag$1 = (cbor, expectedTags) => {
	if (cbor.type !== MajorType$4.Tagged) throw CborError$4.wrongType();
	const tagValue = cbor.tag;
	const matchingTag = expectedTags.find((t) => tagValuesEqual$4(t.value, tagValue));
	if (matchingTag === void 0) throw CborError$4.wrongTag(expectedTags[0], { value: tagValue });
	return matchingTag;
};
/**
* Helper function to extract the content from a tagged CBOR value.
*
* @param cbor - Tagged CBOR value
* @returns The untagged content
* @throws {CborError} `WrongType` if the value is not tagged.
*/
const extractTaggedContent$1 = (cbor) => {
	if (cbor.type !== MajorType$4.Tagged) throw CborError$4.wrongType();
	return cbor.value;
};
/**
* Normalize a timestamp (seconds since the Unix epoch) to whole seconds plus a
* non-negative, sub-second nanosecond part, so dates round-trip byte-identically.
*
* The nanosecond part is truncated toward zero and clamped to [0, u32::MAX]. So
* a negative fraction floors the value (`-1.5` becomes `-1.0`) and sub-nanosecond
* precision is dropped (`1.0000000005` becomes `1.0`).
*
* @internal
*/
function normalizeTimestampSeconds(seconds) {
	if (!Number.isFinite(seconds)) throw CborError$4.invalidDate("non-finite timestamp");
	const whole = Math.trunc(seconds);
	let nsecs = Math.trunc((seconds - whole) * 1e9);
	if (nsecs < 0) nsecs = 0;
	else if (nsecs > 4294967295) nsecs = 4294967295;
	return whole + nsecs / 1e9;
}
/**
* A CBOR-friendly representation of a date and time.
*
* The `CborDate` type provides a wrapper around JavaScript's native `Date` that
* supports encoding and decoding to/from CBOR with tag 1, following the CBOR
* date/time standard specified in RFC 8949.
*
* When encoded to CBOR, dates are represented as tag 1 followed by a numeric
* value representing the number of seconds since (or before) the Unix epoch
* (1970-01-01T00:00:00Z). The numeric value can be a positive or negative
* integer, or a floating-point value for dates with fractional seconds.
*
* # Features
*
* - Supports UTC dates with optional fractional seconds
* - Provides convenient constructors for common date creation patterns
* - Implements the `CborTagged` interface and the `ToCbor` protocol
* - Supports arithmetic operations with durations and between dates
*
* @example
* ```typescript
* import { CborDate } from './date';
*
* // Create a date from a timestamp (seconds since Unix epoch)
* const date = CborDate.fromEpochSeconds(1675854714.0);
*
* // Create a date from year, month, day
* const date2 = CborDate.fromYmd(2023, 2, 8);
*
* // Convert to CBOR
* const cborValue = date.taggedCbor();
*
* // Decode from CBOR
* const decoded = CborDate.fromTaggedCbor(cborValue);
* ```
*/
let dateCodec;
var CborDate$1 = class CborDate {
	/** Debug label: `Object.prototype.toString` reports `[object CborDate]`. */
	get [Symbol.toStringTag]() {
		return "CborDate";
	}
	/**
	* Canonical timestamp in seconds since the Unix epoch as a JS `number`
	* (`f64`). dCBOR encodes Date (tag 1) as a numeric value in seconds, so
	* keeping `_seconds` as the source of truth avoids the millisecond-only
	* round-trip precision loss that going through a JS `Date` instance would
	* introduce.
	*
	* f64 bounds the achievable precision (~16 decimal digits, so roughly
	* microseconds for current epoch values), but the encode/decode round-trip
	* is byte-identical.
	*/
	_seconds;
	/**
	* Creates a new `CborDate` from the given JavaScript `Date`.
	*
	* This method creates a new `CborDate` instance by wrapping a
	* JavaScript `Date`.
	*
	* @param dateTime - A `Date` instance to wrap
	*
	* @returns A new `CborDate` instance
	*
	* @example
	* ```typescript
	* const datetime = new Date();
	* const date = CborDate.fromDate(datetime);
	* ```
	*/
	static fromDate(dateTime) {
		const instance = new CborDate();
		instance._seconds = dateTime.getTime() / 1e3;
		return instance;
	}
	/**
	* Creates a new `CborDate` from year, month, and day components.
	*
	* This method creates a new `CborDate` with the time set to 00:00:00 UTC.
	*
	* @param year - The year component (e.g., 2023)
	* @param month - The month component (1-12)
	* @param day - The day component (1-31)
	*
	* @returns A new `CborDate` instance
	*
	* @example
	* ```typescript
	* // Create February 8, 2023
	* const date = CborDate.fromYmd(2023, 2, 8);
	* ```
	*
	* @throws Error if the provided components do not form a valid date.
	*/
	static fromYmd(year, month, day) {
		const dt = new Date(Date.UTC(year, month - 1, day, 0, 0, 0, 0));
		return CborDate.fromDate(dt);
	}
	/**
	* Creates a new `CborDate` from year, month, day, hour, minute, and second
	* components.
	*
	* @param year - The year component (e.g., 2023)
	* @param month - The month component (1-12)
	* @param day - The day component (1-31)
	* @param hour - The hour component (0-23)
	* @param minute - The minute component (0-59)
	* @param second - The second component (0-59)
	*
	* @returns A new `CborDate` instance
	*
	* @example
	* ```typescript
	* // Create February 8, 2023, 15:30:45 UTC
	* const date = CborDate.fromYmdHms(2023, 2, 8, 15, 30, 45);
	* ```
	*
	* @throws Error if the provided components do not form a valid date and time.
	*/
	static fromYmdHms(year, month, day, hour, minute, second) {
		const dt = new Date(Date.UTC(year, month - 1, day, hour, minute, second, 0));
		return CborDate.fromDate(dt);
	}
	/**
	* Creates a new `CborDate` from seconds since (or before) the Unix epoch.
	*
	* This method creates a new `CborDate` representing the specified number of
	* seconds since the Unix epoch (1970-01-01T00:00:00Z). Negative values
	* represent times before the epoch.
	*
	* @param secondsSinceUnixEpoch - Seconds from the Unix epoch (positive or
	*   negative), which can include a fractional part for sub-second
	*   precision
	*
	* @returns A new `CborDate` instance
	*
	* @example
	* ```typescript
	* // Create a date from a timestamp
	* const date = CborDate.fromEpochSeconds(1675854714.0);
	*
	* // Create a date one second before the Unix epoch
	* const beforeEpoch = CborDate.fromEpochSeconds(-1.0);
	*
	* // Create a date with fractional seconds
	* const withFraction = CborDate.fromEpochSeconds(1675854714.5);
	* ```
	*/
	static fromEpochSeconds(secondsSinceUnixEpoch) {
		const instance = new CborDate();
		instance._seconds = normalizeTimestampSeconds(secondsSinceUnixEpoch);
		return instance;
	}
	/**
	* Creates a new `CborDate` from a string containing an ISO-8601 (RFC-3339)
	* date (with or without time).
	*
	* This method parses a string representation of a date or date-time in
	* ISO-8601/RFC-3339 format and creates a new `CborDate` instance. It
	* supports both full date-time strings (e.g., "2023-02-08T15:30:45Z")
	* and date-only strings (e.g., "2023-02-08").
	*
	* @param value - A string containing a date or date-time in ISO-8601/RFC-3339
	*   format
	*
	* @returns A new `CborDate` instance if parsing succeeds
	*
	* @throws Error if the string cannot be parsed as a valid date or date-time
	*
	* @example
	* ```typescript
	* // Parse a date-time string
	* const date = CborDate.fromString("2023-02-08T15:30:45Z");
	*
	* // Parse a date-only string (time will be set to 00:00:00)
	* const date2 = CborDate.fromString("2023-02-08");
	* ```
	*/
	static fromString(value) {
		const invalidDate = CborError$4.invalidDate("Invalid date string");
		const rfc3339 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;
		const dateOnly = /^\d{4}-\d{2}-\d{2}$/;
		let parsed;
		if (rfc3339.test(value)) parsed = new Date(value);
		else if (dateOnly.test(value)) parsed = /* @__PURE__ */ new Date(`${value}T00:00:00Z`);
		else throw invalidDate;
		const [y, m, d] = value.slice(0, 10).split("-").map(Number);
		const probe = new Date(Date.UTC(y, m - 1, d));
		if (!(probe.getUTCFullYear() === y && probe.getUTCMonth() === m - 1 && probe.getUTCDate() === d) || isNaN(parsed.getTime())) throw invalidDate;
		return CborDate.fromDate(parsed);
	}
	/**
	* Creates a new `CborDate` containing the current date and time.
	*
	* @returns A new `CborDate` instance representing the current UTC date and time
	*
	* @example
	* ```typescript
	* const now = CborDate.now();
	* ```
	*/
	static now() {
		return CborDate.fromDate(/* @__PURE__ */ new Date());
	}
	/**
	* Creates a new `CborDate` containing the current date and time plus the given
	* duration.
	*
	* @param durationMs - The duration in milliseconds to add to the current time
	*
	* @returns A new `CborDate` instance representing the current UTC date and time plus
	* the duration
	*
	* @example
	* ```typescript
	* // Get a date 1 hour from now
	* const oneHourLater = CborDate.withDurationFromNow(3600 * 1000);
	* ```
	*/
	static withDurationFromNow(durationMs) {
		const future = new Date((/* @__PURE__ */ new Date()).getTime() + durationMs);
		return CborDate.fromDate(future);
	}
	/**
	* Returns the underlying JavaScript `Date` object.
	*
	* This method provides access to the wrapped JavaScript `Date`
	* instance.
	*
	* @returns The wrapped `Date` instance
	*
	* @example
	* ```typescript
	* const date = CborDate.now();
	* const datetime = date.toDate();
	* const year = datetime.getFullYear();
	* ```
	*/
	toDate() {
		return /* @__PURE__ */ new Date(this._seconds * 1e3);
	}
	/**
	* The date as the number of seconds since the Unix epoch
	* (1970-01-01T00:00:00Z), as a floating-point `number`. Negative values
	* represent times before the epoch; the fractional part is sub-second
	* precision.
	*
	* @example
	* ```typescript
	* const date = CborDate.fromYmd(2023, 2, 8);
	* const timestamp = date.epochSeconds;
	* ```
	*/
	get epochSeconds() {
		return this._seconds;
	}
	/**
	* Add seconds to this date.
	*
	* @param seconds - Seconds to add (can be fractional)
	* @returns New CborDate instance
	*
	* @example
	* ```typescript
	* const date = CborDate.fromYmd(2022, 3, 21);
	* const tomorrow = date.add(24 * 60 * 60);
	* ```
	*/
	add(seconds) {
		return CborDate.fromEpochSeconds(this.epochSeconds + seconds);
	}
	/**
	* Subtract seconds from this date.
	*
	* @param seconds - Seconds to subtract (can be fractional)
	* @returns New CborDate instance
	*
	* @example
	* ```typescript
	* const date = CborDate.fromYmd(2022, 3, 21);
	* const yesterday = date.subtract(24 * 60 * 60);
	* ```
	*/
	subtract(seconds) {
		return CborDate.fromEpochSeconds(this.epochSeconds - seconds);
	}
	/**
	* Get the difference in seconds between this date and another.
	*
	* @param other - Other CborDate to compare with
	* @returns Difference in seconds (this - other)
	*
	* @example
	* ```typescript
	* const date1 = CborDate.fromYmd(2022, 3, 22);
	* const date2 = CborDate.fromYmd(2022, 3, 21);
	* const diff = date1.difference(date2);
	* // Returns 86400 (one day in seconds)
	* ```
	*/
	difference(other) {
		return this.epochSeconds - other.epochSeconds;
	}
	/**
	* Implementation of the `CborTagged` interface for `CborDate`.
	*
	* This implementation specifies that `CborDate` values are tagged with CBOR tag 1,
	* which is the standard CBOR tag for date/time values represented as seconds
	* since the Unix epoch per RFC 8949.
	*
	* @returns A vector containing tag 1
	*/
	cborTags() {
		return [Tag$2.from(1, "date")];
	}
	/**
	* Converts this `CborDate` to its untagged CBOR content: the epoch-seconds
	* numeric value. It may be an integer or a floating-point number,
	* depending on whether the date has fractional seconds.
	*
	* @returns A CBOR value representing the timestamp
	*/
	untaggedCbor() {
		return cbor$4(this.epochSeconds);
	}
	/**
	* Converts this `CborDate` to a tagged CBOR value with tag 1.
	*
	* @returns Tagged CBOR value
	*/
	taggedCbor() {
		const tag = this.cborTags()[0];
		if (tag === void 0) throw CborError$4.custom("No tags defined for this type");
		return taggedValue(tag, this.untaggedCbor());
	}
	/**
	* The `ToCbor` protocol: dates encode as their tagged form.
	*/
	toCbor() {
		return this.taggedCbor();
	}
	/**
	* Populates this `CborDate` in place from an untagged CBOR value, which
	* must be a number (integer or floating-point) of seconds since the Unix
	* epoch. The static `CborDate.fromUntaggedCbor` is the usual entry point;
	* this instance form exists for reuse.
	*
	* @param cbor - The untagged CBOR value
	*
	* @returns this (populated in place)
	*
	* @throws Error if the CBOR value is not a valid timestamp
	*/
	fromUntaggedCbor(cbor) {
		let timestamp;
		switch (cbor.type) {
			case MajorType$4.Unsigned:
				timestamp = typeof cbor.value === "number" ? cbor.value : Number(cbor.value);
				break;
			case MajorType$4.Negative:
				if (typeof cbor.value === "bigint") timestamp = Number(-cbor.value - 1n);
				else timestamp = -cbor.value - 1;
				break;
			case MajorType$4.Simple:
				if (cbor.value.type === "Float") timestamp = cbor.value.value;
				else throw CborError$4.wrongType();
				break;
			default: throw CborError$4.wrongType();
		}
		this._seconds = normalizeTimestampSeconds(timestamp);
		return this;
	}
	/**
	* Populates this `CborDate` in place from a tag-1 CBOR value.
	*
	* @param cbor - Tagged CBOR value
	*
	* @returns this (populated in place)
	*
	* @throws Error if the CBOR value has the wrong tag or cannot be decoded
	*/
	fromTaggedCbor(cbor) {
		validateTag$1(cbor, this.cborTags());
		const content = extractTaggedContent$1(cbor);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to create a CborDate from tagged CBOR.
	*
	* @param cbor - Tagged CBOR value
	* @returns New CborDate instance
	*/
	static fromTaggedCbor(cbor) {
		return new CborDate().fromTaggedCbor(cbor);
	}
	/**
	* The {@link CborCodec} exemplar: a runtime witness that binds
	* `T = CborDate` for `decodeWith(bytes, CborDate.codec)`.
	*
	* A lazy getter (memoized) rather than a static field: the date ↔ tags
	* module cycle makes an eager initializer hit the temporal dead zone.
	*
	* @beta
	*/
	static get codec() {
		dateCodec ??= {
			tags: [Tag$2.from(1, "date")],
			decode: (c) => CborDate.fromTaggedCbor(c),
			encode: (value) => value.taggedCbor()
		};
		return dateCodec;
	}
	static fromUntaggedCbor(cbor) {
		return new CborDate().fromUntaggedCbor(cbor);
	}
	/**
	* Implementation of the `toString` method for `CborDate`.
	*
	* This implementation provides a string representation of a `CborDate` in ISO-8601
	* format. For dates with time exactly at midnight (00:00:00), only the date
	* part is shown. For other times, a full date-time string is shown.
	*
	* @returns String representation in ISO-8601 format
	*
	* @example
	* ```typescript
	* // A date at midnight will display as just the date
	* const date = CborDate.fromYmd(2023, 2, 8);
	* // Returns "2023-02-08"
	* console.log(date.toString());
	*
	* // A date with time will display as date and time
	* const date2 = CborDate.fromYmdHms(2023, 2, 8, 15, 30, 45);
	* // Returns "2023-02-08T15:30:45.000Z"
	* console.log(date2.toString());
	* ```
	*/
	toString() {
		const dt = /* @__PURE__ */ new Date(this._seconds * 1e3);
		if (!(dt.getUTCHours() !== 0 || dt.getUTCMinutes() !== 0 || dt.getUTCSeconds() !== 0)) {
			const datePart = dt.toISOString().split("T")[0];
			if (datePart === void 0) throw CborError$4.custom("Invalid ISO string format");
			return datePart;
		} else return dt.toISOString().replace(/\.\d{3}Z$/, "Z");
	}
	/**
	* Compare two dates for equality.
	*
	* @param other - Other CborDate to compare
	* @returns true if dates represent the same moment in time
	*/
	equals(other) {
		return this._seconds === other._seconds;
	}
	/**
	* Compare two dates.
	*
	* @param other - Other CborDate to compare
	* @returns -1 if this < other, 0 if equal, 1 if this > other
	*/
	compare(other) {
		if (this._seconds < other._seconds) return -1;
		if (this._seconds > other._seconds) return 1;
		return 0;
	}
	/**
	* Convert to JSON (returns ISO 8601 string).
	*
	* @returns ISO 8601 string
	*/
	toJSON() {
		return this.toString();
	}
	constructor() {
		this._seconds = Date.now() / 1e3;
	}
};
//#endregion
//#region ../bc-dcbor-compat-ts/node_modules/@blockchaincommons/dcbor/dist/diag-BpAWXEUJ.mjs
/**
* String utilities for dCBOR, including Unicode normalization.
*
* @module string-util
*/
/**
* Flank a string with left and right strings.
*
* @param s - String to flank
* @param left - Left flanking string
* @param right - Right flanking string
* @returns Flanked string
*/
const flanked$2 = (s, left, right) => left + s + right;
/**
* Check if a character is printable. Internal helper for {@link sanitized}.
*
* @param c - Character to check
* @returns True if printable
*/
const isPrintable$2 = (c) => {
	if (c.length !== 1) return false;
	const code = c.charCodeAt(0);
	return code > 127 || code >= 32 && code <= 126;
};
/**
* Sanitize a string by replacing non-printable characters with dots.
* Returns None if the string has no printable characters.
*
* @param str - String to sanitize
* @returns Sanitized string or undefined if no printable characters
*/
const sanitized$2 = (str) => {
	let hasPrintable = false;
	const chars = [];
	for (const c of str) if (isPrintable$2(c)) {
		hasPrintable = true;
		chars.push(c);
	} else chars.push(".");
	if (!hasPrintable) return;
	return chars.join("");
};
const resolveOpts$2 = (opts) => {
	const summarize = opts?.summarize ?? false;
	return {
		annotate: opts?.annotate ?? false,
		summarize,
		flat: summarize || (opts?.flat ?? false),
		tags: opts?.tags ?? "global"
	};
};
/**
* Format a CBOR value - or a walk visitor's `WalkElement` - as CBOR
* diagnostic notation.
*
* ```typescript
* diagnostic(value);                       // pretty-printed
* diagnostic(value, { flat: true });       // single line
* diagnostic(value, { annotate: true });   // tag names as annotations
* diagnostic(value, { summarize: true });  // registered summarizers (implies flat)
* ```
*
* @param input - CBOR value, or a `WalkElement` from a walk visitor
* @param opts - Formatting options (explicit `undefined` fields mean
*   "use the default")
* @public
*/
function diagnostic$4(input, opts) {
	const state = resolveOpts$2(opts);
	if (typeof input === "object" && "type" in input && (input.type === "single" || input.type === "keyvalue")) {
		if (input.type === "single") return diagFormat$2(diagItem$2(input.cbor, state), state);
		return `${diagFormat$2(diagItem$2(input.key, state), state)}: ${diagFormat$2(diagItem$2(input.value, state), state)}`;
	}
	return diagFormat$2(diagItem$2(input, state), state);
}
const item$2 = (value) => ({
	kind: "item",
	value
});
const group$2 = (begin, end, items, isPairs, comment) => {
	const g = {
		kind: "group",
		begin,
		end,
		items,
		isPairs
	};
	if (comment !== void 0) g.comment = comment;
	return g;
};
const isGroup$2 = (i) => i.kind === "group";
const containsGroup$2 = (i) => i.kind === "group" && i.items.some(isGroup$2);
const totalStringsLen$2 = (i) => i.kind === "item" ? i.value.length : i.items.reduce((acc, c) => acc + totalStringsLen$2(c), 0);
const greatestStringsLen$2 = (i) => i.kind === "item" ? i.value.length : i.items.reduce((acc, c) => Math.max(acc, totalStringsLen$2(c)), 0);
/**
* Alternates between `pairSeparator` (after even-indexed items - keys) and
* `itemSeparator` (after odd-indexed items - values). Falls back to
* `itemSeparator` for non-pair groups.
*/
function joined$2(elements, itemSeparator, pairSeparator) {
	const sep = pairSeparator ?? itemSeparator;
	let result = "";
	const len = elements.length;
	for (let i = 0; i < len; i++) {
		result += elements[i];
		if (i !== len - 1) result += (i & 1) !== 0 ? itemSeparator : sep;
	}
	return result;
}
const diagFormat$2 = (i, opts) => diagFormatOpt$2(i, 0, "", opts);
function diagFormatOpt$2(i, level, separator, opts) {
	if (i.kind === "item") return formatLine$2(level, opts, i.value, separator, void 0);
	if (opts.flat !== true && (containsGroup$2(i) || totalStringsLen$2(i) > 20 || greatestStringsLen$2(i) > 20)) return multilineComposition$2(i, level, separator, opts);
	return singleLineComposition$2(i, level, separator, opts);
}
function formatLine$2(level, opts, string, separator, comment) {
	const result = `${opts.flat === true ? "" : " ".repeat(level * 4)}${string}${separator}`;
	if (comment !== void 0) return `${result}   / ${comment} /`;
	return result;
}
function singleLineComposition$2(i, level, separator, opts) {
	let str;
	let comment;
	if (i.kind === "item") {
		str = i.value;
		comment = void 0;
	} else {
		str = flanked$2(joined$2(i.items.map((c) => c.kind === "item" ? c.value : singleLineComposition$2(c, level + 1, separator, opts)), ", ", i.isPairs ? ": " : ", "), i.begin, i.end);
		comment = i.comment;
	}
	return formatLine$2(level, opts, str, separator, comment);
}
function multilineComposition$2(i, level, separator, opts) {
	if (i.kind === "item") return i.value;
	const lines = [];
	const openOpts = {
		...opts,
		flat: false
	};
	lines.push(formatLine$2(level, openOpts, i.begin, "", i.comment));
	for (let idx = 0; idx < i.items.length; idx++) {
		const sep = idx === i.items.length - 1 ? "" : i.isPairs && (idx & 1) === 0 ? ":" : ",";
		lines.push(diagFormatOpt$2(i.items[idx], level + 1, sep, opts));
	}
	lines.push(formatLine$2(level, opts, i.end, separator, void 0));
	return lines.join("\n");
}
function diagItem$2(cbor, opts) {
	switch (cbor.type) {
		case MajorType$4.Unsigned: return item$2(formatUnsigned$2(cbor.value));
		case MajorType$4.Negative: return item$2(formatNegative$2(cbor.value));
		case MajorType$4.ByteString: return item$2(formatBytes$2(cbor.value));
		case MajorType$4.Text: return item$2(formatText$2(cbor.value));
		case MajorType$4.Array: return item_array$2(cbor.value, opts);
		case MajorType$4.Map: return item_map$2(cbor.value, opts);
		case MajorType$4.Tagged: return item_tagged$2(cbor.tag, cbor.value, opts);
		case MajorType$4.Simple: return item$2(formatSimple$2(cbor.value));
	}
}
function item_array$2(items, opts) {
	return group$2("[", "]", items.map((it) => diagItem$2(it, opts)), false);
}
function item_map$2(map, opts) {
	const entries = map?.entriesArray ?? [];
	const flatItems = [];
	for (const e of entries) {
		flatItems.push(diagItem$2(e.key, opts));
		flatItems.push(diagItem$2(e.value, opts));
	}
	return group$2("{", "}", flatItems, true);
}
function item_tagged$2(tag, content, opts) {
	if (opts.summarize === true) {
		const summarizer = resolveTagsStore$2(opts.tags)?.summarizer(tag);
		if (summarizer !== void 0) {
			const result = summarizer(content, opts.flat ?? false);
			if (result.ok) return item$2(result.value);
			return item$2(`<error: ${result.error.message}>`);
		}
	}
	let comment;
	if (opts.annotate === true) {
		const store = resolveTagsStore$2(opts.tags);
		const tagObj = { value: tag };
		const assignedName = store?.assignedNameForTag(tagObj);
		if (assignedName !== void 0) comment = assignedName;
	}
	return group$2(`${String(tag)}(`, ")", [diagItem$2(content, opts)], false, comment);
}
function formatUnsigned$2(value) {
	return String(value);
}
function formatNegative$2(value) {
	if (typeof value === "bigint") return String(-value - 1n);
	return String(-value - 1);
}
function formatBytes$2(value) {
	return `h'${bytesToHex$5(value)}'`;
}
function formatText$2(value) {
	return `"${value.replace(/"/g, "\\\"")}"`;
}
function formatSimple$2(value) {
	switch (value.type) {
		case "True": return "true";
		case "False": return "false";
		case "Null": return "null";
		case "Float": return formatFloat$2(value.value);
	}
}
/**
* Format a CBOR float for diagnostic output. Shared with the hex-dump
* annotation path; see {@link floatDisplayString}.
*/
function formatFloat$2(value) {
	return floatDisplayString$2(value);
}
function resolveTagsStore$2(tags) {
	if (tags === "none") return void 0;
	if (tags === "global" || tags === void 0) return getGlobalTagsStore$4();
	return tags;
}
//#endregion
//#region ../bc-dcbor-compat-ts/node_modules/@blockchaincommons/dcbor/dist/diagnostic.mjs
/**
* Hex dump utilities for CBOR data.
*
* Affordances for viewing the encoded binary representation of CBOR as hexadecimal.
* Optionally annotates the output, breaking it up into semantically meaningful lines,
* formatting dates, and adding names of known tags.
*
* @module dump
*/
/**
* Render CBOR as an annotated hex dump: the encoding broken into
* semantically meaningful lines with offsets, values, and tag names
* resolved through the tags store.
*
* For plain hex use `c.toHex()` or `bytesToHex(encodeCbor(v))`.
*
* @param cbor - CBOR value to render
* @param opts - Formatting options (explicit `undefined` fields mean
*   "use the default")
*/
const hexAnnotated$2 = (cbor, opts) => {
	const items = dumpItems$2(cbor, 0, opts?.tagsStore ?? getGlobalTagsStore$4());
	const roundedNoteColumn = (items.reduce((largest, item) => {
		return Math.max(largest, item.formatFirstColumn().length);
	}, 0) + 4 & -4) - 1;
	return items.map((item) => item.format(roundedNoteColumn)).join("\n");
};
/**
* Internal structure for dump items.
*/
var DumpItem$2 = class {
	level;
	data;
	note;
	constructor(level, data, note) {
		this.level = level;
		this.data = data;
		this.note = note;
	}
	format(noteColumn) {
		const column1 = this.formatFirstColumn();
		let column2 = "";
		let padding = "";
		if (this.note !== void 0) {
			const paddingCount = Math.max(1, Math.min(39, noteColumn) - column1.length + 1);
			padding = " ".repeat(paddingCount);
			column2 = `# ${this.note}`;
		}
		return column1 + padding + column2;
	}
	formatFirstColumn() {
		return " ".repeat(this.level * 4) + this.data.map(bytesToHex$5).filter((x) => x.length > 0).join(" ");
	}
};
/**
* Generate dump items for a CBOR value (recursive).
*/
function dumpItems$2(cbor, level, tagsStore) {
	const items = [];
	switch (cbor.type) {
		case MajorType$4.Unsigned: {
			const data = encodeCbor$5(cbor);
			items.push(new DumpItem$2(level, [data], `unsigned(${cbor.value})`));
			break;
		}
		case MajorType$4.Negative: {
			const data = encodeCbor$5(cbor);
			const actualValue = typeof cbor.value === "bigint" ? -1n - cbor.value : -1 - cbor.value;
			items.push(new DumpItem$2(level, [data], `negative(${actualValue})`));
			break;
		}
		case MajorType$4.ByteString: {
			const header = encodeVarInt$2(cbor.value.length, MajorType$4.ByteString);
			items.push(new DumpItem$2(level, [header], `bytes(${cbor.value.length})`));
			if (cbor.value.length > 0) {
				let note = void 0;
				try {
					const sanitizedText = sanitized$2(new TextDecoder("utf-8", { fatal: true }).decode(cbor.value));
					if (sanitizedText !== void 0 && sanitizedText !== "") note = flanked$2(sanitizedText, "\"", "\"");
				} catch {}
				items.push(new DumpItem$2(level + 1, [cbor.value], note));
			}
			break;
		}
		case MajorType$4.Text: {
			const utf8Data = new TextEncoder().encode(cbor.value);
			const header = encodeVarInt$2(utf8Data.length, MajorType$4.Text);
			const firstByte = header[0];
			if (firstByte === void 0) throw CborError$4.custom("Invalid varint encoding");
			const headerData = [new Uint8Array([firstByte]), header.slice(1)];
			items.push(new DumpItem$2(level, headerData, `text(${utf8Data.length})`));
			items.push(new DumpItem$2(level + 1, [utf8Data], flanked$2(cbor.value, "\"", "\"")));
			break;
		}
		case MajorType$4.Array: {
			const header = encodeVarInt$2(cbor.value.length, MajorType$4.Array);
			const firstByte = header[0];
			if (firstByte === void 0) throw CborError$4.custom("Invalid varint encoding");
			const headerData = [new Uint8Array([firstByte]), header.slice(1)];
			items.push(new DumpItem$2(level, headerData, `array(${cbor.value.length})`));
			for (const item of cbor.value) items.push(...dumpItems$2(item, level + 1, tagsStore));
			break;
		}
		case MajorType$4.Map: {
			const header = encodeVarInt$2(cbor.value.size, MajorType$4.Map);
			const firstByte = header[0];
			if (firstByte === void 0) throw CborError$4.custom("Invalid varint encoding");
			const headerData = [new Uint8Array([firstByte]), header.slice(1)];
			items.push(new DumpItem$2(level, headerData, `map(${cbor.value.size})`));
			for (const entry of cbor.value.entriesArray) {
				items.push(...dumpItems$2(entry.key, level + 1, tagsStore));
				items.push(...dumpItems$2(entry.value, level + 1, tagsStore));
			}
			break;
		}
		case MajorType$4.Tagged: {
			const tagValue = cbor.tag;
			if (tagValue === void 0) throw CborError$4.custom("Tagged CBOR value must have a tag");
			const header = encodeVarInt$2(tagValue, MajorType$4.Tagged);
			const firstByte = header[0];
			if (firstByte === void 0) throw CborError$4.custom("Invalid varint encoding");
			const headerData = [new Uint8Array([firstByte]), header.slice(1)];
			const noteComponents = [`tag(${tagValue})`];
			const tag = Tag$2.from(tagValue);
			const tagName = tagsStore.assignedNameForTag(tag);
			if (tagName !== void 0) noteComponents.push(tagName);
			const tagNote = noteComponents.join(" ");
			items.push(new DumpItem$2(level, headerData, tagNote));
			items.push(...dumpItems$2(cbor.value, level + 1, tagsStore));
			break;
		}
		case MajorType$4.Simple: {
			const data = encodeCbor$5(cbor);
			const simple = cbor.value;
			let note;
			if (simple.type === "True") note = "true";
			else if (simple.type === "False") note = "false";
			else if (simple.type === "Null") note = "null";
			else if (simple.type === "Float") note = floatDisplayString$2(simple.value);
			else note = "simple";
			items.push(new DumpItem$2(level, [data], note));
			break;
		}
	}
	return items;
}
//#endregion
//#region ../bc-dcbor-compat-ts/dist/index.mjs
/**
* Create a new Tag.
*
* @param value - The numeric tag value
* @param name - Optional human-readable name
* @returns A new Tag object
*
* @example
* ```typescript
* const dateTag = createTag(1, 'date');
* const customTag = createTag(12345, 'myCustomTag');
* ```
*/
const createTag$1 = (value, name) => {
	if (name !== void 0) return {
		value,
		name
	};
	return { value };
};
/**
* Compare two tag values for equality, normalizing `number` vs `bigint`.
* A raw `===` would treat `100n` and `100` as unequal, so a large tag that
* decoded to a `bigint` wouldn't match the same value written as a `number`.
*/
const tagValuesEqual$3 = (a, b) => {
	if (typeof a === "bigint" || typeof b === "bigint") return BigInt(a) === BigInt(b);
	return a === b;
};
/**
* Get the string representation of a tag.
* Internal function used for error messages.
*
* @param tag - The tag to represent
* @returns String representation (name if available, otherwise value)
*
* @internal
*/
const tagToString$3 = (tag) => tag.name ?? tag.value.toString();
/**
* Convert an Error to a display string.
*
* Matches Rust's `Display` trait / `to_string()` method.
*/
const errorToString$2 = (error) => {
	switch (error.type) {
		case "Underrun": return "early end of CBOR data";
		case "UnsupportedHeaderValue": return "unsupported value in CBOR header";
		case "NonCanonicalNumeric": return "a CBOR numeric value was encoded in non-canonical form";
		case "InvalidSimpleValue": return "an invalid CBOR simple value was encountered";
		case "InvalidString": return `an invalidly-encoded UTF-8 string was encountered in the CBOR (${error.message})`;
		case "NonCanonicalString": return "a CBOR string was not encoded in Unicode Canonical Normalization Form C";
		case "UnusedData": return `the decoded CBOR had ${error.count} extra bytes at the end`;
		case "MisorderedMapKey": return "the decoded CBOR map has keys that are not in canonical order";
		case "DuplicateMapKey": return "the decoded CBOR map has a duplicate key";
		case "MissingMapKey": return "missing CBOR map key";
		case "OutOfRange": return "the CBOR numeric value could not be represented in the specified numeric type";
		case "WrongType": return "the decoded CBOR value was not the expected type";
		case "WrongTag": return `expected CBOR tag ${tagToString$3(error.expected)}, but got ${tagToString$3(error.actual)}`;
		case "InvalidUtf8": return `invalid UTF‑8 string: ${error.message}`;
		case "InvalidDate": return `invalid ISO 8601 date string: ${error.message}`;
		case "Custom": return error.message;
	}
};
/**
* Typed error class for all CBOR-related errors.
*
* Wraps the discriminated union Error type in a JavaScript Error object
* for proper error handling with stack traces.
*
* @example
* ```typescript
* throw new CborError({ type: 'Underrun' });
* throw new CborError({ type: 'WrongTag', expected: tag1, actual: tag2 });
* ```
*/
var CborError$3 = class CborError extends Error {
	/**
	* The structured error information.
	*/
	errorType;
	/**
	* Create a new CborError.
	*
	* @param errorType - The discriminated union error type
	* @param message - Optional custom message (defaults to errorToString(errorType))
	*/
	constructor(errorType, message) {
		super(message ?? errorToString$2(errorType));
		this.name = "CborError";
		this.errorType = errorType;
		if ("captureStackTrace" in Error) Error.captureStackTrace(this, CborError);
	}
	/**
	* Check if an error is a CborError.
	*
	* @param error - Error to check
	* @returns True if error is a CborError
	*/
	static isCborError(error) {
		return error instanceof CborError;
	}
};
/**
* Convert a legacy node into a canonical `@blockchaincommons/dcbor` node.
*
* Leaves are shared, not copied: the canonical functions never mutate their
* inputs. Map nodes unwrap to the inner canonical `CborMap`, so later
* mutations through the legacy wrapper stay visible.
*/
const toNew$2 = (c) => {
	switch (c.type) {
		case MajorType$3.Array: return {
			isCbor: true,
			type: MajorType$3.Array,
			value: c.value.map(toNew$2)
		};
		case MajorType$3.Map: return {
			isCbor: true,
			type: MajorType$3.Map,
			value: c.value._inner
		};
		case MajorType$3.Tagged: return {
			isCbor: true,
			type: MajorType$3.Tagged,
			tag: c.tag,
			value: toNew$2(c.value)
		};
		default: return {
			isCbor: true,
			type: c.type,
			value: c.value
		};
	}
};
/**
* Convert a canonical node into a legacy node with the legacy method set.
* Map nodes wrap the canonical `CborMap` without copying entries.
*/
const fromNew$2 = (n) => {
	switch (n.type) {
		case MajorType$3.Array: return attachMethods$3({
			isCbor: true,
			type: MajorType$3.Array,
			value: n.value.map(fromNew$2)
		});
		case MajorType$3.Map: return attachMethods$3({
			isCbor: true,
			type: MajorType$3.Map,
			value: CborMap$3._fromInner(n.value)
		});
		case MajorType$3.Tagged: return attachMethods$3({
			isCbor: true,
			type: MajorType$3.Tagged,
			tag: n.tag,
			value: fromNew$2(n.value)
		});
		default: return attachMethods$3({
			isCbor: true,
			type: n.type,
			value: n.value
		});
	}
};
/**
* Translate a canonical `CborError` (code + details) back into the legacy
* discriminated-union `CborError`. Non-CborError values are re-thrown as-is.
*/
const toLegacyError$2 = (e) => {
	if (!CborError$4.isCborError(e)) {
		if (e instanceof CborError$3) return e;
		throw e;
	}
	const details = e.details;
	let errorType;
	switch (e.code) {
		case "UnsupportedHeaderValue":
			errorType = {
				type: "UnsupportedHeaderValue",
				value: details["headerValue"]
			};
			break;
		case "UnusedData":
			errorType = {
				type: "UnusedData",
				count: details["count"]
			};
			break;
		case "WrongTag":
			errorType = {
				type: "WrongTag",
				expected: details["expectedTag"],
				actual: details["actualTag"]
			};
			break;
		case "InvalidString":
			errorType = {
				type: "InvalidString",
				message: details["cause"] ?? e.message
			};
			break;
		case "InvalidUtf8":
			errorType = {
				type: "InvalidUtf8",
				message: details["cause"] ?? e.message
			};
			break;
		case "InvalidDate":
			errorType = {
				type: "InvalidDate",
				message: details["cause"] ?? e.message
			};
			break;
		case "Custom":
			errorType = {
				type: "Custom",
				message: e.message
			};
			break;
		default: errorType = { type: e.code };
	}
	return new CborError$3(errorType);
};
/** Run a canonical-package operation, translating thrown errors. */
const delegating$2 = (op) => {
	try {
		return op();
	} catch (e) {
		throw toLegacyError$2(e);
	}
};
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Tag registry and management system.
*
* The TagsStore provides a centralized registry for CBOR tags,
* including name resolution and custom summarizer functions.
*
* The store wraps the `@blockchaincommons/dcbor` `TagsStore` — and the
* global singleton wraps the canonical package's *global* store — so tag
* names and summarizers registered through this legacy API are visible to
* the delegated diagnostic/hex formatters (and vice versa).
*
* @module tags-store
*/
/**
* Convert a canonical tag (whose `name` may be explicitly `undefined`) to the
* legacy `Tag` shape, which omits the property instead.
*/
const toLegacyTag$2 = (tag) => {
	if (tag === void 0) return void 0;
	return tag.name !== void 0 ? {
		value: tag.value,
		name: tag.name
	} : { value: tag.value };
};
/**
* Tag registry implementation.
*
* Stores tags with their names and optional summarizer functions, delegating
* storage to the canonical `@blockchaincommons/dcbor` store.
*/
var TagsStore$3 = class TagsStore {
	_store;
	/** Original (legacy-signature) summarizers, for the `summarizer()` accessor. */
	_legacySummarizers = /* @__PURE__ */ new Map();
	constructor() {
		this._store = new TagsStore$4();
	}
	/**
	* The wrapped canonical `@blockchaincommons/dcbor` store.
	* @internal
	*/
	get _inner() {
		return this._store;
	}
	/**
	* Wrap an existing canonical store without copying registrations.
	* @internal
	*/
	static _fromInner(inner) {
		const store = new TagsStore();
		store._store = inner;
		return store;
	}
	/**
	* Insert a tag into the registry.
	*
	* Matches Rust's TagsStore::insert() behavior:
	* - Throws if the tag name is undefined or empty
	* - Throws if a tag with the same value exists with a different name
	* - Allows re-registering the same tag value with the same name
	*
	* @param tag - The tag to register (must have a non-empty name)
	* @throws Error if tag has no name, empty name, or conflicts with existing registration
	*
	* @example
	* ```typescript
	* const store = new TagsStore();
	* store.insert(createTag(12345, 'myCustomTag'));
	* ```
	*/
	insert(tag) {
		const name = tag.name;
		if (name === void 0 || name === "") throw new Error(`Tag ${tag.value} must have a non-empty name`);
		const existing = this._store.tagForValue(tag.value);
		if (existing?.name !== void 0 && existing.name !== name) throw new Error(`Attempt to register tag: ${tag.value} '${existing.name}' with different name: '${name}'`);
		this._store.register(Tag$2.from(tag.value, name));
	}
	/**
	* Insert multiple tags into the registry.
	* Matches Rust's insert_all() method.
	*
	* @param tags - Array of tags to register
	*
	* @example
	* ```typescript
	* const store = new TagsStore();
	* store.insertAll([
	*   createTag(1, 'date'),
	*   createTag(100, 'custom')
	* ]);
	* ```
	*/
	insertAll(tags) {
		for (const tag of tags) this.insert(tag);
	}
	/**
	* Register a custom summarizer function for a tag.
	*
	* The summarizer is adapted and forwarded to the canonical store, so the
	* delegated diagnostic formatters invoke it (with a legacy-shaped node).
	*
	* @param tagValue - The numeric tag value
	* @param summarizer - The summarizer function
	*
	* @example
	* ```typescript
	* store.setSummarizer(1, (cbor, flat) => {
	*   // Custom date formatting
	*   return `Date(${extractCbor(cbor)})`;
	* });
	* ```
	*/
	setSummarizer(tagValue, summarizer) {
		this._legacySummarizers.set(this._valueKey(tagValue), summarizer);
		this._store.setSummarizer(tagValue, (cbor, flat) => {
			const result = summarizer(fromNew$2(cbor), flat);
			if (result.ok) return result;
			return {
				ok: false,
				error: CborError$4.custom(errorToString$2(result.error))
			};
		});
	}
	assignedNameForTag(tag) {
		return this._store.tagForValue(tag.value)?.name;
	}
	nameForTag(tag) {
		return this.assignedNameForTag(tag) ?? tag.value.toString();
	}
	tagForValue(value) {
		return toLegacyTag$2(this._store.tagForValue(value));
	}
	tagForName(name) {
		return toLegacyTag$2(this._store.tagForName(name));
	}
	nameForValue(value) {
		const tag = this.tagForValue(value);
		return tag !== void 0 ? this.nameForTag(tag) : value.toString();
	}
	summarizer(tag) {
		return this._legacySummarizers.get(this._valueKey(tag));
	}
	_valueKey(value) {
		return value.toString();
	}
};
/**
* Global singleton instance of the tags store.
*/
let globalTagsStore$3;
/**
* Get the global tags store instance.
*
* Creates the instance on first access, wrapping the canonical package's
* global store so registrations are shared with the delegated formatters.
*
* @returns The global TagsStore instance
*
* @example
* ```typescript
* const store = getGlobalTagsStore();
* store.insert(createTag(999, 'myTag'));
* ```
*/
const getGlobalTagsStore$3 = () => {
	globalTagsStore$3 ??= TagsStore$3._fromInner(getGlobalTagsStore$4());
	return globalTagsStore$3;
};
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Hex dump utilities for CBOR data.
*
* Affordances for viewing the encoded binary representation of CBOR as hexadecimal.
* Optionally annotates the output, breaking it up into semantically meaningful lines,
* formatting dates, and adding names of known tags.
*
* The annotated rendering delegates to `@blockchaincommons/dcbor/diagnostic`.
*
* @module dump
*/
/**
* Convert bytes to hex string.
*/
const bytesToHex$3 = (bytes) => {
	return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
};
/**
* Returns the encoded hexadecimal representation of CBOR.
*
* @param cbor - CBOR value to convert
* @returns Hex string
*/
const hex$2 = (cbor) => bytesToHex$3(cborData$2(cbor));
/**
* Returns the encoded hexadecimal representation of CBOR with options.
*
* Optionally annotates the output, e.g., breaking the output up into
* semantically meaningful lines, formatting dates, and adding names of
* known tags.
*
* @param cbor - CBOR value to convert
* @param opts - Formatting options
* @returns Hex string (possibly annotated)
*/
const hexOpt$2 = (cbor, opts = {}) => {
	if (opts.annotate !== true) return hex$2(cbor);
	const tagsStore = opts.tagsStore ?? getGlobalTagsStore$3();
	return delegating$2(() => hexAnnotated$2(toNew$2(cbor), { tagsStore: tagsStore._inner }));
};
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Enhanced diagnostic formatting for CBOR values.
*
* Provides multiple formatting options including
* - Annotated diagnostics with tag names
* - Summarized values using custom summarizers
* - Flat (single-line) vs. pretty (multi-line) formatting
* - Configurable tag store usage
*
* Rendering delegates to `@blockchaincommons/dcbor/diagnostic` (which shares
* this module's option vocabulary); summarizers registered through this
* package's `TagsStore` are consulted through the wrapped canonical store.
*
* @module diag
*/
/**
* Convert the legacy tags-store option to the canonical one (unwrap a
* wrapped store; pass the string variants through).
*/
const toBcTagsOpt$2 = (tags) => {
	if (tags instanceof TagsStore$3) return tags._inner;
	return tags;
};
/**
* Format CBOR value as diagnostic notation with options.
*
* @param cbor - CBOR value to format
* @param opts - Formatting options
* @returns Diagnostic string
*
* @example
* ```typescript
* const value = cbor({ name: 'Alice', age: 30 });
* console.log(diagnosticOpt(value, { flat: true }));
* // {\"name\": \"Alice\", \"age\": 30}
* ```
*/
function diagnosticOpt$2(cbor, opts) {
	return delegating$2(() => diagnostic$4(toNew$2(cbor), {
		annotate: opts?.annotate,
		summarize: opts?.summarize,
		flat: opts?.summarize === true ? true : opts?.flat,
		tags: toBcTagsOpt$2(opts?.tags)
	}));
}
/**
* Format CBOR value as standard diagnostic notation.
*
* @param cbor - CBOR value to format
* @returns Diagnostic string (pretty-printed with multiple lines for complex structures)
*
* @example
* ```typescript
* const value = cbor([1, 2, 3]);
* console.log(diagnostic(value));
* // For simple arrays: "[1, 2, 3]"
* // For nested structures: multi-line formatted output
* ```
*/
function diagnostic$3(cbor) {
	return diagnosticOpt$2(cbor);
}
/**
* Checks if the simple value is a floating point number.
*/
const isFloat$1$2 = (simple) => simple.type === "Float";
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* dCBOR decoding — delegates to `@blockchaincommons/dcbor`, the canonical
* implementation, then rewraps the result into this package's legacy node
* shape. All deterministic-encoding enforcement (canonical numeric forms,
* NFC text, map-key order, no trailing bytes) happens in the canonical
* decoder; thrown errors are translated back to the legacy `CborError`.
*/
function decodeCbor$3(data) {
	return fromNew$2(delegating$2(() => decodeCbor$4(data)));
}
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Convenience utilities for working with CBOR values.
*
* Provides type-safe helpers for checking types, extracting values,
* and working with arrays, maps, and tagged values.
*
* @module conveniences
*/
/**
* Extract native JavaScript value from CBOR.
* Converts CBOR types to their JavaScript equivalents.
*/
const extractCbor$3 = (cbor) => {
	let c;
	if (cbor instanceof Uint8Array) c = decodeCbor$3(cbor);
	else c = cbor;
	switch (c.type) {
		case MajorType$3.Unsigned: return c.value;
		case MajorType$3.Negative: if (typeof c.value === "bigint") return -c.value - 1n;
		else return -c.value - 1;
		case MajorType$3.ByteString: return c.value;
		case MajorType$3.Text: return c.value;
		case MajorType$3.Array: return c.value.map(extractCbor$3);
		case MajorType$3.Map: return c.value;
		case MajorType$3.Tagged: return c;
		case MajorType$3.Simple:
			if (c.value.type === "True") return true;
			if (c.value.type === "False") return false;
			if (c.value.type === "Null") return null;
			if (c.value.type === "Float") return c.value.value;
			return c;
	}
};
/**
* Check if CBOR value is a byte string.
*
* @param cbor - CBOR value to check
* @returns True if value is byte string
*/
const isBytes$1 = (cbor) => {
	return cbor.type === MajorType$3.ByteString;
};
/**
* Check if CBOR value is an array.
*
* @param cbor - CBOR value to check
* @returns True if value is array
*/
const isArray = (cbor) => {
	return cbor.type === MajorType$3.Array;
};
/**
* Check if CBOR value is tagged.
*
* @param cbor - CBOR value to check
* @returns True if value is tagged
*/
const isTagged = (cbor) => {
	return cbor.type === MajorType$3.Tagged;
};
/**
* Extract unsigned integer value if type matches.
*
* @param cbor - CBOR value
* @returns Unsigned integer or undefined
*/
const asUnsigned = (cbor) => {
	if (cbor.type === MajorType$3.Unsigned) return cbor.value;
};
/**
* Extract any integer value (unsigned or negative) if type matches.
*
* @param cbor - CBOR value
* @returns Integer or undefined
*/
const asInteger = (cbor) => {
	if (cbor.type === MajorType$3.Unsigned) return cbor.value;
	else if (cbor.type === MajorType$3.Negative) {
		if (typeof cbor.value === "bigint") return -cbor.value - 1n;
		else return -cbor.value - 1;
	}
};
/**
* Extract byte string value if type matches.
*
* @param cbor - CBOR value
* @returns Byte string or undefined
*/
const asBytes = (cbor) => {
	if (cbor.type === MajorType$3.ByteString) return cbor.value;
};
/**
* Extract text string value if type matches.
*
* @param cbor - CBOR value
* @returns Text string or undefined
*/
const asText = (cbor) => {
	if (cbor.type === MajorType$3.Text) return cbor.value;
};
/**
* Extract array value if type matches.
*
* @param cbor - CBOR value
* @returns Array or undefined
*/
const asArray = (cbor) => {
	if (cbor.type === MajorType$3.Array) return cbor.value;
};
/**
* Extract map value if type matches.
*
* @param cbor - CBOR value
* @returns Map or undefined
*/
const asMap = (cbor) => {
	if (cbor.type === MajorType$3.Map) return cbor.value;
};
/**
* Extract any numeric value (integer or float).
*
* @param cbor - CBOR value
* @returns Number or undefined
*/
const asNumber = (cbor) => {
	if (cbor.type === MajorType$3.Unsigned) return cbor.value;
	if (cbor.type === MajorType$3.Negative) {
		if (typeof cbor.value === "bigint") return -cbor.value - 1n;
		else return -cbor.value - 1;
	}
	if (cbor.type === MajorType$3.Simple) {
		const simple = cbor.value;
		if (isFloat$1$2(simple)) return simple.value;
	}
};
/**
* Extract unsigned integer value, throwing if type doesn't match.
*
* @param cbor - CBOR value
* @returns Unsigned integer
* @throws {CborError} With type 'WrongType' if cbor is not an unsigned integer
*/
const expectUnsigned = (cbor) => {
	const value = asUnsigned(cbor);
	if (value === void 0) throw new CborError$3({ type: "WrongType" });
	return value;
};
/**
* Extract any integer value, throwing if type doesn't match.
*
* @param cbor - CBOR value
* @returns Integer
* @throws {CborError} With type 'WrongType' if cbor is not an integer
*/
const expectInteger = (cbor) => {
	const value = asInteger(cbor);
	if (value === void 0) throw new CborError$3({ type: "WrongType" });
	return value;
};
/**
* Extract byte string value, throwing if type doesn't match.
*
* @param cbor - CBOR value
* @returns Byte string
* @throws {CborError} With type 'WrongType' if cbor is not a byte string
*/
const expectBytes = (cbor) => {
	const value = asBytes(cbor);
	if (value === void 0) throw new CborError$3({ type: "WrongType" });
	return value;
};
/**
* Extract text string value, throwing if type doesn't match.
*
* @param cbor - CBOR value
* @returns Text string
* @throws {CborError} With type 'WrongType' if cbor is not a text string
*/
const expectText = (cbor) => {
	const value = asText(cbor);
	if (value === void 0) throw new CborError$3({ type: "WrongType" });
	return value;
};
/**
* Extract array value, throwing if type doesn't match.
*
* @param cbor - CBOR value
* @returns Array
* @throws {CborError} With type 'WrongType' if cbor is not an array
*/
const expectArray = (cbor) => {
	const value = asArray(cbor);
	if (value === void 0) throw new CborError$3({ type: "WrongType" });
	return value;
};
/**
* Extract map value, throwing if type doesn't match.
*
* @param cbor - CBOR value
* @returns Map
* @throws {CborError} With type 'WrongType' if cbor is not a map
*/
const expectMap = (cbor) => {
	const value = asMap(cbor);
	if (value === void 0) throw new CborError$3({ type: "WrongType" });
	return value;
};
/**
* Extract any numeric value, throwing if type doesn't match.
*
* @param cbor - CBOR value
* @returns Number
* @throws {CborError} With type 'WrongType' if cbor is not a number
*/
const expectNumber = (cbor) => {
	const value = asNumber(cbor);
	if (value === void 0) throw new CborError$3({ type: "WrongType" });
	return value;
};
/**
* Get tag value from tagged CBOR.
*
* @param cbor - CBOR value (must be tagged)
* @returns Tag value or undefined
*/
const tagValue = (cbor) => {
	if (cbor.type !== MajorType$3.Tagged) return;
	return cbor.tag;
};
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Map Support in dCBOR
*
* A deterministic CBOR map that ensures maps with the same content always
* produce identical binary encodings, regardless of insertion order.
*
* This class keeps the historical `@blockchaincommons/dcbor-compat` map API (Rust-flavored
* `insert`/`containsKey`/`len`/`iter` alongside the JS `Map` vocabulary) but
* stores its entries in a `@blockchaincommons/dcbor` `CborMap` — the
* canonical implementation owns key ordering (lexicographic by encoded CBOR
* bytes), duplicate handling, and the decode-time `setNext` ordering checks.
*
* @module map
*/
/**
* A deterministic CBOR map implementation.
*
* Maps are always encoded with keys sorted lexicographically by their
* encoded CBOR representation, ensuring deterministic encoding.
*/
var CborMap$3 = class CborMap {
	_map;
	/**
	* Creates a new, empty CBOR Map.
	* Optionally initializes from a JavaScript Map.
	*/
	constructor(map) {
		this._map = new CborMap$4();
		if (map !== void 0) for (const [key, value] of map.entries()) this.set(key, value);
	}
	/**
	* The wrapped canonical `@blockchaincommons/dcbor` map.
	* @internal
	*/
	get _inner() {
		return this._map;
	}
	/**
	* Wrap an existing canonical map without copying entries.
	* @internal
	*/
	static _fromInner(inner) {
		const map = new CborMap();
		map._map = inner;
		return map;
	}
	/**
	* Creates a new, empty CBOR Map.
	* Matches Rust's Map::new().
	*/
	static new() {
		return new CborMap();
	}
	/**
	* Inserts a key-value pair into the map.
	* Matches Rust's Map::insert().
	*/
	set(key, value) {
		const keyCbor = cbor$3(key);
		const valueCbor = cbor$3(value);
		delegating$2(() => this._map.set(toNew$2(keyCbor), toNew$2(valueCbor)));
	}
	/**
	* Alias for set() to match Rust's insert() method.
	*/
	insert(key, value) {
		this.set(key, value);
	}
	/**
	* Get a value from the map, given a key.
	* Returns undefined if the key is not present in the map.
	* Matches Rust's Map::get().
	*/
	get(key) {
		const stored = delegating$2(() => this._map.get(toNew$2(cbor$3(key))));
		if (stored === void 0) return;
		return extractCbor$3(fromNew$2(stored));
	}
	/**
	* Get a value from the map, given a key.
	* Throws an error if the key is not present.
	* Matches Rust's Map::extract().
	*/
	extract(key) {
		const value = this.get(key);
		if (value === void 0) throw new CborError$3({ type: "MissingMapKey" });
		return value;
	}
	/**
	* Tests if the map contains a key.
	* Matches Rust's Map::contains_key().
	*/
	containsKey(key) {
		return delegating$2(() => this._map.has(toNew$2(cbor$3(key))));
	}
	delete(key) {
		return delegating$2(() => this._map.delete(toNew$2(cbor$3(key))));
	}
	has(key) {
		return this.containsKey(key);
	}
	clear() {
		this._map.clear();
	}
	/**
	* Returns the number of entries in the map.
	* Matches Rust's Map::len().
	*/
	get length() {
		return this._map.size;
	}
	/**
	* Alias for length to match JavaScript Map API.
	* Also matches Rust's Map::len().
	*/
	get size() {
		return this._map.size;
	}
	/**
	* Returns the number of entries in the map.
	* Matches Rust's Map::len().
	*/
	len() {
		return this._map.size;
	}
	/**
	* Checks if the map is empty.
	* Matches Rust's Map::is_empty().
	*/
	isEmpty() {
		return this._map.size === 0;
	}
	/**
	* Get the entries of the map as an array.
	* Keys are sorted in lexicographic order of their encoded CBOR bytes.
	*/
	get entriesArray() {
		const entries = [];
		for (const [key, value] of this._map.entries()) entries.push({
			key: fromNew$2(key),
			value: fromNew$2(value)
		});
		return entries;
	}
	/**
	* Gets an iterator over the entries of the CBOR map, sorted by key.
	* Key sorting order is lexicographic by the key's binary-encoded CBOR.
	* Matches Rust's Map::iter().
	*/
	iter() {
		return this.entriesArray;
	}
	/**
	* Returns an iterator of [key, value] tuples for JavaScript Map API compatibility.
	* This matches the standard JavaScript Map.entries() method behavior.
	*/
	*entries() {
		for (const entry of this.entriesArray) yield [entry.key, entry.value];
	}
	/**
	* Inserts the next key-value pair into the map during decoding.
	* This is used for efficient map building during CBOR decoding.
	* Throws if the key is not in ascending order or is a duplicate.
	* Matches Rust's Map::insert_next().
	*/
	setNext(key, value) {
		const keyCbor = cbor$3(key);
		const valueCbor = cbor$3(value);
		delegating$2(() => this._map.setNext(toNew$2(keyCbor), toNew$2(valueCbor)));
	}
	get debug() {
		return `map({${this.entriesArray.map(CborMap.entryDebug).join(", ")}})`;
	}
	get diagnostic() {
		return `{${this.entriesArray.map(CborMap.entryDiagnostic).join(", ")}}`;
	}
	static entryDebug(entry) {
		const keyDebug = CborMap.formatDebug(entry.key);
		const valueDebug = CborMap.formatDebug(entry.value);
		return `0x${bytesToHex$3(encodeCbor$1$4(entry.key))}: (${keyDebug}, ${valueDebug})`;
	}
	static formatDebug(cbor) {
		switch (cbor.type) {
			case MajorType$3.Unsigned: return `unsigned(${cbor.value})`;
			case MajorType$3.Negative: return `negative(${typeof cbor.value === "bigint" ? -cbor.value - 1n : -cbor.value - 1})`;
			case MajorType$3.ByteString: return `bytes(${bytesToHex$3(cbor.value)})`;
			case MajorType$3.Text: return `text("${cbor.value}")`;
			case MajorType$3.Array: return `array([${cbor.value.map(CborMap.formatDebug).join(", ")}])`;
			case MajorType$3.Map: return cbor.value.debug;
			case MajorType$3.Tagged: return `tagged(${cbor.tag}, ${CborMap.formatDebug(cbor.value)})`;
			case MajorType$3.Simple: {
				const simple = cbor.value;
				if (typeof simple === "object" && simple !== null && "type" in simple) switch (simple.type) {
					case "True": return "simple(true)";
					case "False": return "simple(false)";
					case "Null": return "simple(null)";
					case "Float": return `simple(${simple.value})`;
				}
				return "simple";
			}
			default: return diagnostic$3(cbor);
		}
	}
	static entryDiagnostic(entry) {
		return `${diagnostic$3(entry.key)}: ${diagnostic$3(entry.value)}`;
	}
	*[Symbol.iterator]() {
		for (const entry of this.entriesArray) yield [entry.key, entry.value];
	}
	toMap() {
		const map = /* @__PURE__ */ new Map();
		for (const entry of this.entriesArray) map.set(extractCbor$3(entry.key), extractCbor$3(entry.value));
		return map;
	}
};
/**
* Clone helper used to give each descendant subtree an independent copy of
* the post-visit state — mirrors Rust `State: Clone` + `state.clone()` per
* child in `walk.rs`. Falls back to the value as-is for primitives (which
* don't need cloning) and uses `structuredClone` for objects.
*/
const cloneState$2 = (s) => {
	if (s === null) return s;
	const t = typeof s;
	if (t !== "object" && t !== "function") return s;
	return globalThis.structuredClone(s);
};
/**
* Walk a CBOR tree, visiting each element with a visitor function.
*
* The visitor function is called for each element in the tree, in depth-first order.
* State semantics mirror Rust's `walk_internal`:
*
* - The visitor's returned `newState` propagates **down** to descendants of
*   the just-visited node only.
* - Sibling subtrees each receive an independent clone of the parent's
*   post-visit state, so accumulating mutations in one subtree never leak
*   into a sibling.
* - State changes do not propagate **up**: the public `walk` returns `void`.
*
* For maps, the visitor is called with:
* 1. A 'keyvalue' element containing both key and value
* 2. The key individually (if descent wasn't stopped)
* 3. The value individually (if descent wasn't stopped)
*
* @template State - The type of state to pass into each visit
* @param cbor - The CBOR value to traverse
* @param initialState - Initial state value
* @param visitor - Function to call for each element
*/
const walk$2 = (cbor, initialState, visitor) => {
	walkInternal$2(cbor, 0, { type: "none" }, initialState, visitor);
};
/**
* Internal recursive walk implementation.
*
* @internal
*/
function walkInternal$2(cbor, level, edge, state, visitor) {
	const [postVisitState, stop] = visitor({
		type: "single",
		cbor
	}, level, edge, state);
	if (stop) return;
	switch (cbor.type) {
		case MajorType$3.Array:
			walkArray$2(cbor, level, postVisitState, visitor);
			break;
		case MajorType$3.Map:
			walkMap$2(cbor, level, postVisitState, visitor);
			break;
		case MajorType$3.Tagged: walkTagged$2(cbor, level, postVisitState, visitor);
	}
}
/**
* Walk an array's elements. Each element is visited with an independent
* clone of `parentState`.
*
* @internal
*/
function walkArray$2(cbor, level, parentState, visitor) {
	for (let index = 0; index < cbor.value.length; index++) {
		const item = cbor.value[index];
		if (item === void 0) throw new CborError$3({
			type: "Custom",
			message: `Array element at index ${index} is undefined`
		});
		walkInternal$2(item, level + 1, {
			type: "array_element",
			index
		}, cloneState$2(parentState), visitor);
	}
}
/**
* Walk a map's key-value pairs.
*
* Each kv pair receives a clone of `parentState`. If descent isn't stopped,
* the key and value subtrees receive independent clones of the kv-visit's
* post-visit state.
*
* @internal
*/
function walkMap$2(cbor, level, parentState, visitor) {
	for (const entry of cbor.value.entriesArray) {
		const { key, value } = entry;
		const [kvPostState, kvStop] = visitor({
			type: "keyvalue",
			key,
			value
		}, level + 1, { type: "map_key_value" }, cloneState$2(parentState));
		if (kvStop) continue;
		walkInternal$2(key, level + 1, { type: "map_key" }, cloneState$2(kvPostState), visitor);
		walkInternal$2(value, level + 1, { type: "map_value" }, cloneState$2(kvPostState), visitor);
	}
}
/**
* Walk a tagged value's content. The content visit receives a clone of
* `parentState`.
*
* @internal
*/
function walkTagged$2(cbor, level, parentState, visitor) {
	walkInternal$2(cbor.value, level + 1, { type: "tagged_content" }, cloneState$2(parentState), visitor);
}
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*/
const MajorType$3 = {
	Unsigned: 0,
	Negative: 1,
	ByteString: 2,
	Text: 3,
	Array: 4,
	Map: 5,
	Tagged: 6,
	Simple: 7
};
const MajorTypeNames$2 = {
	[MajorType$3.Unsigned]: "Unsigned",
	[MajorType$3.Negative]: "Negative",
	[MajorType$3.ByteString]: "ByteString",
	[MajorType$3.Text]: "Text",
	[MajorType$3.Array]: "Array",
	[MajorType$3.Map]: "Map",
	[MajorType$3.Tagged]: "Tagged",
	[MajorType$3.Simple]: "Simple"
};
const getMajorTypeName$2 = (type) => MajorTypeNames$2[type];
const isCborNumber$3 = (value) => {
	return typeof value === "number" || typeof value === "bigint";
};
const isCbor$3 = (value) => {
	return value !== null && typeof value === "object" && "isCbor" in value && value.isCbor === true;
};
/**
* Type guard to check if value has taggedCbor method.
*/
/**
* Resolve a numeric/bigint tag value to a `Tag` object, looking up the
* canonical name from the global tags store (matches Rust's
* `try_into_tagged_value` returning the stored `Tag`). Falls back to a
* name-less `{ value }` if no name is registered — never synthesizes a
* placeholder `tag-${value}` string.
*/
const resolveTag$2 = (value) => {
	const stored = getGlobalTagsStore$3().tagForValue(value);
	if (stored !== void 0) return stored;
	return { value };
};
const hasTaggedCbor$3 = (value) => {
	return typeof value === "object" && value !== null && "taggedCbor" in value && typeof value.taggedCbor === "function";
};
/**
* Type guard to check if value has toCbor method.
*/
const hasToCbor$3 = (value) => {
	return typeof value === "object" && value !== null && "toCbor" in value && typeof value.toCbor === "function";
};
/**
* Convert any value to a CBOR representation.
* Matches Rust's `From` trait implementations for CBOR.
*/
const cbor$3 = (value) => {
	if (isCbor$3(value) && "toData" in value) return value;
	if (isCbor$3(value)) return attachMethods$3(value);
	let result;
	if (isCborNumber$3(value)) {
		if (typeof value === "number" && Number.isNaN(value)) result = {
			isCbor: true,
			type: MajorType$3.Simple,
			value: {
				type: "Float",
				value: NaN
			}
		};
		else if (typeof value === "number" && hasFractionalPart$2(value)) result = {
			isCbor: true,
			type: MajorType$3.Simple,
			value: {
				type: "Float",
				value
			}
		};
		else if (value == Infinity) result = {
			isCbor: true,
			type: MajorType$3.Simple,
			value: {
				type: "Float",
				value: Infinity
			}
		};
		else if (value == -Infinity) result = {
			isCbor: true,
			type: MajorType$3.Simple,
			value: {
				type: "Float",
				value: -Infinity
			}
		};
		else if (typeof value === "number" && !Number.isSafeInteger(value)) {
			const big = BigInt(value);
			if (big >= 0n && big <= 18446744073709551615n) result = {
				isCbor: true,
				type: MajorType$3.Unsigned,
				value: big
			};
			else if (big < 0n && big >= -18446744073709551616n) result = {
				isCbor: true,
				type: MajorType$3.Negative,
				value: -big - 1n
			};
			else result = {
				isCbor: true,
				type: MajorType$3.Simple,
				value: {
					type: "Float",
					value
				}
			};
		} else if (typeof value === "bigint" && (value > 18446744073709551615n || value < -18446744073709551616n)) throw new CborError$3({ type: "OutOfRange" });
		else if (value < 0) {
			if (typeof value === "bigint") result = {
				isCbor: true,
				type: MajorType$3.Negative,
				value: -value - 1n
			};
			else result = {
				isCbor: true,
				type: MajorType$3.Negative,
				value: -value - 1
			};
		} else result = {
			isCbor: true,
			type: MajorType$3.Unsigned,
			value
		};
	} else if (typeof value === "string") {
		const normalized = value.normalize("NFC");
		result = {
			isCbor: true,
			type: MajorType$3.Text,
			value: normalized
		};
	} else if (value === null || value === void 0) result = {
		isCbor: true,
		type: MajorType$3.Simple,
		value: { type: "Null" }
	};
	else if (value === true) result = {
		isCbor: true,
		type: MajorType$3.Simple,
		value: { type: "True" }
	};
	else if (value === false) result = {
		isCbor: true,
		type: MajorType$3.Simple,
		value: { type: "False" }
	};
	else if (Array.isArray(value)) result = {
		isCbor: true,
		type: MajorType$3.Array,
		value: value.map(cbor$3)
	};
	else if (value instanceof Uint8Array) result = {
		isCbor: true,
		type: MajorType$3.ByteString,
		value
	};
	else if (value instanceof CborMap$3) result = {
		isCbor: true,
		type: MajorType$3.Map,
		value
	};
	else if (value instanceof Map) result = {
		isCbor: true,
		type: MajorType$3.Map,
		value: new CborMap$3(value)
	};
	else if (value instanceof Set) result = {
		isCbor: true,
		type: MajorType$3.Array,
		value: Array.from(value).map((v) => cbor$3(v))
	};
	else if (hasTaggedCbor$3(value)) return value.taggedCbor();
	else if (hasToCbor$3(value)) return value.toCbor();
	else if (typeof value === "object" && value !== null && "tag" in value && "value" in value) {
		const keys = Object.keys(value);
		const objValue = value;
		if (keys.length === 2 && keys.includes("tag") && keys.includes("value")) return taggedCbor$2(objValue.tag, objValue.value);
		const map = new CborMap$3();
		for (const [key, val] of Object.entries(value)) map.set(cbor$3(key), cbor$3(val));
		result = {
			isCbor: true,
			type: MajorType$3.Map,
			value: map
		};
	} else if (typeof value === "object" && value !== null) {
		const map = new CborMap$3();
		for (const [key, val] of Object.entries(value)) map.set(cbor$3(key), cbor$3(val));
		result = {
			isCbor: true,
			type: MajorType$3.Map,
			value: map
		};
	} else throw new CborError$3({
		type: "Custom",
		message: "Unsupported type for CBOR encoding"
	});
	return attachMethods$3(result);
};
/**
* Encode a CBOR value to binary data.
* Matches Rust's `CBOR::to_cbor_data()` method.
*
* Delegates to `@blockchaincommons/dcbor` — the canonical encoder — via the
* structural node bridge.
*/
const cborData$2 = (value) => {
	const c = cbor$3(value);
	return delegating$2(() => encodeCbor$5(toNew$2(c)));
};
const encodeCbor$1$4 = (value) => {
	return cborData$2(cbor$3(value));
};
const taggedCbor$2 = (tag, value) => {
	const tagNumber = typeof tag === "number" || typeof tag === "bigint" ? tag : Number(tag);
	return attachMethods$3({
		isCbor: true,
		type: MajorType$3.Tagged,
		tag: tagNumber,
		value: cbor$3(value)
	});
};
const toByteString = (data) => {
	return cbor$3(data);
};
const toTaggedValue = (tag, item) => {
	const tagValue = typeof tag === "object" && "value" in tag ? tag.value : tag;
	return attachMethods$3({
		isCbor: true,
		type: MajorType$3.Tagged,
		tag: tagValue,
		value: cbor$3(item)
	});
};
/**
* Attaches instance methods to a CBOR value.
* This enables method chaining like cbor.toHex() instead of Cbor.toHex(cbor).
* @internal
*/
const attachMethods$3 = (obj) => {
	return Object.assign(obj, {
		toData() {
			return cborData$2(this);
		},
		toHex() {
			return bytesToHex$3(cborData$2(this));
		},
		toHexAnnotated(tagsStore) {
			tagsStore = tagsStore ?? getGlobalTagsStore$3();
			return hexOpt$2(this, {
				annotate: true,
				tagsStore
			});
		},
		toString() {
			return diagnosticOpt$2(this, { flat: true });
		},
		toDebugString() {
			return diagnosticOpt$2(this, { flat: false });
		},
		toDiagnostic() {
			return diagnosticOpt$2(this, { flat: false });
		},
		toDiagnosticAnnotated() {
			return diagnosticOpt$2(this, { annotate: true });
		},
		isByteString() {
			return this.type === MajorType$3.ByteString;
		},
		isText() {
			return this.type === MajorType$3.Text;
		},
		isArray() {
			return this.type === MajorType$3.Array;
		},
		isMap() {
			return this.type === MajorType$3.Map;
		},
		isTagged() {
			return this.type === MajorType$3.Tagged;
		},
		isSimple() {
			return this.type === MajorType$3.Simple;
		},
		isBool() {
			return this.type === MajorType$3.Simple && (this.value.type === "True" || this.value.type === "False");
		},
		isTrue() {
			return this.type === MajorType$3.Simple && this.value.type === "True";
		},
		isFalse() {
			return this.type === MajorType$3.Simple && this.value.type === "False";
		},
		isNull() {
			return this.type === MajorType$3.Simple && this.value.type === "Null";
		},
		isNumber() {
			if (this.type === MajorType$3.Unsigned || this.type === MajorType$3.Negative) return true;
			if (this.type === MajorType$3.Simple) return isFloat$1$2(this.value);
			return false;
		},
		isInteger() {
			return this.type === MajorType$3.Unsigned || this.type === MajorType$3.Negative;
		},
		isUnsigned() {
			return this.type === MajorType$3.Unsigned;
		},
		isNegative() {
			return this.type === MajorType$3.Negative;
		},
		isNaN() {
			return this.type === MajorType$3.Simple && this.value.type === "Float" && Number.isNaN(this.value.value);
		},
		isFloat() {
			return this.type === MajorType$3.Simple && isFloat$1$2(this.value);
		},
		asByteString() {
			return this.type === MajorType$3.ByteString ? this.value : void 0;
		},
		asText() {
			return this.type === MajorType$3.Text ? this.value : void 0;
		},
		asArray() {
			return this.type === MajorType$3.Array ? this.value : void 0;
		},
		asMap() {
			return this.type === MajorType$3.Map ? this.value : void 0;
		},
		asTagged() {
			if (this.type !== MajorType$3.Tagged) return;
			return [resolveTag$2(this.tag), this.value];
		},
		asBool() {
			if (this.type !== MajorType$3.Simple) return void 0;
			if (this.value.type === "True") return true;
			if (this.value.type === "False") return false;
		},
		asInteger() {
			if (this.type === MajorType$3.Unsigned) return this.value;
			else if (this.type === MajorType$3.Negative) {
				if (typeof this.value === "bigint") return -this.value - 1n;
				else return -this.value - 1;
			}
		},
		asNumber() {
			if (this.type === MajorType$3.Unsigned) return this.value;
			else if (this.type === MajorType$3.Negative) {
				if (typeof this.value === "bigint") return -this.value - 1n;
				else return -this.value - 1;
			} else if (this.type === MajorType$3.Simple && isFloat$1$2(this.value)) return this.value.value;
		},
		asSimpleValue() {
			return this.type === MajorType$3.Simple ? this.value : void 0;
		},
		toByteString() {
			if (this.type !== MajorType$3.ByteString) throw new TypeError(`Cannot convert CBOR to ByteString: expected ByteString type, got ${getMajorTypeName$2(this.type)}`);
			return this.value;
		},
		toText() {
			if (this.type !== MajorType$3.Text) throw new TypeError(`Cannot convert CBOR to Text: expected Text type, got ${getMajorTypeName$2(this.type)}`);
			return this.value;
		},
		toArray() {
			if (this.type !== MajorType$3.Array) throw new TypeError(`Cannot convert CBOR to Array: expected Array type, got ${getMajorTypeName$2(this.type)}`);
			return this.value;
		},
		toMap() {
			if (this.type !== MajorType$3.Map) throw new TypeError(`Cannot convert CBOR to Map: expected Map type, got ${getMajorTypeName$2(this.type)}`);
			return this.value;
		},
		toTagged() {
			if (this.type !== MajorType$3.Tagged) throw new TypeError(`Cannot convert CBOR to Tagged: expected Tagged type, got ${getMajorTypeName$2(this.type)}`);
			return [resolveTag$2(this.tag), this.value];
		},
		toBool() {
			const result = this.asBool();
			if (result === void 0) throw new TypeError(`Cannot convert CBOR to boolean: expected Simple(True/False) type, got ${getMajorTypeName$2(this.type)}`);
			return result;
		},
		toInteger() {
			const result = this.asInteger();
			if (result === void 0) throw new TypeError(`Cannot convert CBOR to integer: expected Unsigned or Negative type, got ${getMajorTypeName$2(this.type)}`);
			return result;
		},
		toNumber() {
			const result = this.asNumber();
			if (result === void 0) throw new TypeError(`Cannot convert CBOR to number: expected Unsigned, Negative, or Float type, got ${getMajorTypeName$2(this.type)}`);
			return result;
		},
		toSimpleValue() {
			if (this.type !== MajorType$3.Simple) throw new TypeError(`Cannot convert CBOR to Simple: expected Simple type, got ${getMajorTypeName$2(this.type)}`);
			return this.value;
		},
		expectTag(expectedTag) {
			if (this.type !== MajorType$3.Tagged) throw new CborError$3({ type: "WrongType" });
			const expected = typeof expectedTag === "object" && "value" in expectedTag ? expectedTag : { value: expectedTag };
			if (!tagValuesEqual$3(this.tag, expected.value)) throw new CborError$3({
				type: "WrongTag",
				expected,
				actual: { value: this.tag }
			});
			return this.value;
		},
		walk(initialState, visitor) {
			walk$2(this, initialState, visitor);
		},
		validateTag(expectedTags) {
			if (this.type !== MajorType$3.Tagged) throw new CborError$3({ type: "WrongType" });
			const tagValue = this.tag;
			const matchingTag = expectedTags.find((t) => tagValuesEqual$3(t.value, tagValue));
			if (matchingTag === void 0) throw new CborError$3({
				type: "WrongTag",
				expected: expectedTags[0],
				actual: { value: tagValue }
			});
			return matchingTag;
		},
		untagged() {
			if (this.type !== MajorType$3.Tagged) throw new CborError$3({ type: "WrongType" });
			return this.value;
		}
	});
};
attachMethods$3({
	isCbor: true,
	type: MajorType$3.Simple,
	value: { type: "False" }
}), attachMethods$3({
	isCbor: true,
	type: MajorType$3.Simple,
	value: { type: "True" }
}), attachMethods$3({
	isCbor: true,
	type: MajorType$3.Simple,
	value: { type: "Null" }
}), attachMethods$3({
	isCbor: true,
	type: MajorType$3.Simple,
	value: {
		type: "Float",
		value: NaN
	}
});
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Tagged CBOR encoding support.
*
* This module provides the `CborTaggedEncodable` interface, which enables types to
* be encoded as tagged CBOR values.
*
* CBOR tags provide semantic information about the encoded data. For example,
* tag 1 is used for dates, indicating that the value should be interpreted
* as a timestamp. The dCBOR library ensures these tags are encoded
* deterministically.
*
* This interface enables seamless encoding of TypeScript types to properly tagged CBOR
* values.
*
* @module cbor-tagged-encodable
*/
/**
* Helper function to create tagged CBOR from an encodable object.
*
* Uses the first tag from cborTags().
*
* @param encodable - Object implementing CborTaggedEncodable
* @returns Tagged CBOR value
*/
const createTaggedCbor = (encodable) => {
	const tags = encodable.cborTags();
	if (tags.length === 0) throw new CborError$3({
		type: "Custom",
		message: "No tags defined for this type"
	});
	const tag = tags[0];
	if (tag === void 0) throw new CborError$3({
		type: "Custom",
		message: "Tag is undefined"
	});
	const untagged = encodable.untaggedCbor();
	return attachMethods$3({
		isCbor: true,
		type: MajorType$3.Tagged,
		tag: tag.value,
		value: untagged
	});
};
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Tagged CBOR decoding support.
*
* This module provides the `CborTaggedDecodable` interface, which enables types to
* be decoded from tagged CBOR values.
*
* Tagged CBOR values include semantic information about how to interpret the
* data. This interface allows TypeScript types to verify that incoming CBOR data has the
* expected tag(s) and to decode the data appropriately.
*
* @module cbor-tagged-decodable
*/
/**
* Helper function to validate that a CBOR value has one of the expected tags.
*
* @param cbor - CBOR value to validate
* @param expectedTags - Array of valid tags
* @returns The matching tag
* @throws Error if the value is not tagged or has an unexpected tag
*/
const validateTag = (cbor, expectedTags) => {
	if (cbor.type !== MajorType$3.Tagged) throw new CborError$3({ type: "WrongType" });
	const tagValue = cbor.tag;
	const matchingTag = expectedTags.find((t) => tagValuesEqual$3(t.value, tagValue));
	if (matchingTag === void 0) throw new CborError$3({
		type: "WrongTag",
		expected: expectedTags[0],
		actual: { value: tagValue }
	});
	return matchingTag;
};
/**
* Helper function to extract the content from a tagged CBOR value.
*
* @param cbor - Tagged CBOR value
* @returns The untagged content
* @throws Error if the value is not tagged
*/
const extractTaggedContent = (cbor) => {
	if (cbor.type !== MajorType$3.Tagged) throw new CborError$3({ type: "WrongType" });
	return cbor.value;
};
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Date/time support for CBOR with tag(1) encoding.
*
* A CBOR-friendly representation of a date and time.
*
* The `CborDate` type keeps the historical `@blockchaincommons/dcbor-compat` API
* (`fromTimestamp`/`timestamp()`/`fromDatetime`/`datetime()` alongside the
* tagged-CBOR protocol methods) but wraps the canonical
* `@blockchaincommons/dcbor` `CborDate`, which owns timestamp normalization
* (Rust `Date::from_timestamp` parity), strict RFC-3339 parsing, and
* ISO-8601 formatting.
*
* When encoded to CBOR, dates are represented as tag 1 followed by a numeric
* value representing the number of seconds since (or before) the Unix epoch
* (1970-01-01T00:00:00Z). The numeric value can be a positive or negative
* integer, or a floating-point value for dates with fractional seconds.
*
* @module date
*/
/**
* A CBOR-friendly representation of a date and time.
*
* When encoded to CBOR, dates are represented as tag 1 followed by a numeric
* value representing the number of seconds since (or before) the Unix epoch
* (1970-01-01T00:00:00Z). The numeric value can be a positive or negative
* integer, or a floating-point value for dates with fractional seconds.
*
* # Features
*
* - Supports UTC dates with optional fractional seconds
* - Provides convenient constructors for common date creation patterns
* - Implements the `CborTagged`, `CborTaggedEncodable`, and
*   `CborTaggedDecodable` interfaces
* - Supports arithmetic operations with durations and between dates
*
* @example
* ```typescript
* import { CborDate } from './date';
*
* // Create a date from a timestamp (seconds since Unix epoch)
* const date = CborDate.fromTimestamp(1675854714.0);
*
* // Create a date from year, month, day
* const date2 = CborDate.fromYmd(2023, 2, 8);
*
* // Convert to CBOR
* const cborValue = date.taggedCbor();
*
* // Decode from CBOR
* const decoded = CborDate.fromTaggedCbor(cborValue);
* ```
*/
var CborDate = class CborDate {
	/**
	* The wrapped canonical `@blockchaincommons/dcbor` date. It stores the
	* normalized timestamp (seconds since the Unix epoch as an `f64`), so
	* encoding, equality, and ordering match the Rust reference exactly.
	*/
	_date;
	/**
	* Creates a new `CborDate` from the given JavaScript `Date`.
	*
	* @param dateTime - A `Date` instance to wrap
	* @returns A new `CborDate` instance
	*
	* @example
	* ```typescript
	* const datetime = new Date();
	* const date = CborDate.fromDatetime(datetime);
	* ```
	*/
	static fromDatetime(dateTime) {
		return new CborDate(delegating$2(() => CborDate$1.fromDate(dateTime)));
	}
	/**
	* Creates a new `CborDate` from year, month, and day components.
	*
	* This method creates a new `CborDate` with the time set to 00:00:00 UTC.
	*
	* @param year - The year component (e.g., 2023)
	* @param month - The month component (1-12)
	* @param day - The day component (1-31)
	* @returns A new `CborDate` instance
	*
	* @example
	* ```typescript
	* // Create February 8, 2023
	* const date = CborDate.fromYmd(2023, 2, 8);
	* ```
	*/
	static fromYmd(year, month, day) {
		return new CborDate(delegating$2(() => CborDate$1.fromYmd(year, month, day)));
	}
	/**
	* Creates a new `CborDate` from year, month, day, hour, minute, and second
	* components.
	*
	* @param year - The year component (e.g., 2023)
	* @param month - The month component (1-12)
	* @param day - The day component (1-31)
	* @param hour - The hour component (0-23)
	* @param minute - The minute component (0-59)
	* @param second - The second component (0-59)
	* @returns A new `CborDate` instance
	*
	* @example
	* ```typescript
	* // Create February 8, 2023, 15:30:45 UTC
	* const date = CborDate.fromYmdHms(2023, 2, 8, 15, 30, 45);
	* ```
	*/
	static fromYmdHms(year, month, day, hour, minute, second) {
		return new CborDate(delegating$2(() => CborDate$1.fromYmdHms(year, month, day, hour, minute, second)));
	}
	/**
	* Creates a new `CborDate` from seconds since (or before) the Unix epoch.
	*
	* The value is normalized on construction (matching Rust's
	* `Date::from_timestamp`) so the stored value — and thus its encoding,
	* equality, and ordering — matches the reference.
	*
	* @param secondsSinceUnixEpoch - Seconds from the Unix epoch (positive or
	*   negative), which can include a fractional part for sub-second
	*   precision
	* @returns A new `CborDate` instance
	*
	* @example
	* ```typescript
	* // Create a date from a timestamp
	* const date = CborDate.fromTimestamp(1675854714.0);
	*
	* // Create a date one second before the Unix epoch
	* const beforeEpoch = CborDate.fromTimestamp(-1.0);
	*
	* // Create a date with fractional seconds
	* const withFraction = CborDate.fromTimestamp(1675854714.5);
	* ```
	*/
	static fromTimestamp(secondsSinceUnixEpoch) {
		return new CborDate(delegating$2(() => CborDate$1.fromEpochSeconds(secondsSinceUnixEpoch)));
	}
	/**
	* Creates a new `CborDate` from a string containing an ISO-8601 (RFC-3339)
	* date (with or without time).
	*
	* Accepts only strict RFC-3339 date-times (with seconds and an explicit
	* `Z`/±HH:MM offset) or bare `YYYY-MM-DD` dates (read as UTC midnight),
	* matching Rust's `Date::from_string`.
	*
	* @param value - A string containing a date or date-time in ISO-8601/RFC-3339
	*   format
	* @returns A new `CborDate` instance if parsing succeeds
	* @throws Error if the string cannot be parsed as a valid date or date-time
	*
	* @example
	* ```typescript
	* // Parse a date-time string
	* const date = CborDate.fromString("2023-02-08T15:30:45Z");
	*
	* // Parse a date-only string (time will be set to 00:00:00)
	* const date2 = CborDate.fromString("2023-02-08");
	* ```
	*/
	static fromString(value) {
		return new CborDate(delegating$2(() => CborDate$1.fromString(value)));
	}
	/**
	* Creates a new `CborDate` containing the current date and time.
	*
	* @returns A new `CborDate` instance representing the current UTC date and time
	*
	* @example
	* ```typescript
	* const now = CborDate.now();
	* ```
	*/
	static now() {
		return new CborDate(delegating$2(() => CborDate$1.now()));
	}
	/**
	* Creates a new `CborDate` containing the current date and time plus the given
	* duration.
	*
	* @param durationMs - The duration in milliseconds to add to the current time
	* @returns A new `CborDate` instance representing the current UTC date and time plus
	* the duration
	*
	* @example
	* ```typescript
	* // Get a date 1 hour from now
	* const oneHourLater = CborDate.withDurationFromNow(3600 * 1000);
	* ```
	*/
	static withDurationFromNow(durationMs) {
		const future = new Date((/* @__PURE__ */ new Date()).getTime() + durationMs);
		return CborDate.fromDatetime(future);
	}
	/**
	* Returns the underlying JavaScript `Date` object.
	*
	* @returns The wrapped `Date` instance
	*
	* @example
	* ```typescript
	* const date = CborDate.now();
	* const datetime = date.datetime();
	* const year = datetime.getFullYear();
	* ```
	*/
	datetime() {
		return this._date.toDate();
	}
	/**
	* Returns the `CborDate` as the number of seconds since the Unix epoch.
	*
	* Negative values represent times before the epoch. The fractional
	* part represents sub-second precision.
	*
	* @returns Seconds since the Unix epoch as a `number`
	*
	* @example
	* ```typescript
	* const date = CborDate.fromYmd(2023, 2, 8);
	* const timestamp = date.timestamp();
	* ```
	*/
	timestamp() {
		return this._date.epochSeconds;
	}
	/**
	* Add seconds to this date.
	*
	* @param seconds - Seconds to add (can be fractional)
	* @returns New CborDate instance
	*
	* @example
	* ```typescript
	* const date = CborDate.fromYmd(2022, 3, 21);
	* const tomorrow = date.add(24 * 60 * 60);
	* ```
	*/
	add(seconds) {
		return CborDate.fromTimestamp(this.timestamp() + seconds);
	}
	/**
	* Subtract seconds from this date.
	*
	* @param seconds - Seconds to subtract (can be fractional)
	* @returns New CborDate instance
	*
	* @example
	* ```typescript
	* const date = CborDate.fromYmd(2022, 3, 21);
	* const yesterday = date.subtract(24 * 60 * 60);
	* ```
	*/
	subtract(seconds) {
		return CborDate.fromTimestamp(this.timestamp() - seconds);
	}
	/**
	* Get the difference in seconds between this date and another.
	*
	* @param other - Other CborDate to compare with
	* @returns Difference in seconds (this - other)
	*
	* @example
	* ```typescript
	* const date1 = CborDate.fromYmd(2022, 3, 22);
	* const date2 = CborDate.fromYmd(2022, 3, 21);
	* const diff = date1.difference(date2);
	* // Returns 86400 (one day in seconds)
	* ```
	*/
	difference(other) {
		return this.timestamp() - other.timestamp();
	}
	/**
	* Implementation of the `CborTagged` interface for `CborDate`.
	*
	* This implementation specifies that `CborDate` values are tagged with CBOR tag 1,
	* which is the standard CBOR tag for date/time values represented as seconds
	* since the Unix epoch per RFC 8949.
	*
	* @returns A vector containing tag 1
	*/
	cborTags() {
		return [createTag$1(1, "date")];
	}
	/**
	* Implementation of the `CborTaggedEncodable` interface for `CborDate`.
	*
	* Converts this `CborDate` to an untagged CBOR value.
	*
	* The date is converted to a numeric value representing the number of
	* seconds since the Unix epoch. This value may be an integer or a
	* floating-point number, depending on whether the date has fractional
	* seconds.
	*
	* @returns A CBOR value representing the timestamp
	*/
	untaggedCbor() {
		return cbor$3(this.timestamp());
	}
	/**
	* Converts this `CborDate` to a tagged CBOR value with tag 1.
	*
	* @returns Tagged CBOR value
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Implementation of the `CborTaggedDecodable` interface for `CborDate`.
	*
	* Creates a `CborDate` from an untagged CBOR value.
	*
	* The CBOR value must be a numeric value (integer or floating-point)
	* representing the number of seconds since the Unix epoch.
	*
	* @param cbor - The untagged CBOR value
	* @returns This CborDate instance (mutated)
	* @throws Error if the CBOR value is not a valid timestamp
	*/
	fromUntaggedCbor(cbor) {
		let timestamp;
		switch (cbor.type) {
			case MajorType$3.Unsigned:
				timestamp = typeof cbor.value === "number" ? cbor.value : Number(cbor.value);
				break;
			case MajorType$3.Negative:
				if (typeof cbor.value === "bigint") timestamp = Number(-cbor.value - 1n);
				else timestamp = -cbor.value - 1;
				break;
			case MajorType$3.Simple:
				if (cbor.value.type === "Float") timestamp = cbor.value.value;
				else throw new CborError$3({ type: "WrongType" });
				break;
			default: throw new CborError$3({ type: "WrongType" });
		}
		this._date = delegating$2(() => CborDate$1.fromEpochSeconds(timestamp));
		return this;
	}
	/**
	* Creates a `CborDate` from a tagged CBOR value with tag 1.
	*
	* @param cbor - Tagged CBOR value
	* @returns This CborDate instance (mutated)
	* @throws Error if the CBOR value has the wrong tag or cannot be decoded
	*/
	fromTaggedCbor(cbor) {
		const expectedTags = this.cborTags();
		validateTag(cbor, expectedTags);
		const content = extractTaggedContent(cbor);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to create a CborDate from tagged CBOR.
	*
	* @param cbor - Tagged CBOR value
	* @returns New CborDate instance
	*/
	static fromTaggedCbor(cbor) {
		return new CborDate().fromTaggedCbor(cbor);
	}
	/**
	* Static method to create a CborDate from untagged CBOR.
	*
	* @param cbor - Untagged CBOR value
	* @returns New CborDate instance
	*/
	static fromUntaggedCbor(cbor) {
		return new CborDate().fromUntaggedCbor(cbor);
	}
	/**
	* Implementation of the `toString` method for `CborDate`.
	*
	* This implementation provides a string representation of a `CborDate` in ISO-8601
	* format. For dates with time exactly at midnight (00:00:00), only the date
	* part is shown. For other times, a full date-time string is shown.
	*
	* @returns String representation in ISO-8601 format
	*
	* @example
	* ```typescript
	* // A date at midnight will display as just the date
	* const date = CborDate.fromYmd(2023, 2, 8);
	* // Returns "2023-02-08"
	* console.log(date.toString());
	*
	* // A date with time will display as date and time
	* const date2 = CborDate.fromYmdHms(2023, 2, 8, 15, 30, 45);
	* // Returns "2023-02-08T15:30:45Z"
	* console.log(date2.toString());
	* ```
	*/
	toString() {
		return this._date.toString();
	}
	/**
	* Compare two dates for equality.
	*
	* @param other - Other CborDate to compare
	* @returns true if dates represent the same moment in time
	*/
	equals(other) {
		return this.timestamp() === other.timestamp();
	}
	/**
	* Compare two dates.
	*
	* @param other - Other CborDate to compare
	* @returns -1 if this < other, 0 if equal, 1 if this > other
	*/
	compare(other) {
		if (this.timestamp() < other.timestamp()) return -1;
		if (this.timestamp() > other.timestamp()) return 1;
		return 0;
	}
	/**
	* Convert to JSON (returns ISO 8601 string).
	*
	* @returns ISO 8601 string
	*/
	toJSON() {
		return this.toString();
	}
	constructor(date) {
		this._date = date ?? CborDate$1.now();
	}
};
/**
* Converts an array of tag values to their corresponding Tag objects.
* Matches Rust's tags_for_values() function.
*
* This function looks up each tag value in the global tag registry and returns
* an array of complete Tag objects. For any tag values that aren't
* registered in the global registry, it creates a basic Tag with just the
* value (no name).
*
* @param values - Array of numeric tag values to convert
* @returns Array of Tag objects corresponding to the input values
*
* @example
* ```typescript
* // Register some tags first
* registerTags();
*
* // Convert tag values to Tag objects
* const tags = tagsForValues([1, 42, 999]);
*
* // The first tag (value 1) should be registered as "date"
* console.log(tags[0].value); // 1
* console.log(tags[0].name); // "date"
*
* // Unregistered tags will have a value but no name
* console.log(tags[1].value); // 42
* console.log(tags[2].value); // 999
* ```
*/
const tagsForValues = (values) => {
	const globalStore = getGlobalTagsStore$3();
	return values.map((value) => {
		const tag = globalStore.tagForValue(value);
		if (tag !== void 0) return tag;
		return createTag$1(value);
	});
};
//#endregion
//#region ../bc-tags-ts/tests/baseline/tags-baseline.mjs
const MajorType$1$1 = {
	Unsigned: 0,
	Negative: 1,
	ByteString: 2,
	Text: 3,
	Array: 4,
	Map: 5,
	Tagged: 6,
	Simple: 7
};
const isCborNumber$1$1 = (value) => {
	return typeof value === "number" || typeof value === "bigint";
};
const isCbor$1$1 = (value) => {
	return value !== null && typeof value === "object" && "isCbor" in value && value.isCbor === true;
};
/**
* Compare two tag values for equality, normalizing `number` vs `bigint`.
* A raw `===` would treat `100n` and `100` as unequal, so a large tag that
* decoded to a `bigint` wouldn't match the same value written as a `number`.
*
* @internal Exported for cross-module use; not part of the public surface -
* use `Tag.equals` instead.
*/
const tagValuesEqual$1$1 = (a, b) => {
	if (typeof a === "bigint" || typeof b === "bigint") return BigInt(a) === BigInt(b);
	return a === b;
};
/**
* Value-type companion for the `Tag` interface: an interface plus a merged
* `const` with a handful of members. It stays small and must not import the
* encode/format graph.
*/
const Tag$1 = {
	/**
	* Create a Tag from its numeric value, optionally with a name.
	*
	* ```typescript
	* Tag.from(1, "date");
	* Tag.from(12345);
	* ```
	*/
	from(value, name) {
		if (name !== void 0) return {
			value,
			name
		};
		return { value };
	},
	/**
	* Compare two tags for equality: compares by `value` only (normalizing
	* `number` vs `bigint`) and ignores the optional `name`.
	*/
	equals(a, b) {
		return tagValuesEqual$1$1(a.value, b.value);
	}
};
/**
* Get the string representation of a tag.
* Internal function used for error messages.
*
* @param tag - The tag to represent
* @returns String representation (name if available, otherwise value)
*
* @internal
*/
const tagToString$1$1 = (tag) => tag.name ?? tag.value.toString();
const captureStackTrace$1 = Error.captureStackTrace;
/**
* The single error type thrown by dCBOR encoding, decoding, and extraction.
*
* @example
* ```typescript
* try {
*   decodeCbor(bytes);
* } catch (e) {
*   if (CborError.isCborError(e) && e.code === "WrongTag") {
*     console.log(e.details.expectedTag, e.details.actualTag);
*   }
* }
* ```
*/
var CborError$1$1 = class CborError extends Error {
	/** Machine-readable discriminant; switch on this to handle errors. */
	code;
	/** Structured, code-specific data (see {@link CborErrorDetails}). */
	details;
	constructor(code, message, details = {}) {
		super(message);
		this.name = "CborError";
		this.code = code;
		this.details = details;
		Object.setPrototypeOf(this, new.target.prototype);
		if (typeof captureStackTrace$1 === "function") captureStackTrace$1(this, CborError);
	}
	/** Type guard: is `value` a {@link CborError}? Narrows to the
	* code-discriminated {@link CborErrorTyped} union. */
	static isCborError(value) {
		return value instanceof CborError;
	}
	/** The CBOR data ended before a complete item could be decoded. */
	static underrun() {
		return new CborError("Underrun", "early end of CBOR data");
	}
	/** An unsupported/invalid value was found in a CBOR header byte. */
	static unsupportedHeaderValue(headerValue) {
		return new CborError("UnsupportedHeaderValue", "unsupported value in CBOR header", { headerValue });
	}
	/** A numeric value was not in its shortest/canonical dCBOR form. */
	static nonCanonicalNumeric() {
		return new CborError("NonCanonicalNumeric", "a CBOR numeric value was encoded in non-canonical form");
	}
	/** A major-type-7 simple value other than false/true/null/float. */
	static invalidSimpleValue() {
		return new CborError("InvalidSimpleValue", "an invalid CBOR simple value was encountered");
	}
	/** A text string was not valid UTF-8 (with the underlying reason). */
	static invalidString(cause) {
		return new CborError("InvalidString", `an invalidly-encoded UTF-8 string was encountered in the CBOR (${cause})`, { cause });
	}
	/** A text string was not in Unicode NFC. */
	static nonCanonicalString() {
		return new CborError("NonCanonicalString", "a CBOR string was not encoded in Unicode Canonical Normalization Form C");
	}
	/** The decoded item left `count` trailing bytes unconsumed. */
	static unusedData(count) {
		return new CborError("UnusedData", `the decoded CBOR had ${count} extra bytes at the end`, { count });
	}
	/** Map keys were not in canonical ascending byte order. */
	static misorderedMapKey() {
		return new CborError("MisorderedMapKey", "the decoded CBOR map has keys that are not in canonical order");
	}
	/** A map contained a duplicate key. */
	static duplicateMapKey() {
		return new CborError("DuplicateMapKey", "the decoded CBOR map has a duplicate key");
	}
	/** A requested map key was not present. */
	static missingMapKey() {
		return new CborError("MissingMapKey", "missing CBOR map key");
	}
	/** A numeric value could not be represented in the target type. */
	static outOfRange() {
		return new CborError("OutOfRange", "the CBOR numeric value could not be represented in the specified numeric type");
	}
	/** The CBOR value was not the type expected by a conversion. */
	static wrongType() {
		return new CborError("WrongType", "the decoded CBOR value was not the expected type");
	}
	/** A tagged value had a tag other than the one expected. */
	static wrongTag(expected, actual) {
		return new CborError("WrongTag", `expected CBOR tag ${tagToString$1$1(expected)}, but got ${tagToString$1$1(actual)}`, {
			expectedTag: expected,
			actualTag: actual
		});
	}
	/** Invalid UTF-8 in a text string (with the underlying reason). */
	static invalidUtf8(cause) {
		return new CborError("InvalidUtf8", `invalid UTF‑8 string: ${cause}`, { cause });
	}
	/** Invalid ISO 8601 / RFC 3339 date string (with the underlying reason). */
	static invalidDate(cause) {
		return new CborError("InvalidDate", `invalid ISO 8601 date string: ${cause}`, { cause });
	}
	/** An arbitrary error carrying a custom message. */
	static custom(message) {
		return new CborError("Custom", message);
	}
};
/**
* Byte-array utilities shared across the library.
*
* @module stdlib
*/
/**
* Check if two byte arrays are equal.
*/
const areBytesEqual$1 = (a, b) => {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
};
/**
* Lexicographically compare two byte arrays.
* Returns: -1 if a < b, 0 if a == b, 1 if a > b
*/
const lexicographicallyCompareBytes$1 = (a, b) => {
	const minLen = Math.min(a.length, b.length);
	for (let i = 0; i < minLen; i++) {
		const aVal = a[i];
		const bVal = b[i];
		if (aVal === void 0 || bVal === void 0) throw CborError$1$1.custom("Unexpected undefined byte in array");
		if (aVal < bVal) return -1;
		if (aVal > bVal) return 1;
	}
	if (a.length < b.length) return -1;
	if (a.length > b.length) return 1;
	return 0;
};
/**
* A map keyed by encoded CBOR key bytes, kept in canonical (lexicographic)
* byte order.
*
* dCBOR needs exactly one specialised container: keys are the encoded bytes of
* a CBOR value, and the map must iterate in ascending lexicographic byte order
* (that ordering is the deterministic wire contract). This is a thin,
* dependency-free structure over a sorted array with binary-search insertion -
* it gives the exact ordering dCBOR requires, and lets the decode hot path
* append in O(1) since canonical input already arrives sorted.
*
* @module sorted-byte-map
*/
var SortedByteMap$1 = class {
	items = [];
	/** Number of entries. */
	get size() {
		return this.items.length;
	}
	/**
	* Binary search for `key`. Returns the index of an exact match, or the
	* negative value `-(insertionPoint) - 1` when absent, so a single search both
	* tests membership and locates where an insert would go (Java
	* `Arrays.binarySearch` convention).
	*/
	indexOf(key) {
		let lo = 0;
		let hi = this.items.length - 1;
		while (lo <= hi) {
			const mid = lo + hi >>> 1;
			const cmp = lexicographicallyCompareBytes$1(this.items[mid].key, key);
			if (cmp < 0) lo = mid + 1;
			else if (cmp > 0) hi = mid - 1;
			else return mid;
		}
		return -(lo + 1);
	}
	/** Insert or replace the entry for `key`. */
	set(key, value) {
		const i = this.indexOf(key);
		if (i >= 0) this.items[i] = {
			key,
			value
		};
		else this.items.splice(-i - 1, 0, {
			key,
			value
		});
	}
	/**
	* Append an entry whose key is strictly greater than every existing key.
	* Used by canonical decode, where keys arrive already sorted; the caller must
	* guarantee the ordering (this skips the search + shift that {@link set} does).
	*/
	appendGreatest(key, value) {
		this.items.push({
			key,
			value
		});
	}
	/** The value for `key`, or `undefined` if absent. */
	get(key) {
		const i = this.indexOf(key);
		return i >= 0 ? this.items[i].value : void 0;
	}
	/** Whether `key` is present. */
	has(key) {
		return this.indexOf(key) >= 0;
	}
	/** Remove `key`; returns whether it was present. */
	delete(key) {
		const i = this.indexOf(key);
		if (i < 0) return false;
		this.items.splice(i, 1);
		return true;
	}
	/** The greatest key currently stored (ascending order), or `undefined`. */
	maxKey() {
		const n = this.items.length;
		return n > 0 ? this.items[n - 1].key : void 0;
	}
	/** Map over each value (with its key) in ascending key order. */
	map(fn) {
		return this.items.map((e) => fn(e.value, e.key));
	}
};
/**
* Numeric boundary contract and helpers.
*
* ## The `number` / `bigint` contract
*
* dCBOR integers span `[-(2^64), 2^64)`, which exceeds JavaScript's safe
* integer range (`±(2^53 − 1)`). The single, repo-wide rule is:
*
* - An integer that fits in the IEEE-754 **safe** range is represented as a
*   `number`; anything larger (in magnitude) is a `bigint`.
* - Decoding returns the **narrowest exact** representation via
*   {@link narrowInteger}, so small values are ergonomic `number`s and large
*   ones remain lossless `bigint`s.
* - Encoding accepts either at the public edge and normalises once.
*
* Every module funnels its boundary logic through this file - nothing else
* should hard-code `Number.MAX_SAFE_INTEGER`, `2^64`, etc.
*
* @module numeric
*/
/** `BigInt(Number.MAX_SAFE_INTEGER)` - largest integer exact as a `number`. */
const SAFE_MAX_BIG$1 = BigInt(Number.MAX_SAFE_INTEGER);
/** `BigInt(Number.MIN_SAFE_INTEGER)`. */
const SAFE_MIN_BIG$1 = BigInt(Number.MIN_SAFE_INTEGER);
/** Smallest dCBOR-encodable integer: −(2^64). */
const CBOR_INT_MIN$1 = -(1n << 64n);
/**
* Return the narrowest exact representation of an integer: a `number` when it
* fits the safe-integer range, otherwise the `bigint` unchanged. This is the
* canonical way to hand an integer back to callers.
*/
const narrowInteger$1 = (value) => value >= SAFE_MIN_BIG$1 && value <= SAFE_MAX_BIG$1 ? Number(value) : value;
/**
* A growable output buffer for encoding.
*
* The encoder writes a whole CBOR tree into a single `BufWriter` rather than
* allocating a fresh `Uint8Array` per node and concatenating them (which
* re-copies every subtree at every level): one buffer, geometric growth, one
* final right-sized copy.
*
* @module buf-writer
*/
var BufWriter$1 = class {
	buf;
	view;
	pos = 0;
	constructor(initialCapacity = 64) {
		this.buf = new Uint8Array(initialCapacity);
		this.view = new DataView(this.buf.buffer);
	}
	/** Number of bytes written so far. */
	get length() {
		return this.pos;
	}
	/** Grow the backing store so at least `extra` more bytes fit. */
	ensure(extra) {
		const needed = this.pos + extra;
		if (needed <= this.buf.length) return;
		let capacity = this.buf.length * 2;
		while (capacity < needed) capacity *= 2;
		const next = new Uint8Array(capacity);
		next.set(this.buf.subarray(0, this.pos));
		this.buf = next;
		this.view = new DataView(next.buffer);
	}
	writeByte(byte) {
		this.ensure(1);
		this.buf[this.pos] = byte;
		this.pos += 1;
	}
	writeUint16(value) {
		this.ensure(2);
		this.view.setUint16(this.pos, value, false);
		this.pos += 2;
	}
	writeUint32(value) {
		this.ensure(4);
		this.view.setUint32(this.pos, value, false);
		this.pos += 4;
	}
	writeBigUint64(value) {
		this.ensure(8);
		this.view.setBigUint64(this.pos, value, false);
		this.pos += 8;
	}
	writeBytes(bytes) {
		this.ensure(bytes.length);
		this.buf.set(bytes, this.pos);
		this.pos += bytes.length;
	}
	/** Return the written region as a right-sized copy. */
	toBytes() {
		return this.buf.slice(0, this.pos);
	}
};
const typeBits$1 = (t) => {
	return t << 5;
};
/**
* Write a CBOR head (major type + argument) straight into `writer`, avoiding
* the intermediate `Uint8Array` that {@link encodeVarInt} allocates. This is
* the encoder hot path (every node emits a head). It MUST stay byte-identical
* to {@link encodeVarInt}; the golden vectors cover both.
*/
const writeVarInt$1 = (writer, value, majorType) => {
	if (value < 0) throw CborError$1$1.outOfRange();
	if (typeof value === "number" && hasFractionalPart$1(value)) throw CborError$1$1.outOfRange();
	const type = typeBits$1(majorType);
	if (isCborNumber$1$1(value) && value <= Number.MAX_SAFE_INTEGER) {
		const n = Number(value);
		if (n <= 23) writer.writeByte(n | type);
		else if (n <= 255) {
			writer.writeByte(24 | type);
			writer.writeByte(n);
		} else if (n <= 65535) {
			writer.writeByte(25 | type);
			writer.writeUint16(n);
		} else if (n <= 4294967295) {
			writer.writeByte(26 | type);
			writer.writeUint32(n);
		} else {
			writer.writeByte(27 | type);
			writer.writeBigUint64(BigInt(n));
		}
	} else {
		const big = BigInt(value);
		if (big > 18446744073709551615n) throw CborError$1$1.outOfRange();
		writer.writeByte(27 | type);
		writer.writeBigUint64(big);
	}
};
const encodeVarInt$1 = (value, majorType) => {
	if (value < 0) throw CborError$1$1.outOfRange();
	if (typeof value === "number" && hasFractionalPart$1(value)) throw CborError$1$1.outOfRange();
	const type = typeBits$1(majorType);
	if (isCborNumber$1$1(value) && value <= Number.MAX_SAFE_INTEGER) {
		value = Number(value);
		if (value <= 23) return new Uint8Array([value | type]);
		else if (value <= 255) return new Uint8Array([24 | type, value]);
		else if (value <= 65535) {
			const buffer = /* @__PURE__ */ new ArrayBuffer(3);
			const view = new DataView(buffer);
			view.setUint8(0, 25 | type);
			view.setUint16(1, value);
			return new Uint8Array(buffer);
		} else if (value <= 4294967295) {
			const buffer = /* @__PURE__ */ new ArrayBuffer(5);
			const view = new DataView(buffer);
			view.setUint8(0, 26 | type);
			view.setUint32(1, value);
			return new Uint8Array(buffer);
		} else {
			const buffer = /* @__PURE__ */ new ArrayBuffer(9);
			const view = new DataView(buffer);
			view.setUint8(0, 27 | type);
			view.setBigUint64(1, BigInt(value));
			return new Uint8Array(buffer);
		}
	} else {
		const big = BigInt(value);
		if (big > 18446744073709551615n) throw CborError$1$1.outOfRange();
		const buffer = /* @__PURE__ */ new ArrayBuffer(9);
		const view = new DataView(buffer);
		view.setUint8(0, 27 | type);
		view.setBigUint64(1, big);
		return new Uint8Array(buffer);
	}
};
const hasFract$1 = (n) => {
	return n % 1 !== 0;
};
/**
* Shared float→integer exactness gate for every `Exact<Int>.exactFromF*`. A
* float is an exact integer of a width iff it is finite, whole, and inside that
* width's exclusive `(loEx, hiEx)` bounds (use ±Infinity to skip a side). The
* bounds encode the per-width / per-source-precision limits. The three typed
* wrappers below shape the truncated result.
*/
const isExactIntFloat$1 = (source, loEx, hiEx) => Number.isFinite(source) && source > loEx && source < hiEx && !hasFract$1(source);
/** float → small integer (`number`). */
const intFromFloatNum$1 = (source, loEx, hiEx) => isExactIntFloat$1(source, loEx, hiEx) ? Math.trunc(source) : void 0;
/** float → 64-bit integer (`number` if safe, else `bigint`). */
const intFromFloatNarrow$1 = (source, loEx, hiEx) => isExactIntFloat$1(source, loEx, hiEx) ? narrowInteger$1(BigInt(Math.trunc(source))) : void 0;
/** float → 128-bit integer (`bigint`). */
const intFromFloatBig$1 = (source, loEx, hiEx) => isExactIntFloat$1(source, loEx, hiEx) ? BigInt(Math.trunc(source)) : void 0;
/**
* Exact conversions for i128 (JavaScript bigint).
*/
var ExactI128$1 = class {
	static MIN = -(2n ** 127n);
	static MAX = 2n ** 127n - 1n;
	static exactFromF16(source) {
		return intFromFloatBig$1(source, -Infinity, Infinity);
	}
	static exactFromF32(source) {
		return intFromFloatBig$1(source, -Infinity, Infinity);
	}
	static exactFromF64(source) {
		return intFromFloatBig$1(source, -Infinity, Infinity);
	}
	static exactFromU64(source) {
		return BigInt(source);
	}
	static exactFromI64(source) {
		return BigInt(source);
	}
	static exactFromU128(source) {
		if (source > 2n ** 127n - 1n) return void 0;
		return source;
	}
	static exactFromI128(source) {
		return source;
	}
};
/**
* Exact conversions for u16 (0 to 65535).
*/
var ExactU16$1 = class {
	static MIN = 0;
	static MAX = 65535;
	static exactFromF16(source) {
		return intFromFloatNum$1(source, -1, Infinity);
	}
	static exactFromF32(source) {
		return intFromFloatNum$1(source, -1, 65536);
	}
	static exactFromF64(source) {
		return intFromFloatNum$1(source, -1, 65536);
	}
	static exactFromU64(source) {
		const n = typeof source === "bigint" ? Number(source) : source;
		if (n > 65535) return void 0;
		return n;
	}
	static exactFromI64(source) {
		const n = typeof source === "bigint" ? Number(source) : source;
		if (n < 0 || n > 65535) return void 0;
		return n;
	}
	static exactFromU128(source) {
		if (source > 65535n) return void 0;
		return Number(source);
	}
	static exactFromI128(source) {
		if (source < 0n || source > 65535n) return void 0;
		return Number(source);
	}
};
/**
* Exact conversions for u32 (0 to 4294967295).
*/
var ExactU32$1 = class {
	static MIN = 0;
	static MAX = 4294967295;
	static exactFromF16(source) {
		return intFromFloatNum$1(source, -1, Infinity);
	}
	static exactFromF32(source) {
		return intFromFloatNum$1(source, -1, 4294967296);
	}
	static exactFromF64(source) {
		return intFromFloatNum$1(source, -1, 4294967296);
	}
	static exactFromU64(source) {
		const n = typeof source === "bigint" ? Number(source) : source;
		if (n > 4294967295) return void 0;
		return n;
	}
	static exactFromI64(source) {
		const n = typeof source === "bigint" ? Number(source) : source;
		if (n < 0 || n > 4294967295) return void 0;
		return n;
	}
	static exactFromU128(source) {
		if (source > 4294967295n) return void 0;
		return Number(source);
	}
	static exactFromI128(source) {
		if (source < 0n || source > 4294967295n) return void 0;
		return Number(source);
	}
};
/**
* Exact conversions for u64 (0 to 18446744073709551615).
*/
var ExactU64$1 = class {
	static MIN = 0n;
	static MAX = 18446744073709551615n;
	static exactFromF16(source) {
		return intFromFloatNarrow$1(source, -1, Infinity);
	}
	static exactFromF32(source) {
		return intFromFloatNarrow$1(source, -1, 0x10000000000000000);
	}
	static exactFromF64(source) {
		return intFromFloatNarrow$1(source, -1, 0x10000000000000000);
	}
	static exactFromU64(source) {
		return source;
	}
	static exactFromI64(source) {
		if ((typeof source === "bigint" ? source : BigInt(source)) < 0n) return void 0;
		return source;
	}
	static exactFromU128(source) {
		if (source > 18446744073709551615n) return void 0;
		return narrowInteger$1(source);
	}
	static exactFromI128(source) {
		if (source < 0n || source > 18446744073709551615n) return void 0;
		return narrowInteger$1(source);
	}
};
/**
* Float encoding and conversion utilities for dCBOR.
*
* # Floating Point Number Support in dCBOR
*
* dCBOR provides canonical encoding for floating point values.
*
* Per the dCBOR specification, the canonical encoding rules ensure
* deterministic representation:
*
* - Numeric reduction: Floating point values with zero fractional part in
*   range [-2^63, 2^64-1] are automatically encoded as integers (e.g., 42.0
*   becomes 42)
* - Values are encoded in the smallest possible representation that preserves
*   their value
* - All NaN values are canonicalized to a single representation: 0xf97e00
* - Positive/negative infinity are canonicalized to half-precision
*   representations
*
* @module float
*/
/**
* Canonical NaN representation in CBOR: 0xf97e00
*/
const CBOR_NAN$1 = new Uint8Array([
	249,
	126,
	0
]);
/**
* Check if a number has a fractional part.
*/
const hasFractionalPart$1 = (n) => n !== Math.floor(n);
/**
* Read a big-endian IEEE-754 double from the first 8 bytes of `data`.
* @internal
*/
const binary64ToNumber$1 = (data) => new DataView(data.buffer, data.byteOffset, data.byteLength).getFloat64(0, false);
/**
* Encode a number as 4 big-endian bytes of an IEEE-754 single (f32).
*/
const numberToBinary32$1 = (n) => {
	const data = /* @__PURE__ */ new Uint8Array(4);
	new DataView(data.buffer).setFloat32(0, n, false);
	return data;
};
/**
* Read a big-endian IEEE-754 single (f32) from the first 4 bytes of `data`.
*/
const binary32ToNumber$1 = (data) => new DataView(data.buffer, data.byteOffset, data.byteLength).getFloat32(0, false);
const f32ScratchView$1 = /* @__PURE__ */ new DataView(/* @__PURE__ */ new ArrayBuffer(4));
/**
* Compute the 16-bit pattern of the IEEE-754 half-precision value nearest `n`,
* rounding ties to even.
*
* All call sites pass values already exactly representable in binary16 (the
* reduction gates in {@link f16CborData} ensure this), so no rounding occurs on
* a value that is actually stored; the rounding path exists only so the
* reduction round-trip probe (`binary16ToNumber(numberToBinary16(n)) === n`)
* answers correctly for non-representable inputs.
*/
const float16Bits$1 = (n) => {
	f32ScratchView$1.setFloat32(0, n, false);
	const f = f32ScratchView$1.getUint32(0, false);
	const sign = f >>> 16 & 32768;
	const exp = f >>> 23 & 255;
	const mant = f & 8388607;
	if (exp === 255) return sign | (mant !== 0 ? 32256 : 31744);
	const e = exp - 127 + 15;
	if (e >= 31) return sign | 31744;
	if (e <= 0) {
		if (e < -10) return sign;
		const significand = mant | 8388608;
		const shift = 14 - e;
		let result = significand >>> shift;
		const remainder = significand & (1 << shift) - 1;
		const halfway = 1 << shift - 1;
		if (remainder > halfway || remainder === halfway && (result & 1) === 1) result += 1;
		return sign | result;
	}
	let fraction = mant >>> 13;
	const remainder = mant & 8191;
	let exponent = e;
	if (remainder > 4096 || remainder === 4096 && (fraction & 1) === 1) {
		fraction += 1;
		if (fraction === 1024) {
			fraction = 0;
			exponent += 1;
			if (exponent >= 31) return sign | 31744;
		}
	}
	return sign | exponent << 10 | fraction;
};
/**
* Encode a number as 2 big-endian bytes of an IEEE-754 half (f16).
*/
const numberToBinary16$1 = (n) => {
	const bits = float16Bits$1(n);
	return new Uint8Array([bits >> 8 & 255, bits & 255]);
};
/**
* Read a big-endian IEEE-754 half (f16) from the first 2 bytes of `data`.
*/
const binary16ToNumber$1 = (data) => {
	const bits = data[0] << 8 | data[1];
	const sign = (bits & 32768) !== 0 ? -1 : 1;
	const exponent = bits >> 10 & 31;
	const fraction = bits & 1023;
	if (exponent === 0) return sign * fraction * 2 ** -24;
	if (exponent === 31) return fraction !== 0 ? NaN : sign * Infinity;
	return sign * (1 + fraction / 1024) * 2 ** (exponent - 15);
};
/**
* Encode f64 value to CBOR data bytes.
* Implements numeric reduction and canonical encoding rules.
* @internal
*/
const f64CborData$1 = (value) => {
	const n = value;
	const f32Bytes = numberToBinary32$1(n);
	const f = binary32ToNumber$1(f32Bytes);
	if (f === n) return f32CborData$1(f);
	if (n < 0) {
		const i128 = ExactI128$1.exactFromF64(n);
		if (i128 !== void 0) {
			const i = ExactU64$1.exactFromI128(-1n - i128);
			if (i !== void 0) return encodeVarInt$1(i, MajorType$1$1.Negative);
		}
	}
	const u = ExactU64$1.exactFromF64(n);
	if (u !== void 0) return encodeVarInt$1(u, MajorType$1$1.Unsigned);
	if (Number.isNaN(value)) return CBOR_NAN$1;
	const buffer = /* @__PURE__ */ new ArrayBuffer(8);
	new DataView(buffer).setFloat64(0, n, false);
	const bytes = new Uint8Array(buffer);
	return new Uint8Array([251, ...bytes]);
};
/**
* Encode f32 value to CBOR data bytes.
* Implements numeric reduction and canonical encoding rules.
* @internal
*/
const f32CborData$1 = (value) => {
	const n = value;
	const f16Bytes = numberToBinary16$1(n);
	const f = binary16ToNumber$1(f16Bytes);
	if (f === n) return f16CborData$1(f);
	if (n < 0) {
		const u = ExactU64$1.exactFromF32(Math.fround(-1 - n));
		if (u !== void 0) return encodeVarInt$1(u, MajorType$1$1.Negative);
	}
	const u = ExactU32$1.exactFromF32(n);
	if (u !== void 0) return encodeVarInt$1(u, MajorType$1$1.Unsigned);
	if (Number.isNaN(value)) return CBOR_NAN$1;
	const bytes = numberToBinary32$1(n);
	return new Uint8Array([250, ...bytes]);
};
/**
* Encode f16 value to CBOR data bytes.
* Implements numeric reduction and canonical encoding rules.
* @internal
*/
const f16CborData$1 = (value) => {
	const n = value;
	if (n < 0) {
		const u = ExactU64$1.exactFromF64(-1 - n);
		if (u !== void 0) return encodeVarInt$1(u, MajorType$1$1.Negative);
	}
	const u = ExactU16$1.exactFromF64(n);
	if (u !== void 0) return encodeVarInt$1(u, MajorType$1$1.Unsigned);
	if (Number.isNaN(value)) return CBOR_NAN$1;
	const bytes = numberToBinary16$1(value);
	return new Uint8Array([249, ...bytes]);
};
/**
* Render a float to its diagnostic string.
*
* Finite non-zero values with magnitude in [1e-4, 1e16) print in decimal with
* at least one fractional digit (whole values get a trailing `.0`); everything
* else prints in exponential form. Zero prints as `0.0`/`-0.0`.
*
* JS already produces the same shortest round-tripping digits; we only fix up
* the notation threshold, the `e+` → `e` exponent, and the `.0` suffix.
*
* @param value - The float value
* @returns The diagnostic string
*/
const floatDisplayString$1 = (value) => {
	if (Number.isNaN(value)) return "NaN";
	if (!Number.isFinite(value)) return value > 0 ? "Infinity" : "-Infinity";
	if (value === 0) return Object.is(value, -0) ? "-0.0" : "0.0";
	const abs = Math.abs(value);
	if (abs >= 1e-4 && abs < 0x2386f26fc10000) {
		let str = String(value);
		if (!str.includes(".")) str = `${str}.0`;
		return str;
	}
	return value.toExponential().replace("e+", "e");
};
/**
* A forward-only cursor over the input bytes.
*
* Decoding advances a single `pos` through one shared `DataView` rather than
* slicing a fresh sub-view per nested item and threading a consumed-length back
* up the recursion. Every read is bounds-checked against the remaining bytes.
*/
var ByteReader$1 = class {
	view;
	pos = 0;
	constructor(data) {
		this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
	}
	get byteLength() {
		return this.view.byteLength;
	}
	get remaining() {
		return this.view.byteLength - this.pos;
	}
	/** Read the byte at `offset` relative to the current position (no advance). */
	peek(offset) {
		return this.view.getUint8(this.pos + offset);
	}
	/** Advance the cursor by `count` bytes. */
	advance(count) {
		this.pos += count;
	}
	/** A zero-copy view of `len` bytes at the given absolute offset. */
	bytesAt(offset, len) {
		return new Uint8Array(this.view.buffer, this.view.byteOffset + offset, len);
	}
};
/**
* Decode a single dCBOR item from `data`, enforcing every deterministic
* encoding rule (canonical numeric forms, NFC text, map-key order, no
* trailing bytes). Throws {@link CborError} on any violation.
*
* @example
* ```typescript
* const value = decodeCbor(hexToBytes("a1616101")); // {"a": 1}
* expectMap(value).size; // 1
* ```
*
* @throws {CborError} `Underrun` | `UnsupportedHeaderValue` |
*   `NonCanonicalNumeric` | `InvalidSimpleValue` | `InvalidUtf8` |
*   `NonCanonicalString` | `UnusedData` | `MisorderedMapKey` |
*   `DuplicateMapKey` - see {@link CborErrorDetailsByCode}.
* @public
*
* @remarks Decoded byte strings are zero-copy views aliasing the input
* buffer - mutating the input after decoding (or mutating the returned
* bytes) changes the other side. Call `.slice()` first if you need an
* independent copy. This is deliberate: the zero-copy decode performance
* profile is part of the library's contract.
*/
function decodeCbor$1$1(data) {
	const reader = new ByteReader$1(data);
	const cbor = readCbor$1(reader);
	const remaining = reader.byteLength - reader.pos;
	if (remaining !== 0) throw CborError$1$1.unusedData(remaining);
	return cbor;
}
function parseHeader$1(header) {
	return {
		majorType: header >> 5,
		headerValue: header & 31
	};
}
/**
* Read a CBOR head (major type + argument) at the cursor, advancing past it.
* `varIntLen` is the head length (1/2/3/5/9); the argument value is validated
* for canonical minimal-length encoding.
*/
function readHeaderVarint$1(reader) {
	if (reader.remaining < 1) throw CborError$1$1.underrun();
	const header = reader.peek(0);
	const { majorType, headerValue } = parseHeader$1(header);
	const dataRemaining = reader.remaining - 1;
	let value;
	let varIntLen;
	if (headerValue <= 23) {
		value = headerValue;
		varIntLen = 1;
	} else if (headerValue === 24) {
		if (dataRemaining < 1) throw CborError$1$1.underrun();
		value = reader.peek(1);
		if (value < 24) throw CborError$1$1.nonCanonicalNumeric();
		varIntLen = 2;
	} else if (headerValue === 25) {
		if (dataRemaining < 2) throw CborError$1$1.underrun();
		value = (reader.peek(1) << 8 | reader.peek(2)) >>> 0;
		if (value <= 255 && header !== 249) throw CborError$1$1.nonCanonicalNumeric();
		varIntLen = 3;
	} else if (headerValue === 26) {
		if (dataRemaining < 4) throw CborError$1$1.underrun();
		value = (reader.peek(1) << 24 | reader.peek(2) << 16 | reader.peek(3) << 8 | reader.peek(4)) >>> 0;
		if (value <= 65535 && header !== 250) throw CborError$1$1.nonCanonicalNumeric();
		varIntLen = 5;
	} else if (headerValue === 27) {
		if (dataRemaining < 8) throw CborError$1$1.underrun();
		const a = BigInt(reader.peek(1)) << 56n;
		const b = BigInt(reader.peek(2)) << 48n;
		const c = BigInt(reader.peek(3)) << 40n;
		const d = BigInt(reader.peek(4)) << 32n;
		const e = BigInt(reader.peek(5)) << 24n;
		const f = BigInt(reader.peek(6)) << 16n;
		const g = BigInt(reader.peek(7)) << 8n;
		const h = BigInt(reader.peek(8));
		value = narrowInteger$1(a | b | c | d | e | f | g | h);
		if (value <= 4294967295 && header !== 251) throw CborError$1$1.nonCanonicalNumeric();
		varIntLen = 9;
	} else throw CborError$1$1.unsupportedHeaderValue(headerValue);
	reader.advance(varIntLen);
	return {
		majorType,
		value,
		varIntLen
	};
}
function readCbor$1(reader) {
	if (reader.remaining < 1) throw CborError$1$1.underrun();
	const headStart = reader.pos;
	const { majorType, value, varIntLen } = readHeaderVarint$1(reader);
	switch (majorType) {
		case MajorType$1$1.Unsigned: {
			const cbor = attachMethods$1$1({
				isCbor: true,
				type: MajorType$1$1.Unsigned,
				value
			});
			checkCanonicalEncoding$1(cbor, reader.bytesAt(headStart, varIntLen));
			return cbor;
		}
		case MajorType$1$1.Negative: {
			const cbor = attachMethods$1$1({
				isCbor: true,
				type: MajorType$1$1.Negative,
				value
			});
			checkCanonicalEncoding$1(cbor, reader.bytesAt(headStart, varIntLen));
			return cbor;
		}
		case MajorType$1$1.ByteString: {
			if (typeof value === "bigint") throw CborError$1$1.underrun();
			if (reader.remaining < value) throw CborError$1$1.underrun();
			const bytes = reader.bytesAt(reader.pos, value);
			reader.advance(value);
			return attachMethods$1$1({
				isCbor: true,
				type: MajorType$1$1.ByteString,
				value: bytes
			});
		}
		case MajorType$1$1.Text: {
			if (typeof value === "bigint") throw CborError$1$1.underrun();
			if (reader.remaining < value) throw CborError$1$1.underrun();
			const textBytes = reader.bytesAt(reader.pos, value);
			reader.advance(value);
			let text;
			try {
				text = new TextDecoder("utf-8", { fatal: true }).decode(textBytes);
			} catch (e) {
				throw CborError$1$1.invalidUtf8(e instanceof Error ? e.message : String(e));
			}
			if (text.normalize("NFC") !== text) throw CborError$1$1.nonCanonicalString();
			return attachMethods$1$1({
				isCbor: true,
				type: MajorType$1$1.Text,
				value: text
			});
		}
		case MajorType$1$1.Array: {
			const items = [];
			for (let i = 0; i < value; i++) items.push(readCbor$1(reader));
			return attachMethods$1$1({
				isCbor: true,
				type: MajorType$1$1.Array,
				value: items
			});
		}
		case MajorType$1$1.Map: {
			const map = new CborMap$1$1();
			for (let i = 0; i < value; i++) {
				const key = readCbor$1(reader);
				const val = readCbor$1(reader);
				map.setNext(key, val);
			}
			return attachMethods$1$1({
				isCbor: true,
				type: MajorType$1$1.Map,
				value: map
			});
		}
		case MajorType$1$1.Tagged: {
			const item = readCbor$1(reader);
			return attachMethods$1$1({
				isCbor: true,
				type: MajorType$1$1.Tagged,
				tag: value,
				value: item
			});
		}
		case MajorType$1$1.Simple: switch (varIntLen) {
			case 3: {
				const f = binary16ToNumber$1(reader.bytesAt(headStart + 1, 2));
				checkCanonicalEncoding$1(f, reader.bytesAt(headStart, varIntLen));
				return attachMethods$1$1({
					isCbor: true,
					type: MajorType$1$1.Simple,
					value: {
						type: "Float",
						value: f
					}
				});
			}
			case 5: {
				const f = binary32ToNumber$1(reader.bytesAt(headStart + 1, 4));
				checkCanonicalEncoding$1(f, reader.bytesAt(headStart, varIntLen));
				return attachMethods$1$1({
					isCbor: true,
					type: MajorType$1$1.Simple,
					value: {
						type: "Float",
						value: f
					}
				});
			}
			case 9: {
				const f = binary64ToNumber$1(reader.bytesAt(headStart + 1, 8));
				checkCanonicalEncoding$1(f, reader.bytesAt(headStart, varIntLen));
				return attachMethods$1$1({
					isCbor: true,
					type: MajorType$1$1.Simple,
					value: {
						type: "Float",
						value: f
					}
				});
			}
			default: switch (value) {
				case 20: return attachMethods$1$1({
					isCbor: true,
					type: MajorType$1$1.Simple,
					value: { type: "False" }
				});
				case 21: return attachMethods$1$1({
					isCbor: true,
					type: MajorType$1$1.Simple,
					value: { type: "True" }
				});
				case 22: return attachMethods$1$1({
					isCbor: true,
					type: MajorType$1$1.Simple,
					value: { type: "Null" }
				});
				default: throw CborError$1$1.invalidSimpleValue();
			}
		}
	}
}
function checkCanonicalEncoding$1(cbor, buf) {
	if (!areBytesEqual$1(buf, encodeCbor$2(cbor))) throw CborError$1$1.nonCanonicalNumeric();
}
/**
* Extract native JavaScript value from CBOR.
* Converts CBOR types to their JavaScript equivalents.
*
* Returns the closed union {@link CborNative}. Note the two asymmetries
* documented there: maps come back as `CborMap` and tagged values as `Cbor`.
*/
const extractCbor$1$1 = (cbor) => {
	let c;
	if (cbor instanceof Uint8Array) c = decodeCbor$1$1(cbor);
	else c = cbor;
	switch (c.type) {
		case MajorType$1$1.Unsigned: return c.value;
		case MajorType$1$1.Negative: if (typeof c.value === "bigint") return -c.value - 1n;
		else return -c.value - 1;
		case MajorType$1$1.ByteString: return c.value;
		case MajorType$1$1.Text: return c.value;
		case MajorType$1$1.Array: return c.value.map(extractCbor$1$1);
		case MajorType$1$1.Map: return c.value;
		case MajorType$1$1.Tagged: return c;
		case MajorType$1$1.Simple: {
			const simple = c.value;
			switch (simple.type) {
				case "True": return true;
				case "False": return false;
				case "Null": return null;
				case "Float": return simple.value;
				default: return simple;
			}
		}
		default: return c;
	}
};
/**
* Map Support in dCBOR
*
* A deterministic CBOR map implementation that ensures maps with the same
* content always produce identical binary encodings, regardless of insertion
* order.
*
* ## Deterministic Map Representation
*
* The `CborMap` type follows strict deterministic encoding rules as specified by
* dCBOR:
*
* - Map keys are always sorted in lexicographic order of their encoded CBOR bytes
* - Duplicate keys are not allowed (enforced by the implementation)
* - Keys and values can be any type that can be converted to CBOR
* - Numeric reduction is applied (e.g., 3.0 is stored as integer 3)
*
* ## Vocabulary
*
* `CborMap` mirrors the JS `Map` protocol: `set`, `get`, `getOrThrow`, `has`,
* `delete`, `clear`, `size`, `keys()`, `values()`, `entries()`, `forEach`,
* iteration. `get` returns the STORED `Cbor` node (symmetric with
* `entries()`); extract natives explicitly with `extractCbor(map.get(k))`.
*
* @module map
*/
/**
* A deterministic CBOR map implementation.
*
* Maps are always encoded with keys sorted lexicographically by their
* encoded CBOR representation, ensuring deterministic encoding.
*/
var CborMap$1$1 = class {
	/** Debug label: `Object.prototype.toString` reports `[object CborMap]`. */
	get [Symbol.toStringTag]() {
		return "CborMap";
	}
	_dict;
	/**
	* Creates a new, empty CBOR Map.
	* Optionally initializes from a JavaScript Map (every key and value must
	* itself be encodable).
	*/
	constructor(map) {
		this._dict = new SortedByteMap$1();
		if (map !== void 0) for (const [key, value] of map.entries()) this.set(key, value);
	}
	/**
	* Inserts a key-value pair into the map (replacing any entry whose key has
	* the same canonical encoding). Any insertion order is accepted - entries
	* are kept in canonical ascending encoded-key order.
	*
	* @example
	* ```typescript
	* const m = new CborMap();
	* m.set("z", 1);
	* m.set(10, "ten"); // sorts before "z" in the encoding
	* encodeCbor(m);    // deterministic regardless of insertion order
	* ```
	* @public
	*/
	set(key, value) {
		const keyCbor = cbor$1$1(key);
		const valueCbor = cbor$1$1(value);
		const keyData = encodeCbor$2(keyCbor);
		this._dict.set(keyData, {
			key: keyCbor,
			value: valueCbor
		});
	}
	_makeKey(key) {
		return encodeCbor$2(cbor$1$1(key));
	}
	/**
	* Get the STORED `Cbor` node for a key, or `undefined` if absent.
	*
	* This is symmetric with `entries()` - no hidden native extraction, no
	* unwitnessed generics. To read a native value, compose explicitly:
	*
	* ```typescript
	* asNumber(map.get("age"));          // number | undefined, checked
	* extractCbor(map.getOrThrow("age")); // CborNative, throws if absent
	* ```
	* @public
	*/
	get(key) {
		return this._dict.get(this._makeKey(key))?.value;
	}
	/**
	* Get the stored `Cbor` node for a key.
	*
	* @throws {CborError} `MissingMapKey` - the key is not present.
	*/
	getOrThrow(key) {
		const value = this.get(key);
		if (value === void 0) throw CborError$1$1.missingMapKey();
		return value;
	}
	delete(key) {
		const keyData = this._makeKey(key);
		const existed = this._dict.has(keyData);
		this._dict.delete(keyData);
		return existed;
	}
	has(key) {
		return this._dict.has(this._makeKey(key));
	}
	clear() {
		this._dict = new SortedByteMap$1();
	}
	/** The number of entries in the map. */
	get size() {
		return this._dict.size;
	}
	/**
	* Get the entries of the map as an array, sorted in canonical ascending
	* encoded-key order.
	*
	* @internal Public because the encoder, diagnostic formatter, and hex
	* annotator consume it cross-module; not part of the supported surface.
	*/
	get entriesArray() {
		return this._dict.map((value, _key) => ({
			key: value.key,
			value: value.value
		}));
	}
	/** Iterate keys in canonical (sorted encoded-key) order. */
	*keys() {
		for (const entry of this.entriesArray) yield entry.key;
	}
	/** Iterate values in canonical key order. */
	*values() {
		for (const entry of this.entriesArray) yield entry.value;
	}
	/**
	* Iterate `[key, value]` tuples in canonical key order (the JS
	* `Map.entries()` shape).
	*/
	*entries() {
		for (const entry of this.entriesArray) yield [entry.key, entry.value];
	}
	/** JS `Map.forEach` mirror (value first, then key, then the map). */
	forEach(callback, thisArg) {
		for (const entry of this.entriesArray) callback.call(thisArg, entry.value, entry.key, this);
	}
	*[Symbol.iterator]() {
		for (const entry of this.entriesArray) yield [entry.key, entry.value];
	}
	/**
	* Inserts the next key-value pair into the map during decoding.
	* This is used for efficient map building during CBOR decoding.
	* Throws if the key is not in ascending order or is a duplicate.
	*
	* @internal The decoder's append path; not part of the supported surface.
	*/
	setNext(key, value) {
		const keyCbor = cbor$1$1(key);
		const newKey = encodeCbor$2(keyCbor);
		if (this._dict.has(newKey)) throw CborError$1$1.duplicateMapKey();
		const greatest = this._dict.maxKey();
		if (greatest !== void 0) {
			if (lexicographicallyCompareBytes$1(newKey, greatest) <= 0) throw CborError$1$1.misorderedMapKey();
		}
		this._dict.appendGreatest(newKey, {
			key: keyCbor,
			value: cbor$1$1(value)
		});
	}
	/**
	* Convert to a plain JavaScript `Map` of extracted native values.
	* Tagged values come back as `Cbor` nodes and nested maps as `CborMap`
	* (the {@link CborNative} asymmetries).
	*/
	toMap() {
		const map = /* @__PURE__ */ new Map();
		for (const entry of this.entriesArray) map.set(extractCbor$1$1(entry.key), extractCbor$1$1(entry.value));
		return map;
	}
};
/**
* Encodes the simple value to its raw CBOR byte representation.
*
* Returns the CBOR bytes that represent this simple value according to the
* dCBOR deterministic encoding rules:
* - `False` encodes as `0xf4`
* - `True` encodes as `0xf5`
* - `Null` encodes as `0xf6`
* - `Float` values encode according to the IEEE 754 floating point rules,
*   using the shortest representation that preserves precision.
*/
const simpleCborData$1 = (simple) => {
	switch (simple.type) {
		case "False": return encodeVarInt$1(20, MajorType$1$1.Simple);
		case "True": return encodeVarInt$1(21, MajorType$1$1.Simple);
		case "Null": return encodeVarInt$1(22, MajorType$1$1.Simple);
		case "Float": return f64CborData$1(simple.value);
	}
};
Uint8Array.fromHex;
/**
* Convert bytes to a lowercase hex string.
*
* Delegates to the native `Uint8Array.prototype.toHex` where available.
*/
const bytesToHex$1$3 = (bytes) => {
	const native = bytes.toHex;
	if (typeof native === "function") return native.call(bytes);
	let out = "";
	for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
	return out;
};
/**
* The dCBOR value core: the `Cbor` union type, the polymorphic constructor
* `cbor()`, the encoder entry `encodeCbor()`, and the tagged-value
* constructor `taggedValue()`.
*
* ## The API in one paragraph
*
* Construct with `cbor(input)` (the single polymorphic constructor) or
* `taggedValue(tag, content)` (the only explicit tagged-value constructor);
* custom types participate by implementing the one structural protocol
* `ToCbor { toCbor(): Cbor }`. Encode with `encodeCbor(value)`. Decode with
* `decodeCbor(bytes)` (throws) or `tryDecode(bytes)` (returns `Result`).
* Read with the free `isX`/`asX`/`expectX` accessor functions. The only
* instance conveniences on a `Cbor` value are `toData()`, `toHex()`, and a
* cheap `toString()`.
*
* @module cbor
*/
/**
* The instance methods shared by every `Cbor` value: exactly three cheap
* conveniences (plus debug symbols below). Everything else is a free function
* so decode-only bundles never carry the diagnostic formatter, hex annotator,
* tag store, or walker.
*
* `String(c)`/template literals/`console.log` produce `Cbor(0x…)`. Diagnostic
* rendering lives in `@blockchaincommons/dcbor/diagnostic`; opt-in diag-flavored debug
* output lives in `@blockchaincommons/dcbor/debug` (`installDebugHooks()`).
*/
const CBOR_METHODS$1 = {
	toData() {
		return encodeCbor$2(this);
	},
	toHex() {
		return bytesToHex$1$3(encodeCbor$2(this));
	},
	toString() {
		return `Cbor(0x${bytesToHex$1$3(encodeCbor$2(this))})`;
	},
	[Symbol.toStringTag]: "Cbor",
	[Symbol.for("nodejs.util.inspect.custom")]() {
		return this.toString();
	}
};
/**
* Decorate a bare CBOR value (`{ isCbor, type, value[, tag] }`) with the shared
* instance methods. The methods live on {@link CBOR_METHODS} and are installed
* via the prototype - constructed with `Object.create` (not `setPrototypeOf`,
* which would drop the object off V8's fast path). Only the handful of data
* properties are own-properties; the methods are shared, not per-object.
*
* @internal
*/
const attachMethods$1$1 = (obj) => {
	const decorated = Object.create(CBOR_METHODS$1);
	return Object.assign(decorated, obj);
};
const CBOR_FALSE$1 = attachMethods$1$1({
	isCbor: true,
	type: MajorType$1$1.Simple,
	value: { type: "False" }
});
const CBOR_TRUE$1 = attachMethods$1$1({
	isCbor: true,
	type: MajorType$1$1.Simple,
	value: { type: "True" }
});
const CBOR_NULL$1 = attachMethods$1$1({
	isCbor: true,
	type: MajorType$1$1.Simple,
	value: { type: "Null" }
});
const hasTaggedCbor$1$1 = (value) => {
	return typeof value === "object" && value !== null && "taggedCbor" in value && typeof value.taggedCbor === "function";
};
const hasToCbor$1$1 = (value) => {
	return typeof value === "object" && value !== null && "toCbor" in value && typeof value.toCbor === "function";
};
/**
* Convert any supported value to its CBOR representation - the single
* polymorphic constructor.
*
* Custom types participate by implementing {@link ToCbor}
* (`toCbor(): Cbor` - the `toJSON` precedent). Tagged values are built with
* {@link taggedValue}.
*
* @example
* ```typescript
* cbor(42);                          // integer
* cbor("héllo");                     // NFC-normalized text
* cbor([1, "two", true, null]);      // array
* cbor(new Map([["k", 1]]));         // map (canonical key order)
* cbor({ name: "Alice", age: 30 });  // plain object -> map
* ```
*
* @throws {CborError} `OutOfRange` - bigint outside `[-(2^64), 2^64 - 1]`.
* @throws {CborError} `Custom` - unsupported input type, or one of the two
*   directive errors below.
* @public
*
* ## Directive errors
*
* Two input shapes throw a directive `CborError` because encoding them
* silently would produce ambiguous or divergent bytes:
*
* - plain objects shaped exactly `{tag, value}`: use
*   `taggedValue(tag, content)` for a tagged value, or add/rename a key for
*   a map;
* - objects implementing `taggedCbor()` but not `toCbor()`: add
*   `toCbor() { return this.taggedCbor(); }`.
*/
const cbor$1$1 = (value) => {
	if (isCbor$1$1(value) && "toData" in value) return value;
	if (isCbor$1$1(value)) return attachMethods$1$1(value);
	let result;
	if (isCborNumber$1$1(value)) if (typeof value === "number" && Number.isNaN(value)) result = {
		isCbor: true,
		type: MajorType$1$1.Simple,
		value: {
			type: "Float",
			value: NaN
		}
	};
	else if (typeof value === "number" && hasFractionalPart$1(value)) result = {
		isCbor: true,
		type: MajorType$1$1.Simple,
		value: {
			type: "Float",
			value
		}
	};
	else if (value == Infinity) result = {
		isCbor: true,
		type: MajorType$1$1.Simple,
		value: {
			type: "Float",
			value: Infinity
		}
	};
	else if (value == -Infinity) result = {
		isCbor: true,
		type: MajorType$1$1.Simple,
		value: {
			type: "Float",
			value: -Infinity
		}
	};
	else if (typeof value === "number" && !Number.isSafeInteger(value)) {
		const big = BigInt(value);
		if (big >= 0n && big <= 18446744073709551615n) result = {
			isCbor: true,
			type: MajorType$1$1.Unsigned,
			value: big
		};
		else if (big < 0n && big >= CBOR_INT_MIN$1) result = {
			isCbor: true,
			type: MajorType$1$1.Negative,
			value: -big - 1n
		};
		else result = {
			isCbor: true,
			type: MajorType$1$1.Simple,
			value: {
				type: "Float",
				value
			}
		};
	} else if (typeof value === "bigint" && (value > 18446744073709551615n || value < CBOR_INT_MIN$1)) throw CborError$1$1.outOfRange();
	else if (value < 0) if (typeof value === "bigint") result = {
		isCbor: true,
		type: MajorType$1$1.Negative,
		value: -value - 1n
	};
	else result = {
		isCbor: true,
		type: MajorType$1$1.Negative,
		value: -value - 1
	};
	else result = {
		isCbor: true,
		type: MajorType$1$1.Unsigned,
		value
	};
	else if (typeof value === "string") {
		const normalized = value.normalize("NFC");
		result = {
			isCbor: true,
			type: MajorType$1$1.Text,
			value: normalized
		};
	} else if (value === null || value === void 0) return CBOR_NULL$1;
	else if (value === true) return CBOR_TRUE$1;
	else if (value === false) return CBOR_FALSE$1;
	else if (Array.isArray(value)) result = {
		isCbor: true,
		type: MajorType$1$1.Array,
		value: value.map(cbor$1$1)
	};
	else if (value instanceof Uint8Array) result = {
		isCbor: true,
		type: MajorType$1$1.ByteString,
		value
	};
	else if (value instanceof CborMap$1$1) result = {
		isCbor: true,
		type: MajorType$1$1.Map,
		value
	};
	else if (value instanceof Map) result = {
		isCbor: true,
		type: MajorType$1$1.Map,
		value: new CborMap$1$1(value)
	};
	else if (value instanceof Set) result = {
		isCbor: true,
		type: MajorType$1$1.Array,
		value: Array.from(value).map(cbor$1$1)
	};
	else if (hasToCbor$1$1(value)) return value.toCbor();
	else if (hasTaggedCbor$1$1(value)) throw CborError$1$1.custom("objects implementing taggedCbor() are no longer auto-wrapped by cbor(); implement toCbor() (e.g. `toCbor() { return this.taggedCbor(); }`)");
	else if (typeof value === "object" && "tag" in value && "value" in value) {
		const keys = Object.keys(value);
		if (keys.length === 2 && keys.includes("tag") && keys.includes("value")) throw CborError$1$1.custom("plain { tag, value } objects are ambiguous and no longer encode as tagged values; use taggedValue(tag, content) for a tagged value, or add/rename a key to encode a map");
		const map = new CborMap$1$1();
		for (const [key, val] of Object.entries(value)) map.set(cbor$1$1(key), cbor$1$1(val));
		result = {
			isCbor: true,
			type: MajorType$1$1.Map,
			value: map
		};
	} else if (typeof value === "object") {
		const map = new CborMap$1$1();
		for (const [key, val] of Object.entries(value)) map.set(cbor$1$1(key), cbor$1$1(val));
		result = {
			isCbor: true,
			type: MajorType$1$1.Map,
			value: map
		};
	} else throw CborError$1$1.custom("Unsupported type for CBOR encoding");
	return attachMethods$1$1(result);
};
const textEncoder$1 = new TextEncoder();
/**
* Write a CBOR value into `writer`. The whole tree encodes into one growable
* buffer, so nested containers don't allocate-and-concatenate a fresh array
* per level.
*/
const writeCborInto$1 = (writer, value) => {
	const c = cbor$1$1(value);
	switch (c.type) {
		case MajorType$1$1.Unsigned:
			writeVarInt$1(writer, c.value, MajorType$1$1.Unsigned);
			return;
		case MajorType$1$1.Negative:
			writeVarInt$1(writer, c.value, MajorType$1$1.Negative);
			return;
		case MajorType$1$1.ByteString:
			if (c.value instanceof Uint8Array) {
				writeVarInt$1(writer, c.value.length, MajorType$1$1.ByteString);
				writer.writeBytes(c.value);
				return;
			}
			break;
		case MajorType$1$1.Text:
			if (typeof c.value === "string") {
				const utf8Bytes = textEncoder$1.encode(c.value);
				writeVarInt$1(writer, utf8Bytes.length, MajorType$1$1.Text);
				writer.writeBytes(utf8Bytes);
				return;
			}
			break;
		case MajorType$1$1.Tagged:
			if (typeof c.tag === "bigint" || typeof c.tag === "number") {
				writeVarInt$1(writer, c.tag, MajorType$1$1.Tagged);
				writeCborInto$1(writer, c.value);
				return;
			}
			break;
		case MajorType$1$1.Simple:
			writer.writeBytes(simpleCborData$1(c.value));
			return;
		case MajorType$1$1.Array:
			writeVarInt$1(writer, c.value.length, MajorType$1$1.Array);
			for (const item of c.value) writeCborInto$1(writer, item);
			return;
		case MajorType$1$1.Map: {
			const entries = c.value.entriesArray;
			writeVarInt$1(writer, entries.length, MajorType$1$1.Map);
			for (const { key, value: entryValue } of entries) {
				writeCborInto$1(writer, key);
				writeCborInto$1(writer, entryValue);
			}
			return;
		}
	}
	throw CborError$1$1.wrongType();
};
/**
* Encode a value to deterministic CBOR bytes. Accepts anything `cbor()`
* accepts; equal values always produce identical bytes (dCBOR determinism).
*
* @example
* ```typescript
* encodeCbor({ a: 1 });            // Uint8Array [0xa1, 0x61, 0x61, 0x01]
* bytesToHex(encodeCbor("Hello")); // "6548656c6c6f"
* ```
*
* @throws {CborError} Whatever `cbor(value)` throws for unsupported inputs
*   (`OutOfRange`, `Custom`).
* @remarks The decoder's canonicality check re-encodes every decoded value
*   through this function, so it is wire-critical.
* @public
*/
const encodeCbor$2 = (value) => {
	const c = cbor$1$1(value);
	switch (c.type) {
		case MajorType$1$1.Unsigned: return encodeVarInt$1(c.value, MajorType$1$1.Unsigned);
		case MajorType$1$1.Negative: return encodeVarInt$1(c.value, MajorType$1$1.Negative);
		case MajorType$1$1.Simple: return simpleCborData$1(c.value);
		default: {
			const writer = new BufWriter$1();
			writeCborInto$1(writer, c);
			return writer.toBytes();
		}
	}
};
/**
* Tag registry implementation.
*
* Stores tags with their names and optional summarizer functions.
*/
var TagsStore$1$1 = class {
	/** Debug label: `Object.prototype.toString` reports `[object TagsStore]`. */
	get [Symbol.toStringTag]() {
		return "TagsStore";
	}
	_tagsByValue = /* @__PURE__ */ new Map();
	_tagsByName = /* @__PURE__ */ new Map();
	_summarizers = /* @__PURE__ */ new Map();
	constructor() {}
	/**
	* Insert a tag into the registry.
	*
	* - Throws if the tag name is undefined or empty
	* - Throws if a tag with the same value exists with a different name
	* - Allows re-registering the same tag value with the same name
	*
	* @param tag - The tag to register (must have a non-empty name)
	* @throws Error if tag has no name, empty name, or conflicts with existing registration
	*
	* @example
	* ```typescript
	* const store = new TagsStore();
	* store.register(Tag.from(12345, 'myCustomTag'));
	* ```
	*/
	register(tag) {
		const name = tag.name;
		if (name === void 0 || name === "") throw new Error(`Tag ${tag.value} must have a non-empty name`);
		const key = this._valueKey(tag.value);
		const existing = this._tagsByValue.get(key);
		if (existing?.name !== void 0 && existing.name !== name) throw new Error(`Attempt to register tag: ${tag.value} '${existing.name}' with different name: '${name}'`);
		this._tagsByValue.set(key, tag);
		this._tagsByName.set(name, tag);
	}
	/**
	* Register multiple tags; the conflict-throwing validation in `register()`
	* applies per tag.
	*/
	registerAll(tags) {
		for (const tag of tags) this.register(tag);
	}
	/**
	* Register a custom summarizer function for a tag.
	*
	* @param tagValue - The numeric tag value
	* @param summarizer - The summarizer function
	*
	* @example
	* ```typescript
	* store.setSummarizer(1, (cbor, flat) => {
	*   // Custom date formatting
	*   return `Date(${extractCbor(cbor)})`;
	* });
	* ```
	*/
	setSummarizer(tagValue, summarizer) {
		const key = this._valueKey(tagValue);
		this._summarizers.set(key, summarizer);
	}
	assignedNameForTag(tag) {
		const key = this._valueKey(tag.value);
		return this._tagsByValue.get(key)?.name;
	}
	nameForTag(tag) {
		return this.assignedNameForTag(tag) ?? tag.value.toString();
	}
	tagForValue(value) {
		const key = this._valueKey(value);
		return this._tagsByValue.get(key);
	}
	tagForName(name) {
		return this._tagsByName.get(name);
	}
	nameForValue(value) {
		const tag = this.tagForValue(value);
		return tag !== void 0 ? this.nameForTag(tag) : value.toString();
	}
	summarizer(tag) {
		const key = this._valueKey(tag);
		return this._summarizers.get(key);
	}
	/**
	* Create a string key for a numeric tag value.
	* Handles both number and bigint types.
	*
	* @private
	*/
	_valueKey(value) {
		return value.toString();
	}
};
/**
* Global singleton instance of the tags store.
*/
let globalTagsStore$1$1;
/**
* Get the global tags store instance.
*
* Creates the instance on first access.
*
* @returns The global TagsStore instance
*
* @example
* ```typescript
* const store = getGlobalTagsStore();
* store.register(Tag.from(999, 'myTag'));
* ```
*/
const getGlobalTagsStore$1$1 = () => {
	globalTagsStore$1$1 ??= new TagsStore$1$1();
	return globalTagsStore$1$1;
};
/**
* String utilities for dCBOR, including Unicode normalization.
*
* @module string-util
*/
/**
* Flank a string with left and right strings.
*
* @param s - String to flank
* @param left - Left flanking string
* @param right - Right flanking string
* @returns Flanked string
*/
const flanked$1 = (s, left, right) => left + s + right;
/**
* Check if a character is printable. Internal helper for {@link sanitized}.
*
* @param c - Character to check
* @returns True if printable
*/
const isPrintable$1 = (c) => {
	if (c.length !== 1) return false;
	const code = c.charCodeAt(0);
	return code > 127 || code >= 32 && code <= 126;
};
/**
* Sanitize a string by replacing non-printable characters with dots.
* Returns None if the string has no printable characters.
*
* @param str - String to sanitize
* @returns Sanitized string or undefined if no printable characters
*/
const sanitized$1 = (str) => {
	let hasPrintable = false;
	const chars = [];
	for (const c of str) if (isPrintable$1(c)) {
		hasPrintable = true;
		chars.push(c);
	} else chars.push(".");
	if (!hasPrintable) return;
	return chars.join("");
};
const resolveOpts$1 = (opts) => {
	const summarize = opts?.summarize ?? false;
	return {
		annotate: opts?.annotate ?? false,
		summarize,
		flat: summarize || (opts?.flat ?? false),
		tags: opts?.tags ?? "global"
	};
};
/**
* Format a CBOR value - or a walk visitor's `WalkElement` - as CBOR
* diagnostic notation.
*
* ```typescript
* diagnostic(value);                       // pretty-printed
* diagnostic(value, { flat: true });       // single line
* diagnostic(value, { annotate: true });   // tag names as annotations
* diagnostic(value, { summarize: true });  // registered summarizers (implies flat)
* ```
*
* @param input - CBOR value, or a `WalkElement` from a walk visitor
* @param opts - Formatting options (explicit `undefined` fields mean
*   "use the default")
* @public
*/
function diagnostic$1$1(input, opts) {
	const state = resolveOpts$1(opts);
	if (typeof input === "object" && "type" in input && (input.type === "single" || input.type === "keyvalue")) {
		if (input.type === "single") return diagFormat$1(diagItem$1(input.cbor, state), state);
		return `${diagFormat$1(diagItem$1(input.key, state), state)}: ${diagFormat$1(diagItem$1(input.value, state), state)}`;
	}
	return diagFormat$1(diagItem$1(input, state), state);
}
const item$1 = (value) => ({
	kind: "item",
	value
});
const group$1 = (begin, end, items, isPairs, comment) => {
	const g = {
		kind: "group",
		begin,
		end,
		items,
		isPairs
	};
	if (comment !== void 0) g.comment = comment;
	return g;
};
const isGroup$1 = (i) => i.kind === "group";
const containsGroup$1 = (i) => i.kind === "group" && i.items.some(isGroup$1);
const totalStringsLen$1 = (i) => i.kind === "item" ? i.value.length : i.items.reduce((acc, c) => acc + totalStringsLen$1(c), 0);
const greatestStringsLen$1 = (i) => i.kind === "item" ? i.value.length : i.items.reduce((acc, c) => Math.max(acc, totalStringsLen$1(c)), 0);
/**
* Alternates between `pairSeparator` (after even-indexed items - keys) and
* `itemSeparator` (after odd-indexed items - values). Falls back to
* `itemSeparator` for non-pair groups.
*/
function joined$1(elements, itemSeparator, pairSeparator) {
	const sep = pairSeparator ?? itemSeparator;
	let result = "";
	const len = elements.length;
	for (let i = 0; i < len; i++) {
		result += elements[i];
		if (i !== len - 1) result += (i & 1) !== 0 ? itemSeparator : sep;
	}
	return result;
}
const diagFormat$1 = (i, opts) => diagFormatOpt$1(i, 0, "", opts);
function diagFormatOpt$1(i, level, separator, opts) {
	if (i.kind === "item") return formatLine$1(level, opts, i.value, separator, void 0);
	if (opts.flat !== true && (containsGroup$1(i) || totalStringsLen$1(i) > 20 || greatestStringsLen$1(i) > 20)) return multilineComposition$1(i, level, separator, opts);
	return singleLineComposition$1(i, level, separator, opts);
}
function formatLine$1(level, opts, string, separator, comment) {
	const result = `${opts.flat === true ? "" : " ".repeat(level * 4)}${string}${separator}`;
	if (comment !== void 0) return `${result}   / ${comment} /`;
	return result;
}
function singleLineComposition$1(i, level, separator, opts) {
	let str;
	let comment;
	if (i.kind === "item") {
		str = i.value;
		comment = void 0;
	} else {
		str = flanked$1(joined$1(i.items.map((c) => c.kind === "item" ? c.value : singleLineComposition$1(c, level + 1, separator, opts)), ", ", i.isPairs ? ": " : ", "), i.begin, i.end);
		comment = i.comment;
	}
	return formatLine$1(level, opts, str, separator, comment);
}
function multilineComposition$1(i, level, separator, opts) {
	if (i.kind === "item") return i.value;
	const lines = [];
	const openOpts = {
		...opts,
		flat: false
	};
	lines.push(formatLine$1(level, openOpts, i.begin, "", i.comment));
	for (let idx = 0; idx < i.items.length; idx++) {
		const sep = idx === i.items.length - 1 ? "" : i.isPairs && (idx & 1) === 0 ? ":" : ",";
		lines.push(diagFormatOpt$1(i.items[idx], level + 1, sep, opts));
	}
	lines.push(formatLine$1(level, opts, i.end, separator, void 0));
	return lines.join("\n");
}
function diagItem$1(cbor, opts) {
	switch (cbor.type) {
		case MajorType$1$1.Unsigned: return item$1(formatUnsigned$1(cbor.value));
		case MajorType$1$1.Negative: return item$1(formatNegative$1(cbor.value));
		case MajorType$1$1.ByteString: return item$1(formatBytes$1(cbor.value));
		case MajorType$1$1.Text: return item$1(formatText$1(cbor.value));
		case MajorType$1$1.Array: return item_array$1(cbor.value, opts);
		case MajorType$1$1.Map: return item_map$1(cbor.value, opts);
		case MajorType$1$1.Tagged: return item_tagged$1(cbor.tag, cbor.value, opts);
		case MajorType$1$1.Simple: return item$1(formatSimple$1(cbor.value));
	}
}
function item_array$1(items, opts) {
	return group$1("[", "]", items.map((it) => diagItem$1(it, opts)), false);
}
function item_map$1(map, opts) {
	const entries = map?.entriesArray ?? [];
	const flatItems = [];
	for (const e of entries) {
		flatItems.push(diagItem$1(e.key, opts));
		flatItems.push(diagItem$1(e.value, opts));
	}
	return group$1("{", "}", flatItems, true);
}
function item_tagged$1(tag, content, opts) {
	if (opts.summarize === true) {
		const summarizer = resolveTagsStore$1(opts.tags)?.summarizer(tag);
		if (summarizer !== void 0) {
			const result = summarizer(content, opts.flat ?? false);
			if (result.ok) return item$1(result.value);
			return item$1(`<error: ${result.error.message}>`);
		}
	}
	let comment;
	if (opts.annotate === true) {
		const store = resolveTagsStore$1(opts.tags);
		const tagObj = { value: tag };
		const assignedName = store?.assignedNameForTag(tagObj);
		if (assignedName !== void 0) comment = assignedName;
	}
	return group$1(`${String(tag)}(`, ")", [diagItem$1(content, opts)], false, comment);
}
function formatUnsigned$1(value) {
	return String(value);
}
function formatNegative$1(value) {
	if (typeof value === "bigint") return String(-value - 1n);
	return String(-value - 1);
}
function formatBytes$1(value) {
	return `h'${bytesToHex$1$3(value)}'`;
}
function formatText$1(value) {
	return `"${value.replace(/"/g, "\\\"")}"`;
}
function formatSimple$1(value) {
	switch (value.type) {
		case "True": return "true";
		case "False": return "false";
		case "Null": return "null";
		case "Float": return formatFloat$1(value.value);
	}
}
/**
* Format a CBOR float for diagnostic output. Shared with the hex-dump
* annotation path; see {@link floatDisplayString}.
*/
function formatFloat$1(value) {
	return floatDisplayString$1(value);
}
function resolveTagsStore$1(tags) {
	if (tags === "none") return void 0;
	if (tags === "global" || tags === void 0) return getGlobalTagsStore$1$1();
	return tags;
}
/**
* Hex dump utilities for CBOR data.
*
* Affordances for viewing the encoded binary representation of CBOR as hexadecimal.
* Optionally annotates the output, breaking it up into semantically meaningful lines,
* formatting dates, and adding names of known tags.
*
* @module dump
*/
/**
* Render CBOR as an annotated hex dump: the encoding broken into
* semantically meaningful lines with offsets, values, and tag names
* resolved through the tags store.
*
* For plain hex use `c.toHex()` or `bytesToHex(encodeCbor(v))`.
*
* @param cbor - CBOR value to render
* @param opts - Formatting options (explicit `undefined` fields mean
*   "use the default")
*/
const hexAnnotated$1 = (cbor, opts) => {
	const items = dumpItems$1(cbor, 0, opts?.tagsStore ?? getGlobalTagsStore$1$1());
	const roundedNoteColumn = (items.reduce((largest, item) => {
		return Math.max(largest, item.formatFirstColumn().length);
	}, 0) + 4 & -4) - 1;
	return items.map((item) => item.format(roundedNoteColumn)).join("\n");
};
/**
* Internal structure for dump items.
*/
var DumpItem$1 = class {
	level;
	data;
	note;
	constructor(level, data, note) {
		this.level = level;
		this.data = data;
		this.note = note;
	}
	format(noteColumn) {
		const column1 = this.formatFirstColumn();
		let column2 = "";
		let padding = "";
		if (this.note !== void 0) {
			const paddingCount = Math.max(1, Math.min(39, noteColumn) - column1.length + 1);
			padding = " ".repeat(paddingCount);
			column2 = `# ${this.note}`;
		}
		return column1 + padding + column2;
	}
	formatFirstColumn() {
		return " ".repeat(this.level * 4) + this.data.map(bytesToHex$1$3).filter((x) => x.length > 0).join(" ");
	}
};
/**
* Generate dump items for a CBOR value (recursive).
*/
function dumpItems$1(cbor, level, tagsStore) {
	const items = [];
	switch (cbor.type) {
		case MajorType$1$1.Unsigned: {
			const data = encodeCbor$2(cbor);
			items.push(new DumpItem$1(level, [data], `unsigned(${cbor.value})`));
			break;
		}
		case MajorType$1$1.Negative: {
			const data = encodeCbor$2(cbor);
			const actualValue = typeof cbor.value === "bigint" ? -1n - cbor.value : -1 - cbor.value;
			items.push(new DumpItem$1(level, [data], `negative(${actualValue})`));
			break;
		}
		case MajorType$1$1.ByteString: {
			const header = encodeVarInt$1(cbor.value.length, MajorType$1$1.ByteString);
			items.push(new DumpItem$1(level, [header], `bytes(${cbor.value.length})`));
			if (cbor.value.length > 0) {
				let note = void 0;
				try {
					const sanitizedText = sanitized$1(new TextDecoder("utf-8", { fatal: true }).decode(cbor.value));
					if (sanitizedText !== void 0 && sanitizedText !== "") note = flanked$1(sanitizedText, "\"", "\"");
				} catch {}
				items.push(new DumpItem$1(level + 1, [cbor.value], note));
			}
			break;
		}
		case MajorType$1$1.Text: {
			const utf8Data = new TextEncoder().encode(cbor.value);
			const header = encodeVarInt$1(utf8Data.length, MajorType$1$1.Text);
			const firstByte = header[0];
			if (firstByte === void 0) throw CborError$1$1.custom("Invalid varint encoding");
			const headerData = [new Uint8Array([firstByte]), header.slice(1)];
			items.push(new DumpItem$1(level, headerData, `text(${utf8Data.length})`));
			items.push(new DumpItem$1(level + 1, [utf8Data], flanked$1(cbor.value, "\"", "\"")));
			break;
		}
		case MajorType$1$1.Array: {
			const header = encodeVarInt$1(cbor.value.length, MajorType$1$1.Array);
			const firstByte = header[0];
			if (firstByte === void 0) throw CborError$1$1.custom("Invalid varint encoding");
			const headerData = [new Uint8Array([firstByte]), header.slice(1)];
			items.push(new DumpItem$1(level, headerData, `array(${cbor.value.length})`));
			for (const item of cbor.value) items.push(...dumpItems$1(item, level + 1, tagsStore));
			break;
		}
		case MajorType$1$1.Map: {
			const header = encodeVarInt$1(cbor.value.size, MajorType$1$1.Map);
			const firstByte = header[0];
			if (firstByte === void 0) throw CborError$1$1.custom("Invalid varint encoding");
			const headerData = [new Uint8Array([firstByte]), header.slice(1)];
			items.push(new DumpItem$1(level, headerData, `map(${cbor.value.size})`));
			for (const entry of cbor.value.entriesArray) {
				items.push(...dumpItems$1(entry.key, level + 1, tagsStore));
				items.push(...dumpItems$1(entry.value, level + 1, tagsStore));
			}
			break;
		}
		case MajorType$1$1.Tagged: {
			const tagValue = cbor.tag;
			if (tagValue === void 0) throw CborError$1$1.custom("Tagged CBOR value must have a tag");
			const header = encodeVarInt$1(tagValue, MajorType$1$1.Tagged);
			const firstByte = header[0];
			if (firstByte === void 0) throw CborError$1$1.custom("Invalid varint encoding");
			const headerData = [new Uint8Array([firstByte]), header.slice(1)];
			const noteComponents = [`tag(${tagValue})`];
			const tag = Tag$1.from(tagValue);
			const tagName = tagsStore.assignedNameForTag(tag);
			if (tagName !== void 0) noteComponents.push(tagName);
			const tagNote = noteComponents.join(" ");
			items.push(new DumpItem$1(level, headerData, tagNote));
			items.push(...dumpItems$1(cbor.value, level + 1, tagsStore));
			break;
		}
		case MajorType$1$1.Simple: {
			const data = encodeCbor$2(cbor);
			const simple = cbor.value;
			let note;
			if (simple.type === "True") note = "true";
			else if (simple.type === "False") note = "false";
			else if (simple.type === "Null") note = "null";
			else if (simple.type === "Float") note = floatDisplayString$1(simple.value);
			else note = "simple";
			items.push(new DumpItem$1(level, [data], note));
			break;
		}
	}
	return items;
}
/**
* Create a new Tag.
*
* @param value - The numeric tag value
* @param name - Optional human-readable name
* @returns A new Tag object
*
* @example
* ```typescript
* const dateTag = createTag(1, 'date');
* const customTag = createTag(12345, 'myCustomTag');
* ```
*/
const createTag = (value, name) => {
	if (name !== void 0) return {
		value,
		name
	};
	return { value };
};
/**
* Compare two tag values for equality, normalizing `number` vs `bigint`.
* A raw `===` would treat `100n` and `100` as unequal, so a large tag that
* decoded to a `bigint` wouldn't match the same value written as a `number`.
*/
const tagValuesEqual$2 = (a, b) => {
	if (typeof a === "bigint" || typeof b === "bigint") return BigInt(a) === BigInt(b);
	return a === b;
};
/**
* Get the string representation of a tag.
* Internal function used for error messages.
*
* @param tag - The tag to represent
* @returns String representation (name if available, otherwise value)
*
* @internal
*/
const tagToString$2 = (tag) => tag.name ?? tag.value.toString();
/**
* Convert an Error to a display string.
*
* Matches Rust's `Display` trait / `to_string()` method.
*/
const errorToString$1 = (error) => {
	switch (error.type) {
		case "Underrun": return "early end of CBOR data";
		case "UnsupportedHeaderValue": return "unsupported value in CBOR header";
		case "NonCanonicalNumeric": return "a CBOR numeric value was encoded in non-canonical form";
		case "InvalidSimpleValue": return "an invalid CBOR simple value was encountered";
		case "InvalidString": return `an invalidly-encoded UTF-8 string was encountered in the CBOR (${error.message})`;
		case "NonCanonicalString": return "a CBOR string was not encoded in Unicode Canonical Normalization Form C";
		case "UnusedData": return `the decoded CBOR had ${error.count} extra bytes at the end`;
		case "MisorderedMapKey": return "the decoded CBOR map has keys that are not in canonical order";
		case "DuplicateMapKey": return "the decoded CBOR map has a duplicate key";
		case "MissingMapKey": return "missing CBOR map key";
		case "OutOfRange": return "the CBOR numeric value could not be represented in the specified numeric type";
		case "WrongType": return "the decoded CBOR value was not the expected type";
		case "WrongTag": return `expected CBOR tag ${tagToString$2(error.expected)}, but got ${tagToString$2(error.actual)}`;
		case "InvalidUtf8": return `invalid UTF‑8 string: ${error.message}`;
		case "InvalidDate": return `invalid ISO 8601 date string: ${error.message}`;
		case "Custom": return error.message;
	}
};
/**
* Typed error class for all CBOR-related errors.
*
* Wraps the discriminated union Error type in a JavaScript Error object
* for proper error handling with stack traces.
*
* @example
* ```typescript
* throw new CborError({ type: 'Underrun' });
* throw new CborError({ type: 'WrongTag', expected: tag1, actual: tag2 });
* ```
*/
var CborError$2 = class CborError extends Error {
	/**
	* The structured error information.
	*/
	errorType;
	/**
	* Create a new CborError.
	*
	* @param errorType - The discriminated union error type
	* @param message - Optional custom message (defaults to errorToString(errorType))
	*/
	constructor(errorType, message) {
		super(message ?? errorToString$1(errorType));
		this.name = "CborError";
		this.errorType = errorType;
		if ("captureStackTrace" in Error) Error.captureStackTrace(this, CborError);
	}
	/**
	* Check if an error is a CborError.
	*
	* @param error - Error to check
	* @returns True if error is a CborError
	*/
	static isCborError(error) {
		return error instanceof CborError;
	}
};
/**
* Convert a legacy node into a canonical `@blockchaincommons/dcbor` node.
*
* Leaves are shared, not copied: the canonical functions never mutate their
* inputs. Map nodes unwrap to the inner canonical `CborMap`, so later
* mutations through the legacy wrapper stay visible.
*/
const toNew$1 = (c) => {
	switch (c.type) {
		case MajorType$2.Array: return {
			isCbor: true,
			type: MajorType$2.Array,
			value: c.value.map(toNew$1)
		};
		case MajorType$2.Map: return {
			isCbor: true,
			type: MajorType$2.Map,
			value: c.value._inner
		};
		case MajorType$2.Tagged: return {
			isCbor: true,
			type: MajorType$2.Tagged,
			tag: c.tag,
			value: toNew$1(c.value)
		};
		default: return {
			isCbor: true,
			type: c.type,
			value: c.value
		};
	}
};
/**
* Convert a canonical node into a legacy node with the legacy method set.
* Map nodes wrap the canonical `CborMap` without copying entries.
*/
const fromNew$1 = (n) => {
	switch (n.type) {
		case MajorType$2.Array: return attachMethods$2({
			isCbor: true,
			type: MajorType$2.Array,
			value: n.value.map(fromNew$1)
		});
		case MajorType$2.Map: return attachMethods$2({
			isCbor: true,
			type: MajorType$2.Map,
			value: CborMap$2._fromInner(n.value)
		});
		case MajorType$2.Tagged: return attachMethods$2({
			isCbor: true,
			type: MajorType$2.Tagged,
			tag: n.tag,
			value: fromNew$1(n.value)
		});
		default: return attachMethods$2({
			isCbor: true,
			type: n.type,
			value: n.value
		});
	}
};
/**
* Translate a canonical `CborError` (code + details) back into the legacy
* discriminated-union `CborError`. Non-CborError values are re-thrown as-is.
*/
const toLegacyError$1 = (e) => {
	if (!CborError$1$1.isCborError(e)) {
		if (e instanceof CborError$2) return e;
		throw e;
	}
	const details = e.details;
	let errorType;
	switch (e.code) {
		case "UnsupportedHeaderValue":
			errorType = {
				type: "UnsupportedHeaderValue",
				value: details["headerValue"]
			};
			break;
		case "UnusedData":
			errorType = {
				type: "UnusedData",
				count: details["count"]
			};
			break;
		case "WrongTag":
			errorType = {
				type: "WrongTag",
				expected: details["expectedTag"],
				actual: details["actualTag"]
			};
			break;
		case "InvalidString":
			errorType = {
				type: "InvalidString",
				message: details["cause"] ?? e.message
			};
			break;
		case "InvalidUtf8":
			errorType = {
				type: "InvalidUtf8",
				message: details["cause"] ?? e.message
			};
			break;
		case "InvalidDate":
			errorType = {
				type: "InvalidDate",
				message: details["cause"] ?? e.message
			};
			break;
		case "Custom":
			errorType = {
				type: "Custom",
				message: e.message
			};
			break;
		default: errorType = { type: e.code };
	}
	return new CborError$2(errorType);
};
/** Run a canonical-package operation, translating thrown errors. */
const delegating$1 = (op) => {
	try {
		return op();
	} catch (e) {
		throw toLegacyError$1(e);
	}
};
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Tag registry and management system.
*
* The TagsStore provides a centralized registry for CBOR tags,
* including name resolution and custom summarizer functions.
*
* The store wraps the `@blockchaincommons/dcbor` `TagsStore` — and the
* global singleton wraps the canonical package's *global* store — so tag
* names and summarizers registered through this legacy API are visible to
* the delegated diagnostic/hex formatters (and vice versa).
*
* @module tags-store
*/
/**
* Convert a canonical tag (whose `name` may be explicitly `undefined`) to the
* legacy `Tag` shape, which omits the property instead.
*/
const toLegacyTag$1 = (tag) => {
	if (tag === void 0) return void 0;
	return tag.name !== void 0 ? {
		value: tag.value,
		name: tag.name
	} : { value: tag.value };
};
/**
* Tag registry implementation.
*
* Stores tags with their names and optional summarizer functions, delegating
* storage to the canonical `@blockchaincommons/dcbor` store.
*/
var TagsStore$2 = class TagsStore {
	_store;
	/** Original (legacy-signature) summarizers, for the `summarizer()` accessor. */
	_legacySummarizers = /* @__PURE__ */ new Map();
	constructor() {
		this._store = new TagsStore$1$1();
	}
	/**
	* The wrapped canonical `@blockchaincommons/dcbor` store.
	* @internal
	*/
	get _inner() {
		return this._store;
	}
	/**
	* Wrap an existing canonical store without copying registrations.
	* @internal
	*/
	static _fromInner(inner) {
		const store = new TagsStore();
		store._store = inner;
		return store;
	}
	/**
	* Insert a tag into the registry.
	*
	* Matches Rust's TagsStore::insert() behavior:
	* - Throws if the tag name is undefined or empty
	* - Throws if a tag with the same value exists with a different name
	* - Allows re-registering the same tag value with the same name
	*
	* @param tag - The tag to register (must have a non-empty name)
	* @throws Error if tag has no name, empty name, or conflicts with existing registration
	*
	* @example
	* ```typescript
	* const store = new TagsStore();
	* store.insert(createTag(12345, 'myCustomTag'));
	* ```
	*/
	insert(tag) {
		const name = tag.name;
		if (name === void 0 || name === "") throw new Error(`Tag ${tag.value} must have a non-empty name`);
		const existing = this._store.tagForValue(tag.value);
		if (existing?.name !== void 0 && existing.name !== name) throw new Error(`Attempt to register tag: ${tag.value} '${existing.name}' with different name: '${name}'`);
		this._store.register(Tag$1.from(tag.value, name));
	}
	/**
	* Insert multiple tags into the registry.
	* Matches Rust's insert_all() method.
	*
	* @param tags - Array of tags to register
	*
	* @example
	* ```typescript
	* const store = new TagsStore();
	* store.insertAll([
	*   createTag(1, 'date'),
	*   createTag(100, 'custom')
	* ]);
	* ```
	*/
	insertAll(tags) {
		for (const tag of tags) this.insert(tag);
	}
	/**
	* Register a custom summarizer function for a tag.
	*
	* The summarizer is adapted and forwarded to the canonical store, so the
	* delegated diagnostic formatters invoke it (with a legacy-shaped node).
	*
	* @param tagValue - The numeric tag value
	* @param summarizer - The summarizer function
	*
	* @example
	* ```typescript
	* store.setSummarizer(1, (cbor, flat) => {
	*   // Custom date formatting
	*   return `Date(${extractCbor(cbor)})`;
	* });
	* ```
	*/
	setSummarizer(tagValue, summarizer) {
		this._legacySummarizers.set(this._valueKey(tagValue), summarizer);
		this._store.setSummarizer(tagValue, (cbor, flat) => {
			const result = summarizer(fromNew$1(cbor), flat);
			if (result.ok) return result;
			return {
				ok: false,
				error: CborError$1$1.custom(errorToString$1(result.error))
			};
		});
	}
	assignedNameForTag(tag) {
		return this._store.tagForValue(tag.value)?.name;
	}
	nameForTag(tag) {
		return this.assignedNameForTag(tag) ?? tag.value.toString();
	}
	tagForValue(value) {
		return toLegacyTag$1(this._store.tagForValue(value));
	}
	tagForName(name) {
		return toLegacyTag$1(this._store.tagForName(name));
	}
	nameForValue(value) {
		const tag = this.tagForValue(value);
		return tag !== void 0 ? this.nameForTag(tag) : value.toString();
	}
	summarizer(tag) {
		return this._legacySummarizers.get(this._valueKey(tag));
	}
	_valueKey(value) {
		return value.toString();
	}
};
/**
* Global singleton instance of the tags store.
*/
let globalTagsStore$2;
/**
* Get the global tags store instance.
*
* Creates the instance on first access, wrapping the canonical package's
* global store so registrations are shared with the delegated formatters.
*
* @returns The global TagsStore instance
*
* @example
* ```typescript
* const store = getGlobalTagsStore();
* store.insert(createTag(999, 'myTag'));
* ```
*/
const getGlobalTagsStore$2 = () => {
	globalTagsStore$2 ??= TagsStore$2._fromInner(getGlobalTagsStore$1$1());
	return globalTagsStore$2;
};
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Hex dump utilities for CBOR data.
*
* Affordances for viewing the encoded binary representation of CBOR as hexadecimal.
* Optionally annotates the output, breaking it up into semantically meaningful lines,
* formatting dates, and adding names of known tags.
*
* The annotated rendering delegates to `@blockchaincommons/dcbor/diagnostic`.
*
* @module dump
*/
/**
* Convert bytes to hex string.
*/
const bytesToHex$4 = (bytes) => {
	return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
};
/**
* Returns the encoded hexadecimal representation of CBOR.
*
* @param cbor - CBOR value to convert
* @returns Hex string
*/
const hex$1 = (cbor) => bytesToHex$4(cborData$1(cbor));
/**
* Returns the encoded hexadecimal representation of CBOR with options.
*
* Optionally annotates the output, e.g., breaking the output up into
* semantically meaningful lines, formatting dates, and adding names of
* known tags.
*
* @param cbor - CBOR value to convert
* @param opts - Formatting options
* @returns Hex string (possibly annotated)
*/
const hexOpt$1 = (cbor, opts = {}) => {
	if (opts.annotate !== true) return hex$1(cbor);
	const tagsStore = opts.tagsStore ?? getGlobalTagsStore$2();
	return delegating$1(() => hexAnnotated$1(toNew$1(cbor), { tagsStore: tagsStore._inner }));
};
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Enhanced diagnostic formatting for CBOR values.
*
* Provides multiple formatting options including
* - Annotated diagnostics with tag names
* - Summarized values using custom summarizers
* - Flat (single-line) vs. pretty (multi-line) formatting
* - Configurable tag store usage
*
* Rendering delegates to `@blockchaincommons/dcbor/diagnostic` (which shares
* this module's option vocabulary); summarizers registered through this
* package's `TagsStore` are consulted through the wrapped canonical store.
*
* @module diag
*/
/**
* Convert the legacy tags-store option to the canonical one (unwrap a
* wrapped store; pass the string variants through).
*/
const toBcTagsOpt$1 = (tags) => {
	if (tags instanceof TagsStore$2) return tags._inner;
	return tags;
};
/**
* Format CBOR value as diagnostic notation with options.
*
* @param cbor - CBOR value to format
* @param opts - Formatting options
* @returns Diagnostic string
*
* @example
* ```typescript
* const value = cbor({ name: 'Alice', age: 30 });
* console.log(diagnosticOpt(value, { flat: true }));
* // {\"name\": \"Alice\", \"age\": 30}
* ```
*/
function diagnosticOpt$1(cbor, opts) {
	return delegating$1(() => diagnostic$1$1(toNew$1(cbor), {
		annotate: opts?.annotate,
		summarize: opts?.summarize,
		flat: opts?.summarize === true ? true : opts?.flat,
		tags: toBcTagsOpt$1(opts?.tags)
	}));
}
/**
* Format CBOR value as standard diagnostic notation.
*
* @param cbor - CBOR value to format
* @returns Diagnostic string (pretty-printed with multiple lines for complex structures)
*
* @example
* ```typescript
* const value = cbor([1, 2, 3]);
* console.log(diagnostic(value));
* // For simple arrays: "[1, 2, 3]"
* // For nested structures: multi-line formatted output
* ```
*/
function diagnostic$2(cbor) {
	return diagnosticOpt$1(cbor);
}
/**
* Checks if the simple value is a floating point number.
*/
const isFloat$1$1 = (simple) => simple.type === "Float";
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* dCBOR decoding — delegates to `@blockchaincommons/dcbor`, the canonical
* implementation, then rewraps the result into this package's legacy node
* shape. All deterministic-encoding enforcement (canonical numeric forms,
* NFC text, map-key order, no trailing bytes) happens in the canonical
* decoder; thrown errors are translated back to the legacy `CborError`.
*/
function decodeCbor$2(data) {
	return fromNew$1(delegating$1(() => decodeCbor$1$1(data)));
}
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Convenience utilities for working with CBOR values.
*
* Provides type-safe helpers for checking types, extracting values,
* and working with arrays, maps, and tagged values.
*
* @module conveniences
*/
/**
* Extract native JavaScript value from CBOR.
* Converts CBOR types to their JavaScript equivalents.
*/
const extractCbor$2 = (cbor) => {
	let c;
	if (cbor instanceof Uint8Array) c = decodeCbor$2(cbor);
	else c = cbor;
	switch (c.type) {
		case MajorType$2.Unsigned: return c.value;
		case MajorType$2.Negative: if (typeof c.value === "bigint") return -c.value - 1n;
		else return -c.value - 1;
		case MajorType$2.ByteString: return c.value;
		case MajorType$2.Text: return c.value;
		case MajorType$2.Array: return c.value.map(extractCbor$2);
		case MajorType$2.Map: return c.value;
		case MajorType$2.Tagged: return c;
		case MajorType$2.Simple:
			if (c.value.type === "True") return true;
			if (c.value.type === "False") return false;
			if (c.value.type === "Null") return null;
			if (c.value.type === "Float") return c.value.value;
			return c;
	}
};
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Map Support in dCBOR
*
* A deterministic CBOR map that ensures maps with the same content always
* produce identical binary encodings, regardless of insertion order.
*
* This class keeps the historical `@blockchaincommons/dcbor-compat` map API (Rust-flavored
* `insert`/`containsKey`/`len`/`iter` alongside the JS `Map` vocabulary) but
* stores its entries in a `@blockchaincommons/dcbor` `CborMap` — the
* canonical implementation owns key ordering (lexicographic by encoded CBOR
* bytes), duplicate handling, and the decode-time `setNext` ordering checks.
*
* @module map
*/
/**
* A deterministic CBOR map implementation.
*
* Maps are always encoded with keys sorted lexicographically by their
* encoded CBOR representation, ensuring deterministic encoding.
*/
var CborMap$2 = class CborMap {
	_map;
	/**
	* Creates a new, empty CBOR Map.
	* Optionally initializes from a JavaScript Map.
	*/
	constructor(map) {
		this._map = new CborMap$1$1();
		if (map !== void 0) for (const [key, value] of map.entries()) this.set(key, value);
	}
	/**
	* The wrapped canonical `@blockchaincommons/dcbor` map.
	* @internal
	*/
	get _inner() {
		return this._map;
	}
	/**
	* Wrap an existing canonical map without copying entries.
	* @internal
	*/
	static _fromInner(inner) {
		const map = new CborMap();
		map._map = inner;
		return map;
	}
	/**
	* Creates a new, empty CBOR Map.
	* Matches Rust's Map::new().
	*/
	static new() {
		return new CborMap();
	}
	/**
	* Inserts a key-value pair into the map.
	* Matches Rust's Map::insert().
	*/
	set(key, value) {
		const keyCbor = cbor$2(key);
		const valueCbor = cbor$2(value);
		delegating$1(() => this._map.set(toNew$1(keyCbor), toNew$1(valueCbor)));
	}
	/**
	* Alias for set() to match Rust's insert() method.
	*/
	insert(key, value) {
		this.set(key, value);
	}
	/**
	* Get a value from the map, given a key.
	* Returns undefined if the key is not present in the map.
	* Matches Rust's Map::get().
	*/
	get(key) {
		const stored = delegating$1(() => this._map.get(toNew$1(cbor$2(key))));
		if (stored === void 0) return;
		return extractCbor$2(fromNew$1(stored));
	}
	/**
	* Get a value from the map, given a key.
	* Throws an error if the key is not present.
	* Matches Rust's Map::extract().
	*/
	extract(key) {
		const value = this.get(key);
		if (value === void 0) throw new CborError$2({ type: "MissingMapKey" });
		return value;
	}
	/**
	* Tests if the map contains a key.
	* Matches Rust's Map::contains_key().
	*/
	containsKey(key) {
		return delegating$1(() => this._map.has(toNew$1(cbor$2(key))));
	}
	delete(key) {
		return delegating$1(() => this._map.delete(toNew$1(cbor$2(key))));
	}
	has(key) {
		return this.containsKey(key);
	}
	clear() {
		this._map.clear();
	}
	/**
	* Returns the number of entries in the map.
	* Matches Rust's Map::len().
	*/
	get length() {
		return this._map.size;
	}
	/**
	* Alias for length to match JavaScript Map API.
	* Also matches Rust's Map::len().
	*/
	get size() {
		return this._map.size;
	}
	/**
	* Returns the number of entries in the map.
	* Matches Rust's Map::len().
	*/
	len() {
		return this._map.size;
	}
	/**
	* Checks if the map is empty.
	* Matches Rust's Map::is_empty().
	*/
	isEmpty() {
		return this._map.size === 0;
	}
	/**
	* Get the entries of the map as an array.
	* Keys are sorted in lexicographic order of their encoded CBOR bytes.
	*/
	get entriesArray() {
		const entries = [];
		for (const [key, value] of this._map.entries()) entries.push({
			key: fromNew$1(key),
			value: fromNew$1(value)
		});
		return entries;
	}
	/**
	* Gets an iterator over the entries of the CBOR map, sorted by key.
	* Key sorting order is lexicographic by the key's binary-encoded CBOR.
	* Matches Rust's Map::iter().
	*/
	iter() {
		return this.entriesArray;
	}
	/**
	* Returns an iterator of [key, value] tuples for JavaScript Map API compatibility.
	* This matches the standard JavaScript Map.entries() method behavior.
	*/
	*entries() {
		for (const entry of this.entriesArray) yield [entry.key, entry.value];
	}
	/**
	* Inserts the next key-value pair into the map during decoding.
	* This is used for efficient map building during CBOR decoding.
	* Throws if the key is not in ascending order or is a duplicate.
	* Matches Rust's Map::insert_next().
	*/
	setNext(key, value) {
		const keyCbor = cbor$2(key);
		const valueCbor = cbor$2(value);
		delegating$1(() => this._map.setNext(toNew$1(keyCbor), toNew$1(valueCbor)));
	}
	get debug() {
		return `map({${this.entriesArray.map(CborMap.entryDebug).join(", ")}})`;
	}
	get diagnostic() {
		return `{${this.entriesArray.map(CborMap.entryDiagnostic).join(", ")}}`;
	}
	static entryDebug(entry) {
		const keyDebug = CborMap.formatDebug(entry.key);
		const valueDebug = CborMap.formatDebug(entry.value);
		return `0x${bytesToHex$4(encodeCbor$1$3(entry.key))}: (${keyDebug}, ${valueDebug})`;
	}
	static formatDebug(cbor) {
		switch (cbor.type) {
			case MajorType$2.Unsigned: return `unsigned(${cbor.value})`;
			case MajorType$2.Negative: return `negative(${typeof cbor.value === "bigint" ? -cbor.value - 1n : -cbor.value - 1})`;
			case MajorType$2.ByteString: return `bytes(${bytesToHex$4(cbor.value)})`;
			case MajorType$2.Text: return `text("${cbor.value}")`;
			case MajorType$2.Array: return `array([${cbor.value.map(CborMap.formatDebug).join(", ")}])`;
			case MajorType$2.Map: return cbor.value.debug;
			case MajorType$2.Tagged: return `tagged(${cbor.tag}, ${CborMap.formatDebug(cbor.value)})`;
			case MajorType$2.Simple: {
				const simple = cbor.value;
				if (typeof simple === "object" && simple !== null && "type" in simple) switch (simple.type) {
					case "True": return "simple(true)";
					case "False": return "simple(false)";
					case "Null": return "simple(null)";
					case "Float": return `simple(${simple.value})`;
				}
				return "simple";
			}
			default: return diagnostic$2(cbor);
		}
	}
	static entryDiagnostic(entry) {
		return `${diagnostic$2(entry.key)}: ${diagnostic$2(entry.value)}`;
	}
	*[Symbol.iterator]() {
		for (const entry of this.entriesArray) yield [entry.key, entry.value];
	}
	toMap() {
		const map = /* @__PURE__ */ new Map();
		for (const entry of this.entriesArray) map.set(extractCbor$2(entry.key), extractCbor$2(entry.value));
		return map;
	}
};
/**
* Clone helper used to give each descendant subtree an independent copy of
* the post-visit state — mirrors Rust `State: Clone` + `state.clone()` per
* child in `walk.rs`. Falls back to the value as-is for primitives (which
* don't need cloning) and uses `structuredClone` for objects.
*/
const cloneState$1 = (s) => {
	if (s === null) return s;
	const t = typeof s;
	if (t !== "object" && t !== "function") return s;
	return globalThis.structuredClone(s);
};
/**
* Walk a CBOR tree, visiting each element with a visitor function.
*
* The visitor function is called for each element in the tree, in depth-first order.
* State semantics mirror Rust's `walk_internal`:
*
* - The visitor's returned `newState` propagates **down** to descendants of
*   the just-visited node only.
* - Sibling subtrees each receive an independent clone of the parent's
*   post-visit state, so accumulating mutations in one subtree never leak
*   into a sibling.
* - State changes do not propagate **up**: the public `walk` returns `void`.
*
* For maps, the visitor is called with:
* 1. A 'keyvalue' element containing both key and value
* 2. The key individually (if descent wasn't stopped)
* 3. The value individually (if descent wasn't stopped)
*
* @template State - The type of state to pass into each visit
* @param cbor - The CBOR value to traverse
* @param initialState - Initial state value
* @param visitor - Function to call for each element
*/
const walk$1 = (cbor, initialState, visitor) => {
	walkInternal$1(cbor, 0, { type: "none" }, initialState, visitor);
};
/**
* Internal recursive walk implementation.
*
* @internal
*/
function walkInternal$1(cbor, level, edge, state, visitor) {
	const [postVisitState, stop] = visitor({
		type: "single",
		cbor
	}, level, edge, state);
	if (stop) return;
	switch (cbor.type) {
		case MajorType$2.Array:
			walkArray$1(cbor, level, postVisitState, visitor);
			break;
		case MajorType$2.Map:
			walkMap$1(cbor, level, postVisitState, visitor);
			break;
		case MajorType$2.Tagged: walkTagged$1(cbor, level, postVisitState, visitor);
	}
}
/**
* Walk an array's elements. Each element is visited with an independent
* clone of `parentState`.
*
* @internal
*/
function walkArray$1(cbor, level, parentState, visitor) {
	for (let index = 0; index < cbor.value.length; index++) {
		const item = cbor.value[index];
		if (item === void 0) throw new CborError$2({
			type: "Custom",
			message: `Array element at index ${index} is undefined`
		});
		walkInternal$1(item, level + 1, {
			type: "array_element",
			index
		}, cloneState$1(parentState), visitor);
	}
}
/**
* Walk a map's key-value pairs.
*
* Each kv pair receives a clone of `parentState`. If descent isn't stopped,
* the key and value subtrees receive independent clones of the kv-visit's
* post-visit state.
*
* @internal
*/
function walkMap$1(cbor, level, parentState, visitor) {
	for (const entry of cbor.value.entriesArray) {
		const { key, value } = entry;
		const [kvPostState, kvStop] = visitor({
			type: "keyvalue",
			key,
			value
		}, level + 1, { type: "map_key_value" }, cloneState$1(parentState));
		if (kvStop) continue;
		walkInternal$1(key, level + 1, { type: "map_key" }, cloneState$1(kvPostState), visitor);
		walkInternal$1(value, level + 1, { type: "map_value" }, cloneState$1(kvPostState), visitor);
	}
}
/**
* Walk a tagged value's content. The content visit receives a clone of
* `parentState`.
*
* @internal
*/
function walkTagged$1(cbor, level, parentState, visitor) {
	walkInternal$1(cbor.value, level + 1, { type: "tagged_content" }, cloneState$1(parentState), visitor);
}
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*/
const MajorType$2 = {
	Unsigned: 0,
	Negative: 1,
	ByteString: 2,
	Text: 3,
	Array: 4,
	Map: 5,
	Tagged: 6,
	Simple: 7
};
const MajorTypeNames$1 = {
	[MajorType$2.Unsigned]: "Unsigned",
	[MajorType$2.Negative]: "Negative",
	[MajorType$2.ByteString]: "ByteString",
	[MajorType$2.Text]: "Text",
	[MajorType$2.Array]: "Array",
	[MajorType$2.Map]: "Map",
	[MajorType$2.Tagged]: "Tagged",
	[MajorType$2.Simple]: "Simple"
};
const getMajorTypeName$1 = (type) => MajorTypeNames$1[type];
const isCborNumber$2 = (value) => {
	return typeof value === "number" || typeof value === "bigint";
};
const isCbor$2 = (value) => {
	return value !== null && typeof value === "object" && "isCbor" in value && value.isCbor === true;
};
/**
* Type guard to check if value has taggedCbor method.
*/
/**
* Resolve a numeric/bigint tag value to a `Tag` object, looking up the
* canonical name from the global tags store (matches Rust's
* `try_into_tagged_value` returning the stored `Tag`). Falls back to a
* name-less `{ value }` if no name is registered — never synthesizes a
* placeholder `tag-${value}` string.
*/
const resolveTag$1 = (value) => {
	const stored = getGlobalTagsStore$2().tagForValue(value);
	if (stored !== void 0) return stored;
	return { value };
};
const hasTaggedCbor$2 = (value) => {
	return typeof value === "object" && value !== null && "taggedCbor" in value && typeof value.taggedCbor === "function";
};
/**
* Type guard to check if value has toCbor method.
*/
const hasToCbor$2 = (value) => {
	return typeof value === "object" && value !== null && "toCbor" in value && typeof value.toCbor === "function";
};
/**
* Convert any value to a CBOR representation.
* Matches Rust's `From` trait implementations for CBOR.
*/
const cbor$2 = (value) => {
	if (isCbor$2(value) && "toData" in value) return value;
	if (isCbor$2(value)) return attachMethods$2(value);
	let result;
	if (isCborNumber$2(value)) {
		if (typeof value === "number" && Number.isNaN(value)) result = {
			isCbor: true,
			type: MajorType$2.Simple,
			value: {
				type: "Float",
				value: NaN
			}
		};
		else if (typeof value === "number" && hasFractionalPart$1(value)) result = {
			isCbor: true,
			type: MajorType$2.Simple,
			value: {
				type: "Float",
				value
			}
		};
		else if (value == Infinity) result = {
			isCbor: true,
			type: MajorType$2.Simple,
			value: {
				type: "Float",
				value: Infinity
			}
		};
		else if (value == -Infinity) result = {
			isCbor: true,
			type: MajorType$2.Simple,
			value: {
				type: "Float",
				value: -Infinity
			}
		};
		else if (typeof value === "number" && !Number.isSafeInteger(value)) {
			const big = BigInt(value);
			if (big >= 0n && big <= 18446744073709551615n) result = {
				isCbor: true,
				type: MajorType$2.Unsigned,
				value: big
			};
			else if (big < 0n && big >= -18446744073709551616n) result = {
				isCbor: true,
				type: MajorType$2.Negative,
				value: -big - 1n
			};
			else result = {
				isCbor: true,
				type: MajorType$2.Simple,
				value: {
					type: "Float",
					value
				}
			};
		} else if (typeof value === "bigint" && (value > 18446744073709551615n || value < -18446744073709551616n)) throw new CborError$2({ type: "OutOfRange" });
		else if (value < 0) {
			if (typeof value === "bigint") result = {
				isCbor: true,
				type: MajorType$2.Negative,
				value: -value - 1n
			};
			else result = {
				isCbor: true,
				type: MajorType$2.Negative,
				value: -value - 1
			};
		} else result = {
			isCbor: true,
			type: MajorType$2.Unsigned,
			value
		};
	} else if (typeof value === "string") {
		const normalized = value.normalize("NFC");
		result = {
			isCbor: true,
			type: MajorType$2.Text,
			value: normalized
		};
	} else if (value === null || value === void 0) result = {
		isCbor: true,
		type: MajorType$2.Simple,
		value: { type: "Null" }
	};
	else if (value === true) result = {
		isCbor: true,
		type: MajorType$2.Simple,
		value: { type: "True" }
	};
	else if (value === false) result = {
		isCbor: true,
		type: MajorType$2.Simple,
		value: { type: "False" }
	};
	else if (Array.isArray(value)) result = {
		isCbor: true,
		type: MajorType$2.Array,
		value: value.map(cbor$2)
	};
	else if (value instanceof Uint8Array) result = {
		isCbor: true,
		type: MajorType$2.ByteString,
		value
	};
	else if (value instanceof CborMap$2) result = {
		isCbor: true,
		type: MajorType$2.Map,
		value
	};
	else if (value instanceof Map) result = {
		isCbor: true,
		type: MajorType$2.Map,
		value: new CborMap$2(value)
	};
	else if (value instanceof Set) result = {
		isCbor: true,
		type: MajorType$2.Array,
		value: Array.from(value).map((v) => cbor$2(v))
	};
	else if (hasTaggedCbor$2(value)) return value.taggedCbor();
	else if (hasToCbor$2(value)) return value.toCbor();
	else if (typeof value === "object" && value !== null && "tag" in value && "value" in value) {
		const keys = Object.keys(value);
		const objValue = value;
		if (keys.length === 2 && keys.includes("tag") && keys.includes("value")) return taggedCbor$1(objValue.tag, objValue.value);
		const map = new CborMap$2();
		for (const [key, val] of Object.entries(value)) map.set(cbor$2(key), cbor$2(val));
		result = {
			isCbor: true,
			type: MajorType$2.Map,
			value: map
		};
	} else if (typeof value === "object" && value !== null) {
		const map = new CborMap$2();
		for (const [key, val] of Object.entries(value)) map.set(cbor$2(key), cbor$2(val));
		result = {
			isCbor: true,
			type: MajorType$2.Map,
			value: map
		};
	} else throw new CborError$2({
		type: "Custom",
		message: "Unsupported type for CBOR encoding"
	});
	return attachMethods$2(result);
};
/**
* Encode a CBOR value to binary data.
* Matches Rust's `CBOR::to_cbor_data()` method.
*
* Delegates to `@blockchaincommons/dcbor` — the canonical encoder — via the
* structural node bridge.
*/
const cborData$1 = (value) => {
	const c = cbor$2(value);
	return delegating$1(() => encodeCbor$2(toNew$1(c)));
};
const encodeCbor$1$3 = (value) => {
	return cborData$1(cbor$2(value));
};
const taggedCbor$1 = (tag, value) => {
	const tagNumber = typeof tag === "number" || typeof tag === "bigint" ? tag : Number(tag);
	return attachMethods$2({
		isCbor: true,
		type: MajorType$2.Tagged,
		tag: tagNumber,
		value: cbor$2(value)
	});
};
/**
* Attaches instance methods to a CBOR value.
* This enables method chaining like cbor.toHex() instead of Cbor.toHex(cbor).
* @internal
*/
const attachMethods$2 = (obj) => {
	return Object.assign(obj, {
		toData() {
			return cborData$1(this);
		},
		toHex() {
			return bytesToHex$4(cborData$1(this));
		},
		toHexAnnotated(tagsStore) {
			tagsStore = tagsStore ?? getGlobalTagsStore$2();
			return hexOpt$1(this, {
				annotate: true,
				tagsStore
			});
		},
		toString() {
			return diagnosticOpt$1(this, { flat: true });
		},
		toDebugString() {
			return diagnosticOpt$1(this, { flat: false });
		},
		toDiagnostic() {
			return diagnosticOpt$1(this, { flat: false });
		},
		toDiagnosticAnnotated() {
			return diagnosticOpt$1(this, { annotate: true });
		},
		isByteString() {
			return this.type === MajorType$2.ByteString;
		},
		isText() {
			return this.type === MajorType$2.Text;
		},
		isArray() {
			return this.type === MajorType$2.Array;
		},
		isMap() {
			return this.type === MajorType$2.Map;
		},
		isTagged() {
			return this.type === MajorType$2.Tagged;
		},
		isSimple() {
			return this.type === MajorType$2.Simple;
		},
		isBool() {
			return this.type === MajorType$2.Simple && (this.value.type === "True" || this.value.type === "False");
		},
		isTrue() {
			return this.type === MajorType$2.Simple && this.value.type === "True";
		},
		isFalse() {
			return this.type === MajorType$2.Simple && this.value.type === "False";
		},
		isNull() {
			return this.type === MajorType$2.Simple && this.value.type === "Null";
		},
		isNumber() {
			if (this.type === MajorType$2.Unsigned || this.type === MajorType$2.Negative) return true;
			if (this.type === MajorType$2.Simple) return isFloat$1$1(this.value);
			return false;
		},
		isInteger() {
			return this.type === MajorType$2.Unsigned || this.type === MajorType$2.Negative;
		},
		isUnsigned() {
			return this.type === MajorType$2.Unsigned;
		},
		isNegative() {
			return this.type === MajorType$2.Negative;
		},
		isNaN() {
			return this.type === MajorType$2.Simple && this.value.type === "Float" && Number.isNaN(this.value.value);
		},
		isFloat() {
			return this.type === MajorType$2.Simple && isFloat$1$1(this.value);
		},
		asByteString() {
			return this.type === MajorType$2.ByteString ? this.value : void 0;
		},
		asText() {
			return this.type === MajorType$2.Text ? this.value : void 0;
		},
		asArray() {
			return this.type === MajorType$2.Array ? this.value : void 0;
		},
		asMap() {
			return this.type === MajorType$2.Map ? this.value : void 0;
		},
		asTagged() {
			if (this.type !== MajorType$2.Tagged) return;
			return [resolveTag$1(this.tag), this.value];
		},
		asBool() {
			if (this.type !== MajorType$2.Simple) return void 0;
			if (this.value.type === "True") return true;
			if (this.value.type === "False") return false;
		},
		asInteger() {
			if (this.type === MajorType$2.Unsigned) return this.value;
			else if (this.type === MajorType$2.Negative) {
				if (typeof this.value === "bigint") return -this.value - 1n;
				else return -this.value - 1;
			}
		},
		asNumber() {
			if (this.type === MajorType$2.Unsigned) return this.value;
			else if (this.type === MajorType$2.Negative) {
				if (typeof this.value === "bigint") return -this.value - 1n;
				else return -this.value - 1;
			} else if (this.type === MajorType$2.Simple && isFloat$1$1(this.value)) return this.value.value;
		},
		asSimpleValue() {
			return this.type === MajorType$2.Simple ? this.value : void 0;
		},
		toByteString() {
			if (this.type !== MajorType$2.ByteString) throw new TypeError(`Cannot convert CBOR to ByteString: expected ByteString type, got ${getMajorTypeName$1(this.type)}`);
			return this.value;
		},
		toText() {
			if (this.type !== MajorType$2.Text) throw new TypeError(`Cannot convert CBOR to Text: expected Text type, got ${getMajorTypeName$1(this.type)}`);
			return this.value;
		},
		toArray() {
			if (this.type !== MajorType$2.Array) throw new TypeError(`Cannot convert CBOR to Array: expected Array type, got ${getMajorTypeName$1(this.type)}`);
			return this.value;
		},
		toMap() {
			if (this.type !== MajorType$2.Map) throw new TypeError(`Cannot convert CBOR to Map: expected Map type, got ${getMajorTypeName$1(this.type)}`);
			return this.value;
		},
		toTagged() {
			if (this.type !== MajorType$2.Tagged) throw new TypeError(`Cannot convert CBOR to Tagged: expected Tagged type, got ${getMajorTypeName$1(this.type)}`);
			return [resolveTag$1(this.tag), this.value];
		},
		toBool() {
			const result = this.asBool();
			if (result === void 0) throw new TypeError(`Cannot convert CBOR to boolean: expected Simple(True/False) type, got ${getMajorTypeName$1(this.type)}`);
			return result;
		},
		toInteger() {
			const result = this.asInteger();
			if (result === void 0) throw new TypeError(`Cannot convert CBOR to integer: expected Unsigned or Negative type, got ${getMajorTypeName$1(this.type)}`);
			return result;
		},
		toNumber() {
			const result = this.asNumber();
			if (result === void 0) throw new TypeError(`Cannot convert CBOR to number: expected Unsigned, Negative, or Float type, got ${getMajorTypeName$1(this.type)}`);
			return result;
		},
		toSimpleValue() {
			if (this.type !== MajorType$2.Simple) throw new TypeError(`Cannot convert CBOR to Simple: expected Simple type, got ${getMajorTypeName$1(this.type)}`);
			return this.value;
		},
		expectTag(expectedTag) {
			if (this.type !== MajorType$2.Tagged) throw new CborError$2({ type: "WrongType" });
			const expected = typeof expectedTag === "object" && "value" in expectedTag ? expectedTag : { value: expectedTag };
			if (!tagValuesEqual$2(this.tag, expected.value)) throw new CborError$2({
				type: "WrongTag",
				expected,
				actual: { value: this.tag }
			});
			return this.value;
		},
		walk(initialState, visitor) {
			walk$1(this, initialState, visitor);
		},
		validateTag(expectedTags) {
			if (this.type !== MajorType$2.Tagged) throw new CborError$2({ type: "WrongType" });
			const tagValue = this.tag;
			const matchingTag = expectedTags.find((t) => tagValuesEqual$2(t.value, tagValue));
			if (matchingTag === void 0) throw new CborError$2({
				type: "WrongTag",
				expected: expectedTags[0],
				actual: { value: tagValue }
			});
			return matchingTag;
		},
		untagged() {
			if (this.type !== MajorType$2.Tagged) throw new CborError$2({ type: "WrongType" });
			return this.value;
		}
	});
};
attachMethods$2({
	isCbor: true,
	type: MajorType$2.Simple,
	value: { type: "False" }
}), attachMethods$2({
	isCbor: true,
	type: MajorType$2.Simple,
	value: { type: "True" }
}), attachMethods$2({
	isCbor: true,
	type: MajorType$2.Simple,
	value: { type: "Null" }
}), attachMethods$2({
	isCbor: true,
	type: MajorType$2.Simple,
	value: {
		type: "Float",
		value: NaN
	}
});
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* CBOR Tags Registry
*
* This is a 1:1 port of the Rust bc-tags-rust implementation.
*
* @see https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md
*
* As of August 13 2022, the [IANA registry of CBOR tags](https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml)
* has the following low-numbered values available:
*
* One byte encoding: 6-15, 19-20
* Two byte encoding: 48-51, 53, 55-60, 62, 88-95, 99, 102, 105-109, 113-119,
* 128-255
*
* Tags in the range 0-23 require "standards action" for the IANA to recognize.
* Tags in the range 24-32767 require a specification to reserve.
* Tags in the range 24-255 only require two bytes to encode.
* Higher numbered tags are first-come, first-served.
*/
const URI$1 = createTag(32, "url");
const UUID$1 = createTag(37, "uuid");
const ENVELOPE = createTag(200, "envelope");
const LEAF = createTag(201, "leaf");
const JSON$1 = createTag(262, "json");
const KNOWN_VALUE = createTag(4e4, "known-value");
const DIGEST = createTag(40001, "digest");
const ENCRYPTED = createTag(40002, "encrypted");
const COMPRESSED = createTag(40003, "compressed");
const X25519_PRIVATE_KEY = createTag(40010, "agreement-private-key");
const X25519_PUBLIC_KEY = createTag(40011, "agreement-public-key");
const ARID$1 = createTag(40012, "arid");
const PRIVATE_KEYS = createTag(40013, "crypto-prvkeys");
const NONCE = createTag(40014, "nonce");
const PRIVATE_KEY_BASE = createTag(40016, "crypto-prvkey-base");
const PUBLIC_KEYS = createTag(40017, "crypto-pubkeys");
const SALT = createTag(40018, "salt");
const SEALED_MESSAGE = createTag(40019, "crypto-sealed");
const SIGNATURE = createTag(40020, "signature");
const SIGNING_PRIVATE_KEY = createTag(40021, "signing-private-key");
const SIGNING_PUBLIC_KEY = createTag(40022, "signing-public-key");
const SYMMETRIC_KEY = createTag(40023, "crypto-key");
const XID$1 = createTag(40024, "xid");
const REFERENCE = createTag(40025, "reference");
const ENCRYPTED_KEY = createTag(40027, "encrypted-key");
const MLKEM_PRIVATE_KEY = createTag(40100, "mlkem-private-key");
const MLKEM_PUBLIC_KEY = createTag(40101, "mlkem-public-key");
const MLKEM_CIPHERTEXT = createTag(40102, "mlkem-ciphertext");
const MLDSA_PRIVATE_KEY = createTag(40103, "mldsa-private-key");
const MLDSA_PUBLIC_KEY = createTag(40104, "mldsa-public-key");
const MLDSA_SIGNATURE = createTag(40105, "mldsa-signature");
const SEED = createTag(40300, "seed");
const EC_KEY = createTag(40306, "eckey");
const SSKR_SHARE = createTag(40309, "sskr");
const SSH_TEXT_PRIVATE_KEY = createTag(40800, "ssh-private");
const SSH_TEXT_PUBLIC_KEY = createTag(40801, "ssh-public");
const SSH_TEXT_SIGNATURE = createTag(40802, "ssh-signature");
const SEED_V1 = createTag(300, "crypto-seed");
const EC_KEY_V1 = createTag(306, "crypto-eckey");
const SSKR_SHARE_V1 = createTag(309, "crypto-sskr");
//#endregion
//#region src/utils.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Utility functions for byte array conversions and comparisons.
*
* These functions provide cross-platform support for common byte manipulation
* operations needed in cryptographic and encoding contexts.
*
* @packageDocumentation
*/
/**
* Convert a Uint8Array to a lowercase hexadecimal string.
*
* @param data - The byte array to convert
* @returns A lowercase hex string representation (2 characters per byte)
*
* @example
* ```typescript
* const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
* bytesToHex(bytes); // "deadbeef"
* ```
*/
function bytesToHex(data) {
	return Array.from(data).map((b) => b.toString(16).padStart(2, "0")).join("");
}
/**
* Convert a hexadecimal string to a Uint8Array.
*
* @param hex - A hex string (must have even length, case-insensitive)
* @returns The decoded byte array
* @throws {Error} If the hex string has odd length or contains invalid characters
*
* @example
* ```typescript
* hexToBytes("deadbeef"); // Uint8Array([0xde, 0xad, 0xbe, 0xef])
* hexToBytes("DEADBEEF"); // Uint8Array([0xde, 0xad, 0xbe, 0xef])
* hexToBytes("xyz"); // throws Error: Invalid hex string
* ```
*/
function hexToBytes(hex) {
	if (hex.length % 2 !== 0) throw new Error(`Hex string must have even length, got ${hex.length}`);
	if (!/^[0-9A-Fa-f]*$/.test(hex)) throw new Error("Invalid hex string: contains non-hexadecimal characters");
	const data = new Uint8Array(hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) data[i / 2] = parseInt(hex.substring(i, i + 2), 16);
	return data;
}
/**
* Convert a Uint8Array to a base64-encoded string.
*
* This function works in both browser and Node.js environments.
* Uses btoa which is available in browsers and Node.js 16+.
*
* @param data - The byte array to encode
* @returns A base64-encoded string
*
* @example
* ```typescript
* const bytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
* toBase64(bytes); // "SGVsbG8="
* ```
*/
function toBase64(data) {
	let binary = "";
	for (const byte of data) binary += String.fromCharCode(byte);
	return btoa(binary);
}
/**
* Convert a base64-encoded string to a Uint8Array.
*
* This function works in both browser and Node.js environments.
* Uses atob which is available in browsers and Node.js 16+.
*
* @param base64 - A base64-encoded string
* @returns The decoded byte array
*
* @example
* ```typescript
* fromBase64("SGVsbG8="); // Uint8Array([72, 101, 108, 108, 111])
* ```
*/
function fromBase64(base64) {
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes;
}
/**
* Compare two Uint8Arrays for equality using constant-time comparison.
*
* This function is designed to be resistant to timing attacks by always
* comparing all bytes regardless of where a difference is found. The
* comparison time depends only on the length of the arrays, not on where
* they differ.
*
* **Security Note**: If the arrays have different lengths, this function
* returns `false` immediately, which does leak length information. For
* cryptographic uses where length should also be secret, ensure both
* arrays are the same length before comparison.
*
* @param a - First byte array
* @param b - Second byte array
* @returns `true` if both arrays have the same length and identical contents
*
* @example
* ```typescript
* const key1 = new Uint8Array([1, 2, 3, 4]);
* const key2 = new Uint8Array([1, 2, 3, 4]);
* const key3 = new Uint8Array([1, 2, 3, 5]);
*
* bytesEqual(key1, key2); // true
* bytesEqual(key1, key3); // false
* ```
*/
function bytesEqual(a, b) {
	if (a.length !== b.length) return false;
	let result = 0;
	for (let i = 0; i < a.length; i++) result |= a[i] ^ b[i];
	return result === 0;
}
//#endregion
//#region src/json.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* A CBOR-tagged container for UTF-8 JSON text.
*
* Ported from bc-components-rust/src/json.rs
*
* The `JSON` type wraps UTF-8 JSON text as a CBOR byte string with tag 262.
* This allows JSON data to be embedded within CBOR structures while
* maintaining type information through the tag.
*
* This implementation does not validate that the contained data is well-formed
* JSON. It simply provides a type-safe wrapper around byte data that is
* intended to contain JSON text.
*
* # CBOR Serialization
*
* `JSON` implements the CBOR tagged encoding interfaces, which means it can be
* serialized to and deserialized from CBOR with tag 262 (`TAG_JSON`).
*
* @example
* ```typescript
* import { JSON } from '@blockchaincommons/components';
*
* // Create JSON from a string
* const json = JSON.fromString('{"key": "value"}');
* console.log(json.asStr()); // {"key": "value"}
*
* // Create JSON from bytes
* const json2 = JSON.fromData(new TextEncoder().encode('[1, 2, 3]'));
* console.log(json2.len()); // 9
* ```
*/
/**
* A CBOR-tagged container for UTF-8 JSON text.
*
* Wraps UTF-8 JSON text as a CBOR byte string with tag 262.
* This allows JSON data to be embedded within CBOR structures while
* maintaining type information through the tag.
*/
var JSON = class JSON {
	_data;
	constructor(data) {
		this._data = new Uint8Array(data);
	}
	/**
	* Create a new JSON instance from byte data.
	*/
	static fromData(data) {
		return new JSON(data);
	}
	/**
	* Create a new JSON instance from a string.
	*/
	static fromString(s) {
		const encoder = new TextEncoder();
		return new JSON(encoder.encode(s));
	}
	/**
	* Create a new JSON instance from a hexadecimal string.
	*/
	static fromHex(hex) {
		return new JSON(hexToBytes(hex));
	}
	/**
	* Return the length of the JSON data in bytes.
	*/
	len() {
		return this._data.length;
	}
	/**
	* Return true if the JSON data is empty.
	*/
	isEmpty() {
		return this._data.length === 0;
	}
	/**
	* Return the data as a byte slice.
	*/
	asBytes() {
		return new Uint8Array(this._data);
	}
	/**
	* Return the data as a UTF-8 string slice.
	*
	* @throws Error if the data is not valid UTF-8.
	*/
	asStr() {
		return new TextDecoder("utf-8", { fatal: true }).decode(this._data);
	}
	/**
	* Return the data as a hexadecimal string.
	*/
	hex() {
		return bytesToHex(this._data);
	}
	/**
	* Return a copy of the underlying data.
	*/
	toData() {
		return new Uint8Array(this._data);
	}
	/**
	* Compare with another JSON.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `JSON(${this.asStr()})`;
	}
	/**
	* Returns the CBOR tags associated with JSON.
	*/
	cborTags() {
		return tagsForValues([JSON$1.value]);
	}
	/**
	* Returns the untagged CBOR encoding (as a byte string).
	*/
	untaggedCbor() {
		return toByteString(this._data);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates a JSON by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cborValue) {
		const data = expectBytes(cborValue);
		return JSON.fromData(data);
	}
	/**
	* Creates a JSON by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		return JSON.fromString("").fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return JSON.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return JSON.fromString("").fromUntaggedCbor(cborValue);
	}
};
//#endregion
//#region ../bc-crypto-ts/tests/baseline/crypto-baseline.mjs
var __defProp = Object.defineProperty;
var __exportAll = (all, no_symbols) => {
	let target = {};
	for (var name in all) __defProp(target, name, {
		get: all[name],
		enumerable: true
	});
	if (!no_symbols) __defProp(target, Symbol.toStringTag, { value: "Module" });
	return target;
};
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*/
var hash_exports = /* @__PURE__ */ __exportAll({
	CRC32_SIZE: () => 4,
	SHA256_SIZE: () => 32,
	SHA512_SIZE: () => 64,
	crc32: () => crc32$1,
	crc32Data: () => crc32Data,
	crc32DataOpt: () => crc32DataOpt,
	doubleSha256: () => doubleSha256,
	hkdfHmacSha256: () => hkdfHmacSha256,
	hkdfHmacSha512: () => hkdfHmacSha512,
	hmacSha256: () => hmacSha256$1,
	hmacSha512: () => hmacSha512,
	pbkdf2HmacSha256: () => pbkdf2HmacSha256,
	pbkdf2HmacSha512: () => pbkdf2HmacSha512,
	sha256: () => sha256$2,
	sha512: () => sha512$1
});
const CRC32_TABLE$3 = /* @__PURE__ */ new Uint32Array(256);
for (let i = 0; i < 256; i++) {
	let crc = i;
	for (let j = 0; j < 8; j++) crc = (crc & 1) !== 0 ? crc >>> 1 ^ 3988292384 : crc >>> 1;
	CRC32_TABLE$3[i] = crc >>> 0;
}
/**
* Calculate CRC-32 checksum
*/
function crc32$1(data) {
	let crc = 4294967295;
	for (const byte of data) crc = CRC32_TABLE$3[(crc ^ byte) & 255] ^ crc >>> 8;
	return (crc ^ 4294967295) >>> 0;
}
/**
* Calculate CRC-32 checksum and return as a 4-byte big-endian array
*/
function crc32Data(data) {
	return crc32DataOpt(data, false);
}
/**
* Calculate CRC-32 checksum and return as a 4-byte array
* @param data - Input data
* @param littleEndian - If true, returns little-endian; otherwise big-endian
*/
function crc32DataOpt(data, littleEndian) {
	const checksum = crc32$1(data);
	const result = /* @__PURE__ */ new Uint8Array(4);
	new DataView(result.buffer).setUint32(0, checksum, littleEndian);
	return result;
}
/**
* Calculate SHA-256 hash
*/
function sha256$2(data) {
	return sha256(data);
}
/**
* Calculate double SHA-256 hash (SHA-256 of SHA-256)
* This is the standard Bitcoin hashing function
*/
function doubleSha256(message) {
	return sha256$2(sha256$2(message));
}
/**
* Calculate SHA-512 hash
*/
function sha512$1(data) {
	return sha512(data);
}
/**
* Calculate HMAC-SHA-256
*/
function hmacSha256$1(key, message) {
	return hmac(sha256, key, message);
}
/**
* Calculate HMAC-SHA-512
*/
function hmacSha512(key, message) {
	return hmac(sha512, key, message);
}
/**
* Derive a key using PBKDF2 with HMAC-SHA-256
*/
function pbkdf2HmacSha256(password, salt, iterations, keyLen) {
	return pbkdf2(sha256, password, salt, {
		c: iterations,
		dkLen: keyLen
	});
}
/**
* Derive a key using PBKDF2 with HMAC-SHA-512
*/
function pbkdf2HmacSha512(password, salt, iterations, keyLen) {
	return pbkdf2(sha512, password, salt, {
		c: iterations,
		dkLen: keyLen
	});
}
/**
* Derive a key using HKDF with HMAC-SHA-256
*/
function hkdfHmacSha256(keyMaterial, salt, keyLen) {
	return hkdf(sha256, keyMaterial, salt, void 0, keyLen);
}
/**
* Derive a key using HKDF with HMAC-SHA-512
*/
function hkdfHmacSha512(keyMaterial, salt, keyLen) {
	return hkdf(sha512, keyMaterial, salt, void 0, keyLen);
}
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*/
/**
* AEAD-specific error for authentication failures
*/
var AeadError = class extends Error {
	constructor(message = "AEAD authentication failed") {
		super(message);
		this.name = "AeadError";
	}
};
/**
* Generic crypto error type
*/
var CryptoError$1 = class CryptoError extends Error {
	cause;
	constructor(message, cause) {
		super(message);
		this.name = "CryptoError";
		this.cause = cause;
	}
	/**
	* Create a CryptoError for AEAD authentication failures.
	*
	* @param error - Optional underlying AeadError
	* @returns A CryptoError wrapping the AEAD error
	*/
	static aead(error) {
		return new CryptoError("AEAD error", error ?? new AeadError());
	}
	/**
	* Create a CryptoError for invalid parameter values.
	*
	* **TS-specific.** Rust's `bc_crypto::Error` enum has no
	* `InvalidParameter` variant; size validation in Rust is enforced at
	* compile time via fixed-size array references (e.g. `&[u8; 32]`) or
	* via `panic!`/`expect(...)` for runtime checks. The TS port has no
	* fixed-size array types, so it surfaces those same conditions through
	* a thrown `CryptoError.invalidParameter(...)`. Catching this is
	* equivalent to defensive guards around an `expect`-style panic on the
	* Rust side.
	*
	* @param message - Description of the invalid parameter
	* @returns A CryptoError describing the invalid parameter
	*/
	static invalidParameter(message) {
		return new CryptoError(`Invalid parameter: ${message}`);
	}
};
/**
* Encrypt data using ChaCha20-Poly1305 AEAD cipher with additional authenticated data.
*
* **Security Warning**: The nonce MUST be unique for every encryption operation
* with the same key. Reusing a nonce completely breaks the security of the
* encryption scheme and can reveal plaintext.
*
* @param plaintext - The data to encrypt
* @param key - 32-byte encryption key
* @param nonce - 12-byte nonce (MUST be unique per encryption with the same key)
* @param aad - Additional authenticated data (not encrypted, but integrity-protected)
* @returns Tuple of [ciphertext, authTag] where authTag is 16 bytes
* @throws {CryptoError} If key is not 32 bytes or nonce is not 12 bytes
*/
function aeadChaCha20Poly1305EncryptWithAad(plaintext, key, nonce, aad) {
	if (key.length !== 32) throw CryptoError$1.invalidParameter(`Key must be 32 bytes`);
	if (nonce.length !== 12) throw CryptoError$1.invalidParameter(`Nonce must be 12 bytes`);
	const sealed = chacha20poly1305(key, nonce, aad).encrypt(plaintext);
	return [sealed.slice(0, sealed.length - 16), sealed.slice(sealed.length - 16)];
}
/**
* Decrypt data using ChaCha20-Poly1305 AEAD cipher with additional authenticated data.
*
* @param ciphertext - The encrypted data
* @param key - 32-byte encryption key (must match key used for encryption)
* @param nonce - 12-byte nonce (must match nonce used for encryption)
* @param aad - Additional authenticated data (must exactly match AAD used for encryption)
* @param authTag - 16-byte authentication tag from encryption
* @returns Decrypted plaintext
* @throws {CryptoError} If key/nonce/authTag sizes are invalid
* @throws {CryptoError} If authentication fails (tampered data, wrong key/nonce, or AAD mismatch)
*/
function aeadChaCha20Poly1305DecryptWithAad(ciphertext, key, nonce, aad, authTag) {
	if (key.length !== 32) throw CryptoError$1.invalidParameter(`Key must be 32 bytes`);
	if (nonce.length !== 12) throw CryptoError$1.invalidParameter(`Nonce must be 12 bytes`);
	if (authTag.length !== 16) throw CryptoError$1.invalidParameter(`Auth tag must be 16 bytes`);
	const sealed = new Uint8Array(ciphertext.length + authTag.length);
	sealed.set(ciphertext);
	sealed.set(authTag, ciphertext.length);
	try {
		return chacha20poly1305(key, nonce, aad).decrypt(sealed);
	} catch (error) {
		const aeadError = new AeadError(`Decryption failed: ${error instanceof Error ? error.message : "authentication error"}`);
		throw CryptoError$1.aead(aeadError);
	}
}
/**
* Derive an X25519 agreement private key from key material.
* Uses HKDF with "agreement" as domain separation salt.
*/
function deriveAgreementPrivateKey(keyMaterial) {
	return hkdfHmacSha256(keyMaterial, new TextEncoder().encode("agreement"), 32);
}
/**
* Derive a signing private key from key material.
* Uses HKDF with "signing" as domain separation salt.
*/
function deriveSigningPrivateKey(keyMaterial) {
	return hkdfHmacSha256(keyMaterial, new TextEncoder().encode("signing"), 32);
}
/**
* Derive an X25519 public key from a private key.
*/
function x25519PublicKeyFromPrivateKey(privateKey) {
	if (privateKey.length !== 32) throw new Error(`Private key must be 32 bytes`);
	return x25519.getPublicKey(privateKey);
}
const SYMMETRIC_KEY_SIZE$1 = 32;
/**
* Compute a shared symmetric key using X25519 key agreement (ECDH).
*
* This function performs X25519 Diffie-Hellman key agreement and then
* derives a symmetric key using HKDF-SHA256 with "agreement" as the salt.
* This matches the Rust bc-crypto implementation for cross-platform compatibility.
*
* **Low-order public key handling.** The underlying `@noble/curves` X25519
* implementation rejects low-order public keys (where the u-coordinate is
* `0`) by throwing `'invalid private or public key received'`. Rust's
* `x25519-dalek` (v2.0-rc.2) instead silently produces the all-zero shared
* secret. This means an adversarial low-order public key fed in via TS
* surfaces as an exception, while in Rust it would yield an HKDF-derived
* key from a zero shared secret. For honest inputs both implementations
* produce byte-identical results; the TS port's stricter behaviour is a
* security improvement, not a parity bug.
*
* @param x25519Private - 32-byte X25519 private key
* @param x25519Public - 32-byte X25519 public key from the other party
* @returns 32-byte derived symmetric key
* @throws {Error} If private key is not 32 bytes or public key is not 32 bytes
* @throws {Error} If the public key is low-order (`@noble/curves`-specific guard)
*/
function x25519SharedKey(x25519Private, x25519Public) {
	if (x25519Private.length !== 32) throw new Error(`Private key must be 32 bytes`);
	if (x25519Public.length !== 32) throw new Error(`Public key must be 32 bytes`);
	return hkdfHmacSha256(x25519.getSharedSecret(x25519Private, x25519Public), new TextEncoder().encode("agreement"), SYMMETRIC_KEY_SIZE$1);
}
/**
* Derive a compressed ECDSA public key from a private key.
*/
function ecdsaPublicKeyFromPrivateKey(privateKey) {
	if (privateKey.length !== 32) throw new Error(`Private key must be 32 bytes`);
	return secp256k1.getPublicKey(privateKey, true);
}
/**
* Decompress a compressed public key to uncompressed format.
*/
function ecdsaDecompressPublicKey(compressed) {
	if (compressed.length !== 33) throw new Error(`Compressed public key must be 33 bytes`);
	return secp256k1.Point.fromBytes(compressed).toBytes(false);
}
/**
* Compress an uncompressed public key.
*/
function ecdsaCompressPublicKey(uncompressed) {
	if (uncompressed.length !== 65) throw new Error(`Uncompressed public key must be 65 bytes`);
	return secp256k1.Point.fromBytes(uncompressed).toBytes(true);
}
/**
* Derive an ECDSA private key from key material using HKDF.
*
* Note: This directly returns the HKDF output without validation,
* matching the Rust reference implementation behavior.
*/
function ecdsaDerivePrivateKey(keyMaterial) {
	return hkdfHmacSha256(keyMaterial, new TextEncoder().encode("signing"), 32);
}
/**
* Extract the x-only (Schnorr) public key from a private key.
* This is used for BIP-340 Schnorr signatures.
*/
function schnorrPublicKeyFromPrivateKey(privateKey) {
	if (privateKey.length !== 32) throw new Error(`Private key must be 32 bytes`);
	return secp256k1.getPublicKey(privateKey, false).slice(1, 33);
}
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*/
/**
* Sign a message using ECDSA with secp256k1.
*
* The message is hashed with double SHA-256 before signing (Bitcoin standard).
*
* **Security Note**: The private key must be kept secret. ECDSA requires
* cryptographically secure random nonces internally; this is handled by
* the underlying library using RFC 6979 deterministic nonces.
*
* @param privateKey - 32-byte secp256k1 private key
* @param message - Message to sign (any length, will be double-SHA256 hashed)
* @returns 64-byte compact signature (r || s format)
* @throws {Error} If private key is not 32 bytes
*/
function ecdsaSign(privateKey, message) {
	if (privateKey.length !== 32) throw new Error(`Private key must be 32 bytes`);
	const messageHash = doubleSha256(message);
	return secp256k1.sign(messageHash, privateKey, { prehash: false });
}
/**
* Verify an ECDSA signature with secp256k1.
*
* The message is hashed with double SHA-256 before verification (Bitcoin standard).
*
* @param publicKey - 33-byte compressed secp256k1 public key
* @param signature - 64-byte compact signature (r || s format)
* @param message - Original message that was signed
* @returns `true` if signature is valid, `false` if signature verification fails
* @throws {Error} If public key is not 33 bytes or signature is not 64 bytes
*/
function ecdsaVerify(publicKey, signature, message) {
	if (publicKey.length !== 33) throw new Error(`Public key must be 33 bytes`);
	if (signature.length !== 64) throw new Error(`Signature must be 64 bytes`);
	try {
		const messageHash = doubleSha256(message);
		return secp256k1.verify(signature, messageHash, publicKey, { prehash: false });
	} catch {
		return false;
	}
}
/**
* Returns the Web Crypto API for the current environment. Available natively
* in browsers and in Node.js >= 15 via `globalThis.crypto`.
*/
function getCrypto$2() {
	if (typeof globalThis !== "undefined" && globalThis.crypto != null) return globalThis.crypto;
	throw new Error("No crypto API available in this environment");
}
/**
* Generate a Uint8Array of cryptographically strong random bytes of the given size.
*/
function randomData$2(size) {
	const data = new Uint8Array(size);
	fillRandomData$2(data);
	return data;
}
/**
* Fill the given Uint8Array with cryptographically strong random bytes.
*/
function fillRandomData$2(data) {
	getCrypto$2().getRandomValues(data);
}
/**
* Returns the next cryptographically strong random 64-bit unsigned integer.
*
* This mirrors Rust's module-private `secure_random::next_u64()` and is not
* re-exported from the package surface (matches Rust `lib.rs` behavior).
*/
function nextU64$2() {
	const data = /* @__PURE__ */ new Uint8Array(8);
	fillRandomData$2(data);
	return new DataView(data.buffer).getBigUint64(0, true);
}
/**
* A random number generator that can be used as a source of
* cryptographically-strong randomness.
*
* Uses the Web Crypto API (crypto.getRandomValues) which is available
* in both browsers and Node.js >= 15.
*/
var SecureRandomNumberGenerator$2 = class {
	/**
	* Returns the next random 32-bit unsigned integer.
	*
	* Mirrors Rust's `next_u32` impl which returns `next_u64() as u32` —
	* the low 32 bits of a 64-bit draw.
	*/
	nextU32() {
		return Number(this.nextU64() & 4294967295n) >>> 0;
	}
	/**
	* Returns the next random 64-bit unsigned integer as a bigint.
	*/
	nextU64() {
		return nextU64$2();
	}
	/**
	* Fills the given Uint8Array with random bytes.
	*/
	fillBytes(dest) {
		fillRandomData$2(dest);
	}
	/**
	* Returns a Uint8Array of random bytes of the given size.
	*/
	randomData(size) {
		return randomData$2(size);
	}
	/**
	* Fills the given Uint8Array with random bytes.
	*/
	fillRandomData(data) {
		fillRandomData$2(data);
	}
};
/**
* Sign a message using Schnorr signature (BIP-340).
* Uses secure random auxiliary randomness.
*
* @param ecdsaPrivateKey - 32-byte private key
* @param message - Message to sign (not pre-hashed, per BIP-340)
* @returns 64-byte Schnorr signature
*/
function schnorrSign(ecdsaPrivateKey, message) {
	return schnorrSignUsing(ecdsaPrivateKey, message, new SecureRandomNumberGenerator$2());
}
/**
* Sign a message using Schnorr signature with a custom RNG.
*
* @param ecdsaPrivateKey - 32-byte private key
* @param message - Message to sign
* @param rng - Random number generator for auxiliary randomness
* @returns 64-byte Schnorr signature
*/
function schnorrSignUsing(ecdsaPrivateKey, message, rng) {
	return schnorrSignWithAuxRand(ecdsaPrivateKey, message, rng.randomData(32));
}
/**
* Sign a message using Schnorr signature with specific auxiliary randomness.
* This is useful for deterministic signing in tests.
*
* @param ecdsaPrivateKey - 32-byte private key
* @param message - Message to sign
* @param auxRand - 32-byte auxiliary randomness (per BIP-340)
* @returns 64-byte Schnorr signature
*/
function schnorrSignWithAuxRand(ecdsaPrivateKey, message, auxRand) {
	if (ecdsaPrivateKey.length !== 32) throw new Error(`Private key must be 32 bytes`);
	if (auxRand.length !== 32) throw new Error("Auxiliary randomness must be 32 bytes");
	return schnorr.sign(message, ecdsaPrivateKey, auxRand);
}
/**
* Verify a Schnorr signature (BIP-340).
*
* @param schnorrPublicKey - 32-byte x-only public key
* @param signature - 64-byte Schnorr signature
* @param message - Original message
* @returns true if signature is valid
*/
function schnorrVerify(schnorrPublicKey, signature, message) {
	if (schnorrPublicKey.length !== 32) throw new Error(`Public key must be 32 bytes`);
	if (signature.length !== 64) throw new Error(`Signature must be 64 bytes`);
	try {
		return schnorr.verify(signature, message, schnorrPublicKey);
	} catch {
		return false;
	}
}
/**
* Derive an Ed25519 public key from a private key.
*/
function ed25519PublicKeyFromPrivateKey(privateKey) {
	if (privateKey.length !== 32) throw new Error(`Private key must be 32 bytes`);
	return ed25519.getPublicKey(privateKey);
}
/**
* Sign a message using Ed25519.
*
* **Security Note**: The private key must be kept secret. The same private key
* can safely sign multiple messages.
*
* @param privateKey - 32-byte Ed25519 private key
* @param message - Message to sign (any length)
* @returns 64-byte Ed25519 signature
* @throws {Error} If private key is not 32 bytes
*/
function ed25519Sign(privateKey, message) {
	if (privateKey.length !== 32) throw new Error(`Private key must be 32 bytes`);
	return ed25519.sign(message, privateKey);
}
/**
* Verify an Ed25519 signature.
*
* @param publicKey - 32-byte Ed25519 public key
* @param message - Original message that was signed
* @param signature - 64-byte Ed25519 signature
* @returns `true` if signature is valid, `false` if signature verification fails
* @throws {Error} If public key is not 32 bytes or signature is not 64 bytes
*/
function ed25519Verify(publicKey, message, signature) {
	if (publicKey.length !== 32) throw new Error(`Public key must be 32 bytes`);
	if (signature.length !== 64) throw new Error(`Signature must be 64 bytes`);
	try {
		return ed25519.verify(signature, message, publicKey);
	} catch {
		return false;
	}
}
/**
* Derive a key using Scrypt with custom parameters.
*
* @param password - Password or passphrase
* @param salt - Salt value
* @param outputLen - Desired output length
* @param logN - Log2 of the CPU/memory cost parameter N (must be <64)
* @param r - Block size parameter (must be >0)
* @param p - Parallelization parameter (must be >0)
* @returns Derived key
*/
function scryptOpt(password, salt, outputLen, logN, r, p) {
	if (logN >= 64) throw new Error("logN must be <64");
	if (r === 0) throw new Error("r must be >0");
	if (p === 0) throw new Error("p must be >0");
	const N = 1 << logN;
	return scrypt(password, salt, {
		N,
		r,
		p,
		dkLen: outputLen
	});
}
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*/
/**
* Derive a key using Argon2id with default parameters.
*
* Mirrors Rust `bc_crypto::argon2id` which calls `Argon2::default()`. The
* upstream `argon2` crate's defaults are `t = 2` iterations, `m = 19 * 1024
* = 19456` KiB of memory, `p = 1` lane (per `argon2-0.5.x/src/params.rs`).
*
* @param password - Password or passphrase
* @param salt - Salt value (must be at least 8 bytes)
* @param outputLen - Desired output length
* @returns Derived key
*/
function argon2id$1(password, salt, outputLen) {
	return argon2idHashOpt(password, salt, outputLen, 2, 19456, 1);
}
/**
* Derive a key using Argon2id with custom parameters.
*
* @param password - Password or passphrase
* @param salt - Salt value (must be at least 8 bytes)
* @param outputLen - Desired output length
* @param iterations - Number of iterations (t)
* @param memory - Memory in KiB (m)
* @param parallelism - Degree of parallelism (p)
* @returns Derived key
*/
function argon2idHashOpt(password, salt, outputLen, iterations, memory, parallelism) {
	return argon2id(password, salt, {
		t: iterations,
		m: memory,
		p: parallelism,
		dkLen: outputLen
	});
}
//#endregion
//#region ../bc-ur-ts/tests/baseline/uniform-resources-baseline.mjs
const MajorType$1 = {
	Unsigned: 0,
	Negative: 1,
	ByteString: 2,
	Text: 3,
	Array: 4,
	Map: 5,
	Tagged: 6,
	Simple: 7
};
const isCborNumber$1 = (value) => {
	return typeof value === "number" || typeof value === "bigint";
};
const isCbor$1 = (value) => {
	return value !== null && typeof value === "object" && "isCbor" in value && value.isCbor === true;
};
/**
* Compare two tag values for equality, normalizing `number` vs `bigint`.
* A raw `===` would treat `100n` and `100` as unequal, so a large tag that
* decoded to a `bigint` wouldn't match the same value written as a `number`.
*
* @internal Exported for cross-module use; not part of the public surface -
* use `Tag.equals` instead.
*/
const tagValuesEqual$1 = (a, b) => {
	if (typeof a === "bigint" || typeof b === "bigint") return BigInt(a) === BigInt(b);
	return a === b;
};
/**
* Value-type companion for the `Tag` interface: an interface plus a merged
* `const` with a handful of members. It stays small and must not import the
* encode/format graph.
*/
const Tag = {
	/**
	* Create a Tag from its numeric value, optionally with a name.
	*
	* ```typescript
	* Tag.from(1, "date");
	* Tag.from(12345);
	* ```
	*/
	from(value, name) {
		if (name !== void 0) return {
			value,
			name
		};
		return { value };
	},
	/**
	* Compare two tags for equality: compares by `value` only (normalizing
	* `number` vs `bigint`) and ignores the optional `name`.
	*/
	equals(a, b) {
		return tagValuesEqual$1(a.value, b.value);
	}
};
/**
* Get the string representation of a tag.
* Internal function used for error messages.
*
* @param tag - The tag to represent
* @returns String representation (name if available, otherwise value)
*
* @internal
*/
const tagToString$1 = (tag) => tag.name ?? tag.value.toString();
const captureStackTrace = Error.captureStackTrace;
/**
* The single error type thrown by dCBOR encoding, decoding, and extraction.
*
* @example
* ```typescript
* try {
*   decodeCbor(bytes);
* } catch (e) {
*   if (CborError.isCborError(e) && e.code === "WrongTag") {
*     console.log(e.details.expectedTag, e.details.actualTag);
*   }
* }
* ```
*/
var CborError$1 = class CborError extends Error {
	/** Machine-readable discriminant; switch on this to handle errors. */
	code;
	/** Structured, code-specific data (see {@link CborErrorDetails}). */
	details;
	constructor(code, message, details = {}) {
		super(message);
		this.name = "CborError";
		this.code = code;
		this.details = details;
		Object.setPrototypeOf(this, new.target.prototype);
		if (typeof captureStackTrace === "function") captureStackTrace(this, CborError);
	}
	/** Type guard: is `value` a {@link CborError}? Narrows to the
	* code-discriminated {@link CborErrorTyped} union. */
	static isCborError(value) {
		return value instanceof CborError;
	}
	/** The CBOR data ended before a complete item could be decoded. */
	static underrun() {
		return new CborError("Underrun", "early end of CBOR data");
	}
	/** An unsupported/invalid value was found in a CBOR header byte. */
	static unsupportedHeaderValue(headerValue) {
		return new CborError("UnsupportedHeaderValue", "unsupported value in CBOR header", { headerValue });
	}
	/** A numeric value was not in its shortest/canonical dCBOR form. */
	static nonCanonicalNumeric() {
		return new CborError("NonCanonicalNumeric", "a CBOR numeric value was encoded in non-canonical form");
	}
	/** A major-type-7 simple value other than false/true/null/float. */
	static invalidSimpleValue() {
		return new CborError("InvalidSimpleValue", "an invalid CBOR simple value was encountered");
	}
	/** A text string was not valid UTF-8 (with the underlying reason). */
	static invalidString(cause) {
		return new CborError("InvalidString", `an invalidly-encoded UTF-8 string was encountered in the CBOR (${cause})`, { cause });
	}
	/** A text string was not in Unicode NFC. */
	static nonCanonicalString() {
		return new CborError("NonCanonicalString", "a CBOR string was not encoded in Unicode Canonical Normalization Form C");
	}
	/** The decoded item left `count` trailing bytes unconsumed. */
	static unusedData(count) {
		return new CborError("UnusedData", `the decoded CBOR had ${count} extra bytes at the end`, { count });
	}
	/** Map keys were not in canonical ascending byte order. */
	static misorderedMapKey() {
		return new CborError("MisorderedMapKey", "the decoded CBOR map has keys that are not in canonical order");
	}
	/** A map contained a duplicate key. */
	static duplicateMapKey() {
		return new CborError("DuplicateMapKey", "the decoded CBOR map has a duplicate key");
	}
	/** A requested map key was not present. */
	static missingMapKey() {
		return new CborError("MissingMapKey", "missing CBOR map key");
	}
	/** A numeric value could not be represented in the target type. */
	static outOfRange() {
		return new CborError("OutOfRange", "the CBOR numeric value could not be represented in the specified numeric type");
	}
	/** The CBOR value was not the type expected by a conversion. */
	static wrongType() {
		return new CborError("WrongType", "the decoded CBOR value was not the expected type");
	}
	/** A tagged value had a tag other than the one expected. */
	static wrongTag(expected, actual) {
		return new CborError("WrongTag", `expected CBOR tag ${tagToString$1(expected)}, but got ${tagToString$1(actual)}`, {
			expectedTag: expected,
			actualTag: actual
		});
	}
	/** Invalid UTF-8 in a text string (with the underlying reason). */
	static invalidUtf8(cause) {
		return new CborError("InvalidUtf8", `invalid UTF‑8 string: ${cause}`, { cause });
	}
	/** Invalid ISO 8601 / RFC 3339 date string (with the underlying reason). */
	static invalidDate(cause) {
		return new CborError("InvalidDate", `invalid ISO 8601 date string: ${cause}`, { cause });
	}
	/** An arbitrary error carrying a custom message. */
	static custom(message) {
		return new CborError("Custom", message);
	}
};
/**
* Byte-array utilities shared across the library.
*
* @module stdlib
*/
/**
* Check if two byte arrays are equal.
*/
const areBytesEqual = (a, b) => {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
};
/**
* Lexicographically compare two byte arrays.
* Returns: -1 if a < b, 0 if a == b, 1 if a > b
*/
const lexicographicallyCompareBytes = (a, b) => {
	const minLen = Math.min(a.length, b.length);
	for (let i = 0; i < minLen; i++) {
		const aVal = a[i];
		const bVal = b[i];
		if (aVal === void 0 || bVal === void 0) throw CborError$1.custom("Unexpected undefined byte in array");
		if (aVal < bVal) return -1;
		if (aVal > bVal) return 1;
	}
	if (a.length < b.length) return -1;
	if (a.length > b.length) return 1;
	return 0;
};
/**
* A map keyed by encoded CBOR key bytes, kept in canonical (lexicographic)
* byte order.
*
* dCBOR needs exactly one specialised container: keys are the encoded bytes of
* a CBOR value, and the map must iterate in ascending lexicographic byte order
* (that ordering is the deterministic wire contract). This is a thin,
* dependency-free structure over a sorted array with binary-search insertion -
* it gives the exact ordering dCBOR requires, and lets the decode hot path
* append in O(1) since canonical input already arrives sorted.
*
* @module sorted-byte-map
*/
var SortedByteMap = class {
	items = [];
	/** Number of entries. */
	get size() {
		return this.items.length;
	}
	/**
	* Binary search for `key`. Returns the index of an exact match, or the
	* negative value `-(insertionPoint) - 1` when absent, so a single search both
	* tests membership and locates where an insert would go (Java
	* `Arrays.binarySearch` convention).
	*/
	indexOf(key) {
		let lo = 0;
		let hi = this.items.length - 1;
		while (lo <= hi) {
			const mid = lo + hi >>> 1;
			const cmp = lexicographicallyCompareBytes(this.items[mid].key, key);
			if (cmp < 0) lo = mid + 1;
			else if (cmp > 0) hi = mid - 1;
			else return mid;
		}
		return -(lo + 1);
	}
	/** Insert or replace the entry for `key`. */
	set(key, value) {
		const i = this.indexOf(key);
		if (i >= 0) this.items[i] = {
			key,
			value
		};
		else this.items.splice(-i - 1, 0, {
			key,
			value
		});
	}
	/**
	* Append an entry whose key is strictly greater than every existing key.
	* Used by canonical decode, where keys arrive already sorted; the caller must
	* guarantee the ordering (this skips the search + shift that {@link set} does).
	*/
	appendGreatest(key, value) {
		this.items.push({
			key,
			value
		});
	}
	/** The value for `key`, or `undefined` if absent. */
	get(key) {
		const i = this.indexOf(key);
		return i >= 0 ? this.items[i].value : void 0;
	}
	/** Whether `key` is present. */
	has(key) {
		return this.indexOf(key) >= 0;
	}
	/** Remove `key`; returns whether it was present. */
	delete(key) {
		const i = this.indexOf(key);
		if (i < 0) return false;
		this.items.splice(i, 1);
		return true;
	}
	/** The greatest key currently stored (ascending order), or `undefined`. */
	maxKey() {
		const n = this.items.length;
		return n > 0 ? this.items[n - 1].key : void 0;
	}
	/** Map over each value (with its key) in ascending key order. */
	map(fn) {
		return this.items.map((e) => fn(e.value, e.key));
	}
};
/**
* Numeric boundary contract and helpers.
*
* ## The `number` / `bigint` contract
*
* dCBOR integers span `[-(2^64), 2^64)`, which exceeds JavaScript's safe
* integer range (`±(2^53 − 1)`). The single, repo-wide rule is:
*
* - An integer that fits in the IEEE-754 **safe** range is represented as a
*   `number`; anything larger (in magnitude) is a `bigint`.
* - Decoding returns the **narrowest exact** representation via
*   {@link narrowInteger}, so small values are ergonomic `number`s and large
*   ones remain lossless `bigint`s.
* - Encoding accepts either at the public edge and normalises once.
*
* Every module funnels its boundary logic through this file - nothing else
* should hard-code `Number.MAX_SAFE_INTEGER`, `2^64`, etc.
*
* @module numeric
*/
/** `BigInt(Number.MAX_SAFE_INTEGER)` - largest integer exact as a `number`. */
const SAFE_MAX_BIG = BigInt(Number.MAX_SAFE_INTEGER);
/** `BigInt(Number.MIN_SAFE_INTEGER)`. */
const SAFE_MIN_BIG = BigInt(Number.MIN_SAFE_INTEGER);
/** Smallest dCBOR-encodable integer: −(2^64). */
const CBOR_INT_MIN = -(1n << 64n);
/**
* Return the narrowest exact representation of an integer: a `number` when it
* fits the safe-integer range, otherwise the `bigint` unchanged. This is the
* canonical way to hand an integer back to callers.
*/
const narrowInteger = (value) => value >= SAFE_MIN_BIG && value <= SAFE_MAX_BIG ? Number(value) : value;
/**
* A growable output buffer for encoding.
*
* The encoder writes a whole CBOR tree into a single `BufWriter` rather than
* allocating a fresh `Uint8Array` per node and concatenating them (which
* re-copies every subtree at every level): one buffer, geometric growth, one
* final right-sized copy.
*
* @module buf-writer
*/
var BufWriter = class {
	buf;
	view;
	pos = 0;
	constructor(initialCapacity = 64) {
		this.buf = new Uint8Array(initialCapacity);
		this.view = new DataView(this.buf.buffer);
	}
	/** Number of bytes written so far. */
	get length() {
		return this.pos;
	}
	/** Grow the backing store so at least `extra` more bytes fit. */
	ensure(extra) {
		const needed = this.pos + extra;
		if (needed <= this.buf.length) return;
		let capacity = this.buf.length * 2;
		while (capacity < needed) capacity *= 2;
		const next = new Uint8Array(capacity);
		next.set(this.buf.subarray(0, this.pos));
		this.buf = next;
		this.view = new DataView(next.buffer);
	}
	writeByte(byte) {
		this.ensure(1);
		this.buf[this.pos] = byte;
		this.pos += 1;
	}
	writeUint16(value) {
		this.ensure(2);
		this.view.setUint16(this.pos, value, false);
		this.pos += 2;
	}
	writeUint32(value) {
		this.ensure(4);
		this.view.setUint32(this.pos, value, false);
		this.pos += 4;
	}
	writeBigUint64(value) {
		this.ensure(8);
		this.view.setBigUint64(this.pos, value, false);
		this.pos += 8;
	}
	writeBytes(bytes) {
		this.ensure(bytes.length);
		this.buf.set(bytes, this.pos);
		this.pos += bytes.length;
	}
	/** Return the written region as a right-sized copy. */
	toBytes() {
		return this.buf.slice(0, this.pos);
	}
};
const typeBits = (t) => {
	return t << 5;
};
/**
* Write a CBOR head (major type + argument) straight into `writer`, avoiding
* the intermediate `Uint8Array` that {@link encodeVarInt} allocates. This is
* the encoder hot path (every node emits a head). It MUST stay byte-identical
* to {@link encodeVarInt}; the golden vectors cover both.
*/
const writeVarInt = (writer, value, majorType) => {
	if (value < 0) throw CborError$1.outOfRange();
	if (typeof value === "number" && hasFractionalPart(value)) throw CborError$1.outOfRange();
	const type = typeBits(majorType);
	if (isCborNumber$1(value) && value <= Number.MAX_SAFE_INTEGER) {
		const n = Number(value);
		if (n <= 23) writer.writeByte(n | type);
		else if (n <= 255) {
			writer.writeByte(24 | type);
			writer.writeByte(n);
		} else if (n <= 65535) {
			writer.writeByte(25 | type);
			writer.writeUint16(n);
		} else if (n <= 4294967295) {
			writer.writeByte(26 | type);
			writer.writeUint32(n);
		} else {
			writer.writeByte(27 | type);
			writer.writeBigUint64(BigInt(n));
		}
	} else {
		const big = BigInt(value);
		if (big > 18446744073709551615n) throw CborError$1.outOfRange();
		writer.writeByte(27 | type);
		writer.writeBigUint64(big);
	}
};
const encodeVarInt = (value, majorType) => {
	if (value < 0) throw CborError$1.outOfRange();
	if (typeof value === "number" && hasFractionalPart(value)) throw CborError$1.outOfRange();
	const type = typeBits(majorType);
	if (isCborNumber$1(value) && value <= Number.MAX_SAFE_INTEGER) {
		value = Number(value);
		if (value <= 23) return new Uint8Array([value | type]);
		else if (value <= 255) return new Uint8Array([24 | type, value]);
		else if (value <= 65535) {
			const buffer = /* @__PURE__ */ new ArrayBuffer(3);
			const view = new DataView(buffer);
			view.setUint8(0, 25 | type);
			view.setUint16(1, value);
			return new Uint8Array(buffer);
		} else if (value <= 4294967295) {
			const buffer = /* @__PURE__ */ new ArrayBuffer(5);
			const view = new DataView(buffer);
			view.setUint8(0, 26 | type);
			view.setUint32(1, value);
			return new Uint8Array(buffer);
		} else {
			const buffer = /* @__PURE__ */ new ArrayBuffer(9);
			const view = new DataView(buffer);
			view.setUint8(0, 27 | type);
			view.setBigUint64(1, BigInt(value));
			return new Uint8Array(buffer);
		}
	} else {
		const big = BigInt(value);
		if (big > 18446744073709551615n) throw CborError$1.outOfRange();
		const buffer = /* @__PURE__ */ new ArrayBuffer(9);
		const view = new DataView(buffer);
		view.setUint8(0, 27 | type);
		view.setBigUint64(1, big);
		return new Uint8Array(buffer);
	}
};
const hasFract = (n) => {
	return n % 1 !== 0;
};
/**
* Shared float→integer exactness gate for every `Exact<Int>.exactFromF*`. A
* float is an exact integer of a width iff it is finite, whole, and inside that
* width's exclusive `(loEx, hiEx)` bounds (use ±Infinity to skip a side). The
* bounds encode the per-width / per-source-precision limits. The three typed
* wrappers below shape the truncated result.
*/
const isExactIntFloat = (source, loEx, hiEx) => Number.isFinite(source) && source > loEx && source < hiEx && !hasFract(source);
/** float → small integer (`number`). */
const intFromFloatNum = (source, loEx, hiEx) => isExactIntFloat(source, loEx, hiEx) ? Math.trunc(source) : void 0;
/** float → 64-bit integer (`number` if safe, else `bigint`). */
const intFromFloatNarrow = (source, loEx, hiEx) => isExactIntFloat(source, loEx, hiEx) ? narrowInteger(BigInt(Math.trunc(source))) : void 0;
/** float → 128-bit integer (`bigint`). */
const intFromFloatBig = (source, loEx, hiEx) => isExactIntFloat(source, loEx, hiEx) ? BigInt(Math.trunc(source)) : void 0;
/**
* Exact conversions for i128 (JavaScript bigint).
*/
var ExactI128 = class {
	static MIN = -(2n ** 127n);
	static MAX = 2n ** 127n - 1n;
	static exactFromF16(source) {
		return intFromFloatBig(source, -Infinity, Infinity);
	}
	static exactFromF32(source) {
		return intFromFloatBig(source, -Infinity, Infinity);
	}
	static exactFromF64(source) {
		return intFromFloatBig(source, -Infinity, Infinity);
	}
	static exactFromU64(source) {
		return BigInt(source);
	}
	static exactFromI64(source) {
		return BigInt(source);
	}
	static exactFromU128(source) {
		if (source > 2n ** 127n - 1n) return void 0;
		return source;
	}
	static exactFromI128(source) {
		return source;
	}
};
/**
* Exact conversions for u16 (0 to 65535).
*/
var ExactU16 = class {
	static MIN = 0;
	static MAX = 65535;
	static exactFromF16(source) {
		return intFromFloatNum(source, -1, Infinity);
	}
	static exactFromF32(source) {
		return intFromFloatNum(source, -1, 65536);
	}
	static exactFromF64(source) {
		return intFromFloatNum(source, -1, 65536);
	}
	static exactFromU64(source) {
		const n = typeof source === "bigint" ? Number(source) : source;
		if (n > 65535) return void 0;
		return n;
	}
	static exactFromI64(source) {
		const n = typeof source === "bigint" ? Number(source) : source;
		if (n < 0 || n > 65535) return void 0;
		return n;
	}
	static exactFromU128(source) {
		if (source > 65535n) return void 0;
		return Number(source);
	}
	static exactFromI128(source) {
		if (source < 0n || source > 65535n) return void 0;
		return Number(source);
	}
};
/**
* Exact conversions for u32 (0 to 4294967295).
*/
var ExactU32 = class {
	static MIN = 0;
	static MAX = 4294967295;
	static exactFromF16(source) {
		return intFromFloatNum(source, -1, Infinity);
	}
	static exactFromF32(source) {
		return intFromFloatNum(source, -1, 4294967296);
	}
	static exactFromF64(source) {
		return intFromFloatNum(source, -1, 4294967296);
	}
	static exactFromU64(source) {
		const n = typeof source === "bigint" ? Number(source) : source;
		if (n > 4294967295) return void 0;
		return n;
	}
	static exactFromI64(source) {
		const n = typeof source === "bigint" ? Number(source) : source;
		if (n < 0 || n > 4294967295) return void 0;
		return n;
	}
	static exactFromU128(source) {
		if (source > 4294967295n) return void 0;
		return Number(source);
	}
	static exactFromI128(source) {
		if (source < 0n || source > 4294967295n) return void 0;
		return Number(source);
	}
};
/**
* Exact conversions for u64 (0 to 18446744073709551615).
*/
var ExactU64 = class {
	static MIN = 0n;
	static MAX = 18446744073709551615n;
	static exactFromF16(source) {
		return intFromFloatNarrow(source, -1, Infinity);
	}
	static exactFromF32(source) {
		return intFromFloatNarrow(source, -1, 0x10000000000000000);
	}
	static exactFromF64(source) {
		return intFromFloatNarrow(source, -1, 0x10000000000000000);
	}
	static exactFromU64(source) {
		return source;
	}
	static exactFromI64(source) {
		if ((typeof source === "bigint" ? source : BigInt(source)) < 0n) return void 0;
		return source;
	}
	static exactFromU128(source) {
		if (source > 18446744073709551615n) return void 0;
		return narrowInteger(source);
	}
	static exactFromI128(source) {
		if (source < 0n || source > 18446744073709551615n) return void 0;
		return narrowInteger(source);
	}
};
/**
* Float encoding and conversion utilities for dCBOR.
*
* # Floating Point Number Support in dCBOR
*
* dCBOR provides canonical encoding for floating point values.
*
* Per the dCBOR specification, the canonical encoding rules ensure
* deterministic representation:
*
* - Numeric reduction: Floating point values with zero fractional part in
*   range [-2^63, 2^64-1] are automatically encoded as integers (e.g., 42.0
*   becomes 42)
* - Values are encoded in the smallest possible representation that preserves
*   their value
* - All NaN values are canonicalized to a single representation: 0xf97e00
* - Positive/negative infinity are canonicalized to half-precision
*   representations
*
* @module float
*/
/**
* Canonical NaN representation in CBOR: 0xf97e00
*/
const CBOR_NAN = new Uint8Array([
	249,
	126,
	0
]);
/**
* Check if a number has a fractional part.
*/
const hasFractionalPart = (n) => n !== Math.floor(n);
/**
* Read a big-endian IEEE-754 double from the first 8 bytes of `data`.
* @internal
*/
const binary64ToNumber = (data) => new DataView(data.buffer, data.byteOffset, data.byteLength).getFloat64(0, false);
/**
* Encode a number as 4 big-endian bytes of an IEEE-754 single (f32).
*/
const numberToBinary32 = (n) => {
	const data = /* @__PURE__ */ new Uint8Array(4);
	new DataView(data.buffer).setFloat32(0, n, false);
	return data;
};
/**
* Read a big-endian IEEE-754 single (f32) from the first 4 bytes of `data`.
*/
const binary32ToNumber = (data) => new DataView(data.buffer, data.byteOffset, data.byteLength).getFloat32(0, false);
const f32ScratchView = /* @__PURE__ */ new DataView(/* @__PURE__ */ new ArrayBuffer(4));
/**
* Compute the 16-bit pattern of the IEEE-754 half-precision value nearest `n`,
* rounding ties to even.
*
* All call sites pass values already exactly representable in binary16 (the
* reduction gates in {@link f16CborData} ensure this), so no rounding occurs on
* a value that is actually stored; the rounding path exists only so the
* reduction round-trip probe (`binary16ToNumber(numberToBinary16(n)) === n`)
* answers correctly for non-representable inputs.
*/
const float16Bits = (n) => {
	f32ScratchView.setFloat32(0, n, false);
	const f = f32ScratchView.getUint32(0, false);
	const sign = f >>> 16 & 32768;
	const exp = f >>> 23 & 255;
	const mant = f & 8388607;
	if (exp === 255) return sign | (mant !== 0 ? 32256 : 31744);
	const e = exp - 127 + 15;
	if (e >= 31) return sign | 31744;
	if (e <= 0) {
		if (e < -10) return sign;
		const significand = mant | 8388608;
		const shift = 14 - e;
		let result = significand >>> shift;
		const remainder = significand & (1 << shift) - 1;
		const halfway = 1 << shift - 1;
		if (remainder > halfway || remainder === halfway && (result & 1) === 1) result += 1;
		return sign | result;
	}
	let fraction = mant >>> 13;
	const remainder = mant & 8191;
	let exponent = e;
	if (remainder > 4096 || remainder === 4096 && (fraction & 1) === 1) {
		fraction += 1;
		if (fraction === 1024) {
			fraction = 0;
			exponent += 1;
			if (exponent >= 31) return sign | 31744;
		}
	}
	return sign | exponent << 10 | fraction;
};
/**
* Encode a number as 2 big-endian bytes of an IEEE-754 half (f16).
*/
const numberToBinary16 = (n) => {
	const bits = float16Bits(n);
	return new Uint8Array([bits >> 8 & 255, bits & 255]);
};
/**
* Read a big-endian IEEE-754 half (f16) from the first 2 bytes of `data`.
*/
const binary16ToNumber = (data) => {
	const bits = data[0] << 8 | data[1];
	const sign = (bits & 32768) !== 0 ? -1 : 1;
	const exponent = bits >> 10 & 31;
	const fraction = bits & 1023;
	if (exponent === 0) return sign * fraction * 2 ** -24;
	if (exponent === 31) return fraction !== 0 ? NaN : sign * Infinity;
	return sign * (1 + fraction / 1024) * 2 ** (exponent - 15);
};
/**
* Encode f64 value to CBOR data bytes.
* Implements numeric reduction and canonical encoding rules.
* @internal
*/
const f64CborData = (value) => {
	const n = value;
	const f32Bytes = numberToBinary32(n);
	const f = binary32ToNumber(f32Bytes);
	if (f === n) return f32CborData(f);
	if (n < 0) {
		const i128 = ExactI128.exactFromF64(n);
		if (i128 !== void 0) {
			const i = ExactU64.exactFromI128(-1n - i128);
			if (i !== void 0) return encodeVarInt(i, MajorType$1.Negative);
		}
	}
	const u = ExactU64.exactFromF64(n);
	if (u !== void 0) return encodeVarInt(u, MajorType$1.Unsigned);
	if (Number.isNaN(value)) return CBOR_NAN;
	const buffer = /* @__PURE__ */ new ArrayBuffer(8);
	new DataView(buffer).setFloat64(0, n, false);
	const bytes = new Uint8Array(buffer);
	return new Uint8Array([251, ...bytes]);
};
/**
* Encode f32 value to CBOR data bytes.
* Implements numeric reduction and canonical encoding rules.
* @internal
*/
const f32CborData = (value) => {
	const n = value;
	const f16Bytes = numberToBinary16(n);
	const f = binary16ToNumber(f16Bytes);
	if (f === n) return f16CborData(f);
	if (n < 0) {
		const u = ExactU64.exactFromF32(Math.fround(-1 - n));
		if (u !== void 0) return encodeVarInt(u, MajorType$1.Negative);
	}
	const u = ExactU32.exactFromF32(n);
	if (u !== void 0) return encodeVarInt(u, MajorType$1.Unsigned);
	if (Number.isNaN(value)) return CBOR_NAN;
	const bytes = numberToBinary32(n);
	return new Uint8Array([250, ...bytes]);
};
/**
* Encode f16 value to CBOR data bytes.
* Implements numeric reduction and canonical encoding rules.
* @internal
*/
const f16CborData = (value) => {
	const n = value;
	if (n < 0) {
		const u = ExactU64.exactFromF64(-1 - n);
		if (u !== void 0) return encodeVarInt(u, MajorType$1.Negative);
	}
	const u = ExactU16.exactFromF64(n);
	if (u !== void 0) return encodeVarInt(u, MajorType$1.Unsigned);
	if (Number.isNaN(value)) return CBOR_NAN;
	const bytes = numberToBinary16(value);
	return new Uint8Array([249, ...bytes]);
};
/**
* Render a float to its diagnostic string.
*
* Finite non-zero values with magnitude in [1e-4, 1e16) print in decimal with
* at least one fractional digit (whole values get a trailing `.0`); everything
* else prints in exponential form. Zero prints as `0.0`/`-0.0`.
*
* JS already produces the same shortest round-tripping digits; we only fix up
* the notation threshold, the `e+` → `e` exponent, and the `.0` suffix.
*
* @param value - The float value
* @returns The diagnostic string
*/
const floatDisplayString = (value) => {
	if (Number.isNaN(value)) return "NaN";
	if (!Number.isFinite(value)) return value > 0 ? "Infinity" : "-Infinity";
	if (value === 0) return Object.is(value, -0) ? "-0.0" : "0.0";
	const abs = Math.abs(value);
	if (abs >= 1e-4 && abs < 0x2386f26fc10000) {
		let str = String(value);
		if (!str.includes(".")) str = `${str}.0`;
		return str;
	}
	return value.toExponential().replace("e+", "e");
};
/**
* A forward-only cursor over the input bytes.
*
* Decoding advances a single `pos` through one shared `DataView` rather than
* slicing a fresh sub-view per nested item and threading a consumed-length back
* up the recursion. Every read is bounds-checked against the remaining bytes.
*/
var ByteReader = class {
	view;
	pos = 0;
	constructor(data) {
		this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
	}
	get byteLength() {
		return this.view.byteLength;
	}
	get remaining() {
		return this.view.byteLength - this.pos;
	}
	/** Read the byte at `offset` relative to the current position (no advance). */
	peek(offset) {
		return this.view.getUint8(this.pos + offset);
	}
	/** Advance the cursor by `count` bytes. */
	advance(count) {
		this.pos += count;
	}
	/** A zero-copy view of `len` bytes at the given absolute offset. */
	bytesAt(offset, len) {
		return new Uint8Array(this.view.buffer, this.view.byteOffset + offset, len);
	}
};
/**
* Decode a single dCBOR item from `data`, enforcing every deterministic
* encoding rule (canonical numeric forms, NFC text, map-key order, no
* trailing bytes). Throws {@link CborError} on any violation.
*
* @example
* ```typescript
* const value = decodeCbor(hexToBytes("a1616101")); // {"a": 1}
* expectMap(value).size; // 1
* ```
*
* @throws {CborError} `Underrun` | `UnsupportedHeaderValue` |
*   `NonCanonicalNumeric` | `InvalidSimpleValue` | `InvalidUtf8` |
*   `NonCanonicalString` | `UnusedData` | `MisorderedMapKey` |
*   `DuplicateMapKey` - see {@link CborErrorDetailsByCode}.
* @public
*
* @remarks Decoded byte strings are zero-copy views aliasing the input
* buffer - mutating the input after decoding (or mutating the returned
* bytes) changes the other side. Call `.slice()` first if you need an
* independent copy. This is deliberate: the zero-copy decode performance
* profile is part of the library's contract.
*/
function decodeCbor$1(data) {
	const reader = new ByteReader(data);
	const cbor = readCbor(reader);
	const remaining = reader.byteLength - reader.pos;
	if (remaining !== 0) throw CborError$1.unusedData(remaining);
	return cbor;
}
function parseHeader(header) {
	return {
		majorType: header >> 5,
		headerValue: header & 31
	};
}
/**
* Read a CBOR head (major type + argument) at the cursor, advancing past it.
* `varIntLen` is the head length (1/2/3/5/9); the argument value is validated
* for canonical minimal-length encoding.
*/
function readHeaderVarint(reader) {
	if (reader.remaining < 1) throw CborError$1.underrun();
	const header = reader.peek(0);
	const { majorType, headerValue } = parseHeader(header);
	const dataRemaining = reader.remaining - 1;
	let value;
	let varIntLen;
	if (headerValue <= 23) {
		value = headerValue;
		varIntLen = 1;
	} else if (headerValue === 24) {
		if (dataRemaining < 1) throw CborError$1.underrun();
		value = reader.peek(1);
		if (value < 24) throw CborError$1.nonCanonicalNumeric();
		varIntLen = 2;
	} else if (headerValue === 25) {
		if (dataRemaining < 2) throw CborError$1.underrun();
		value = (reader.peek(1) << 8 | reader.peek(2)) >>> 0;
		if (value <= 255 && header !== 249) throw CborError$1.nonCanonicalNumeric();
		varIntLen = 3;
	} else if (headerValue === 26) {
		if (dataRemaining < 4) throw CborError$1.underrun();
		value = (reader.peek(1) << 24 | reader.peek(2) << 16 | reader.peek(3) << 8 | reader.peek(4)) >>> 0;
		if (value <= 65535 && header !== 250) throw CborError$1.nonCanonicalNumeric();
		varIntLen = 5;
	} else if (headerValue === 27) {
		if (dataRemaining < 8) throw CborError$1.underrun();
		const a = BigInt(reader.peek(1)) << 56n;
		const b = BigInt(reader.peek(2)) << 48n;
		const c = BigInt(reader.peek(3)) << 40n;
		const d = BigInt(reader.peek(4)) << 32n;
		const e = BigInt(reader.peek(5)) << 24n;
		const f = BigInt(reader.peek(6)) << 16n;
		const g = BigInt(reader.peek(7)) << 8n;
		const h = BigInt(reader.peek(8));
		value = narrowInteger(a | b | c | d | e | f | g | h);
		if (value <= 4294967295 && header !== 251) throw CborError$1.nonCanonicalNumeric();
		varIntLen = 9;
	} else throw CborError$1.unsupportedHeaderValue(headerValue);
	reader.advance(varIntLen);
	return {
		majorType,
		value,
		varIntLen
	};
}
function readCbor(reader) {
	if (reader.remaining < 1) throw CborError$1.underrun();
	const headStart = reader.pos;
	const { majorType, value, varIntLen } = readHeaderVarint(reader);
	switch (majorType) {
		case MajorType$1.Unsigned: {
			const cbor = attachMethods$1({
				isCbor: true,
				type: MajorType$1.Unsigned,
				value
			});
			checkCanonicalEncoding(cbor, reader.bytesAt(headStart, varIntLen));
			return cbor;
		}
		case MajorType$1.Negative: {
			const cbor = attachMethods$1({
				isCbor: true,
				type: MajorType$1.Negative,
				value
			});
			checkCanonicalEncoding(cbor, reader.bytesAt(headStart, varIntLen));
			return cbor;
		}
		case MajorType$1.ByteString: {
			if (typeof value === "bigint") throw CborError$1.underrun();
			if (reader.remaining < value) throw CborError$1.underrun();
			const bytes = reader.bytesAt(reader.pos, value);
			reader.advance(value);
			return attachMethods$1({
				isCbor: true,
				type: MajorType$1.ByteString,
				value: bytes
			});
		}
		case MajorType$1.Text: {
			if (typeof value === "bigint") throw CborError$1.underrun();
			if (reader.remaining < value) throw CborError$1.underrun();
			const textBytes = reader.bytesAt(reader.pos, value);
			reader.advance(value);
			let text;
			try {
				text = new TextDecoder("utf-8", { fatal: true }).decode(textBytes);
			} catch (e) {
				throw CborError$1.invalidUtf8(e instanceof Error ? e.message : String(e));
			}
			if (text.normalize("NFC") !== text) throw CborError$1.nonCanonicalString();
			return attachMethods$1({
				isCbor: true,
				type: MajorType$1.Text,
				value: text
			});
		}
		case MajorType$1.Array: {
			const items = [];
			for (let i = 0; i < value; i++) items.push(readCbor(reader));
			return attachMethods$1({
				isCbor: true,
				type: MajorType$1.Array,
				value: items
			});
		}
		case MajorType$1.Map: {
			const map = new CborMap$1();
			for (let i = 0; i < value; i++) {
				const key = readCbor(reader);
				const val = readCbor(reader);
				map.setNext(key, val);
			}
			return attachMethods$1({
				isCbor: true,
				type: MajorType$1.Map,
				value: map
			});
		}
		case MajorType$1.Tagged: {
			const item = readCbor(reader);
			return attachMethods$1({
				isCbor: true,
				type: MajorType$1.Tagged,
				tag: value,
				value: item
			});
		}
		case MajorType$1.Simple: switch (varIntLen) {
			case 3: {
				const f = binary16ToNumber(reader.bytesAt(headStart + 1, 2));
				checkCanonicalEncoding(f, reader.bytesAt(headStart, varIntLen));
				return attachMethods$1({
					isCbor: true,
					type: MajorType$1.Simple,
					value: {
						type: "Float",
						value: f
					}
				});
			}
			case 5: {
				const f = binary32ToNumber(reader.bytesAt(headStart + 1, 4));
				checkCanonicalEncoding(f, reader.bytesAt(headStart, varIntLen));
				return attachMethods$1({
					isCbor: true,
					type: MajorType$1.Simple,
					value: {
						type: "Float",
						value: f
					}
				});
			}
			case 9: {
				const f = binary64ToNumber(reader.bytesAt(headStart + 1, 8));
				checkCanonicalEncoding(f, reader.bytesAt(headStart, varIntLen));
				return attachMethods$1({
					isCbor: true,
					type: MajorType$1.Simple,
					value: {
						type: "Float",
						value: f
					}
				});
			}
			default: switch (value) {
				case 20: return attachMethods$1({
					isCbor: true,
					type: MajorType$1.Simple,
					value: { type: "False" }
				});
				case 21: return attachMethods$1({
					isCbor: true,
					type: MajorType$1.Simple,
					value: { type: "True" }
				});
				case 22: return attachMethods$1({
					isCbor: true,
					type: MajorType$1.Simple,
					value: { type: "Null" }
				});
				default: throw CborError$1.invalidSimpleValue();
			}
		}
	}
}
function checkCanonicalEncoding(cbor, buf) {
	if (!areBytesEqual(buf, encodeCbor(cbor))) throw CborError$1.nonCanonicalNumeric();
}
/**
* Extract native JavaScript value from CBOR.
* Converts CBOR types to their JavaScript equivalents.
*
* Returns the closed union {@link CborNative}. Note the two asymmetries
* documented there: maps come back as `CborMap` and tagged values as `Cbor`.
*/
const extractCbor$1 = (cbor) => {
	let c;
	if (cbor instanceof Uint8Array) c = decodeCbor$1(cbor);
	else c = cbor;
	switch (c.type) {
		case MajorType$1.Unsigned: return c.value;
		case MajorType$1.Negative: if (typeof c.value === "bigint") return -c.value - 1n;
		else return -c.value - 1;
		case MajorType$1.ByteString: return c.value;
		case MajorType$1.Text: return c.value;
		case MajorType$1.Array: return c.value.map(extractCbor$1);
		case MajorType$1.Map: return c.value;
		case MajorType$1.Tagged: return c;
		case MajorType$1.Simple: {
			const simple = c.value;
			switch (simple.type) {
				case "True": return true;
				case "False": return false;
				case "Null": return null;
				case "Float": return simple.value;
				default: return simple;
			}
		}
		default: return c;
	}
};
/**
* Map Support in dCBOR
*
* A deterministic CBOR map implementation that ensures maps with the same
* content always produce identical binary encodings, regardless of insertion
* order.
*
* ## Deterministic Map Representation
*
* The `CborMap` type follows strict deterministic encoding rules as specified by
* dCBOR:
*
* - Map keys are always sorted in lexicographic order of their encoded CBOR bytes
* - Duplicate keys are not allowed (enforced by the implementation)
* - Keys and values can be any type that can be converted to CBOR
* - Numeric reduction is applied (e.g., 3.0 is stored as integer 3)
*
* ## Vocabulary
*
* `CborMap` mirrors the JS `Map` protocol: `set`, `get`, `getOrThrow`, `has`,
* `delete`, `clear`, `size`, `keys()`, `values()`, `entries()`, `forEach`,
* iteration. `get` returns the STORED `Cbor` node (symmetric with
* `entries()`); extract natives explicitly with `extractCbor(map.get(k))`.
*
* @module map
*/
/**
* A deterministic CBOR map implementation.
*
* Maps are always encoded with keys sorted lexicographically by their
* encoded CBOR representation, ensuring deterministic encoding.
*/
var CborMap$1 = class {
	/** Debug label: `Object.prototype.toString` reports `[object CborMap]`. */
	get [Symbol.toStringTag]() {
		return "CborMap";
	}
	_dict;
	/**
	* Creates a new, empty CBOR Map.
	* Optionally initializes from a JavaScript Map (every key and value must
	* itself be encodable).
	*/
	constructor(map) {
		this._dict = new SortedByteMap();
		if (map !== void 0) for (const [key, value] of map.entries()) this.set(key, value);
	}
	/**
	* Inserts a key-value pair into the map (replacing any entry whose key has
	* the same canonical encoding). Any insertion order is accepted - entries
	* are kept in canonical ascending encoded-key order.
	*
	* @example
	* ```typescript
	* const m = new CborMap();
	* m.set("z", 1);
	* m.set(10, "ten"); // sorts before "z" in the encoding
	* encodeCbor(m);    // deterministic regardless of insertion order
	* ```
	* @public
	*/
	set(key, value) {
		const keyCbor = cbor$1(key);
		const valueCbor = cbor$1(value);
		const keyData = encodeCbor(keyCbor);
		this._dict.set(keyData, {
			key: keyCbor,
			value: valueCbor
		});
	}
	_makeKey(key) {
		return encodeCbor(cbor$1(key));
	}
	/**
	* Get the STORED `Cbor` node for a key, or `undefined` if absent.
	*
	* This is symmetric with `entries()` - no hidden native extraction, no
	* unwitnessed generics. To read a native value, compose explicitly:
	*
	* ```typescript
	* asNumber(map.get("age"));          // number | undefined, checked
	* extractCbor(map.getOrThrow("age")); // CborNative, throws if absent
	* ```
	* @public
	*/
	get(key) {
		return this._dict.get(this._makeKey(key))?.value;
	}
	/**
	* Get the stored `Cbor` node for a key.
	*
	* @throws {CborError} `MissingMapKey` - the key is not present.
	*/
	getOrThrow(key) {
		const value = this.get(key);
		if (value === void 0) throw CborError$1.missingMapKey();
		return value;
	}
	delete(key) {
		const keyData = this._makeKey(key);
		const existed = this._dict.has(keyData);
		this._dict.delete(keyData);
		return existed;
	}
	has(key) {
		return this._dict.has(this._makeKey(key));
	}
	clear() {
		this._dict = new SortedByteMap();
	}
	/** The number of entries in the map. */
	get size() {
		return this._dict.size;
	}
	/**
	* Get the entries of the map as an array, sorted in canonical ascending
	* encoded-key order.
	*
	* @internal Public because the encoder, diagnostic formatter, and hex
	* annotator consume it cross-module; not part of the supported surface.
	*/
	get entriesArray() {
		return this._dict.map((value, _key) => ({
			key: value.key,
			value: value.value
		}));
	}
	/** Iterate keys in canonical (sorted encoded-key) order. */
	*keys() {
		for (const entry of this.entriesArray) yield entry.key;
	}
	/** Iterate values in canonical key order. */
	*values() {
		for (const entry of this.entriesArray) yield entry.value;
	}
	/**
	* Iterate `[key, value]` tuples in canonical key order (the JS
	* `Map.entries()` shape).
	*/
	*entries() {
		for (const entry of this.entriesArray) yield [entry.key, entry.value];
	}
	/** JS `Map.forEach` mirror (value first, then key, then the map). */
	forEach(callback, thisArg) {
		for (const entry of this.entriesArray) callback.call(thisArg, entry.value, entry.key, this);
	}
	*[Symbol.iterator]() {
		for (const entry of this.entriesArray) yield [entry.key, entry.value];
	}
	/**
	* Inserts the next key-value pair into the map during decoding.
	* This is used for efficient map building during CBOR decoding.
	* Throws if the key is not in ascending order or is a duplicate.
	*
	* @internal The decoder's append path; not part of the supported surface.
	*/
	setNext(key, value) {
		const keyCbor = cbor$1(key);
		const newKey = encodeCbor(keyCbor);
		if (this._dict.has(newKey)) throw CborError$1.duplicateMapKey();
		const greatest = this._dict.maxKey();
		if (greatest !== void 0) {
			if (lexicographicallyCompareBytes(newKey, greatest) <= 0) throw CborError$1.misorderedMapKey();
		}
		this._dict.appendGreatest(newKey, {
			key: keyCbor,
			value: cbor$1(value)
		});
	}
	/**
	* Convert to a plain JavaScript `Map` of extracted native values.
	* Tagged values come back as `Cbor` nodes and nested maps as `CborMap`
	* (the {@link CborNative} asymmetries).
	*/
	toMap() {
		const map = /* @__PURE__ */ new Map();
		for (const entry of this.entriesArray) map.set(extractCbor$1(entry.key), extractCbor$1(entry.value));
		return map;
	}
};
/**
* Encodes the simple value to its raw CBOR byte representation.
*
* Returns the CBOR bytes that represent this simple value according to the
* dCBOR deterministic encoding rules:
* - `False` encodes as `0xf4`
* - `True` encodes as `0xf5`
* - `Null` encodes as `0xf6`
* - `Float` values encode according to the IEEE 754 floating point rules,
*   using the shortest representation that preserves precision.
*/
const simpleCborData = (simple) => {
	switch (simple.type) {
		case "False": return encodeVarInt(20, MajorType$1.Simple);
		case "True": return encodeVarInt(21, MajorType$1.Simple);
		case "Null": return encodeVarInt(22, MajorType$1.Simple);
		case "Float": return f64CborData(simple.value);
	}
};
Uint8Array.fromHex;
/**
* Convert bytes to a lowercase hex string.
*
* Delegates to the native `Uint8Array.prototype.toHex` where available.
*/
const bytesToHex$1 = (bytes) => {
	const native = bytes.toHex;
	if (typeof native === "function") return native.call(bytes);
	let out = "";
	for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
	return out;
};
/**
* The dCBOR value core: the `Cbor` union type, the polymorphic constructor
* `cbor()`, the encoder entry `encodeCbor()`, and the tagged-value
* constructor `taggedValue()`.
*
* ## The API in one paragraph
*
* Construct with `cbor(input)` (the single polymorphic constructor) or
* `taggedValue(tag, content)` (the only explicit tagged-value constructor);
* custom types participate by implementing the one structural protocol
* `ToCbor { toCbor(): Cbor }`. Encode with `encodeCbor(value)`. Decode with
* `decodeCbor(bytes)` (throws) or `tryDecode(bytes)` (returns `Result`).
* Read with the free `isX`/`asX`/`expectX` accessor functions. The only
* instance conveniences on a `Cbor` value are `toData()`, `toHex()`, and a
* cheap `toString()`.
*
* @module cbor
*/
/**
* The instance methods shared by every `Cbor` value: exactly three cheap
* conveniences (plus debug symbols below). Everything else is a free function
* so decode-only bundles never carry the diagnostic formatter, hex annotator,
* tag store, or walker.
*
* `String(c)`/template literals/`console.log` produce `Cbor(0x…)`. Diagnostic
* rendering lives in `@blockchaincommons/dcbor/diagnostic`; opt-in diag-flavored debug
* output lives in `@blockchaincommons/dcbor/debug` (`installDebugHooks()`).
*/
const CBOR_METHODS = {
	toData() {
		return encodeCbor(this);
	},
	toHex() {
		return bytesToHex$1(encodeCbor(this));
	},
	toString() {
		return `Cbor(0x${bytesToHex$1(encodeCbor(this))})`;
	},
	[Symbol.toStringTag]: "Cbor",
	[Symbol.for("nodejs.util.inspect.custom")]() {
		return this.toString();
	}
};
/**
* Decorate a bare CBOR value (`{ isCbor, type, value[, tag] }`) with the shared
* instance methods. The methods live on {@link CBOR_METHODS} and are installed
* via the prototype - constructed with `Object.create` (not `setPrototypeOf`,
* which would drop the object off V8's fast path). Only the handful of data
* properties are own-properties; the methods are shared, not per-object.
*
* @internal
*/
const attachMethods$1 = (obj) => {
	const decorated = Object.create(CBOR_METHODS);
	return Object.assign(decorated, obj);
};
const CBOR_FALSE = attachMethods$1({
	isCbor: true,
	type: MajorType$1.Simple,
	value: { type: "False" }
});
const CBOR_TRUE = attachMethods$1({
	isCbor: true,
	type: MajorType$1.Simple,
	value: { type: "True" }
});
const CBOR_NULL = attachMethods$1({
	isCbor: true,
	type: MajorType$1.Simple,
	value: { type: "Null" }
});
const hasTaggedCbor$1 = (value) => {
	return typeof value === "object" && value !== null && "taggedCbor" in value && typeof value.taggedCbor === "function";
};
const hasToCbor$1 = (value) => {
	return typeof value === "object" && value !== null && "toCbor" in value && typeof value.toCbor === "function";
};
/**
* Convert any supported value to its CBOR representation - the single
* polymorphic constructor.
*
* Custom types participate by implementing {@link ToCbor}
* (`toCbor(): Cbor` - the `toJSON` precedent). Tagged values are built with
* {@link taggedValue}.
*
* @example
* ```typescript
* cbor(42);                          // integer
* cbor("héllo");                     // NFC-normalized text
* cbor([1, "two", true, null]);      // array
* cbor(new Map([["k", 1]]));         // map (canonical key order)
* cbor({ name: "Alice", age: 30 });  // plain object -> map
* ```
*
* @throws {CborError} `OutOfRange` - bigint outside `[-(2^64), 2^64 - 1]`.
* @throws {CborError} `Custom` - unsupported input type, or one of the two
*   directive errors below.
* @public
*
* ## Directive errors
*
* Two input shapes throw a directive `CborError` because encoding them
* silently would produce ambiguous or divergent bytes:
*
* - plain objects shaped exactly `{tag, value}`: use
*   `taggedValue(tag, content)` for a tagged value, or add/rename a key for
*   a map;
* - objects implementing `taggedCbor()` but not `toCbor()`: add
*   `toCbor() { return this.taggedCbor(); }`.
*/
const cbor$1 = (value) => {
	if (isCbor$1(value) && "toData" in value) return value;
	if (isCbor$1(value)) return attachMethods$1(value);
	let result;
	if (isCborNumber$1(value)) if (typeof value === "number" && Number.isNaN(value)) result = {
		isCbor: true,
		type: MajorType$1.Simple,
		value: {
			type: "Float",
			value: NaN
		}
	};
	else if (typeof value === "number" && hasFractionalPart(value)) result = {
		isCbor: true,
		type: MajorType$1.Simple,
		value: {
			type: "Float",
			value
		}
	};
	else if (value == Infinity) result = {
		isCbor: true,
		type: MajorType$1.Simple,
		value: {
			type: "Float",
			value: Infinity
		}
	};
	else if (value == -Infinity) result = {
		isCbor: true,
		type: MajorType$1.Simple,
		value: {
			type: "Float",
			value: -Infinity
		}
	};
	else if (typeof value === "number" && !Number.isSafeInteger(value)) {
		const big = BigInt(value);
		if (big >= 0n && big <= 18446744073709551615n) result = {
			isCbor: true,
			type: MajorType$1.Unsigned,
			value: big
		};
		else if (big < 0n && big >= CBOR_INT_MIN) result = {
			isCbor: true,
			type: MajorType$1.Negative,
			value: -big - 1n
		};
		else result = {
			isCbor: true,
			type: MajorType$1.Simple,
			value: {
				type: "Float",
				value
			}
		};
	} else if (typeof value === "bigint" && (value > 18446744073709551615n || value < CBOR_INT_MIN)) throw CborError$1.outOfRange();
	else if (value < 0) if (typeof value === "bigint") result = {
		isCbor: true,
		type: MajorType$1.Negative,
		value: -value - 1n
	};
	else result = {
		isCbor: true,
		type: MajorType$1.Negative,
		value: -value - 1
	};
	else result = {
		isCbor: true,
		type: MajorType$1.Unsigned,
		value
	};
	else if (typeof value === "string") {
		const normalized = value.normalize("NFC");
		result = {
			isCbor: true,
			type: MajorType$1.Text,
			value: normalized
		};
	} else if (value === null || value === void 0) return CBOR_NULL;
	else if (value === true) return CBOR_TRUE;
	else if (value === false) return CBOR_FALSE;
	else if (Array.isArray(value)) result = {
		isCbor: true,
		type: MajorType$1.Array,
		value: value.map(cbor$1)
	};
	else if (value instanceof Uint8Array) result = {
		isCbor: true,
		type: MajorType$1.ByteString,
		value
	};
	else if (value instanceof CborMap$1) result = {
		isCbor: true,
		type: MajorType$1.Map,
		value
	};
	else if (value instanceof Map) result = {
		isCbor: true,
		type: MajorType$1.Map,
		value: new CborMap$1(value)
	};
	else if (value instanceof Set) result = {
		isCbor: true,
		type: MajorType$1.Array,
		value: Array.from(value).map(cbor$1)
	};
	else if (hasToCbor$1(value)) return value.toCbor();
	else if (hasTaggedCbor$1(value)) throw CborError$1.custom("objects implementing taggedCbor() are no longer auto-wrapped by cbor(); implement toCbor() (e.g. `toCbor() { return this.taggedCbor(); }`)");
	else if (typeof value === "object" && "tag" in value && "value" in value) {
		const keys = Object.keys(value);
		if (keys.length === 2 && keys.includes("tag") && keys.includes("value")) throw CborError$1.custom("plain { tag, value } objects are ambiguous and no longer encode as tagged values; use taggedValue(tag, content) for a tagged value, or add/rename a key to encode a map");
		const map = new CborMap$1();
		for (const [key, val] of Object.entries(value)) map.set(cbor$1(key), cbor$1(val));
		result = {
			isCbor: true,
			type: MajorType$1.Map,
			value: map
		};
	} else if (typeof value === "object") {
		const map = new CborMap$1();
		for (const [key, val] of Object.entries(value)) map.set(cbor$1(key), cbor$1(val));
		result = {
			isCbor: true,
			type: MajorType$1.Map,
			value: map
		};
	} else throw CborError$1.custom("Unsupported type for CBOR encoding");
	return attachMethods$1(result);
};
const textEncoder = new TextEncoder();
/**
* Write a CBOR value into `writer`. The whole tree encodes into one growable
* buffer, so nested containers don't allocate-and-concatenate a fresh array
* per level.
*/
const writeCborInto = (writer, value) => {
	const c = cbor$1(value);
	switch (c.type) {
		case MajorType$1.Unsigned:
			writeVarInt(writer, c.value, MajorType$1.Unsigned);
			return;
		case MajorType$1.Negative:
			writeVarInt(writer, c.value, MajorType$1.Negative);
			return;
		case MajorType$1.ByteString:
			if (c.value instanceof Uint8Array) {
				writeVarInt(writer, c.value.length, MajorType$1.ByteString);
				writer.writeBytes(c.value);
				return;
			}
			break;
		case MajorType$1.Text:
			if (typeof c.value === "string") {
				const utf8Bytes = textEncoder.encode(c.value);
				writeVarInt(writer, utf8Bytes.length, MajorType$1.Text);
				writer.writeBytes(utf8Bytes);
				return;
			}
			break;
		case MajorType$1.Tagged:
			if (typeof c.tag === "bigint" || typeof c.tag === "number") {
				writeVarInt(writer, c.tag, MajorType$1.Tagged);
				writeCborInto(writer, c.value);
				return;
			}
			break;
		case MajorType$1.Simple:
			writer.writeBytes(simpleCborData(c.value));
			return;
		case MajorType$1.Array:
			writeVarInt(writer, c.value.length, MajorType$1.Array);
			for (const item of c.value) writeCborInto(writer, item);
			return;
		case MajorType$1.Map: {
			const entries = c.value.entriesArray;
			writeVarInt(writer, entries.length, MajorType$1.Map);
			for (const { key, value: entryValue } of entries) {
				writeCborInto(writer, key);
				writeCborInto(writer, entryValue);
			}
			return;
		}
	}
	throw CborError$1.wrongType();
};
/**
* Encode a value to deterministic CBOR bytes. Accepts anything `cbor()`
* accepts; equal values always produce identical bytes (dCBOR determinism).
*
* @example
* ```typescript
* encodeCbor({ a: 1 });            // Uint8Array [0xa1, 0x61, 0x61, 0x01]
* bytesToHex(encodeCbor("Hello")); // "6548656c6c6f"
* ```
*
* @throws {CborError} Whatever `cbor(value)` throws for unsupported inputs
*   (`OutOfRange`, `Custom`).
* @remarks The decoder's canonicality check re-encodes every decoded value
*   through this function, so it is wire-critical.
* @public
*/
const encodeCbor = (value) => {
	const c = cbor$1(value);
	switch (c.type) {
		case MajorType$1.Unsigned: return encodeVarInt(c.value, MajorType$1.Unsigned);
		case MajorType$1.Negative: return encodeVarInt(c.value, MajorType$1.Negative);
		case MajorType$1.Simple: return simpleCborData(c.value);
		default: {
			const writer = new BufWriter();
			writeCborInto(writer, c);
			return writer.toBytes();
		}
	}
};
/**
* Tag registry implementation.
*
* Stores tags with their names and optional summarizer functions.
*/
var TagsStore$1 = class {
	/** Debug label: `Object.prototype.toString` reports `[object TagsStore]`. */
	get [Symbol.toStringTag]() {
		return "TagsStore";
	}
	_tagsByValue = /* @__PURE__ */ new Map();
	_tagsByName = /* @__PURE__ */ new Map();
	_summarizers = /* @__PURE__ */ new Map();
	constructor() {}
	/**
	* Insert a tag into the registry.
	*
	* - Throws if the tag name is undefined or empty
	* - Throws if a tag with the same value exists with a different name
	* - Allows re-registering the same tag value with the same name
	*
	* @param tag - The tag to register (must have a non-empty name)
	* @throws Error if tag has no name, empty name, or conflicts with existing registration
	*
	* @example
	* ```typescript
	* const store = new TagsStore();
	* store.register(Tag.from(12345, 'myCustomTag'));
	* ```
	*/
	register(tag) {
		const name = tag.name;
		if (name === void 0 || name === "") throw new Error(`Tag ${tag.value} must have a non-empty name`);
		const key = this._valueKey(tag.value);
		const existing = this._tagsByValue.get(key);
		if (existing?.name !== void 0 && existing.name !== name) throw new Error(`Attempt to register tag: ${tag.value} '${existing.name}' with different name: '${name}'`);
		this._tagsByValue.set(key, tag);
		this._tagsByName.set(name, tag);
	}
	/**
	* Register multiple tags; the conflict-throwing validation in `register()`
	* applies per tag.
	*/
	registerAll(tags) {
		for (const tag of tags) this.register(tag);
	}
	/**
	* Register a custom summarizer function for a tag.
	*
	* @param tagValue - The numeric tag value
	* @param summarizer - The summarizer function
	*
	* @example
	* ```typescript
	* store.setSummarizer(1, (cbor, flat) => {
	*   // Custom date formatting
	*   return `Date(${extractCbor(cbor)})`;
	* });
	* ```
	*/
	setSummarizer(tagValue, summarizer) {
		const key = this._valueKey(tagValue);
		this._summarizers.set(key, summarizer);
	}
	assignedNameForTag(tag) {
		const key = this._valueKey(tag.value);
		return this._tagsByValue.get(key)?.name;
	}
	nameForTag(tag) {
		return this.assignedNameForTag(tag) ?? tag.value.toString();
	}
	tagForValue(value) {
		const key = this._valueKey(value);
		return this._tagsByValue.get(key);
	}
	tagForName(name) {
		return this._tagsByName.get(name);
	}
	nameForValue(value) {
		const tag = this.tagForValue(value);
		return tag !== void 0 ? this.nameForTag(tag) : value.toString();
	}
	summarizer(tag) {
		const key = this._valueKey(tag);
		return this._summarizers.get(key);
	}
	/**
	* Create a string key for a numeric tag value.
	* Handles both number and bigint types.
	*
	* @private
	*/
	_valueKey(value) {
		return value.toString();
	}
};
/**
* Global singleton instance of the tags store.
*/
let globalTagsStore$1;
/**
* Get the global tags store instance.
*
* Creates the instance on first access.
*
* @returns The global TagsStore instance
*
* @example
* ```typescript
* const store = getGlobalTagsStore();
* store.register(Tag.from(999, 'myTag'));
* ```
*/
const getGlobalTagsStore$1 = () => {
	globalTagsStore$1 ??= new TagsStore$1();
	return globalTagsStore$1;
};
/**
* String utilities for dCBOR, including Unicode normalization.
*
* @module string-util
*/
/**
* Flank a string with left and right strings.
*
* @param s - String to flank
* @param left - Left flanking string
* @param right - Right flanking string
* @returns Flanked string
*/
const flanked = (s, left, right) => left + s + right;
/**
* Check if a character is printable. Internal helper for {@link sanitized}.
*
* @param c - Character to check
* @returns True if printable
*/
const isPrintable = (c) => {
	if (c.length !== 1) return false;
	const code = c.charCodeAt(0);
	return code > 127 || code >= 32 && code <= 126;
};
/**
* Sanitize a string by replacing non-printable characters with dots.
* Returns None if the string has no printable characters.
*
* @param str - String to sanitize
* @returns Sanitized string or undefined if no printable characters
*/
const sanitized = (str) => {
	let hasPrintable = false;
	const chars = [];
	for (const c of str) if (isPrintable(c)) {
		hasPrintable = true;
		chars.push(c);
	} else chars.push(".");
	if (!hasPrintable) return;
	return chars.join("");
};
const resolveOpts = (opts) => {
	const summarize = opts?.summarize ?? false;
	return {
		annotate: opts?.annotate ?? false,
		summarize,
		flat: summarize || (opts?.flat ?? false),
		tags: opts?.tags ?? "global"
	};
};
/**
* Format a CBOR value - or a walk visitor's `WalkElement` - as CBOR
* diagnostic notation.
*
* ```typescript
* diagnostic(value);                       // pretty-printed
* diagnostic(value, { flat: true });       // single line
* diagnostic(value, { annotate: true });   // tag names as annotations
* diagnostic(value, { summarize: true });  // registered summarizers (implies flat)
* ```
*
* @param input - CBOR value, or a `WalkElement` from a walk visitor
* @param opts - Formatting options (explicit `undefined` fields mean
*   "use the default")
* @public
*/
function diagnostic$1(input, opts) {
	const state = resolveOpts(opts);
	if (typeof input === "object" && "type" in input && (input.type === "single" || input.type === "keyvalue")) {
		if (input.type === "single") return diagFormat(diagItem(input.cbor, state), state);
		return `${diagFormat(diagItem(input.key, state), state)}: ${diagFormat(diagItem(input.value, state), state)}`;
	}
	return diagFormat(diagItem(input, state), state);
}
const item = (value) => ({
	kind: "item",
	value
});
const group = (begin, end, items, isPairs, comment) => {
	const g = {
		kind: "group",
		begin,
		end,
		items,
		isPairs
	};
	if (comment !== void 0) g.comment = comment;
	return g;
};
const isGroup = (i) => i.kind === "group";
const containsGroup = (i) => i.kind === "group" && i.items.some(isGroup);
const totalStringsLen = (i) => i.kind === "item" ? i.value.length : i.items.reduce((acc, c) => acc + totalStringsLen(c), 0);
const greatestStringsLen = (i) => i.kind === "item" ? i.value.length : i.items.reduce((acc, c) => Math.max(acc, totalStringsLen(c)), 0);
/**
* Alternates between `pairSeparator` (after even-indexed items - keys) and
* `itemSeparator` (after odd-indexed items - values). Falls back to
* `itemSeparator` for non-pair groups.
*/
function joined(elements, itemSeparator, pairSeparator) {
	const sep = pairSeparator ?? itemSeparator;
	let result = "";
	const len = elements.length;
	for (let i = 0; i < len; i++) {
		result += elements[i];
		if (i !== len - 1) result += (i & 1) !== 0 ? itemSeparator : sep;
	}
	return result;
}
const diagFormat = (i, opts) => diagFormatOpt(i, 0, "", opts);
function diagFormatOpt(i, level, separator, opts) {
	if (i.kind === "item") return formatLine(level, opts, i.value, separator, void 0);
	if (opts.flat !== true && (containsGroup(i) || totalStringsLen(i) > 20 || greatestStringsLen(i) > 20)) return multilineComposition(i, level, separator, opts);
	return singleLineComposition(i, level, separator, opts);
}
function formatLine(level, opts, string, separator, comment) {
	const result = `${opts.flat === true ? "" : " ".repeat(level * 4)}${string}${separator}`;
	if (comment !== void 0) return `${result}   / ${comment} /`;
	return result;
}
function singleLineComposition(i, level, separator, opts) {
	let str;
	let comment;
	if (i.kind === "item") {
		str = i.value;
		comment = void 0;
	} else {
		str = flanked(joined(i.items.map((c) => c.kind === "item" ? c.value : singleLineComposition(c, level + 1, separator, opts)), ", ", i.isPairs ? ": " : ", "), i.begin, i.end);
		comment = i.comment;
	}
	return formatLine(level, opts, str, separator, comment);
}
function multilineComposition(i, level, separator, opts) {
	if (i.kind === "item") return i.value;
	const lines = [];
	const openOpts = {
		...opts,
		flat: false
	};
	lines.push(formatLine(level, openOpts, i.begin, "", i.comment));
	for (let idx = 0; idx < i.items.length; idx++) {
		const sep = idx === i.items.length - 1 ? "" : i.isPairs && (idx & 1) === 0 ? ":" : ",";
		lines.push(diagFormatOpt(i.items[idx], level + 1, sep, opts));
	}
	lines.push(formatLine(level, opts, i.end, separator, void 0));
	return lines.join("\n");
}
function diagItem(cbor, opts) {
	switch (cbor.type) {
		case MajorType$1.Unsigned: return item(formatUnsigned(cbor.value));
		case MajorType$1.Negative: return item(formatNegative(cbor.value));
		case MajorType$1.ByteString: return item(formatBytes(cbor.value));
		case MajorType$1.Text: return item(formatText(cbor.value));
		case MajorType$1.Array: return item_array(cbor.value, opts);
		case MajorType$1.Map: return item_map(cbor.value, opts);
		case MajorType$1.Tagged: return item_tagged(cbor.tag, cbor.value, opts);
		case MajorType$1.Simple: return item(formatSimple(cbor.value));
	}
}
function item_array(items, opts) {
	return group("[", "]", items.map((it) => diagItem(it, opts)), false);
}
function item_map(map, opts) {
	const entries = map?.entriesArray ?? [];
	const flatItems = [];
	for (const e of entries) {
		flatItems.push(diagItem(e.key, opts));
		flatItems.push(diagItem(e.value, opts));
	}
	return group("{", "}", flatItems, true);
}
function item_tagged(tag, content, opts) {
	if (opts.summarize === true) {
		const summarizer = resolveTagsStore(opts.tags)?.summarizer(tag);
		if (summarizer !== void 0) {
			const result = summarizer(content, opts.flat ?? false);
			if (result.ok) return item(result.value);
			return item(`<error: ${result.error.message}>`);
		}
	}
	let comment;
	if (opts.annotate === true) {
		const store = resolveTagsStore(opts.tags);
		const tagObj = { value: tag };
		const assignedName = store?.assignedNameForTag(tagObj);
		if (assignedName !== void 0) comment = assignedName;
	}
	return group(`${String(tag)}(`, ")", [diagItem(content, opts)], false, comment);
}
function formatUnsigned(value) {
	return String(value);
}
function formatNegative(value) {
	if (typeof value === "bigint") return String(-value - 1n);
	return String(-value - 1);
}
function formatBytes(value) {
	return `h'${bytesToHex$1(value)}'`;
}
function formatText(value) {
	return `"${value.replace(/"/g, "\\\"")}"`;
}
function formatSimple(value) {
	switch (value.type) {
		case "True": return "true";
		case "False": return "false";
		case "Null": return "null";
		case "Float": return formatFloat(value.value);
	}
}
/**
* Format a CBOR float for diagnostic output. Shared with the hex-dump
* annotation path; see {@link floatDisplayString}.
*/
function formatFloat(value) {
	return floatDisplayString(value);
}
function resolveTagsStore(tags) {
	if (tags === "none") return void 0;
	if (tags === "global" || tags === void 0) return getGlobalTagsStore$1();
	return tags;
}
/**
* Hex dump utilities for CBOR data.
*
* Affordances for viewing the encoded binary representation of CBOR as hexadecimal.
* Optionally annotates the output, breaking it up into semantically meaningful lines,
* formatting dates, and adding names of known tags.
*
* @module dump
*/
/**
* Render CBOR as an annotated hex dump: the encoding broken into
* semantically meaningful lines with offsets, values, and tag names
* resolved through the tags store.
*
* For plain hex use `c.toHex()` or `bytesToHex(encodeCbor(v))`.
*
* @param cbor - CBOR value to render
* @param opts - Formatting options (explicit `undefined` fields mean
*   "use the default")
*/
const hexAnnotated = (cbor, opts) => {
	const items = dumpItems(cbor, 0, opts?.tagsStore ?? getGlobalTagsStore$1());
	const roundedNoteColumn = (items.reduce((largest, item) => {
		return Math.max(largest, item.formatFirstColumn().length);
	}, 0) + 4 & -4) - 1;
	return items.map((item) => item.format(roundedNoteColumn)).join("\n");
};
/**
* Internal structure for dump items.
*/
var DumpItem = class {
	level;
	data;
	note;
	constructor(level, data, note) {
		this.level = level;
		this.data = data;
		this.note = note;
	}
	format(noteColumn) {
		const column1 = this.formatFirstColumn();
		let column2 = "";
		let padding = "";
		if (this.note !== void 0) {
			const paddingCount = Math.max(1, Math.min(39, noteColumn) - column1.length + 1);
			padding = " ".repeat(paddingCount);
			column2 = `# ${this.note}`;
		}
		return column1 + padding + column2;
	}
	formatFirstColumn() {
		return " ".repeat(this.level * 4) + this.data.map(bytesToHex$1).filter((x) => x.length > 0).join(" ");
	}
};
/**
* Generate dump items for a CBOR value (recursive).
*/
function dumpItems(cbor, level, tagsStore) {
	const items = [];
	switch (cbor.type) {
		case MajorType$1.Unsigned: {
			const data = encodeCbor(cbor);
			items.push(new DumpItem(level, [data], `unsigned(${cbor.value})`));
			break;
		}
		case MajorType$1.Negative: {
			const data = encodeCbor(cbor);
			const actualValue = typeof cbor.value === "bigint" ? -1n - cbor.value : -1 - cbor.value;
			items.push(new DumpItem(level, [data], `negative(${actualValue})`));
			break;
		}
		case MajorType$1.ByteString: {
			const header = encodeVarInt(cbor.value.length, MajorType$1.ByteString);
			items.push(new DumpItem(level, [header], `bytes(${cbor.value.length})`));
			if (cbor.value.length > 0) {
				let note = void 0;
				try {
					const sanitizedText = sanitized(new TextDecoder("utf-8", { fatal: true }).decode(cbor.value));
					if (sanitizedText !== void 0 && sanitizedText !== "") note = flanked(sanitizedText, "\"", "\"");
				} catch {}
				items.push(new DumpItem(level + 1, [cbor.value], note));
			}
			break;
		}
		case MajorType$1.Text: {
			const utf8Data = new TextEncoder().encode(cbor.value);
			const header = encodeVarInt(utf8Data.length, MajorType$1.Text);
			const firstByte = header[0];
			if (firstByte === void 0) throw CborError$1.custom("Invalid varint encoding");
			const headerData = [new Uint8Array([firstByte]), header.slice(1)];
			items.push(new DumpItem(level, headerData, `text(${utf8Data.length})`));
			items.push(new DumpItem(level + 1, [utf8Data], flanked(cbor.value, "\"", "\"")));
			break;
		}
		case MajorType$1.Array: {
			const header = encodeVarInt(cbor.value.length, MajorType$1.Array);
			const firstByte = header[0];
			if (firstByte === void 0) throw CborError$1.custom("Invalid varint encoding");
			const headerData = [new Uint8Array([firstByte]), header.slice(1)];
			items.push(new DumpItem(level, headerData, `array(${cbor.value.length})`));
			for (const item of cbor.value) items.push(...dumpItems(item, level + 1, tagsStore));
			break;
		}
		case MajorType$1.Map: {
			const header = encodeVarInt(cbor.value.size, MajorType$1.Map);
			const firstByte = header[0];
			if (firstByte === void 0) throw CborError$1.custom("Invalid varint encoding");
			const headerData = [new Uint8Array([firstByte]), header.slice(1)];
			items.push(new DumpItem(level, headerData, `map(${cbor.value.size})`));
			for (const entry of cbor.value.entriesArray) {
				items.push(...dumpItems(entry.key, level + 1, tagsStore));
				items.push(...dumpItems(entry.value, level + 1, tagsStore));
			}
			break;
		}
		case MajorType$1.Tagged: {
			const tagValue = cbor.tag;
			if (tagValue === void 0) throw CborError$1.custom("Tagged CBOR value must have a tag");
			const header = encodeVarInt(tagValue, MajorType$1.Tagged);
			const firstByte = header[0];
			if (firstByte === void 0) throw CborError$1.custom("Invalid varint encoding");
			const headerData = [new Uint8Array([firstByte]), header.slice(1)];
			const noteComponents = [`tag(${tagValue})`];
			const tag = Tag.from(tagValue);
			const tagName = tagsStore.assignedNameForTag(tag);
			if (tagName !== void 0) noteComponents.push(tagName);
			const tagNote = noteComponents.join(" ");
			items.push(new DumpItem(level, headerData, tagNote));
			items.push(...dumpItems(cbor.value, level + 1, tagsStore));
			break;
		}
		case MajorType$1.Simple: {
			const data = encodeCbor(cbor);
			const simple = cbor.value;
			let note;
			if (simple.type === "True") note = "true";
			else if (simple.type === "False") note = "false";
			else if (simple.type === "Null") note = "null";
			else if (simple.type === "Float") note = floatDisplayString(simple.value);
			else note = "simple";
			items.push(new DumpItem(level, [data], note));
			break;
		}
	}
	return items;
}
/**
* Compare two tag values for equality, normalizing `number` vs `bigint`.
* A raw `===` would treat `100n` and `100` as unequal, so a large tag that
* decoded to a `bigint` wouldn't match the same value written as a `number`.
*/
const tagValuesEqual = (a, b) => {
	if (typeof a === "bigint" || typeof b === "bigint") return BigInt(a) === BigInt(b);
	return a === b;
};
/**
* Get the string representation of a tag.
* Internal function used for error messages.
*
* @param tag - The tag to represent
* @returns String representation (name if available, otherwise value)
*
* @internal
*/
const tagToString = (tag) => tag.name ?? tag.value.toString();
/**
* Convert an Error to a display string.
*
* Matches Rust's `Display` trait / `to_string()` method.
*/
const errorToString = (error) => {
	switch (error.type) {
		case "Underrun": return "early end of CBOR data";
		case "UnsupportedHeaderValue": return "unsupported value in CBOR header";
		case "NonCanonicalNumeric": return "a CBOR numeric value was encoded in non-canonical form";
		case "InvalidSimpleValue": return "an invalid CBOR simple value was encountered";
		case "InvalidString": return `an invalidly-encoded UTF-8 string was encountered in the CBOR (${error.message})`;
		case "NonCanonicalString": return "a CBOR string was not encoded in Unicode Canonical Normalization Form C";
		case "UnusedData": return `the decoded CBOR had ${error.count} extra bytes at the end`;
		case "MisorderedMapKey": return "the decoded CBOR map has keys that are not in canonical order";
		case "DuplicateMapKey": return "the decoded CBOR map has a duplicate key";
		case "MissingMapKey": return "missing CBOR map key";
		case "OutOfRange": return "the CBOR numeric value could not be represented in the specified numeric type";
		case "WrongType": return "the decoded CBOR value was not the expected type";
		case "WrongTag": return `expected CBOR tag ${tagToString(error.expected)}, but got ${tagToString(error.actual)}`;
		case "InvalidUtf8": return `invalid UTF‑8 string: ${error.message}`;
		case "InvalidDate": return `invalid ISO 8601 date string: ${error.message}`;
		case "Custom": return error.message;
	}
};
/**
* Typed error class for all CBOR-related errors.
*
* Wraps the discriminated union Error type in a JavaScript Error object
* for proper error handling with stack traces.
*
* @example
* ```typescript
* throw new CborError({ type: 'Underrun' });
* throw new CborError({ type: 'WrongTag', expected: tag1, actual: tag2 });
* ```
*/
var CborError = class CborError extends Error {
	/**
	* The structured error information.
	*/
	errorType;
	/**
	* Create a new CborError.
	*
	* @param errorType - The discriminated union error type
	* @param message - Optional custom message (defaults to errorToString(errorType))
	*/
	constructor(errorType, message) {
		super(message ?? errorToString(errorType));
		this.name = "CborError";
		this.errorType = errorType;
		if ("captureStackTrace" in Error) Error.captureStackTrace(this, CborError);
	}
	/**
	* Check if an error is a CborError.
	*
	* @param error - Error to check
	* @returns True if error is a CborError
	*/
	static isCborError(error) {
		return error instanceof CborError;
	}
};
/**
* Convert a legacy node into a canonical `@blockchaincommons/dcbor` node.
*
* Leaves are shared, not copied: the canonical functions never mutate their
* inputs. Map nodes unwrap to the inner canonical `CborMap`, so later
* mutations through the legacy wrapper stay visible.
*/
const toNew = (c) => {
	switch (c.type) {
		case MajorType.Array: return {
			isCbor: true,
			type: MajorType.Array,
			value: c.value.map(toNew)
		};
		case MajorType.Map: return {
			isCbor: true,
			type: MajorType.Map,
			value: c.value._inner
		};
		case MajorType.Tagged: return {
			isCbor: true,
			type: MajorType.Tagged,
			tag: c.tag,
			value: toNew(c.value)
		};
		default: return {
			isCbor: true,
			type: c.type,
			value: c.value
		};
	}
};
/**
* Convert a canonical node into a legacy node with the legacy method set.
* Map nodes wrap the canonical `CborMap` without copying entries.
*/
const fromNew = (n) => {
	switch (n.type) {
		case MajorType.Array: return attachMethods({
			isCbor: true,
			type: MajorType.Array,
			value: n.value.map(fromNew)
		});
		case MajorType.Map: return attachMethods({
			isCbor: true,
			type: MajorType.Map,
			value: CborMap._fromInner(n.value)
		});
		case MajorType.Tagged: return attachMethods({
			isCbor: true,
			type: MajorType.Tagged,
			tag: n.tag,
			value: fromNew(n.value)
		});
		default: return attachMethods({
			isCbor: true,
			type: n.type,
			value: n.value
		});
	}
};
/**
* Translate a canonical `CborError` (code + details) back into the legacy
* discriminated-union `CborError`. Non-CborError values are re-thrown as-is.
*/
const toLegacyError = (e) => {
	if (!CborError$1.isCborError(e)) {
		if (e instanceof CborError) return e;
		throw e;
	}
	const details = e.details;
	let errorType;
	switch (e.code) {
		case "UnsupportedHeaderValue":
			errorType = {
				type: "UnsupportedHeaderValue",
				value: details["headerValue"]
			};
			break;
		case "UnusedData":
			errorType = {
				type: "UnusedData",
				count: details["count"]
			};
			break;
		case "WrongTag":
			errorType = {
				type: "WrongTag",
				expected: details["expectedTag"],
				actual: details["actualTag"]
			};
			break;
		case "InvalidString":
			errorType = {
				type: "InvalidString",
				message: details["cause"] ?? e.message
			};
			break;
		case "InvalidUtf8":
			errorType = {
				type: "InvalidUtf8",
				message: details["cause"] ?? e.message
			};
			break;
		case "InvalidDate":
			errorType = {
				type: "InvalidDate",
				message: details["cause"] ?? e.message
			};
			break;
		case "Custom":
			errorType = {
				type: "Custom",
				message: e.message
			};
			break;
		default: errorType = { type: e.code };
	}
	return new CborError(errorType);
};
/** Run a canonical-package operation, translating thrown errors. */
const delegating = (op) => {
	try {
		return op();
	} catch (e) {
		throw toLegacyError(e);
	}
};
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Tag registry and management system.
*
* The TagsStore provides a centralized registry for CBOR tags,
* including name resolution and custom summarizer functions.
*
* The store wraps the `@blockchaincommons/dcbor` `TagsStore` — and the
* global singleton wraps the canonical package's *global* store — so tag
* names and summarizers registered through this legacy API are visible to
* the delegated diagnostic/hex formatters (and vice versa).
*
* @module tags-store
*/
/**
* Convert a canonical tag (whose `name` may be explicitly `undefined`) to the
* legacy `Tag` shape, which omits the property instead.
*/
const toLegacyTag = (tag) => {
	if (tag === void 0) return void 0;
	return tag.name !== void 0 ? {
		value: tag.value,
		name: tag.name
	} : { value: tag.value };
};
/**
* Tag registry implementation.
*
* Stores tags with their names and optional summarizer functions, delegating
* storage to the canonical `@blockchaincommons/dcbor` store.
*/
var TagsStore = class TagsStore {
	_store;
	/** Original (legacy-signature) summarizers, for the `summarizer()` accessor. */
	_legacySummarizers = /* @__PURE__ */ new Map();
	constructor() {
		this._store = new TagsStore$1();
	}
	/**
	* The wrapped canonical `@blockchaincommons/dcbor` store.
	* @internal
	*/
	get _inner() {
		return this._store;
	}
	/**
	* Wrap an existing canonical store without copying registrations.
	* @internal
	*/
	static _fromInner(inner) {
		const store = new TagsStore();
		store._store = inner;
		return store;
	}
	/**
	* Insert a tag into the registry.
	*
	* Matches Rust's TagsStore::insert() behavior:
	* - Throws if the tag name is undefined or empty
	* - Throws if a tag with the same value exists with a different name
	* - Allows re-registering the same tag value with the same name
	*
	* @param tag - The tag to register (must have a non-empty name)
	* @throws Error if tag has no name, empty name, or conflicts with existing registration
	*
	* @example
	* ```typescript
	* const store = new TagsStore();
	* store.insert(createTag(12345, 'myCustomTag'));
	* ```
	*/
	insert(tag) {
		const name = tag.name;
		if (name === void 0 || name === "") throw new Error(`Tag ${tag.value} must have a non-empty name`);
		const existing = this._store.tagForValue(tag.value);
		if (existing?.name !== void 0 && existing.name !== name) throw new Error(`Attempt to register tag: ${tag.value} '${existing.name}' with different name: '${name}'`);
		this._store.register(Tag.from(tag.value, name));
	}
	/**
	* Insert multiple tags into the registry.
	* Matches Rust's insert_all() method.
	*
	* @param tags - Array of tags to register
	*
	* @example
	* ```typescript
	* const store = new TagsStore();
	* store.insertAll([
	*   createTag(1, 'date'),
	*   createTag(100, 'custom')
	* ]);
	* ```
	*/
	insertAll(tags) {
		for (const tag of tags) this.insert(tag);
	}
	/**
	* Register a custom summarizer function for a tag.
	*
	* The summarizer is adapted and forwarded to the canonical store, so the
	* delegated diagnostic formatters invoke it (with a legacy-shaped node).
	*
	* @param tagValue - The numeric tag value
	* @param summarizer - The summarizer function
	*
	* @example
	* ```typescript
	* store.setSummarizer(1, (cbor, flat) => {
	*   // Custom date formatting
	*   return `Date(${extractCbor(cbor)})`;
	* });
	* ```
	*/
	setSummarizer(tagValue, summarizer) {
		this._legacySummarizers.set(this._valueKey(tagValue), summarizer);
		this._store.setSummarizer(tagValue, (cbor, flat) => {
			const result = summarizer(fromNew(cbor), flat);
			if (result.ok) return result;
			return {
				ok: false,
				error: CborError$1.custom(errorToString(result.error))
			};
		});
	}
	assignedNameForTag(tag) {
		return this._store.tagForValue(tag.value)?.name;
	}
	nameForTag(tag) {
		return this.assignedNameForTag(tag) ?? tag.value.toString();
	}
	tagForValue(value) {
		return toLegacyTag(this._store.tagForValue(value));
	}
	tagForName(name) {
		return toLegacyTag(this._store.tagForName(name));
	}
	nameForValue(value) {
		const tag = this.tagForValue(value);
		return tag !== void 0 ? this.nameForTag(tag) : value.toString();
	}
	summarizer(tag) {
		return this._legacySummarizers.get(this._valueKey(tag));
	}
	_valueKey(value) {
		return value.toString();
	}
};
/**
* Global singleton instance of the tags store.
*/
let globalTagsStore;
/**
* Get the global tags store instance.
*
* Creates the instance on first access, wrapping the canonical package's
* global store so registrations are shared with the delegated formatters.
*
* @returns The global TagsStore instance
*
* @example
* ```typescript
* const store = getGlobalTagsStore();
* store.insert(createTag(999, 'myTag'));
* ```
*/
const getGlobalTagsStore = () => {
	globalTagsStore ??= TagsStore._fromInner(getGlobalTagsStore$1());
	return globalTagsStore;
};
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Hex dump utilities for CBOR data.
*
* Affordances for viewing the encoded binary representation of CBOR as hexadecimal.
* Optionally annotates the output, breaking it up into semantically meaningful lines,
* formatting dates, and adding names of known tags.
*
* The annotated rendering delegates to `@blockchaincommons/dcbor/diagnostic`.
*
* @module dump
*/
/**
* Convert bytes to hex string.
*/
const bytesToHex$2 = (bytes) => {
	return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
};
/**
* Returns the encoded hexadecimal representation of CBOR.
*
* @param cbor - CBOR value to convert
* @returns Hex string
*/
const hex = (cbor) => bytesToHex$2(cborData(cbor));
/**
* Returns the encoded hexadecimal representation of CBOR with options.
*
* Optionally annotates the output, e.g., breaking the output up into
* semantically meaningful lines, formatting dates, and adding names of
* known tags.
*
* @param cbor - CBOR value to convert
* @param opts - Formatting options
* @returns Hex string (possibly annotated)
*/
const hexOpt = (cbor, opts = {}) => {
	if (opts.annotate !== true) return hex(cbor);
	const tagsStore = opts.tagsStore ?? getGlobalTagsStore();
	return delegating(() => hexAnnotated(toNew(cbor), { tagsStore: tagsStore._inner }));
};
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Enhanced diagnostic formatting for CBOR values.
*
* Provides multiple formatting options including
* - Annotated diagnostics with tag names
* - Summarized values using custom summarizers
* - Flat (single-line) vs. pretty (multi-line) formatting
* - Configurable tag store usage
*
* Rendering delegates to `@blockchaincommons/dcbor/diagnostic` (which shares
* this module's option vocabulary); summarizers registered through this
* package's `TagsStore` are consulted through the wrapped canonical store.
*
* @module diag
*/
/**
* Convert the legacy tags-store option to the canonical one (unwrap a
* wrapped store; pass the string variants through).
*/
const toBcTagsOpt = (tags) => {
	if (tags instanceof TagsStore) return tags._inner;
	return tags;
};
/**
* Format CBOR value as diagnostic notation with options.
*
* @param cbor - CBOR value to format
* @param opts - Formatting options
* @returns Diagnostic string
*
* @example
* ```typescript
* const value = cbor({ name: 'Alice', age: 30 });
* console.log(diagnosticOpt(value, { flat: true }));
* // {\"name\": \"Alice\", \"age\": 30}
* ```
*/
function diagnosticOpt(cbor, opts) {
	return delegating(() => diagnostic$1(toNew(cbor), {
		annotate: opts?.annotate,
		summarize: opts?.summarize,
		flat: opts?.summarize === true ? true : opts?.flat,
		tags: toBcTagsOpt(opts?.tags)
	}));
}
/**
* Format CBOR value as standard diagnostic notation.
*
* @param cbor - CBOR value to format
* @returns Diagnostic string (pretty-printed with multiple lines for complex structures)
*
* @example
* ```typescript
* const value = cbor([1, 2, 3]);
* console.log(diagnostic(value));
* // For simple arrays: "[1, 2, 3]"
* // For nested structures: multi-line formatted output
* ```
*/
function diagnostic(cbor) {
	return diagnosticOpt(cbor);
}
/**
* Checks if the simple value is a floating point number.
*/
const isFloat$1 = (simple) => simple.type === "Float";
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* dCBOR decoding — delegates to `@blockchaincommons/dcbor`, the canonical
* implementation, then rewraps the result into this package's legacy node
* shape. All deterministic-encoding enforcement (canonical numeric forms,
* NFC text, map-key order, no trailing bytes) happens in the canonical
* decoder; thrown errors are translated back to the legacy `CborError`.
*/
function decodeCbor(data) {
	return fromNew(delegating(() => decodeCbor$1(data)));
}
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Convenience utilities for working with CBOR values.
*
* Provides type-safe helpers for checking types, extracting values,
* and working with arrays, maps, and tagged values.
*
* @module conveniences
*/
/**
* Extract native JavaScript value from CBOR.
* Converts CBOR types to their JavaScript equivalents.
*/
const extractCbor = (cbor) => {
	let c;
	if (cbor instanceof Uint8Array) c = decodeCbor(cbor);
	else c = cbor;
	switch (c.type) {
		case MajorType.Unsigned: return c.value;
		case MajorType.Negative: if (typeof c.value === "bigint") return -c.value - 1n;
		else return -c.value - 1;
		case MajorType.ByteString: return c.value;
		case MajorType.Text: return c.value;
		case MajorType.Array: return c.value.map(extractCbor);
		case MajorType.Map: return c.value;
		case MajorType.Tagged: return c;
		case MajorType.Simple:
			if (c.value.type === "True") return true;
			if (c.value.type === "False") return false;
			if (c.value.type === "Null") return null;
			if (c.value.type === "Float") return c.value.value;
			return c;
	}
};
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Map Support in dCBOR
*
* A deterministic CBOR map that ensures maps with the same content always
* produce identical binary encodings, regardless of insertion order.
*
* This class keeps the historical `@blockchaincommons/dcbor-compat` map API (Rust-flavored
* `insert`/`containsKey`/`len`/`iter` alongside the JS `Map` vocabulary) but
* stores its entries in a `@blockchaincommons/dcbor` `CborMap` — the
* canonical implementation owns key ordering (lexicographic by encoded CBOR
* bytes), duplicate handling, and the decode-time `setNext` ordering checks.
*
* @module map
*/
/**
* A deterministic CBOR map implementation.
*
* Maps are always encoded with keys sorted lexicographically by their
* encoded CBOR representation, ensuring deterministic encoding.
*/
var CborMap = class CborMap {
	_map;
	/**
	* Creates a new, empty CBOR Map.
	* Optionally initializes from a JavaScript Map.
	*/
	constructor(map) {
		this._map = new CborMap$1();
		if (map !== void 0) for (const [key, value] of map.entries()) this.set(key, value);
	}
	/**
	* The wrapped canonical `@blockchaincommons/dcbor` map.
	* @internal
	*/
	get _inner() {
		return this._map;
	}
	/**
	* Wrap an existing canonical map without copying entries.
	* @internal
	*/
	static _fromInner(inner) {
		const map = new CborMap();
		map._map = inner;
		return map;
	}
	/**
	* Creates a new, empty CBOR Map.
	* Matches Rust's Map::new().
	*/
	static new() {
		return new CborMap();
	}
	/**
	* Inserts a key-value pair into the map.
	* Matches Rust's Map::insert().
	*/
	set(key, value) {
		const keyCbor = cbor(key);
		const valueCbor = cbor(value);
		delegating(() => this._map.set(toNew(keyCbor), toNew(valueCbor)));
	}
	/**
	* Alias for set() to match Rust's insert() method.
	*/
	insert(key, value) {
		this.set(key, value);
	}
	/**
	* Get a value from the map, given a key.
	* Returns undefined if the key is not present in the map.
	* Matches Rust's Map::get().
	*/
	get(key) {
		const stored = delegating(() => this._map.get(toNew(cbor(key))));
		if (stored === void 0) return;
		return extractCbor(fromNew(stored));
	}
	/**
	* Get a value from the map, given a key.
	* Throws an error if the key is not present.
	* Matches Rust's Map::extract().
	*/
	extract(key) {
		const value = this.get(key);
		if (value === void 0) throw new CborError({ type: "MissingMapKey" });
		return value;
	}
	/**
	* Tests if the map contains a key.
	* Matches Rust's Map::contains_key().
	*/
	containsKey(key) {
		return delegating(() => this._map.has(toNew(cbor(key))));
	}
	delete(key) {
		return delegating(() => this._map.delete(toNew(cbor(key))));
	}
	has(key) {
		return this.containsKey(key);
	}
	clear() {
		this._map.clear();
	}
	/**
	* Returns the number of entries in the map.
	* Matches Rust's Map::len().
	*/
	get length() {
		return this._map.size;
	}
	/**
	* Alias for length to match JavaScript Map API.
	* Also matches Rust's Map::len().
	*/
	get size() {
		return this._map.size;
	}
	/**
	* Returns the number of entries in the map.
	* Matches Rust's Map::len().
	*/
	len() {
		return this._map.size;
	}
	/**
	* Checks if the map is empty.
	* Matches Rust's Map::is_empty().
	*/
	isEmpty() {
		return this._map.size === 0;
	}
	/**
	* Get the entries of the map as an array.
	* Keys are sorted in lexicographic order of their encoded CBOR bytes.
	*/
	get entriesArray() {
		const entries = [];
		for (const [key, value] of this._map.entries()) entries.push({
			key: fromNew(key),
			value: fromNew(value)
		});
		return entries;
	}
	/**
	* Gets an iterator over the entries of the CBOR map, sorted by key.
	* Key sorting order is lexicographic by the key's binary-encoded CBOR.
	* Matches Rust's Map::iter().
	*/
	iter() {
		return this.entriesArray;
	}
	/**
	* Returns an iterator of [key, value] tuples for JavaScript Map API compatibility.
	* This matches the standard JavaScript Map.entries() method behavior.
	*/
	*entries() {
		for (const entry of this.entriesArray) yield [entry.key, entry.value];
	}
	/**
	* Inserts the next key-value pair into the map during decoding.
	* This is used for efficient map building during CBOR decoding.
	* Throws if the key is not in ascending order or is a duplicate.
	* Matches Rust's Map::insert_next().
	*/
	setNext(key, value) {
		const keyCbor = cbor(key);
		const valueCbor = cbor(value);
		delegating(() => this._map.setNext(toNew(keyCbor), toNew(valueCbor)));
	}
	get debug() {
		return `map({${this.entriesArray.map(CborMap.entryDebug).join(", ")}})`;
	}
	get diagnostic() {
		return `{${this.entriesArray.map(CborMap.entryDiagnostic).join(", ")}}`;
	}
	static entryDebug(entry) {
		const keyDebug = CborMap.formatDebug(entry.key);
		const valueDebug = CborMap.formatDebug(entry.value);
		return `0x${bytesToHex$2(encodeCbor$1(entry.key))}: (${keyDebug}, ${valueDebug})`;
	}
	static formatDebug(cbor) {
		switch (cbor.type) {
			case MajorType.Unsigned: return `unsigned(${cbor.value})`;
			case MajorType.Negative: return `negative(${typeof cbor.value === "bigint" ? -cbor.value - 1n : -cbor.value - 1})`;
			case MajorType.ByteString: return `bytes(${bytesToHex$2(cbor.value)})`;
			case MajorType.Text: return `text("${cbor.value}")`;
			case MajorType.Array: return `array([${cbor.value.map(CborMap.formatDebug).join(", ")}])`;
			case MajorType.Map: return cbor.value.debug;
			case MajorType.Tagged: return `tagged(${cbor.tag}, ${CborMap.formatDebug(cbor.value)})`;
			case MajorType.Simple: {
				const simple = cbor.value;
				if (typeof simple === "object" && simple !== null && "type" in simple) switch (simple.type) {
					case "True": return "simple(true)";
					case "False": return "simple(false)";
					case "Null": return "simple(null)";
					case "Float": return `simple(${simple.value})`;
				}
				return "simple";
			}
			default: return diagnostic(cbor);
		}
	}
	static entryDiagnostic(entry) {
		return `${diagnostic(entry.key)}: ${diagnostic(entry.value)}`;
	}
	*[Symbol.iterator]() {
		for (const entry of this.entriesArray) yield [entry.key, entry.value];
	}
	toMap() {
		const map = /* @__PURE__ */ new Map();
		for (const entry of this.entriesArray) map.set(extractCbor(entry.key), extractCbor(entry.value));
		return map;
	}
};
/**
* Clone helper used to give each descendant subtree an independent copy of
* the post-visit state — mirrors Rust `State: Clone` + `state.clone()` per
* child in `walk.rs`. Falls back to the value as-is for primitives (which
* don't need cloning) and uses `structuredClone` for objects.
*/
const cloneState = (s) => {
	if (s === null) return s;
	const t = typeof s;
	if (t !== "object" && t !== "function") return s;
	return globalThis.structuredClone(s);
};
/**
* Walk a CBOR tree, visiting each element with a visitor function.
*
* The visitor function is called for each element in the tree, in depth-first order.
* State semantics mirror Rust's `walk_internal`:
*
* - The visitor's returned `newState` propagates **down** to descendants of
*   the just-visited node only.
* - Sibling subtrees each receive an independent clone of the parent's
*   post-visit state, so accumulating mutations in one subtree never leak
*   into a sibling.
* - State changes do not propagate **up**: the public `walk` returns `void`.
*
* For maps, the visitor is called with:
* 1. A 'keyvalue' element containing both key and value
* 2. The key individually (if descent wasn't stopped)
* 3. The value individually (if descent wasn't stopped)
*
* @template State - The type of state to pass into each visit
* @param cbor - The CBOR value to traverse
* @param initialState - Initial state value
* @param visitor - Function to call for each element
*/
const walk = (cbor, initialState, visitor) => {
	walkInternal(cbor, 0, { type: "none" }, initialState, visitor);
};
/**
* Internal recursive walk implementation.
*
* @internal
*/
function walkInternal(cbor, level, edge, state, visitor) {
	const [postVisitState, stop] = visitor({
		type: "single",
		cbor
	}, level, edge, state);
	if (stop) return;
	switch (cbor.type) {
		case MajorType.Array:
			walkArray(cbor, level, postVisitState, visitor);
			break;
		case MajorType.Map:
			walkMap(cbor, level, postVisitState, visitor);
			break;
		case MajorType.Tagged: walkTagged(cbor, level, postVisitState, visitor);
	}
}
/**
* Walk an array's elements. Each element is visited with an independent
* clone of `parentState`.
*
* @internal
*/
function walkArray(cbor, level, parentState, visitor) {
	for (let index = 0; index < cbor.value.length; index++) {
		const item = cbor.value[index];
		if (item === void 0) throw new CborError({
			type: "Custom",
			message: `Array element at index ${index} is undefined`
		});
		walkInternal(item, level + 1, {
			type: "array_element",
			index
		}, cloneState(parentState), visitor);
	}
}
/**
* Walk a map's key-value pairs.
*
* Each kv pair receives a clone of `parentState`. If descent isn't stopped,
* the key and value subtrees receive independent clones of the kv-visit's
* post-visit state.
*
* @internal
*/
function walkMap(cbor, level, parentState, visitor) {
	for (const entry of cbor.value.entriesArray) {
		const { key, value } = entry;
		const [kvPostState, kvStop] = visitor({
			type: "keyvalue",
			key,
			value
		}, level + 1, { type: "map_key_value" }, cloneState(parentState));
		if (kvStop) continue;
		walkInternal(key, level + 1, { type: "map_key" }, cloneState(kvPostState), visitor);
		walkInternal(value, level + 1, { type: "map_value" }, cloneState(kvPostState), visitor);
	}
}
/**
* Walk a tagged value's content. The content visit receives a clone of
* `parentState`.
*
* @internal
*/
function walkTagged(cbor, level, parentState, visitor) {
	walkInternal(cbor.value, level + 1, { type: "tagged_content" }, cloneState(parentState), visitor);
}
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*/
const MajorType = {
	Unsigned: 0,
	Negative: 1,
	ByteString: 2,
	Text: 3,
	Array: 4,
	Map: 5,
	Tagged: 6,
	Simple: 7
};
const MajorTypeNames = {
	[MajorType.Unsigned]: "Unsigned",
	[MajorType.Negative]: "Negative",
	[MajorType.ByteString]: "ByteString",
	[MajorType.Text]: "Text",
	[MajorType.Array]: "Array",
	[MajorType.Map]: "Map",
	[MajorType.Tagged]: "Tagged",
	[MajorType.Simple]: "Simple"
};
const getMajorTypeName = (type) => MajorTypeNames[type];
const isCborNumber = (value) => {
	return typeof value === "number" || typeof value === "bigint";
};
const isCbor = (value) => {
	return value !== null && typeof value === "object" && "isCbor" in value && value.isCbor === true;
};
/**
* Type guard to check if value has taggedCbor method.
*/
/**
* Resolve a numeric/bigint tag value to a `Tag` object, looking up the
* canonical name from the global tags store (matches Rust's
* `try_into_tagged_value` returning the stored `Tag`). Falls back to a
* name-less `{ value }` if no name is registered — never synthesizes a
* placeholder `tag-${value}` string.
*/
const resolveTag = (value) => {
	const stored = getGlobalTagsStore().tagForValue(value);
	if (stored !== void 0) return stored;
	return { value };
};
const hasTaggedCbor = (value) => {
	return typeof value === "object" && value !== null && "taggedCbor" in value && typeof value.taggedCbor === "function";
};
/**
* Type guard to check if value has toCbor method.
*/
const hasToCbor = (value) => {
	return typeof value === "object" && value !== null && "toCbor" in value && typeof value.toCbor === "function";
};
/**
* Convert any value to a CBOR representation.
* Matches Rust's `From` trait implementations for CBOR.
*/
const cbor = (value) => {
	if (isCbor(value) && "toData" in value) return value;
	if (isCbor(value)) return attachMethods(value);
	let result;
	if (isCborNumber(value)) {
		if (typeof value === "number" && Number.isNaN(value)) result = {
			isCbor: true,
			type: MajorType.Simple,
			value: {
				type: "Float",
				value: NaN
			}
		};
		else if (typeof value === "number" && hasFractionalPart(value)) result = {
			isCbor: true,
			type: MajorType.Simple,
			value: {
				type: "Float",
				value
			}
		};
		else if (value == Infinity) result = {
			isCbor: true,
			type: MajorType.Simple,
			value: {
				type: "Float",
				value: Infinity
			}
		};
		else if (value == -Infinity) result = {
			isCbor: true,
			type: MajorType.Simple,
			value: {
				type: "Float",
				value: -Infinity
			}
		};
		else if (typeof value === "number" && !Number.isSafeInteger(value)) {
			const big = BigInt(value);
			if (big >= 0n && big <= 18446744073709551615n) result = {
				isCbor: true,
				type: MajorType.Unsigned,
				value: big
			};
			else if (big < 0n && big >= -18446744073709551616n) result = {
				isCbor: true,
				type: MajorType.Negative,
				value: -big - 1n
			};
			else result = {
				isCbor: true,
				type: MajorType.Simple,
				value: {
					type: "Float",
					value
				}
			};
		} else if (typeof value === "bigint" && (value > 18446744073709551615n || value < -18446744073709551616n)) throw new CborError({ type: "OutOfRange" });
		else if (value < 0) {
			if (typeof value === "bigint") result = {
				isCbor: true,
				type: MajorType.Negative,
				value: -value - 1n
			};
			else result = {
				isCbor: true,
				type: MajorType.Negative,
				value: -value - 1
			};
		} else result = {
			isCbor: true,
			type: MajorType.Unsigned,
			value
		};
	} else if (typeof value === "string") {
		const normalized = value.normalize("NFC");
		result = {
			isCbor: true,
			type: MajorType.Text,
			value: normalized
		};
	} else if (value === null || value === void 0) result = {
		isCbor: true,
		type: MajorType.Simple,
		value: { type: "Null" }
	};
	else if (value === true) result = {
		isCbor: true,
		type: MajorType.Simple,
		value: { type: "True" }
	};
	else if (value === false) result = {
		isCbor: true,
		type: MajorType.Simple,
		value: { type: "False" }
	};
	else if (Array.isArray(value)) result = {
		isCbor: true,
		type: MajorType.Array,
		value: value.map(cbor)
	};
	else if (value instanceof Uint8Array) result = {
		isCbor: true,
		type: MajorType.ByteString,
		value
	};
	else if (value instanceof CborMap) result = {
		isCbor: true,
		type: MajorType.Map,
		value
	};
	else if (value instanceof Map) result = {
		isCbor: true,
		type: MajorType.Map,
		value: new CborMap(value)
	};
	else if (value instanceof Set) result = {
		isCbor: true,
		type: MajorType.Array,
		value: Array.from(value).map((v) => cbor(v))
	};
	else if (hasTaggedCbor(value)) return value.taggedCbor();
	else if (hasToCbor(value)) return value.toCbor();
	else if (typeof value === "object" && value !== null && "tag" in value && "value" in value) {
		const keys = Object.keys(value);
		const objValue = value;
		if (keys.length === 2 && keys.includes("tag") && keys.includes("value")) return taggedCbor(objValue.tag, objValue.value);
		const map = new CborMap();
		for (const [key, val] of Object.entries(value)) map.set(cbor(key), cbor(val));
		result = {
			isCbor: true,
			type: MajorType.Map,
			value: map
		};
	} else if (typeof value === "object" && value !== null) {
		const map = new CborMap();
		for (const [key, val] of Object.entries(value)) map.set(cbor(key), cbor(val));
		result = {
			isCbor: true,
			type: MajorType.Map,
			value: map
		};
	} else throw new CborError({
		type: "Custom",
		message: "Unsupported type for CBOR encoding"
	});
	return attachMethods(result);
};
/**
* Encode a CBOR value to binary data.
* Matches Rust's `CBOR::to_cbor_data()` method.
*
* Delegates to `@blockchaincommons/dcbor` — the canonical encoder — via the
* structural node bridge.
*/
const cborData = (value) => {
	const c = cbor(value);
	return delegating(() => encodeCbor(toNew(c)));
};
const encodeCbor$1 = (value) => {
	return cborData(cbor(value));
};
const taggedCbor = (tag, value) => {
	const tagNumber = typeof tag === "number" || typeof tag === "bigint" ? tag : Number(tag);
	return attachMethods({
		isCbor: true,
		type: MajorType.Tagged,
		tag: tagNumber,
		value: cbor(value)
	});
};
/**
* Attaches instance methods to a CBOR value.
* This enables method chaining like cbor.toHex() instead of Cbor.toHex(cbor).
* @internal
*/
const attachMethods = (obj) => {
	return Object.assign(obj, {
		toData() {
			return cborData(this);
		},
		toHex() {
			return bytesToHex$2(cborData(this));
		},
		toHexAnnotated(tagsStore) {
			tagsStore = tagsStore ?? getGlobalTagsStore();
			return hexOpt(this, {
				annotate: true,
				tagsStore
			});
		},
		toString() {
			return diagnosticOpt(this, { flat: true });
		},
		toDebugString() {
			return diagnosticOpt(this, { flat: false });
		},
		toDiagnostic() {
			return diagnosticOpt(this, { flat: false });
		},
		toDiagnosticAnnotated() {
			return diagnosticOpt(this, { annotate: true });
		},
		isByteString() {
			return this.type === MajorType.ByteString;
		},
		isText() {
			return this.type === MajorType.Text;
		},
		isArray() {
			return this.type === MajorType.Array;
		},
		isMap() {
			return this.type === MajorType.Map;
		},
		isTagged() {
			return this.type === MajorType.Tagged;
		},
		isSimple() {
			return this.type === MajorType.Simple;
		},
		isBool() {
			return this.type === MajorType.Simple && (this.value.type === "True" || this.value.type === "False");
		},
		isTrue() {
			return this.type === MajorType.Simple && this.value.type === "True";
		},
		isFalse() {
			return this.type === MajorType.Simple && this.value.type === "False";
		},
		isNull() {
			return this.type === MajorType.Simple && this.value.type === "Null";
		},
		isNumber() {
			if (this.type === MajorType.Unsigned || this.type === MajorType.Negative) return true;
			if (this.type === MajorType.Simple) return isFloat$1(this.value);
			return false;
		},
		isInteger() {
			return this.type === MajorType.Unsigned || this.type === MajorType.Negative;
		},
		isUnsigned() {
			return this.type === MajorType.Unsigned;
		},
		isNegative() {
			return this.type === MajorType.Negative;
		},
		isNaN() {
			return this.type === MajorType.Simple && this.value.type === "Float" && Number.isNaN(this.value.value);
		},
		isFloat() {
			return this.type === MajorType.Simple && isFloat$1(this.value);
		},
		asByteString() {
			return this.type === MajorType.ByteString ? this.value : void 0;
		},
		asText() {
			return this.type === MajorType.Text ? this.value : void 0;
		},
		asArray() {
			return this.type === MajorType.Array ? this.value : void 0;
		},
		asMap() {
			return this.type === MajorType.Map ? this.value : void 0;
		},
		asTagged() {
			if (this.type !== MajorType.Tagged) return;
			return [resolveTag(this.tag), this.value];
		},
		asBool() {
			if (this.type !== MajorType.Simple) return void 0;
			if (this.value.type === "True") return true;
			if (this.value.type === "False") return false;
		},
		asInteger() {
			if (this.type === MajorType.Unsigned) return this.value;
			else if (this.type === MajorType.Negative) {
				if (typeof this.value === "bigint") return -this.value - 1n;
				else return -this.value - 1;
			}
		},
		asNumber() {
			if (this.type === MajorType.Unsigned) return this.value;
			else if (this.type === MajorType.Negative) {
				if (typeof this.value === "bigint") return -this.value - 1n;
				else return -this.value - 1;
			} else if (this.type === MajorType.Simple && isFloat$1(this.value)) return this.value.value;
		},
		asSimpleValue() {
			return this.type === MajorType.Simple ? this.value : void 0;
		},
		toByteString() {
			if (this.type !== MajorType.ByteString) throw new TypeError(`Cannot convert CBOR to ByteString: expected ByteString type, got ${getMajorTypeName(this.type)}`);
			return this.value;
		},
		toText() {
			if (this.type !== MajorType.Text) throw new TypeError(`Cannot convert CBOR to Text: expected Text type, got ${getMajorTypeName(this.type)}`);
			return this.value;
		},
		toArray() {
			if (this.type !== MajorType.Array) throw new TypeError(`Cannot convert CBOR to Array: expected Array type, got ${getMajorTypeName(this.type)}`);
			return this.value;
		},
		toMap() {
			if (this.type !== MajorType.Map) throw new TypeError(`Cannot convert CBOR to Map: expected Map type, got ${getMajorTypeName(this.type)}`);
			return this.value;
		},
		toTagged() {
			if (this.type !== MajorType.Tagged) throw new TypeError(`Cannot convert CBOR to Tagged: expected Tagged type, got ${getMajorTypeName(this.type)}`);
			return [resolveTag(this.tag), this.value];
		},
		toBool() {
			const result = this.asBool();
			if (result === void 0) throw new TypeError(`Cannot convert CBOR to boolean: expected Simple(True/False) type, got ${getMajorTypeName(this.type)}`);
			return result;
		},
		toInteger() {
			const result = this.asInteger();
			if (result === void 0) throw new TypeError(`Cannot convert CBOR to integer: expected Unsigned or Negative type, got ${getMajorTypeName(this.type)}`);
			return result;
		},
		toNumber() {
			const result = this.asNumber();
			if (result === void 0) throw new TypeError(`Cannot convert CBOR to number: expected Unsigned, Negative, or Float type, got ${getMajorTypeName(this.type)}`);
			return result;
		},
		toSimpleValue() {
			if (this.type !== MajorType.Simple) throw new TypeError(`Cannot convert CBOR to Simple: expected Simple type, got ${getMajorTypeName(this.type)}`);
			return this.value;
		},
		expectTag(expectedTag) {
			if (this.type !== MajorType.Tagged) throw new CborError({ type: "WrongType" });
			const expected = typeof expectedTag === "object" && "value" in expectedTag ? expectedTag : { value: expectedTag };
			if (!tagValuesEqual(this.tag, expected.value)) throw new CborError({
				type: "WrongTag",
				expected,
				actual: { value: this.tag }
			});
			return this.value;
		},
		walk(initialState, visitor) {
			walk(this, initialState, visitor);
		},
		validateTag(expectedTags) {
			if (this.type !== MajorType.Tagged) throw new CborError({ type: "WrongType" });
			const tagValue = this.tag;
			const matchingTag = expectedTags.find((t) => tagValuesEqual(t.value, tagValue));
			if (matchingTag === void 0) throw new CborError({
				type: "WrongTag",
				expected: expectedTags[0],
				actual: { value: tagValue }
			});
			return matchingTag;
		},
		untagged() {
			if (this.type !== MajorType.Tagged) throw new CborError({ type: "WrongType" });
			return this.value;
		}
	});
};
attachMethods({
	isCbor: true,
	type: MajorType.Simple,
	value: { type: "False" }
}), attachMethods({
	isCbor: true,
	type: MajorType.Simple,
	value: { type: "True" }
}), attachMethods({
	isCbor: true,
	type: MajorType.Simple,
	value: { type: "Null" }
}), attachMethods({
	isCbor: true,
	type: MajorType.Simple,
	value: {
		type: "Float",
		value: NaN
	}
});
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Error type for UR encoding/decoding operations.
*/
var URError = class extends Error {
	constructor(message) {
		super(message);
		this.name = "URError";
	}
};
/**
* Error type for invalid UR schemes.
*
* Message matches Rust bc-ur-rust/src/error.rs: `invalid UR scheme`.
*/
var InvalidSchemeError = class extends URError {
	constructor() {
		super("invalid UR scheme");
		this.name = "InvalidSchemeError";
	}
};
/**
* Error type for unspecified UR types.
*
* Message matches Rust bc-ur-rust/src/error.rs: `no UR type specified`.
*/
var TypeUnspecifiedError = class extends URError {
	constructor() {
		super("no UR type specified");
		this.name = "TypeUnspecifiedError";
	}
};
/**
* Error type for invalid UR types.
*
* Message matches Rust bc-ur-rust/src/error.rs: `invalid UR type`.
*/
var InvalidTypeError = class extends URError {
	constructor() {
		super("invalid UR type");
		this.name = "InvalidTypeError";
	}
};
/**
* Error type for non-single-part URs.
*/
var NotSinglePartError = class extends URError {
	constructor() {
		super("UR is not a single-part");
		this.name = "NotSinglePartError";
	}
};
/**
* Error type for unexpected UR types.
*
* Message matches Rust bc-ur-rust/src/error.rs:
* `expected UR type {expected}, but found {found}`.
*/
var UnexpectedTypeError = class extends URError {
	constructor(expected, found) {
		super(`expected UR type ${expected}, but found ${found}`);
		this.name = "UnexpectedTypeError";
	}
};
/**
* Error type for Bytewords encoding/decoding errors.
*
* Message matches Rust bc-ur-rust/src/error.rs: `Bytewords error ({0})`.
*/
var BytewordsError = class extends URError {
	constructor(message) {
		super(`Bytewords error (${message})`);
		this.name = "BytewordsError";
	}
};
/**
* Error type for CBOR encoding/decoding errors.
*
* Message matches Rust bc-ur-rust/src/error.rs: `CBOR error ({0})`.
*/
var CBORError = class extends URError {
	constructor(message) {
		super(`CBOR error (${message})`);
		this.name = "CBORError";
	}
};
/**
* Error type for UR decoder errors.
* Matches Rust's Error::UR(String) variant.
*/
var URDecodeError = class extends URError {
	constructor(message) {
		super(`UR decoder error (${message})`);
		this.name = "URDecodeError";
	}
};
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*/
/**
* Checks if a character is a valid UR type character.
*
* Mirrors Rust's `URTypeChar::is_ur_type` (`bc-ur-rust/src/utils.rs:6-19`):
* lowercase a-z, digits 0-9, and the hyphen `-`.
*/
function isURTypeChar(char) {
	const code = char.charCodeAt(0);
	if (code >= 97 && code <= 122) return true;
	if (code >= 48 && code <= 57) return true;
	if (code === 45) return true;
	return false;
}
/**
* Checks if a string is a valid UR type.
*
* Mirrors Rust's `URTypeString::is_ur_type` (`bc-ur-rust/src/utils.rs:26-32`)
* which is `self.chars().all(...)` — meaning **the empty string is accepted**
* (a vacuously-true `all` over no chars). We mirror that here so that
* `URType::new("")` succeeds in both ports; the round-trip then fails at
* decode-time with `TypeUnspecified`.
*/
function isValidURType(urType) {
	return Array.from(urType).every((char) => isURTypeChar(char));
}
/**
* Bytewords for encoding/decoding bytes as words.
* See: https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-004-bytewords.md
*/
const BYTEWORDS = [
	"able",
	"acid",
	"also",
	"apex",
	"aqua",
	"arch",
	"atom",
	"aunt",
	"away",
	"axis",
	"back",
	"bald",
	"barn",
	"belt",
	"beta",
	"bias",
	"blue",
	"body",
	"brag",
	"brew",
	"bulb",
	"buzz",
	"calm",
	"cash",
	"cats",
	"chef",
	"city",
	"claw",
	"code",
	"cola",
	"cook",
	"cost",
	"crux",
	"curl",
	"cusp",
	"cyan",
	"dark",
	"data",
	"days",
	"deli",
	"dice",
	"diet",
	"door",
	"down",
	"draw",
	"drop",
	"drum",
	"dull",
	"duty",
	"each",
	"easy",
	"echo",
	"edge",
	"epic",
	"even",
	"exam",
	"exit",
	"eyes",
	"fact",
	"fair",
	"fern",
	"figs",
	"film",
	"fish",
	"fizz",
	"flap",
	"flew",
	"flux",
	"foxy",
	"free",
	"frog",
	"fuel",
	"fund",
	"gala",
	"game",
	"gear",
	"gems",
	"gift",
	"girl",
	"glow",
	"good",
	"gray",
	"grim",
	"guru",
	"gush",
	"gyro",
	"half",
	"hang",
	"hard",
	"hawk",
	"heat",
	"help",
	"high",
	"hill",
	"holy",
	"hope",
	"horn",
	"huts",
	"iced",
	"idea",
	"idle",
	"inch",
	"inky",
	"into",
	"iris",
	"iron",
	"item",
	"jade",
	"jazz",
	"join",
	"jolt",
	"jowl",
	"judo",
	"jugs",
	"jump",
	"junk",
	"jury",
	"keep",
	"keno",
	"kept",
	"keys",
	"kick",
	"kiln",
	"king",
	"kite",
	"kiwi",
	"knob",
	"lamb",
	"lava",
	"lazy",
	"leaf",
	"legs",
	"liar",
	"limp",
	"lion",
	"list",
	"logo",
	"loud",
	"love",
	"luau",
	"luck",
	"lung",
	"main",
	"many",
	"math",
	"maze",
	"memo",
	"menu",
	"meow",
	"mild",
	"mint",
	"miss",
	"monk",
	"nail",
	"navy",
	"need",
	"news",
	"next",
	"noon",
	"note",
	"numb",
	"obey",
	"oboe",
	"omit",
	"onyx",
	"open",
	"oval",
	"owls",
	"paid",
	"part",
	"peck",
	"play",
	"plus",
	"poem",
	"pool",
	"pose",
	"puff",
	"puma",
	"purr",
	"quad",
	"quiz",
	"race",
	"ramp",
	"real",
	"redo",
	"rich",
	"road",
	"rock",
	"roof",
	"ruby",
	"ruin",
	"runs",
	"rust",
	"safe",
	"saga",
	"scar",
	"sets",
	"silk",
	"skew",
	"slot",
	"soap",
	"solo",
	"song",
	"stub",
	"surf",
	"swan",
	"taco",
	"task",
	"taxi",
	"tent",
	"tied",
	"time",
	"tiny",
	"toil",
	"tomb",
	"toys",
	"trip",
	"tuna",
	"twin",
	"ugly",
	"undo",
	"unit",
	"urge",
	"user",
	"vast",
	"very",
	"veto",
	"vial",
	"vibe",
	"view",
	"visa",
	"void",
	"vows",
	"wall",
	"wand",
	"warm",
	"wasp",
	"wave",
	"waxy",
	"webs",
	"what",
	"when",
	"whiz",
	"wolf",
	"work",
	"yank",
	"yawn",
	"yell",
	"yoga",
	"yurt",
	"zaps",
	"zero",
	"zest",
	"zinc",
	"zone",
	"zoom"
];
/**
* Create a reverse mapping for fast byteword lookup.
*/
function createBytewordsMap() {
	const map = /* @__PURE__ */ new Map();
	BYTEWORDS.forEach((word, index) => {
		map.set(word, index);
	});
	return map;
}
const BYTEWORDS_MAP = createBytewordsMap();
/**
* Bytemojis for encoding/decoding bytes as emojis.
* See: https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2024-008-bytemoji.md
*/
const BYTEMOJIS = [
	"😀",
	"😂",
	"😆",
	"😉",
	"🙄",
	"😋",
	"😎",
	"😍",
	"😘",
	"😭",
	"🫠",
	"🥱",
	"🤩",
	"😶",
	"🤨",
	"🫥",
	"🥵",
	"🥶",
	"😳",
	"🤪",
	"😵",
	"😡",
	"🤢",
	"😇",
	"🤠",
	"🤡",
	"🥳",
	"🥺",
	"😬",
	"🤑",
	"🙃",
	"🤯",
	"😈",
	"👹",
	"👺",
	"💀",
	"👻",
	"👽",
	"😺",
	"😹",
	"😻",
	"😽",
	"🙀",
	"😿",
	"🫶",
	"🤲",
	"🙌",
	"🤝",
	"👍",
	"👎",
	"👈",
	"👆",
	"💪",
	"👄",
	"🦷",
	"👂",
	"👃",
	"🧠",
	"👀",
	"🤚",
	"🦶",
	"🍎",
	"🍊",
	"🍋",
	"🍌",
	"🍉",
	"🍇",
	"🍓",
	"🫐",
	"🍒",
	"🍑",
	"🍍",
	"🥝",
	"🍆",
	"🥑",
	"🥦",
	"🍅",
	"🌽",
	"🥕",
	"🫒",
	"🧄",
	"🥐",
	"🥯",
	"🍞",
	"🧀",
	"🥚",
	"🍗",
	"🌭",
	"🍔",
	"🍟",
	"🍕",
	"🌮",
	"🥙",
	"🍱",
	"🍜",
	"🍤",
	"🍚",
	"🥠",
	"🍨",
	"🍦",
	"🎂",
	"🪴",
	"🌵",
	"🌱",
	"💐",
	"🍁",
	"🍄",
	"🌹",
	"🌺",
	"🌼",
	"🌻",
	"🌸",
	"💨",
	"🌊",
	"💧",
	"💦",
	"🌀",
	"🌈",
	"🌞",
	"🌝",
	"🌛",
	"🌜",
	"🌙",
	"🌎",
	"💫",
	"⭐",
	"🪐",
	"🌐",
	"💛",
	"💔",
	"💘",
	"💖",
	"💕",
	"🏁",
	"🚩",
	"💬",
	"💯",
	"🚫",
	"🔴",
	"🔷",
	"🟩",
	"🛑",
	"🔺",
	"🚗",
	"🚑",
	"🚒",
	"🚜",
	"🛵",
	"🚨",
	"🚀",
	"🚁",
	"🛟",
	"🚦",
	"🏰",
	"🎡",
	"🎢",
	"🎠",
	"🏠",
	"🔔",
	"🔑",
	"🚪",
	"🪑",
	"🎈",
	"💌",
	"📦",
	"📫",
	"📖",
	"📚",
	"📌",
	"🧮",
	"🔒",
	"💎",
	"📷",
	"⏰",
	"⏳",
	"📡",
	"💡",
	"💰",
	"🧲",
	"🧸",
	"🎁",
	"🎀",
	"🎉",
	"🪭",
	"👑",
	"🫖",
	"🔭",
	"🛁",
	"🏆",
	"🥁",
	"🎷",
	"🎺",
	"🏀",
	"🏈",
	"🎾",
	"🏓",
	"✨",
	"🔥",
	"💥",
	"👕",
	"👚",
	"👖",
	"🩳",
	"👗",
	"👔",
	"🧢",
	"👓",
	"🧶",
	"🧵",
	"💍",
	"👠",
	"👟",
	"🧦",
	"🧤",
	"👒",
	"👜",
	"🐱",
	"🐶",
	"🐭",
	"🐹",
	"🐰",
	"🦊",
	"🐻",
	"🐼",
	"🐨",
	"🐯",
	"🦁",
	"🐮",
	"🐷",
	"🐸",
	"🐵",
	"🐔",
	"🐥",
	"🦆",
	"🦉",
	"🐴",
	"🦄",
	"🐝",
	"🐛",
	"🦋",
	"🐌",
	"🐞",
	"🐢",
	"🐺",
	"🐍",
	"🪽",
	"🐙",
	"🦑",
	"🪼",
	"🦞",
	"🦀",
	"🐚",
	"🦭",
	"🐟",
	"🐬",
	"🐳"
];
/**
* Encodes an arbitrary byte slice as a string of space-separated bytewords.
*
* Mirrors `bytewords::encode_to_words` in `bc-ur-rust` (≥ v0.19.1). Does not
* add a CRC32 checksum — use {@link encodeBytewords} for UR-style encoding.
*/
function encodeToWords(data) {
	const words = [];
	for (const byte of data) {
		const word = BYTEWORDS[byte];
		if (word === void 0) throw new Error(`Invalid byte value: ${byte}`);
		words.push(word);
	}
	return words.join(" ");
}
/**
* Encodes an arbitrary byte slice as a string of space-separated bytemojis.
*
* Mirrors `bytewords::encode_to_bytemojis` in `bc-ur-rust` (≥ v0.19.1).
*/
function encodeToBytemojis(data) {
	const emojis = [];
	for (const byte of data) {
		const emoji = BYTEMOJIS[byte];
		if (emoji === void 0) throw new Error(`Invalid byte value: ${byte}`);
		emojis.push(emoji);
	}
	return emojis.join(" ");
}
/**
* Encodes a 4-byte slice as a string of bytewords for identification.
*
* Thin wrapper over {@link encodeToWords} that enforces the 4-byte length
* contract historically used by `bc-ur-rust`'s `bytewords::identifier`.
*/
function encodeBytewordsIdentifier(data) {
	if (data.length !== 4) throw new Error("Identifier data must be exactly 4 bytes");
	return encodeToWords(data);
}
/**
* Encodes a 4-byte slice as a string of bytemojis for identification.
*
* Thin wrapper over {@link encodeToBytemojis} that enforces the 4-byte length
* contract historically used by `bc-ur-rust`'s `bytewords::bytemoji_identifier`.
*/
function encodeBytemojisIdentifier(data) {
	if (data.length !== 4) throw new Error("Identifier data must be exactly 4 bytes");
	return encodeToBytemojis(data);
}
/**
* Create a reverse mapping for minimal bytewords (first+last char) lookup.
*/
function createMinimalBytewordsMap() {
	const map = /* @__PURE__ */ new Map();
	BYTEWORDS.forEach((word, index) => {
		const minimal = word[0] + word[3];
		map.set(minimal, index);
	});
	return map;
}
const MINIMAL_BYTEWORDS_MAP = createMinimalBytewordsMap();
new Set(BYTEMOJIS);
(() => {
	const map = /* @__PURE__ */ new Map();
	for (const word of BYTEWORDS) map.set(word[0] + word[word.length - 1], word);
	return map;
})();
(() => {
	const map = /* @__PURE__ */ new Map();
	for (const word of BYTEWORDS) map.set(word.slice(0, 3), word);
	return map;
})();
(() => {
	const map = /* @__PURE__ */ new Map();
	for (const word of BYTEWORDS) map.set(word.slice(1), word);
	return map;
})();
/**
* CRC32 lookup table (IEEE polynomial).
*/
const CRC32_TABLE$1 = (() => {
	const table = [];
	for (let i = 0; i < 256; i++) {
		let c = i;
		for (let j = 0; j < 8; j++) c = (c & 1) !== 0 ? 3988292384 ^ c >>> 1 : c >>> 1;
		table.push(c >>> 0);
	}
	return table;
})();
/**
* Calculate CRC32 checksum of data.
*/
function crc32(data) {
	let crc = 4294967295;
	for (const byte of data) crc = (CRC32_TABLE$1[(crc ^ byte) & 255] ^ crc >>> 8) >>> 0;
	return (crc ^ 4294967295) >>> 0;
}
/**
* Convert a 32-bit number to 4 bytes (big-endian).
*/
function uint32ToBytes(value) {
	return new Uint8Array([
		value >>> 24 & 255,
		value >>> 16 & 255,
		value >>> 8 & 255,
		value & 255
	]);
}
/**
* Encode data as bytewords with the specified style.
* Includes CRC32 checksum.
*/
function encodeBytewords(data, style = "minimal") {
	const checksumBytes = uint32ToBytes(crc32(data));
	const dataWithChecksum = new Uint8Array(data.length + 4);
	dataWithChecksum.set(data);
	dataWithChecksum.set(checksumBytes, data.length);
	const words = [];
	for (const byte of dataWithChecksum) {
		const word = BYTEWORDS[byte];
		if (word === void 0) throw new Error(`Invalid byte value: ${byte}`);
		switch (style) {
			case "standard":
				words.push(word);
				break;
			case "uri":
				words.push(word);
				break;
			case "minimal": words.push(word[0] + word[3]);
		}
	}
	switch (style) {
		case "standard": return words.join(" ");
		case "uri": return words.join("-");
		case "minimal": return words.join("");
	}
}
/**
* Returns true if every code unit of `s` is in the ASCII range (0..=127).
*
* Mirrors Rust's `str::is_ascii` used at `ur::bytewords::decode` line 105.
* We test the raw code units (rather than Array.from + codepoint) because
* any non-BMP character has surrogate pairs both ≥ 0xD800, which already
* exceed 0x7F.
*/
function isAsciiString(s) {
	for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) > 127) return false;
	return true;
}
/**
* Decode bytewords string back to data.
* Validates and removes CRC32 checksum.
*
* Errors mirror the upstream Rust `ur::bytewords::Error` enum
* (`ur-0.4.1/src/bytewords.rs`):
* - `NonAscii` — input contains non-ASCII characters (checked first).
* - `InvalidLength` — minimal-style input has odd length.
* - `InvalidWord` — a token does not map to a byteword index.
* - `InvalidChecksum` — the trailing 4-byte CRC32 does not match.
*
* All variants are surfaced as {@link BytewordsError} with the same default
* `Display` strings as Rust (e.g. "invalid checksum", "non-ASCII"), so
* callers can branch on the error class rather than the bare `Error`
* thrown by earlier revisions of this port.
*/
function decodeBytewords(encoded, style = "minimal") {
	if (!isAsciiString(encoded)) throw new BytewordsError("bytewords string contains non-ASCII characters");
	const lowercased = encoded.toLowerCase();
	let bytes;
	switch (style) {
		case "standard":
			bytes = lowercased.split(" ").map((word) => {
				const index = BYTEWORDS_MAP.get(word);
				if (index === void 0) throw new BytewordsError("invalid word");
				return index;
			});
			break;
		case "uri":
			bytes = lowercased.split("-").map((word) => {
				const index = BYTEWORDS_MAP.get(word);
				if (index === void 0) throw new BytewordsError("invalid word");
				return index;
			});
			break;
		case "minimal":
			if (lowercased.length % 2 !== 0) throw new BytewordsError("invalid length");
			bytes = [];
			for (let i = 0; i < lowercased.length; i += 2) {
				const minimal = lowercased.slice(i, i + 2);
				const index = MINIMAL_BYTEWORDS_MAP.get(minimal);
				if (index === void 0) throw new BytewordsError("invalid word");
				bytes.push(index);
			}
	}
	if (bytes.length < 4) throw new BytewordsError("invalid checksum");
	const dataWithChecksum = new Uint8Array(bytes);
	const data = dataWithChecksum.slice(0, -4);
	const checksumBytes = dataWithChecksum.slice(-4);
	if (crc32(data) !== (checksumBytes[0] << 24 | checksumBytes[1] << 16 | checksumBytes[2] << 8 | checksumBytes[3]) >>> 0) throw new BytewordsError("invalid checksum");
	return data;
}
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*/
/**
* Represents a UR (Uniform Resource) type identifier.
*
* Valid UR types contain only lowercase letters, digits, and hyphens.
*
* @example
* ```typescript
* const urType = new URType('test');
* console.log(urType.string()); // "test"
* ```
*/
var URType = class URType {
	_type;
	/**
	* Creates a new URType from the provided type string.
	*
	* @param urType - The UR type as a string
	* @throws {InvalidTypeError} If the type contains invalid characters
	*
	* @example
	* ```typescript
	* const urType = new URType('test');
	* ```
	*/
	constructor(urType) {
		if (!isValidURType(urType)) throw new InvalidTypeError();
		this._type = urType;
	}
	/**
	* Returns the string representation of the URType.
	*
	* @example
	* ```typescript
	* const urType = new URType('test');
	* console.log(urType.string()); // "test"
	* ```
	*/
	string() {
		return this._type;
	}
	/**
	* Checks equality with another URType based on the type string.
	*/
	equals(other) {
		return this._type === other._type;
	}
	/**
	* Returns the string representation.
	*/
	toString() {
		return this._type;
	}
	/**
	* Creates a URType from a string, throwing an error if invalid.
	*
	* @param value - The UR type string
	* @returns A new URType instance
	* @throws {InvalidTypeError} If the type is invalid
	*/
	static from(value) {
		return new URType(value);
	}
	/**
	* Safely creates a URType, returning a typed `Result`-shaped
	* discriminated union instead of throwing.
	*
	* Mirrors Rust `impl TryFrom<&str> for URType` /
	* `impl TryFrom<String> for URType` (`bc-ur-rust/src/ur_type.rs`),
	* which return `Result<URType, Error>`. The TS shape is the
	* idiomatic discriminated form so callers can branch on `ok`
	* without `instanceof`:
	*
	* @example
	* ```typescript
	* const r = URType.tryFrom("test");
	* if (r.ok) {
	*   console.log(r.value.string()); // "test"
	* } else {
	*   console.error(r.error.message);
	* }
	* ```
	*
	* @param value - The UR type string
	* @returns A typed Result: `{ ok: true; value: URType }` on success,
	*   `{ ok: false; error: InvalidTypeError }` on failure.
	*/
	static tryFrom(value) {
		try {
			return {
				ok: true,
				value: new URType(value)
			};
		} catch (error) {
			return {
				ok: false,
				error
			};
		}
	}
};
/**
* A Uniform Resource (UR) is a URI-encoded CBOR object.
*
* URs are defined in [BCR-2020-005: Uniform Resources](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md).
*
* @example
* ```typescript
* import { UR } from '@blockchaincommons/uniform-resources';
* import { CBOR } from '@blockchaincommons/dcbor-compat';
*
* // Create a UR from a CBOR object
* const cbor = CBOR.fromArray([1, 2, 3]);
* const ur = UR.new('test', cbor);
*
* // Encode to string
* const urString = ur.string();
* console.log(urString); // "ur:test/..."
*
* // Decode from string
* const decodedUR = UR.fromURString(urString);
* console.log(decodedUR.urTypeStr()); // "test"
* ```
*/
var UR = class UR {
	_urType;
	_cbor;
	/**
	* Creates a new UR from the provided type and CBOR data.
	*
	* @param urType - The UR type (will be validated)
	* @param cbor - The CBOR data to encode
	* @throws {InvalidTypeError} If the type is invalid
	*
	* @example
	* ```typescript
	* const ur = UR.new('bytes', CBOR.fromString('hello'));
	* ```
	*/
	static new(urType, cbor) {
		const type = typeof urType === "string" ? new URType(urType) : urType;
		return new UR(type, cbor);
	}
	/**
	* Creates a new UR from a UR string.
	*
	* Mirrors Rust's `UR::from_ur_string` (`bc-ur-rust/src/ur.rs:25-38`):
	* 1. lowercase the entire string.
	* 2. strip the `"ur:"` prefix → {@link InvalidSchemeError} if absent.
	* 3. split on the first `/` → {@link TypeUnspecifiedError} if absent.
	* 4. validate the type via {@link URType} → {@link InvalidTypeError}.
	* 5. delegate the data section to the upstream-style decoder, which
	*    classifies the UR as single- or multi-part. Multi-part input is
	*    rejected with {@link NotSinglePartError}.
	* 6. decode the bytewords payload (CRC32 + minimal mapping) →
	*    {@link BytewordsError} on failure.
	* 7. parse the resulting bytes as CBOR → {@link CBORError} on failure.
	*
	* @param urString - A UR string like "ur:test/..."
	* @throws {InvalidSchemeError} If the string doesn't start with "ur:"
	* @throws {TypeUnspecifiedError} If no `/` separator is present
	* @throws {InvalidTypeError} If the type contains invalid characters
	* @throws {NotSinglePartError} If the UR is multi-part
	* @throws {URDecodeError} For upstream-decoder errors (invalid indices, etc.)
	* @throws {BytewordsError} If bytewords decoding fails
	* @throws {CBORError} If CBOR parsing fails
	*
	* @example
	* ```typescript
	* const ur = UR.fromURString('ur:test/lsadaoaxjygonesw');
	* ```
	*/
	static fromURString(urString) {
		const { urType, cbor } = URStringDecoder.decode(urString);
		return new UR(urType, cbor);
	}
	constructor(urType, cbor) {
		this._urType = urType;
		this._cbor = cbor;
	}
	/**
	* Returns the UR type.
	*/
	urType() {
		return this._urType;
	}
	/**
	* Returns the UR type as a string.
	*/
	urTypeStr() {
		return this._urType.string();
	}
	/**
	* Returns the CBOR data.
	*/
	cbor() {
		return this._cbor;
	}
	/**
	* Returns the string representation of the UR (lowercase, suitable for display).
	*
	* @example
	* ```typescript
	* const ur = UR.new('test', CBOR.fromArray([1, 2, 3]));
	* console.log(ur.string()); // "ur:test/lsadaoaxjygonesw"
	* ```
	*/
	string() {
		const cborData = this._cbor.toData();
		return URStringEncoder.encode(this._urType.string(), cborData);
	}
	/**
	* Returns the QR string representation (uppercase, most efficient for QR codes).
	*/
	qrString() {
		return this.string().toUpperCase();
	}
	/**
	* Returns the QR data as bytes (uppercase UR string as UTF-8).
	*
	* Mirrors Rust's `UR::qr_data` (`ur.rs:52`) which does
	* `self.qr_string().as_bytes().to_vec()` — the string's UTF-8 byte
	* representation. We use `TextEncoder` rather than per-codepoint
	* truncation so the behaviour stays correct if the QR string ever
	* contains non-ASCII characters.
	*/
	qrData() {
		return new TextEncoder().encode(this.qrString());
	}
	/**
	* Checks if the UR type matches the expected type.
	*
	* @param expectedType - The expected type
	* @throws {UnexpectedTypeError} If the types don't match
	*/
	checkType(expectedType) {
		const expected = typeof expectedType === "string" ? new URType(expectedType) : expectedType;
		if (!this._urType.equals(expected)) throw new UnexpectedTypeError(expected.string(), this._urType.string());
	}
	/**
	* Returns the string representation.
	*/
	toString() {
		return this.string();
	}
	/**
	* Checks equality with another UR.
	*
	* Mirrors Rust's derived `PartialEq for UR` which compares the inner
	* `ur_type` and the inner `cbor` field directly. We compare CBOR
	* bytewise — `Uint8Array` equality, not `Array#toString` (which would
	* coerce to a comma-joined string and could collide on pathological
	* inputs).
	*/
	equals(other) {
		if (!this._urType.equals(other._urType)) return false;
		const a = this._cbor.toData();
		const b = other._cbor.toData();
		if (a.length !== b.length) return false;
		for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
		return true;
	}
};
/**
* Encodes a UR string using Bytewords minimal encoding.
* This handles single-part URs according to BCR-2020-005.
*/
var URStringEncoder = class {
	static encode(urType, cborData) {
		return `ur:${urType}/${encodeBytewords(cborData, "minimal")}`;
	}
};
/**
* Decodes a UR string back to its components.
*
* Mirrors the validation pipeline of Rust's `UR::from_ur_string`
* (`bc-ur-rust/src/ur.rs:25-38`) plus the upstream `ur::decode`
* (`ur-0.4.1/src/ur.rs:238-266`):
*
*   1. lowercase
*   2. strip `"ur:"`               → {@link InvalidSchemeError}
*   3. find `/`                     → {@link TypeUnspecifiedError}
*   4. validate the type            → {@link InvalidTypeError}
*   5. classify single- vs multi-part by looking at the data section
*   6. multi-part                   → {@link NotSinglePartError}
*   7. invalid multi-part indices   → {@link URDecodeError("Invalid indices")}
*   8. minimal bytewords decode     → {@link BytewordsError}
*   9. CBOR parse                   → {@link CBORError}
*/
var URStringDecoder = class {
	static decode(urString) {
		const lowercased = urString.toLowerCase();
		if (!lowercased.startsWith("ur:")) throw new InvalidSchemeError();
		const afterScheme = lowercased.substring(3);
		const slashIdx = afterScheme.indexOf("/");
		if (slashIdx === -1) throw new TypeUnspecifiedError();
		const typeStr = afterScheme.substring(0, slashIdx);
		const dataSection = afterScheme.substring(slashIdx + 1);
		const urType = new URType(typeStr);
		const lastSlash = dataSection.lastIndexOf("/");
		if (lastSlash !== -1) {
			const indices = dataSection.substring(0, lastSlash);
			const dashIdx = indices.indexOf("-");
			if (dashIdx === -1) throw new URDecodeError("Invalid indices");
			const seqNumStr = indices.substring(0, dashIdx);
			const seqLenStr = indices.substring(dashIdx + 1);
			if (!/^\d+$/.test(seqNumStr) || !/^\d+$/.test(seqLenStr)) throw new URDecodeError("Invalid indices");
			const seqNum = Number(seqNumStr);
			const seqLen = Number(seqLenStr);
			if (seqNum > 65535 || seqLen > 65535) throw new URDecodeError("Invalid indices");
			throw new NotSinglePartError();
		}
		let cborData;
		try {
			cborData = decodeBytewords(dataSection, "minimal");
		} catch (error) {
			if (error instanceof BytewordsError) throw error;
			throw new BytewordsError(error instanceof Error ? error.message : String(error));
		}
		let cbor;
		try {
			cbor = decodeCbor(cborData);
		} catch (error) {
			if (error instanceof CBORError) throw error;
			throw new CBORError(error instanceof Error ? error.message : String(error));
		}
		return {
			urType,
			cbor
		};
	}
};
const CRC32_TABLE$2 = /* @__PURE__ */ new Uint32Array(256);
for (let i = 0; i < 256; i++) {
	let crc = i;
	for (let j = 0; j < 8; j++) crc = (crc & 1) !== 0 ? crc >>> 1 ^ 3988292384 : crc >>> 1;
	CRC32_TABLE$2[i] = crc >>> 0;
}
//#endregion
//#region src/digest.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* SHA-256 cryptographic digest (32 bytes)
*
* Ported from bc-components-rust/src/digest.rs
*
* A `Digest` represents the cryptographic hash of some data. In this
* implementation, SHA-256 is used, which produces a 32-byte hash value.
* Digests are used throughout the crate for data verification and as unique
* identifiers derived from data.
*
* # CBOR Serialization
*
* `Digest` implements the CBOR tagged encoding interfaces, which means it can be
* serialized to and deserialized from CBOR with a specific tag (TAG_DIGEST = 40001).
*
* # UR Serialization
*
* When serialized as a Uniform Resource (UR), a `Digest` is represented as a
* binary blob with the type "digest".
*
* @example
* ```typescript
* import { Digest } from '@blockchaincommons/components';
*
* // Create a digest from a string
* const data = new TextEncoder().encode("hello world");
* const digest = Digest.fromImage(data);
*
* // Validate that the digest matches the original data
* console.log(digest.validate(data)); // true
*
* // Create a digest from a hex string
* const hexString = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
* const digest2 = Digest.fromHex(hexString);
*
* // Retrieve the digest as hex
* console.log(digest2.hex()); // b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
* ```
*/
var Digest = class Digest {
	static DIGEST_SIZE = 32;
	_data;
	constructor(data) {
		if (data.length !== Digest.DIGEST_SIZE) throw CryptoError.invalidSize(Digest.DIGEST_SIZE, data.length);
		this._data = new Uint8Array(data);
	}
	/**
	* Get the digest data.
	*/
	data() {
		return this._data;
	}
	/**
	* Create a Digest from a 32-byte array.
	*/
	static fromData(data) {
		return new Digest(new Uint8Array(data));
	}
	/**
	* Create a Digest from data, validating the length.
	* Alias for fromData for compatibility with Rust API.
	*/
	static fromDataRef(data) {
		return Digest.fromData(data);
	}
	/**
	* Create a Digest from hex string.
	*
	* @throws Error if the hex string is not exactly 64 characters.
	*/
	static fromHex(hex) {
		return new Digest(hexToBytes(hex));
	}
	/**
	* Compute SHA-256 digest of data (called "image" in Rust).
	*
	* @param image - The data to hash
	*/
	static fromImage(image) {
		const hashData = sha256$2(image);
		return new Digest(new Uint8Array(hashData));
	}
	/**
	* Compute SHA-256 digest from multiple data parts.
	*
	* The parts are concatenated and then hashed.
	*
	* @param imageParts - Array of byte arrays to concatenate and hash
	*/
	static fromImageParts(imageParts) {
		const totalLength = imageParts.reduce((sum, part) => sum + part.length, 0);
		const buf = new Uint8Array(totalLength);
		let offset = 0;
		for (const part of imageParts) {
			buf.set(part, offset);
			offset += part.length;
		}
		return Digest.fromImage(buf);
	}
	/**
	* Compute SHA-256 digest from an array of Digests.
	*
	* The digest bytes are concatenated and then hashed.
	*
	* @param digests - Array of Digests to combine
	*/
	static fromDigests(digests) {
		const buf = new Uint8Array(digests.length * Digest.DIGEST_SIZE);
		let offset = 0;
		for (const digest of digests) {
			buf.set(digest._data, offset);
			offset += Digest.DIGEST_SIZE;
		}
		return Digest.fromImage(buf);
	}
	/**
	* Compute SHA-256 digest of data (legacy alias for fromImage).
	* @deprecated Use fromImage instead
	*/
	static hash(data) {
		return Digest.fromImage(data);
	}
	/**
	* Get the raw digest bytes as a copy.
	*/
	toData() {
		return new Uint8Array(this._data);
	}
	/**
	* Get a reference to the raw digest bytes.
	*/
	asBytes() {
		return this._data;
	}
	/**
	* Get hex string representation.
	*/
	hex() {
		return bytesToHex(this._data);
	}
	/**
	* Get hex string representation (alias for hex()).
	*/
	toHex() {
		return this.hex();
	}
	/**
	* Get base64 representation.
	*/
	toBase64() {
		return toBase64(this._data);
	}
	/**
	* Get the first four bytes of the digest as a hexadecimal string.
	* Useful for short descriptions.
	*/
	shortDescription() {
		return bytesToHex(this._data.slice(0, 4));
	}
	/**
	* Validate the digest against the given image.
	*
	* The image is hashed with SHA-256 and compared to this digest.
	* @returns `true` if the digest matches the image.
	*/
	validate(image) {
		return this.equals(Digest.fromImage(image));
	}
	/**
	* Compare with another Digest.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Compare digests lexicographically.
	*/
	compare(other) {
		for (let i = 0; i < this._data.length; i++) {
			const a = this._data[i];
			const b = other._data[i];
			if (a < b) return -1;
			if (a > b) return 1;
		}
		return 0;
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `Digest(${this.hex()})`;
	}
	/**
	* A Digest is its own digest provider - returns itself.
	*/
	digest() {
		return this;
	}
	/**
	* Returns the CBOR tags associated with Digest.
	*/
	cborTags() {
		return tagsForValues([DIGEST.value]);
	}
	/**
	* Returns the untagged CBOR encoding (as a byte string).
	*/
	untaggedCbor() {
		return toByteString(this._data);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates a Digest by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cbor) {
		const data = expectBytes(cbor);
		return Digest.fromData(data);
	}
	/**
	* Creates a Digest by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cbor) {
		validateTag(cbor, this.cborTags());
		const content = extractTaggedContent(cbor);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cbor) {
		return new Digest(new Uint8Array(Digest.DIGEST_SIZE)).fromTaggedCbor(cbor);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cbor = decodeCbor$3(data);
		return Digest.fromTaggedCbor(cbor);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cbor = decodeCbor$3(data);
		const bytes = expectBytes(cbor);
		return Digest.fromData(bytes);
	}
	/**
	* Returns the UR representation of the Digest.
	* Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
	*/
	ur() {
		return UR.new("digest", this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates a Digest from a UR.
	*/
	static fromUR(ur) {
		ur.checkType("digest");
		return new Digest(new Uint8Array(Digest.DIGEST_SIZE)).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates a Digest from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return Digest.fromUR(ur);
	}
	/**
	* Validate the given data against the digest, if any.
	*
	* Returns `true` if the digest is `undefined` or if the digest matches the
	* image's digest. Returns `false` if the digest does not match.
	*/
	static validateOpt(image, digest) {
		if (digest === void 0) return true;
		return digest.validate(image);
	}
};
//#endregion
//#region src/compressed.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* A compressed binary object with integrity verification.
*
* Ported from bc-components-rust/src/compressed.rs
*
* `Compressed` provides a way to efficiently store and transmit binary data
* using the DEFLATE compression algorithm. It includes built-in integrity
* verification through a CRC32 checksum and optional cryptographic digest.
*
* The compression is implemented using the raw DEFLATE format as described in
* [IETF RFC 1951](https://www.ietf.org/rfc/rfc1951.txt).
*
* Features:
* - Automatic compression with configurable compression level
* - Integrity verification via CRC32 checksum
* - Optional cryptographic digest for content identification
* - Smart behavior for small data (stores decompressed if compression would
*   increase size)
* - CBOR serialization/deserialization support
*
* @example
* ```typescript
* import { Compressed } from '@blockchaincommons/components';
*
* // Compress a string
* const data = new TextEncoder().encode(
*   "This is a longer string that should compress well with repeated patterns."
* );
* const compressed = Compressed.fromDecompressedData(data);
*
* // The compressed size should be smaller than the original
* console.log(compressed.compressionRatio()); // < 1.0
*
* // We can recover the original data
* const decompressed = compressed.decompress();
* ```
*/
/**
* A compressed binary object with integrity verification.
*
* Uses DEFLATE compression with CRC32 checksums for integrity verification.
* Optionally includes a cryptographic digest for content identification.
*/
var Compressed = class Compressed {
	/** CRC32 checksum of the decompressed data for integrity verification */
	_checksum;
	/** Size of the original decompressed data in bytes */
	_decompressedSize;
	/** The compressed data (or original data if compression is ineffective) */
	_compressedData;
	/** Optional cryptographic digest of the content */
	_digest;
	constructor(checksum, decompressedSize, compressedData, digest) {
		if (compressedData.length > decompressedSize) throw CryptoError.cryptoOperation("compressed data is larger than decompressed size");
		this._checksum = checksum;
		this._decompressedSize = decompressedSize;
		this._compressedData = new Uint8Array(compressedData);
		this._digest = digest;
	}
	/**
	* Creates a new `Compressed` object with the specified parameters.
	*
	* This is a low-level constructor that allows direct creation of a
	* `Compressed` object without performing compression. It's primarily
	* intended for deserialization or when working with pre-compressed data.
	*
	* @param checksum - CRC32 checksum of the decompressed data
	* @param decompressedSize - Size of the original decompressed data in bytes
	* @param compressedData - The compressed data bytes
	* @param digest - Optional cryptographic digest of the content
	* @returns A new `Compressed` object
	* @throws CryptoError if the compressed data is larger than the decompressed size
	*/
	static new(checksum, decompressedSize, compressedData, digest) {
		return new Compressed(checksum, decompressedSize, compressedData, digest);
	}
	/**
	* Creates a new `Compressed` object by compressing the provided data.
	*
	* This is the primary method for creating compressed data. It automatically
	* handles compression using the DEFLATE algorithm with compression level 6.
	*
	* If the compressed data would be larger than the original data (which can
	* happen with small or already compressed inputs), the original data is
	* stored instead.
	*
	* @param decompressedData - The original data to compress
	* @param digest - Optional cryptographic digest of the content
	* @returns A new `Compressed` object containing the compressed (or original) data
	*/
	static fromDecompressedData(decompressedData, digest) {
		const compressedData = deflateRaw(decompressedData, { level: 6 });
		const checksum = hash_exports.crc32(decompressedData);
		const decompressedSize = decompressedData.length;
		const compressedSize = compressedData.length;
		if (compressedSize !== 0 && compressedSize < decompressedSize) return new Compressed(checksum, decompressedSize, compressedData, digest);
		else return new Compressed(checksum, decompressedSize, new Uint8Array(decompressedData), digest);
	}
	/**
	* Decompresses and returns the original decompressed data.
	*
	* This method performs the reverse of the compression process, restoring
	* the original data. It also verifies the integrity of the data using the
	* stored checksum.
	*
	* @returns The decompressed data
	* @throws CryptoError if the compressed data is corrupt or checksum doesn't match
	*/
	decompress() {
		if (this._compressedData.length >= this._decompressedSize) return new Uint8Array(this._compressedData);
		try {
			const decompressedData = inflateRaw(this._compressedData);
			if (hash_exports.crc32(decompressedData) !== this._checksum) throw CryptoError.cryptoOperation("compressed data checksum mismatch");
			return decompressedData;
		} catch (e) {
			if (e instanceof CryptoError) throw e;
			throw CryptoError.cryptoOperation("corrupt compressed data");
		}
	}
	/**
	* Returns the size of the compressed data in bytes.
	*/
	compressedSize() {
		return this._compressedData.length;
	}
	/**
	* Returns the size of the decompressed data in bytes.
	*/
	decompressedSize() {
		return this._decompressedSize;
	}
	/**
	* Returns the CRC32 checksum of the decompressed data.
	*/
	checksum() {
		return this._checksum;
	}
	/**
	* Returns the compression ratio of the data.
	*
	* The compression ratio is calculated as (compressed size) / (decompressed size),
	* so lower values indicate better compression.
	*
	* @returns A floating-point value representing the compression ratio.
	* - Values less than 1.0 indicate effective compression
	* - Values equal to 1.0 indicate no compression was applied
	* - Values of NaN can occur if the decompressed size is zero
	*/
	compressionRatio() {
		return this._compressedData.length / this._decompressedSize;
	}
	/**
	* Returns the digest of the compressed data, if available.
	*
	* @returns The `Digest` associated with this compressed data, or undefined if none.
	*/
	digestOpt() {
		return this._digest;
	}
	/**
	* Returns whether this compressed data has an associated digest.
	*/
	hasDigest() {
		return this._digest !== void 0;
	}
	/**
	* Returns the cryptographic digest associated with this compressed data.
	*
	* @returns A `Digest`
	* @throws Error if there is no digest associated with this compressed data
	*/
	digest() {
		if (this._digest === void 0) throw new Error("No digest associated with this compressed data");
		return this._digest;
	}
	/**
	* Compare with another Compressed.
	*/
	equals(other) {
		if (this._checksum !== other._checksum) return false;
		if (this._decompressedSize !== other._decompressedSize) return false;
		if (this._compressedData.length !== other._compressedData.length) return false;
		for (let i = 0; i < this._compressedData.length; i++) if (this._compressedData[i] !== other._compressedData[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*/
	toString() {
		const checksumHex = bytesToHex(new Uint8Array([
			this._checksum >>> 24 & 255,
			this._checksum >>> 16 & 255,
			this._checksum >>> 8 & 255,
			this._checksum & 255
		]));
		const digestStr = this._digest?.shortDescription() ?? "None";
		return `Compressed(checksum: ${checksumHex}, size: ${this.compressedSize()}/${this._decompressedSize}, ratio: ${this.compressionRatio().toFixed(2)}, digest: ${digestStr})`;
	}
	/**
	* Returns the CBOR tags associated with Compressed.
	*/
	cborTags() {
		return tagsForValues([COMPRESSED.value]);
	}
	/**
	* Returns the untagged CBOR encoding (as an array).
	*
	* Format:
	* ```
	* [
	*   checksum: uint,
	*   decompressed_size: uint,
	*   compressed_data: bytes,
	*   digest?: Digest  // Optional
	* ]
	* ```
	*/
	untaggedCbor() {
		const elements = [
			this._checksum >>> 0,
			this._decompressedSize,
			toByteString(this._compressedData)
		];
		if (this._digest !== void 0) elements.push(this._digest.taggedCbor());
		return cbor$3(elements);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates a Compressed by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cborValue) {
		const elements = expectArray(cborValue);
		if (elements.length < 3 || elements.length > 4) throw CryptoError.invalidData("invalid number of elements in compressed");
		const checksum = expectInteger(elements[0]);
		const decompressedSize = expectInteger(elements[1]);
		const compressedData = expectBytes(elements[2]);
		let digest;
		if (elements.length === 4) digest = Digest.fromTaggedCbor(elements[3]);
		return Compressed.new(Number(checksum), Number(decompressedSize), compressedData, digest);
	}
	/**
	* Creates a Compressed by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		return Compressed.fromDecompressedData(/* @__PURE__ */ new Uint8Array(0)).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return Compressed.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return Compressed.fromDecompressedData(/* @__PURE__ */ new Uint8Array(0)).fromUntaggedCbor(cborValue);
	}
};
//#endregion
//#region src/hkdf-rng.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* A deterministic random number generator based on HKDF-HMAC-SHA256.
*
* Ported from bc-components-rust/src/hkdf_rng.rs
*
* `HKDFRng` uses the HMAC-based Key Derivation Function (HKDF) to generate
* deterministic random numbers from a combination of key material and salt. It
* serves as a key-stretching mechanism that can produce an arbitrary amount of
* random-looking bytes from a single seed.
*
* Since it produces deterministic output based on the same inputs, it's useful
* for situations where repeatable randomness is required, such as in testing
* or when deterministically deriving keys from a master seed.
*
* Security considerations:
* - The security of the generator depends on the entropy and secrecy of the
*   key material
* - The same key material and salt will always produce the same sequence
* - Use a secure random seed for cryptographic applications
* - Never reuse the same HKDFRng instance for different purposes
*
* The implementation automatically handles buffer management, fetching new
* data using HKDF as needed with an incrementing counter to ensure unique
* output for each request.
*
* @example
* ```typescript
* import { HKDFRng } from '@blockchaincommons/components';
*
* // Create an HKDF-based RNG
* const rng = HKDFRng.new(new TextEncoder().encode("my secure seed"), "wallet-derivation");
*
* // Generate two u32 values
* const random1 = rng.nextU32();
* const random2 = rng.nextU32();
*
* // The same seed and salt will always produce the same sequence
* const rng2 = HKDFRng.new(new TextEncoder().encode("my secure seed"), "wallet-derivation");
* console.log(random1 === rng2.nextU32()); // true
* console.log(random2 === rng2.nextU32()); // true
* ```
*/
const DEFAULT_PAGE_LENGTH = 32;
/**
* A deterministic random number generator based on HKDF-HMAC-SHA256.
*
* Implements the RandomNumberGenerator interface from @blockchaincommons/rand.
*/
var HKDFRng = class HKDFRng {
	/** Internal buffer of generated bytes */
	_buffer;
	/** Current position in the buffer */
	_position;
	/** Source key material (seed) */
	_keyMaterial;
	/** Salt value to combine with the key material */
	_salt;
	/** Length of each "page" of generated data */
	_pageLength;
	/** Current page index */
	_pageIndex;
	constructor(keyMaterial, salt, pageLength) {
		this._buffer = /* @__PURE__ */ new Uint8Array(0);
		this._position = 0;
		this._keyMaterial = new Uint8Array(keyMaterial);
		this._salt = salt;
		this._pageLength = pageLength;
		this._pageIndex = 0;
	}
	/**
	* Creates a new `HKDFRng` with a custom page length.
	*
	* @param keyMaterial - The seed material to derive random numbers from
	* @param salt - A salt value to mix with the key material
	* @param pageLength - The number of bytes to generate in each HKDF call
	* @returns A new `HKDFRng` instance configured with the specified parameters
	*/
	static newWithPageLength(keyMaterial, salt, pageLength) {
		return new HKDFRng(keyMaterial, salt, pageLength);
	}
	/**
	* Creates a new `HKDFRng` with the default page length of 32 bytes.
	*
	* @param keyMaterial - The seed material to derive random numbers from
	* @param salt - A salt value to mix with the key material
	* @returns A new `HKDFRng` instance configured with the specified key material and salt
	*/
	static new(keyMaterial, salt) {
		return HKDFRng.newWithPageLength(keyMaterial, salt, DEFAULT_PAGE_LENGTH);
	}
	/**
	* Refills the internal buffer with new deterministic random bytes.
	*
	* This method is called automatically when the internal buffer is exhausted.
	* It uses HKDF-HMAC-SHA256 to generate a new page of random bytes using the
	* key material, salt, and current page index.
	*/
	fillBuffer() {
		const saltString = `${this._salt}-${this._pageIndex}`;
		const encoder = new TextEncoder();
		this._buffer = hkdfHmacSha256(this._keyMaterial, encoder.encode(saltString), this._pageLength);
		this._position = 0;
		this._pageIndex += 1;
	}
	/**
	* Generates the specified number of deterministic random bytes.
	*
	* @param length - The number of bytes to generate
	* @returns A Uint8Array containing the requested number of deterministic random bytes
	*/
	nextBytes(length) {
		const result = [];
		while (result.length < length) {
			if (this._position >= this._buffer.length) this.fillBuffer();
			const remaining = length - result.length;
			const available = this._buffer.length - this._position;
			const take = Math.min(remaining, available);
			for (let i = 0; i < take; i++) result.push(this._buffer[this._position + i]);
			this._position += take;
		}
		return new Uint8Array(result);
	}
	/**
	* Generates deterministic random bytes.
	*
	* @param length - The number of bytes to generate
	* @returns A Uint8Array of random bytes
	*/
	randomData(length) {
		return this.nextBytes(length);
	}
	/**
	* Fills the provided buffer with deterministic random bytes.
	*
	* @param dest - The buffer to fill with random bytes
	*/
	fillBytes(dest) {
		const bytes = this.nextBytes(dest.length);
		dest.set(bytes);
	}
	/**
	* Generates a random `u32` value.
	*
	* @returns A deterministic random 32-bit unsigned integer
	*/
	nextU32() {
		const bytes = this.nextBytes(4);
		return (bytes[0] | bytes[1] << 8 | bytes[2] << 16 | bytes[3] << 24) >>> 0;
	}
	/**
	* Generates a random `u64` value.
	*
	* Note: JavaScript numbers can only safely represent integers up to 2^53 - 1,
	* so this returns a BigInt for full 64-bit precision.
	*
	* @returns A deterministic random 64-bit unsigned integer as BigInt
	*/
	nextU64() {
		const bytes = this.nextBytes(8);
		let result = BigInt(0);
		for (let i = 7; i >= 0; i--) result = result << BigInt(8) | BigInt(bytes[i]);
		return result;
	}
	/**
	* Attempts to fill the provided buffer with random bytes.
	* This implementation never fails.
	*
	* @param dest - The buffer to fill with random bytes
	*/
	tryFillBytes(dest) {
		this.fillBytes(dest);
	}
	/**
	* Fills the provided buffer with deterministic random bytes.
	* Alias for fillBytes for interface compatibility.
	*
	* @param data - The buffer to fill with random bytes
	*/
	fillRandomData(data) {
		this.fillBytes(data);
	}
	/**
	* Returns the key material (for testing purposes).
	*/
	getKeyMaterial() {
		return new Uint8Array(this._keyMaterial);
	}
	/**
	* Returns the salt (for testing purposes).
	*/
	getSalt() {
		return this._salt;
	}
	/**
	* Returns the page length (for testing purposes).
	*/
	getPageLength() {
		return this._pageLength;
	}
	/**
	* Returns the current page index (for testing purposes).
	*/
	getPageIndex() {
		return this._pageIndex;
	}
};
//#endregion
//#region src/digest-provider.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* DigestProvider interface for types that can provide a cryptographic digest.
*
* Ported from bc-components-rust/src/digest_provider.rs
*
* A type that can provide a single unique digest that characterizes its contents.
* This trait is used to define a common interface for objects that can produce
* a cryptographic digest (hash) of their content.
*
* @example
* ```typescript
* import { DigestProvider, Digest } from '@blockchaincommons/components';
*
* class Document implements DigestProvider {
*   private content: Uint8Array;
*   private cachedDigest?: Digest;
*
*   constructor(content: Uint8Array) {
*     this.content = content;
*   }
*
*   digest(): Digest {
*     if (!this.cachedDigest) {
*       this.cachedDigest = Digest.fromImage(this.content);
*     }
*     return this.cachedDigest;
*   }
* }
* ```
*/
/**
* Helper function to get a digest from a byte array.
* This provides DigestProvider-like functionality for raw bytes.
*
* @param data - The byte array to hash
* @returns A Promise resolving to a Digest of the data
*/
function digestFromBytes(data) {
	return Promise.resolve(Digest.fromImage(data));
}
//#endregion
//#region ../bc-rand-ts/tests/baseline/rand-baseline.mjs
/**
* Wide multiplication for 32-bit unsigned integers.
* @param a - First 32-bit value
* @param b - Second 32-bit value
* @returns Tuple of (low 32 bits, high 32 bits) as bigints
*/
function wideMulU32(a, b) {
	const wide = BigInt(a >>> 0) * BigInt(b >>> 0);
	return [wide & 4294967295n, wide >> 32n];
}
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*/
/**
* Converts a signed integer to its unsigned magnitude.
* For positive numbers, returns the number unchanged.
* For negative numbers, returns the absolute value (wrapping for MIN values).
*
* This matches Rust's wrapping_abs() behavior.
*/
function toMagnitude(value, bits) {
	switch (bits) {
		case 8: {
			const i8Value = value << 24 >> 24;
			return Math.abs(i8Value) & 255;
		}
		case 16: {
			const i16Value = value << 16 >> 16;
			return Math.abs(i16Value) & 65535;
		}
		case 32: {
			const i32Value = value | 0;
			if (i32Value === -2147483648) return 2147483648;
			return Math.abs(i32Value) >>> 0;
		}
	}
}
/**
* Returns a random `u32` value strictly less than `upperBound`.
*/
function rngNextWithUpperBoundU32(rng, upperBound) {
	if (upperBound === 0) throw new Error("upperBound must be non-zero");
	const ub = upperBound >>> 0;
	let random = Number(rng.nextU64() & 4294967295n);
	let m = wideMulU32(random, ub);
	if (Number(m[0]) < ub) {
		const t = (4294967296 - ub >>> 0) % ub;
		while (Number(m[0]) < t) {
			random = Number(rng.nextU64() & 4294967295n);
			m = wideMulU32(random, ub);
		}
	}
	return Number(m[1]);
}
function fromU64ThrowsIfAbove(value, max) {
	if (value > max) throw new Error("from_u64 conversion overflow");
	return value;
}
/** Random `i32` in the closed range [start, end]. */
function rngNextInClosedRangeI32(rng, start, end) {
	if (start > end) throw new Error("start must be less than or equal to end");
	const lo = start | 0;
	const delta = toMagnitude((end | 0) - lo, 32);
	if (delta === 4294967295) return Number(fromU64ThrowsIfAbove(rng.nextU64(), 2147483647n));
	return lo + rngNextWithUpperBoundU32(rng, delta + 1) | 0;
}
/**
* Returns the Web Crypto API for the current environment. Available natively
* in browsers and in Node.js >= 15 via `globalThis.crypto`.
*/
function getCrypto$1() {
	if (typeof globalThis !== "undefined" && globalThis.crypto != null) return globalThis.crypto;
	throw new Error("No crypto API available in this environment");
}
/**
* Generate a Uint8Array of cryptographically strong random bytes of the given size.
*/
function randomData$1(size) {
	const data = new Uint8Array(size);
	fillRandomData$1(data);
	return data;
}
/**
* Fill the given Uint8Array with cryptographically strong random bytes.
*/
function fillRandomData$1(data) {
	getCrypto$1().getRandomValues(data);
}
/**
* Returns the next cryptographically strong random 64-bit unsigned integer.
*
* This mirrors Rust's module-private `secure_random::next_u64()` and is not
* re-exported from the package surface (matches Rust `lib.rs` behavior).
*/
function nextU64$1() {
	const data = /* @__PURE__ */ new Uint8Array(8);
	fillRandomData$1(data);
	return new DataView(data.buffer).getBigUint64(0, true);
}
/**
* A random number generator that can be used as a source of
* cryptographically-strong randomness.
*
* Uses the Web Crypto API (crypto.getRandomValues) which is available
* in both browsers and Node.js >= 15.
*/
var SecureRandomNumberGenerator$1 = class {
	/**
	* Returns the next random 32-bit unsigned integer.
	*
	* Mirrors Rust's `next_u32` impl which returns `next_u64() as u32` —
	* the low 32 bits of a 64-bit draw.
	*/
	nextU32() {
		return Number(this.nextU64() & 4294967295n) >>> 0;
	}
	/**
	* Returns the next random 64-bit unsigned integer as a bigint.
	*/
	nextU64() {
		return nextU64$1();
	}
	/**
	* Fills the given Uint8Array with random bytes.
	*/
	fillBytes(dest) {
		fillRandomData$1(dest);
	}
	/**
	* Returns a Uint8Array of random bytes of the given size.
	*/
	randomData(size) {
		return randomData$1(size);
	}
	/**
	* Fills the given Uint8Array with random bytes.
	*/
	fillRandomData(data) {
		fillRandomData$1(data);
	}
};
//#endregion
//#region src/nonce.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* A random nonce ("number used once").
*
* Ported from bc-components-rust/src/nonce.rs
*
* A `Nonce` is a cryptographic primitive consisting of a random or
* pseudo-random number that is used only once in a cryptographic
* communication. Nonces are often used in authentication protocols, encryption
* algorithms, and digital signatures to prevent replay attacks and ensure
* the uniqueness of encrypted messages.
*
* In this implementation, a `Nonce` is a 12-byte random value. The size is
* chosen to be sufficiently large to prevent collisions while remaining
* efficient for storage and transmission.
*
* # CBOR Serialization
*
* `Nonce` implements the CBOR tagged encoding interfaces, which means it can be
* serialized to and deserialized from CBOR with a specific tag (TAG_NONCE = 40014).
*
* # UR Serialization
*
* When serialized as a Uniform Resource (UR), a `Nonce` is represented as a
* binary blob with the type "nonce".
*
* # Common Uses
*
* - In authenticated encryption schemes like AES-GCM or ChaCha20-Poly1305
* - For initializing counters in counter-mode block ciphers
* - In challenge-response authentication protocols
* - To prevent replay attacks in secure communications
*
* @example
* ```typescript
* import { Nonce } from '@blockchaincommons/components';
*
* // Generate a new random nonce
* const nonce = Nonce.new();
*
* // Create a nonce from a byte array
* const data = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
* const nonce2 = Nonce.fromData(data);
*
* // Access the nonce data
* const nonceData = nonce2.data();
* ```
*/
var Nonce = class Nonce {
	static NONCE_SIZE = 12;
	_data;
	constructor(data) {
		if (data.length !== Nonce.NONCE_SIZE) throw CryptoError.invalidSize(Nonce.NONCE_SIZE, data.length);
		this._data = new Uint8Array(data);
	}
	/**
	* Create a new random nonce.
	*/
	static new() {
		const rng = new SecureRandomNumberGenerator$1();
		return new Nonce(rng.randomData(Nonce.NONCE_SIZE));
	}
	/**
	* Create a new random nonce (alias for compatibility).
	*/
	static random() {
		return Nonce.new();
	}
	/**
	* Restores a nonce from data.
	*/
	static fromData(data) {
		return new Nonce(new Uint8Array(data));
	}
	/**
	* Restores a nonce from data (validates length).
	*/
	static fromDataRef(data) {
		if (data.length !== Nonce.NONCE_SIZE) throw CryptoError.invalidSize(Nonce.NONCE_SIZE, data.length);
		return Nonce.fromData(data);
	}
	/**
	* Create a Nonce from raw bytes (legacy alias).
	*/
	static from(data) {
		return Nonce.fromData(data);
	}
	/**
	* Create a new nonce from the given hexadecimal string.
	*
	* @throws Error if the string is not exactly 24 hexadecimal digits.
	*/
	static fromHex(hex) {
		return new Nonce(hexToBytes(hex));
	}
	/**
	* Generate a random nonce using provided RNG.
	*/
	static randomUsing(rng) {
		return new Nonce(rng.randomData(Nonce.NONCE_SIZE));
	}
	/**
	* Get the data of the nonce.
	*/
	data() {
		return this._data;
	}
	/**
	* Get the nonce as a byte slice.
	*/
	asBytes() {
		return this._data;
	}
	/**
	* Get the raw nonce bytes as a copy.
	*/
	toData() {
		return new Uint8Array(this._data);
	}
	/**
	* The data as a hexadecimal string.
	*/
	hex() {
		return bytesToHex(this._data);
	}
	/**
	* Get hex string representation (alias for hex()).
	*/
	toHex() {
		return this.hex();
	}
	/**
	* Get base64 representation.
	*/
	toBase64() {
		return toBase64(this._data);
	}
	/**
	* Compare with another Nonce.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `Nonce(${this.hex()})`;
	}
	/**
	* Returns the CBOR tags associated with Nonce.
	*/
	cborTags() {
		return tagsForValues([NONCE.value]);
	}
	/**
	* Returns the untagged CBOR encoding (as a byte string).
	*/
	untaggedCbor() {
		return toByteString(this._data);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates a Nonce by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cbor) {
		const data = expectBytes(cbor);
		return Nonce.fromDataRef(data);
	}
	/**
	* Creates a Nonce by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cbor) {
		validateTag(cbor, this.cborTags());
		const content = extractTaggedContent(cbor);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cbor) {
		return new Nonce(new Uint8Array(Nonce.NONCE_SIZE)).fromTaggedCbor(cbor);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cbor = decodeCbor$3(data);
		return Nonce.fromTaggedCbor(cbor);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cbor = decodeCbor$3(data);
		const bytes = expectBytes(cbor);
		return Nonce.fromDataRef(bytes);
	}
	/**
	* Returns the UR representation of the Nonce.
	* Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
	*/
	ur() {
		return UR.new("nonce", this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates a Nonce from a UR.
	*/
	static fromUR(ur) {
		ur.checkType("nonce");
		return new Nonce(new Uint8Array(Nonce.NONCE_SIZE)).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates a Nonce from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return Nonce.fromUR(ur);
	}
};
//#endregion
//#region src/salt.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Random salt used to decorrelate other information.
*
* Ported from bc-components-rust/src/salt.rs
*
* A `Salt` is a cryptographic primitive consisting of random data that is used
* to modify the output of a cryptographic function. Salts are primarily used
* in password hashing to defend against dictionary attacks, rainbow table
* attacks, and pre-computation attacks. They are also used in other
* cryptographic contexts to ensure uniqueness and prevent correlation between
* different parts of a cryptosystem.
*
* Unlike a `Nonce` which has a fixed size, a `Salt` in this implementation can
* have a variable length (minimum 8 bytes). Different salt creation methods
* are provided to generate salts of appropriate sizes for different use cases.
*
* # Minimum Size Requirement
*
* For security reasons, salts must be at least 8 bytes long. Attempting to
* create a salt with fewer than 8 bytes will result in an error.
*
* # CBOR Serialization
*
* `Salt` implements the CBOR tagged encoding interfaces, which means it can be
* serialized to and deserialized from CBOR with a specific tag (TAG_SALT = 40018).
*
* # UR Serialization
*
* When serialized as a Uniform Resource (UR), a `Salt` is represented as a
* binary blob with the type "salt".
*
* # Common Uses
*
* - Password hashing and key derivation functions
* - Preventing correlation in cryptographic protocols
* - Randomizing data before encryption to prevent pattern recognition
* - Adding entropy to improve security in various cryptographic functions
*
* @example
* ```typescript
* import { Salt } from '@blockchaincommons/components';
*
* // Generate a salt with 16 bytes
* const salt = Salt.newWithLen(16);
* console.log(salt.len()); // 16
*
* // Generate a salt proportional to 100 bytes of data
* const salt2 = Salt.newForSize(100);
*
* // Generate a salt with length between 16 and 32 bytes
* const salt3 = Salt.newInRange(16, 32);
* ```
*/
const MIN_SALT_SIZE = 8;
var Salt = class Salt {
	_data;
	constructor(data) {
		this._data = new Uint8Array(data);
	}
	/**
	* Create a new salt from data.
	* Note: Does not validate minimum size to allow for CBOR deserialization.
	*/
	static fromData(data) {
		return new Salt(new Uint8Array(data));
	}
	/**
	* Create a Salt from raw bytes (legacy alias).
	*/
	static from(data) {
		return Salt.fromData(data);
	}
	/**
	* Create a new salt from the given hexadecimal string.
	*/
	static fromHex(hex) {
		return Salt.fromData(hexToBytes(hex));
	}
	/**
	* Create a specific number of bytes of salt.
	*
	* @throws Error if the number of bytes is less than 8.
	*/
	static newWithLen(count) {
		const rng = new SecureRandomNumberGenerator$1();
		return Salt.newWithLenUsing(count, rng);
	}
	/**
	* Create a specific number of bytes of salt using provided RNG.
	*
	* @throws Error if the number of bytes is less than 8.
	*/
	static newWithLenUsing(count, rng) {
		if (count < MIN_SALT_SIZE) throw CryptoError.dataTooShort("salt", MIN_SALT_SIZE, count);
		return new Salt(rng.randomData(count));
	}
	/**
	* Create a number of bytes of salt chosen randomly from the given range.
	*
	* @throws Error if the minimum number of bytes is less than 8.
	*/
	static newInRange(minSize, maxSize) {
		if (minSize < MIN_SALT_SIZE) throw CryptoError.dataTooShort("salt", MIN_SALT_SIZE, minSize);
		const rng = new SecureRandomNumberGenerator$1();
		return Salt.newInRangeUsing(minSize, maxSize, rng);
	}
	/**
	* Create a number of bytes of salt chosen randomly from the given range using provided RNG.
	*
	* @throws Error if the minimum number of bytes is less than 8.
	*/
	static newInRangeUsing(minSize, maxSize, rng) {
		if (minSize < MIN_SALT_SIZE) throw CryptoError.dataTooShort("salt", MIN_SALT_SIZE, minSize);
		const count = rngNextInClosedRangeI32(rng, minSize, maxSize);
		return Salt.newWithLenUsing(count, rng);
	}
	/**
	* Create a number of bytes of salt generally proportionate to the size of
	* the object being salted.
	*/
	static newForSize(size) {
		const rng = new SecureRandomNumberGenerator$1();
		return Salt.newForSizeUsing(size, rng);
	}
	/**
	* Create a number of bytes of salt generally proportionate to the size of
	* the object being salted using provided RNG.
	*/
	static newForSizeUsing(size, rng) {
		const count = size;
		const minSize = Math.max(MIN_SALT_SIZE, Math.ceil(count * .05));
		const maxSize = Math.max(minSize + 8, Math.ceil(count * .25));
		return Salt.newInRangeUsing(minSize, maxSize, rng);
	}
	/**
	* Generate a random salt with specified size (legacy alias for newWithLen).
	*/
	static random(size = 16) {
		return Salt.newWithLen(size);
	}
	/**
	* Generate a random salt with specified size using provided RNG (legacy alias).
	*/
	static randomUsing(rng, size = 16) {
		return Salt.newWithLenUsing(size, rng);
	}
	/**
	* Generate a proportionally-sized salt (legacy alias for newForSize).
	*/
	static proportional(dataSize) {
		return Salt.newForSize(dataSize);
	}
	/**
	* Return the length of the salt.
	*/
	len() {
		return this._data.length;
	}
	/**
	* Return the length of the salt (alias for len).
	*/
	size() {
		return this.len();
	}
	/**
	* Return true if the salt is empty (this is not recommended).
	*/
	isEmpty() {
		return this._data.length === 0;
	}
	/**
	* Return the data of the salt.
	*/
	asBytes() {
		return this._data;
	}
	/**
	* Get the raw salt bytes as a copy.
	*/
	toData() {
		return new Uint8Array(this._data);
	}
	/**
	* The data as a hexadecimal string.
	*/
	hex() {
		return bytesToHex(this._data);
	}
	/**
	* Get hex string representation (alias for hex()).
	*/
	toHex() {
		return this.hex();
	}
	/**
	* Get base64 representation.
	*/
	toBase64() {
		return toBase64(this._data);
	}
	/**
	* Compare with another Salt.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation showing the salt's length.
	*/
	toString() {
		return `Salt(${this.len()})`;
	}
	/**
	* Returns the CBOR tags associated with Salt.
	*/
	cborTags() {
		return tagsForValues([SALT.value]);
	}
	/**
	* Returns the untagged CBOR encoding (as a byte string).
	*/
	untaggedCbor() {
		return toByteString(this._data);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates a Salt by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cbor) {
		const data = expectBytes(cbor);
		return Salt.fromData(data);
	}
	/**
	* Creates a Salt by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cbor) {
		validateTag(cbor, this.cborTags());
		const content = extractTaggedContent(cbor);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cbor) {
		return new Salt(/* @__PURE__ */ new Uint8Array(0)).fromTaggedCbor(cbor);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cbor = decodeCbor$3(data);
		return Salt.fromTaggedCbor(cbor);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cbor = decodeCbor$3(data);
		const bytes = expectBytes(cbor);
		return Salt.fromData(bytes);
	}
	/**
	* Returns the UR representation of the Salt.
	* Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
	*/
	ur() {
		return UR.new("salt", this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates a Salt from a UR.
	*/
	static fromUR(ur) {
		ur.checkType("salt");
		return new Salt(/* @__PURE__ */ new Uint8Array(0)).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates a Salt from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return Salt.fromUR(ur);
	}
};
//#endregion
//#region src/seed.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Cryptographic seed with optional metadata (minimum 16 bytes)
* Ported from bc-components-rust/src/seed.rs
*
* A `Seed` is a source of entropy used to generate cryptographic keys in a
* deterministic manner. Unlike randomly generated keys, seed-derived keys can
* be recreated if you have the original seed, making them useful for backup
* and recovery scenarios.
*
* This implementation of `Seed` includes the random seed data as well as
* optional metadata:
* - A name (for identifying the seed)
* - A note (for storing additional information)
* - A creation date
*
* The minimum seed length is 16 bytes to ensure sufficient security and
* entropy.
*
* # CBOR Serialization
*
* `Seed` implements the CBOR tagged encoding interfaces, which means it can be
* serialized to and deserialized from CBOR with specific tags. The tags used
* are `TAG_SEED` (40300) and the older `TAG_SEED_V1` (300) for backward compatibility.
*
* When serialized to CBOR, a `Seed` is represented as a map with the following
* keys:
* - 1: The seed data (required)
* - 2: The creation date (optional)
* - 3: The name (optional, omitted if empty)
* - 4: The note (optional, omitted if empty)
*
* # UR Serialization
*
* When serialized as a Uniform Resource (UR), a `Seed` is represented with the
* type "seed".
*/
var Seed = class Seed {
	/**
	* Minimum seed length in bytes (matches Rust MIN_SEED_LENGTH).
	*/
	static MIN_SEED_LENGTH = 16;
	_data;
	_name;
	_note;
	_creationDate;
	constructor(data, name, note, creationDate) {
		if (data.length < Seed.MIN_SEED_LENGTH) throw CryptoError.dataTooShort("seed", Seed.MIN_SEED_LENGTH, data.length);
		this._data = new Uint8Array(data);
		this._name = name ?? "";
		this._note = note ?? "";
		this._creationDate = creationDate;
	}
	/**
	* Create a new random seed with default length (16 bytes).
	*
	* Rust equivalent: `Seed::new()`
	*/
	static new() {
		return Seed.newWithLen(Seed.MIN_SEED_LENGTH);
	}
	/**
	* Create a new random seed with a specified length.
	*
	* Rust equivalent: `Seed::new_with_len(count)`
	*
	* @param count - Number of bytes (must be >= 16)
	* @throws CryptoError if count < 16
	*/
	static newWithLen(count) {
		const rng = new SecureRandomNumberGenerator$1();
		return Seed.newWithLenUsing(count, rng);
	}
	/**
	* Create a new random seed with a specified length using provided RNG.
	*
	* Rust equivalent: `Seed::new_with_len_using(count, rng)`
	*
	* @param count - Number of bytes (must be >= 16)
	* @param rng - Random number generator
	* @throws CryptoError if count < 16
	*/
	static newWithLenUsing(count, rng) {
		const data = rng.randomData(count);
		return Seed.newOpt(data, void 0, void 0, void 0);
	}
	/**
	* Create a new seed from data and optional metadata.
	*
	* Rust equivalent: `Seed::new_opt(data, name, note, creation_date)`
	*
	* @param data - Seed bytes (must be >= 16 bytes)
	* @param name - Optional name for the seed
	* @param note - Optional note for the seed
	* @param creationDate - Optional creation date
	* @throws CryptoError if data < 16 bytes
	*/
	static newOpt(data, name, note, creationDate) {
		return new Seed(data, name, note, creationDate);
	}
	/**
	* Create a Seed from raw bytes with optional metadata.
	*
	* Note: The input data is copied to prevent external mutation of the seed's internal state.
	*
	* @param data - Seed bytes (must be >= 16 bytes)
	* @param metadata - Optional metadata object
	*/
	static from(data, metadata) {
		return new Seed(new Uint8Array(data), metadata?.name, metadata?.note, metadata?.createdAt);
	}
	/**
	* Create a Seed from hex string with optional metadata.
	*
	* @param hex - Hex string representing seed bytes
	* @param metadata - Optional metadata object
	*/
	static fromHex(hex, metadata) {
		return Seed.from(hexToBytes(hex), metadata);
	}
	/**
	* Generate a random seed with specified size (default 32 bytes).
	*
	* Convenience method that wraps `newWithLen()`.
	*
	* @param size - Number of bytes (must be >= 16, default 32)
	* @param metadata - Optional metadata object
	*/
	static random(size = 32, metadata) {
		const seed = Seed.newWithLen(size);
		if (metadata?.name !== void 0) seed.setName(metadata.name);
		if (metadata?.note !== void 0) seed.setNote(metadata.note);
		if (metadata?.createdAt !== void 0) seed.setCreationDate(metadata.createdAt);
		return seed;
	}
	/**
	* Generate a random seed using provided RNG.
	*
	* Convenience method that wraps `newWithLenUsing()`.
	*
	* @param rng - Random number generator
	* @param size - Number of bytes (must be >= 16, default 32)
	* @param metadata - Optional metadata object
	*/
	static randomUsing(rng, size = 32, metadata) {
		const seed = Seed.newWithLenUsing(size, rng);
		if (metadata?.name !== void 0) seed.setName(metadata.name);
		if (metadata?.note !== void 0) seed.setNote(metadata.note);
		if (metadata?.createdAt !== void 0) seed.setCreationDate(metadata.createdAt);
		return seed;
	}
	/**
	* Return the data of the seed as a reference to the internal bytes.
	*
	* Rust equivalent: `seed.as_bytes()`
	*
	* Note: Returns a reference to internal data. For a copy, use `toData()`.
	*/
	asBytes() {
		return this._data;
	}
	/**
	* Get the raw seed bytes (copy).
	*
	* Note: Returns a copy to prevent external mutation of the seed's internal state.
	*/
	toData() {
		return new Uint8Array(this._data);
	}
	/**
	* Get hex string representation.
	*/
	toHex() {
		return bytesToHex(this._data);
	}
	/**
	* Get base64 representation.
	*/
	toBase64() {
		return toBase64(this._data);
	}
	/**
	* Get seed size in bytes.
	*/
	size() {
		return this._data.length;
	}
	/**
	* Return the name of the seed.
	*
	* Rust equivalent: `seed.name()` - returns empty string if not set.
	*/
	name() {
		return this._name;
	}
	/**
	* Set the name of the seed.
	*
	* Rust equivalent: `seed.set_name(name)`
	*/
	setName(name) {
		this._name = name;
	}
	/**
	* Return the note of the seed.
	*
	* Rust equivalent: `seed.note()` - returns empty string if not set.
	*/
	note() {
		return this._note;
	}
	/**
	* Set the note of the seed.
	*
	* Rust equivalent: `seed.set_note(note)`
	*/
	setNote(note) {
		this._note = note;
	}
	/**
	* Return the creation date of the seed.
	*
	* Rust equivalent: `seed.creation_date()`
	*/
	creationDate() {
		return this._creationDate;
	}
	/**
	* Set the creation date of the seed.
	*
	* Rust equivalent: `seed.set_creation_date(date)`
	*/
	setCreationDate(creationDate) {
		this._creationDate = creationDate;
	}
	/**
	* Return the creation date of the seed (alias for creationDate).
	*
	* @deprecated Use `creationDate()` for Rust API parity.
	*/
	createdAt() {
		return this.creationDate();
	}
	/**
	* Set the creation date of the seed (alias for setCreationDate).
	*
	* @deprecated Use `setCreationDate()` for Rust API parity.
	*/
	setCreatedAt(date) {
		this.setCreationDate(date);
	}
	/**
	* Get metadata as an object.
	*
	* TypeScript convenience method - returns a snapshot of current metadata.
	*/
	getMetadata() {
		const metadata = {};
		if (this._name.length > 0) metadata.name = this._name;
		if (this._note.length > 0) metadata.note = this._note;
		if (this._creationDate !== void 0) metadata.createdAt = this._creationDate;
		return metadata;
	}
	/**
	* Compare with another Seed.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `Seed(${this.toHex().substring(0, 16)}..., ${this.size()} bytes)`;
	}
	/**
	* Returns unique data from which cryptographic keys can be derived.
	*
	* This implementation returns a copy of the seed data, which can be used
	* as entropy for deriving private keys in various cryptographic schemes.
	*
	* @returns A Uint8Array containing the seed data
	*/
	privateKeyData() {
		return this.toData();
	}
	/**
	* Returns the CBOR tags associated with Seed.
	* Includes TAG_SEED (40300) and TAG_SEED_V1 (300) for backward compatibility.
	*/
	cborTags() {
		return tagsForValues([SEED.value, SEED_V1.value]);
	}
	/**
	* Returns the untagged CBOR encoding (as a map).
	* Map keys:
	* - 1: seed data (required)
	* - 2: creation date (optional)
	* - 3: name (optional, omitted if empty)
	* - 4: note (optional, omitted if empty)
	*/
	untaggedCbor() {
		const map = CborMap$3.new();
		map.insert(1, toByteString(this._data));
		if (this._creationDate !== void 0) {
			const cborDate = CborDate.fromDatetime(this._creationDate);
			map.insert(2, cborDate.taggedCbor());
		}
		if (this._name.length > 0) map.insert(3, this._name);
		if (this._note.length > 0) map.insert(4, this._note);
		return cbor$3(map);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates a Seed by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cborValue) {
		const map = expectMap(cborValue);
		const data = map.extract(1);
		if (data.length === 0) throw CryptoError.invalidData("Seed data is empty");
		let creationDate;
		const dateValue = map.get(2);
		if (dateValue !== void 0) creationDate = CborDate.fromTaggedCbor(cbor$3(dateValue)).datetime();
		const name = map.get(3);
		const note = map.get(4);
		return Seed.newOpt(new Uint8Array(data), name, note, creationDate);
	}
	/**
	* Creates a Seed by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cbor) {
		validateTag(cbor, this.cborTags());
		const content = extractTaggedContent(cbor);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		return Seed.new().fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return Seed.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return Seed.new().fromUntaggedCbor(cborValue);
	}
	/**
	* Returns the UR representation of the Seed.
	* Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
	*/
	ur() {
		return UR.new("seed", this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates a Seed from a UR.
	*/
	static fromUR(ur) {
		ur.checkType("seed");
		return Seed.new().fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates a Seed from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return Seed.fromUR(ur);
	}
};
//#endregion
//#region src/reference.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* A globally unique reference to a globally unique object.
*
* Ported from bc-components-rust/src/reference.rs
*
* `Reference` is a 32-byte fixed-size identifier — typically derived from a
* SHA-256 digest of an object's serialized form, but Rust also exposes
* `Reference::from_data` for cases (like `XID`) where the underlying bytes
* are themselves directly the reference identity.
*
* CDDL:
* ```cddl
* Reference = #6.40025(bytes .size 32)
* ```
*/
/**
* Type guard to check if an object implements the ReferenceProvider interface.
*/
function isReferenceProvider(obj) {
	return typeof obj === "object" && obj !== null && "reference" in obj && typeof obj.reference === "function";
}
/**
* A globally unique reference to a globally unique object.
*
* Internally stores 32 raw bytes (matches Rust's `Reference([u8; 32])`).
* Most callers obtain a `Reference` via `fromDigest`, but `XID` (and similar
* content-addressable types whose bytes _are_ the reference) construct
* via `fromData` directly.
*/
var Reference = class Reference {
	/** Reference data size in bytes — matches Rust `Reference::REFERENCE_SIZE`. */
	static REFERENCE_SIZE = 32;
	_data;
	constructor(data) {
		this._data = data;
	}
	/** Create a Reference from exactly 32 bytes. Mirrors Rust `Reference::from_data`. */
	static fromData(data) {
		if (data.length !== Reference.REFERENCE_SIZE) throw CryptoError.invalidSize(Reference.REFERENCE_SIZE, data.length);
		return new Reference(new Uint8Array(data));
	}
	/** Alias of `fromData` for parity with Rust `from_data_ref`. */
	static fromDataRef(data) {
		return Reference.fromData(data);
	}
	/** Create a Reference from a Digest's underlying bytes. */
	static fromDigest(digest) {
		return new Reference(new Uint8Array(digest.toData()));
	}
	/** Backwards-compatible alias of `fromDigest`. */
	static from(digest) {
		return Reference.fromDigest(digest);
	}
	/** Create a Reference from a 64-character hex string. */
	static fromHex(hex) {
		return Reference.fromData(hexToBytes(hex));
	}
	/**
	* Create a Reference whose bytes are the SHA-256 digest of the input.
	*
	* @deprecated Prefer `Reference.fromDigest(Digest.fromImage(data))` for
	*   clarity, or `Reference.fromData(data)` if `data` is already 32 bytes
	*   that should be wrapped without hashing (matches Rust `from_data`).
	*/
	static hash(data) {
		return Reference.fromDigest(Digest.fromImage(data));
	}
	/** Returns the 32 reference bytes (copy). */
	data() {
		return new Uint8Array(this._data);
	}
	/** Alias of `data()`. */
	asBytes() {
		return this.data();
	}
	/** Returns a `Digest` constructed from these 32 bytes (no hashing). */
	getDigest() {
		return Digest.fromData(this._data);
	}
	/** The full 64-character lowercase hex of the reference. */
	refHex() {
		return bytesToHex(this._data);
	}
	/** The first 4 bytes of the reference. */
	refDataShort() {
		return this._data.slice(0, 4);
	}
	/** The first 4 bytes of the reference, as 8 lowercase hex characters. */
	refHexShort() {
		return bytesToHex(this._data.slice(0, 4));
	}
	/**
	* The first 4 bytes as upper-case bytewords identifier.
	*
	* @param prefix - Optional prefix prepended with a single space.
	*/
	bytewordsIdentifier(prefix) {
		const s = encodeBytewordsIdentifier(this.refDataShort()).toUpperCase();
		return prefix !== void 0 ? `${prefix} ${s}` : s;
	}
	/**
	* The first 4 bytes as upper-case bytemojis identifier.
	*
	* @param prefix - Optional prefix prepended with a single space.
	*/
	bytemojiIdentifier(prefix) {
		const s = encodeBytemojisIdentifier(this.refDataShort()).toUpperCase();
		return prefix !== void 0 ? `${prefix} ${s}` : s;
	}
	/** Backwards-compatible alias of `refHex()`. */
	toHex() {
		return this.refHex();
	}
	/** Backwards-compatible alias of `refHex()`. */
	fullReference() {
		return this.refHex();
	}
	/** Returns the 32 raw bytes encoded as base64. */
	toBase64() {
		return toBase64(this._data);
	}
	/**
	* Returns a short representation of this reference in the requested format.
	*
	* Mirrors the legacy TS API; new code should prefer `refHexShort`,
	* `bytewordsIdentifier`, or `bytemojiIdentifier` directly.
	*/
	shortReference(format = "hex") {
		switch (format) {
			case "hex": return this.refHexShort();
			case "bytewords": return encodeBytewordsIdentifier(this.refDataShort());
			case "bytemojis": return encodeBytemojisIdentifier(this.refDataShort());
			default: {
				const _exhaustive = format;
				throw CryptoError.invalidFormat(`Unknown reference format: ${String(_exhaustive)}`);
			}
		}
	}
	/** A Reference to this Reference (matches Rust's blanket `ReferenceProvider` impl). */
	reference() {
		return Reference.fromDigest(this.digest());
	}
	/**
	* SHA-256 of `taggedCbor().toCborData()`.
	*
	* Matches Rust's `DigestProvider for Reference` —
	* `Digest::from_image(self.tagged_cbor().to_cbor_data())`.
	*/
	digest() {
		return Digest.fromImage(this.taggedCborData());
	}
	cborTags() {
		return tagsForValues([REFERENCE.value]);
	}
	/** Untagged CBOR — a single byte string of the 32 raw bytes. */
	untaggedCbor() {
		return toByteString(this._data);
	}
	taggedCbor() {
		return createTaggedCbor(this);
	}
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	fromUntaggedCbor(cbor) {
		return Reference.fromData(expectBytes(cbor));
	}
	fromTaggedCbor(cbor) {
		validateTag(cbor, this.cborTags());
		return this.fromUntaggedCbor(extractTaggedContent(cbor));
	}
	static fromTaggedCbor(cbor) {
		return new Reference(new Uint8Array(Reference.REFERENCE_SIZE)).fromTaggedCbor(cbor);
	}
	static fromTaggedCborData(data) {
		return Reference.fromTaggedCbor(decodeCbor$3(data));
	}
	static fromUntaggedCborData(data) {
		return new Reference(new Uint8Array(Reference.REFERENCE_SIZE)).fromUntaggedCbor(decodeCbor$3(data));
	}
	static UR_TYPE = "reference";
	/** UR representation — `ur:reference/...`, untagged CBOR payload. */
	ur() {
		return UR.new(Reference.UR_TYPE, this.untaggedCbor());
	}
	urString() {
		return this.ur().string();
	}
	static fromUR(ur) {
		ur.checkType(Reference.UR_TYPE);
		return new Reference(new Uint8Array(Reference.REFERENCE_SIZE)).fromUntaggedCbor(ur.cbor());
	}
	static fromURString(s) {
		return Reference.fromUR(UR.fromURString(s));
	}
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/** Debug-style representation: `Reference(<8-hex-prefix>)`. */
	toString() {
		return `Reference(${this.refHexShort()})`;
	}
};
//#endregion
//#region src/id/arid.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* An "Apparently Random Identifier" (ARID)
*
* Ported from bc-components-rust/src/id/arid.rs
*
* An ARID is a cryptographically strong, universally unique identifier with
* the following properties:
* - Non-correlatability: The sequence of bits cannot be correlated with its
*   referent or any other ARID
* - Neutral semantics: Contains no inherent type information
* - Open generation: Any method of generation is allowed as long as it
*   produces statistically random bits
* - Minimum strength: Must be 256 bits (32 bytes) in length
* - Cryptographic suitability: Can be used as inputs to cryptographic
*   constructs
*
* Unlike digests/hashes which identify a fixed, immutable state of data, ARIDs
* can serve as stable identifiers for mutable data structures.
*
* ARIDs should not be confused with or cast to/from other identifier types
* (like UUIDs), used as nonces, keys, or cryptographic seeds.
*
* As defined in [BCR-2022-002](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2022-002-arid.md).
*
* # CBOR Serialization
*
* `ARID` implements the CBOR tagged encoding interfaces, which means it can be
* serialized to and deserialized from CBOR with a specific tag (TAG_ARID = 40012).
*
* # UR Serialization
*
* When serialized as a Uniform Resource (UR), an `ARID` is represented as a
* binary blob with the type "arid".
*
* @example
* ```typescript
* import { ARID } from '@blockchaincommons/components';
*
* // Create a new random ARID
* const arid = ARID.new();
*
* // Create an ARID from a hex string
* const arid2 = ARID.fromHex("...");
*
* // Get the ARID as hex
* console.log(arid.hex());
* ```
*/
var ARID = class ARID {
	static ARID_SIZE = 32;
	_data;
	constructor(data) {
		if (data.length !== ARID.ARID_SIZE) throw CryptoError.invalidSize(ARID.ARID_SIZE, data.length);
		this._data = new Uint8Array(data);
	}
	/**
	* Create a new random ARID.
	*/
	static new() {
		const rng = new SecureRandomNumberGenerator$1();
		return new ARID(rng.randomData(ARID.ARID_SIZE));
	}
	/**
	* Create a new random ARID (alias for new()).
	*/
	static random() {
		return ARID.new();
	}
	/**
	* Restore an ARID from a fixed-size array of bytes.
	*/
	static fromData(data) {
		return new ARID(new Uint8Array(data));
	}
	/**
	* Create a new ARID from a reference to an array of bytes.
	*/
	static fromDataRef(data) {
		if (data.length !== ARID.ARID_SIZE) throw CryptoError.invalidSize(ARID.ARID_SIZE, data.length);
		return ARID.fromData(data);
	}
	/**
	* Create an ARID from raw bytes (legacy alias).
	*/
	static from(data) {
		return ARID.fromData(data);
	}
	/**
	* Create a new ARID from the given hexadecimal string.
	*
	* @throws Error if the string is not exactly 64 hexadecimal digits.
	*/
	static fromHex(hex) {
		return new ARID(hexToBytes(hex));
	}
	/**
	* Get the data of the ARID as an array of bytes.
	*/
	data() {
		return this._data;
	}
	/**
	* Get the data of the ARID as a byte slice.
	*/
	asBytes() {
		return this._data;
	}
	/**
	* Get the raw ARID bytes as a copy.
	*/
	toData() {
		return new Uint8Array(this._data);
	}
	/**
	* The data as a hexadecimal string.
	*/
	hex() {
		return bytesToHex(this._data);
	}
	/**
	* Get hex string representation (alias for hex()).
	*/
	toHex() {
		return this.hex();
	}
	/**
	* Get base64 representation.
	*/
	toBase64() {
		return toBase64(this._data);
	}
	/**
	* The first four bytes of the ARID as a hexadecimal string.
	*/
	shortDescription() {
		return bytesToHex(this._data.slice(0, 4));
	}
	/**
	* Compare with another ARID.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Compare ARIDs lexicographically.
	*/
	compare(other) {
		for (let i = 0; i < this._data.length; i++) {
			const a = this._data[i];
			const b = other._data[i];
			if (a < b) return -1;
			if (a > b) return 1;
		}
		return 0;
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `ARID(${this.hex()})`;
	}
	/**
	* Returns the CBOR tags associated with ARID.
	*/
	cborTags() {
		return tagsForValues([ARID$1.value]);
	}
	/**
	* Returns the untagged CBOR encoding (as a byte string).
	*/
	untaggedCbor() {
		return toByteString(this._data);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates an ARID by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cbor) {
		const data = expectBytes(cbor);
		return ARID.fromDataRef(data);
	}
	/**
	* Creates an ARID by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cbor) {
		validateTag(cbor, this.cborTags());
		const content = extractTaggedContent(cbor);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cbor) {
		return new ARID(new Uint8Array(ARID.ARID_SIZE)).fromTaggedCbor(cbor);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cbor = decodeCbor$3(data);
		return ARID.fromTaggedCbor(cbor);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cbor = decodeCbor$3(data);
		const bytes = expectBytes(cbor);
		return ARID.fromDataRef(bytes);
	}
	/**
	* Returns the UR representation of the ARID.
	* Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
	*/
	ur() {
		return UR.new("arid", this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates an ARID from a UR.
	*/
	static fromUR(ur) {
		ur.checkType("arid");
		return new ARID(new Uint8Array(ARID.ARID_SIZE)).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates an ARID from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return ARID.fromUR(ur);
	}
	/**
	* Alias for fromURString for Rust API compatibility.
	*/
	static fromUrString(urString) {
		return ARID.fromURString(urString);
	}
};
//#endregion
//#region src/id/uuid.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Universally Unique Identifier (UUID) - 16-byte identifier
*
* UUIDs are 128-bit (16-byte) identifiers that are designed to be unique
* across space and time. This implementation creates type 4 (random) UUIDs,
* following the UUID specification:
*
* - Version field (bits 48-51) is set to 4, indicating a random UUID
* - Variant field (bits 64-65) is set to 2, indicating RFC 4122/DCE 1.1 UUID
*   variant
*
* Unlike ARIDs, UUIDs:
* - Are shorter (128 bits vs 256 bits)
* - Contain version and variant metadata within the identifier
* - Have a canonical string representation with 5 groups separated by hyphens
*
* The canonical textual representation of a UUID takes the form:
* `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` where each `x` is a hexadecimal digit.
*
* # CBOR Serialization
*
* `UUID` is serialized to CBOR with tag 37 (standard UUID tag).
*
* # UR Serialization
*
* When serialized as a Uniform Resource (UR), a `UUID` is represented with the
* type "uuid".
*/
const UUID_SIZE = 16;
var UUID = class UUID {
	static UUID_SIZE = UUID_SIZE;
	_data;
	constructor(data) {
		if (data.length !== UUID_SIZE) throw CryptoError.invalidSize(UUID_SIZE, data.length);
		this._data = new Uint8Array(data);
	}
	/**
	* Create a new random UUID (v4).
	*/
	static new() {
		return UUID.random();
	}
	/**
	* Create a UUID from raw bytes.
	*/
	static fromData(data) {
		return new UUID(new Uint8Array(data));
	}
	/**
	* Restores a UUID from data (validates length).
	*/
	static fromDataRef(data) {
		if (data.length !== UUID_SIZE) throw CryptoError.invalidSize(UUID_SIZE, data.length);
		return UUID.fromData(data);
	}
	/**
	* Create a UUID from raw bytes (legacy alias).
	*/
	static from(data) {
		return UUID.fromData(data);
	}
	/**
	* Create a UUID from hex string (32 hex chars)
	*/
	static fromHex(hex) {
		if (hex.length !== 32) throw CryptoError.invalidFormat(`UUID hex must be 32 characters, got ${hex.length}`);
		const data = /* @__PURE__ */ new Uint8Array(16);
		for (let i = 0; i < 16; i++) data[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
		return new UUID(data);
	}
	/**
	* Create a UUID from string representation (standard UUID format)
	* Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	*/
	static fromString(uuidString) {
		if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(uuidString)) throw CryptoError.invalidFormat(`Invalid UUID format: ${uuidString}`);
		const hex = uuidString.replace(/-/g, "");
		return UUID.fromHex(hex);
	}
	/**
	* Generate a random UUID (v4)
	*/
	static random() {
		const data = new Uint8Array(UUID_SIZE);
		globalThis.crypto.getRandomValues(data);
		data[6] = data[6] & 15 | 64;
		data[8] = data[8] & 63 | 128;
		return new UUID(data);
	}
	/**
	* Get the data of the UUID.
	*/
	data() {
		return this._data;
	}
	/**
	* Get the UUID as a byte slice.
	*/
	asBytes() {
		return this._data;
	}
	/**
	* Get the raw UUID bytes as a copy.
	*/
	toData() {
		return new Uint8Array(this._data);
	}
	/**
	* Get hex string representation (lowercase, matching Rust implementation).
	*/
	hex() {
		return bytesToHex(this._data);
	}
	/**
	* Get hex string representation (alias for hex()).
	*/
	toHex() {
		return this.hex();
	}
	/**
	* Get standard UUID string representation.
	* Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	*/
	toString() {
		const hex = this.toHex();
		return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
	}
	/**
	* Get base64 representation.
	*/
	toBase64() {
		return toBase64(this._data);
	}
	/**
	* Compare with another UUID.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Returns the CBOR tags associated with UUID.
	*/
	cborTags() {
		return tagsForValues([UUID$1.value]);
	}
	/**
	* Returns the untagged CBOR encoding (as a byte string).
	*/
	untaggedCbor() {
		return toByteString(this._data);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates a UUID by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cbor) {
		const data = expectBytes(cbor);
		return UUID.fromDataRef(data);
	}
	/**
	* Creates a UUID by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cbor) {
		validateTag(cbor, this.cborTags());
		const content = extractTaggedContent(cbor);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cbor) {
		return new UUID(new Uint8Array(UUID_SIZE)).fromTaggedCbor(cbor);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cbor = decodeCbor$3(data);
		return UUID.fromTaggedCbor(cbor);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cbor = decodeCbor$3(data);
		const bytes = expectBytes(cbor);
		return UUID.fromDataRef(bytes);
	}
	/**
	* Returns the UR representation of the UUID.
	* Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
	*/
	ur() {
		return UR.new("uuid", this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates a UUID from a UR.
	*/
	static fromUR(ur) {
		ur.checkType("uuid");
		return new UUID(new Uint8Array(UUID_SIZE)).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates a UUID from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return UUID.fromUR(ur);
	}
};
//#endregion
//#region src/id/xid.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* eXtensible Identifier (XID) - 32-byte identifier bound to a public key
*
* A XID is a unique 32-byte identifier for a subject entity (person,
* organization, device, or any other entity). XIDs have the following
* characteristics:
*
* - They're cryptographically tied to a public key at inception (the
*   "inception key")
* - They remain stable throughout their lifecycle even as their keys and
*   permissions change
* - They can be extended to XID documents containing keys, endpoints,
*   permissions, and delegation info
* - They support key rotation and multiple verification schemes
* - They allow for delegation of specific permissions to other entities
* - They can include resolution methods to locate and verify the XID document
*
* A XID is created by taking the SHA-256 hash of the CBOR encoding of a public
* signing key. This ensures the XID is cryptographically tied to the key.
*
* As defined in [BCR-2024-010](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2024-010-xid.md).
*
* # CBOR Serialization
*
* `XID` is serialized to CBOR with tag 40024 (standard XID tag).
*
* # UR Serialization
*
* When serialized as a Uniform Resource (UR), a `XID` is represented with the
* type "xid".
*/
/**
* XID prefix glyph for the upper-case bytewords/bytemoji identifier.
*
* Exported as the single source of truth so dependent packages (`@blockchaincommons/xid`,
* `@blockchaincommons/envelope`, etc.) don't redefine the literal `"🅧"`.
*/
const XID_PREFIX = "🅧";
const XID_SIZE = 32;
/**
* Type guard for {@link XIDProvider}.
*/
function isXIDProvider(obj) {
	return typeof obj === "object" && obj !== null && "xid" in obj && typeof obj.xid === "function";
}
var XID = class XID {
	static XID_SIZE = XID_SIZE;
	_data;
	constructor(data) {
		if (data.length !== XID_SIZE) throw CryptoError.invalidSize(XID_SIZE, data.length);
		this._data = new Uint8Array(data);
	}
	/**
	* Create a new XID from data.
	*/
	static fromData(data) {
		return new XID(new Uint8Array(data));
	}
	/**
	* Create a new XID from data (validates length).
	*
	* Returns error if the data is not the correct length.
	*/
	static fromDataRef(data) {
		if (data.length !== XID_SIZE) throw CryptoError.invalidSize(XID_SIZE, data.length);
		return XID.fromData(data);
	}
	/**
	* Create an XID from raw bytes (legacy alias).
	*/
	static from(data) {
		return XID.fromData(data);
	}
	/**
	* Create an XID from hex string (64 hex characters).
	*/
	static fromHex(hex) {
		if (hex.length !== 64) throw CryptoError.invalidFormat(`XID hex must be 64 characters, got ${hex.length}`);
		const data = /* @__PURE__ */ new Uint8Array(32);
		for (let i = 0; i < 32; i++) data[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
		return new XID(data);
	}
	/**
	* Generate a random XID (for testing purposes).
	*
	* Note: In practice, XIDs should be created from the SHA-256 hash of a
	* public signing key's CBOR encoding.
	*/
	static random() {
		const data = new Uint8Array(XID_SIZE);
		const crypto = globalThis.crypto;
		if (crypto !== void 0 && typeof crypto.getRandomValues === "function") crypto.getRandomValues(data);
		else for (let i = 0; i < XID_SIZE; i++) data[i] = Math.floor(Math.random() * 256);
		return new XID(data);
	}
	/**
	* Create a new XID from the given public key (the "genesis key").
	*
	* The XID is the SHA-256 digest of the CBOR encoding of the public key.
	* This matches Rust's `XID::new(genesis_key: impl AsRef<SigningPublicKey>)`.
	*/
	static newFromSigningKey(signingPublicKey) {
		const keyCborData = signingPublicKey.taggedCborData();
		const digest = Digest.fromImage(keyCborData);
		return XID.fromData(digest.toData());
	}
	/**
	* Mirror of Rust's `From<&SigningPublicKey> for XID`.
	* Equivalent to {@link newFromSigningKey}; provided for API parity.
	*/
	static fromSigningPublicKey(signingPublicKey) {
		return XID.newFromSigningKey(signingPublicKey);
	}
	/**
	* Mirror of Rust's `From<&PublicKeys> for XID`.
	* The XID is derived from the bundle's signing public key.
	*/
	static fromPublicKeys(publicKeys) {
		return XID.newFromSigningKey(publicKeys.signingPublicKey());
	}
	/**
	* Mirror of Rust's `From<&PrivateKeyBase> for XID` (secp256k1 feature).
	* The XID is derived from the schnorr signing public key.
	*/
	static fromPrivateKeyBase(base) {
		return XID.newFromSigningKey(base.schnorrSigningPrivateKey().publicKey());
	}
	/**
	* Mirror of Rust's `TryFrom<&SigningPrivateKey> for XID`.
	* The XID is derived from the corresponding public key.
	*/
	static tryFromSigningPrivateKey(signingPrivateKey) {
		return XID.newFromSigningKey(signingPrivateKey.publicKey());
	}
	/**
	* Validate the XID against the given public key.
	*
	* Returns true if the SHA-256 hash of the key's CBOR encoding matches
	* the XID data. This matches Rust's `XID::validate(&self, key: &SigningPublicKey)`.
	*/
	validate(signingPublicKey) {
		const keyData = signingPublicKey.taggedCborData();
		const digest = Digest.fromImage(keyData);
		return this.equals(XID.fromData(digest.toData()));
	}
	/**
	* Return the data of the XID.
	*/
	data() {
		return this._data;
	}
	/**
	* Get the data of the XID as a byte slice.
	*/
	asBytes() {
		return this._data;
	}
	/**
	* Get a copy of the raw XID bytes.
	*/
	toData() {
		return new Uint8Array(this._data);
	}
	/**
	* Get hex string representation (lowercase, matching Rust implementation).
	*/
	toHex() {
		return bytesToHex(this._data);
	}
	/**
	* Get base64 representation.
	*/
	toBase64() {
		return toBase64(this._data);
	}
	/**
	* Get short description (first 4 bytes) as hex.
	*/
	shortDescription() {
		return bytesToHex(this._data.slice(0, 4));
	}
	/**
	* Get short reference (first 4 bytes) as hex (alias for shortDescription).
	*/
	shortReference() {
		return this.shortDescription();
	}
	/**
	* Get the first four bytes of the XID as upper-case ByteWords.
	*
	* @param prefix - If true, prepends the XID prefix "🅧 "
	* @returns Space-separated uppercase bytewords, e.g., "🅧 URGE DICE GURU IRIS"
	*/
	bytewordsIdentifier(prefix = false) {
		const words = encodeBytewordsIdentifier(this._data.slice(0, 4)).toUpperCase();
		return prefix ? `${XID_PREFIX} ${words}` : words;
	}
	/**
	* Get the first four bytes of the XID as Bytemoji.
	*
	* @param prefix - If true, prepends the XID prefix "🅧 "
	* @returns Space-separated emojis, e.g., "🅧 🐻 😻 🍞 💐"
	*/
	bytemojisIdentifier(prefix = false) {
		const emojis = encodeBytemojisIdentifier(this._data.slice(0, 4));
		return prefix ? `${XID_PREFIX} ${emojis}` : emojis;
	}
	/**
	* XIDProvider impl — returns this XID.
	*
	* Mirrors Rust's blanket `impl XIDProvider for XID`.
	*/
	xid() {
		return this;
	}
	/**
	* ReferenceProvider impl — produces a Reference whose 32 bytes are the
	* raw XID data.
	*
	* Mirrors Rust's `impl ReferenceProvider for XID { fn reference(&self) ->
	* Reference { Reference::from_data(*self.data()) } }` — note this is a
	* direct wrap, not a SHA-256 hash of the XID.
	*/
	reference() {
		return Reference.fromData(this._data);
	}
	/**
	* Compare with another XID.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation (short format, matching Rust Display).
	* Uses first 4 bytes of the XID as hex, e.g., "XID(71274df1)".
	*/
	toString() {
		return `XID(${this.shortDescription()})`;
	}
	/**
	* Returns the CBOR tags associated with XID.
	*/
	cborTags() {
		return tagsForValues([XID$1.value]);
	}
	/**
	* Returns the untagged CBOR encoding (as a byte string).
	*/
	untaggedCbor() {
		return toByteString(this._data);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates a XID by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cbor) {
		const data = expectBytes(cbor);
		return XID.fromDataRef(data);
	}
	/**
	* Creates a XID by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cbor) {
		validateTag(cbor, this.cborTags());
		const content = extractTaggedContent(cbor);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cbor) {
		return new XID(new Uint8Array(XID_SIZE)).fromTaggedCbor(cbor);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cbor = decodeCbor$3(data);
		return XID.fromTaggedCbor(cbor);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cbor = decodeCbor$3(data);
		const bytes = expectBytes(cbor);
		return XID.fromDataRef(bytes);
	}
	/**
	* Returns the UR representation of the XID.
	* Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
	*/
	ur() {
		return UR.new("xid", this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates a XID from a UR.
	*/
	static fromUR(ur) {
		ur.checkType("xid");
		return new XID(new Uint8Array(XID_SIZE)).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates a XID from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return XID.fromUR(ur);
	}
};
//#endregion
//#region src/id/uri.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Uniform Resource Identifier (URI) - String-based identifier
*
* A URI is a string of characters that unambiguously identifies a particular
* resource. This implementation validates URIs using the URL API to ensure
* conformance to RFC 3986.
*
* URIs are commonly used for:
* - Web addresses (URLs like "https://example.com")
* - Resource identifiers in various protocols
* - Namespace identifiers
* - References to resources in distributed systems
*
* # CBOR Serialization
*
* `URI` is serialized to CBOR with tag 32 (standard URI tag).
*
* # UR Serialization
*
* When serialized as a Uniform Resource (UR), a `URI` is represented with the
* type "url".
*/
var URI = class URI {
	_uri;
	constructor(uri) {
		this._uri = uri;
	}
	/**
	* Creates a new `URI` from a string with validation.
	*/
	static new(uri) {
		try {
			new URL(uri);
			return new URI(uri);
		} catch {
			throw CryptoError.invalidData("URI: invalid URI format");
		}
	}
	/**
	* Create a URI from string (legacy alias).
	*/
	static from(uri) {
		return URI.new(uri);
	}
	/**
	* Parse a URI string (alias for new()).
	*/
	static parse(uriString) {
		return URI.new(uriString);
	}
	/**
	* Get the URI as a string reference.
	*/
	asRef() {
		return this._uri;
	}
	/**
	* Get the URI string.
	*/
	toString() {
		return this._uri;
	}
	/**
	* Get the URI string (alias).
	*/
	toURI() {
		return this._uri;
	}
	/**
	* Get the raw URI string.
	*/
	getRaw() {
		return this._uri;
	}
	/**
	* Get scheme (e.g., "http", "https", "urn").
	*/
	scheme() {
		const match = /^([a-z][a-z0-9+.-]*):\/?\/?/i.exec(this._uri);
		return match !== null ? match[1] : null;
	}
	/**
	* Get path component.
	*/
	path() {
		try {
			return new URL(this._uri).pathname;
		} catch {
			return this._uri.replace(/^[a-z][a-z0-9+.-]*:\/?\/?/i, "");
		}
	}
	/**
	* Check if URI is absolute (has a scheme).
	*/
	isAbsolute() {
		return /^[a-z][a-z0-9+.-]*:/i.test(this._uri);
	}
	/**
	* Check if URI is relative.
	*/
	isRelative() {
		return !this.isAbsolute();
	}
	/**
	* Compare with another URI.
	*/
	equals(other) {
		return this._uri === other._uri;
	}
	/**
	* Check if URI starts with given prefix.
	*/
	startsWith(prefix) {
		return this._uri.startsWith(prefix);
	}
	/**
	* Get base64 representation of the URI string.
	*/
	toBase64() {
		return toBase64(new TextEncoder().encode(this._uri));
	}
	/**
	* Get the length of the URI string.
	*/
	length() {
		return this._uri.length;
	}
	/**
	* Returns the CBOR tags associated with URI.
	*/
	cborTags() {
		return tagsForValues([URI$1.value]);
	}
	/**
	* Returns the untagged CBOR encoding (as a text string).
	*/
	untaggedCbor() {
		return cbor$3(this._uri);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates a URI by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cborValue) {
		const text = expectText(cborValue);
		return URI.new(text);
	}
	/**
	* Creates a URI by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		return new URI("https://placeholder.invalid").fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return URI.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		const text = expectText(cborValue);
		return URI.new(text);
	}
	/**
	* Returns the UR representation of the URI.
	* Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
	*/
	ur() {
		return UR.new("url", this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates a URI from a UR.
	*/
	static fromUR(ur) {
		ur.checkType("url");
		return new URI("https://placeholder.invalid").fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates a URI from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return URI.fromUR(ur);
	}
};
//#endregion
//#region src/ed25519/ed25519-public-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Ed25519 public key for EdDSA signature verification (32 bytes)
* Ported from bc-components-rust/src/ed25519/ed25519_public_key.rs
*/
var Ed25519PublicKey = class Ed25519PublicKey {
	_data;
	constructor(data) {
		if (data.length !== 32) throw CryptoError.invalidSize(32, data.length);
		this._data = new Uint8Array(data);
	}
	/**
	* Create an Ed25519PublicKey from raw bytes (32 bytes).
	*/
	static from(data) {
		return new Ed25519PublicKey(data);
	}
	/**
	* Mirror of Rust `Ed25519PublicKey::from_data` — exact-length copy.
	*/
	static fromData(data) {
		return new Ed25519PublicKey(data);
	}
	/**
	* Mirror of Rust `Ed25519PublicKey::from_data_ref` — validates length.
	*/
	static fromDataRef(data) {
		if (data.length !== 32) throw CryptoError.invalidSize(32, data.length);
		return new Ed25519PublicKey(data);
	}
	/**
	* Create an Ed25519PublicKey from hex string.
	*/
	static fromHex(hex) {
		return new Ed25519PublicKey(hexToBytes(hex));
	}
	/** Returns the 32 raw public key bytes (copy). */
	data() {
		return new Uint8Array(this._data);
	}
	/** Alias of {@link data}. */
	asBytes() {
		return this.data();
	}
	/** Backwards-compatible alias of {@link data}. */
	toData() {
		return this.data();
	}
	/**
	* Get hex string representation
	*/
	toHex() {
		return bytesToHex(this._data);
	}
	/**
	* Get base64 representation
	*/
	toBase64() {
		return toBase64(this._data);
	}
	/**
	* Verify a signature using Ed25519
	*/
	verify(message, signature) {
		try {
			if (signature.length !== 64) throw CryptoError.invalidSize(64, signature.length);
			return ed25519Verify(this._data, message, signature);
		} catch (e) {
			throw CryptoError.cryptoOperation(`Ed25519 verification failed: ${String(e)}`);
		}
	}
	/**
	* Compare with another Ed25519PublicKey
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*
	* Mirrors Rust `Display for Ed25519PublicKey`
	* (`bc-components-rust/src/ed25519/ed25519_public_key.rs`):
	*   `Ed25519PublicKey(<ref_hex_short>)`
	* where the reference is computed from the **raw 32-byte data**
	* (not tagged CBOR) — same pattern as SchnorrPublicKey.
	*/
	toString() {
		return `Ed25519PublicKey(${Digest.fromImage(this._data).shortDescription()})`;
	}
};
//#endregion
//#region src/ed25519/ed25519-private-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Ed25519 private key for EdDSA signatures (32 bytes seed)
* Ported from bc-components-rust/src/ed25519_private_key.rs
*/
var Ed25519PrivateKey = class Ed25519PrivateKey {
	seed;
	_publicKey;
	constructor(seed) {
		if (seed.length !== 32) throw CryptoError.invalidSize(32, seed.length);
		this.seed = new Uint8Array(seed);
	}
	/**
	* Create an Ed25519PrivateKey from seed (32 bytes)
	*/
	static from(seed) {
		return new Ed25519PrivateKey(new Uint8Array(seed));
	}
	/**
	* Create an Ed25519PrivateKey from hex string (64 hex characters)
	*/
	static fromHex(hex) {
		return new Ed25519PrivateKey(hexToBytes(hex));
	}
	/**
	* Generate a random Ed25519PrivateKey
	*/
	static random() {
		const rng = new SecureRandomNumberGenerator$1();
		return new Ed25519PrivateKey(rng.randomData(32));
	}
	/**
	* Generate a random Ed25519PrivateKey using provided RNG
	*/
	static randomUsing(rng) {
		return new Ed25519PrivateKey(rng.randomData(32));
	}
	/**
	* Derives an Ed25519 private key from the given key material via
	* HKDF-SHA-256 with salt `"signing"` and empty info (matches Rust
	* `bc_crypto::derive_signing_private_key`).
	*/
	static deriveFromKeyMaterial(keyMaterial) {
		return new Ed25519PrivateKey(deriveSigningPrivateKey(keyMaterial));
	}
	/**
	* Get the raw seed bytes (32 bytes).
	*/
	data() {
		return new Uint8Array(this.seed);
	}
	/** Alias of {@link data}. */
	asBytes() {
		return this.data();
	}
	/** Backwards-compatible alias of {@link data}. */
	toData() {
		return this.data();
	}
	/**
	* Get hex string representation of the seed
	*/
	toHex() {
		return bytesToHex(this.seed);
	}
	/**
	* Get base64 representation of the seed
	*/
	toBase64() {
		return toBase64(this.seed);
	}
	/**
	* Derive the corresponding public key
	*/
	publicKey() {
		if (this._publicKey === void 0) {
			const publicKeyBytes = ed25519PublicKeyFromPrivateKey(this.seed);
			this._publicKey = Ed25519PublicKey.from(publicKeyBytes);
		}
		return this._publicKey;
	}
	/**
	* Sign a message using Ed25519
	*/
	sign(message) {
		try {
			const signature = ed25519Sign(this.seed, message);
			return new Uint8Array(signature);
		} catch (e) {
			throw CryptoError.cryptoOperation(`Ed25519 signing failed: ${String(e)}`);
		}
	}
	/**
	* Compare with another Ed25519PrivateKey
	*/
	equals(other) {
		if (this.seed.length !== other.seed.length) return false;
		for (let i = 0; i < this.seed.length; i++) if (this.seed[i] !== other.seed[i]) return false;
		return true;
	}
	/**
	* Get string representation
	*/
	toString() {
		return `Ed25519PrivateKey(${this.toHex().substring(0, 16)}...)`;
	}
};
//#endregion
//#region src/sr25519/sr25519-public-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Sr25519PublicKey - Public key for Schnorr signatures over Ristretto25519
*
* SR25519 is the signature scheme used by Polkadot/Substrate.
* It is based on Schnorr signatures over the Ristretto group.
*
* Note: SR25519 uses the SigningPublicKey CBOR tag (40022) with discriminator 3.
*
* Ported from bc-components-rust/src/sr25519/sr25519_public_key.rs
*/
/**
* Sr25519PublicKey - Public key for Schnorr signatures over Ristretto25519.
*
* This is the signature scheme used by Polkadot/Substrate.
*/
var Sr25519PublicKey = class Sr25519PublicKey {
	_data;
	constructor(data) {
		if (data.length !== 32) throw new Error(`Sr25519PublicKey must be 32 bytes, got ${data.length}`);
		this._data = new Uint8Array(data);
	}
	/**
	* Create an Sr25519 public key from raw bytes.
	*/
	static from(data) {
		return new Sr25519PublicKey(data);
	}
	/**
	* Create an Sr25519 public key from a hex string.
	*/
	static fromHex(hex) {
		const matches = hex.match(/.{1,2}/g);
		if (matches === null) throw new Error("Invalid hex string");
		const data = new Uint8Array(matches.map((byte) => parseInt(byte, 16)));
		return Sr25519PublicKey.from(data);
	}
	/**
	* Returns the raw key bytes.
	*/
	toData() {
		return new Uint8Array(this._data);
	}
	/**
	* Returns the raw key bytes (alias for toData).
	*/
	asBytes() {
		return this._data;
	}
	/**
	* Returns the hex representation of the key.
	*/
	toHex() {
		return bytesToHex(this._data);
	}
	/**
	* Verify a signature using the default "substrate" context.
	*
	* @param signature - The 64-byte signature
	* @param message - The message that was signed
	* @returns true if the signature is valid
	*/
	verify(signature, message) {
		return this.verifyWithContext(signature, message, SR25519_DEFAULT_CONTEXT);
	}
	/**
	* Verify a signature using a custom context.
	*
	* The underlying `@scure/sr25519` library hard-codes the `"substrate"`
	* signing context. To avoid silently accepting/rejecting cross-platform
	* signatures, this method throws when called with any other context —
	* matching the symmetric guard in `Sr25519PrivateKey.signWithContext`.
	*
	* @param signature - The 64-byte signature
	* @param message - The message that was signed
	* @param context - The signing context (must equal `SR25519_DEFAULT_CONTEXT`)
	* @returns true if the signature is valid
	* @throws CryptoError if `context` is not the substrate default
	*/
	verifyWithContext(signature, message, context) {
		if (!bytesEqual(context, SR25519_DEFAULT_CONTEXT)) throw CryptoError.cryptoOperation("Sr25519: only the default substrate context is supported by the underlying library");
		try {
			return sr25519.verify(message, signature, this._data);
		} catch {
			return false;
		}
	}
	/**
	* Compare with another Sr25519PublicKey.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `Sr25519PublicKey(${bytesToHex(this._data).substring(0, 16)}...)`;
	}
};
//#endregion
//#region src/sr25519/sr25519-private-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Sr25519PrivateKey - Schnorr signatures over Ristretto25519
*
* SR25519 is the signature scheme used by Polkadot/Substrate.
* It is based on Schnorr signatures over the Ristretto group.
*
* Key sizes:
* - Private key (seed): 32 bytes
* - Public key: 32 bytes
* - Signature: 64 bytes
*
* Note: SR25519 uses the SigningPrivateKey CBOR tag (40021) with discriminator 3.
*
* Ported from bc-components-rust/src/sr25519/sr25519_private_key.rs
*/
/** Size of SR25519 private key (seed) in bytes */
const SR25519_PRIVATE_KEY_SIZE = 32;
/** Size of SR25519 public key in bytes */
const SR25519_PUBLIC_KEY_SIZE = 32;
/** Size of SR25519 signature in bytes */
const SR25519_SIGNATURE_SIZE = 64;
/** Default signing context (Substrate/Polkadot compatible) */
const SR25519_DEFAULT_CONTEXT = new TextEncoder().encode("substrate");
/**
* Sr25519PrivateKey - Private key for Schnorr signatures over Ristretto25519.
*
* This is the signature scheme used by Polkadot/Substrate.
*/
var Sr25519PrivateKey = class Sr25519PrivateKey {
	_seed;
	_cachedPublicKey;
	constructor(seed) {
		if (seed.length !== 32) throw new Error(`Sr25519PrivateKey seed must be 32 bytes, got ${seed.length}`);
		this._seed = new Uint8Array(seed);
	}
	/**
	* Create a new random Sr25519 private key.
	*/
	static random() {
		const rng = new SecureRandomNumberGenerator$1();
		return Sr25519PrivateKey.randomUsing(rng);
	}
	/**
	* Create a new random Sr25519 private key using the provided RNG.
	*/
	static randomUsing(rng) {
		const seed = rng.randomData(32);
		return new Sr25519PrivateKey(seed);
	}
	/**
	* Create an Sr25519 private key from a 32-byte seed.
	*/
	static fromSeed(seed) {
		return new Sr25519PrivateKey(seed);
	}
	/**
	* Create an Sr25519 private key from raw data.
	* Alias for fromSeed.
	*/
	static from(data) {
		return Sr25519PrivateKey.fromSeed(data);
	}
	/**
	* Create an Sr25519 private key from a hex string.
	*/
	static fromHex(hex) {
		const matches = hex.match(/.{1,2}/g);
		if (matches === null) throw new Error("Invalid hex string");
		const data = new Uint8Array(matches.map((byte) => parseInt(byte, 16)));
		return Sr25519PrivateKey.fromSeed(data);
	}
	/**
	* Derive an Sr25519 private key from arbitrary key material using BLAKE2b.
	*
	* @param keyMaterial - Arbitrary bytes to derive the key from
	* @returns A new Sr25519 private key
	*/
	static deriveFromKeyMaterial(keyMaterial) {
		const seed = blake2b(keyMaterial, { dkLen: 32 });
		return new Sr25519PrivateKey(seed);
	}
	/**
	* Generate a keypair and return both private and public keys.
	*
	* @returns Tuple of [privateKey, publicKey]
	*/
	static keypair() {
		const privateKey = Sr25519PrivateKey.random();
		return [privateKey, privateKey.publicKey()];
	}
	/**
	* Generate a keypair using the provided RNG.
	*
	* @param rng - Random number generator
	* @returns Tuple of [privateKey, publicKey]
	*/
	static keypairUsing(rng) {
		const privateKey = Sr25519PrivateKey.randomUsing(rng);
		return [privateKey, privateKey.publicKey()];
	}
	/**
	* Returns the raw seed bytes.
	*/
	toData() {
		return new Uint8Array(this._seed);
	}
	/**
	* Returns the raw seed bytes (alias for toData).
	*/
	asBytes() {
		return this._seed;
	}
	/**
	* Returns the hex representation of the seed.
	*/
	toHex() {
		return bytesToHex(this._seed);
	}
	/**
	* Derives the corresponding public key.
	*/
	publicKey() {
		if (this._cachedPublicKey === void 0) {
			const secretKey = sr25519.secretFromSeed(this._seed);
			const pubKeyBytes = sr25519.getPublicKey(secretKey);
			this._cachedPublicKey = Sr25519PublicKey.from(pubKeyBytes);
		}
		return this._cachedPublicKey;
	}
	/**
	* Sign a message using the default "substrate" context.
	*
	* @param message - The message to sign
	* @returns 64-byte signature
	*/
	sign(message) {
		return this.signWithContext(message, SR25519_DEFAULT_CONTEXT);
	}
	/**
	* Sign a message using a custom context.
	*
	* The underlying `@scure/sr25519` library hard-codes the `"substrate"`
	* signing context. Calling with any other context byte-slice would
	* silently produce a non-cross-platform signature, so we fail loudly
	* instead — callers must use the substrate default until a
	* context-aware library is wired in.
	*
	* @param message - The message to sign
	* @param context - The signing context (must equal `SR25519_DEFAULT_CONTEXT`)
	* @returns 64-byte signature
	* @throws CryptoError if `context` is not the substrate default
	*/
	signWithContext(message, context) {
		if (!bytesEqual(context, SR25519_DEFAULT_CONTEXT)) throw CryptoError.cryptoOperation("Sr25519: only the default substrate context is supported by the underlying library");
		const secretKey = sr25519.secretFromSeed(this._seed);
		return sr25519.sign(secretKey, message);
	}
	/**
	* Compare with another Sr25519PrivateKey.
	*/
	equals(other) {
		if (this._seed.length !== other._seed.length) return false;
		for (let i = 0; i < this._seed.length; i++) if (this._seed[i] !== other._seed[i]) return false;
		return true;
	}
	/**
	* Get string representation (truncated for security).
	*/
	toString() {
		return `Sr25519PrivateKey(${bytesToHex(this._seed).substring(0, 8)}...)`;
	}
};
//#endregion
//#region src/ec-key/ec-uncompressed-public-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* EC uncompressed public key for ECDSA (secp256k1, 65 bytes)
*
* An `ECUncompressedPublicKey` is a 65-byte uncompressed representation of a
* public key on the secp256k1 curve. The first byte is 0x04 (uncompressed prefix),
* followed by the 32-byte x-coordinate and 32-byte y-coordinate.
*
* While compressed public keys (33 bytes) are preferred for space efficiency,
* uncompressed keys are sometimes needed for compatibility with legacy systems.
*
* # CBOR Serialization
*
* `ECUncompressedPublicKey` is serialized to CBOR with tags 40306 (or legacy 306).
*
* The format is a map:
* ```
* #6.40306({
*   3: h'<65-byte-uncompressed-public-key>' // key data
* })
* ```
*
* Ported from bc-components-rust/src/ec_key/ec_uncompressed_public_key.rs
*/
var ECUncompressedPublicKey = class ECUncompressedPublicKey {
	static KEY_SIZE = 65;
	_data;
	constructor(data) {
		if (data.length !== 65) throw CryptoError.invalidSize(65, data.length);
		this._data = new Uint8Array(data);
	}
	/**
	* Restore an ECUncompressedPublicKey from a fixed-size array of bytes.
	*/
	static fromData(data) {
		return new ECUncompressedPublicKey(new Uint8Array(data));
	}
	/**
	* Restore an ECUncompressedPublicKey from a reference to an array of bytes.
	* Validates the length.
	*/
	static fromDataRef(data) {
		if (data.length !== 65) throw CryptoError.invalidSize(65, data.length);
		return ECUncompressedPublicKey.fromData(data);
	}
	/**
	* Create an ECUncompressedPublicKey from raw bytes (legacy alias).
	*/
	static from(data) {
		return ECUncompressedPublicKey.fromData(data);
	}
	/**
	* Restore an ECUncompressedPublicKey from a hex string.
	*/
	static fromHex(hex) {
		return ECUncompressedPublicKey.fromData(hexToBytes(hex));
	}
	/**
	* Get a reference to the fixed-size array of bytes.
	*/
	data() {
		return this._data;
	}
	/**
	* Get the raw public key bytes (copy).
	*/
	toData() {
		return new Uint8Array(this._data);
	}
	/**
	* Get hex string representation.
	*/
	hex() {
		return bytesToHex(this._data);
	}
	/**
	* Get hex string representation (alias for hex()).
	*/
	toHex() {
		return this.hex();
	}
	/**
	* Get base64 representation.
	*/
	toBase64() {
		return toBase64(this._data);
	}
	/**
	* Convert to compressed public key format.
	* Note: Returns the compressed bytes. To get ECPublicKey, use the ec-public-key module.
	*/
	compressedData() {
		return ecdsaCompressPublicKey(this._data);
	}
	/**
	* Compare with another ECUncompressedPublicKey.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `ECUncompressedPublicKey(${this.toHex().substring(0, 16)}...)`;
	}
	/**
	* Returns the CBOR tags associated with ECUncompressedPublicKey.
	*/
	cborTags() {
		return tagsForValues([EC_KEY.value, EC_KEY_V1.value]);
	}
	/**
	* Returns the untagged CBOR encoding.
	*
	* Format: { 3: h'<65-byte-key>' }
	*/
	untaggedCbor() {
		const map = /* @__PURE__ */ new Map();
		map.set(3, toByteString(this._data));
		return cbor$3(map);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates an ECUncompressedPublicKey by decoding it from untagged CBOR.
	*
	* Format: { 3: h'<65-byte-key>' }
	*/
	fromUntaggedCbor(cborValue) {
		const map = expectMap(cborValue);
		if (map.get(2) === true) throw new Error("Expected ECUncompressedPublicKey but found private key");
		const keyData = map.extract(3);
		if (keyData === void 0 || keyData.length === 0) throw new Error("ECUncompressedPublicKey CBOR must have key 3 (data)");
		return ECUncompressedPublicKey.fromDataRef(keyData);
	}
	/**
	* Creates an ECUncompressedPublicKey by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		return new ECUncompressedPublicKey(/* @__PURE__ */ new Uint8Array(65)).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return ECUncompressedPublicKey.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return new ECUncompressedPublicKey(/* @__PURE__ */ new Uint8Array(65)).fromUntaggedCbor(cborValue);
	}
	/**
	* Returns the UR representation of the ECUncompressedPublicKey.
	* Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
	*/
	ur() {
		const name = EC_KEY.name;
		if (name === void 0) throw new Error("TAG_EC_KEY.name is undefined");
		return UR.new(name, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates an ECUncompressedPublicKey from a UR.
	*/
	static fromUR(ur) {
		const name = EC_KEY.name;
		if (name === void 0) throw new Error("TAG_EC_KEY.name is undefined");
		ur.checkType(name);
		return new ECUncompressedPublicKey(/* @__PURE__ */ new Uint8Array(65)).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates an ECUncompressedPublicKey from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return ECUncompressedPublicKey.fromUR(ur);
	}
};
//#endregion
//#region src/ec-key/ec-public-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* EC compressed public key for ECDSA verification (secp256k1, 33 bytes)
*
* An `ECPublicKey` is a 33-byte compressed representation of a public key on
* the secp256k1 curve. The first byte is a prefix (0x02 or 0x03) that
* indicates the parity of the y-coordinate, followed by the 32-byte
* x-coordinate.
*
* These public keys are used to:
* - Verify ECDSA signatures
* - Identify the owner of a private key without revealing the private key
*
* # CBOR Serialization
*
* `ECPublicKey` is serialized to CBOR with tags 40306 (or legacy 306).
*
* The format is a map:
* ```
* #6.40306({
*   3: h'<33-byte-public-key>' // key data (no key 2 means public key)
* })
* ```
*
* Ported from bc-components-rust/src/ec_key/ec_public_key.rs
*/
var ECPublicKey = class ECPublicKey {
	static KEY_SIZE = 33;
	_data;
	constructor(data) {
		if (data.length !== 33) throw CryptoError.invalidSize(33, data.length);
		this._data = new Uint8Array(data);
	}
	/**
	* Restore an ECPublicKey from a fixed-size array of bytes.
	*/
	static fromData(data) {
		return new ECPublicKey(new Uint8Array(data));
	}
	/**
	* Restore an ECPublicKey from a reference to an array of bytes.
	* Validates the length.
	*/
	static fromDataRef(data) {
		if (data.length !== 33) throw CryptoError.invalidSize(33, data.length);
		return ECPublicKey.fromData(data);
	}
	/**
	* Create an ECPublicKey from raw bytes (legacy alias).
	*/
	static from(data) {
		return ECPublicKey.fromData(data);
	}
	/**
	* Restore an ECPublicKey from a hex string.
	*/
	static fromHex(hex) {
		return ECPublicKey.fromData(hexToBytes(hex));
	}
	/**
	* Get a reference to the fixed-size array of bytes.
	*/
	data() {
		return this._data;
	}
	/**
	* Get the raw public key bytes (copy).
	*/
	toData() {
		return new Uint8Array(this._data);
	}
	/**
	* Get hex string representation.
	*/
	hex() {
		return bytesToHex(this._data);
	}
	/**
	* Get hex string representation (alias for hex()).
	*/
	toHex() {
		return this.hex();
	}
	/**
	* Get base64 representation.
	*/
	toBase64() {
		return toBase64(this._data);
	}
	/**
	* Returns the compressed public key (self).
	*
	* This method implements the ECKey interface. Since ECPublicKey is already
	* a compressed public key, this returns itself.
	*/
	publicKey() {
		return this;
	}
	/**
	* Convert this compressed public key to uncompressed format.
	*/
	uncompressedPublicKey() {
		const uncompressed = ecdsaDecompressPublicKey(this._data);
		return ECUncompressedPublicKey.fromData(uncompressed);
	}
	/**
	* Verify an ECDSA signature.
	*
	* @param signature - The 64-byte signature to verify
	* @param message - The message that was signed
	* @returns true if the signature is valid
	*/
	verify(signature, message) {
		try {
			return ecdsaVerify(this._data, signature, message);
		} catch {
			return false;
		}
	}
	/**
	* Compare with another ECPublicKey.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `ECPublicKey(${this.toHex().substring(0, 16)}...)`;
	}
	/**
	* Returns the CBOR tags associated with ECPublicKey.
	*/
	cborTags() {
		return tagsForValues([EC_KEY.value, EC_KEY_V1.value]);
	}
	/**
	* Returns the untagged CBOR encoding.
	*
	* Format: { 3: h'<33-byte-key>' }
	* Note: No key 2 indicates this is a public key
	*/
	untaggedCbor() {
		const map = /* @__PURE__ */ new Map();
		map.set(3, toByteString(this._data));
		return cbor$3(map);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates an ECPublicKey by decoding it from untagged CBOR.
	*
	* Format: { 3: h'<33-byte-key>' }
	*/
	fromUntaggedCbor(cborValue) {
		const map = expectMap(cborValue);
		if (map.get(2) === true) throw new Error("Expected ECPublicKey but found private key (key 2 is true)");
		const keyData = map.extract(3);
		if (keyData === void 0 || keyData.length === 0) throw new Error("ECPublicKey CBOR must have key 3 (data)");
		return ECPublicKey.fromDataRef(keyData);
	}
	/**
	* Creates an ECPublicKey by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		return new ECPublicKey(/* @__PURE__ */ new Uint8Array(33)).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return ECPublicKey.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return new ECPublicKey(/* @__PURE__ */ new Uint8Array(33)).fromUntaggedCbor(cborValue);
	}
	/**
	* Returns the UR representation of the ECPublicKey.
	* Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
	*/
	ur() {
		const name = EC_KEY.name;
		if (name === void 0) throw new Error("TAG_EC_KEY.name is undefined");
		return UR.new(name, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates an ECPublicKey from a UR.
	*/
	static fromUR(ur) {
		const name = EC_KEY.name;
		if (name === void 0) throw new Error("TAG_EC_KEY.name is undefined");
		ur.checkType(name);
		return new ECPublicKey(/* @__PURE__ */ new Uint8Array(33)).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates an ECPublicKey from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return ECPublicKey.fromUR(ur);
	}
};
//#endregion
//#region src/ec-key/schnorr-public-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Schnorr (x-only) public key for BIP-340 signatures (secp256k1, 32 bytes)
*
* A `SchnorrPublicKey` is a 32-byte "x-only" public key used with the BIP-340
* Schnorr signature scheme. Unlike compressed ECDSA public keys (33 bytes)
* that include a prefix byte indicating the parity of the y-coordinate,
* Schnorr public keys only contain the x-coordinate of the elliptic curve
* point.
*
* Schnorr signatures offer several advantages over traditional ECDSA
* signatures:
* - Linearity: Enables key and signature aggregation
* - Non-malleability: Prevents third parties from modifying signatures
* - Smaller size: Signatures are 64 bytes vs 70-72 bytes for ECDSA
* - Better privacy: Makes different multisig policies indistinguishable
*
* Schnorr signatures were introduced to Bitcoin via the Taproot upgrade
* (BIP-340).
*
* Note: SchnorrPublicKey does not have CBOR serialization in the Rust
* implementation, so we keep it simple here.
*
* Ported from bc-components-rust/src/ec_key/schnorr_public_key.rs
*/
var SchnorrPublicKey = class SchnorrPublicKey {
	static KEY_SIZE = 32;
	_data;
	constructor(data) {
		if (data.length !== 32) throw CryptoError.invalidSize(32, data.length);
		this._data = new Uint8Array(data);
	}
	/**
	* Restore a SchnorrPublicKey from a fixed-size array of bytes.
	*/
	static fromData(data) {
		return new SchnorrPublicKey(new Uint8Array(data));
	}
	/**
	* Restore a SchnorrPublicKey from a reference to an array of bytes.
	* Validates the length.
	*/
	static fromDataRef(data) {
		if (data.length !== 32) throw CryptoError.invalidSize(32, data.length);
		return SchnorrPublicKey.fromData(data);
	}
	/**
	* Create a SchnorrPublicKey from raw bytes (legacy alias).
	*/
	static from(data) {
		return SchnorrPublicKey.fromData(data);
	}
	/**
	* Restore a SchnorrPublicKey from a hex string.
	*/
	static fromHex(hex) {
		return SchnorrPublicKey.fromData(hexToBytes(hex));
	}
	/**
	* Get a reference to the fixed-size array of bytes.
	*/
	data() {
		return this._data;
	}
	/**
	* Get the raw public key bytes (copy).
	*/
	toData() {
		return new Uint8Array(this._data);
	}
	/**
	* Get hex string representation.
	*/
	hex() {
		return bytesToHex(this._data);
	}
	/**
	* Get hex string representation (alias for hex()).
	*/
	toHex() {
		return this.hex();
	}
	/**
	* Get base64 representation.
	*/
	toBase64() {
		return toBase64(this._data);
	}
	/**
	* Verify a Schnorr signature (BIP-340).
	*
	* @param signature - The 64-byte signature to verify
	* @param message - The message that was signed
	* @returns true if the signature is valid
	*/
	schnorrVerify(signature, message) {
		try {
			return schnorrVerify(this._data, signature, message);
		} catch {
			return false;
		}
	}
	/**
	* Compare with another SchnorrPublicKey.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*
	* Mirrors Rust `Display for SchnorrPublicKey`
	* (`bc-components-rust/src/ec_key/schnorr_public_key.rs:116-120`)
	* — the reference is computed from the **raw 32-byte key data**
	* (not the tagged-CBOR form): `Reference::from_digest(Digest::from_image(self.data()))`.
	* `ref_hex_short()` returns the first 8 hex chars of that
	* reference's binary form (= SHA-256(data)[0..4]).
	*/
	toString() {
		return `SchnorrPublicKey(${Digest.fromImage(this._data).shortDescription()})`;
	}
};
//#endregion
//#region src/ec-key/ec-private-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* EC private key for ECDSA and Schnorr signatures (secp256k1, 32 bytes)
*
* An `ECPrivateKey` is a 32-byte secret value that can be used to:
* - Generate its corresponding public key
* - Sign messages using the ECDSA signature scheme
* - Sign messages using the Schnorr signature scheme (BIP-340)
*
* These keys use the secp256k1 curve, which is the same curve used in Bitcoin
* and other cryptocurrencies.
*
* # CBOR Serialization
*
* `ECPrivateKey` is serialized to CBOR with tags 40306 (or legacy 306).
*
* The format is a map:
* ```
* #6.40306({
*   2: true,                    // indicates private key
*   3: h'<32-byte-private-key>' // key data
* })
* ```
*
* Ported from bc-components-rust/src/ec_key/ec_private_key.rs
*/
var ECPrivateKey = class ECPrivateKey {
	static KEY_SIZE = 32;
	_data;
	_publicKey;
	_schnorrPublicKey;
	constructor(data) {
		if (data.length !== 32) throw CryptoError.invalidSize(32, data.length);
		this._data = new Uint8Array(data);
	}
	/**
	* Generate a new random ECPrivateKey.
	*/
	static new() {
		return ECPrivateKey.random();
	}
	/**
	* Generate a new random ECPrivateKey.
	*/
	static random() {
		const rng = new SecureRandomNumberGenerator$1();
		return ECPrivateKey.newUsing(rng);
	}
	/**
	* Generate a new random ECPrivateKey using provided RNG.
	*/
	static newUsing(rng) {
		return new ECPrivateKey(rng.randomData(32));
	}
	/**
	* Generate a new random ECPrivateKey and corresponding ECPublicKey.
	*/
	static keypair() {
		const privateKey = ECPrivateKey.new();
		return [privateKey, privateKey.publicKey()];
	}
	/**
	* Generate a new random ECPrivateKey and corresponding ECPublicKey
	* using the given random number generator.
	*/
	static keypairUsing(rng) {
		const privateKey = ECPrivateKey.newUsing(rng);
		return [privateKey, privateKey.publicKey()];
	}
	/**
	* Derive an ECPrivateKey from the given key material.
	*
	* @param keyMaterial - The key material to derive from
	* @returns A new ECPrivateKey derived from the key material
	*/
	static deriveFromKeyMaterial(keyMaterial) {
		return new ECPrivateKey(ecdsaDerivePrivateKey(keyMaterial));
	}
	/**
	* Restore an ECPrivateKey from a fixed-size array of bytes.
	*/
	static fromData(data) {
		return new ECPrivateKey(new Uint8Array(data));
	}
	/**
	* Restore an ECPrivateKey from a reference to an array of bytes.
	* Validates the length.
	*/
	static fromDataRef(data) {
		if (data.length !== 32) throw CryptoError.invalidSize(32, data.length);
		return ECPrivateKey.fromData(data);
	}
	/**
	* Create an ECPrivateKey from raw bytes (legacy alias).
	*/
	static from(data) {
		return ECPrivateKey.fromData(data);
	}
	/**
	* Restore an ECPrivateKey from a hex string.
	*/
	static fromHex(hex) {
		return ECPrivateKey.fromData(hexToBytes(hex));
	}
	/**
	* Get a reference to the fixed-size array of bytes.
	*/
	data() {
		return this._data;
	}
	/**
	* Get the raw private key bytes (copy).
	*/
	toData() {
		return new Uint8Array(this._data);
	}
	/**
	* Get hex string representation.
	*/
	hex() {
		return bytesToHex(this._data);
	}
	/**
	* Get hex string representation (alias for hex()).
	*/
	toHex() {
		return this.hex();
	}
	/**
	* Get base64 representation.
	*/
	toBase64() {
		return toBase64(this._data);
	}
	/**
	* Get the ECPublicKey (compressed) corresponding to this ECPrivateKey.
	*/
	publicKey() {
		if (this._publicKey === void 0) {
			const publicKeyBytes = ecdsaPublicKeyFromPrivateKey(this._data);
			this._publicKey = ECPublicKey.fromData(publicKeyBytes);
		}
		return this._publicKey;
	}
	/**
	* Get the SchnorrPublicKey (x-only) corresponding to this ECPrivateKey.
	*/
	schnorrPublicKey() {
		if (this._schnorrPublicKey === void 0) {
			const publicKeyBytes = schnorrPublicKeyFromPrivateKey(this._data);
			this._schnorrPublicKey = SchnorrPublicKey.fromData(publicKeyBytes);
		}
		return this._schnorrPublicKey;
	}
	/**
	* Sign a message using ECDSA.
	*
	* @param message - The message to sign
	* @returns A 64-byte signature
	*/
	ecdsaSign(message) {
		try {
			return ecdsaSign(this._data, message);
		} catch (e) {
			throw CryptoError.cryptoOperation(`ECDSA signing failed: ${String(e)}`);
		}
	}
	/**
	* Sign a message using Schnorr signature (BIP-340).
	*
	* @param message - The message to sign
	* @returns A 64-byte signature
	*/
	schnorrSign(message) {
		try {
			return schnorrSign(this._data, message);
		} catch (e) {
			throw CryptoError.cryptoOperation(`Schnorr signing failed: ${String(e)}`);
		}
	}
	/**
	* Sign a message using Schnorr signature with custom RNG.
	*
	* @param message - The message to sign
	* @param rng - Random number generator for auxiliary randomness
	* @returns A 64-byte signature
	*/
	schnorrSignUsing(message, rng) {
		try {
			return schnorrSignUsing(this._data, message, rng);
		} catch (e) {
			throw CryptoError.cryptoOperation(`Schnorr signing failed: ${String(e)}`);
		}
	}
	/**
	* Compare with another ECPrivateKey.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `ECPrivateKey(${this.toHex().substring(0, 16)}...)`;
	}
	/**
	* Returns the CBOR tags associated with ECPrivateKey.
	*/
	cborTags() {
		return tagsForValues([EC_KEY.value, EC_KEY_V1.value]);
	}
	/**
	* Returns the untagged CBOR encoding.
	*
	* Format: { 2: true, 3: h'<32-byte-key>' }
	*/
	untaggedCbor() {
		const map = /* @__PURE__ */ new Map();
		map.set(2, true);
		map.set(3, toByteString(this._data));
		return cbor$3(map);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates an ECPrivateKey by decoding it from untagged CBOR.
	*
	* Format: { 2: true, 3: h'<32-byte-key>' }
	*/
	fromUntaggedCbor(cborValue) {
		const map = expectMap(cborValue);
		if (map.get(2) !== true) throw new Error("ECPrivateKey CBOR must have key 2 set to true");
		const keyData = map.extract(3);
		if (keyData === void 0 || keyData.length === 0) throw new Error("ECPrivateKey CBOR must have key 3 (data)");
		return ECPrivateKey.fromDataRef(keyData);
	}
	/**
	* Creates an ECPrivateKey by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		return new ECPrivateKey(/* @__PURE__ */ new Uint8Array(32)).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return ECPrivateKey.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return new ECPrivateKey(/* @__PURE__ */ new Uint8Array(32)).fromUntaggedCbor(cborValue);
	}
	/**
	* Returns the UR representation of the ECPrivateKey.
	* Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
	*/
	ur() {
		const name = EC_KEY.name;
		if (name === void 0) throw new Error("TAG_EC_KEY.name is undefined");
		return UR.new(name, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates an ECPrivateKey from a UR.
	*/
	static fromUR(ur) {
		const name = EC_KEY.name;
		if (name === void 0) throw new Error("TAG_EC_KEY.name is undefined");
		ur.checkType(name);
		return new ECPrivateKey(/* @__PURE__ */ new Uint8Array(32)).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates an ECPrivateKey from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return ECPrivateKey.fromUR(ur);
	}
};
//#endregion
//#region src/mldsa/mldsa-level.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* MLDSA Security Level - ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
*
* ML-DSA is a post-quantum digital signature algorithm standardized by NIST.
* It provides three security levels corresponding to different NIST security categories.
*
* Security levels:
* - MLDSA44: NIST Level 2 (equivalent to AES-128)
* - MLDSA65: NIST Level 3 (equivalent to AES-192)
* - MLDSA87: NIST Level 5 (equivalent to AES-256)
*
* Ported from bc-components-rust/src/mldsa/mldsa_level.rs
*
* Naming note: Rust calls this enum `MLDSA`. TypeScript uses `MLDSALevel`
* to avoid colliding with the keypair type names (`MLDSAPrivateKey` /
* `MLDSAPublicKey` / `MLDSASignature`). The CBOR discriminator (the
* numeric level) is identical in both languages — this is a TS-only
* naming choice with no wire-format effect.
*/
/**
* ML-DSA security levels.
*
* The numeric values correspond to NIST security levels:
* - 2: NIST Level 2 (MLDSA44)
* - 3: NIST Level 3 (MLDSA65)
* - 5: NIST Level 5 (MLDSA87)
*/
let MLDSALevel = /* @__PURE__ */ function(MLDSALevel) {
	/** NIST Level 2 - AES-128 equivalent security */
	MLDSALevel[MLDSALevel["MLDSA44"] = 2] = "MLDSA44";
	/** NIST Level 3 - AES-192 equivalent security */
	MLDSALevel[MLDSALevel["MLDSA65"] = 3] = "MLDSA65";
	/** NIST Level 5 - AES-256 equivalent security */
	MLDSALevel[MLDSALevel["MLDSA87"] = 5] = "MLDSA87";
	return MLDSALevel;
}({});
/**
* Key sizes for each ML-DSA security level.
*/
const MLDSA_KEY_SIZES = {
	[2]: {
		privateKey: 2560,
		publicKey: 1312,
		signature: 2420
	},
	[3]: {
		privateKey: 4032,
		publicKey: 1952,
		signature: 3309
	},
	[5]: {
		privateKey: 4896,
		publicKey: 2592,
		signature: 4627
	}
};
/**
* Get the private key size for a given ML-DSA level.
*/
function mldsaPrivateKeySize(level) {
	return MLDSA_KEY_SIZES[level].privateKey;
}
/**
* Get the public key size for a given ML-DSA level.
*/
function mldsaPublicKeySize(level) {
	return MLDSA_KEY_SIZES[level].publicKey;
}
/**
* Get the signature size for a given ML-DSA level.
*/
function mldsaSignatureSize(level) {
	return MLDSA_KEY_SIZES[level].signature;
}
/**
* Convert an ML-DSA level to its string representation.
*/
function mldsaLevelToString(level) {
	switch (level) {
		case 2: return "MLDSA44";
		case 3: return "MLDSA65";
		case 5: return "MLDSA87";
	}
}
/**
* Parse an ML-DSA level from its numeric value.
*/
function mldsaLevelFromValue(value) {
	switch (value) {
		case 2: return 2;
		case 3: return 3;
		case 5: return 5;
		default: throw new Error(`Invalid MLDSA level value: ${value}`);
	}
}
/**
* Generate an ML-DSA keypair for the given security level.
*
* @param level - The ML-DSA security level
* @returns Object containing publicKey and secretKey bytes
*/
function mldsaGenerateKeypair(level) {
	return mldsaGenerateKeypairUsing(level, new SecureRandomNumberGenerator$1());
}
/**
* Generate an ML-DSA keypair using a provided RNG.
*
* @param level - The ML-DSA security level
* @param rng - Random number generator
* @returns Object containing publicKey and secretKey bytes
*/
function mldsaGenerateKeypairUsing(level, rng) {
	const seed = rng.randomData(32);
	switch (level) {
		case 2: {
			const keypair = ml_dsa44.keygen(seed);
			return {
				publicKey: keypair.publicKey,
				secretKey: keypair.secretKey
			};
		}
		case 3: {
			const keypair = ml_dsa65.keygen(seed);
			return {
				publicKey: keypair.publicKey,
				secretKey: keypair.secretKey
			};
		}
		case 5: {
			const keypair = ml_dsa87.keygen(seed);
			return {
				publicKey: keypair.publicKey,
				secretKey: keypair.secretKey
			};
		}
	}
}
/**
* Sign a message using ML-DSA.
*
* @param level - The ML-DSA security level
* @param secretKey - The secret key bytes
* @param message - The message to sign
* @returns The signature bytes
*/
function mldsaSign(level, secretKey, message) {
	switch (level) {
		case 2: return ml_dsa44.sign(message, secretKey);
		case 3: return ml_dsa65.sign(message, secretKey);
		case 5: return ml_dsa87.sign(message, secretKey);
	}
}
/**
* Verify a signature using ML-DSA.
*
* @param level - The ML-DSA security level
* @param publicKey - The public key bytes
* @param message - The message that was signed
* @param signature - The signature to verify
* @returns True if the signature is valid
*/
function mldsaVerify(level, publicKey, message, signature) {
	try {
		switch (level) {
			case 2: return ml_dsa44.verify(signature, message, publicKey);
			case 3: return ml_dsa65.verify(signature, message, publicKey);
			case 5: return ml_dsa87.verify(signature, message, publicKey);
		}
	} catch {
		return false;
	}
}
//#endregion
//#region src/mldsa/mldsa-public-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* MLDSAPublicKey - ML-DSA Public Key for post-quantum signature verification
*
* MLDSAPublicKey wraps an ML-DSA public key for verifying signatures.
* It supports all three security levels (MLDSA44, MLDSA65, MLDSA87).
*
* # CBOR Serialization
*
* MLDSAPublicKey is serialized with tag 40104:
* ```
* #6.40104([level, h'<public-key-bytes>'])
* ```
*
* # UR Serialization
*
* UR type: `mldsa-public-key`
*
* Ported from bc-components-rust/src/mldsa/mldsa_public_key.rs
*/
/**
* MLDSAPublicKey - Post-quantum signature verification key using ML-DSA.
*/
var MLDSAPublicKey = class MLDSAPublicKey {
	_level;
	_data;
	constructor(level, data) {
		const expectedSize = mldsaPublicKeySize(level);
		if (data.length !== expectedSize) throw new Error(`MLDSAPublicKey (${mldsaLevelToString(level)}) must be ${expectedSize} bytes, got ${data.length}`);
		this._level = level;
		this._data = new Uint8Array(data);
	}
	/**
	* Create an MLDSAPublicKey from raw bytes.
	*
	* @param level - The ML-DSA security level
	* @param data - The public key bytes
	*/
	static fromBytes(level, data) {
		return new MLDSAPublicKey(level, data);
	}
	/**
	* Returns the security level of this key.
	*/
	level() {
		return this._level;
	}
	/**
	* Returns the raw key bytes.
	*/
	asBytes() {
		return this._data;
	}
	/**
	* Returns a copy of the raw key bytes.
	*/
	data() {
		return new Uint8Array(this._data);
	}
	/**
	* Returns the size of the key in bytes.
	*/
	size() {
		return this._data.length;
	}
	/**
	* Verify a signature against a message.
	*
	* @param signature - The ML-DSA signature to verify
	* @param message - The message that was signed
	* @returns True if the signature is valid
	*/
	verify(signature, message) {
		if (signature.level() !== this._level) return false;
		return mldsaVerify(this._level, this._data, message, signature.asBytes());
	}
	/**
	* Compare with another MLDSAPublicKey.
	*/
	equals(other) {
		if (this._level !== other._level) return false;
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*/
	toString() {
		const hex = bytesToHex(this._data);
		return `MLDSAPublicKey(${mldsaLevelToString(this._level)}, ${hex.substring(0, 16)}...)`;
	}
	/**
	* Returns the CBOR tags associated with MLDSAPublicKey.
	*/
	cborTags() {
		return tagsForValues([MLDSA_PUBLIC_KEY.value]);
	}
	/**
	* Returns the untagged CBOR encoding.
	*
	* Format: [level, key_bytes]
	*/
	untaggedCbor() {
		return cbor$3([this._level, this._data]);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates an MLDSAPublicKey by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cborValue) {
		const elements = expectArray(cborValue);
		if (elements.length !== 2) throw new Error(`MLDSAPublicKey CBOR must have 2 elements, got ${elements.length}`);
		const level = mldsaLevelFromValue(Number(expectInteger(elements[0])));
		const data = expectBytes(elements[1]);
		return MLDSAPublicKey.fromBytes(level, data);
	}
	/**
	* Creates an MLDSAPublicKey by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		const dummyData = new Uint8Array(mldsaPublicKeySize(2));
		return new MLDSAPublicKey(2, dummyData).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return MLDSAPublicKey.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		const dummyData = new Uint8Array(mldsaPublicKeySize(2));
		return new MLDSAPublicKey(2, dummyData).fromUntaggedCbor(cborValue);
	}
	/**
	* Returns the UR representation.
	*/
	ur() {
		const name = MLDSA_PUBLIC_KEY.name;
		if (name === void 0) throw new Error("MLDSA_PUBLIC_KEY tag name is undefined");
		return UR.new(name, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates an MLDSAPublicKey from a UR.
	*/
	static fromUR(ur) {
		if (ur.urTypeStr() !== MLDSA_PUBLIC_KEY.name) throw new Error(`Expected UR type ${MLDSA_PUBLIC_KEY.name}, got ${ur.urTypeStr()}`);
		const dummyData = new Uint8Array(mldsaPublicKeySize(2));
		return new MLDSAPublicKey(2, dummyData).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates an MLDSAPublicKey from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return MLDSAPublicKey.fromUR(ur);
	}
};
//#endregion
//#region src/mldsa/mldsa-signature.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* MLDSASignature - ML-DSA Digital Signature
*
* MLDSASignature wraps an ML-DSA signature for serialization and verification.
* It supports all three security levels (MLDSA44, MLDSA65, MLDSA87).
*
* # CBOR Serialization
*
* MLDSASignature is serialized with tag 40105:
* ```
* #6.40105([level, h'<signature-bytes>'])
* ```
*
* # UR Serialization
*
* UR type: `mldsa-signature`
*
* Ported from bc-components-rust/src/mldsa/mldsa_signature.rs
*/
/**
* MLDSASignature - Post-quantum digital signature using ML-DSA.
*/
var MLDSASignature = class MLDSASignature {
	_level;
	_data;
	constructor(level, data) {
		const expectedSize = mldsaSignatureSize(level);
		if (data.length !== expectedSize) throw new Error(`MLDSASignature (${mldsaLevelToString(level)}) must be ${expectedSize} bytes, got ${data.length}`);
		this._level = level;
		this._data = new Uint8Array(data);
	}
	/**
	* Create an MLDSASignature from raw bytes.
	*
	* @param level - The ML-DSA security level
	* @param data - The signature bytes
	*/
	static fromBytes(level, data) {
		return new MLDSASignature(level, data);
	}
	/**
	* Returns the security level of this signature.
	*/
	level() {
		return this._level;
	}
	/**
	* Returns the raw signature bytes.
	*/
	asBytes() {
		return this._data;
	}
	/**
	* Returns a copy of the raw signature bytes.
	*/
	data() {
		return new Uint8Array(this._data);
	}
	/**
	* Returns the size of the signature in bytes.
	*/
	size() {
		return this._data.length;
	}
	/**
	* Compare with another MLDSASignature.
	*/
	equals(other) {
		if (this._level !== other._level) return false;
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*/
	toString() {
		const hex = bytesToHex(this._data);
		return `MLDSASignature(${mldsaLevelToString(this._level)}, ${hex.substring(0, 16)}...)`;
	}
	/**
	* Returns the CBOR tags associated with MLDSASignature.
	*/
	cborTags() {
		return tagsForValues([MLDSA_SIGNATURE.value]);
	}
	/**
	* Returns the untagged CBOR encoding.
	*
	* Format: [level, signature_bytes]
	*/
	untaggedCbor() {
		return cbor$3([this._level, this._data]);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates an MLDSASignature by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cborValue) {
		const elements = expectArray(cborValue);
		if (elements.length !== 2) throw new Error(`MLDSASignature CBOR must have 2 elements, got ${elements.length}`);
		const level = mldsaLevelFromValue(Number(expectInteger(elements[0])));
		const data = expectBytes(elements[1]);
		return MLDSASignature.fromBytes(level, data);
	}
	/**
	* Creates an MLDSASignature by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		const dummyData = new Uint8Array(mldsaSignatureSize(2));
		return new MLDSASignature(2, dummyData).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return MLDSASignature.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		const dummyData = new Uint8Array(mldsaSignatureSize(2));
		return new MLDSASignature(2, dummyData).fromUntaggedCbor(cborValue);
	}
	/**
	* Returns the UR representation.
	*/
	ur() {
		const name = MLDSA_SIGNATURE.name;
		if (name === void 0) throw new Error("MLDSA_SIGNATURE tag name is undefined");
		return UR.new(name, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates an MLDSASignature from a UR.
	*/
	static fromUR(ur) {
		if (ur.urTypeStr() !== MLDSA_SIGNATURE.name) throw new Error(`Expected UR type ${MLDSA_SIGNATURE.name}, got ${ur.urTypeStr()}`);
		const dummyData = new Uint8Array(mldsaSignatureSize(2));
		return new MLDSASignature(2, dummyData).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates an MLDSASignature from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return MLDSASignature.fromUR(ur);
	}
};
//#endregion
//#region src/mldsa/mldsa-private-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* MLDSAPrivateKey - ML-DSA Private Key for post-quantum digital signatures
*
* MLDSAPrivateKey wraps an ML-DSA secret key for signing messages.
* It supports all three security levels (MLDSA44, MLDSA65, MLDSA87).
*
* # CBOR Serialization
*
* MLDSAPrivateKey is serialized with tag 40103:
* ```
* #6.40103([level, h'<private-key-bytes>'])
* ```
*
* # UR Serialization
*
* UR type: `mldsa-private-key`
*
* Ported from bc-components-rust/src/mldsa/mldsa_private_key.rs
*/
/**
* MLDSAPrivateKey - Post-quantum signing private key using ML-DSA.
*/
var MLDSAPrivateKey = class MLDSAPrivateKey {
	_level;
	_data;
	constructor(level, data) {
		const expectedSize = mldsaPrivateKeySize(level);
		if (data.length !== expectedSize) throw new Error(`MLDSAPrivateKey (${mldsaLevelToString(level)}) must be ${expectedSize} bytes, got ${data.length}`);
		this._level = level;
		this._data = new Uint8Array(data);
	}
	/**
	* Generate a new random MLDSAPrivateKey with the specified security level.
	*
	* @param level - The ML-DSA security level (default: MLDSA65)
	*/
	static new(level = 3) {
		const rng = new SecureRandomNumberGenerator$1();
		return MLDSAPrivateKey.newUsing(level, rng);
	}
	/**
	* Generate a new random MLDSAPrivateKey using the provided RNG.
	*
	* @param level - The ML-DSA security level
	* @param rng - Random number generator
	*/
	static newUsing(level, rng) {
		const keypair = mldsaGenerateKeypairUsing(level, rng);
		return new MLDSAPrivateKey(level, keypair.secretKey);
	}
	/**
	* Create an MLDSAPrivateKey from raw bytes.
	*
	* @param level - The ML-DSA security level
	* @param data - The private key bytes
	*/
	static fromBytes(level, data) {
		return new MLDSAPrivateKey(level, data);
	}
	/**
	* Generate a keypair and return both private and public keys.
	*
	* @param level - The ML-DSA security level (default: MLDSA65)
	* @returns Tuple of [privateKey, publicKey]
	*/
	static keypair(level = 3) {
		const rng = new SecureRandomNumberGenerator$1();
		return MLDSAPrivateKey.keypairUsing(level, rng);
	}
	/**
	* Generate a keypair using the provided RNG.
	*
	* @param level - The ML-DSA security level
	* @param rng - Random number generator
	* @returns Tuple of [privateKey, publicKey]
	*/
	static keypairUsing(level, rng) {
		const keypairData = mldsaGenerateKeypairUsing(level, rng);
		return [new MLDSAPrivateKey(level, keypairData.secretKey), MLDSAPublicKey.fromBytes(level, keypairData.publicKey)];
	}
	/**
	* Returns the security level of this key.
	*/
	level() {
		return this._level;
	}
	/**
	* Returns the raw key bytes.
	*/
	asBytes() {
		return this._data;
	}
	/**
	* Returns a copy of the raw key bytes.
	*/
	data() {
		return new Uint8Array(this._data);
	}
	/**
	* Returns the size of the key in bytes.
	*/
	size() {
		return this._data.length;
	}
	/**
	* Sign a message with this private key.
	*
	* @param message - The message to sign
	* @returns The ML-DSA signature
	*/
	sign(message) {
		const sigBytes = mldsaSign(this._level, this._data, message);
		return MLDSASignature.fromBytes(this._level, sigBytes);
	}
	/**
	* Derive the public key from this private key.
	*
	* Note: ML-DSA doesn't have a direct derivation method, so we need to
	* regenerate the keypair from seed. For now, we extract from the secret key
	* structure (the public key is embedded in the secret key for ML-DSA).
	*/
	publicKey() {
		throw new Error("MLDSAPrivateKey.publicKey() is not supported. Use MLDSAPrivateKey.keypair() to generate both keys together.");
	}
	/**
	* Compare with another MLDSAPrivateKey.
	*/
	equals(other) {
		if (this._level !== other._level) return false;
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation (truncated for security).
	*/
	toString() {
		const hex = bytesToHex(this._data);
		return `MLDSAPrivateKey(${mldsaLevelToString(this._level)}, ${hex.substring(0, 8)}...)`;
	}
	/**
	* Returns the CBOR tags associated with MLDSAPrivateKey.
	*/
	cborTags() {
		return tagsForValues([MLDSA_PRIVATE_KEY.value]);
	}
	/**
	* Returns the untagged CBOR encoding.
	*
	* Format: [level, key_bytes]
	*/
	untaggedCbor() {
		return cbor$3([this._level, this._data]);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates an MLDSAPrivateKey by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cborValue) {
		const elements = expectArray(cborValue);
		if (elements.length !== 2) throw new Error(`MLDSAPrivateKey CBOR must have 2 elements, got ${elements.length}`);
		const level = mldsaLevelFromValue(Number(expectInteger(elements[0])));
		const data = expectBytes(elements[1]);
		return MLDSAPrivateKey.fromBytes(level, data);
	}
	/**
	* Creates an MLDSAPrivateKey by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		const dummyData = new Uint8Array(mldsaPrivateKeySize(2));
		return new MLDSAPrivateKey(2, dummyData).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return MLDSAPrivateKey.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		const dummyData = new Uint8Array(mldsaPrivateKeySize(2));
		return new MLDSAPrivateKey(2, dummyData).fromUntaggedCbor(cborValue);
	}
	/**
	* Returns the UR representation.
	*/
	ur() {
		const name = MLDSA_PRIVATE_KEY.name;
		if (name === void 0) throw new Error("MLDSA_PRIVATE_KEY tag name is undefined");
		return UR.new(name, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates an MLDSAPrivateKey from a UR.
	*/
	static fromUR(ur) {
		if (ur.urTypeStr() !== MLDSA_PRIVATE_KEY.name) throw new Error(`Expected UR type ${MLDSA_PRIVATE_KEY.name}, got ${ur.urTypeStr()}`);
		const dummyData = new Uint8Array(mldsaPrivateKeySize(2));
		return new MLDSAPrivateKey(2, dummyData).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates an MLDSAPrivateKey from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return MLDSAPrivateKey.fromUR(ur);
	}
};
//#endregion
//#region src/ssh/internal/ssh-buffer.ts
/**
* Copyright © 2025-2026 Parity Technologies
*
* RFC 4251/4253 length-prefixed wire format primitives used by every OpenSSH
* binary blob (key bodies, signature blobs, SSHSIG, etc.).
*
* Mirrors what Rust's `ssh-encoding` crate (transitive dep of `ssh-key`)
* produces byte-for-byte, so encodes here round-trip with bytes Rust emits.
*
* Spec references:
*  - RFC 4251 §5  (data types: byte, boolean, uint32, uint64, string, mpint,
*    name-list)
*  - RFC 4253 §6.6 (key/signature framing uses the same primitives)
*/
const MAX_UINT32 = 4294967295;
var SshBufferReader = class {
	bytes;
	view;
	offset;
	constructor(bytes) {
		this.bytes = bytes;
		this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
		this.offset = 0;
	}
	position() {
		return this.offset;
	}
	remaining() {
		return this.bytes.length - this.offset;
	}
	isAtEnd() {
		return this.offset >= this.bytes.length;
	}
	requireBytes(n, what) {
		if (this.offset + n > this.bytes.length) throw new Error(`SshBuffer: not enough bytes for ${what} (need ${n}, have ${this.bytes.length - this.offset})`);
	}
	readByte() {
		this.requireBytes(1, "byte");
		return this.bytes[this.offset++];
	}
	readBoolean() {
		return this.readByte() !== 0;
	}
	readUint32() {
		this.requireBytes(4, "uint32");
		const v = this.view.getUint32(this.offset, false);
		this.offset += 4;
		return v;
	}
	/** Read a length-prefixed string as raw bytes (no UTF-8 decoding). */
	readString() {
		const len = this.readUint32();
		this.requireBytes(len, "string body");
		const start = this.bytes.byteOffset + this.offset;
		const slice = new Uint8Array(this.bytes.buffer.slice(start, start + len));
		this.offset += len;
		return slice;
	}
	/** Read a length-prefixed string as UTF-8 text. */
	readStringUtf8() {
		return new TextDecoder("utf-8", { fatal: true }).decode(this.readString());
	}
	/**
	* Read an `mpint` (RFC 4251 §5) — two's-complement big-endian integer with
	* optional 0x00 sign byte. We surface the raw bytes verbatim so callers can
	* decide how to strip the sign byte for unsigned coordinate values.
	*/
	readMpint() {
		return this.readString();
	}
	/** Read a name-list (RFC 4251 §5) — a string of comma-separated US-ASCII names. */
	readNameList() {
		const text = this.readStringUtf8();
		return text.length === 0 ? [] : text.split(",");
	}
};
var SshBufferWriter = class {
	chunks = [];
	size = 0;
	writeByte(b) {
		if (b < 0 || b > 255 || !Number.isInteger(b)) throw new Error(`SshBuffer: byte out of range: ${b}`);
		const buf = /* @__PURE__ */ new Uint8Array(1);
		buf[0] = b;
		this.chunks.push(buf);
		this.size += 1;
		return this;
	}
	writeBoolean(v) {
		return this.writeByte(v ? 1 : 0);
	}
	writeUint32(v) {
		if (v < 0 || v > MAX_UINT32 || !Number.isInteger(v)) throw new Error(`SshBuffer: uint32 out of range: ${v}`);
		const buf = /* @__PURE__ */ new Uint8Array(4);
		new DataView(buf.buffer).setUint32(0, v, false);
		this.chunks.push(buf);
		this.size += 4;
		return this;
	}
	/** Write a length-prefixed byte string. */
	writeString(bytes) {
		this.writeUint32(bytes.length);
		this.chunks.push(bytes);
		this.size += bytes.length;
		return this;
	}
	/** Write a length-prefixed UTF-8 string. */
	writeStringUtf8(text) {
		return this.writeString(new TextEncoder().encode(text));
	}
	/**
	* Write an `mpint` (RFC 4251 §5).
	*
	* Two's complement big-endian. For *positive* values (which is all we
	* handle — EC coordinates, SSH public-key parameters), if the most
	* significant byte has the high bit set, a leading 0x00 must be added so
	* the value is not interpreted as negative. Leading zeros are otherwise
	* stripped. Zero is encoded as an empty string (length 0).
	*/
	writeMpintUnsigned(bytes) {
		let start = 0;
		while (start < bytes.length && bytes[start] === 0) start++;
		if (start === bytes.length) return this.writeString(/* @__PURE__ */ new Uint8Array(0));
		const needsSignByte = (bytes[start] & 128) !== 0;
		const len = bytes.length - start + (needsSignByte ? 1 : 0);
		const out = new Uint8Array(len);
		if (needsSignByte) {
			out[0] = 0;
			out.set(bytes.subarray(start), 1);
		} else out.set(bytes.subarray(start), 0);
		return this.writeString(out);
	}
	writeNameList(names) {
		return this.writeStringUtf8(names.join(","));
	}
	/** Append a raw blob without length-prefixing it. */
	writeRaw(bytes) {
		this.chunks.push(bytes);
		this.size += bytes.length;
		return this;
	}
	bytes() {
		const out = new Uint8Array(this.size);
		let pos = 0;
		for (const chunk of this.chunks) {
			out.set(chunk, pos);
			pos += chunk.length;
		}
		return out;
	}
};
/**
* Strip an optional leading 0x00 sign byte from an unsigned mpint.
*
* RFC 4251 §5 mpints are two's-complement, so positive values whose
* MSB is set carry a leading 0x00. EC curve coordinate bytes never need
* the sign byte once stripped.
*/
function stripMpintSignByte(bytes) {
	if (bytes.length > 0 && bytes[0] === 0) return bytes.subarray(1);
	return bytes;
}
/**
* Pad an unsigned big-endian byte sequence to an exact length, throwing
* if the input is longer than `len`. Used for fixed-width EC coordinates.
*/
function padLeftToLength(bytes, len) {
	if (bytes.length === len) return bytes;
	if (bytes.length > len) throw new Error(`padLeftToLength: input ${bytes.length} > target ${len}`);
	const out = new Uint8Array(len);
	out.set(bytes, len - bytes.length);
	return out;
}
//#endregion
//#region src/ssh/internal/ssh-pem.ts
/**
* Copyright © 2025-2026 Parity Technologies
*
* Minimal PEM (RFC 7468 §3) reader/writer with the byte-shape conventions
* used by Rust `ssh-key` 0.6.7:
*
*   - Wrap base64 at **70 columns** for OpenSSH private keys
*     (`pem-rfc7468` default for that format).
*   - Wrap base64 at **76 columns** for SSHSIG (`PROTOCOL.sshsig` rubric).
*   - LF newlines (matches `LineEnding::LF`, which is the rubric used for
*     all parity fixtures in `bc-components-rust/src/lib.rs`).
*   - Trailing newline after the END line.
*/
const BEGIN = "-----BEGIN ";
const END = "-----END ";
const SUFFIX = "-----";
/**
* Parse a single PEM block. Tolerant of CRLF, trailing whitespace, leading
* whitespace lines and `Proc-Type` / `DEK-Info` headers (the SSHSIG/OpenSSH
* formats don't use those, but we ignore them to be robust).
*/
function parsePem(text, expectedLabel) {
	const lines = text.split(/\r?\n/);
	let i = 0;
	while (i < lines.length && lines[i].trim() === "") i++;
	if (i >= lines.length) throw new Error("PEM: empty input");
	const beginLine = lines[i];
	if (!beginLine.startsWith(BEGIN) || !beginLine.endsWith(SUFFIX)) throw new Error(`PEM: expected '-----BEGIN <label>-----' header, got '${beginLine}'`);
	const label = beginLine.slice(11, beginLine.length - 5);
	if (expectedLabel !== void 0 && label !== expectedLabel) throw new Error(`PEM: expected label '${expectedLabel}', got '${label}'`);
	i++;
	while (i < lines.length && /^[A-Za-z][A-Za-z0-9-]*:/.test(lines[i].trim())) i++;
	if (i < lines.length && lines[i].trim() === "") i++;
	const bodyLines = [];
	let endLine;
	for (; i < lines.length; i++) {
		const line = lines[i];
		if (line.startsWith(END)) {
			endLine = line;
			break;
		}
		bodyLines.push(line);
	}
	if (endLine === void 0) throw new Error("PEM: missing '-----END <label>-----' footer");
	if (!endLine.endsWith(SUFFIX)) throw new Error(`PEM: malformed END line '${endLine}'`);
	const endLabel = endLine.slice(9, endLine.length - 5);
	if (endLabel !== label) throw new Error(`PEM: BEGIN/END label mismatch ('${label}' vs '${endLabel}')`);
	const body = bodyLines.join("").replace(/\s+/g, "");
	return {
		label,
		data: base64.decode(body)
	};
}
/**
* Encode a PEM block. `width` is the base64 column width (70 for OpenSSH
* private keys; 76 for SSHSIG signatures). Trailing newline is included
* to match the Rust fixtures.
*/
function encodePem(label, data, width) {
	const b64 = base64.encode(data);
	const lines = [];
	lines.push(`${BEGIN}${label}${SUFFIX}`);
	for (let i = 0; i < b64.length; i += width) lines.push(b64.slice(i, i + width));
	lines.push(`${END}${label}${SUFFIX}`);
	return `${lines.join("\n")}\n`;
}
//#endregion
//#region src/ssh/internal/dsa.ts
/**
* Copyright © 2025-2026 Parity Technologies
*
* SSH-DSA digital signature algorithm (FIPS 186-4 §4) with RFC 6979
* deterministic k generation.
*
* Mirrors the Rust `dsa` crate (RustCrypto, used by `ssh-key` 0.6.7) so
* signatures are byte-identical given the same key + message + hash.
*
* Used only for SSH-DSA (`ssh-dss`):
*   - q is 160 bits
*   - hash is SHA-1 (also used as HMAC hash for RFC 6979)
*   - signature is fixed 40 bytes: r (20) || s (20)
*
* Note: DSA with q=160 / SHA-1 is cryptographically deprecated. We
* support it only for parity with Rust's `bc-components-rust` SSH
* keygen path, which itself is feature-gated and primarily used in
* legacy-interop tests. Do NOT use this module for new keys.
*/
function modpow(base, exp, mod) {
	if (mod === 1n) return 0n;
	let result = 1n;
	let b = base % mod;
	if (b < 0n) b += mod;
	let e = exp;
	while (e > 0n) {
		if ((e & 1n) !== 0n) result = result * b % mod;
		e >>= 1n;
		b = b * b % mod;
	}
	return result;
}
function modinv(a, m) {
	let oldR = (a % m + m) % m;
	let r = m;
	let oldS = 1n;
	let s = 0n;
	while (r !== 0n) {
		const q = oldR / r;
		[oldR, r] = [r, oldR - q * r];
		[oldS, s] = [s, oldS - q * s];
	}
	if (oldR !== 1n) throw new Error("dsa: modular inverse does not exist");
	return (oldS % m + m) % m;
}
function bytesToBigint(bytes) {
	let v = 0n;
	for (const b of bytes) v = v << 8n | BigInt(b);
	return v;
}
function bigintToBytesFixed(v, len) {
	const out = new Uint8Array(len);
	let n = v;
	for (let i = len - 1; i >= 0; i--) {
		out[i] = Number(n & 255n);
		n >>= 8n;
	}
	if (n !== 0n) throw new Error(`dsa: integer does not fit in ${len} bytes`);
	return out;
}
function concatBytes(...arrs) {
	let total = 0;
	for (const a of arrs) total += a.length;
	const out = new Uint8Array(total);
	let pos = 0;
	for (const a of arrs) {
		out.set(a, pos);
		pos += a.length;
	}
	return out;
}
/**
* `bits2int` per RFC 6979 §2.3.2: interpret the input bits as a big-endian
* integer, truncating the rightmost bits if the bit length exceeds qlen.
*/
function bits2int(input, qlenBits) {
	let v = bytesToBigint(input);
	const inputBits = input.length * 8;
	if (inputBits > qlenBits) v >>= BigInt(inputBits - qlenBits);
	return v;
}
/**
* `int2octets` per RFC 6979 §2.3.3: integer → fixed-length bytes (qlen/8).
*/
function int2octets(v, rolen) {
	return bigintToBytesFixed(v, rolen);
}
/**
* `bits2octets` per RFC 6979 §2.3.4: bits2int reduced mod q, then int2octets.
*/
function bits2octets(input, q, qlenBits, rolen) {
	const z1 = bits2int(input, qlenBits);
	let z2 = z1 - q;
	if (z2 < 0n) z2 = z1;
	return int2octets(z2 % q, rolen);
}
/**
* Derive a deterministic per-signature nonce `k` per RFC 6979 §3.2 using
* HMAC-SHA-1 (the hash paired with DSA-1024/q-160).
*/
function rfc6979Nonce(q, x, hashedMessage) {
	const qlenBits = q.toString(2).length;
	const rolen = Math.ceil(qlenBits / 8);
	const hlen = 20;
	const xOct = int2octets(bytesToBigint(x), rolen);
	const h1Oct = bits2octets(hashedMessage, q, qlenBits, rolen);
	let V = new Uint8Array(hlen).fill(1);
	let K = new Uint8Array(hlen).fill(0);
	K = hmac(sha1, K, concatBytes(V, new Uint8Array([0]), xOct, h1Oct));
	V = hmac(sha1, K, V);
	K = hmac(sha1, K, concatBytes(V, new Uint8Array([1]), xOct, h1Oct));
	V = hmac(sha1, K, V);
	for (let iter = 0; iter < 1024; iter++) {
		let T = /* @__PURE__ */ new Uint8Array(0);
		while (T.length < rolen) {
			V = hmac(sha1, K, V);
			T = concatBytes(T, V);
		}
		const k = bits2int(T, qlenBits);
		if (k >= 1n && k < q) return k;
		K = hmac(sha1, K, concatBytes(V, new Uint8Array([0])));
		V = hmac(sha1, K, V);
	}
	throw new Error("dsa: RFC 6979 failed to produce a valid k after 1024 iterations");
}
/**
* Sign `messageDigest` with the DSA private key, returning a fixed-length
* `r || s` signature. Uses RFC 6979 deterministic `k` so signatures match
* Rust's `dsa` crate byte-for-byte.
*
* Output length is `2 * (qlen / 8)` = 40 bytes for SSH-DSA-1024.
*/
function dsaSign(params) {
	const p = bytesToBigint(params.p);
	const q = bytesToBigint(params.q);
	const g = bytesToBigint(params.g);
	const x = bytesToBigint(params.x);
	const qlenBits = q.toString(2).length;
	const rolen = Math.ceil(qlenBits / 8);
	const k = rfc6979Nonce(q, params.x, params.messageDigest);
	const r = modpow(g, k, p) % q;
	if (r === 0n) throw new Error("dsa: degenerate signature with r=0");
	const z = bits2int(params.messageDigest, qlenBits);
	const s = modinv(k, q) * (z + x * r) % q;
	if (s === 0n) throw new Error("dsa: degenerate signature with s=0");
	const out = new Uint8Array(rolen * 2);
	out.set(bigintToBytesFixed(r, rolen), 0);
	out.set(bigintToBytesFixed(s, rolen), rolen);
	return out;
}
/**
* Verify a DSA `r || s` signature against the message digest and public key.
* Returns `true` iff the signature is valid; never throws on bad input.
*/
function dsaVerify(params) {
	try {
		const p = bytesToBigint(params.p);
		const q = bytesToBigint(params.q);
		const g = bytesToBigint(params.g);
		const y = bytesToBigint(params.y);
		const qlenBits = q.toString(2).length;
		const rolen = Math.ceil(qlenBits / 8);
		if (params.signature.length !== rolen * 2) return false;
		const r = bytesToBigint(params.signature.subarray(0, rolen));
		const s = bytesToBigint(params.signature.subarray(rolen));
		if (r <= 0n || r >= q) return false;
		if (s <= 0n || s >= q) return false;
		const w = modinv(s, q);
		const u1 = bits2int(params.messageDigest, qlenBits) * w % q;
		const u2 = r * w % q;
		return modpow(g, u1, p) * modpow(y, u2, p) % p % q === r;
	} catch {
		return false;
	}
}
//#endregion
//#region src/ssh/ssh-algorithm.ts
/** Wire-format algorithm name as it appears in OpenSSH text and in the key blob. */
const SSH_ALGO_ED25519 = "ssh-ed25519";
const SSH_ALGO_DSA = "ssh-dss";
const SSH_ALGO_ECDSA_NISTP256 = "ecdsa-sha2-nistp256";
const SSH_ALGO_ECDSA_NISTP384 = "ecdsa-sha2-nistp384";
/** OpenSSH curve identifier embedded inside ECDSA key blobs. */
const SSH_CURVE_NISTP256 = "nistp256";
const SSH_CURVE_NISTP384 = "nistp384";
function sshAlgorithmName(algo) {
	switch (algo.kind) {
		case "ed25519": return SSH_ALGO_ED25519;
		case "dsa": return SSH_ALGO_DSA;
		case "ecdsa": switch (algo.curve) {
			case "nistp256": return SSH_ALGO_ECDSA_NISTP256;
			case "nistp384": return SSH_ALGO_ECDSA_NISTP384;
		}
	}
}
function parseSshAlgorithm(name) {
	switch (name) {
		case SSH_ALGO_ED25519: return { kind: "ed25519" };
		case SSH_ALGO_DSA: return { kind: "dsa" };
		case SSH_ALGO_ECDSA_NISTP256: return {
			kind: "ecdsa",
			curve: "nistp256"
		};
		case SSH_ALGO_ECDSA_NISTP384: return {
			kind: "ecdsa",
			curve: "nistp384"
		};
		default: throw new Error(`Unsupported SSH algorithm '${name}'. v1.1 supports ${SSH_ALGO_ED25519}, ${SSH_ALGO_DSA}, ${SSH_ALGO_ECDSA_NISTP256}, ${SSH_ALGO_ECDSA_NISTP384} (see SSH_PLAN.md V2 for RSA / P-521).`);
	}
}
/**
* Wire-format curve name corresponding to a `SshEcdsaCurve`.
*/
function sshCurveName(curve) {
	switch (curve) {
		case "nistp256": return SSH_CURVE_NISTP256;
		case "nistp384": return SSH_CURVE_NISTP384;
	}
}
/**
* Byte length of an uncompressed SEC1 point (`0x04 || X || Y`) for the curve.
*/
function sshEcdsaPointLen(curve) {
	switch (curve) {
		case "nistp256": return 65;
		case "nistp384": return 97;
	}
}
/**
* Byte length of the canonical (no sign byte) private scalar for the curve.
*/
function sshEcdsaScalarLen(curve) {
	switch (curve) {
		case "nistp256": return 32;
		case "nistp384": return 48;
	}
}
//#endregion
//#region src/ssh/ssh-public-key.ts
/**
* Copyright © 2025-2026 Parity Technologies
*
* SSH public-key parser/serializer covering Ed25519, DSA, ECDSA P-256,
* and ECDSA P-384.
*
* Mirrors `ssh_key::PublicKey` (crate `ssh-key` v0.6.7) — same OpenSSH
* single-line text format, same SSH wire-format blob layout (RFC 4253 §6.6),
* so byte-for-byte round-trips with bytes Rust emits.
*
* OpenSSH single-line public key format:
*
*     <algorithm> <base64-encoded-blob> [<comment>]
*
* Per-algorithm blob layouts (RFC 4253 §6.6 + extensions):
*
*   ssh-ed25519:
*     string  "ssh-ed25519"
*     string  <32-byte raw public key>
*
*   ssh-dss:
*     string  "ssh-dss"
*     mpint   p   (1024-bit prime)
*     mpint   q   (160-bit prime divisor of p-1)
*     mpint   g   (generator)
*     mpint   y   (public)
*
*   ecdsa-sha2-nistp256:
*     string  "ecdsa-sha2-nistp256"
*     string  "nistp256"
*     string  <0x04 || X (32 bytes) || Y (32 bytes)>   (SEC1 uncompressed)
*
*   ecdsa-sha2-nistp384:
*     string  "ecdsa-sha2-nistp384"
*     string  "nistp384"
*     string  <0x04 || X (48 bytes) || Y (48 bytes)>   (SEC1 uncompressed)
*/
const ED25519_PUBLIC_KEY_LEN = 32;
var SSHPublicKey = class SSHPublicKey {
	data;
	comment;
	constructor(data, comment) {
		this.data = data;
		this.comment = comment;
	}
	/** Algorithm tag for this key. */
	get algorithm() {
		const data = this.data;
		switch (data.kind) {
			case "ed25519": return { kind: "ed25519" };
			case "dsa": return { kind: "dsa" };
			case "ecdsa": return {
				kind: "ecdsa",
				curve: data.curve
			};
			default: throw new Error(`SSHPublicKey: unreachable kind ${String(data)}`);
		}
	}
	static ed25519(keyBytes, comment = "") {
		if (keyBytes.length !== ED25519_PUBLIC_KEY_LEN) throw new Error(`SSHPublicKey ed25519: expected ${ED25519_PUBLIC_KEY_LEN} bytes, got ${keyBytes.length}`);
		return new SSHPublicKey({
			kind: "ed25519",
			pubBytes: new Uint8Array(keyBytes)
		}, comment);
	}
	static ecdsaP256(uncompressedPoint, comment = "") {
		return SSHPublicKey.ecdsa("nistp256", uncompressedPoint, comment);
	}
	static ecdsaP384(uncompressedPoint, comment = "") {
		return SSHPublicKey.ecdsa("nistp384", uncompressedPoint, comment);
	}
	static ecdsa(curve, uncompressedPoint, comment = "") {
		const expected = sshEcdsaPointLen(curve);
		if (uncompressedPoint.length !== expected || uncompressedPoint[0] !== 4) throw new Error(`SSHPublicKey ecdsa-${curve}: expected ${expected}-byte uncompressed SEC1 point (0x04 prefix), got ${uncompressedPoint.length} bytes prefix=0x${uncompressedPoint[0]?.toString(16) ?? "?"}`);
		return new SSHPublicKey({
			kind: "ecdsa",
			curve,
			point: new Uint8Array(uncompressedPoint)
		}, comment);
	}
	/** DSA public key. p/q/g/y must already be canonical positive bytes (no sign byte). */
	static dsa(p, q, g, y, comment = "") {
		return new SSHPublicKey({
			kind: "dsa",
			p: new Uint8Array(p),
			q: new Uint8Array(q),
			g: new Uint8Array(g),
			y: new Uint8Array(y)
		}, comment);
	}
	/**
	* Returns a copy of this SSH public key with the comment replaced.
	*
	* Mirrors `ssh_key::PublicKey::set_comment` (mutating in Rust; we
	* return a new instance to keep the type immutable).
	*/
	withComment(comment) {
		return new SSHPublicKey(this.data, comment);
	}
	static fromOpenssh(text) {
		const trimmed = text.trim();
		if (trimmed.length === 0) throw new Error("SSHPublicKey.fromOpenssh: empty input");
		const firstSpace = trimmed.indexOf(" ");
		if (firstSpace < 0) throw new Error(`SSHPublicKey.fromOpenssh: expected '<algo> <base64> [comment]', got '${trimmed}'`);
		const algoName = trimmed.slice(0, firstSpace);
		const rest = trimmed.slice(firstSpace + 1);
		const secondSpace = rest.indexOf(" ");
		let blobB64;
		let comment;
		if (secondSpace < 0) {
			blobB64 = rest;
			comment = "";
		} else {
			blobB64 = rest.slice(0, secondSpace);
			comment = rest.slice(secondSpace + 1);
		}
		parseSshAlgorithm(algoName);
		const blob = base64.decode(blobB64);
		const parsed = SSHPublicKey.fromBlob(blob, comment);
		if (sshAlgorithmName(parsed.algorithm) !== algoName) throw new Error(`SSHPublicKey.fromOpenssh: outer algorithm '${algoName}' does not match inner '${sshAlgorithmName(parsed.algorithm)}'`);
		return parsed;
	}
	toOpenssh() {
		const algoName = sshAlgorithmName(this.algorithm);
		const blobB64 = base64.encode(this.toBlob());
		return this.comment.length === 0 ? `${algoName} ${blobB64}` : `${algoName} ${blobB64} ${this.comment}`;
	}
	static fromBlob(blob, comment = "") {
		const reader = new SshBufferReader(blob);
		const algorithm = parseSshAlgorithm(decodeUtf8$2(reader.readString()));
		switch (algorithm.kind) {
			case "ed25519": {
				const pub = reader.readString();
				if (!reader.isAtEnd()) throw new Error("SSHPublicKey.fromBlob ed25519: trailing bytes after public key");
				return SSHPublicKey.ed25519(pub, comment);
			}
			case "dsa": {
				const p = stripDsaMpint(reader.readMpint());
				const q = stripDsaMpint(reader.readMpint());
				const g = stripDsaMpint(reader.readMpint());
				const y = stripDsaMpint(reader.readMpint());
				if (!reader.isAtEnd()) throw new Error("SSHPublicKey.fromBlob dsa: trailing bytes after y");
				return SSHPublicKey.dsa(p, q, g, y, comment);
			}
			case "ecdsa": {
				const curveName = decodeUtf8$2(reader.readString());
				if (curveName !== sshCurveName(algorithm.curve)) throw new Error(`SSHPublicKey.fromBlob ecdsa: blob curve '${curveName}' does not match algorithm '${sshCurveName(algorithm.curve)}'`);
				const point = reader.readString();
				if (!reader.isAtEnd()) throw new Error("SSHPublicKey.fromBlob ecdsa: trailing bytes after public point");
				return SSHPublicKey.ecdsa(algorithm.curve, point, comment);
			}
		}
	}
	toBlob() {
		const writer = new SshBufferWriter();
		writer.writeStringUtf8(sshAlgorithmName(this.algorithm));
		switch (this.data.kind) {
			case "ed25519":
				writer.writeString(this.data.pubBytes);
				break;
			case "dsa":
				writer.writeMpintUnsigned(this.data.p);
				writer.writeMpintUnsigned(this.data.q);
				writer.writeMpintUnsigned(this.data.g);
				writer.writeMpintUnsigned(this.data.y);
				break;
			case "ecdsa":
				writer.writeStringUtf8(sshCurveName(this.data.curve));
				writer.writeString(this.data.point);
		}
		return writer.bytes();
	}
	digest() {
		return sha256(new TextEncoder().encode(this.toOpenssh()));
	}
	refHexShort() {
		const d = this.digest();
		let s = "";
		for (let i = 0; i < 4; i++) s += d[i].toString(16).padStart(2, "0");
		return s;
	}
	toString() {
		return `SSHPublicKey(${this.refHexShort()})`;
	}
	equals(other) {
		return this.toOpenssh() === other.toOpenssh();
	}
	/**
	* Comment-insensitive equality: matches when algorithm and key data
	* agree, ignoring the comment. Used by verify paths since SSH
	* wire-format pubkey blobs carry the key but not the comment.
	*/
	keyEquals(other) {
		return bytesEqual$3(this.toBlob(), other.toBlob());
	}
	/**
	* Algorithm-specific raw payload bytes. Throws for DSA — DSA needs structured
	* access via `data.p/q/g/y`.
	*/
	get keyBytes() {
		const data = this.data;
		switch (data.kind) {
			case "ed25519": return data.pubBytes;
			case "ecdsa": return data.point;
			case "dsa": throw new Error("SSHPublicKey.keyBytes is not defined for DSA — use `data.p/q/g/y` instead");
			default: throw new Error(`SSHPublicKey: unreachable kind ${String(data)}`);
		}
	}
	verifySshSignature(namespace, message, signature) {
		if (!this.keyEquals(signature.publicKey)) return false;
		if (signature.namespace !== namespace) return false;
		const messageDigest = signature.hashAlgorithm === "sha256" ? sha256(message) : sha512(message);
		const signedData = signedDataBlobInline(namespace, signature.hashAlgorithm, messageDigest);
		try {
			switch (this.data.kind) {
				case "ed25519": return ed25519.verify(signature.signatureBytes, signedData, this.data.pubBytes);
				case "ecdsa":
					switch (this.data.curve) {
						case "nistp256": return p256.verify(signature.signatureBytes, signedData, this.data.point, { format: "compact" });
						case "nistp384": return p384.verify(signature.signatureBytes, signedData, this.data.point, { format: "compact" });
					}
					return false;
				case "dsa": {
					const innerDigest = sha1(signedData);
					return dsaVerify({
						p: this.data.p,
						q: this.data.q,
						g: this.data.g,
						y: this.data.y,
						messageDigest: innerDigest,
						signature: signature.signatureBytes
					});
				}
			}
		} catch {
			return false;
		}
	}
};
function decodeUtf8$2(bytes) {
	return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}
function bytesEqual$3(a, b) {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}
/**
* Strip the optional 0x00 sign byte from a positive `mpint` and return the
* canonical (unsigned) bytes. Used for DSA p/q/g/y components.
*/
function stripDsaMpint(mpint) {
	if (mpint.length > 0 && mpint[0] === 0) return new Uint8Array(mpint.subarray(1));
	return new Uint8Array(mpint);
}
const SSHSIG_MAGIC = new TextEncoder().encode("SSHSIG");
function signedDataBlobInline(namespace, hashAlg, messageDigest) {
	const w = new SshBufferWriter();
	w.writeRaw(SSHSIG_MAGIC);
	w.writeStringUtf8(namespace);
	w.writeString(/* @__PURE__ */ new Uint8Array(0));
	w.writeStringUtf8(hashAlg);
	w.writeString(messageDigest);
	return w.bytes();
}
//#endregion
//#region src/ssh/ssh-signature.ts
/**
* Copyright © 2025-2026 Parity Technologies
*
* SSHSIG (PROTOCOL.sshsig) parser/serializer — the OpenSSH armored
* signature format used by `ssh-keygen -Y sign`.
*
* Mirrors `ssh_key::SshSig` (crate `ssh-key` v0.6.7), so blobs round-trip
* byte-identically with bytes Rust emits.
*
* Outer PEM:
*
*     -----BEGIN SSH SIGNATURE-----
*     <base64, 76-char wrap, LF newlines>
*     -----END SSH SIGNATURE-----
*
* Inner blob (`PROTOCOL.sshsig` §2):
*
*     6 bytes "SSHSIG" magic
*     uint32  version          (must be 1)
*     string  publickey         (SSH wire-format pubkey blob)
*     string  namespace         (UTF-8)
*     string  reserved          (currently empty)
*     string  hash_algorithm    ("sha256" | "sha512")
*     string  signature         (algorithm-specific signature blob):
*
*   ssh-ed25519 signature blob:
*     string  algorithm "ssh-ed25519"
*     string  raw 64-byte signature
*
*   ecdsa-sha2-nistp256 / ecdsa-sha2-nistp384 signature blob:
*     string  algorithm "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384"
*     string  inner-blob:
*         mpint r
*         mpint s
*
*   ssh-dss signature blob:
*     string  algorithm "ssh-dss"
*     string  raw 40-byte signature  (r || s, 20 bytes each, q = 160 bits)
*/
const PEM_LABEL$1 = "SSH SIGNATURE";
const PEM_LINE_WIDTH$1 = 76;
const MAGIC$1 = new TextEncoder().encode("SSHSIG");
const SUPPORTED_VERSION = 1;
const ED25519_SIGNATURE_LEN = 64;
const DSA_SIGNATURE_LEN = 40;
var SSHSignature = class SSHSignature {
	publicKey;
	namespace;
	reserved;
	hashAlgorithm;
	/**
	* Raw signature bytes specific to the algorithm:
	*   ed25519 → 64-byte concatenation `r || s`
	*   ecdsa-p256 → 64-byte concatenation `r || s` (we strip the SSH
	*     mpint sign bytes on parse and re-add them on serialize, so this
	*     stays a fixed 64-byte canonical form internally)
	*/
	signatureBytes;
	constructor(publicKey, namespace, reserved, hashAlgorithm, signatureBytes) {
		this.publicKey = publicKey;
		this.namespace = namespace;
		this.reserved = reserved;
		this.hashAlgorithm = hashAlgorithm;
		this.signatureBytes = signatureBytes;
	}
	static fromPem(text) {
		const { data } = parsePem(text, PEM_LABEL$1);
		return SSHSignature.fromBlob(data);
	}
	static fromBlob(blob) {
		if (blob.length < MAGIC$1.length || !bytesEqual$2(blob.subarray(0, MAGIC$1.length), MAGIC$1)) throw new Error("SSHSignature: missing 'SSHSIG' magic");
		const reader = new SshBufferReader(blob.subarray(MAGIC$1.length));
		const version = reader.readUint32();
		if (version !== SUPPORTED_VERSION) throw new Error(`SSHSignature: unsupported SSHSIG version ${version} (expected ${SUPPORTED_VERSION})`);
		const publicKeyBlob = reader.readString();
		const publicKey = SSHPublicKey.fromBlob(publicKeyBlob);
		const namespace = decodeUtf8$1(reader.readString());
		const reserved = reader.readString();
		const hashAlgRaw = decodeUtf8$1(reader.readString());
		if (hashAlgRaw !== "sha256" && hashAlgRaw !== "sha512") throw new Error(`SSHSignature: unsupported hash algorithm '${hashAlgRaw}'`);
		const sigBlob = reader.readString();
		if (!reader.isAtEnd()) throw new Error("SSHSignature: trailing bytes after signature blob");
		const signatureBytes = decodeAlgorithmSignature(publicKey.algorithm, sigBlob);
		return new SSHSignature(publicKey, namespace, reserved, hashAlgRaw, signatureBytes);
	}
	toPem() {
		return encodePem(PEM_LABEL$1, this.toBlob(), PEM_LINE_WIDTH$1);
	}
	toBlob() {
		const writer = new SshBufferWriter();
		writer.writeRaw(MAGIC$1);
		writer.writeUint32(SUPPORTED_VERSION);
		writer.writeString(this.publicKey.toBlob());
		writer.writeStringUtf8(this.namespace);
		writer.writeString(this.reserved);
		writer.writeStringUtf8(this.hashAlgorithm);
		writer.writeString(encodeAlgorithmSignature(this.publicKey.algorithm, this.signatureBytes));
		return writer.bytes();
	}
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
	static signedDataBlob(namespace, hashAlgorithm, messageDigest) {
		const w = new SshBufferWriter();
		w.writeRaw(MAGIC$1);
		w.writeStringUtf8(namespace);
		w.writeString(/* @__PURE__ */ new Uint8Array(0));
		w.writeStringUtf8(hashAlgorithm);
		w.writeString(messageDigest);
		return w.bytes();
	}
	/** Construct from already-decoded parts (used by Phase 7 sign path). */
	static fromParts(publicKey, namespace, hashAlgorithm, signatureBytes) {
		return new SSHSignature(publicKey, namespace, /* @__PURE__ */ new Uint8Array(0), hashAlgorithm, new Uint8Array(signatureBytes));
	}
	/** Fixed-string mirror of Rust summarizer for `TAG_SSH_TEXT_SIGNATURE`. */
	toString() {
		return "SSHSignature";
	}
	/** SHA-256 digest of canonical PEM bytes — kept for parity with key types. */
	digest() {
		return sha256(new TextEncoder().encode(this.toPem()));
	}
};
function decodeUtf8$1(bytes) {
	return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}
function bytesEqual$2(a, b) {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}
/**
* Strip the algorithm wrapping from a signature blob and return the raw
* algorithm-specific bytes (concatenation form):
*   ed25519 → 64 bytes raw
*   ecdsa   → `r || s`, fixed-width per curve (32 for P-256, 48 for P-384)
*   dsa     → 40 bytes raw `r || s` (q = 160 bits)
*/
function decodeAlgorithmSignature(algorithm, sigBlob) {
	const r = new SshBufferReader(sigBlob);
	const algoName = decodeUtf8$1(r.readString());
	const expected = sshAlgorithmName(algorithm);
	if (algoName !== expected) throw new Error(`SSHSignature: signature algorithm '${algoName}' does not match key algorithm '${expected}'`);
	switch (algorithm.kind) {
		case "ed25519": {
			const sig = r.readString();
			if (!r.isAtEnd()) throw new Error("SSHSignature ed25519: trailing bytes after raw signature");
			if (sig.length !== ED25519_SIGNATURE_LEN) throw new Error(`SSHSignature ed25519: expected ${ED25519_SIGNATURE_LEN}-byte signature, got ${sig.length}`);
			return new Uint8Array(sig);
		}
		case "ecdsa": {
			const inner = r.readString();
			if (!r.isAtEnd()) throw new Error("SSHSignature ecdsa: trailing bytes after inner signature blob");
			const innerR = new SshBufferReader(inner);
			const scalarLen = sshEcdsaScalarLen(algorithm.curve);
			const rBytes = stripAndPad(innerR.readMpint(), scalarLen, "ecdsa");
			const sBytes = stripAndPad(innerR.readMpint(), scalarLen, "ecdsa");
			if (!innerR.isAtEnd()) throw new Error("SSHSignature ecdsa: trailing bytes after r,s");
			const out = new Uint8Array(scalarLen * 2);
			out.set(rBytes, 0);
			out.set(sBytes, scalarLen);
			return out;
		}
		case "dsa": {
			const sig = r.readString();
			if (!r.isAtEnd()) throw new Error("SSHSignature dsa: trailing bytes after raw signature");
			if (sig.length !== DSA_SIGNATURE_LEN) throw new Error(`SSHSignature dsa: expected ${DSA_SIGNATURE_LEN}-byte signature, got ${sig.length}`);
			return new Uint8Array(sig);
		}
	}
}
function encodeAlgorithmSignature(algorithm, signatureBytes) {
	const w = new SshBufferWriter();
	w.writeStringUtf8(sshAlgorithmName(algorithm));
	switch (algorithm.kind) {
		case "ed25519":
			if (signatureBytes.length !== ED25519_SIGNATURE_LEN) throw new Error(`SSHSignature ed25519: signatureBytes length ${signatureBytes.length} != ${ED25519_SIGNATURE_LEN}`);
			w.writeString(signatureBytes);
			break;
		case "ecdsa": {
			const scalarLen = sshEcdsaScalarLen(algorithm.curve);
			const expectedLen = scalarLen * 2;
			if (signatureBytes.length !== expectedLen) throw new Error(`SSHSignature ecdsa: signatureBytes length ${signatureBytes.length} != ${expectedLen} (r||s)`);
			const inner = new SshBufferWriter();
			inner.writeMpintUnsigned(signatureBytes.subarray(0, scalarLen));
			inner.writeMpintUnsigned(signatureBytes.subarray(scalarLen));
			w.writeString(inner.bytes());
			break;
		}
		case "dsa":
			if (signatureBytes.length !== DSA_SIGNATURE_LEN) throw new Error(`SSHSignature dsa: signatureBytes length ${signatureBytes.length} != ${DSA_SIGNATURE_LEN} (r||s)`);
			w.writeString(signatureBytes);
	}
	return w.bytes();
}
function stripAndPad(mpint, len, label) {
	const stripped = mpint[0] === 0 ? mpint.subarray(1) : mpint;
	if (stripped.length > len) throw new Error(`SSHSignature ${label}: r/s component too large (${stripped.length} bytes)`);
	if (stripped.length === len) return new Uint8Array(stripped);
	const out = new Uint8Array(len);
	out.set(stripped, len - stripped.length);
	return out;
}
//#endregion
//#region src/ssh/ssh-private-key.ts
/**
* Copyright © 2025-2026 Parity Technologies
*
* SSH private-key parser/serializer for the OpenSSH binary key format
* (`-----BEGIN OPENSSH PRIVATE KEY-----`), spec: PROTOCOL.key in
* https://github.com/openssh/openssh-portable.
*
* Mirrors `ssh_key::PrivateKey` (crate `ssh-key` v0.6.7) byte-for-byte for
* unencrypted Ed25519, DSA, ECDSA P-256, and ECDSA P-384 keys. Encrypted
* keys (bcrypt-pbkdf + AES-256-CTR), RSA, and P-521 are deferred to v2 —
* see `SSH_PLAN.md` V2.A-V2.D.
*
* Wire-format summary (after base64-decoding the PEM body):
*
*     "openssh-key-v1\0"                  (15 bytes magic)
*     string  ciphername                  (must be "none" in v1)
*     string  kdfname                     (must be "none" in v1)
*     string  kdfoptions                  (empty when ciphername = "none")
*     uint32  nkeys                       (must be 1 in v1)
*     string  publickey-blob              (`SSHPublicKey.toBlob` payload)
*     string  encrypted-section:
*                 uint32  checkint
*                 uint32  checkint        (must equal first checkint)
*                 algorithm-specific keypair fields
*                 string  comment
*                 padding 0x01, 0x02, ... up to 8-byte block boundary
*
*   ed25519 keypair fields:
*     string  algorithm  ("ssh-ed25519")
*     string  public_key (32 bytes)
*     string  private_key (64 bytes — seed (32) || public (32))
*
*   ecdsa-sha2-nistp{256,384} keypair fields:
*     string  algorithm  ("ecdsa-sha2-nistp{256,384}")
*     string  curve      ("nistp{256,384}")
*     string  public_point (65 / 97 bytes — 0x04 || X || Y)
*     mpint   private_scalar (canonical: 32/48 bytes, with 0x00 sign byte if MSB set)
*
*   ssh-dss keypair fields:
*     string  algorithm  ("ssh-dss")
*     mpint   p (re-stated)
*     mpint   q (re-stated)
*     mpint   g (re-stated)
*     mpint   y (re-stated)
*     mpint   x (private)
*/
const PEM_LABEL = "OPENSSH PRIVATE KEY";
const PEM_LINE_WIDTH = 70;
const MAGIC = new TextEncoder().encode("openssh-key-v1\0");
const CIPHER_NONE = "none";
const KDF_NONE = "none";
const NKEYS = 1;
const BLOCK_SIZE_NONE = 8;
const ED25519_SEED_LEN = 32;
const ED25519_PUBLIC_LEN = 32;
function bytesEqual$1(a, b) {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}
function decodeUtf8(bytes) {
	return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}
function stripPositiveMpint(mpint) {
	if (mpint.length > 0 && mpint[0] === 0) return new Uint8Array(mpint.subarray(1));
	return new Uint8Array(mpint);
}
var SSHPrivateKey = class SSHPrivateKey {
	data;
	comment;
	/**
	* 32-bit checkint preserved on round-trip — `ssh-key` retains the parsed
	* value, so to round-trip byte-identically we do too.
	*/
	checkint;
	constructor(data, comment, checkint) {
		this.data = data;
		this.comment = comment;
		this.checkint = checkint >>> 0;
	}
	/**
	* Construct an `SSHPrivateKey` from already-decoded parts. Used by
	* `PrivateKeyBase.sshSigningPrivateKey` after generating key material
	* from an HKDF-seeded RNG. The `checkint` should be derived
	* deterministically from the private bytes (matching Rust's
	* `ssh-key` 0.6.7 `KeypairData::checkint`).
	*/
	static fromParts(data, comment, checkint) {
		return new SSHPrivateKey(data, comment, checkint);
	}
	/** Algorithm tag for this key. */
	get algorithm() {
		const data = this.data;
		switch (data.kind) {
			case "ed25519": return { kind: "ed25519" };
			case "dsa": return { kind: "dsa" };
			case "ecdsa": return {
				kind: "ecdsa",
				curve: data.curve
			};
			default: throw new Error(`SSHPrivateKey: unreachable kind ${String(data)}`);
		}
	}
	get publicBytes() {
		const data = this.data;
		switch (data.kind) {
			case "ed25519": return data.pubBytes;
			case "ecdsa": return data.point;
			case "dsa": throw new Error("SSHPrivateKey.publicBytes is not defined for DSA — use `data.p/q/g/y` instead");
			default: throw new Error(`SSHPrivateKey: unreachable kind ${String(data)}`);
		}
	}
	get privateBytes() {
		const data = this.data;
		switch (data.kind) {
			case "ed25519": return data.seed;
			case "ecdsa": return data.scalar;
			case "dsa": throw new Error("SSHPrivateKey.privateBytes is not defined for DSA — use `data.x` instead");
			default: throw new Error(`SSHPrivateKey: unreachable kind ${String(data)}`);
		}
	}
	static fromOpenssh(text) {
		const { data } = parsePem(text, PEM_LABEL);
		return SSHPrivateKey.fromBlob(data);
	}
	static fromBlob(blob) {
		if (blob.length < MAGIC.length || !bytesEqual$1(blob.subarray(0, MAGIC.length), MAGIC)) throw new Error("SSHPrivateKey: missing 'openssh-key-v1' magic");
		const reader = new SshBufferReader(blob.subarray(MAGIC.length));
		const ciphername = decodeUtf8(reader.readString());
		const kdfname = decodeUtf8(reader.readString());
		if (ciphername !== CIPHER_NONE || kdfname !== KDF_NONE) throw new Error(`SSHPrivateKey: encrypted keys are not supported in v1 (ciphername='${ciphername}', kdfname='${kdfname}'). See SSH_PLAN.md V2.B.`);
		const kdfoptions = reader.readString();
		if (kdfoptions.length !== 0) throw new Error(`SSHPrivateKey: expected empty kdfoptions for ciphername='none', got ${kdfoptions.length} bytes`);
		const nkeys = reader.readUint32();
		if (nkeys !== NKEYS) throw new Error(`SSHPrivateKey: expected exactly ${NKEYS} key, got ${nkeys}`);
		const publicKeyBlob = reader.readString();
		const publicKey = SSHPublicKey.fromBlob(publicKeyBlob);
		const encryptedBlob = reader.readString();
		if (!reader.isAtEnd()) throw new Error("SSHPrivateKey: trailing bytes after encrypted section");
		if (encryptedBlob.length % BLOCK_SIZE_NONE !== 0) throw new Error(`SSHPrivateKey: encrypted section length ${encryptedBlob.length} is not a multiple of ${BLOCK_SIZE_NONE}`);
		const innerReader = new SshBufferReader(encryptedBlob);
		const checkint1 = innerReader.readUint32();
		const checkint2 = innerReader.readUint32();
		if (checkint1 !== checkint2) throw new Error(`SSHPrivateKey: checkint mismatch (0x${checkint1.toString(16)} vs 0x${checkint2.toString(16)}) — file is corrupted or encrypted`);
		const algoName = decodeUtf8(innerReader.readString());
		const algorithm = parseSshAlgorithm(algoName);
		if (sshAlgorithmName(publicKey.algorithm) !== algoName) throw new Error(`SSHPrivateKey: outer/inner algorithm mismatch ('${sshAlgorithmName(publicKey.algorithm)}' vs '${algoName}')`);
		let data;
		switch (algorithm.kind) {
			case "ed25519": {
				const pubBytes = innerReader.readString();
				if (pubBytes.length !== ED25519_PUBLIC_LEN) throw new Error(`SSHPrivateKey ed25519: public key length ${pubBytes.length} != ${ED25519_PUBLIC_LEN}`);
				if (publicKey.data.kind !== "ed25519" || !bytesEqual$1(pubBytes, publicKey.data.pubBytes)) throw new Error("SSHPrivateKey ed25519: outer/inner public-key mismatch");
				const combined = innerReader.readString();
				if (combined.length !== 64) throw new Error(`SSHPrivateKey ed25519: combined seed||public length ${combined.length} != 64`);
				if (!bytesEqual$1(combined.subarray(ED25519_SEED_LEN), pubBytes)) throw new Error("SSHPrivateKey ed25519: combined-blob public tail does not match public field");
				data = {
					kind: "ed25519",
					seed: new Uint8Array(combined.subarray(0, ED25519_SEED_LEN)),
					pubBytes: new Uint8Array(pubBytes)
				};
				break;
			}
			case "ecdsa": {
				const expectedCurve = sshCurveName(algorithm.curve);
				const curveName = decodeUtf8(innerReader.readString());
				if (curveName !== expectedCurve) throw new Error(`SSHPrivateKey ecdsa: blob curve '${curveName}' does not match algorithm '${expectedCurve}'`);
				const point = innerReader.readString();
				const expectedPointLen = sshEcdsaPointLen(algorithm.curve);
				if (point.length !== expectedPointLen || point[0] !== 4) throw new Error(`SSHPrivateKey ecdsa: expected ${expectedPointLen}-byte uncompressed point (0x04 prefix), got ${point.length} bytes prefix=0x${point[0]?.toString(16) ?? "?"}`);
				if (publicKey.data.kind !== "ecdsa" || !bytesEqual$1(point, publicKey.data.point)) throw new Error("SSHPrivateKey ecdsa: outer/inner public-key mismatch");
				const scalar = padLeftToLength(stripMpintSignByte(innerReader.readMpint()), sshEcdsaScalarLen(algorithm.curve));
				data = {
					kind: "ecdsa",
					curve: algorithm.curve,
					point: new Uint8Array(point),
					scalar
				};
				break;
			}
			case "dsa": {
				const p = stripPositiveMpint(innerReader.readMpint());
				const q = stripPositiveMpint(innerReader.readMpint());
				const g = stripPositiveMpint(innerReader.readMpint());
				const y = stripPositiveMpint(innerReader.readMpint());
				const x = stripPositiveMpint(innerReader.readMpint());
				if (publicKey.data.kind !== "dsa") throw new Error("SSHPrivateKey dsa: outer key is not DSA");
				if (!bytesEqual$1(p, publicKey.data.p) || !bytesEqual$1(q, publicKey.data.q) || !bytesEqual$1(g, publicKey.data.g) || !bytesEqual$1(y, publicKey.data.y)) throw new Error("SSHPrivateKey dsa: outer/inner public-parameter mismatch");
				data = {
					kind: "dsa",
					p,
					q,
					g,
					y,
					x
				};
				break;
			}
		}
		const comment = decodeUtf8(innerReader.readString());
		let pad = 1;
		while (!innerReader.isAtEnd()) {
			const b = innerReader.readByte();
			if (b !== pad) throw new Error(`SSHPrivateKey: bad padding byte at offset ${innerReader.position()} (expected 0x${pad.toString(16)}, got 0x${b.toString(16)})`);
			pad++;
		}
		return new SSHPrivateKey(data, comment, checkint1);
	}
	/**
	* Re-serialize to the canonical OpenSSH armored format.
	*
	* Matches Rust `ssh_key::PrivateKey::to_openssh(LineEnding::LF)`.
	*/
	toOpenssh() {
		return encodePem(PEM_LABEL, this.toBlob(), PEM_LINE_WIDTH);
	}
	toBlob() {
		const writer = new SshBufferWriter();
		writer.writeRaw(MAGIC);
		writer.writeStringUtf8(CIPHER_NONE);
		writer.writeStringUtf8(KDF_NONE);
		writer.writeString(/* @__PURE__ */ new Uint8Array(0));
		writer.writeUint32(NKEYS);
		writer.writeString(this.publicBlob());
		writer.writeString(this.encryptedSection());
		return writer.bytes();
	}
	publicKey() {
		switch (this.data.kind) {
			case "ed25519": return SSHPublicKey.ed25519(this.data.pubBytes, this.comment);
			case "ecdsa": return SSHPublicKey.ecdsa(this.data.curve, this.data.point, this.comment);
			case "dsa": return SSHPublicKey.dsa(this.data.p, this.data.q, this.data.g, this.data.y, this.comment);
		}
	}
	publicBlob() {
		return this.publicKey().toBlob();
	}
	encryptedSection() {
		const w = new SshBufferWriter();
		w.writeUint32(this.checkint);
		w.writeUint32(this.checkint);
		w.writeStringUtf8(sshAlgorithmName(this.algorithm));
		switch (this.data.kind) {
			case "ed25519": {
				w.writeString(this.data.pubBytes);
				const combined = /* @__PURE__ */ new Uint8Array(64);
				combined.set(this.data.seed, 0);
				combined.set(this.data.pubBytes, ED25519_SEED_LEN);
				w.writeString(combined);
				break;
			}
			case "ecdsa":
				w.writeStringUtf8(sshCurveName(this.data.curve));
				w.writeString(this.data.point);
				w.writeMpintUnsigned(this.data.scalar);
				break;
			case "dsa":
				w.writeMpintUnsigned(this.data.p);
				w.writeMpintUnsigned(this.data.q);
				w.writeMpintUnsigned(this.data.g);
				w.writeMpintUnsigned(this.data.y);
				w.writeMpintUnsigned(this.data.x);
		}
		w.writeStringUtf8(this.comment);
		const body = w.bytes();
		const padLen = (BLOCK_SIZE_NONE - body.length % BLOCK_SIZE_NONE) % BLOCK_SIZE_NONE;
		if (padLen === 0) return body;
		const out = new Uint8Array(body.length + padLen);
		out.set(body, 0);
		for (let i = 0; i < padLen; i++) out[body.length + i] = i + 1;
		return out;
	}
	digest() {
		return sha256(new TextEncoder().encode(this.toOpenssh()));
	}
	refHexShort() {
		const d = this.digest();
		let s = "";
		for (let i = 0; i < 4; i++) s += d[i].toString(16).padStart(2, "0");
		return s;
	}
	toString() {
		return `SSHPrivateKey(${this.refHexShort()})`;
	}
	sign(namespace, hashAlgorithm, message) {
		const messageDigest = digestForHash(hashAlgorithm, message);
		const signedData = SSHSignature.signedDataBlob(namespace, hashAlgorithm, messageDigest);
		let signatureBytes;
		switch (this.data.kind) {
			case "ed25519":
				signatureBytes = ed25519.sign(signedData, this.data.seed);
				break;
			case "ecdsa":
				switch (this.data.curve) {
					case "nistp256":
						signatureBytes = p256.sign(signedData, this.data.scalar, { format: "compact" });
						break;
					case "nistp384": signatureBytes = p384.sign(signedData, this.data.scalar, { format: "compact" });
				}
				break;
			case "dsa": {
				const innerDigest = sha1(signedData);
				signatureBytes = dsaSign({
					p: this.data.p,
					q: this.data.q,
					g: this.data.g,
					y: this.data.y,
					x: this.data.x,
					messageDigest: innerDigest
				});
				break;
			}
		}
		return SSHSignature.fromParts(this.publicKey(), namespace, hashAlgorithm, signatureBytes);
	}
};
function digestForHash(alg, message) {
	switch (alg) {
		case "sha256": return sha256(message);
		case "sha512": return sha512(message);
	}
}
//#endregion
//#region src/x25519/x25519-public-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* X25519 public key for ECDH key exchange (32 bytes)
*
* X25519 is an elliptic-curve Diffie-Hellman key exchange protocol based on
* Curve25519 as defined in RFC 7748. It allows two parties to establish a
* shared secret key over an insecure channel.
*
* The X25519 public key is generated from a corresponding private key and is
* designed to be:
* - Compact (32 bytes)
* - Fast to use in key agreement operations
* - Resistant to various cryptographic attacks
*
* # CBOR Serialization
*
* `X25519PublicKey` is serialized to CBOR with tag 40011.
*
* ```
* #6.40011(h'<32-byte-public-key>')
* ```
*
* Ported from bc-components-rust/src/x25519/x25519_public_key.rs
*/
var X25519PublicKey = class X25519PublicKey {
	static KEY_SIZE = 32;
	_data;
	constructor(data) {
		if (data.length !== 32) throw CryptoError.invalidSize(32, data.length);
		this._data = new Uint8Array(data);
	}
	/**
	* Restore an X25519PublicKey from a fixed-size array of bytes.
	*/
	static fromData(data) {
		return new X25519PublicKey(new Uint8Array(data));
	}
	/**
	* Restore an X25519PublicKey from a reference to an array of bytes.
	* Validates the length.
	*/
	static fromDataRef(data) {
		if (data.length !== 32) throw CryptoError.invalidSize(32, data.length);
		return X25519PublicKey.fromData(data);
	}
	/**
	* Create an X25519PublicKey from raw bytes (legacy alias).
	*/
	static from(data) {
		return X25519PublicKey.fromData(data);
	}
	/**
	* Restore an X25519PublicKey from a hex string.
	*/
	static fromHex(hex) {
		return X25519PublicKey.fromData(hexToBytes(hex));
	}
	/**
	* Get a reference to the fixed-size array of bytes.
	*/
	data() {
		return this._data;
	}
	/**
	* Get the raw public key bytes (copy).
	*/
	toData() {
		return new Uint8Array(this._data);
	}
	/**
	* Get hex string representation.
	*/
	hex() {
		return bytesToHex(this._data);
	}
	/**
	* Get hex string representation (alias for hex()).
	*/
	toHex() {
		return this.hex();
	}
	/**
	* Get base64 representation.
	*/
	toBase64() {
		return toBase64(this._data);
	}
	/**
	* Compare with another X25519PublicKey.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*
	* Mirrors Rust `Display for X25519PublicKey`
	* (`bc-components-rust/src/x25519/x25519_public_key.rs:166-168`):
	*   `X25519PublicKey(<ref_hex_short>)` where the reference is
	*   computed from the **tagged-CBOR** form of the key.
	*/
	toString() {
		return `X25519PublicKey(${Digest.fromImage(this.taggedCborData()).shortDescription()})`;
	}
	/**
	* Returns the CBOR tags associated with X25519PublicKey.
	*/
	cborTags() {
		return tagsForValues([X25519_PUBLIC_KEY.value]);
	}
	/**
	* Returns the untagged CBOR encoding (as a byte string).
	*/
	untaggedCbor() {
		return toByteString(this._data);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates an X25519PublicKey by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cbor) {
		const data = expectBytes(cbor);
		return X25519PublicKey.fromDataRef(data);
	}
	/**
	* Creates an X25519PublicKey by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cbor) {
		validateTag(cbor, this.cborTags());
		const content = extractTaggedContent(cbor);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cbor) {
		return new X25519PublicKey(/* @__PURE__ */ new Uint8Array(32)).fromTaggedCbor(cbor);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cbor = decodeCbor$3(data);
		return X25519PublicKey.fromTaggedCbor(cbor);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cbor = decodeCbor$3(data);
		return new X25519PublicKey(/* @__PURE__ */ new Uint8Array(32)).fromUntaggedCbor(cbor);
	}
	/**
	* Returns the UR representation of the X25519PublicKey.
	* Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
	*/
	ur() {
		const name = X25519_PUBLIC_KEY.name;
		if (name === void 0) throw new Error("X25519_PUBLIC_KEY tag name is undefined");
		return UR.new(name, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates an X25519PublicKey from a UR.
	*/
	static fromUR(ur) {
		const name = X25519_PUBLIC_KEY.name;
		if (name === void 0) throw new Error("X25519_PUBLIC_KEY tag name is undefined");
		ur.checkType(name);
		return new X25519PublicKey(/* @__PURE__ */ new Uint8Array(32)).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates an X25519PublicKey from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return X25519PublicKey.fromUR(ur);
	}
};
//#endregion
//#region src/symmetric/authentication-tag.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Authentication tag for AEAD encryption (16 bytes)
*
* An `AuthenticationTag` is a 16-byte value generated during ChaCha20-Poly1305
* authenticated encryption. It serves as a message authentication code (MAC)
* that verifies both the authenticity and integrity of the encrypted message.
*
* During decryption, the tag is verified to ensure:
* - The message has not been tampered with (integrity)
* - The message was encrypted by someone who possesses the encryption key
*   (authenticity)
*
* This implementation follows the Poly1305 MAC algorithm as specified in
* [RFC-8439](https://datatracker.ietf.org/doc/html/rfc8439).
*
* Ported from bc-components-rust/src/symmetric/authentication_tag.rs
*/
const AUTHENTICATION_TAG_SIZE = 16;
var AuthenticationTag = class AuthenticationTag {
	static AUTHENTICATION_TAG_SIZE = AUTHENTICATION_TAG_SIZE;
	_data;
	constructor(data) {
		if (data.length !== AUTHENTICATION_TAG_SIZE) throw CryptoError.invalidSize(AUTHENTICATION_TAG_SIZE, data.length);
		this._data = new Uint8Array(data);
	}
	/**
	* Restore an AuthenticationTag from a fixed-size array of bytes.
	*/
	static fromData(data) {
		return new AuthenticationTag(new Uint8Array(data));
	}
	/**
	* Restore an AuthenticationTag from a reference to an array of bytes.
	*/
	static fromDataRef(data) {
		if (data.length !== AUTHENTICATION_TAG_SIZE) throw CryptoError.invalidSize(AUTHENTICATION_TAG_SIZE, data.length);
		return AuthenticationTag.fromData(data);
	}
	/**
	* Create an AuthenticationTag from raw bytes (legacy alias).
	*/
	static from(data) {
		return AuthenticationTag.fromData(data);
	}
	/**
	* Create an AuthenticationTag from hex string.
	*/
	static fromHex(hex) {
		return AuthenticationTag.fromData(hexToBytes(hex));
	}
	/**
	* Get a reference to the fixed-size array of bytes.
	*/
	data() {
		return this._data;
	}
	/**
	* Get the reference as a byte slice.
	*/
	asBytes() {
		return this._data;
	}
	/**
	* Get the raw tag bytes as a copy.
	*/
	toData() {
		return new Uint8Array(this._data);
	}
	/**
	* Get hex string representation.
	*/
	toHex() {
		return bytesToHex(this._data);
	}
	/**
	* Get base64 representation.
	*/
	toBase64() {
		return toBase64(this._data);
	}
	/**
	* Compare with another AuthenticationTag.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `AuthenticationTag(${this.toHex()})`;
	}
	/**
	* Returns the untagged CBOR encoding (as a byte string).
	* AuthenticationTag has no CBOR tag - it's serialized as a plain byte string.
	*/
	toCbor() {
		return toByteString(this._data);
	}
	/**
	* Returns the CBOR binary representation.
	*/
	toCborData() {
		return this.toCbor().toData();
	}
	/**
	* Creates an AuthenticationTag from CBOR.
	*/
	static fromCbor(cbor) {
		const data = expectBytes(cbor);
		return AuthenticationTag.fromDataRef(data);
	}
	/**
	* Creates an AuthenticationTag from CBOR binary data.
	*/
	static fromCborData(data) {
		const cbor = decodeCbor$3(data);
		return AuthenticationTag.fromCbor(cbor);
	}
};
//#endregion
//#region src/symmetric/encrypted-message.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Encrypted message with ChaCha20-Poly1305 AEAD
*
* A secure encrypted message using IETF ChaCha20-Poly1305 authenticated
* encryption.
*
* `EncryptedMessage` represents data that has been encrypted using a symmetric
* key with the ChaCha20-Poly1305 AEAD (Authenticated Encryption with
* Associated Data) construction as specified in [RFC-8439](https://datatracker.ietf.org/doc/html/rfc8439).
*
* An `EncryptedMessage` contains:
* - `ciphertext`: The encrypted data (same length as the original plaintext)
* - `aad`: Additional Authenticated Data that is not encrypted but is
*   authenticated (optional)
* - `nonce`: A 12-byte number used once for this specific encryption operation
* - `auth`: A 16-byte authentication tag that verifies the integrity of the
*   message
*
* The `aad` field is often used to include the `Digest` of the plaintext,
* which allows verification of the plaintext after decryption and preserves
* the unique identity of the data when used with structures like Gordian
* Envelope.
*
* # CBOR Serialization
*
* `EncryptedMessage` is serialized to CBOR with tag 40002.
*
* CDDL:
* ```cddl
* EncryptedMessage =
*     #6.40002([ ciphertext: bstr, nonce: bstr, auth: bstr, ? aad: bstr ])
* ```
*
* # UR Serialization
*
* When serialized as a Uniform Resource (UR), an `EncryptedMessage` is
* represented with the type "encrypted".
*
* Ported from bc-components-rust/src/symmetric/encrypted_message.rs
*/
var EncryptedMessage = class EncryptedMessage {
	_ciphertext;
	_aad;
	_nonce;
	_auth;
	constructor(ciphertext, aad, nonce, auth) {
		this._ciphertext = new Uint8Array(ciphertext);
		this._aad = new Uint8Array(aad);
		this._nonce = nonce;
		this._auth = auth;
	}
	/**
	* Restores an EncryptedMessage from its components.
	*/
	static new(ciphertext, aad, nonce, auth) {
		const authTag = auth instanceof AuthenticationTag ? auth : AuthenticationTag.fromData(auth);
		return new EncryptedMessage(ciphertext, aad, nonce, authTag);
	}
	/**
	* Create an EncryptedMessage from components (legacy alias).
	*/
	static from(nonce, ciphertext, tag, aad) {
		return new EncryptedMessage(ciphertext, aad ?? /* @__PURE__ */ new Uint8Array(0), nonce, tag);
	}
	/**
	* Returns a reference to the ciphertext data.
	*/
	ciphertext() {
		return this._ciphertext;
	}
	/**
	* Returns a reference to the additional authenticated data (AAD).
	*/
	aad() {
		return this._aad;
	}
	/**
	* Returns a reference to the nonce value used for encryption.
	*/
	nonce() {
		return this._nonce;
	}
	/**
	* Returns a reference to the authentication tag value used for encryption.
	*/
	authenticationTag() {
		return this._auth;
	}
	/**
	* Returns a CBOR representation in the AAD field, if it exists.
	*/
	aadCbor() {
		if (this._aad.length === 0) return null;
		try {
			return decodeCbor$3(this._aad);
		} catch {
			return null;
		}
	}
	/**
	* Returns a Digest instance if the AAD data can be parsed as CBOR.
	*/
	aadDigest() {
		const aadCbor = this.aadCbor();
		if (aadCbor === null) return null;
		try {
			return Digest.fromTaggedCbor(aadCbor);
		} catch {
			return null;
		}
	}
	/**
	* Returns true if the AAD data can be parsed as a Digest.
	*/
	hasDigest() {
		return this.aadDigest() !== null;
	}
	/**
	* Compare with another EncryptedMessage.
	*/
	equals(other) {
		if (this._ciphertext.length !== other._ciphertext.length) return false;
		for (let i = 0; i < this._ciphertext.length; i++) if (this._ciphertext[i] !== other._ciphertext[i]) return false;
		if (this._aad.length !== other._aad.length) return false;
		for (let i = 0; i < this._aad.length; i++) if (this._aad[i] !== other._aad[i]) return false;
		return this._nonce.equals(other._nonce) && this._auth.equals(other._auth);
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `EncryptedMessage(ciphertext: ${bytesToHex(this._ciphertext).substring(0, 16)}..., nonce: ${this._nonce.toHex()}, auth: ${this._auth.toHex()})`;
	}
	/**
	* Returns the CBOR tags associated with EncryptedMessage.
	*/
	cborTags() {
		return tagsForValues([ENCRYPTED.value]);
	}
	/**
	* Returns the untagged CBOR encoding (as an array).
	* Array format: [ciphertext, nonce, auth, ?aad]
	*/
	untaggedCbor() {
		const elements = [
			toByteString(this._ciphertext),
			toByteString(this._nonce.data()),
			toByteString(this._auth.data())
		];
		if (this._aad.length > 0) elements.push(toByteString(this._aad));
		return cbor$3(elements);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates an EncryptedMessage by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cborValue) {
		const elements = expectArray(cborValue);
		if (elements.length < 3) throw new Error("EncryptedMessage must have at least 3 elements");
		const ciphertext = expectBytes(elements[0]);
		const nonceData = expectBytes(elements[1]);
		const nonce = Nonce.fromDataRef(nonceData);
		const authData = expectBytes(elements[2]);
		const auth = AuthenticationTag.fromDataRef(authData);
		const aad = elements.length > 3 ? expectBytes(elements[3]) : /* @__PURE__ */ new Uint8Array(0);
		return EncryptedMessage.new(ciphertext, aad, nonce, auth);
	}
	/**
	* Creates an EncryptedMessage by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		return new EncryptedMessage(/* @__PURE__ */ new Uint8Array(0), /* @__PURE__ */ new Uint8Array(0), Nonce.new(), AuthenticationTag.fromData(/* @__PURE__ */ new Uint8Array(16))).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return EncryptedMessage.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return new EncryptedMessage(/* @__PURE__ */ new Uint8Array(0), /* @__PURE__ */ new Uint8Array(0), Nonce.new(), AuthenticationTag.fromData(/* @__PURE__ */ new Uint8Array(16))).fromUntaggedCbor(cborValue);
	}
	/**
	* Returns the UR representation of the EncryptedMessage.
	* Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
	*/
	ur() {
		return UR.new("encrypted", this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates an EncryptedMessage from a UR.
	*/
	static fromUR(ur) {
		ur.checkType("encrypted");
		return new EncryptedMessage(/* @__PURE__ */ new Uint8Array(0), /* @__PURE__ */ new Uint8Array(0), Nonce.new(), AuthenticationTag.fromData(/* @__PURE__ */ new Uint8Array(16))).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates an EncryptedMessage from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return EncryptedMessage.fromUR(ur);
	}
};
//#endregion
//#region src/symmetric/symmetric-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Symmetric key for ChaCha20-Poly1305 AEAD encryption (32 bytes)
*
* A symmetric encryption key used for both encryption and decryption.
*
* `SymmetricKey` is a 32-byte cryptographic key used with ChaCha20-Poly1305
* AEAD (Authenticated Encryption with Associated Data) encryption. This
* implementation follows the IETF ChaCha20-Poly1305 specification as defined
* in [RFC-8439](https://datatracker.ietf.org/doc/html/rfc8439).
*
* Symmetric encryption uses the same key for both encryption and decryption,
* unlike asymmetric encryption where different keys are used for each
* operation.
*
* # CBOR Serialization
*
* `SymmetricKey` is serialized to CBOR with tag 40023.
*
* Ported from bc-components-rust/src/symmetric/symmetric_key.rs
*/
const SYMMETRIC_KEY_SIZE = 32;
var SymmetricKey = class SymmetricKey {
	static SYMMETRIC_KEY_SIZE = SYMMETRIC_KEY_SIZE;
	_data;
	constructor(data) {
		if (data.length !== SYMMETRIC_KEY_SIZE) throw CryptoError.invalidSize(SYMMETRIC_KEY_SIZE, data.length);
		this._data = new Uint8Array(data);
	}
	/**
	* Create a new random symmetric key.
	*/
	static new() {
		return SymmetricKey.random();
	}
	/**
	* Create a new symmetric key from data.
	*/
	static fromData(data) {
		return new SymmetricKey(new Uint8Array(data));
	}
	/**
	* Create a new symmetric key from data (validates length).
	*/
	static fromDataRef(data) {
		if (data.length !== SYMMETRIC_KEY_SIZE) throw CryptoError.invalidSize(SYMMETRIC_KEY_SIZE, data.length);
		return SymmetricKey.fromData(data);
	}
	/**
	* Create a SymmetricKey from raw bytes (legacy alias).
	*/
	static from(data) {
		return SymmetricKey.fromData(data);
	}
	/**
	* Create a SymmetricKey from hex string.
	*/
	static fromHex(hex) {
		return SymmetricKey.fromData(hexToBytes(hex));
	}
	/**
	* Generate a random symmetric key.
	*/
	static random() {
		const rng = new SecureRandomNumberGenerator$1();
		return SymmetricKey.randomUsing(rng);
	}
	/**
	* Generate a random symmetric key using provided RNG.
	*/
	static randomUsing(rng) {
		return new SymmetricKey(rng.randomData(SYMMETRIC_KEY_SIZE));
	}
	/**
	* Get the data of the symmetric key.
	*/
	data() {
		return this._data;
	}
	/**
	* Get the data of the symmetric key as a byte slice.
	*/
	asBytes() {
		return this._data;
	}
	/**
	* Get a copy of the raw key bytes.
	*/
	toData() {
		return new Uint8Array(this._data);
	}
	/**
	* Get hex string representation.
	*/
	hex() {
		return bytesToHex(this._data);
	}
	/**
	* Get hex string representation (alias for hex()).
	*/
	toHex() {
		return this.hex();
	}
	/**
	* Get base64 representation.
	*/
	toBase64() {
		return toBase64(this._data);
	}
	/**
	* Compare with another SymmetricKey.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `SymmetricKey(${this.hex().substring(0, 8)}...)`;
	}
	/**
	* Encrypt the given plaintext with this key, and the given additional
	* authenticated data and nonce.
	*/
	encrypt(plaintext, aad, nonce) {
		const effectiveNonce = nonce ?? Nonce.new();
		const effectiveAad = aad ?? /* @__PURE__ */ new Uint8Array(0);
		const [ciphertext, authTag] = aeadChaCha20Poly1305EncryptWithAad(plaintext, this._data, effectiveNonce.data(), effectiveAad);
		return EncryptedMessage.new(ciphertext, effectiveAad, effectiveNonce, authTag);
	}
	/**
	* Decrypt the given encrypted message with this key.
	*/
	decrypt(message) {
		return aeadChaCha20Poly1305DecryptWithAad(message.ciphertext(), this._data, message.nonce().data(), message.aad(), message.authenticationTag().data());
	}
	/**
	* Returns the CBOR tags associated with SymmetricKey.
	*/
	cborTags() {
		return tagsForValues([SYMMETRIC_KEY.value]);
	}
	/**
	* Returns the untagged CBOR encoding (as a byte string).
	*/
	untaggedCbor() {
		return toByteString(this._data);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates a SymmetricKey by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cbor) {
		const data = expectBytes(cbor);
		return SymmetricKey.fromDataRef(data);
	}
	/**
	* Creates a SymmetricKey by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cbor) {
		validateTag(cbor, this.cborTags());
		const content = extractTaggedContent(cbor);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cbor) {
		return new SymmetricKey(new Uint8Array(SYMMETRIC_KEY_SIZE)).fromTaggedCbor(cbor);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cbor = decodeCbor$3(data);
		return SymmetricKey.fromTaggedCbor(cbor);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cbor = decodeCbor$3(data);
		const bytes = expectBytes(cbor);
		return SymmetricKey.fromDataRef(bytes);
	}
	/**
	* Get the UR type for symmetric keys.
	*/
	static UR_TYPE = "crypto-key";
	/**
	* Returns the UR representation of the symmetric key.
	*
	* The UR type prefix (`ur:crypto-key/...`) carries the CBOR tag, so the
	* inner CBOR must be untagged — matches Rust's `UREncodable` blanket impl.
	*/
	ur() {
		return UR.new(SymmetricKey.UR_TYPE, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation of the symmetric key.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates a SymmetricKey from a UR.
	*/
	static fromUR(ur) {
		ur.checkType(SymmetricKey.UR_TYPE);
		return SymmetricKey.fromData(new Uint8Array(SymmetricKey.SYMMETRIC_KEY_SIZE)).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates a SymmetricKey from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return SymmetricKey.fromUR(ur);
	}
	/**
	* Alias for fromURString for Rust API compatibility.
	*/
	static fromUrString(urString) {
		return SymmetricKey.fromURString(urString);
	}
};
//#endregion
//#region src/x25519/x25519-private-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* X25519 private key for ECDH key exchange (32 bytes seed)
*
* X25519 is an elliptic-curve Diffie-Hellman key exchange protocol based on
* Curve25519 as defined in RFC 7748. It allows two parties to establish a
* shared secret key over an insecure channel.
*
* Key features of X25519:
* - High security (128-bit security level)
* - High performance
* - Small key sizes (32 bytes)
* - Protection against various side-channel attacks
*
* # CBOR Serialization
*
* `X25519PrivateKey` is serialized to CBOR with tag 40010.
*
* ```
* #6.40010(h'<32-byte-private-key>')
* ```
*
* Ported from bc-components-rust/src/x25519/x25519_private_key.rs
*/
var X25519PrivateKey = class X25519PrivateKey {
	static KEY_SIZE = 32;
	_data;
	_publicKey;
	constructor(data) {
		if (data.length !== 32) throw CryptoError.invalidSize(32, data.length);
		this._data = new Uint8Array(data);
	}
	/**
	* Generate a new random X25519PrivateKey.
	*/
	static new() {
		return X25519PrivateKey.random();
	}
	/**
	* Generate a new random X25519PrivateKey.
	*/
	static random() {
		const rng = new SecureRandomNumberGenerator$1();
		return X25519PrivateKey.newUsing(rng);
	}
	/**
	* Generate a new random X25519PrivateKey using provided RNG.
	*/
	static newUsing(rng) {
		return new X25519PrivateKey(rng.randomData(32));
	}
	/**
	* Generate a new random X25519PrivateKey and corresponding X25519PublicKey.
	*/
	static keypair() {
		const privateKey = X25519PrivateKey.new();
		return [privateKey, privateKey.publicKey()];
	}
	/**
	* Generate a new random X25519PrivateKey and corresponding X25519PublicKey
	* using the given random number generator.
	*/
	static keypairUsing(rng) {
		const privateKey = X25519PrivateKey.newUsing(rng);
		return [privateKey, privateKey.publicKey()];
	}
	/**
	* Derive an X25519PrivateKey from the given key material.
	*
	* @param keyMaterial - The key material to derive from
	* @returns A new X25519PrivateKey derived from the key material
	*/
	static deriveFromKeyMaterial(keyMaterial) {
		return new X25519PrivateKey(deriveAgreementPrivateKey(keyMaterial));
	}
	/**
	* Restore an X25519PrivateKey from a fixed-size array of bytes.
	*/
	static fromData(data) {
		return new X25519PrivateKey(new Uint8Array(data));
	}
	/**
	* Restore an X25519PrivateKey from a reference to an array of bytes.
	* Validates the length.
	*/
	static fromDataRef(data) {
		if (data.length !== 32) throw CryptoError.invalidSize(32, data.length);
		return X25519PrivateKey.fromData(data);
	}
	/**
	* Create an X25519PrivateKey from raw bytes (legacy alias).
	*/
	static from(data) {
		return X25519PrivateKey.fromData(data);
	}
	/**
	* Restore an X25519PrivateKey from a hex string.
	*/
	static fromHex(hex) {
		return X25519PrivateKey.fromData(hexToBytes(hex));
	}
	/**
	* Get a reference to the fixed-size array of bytes.
	*/
	data() {
		return this._data;
	}
	/**
	* Get the raw private key bytes (copy).
	*/
	toData() {
		return new Uint8Array(this._data);
	}
	/**
	* Get hex string representation.
	*/
	hex() {
		return bytesToHex(this._data);
	}
	/**
	* Get hex string representation (alias for hex()).
	*/
	toHex() {
		return this.hex();
	}
	/**
	* Get base64 representation.
	*/
	toBase64() {
		return toBase64(this._data);
	}
	/**
	* Get the X25519PublicKey corresponding to this X25519PrivateKey.
	*/
	publicKey() {
		if (this._publicKey === void 0) {
			const publicKeyBytes = x25519PublicKeyFromPrivateKey(this._data);
			this._publicKey = X25519PublicKey.fromData(publicKeyBytes);
		}
		return this._publicKey;
	}
	/**
	* Derive a shared symmetric key from this X25519PrivateKey and the given
	* X25519PublicKey.
	*
	* @param publicKey - The other party's public key
	* @returns A SymmetricKey derived from the shared secret
	*/
	sharedKeyWith(publicKey) {
		const shared = x25519SharedKey(this._data, publicKey.data());
		return SymmetricKey.fromData(shared);
	}
	/**
	* Perform ECDH key agreement with a public key (legacy method).
	*
	* @deprecated Use sharedKeyWith() instead which returns a SymmetricKey
	*/
	sharedSecret(publicKey) {
		try {
			const shared = x25519SharedKey(this._data, publicKey.data());
			return new Uint8Array(shared);
		} catch (e) {
			throw CryptoError.cryptoOperation(`ECDH key agreement failed: ${String(e)}`);
		}
	}
	/**
	* Compare with another X25519PrivateKey.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `X25519PrivateKey(${this.toHex().substring(0, 16)}...)`;
	}
	/**
	* Returns the CBOR tags associated with X25519PrivateKey.
	*/
	cborTags() {
		return tagsForValues([X25519_PRIVATE_KEY.value]);
	}
	/**
	* Returns the untagged CBOR encoding (as a byte string).
	*/
	untaggedCbor() {
		return toByteString(this._data);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates an X25519PrivateKey by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cbor) {
		const data = expectBytes(cbor);
		return X25519PrivateKey.fromDataRef(data);
	}
	/**
	* Creates an X25519PrivateKey by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cbor) {
		validateTag(cbor, this.cborTags());
		const content = extractTaggedContent(cbor);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cbor) {
		return new X25519PrivateKey(/* @__PURE__ */ new Uint8Array(32)).fromTaggedCbor(cbor);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cbor = decodeCbor$3(data);
		return X25519PrivateKey.fromTaggedCbor(cbor);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cbor = decodeCbor$3(data);
		return new X25519PrivateKey(/* @__PURE__ */ new Uint8Array(32)).fromUntaggedCbor(cbor);
	}
	/**
	* Returns the UR representation of the X25519PrivateKey.
	* Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
	*/
	ur() {
		const name = X25519_PRIVATE_KEY.name;
		if (name === void 0) throw new Error("X25519_PRIVATE_KEY tag name is undefined");
		return UR.new(name, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates an X25519PrivateKey from a UR.
	*/
	static fromUR(ur) {
		const name = X25519_PRIVATE_KEY.name;
		if (name === void 0) throw new Error("X25519_PRIVATE_KEY tag name is undefined");
		ur.checkType(name);
		return new X25519PrivateKey(/* @__PURE__ */ new Uint8Array(32)).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates an X25519PrivateKey from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return X25519PrivateKey.fromUR(ur);
	}
};
//#endregion
//#region src/mlkem/mlkem-level.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* MLKEM Security Level - ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism)
*
* ML-KEM is a post-quantum key encapsulation mechanism standardized by NIST.
* It provides three security levels corresponding to different NIST security categories.
*
* Security levels:
* - MLKEM512: NIST Level 1 (equivalent to AES-128)
* - MLKEM768: NIST Level 3 (equivalent to AES-192)
* - MLKEM1024: NIST Level 5 (equivalent to AES-256)
*
* Ported from bc-components-rust/src/mlkem/mlkem_level.rs
*
* Naming note: Rust calls this enum `MLKEM`. TypeScript uses `MLKEMLevel`
* to avoid colliding with the keypair type names (`MLKEMPrivateKey` /
* `MLKEMPublicKey` / `MLKEMCiphertext`). The CBOR discriminator (the
* numeric level) is identical in both languages — this is a TS-only
* naming choice with no wire-format effect.
*/
/**
* ML-KEM security levels.
*
* The numeric values correspond to the ML-KEM parameter set:
* - 512: ML-KEM-512 (NIST Level 1)
* - 768: ML-KEM-768 (NIST Level 3)
* - 1024: ML-KEM-1024 (NIST Level 5)
*/
let MLKEMLevel = /* @__PURE__ */ function(MLKEMLevel) {
	/** NIST Level 1 - AES-128 equivalent security */
	MLKEMLevel[MLKEMLevel["MLKEM512"] = 512] = "MLKEM512";
	/** NIST Level 3 - AES-192 equivalent security */
	MLKEMLevel[MLKEMLevel["MLKEM768"] = 768] = "MLKEM768";
	/** NIST Level 5 - AES-256 equivalent security */
	MLKEMLevel[MLKEMLevel["MLKEM1024"] = 1024] = "MLKEM1024";
	return MLKEMLevel;
}({});
/**
* Key sizes for each ML-KEM security level.
*/
const MLKEM_KEY_SIZES = {
	[512]: {
		privateKey: 1632,
		publicKey: 800,
		ciphertext: 768,
		sharedSecret: 32
	},
	[768]: {
		privateKey: 2400,
		publicKey: 1184,
		ciphertext: 1088,
		sharedSecret: 32
	},
	[1024]: {
		privateKey: 3168,
		publicKey: 1568,
		ciphertext: 1568,
		sharedSecret: 32
	}
};
/**
* Get the private key size for a given ML-KEM level.
*/
function mlkemPrivateKeySize(level) {
	return MLKEM_KEY_SIZES[level].privateKey;
}
/**
* Get the public key size for a given ML-KEM level.
*/
function mlkemPublicKeySize(level) {
	return MLKEM_KEY_SIZES[level].publicKey;
}
/**
* Get the ciphertext size for a given ML-KEM level.
*/
function mlkemCiphertextSize(level) {
	return MLKEM_KEY_SIZES[level].ciphertext;
}
/**
* Get the shared secret size for a given ML-KEM level.
* Note: This is always 32 bytes for all ML-KEM levels.
*/
function mlkemSharedSecretSize(level) {
	return MLKEM_KEY_SIZES[level].sharedSecret;
}
/**
* Convert an ML-KEM level to its string representation.
*/
function mlkemLevelToString(level) {
	switch (level) {
		case 512: return "MLKEM512";
		case 768: return "MLKEM768";
		case 1024: return "MLKEM1024";
	}
}
/**
* Parse an ML-KEM level from its numeric value.
*/
function mlkemLevelFromValue(value) {
	switch (value) {
		case 512: return 512;
		case 768: return 768;
		case 1024: return 1024;
		default: throw new Error(`Invalid MLKEM level value: ${value}`);
	}
}
/**
* Generate an ML-KEM keypair for the given security level.
*
* @param level - The ML-KEM security level
* @returns Object containing publicKey and secretKey bytes
*/
function mlkemGenerateKeypair(level) {
	return mlkemGenerateKeypairUsing(level, new SecureRandomNumberGenerator$1());
}
/**
* Generate an ML-KEM keypair using a provided RNG.
*
* @param level - The ML-KEM security level
* @param rng - Random number generator
* @returns Object containing publicKey and secretKey bytes
*/
function mlkemGenerateKeypairUsing(level, rng) {
	const seed = rng.randomData(64);
	switch (level) {
		case 512: {
			const keypair = ml_kem512.keygen(seed);
			return {
				publicKey: keypair.publicKey,
				secretKey: keypair.secretKey
			};
		}
		case 768: {
			const keypair = ml_kem768.keygen(seed);
			return {
				publicKey: keypair.publicKey,
				secretKey: keypair.secretKey
			};
		}
		case 1024: {
			const keypair = ml_kem1024.keygen(seed);
			return {
				publicKey: keypair.publicKey,
				secretKey: keypair.secretKey
			};
		}
	}
}
/**
* Encapsulate a new shared secret using a public key.
*
* @param level - The ML-KEM security level
* @param publicKey - The public key bytes
* @returns Object containing sharedSecret and ciphertext bytes
*/
function mlkemEncapsulate(level, publicKey) {
	switch (level) {
		case 512: {
			const result = ml_kem512.encapsulate(publicKey);
			return {
				sharedSecret: result.sharedSecret,
				ciphertext: result.cipherText
			};
		}
		case 768: {
			const result = ml_kem768.encapsulate(publicKey);
			return {
				sharedSecret: result.sharedSecret,
				ciphertext: result.cipherText
			};
		}
		case 1024: {
			const result = ml_kem1024.encapsulate(publicKey);
			return {
				sharedSecret: result.sharedSecret,
				ciphertext: result.cipherText
			};
		}
	}
}
/**
* Decapsulate a shared secret using a private key and ciphertext.
*
* @param level - The ML-KEM security level
* @param secretKey - The secret key bytes
* @param ciphertext - The ciphertext bytes
* @returns The shared secret bytes
*/
function mlkemDecapsulate(level, secretKey, ciphertext) {
	switch (level) {
		case 512: return ml_kem512.decapsulate(ciphertext, secretKey);
		case 768: return ml_kem768.decapsulate(ciphertext, secretKey);
		case 1024: return ml_kem1024.decapsulate(ciphertext, secretKey);
	}
}
/**
* Private key portion sizes for each ML-KEM level.
* The decapsulation key structure is: dk = (dk_pke || ek_pke || H(ek) || z)
* where dk_pke is the private portion before the public key.
*/
const MLKEM_DK_PKE_SIZES = {
	[512]: 768,
	[768]: 1152,
	[1024]: 1536
};
/**
* Extract the public key from a secret key.
*
* In ML-KEM (FIPS 203), the decapsulation key contains the encapsulation key (public key)
* embedded within it. The structure is: dk = (dk_pke || ek_pke || H(ek) || z)
*
* @param level - The ML-KEM security level
* @param secretKey - The secret key bytes
* @returns The public key bytes extracted from the secret key
*/
function mlkemExtractPublicKey(level, secretKey) {
	const dkPkeSize = MLKEM_DK_PKE_SIZES[level];
	const publicKeySize = MLKEM_KEY_SIZES[level].publicKey;
	const offset = dkPkeSize;
	return secretKey.slice(offset, offset + publicKeySize);
}
//#endregion
//#region src/encapsulation/encapsulation-scheme.ts
/**
* Available key encapsulation schemes.
*/
let EncapsulationScheme = /* @__PURE__ */ function(EncapsulationScheme) {
	/**
	* X25519 Diffie-Hellman key exchange (default).
	* Based on Curve25519 as defined in RFC 7748.
	*/
	EncapsulationScheme["X25519"] = "x25519";
	/**
	* ML-KEM-512 post-quantum key encapsulation (NIST security level 1).
	*/
	EncapsulationScheme["MLKEM512"] = "mlkem512";
	/**
	* ML-KEM-768 post-quantum key encapsulation (NIST security level 3).
	*/
	EncapsulationScheme["MLKEM768"] = "mlkem768";
	/**
	* ML-KEM-1024 post-quantum key encapsulation (NIST security level 5).
	*/
	EncapsulationScheme["MLKEM1024"] = "mlkem1024";
	return EncapsulationScheme;
}({});
/**
* Returns the default encapsulation scheme (X25519).
*/
function defaultEncapsulationScheme() {
	return "x25519";
}
/**
* Generate a new keypair for the given encapsulation scheme.
*
* @param scheme - The encapsulation scheme to use (defaults to X25519)
* @returns A tuple of [privateKey, publicKey]
*/
function createEncapsulationKeypair(scheme = "x25519") {
	switch (scheme) {
		case "x25519": return EncapsulationPrivateKey.keypair();
		case "mlkem512": return EncapsulationPrivateKey.mlkemKeypair(512);
		case "mlkem768": return EncapsulationPrivateKey.mlkemKeypair(768);
		case "mlkem1024": return EncapsulationPrivateKey.mlkemKeypair(1024);
	}
}
/**
* Generate a new keypair for the given encapsulation scheme using a specific RNG.
*
* Note: Only X25519 supports deterministic keypair generation.
* MLKEM schemes do not support deterministic generation (matching Rust behavior).
*
* @param rng - The random number generator to use
* @param scheme - The encapsulation scheme to use (defaults to X25519)
* @returns A tuple of [privateKey, publicKey]
* @throws Error if the scheme doesn't support deterministic generation
*/
function createEncapsulationKeypairUsing(rng, scheme = "x25519") {
	switch (scheme) {
		case "x25519": return EncapsulationPrivateKey.keypairUsing(rng);
		case "mlkem512":
		case "mlkem768":
		case "mlkem1024": throw new Error("Deterministic keypair generation not supported for this encapsulation scheme");
	}
}
//#endregion
//#region src/mlkem/mlkem-ciphertext.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* MLKEMCiphertext - ML-KEM Ciphertext for post-quantum key encapsulation
*
* MLKEMCiphertext wraps an ML-KEM ciphertext for transmission and decapsulation.
* It supports all three security levels (MLKEM512, MLKEM768, MLKEM1024).
*
* # CBOR Serialization
*
* MLKEMCiphertext is serialized with tag 40102:
* ```
* #6.40102([level, h'<ciphertext-bytes>'])
* ```
*
* # UR Serialization
*
* UR type: `mlkem-ciphertext`
*
* Ported from bc-components-rust/src/mlkem/mlkem_ciphertext.rs
*/
/**
* MLKEMCiphertext - Post-quantum key encapsulation ciphertext using ML-KEM.
*/
var MLKEMCiphertext = class MLKEMCiphertext {
	_level;
	_data;
	constructor(level, data) {
		const expectedSize = mlkemCiphertextSize(level);
		if (data.length !== expectedSize) throw new Error(`MLKEMCiphertext (${mlkemLevelToString(level)}) must be ${expectedSize} bytes, got ${data.length}`);
		this._level = level;
		this._data = new Uint8Array(data);
	}
	/**
	* Create an MLKEMCiphertext from raw bytes.
	*
	* @param level - The ML-KEM security level
	* @param data - The ciphertext bytes
	*/
	static fromBytes(level, data) {
		return new MLKEMCiphertext(level, data);
	}
	/**
	* Returns the security level of this ciphertext.
	*/
	level() {
		return this._level;
	}
	/**
	* Returns the raw ciphertext bytes.
	*/
	asBytes() {
		return this._data;
	}
	/**
	* Returns a copy of the raw ciphertext bytes.
	*/
	data() {
		return new Uint8Array(this._data);
	}
	/**
	* Returns the size of the ciphertext in bytes.
	*/
	size() {
		return this._data.length;
	}
	/**
	* Compare with another MLKEMCiphertext.
	*/
	equals(other) {
		if (this._level !== other._level) return false;
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*/
	toString() {
		const hex = bytesToHex(this._data);
		return `MLKEMCiphertext(${mlkemLevelToString(this._level)}, ${hex.substring(0, 16)}...)`;
	}
	/**
	* Returns the CBOR tags associated with MLKEMCiphertext.
	*/
	cborTags() {
		return tagsForValues([MLKEM_CIPHERTEXT.value]);
	}
	/**
	* Returns the untagged CBOR encoding.
	*
	* Format: [level, ciphertext_bytes]
	*/
	untaggedCbor() {
		return cbor$3([this._level, this._data]);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates an MLKEMCiphertext by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cborValue) {
		const elements = expectArray(cborValue);
		if (elements.length !== 2) throw new Error(`MLKEMCiphertext CBOR must have 2 elements, got ${elements.length}`);
		const level = mlkemLevelFromValue(Number(expectInteger(elements[0])));
		const data = expectBytes(elements[1]);
		return MLKEMCiphertext.fromBytes(level, data);
	}
	/**
	* Creates an MLKEMCiphertext by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		const dummyData = new Uint8Array(mlkemCiphertextSize(512));
		return new MLKEMCiphertext(512, dummyData).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return MLKEMCiphertext.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		const dummyData = new Uint8Array(mlkemCiphertextSize(512));
		return new MLKEMCiphertext(512, dummyData).fromUntaggedCbor(cborValue);
	}
	/**
	* Returns the UR representation.
	*/
	ur() {
		const name = MLKEM_CIPHERTEXT.name;
		if (name === void 0) throw new Error("MLKEM_CIPHERTEXT tag name is undefined");
		return UR.new(name, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates an MLKEMCiphertext from a UR.
	*/
	static fromUR(ur) {
		if (ur.urTypeStr() !== MLKEM_CIPHERTEXT.name) throw new Error(`Expected UR type ${MLKEM_CIPHERTEXT.name}, got ${ur.urTypeStr()}`);
		const dummyData = new Uint8Array(mlkemCiphertextSize(512));
		return new MLKEMCiphertext(512, dummyData).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates an MLKEMCiphertext from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return MLKEMCiphertext.fromUR(ur);
	}
};
//#endregion
//#region src/encapsulation/encapsulation-ciphertext.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Encapsulation ciphertext for key encapsulation mechanisms
*
* This type represents the ciphertext produced during key encapsulation.
* For X25519, this is actually an ephemeral public key used in ECDH.
* For MLKEM, this is the ciphertext from the ML-KEM encapsulation.
*
* # CBOR Serialization
*
* For X25519, the ciphertext is serialized with the X25519 public key tag (40011).
* For MLKEM, the ciphertext is serialized with tag 40102.
*
* Ported from bc-components-rust/src/encapsulation/encapsulation_ciphertext.rs
*/
/**
* Convert MLKEMLevel to EncapsulationScheme
*/
function mlkemLevelToScheme$2(level) {
	switch (level) {
		case 512: return "mlkem512";
		case 768: return "mlkem768";
		case 1024: return "mlkem1024";
	}
}
/**
* Check if a scheme is an MLKEM scheme
*/
function isMlkemScheme$2(scheme) {
	return scheme === "mlkem512" || scheme === "mlkem768" || scheme === "mlkem1024";
}
/**
* Represents the ciphertext from a key encapsulation operation.
*
* For X25519, this wraps an ephemeral public key.
* For MLKEM, this wraps an MLKEMCiphertext.
*/
var EncapsulationCiphertext = class EncapsulationCiphertext {
	_scheme;
	_x25519PublicKey;
	_mlkemCiphertext;
	constructor(scheme, x25519PublicKey, mlkemCiphertext) {
		this._scheme = scheme;
		this._x25519PublicKey = x25519PublicKey;
		this._mlkemCiphertext = mlkemCiphertext;
	}
	/**
	* Create an EncapsulationCiphertext from an X25519PublicKey.
	*/
	static fromX25519PublicKey(publicKey) {
		return new EncapsulationCiphertext("x25519", publicKey, void 0);
	}
	/**
	* Create an EncapsulationCiphertext from raw X25519 data.
	*/
	static fromX25519Data(data) {
		const publicKey = X25519PublicKey.fromDataRef(data);
		return EncapsulationCiphertext.fromX25519PublicKey(publicKey);
	}
	/**
	* Create an EncapsulationCiphertext from an MLKEMCiphertext.
	*/
	static fromMlkem(ciphertext) {
		const scheme = mlkemLevelToScheme$2(ciphertext.level());
		return new EncapsulationCiphertext(scheme, void 0, ciphertext);
	}
	/**
	* Create an EncapsulationCiphertext from raw MLKEM ciphertext bytes.
	*/
	static fromMlkemData(level, data) {
		const ciphertext = MLKEMCiphertext.fromBytes(level, data);
		return EncapsulationCiphertext.fromMlkem(ciphertext);
	}
	/**
	* Returns the encapsulation scheme.
	*/
	encapsulationScheme() {
		return this._scheme;
	}
	/**
	* Returns true if this is an X25519 ciphertext.
	*/
	isX25519() {
		return this._scheme === "x25519";
	}
	/**
	* Returns true if this is an MLKEM ciphertext.
	*/
	isMlkem() {
		return isMlkemScheme$2(this._scheme);
	}
	/**
	* Returns the X25519 public key if this is an X25519 ciphertext.
	* @throws Error if this is not an X25519 ciphertext
	*/
	x25519PublicKey() {
		if (this._x25519PublicKey === void 0) throw new Error("Not an X25519 ciphertext");
		return this._x25519PublicKey;
	}
	/**
	* Returns the MLKEM ciphertext if this is an MLKEM ciphertext.
	* @throws Error if this is not an MLKEM ciphertext
	*/
	mlkemCiphertext() {
		if (this._mlkemCiphertext === void 0) throw new Error("Not an MLKEM ciphertext");
		return this._mlkemCiphertext;
	}
	/**
	* Returns the X25519 public key if available, or null.
	*/
	toX25519() {
		return this._x25519PublicKey ?? null;
	}
	/**
	* Returns the MLKEM ciphertext if available, or null.
	*/
	toMlkem() {
		return this._mlkemCiphertext ?? null;
	}
	/**
	* Returns the raw ciphertext data.
	*/
	data() {
		if (this._scheme === "x25519") {
			const pk = this._x25519PublicKey;
			if (pk === void 0) throw new Error("X25519 public key not set");
			return pk.data();
		} else if (isMlkemScheme$2(this._scheme)) {
			const ct = this._mlkemCiphertext;
			if (ct === void 0) throw new Error("MLKEM ciphertext not set");
			return ct.data();
		}
		throw new Error(`Unsupported scheme: ${String(this._scheme)}`);
	}
	/**
	* Compare with another EncapsulationCiphertext.
	*/
	equals(other) {
		if (this._scheme !== other._scheme) return false;
		if (this._scheme === "x25519") {
			const thisPk = this._x25519PublicKey;
			const otherPk = other._x25519PublicKey;
			if (thisPk === void 0 || otherPk === void 0) return false;
			return thisPk.equals(otherPk);
		} else if (isMlkemScheme$2(this._scheme)) {
			const thisCt = this._mlkemCiphertext;
			const otherCt = other._mlkemCiphertext;
			if (thisCt === void 0 || otherCt === void 0) return false;
			return thisCt.equals(otherCt);
		}
		return false;
	}
	/**
	* Get string representation.
	*/
	toString() {
		if (this._scheme === "x25519") return `EncapsulationCiphertext(X25519, ${bytesToHex(this.data()).substring(0, 16)}...)`;
		else if (isMlkemScheme$2(this._scheme)) return `EncapsulationCiphertext(${String(this._scheme)}, ${bytesToHex(this.data()).substring(0, 16)}...)`;
		return `EncapsulationCiphertext(${String(this._scheme)})`;
	}
	/**
	* Returns the CBOR tags associated with this ciphertext.
	*/
	cborTags() {
		if (this._scheme === "x25519") return tagsForValues([X25519_PUBLIC_KEY.value]);
		else if (isMlkemScheme$2(this._scheme)) return tagsForValues([MLKEM_CIPHERTEXT.value]);
		throw new Error(`Unsupported scheme: ${String(this._scheme)}`);
	}
	/**
	* Returns the untagged CBOR encoding.
	*/
	untaggedCbor() {
		if (this._scheme === "x25519") {
			const pk = this._x25519PublicKey;
			if (pk === void 0) throw new Error("X25519 public key not set");
			return toByteString(pk.data());
		} else if (isMlkemScheme$2(this._scheme)) {
			const ct = this._mlkemCiphertext;
			if (ct === void 0) throw new Error("MLKEM ciphertext not set");
			return ct.untaggedCbor();
		}
		throw new Error(`Unsupported scheme: ${String(this._scheme)}`);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates an EncapsulationCiphertext by decoding it from untagged CBOR.
	* Note: Without tags, we assume X25519 scheme.
	*/
	fromUntaggedCbor(cborValue) {
		const data = expectBytes(cborValue);
		const publicKey = X25519PublicKey.fromDataRef(data);
		return EncapsulationCiphertext.fromX25519PublicKey(publicKey);
	}
	/**
	* Creates an EncapsulationCiphertext by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		const tag = tagValue(cborValue);
		if (tag === X25519_PUBLIC_KEY.value) {
			const content = extractTaggedContent(cborValue);
			const data = expectBytes(content);
			const publicKey = X25519PublicKey.fromDataRef(data);
			return EncapsulationCiphertext.fromX25519PublicKey(publicKey);
		}
		if (tag === MLKEM_CIPHERTEXT.value) {
			const mlkemCiphertext = MLKEMCiphertext.fromTaggedCbor(cborValue);
			return EncapsulationCiphertext.fromMlkem(mlkemCiphertext);
		}
		throw new Error(`Unknown ciphertext tag: ${tag}`);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		return EncapsulationCiphertext.fromX25519PublicKey(X25519PublicKey.fromData(/* @__PURE__ */ new Uint8Array(32))).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return EncapsulationCiphertext.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return EncapsulationCiphertext.fromX25519PublicKey(X25519PublicKey.fromData(/* @__PURE__ */ new Uint8Array(32))).fromUntaggedCbor(cborValue);
	}
};
//#endregion
//#region src/mlkem/mlkem-public-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* MLKEMPublicKey - ML-KEM Public Key for post-quantum key encapsulation
*
* MLKEMPublicKey wraps an ML-KEM public key for encapsulating shared secrets.
* It supports all three security levels (MLKEM512, MLKEM768, MLKEM1024).
*
* # CBOR Serialization
*
* MLKEMPublicKey is serialized with tag 40101:
* ```
* #6.40101([level, h'<public-key-bytes>'])
* ```
*
* # UR Serialization
*
* UR type: `mlkem-public-key`
*
* Ported from bc-components-rust/src/mlkem/mlkem_public_key.rs
*/
/**
* MLKEMPublicKey - Post-quantum key encapsulation public key using ML-KEM.
*/
var MLKEMPublicKey = class MLKEMPublicKey {
	_level;
	_data;
	constructor(level, data) {
		const expectedSize = mlkemPublicKeySize(level);
		if (data.length !== expectedSize) throw new Error(`MLKEMPublicKey (${mlkemLevelToString(level)}) must be ${expectedSize} bytes, got ${data.length}`);
		this._level = level;
		this._data = new Uint8Array(data);
	}
	/**
	* Create an MLKEMPublicKey from raw bytes.
	*
	* @param level - The ML-KEM security level
	* @param data - The public key bytes
	*/
	static fromBytes(level, data) {
		return new MLKEMPublicKey(level, data);
	}
	/**
	* Returns the security level of this key.
	*/
	level() {
		return this._level;
	}
	/**
	* Returns the raw key bytes.
	*/
	asBytes() {
		return this._data;
	}
	/**
	* Returns a copy of the raw key bytes.
	*/
	data() {
		return new Uint8Array(this._data);
	}
	/**
	* Returns the size of the key in bytes.
	*/
	size() {
		return this._data.length;
	}
	/**
	* Encapsulate a new shared secret.
	*
	* This creates a random shared secret and encapsulates it, returning both
	* the shared secret (to be used as a symmetric key) and the ciphertext
	* (to be sent to the private key holder for decapsulation).
	*
	* @returns Object containing sharedSecret and ciphertext
	*/
	encapsulate() {
		const result = mlkemEncapsulate(this._level, this._data);
		return {
			sharedSecret: SymmetricKey.fromData(result.sharedSecret),
			ciphertext: MLKEMCiphertext.fromBytes(this._level, result.ciphertext)
		};
	}
	/**
	* Compare with another MLKEMPublicKey.
	*/
	equals(other) {
		if (this._level !== other._level) return false;
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*/
	toString() {
		const hex = bytesToHex(this._data);
		return `MLKEMPublicKey(${mlkemLevelToString(this._level)}, ${hex.substring(0, 16)}...)`;
	}
	/**
	* Returns the CBOR tags associated with MLKEMPublicKey.
	*/
	cborTags() {
		return tagsForValues([MLKEM_PUBLIC_KEY.value]);
	}
	/**
	* Returns the untagged CBOR encoding.
	*
	* Format: [level, key_bytes]
	*/
	untaggedCbor() {
		return cbor$3([this._level, this._data]);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates an MLKEMPublicKey by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cborValue) {
		const elements = expectArray(cborValue);
		if (elements.length !== 2) throw new Error(`MLKEMPublicKey CBOR must have 2 elements, got ${elements.length}`);
		const level = mlkemLevelFromValue(Number(expectInteger(elements[0])));
		const data = expectBytes(elements[1]);
		return MLKEMPublicKey.fromBytes(level, data);
	}
	/**
	* Creates an MLKEMPublicKey by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		const dummyData = new Uint8Array(mlkemPublicKeySize(512));
		return new MLKEMPublicKey(512, dummyData).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return MLKEMPublicKey.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		const dummyData = new Uint8Array(mlkemPublicKeySize(512));
		return new MLKEMPublicKey(512, dummyData).fromUntaggedCbor(cborValue);
	}
	/**
	* Returns the UR representation.
	*/
	ur() {
		const name = MLKEM_PUBLIC_KEY.name;
		if (name === void 0) throw new Error("MLKEM_PUBLIC_KEY tag name is undefined");
		return UR.new(name, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates an MLKEMPublicKey from a UR.
	*/
	static fromUR(ur) {
		if (ur.urTypeStr() !== MLKEM_PUBLIC_KEY.name) throw new Error(`Expected UR type ${MLKEM_PUBLIC_KEY.name}, got ${ur.urTypeStr()}`);
		const dummyData = new Uint8Array(mlkemPublicKeySize(512));
		return new MLKEMPublicKey(512, dummyData).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates an MLKEMPublicKey from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return MLKEMPublicKey.fromUR(ur);
	}
};
//#endregion
//#region src/encapsulation/encapsulation-public-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Encapsulation public key for key encapsulation mechanisms
*
* This type represents a public key that can be used to encapsulate (encrypt)
* a shared secret. The recipient can then use their corresponding private key
* to decapsulate (decrypt) the shared secret.
*
* For X25519, encapsulation works by:
* 1. Generating an ephemeral key pair
* 2. Performing ECDH with the ephemeral private key and the recipient's public key
* 3. Returning the shared secret and the ephemeral public key as "ciphertext"
*
* For MLKEM, encapsulation uses the ML-KEM algorithm to generate a shared secret
* and ciphertext.
*
* # CBOR Serialization
*
* For X25519, the public key is serialized with tag 40011.
* For MLKEM, the public key is serialized with tag 40101.
*
* Ported from bc-components-rust/src/encapsulation/encapsulation_public_key.rs
*/
/**
* Convert MLKEMLevel to EncapsulationScheme
*/
function mlkemLevelToScheme$1(level) {
	switch (level) {
		case 512: return "mlkem512";
		case 768: return "mlkem768";
		case 1024: return "mlkem1024";
	}
}
/**
* Check if a scheme is an MLKEM scheme
*/
function isMlkemScheme$1(scheme) {
	return scheme === "mlkem512" || scheme === "mlkem768" || scheme === "mlkem1024";
}
/**
* Represents a public key for key encapsulation.
*
* Use this to encapsulate a shared secret for a recipient.
*/
var EncapsulationPublicKey = class EncapsulationPublicKey {
	_scheme;
	_x25519PublicKey;
	_mlkemPublicKey;
	constructor(scheme, x25519PublicKey, mlkemPublicKey) {
		this._scheme = scheme;
		this._x25519PublicKey = x25519PublicKey;
		this._mlkemPublicKey = mlkemPublicKey;
	}
	/**
	* Create an EncapsulationPublicKey from an X25519PublicKey.
	*/
	static fromX25519PublicKey(publicKey) {
		return new EncapsulationPublicKey("x25519", publicKey, void 0);
	}
	/**
	* Create an EncapsulationPublicKey from raw X25519 public key bytes.
	*/
	static fromX25519Data(data) {
		const publicKey = X25519PublicKey.fromDataRef(data);
		return EncapsulationPublicKey.fromX25519PublicKey(publicKey);
	}
	/**
	* Create an EncapsulationPublicKey from an MLKEMPublicKey.
	*/
	static fromMlkem(publicKey) {
		const scheme = mlkemLevelToScheme$1(publicKey.level());
		return new EncapsulationPublicKey(scheme, void 0, publicKey);
	}
	/**
	* Create an EncapsulationPublicKey from raw MLKEM public key bytes.
	*/
	static fromMlkemData(level, data) {
		const publicKey = MLKEMPublicKey.fromBytes(level, data);
		return EncapsulationPublicKey.fromMlkem(publicKey);
	}
	/**
	* Returns the encapsulation scheme.
	*/
	encapsulationScheme() {
		return this._scheme;
	}
	/**
	* Returns true if this is an X25519 public key.
	*/
	isX25519() {
		return this._scheme === "x25519";
	}
	/**
	* Returns true if this is an MLKEM public key.
	*/
	isMlkem() {
		return isMlkemScheme$1(this._scheme);
	}
	/**
	* Returns the X25519 public key if this is an X25519 encapsulation key.
	* @throws Error if this is not an X25519 key
	*/
	x25519PublicKey() {
		if (this._x25519PublicKey === void 0) throw new Error("Not an X25519 public key");
		return this._x25519PublicKey;
	}
	/**
	* Returns the MLKEM public key if this is an MLKEM encapsulation key.
	* @throws Error if this is not an MLKEM key
	*/
	mlkemPublicKey() {
		if (this._mlkemPublicKey === void 0) throw new Error("Not an MLKEM public key");
		return this._mlkemPublicKey;
	}
	/**
	* Returns the X25519 public key if available, or null.
	*/
	toX25519() {
		return this._x25519PublicKey ?? null;
	}
	/**
	* Returns the MLKEM public key if available, or null.
	*/
	toMlkem() {
		return this._mlkemPublicKey ?? null;
	}
	/**
	* Returns the raw public key data.
	*/
	data() {
		if (this._scheme === "x25519") {
			const pk = this._x25519PublicKey;
			if (pk === void 0) throw new Error("X25519 public key not set");
			return pk.data();
		} else if (isMlkemScheme$1(this._scheme)) {
			const pk = this._mlkemPublicKey;
			if (pk === void 0) throw new Error("MLKEM public key not set");
			return pk.data();
		}
		throw new Error(`Unsupported scheme: ${String(this._scheme)}`);
	}
	/**
	* Returns this object as an EncapsulationPublicKey.
	*
	* This method allows EncapsulationPublicKey to implement the Encrypter interface.
	* Since this class is itself an encapsulation public key, it returns `this`.
	*
	* @returns This encapsulation public key
	*/
	encapsulationPublicKey() {
		return this;
	}
	/**
	* Encapsulate a new shared secret for this public key.
	*
	* This generates a random shared secret and encapsulates it so that only
	* the holder of the corresponding private key can recover it.
	*
	* @returns A tuple of [sharedSecret, ciphertext]
	*/
	encapsulateNewSharedSecret() {
		if (this._scheme === "x25519") {
			const pk = this._x25519PublicKey;
			if (pk === void 0) throw new Error("X25519 public key not set");
			const [ephemeralPrivate, ephemeralPublic] = X25519PrivateKey.keypair();
			return [ephemeralPrivate.sharedKeyWith(pk), EncapsulationCiphertext.fromX25519PublicKey(ephemeralPublic)];
		} else if (isMlkemScheme$1(this._scheme)) {
			const pk = this._mlkemPublicKey;
			if (pk === void 0) throw new Error("MLKEM public key not set");
			const { sharedSecret, ciphertext: mlkemCiphertext } = pk.encapsulate();
			return [sharedSecret, EncapsulationCiphertext.fromMlkem(mlkemCiphertext)];
		}
		throw new Error(`Unsupported scheme: ${String(this._scheme)}`);
	}
	/**
	* Compare with another EncapsulationPublicKey.
	*/
	equals(other) {
		if (this._scheme !== other._scheme) return false;
		if (this._scheme === "x25519") {
			const thisPk = this._x25519PublicKey;
			const otherPk = other._x25519PublicKey;
			if (thisPk === void 0 || otherPk === void 0) return false;
			return thisPk.equals(otherPk);
		} else if (isMlkemScheme$1(this._scheme)) {
			const thisPk = this._mlkemPublicKey;
			const otherPk = other._mlkemPublicKey;
			if (thisPk === void 0 || otherPk === void 0) return false;
			return thisPk.equals(otherPk);
		}
		return false;
	}
	/**
	* Get string representation.
	*
	* Mirrors Rust `Display for EncapsulationPublicKey`
	* (`bc-components-rust/src/encapsulation/encapsulation_public_key.rs:191-205`):
	*   `EncapsulationPublicKey(<ref_hex_short>, <inner_key_display>)`
	* where ref_hex_short is computed from the tagged-CBOR form.
	*/
	toString() {
		const refShort = this.reference().shortReference("hex");
		let innerDisplay;
		if (this._scheme === "x25519" && this._x25519PublicKey !== void 0) innerDisplay = this._x25519PublicKey.toString();
		else if (isMlkemScheme$1(this._scheme) && this._mlkemPublicKey !== void 0) innerDisplay = this._mlkemPublicKey.toString();
		else innerDisplay = String(this._scheme);
		return `EncapsulationPublicKey(${refShort}, ${innerDisplay})`;
	}
	/**
	* Returns a unique reference to this EncapsulationPublicKey instance.
	*
	* The reference is derived from the SHA-256 hash of the tagged CBOR
	* representation, providing a unique, content-addressable identifier.
	*/
	reference() {
		const digest = Digest.fromImage(this.taggedCborData());
		return Reference.from(digest);
	}
	/**
	* Returns the CBOR tags associated with this public key.
	*/
	cborTags() {
		if (this._scheme === "x25519") return tagsForValues([X25519_PUBLIC_KEY.value]);
		else if (isMlkemScheme$1(this._scheme)) return tagsForValues([MLKEM_PUBLIC_KEY.value]);
		throw new Error(`Unsupported scheme: ${String(this._scheme)}`);
	}
	/**
	* Returns the untagged CBOR encoding.
	*/
	untaggedCbor() {
		if (this._scheme === "x25519") {
			const pk = this._x25519PublicKey;
			if (pk === void 0) throw new Error("X25519 public key not set");
			return toByteString(pk.data());
		} else if (isMlkemScheme$1(this._scheme)) {
			const pk = this._mlkemPublicKey;
			if (pk === void 0) throw new Error("MLKEM public key not set");
			return pk.untaggedCbor();
		}
		throw new Error(`Unsupported scheme: ${String(this._scheme)}`);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates an EncapsulationPublicKey by decoding it from untagged CBOR.
	* Note: Without tags, we assume X25519 scheme.
	*/
	fromUntaggedCbor(cborValue) {
		const data = expectBytes(cborValue);
		const publicKey = X25519PublicKey.fromDataRef(data);
		return EncapsulationPublicKey.fromX25519PublicKey(publicKey);
	}
	/**
	* Creates an EncapsulationPublicKey by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		const tag = tagValue(cborValue);
		if (tag === X25519_PUBLIC_KEY.value) {
			const content = extractTaggedContent(cborValue);
			const data = expectBytes(content);
			const publicKey = X25519PublicKey.fromDataRef(data);
			return EncapsulationPublicKey.fromX25519PublicKey(publicKey);
		}
		if (tag === MLKEM_PUBLIC_KEY.value) {
			const mlkemPublic = MLKEMPublicKey.fromTaggedCbor(cborValue);
			return EncapsulationPublicKey.fromMlkem(mlkemPublic);
		}
		throw new Error(`Unknown public key tag: ${tag}`);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		return EncapsulationPublicKey.fromX25519PublicKey(X25519PublicKey.fromData(/* @__PURE__ */ new Uint8Array(32))).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return EncapsulationPublicKey.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return EncapsulationPublicKey.fromX25519PublicKey(X25519PublicKey.fromData(/* @__PURE__ */ new Uint8Array(32))).fromUntaggedCbor(cborValue);
	}
	/**
	* Returns the UR representation.
	*/
	ur() {
		if (this._scheme === "x25519") {
			const name = X25519_PUBLIC_KEY.name;
			if (name === void 0) throw new Error("TAG_X25519_PUBLIC_KEY.name is undefined");
			return UR.new(name, this.untaggedCbor());
		} else if (isMlkemScheme$1(this._scheme)) {
			const pk = this._mlkemPublicKey;
			if (pk === void 0) throw new Error("MLKEM public key not set");
			return pk.ur();
		}
		throw new Error(`Unsupported scheme: ${String(this._scheme)}`);
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates an EncapsulationPublicKey from a UR.
	*/
	static fromUR(ur) {
		if (ur.urTypeStr() === X25519_PUBLIC_KEY.name) return EncapsulationPublicKey.fromX25519PublicKey(X25519PublicKey.fromData(/* @__PURE__ */ new Uint8Array(32))).fromUntaggedCbor(ur.cbor());
		if (ur.urTypeStr() === MLKEM_PUBLIC_KEY.name) {
			const mlkemPublic = MLKEMPublicKey.fromUR(ur);
			return EncapsulationPublicKey.fromMlkem(mlkemPublic);
		}
		throw new Error(`Unknown UR type for EncapsulationPublicKey: ${ur.urTypeStr()}`);
	}
	/**
	* Creates an EncapsulationPublicKey from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return EncapsulationPublicKey.fromUR(ur);
	}
};
//#endregion
//#region src/mlkem/mlkem-private-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* MLKEMPrivateKey - ML-KEM Private Key for post-quantum key decapsulation
*
* MLKEMPrivateKey wraps an ML-KEM secret key for decapsulating shared secrets.
* It supports all three security levels (MLKEM512, MLKEM768, MLKEM1024).
*
* # CBOR Serialization
*
* MLKEMPrivateKey is serialized with tag 40100:
* ```
* #6.40100([level, h'<private-key-bytes>'])
* ```
*
* # UR Serialization
*
* UR type: `mlkem-private-key`
*
* Ported from bc-components-rust/src/mlkem/mlkem_private_key.rs
*/
/**
* MLKEMPrivateKey - Post-quantum key decapsulation private key using ML-KEM.
*/
var MLKEMPrivateKey = class MLKEMPrivateKey {
	_level;
	_data;
	constructor(level, data) {
		const expectedSize = mlkemPrivateKeySize(level);
		if (data.length !== expectedSize) throw new Error(`MLKEMPrivateKey (${mlkemLevelToString(level)}) must be ${expectedSize} bytes, got ${data.length}`);
		this._level = level;
		this._data = new Uint8Array(data);
	}
	/**
	* Generate a new random MLKEMPrivateKey with the specified security level.
	*
	* @param level - The ML-KEM security level (default: MLKEM768)
	*/
	static new(level = 768) {
		const rng = new SecureRandomNumberGenerator$1();
		return MLKEMPrivateKey.newUsing(level, rng);
	}
	/**
	* Generate a new random MLKEMPrivateKey using the provided RNG.
	*
	* @param level - The ML-KEM security level
	* @param rng - Random number generator
	*/
	static newUsing(level, rng) {
		const keypair = mlkemGenerateKeypairUsing(level, rng);
		return new MLKEMPrivateKey(level, keypair.secretKey);
	}
	/**
	* Create an MLKEMPrivateKey from raw bytes.
	*
	* @param level - The ML-KEM security level
	* @param data - The private key bytes
	*/
	static fromBytes(level, data) {
		return new MLKEMPrivateKey(level, data);
	}
	/**
	* Generate a keypair and return both private and public keys.
	*
	* @param level - The ML-KEM security level (default: MLKEM768)
	* @returns Tuple of [privateKey, publicKey]
	*/
	static keypair(level = 768) {
		const rng = new SecureRandomNumberGenerator$1();
		return MLKEMPrivateKey.keypairUsing(level, rng);
	}
	/**
	* Generate a keypair using the provided RNG.
	*
	* @param level - The ML-KEM security level
	* @param rng - Random number generator
	* @returns Tuple of [privateKey, publicKey]
	*/
	static keypairUsing(level, rng) {
		const keypairData = mlkemGenerateKeypairUsing(level, rng);
		return [new MLKEMPrivateKey(level, keypairData.secretKey), MLKEMPublicKey.fromBytes(level, keypairData.publicKey)];
	}
	/**
	* Returns the security level of this key.
	*/
	level() {
		return this._level;
	}
	/**
	* Returns the raw key bytes.
	*/
	asBytes() {
		return this._data;
	}
	/**
	* Returns a copy of the raw key bytes.
	*/
	data() {
		return new Uint8Array(this._data);
	}
	/**
	* Returns the size of the key in bytes.
	*/
	size() {
		return this._data.length;
	}
	/**
	* Decapsulate a shared secret from a ciphertext.
	*
	* @param ciphertext - The ML-KEM ciphertext
	* @returns The decapsulated shared secret as a SymmetricKey
	*/
	decapsulate(ciphertext) {
		if (ciphertext.level() !== this._level) throw new Error(`Ciphertext level (${mlkemLevelToString(ciphertext.level())}) does not match key level (${mlkemLevelToString(this._level)})`);
		const sharedSecret = mlkemDecapsulate(this._level, this._data, ciphertext.asBytes());
		return SymmetricKey.fromData(sharedSecret);
	}
	/**
	* Derives and returns the corresponding public key.
	*
	* In ML-KEM (FIPS 203), the decapsulation key contains the encapsulation key (public key)
	* embedded within it. This method extracts that public key.
	*
	* @returns The corresponding MLKEMPublicKey
	*/
	publicKey() {
		const publicKeyData = mlkemExtractPublicKey(this._level, this._data);
		return MLKEMPublicKey.fromBytes(this._level, publicKeyData);
	}
	/**
	* Compare with another MLKEMPrivateKey.
	*/
	equals(other) {
		if (this._level !== other._level) return false;
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation (truncated for security).
	*/
	toString() {
		const hex = bytesToHex(this._data);
		return `MLKEMPrivateKey(${mlkemLevelToString(this._level)}, ${hex.substring(0, 8)}...)`;
	}
	/**
	* Returns the CBOR tags associated with MLKEMPrivateKey.
	*/
	cborTags() {
		return tagsForValues([MLKEM_PRIVATE_KEY.value]);
	}
	/**
	* Returns the untagged CBOR encoding.
	*
	* Format: [level, key_bytes]
	*/
	untaggedCbor() {
		return cbor$3([this._level, this._data]);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates an MLKEMPrivateKey by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cborValue) {
		const elements = expectArray(cborValue);
		if (elements.length !== 2) throw new Error(`MLKEMPrivateKey CBOR must have 2 elements, got ${elements.length}`);
		const level = mlkemLevelFromValue(Number(expectInteger(elements[0])));
		const data = expectBytes(elements[1]);
		return MLKEMPrivateKey.fromBytes(level, data);
	}
	/**
	* Creates an MLKEMPrivateKey by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		const dummyData = new Uint8Array(mlkemPrivateKeySize(512));
		return new MLKEMPrivateKey(512, dummyData).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return MLKEMPrivateKey.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		const dummyData = new Uint8Array(mlkemPrivateKeySize(512));
		return new MLKEMPrivateKey(512, dummyData).fromUntaggedCbor(cborValue);
	}
	/**
	* Returns the UR representation.
	*/
	ur() {
		const name = MLKEM_PRIVATE_KEY.name;
		if (name === void 0) throw new Error("MLKEM_PRIVATE_KEY tag name is undefined");
		return UR.new(name, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates an MLKEMPrivateKey from a UR.
	*/
	static fromUR(ur) {
		if (ur.urTypeStr() !== MLKEM_PRIVATE_KEY.name) throw new Error(`Expected UR type ${MLKEM_PRIVATE_KEY.name}, got ${ur.urTypeStr()}`);
		const dummyData = new Uint8Array(mlkemPrivateKeySize(512));
		return new MLKEMPrivateKey(512, dummyData).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates an MLKEMPrivateKey from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return MLKEMPrivateKey.fromUR(ur);
	}
};
//#endregion
//#region src/encapsulation/encapsulation-private-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Encapsulation private key for key encapsulation mechanisms
*
* This type represents a private key that can be used to decapsulate (decrypt)
* a shared secret that was encapsulated using the corresponding public key.
*
* For X25519, decapsulation works by:
* 1. Receiving the ephemeral public key (ciphertext)
* 2. Performing ECDH with the private key and the ephemeral public key
* 3. Returning the shared secret
*
* For MLKEM, decapsulation uses the ML-KEM algorithm to recover the shared secret.
*
* # CBOR Serialization
*
* For X25519, the private key is serialized with tag 40010.
* For MLKEM, the private key is serialized with tag 40100.
*
* Ported from bc-components-rust/src/encapsulation/encapsulation_private_key.rs
*/
/**
* Convert MLKEMLevel to EncapsulationScheme
*/
function mlkemLevelToScheme(level) {
	switch (level) {
		case 512: return "mlkem512";
		case 768: return "mlkem768";
		case 1024: return "mlkem1024";
	}
}
/**
* Check if a scheme is an MLKEM scheme
*/
function isMlkemScheme(scheme) {
	return scheme === "mlkem512" || scheme === "mlkem768" || scheme === "mlkem1024";
}
/**
* Represents a private key for key encapsulation.
*
* Use this to decapsulate a shared secret from ciphertext.
*/
var EncapsulationPrivateKey = class EncapsulationPrivateKey {
	_scheme;
	_x25519PrivateKey;
	_mlkemPrivateKey;
	constructor(scheme, x25519PrivateKey, mlkemPrivateKey) {
		this._scheme = scheme;
		this._x25519PrivateKey = x25519PrivateKey;
		this._mlkemPrivateKey = mlkemPrivateKey;
	}
	/**
	* Create an EncapsulationPrivateKey from an X25519PrivateKey.
	*/
	static fromX25519PrivateKey(privateKey) {
		return new EncapsulationPrivateKey("x25519", privateKey, void 0);
	}
	/**
	* Create an EncapsulationPrivateKey from raw X25519 private key bytes.
	*/
	static fromX25519Data(data) {
		const privateKey = X25519PrivateKey.fromDataRef(data);
		return EncapsulationPrivateKey.fromX25519PrivateKey(privateKey);
	}
	/**
	* Create an EncapsulationPrivateKey from an MLKEMPrivateKey.
	*/
	static fromMlkem(privateKey) {
		const scheme = mlkemLevelToScheme(privateKey.level());
		return new EncapsulationPrivateKey(scheme, void 0, privateKey);
	}
	/**
	* Create an EncapsulationPrivateKey from raw MLKEM private key bytes.
	*/
	static fromMlkemData(level, data) {
		const privateKey = MLKEMPrivateKey.fromBytes(level, data);
		return EncapsulationPrivateKey.fromMlkem(privateKey);
	}
	/**
	* Generate a new random X25519 encapsulation private key.
	*/
	static new() {
		return EncapsulationPrivateKey.random();
	}
	/**
	* Generate a new random X25519 encapsulation private key.
	*/
	static random() {
		const rng = new SecureRandomNumberGenerator$1();
		return EncapsulationPrivateKey.newUsing(rng);
	}
	/**
	* Generate a new random X25519 encapsulation private key using provided RNG.
	*/
	static newUsing(rng) {
		const x25519Private = X25519PrivateKey.newUsing(rng);
		return EncapsulationPrivateKey.fromX25519PrivateKey(x25519Private);
	}
	/**
	* Generate a new MLKEM encapsulation private key.
	*/
	static newMlkem(level = 768) {
		const mlkemPrivate = MLKEMPrivateKey.new(level);
		return EncapsulationPrivateKey.fromMlkem(mlkemPrivate);
	}
	/**
	* Generate a new MLKEM encapsulation private key using provided RNG.
	*/
	static newMlkemUsing(level, rng) {
		const mlkemPrivate = MLKEMPrivateKey.newUsing(level, rng);
		return EncapsulationPrivateKey.fromMlkem(mlkemPrivate);
	}
	/**
	* Generate a new keypair for X25519.
	*/
	static keypair() {
		const privateKey = EncapsulationPrivateKey.new();
		return [privateKey, privateKey.publicKey()];
	}
	/**
	* Generate a new keypair using the given RNG (X25519).
	*/
	static keypairUsing(rng) {
		const privateKey = EncapsulationPrivateKey.newUsing(rng);
		return [privateKey, privateKey.publicKey()];
	}
	/**
	* Generate a new MLKEM keypair.
	*/
	static mlkemKeypair(level = 768) {
		const [mlkemPrivate, mlkemPublic] = MLKEMPrivateKey.keypair(level);
		return [EncapsulationPrivateKey.fromMlkem(mlkemPrivate), EncapsulationPublicKey.fromMlkem(mlkemPublic)];
	}
	/**
	* Generate a new MLKEM keypair using the given RNG.
	*/
	static mlkemKeypairUsing(level, rng) {
		const [mlkemPrivate, mlkemPublic] = MLKEMPrivateKey.keypairUsing(level, rng);
		return [EncapsulationPrivateKey.fromMlkem(mlkemPrivate), EncapsulationPublicKey.fromMlkem(mlkemPublic)];
	}
	/**
	* Returns the encapsulation scheme.
	*/
	encapsulationScheme() {
		return this._scheme;
	}
	/**
	* Returns true if this is an X25519 private key.
	*/
	isX25519() {
		return this._scheme === "x25519";
	}
	/**
	* Returns true if this is an MLKEM private key.
	*/
	isMlkem() {
		return isMlkemScheme(this._scheme);
	}
	/**
	* Returns the X25519 private key if this is an X25519 encapsulation key.
	* @throws Error if this is not an X25519 key
	*/
	x25519PrivateKey() {
		if (this._x25519PrivateKey === void 0) throw new Error("Not an X25519 private key");
		return this._x25519PrivateKey;
	}
	/**
	* Returns the MLKEM private key if this is an MLKEM encapsulation key.
	* @throws Error if this is not an MLKEM key
	*/
	mlkemPrivateKey() {
		if (this._mlkemPrivateKey === void 0) throw new Error("Not an MLKEM private key");
		return this._mlkemPrivateKey;
	}
	/**
	* Returns the X25519 private key if available, or null.
	*/
	toX25519() {
		return this._x25519PrivateKey ?? null;
	}
	/**
	* Returns the MLKEM private key if available, or null.
	*/
	toMlkem() {
		return this._mlkemPrivateKey ?? null;
	}
	/**
	* Returns the raw private key data.
	*/
	data() {
		if (this._scheme === "x25519") {
			const pk = this._x25519PrivateKey;
			if (pk === void 0) throw new Error("X25519 private key not set");
			return pk.data();
		} else if (isMlkemScheme(this._scheme)) {
			const pk = this._mlkemPrivateKey;
			if (pk === void 0) throw new Error("MLKEM private key not set");
			return pk.data();
		}
		throw new Error(`Unsupported scheme: ${String(this._scheme)}`);
	}
	/**
	* Get the public key corresponding to this private key.
	*/
	publicKey() {
		if (this._scheme === "x25519") {
			const pk = this._x25519PrivateKey;
			if (pk === void 0) throw new Error("X25519 private key not set");
			const x25519Public = pk.publicKey();
			return EncapsulationPublicKey.fromX25519PublicKey(x25519Public);
		} else if (isMlkemScheme(this._scheme)) {
			const pk = this._mlkemPrivateKey;
			if (pk === void 0) throw new Error("MLKEM private key not set");
			const mlkemPublic = pk.publicKey();
			return EncapsulationPublicKey.fromMlkem(mlkemPublic);
		}
		throw new Error(`Unsupported scheme: ${String(this._scheme)}`);
	}
	/**
	* Decapsulate a shared secret from ciphertext.
	*
	* @param ciphertext - The ciphertext from encapsulation
	* @returns The decapsulated shared secret
	* @throws CryptoError if the scheme doesn't match
	*/
	decapsulateSharedSecret(ciphertext) {
		if (ciphertext.encapsulationScheme() !== this._scheme) throw CryptoError.invalidData(`Scheme mismatch: expected ${String(this._scheme)}, got ${String(ciphertext.encapsulationScheme())}`);
		if (this._scheme === "x25519") {
			const pk = this._x25519PrivateKey;
			if (pk === void 0) throw new Error("X25519 private key not set");
			const ephemeralPublic = ciphertext.x25519PublicKey();
			return pk.sharedKeyWith(ephemeralPublic);
		} else if (isMlkemScheme(this._scheme)) {
			const pk = this._mlkemPrivateKey;
			if (pk === void 0) throw new Error("MLKEM private key not set");
			const mlkemCiphertext = ciphertext.mlkemCiphertext();
			return pk.decapsulate(mlkemCiphertext);
		}
		throw new Error(`Unsupported scheme: ${String(this._scheme)}`);
	}
	/**
	* Compare with another EncapsulationPrivateKey.
	*/
	equals(other) {
		if (this._scheme !== other._scheme) return false;
		if (this._scheme === "x25519") {
			const thisPk = this._x25519PrivateKey;
			const otherPk = other._x25519PrivateKey;
			if (thisPk === void 0 || otherPk === void 0) return false;
			return thisPk.equals(otherPk);
		} else if (isMlkemScheme(this._scheme)) {
			const thisPk = this._mlkemPrivateKey;
			const otherPk = other._mlkemPrivateKey;
			if (thisPk === void 0 || otherPk === void 0) return false;
			return thisPk.equals(otherPk);
		}
		return false;
	}
	/**
	* Get string representation.
	*/
	toString() {
		if (this._scheme === "x25519") return `EncapsulationPrivateKey(X25519, ${bytesToHex(this.data()).substring(0, 16)}...)`;
		else if (isMlkemScheme(this._scheme)) return `EncapsulationPrivateKey(${String(this._scheme)}, ${bytesToHex(this.data()).substring(0, 16)}...)`;
		return `EncapsulationPrivateKey(${String(this._scheme)})`;
	}
	/**
	* Returns a unique reference to this EncapsulationPrivateKey instance.
	*
	* The reference is derived from the SHA-256 hash of the tagged CBOR
	* representation, providing a unique, content-addressable identifier.
	*/
	reference() {
		const digest = Digest.fromImage(this.taggedCborData());
		return Reference.from(digest);
	}
	/**
	* Returns the CBOR tags associated with this private key.
	*/
	cborTags() {
		if (this._scheme === "x25519") return tagsForValues([X25519_PRIVATE_KEY.value]);
		else if (isMlkemScheme(this._scheme)) return tagsForValues([MLKEM_PRIVATE_KEY.value]);
		throw new Error(`Unsupported scheme: ${String(this._scheme)}`);
	}
	/**
	* Returns the untagged CBOR encoding.
	*/
	untaggedCbor() {
		if (this._scheme === "x25519") {
			const pk = this._x25519PrivateKey;
			if (pk === void 0) throw new Error("X25519 private key not set");
			return toByteString(pk.data());
		} else if (isMlkemScheme(this._scheme)) {
			const pk = this._mlkemPrivateKey;
			if (pk === void 0) throw new Error("MLKEM private key not set");
			return pk.untaggedCbor();
		}
		throw new Error(`Unsupported scheme: ${String(this._scheme)}`);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates an EncapsulationPrivateKey by decoding it from untagged CBOR.
	* Note: Without tags, we assume X25519 scheme.
	*/
	fromUntaggedCbor(cborValue) {
		const data = expectBytes(cborValue);
		const privateKey = X25519PrivateKey.fromDataRef(data);
		return EncapsulationPrivateKey.fromX25519PrivateKey(privateKey);
	}
	/**
	* Creates an EncapsulationPrivateKey by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		const tag = tagValue(cborValue);
		if (tag === X25519_PRIVATE_KEY.value) {
			const content = extractTaggedContent(cborValue);
			const data = expectBytes(content);
			const privateKey = X25519PrivateKey.fromDataRef(data);
			return EncapsulationPrivateKey.fromX25519PrivateKey(privateKey);
		}
		if (tag === MLKEM_PRIVATE_KEY.value) {
			const mlkemPrivate = MLKEMPrivateKey.fromTaggedCbor(cborValue);
			return EncapsulationPrivateKey.fromMlkem(mlkemPrivate);
		}
		throw new Error(`Unknown private key tag: ${tag}`);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		return EncapsulationPrivateKey.fromX25519PrivateKey(X25519PrivateKey.fromData(/* @__PURE__ */ new Uint8Array(32))).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return EncapsulationPrivateKey.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return EncapsulationPrivateKey.fromX25519PrivateKey(X25519PrivateKey.fromData(/* @__PURE__ */ new Uint8Array(32))).fromUntaggedCbor(cborValue);
	}
	/**
	* Returns the UR representation.
	*/
	ur() {
		if (this._scheme === "x25519") {
			const name = X25519_PRIVATE_KEY.name;
			if (name === void 0) throw new Error("TAG_X25519_PRIVATE_KEY.name is undefined");
			return UR.new(name, this.untaggedCbor());
		} else if (isMlkemScheme(this._scheme)) {
			const pk = this._mlkemPrivateKey;
			if (pk === void 0) throw new Error("MLKEM private key not set");
			return pk.ur();
		}
		throw new Error(`Unsupported scheme: ${String(this._scheme)}`);
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates an EncapsulationPrivateKey from a UR.
	*/
	static fromUR(ur) {
		if (ur.urTypeStr() === X25519_PRIVATE_KEY.name) return EncapsulationPrivateKey.fromX25519PrivateKey(X25519PrivateKey.fromData(/* @__PURE__ */ new Uint8Array(32))).fromUntaggedCbor(ur.cbor());
		if (ur.urTypeStr() === MLKEM_PRIVATE_KEY.name) {
			const mlkemPrivate = MLKEMPrivateKey.fromUR(ur);
			return EncapsulationPrivateKey.fromMlkem(mlkemPrivate);
		}
		throw new Error(`Unknown UR type for EncapsulationPrivateKey: ${ur.urTypeStr()}`);
	}
	/**
	* Creates an EncapsulationPrivateKey from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return EncapsulationPrivateKey.fromUR(ur);
	}
};
//#endregion
//#region src/private-key-base.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* PrivateKeyBase - Root cryptographic material for deterministic key derivation
*
* PrivateKeyBase is a 32-byte value that serves as the root of cryptographic
* material from which various keys can be deterministically derived.
*
* # CBOR Serialization
*
* PrivateKeyBase is serialized with tag 40016:
* ```
* #6.40016(h'<32-byte-key-material>')
* ```
*
* # UR Serialization
*
* UR type: `crypto-prvkey-base`
*
* Ported from bc-components-rust/src/private_key_base.rs
*/
/** Default size of PrivateKeyBase key material in bytes (used for random generation) */
const PRIVATE_KEY_BASE_DEFAULT_SIZE = 32;
/** Key derivation salt string - must match Rust's bc-crypto derive functions */
const SALT_SIGNING = "signing";
/**
* PrivateKeyBase - Root cryptographic material for deterministic key derivation.
*
* This is the foundation from which signing keys and agreement keys can be
* deterministically derived using HKDF.
*/
var PrivateKeyBase = class PrivateKeyBase {
	_data;
	constructor(data) {
		if (data.length === 0) throw new Error("PrivateKeyBase must have non-zero length");
		this._data = new Uint8Array(data);
	}
	/**
	* Create a new random PrivateKeyBase.
	*/
	static new() {
		const rng = new SecureRandomNumberGenerator$1();
		return PrivateKeyBase.newUsing(rng);
	}
	/**
	* Create a new random PrivateKeyBase using the provided RNG.
	*/
	static newUsing(rng) {
		const data = rng.randomData(PRIVATE_KEY_BASE_DEFAULT_SIZE);
		return new PrivateKeyBase(data);
	}
	/**
	* Create a PrivateKeyBase from raw bytes.
	*
	* @param data - 32 bytes of key material
	*/
	static fromData(data) {
		return new PrivateKeyBase(data);
	}
	/**
	* Returns the raw key material.
	*/
	asBytes() {
		return this._data;
	}
	/**
	* Returns a copy of the raw key material.
	*/
	data() {
		return new Uint8Array(this._data);
	}
	/**
	* Derive an Ed25519 signing private key.
	*
	* Uses HKDF with salt "signing", matching Rust's derive_signing_private_key().
	*/
	ed25519SigningPrivateKey() {
		const derivedKey = this._deriveKey(SALT_SIGNING);
		const ed25519Key = Ed25519PrivateKey.from(derivedKey);
		return SigningPrivateKey.newEd25519(ed25519Key);
	}
	/**
	* Derive an X25519 agreement private key.
	*
	* Uses HKDF with salt "agreement", matching Rust's derive_agreement_private_key().
	*/
	x25519PrivateKey() {
		return X25519PrivateKey.deriveFromKeyMaterial(this._data);
	}
	/**
	* Get EncapsulationPrivateKey for decryption.
	*
	* Returns the derived X25519 private key wrapped as EncapsulationPrivateKey.
	*/
	encapsulationPrivateKey() {
		return EncapsulationPrivateKey.fromX25519PrivateKey(this.x25519PrivateKey());
	}
	/**
	* Decapsulate a shared secret from a ciphertext.
	*
	* Implements the `Decrypter` interface so a `PrivateKeyBase` can be used
	* directly as a recipient key, mirroring Rust `impl Decrypter for
	* PrivateKeyBase`.
	*/
	decapsulateSharedSecret(ciphertext) {
		return this.encapsulationPrivateKey().decapsulateSharedSecret(ciphertext);
	}
	/**
	* Derive a PrivateKeys container with Ed25519 signing and X25519 agreement keys.
	*
	* @returns PrivateKeys containing the derived signing and encapsulation keys
	*/
	ed25519PrivateKeys() {
		return PrivateKeys.withKeys(this.ed25519SigningPrivateKey(), this.encapsulationPrivateKey());
	}
	/**
	* Derive a PublicKeys container from the derived keys.
	*
	* @returns PublicKeys containing the derived public keys
	*/
	ed25519PublicKeys() {
		return this.ed25519PrivateKeys().publicKeys();
	}
	/**
	* Derive a Schnorr signing private key.
	*
	* Uses ECPrivateKey.deriveFromKeyMaterial() matching Rust's
	* PrivateKeyBase::schnorr_signing_private_key().
	*/
	schnorrSigningPrivateKey() {
		const ecKey = ECPrivateKey.deriveFromKeyMaterial(this._data);
		return SigningPrivateKey.newSchnorr(ecKey);
	}
	/**
	* Derive a PrivateKeys container with Schnorr signing and X25519 agreement keys.
	*
	* Matches Rust's PrivateKeyBase::schnorr_private_keys().
	*/
	schnorrPrivateKeys() {
		return PrivateKeys.withKeys(this.schnorrSigningPrivateKey(), this.encapsulationPrivateKey());
	}
	/**
	* Derive a PublicKeys container from Schnorr derived keys.
	*/
	schnorrPublicKeys() {
		return this.schnorrPrivateKeys().publicKeys();
	}
	/**
	* Derive an ECDSA signing private key.
	*
	* Uses ECPrivateKey.deriveFromKeyMaterial() matching Rust's
	* PrivateKeyBase::ecdsa_signing_private_key().
	*/
	ecdsaSigningPrivateKey() {
		const ecKey = ECPrivateKey.deriveFromKeyMaterial(this._data);
		return SigningPrivateKey.newEcdsa(ecKey);
	}
	/**
	* Derive a PrivateKeys container with ECDSA signing and X25519 agreement keys.
	*
	* Matches Rust's PrivateKeyBase::ecdsa_private_keys().
	*/
	ecdsaPrivateKeys() {
		return PrivateKeys.withKeys(this.ecdsaSigningPrivateKey(), this.encapsulationPrivateKey());
	}
	/**
	* Derive a PublicKeys container from ECDSA derived keys.
	*/
	ecdsaPublicKeys() {
		return this.ecdsaPrivateKeys().publicKeys();
	}
	/**
	* Derive an SSH `SigningPrivateKey` from this `PrivateKeyBase`.
	*
	* Mirrors Rust `PrivateKeyBase::ssh_signing_private_key`
	* (`bc-components-rust/src/private_key_base.rs:179-207`):
	* builds an `HKDFRng` seeded by `this._data` with salt
	* `sshAlgorithmName(algorithm)`, then dispatches to the matching
	* `*Keypair::random` constructor.
	*
	* Supported algorithms (matching the four `SignatureScheme.SshXxx`
	* variants Rust ships in `signature_scheme.rs`):
	*   - Ed25519 (`ssh-ed25519`)
	*   - DSA (`ssh-dss`) — **throws**: byte-deterministic DSA-1024 prime
	*     generation requires porting the upstream `dsa` crate's
	*     FIPS 186-4 prime search, which is not yet implemented in TS.
	*   - ECDSA P-256 (`ecdsa-sha2-nistp256`)
	*   - ECDSA P-384 (`ecdsa-sha2-nistp384`)
	*
	* @param algorithm - The SSH key algorithm to derive
	* @param comment   - Optional comment carried through the OpenSSH PEM
	*/
	sshSigningPrivateKey(algorithm, comment = "") {
		const rng = HKDFRng.new(this._data, sshAlgorithmName(algorithm));
		let data;
		switch (algorithm.kind) {
			case "ed25519": {
				const seed = rng.randomData(32);
				const pubBytes = ed25519.getPublicKey(seed);
				data = {
					kind: "ed25519",
					seed,
					pubBytes: new Uint8Array(pubBytes)
				};
				break;
			}
			case "ecdsa": {
				const scalarLen = sshEcdsaScalarLen(algorithm.curve);
				const pointLen = sshEcdsaPointLen(algorithm.curve);
				const curve = algorithm.curve === "nistp256" ? p256 : p384;
				let scalar;
				for (;;) {
					const bytes = rng.randomData(scalarLen);
					if (curve.utils.isValidSecretKey(bytes)) {
						scalar = bytes;
						break;
					}
				}
				const point = curve.getPublicKey(scalar, false);
				if (point.length !== pointLen || point[0] !== 4) throw new Error(`sshSigningPrivateKey ecdsa-${algorithm.curve}: noble returned non-uncompressed point`);
				data = {
					kind: "ecdsa",
					curve: algorithm.curve,
					point: new Uint8Array(point),
					scalar
				};
				break;
			}
			case "dsa": throw new Error("SSH DSA key generation is not yet implemented in TS. Rust's `bc-components-rust` ships byte-deterministic DSA-1024 keygen via the `dsa` crate's FIPS 186-4 prime search, which has not been ported. See SSH_V2_PLAN.md A.1 for status. Sign/verify and PEM round-trip work for DSA keys parsed from existing Rust-generated PEM input.");
		}
		const checkint = sshCheckintFromPrivateBytes(data);
		const sshKey = SSHPrivateKey.fromParts(data, comment, checkint);
		return SigningPrivateKey.fromSsh(sshKey);
	}
	/**
	* Derive a `PrivateKeys` container with an SSH signing key and an X25519
	* agreement key. Mirrors Rust `PrivateKeyBase::ssh_private_keys`
	* (`bc-components-rust/src/private_key_base.rs:273-283`).
	*/
	sshPrivateKeys(algorithm, comment = "") {
		return PrivateKeys.withKeys(this.sshSigningPrivateKey(algorithm, comment), this.encapsulationPrivateKey());
	}
	/**
	* Derive a `PublicKeys` container from `sshPrivateKeys`. Mirrors Rust
	* `PrivateKeyBase::ssh_public_keys`
	* (`bc-components-rust/src/private_key_base.rs:289-300`).
	*/
	sshPublicKeys(algorithm, comment = "") {
		return this.sshPrivateKeys(algorithm, comment).publicKeys();
	}
	/**
	* Internal key derivation using HKDF-SHA256.
	* Matches Rust's hkdf_hmac_sha256(key_material, salt, key_len) with empty info.
	*/
	_deriveKey(salt) {
		return hkdfHmacSha256(this._data, new TextEncoder().encode(salt), 32);
	}
	/**
	* Compare with another PrivateKeyBase.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation (truncated for security).
	*/
	toString() {
		return `PrivateKeyBase(${bytesToHex(this._data).substring(0, 8)}...)`;
	}
	/**
	* Returns the CBOR tags associated with PrivateKeyBase.
	*/
	cborTags() {
		return tagsForValues([PRIVATE_KEY_BASE.value]);
	}
	/**
	* Returns the untagged CBOR encoding.
	*/
	untaggedCbor() {
		return toByteString(this._data);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates a PrivateKeyBase by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cborValue) {
		const data = expectBytes(cborValue);
		return PrivateKeyBase.fromData(data);
	}
	/**
	* Creates a PrivateKeyBase by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		return new PrivateKeyBase(new Uint8Array(PRIVATE_KEY_BASE_DEFAULT_SIZE)).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return PrivateKeyBase.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return new PrivateKeyBase(new Uint8Array(PRIVATE_KEY_BASE_DEFAULT_SIZE)).fromUntaggedCbor(cborValue);
	}
	/**
	* Returns the UR representation.
	*/
	ur() {
		const name = PRIVATE_KEY_BASE.name;
		if (name === void 0) throw new Error("PRIVATE_KEY_BASE tag name is undefined");
		return UR.new(name, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates a PrivateKeyBase from a UR.
	*/
	static fromUR(ur) {
		if (ur.urTypeStr() !== PRIVATE_KEY_BASE.name) throw new Error(`Expected UR type ${PRIVATE_KEY_BASE.name}, got ${ur.urTypeStr()}`);
		return new PrivateKeyBase(new Uint8Array(PRIVATE_KEY_BASE_DEFAULT_SIZE)).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates a PrivateKeyBase from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return PrivateKeyBase.fromUR(ur);
	}
};
/**
* Mirror of `ssh-key` 0.6.7 `KeypairData::checkint`
* (`ssh-key/src/private/keypair.rs:215-241`): XOR successive 4-byte
* big-endian chunks of the algorithm-specific private bytes.
*
*   - Ed25519 → seed (32 bytes)
*   - ECDSA   → canonical scalar (32 / 48 bytes)
*   - DSA     → secret exponent x bytes
*
* The `chunks_exact(4)` rule discards any trailing bytes whose count
* is not a multiple of 4 — match it here.
*/
function sshCheckintFromPrivateBytes(data) {
	let bytes;
	switch (data.kind) {
		case "ed25519":
			bytes = data.seed;
			break;
		case "ecdsa":
			bytes = data.scalar;
			break;
		case "dsa": bytes = data.x;
	}
	let n = 0;
	const fullChunks = Math.floor(bytes.length / 4);
	for (let i = 0; i < fullChunks; i++) {
		const off = i * 4;
		const chunk = (bytes[off] << 24 | bytes[off + 1] << 16 | bytes[off + 2] << 8 | bytes[off + 3]) >>> 0;
		n = (n ^ chunk) >>> 0;
	}
	return n;
}
//#endregion
//#region src/signing/signature-scheme.ts
/**
* Supported digital signature schemes.
*
* This enum represents the various signature schemes supported in this package.
* - Schnorr: BIP-340 Schnorr signature scheme (secp256k1) - DEFAULT
* - ECDSA: ECDSA signature scheme (secp256k1)
* - Ed25519: RFC 8032 signatures
* - Sr25519: Schnorr over Ristretto25519, used by Polkadot/Substrate
* - MLDSA44: ML-DSA44 post-quantum signature scheme (NIST level 2)
* - MLDSA65: ML-DSA65 post-quantum signature scheme (NIST level 3)
* - MLDSA87: ML-DSA87 post-quantum signature scheme (NIST level 5)
* - SshEd25519: Ed25519 via SSH agent
* - SshDsa: DSA via SSH agent
* - SshEcdsaP256: ECDSA P-256 via SSH agent
* - SshEcdsaP384: ECDSA P-384 via SSH agent
*
* Wire format note: Rust models `SignatureScheme` as a unit-only enum;
* TypeScript uses string-typed values for ergonomic `switch`/`equals`
* checks. The CBOR/UR wire format never includes the scheme name —
* only the scheme's integer/byte-string discriminator on `Signature`,
* `SigningPrivateKey`, `SigningPublicKey` — so this is a stylistic
* difference, not a parity gap.
*/
let SignatureScheme = /* @__PURE__ */ function(SignatureScheme) {
	/**
	* BIP-340 Schnorr signature scheme (secp256k1)
	* Default scheme (matching Rust bc-components default when secp256k1 is enabled)
	*/
	SignatureScheme["Schnorr"] = "Schnorr";
	/**
	* ECDSA signature scheme (secp256k1)
	*/
	SignatureScheme["Ecdsa"] = "Ecdsa";
	/**
	* Ed25519 signature scheme (RFC 8032)
	*/
	SignatureScheme["Ed25519"] = "Ed25519";
	/**
	* SR25519 signature scheme (Schnorr over Ristretto25519)
	* Used by Polkadot/Substrate
	*/
	SignatureScheme["Sr25519"] = "Sr25519";
	/**
	* ML-DSA44 post-quantum signature scheme (NIST level 2)
	*/
	SignatureScheme["MLDSA44"] = "MLDSA44";
	/**
	* ML-DSA65 post-quantum signature scheme (NIST level 3)
	*/
	SignatureScheme["MLDSA65"] = "MLDSA65";
	/**
	* ML-DSA87 post-quantum signature scheme (NIST level 5)
	*/
	SignatureScheme["MLDSA87"] = "MLDSA87";
	/**
	* Ed25519 signature via SSH agent.
	* Requires SSH agent daemon support.
	*/
	SignatureScheme["SshEd25519"] = "SshEd25519";
	/**
	* DSA signature via SSH agent.
	* Requires SSH agent daemon support.
	*/
	SignatureScheme["SshDsa"] = "SshDsa";
	/**
	* ECDSA P-256 signature via SSH agent.
	* Requires SSH agent daemon support.
	*/
	SignatureScheme["SshEcdsaP256"] = "SshEcdsaP256";
	/**
	* ECDSA P-384 signature via SSH agent.
	* Requires SSH agent daemon support.
	*/
	SignatureScheme["SshEcdsaP384"] = "SshEcdsaP384";
	return SignatureScheme;
}({});
/**
* Get the default signature scheme.
* Defaults to Schnorr (matching Rust bc-components default when secp256k1 is enabled).
*/
function defaultSignatureScheme() {
	return "Schnorr";
}
/**
* Check if a signature scheme requires SSH agent support.
*
* @param scheme - The signature scheme to check
* @returns true if the scheme requires SSH agent
*/
function isSshScheme(scheme) {
	return scheme === "SshEd25519" || scheme === "SshDsa" || scheme === "SshEcdsaP256" || scheme === "SshEcdsaP384";
}
/**
* Check if a signature scheme is a post-quantum ML-DSA scheme.
*
* @param scheme - The signature scheme to check
* @returns true if the scheme is an ML-DSA scheme
*/
function isMldsaScheme(scheme) {
	return scheme === "MLDSA44" || scheme === "MLDSA65" || scheme === "MLDSA87";
}
/**
* Map an `SshXxx` `SignatureScheme` value to its underlying
* `SshAlgorithm`. Helper for `createKeypair`/`createKeypairUsing`.
*/
function sshSchemeToAlgorithm(scheme) {
	switch (scheme) {
		case "SshEd25519": return { kind: "ed25519" };
		case "SshDsa": return { kind: "dsa" };
		case "SshEcdsaP256": return {
			kind: "ecdsa",
			curve: "nistp256"
		};
		case "SshEcdsaP384": return {
			kind: "ecdsa",
			curve: "nistp384"
		};
		case "Schnorr":
		case "Ecdsa":
		case "Ed25519":
		case "Sr25519":
		case "MLDSA44":
		case "MLDSA65":
		case "MLDSA87": throw new Error(`Not an SSH SignatureScheme: ${scheme}`);
	}
}
/**
* Creates a new key pair for the signature scheme.
*
* @param scheme  - The signature scheme to use
* @param comment - Optional comment for SSH keys (ignored for non-SSH schemes;
*                  mirrors Rust `SignatureScheme::keypair_opt(comment)` at
*                  `signature_scheme.rs:152`)
* @returns A tuple containing a signing private key and its corresponding public key
*/
function createKeypair(scheme, comment = "") {
	switch (scheme) {
		case "Schnorr": {
			const ecKey = ECPrivateKey.random();
			const privateKey = SigningPrivateKey.newSchnorr(ecKey);
			return [privateKey, privateKey.publicKey()];
		}
		case "Ecdsa": {
			const ecKey = ECPrivateKey.random();
			const privateKey = SigningPrivateKey.newEcdsa(ecKey);
			return [privateKey, privateKey.publicKey()];
		}
		case "Ed25519": {
			const ed25519Key = Ed25519PrivateKey.random();
			const privateKey = SigningPrivateKey.newEd25519(ed25519Key);
			return [privateKey, privateKey.publicKey()];
		}
		case "Sr25519": {
			const sr25519Key = Sr25519PrivateKey.random();
			const privateKey = SigningPrivateKey.newSr25519(sr25519Key);
			return [privateKey, privateKey.publicKey()];
		}
		case "MLDSA44": {
			const mldsaKey = MLDSAPrivateKey.new(2);
			const privateKey = SigningPrivateKey.newMldsa(mldsaKey);
			return [privateKey, privateKey.publicKey()];
		}
		case "MLDSA65": {
			const mldsaKey = MLDSAPrivateKey.new(3);
			const privateKey = SigningPrivateKey.newMldsa(mldsaKey);
			return [privateKey, privateKey.publicKey()];
		}
		case "MLDSA87": {
			const mldsaKey = MLDSAPrivateKey.new(5);
			const privateKey = SigningPrivateKey.newMldsa(mldsaKey);
			return [privateKey, privateKey.publicKey()];
		}
		case "SshEd25519":
		case "SshDsa":
		case "SshEcdsaP256":
		case "SshEcdsaP384": {
			const privateKey = PrivateKeyBase.new().sshSigningPrivateKey(sshSchemeToAlgorithm(scheme), comment);
			return [privateKey, privateKey.publicKey()];
		}
	}
}
/**
* Creates a new key pair for the signature scheme using a provided RNG.
*
* @param scheme  - The signature scheme to use
* @param rng     - The random number generator to use
* @param comment - Optional comment for SSH keys (ignored for non-SSH schemes;
*                  mirrors Rust `SignatureScheme::keypair_using(rng, comment)`
*                  at `signature_scheme.rs:316`)
* @returns A tuple containing a signing private key and its corresponding public key
* @throws CryptoError for MLDSA (which doesn't support deterministic generation)
*/
function createKeypairUsing(scheme, rng, comment = "") {
	switch (scheme) {
		case "Schnorr": {
			const ecKey = ECPrivateKey.newUsing(rng);
			const privateKey = SigningPrivateKey.newSchnorr(ecKey);
			return [privateKey, privateKey.publicKey()];
		}
		case "Ecdsa": {
			const ecKey = ECPrivateKey.newUsing(rng);
			const privateKey = SigningPrivateKey.newEcdsa(ecKey);
			return [privateKey, privateKey.publicKey()];
		}
		case "Ed25519": {
			const ed25519Key = Ed25519PrivateKey.randomUsing(rng);
			const privateKey = SigningPrivateKey.newEd25519(ed25519Key);
			return [privateKey, privateKey.publicKey()];
		}
		case "Sr25519": {
			const sr25519Key = Sr25519PrivateKey.randomUsing(rng);
			const privateKey = SigningPrivateKey.newSr25519(sr25519Key);
			return [privateKey, privateKey.publicKey()];
		}
		case "MLDSA44":
		case "MLDSA65":
		case "MLDSA87": throw CryptoError.general(`Deterministic keypair generation not supported for ${scheme}. Use createKeypair() instead.`);
		case "SshEd25519":
		case "SshDsa":
		case "SshEcdsaP256":
		case "SshEcdsaP384": {
			const privateKey = PrivateKeyBase.newUsing(rng).sshSigningPrivateKey(sshSchemeToAlgorithm(scheme), comment);
			return [privateKey, privateKey.publicKey()];
		}
	}
}
//#endregion
//#region src/signing/signature.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* A digital signature created with various signature algorithms.
*
* `Signature` represents different types of digital signatures.
* Supports Schnorr, ECDSA, Ed25519, and Sr25519 signatures.
*
* Signatures can be serialized to and from CBOR with tag 40020.
*
* # CBOR Serialization
*
* The CBOR encoding (matching Rust bc-components):
* - Schnorr: `#6.40020(h'<64-byte-signature>')` (bare byte string)
* - ECDSA:   `#6.40020([1, h'<64-byte-signature>'])`
* - Ed25519: `#6.40020([2, h'<64-byte-signature>'])`
* - Sr25519: `#6.40020([3, h'<64-byte-signature>'])`
*
* Ported from bc-components-rust/src/signing/signature.rs
*/
/**
* A digital signature created with various signature algorithms.
*
* Currently supports:
* - Schnorr signatures (64 bytes) - bare byte string in CBOR
* - ECDSA signatures (64 bytes) - discriminator 1
* - Ed25519 signatures (64 bytes) - discriminator 2
* - Sr25519 signatures (64 bytes) - discriminator 3
* - MLDSA signatures (post-quantum) - tagged CBOR delegating to MLDSASignature
*/
var Signature = class Signature {
	_type;
	_data;
	_mldsaSignature;
	_sshSig;
	constructor(type, data, mldsaSignature, sshSig) {
		this._type = type;
		this._data = new Uint8Array(data);
		this._mldsaSignature = mldsaSignature;
		this._sshSig = sshSig;
	}
	/**
	* Creates a Schnorr signature from a 64-byte array.
	*
	* @param data - The 64-byte signature data
	* @returns A new Schnorr signature
	*/
	static schnorrFromData(data) {
		if (data.length !== 64) throw CryptoError.invalidSize(64, data.length);
		return new Signature("Schnorr", data);
	}
	/**
	* Creates a Schnorr signature from a hex string.
	*
	* @param hex - The hex-encoded signature data
	* @returns A new Schnorr signature
	*/
	static schnorrFromHex(hex) {
		return Signature.schnorrFromData(hexToBytes(hex));
	}
	/**
	* Creates an ECDSA signature from a 64-byte array.
	*
	* @param data - The 64-byte signature data
	* @returns A new ECDSA signature
	*/
	static ecdsaFromData(data) {
		if (data.length !== 64) throw CryptoError.invalidSize(64, data.length);
		return new Signature("Ecdsa", data);
	}
	/**
	* Creates an ECDSA signature from a hex string.
	*
	* @param hex - The hex-encoded signature data
	* @returns A new ECDSA signature
	*/
	static ecdsaFromHex(hex) {
		return Signature.ecdsaFromData(hexToBytes(hex));
	}
	/**
	* Creates an Ed25519 signature from a 64-byte array.
	*
	* @param data - The 64-byte signature data
	* @returns A new Ed25519 signature
	*/
	static ed25519FromData(data) {
		if (data.length !== 64) throw CryptoError.invalidSize(64, data.length);
		return new Signature("Ed25519", data);
	}
	/**
	* Creates an Ed25519 signature from a hex string.
	*
	* @param hex - The hex-encoded signature data
	* @returns A new Ed25519 signature
	*/
	static ed25519FromHex(hex) {
		return Signature.ed25519FromData(hexToBytes(hex));
	}
	/**
	* Creates an Sr25519 signature from a 64-byte array.
	*
	* @param data - The 64-byte signature data
	* @returns A new Sr25519 signature
	*/
	static sr25519FromData(data) {
		if (data.length !== 64) throw CryptoError.invalidSize(64, data.length);
		return new Signature("Sr25519", data);
	}
	/**
	* Creates an Sr25519 signature from a hex string.
	*
	* @param hex - The hex-encoded signature data
	* @returns A new Sr25519 signature
	*/
	static sr25519FromHex(hex) {
		return Signature.sr25519FromData(hexToBytes(hex));
	}
	/**
	* Creates a Signature from an MLDSASignature.
	*
	* @param sig - The MLDSASignature
	* @returns A new Signature wrapping the MLDSA signature
	*/
	static mldsaFromSignature(sig) {
		let scheme;
		switch (sig.level()) {
			case 2:
				scheme = "MLDSA44";
				break;
			case 3:
				scheme = "MLDSA65";
				break;
			case 5:
				scheme = "MLDSA87";
				break;
			default: throw new Error(`Unknown MLDSA level: ${sig.level()}`);
		}
		return new Signature(scheme, sig.data(), sig);
	}
	/**
	* Creates a Signature from an SSHSignature.
	*
	* Mirrors Rust `Signature::from_ssh`
	* (`bc-components-rust/src/signing/signature.rs:398`).
	*
	* The signature scheme is derived from the inner public-key algorithm,
	* matching Rust `Signature::scheme()` at lines 506-519.
	*
	* @param sig - The SSHSignature
	* @returns A new SSH Signature
	*/
	static fromSsh(sig) {
		let scheme;
		switch (sig.publicKey.data.kind) {
			case "ed25519":
				scheme = "SshEd25519";
				break;
			case "dsa":
				scheme = "SshDsa";
				break;
			case "ecdsa": switch (sig.publicKey.data.curve) {
				case "nistp256":
					scheme = "SshEcdsaP256";
					break;
				case "nistp384": scheme = "SshEcdsaP384";
			}
		}
		return new Signature(scheme, sig.signatureBytes, void 0, sig);
	}
	/**
	* Returns the signature scheme used to create this signature.
	*/
	scheme() {
		return this._type;
	}
	/**
	* Returns a human-readable string identifying the signature type.
	* @returns A string like "Ed25519", "Schnorr", "ECDSA", "Sr25519", "MLDSA-44", etc.
	*/
	signatureType() {
		switch (this._type) {
			case "Ed25519": return "Ed25519";
			case "Schnorr": return "Schnorr";
			case "Ecdsa": return "Ecdsa";
			case "Sr25519": return "Sr25519";
			case "MLDSA44": return "MLDSA-44";
			case "MLDSA65": return "MLDSA-65";
			case "MLDSA87": return "MLDSA-87";
			case "SshEd25519": return "SshEd25519";
			case "SshDsa": return "SshDsa";
			case "SshEcdsaP256": return "SshEcdsaP256";
			case "SshEcdsaP384": return "SshEcdsaP384";
			default: return this._type;
		}
	}
	/**
	* Returns the raw signature data.
	*/
	data() {
		return this._data;
	}
	/**
	* Returns the Schnorr signature data if this is a Schnorr signature.
	*
	* @returns The 64-byte signature data if this is a Schnorr signature, null otherwise
	*/
	toSchnorr() {
		if (this._type === "Schnorr") return this._data;
		return null;
	}
	/**
	* Checks if this is a Schnorr signature.
	*/
	isSchnorr() {
		return this._type === "Schnorr";
	}
	/**
	* Returns the ECDSA signature data if this is an ECDSA signature.
	*
	* @returns The 64-byte signature data if this is an ECDSA signature, null otherwise
	*/
	toEcdsa() {
		if (this._type === "Ecdsa") return this._data;
		return null;
	}
	/**
	* Checks if this is an ECDSA signature.
	*/
	isEcdsa() {
		return this._type === "Ecdsa";
	}
	/**
	* Returns the Ed25519 signature data if this is an Ed25519 signature.
	*
	* @returns The 64-byte signature data if this is an Ed25519 signature, null otherwise
	*/
	toEd25519() {
		if (this._type === "Ed25519") return this._data;
		return null;
	}
	/**
	* Checks if this is an Ed25519 signature.
	*/
	isEd25519() {
		return this._type === "Ed25519";
	}
	/**
	* Returns the Sr25519 signature data if this is an Sr25519 signature.
	*
	* @returns The 64-byte signature data if this is an Sr25519 signature, null otherwise
	*/
	toSr25519() {
		if (this._type === "Sr25519") return this._data;
		return null;
	}
	/**
	* Checks if this is an Sr25519 signature.
	*/
	isSr25519() {
		return this._type === "Sr25519";
	}
	/**
	* Returns the MLDSASignature if this is an MLDSA signature.
	*
	* @returns The MLDSASignature if this is an MLDSA signature, null otherwise
	*/
	toMldsa() {
		if (isMldsaScheme(this._type) && this._mldsaSignature !== void 0) return this._mldsaSignature;
		return null;
	}
	/**
	* Checks if this is an MLDSA signature.
	*/
	isMldsa() {
		return isMldsaScheme(this._type);
	}
	/**
	* Returns the underlying SSHSignature if this is an SSH signature.
	*
	* Mirrors Rust `Signature::to_ssh`
	* (`bc-components-rust/src/signing/signature.rs:459`).
	*
	* @returns The SSHSignature if this is an SSH signature, null otherwise
	*/
	toSsh() {
		return this._sshSig ?? null;
	}
	/**
	* Checks if this is an SSH signature.
	*/
	isSsh() {
		return this._sshSig !== void 0;
	}
	/**
	* Get hex string representation of the signature data.
	*/
	toHex() {
		return bytesToHex(this._data);
	}
	/**
	* Compare with another Signature.
	*/
	equals(other) {
		if (this._type !== other._type) return false;
		if (this._sshSig !== void 0 || other._sshSig !== void 0) {
			if (this._sshSig === void 0 || other._sshSig === void 0) return false;
			return this._sshSig.toPem() === other._sshSig.toPem();
		}
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `Signature(${this._type}, ${this.toHex().substring(0, 16)}...)`;
	}
	/**
	* Returns the CBOR tags associated with Signature.
	*/
	cborTags() {
		return tagsForValues([SIGNATURE.value]);
	}
	/**
	* Returns the untagged CBOR encoding.
	*
	* Format (matching Rust bc-components):
	* - Schnorr: h'<64-byte-signature>' (bare byte string)
	* - ECDSA:   [1, h'<64-byte-signature>']
	* - Ed25519: [2, h'<64-byte-signature>']
	* - Sr25519: [3, h'<64-byte-signature>']
	*/
	untaggedCbor() {
		switch (this._type) {
			case "Schnorr": return toByteString(this._data);
			case "Ecdsa": return cbor$3([1, toByteString(this._data)]);
			case "Ed25519": return cbor$3([2, toByteString(this._data)]);
			case "Sr25519": return cbor$3([3, toByteString(this._data)]);
			case "MLDSA44":
			case "MLDSA65":
			case "MLDSA87":
				if (this._mldsaSignature === void 0) throw new Error("MLDSA signature is missing");
				return this._mldsaSignature.taggedCbor();
			case "SshEd25519":
			case "SshDsa":
			case "SshEcdsaP256":
			case "SshEcdsaP384":
				if (this._sshSig === void 0) throw new Error("SSH signature is missing");
				return toTaggedValue(SSH_TEXT_SIGNATURE, this._sshSig.toPem());
		}
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates a Signature by decoding it from untagged CBOR.
	*
	* Format (matching Rust bc-components):
	* - h'<64-byte-signature>' (bare byte string) for Schnorr
	* - [1, h'<64-byte-signature>'] for ECDSA
	* - [2, h'<64-byte-signature>'] for Ed25519
	* - [3, h'<64-byte-signature>'] for Sr25519
	*/
	fromUntaggedCbor(cborValue) {
		if (isBytes$1(cborValue)) {
			const signatureData = expectBytes(cborValue);
			return Signature.schnorrFromData(signatureData);
		}
		if (isArray(cborValue)) {
			const elements = expectArray(cborValue);
			if (elements.length !== 2) throw new Error("Signature array must have 2 elements");
			const discriminator = expectUnsigned(elements[0]);
			const signatureData = expectBytes(elements[1]);
			switch (Number(discriminator)) {
				case 1: return Signature.ecdsaFromData(signatureData);
				case 2: return Signature.ed25519FromData(signatureData);
				case 3: return Signature.sr25519FromData(signatureData);
				default: throw new Error(`Unknown signature discriminator: ${discriminator}`);
			}
		}
		if (isTagged(cborValue)) {
			const tagged = cborValue.asTagged();
			if (tagged?.[0].value === MLDSA_SIGNATURE.value) {
				const mldsaSig = MLDSASignature.fromTaggedCbor(cborValue);
				return Signature.mldsaFromSignature(mldsaSig);
			}
			if (tagged?.[0].value === SSH_TEXT_SIGNATURE.value) {
				const text = expectText(tagged[1]);
				const sshSig = SSHSignature.fromPem(text);
				return Signature.fromSsh(sshSig);
			}
		}
		throw new Error("Signature must be a byte string (Schnorr), array (ECDSA/Ed25519/Sr25519), tagged MLDSA, or tagged SSH");
	}
	/**
	* Creates a Signature by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		return new Signature("Ed25519", /* @__PURE__ */ new Uint8Array(64)).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return Signature.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return new Signature("Ed25519", /* @__PURE__ */ new Uint8Array(64)).fromUntaggedCbor(cborValue);
	}
	/**
	* Get the UR type for signatures.
	*/
	static UR_TYPE = "signature";
	/**
	* Returns the UR representation of the signature.
	*
	* The UR type prefix (`ur:signature/...`) carries the CBOR tag, so the
	* inner CBOR must be untagged — matches Rust's `UREncodable` blanket impl.
	*/
	ur() {
		return UR.new(Signature.UR_TYPE, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation of the signature.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates a Signature from a UR.
	*/
	static fromUR(ur) {
		ur.checkType(Signature.UR_TYPE);
		return Signature.schnorrFromData(/* @__PURE__ */ new Uint8Array(64)).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates a Signature from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return Signature.fromUR(ur);
	}
	/**
	* Alias for fromURString for Rust API compatibility.
	*/
	static fromUrString(urString) {
		return Signature.fromURString(urString);
	}
};
//#endregion
//#region src/signing/signing-public-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* A public key used for verifying digital signatures.
*
* `SigningPublicKey` is a type representing different types of signing public
* keys. Supports Schnorr, ECDSA, Ed25519, and SR25519.
*
* This type implements the `Verifier` interface, allowing it to verify signatures.
*
* # CBOR Serialization
*
* `SigningPublicKey` is serialized to CBOR with tag 40022.
*
* The CBOR encoding (matching Rust bc-components):
* - Schnorr: `#6.40022(h'<32-byte-x-only-public-key>')` (bare byte string)
* - ECDSA:   `#6.40022([1, h'<33-byte-compressed-public-key>'])`
* - Ed25519: `#6.40022([2, h'<32-byte-public-key>'])`
* - Sr25519: `#6.40022([3, h'<32-byte-public-key>'])`
*
* Ported from bc-components-rust/src/signing/signing_public_key.rs
*/
/**
* A public key used for verifying digital signatures.
*
* Currently supports:
* - Schnorr public keys (32 bytes, x-only) - bare byte string in CBOR
* - ECDSA public keys (33 bytes, compressed) - discriminator 1
* - Ed25519 public keys (32 bytes) - discriminator 2
* - Sr25519 public keys (32 bytes) - discriminator 3
* - MLDSA public keys (post-quantum) - tagged CBOR delegating to MLDSAPublicKey
*/
var SigningPublicKey = class SigningPublicKey {
	_type;
	_schnorrKey;
	_ecdsaKey;
	_ed25519Key;
	_sr25519Key;
	_mldsaKey;
	_sshKey;
	constructor(type, schnorrKey, ecdsaKey, ed25519Key, sr25519Key, mldsaKey, sshKey) {
		this._type = type;
		this._schnorrKey = schnorrKey;
		this._ecdsaKey = ecdsaKey;
		this._ed25519Key = ed25519Key;
		this._sr25519Key = sr25519Key;
		this._mldsaKey = mldsaKey;
		this._sshKey = sshKey;
	}
	/**
	* Creates a new signing public key from a Schnorr (x-only) public key.
	*
	* @param key - A SchnorrPublicKey
	* @returns A new signing public key containing the Schnorr key
	*/
	static fromSchnorr(key) {
		return new SigningPublicKey("Schnorr", key, void 0, void 0, void 0, void 0);
	}
	/**
	* Creates a new signing public key from an ECDSA (compressed) public key.
	*
	* @param key - An ECPublicKey
	* @returns A new signing public key containing the ECDSA key
	*/
	static fromEcdsa(key) {
		return new SigningPublicKey("Ecdsa", void 0, key, void 0, void 0, void 0);
	}
	/**
	* Creates a new signing public key from an Ed25519 public key.
	*
	* @param key - An Ed25519 public key
	* @returns A new signing public key containing the Ed25519 key
	*/
	static fromEd25519(key) {
		return new SigningPublicKey("Ed25519", void 0, void 0, key, void 0, void 0);
	}
	/**
	* Creates a new signing public key from an Sr25519 public key.
	*
	* @param key - An Sr25519 public key
	* @returns A new signing public key containing the Sr25519 key
	*/
	static fromSr25519(key) {
		return new SigningPublicKey("Sr25519", void 0, void 0, void 0, key, void 0);
	}
	/**
	* Creates a new signing public key from an MLDSAPublicKey.
	*
	* @param key - An MLDSAPublicKey
	* @returns A new signing public key containing the MLDSA key
	*/
	static fromMldsa(key) {
		let scheme;
		switch (key.level()) {
			case 2:
				scheme = "MLDSA44";
				break;
			case 3:
				scheme = "MLDSA65";
				break;
			case 5:
				scheme = "MLDSA87";
				break;
			default: throw new Error(`Unknown MLDSA level: ${key.level()}`);
		}
		return new SigningPublicKey(scheme, void 0, void 0, void 0, void 0, key);
	}
	/**
	* Creates a new signing public key from an SSHPublicKey.
	*
	* Mirrors Rust `SigningPublicKey::from_ssh`
	* (`bc-components-rust/src/signing/signing_public_key.rs:214`).
	*
	* @param key - An SSHPublicKey
	* @returns A new signing public key wrapping the SSH public key
	*/
	static fromSsh(key) {
		let scheme;
		switch (key.data.kind) {
			case "ed25519":
				scheme = "SshEd25519";
				break;
			case "dsa":
				scheme = "SshDsa";
				break;
			case "ecdsa": switch (key.data.curve) {
				case "nistp256":
					scheme = "SshEcdsaP256";
					break;
				case "nistp384": scheme = "SshEcdsaP384";
			}
		}
		return new SigningPublicKey(scheme, void 0, void 0, void 0, void 0, void 0, key);
	}
	/**
	* Returns the signature scheme of this key.
	*/
	scheme() {
		return this._type;
	}
	/**
	* Returns a human-readable string identifying the key type.
	* @returns A string like "Ed25519", "Schnorr", "ECDSA", "Sr25519", "MLDSA-44", etc.
	*/
	keyType() {
		switch (this._type) {
			case "Ed25519": return "Ed25519";
			case "Schnorr": return "Schnorr";
			case "Ecdsa": return "ECDSA";
			case "Sr25519": return "Sr25519";
			case "MLDSA44": return "MLDSA-44";
			case "MLDSA65": return "MLDSA-65";
			case "MLDSA87": return "MLDSA-87";
			case "SshEd25519": return "SSH-Ed25519";
			case "SshDsa": return "SSH-DSA";
			case "SshEcdsaP256": return "SSH-ECDSA-P256";
			case "SshEcdsaP384": return "SSH-ECDSA-P384";
			default: return this._type;
		}
	}
	/**
	* Returns the underlying Schnorr public key if this is a Schnorr key.
	*
	* @returns The SchnorrPublicKey if this is a Schnorr key, null otherwise
	*/
	toSchnorr() {
		if (this._type === "Schnorr" && this._schnorrKey !== void 0) return this._schnorrKey;
		return null;
	}
	/**
	* Returns the underlying ECDSA public key if this is an ECDSA key.
	*
	* @returns The ECPublicKey if this is an ECDSA key, null otherwise
	*/
	toEcdsa() {
		if (this._type === "Ecdsa" && this._ecdsaKey !== void 0) return this._ecdsaKey;
		return null;
	}
	/**
	* Returns the underlying Ed25519 public key if this is an Ed25519 key.
	*
	* @returns The Ed25519 public key if this is an Ed25519 key, null otherwise
	*/
	toEd25519() {
		if (this._type === "Ed25519" && this._ed25519Key !== void 0) return this._ed25519Key;
		return null;
	}
	/**
	* Returns the underlying Sr25519 public key if this is an Sr25519 key.
	*
	* @returns The Sr25519 public key if this is an Sr25519 key, null otherwise
	*/
	toSr25519() {
		if (this._type === "Sr25519" && this._sr25519Key !== void 0) return this._sr25519Key;
		return null;
	}
	/**
	* Checks if this is a Schnorr signing key.
	*/
	isSchnorr() {
		return this._type === "Schnorr";
	}
	/**
	* Checks if this is an ECDSA signing key.
	*/
	isEcdsa() {
		return this._type === "Ecdsa";
	}
	/**
	* Checks if this is an Ed25519 signing key.
	*/
	isEd25519() {
		return this._type === "Ed25519";
	}
	/**
	* Checks if this is an Sr25519 signing key.
	*/
	isSr25519() {
		return this._type === "Sr25519";
	}
	/**
	* Returns the underlying MLDSA public key if this is an MLDSA key.
	*
	* @returns The MLDSAPublicKey if this is an MLDSA key, null otherwise
	*/
	toMldsa() {
		if (isMldsaScheme(this._type) && this._mldsaKey !== void 0) return this._mldsaKey;
		return null;
	}
	/**
	* Checks if this is an MLDSA signing key.
	*/
	isMldsa() {
		return isMldsaScheme(this._type);
	}
	/**
	* Returns the underlying SSH public key if this is an SSH key.
	*
	* Mirrors Rust `SigningPublicKey::to_ssh`
	* (`bc-components-rust/src/signing/signing_public_key.rs:272`).
	*
	* @returns The SSHPublicKey if this is an SSH key, null otherwise
	*/
	toSsh() {
		return this._sshKey ?? null;
	}
	/**
	* Checks if this is an SSH signing key.
	*/
	isSsh() {
		return this._sshKey !== void 0;
	}
	/**
	* Returns a copy of this SSH public key with its comment replaced.
	* Throws if this is not an SSH key — mirrors Rust's `set_comment`
	* which is only callable on `SigningPublicKey::SSH` variants.
	*/
	withSshComment(comment) {
		if (this._sshKey === void 0) throw new Error(`SigningPublicKey.withSshComment: not an SSH key (scheme: ${this._type})`);
		return SigningPublicKey.fromSsh(this._sshKey.withComment(comment));
	}
	/**
	* Compare with another SigningPublicKey.
	*/
	equals(other) {
		if (this._type !== other._type) return false;
		switch (this._type) {
			case "Schnorr":
				if (this._schnorrKey === void 0 || other._schnorrKey === void 0) return false;
				return this._schnorrKey.equals(other._schnorrKey);
			case "Ecdsa":
				if (this._ecdsaKey === void 0 || other._ecdsaKey === void 0) return false;
				return this._ecdsaKey.equals(other._ecdsaKey);
			case "Ed25519":
				if (this._ed25519Key === void 0 || other._ed25519Key === void 0) return false;
				return this._ed25519Key.equals(other._ed25519Key);
			case "Sr25519":
				if (this._sr25519Key === void 0 || other._sr25519Key === void 0) return false;
				return this._sr25519Key.equals(other._sr25519Key);
			case "MLDSA44":
			case "MLDSA65":
			case "MLDSA87":
				if (this._mldsaKey === void 0 || other._mldsaKey === void 0) return false;
				return this._mldsaKey.equals(other._mldsaKey);
			case "SshEd25519":
			case "SshDsa":
			case "SshEcdsaP256":
			case "SshEcdsaP384":
				if (this._sshKey === void 0 || other._sshKey === void 0) return false;
				return this._sshKey.equals(other._sshKey);
		}
	}
	/**
	* Get string representation.
	*
	* Mirrors Rust `Display for SigningPublicKey`
	* (`bc-components-rust/src/signing/signing_public_key.rs:573-606`):
	*   `SigningPublicKey(<ref_hex_short>, <inner_key_display>)`
	* The reference is computed from the tagged-CBOR form.
	*/
	toString() {
		const refShort = this.reference().shortReference("hex");
		let innerDisplay;
		switch (this._type) {
			case "Schnorr":
				innerDisplay = this._schnorrKey?.toString() ?? String(this._type);
				break;
			case "Ecdsa":
				innerDisplay = this._ecdsaKey?.toString() ?? String(this._type);
				break;
			case "Ed25519":
				innerDisplay = this._ed25519Key?.toString() ?? String(this._type);
				break;
			case "Sr25519":
				innerDisplay = this._sr25519Key?.toString() ?? String(this._type);
				break;
			case "MLDSA44":
			case "MLDSA65":
			case "MLDSA87":
				innerDisplay = this._mldsaKey?.toString() ?? String(this._type);
				break;
			case "SshEd25519":
			case "SshDsa":
			case "SshEcdsaP256":
			case "SshEcdsaP384": innerDisplay = this._sshKey?.toString() ?? `SSHPublicKey(${refShort})`;
		}
		return `SigningPublicKey(${refShort}, ${innerDisplay})`;
	}
	/**
	* Returns a unique reference to this SigningPublicKey instance.
	*
	* The reference is derived from the SHA-256 hash of the tagged CBOR
	* representation, providing a unique, content-addressable identifier.
	*/
	reference() {
		const digest = Digest.fromImage(this.taggedCborData());
		return Reference.from(digest);
	}
	/**
	* Verifies a signature against a message.
	*
	* @param signature - The signature to verify
	* @param message - The message that was allegedly signed
	* @returns `true` if the signature is valid, `false` otherwise
	*/
	verify(signature, message) {
		if (signature.scheme() !== this._type) return false;
		switch (this._type) {
			case "Schnorr": {
				if (this._schnorrKey === void 0) return false;
				const sigData = signature.toSchnorr();
				if (sigData === null) return false;
				try {
					return this._schnorrKey.schnorrVerify(sigData, message);
				} catch {
					return false;
				}
			}
			case "Ecdsa": {
				if (this._ecdsaKey === void 0) return false;
				const sigData = signature.toEcdsa();
				if (sigData === null) return false;
				try {
					return this._ecdsaKey.verify(sigData, message);
				} catch {
					return false;
				}
			}
			case "Ed25519": {
				if (this._ed25519Key === void 0) return false;
				const sigData = signature.toEd25519();
				if (sigData === null) return false;
				try {
					return this._ed25519Key.verify(message, sigData);
				} catch {
					return false;
				}
			}
			case "Sr25519": {
				if (this._sr25519Key === void 0) return false;
				const sigData = signature.toSr25519();
				if (sigData === null) return false;
				try {
					return this._sr25519Key.verify(sigData, message);
				} catch {
					return false;
				}
			}
			case "MLDSA44":
			case "MLDSA65":
			case "MLDSA87": {
				if (this._mldsaKey === void 0) return false;
				const mldsaSig = signature.toMldsa();
				if (mldsaSig === null) return false;
				try {
					return this._mldsaKey.verify(mldsaSig, message);
				} catch {
					return false;
				}
			}
			case "SshEd25519":
			case "SshDsa":
			case "SshEcdsaP256":
			case "SshEcdsaP384": {
				if (this._sshKey === void 0) return false;
				const sshSig = signature.toSsh();
				if (sshSig === null) return false;
				try {
					return this._sshKey.verifySshSignature(sshSig.namespace, message, sshSig);
				} catch {
					return false;
				}
			}
		}
	}
	/**
	* Returns the CBOR tags associated with SigningPublicKey.
	*/
	cborTags() {
		return tagsForValues([SIGNING_PUBLIC_KEY.value]);
	}
	/**
	* Returns the untagged CBOR encoding.
	*
	* Format (matching Rust bc-components):
	* - Schnorr: h'<32-byte-x-only-public-key>' (bare byte string)
	* - ECDSA:   [1, h'<33-byte-compressed-public-key>']
	* - Ed25519: [2, h'<32-byte-public-key>']
	* - Sr25519: [3, h'<32-byte-public-key>']
	*/
	untaggedCbor() {
		switch (this._type) {
			case "Schnorr":
				if (this._schnorrKey === void 0) throw new Error("Schnorr public key is missing");
				return toByteString(this._schnorrKey.toData());
			case "Ecdsa":
				if (this._ecdsaKey === void 0) throw new Error("ECDSA public key is missing");
				return cbor$3([1, toByteString(this._ecdsaKey.toData())]);
			case "Ed25519":
				if (this._ed25519Key === void 0) throw new Error("Ed25519 public key is missing");
				return cbor$3([2, toByteString(this._ed25519Key.toData())]);
			case "Sr25519":
				if (this._sr25519Key === void 0) throw new Error("Sr25519 public key is missing");
				return cbor$3([3, toByteString(this._sr25519Key.toData())]);
			case "MLDSA44":
			case "MLDSA65":
			case "MLDSA87":
				if (this._mldsaKey === void 0) throw new Error("MLDSA public key is missing");
				return this._mldsaKey.taggedCbor();
			case "SshEd25519":
			case "SshDsa":
			case "SshEcdsaP256":
			case "SshEcdsaP384":
				if (this._sshKey === void 0) throw new Error("SSH public key is missing");
				return toTaggedValue(SSH_TEXT_PUBLIC_KEY, this._sshKey.toOpenssh());
		}
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates a SigningPublicKey by decoding it from untagged CBOR.
	*
	* Format (matching Rust bc-components):
	* - h'<32-byte-key>' (bare byte string) for Schnorr
	* - [1, h'<33-byte-key>'] for ECDSA
	* - [2, h'<32-byte-key>'] for Ed25519
	* - [3, h'<32-byte-key>'] for Sr25519
	*/
	fromUntaggedCbor(cborValue) {
		if (isBytes$1(cborValue)) {
			const keyData = expectBytes(cborValue);
			return SigningPublicKey.fromSchnorr(SchnorrPublicKey.from(keyData));
		}
		if (isArray(cborValue)) {
			const elements = expectArray(cborValue);
			if (elements.length !== 2) throw new Error("SigningPublicKey array must have 2 elements");
			const discriminator = expectUnsigned(elements[0]);
			const keyData = expectBytes(elements[1]);
			switch (Number(discriminator)) {
				case 1: return SigningPublicKey.fromEcdsa(ECPublicKey.from(keyData));
				case 2: return SigningPublicKey.fromEd25519(Ed25519PublicKey.from(keyData));
				case 3: return SigningPublicKey.fromSr25519(Sr25519PublicKey.from(keyData));
				default: throw new Error(`Unknown SigningPublicKey discriminator: ${discriminator}`);
			}
		}
		if (isTagged(cborValue)) {
			const tagged = cborValue.asTagged();
			if (tagged?.[0].value === MLDSA_PUBLIC_KEY.value) {
				const mldsaKey = MLDSAPublicKey.fromTaggedCbor(cborValue);
				return SigningPublicKey.fromMldsa(mldsaKey);
			}
			if (tagged?.[0].value === SSH_TEXT_PUBLIC_KEY.value) {
				const text = expectText(tagged[1]);
				const sshKey = SSHPublicKey.fromOpenssh(text);
				return SigningPublicKey.fromSsh(sshKey);
			}
		}
		throw new Error("SigningPublicKey must be a byte string (Schnorr), array (ECDSA/Ed25519/Sr25519), tagged MLDSA, or tagged SSH");
	}
	/**
	* Creates a SigningPublicKey by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		return new SigningPublicKey("Ed25519", void 0, void 0, Ed25519PublicKey.from(/* @__PURE__ */ new Uint8Array(32))).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return SigningPublicKey.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return SigningPublicKey.fromUntaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR.
	*/
	static fromUntaggedCbor(cborValue) {
		return new SigningPublicKey("Ed25519", void 0, void 0, Ed25519PublicKey.from(/* @__PURE__ */ new Uint8Array(32))).fromUntaggedCbor(cborValue);
	}
	/**
	* Get the UR type for signing public keys.
	*/
	static UR_TYPE = "signing-public-key";
	/**
	* Returns the UR representation of the signing public key.
	*/
	ur() {
		return UR.new(SigningPublicKey.UR_TYPE, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation of the signing public key.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates a SigningPublicKey from a UR.
	*/
	static fromUR(ur) {
		ur.checkType(SigningPublicKey.UR_TYPE);
		return SigningPublicKey.fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates a SigningPublicKey from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return SigningPublicKey.fromUR(ur);
	}
	/**
	* Alias for fromURString for Rust API compatibility.
	*/
	static fromUrString(urString) {
		return SigningPublicKey.fromURString(urString);
	}
	/**
	* Returns the OpenSSH single-line public-key text for an SSH public key.
	*
	* Only valid when this `SigningPublicKey` wraps an `SSHPublicKey`
	* (i.e. one of the four `SignatureScheme.SshXxx` variants). Mirrors
	* Rust's `SigningPublicKey::SSH(key) => key.to_openssh()` usage at
	* `signing_public_key.rs:442`.
	*/
	toSshOpenssh() {
		if (this._sshKey === void 0) throw new Error(`SigningPublicKey is not an SSH key (scheme: ${this._type})`);
		return this._sshKey.toOpenssh();
	}
};
//#endregion
//#region src/signing/signing-private-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* A private key used for creating digital signatures.
*
* `SigningPrivateKey` is a type representing different types of signing
* private keys. Supports Schnorr, ECDSA, Ed25519, and SR25519.
*
* This type implements the `Signer` interface, allowing it to create signatures.
*
* # CBOR Serialization
*
* `SigningPrivateKey` is serialized to CBOR with tag 40021.
*
* The CBOR encoding (matching Rust bc-components):
* - Schnorr: `#6.40021(h'<32-byte-private-key>')` (bare byte string)
* - ECDSA:   `#6.40021([1, h'<32-byte-private-key>'])`
* - Ed25519: `#6.40021([2, h'<32-byte-private-key>'])`
* - SR25519: `#6.40021([3, h'<32-byte-seed>'])`
*
* Ported from bc-components-rust/src/signing/signing_private_key.rs
*/
/**
* A private key used for creating digital signatures.
*
* Currently supports:
* - Schnorr private keys (32 bytes, secp256k1) - bare byte string in CBOR
* - ECDSA private keys (32 bytes, secp256k1) - discriminator 1
* - Ed25519 private keys (32 bytes) - discriminator 2
* - SR25519 private keys (32-byte seed) - discriminator 3
* - MLDSA private keys (post-quantum) - tagged CBOR delegating to MLDSAPrivateKey
*/
var SigningPrivateKey = class SigningPrivateKey {
	_type;
	_ecKey;
	_ed25519Key;
	_sr25519Key;
	_mldsaKey;
	_sshKey;
	constructor(type, ecKey, ed25519Key, sr25519Key, mldsaKey, sshKey) {
		this._type = type;
		this._ecKey = ecKey;
		this._ed25519Key = ed25519Key;
		this._sr25519Key = sr25519Key;
		this._mldsaKey = mldsaKey;
		this._sshKey = sshKey;
	}
	/**
	* Creates a new Schnorr signing private key from an ECPrivateKey.
	*
	* @param key - The EC private key to use for Schnorr signing
	* @returns A new Schnorr signing private key
	*/
	static newSchnorr(key) {
		return new SigningPrivateKey("Schnorr", key, void 0, void 0, void 0);
	}
	/**
	* Creates a new ECDSA signing private key from an ECPrivateKey.
	*
	* @param key - The EC private key to use for ECDSA signing
	* @returns A new ECDSA signing private key
	*/
	static newEcdsa(key) {
		return new SigningPrivateKey("Ecdsa", key, void 0, void 0, void 0);
	}
	/**
	* Creates a new Ed25519 signing private key from an Ed25519PrivateKey.
	*
	* @param key - The Ed25519 private key to use
	* @returns A new Ed25519 signing private key
	*/
	static newEd25519(key) {
		return new SigningPrivateKey("Ed25519", void 0, key, void 0, void 0);
	}
	/**
	* Creates a new SR25519 signing private key from an Sr25519PrivateKey.
	*
	* @param key - The SR25519 private key to use
	* @returns A new SR25519 signing private key
	*/
	static newSr25519(key) {
		return new SigningPrivateKey("Sr25519", void 0, void 0, key, void 0);
	}
	/**
	* Creates a new MLDSA signing private key from an MLDSAPrivateKey.
	*
	* @param key - The MLDSA private key to use
	* @returns A new MLDSA signing private key
	*/
	static newMldsa(key) {
		let scheme;
		switch (key.level()) {
			case 2:
				scheme = "MLDSA44";
				break;
			case 3:
				scheme = "MLDSA65";
				break;
			case 5:
				scheme = "MLDSA87";
				break;
			default: throw new Error(`Unknown MLDSA level: ${key.level()}`);
		}
		return new SigningPrivateKey(scheme, void 0, void 0, void 0, key);
	}
	/**
	* Creates a new SSH signing private key from an SSHPrivateKey.
	*
	* Mirrors Rust `SigningPrivateKey::new_ssh`
	* (`bc-components-rust/src/signing/signing_private_key.rs:317`).
	*
	* @param key - The SSH private key to wrap
	* @returns A new SSH signing private key
	*/
	static fromSsh(key) {
		let scheme;
		switch (key.data.kind) {
			case "ed25519":
				scheme = "SshEd25519";
				break;
			case "dsa":
				scheme = "SshDsa";
				break;
			case "ecdsa": switch (key.data.curve) {
				case "nistp256":
					scheme = "SshEcdsaP256";
					break;
				case "nistp384": scheme = "SshEcdsaP384";
			}
		}
		return new SigningPrivateKey(scheme, void 0, void 0, void 0, void 0, key);
	}
	/**
	* Creates a new random Ed25519 signing private key.
	*
	* @returns A new random Ed25519 signing private key
	*/
	static random() {
		return SigningPrivateKey.newEd25519(Ed25519PrivateKey.random());
	}
	/**
	* Creates a new random Schnorr signing private key.
	*
	* @returns A new random Schnorr signing private key
	*/
	static randomSchnorr() {
		return SigningPrivateKey.newSchnorr(ECPrivateKey.random());
	}
	/**
	* Creates a new random ECDSA signing private key.
	*
	* @returns A new random ECDSA signing private key
	*/
	static randomEcdsa() {
		return SigningPrivateKey.newEcdsa(ECPrivateKey.random());
	}
	/**
	* Creates a new random SR25519 signing private key.
	*
	* @returns A new random SR25519 signing private key
	*/
	static randomSr25519() {
		return SigningPrivateKey.newSr25519(Sr25519PrivateKey.random());
	}
	/**
	* Returns the signature scheme of this key.
	*/
	scheme() {
		return this._type;
	}
	/**
	* Returns a human-readable string identifying the key type.
	* @returns A string like "Ed25519", "Schnorr", "ECDSA", "Sr25519", "MLDSA-44", etc.
	*/
	keyType() {
		switch (this._type) {
			case "Ed25519": return "Ed25519";
			case "Schnorr": return "Schnorr";
			case "Ecdsa": return "ECDSA";
			case "Sr25519": return "Sr25519";
			case "MLDSA44": return "MLDSA-44";
			case "MLDSA65": return "MLDSA-65";
			case "MLDSA87": return "MLDSA-87";
			case "SshEd25519": return "SSH-Ed25519";
			case "SshDsa": return "SSH-DSA";
			case "SshEcdsaP256": return "SSH-ECDSA-P256";
			case "SshEcdsaP384": return "SSH-ECDSA-P384";
			default: return this._type;
		}
	}
	/**
	* Returns the underlying EC private key if this is a Schnorr or ECDSA key.
	*
	* @returns The EC private key if this is a Schnorr or ECDSA key, null otherwise
	*/
	toEc() {
		if ((this._type === "Schnorr" || this._type === "Ecdsa") && this._ecKey !== void 0) return this._ecKey;
		return null;
	}
	/**
	* Returns the underlying Schnorr private key if this is a Schnorr key.
	*
	* @returns The EC private key if this is a Schnorr key, null otherwise
	*/
	toSchnorr() {
		if (this._type === "Schnorr" && this._ecKey !== void 0) return this._ecKey;
		return null;
	}
	/**
	* Returns the underlying ECDSA private key if this is an ECDSA key.
	*
	* @returns The EC private key if this is an ECDSA key, null otherwise
	*/
	toEcdsa() {
		if (this._type === "Ecdsa" && this._ecKey !== void 0) return this._ecKey;
		return null;
	}
	/**
	* Returns the underlying Ed25519 private key if this is an Ed25519 key.
	*
	* @returns The Ed25519 private key if this is an Ed25519 key, null otherwise
	*/
	toEd25519() {
		if (this._type === "Ed25519" && this._ed25519Key !== void 0) return this._ed25519Key;
		return null;
	}
	/**
	* Returns the underlying Sr25519 private key if this is an Sr25519 key.
	*
	* @returns The Sr25519 private key if this is an Sr25519 key, null otherwise
	*/
	toSr25519() {
		if (this._type === "Sr25519" && this._sr25519Key !== void 0) return this._sr25519Key;
		return null;
	}
	/**
	* Returns the underlying MLDSA private key if this is an MLDSA key.
	*
	* @returns The MLDSA private key if this is an MLDSA key, null otherwise
	*/
	toMldsa() {
		if (isMldsaScheme(this._type) && this._mldsaKey !== void 0) return this._mldsaKey;
		return null;
	}
	/**
	* Checks if this is a Schnorr signing key.
	*/
	isSchnorr() {
		return this._type === "Schnorr";
	}
	/**
	* Checks if this is an ECDSA signing key.
	*/
	isEcdsa() {
		return this._type === "Ecdsa";
	}
	/**
	* Checks if this is an Ed25519 signing key.
	*/
	isEd25519() {
		return this._type === "Ed25519";
	}
	/**
	* Checks if this is an Sr25519 signing key.
	*/
	isSr25519() {
		return this._type === "Sr25519";
	}
	/**
	* Checks if this is an MLDSA signing key.
	*/
	isMldsa() {
		return isMldsaScheme(this._type);
	}
	/**
	* Derives the corresponding public key for this private key.
	*
	* @returns The public key corresponding to this private key
	*/
	publicKey() {
		switch (this._type) {
			case "Schnorr":
				if (this._ecKey === void 0) throw new Error("EC private key is missing");
				return SigningPublicKey.fromSchnorr(this._ecKey.schnorrPublicKey());
			case "Ecdsa":
				if (this._ecKey === void 0) throw new Error("EC private key is missing");
				return SigningPublicKey.fromEcdsa(this._ecKey.publicKey());
			case "Ed25519":
				if (this._ed25519Key === void 0) throw new Error("Ed25519 private key is missing");
				return SigningPublicKey.fromEd25519(this._ed25519Key.publicKey());
			case "Sr25519":
				if (this._sr25519Key === void 0) throw new Error("Sr25519 private key is missing");
				return SigningPublicKey.fromSr25519(this._sr25519Key.publicKey());
			case "MLDSA44":
			case "MLDSA65":
			case "MLDSA87":
				if (this._mldsaKey === void 0) throw new Error("MLDSA private key is missing");
				return SigningPublicKey.fromMldsa(this._mldsaKey.publicKey());
			case "SshEd25519":
			case "SshDsa":
			case "SshEcdsaP256":
			case "SshEcdsaP384":
				if (this._sshKey === void 0) throw new Error("SSH private key is missing");
				return SigningPublicKey.fromSsh(this._sshKey.publicKey());
		}
	}
	/**
	* Returns the underlying SSH private key if this is an SSH key.
	*
	* Mirrors Rust `SigningPrivateKey::to_ssh`
	* (`bc-components-rust/src/signing/signing_private_key.rs:387`).
	*
	* @returns The SSHPrivateKey if this is an SSH key, null otherwise
	*/
	toSsh() {
		return this._sshKey ?? null;
	}
	/**
	* Checks if this is an SSH signing key.
	*/
	isSsh() {
		return this._sshKey !== void 0;
	}
	/**
	* Compare with another SigningPrivateKey.
	*/
	equals(other) {
		if (this._type !== other._type) return false;
		switch (this._type) {
			case "Schnorr":
			case "Ecdsa":
				if (this._ecKey === void 0 || other._ecKey === void 0) return false;
				return this._ecKey.equals(other._ecKey);
			case "Ed25519":
				if (this._ed25519Key === void 0 || other._ed25519Key === void 0) return false;
				return this._ed25519Key.equals(other._ed25519Key);
			case "Sr25519":
				if (this._sr25519Key === void 0 || other._sr25519Key === void 0) return false;
				return this._sr25519Key.equals(other._sr25519Key);
			case "MLDSA44":
			case "MLDSA65":
			case "MLDSA87":
				if (this._mldsaKey === void 0 || other._mldsaKey === void 0) return false;
				return this._mldsaKey.equals(other._mldsaKey);
			case "SshEd25519":
			case "SshDsa":
			case "SshEcdsaP256":
			case "SshEcdsaP384":
				if (this._sshKey === void 0 || other._sshKey === void 0) return false;
				return this._sshKey.toOpenssh() === other._sshKey.toOpenssh();
		}
	}
	/**
	* Mirror of Rust `Display for SigningPrivateKey`
	* (`bc-components-rust/src/signing/signing_private_key.rs:1048-1095`):
	*   `SigningPrivateKey(<refHexShort>, <inner>)`
	* where `<inner>` is:
	*   - `SchnorrPrivateKey(<refHexShort>)` / `ECDSAPrivateKey(<refHexShort>)`
	*     for the secp256k1 variants (Rust formats them inline by tag rather
	*     than delegating to the inner key's Display)
	*   - the inner key's Display for Ed25519 and MLDSA
	*   - `SSHPrivateKey(<refHexShort>)` for SSH
	* The previous abbreviated form (`SigningPrivateKey(<type>)` only) was
	* a parity drift caught by the E1a summarizer audit.
	*/
	toString() {
		const refShort = this.reference().shortReference("hex");
		let innerDisplay;
		switch (this._type) {
			case "Schnorr":
				innerDisplay = `SchnorrPrivateKey(${refShort})`;
				break;
			case "Ecdsa":
				innerDisplay = `ECDSAPrivateKey(${refShort})`;
				break;
			case "Ed25519":
				innerDisplay = this._ed25519Key?.toString() ?? String(this._type);
				break;
			case "Sr25519":
				innerDisplay = this._sr25519Key?.toString() ?? String(this._type);
				break;
			case "MLDSA44":
			case "MLDSA65":
			case "MLDSA87":
				innerDisplay = this._mldsaKey?.toString() ?? String(this._type);
				break;
			case "SshEd25519":
			case "SshDsa":
			case "SshEcdsaP256":
			case "SshEcdsaP384": innerDisplay = this._sshKey?.toString() ?? `SSHPrivateKey(${refShort})`;
		}
		return `SigningPrivateKey(${refShort}, ${innerDisplay})`;
	}
	/**
	* Returns a unique reference to this SigningPrivateKey instance.
	*
	* The reference is derived from the SHA-256 hash of the tagged CBOR
	* representation, providing a unique, content-addressable identifier.
	*/
	reference() {
		const digest = Digest.fromImage(this.taggedCborData());
		return Reference.from(digest);
	}
	/**
	* Signs a message with optional signing options.
	*
	* Different signature schemes may use the options differently:
	* - Schnorr: Can accept a custom random number generator via SigningOptions.Schnorr
	* - SSH: Would require namespace and hash algorithm (not yet implemented)
	* - Other schemes (ECDSA, Ed25519, Sr25519, MLDSA): Options are ignored
	*
	* @param message - The message to sign
	* @param options - Optional signing options
	* @returns The digital signature
	*/
	signWithOptions(message, options) {
		switch (this._type) {
			case "Schnorr": {
				if (this._ecKey === void 0) throw new Error("EC private key is missing");
				if (options?.type === "Schnorr") {
					const sigData = this._ecKey.schnorrSignUsing(message, options.rng);
					return Signature.schnorrFromData(sigData);
				}
				const sigData = this._ecKey.schnorrSign(message);
				return Signature.schnorrFromData(sigData);
			}
			case "Ecdsa": {
				if (this._ecKey === void 0) throw new Error("EC private key is missing");
				const sigData = this._ecKey.ecdsaSign(message);
				return Signature.ecdsaFromData(sigData);
			}
			case "Ed25519": {
				if (this._ed25519Key === void 0) throw new Error("Ed25519 private key is missing");
				const sigData = this._ed25519Key.sign(message);
				return Signature.ed25519FromData(sigData);
			}
			case "Sr25519": {
				if (this._sr25519Key === void 0) throw new Error("Sr25519 private key is missing");
				const sigData = this._sr25519Key.sign(message);
				return Signature.sr25519FromData(sigData);
			}
			case "MLDSA44":
			case "MLDSA65":
			case "MLDSA87": {
				if (this._mldsaKey === void 0) throw new Error("MLDSA private key is missing");
				const mldsaSig = this._mldsaKey.sign(message);
				return Signature.mldsaFromSignature(mldsaSig);
			}
			case "SshEd25519":
			case "SshDsa":
			case "SshEcdsaP256":
			case "SshEcdsaP384": {
				if (this._sshKey === void 0) throw new Error("SSH private key is missing");
				if (options?.type !== "Ssh") throw new Error("Missing namespace and hash algorithm for SSH signing");
				const sshSig = this._sshKey.sign(options.namespace, options.hashAlg, message);
				return Signature.fromSsh(sshSig);
			}
		}
	}
	/**
	* Signs a message using default options.
	*
	* This is a convenience method that calls `signWithOptions` with no options.
	*
	* @param message - The message to sign
	* @returns The digital signature
	*/
	sign(message) {
		return this.signWithOptions(message);
	}
	/**
	* Verifies a signature against a message using the derived public key.
	*
	* Mirrors Rust's `Verifier for SigningPrivateKey`: only Schnorr keys
	* actually verify; every other scheme returns `false`. Callers needing
	* verification for Ed25519 / ECDSA / Sr25519 / MLDSA should derive the
	* public key first via `publicKey().verify(...)`.
	*
	* @param signature - The signature to verify
	* @param message - The message that was allegedly signed
	* @returns `true` if the signature is a valid Schnorr signature
	*/
	verify(signature, message) {
		if (this._type !== "Schnorr" || this._ecKey === void 0) return false;
		const sigData = signature.toSchnorr();
		if (sigData === null) return false;
		return this._ecKey.schnorrPublicKey().schnorrVerify(sigData, message);
	}
	/**
	* Signs a message using Schnorr with the provided random number generator.
	*
	* This method is only valid for Schnorr keys.
	*
	* @param message - The message to sign
	* @param rng - The random number generator to use for signature creation
	* @returns The Schnorr signature
	* @throws Error if this is not a Schnorr key
	*/
	schnorrSign(message, rng) {
		const privateKey = this.toSchnorr();
		if (privateKey === null) throw new Error("Invalid key type for Schnorr signing");
		const sigData = privateKey.schnorrSignUsing(message, rng);
		return Signature.schnorrFromData(sigData);
	}
	/**
	* Signs a message using ECDSA.
	*
	* This method is only valid for ECDSA keys.
	*
	* @param message - The message to sign
	* @returns The ECDSA signature
	* @throws Error if this is not an ECDSA key
	*/
	ecdsaSign(message) {
		const privateKey = this.toEcdsa();
		if (privateKey === null) throw new Error("Invalid key type for ECDSA signing");
		const sigData = privateKey.ecdsaSign(message);
		return Signature.ecdsaFromData(sigData);
	}
	/**
	* Signs a message using Ed25519.
	*
	* This method is only valid for Ed25519 keys.
	*
	* @param message - The message to sign
	* @returns The Ed25519 signature
	* @throws Error if this is not an Ed25519 key
	*/
	ed25519Sign(message) {
		const privateKey = this.toEd25519();
		if (privateKey === null) throw new Error("Invalid key type for Ed25519 signing");
		const sigData = privateKey.sign(message);
		return Signature.ed25519FromData(sigData);
	}
	/**
	* Signs a message using SR25519.
	*
	* This method is only valid for SR25519 keys.
	*
	* @param message - The message to sign
	* @returns The SR25519 signature
	* @throws Error if this is not an SR25519 key
	*/
	sr25519Sign(message) {
		const privateKey = this.toSr25519();
		if (privateKey === null) throw new Error("Invalid key type for SR25519 signing");
		const sigData = privateKey.sign(message);
		return Signature.sr25519FromData(sigData);
	}
	/**
	* Signs a message using ML-DSA.
	*
	* This method is only valid for MLDSA keys.
	*
	* @param message - The message to sign
	* @returns The ML-DSA signature
	* @throws Error if this is not an MLDSA key
	*/
	mldsaSign(message) {
		const privateKey = this.toMldsa();
		if (privateKey === null) throw new Error("Invalid key type for MLDSA signing");
		const mldsaSig = privateKey.sign(message);
		return Signature.mldsaFromSignature(mldsaSig);
	}
	/**
	* Returns the CBOR tags associated with SigningPrivateKey.
	*/
	cborTags() {
		return tagsForValues([SIGNING_PRIVATE_KEY.value]);
	}
	/**
	* Returns the untagged CBOR encoding.
	*
	* Format (matching Rust bc-components):
	* - Schnorr: h'<32-byte-private-key>' (bare byte string)
	* - ECDSA:   [1, h'<32-byte-private-key>']
	* - Ed25519: [2, h'<32-byte-private-key>']
	* - Sr25519: [3, h'<32-byte-seed>']
	* - MLDSA:   delegates to MLDSAPrivateKey (tagged)
	*/
	untaggedCbor() {
		switch (this._type) {
			case "Schnorr":
				if (this._ecKey === void 0) throw new Error("EC private key is missing");
				return toByteString(this._ecKey.toData());
			case "Ecdsa":
				if (this._ecKey === void 0) throw new Error("EC private key is missing");
				return cbor$3([1, toByteString(this._ecKey.toData())]);
			case "Ed25519":
				if (this._ed25519Key === void 0) throw new Error("Ed25519 private key is missing");
				return cbor$3([2, toByteString(this._ed25519Key.toData())]);
			case "Sr25519":
				if (this._sr25519Key === void 0) throw new Error("Sr25519 private key is missing");
				return cbor$3([3, toByteString(this._sr25519Key.toData())]);
			case "MLDSA44":
			case "MLDSA65":
			case "MLDSA87":
				if (this._mldsaKey === void 0) throw new Error("MLDSA private key is missing");
				return this._mldsaKey.taggedCbor();
			case "SshEd25519":
			case "SshDsa":
			case "SshEcdsaP256":
			case "SshEcdsaP384":
				if (this._sshKey === void 0) throw new Error("SSH private key is missing");
				return toTaggedValue(SSH_TEXT_PRIVATE_KEY, this._sshKey.toOpenssh());
		}
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates a SigningPrivateKey by decoding it from untagged CBOR.
	*
	* Format (matching Rust bc-components):
	* - h'<32-byte-key>' (bare byte string) for Schnorr
	* - [1, h'<32-byte-key>'] for ECDSA
	* - [2, h'<32-byte-key>'] for Ed25519
	* - [3, h'<32-byte-seed>'] for Sr25519
	* - tagged MLDSA private key for MLDSA variants
	*/
	fromUntaggedCbor(cborValue) {
		if (isBytes$1(cborValue)) {
			const keyData = expectBytes(cborValue);
			return SigningPrivateKey.newSchnorr(ECPrivateKey.from(keyData));
		}
		if (isArray(cborValue)) {
			const elements = expectArray(cborValue);
			if (elements.length !== 2) throw new Error("SigningPrivateKey array must have 2 elements");
			const discriminator = expectUnsigned(elements[0]);
			const keyData = expectBytes(elements[1]);
			switch (Number(discriminator)) {
				case 1: return SigningPrivateKey.newEcdsa(ECPrivateKey.from(keyData));
				case 2: return SigningPrivateKey.newEd25519(Ed25519PrivateKey.from(keyData));
				case 3: return SigningPrivateKey.newSr25519(Sr25519PrivateKey.from(keyData));
				default: throw new Error(`Unknown SigningPrivateKey discriminator: ${discriminator}`);
			}
		}
		if (isTagged(cborValue)) {
			const tagged = cborValue.asTagged();
			if (tagged?.[0].value === MLDSA_PRIVATE_KEY.value) {
				const mldsaKey = MLDSAPrivateKey.fromTaggedCbor(cborValue);
				return SigningPrivateKey.newMldsa(mldsaKey);
			}
			if (tagged?.[0].value === SSH_TEXT_PRIVATE_KEY.value) {
				const text = expectText(tagged[1]);
				const sshKey = SSHPrivateKey.fromOpenssh(text);
				return SigningPrivateKey.fromSsh(sshKey);
			}
		}
		throw new Error("SigningPrivateKey must be a byte string (Schnorr), array (ECDSA/Ed25519/Sr25519), tagged MLDSA, or tagged SSH");
	}
	/**
	* Creates a SigningPrivateKey by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		return new SigningPrivateKey("Ed25519", void 0, Ed25519PrivateKey.from(/* @__PURE__ */ new Uint8Array(32))).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return SigningPrivateKey.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return SigningPrivateKey.fromUntaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR.
	*/
	static fromUntaggedCbor(cborValue) {
		return new SigningPrivateKey("Ed25519", void 0, Ed25519PrivateKey.from(/* @__PURE__ */ new Uint8Array(32))).fromUntaggedCbor(cborValue);
	}
	/**
	* Get the UR type for signing private keys.
	*/
	static UR_TYPE = "signing-private-key";
	/**
	* Returns the UR representation of the signing private key.
	*/
	ur() {
		return UR.new(SigningPrivateKey.UR_TYPE, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation of the signing private key.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates a SigningPrivateKey from a UR.
	*/
	static fromUR(ur) {
		ur.checkType(SigningPrivateKey.UR_TYPE);
		return SigningPrivateKey.fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates a SigningPrivateKey from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return SigningPrivateKey.fromUR(ur);
	}
	/**
	* Alias for fromURString for Rust API compatibility.
	*/
	static fromUrString(urString) {
		return SigningPrivateKey.fromURString(urString);
	}
	/**
	* Returns the canonical OpenSSH armored PEM for an SSH private key.
	*
	* Only valid when this `SigningPrivateKey` wraps an `SSHPrivateKey`
	* (i.e. one of the four `SignatureScheme.SshXxx` variants). Mirrors
	* Rust's `SigningPrivateKey::SSH(key) => key.to_openssh(LineEnding::LF)`
	* usage at `signing_private_key.rs:896`.
	*/
	toSshOpenssh() {
		if (this._sshKey === void 0) throw new Error(`SigningPrivateKey is not an SSH key (scheme: ${this._type})`);
		return this._sshKey.toOpenssh();
	}
};
//#endregion
//#region src/public-keys.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* PublicKeys - Container for signing and encapsulation public keys
*
* PublicKeys combines a SigningPublicKey (for signature verification) and an
* EncapsulationPublicKey (for key agreement/encryption) into a single unit.
*
* This is the public counterpart to PrivateKeys.
*
* # CBOR Serialization
*
* PublicKeys is serialized with tag 40017:
* ```
* #6.40017([<SigningPublicKey>, <EncapsulationPublicKey>])
* ```
*
* # UR Serialization
*
* UR type: `crypto-pubkeys`
*
* Ported from bc-components-rust/src/public_keys.rs
*/
/**
* PublicKeys - Container for a signing public key and an encapsulation public key.
*
* This type provides a convenient way to share public keys for both
* signature verification and encryption operations.
*/
var PublicKeys = class PublicKeys {
	_signingPublicKey;
	_encapsulationPublicKey;
	constructor(signingPublicKey, encapsulationPublicKey) {
		this._signingPublicKey = signingPublicKey;
		this._encapsulationPublicKey = encapsulationPublicKey;
	}
	/**
	* Create a new PublicKeys container with the given keys.
	*/
	static new(signingPublicKey, encapsulationPublicKey) {
		return new PublicKeys(signingPublicKey, encapsulationPublicKey);
	}
	/**
	* Returns the signing public key.
	*/
	signingPublicKey() {
		return this._signingPublicKey;
	}
	/**
	* Returns the encapsulation public key.
	*
	* Note: Named to match Rust's API (which has a typo but we maintain compatibility)
	*/
	encapsulationPublicKey() {
		return this._encapsulationPublicKey;
	}
	/**
	* Verify a signature against a message.
	*/
	verify(signature, message) {
		return this._signingPublicKey.verify(signature, message);
	}
	/**
	* Encapsulate a new shared secret using the encapsulation public key.
	*
	* This implements the Encrypter interface, allowing PublicKeys to be used
	* in encryption contexts where a shared secret needs to be generated.
	*
	* @returns A tuple of [SymmetricKey, EncapsulationCiphertext]
	*/
	encapsulateNewSharedSecret() {
		return this._encapsulationPublicKey.encapsulateNewSharedSecret();
	}
	/**
	* Returns a unique reference to this PublicKeys instance.
	*
	* The reference is derived from the SHA-256 hash of the tagged CBOR
	* representation, providing a unique, content-addressable identifier.
	*/
	reference() {
		const digest = Digest.fromImage(this.taggedCborData());
		return Reference.from(digest);
	}
	/**
	* Compare with another PublicKeys.
	*/
	equals(other) {
		return this._signingPublicKey.equals(other._signingPublicKey) && this._encapsulationPublicKey.equals(other._encapsulationPublicKey);
	}
	/**
	* Get string representation.
	*
	* Mirrors Rust `Display for PublicKeys`
	* (`bc-components-rust/src/public_keys.rs:216-225`):
	*   `PublicKeys(<short_reference>, <signing_public_key>, <encapsulation_public_key>)`
	*
	* The earlier short form (`PublicKeys(<short_reference>)`) was
	* observable in envelope notation as a missing key fingerprint
	* trail in the GSTP `'sender': XID(...) [ 'key': PublicKeys(...) ]`
	* format-pin (G1 in `PARITY_OUTSTANDING.md`).
	*/
	toString() {
		return `PublicKeys(${this.reference().shortReference("hex")}, ${this._signingPublicKey.toString()}, ${this._encapsulationPublicKey.toString()})`;
	}
	/**
	* Returns the CBOR tags associated with PublicKeys.
	*/
	cborTags() {
		return tagsForValues([PUBLIC_KEYS.value]);
	}
	/**
	* Returns the untagged CBOR encoding.
	*
	* Format: [<SigningPublicKey>, <EncapsulationPublicKey>]
	*/
	untaggedCbor() {
		return cbor$3([this._signingPublicKey.taggedCbor(), this._encapsulationPublicKey.taggedCbor()]);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates a PublicKeys by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cborValue) {
		const elements = expectArray(cborValue);
		if (elements.length !== 2) throw new Error(`PublicKeys must have 2 elements, got ${elements.length}`);
		const signingPublicKey = SigningPublicKey.fromTaggedCbor(elements[0]);
		const encapsulationPublicKey = EncapsulationPublicKey.fromTaggedCbor(elements[1]);
		return new PublicKeys(signingPublicKey, encapsulationPublicKey);
	}
	/**
	* Creates a PublicKeys by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		const signingKeyPrefix = new Uint8Array([
			130,
			2,
			88,
			32
		]);
		const signingKeyData = /* @__PURE__ */ new Uint8Array(36);
		signingKeyData.set(signingKeyPrefix, 0);
		const signingKey = SigningPublicKey.fromUntaggedCborData(signingKeyData);
		const encapsulationKeyPrefix = new Uint8Array([88, 32]);
		const encapsulationKeyData = /* @__PURE__ */ new Uint8Array(34);
		encapsulationKeyData.set(encapsulationKeyPrefix, 0);
		const encapsulationKey = EncapsulationPublicKey.fromUntaggedCborData(encapsulationKeyData);
		return new PublicKeys(signingKey, encapsulationKey).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return PublicKeys.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		const signingKeyPrefix = new Uint8Array([
			130,
			2,
			88,
			32
		]);
		const signingKeyData = /* @__PURE__ */ new Uint8Array(36);
		signingKeyData.set(signingKeyPrefix, 0);
		const signingKey = SigningPublicKey.fromUntaggedCborData(signingKeyData);
		const encapsulationKeyPrefix = new Uint8Array([88, 32]);
		const encapsulationKeyData = /* @__PURE__ */ new Uint8Array(34);
		encapsulationKeyData.set(encapsulationKeyPrefix, 0);
		const encapsulationKey = EncapsulationPublicKey.fromUntaggedCborData(encapsulationKeyData);
		return new PublicKeys(signingKey, encapsulationKey).fromUntaggedCbor(cborValue);
	}
	/**
	* Returns the UR representation.
	*/
	ur() {
		const name = PUBLIC_KEYS.name;
		if (name === void 0) throw new Error("PUBLIC_KEYS tag name is undefined");
		return UR.new(name, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates a PublicKeys from a UR.
	*/
	static fromUR(ur) {
		if (ur.urTypeStr() !== PUBLIC_KEYS.name) throw new Error(`Expected UR type ${PUBLIC_KEYS.name}, got ${ur.urTypeStr()}`);
		const signingKeyPrefix = new Uint8Array([
			130,
			2,
			88,
			32
		]);
		const signingKeyData = /* @__PURE__ */ new Uint8Array(36);
		signingKeyData.set(signingKeyPrefix, 0);
		const signingKey = SigningPublicKey.fromUntaggedCborData(signingKeyData);
		const encapsulationKeyPrefix = new Uint8Array([88, 32]);
		const encapsulationKeyData = /* @__PURE__ */ new Uint8Array(34);
		encapsulationKeyData.set(encapsulationKeyPrefix, 0);
		const encapsulationKey = EncapsulationPublicKey.fromUntaggedCborData(encapsulationKeyData);
		return new PublicKeys(signingKey, encapsulationKey).fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates a PublicKeys from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return PublicKeys.fromUR(ur);
	}
};
//#endregion
//#region src/private-keys.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* PrivateKeys - Container for signing and encapsulation private keys
*
* PrivateKeys combines a SigningPrivateKey (for digital signatures) and an
* EncapsulationPrivateKey (for key agreement/encryption) into a single unit.
*
* # CBOR Serialization
*
* PrivateKeys is serialized with tag 40013:
* ```
* #6.40013([<SigningPrivateKey>, <EncapsulationPrivateKey>])
* ```
*
* # UR Serialization
*
* UR type: `crypto-prvkeys`
*
* Ported from bc-components-rust/src/private_keys.rs
*/
/**
* PrivateKeys - Container for a signing key and an encapsulation key.
*
* This type provides a convenient way to manage a pair of private keys
* for both signing and encryption operations.
*/
var PrivateKeys = class PrivateKeys {
	_signingPrivateKey;
	_encapsulationPrivateKey;
	constructor(signingPrivateKey, encapsulationPrivateKey) {
		this._signingPrivateKey = signingPrivateKey;
		this._encapsulationPrivateKey = encapsulationPrivateKey;
	}
	/**
	* Create a new PrivateKeys container with the given keys.
	*/
	static withKeys(signingPrivateKey, encapsulationPrivateKey) {
		return new PrivateKeys(signingPrivateKey, encapsulationPrivateKey);
	}
	/**
	* Create a new PrivateKeys container with random Ed25519/X25519 keys.
	*/
	static new() {
		const signingKey = SigningPrivateKey.random();
		const encapsulationKey = EncapsulationPrivateKey.random();
		return new PrivateKeys(signingKey, encapsulationKey);
	}
	/**
	* Generate a new PrivateKeys container with random Ed25519/X25519 keys.
	* This is an alias for new() for API compatibility.
	*/
	static generate() {
		return PrivateKeys.new();
	}
	/**
	* Returns the signing private key.
	*/
	signingPrivateKey() {
		return this._signingPrivateKey;
	}
	/**
	* Returns the encapsulation private key.
	*
	* Note: Named to match Rust's API (which has a typo but we maintain compatibility)
	*/
	encapsulationPrivateKey() {
		return this._encapsulationPrivateKey;
	}
	/**
	* Derive the corresponding public keys.
	*/
	publicKeys() {
		const signingPublicKey = this._signingPrivateKey.publicKey();
		const encapsulationPublicKey = this._encapsulationPrivateKey.publicKey();
		return PublicKeys.new(signingPublicKey, encapsulationPublicKey);
	}
	/**
	* Sign a message with optional signing options using the signing private key.
	*/
	signWithOptions(message, options) {
		return this._signingPrivateKey.signWithOptions(message, options);
	}
	/**
	* Sign a message using the signing private key.
	*/
	sign(message) {
		return this._signingPrivateKey.sign(message);
	}
	/**
	* Decapsulate a shared secret from a ciphertext.
	*
	* This implements the Decrypter interface, allowing PrivateKeys to be used
	* in encryption contexts where a shared secret needs to be recovered.
	*/
	decapsulateSharedSecret(ciphertext) {
		return this._encapsulationPrivateKey.decapsulateSharedSecret(ciphertext);
	}
	/**
	* Returns a unique reference to this PrivateKeys instance.
	*
	* The reference is derived from the SHA-256 hash of the tagged CBOR
	* representation, providing a unique, content-addressable identifier.
	*/
	reference() {
		const digest = Digest.fromImage(this.taggedCborData());
		return Reference.from(digest);
	}
	/**
	* Compare with another PrivateKeys.
	*/
	equals(other) {
		return this._signingPrivateKey.equals(other._signingPrivateKey) && this._encapsulationPrivateKey.equals(other._encapsulationPrivateKey);
	}
	/**
	* Mirror of Rust `Display for PrivateKeys`
	* (`bc-components-rust/src/private_keys.rs:229-238`):
	*   `PrivateKeys(<refHexShort>, <signingPrivateKey>, <encapsulationPrivateKey>)`
	* The previous abbreviated form (`PrivateKeys(<short>)` only) was a
	* parity drift caught by the E1a summarizer audit.
	*/
	toString() {
		return `PrivateKeys(${this.reference().shortReference("hex")}, ${this._signingPrivateKey.toString()}, ${this._encapsulationPrivateKey.toString()})`;
	}
	/**
	* Returns the CBOR tags associated with PrivateKeys.
	*/
	cborTags() {
		return tagsForValues([PRIVATE_KEYS.value]);
	}
	/**
	* Returns the untagged CBOR encoding.
	*
	* Format: [<SigningPrivateKey>, <EncapsulationPrivateKey>]
	*/
	untaggedCbor() {
		return cbor$3([this._signingPrivateKey.taggedCbor(), this._encapsulationPrivateKey.taggedCbor()]);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates a PrivateKeys by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cborValue) {
		const elements = expectArray(cborValue);
		if (elements.length !== 2) throw new Error(`PrivateKeys must have 2 elements, got ${elements.length}`);
		const signingPrivateKey = SigningPrivateKey.fromTaggedCbor(elements[0]);
		const encapsulationPrivateKey = EncapsulationPrivateKey.fromTaggedCbor(elements[1]);
		return new PrivateKeys(signingPrivateKey, encapsulationPrivateKey);
	}
	/**
	* Creates a PrivateKeys by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		return PrivateKeys.new().fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return PrivateKeys.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return PrivateKeys.new().fromUntaggedCbor(cborValue);
	}
	/**
	* Returns the UR representation.
	*/
	ur() {
		const name = PRIVATE_KEYS.name;
		if (name === void 0) throw new Error("PRIVATE_KEYS tag name is undefined");
		return UR.new(name, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates a PrivateKeys from a UR.
	*/
	static fromUR(ur) {
		if (ur.urTypeStr() !== PRIVATE_KEYS.name) throw new Error(`Expected UR type ${PRIVATE_KEYS.name}, got ${ur.urTypeStr()}`);
		return PrivateKeys.new().fromUntaggedCbor(ur.cbor());
	}
	/**
	* Creates a PrivateKeys from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return PrivateKeys.fromUR(ur);
	}
};
//#endregion
//#region src/keypair.ts
/**
* Generates a key pair using the default signature and encapsulation schemes
* (Schnorr + X25519).
*
* Mirrors Rust `pub fn keypair() -> (PrivateKeys, PublicKeys)`.
*/
function keypair() {
	return keypairOpt(defaultSignatureScheme(), defaultEncapsulationScheme());
}
/**
* Generates a key pair using the default schemes and a provided RNG.
*
* Mirrors Rust `pub fn keypair_using(rng) -> Result<(PrivateKeys, PublicKeys)>`.
*
* Note: ML-KEM does not support deterministic generation. This helper uses
* the default encapsulation scheme (X25519), which does.
*/
function keypairUsing(rng) {
	return keypairOptUsing(defaultSignatureScheme(), defaultEncapsulationScheme(), rng);
}
/**
* Generates a key pair with explicit signature and encapsulation schemes.
*
* Mirrors Rust `pub fn keypair_opt(sig, enc) -> (PrivateKeys, PublicKeys)`.
*/
function keypairOpt(signatureScheme, encapsulationScheme) {
	const [signingPrivateKey, signingPublicKey] = createKeypair(signatureScheme);
	const [encapsulationPrivateKey, encapsulationPublicKey] = createEncapsulationKeypair(encapsulationScheme);
	return [PrivateKeys.withKeys(signingPrivateKey, encapsulationPrivateKey), PublicKeys.new(signingPublicKey, encapsulationPublicKey)];
}
/**
* Generates a key pair with explicit schemes and a provided RNG.
*
* Mirrors Rust `pub fn keypair_opt_using(sig, enc, rng) ->
*   Result<(PrivateKeys, PublicKeys)>`.
*
* Throws if either scheme does not support deterministic generation
* (e.g. ML-DSA / ML-KEM, or any SSH-based signing scheme).
*/
function keypairOptUsing(signatureScheme, encapsulationScheme, rng) {
	const [signingPrivateKey, signingPublicKey] = createKeypairUsing(signatureScheme, rng);
	const [encapsulationPrivateKey, encapsulationPublicKey] = createEncapsulationKeypairUsing(rng, encapsulationScheme);
	return [PrivateKeys.withKeys(signingPrivateKey, encapsulationPrivateKey), PublicKeys.new(signingPublicKey, encapsulationPublicKey)];
}
//#endregion
//#region src/ec-key/ec-key-base.ts
/**
* Type guard to check if an object implements ECKeyBase.
*/
function isECKeyBase(obj) {
	if (obj === null || typeof obj !== "object") return false;
	const candidate = obj;
	return typeof candidate.data === "function" && typeof candidate.hex === "function";
}
/**
* Type guard to check if an object implements ECKey.
*/
function isECKey(obj) {
	if (!isECKeyBase(obj)) return false;
	return typeof obj.publicKey === "function";
}
/**
* Type guard to check if an object implements ECPublicKeyBase.
*/
function isECPublicKeyBase(obj) {
	if (!isECKey(obj)) return false;
	return typeof obj.uncompressedPublicKey === "function";
}
//#endregion
//#region src/encapsulation/sealed-message.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Sealed message for anonymous authenticated encryption
*
* A `SealedMessage` combines key encapsulation with symmetric encryption to
* provide anonymous authenticated encryption. The sender's identity is not
* revealed, and only the intended recipient can decrypt the message.
*
* The sealing process:
* 1. Encapsulate a new shared secret using the recipient's public key
* 2. Use the shared secret to encrypt the plaintext with ChaCha20-Poly1305
* 3. Return the encrypted message and the encapsulation ciphertext
*
* The unsealing process:
* 1. Decapsulate the shared secret using the recipient's private key
* 2. Use the shared secret to decrypt the ciphertext
* 3. Return the plaintext
*
* Features:
* - Anonymous sender (sender identity not revealed)
* - Authenticated encryption
* - Forward secrecy (each message uses different ephemeral key)
*
* # CBOR Serialization
*
* `SealedMessage` is serialized as a 2-element array with tag 40019:
*
* ```cddl
* SealedMessage = #6.40019([
*   message: EncryptedMessage,
*   encapsulated_key: EncapsulationCiphertext
* ])
* ```
*
* # UR Serialization
*
* When serialized as a Uniform Resource (UR), a `SealedMessage` is
* represented with the type "crypto-sealed".
*
* Ported from bc-components-rust/src/encapsulation/sealed_message.rs
*/
/**
* A sealed message providing anonymous authenticated encryption.
*/
var SealedMessage = class SealedMessage {
	_message;
	_encapsulatedKey;
	constructor(message, encapsulatedKey) {
		this._message = message;
		this._encapsulatedKey = encapsulatedKey;
	}
	/**
	* Create a SealedMessage from its components.
	*/
	static from(message, encapsulatedKey) {
		return new SealedMessage(message, encapsulatedKey);
	}
	/**
	* Seal a message for a recipient (no additional authenticated data).
	*
	* @param plaintext - The message to encrypt
	* @param recipient - The recipient's public key
	* @returns A sealed message that only the recipient can decrypt
	*/
	static new(plaintext, recipient) {
		return SealedMessage.newWithAad(plaintext, recipient, /* @__PURE__ */ new Uint8Array(0));
	}
	/**
	* Seal a message for a recipient with additional authenticated data.
	*
	* @param plaintext - The message to encrypt
	* @param recipient - The recipient's public key
	* @param aad - Additional authenticated data (not encrypted but authenticated)
	* @returns A sealed message that only the recipient can decrypt
	*/
	static newWithAad(plaintext, recipient, aad) {
		return SealedMessage.newOpt(plaintext, recipient, aad, void 0);
	}
	/**
	* Seal a message with optional test nonce (for deterministic testing).
	*
	* @param plaintext - The message to encrypt
	* @param recipient - The recipient's public key
	* @param aad - Additional authenticated data
	* @param testNonce - Optional fixed nonce for testing (DO NOT use in production)
	* @returns A sealed message
	*/
	static newOpt(plaintext, recipient, aad, testNonce) {
		const [sharedSecret, ciphertext] = recipient.encapsulateNewSharedSecret();
		const nonce = testNonce ?? Nonce.new();
		const encryptedMessage = sharedSecret.encrypt(plaintext, aad, nonce);
		return new SealedMessage(encryptedMessage, ciphertext);
	}
	/**
	* Returns the encrypted message.
	*/
	message() {
		return this._message;
	}
	/**
	* Returns the encapsulation ciphertext (ephemeral public key for X25519).
	*/
	encapsulatedKey() {
		return this._encapsulatedKey;
	}
	/**
	* Returns the encapsulation scheme used.
	*/
	encapsulationScheme() {
		return this._encapsulatedKey.encapsulationScheme();
	}
	/**
	* Decrypt the sealed message using the recipient's private key.
	*
	* @param privateKey - The recipient's private key
	* @returns The decrypted plaintext
	* @throws Error if decryption fails
	*/
	decrypt(privateKey) {
		return privateKey.decapsulateSharedSecret(this._encapsulatedKey).decrypt(this._message);
	}
	/**
	* Compare with another SealedMessage.
	*/
	equals(other) {
		return this._message.equals(other._message) && this._encapsulatedKey.equals(other._encapsulatedKey);
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `SealedMessage(${this._encapsulatedKey.encapsulationScheme()}, ciphertext: ${bytesToHex(this._message.ciphertext()).substring(0, 16)}...)`;
	}
	/**
	* Returns the CBOR tags associated with SealedMessage.
	*/
	cborTags() {
		return tagsForValues([SEALED_MESSAGE.value]);
	}
	/**
	* Returns the untagged CBOR encoding.
	* Format: [EncryptedMessage (tagged), EncapsulationCiphertext (tagged)]
	*/
	untaggedCbor() {
		const elements = [this._message.taggedCbor(), this._encapsulatedKey.taggedCbor()];
		return cbor$3(elements);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates a SealedMessage by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cborValue) {
		const elements = expectArray(cborValue);
		if (elements.length !== 2) throw new Error(`SealedMessage must have 2 elements, got ${elements.length}`);
		const message = EncryptedMessage.fromTaggedCbor(elements[0]);
		const encapsulatedKey = EncapsulationCiphertext.fromTaggedCbor(elements[1]);
		return new SealedMessage(message, encapsulatedKey);
	}
	/**
	* Creates a SealedMessage by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		const dummyMessage = EncryptedMessage.new(/* @__PURE__ */ new Uint8Array(0), /* @__PURE__ */ new Uint8Array(0), Nonce.new(), /* @__PURE__ */ new Uint8Array(16));
		const dummyCiphertext = EncapsulationCiphertext.fromX25519PublicKey(X25519PublicKey.fromData(/* @__PURE__ */ new Uint8Array(32)));
		return new SealedMessage(dummyMessage, dummyCiphertext).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return SealedMessage.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		const dummyMessage = EncryptedMessage.new(/* @__PURE__ */ new Uint8Array(0), /* @__PURE__ */ new Uint8Array(0), Nonce.new(), /* @__PURE__ */ new Uint8Array(16));
		const dummyCiphertext = EncapsulationCiphertext.fromX25519PublicKey(X25519PublicKey.fromData(/* @__PURE__ */ new Uint8Array(32)));
		return new SealedMessage(dummyMessage, dummyCiphertext).fromUntaggedCbor(cborValue);
	}
	/**
	* Returns the UR representation of the SealedMessage.
	* Note: URs use untagged CBOR since the type is conveyed by the UR type itself.
	*/
	ur() {
		const name = SEALED_MESSAGE.name;
		if (name === void 0) throw new Error("TAG_SEALED_MESSAGE.name is undefined");
		return UR.new(name, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates a SealedMessage from a UR.
	*/
	static fromUR(ur) {
		const name = SEALED_MESSAGE.name;
		if (name === void 0) throw new Error("TAG_SEALED_MESSAGE.name is undefined");
		ur.checkType(name);
		return SealedMessage.fromUntaggedCborData(ur.cbor().toData());
	}
	/**
	* Creates a SealedMessage from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return SealedMessage.fromUR(ur);
	}
};
//#endregion
//#region src/encrypted-key/hash-type.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Hash type enum for key derivation functions
*
* This enum represents the supported hash algorithms for HKDF and PBKDF2.
*
* CDDL:
* ```cddl
* HashType = SHA256 / SHA512
* SHA256 = 0
* SHA512 = 1
* ```
*
* Ported from bc-components-rust/src/encrypted_key/hash_type.rs
*/
/**
* Enum representing supported hash types for key derivation.
*/
let HashType = /* @__PURE__ */ function(HashType) {
	/** SHA-256 hash algorithm */
	HashType[HashType["SHA256"] = 0] = "SHA256";
	/** SHA-512 hash algorithm */
	HashType[HashType["SHA512"] = 1] = "SHA512";
	return HashType;
}({});
/**
* Convert HashType to its string representation.
*/
function hashTypeToString(hashType) {
	switch (hashType) {
		case 0: return "SHA256";
		case 1: return "SHA512";
		default: throw new Error(`Unknown HashType: ${String(hashType)}`);
	}
}
/**
* Convert HashType to CBOR.
*/
function hashTypeToCbor(hashType) {
	return cbor$3(hashType);
}
/**
* Parse HashType from CBOR.
*/
function hashTypeFromCbor(cborValue) {
	const value = expectNumber(cborValue);
	switch (value) {
		case 0: return 0;
		case 1: return 1;
		default: throw new Error(`Invalid HashType: ${value}`);
	}
}
//#endregion
//#region src/encrypted-key/key-derivation-method.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Key derivation method enum
*
* This enum represents the supported key derivation methods for encrypting keys.
*
* CDDL:
* ```cddl
* KeyDerivationMethod = HKDF / PBKDF2 / Scrypt / Argon2id / SSHAgent
* HKDF = 0
* PBKDF2 = 1
* Scrypt = 2
* Argon2id = 3
* SSHAgent = 4
* ```
*
* Ported from bc-components-rust/src/encrypted_key/key_derivation_method.rs
*/
/**
* Enum representing supported key derivation methods.
*/
let KeyDerivationMethod = /* @__PURE__ */ function(KeyDerivationMethod) {
	/** HKDF (HMAC-based Key Derivation Function) - RFC 5869 */
	KeyDerivationMethod[KeyDerivationMethod["HKDF"] = 0] = "HKDF";
	/** PBKDF2 (Password-Based Key Derivation Function 2) - RFC 8018 */
	KeyDerivationMethod[KeyDerivationMethod["PBKDF2"] = 1] = "PBKDF2";
	/** Scrypt - RFC 7914 */
	KeyDerivationMethod[KeyDerivationMethod["Scrypt"] = 2] = "Scrypt";
	/** Argon2id - RFC 9106 (default, most secure for passwords) */
	KeyDerivationMethod[KeyDerivationMethod["Argon2id"] = 3] = "Argon2id";
	/** SSH Agent - Uses SSH agent for key derivation */
	KeyDerivationMethod[KeyDerivationMethod["SSHAgent"] = 4] = "SSHAgent";
	return KeyDerivationMethod;
}({});
/**
* Returns the default key derivation method (Argon2id).
*/
function defaultKeyDerivationMethod() {
	return 3;
}
/**
* Returns the zero-based index of the key derivation method.
*/
function keyDerivationMethodIndex(method) {
	return method;
}
/**
* Attempts to create a KeyDerivationMethod from a zero-based index.
*/
function keyDerivationMethodFromIndex(index) {
	switch (index) {
		case 0: return 0;
		case 1: return 1;
		case 2: return 2;
		case 3: return 3;
		case 4: return 4;
		default: return;
	}
}
/**
* Convert KeyDerivationMethod to its string representation.
*/
function keyDerivationMethodToString(method) {
	switch (method) {
		case 0: return "HKDF";
		case 1: return "PBKDF2";
		case 2: return "Scrypt";
		case 3: return "Argon2id";
		case 4: return "SSHAgent";
		default: throw new Error(`Unknown KeyDerivationMethod: ${String(method)}`);
	}
}
/**
* Parse KeyDerivationMethod from CBOR.
*/
function keyDerivationMethodFromCbor(cborValue) {
	const value = expectNumber(cborValue);
	const method = keyDerivationMethodFromIndex(Number(value));
	if (method === void 0) throw new Error(`Invalid KeyDerivationMethod index: ${value}`);
	return method;
}
//#endregion
//#region src/encrypted-key/hkdf-params.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* HKDF (HMAC-based Key Derivation Function) parameters
*
* HKDF is a key derivation function based on HMAC, defined in RFC 5869.
* It is NOT suitable for password-based key derivation (use PBKDF2, Scrypt,
* or Argon2id instead).
*
* CDDL:
* ```cddl
* HKDFParams = [0, Salt, HashType]
* ```
*
* Ported from bc-components-rust/src/encrypted_key/hkdf_params.rs
*/
/** Default salt length for key derivation */
const SALT_LEN = 16;
/**
* HKDF parameters for key derivation.
*
* HKDF is suitable for deriving keys from high-entropy inputs (like other keys),
* but NOT for password-based key derivation.
*/
var HKDFParams = class HKDFParams {
	static INDEX = 0;
	_salt;
	_hashType;
	constructor(salt, hashType) {
		this._salt = salt;
		this._hashType = hashType;
	}
	/**
	* Create new HKDF parameters with default settings.
	* Uses a random 16-byte salt and SHA-256.
	*/
	static new() {
		return HKDFParams.newOpt(Salt.newWithLen(16), 0);
	}
	/**
	* Create HKDF parameters with custom settings.
	*/
	static newOpt(salt, hashType) {
		return new HKDFParams(salt, hashType);
	}
	/** Returns the salt. */
	salt() {
		return this._salt;
	}
	/** Returns the hash type. */
	hashType() {
		return this._hashType;
	}
	/** Returns the method index for CBOR encoding. */
	index() {
		return HKDFParams.INDEX;
	}
	/**
	* Derive a key from the secret and encrypt the content key.
	*/
	lock(contentKey, secret) {
		const derivedKeyData = this._deriveKey(secret);
		const derivedKey = SymmetricKey.fromData(derivedKeyData);
		const encodedMethod = this.toCbor().toData();
		return derivedKey.encrypt(contentKey.data(), encodedMethod, Nonce.new());
	}
	/**
	* Derive a key from the secret and decrypt the content key.
	*/
	unlock(encryptedMessage, secret) {
		const derivedKeyData = this._deriveKey(secret);
		const contentKeyData = SymmetricKey.fromData(derivedKeyData).decrypt(encryptedMessage);
		return SymmetricKey.fromData(contentKeyData);
	}
	_deriveKey(secret) {
		switch (this._hashType) {
			case 0: return hkdfHmacSha256(secret, this._salt.asBytes(), 32);
			case 1: return hash_exports.hkdfHmacSha512(secret, this._salt.asBytes(), 32);
			default: throw new Error(`Unknown hash type: ${String(this._hashType)}`);
		}
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `HKDF(${hashTypeToString(this._hashType)})`;
	}
	/**
	* Check equality with another HKDFParams.
	*/
	equals(other) {
		return this._salt.equals(other._salt) && this._hashType === other._hashType;
	}
	/**
	* Convert to CBOR.
	* Format: [0, Salt, HashType]   (Salt is encoded as a tagged value — `#6.40018(bytes)`)
	*/
	toCbor() {
		return cbor$3([
			cbor$3(HKDFParams.INDEX),
			this._salt.taggedCbor(),
			hashTypeToCbor(this._hashType)
		]);
	}
	/**
	* Convert to CBOR binary data.
	*/
	toCborData() {
		return this.toCbor().toData();
	}
	/**
	* Parse from CBOR.
	*/
	static fromCbor(cborValue) {
		const array = expectArray(cborValue);
		if (array.length !== 3) throw new Error(`Invalid HKDFParams: expected 3 elements, got ${array.length}`);
		const index = expectNumber(array[0]);
		if (index !== HKDFParams.INDEX) throw new Error(`Invalid HKDFParams index: expected ${HKDFParams.INDEX}, got ${index}`);
		const salt = Salt.fromTaggedCbor(array[1]);
		const hashType = hashTypeFromCbor(array[2]);
		return new HKDFParams(salt, hashType);
	}
};
//#endregion
//#region src/encrypted-key/pbkdf2-params.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* PBKDF2 (Password-Based Key Derivation Function 2) parameters
*
* PBKDF2 is a key derivation function defined in RFC 8018 (PKCS #5 v2.1).
* It is suitable for password-based key derivation.
*
* CDDL:
* ```cddl
* PBKDF2Params = [1, Salt, iterations: uint, HashType]
* ```
*
* Ported from bc-components-rust/src/encrypted_key/pbkdf2_params.rs
*/
/** Default number of iterations for PBKDF2 */
const DEFAULT_PBKDF2_ITERATIONS = 1e5;
/**
* PBKDF2 parameters for password-based key derivation.
*/
var PBKDF2Params = class PBKDF2Params {
	static INDEX = 1;
	_salt;
	_iterations;
	_hashType;
	constructor(salt, iterations, hashType) {
		this._salt = salt;
		this._iterations = iterations;
		this._hashType = hashType;
	}
	/**
	* Create new PBKDF2 parameters with default settings.
	* Uses a random 16-byte salt, 100,000 iterations, and SHA-256.
	*/
	static new() {
		return PBKDF2Params.newOpt(Salt.newWithLen(16), DEFAULT_PBKDF2_ITERATIONS, 0);
	}
	/**
	* Create PBKDF2 parameters with custom settings.
	*/
	static newOpt(salt, iterations, hashType) {
		return new PBKDF2Params(salt, iterations, hashType);
	}
	/** Returns the salt. */
	salt() {
		return this._salt;
	}
	/** Returns the number of iterations. */
	iterations() {
		return this._iterations;
	}
	/** Returns the hash type. */
	hashType() {
		return this._hashType;
	}
	/** Returns the method index for CBOR encoding. */
	index() {
		return PBKDF2Params.INDEX;
	}
	/**
	* Derive a key from the secret and encrypt the content key.
	*/
	lock(contentKey, secret) {
		const derivedKeyData = this._deriveKey(secret);
		const derivedKey = SymmetricKey.fromData(derivedKeyData);
		const encodedMethod = this.toCbor().toData();
		return derivedKey.encrypt(contentKey.data(), encodedMethod, Nonce.new());
	}
	/**
	* Derive a key from the secret and decrypt the content key.
	*/
	unlock(encryptedMessage, secret) {
		const derivedKeyData = this._deriveKey(secret);
		const contentKeyData = SymmetricKey.fromData(derivedKeyData).decrypt(encryptedMessage);
		return SymmetricKey.fromData(contentKeyData);
	}
	_deriveKey(secret) {
		switch (this._hashType) {
			case 0: return pbkdf2HmacSha256(secret, this._salt.asBytes(), this._iterations, 32);
			case 1: return hash_exports.pbkdf2HmacSha512(secret, this._salt.asBytes(), this._iterations, 32);
			default: throw new Error(`Unknown hash type: ${String(this._hashType)}`);
		}
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `PBKDF2(${hashTypeToString(this._hashType)})`;
	}
	/**
	* Check equality with another PBKDF2Params.
	*/
	equals(other) {
		return this._salt.equals(other._salt) && this._iterations === other._iterations && this._hashType === other._hashType;
	}
	/**
	* Convert to CBOR.
	* Format: [1, Salt, iterations, HashType]   (Salt is encoded as a tagged value — `#6.40018(bytes)`)
	*/
	toCbor() {
		return cbor$3([
			cbor$3(PBKDF2Params.INDEX),
			this._salt.taggedCbor(),
			cbor$3(this._iterations),
			hashTypeToCbor(this._hashType)
		]);
	}
	/**
	* Convert to CBOR binary data.
	*/
	toCborData() {
		return this.toCbor().toData();
	}
	/**
	* Parse from CBOR.
	*/
	static fromCbor(cborValue) {
		const array = expectArray(cborValue);
		if (array.length !== 4) throw new Error(`Invalid PBKDF2Params: expected 4 elements, got ${array.length}`);
		const index = expectNumber(array[0]);
		if (index !== PBKDF2Params.INDEX) throw new Error(`Invalid PBKDF2Params index: expected ${PBKDF2Params.INDEX}, got ${index}`);
		const salt = Salt.fromTaggedCbor(array[1]);
		const iterations = Number(expectNumber(array[2]));
		const hashType = hashTypeFromCbor(array[3]);
		return new PBKDF2Params(salt, iterations, hashType);
	}
};
//#endregion
//#region src/encrypted-key/scrypt-params.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Scrypt parameters for password-based key derivation
*
* Scrypt is a memory-hard key derivation function defined in RFC 7914.
* It is suitable for password-based key derivation and is more resistant
* to hardware brute-force attacks than PBKDF2.
*
* CDDL:
* ```cddl
* ScryptParams = [2, Salt, log_n: uint, r: uint, p: uint]
* ```
*
* Ported from bc-components-rust/src/encrypted_key/scrypt_params.rs
*/
/** Default log_n parameter (2^15 = 32768 iterations) */
const DEFAULT_SCRYPT_LOG_N = 15;
/** Default r parameter (block size) */
const DEFAULT_SCRYPT_R = 8;
/** Default p parameter (parallelism) */
const DEFAULT_SCRYPT_P = 1;
/**
* Scrypt parameters for password-based key derivation.
*
* Parameters:
* - log_n: CPU/memory cost parameter (N = 2^log_n)
* - r: Block size parameter
* - p: Parallelization parameter
*/
var ScryptParams = class ScryptParams {
	static INDEX = 2;
	_salt;
	_logN;
	_r;
	_p;
	constructor(salt, logN, r, p) {
		this._salt = salt;
		this._logN = logN;
		this._r = r;
		this._p = p;
	}
	/**
	* Create new Scrypt parameters with default settings.
	* Uses a random 16-byte salt, log_n=15, r=8, p=1.
	*/
	static new() {
		return ScryptParams.newOpt(Salt.newWithLen(16), 15, 8, 1);
	}
	/**
	* Create Scrypt parameters with custom settings.
	*/
	static newOpt(salt, logN, r, p) {
		return new ScryptParams(salt, logN, r, p);
	}
	/** Returns the salt. */
	salt() {
		return this._salt;
	}
	/** Returns the log_n parameter. */
	logN() {
		return this._logN;
	}
	/** Returns the r parameter (block size). */
	r() {
		return this._r;
	}
	/** Returns the p parameter (parallelism). */
	p() {
		return this._p;
	}
	/** Returns the method index for CBOR encoding. */
	index() {
		return ScryptParams.INDEX;
	}
	/**
	* Derive a key from the secret and encrypt the content key.
	*/
	lock(contentKey, secret) {
		const derivedKeyData = this._deriveKey(secret);
		const derivedKey = SymmetricKey.fromData(derivedKeyData);
		const encodedMethod = this.toCbor().toData();
		return derivedKey.encrypt(contentKey.data(), encodedMethod, Nonce.new());
	}
	/**
	* Derive a key from the secret and decrypt the content key.
	*/
	unlock(encryptedMessage, secret) {
		const derivedKeyData = this._deriveKey(secret);
		const contentKeyData = SymmetricKey.fromData(derivedKeyData).decrypt(encryptedMessage);
		return SymmetricKey.fromData(contentKeyData);
	}
	_deriveKey(secret) {
		return scryptOpt(secret, this._salt.asBytes(), 32, this._logN, this._r, this._p);
	}
	/**
	* Get string representation.
	*/
	toString() {
		return "Scrypt";
	}
	/**
	* Check equality with another ScryptParams.
	*/
	equals(other) {
		return this._salt.equals(other._salt) && this._logN === other._logN && this._r === other._r && this._p === other._p;
	}
	/**
	* Convert to CBOR.
	* Format: [2, Salt, log_n, r, p]   (Salt is encoded as a tagged value — `#6.40018(bytes)`)
	*/
	toCbor() {
		return cbor$3([
			cbor$3(ScryptParams.INDEX),
			this._salt.taggedCbor(),
			cbor$3(this._logN),
			cbor$3(this._r),
			cbor$3(this._p)
		]);
	}
	/**
	* Convert to CBOR binary data.
	*/
	toCborData() {
		return this.toCbor().toData();
	}
	/**
	* Parse from CBOR.
	*/
	static fromCbor(cborValue) {
		const array = expectArray(cborValue);
		if (array.length !== 5) throw new Error(`Invalid ScryptParams: expected 5 elements, got ${array.length}`);
		const index = expectNumber(array[0]);
		if (index !== ScryptParams.INDEX) throw new Error(`Invalid ScryptParams index: expected ${ScryptParams.INDEX}, got ${index}`);
		const salt = Salt.fromTaggedCbor(array[1]);
		const logN = Number(expectNumber(array[2]));
		const r = Number(expectNumber(array[3]));
		const p = Number(expectNumber(array[4]));
		return new ScryptParams(salt, logN, r, p);
	}
};
//#endregion
//#region src/encrypted-key/argon2id-params.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Argon2id parameters for password-based key derivation
*
* Argon2id is a memory-hard key derivation function defined in RFC 9106.
* It combines Argon2i (resistant to side-channel attacks) and Argon2d
* (resistant to GPU cracking attacks). It is the recommended choice for
* password-based key derivation.
*
* CDDL:
* ```cddl
* Argon2idParams = [3, Salt]
* ```
*
* Note: Argon2id uses sensible defaults for memory, iterations, and parallelism.
* Only the salt is configurable in the CBOR encoding for simplicity.
*
* Ported from bc-components-rust/src/encrypted_key/argon2id_params.rs
*/
/**
* Argon2id parameters for password-based key derivation.
*
* This is the recommended method for password-based key derivation as it
* provides the best protection against both GPU cracking and side-channel
* attacks.
*/
var Argon2idParams = class Argon2idParams {
	static INDEX = 3;
	_salt;
	constructor(salt) {
		this._salt = salt;
	}
	/**
	* Create new Argon2id parameters with default settings.
	* Uses a random 16-byte salt.
	*/
	static new() {
		return Argon2idParams.newOpt(Salt.newWithLen(16));
	}
	/**
	* Create Argon2id parameters with a custom salt.
	*/
	static newOpt(salt) {
		return new Argon2idParams(salt);
	}
	/** Returns the salt. */
	salt() {
		return this._salt;
	}
	/** Returns the method index for CBOR encoding. */
	index() {
		return Argon2idParams.INDEX;
	}
	/**
	* Derive a key from the secret and encrypt the content key.
	*/
	lock(contentKey, secret) {
		const derivedKeyData = this._deriveKey(secret);
		const derivedKey = SymmetricKey.fromData(derivedKeyData);
		const encodedMethod = this.toCbor().toData();
		return derivedKey.encrypt(contentKey.data(), encodedMethod, Nonce.new());
	}
	/**
	* Derive a key from the secret and decrypt the content key.
	*/
	unlock(encryptedMessage, secret) {
		const derivedKeyData = this._deriveKey(secret);
		const contentKeyData = SymmetricKey.fromData(derivedKeyData).decrypt(encryptedMessage);
		return SymmetricKey.fromData(contentKeyData);
	}
	_deriveKey(secret) {
		return argon2id$1(secret, this._salt.asBytes(), 32);
	}
	/**
	* Get string representation.
	*/
	toString() {
		return "Argon2id";
	}
	/**
	* Check equality with another Argon2idParams.
	*/
	equals(other) {
		return this._salt.equals(other._salt);
	}
	/**
	* Convert to CBOR.
	* Format: [3, Salt]   (Salt is encoded as a tagged value — `#6.40018(bytes)`)
	*/
	toCbor() {
		return cbor$3([cbor$3(Argon2idParams.INDEX), this._salt.taggedCbor()]);
	}
	/**
	* Convert to CBOR binary data.
	*/
	toCborData() {
		return this.toCbor().toData();
	}
	/**
	* Parse from CBOR.
	*/
	static fromCbor(cborValue) {
		const array = expectArray(cborValue);
		if (array.length !== 2) throw new Error(`Invalid Argon2idParams: expected 2 elements, got ${array.length}`);
		const index = expectNumber(array[0]);
		if (index !== Argon2idParams.INDEX) throw new Error(`Invalid Argon2idParams index: expected ${Argon2idParams.INDEX}, got ${index}`);
		const salt = Salt.fromTaggedCbor(array[1]);
		return new Argon2idParams(salt);
	}
};
/**
* SSH Agent parameters for key derivation.
*
* This method uses an SSH agent daemon to derive encryption keys.
* The agent signs a challenge derived from the salt using the specified
* SSH key identity, and the signature is used to derive the encryption key.
*
* **Note:** SSH agent communication requires platform-specific support and
* may not be available in all JavaScript environments. The lock/unlock
* methods will throw an error if SSH agent support is not available.
*
* **Parity / portability note:** Rust gates SSH-agent support behind the
* `ssh-agent` feature flag and links to OS-native libraries
* (`ssh-agent-client-rs`). The TS port deliberately stubs the lock/unlock
* paths because no portable browser-friendly SSH-agent transport exists.
* The CBOR encoding of `SSHAgentParams` is still byte-identical, so a
* payload produced in Rust can be inspected and parsed in TS — only the
* actual key-derivation operation is unavailable.
*/
var SSHAgentParams = class SSHAgentParams {
	static INDEX = 4;
	_salt;
	_id;
	constructor(salt, id) {
		this._salt = salt;
		this._id = id;
	}
	/**
	* Create new SSH agent parameters with default salt and specified key ID.
	*
	* @param id - The SSH key identity (usually the key comment or public key fingerprint)
	*/
	static new(id) {
		return SSHAgentParams.newOpt(Salt.newWithLen(16), id);
	}
	/**
	* Create SSH agent parameters with custom salt and key ID.
	*
	* @param salt - The salt for key derivation
	* @param id - The SSH key identity
	*/
	static newOpt(salt, id) {
		return new SSHAgentParams(salt, id);
	}
	/** Returns the salt. */
	salt() {
		return this._salt;
	}
	/** Returns the SSH key identity. */
	id() {
		return this._id;
	}
	/** Returns the method index for CBOR encoding. */
	index() {
		return SSHAgentParams.INDEX;
	}
	/**
	* Derive a key using SSH agent and encrypt the content key.
	*
	* **Note:** This method requires SSH agent support which is not yet
	* implemented in this TypeScript port. Use an alternative key derivation
	* method or implement SSH agent communication for your environment.
	*
	* @throws CryptoError - SSH agent support is not available
	*/
	lock(_contentKey, _secret) {
		throw CryptoError.sshAgent("SSH agent key derivation is not yet implemented in this TypeScript port. Use HKDF, PBKDF2, Scrypt, or Argon2id instead.");
	}
	/**
	* Derive a key using SSH agent and decrypt the content key.
	*
	* **Note:** This method requires SSH agent support which is not yet
	* implemented in this TypeScript port. Use an alternative key derivation
	* method or implement SSH agent communication for your environment.
	*
	* @throws CryptoError - SSH agent support is not available
	*/
	unlock(_encryptedMessage, _secret) {
		throw CryptoError.sshAgent("SSH agent key derivation is not yet implemented in this TypeScript port. Use HKDF, PBKDF2, Scrypt, or Argon2id instead.");
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `SSHAgent(id: "${this._id}")`;
	}
	/**
	* Check equality with another SSHAgentParams.
	*/
	equals(other) {
		return this._salt.equals(other._salt) && this._id === other._id;
	}
	/**
	* Convert to CBOR.
	* Format: [4, Salt, id: tstr]   (Salt is encoded as a tagged value — `#6.40018(bytes)`)
	*/
	toCbor() {
		return cbor$3([
			cbor$3(SSHAgentParams.INDEX),
			this._salt.taggedCbor(),
			cbor$3(this._id)
		]);
	}
	/**
	* Convert to CBOR binary data.
	*/
	toCborData() {
		return this.toCbor().toData();
	}
	/**
	* Parse from CBOR.
	*/
	static fromCbor(cborValue) {
		const array = expectArray(cborValue);
		if (array.length !== 3) throw new Error(`Invalid SSHAgentParams: expected 3 elements, got ${array.length}`);
		const index = expectNumber(array[0]);
		if (index !== SSHAgentParams.INDEX) throw new Error(`Invalid SSHAgentParams index: expected ${SSHAgentParams.INDEX}, got ${index}`);
		const salt = Salt.fromTaggedCbor(array[1]);
		const id = expectText(array[2]);
		return new SSHAgentParams(salt, id);
	}
};
//#endregion
//#region src/encrypted-key/key-derivation-params.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Key derivation parameters union type
*
* This type represents the derivation parameters for all supported methods.
* It provides a unified interface for locking and unlocking keys regardless
* of the underlying derivation method.
*
* Ported from bc-components-rust/src/encrypted_key/key_derivation_params.rs
*/
/**
* Create HKDF derivation parameters.
*/
function hkdfParams(params) {
	return {
		type: "hkdf",
		params: params ?? HKDFParams.new()
	};
}
/**
* Create PBKDF2 derivation parameters.
*/
function pbkdf2Params(params) {
	return {
		type: "pbkdf2",
		params: params ?? PBKDF2Params.new()
	};
}
/**
* Create Scrypt derivation parameters.
*/
function scryptParams(params) {
	return {
		type: "scrypt",
		params: params ?? ScryptParams.new()
	};
}
/**
* Create Argon2id derivation parameters.
*/
function argon2idParams(params) {
	return {
		type: "argon2id",
		params: params ?? Argon2idParams.new()
	};
}
/**
* Create SSH agent derivation parameters.
*
* @param idOrParams - Either an SSH key identity string or SSHAgentParams instance
*/
function sshAgentParams(idOrParams) {
	if (typeof idOrParams === "string") return {
		type: "sshagent",
		params: SSHAgentParams.new(idOrParams)
	};
	return {
		type: "sshagent",
		params: idOrParams
	};
}
/**
* Create default key derivation parameters (Argon2id).
*/
function defaultKeyDerivationParams() {
	return argon2idParams();
}
/**
* Get the key derivation method for the given parameters.
*/
function keyDerivationParamsMethod(kdp) {
	switch (kdp.type) {
		case "hkdf": return 0;
		case "pbkdf2": return 1;
		case "scrypt": return 2;
		case "argon2id": return 3;
		case "sshagent": return 4;
	}
}
/**
* Check if the parameters use a password-based method.
* Password-based methods (PBKDF2, Scrypt, Argon2id) are designed for
* low-entropy secrets like passwords.
*/
function isPasswordBased(kdp) {
	return kdp.type === "pbkdf2" || kdp.type === "scrypt" || kdp.type === "argon2id";
}
/**
* Check if the parameters use SSH Agent for key derivation.
*
* Note: SSH Agent key derivation is not yet functional in TypeScript.
* This function is useful for detecting envelopes locked by other
* implementations (e.g., Rust).
*/
function isSshAgent(kdp) {
	return kdp.type === "sshagent";
}
/**
* Lock (encrypt) a content key using the derived key.
*/
function lockWithParams(kdp, contentKey, secret) {
	switch (kdp.type) {
		case "hkdf": return kdp.params.lock(contentKey, secret);
		case "pbkdf2": return kdp.params.lock(contentKey, secret);
		case "scrypt": return kdp.params.lock(contentKey, secret);
		case "argon2id": return kdp.params.lock(contentKey, secret);
		case "sshagent": return kdp.params.lock(contentKey, secret);
	}
}
/**
* Convert KeyDerivationParams to CBOR.
*/
function keyDerivationParamsToCbor(kdp) {
	switch (kdp.type) {
		case "hkdf": return kdp.params.toCbor();
		case "pbkdf2": return kdp.params.toCbor();
		case "scrypt": return kdp.params.toCbor();
		case "argon2id": return kdp.params.toCbor();
		case "sshagent": return kdp.params.toCbor();
	}
}
/**
* Convert KeyDerivationParams to CBOR binary data.
*/
function keyDerivationParamsToCborData(kdp) {
	return keyDerivationParamsToCbor(kdp).toData();
}
/**
* Get string representation of KeyDerivationParams.
*/
function keyDerivationParamsToString(kdp) {
	switch (kdp.type) {
		case "hkdf": return kdp.params.toString();
		case "pbkdf2": return kdp.params.toString();
		case "scrypt": return kdp.params.toString();
		case "argon2id": return kdp.params.toString();
		case "sshagent": return kdp.params.toString();
	}
}
/**
* Parse KeyDerivationParams from CBOR.
*/
function keyDerivationParamsFromCbor(cborValue) {
	const array = expectArray(cborValue);
	if (array.length === 0) throw new Error("Invalid KeyDerivationParams: empty array");
	const index = expectNumber(array[0]);
	const method = keyDerivationMethodFromIndex(Number(index));
	if (method === void 0) throw new Error(`Invalid KeyDerivationMethod index: ${index}`);
	switch (method) {
		case 0: return {
			type: "hkdf",
			params: HKDFParams.fromCbor(cborValue)
		};
		case 1: return {
			type: "pbkdf2",
			params: PBKDF2Params.fromCbor(cborValue)
		};
		case 2: return {
			type: "scrypt",
			params: ScryptParams.fromCbor(cborValue)
		};
		case 3: return {
			type: "argon2id",
			params: Argon2idParams.fromCbor(cborValue)
		};
		case 4: return {
			type: "sshagent",
			params: SSHAgentParams.fromCbor(cborValue)
		};
	}
}
//#endregion
//#region src/encrypted-key/encrypted-key.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* Encrypted key for secure symmetric key storage
*
* `EncryptedKey` provides symmetric encryption and decryption of content keys
* using various key derivation methods (HKDF, PBKDF2, Scrypt, Argon2id).
*
* The form of an `EncryptedKey` is an `EncryptedMessage` that contains the
* encrypted content key, with its Additional Authenticated Data (AAD) being
* the CBOR encoding of the key derivation method and parameters.
*
* CDDL:
* ```cddl
* EncryptedKey = #6.40027(EncryptedMessage)
*
* EncryptedMessage =
*     #6.40002([ ciphertext: bstr, nonce: bstr, auth: bstr, aad: bstr .cbor KeyDerivation ])
*
* KeyDerivation = HKDFParams / PBKDF2Params / ScryptParams / Argon2idParams
* ```
*
* Ported from bc-components-rust/src/encrypted_key/encrypted_key_impl.rs
*/
/**
* Encrypted key providing secure storage of symmetric keys.
*
* Use `lock()` to encrypt a content key with a password or secret,
* and `unlock()` to decrypt it.
*/
var EncryptedKey = class EncryptedKey {
	_params;
	_encryptedMessage;
	constructor(params, encryptedMessage) {
		this._params = params;
		this._encryptedMessage = encryptedMessage;
	}
	/**
	* Lock (encrypt) a content key using custom derivation parameters.
	*
	* @param params - The key derivation parameters to use
	* @param secret - The secret (password or key material) to derive from
	* @param contentKey - The symmetric key to encrypt
	* @returns The encrypted key
	*/
	static lockOpt(params, secret, contentKey) {
		const encryptedMessage = lockWithParams(params, contentKey, secret);
		return new EncryptedKey(params, encryptedMessage);
	}
	/**
	* Lock (encrypt) a content key using a specific derivation method with defaults.
	*
	* @param method - The key derivation method to use
	* @param secret - The secret (password or key material) to derive from
	* @param contentKey - The symmetric key to encrypt
	* @returns The encrypted key
	*/
	static lock(method, secret, contentKey) {
		let params;
		switch (method) {
			case 0:
				params = hkdfParams();
				break;
			case 1:
				params = pbkdf2Params();
				break;
			case 2:
				params = scryptParams();
				break;
			case 3:
				params = argon2idParams();
				break;
			case 4: throw new Error("SSH Agent key derivation cannot be used with lock() - use lockOpt() with sshAgentParams() instead");
		}
		return EncryptedKey.lockOpt(params, secret, contentKey);
	}
	/**
	* Returns the encrypted message.
	*/
	encryptedMessage() {
		return this._encryptedMessage;
	}
	/**
	* Returns the key derivation parameters.
	*/
	params() {
		return this._params;
	}
	/**
	* Returns the key derivation method.
	*/
	method() {
		return keyDerivationParamsMethod(this._params);
	}
	/**
	* Check if this uses a password-based key derivation method.
	*/
	isPasswordBased() {
		return isPasswordBased(this._params);
	}
	/**
	* Check if this uses SSH Agent for key derivation.
	*
	* Note: SSH Agent key derivation is not yet functional in TypeScript.
	* This method is useful for detecting envelopes locked by other
	* implementations (e.g., Rust).
	*/
	isSshAgent() {
		return isSshAgent(this._params);
	}
	/**
	* Unlock (decrypt) the content key.
	*
	* @param secret - The secret (password or key material) used to lock
	* @returns The decrypted symmetric key
	* @throws CryptoError if decryption fails (wrong password, tampered data, etc.)
	*/
	unlock(secret) {
		const aad = this._encryptedMessage.aad();
		if (aad.length === 0) throw CryptoError.invalidData("Missing AAD in EncryptedKey");
		const params = keyDerivationParamsFromCbor(decodeCbor$3(aad));
		switch (params.type) {
			case "hkdf": return params.params.unlock(this._encryptedMessage, secret);
			case "pbkdf2": return params.params.unlock(this._encryptedMessage, secret);
			case "scrypt": return params.params.unlock(this._encryptedMessage, secret);
			case "argon2id": return params.params.unlock(this._encryptedMessage, secret);
			case "sshagent": return params.params.unlock(this._encryptedMessage, secret);
		}
	}
	/**
	* Check equality with another EncryptedKey.
	*/
	equals(other) {
		return this._encryptedMessage.equals(other._encryptedMessage);
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `EncryptedKey(${keyDerivationParamsToString(this._params)})`;
	}
	/**
	* Returns the CBOR tags associated with EncryptedKey.
	*/
	cborTags() {
		return tagsForValues([ENCRYPTED_KEY.value]);
	}
	/**
	* Returns the untagged CBOR encoding.
	* The EncryptedMessage is encoded with its own tag (40002).
	*/
	untaggedCbor() {
		return this._encryptedMessage.taggedCbor();
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates an EncryptedKey by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cborValue) {
		const encryptedMessage = EncryptedMessage.fromTaggedCbor(cborValue);
		const aad = encryptedMessage.aad();
		if (aad.length === 0) throw CryptoError.invalidData("Missing AAD in EncryptedKey");
		const params = keyDerivationParamsFromCbor(decodeCbor$3(aad));
		return new EncryptedKey(params, encryptedMessage);
	}
	/**
	* Creates an EncryptedKey by decoding it from tagged CBOR.
	*/
	fromTaggedCbor(cborValue) {
		validateTag(cborValue, this.cborTags());
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		const dummyParams = hkdfParams();
		const dummyMessage = EncryptedMessage.new(/* @__PURE__ */ new Uint8Array(32), /* @__PURE__ */ new Uint8Array(0), { data: () => /* @__PURE__ */ new Uint8Array(12) }, /* @__PURE__ */ new Uint8Array(16));
		return new EncryptedKey(dummyParams, dummyMessage).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return EncryptedKey.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		const dummyParams = hkdfParams();
		const dummyMessage = EncryptedMessage.new(/* @__PURE__ */ new Uint8Array(32), /* @__PURE__ */ new Uint8Array(0), { data: () => /* @__PURE__ */ new Uint8Array(12) }, /* @__PURE__ */ new Uint8Array(16));
		return new EncryptedKey(dummyParams, dummyMessage).fromUntaggedCbor(cborValue);
	}
	/**
	* Returns the UR representation.
	*/
	ur() {
		const name = ENCRYPTED_KEY.name;
		if (name === void 0) throw new Error("TAG_ENCRYPTED_KEY.name is undefined");
		return UR.new(name, this.untaggedCbor());
	}
	/**
	* Returns the UR string representation.
	*/
	urString() {
		return this.ur().string();
	}
	/**
	* Creates an EncryptedKey from a UR.
	*/
	static fromUR(ur) {
		const name = ENCRYPTED_KEY.name;
		if (name === void 0) throw new Error("TAG_ENCRYPTED_KEY.name is undefined");
		ur.checkType(name);
		return EncryptedKey.fromUntaggedCborData(ur.cbor().toData());
	}
	/**
	* Creates an EncryptedKey from a UR string.
	*/
	static fromURString(urString) {
		const ur = UR.fromURString(urString);
		return EncryptedKey.fromUR(ur);
	}
};
//#endregion
//#region ../bc-sskr-ts/tests/baseline/sskr-baseline.mjs
/**
* Error class for Shamir secret sharing operations.
*/
var ShamirError = class ShamirError extends Error {
	type;
	constructor(type, message) {
		super(message ?? ShamirError.defaultMessage(type));
		this.type = type;
		this.name = "ShamirError";
	}
	static defaultMessage(type) {
		switch (type) {
			case "SecretTooLong": return "secret is too long";
			case "TooManyShares": return "too many shares";
			case "InterpolationFailure": return "interpolation failed";
			case "ChecksumFailure": return "checksum failure";
			case "SecretTooShort": return "secret is too short";
			case "SecretNotEvenLen": return "secret is not of even length";
			case "InvalidThreshold": return "invalid threshold";
			case "SharesUnequalLength": return "shares have unequal length";
		}
	}
};
const fromNumH = (n) => n / 2 ** 32 | 0;
const fromNumL = (n) => n >>> 0;
function setU64FromNum(view, byteOffset, n, isLE) {
	const h = fromNumH(n);
	const l = fromNumL(n);
	view.setUint32(byteOffset, isLE ? l : h, isLE);
	view.setUint32(byteOffset + 4, isLE ? h : l, isLE);
}
/**
* Checks if something is Uint8Array. Be careful: nodejs Buffer will return true.
* @param a - value to test
* @returns `true` when the value is a Uint8Array-compatible view.
* @example
* Check whether a value is a Uint8Array-compatible view.
* ```ts
* isBytes(new Uint8Array([1, 2, 3]));
* ```
*/
function isBytes(a) {
	return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
const atitle = (title) => title ? `"${title}" ` : "";
/**
* Asserts something is a non-negative integer.
* @param n - number to validate
* @param title - label included in thrown errors
* @returns The validated number.
* @throws On wrong argument types. {@link TypeError}
* @throws On wrong argument ranges or values. {@link RangeError}
* @example
* Validate a non-negative integer option.
* ```ts
* anumber(32, 'length');
* ```
*/
function anumber(n, title = "") {
	if (typeof n !== "number") throw new TypeError(atitle(title) + "expected number, got " + typeof n);
	if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
	return n;
}
/**
* Asserts something is Uint8Array.
* @param value - value to validate
* @param length - optional exact length constraint
* @param title - label included in thrown errors
* @returns The validated byte array.
* @throws On wrong argument types. {@link TypeError}
* @throws On wrong argument ranges or values. {@link RangeError}
* @example
* Validate that a value is a byte array.
* ```ts
* abytes(new Uint8Array([1, 2, 3]));
* ```
*/
function abytes(value, length, title = "") {
	if (isBytes(value) && (length === void 0 || value.length === length)) return value;
	if (length !== void 0) anumber(length, "length");
	const bytes = isBytes(value);
	const ofLen = length !== void 0 ? ` of length ${length}` : "";
	const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
	const message = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
	if (!bytes) throw new TypeError(message);
	throw new RangeError(message);
}
/**
* Asserts something is a wrapped hash constructor.
* @param h - hash constructor to validate
* @throws On wrong argument types or invalid hash wrapper shape. {@link TypeError}
* @throws On invalid hash metadata ranges or values. {@link RangeError}
* @throws If the hash metadata allows empty outputs or block sizes. {@link Error}
* @example
* Validate a callable hash wrapper.
* ```ts
* import { ahash } from '@noble/hashes/utils.js';
* import { sha256 } from '@noble/hashes/sha2.js';
* ahash(sha256);
* ```
*/
function ahash(h) {
	if (typeof h !== "function" || typeof h.create !== "function") throw new TypeError("expected hash wrapped by utils.createHasher");
	anumber(h.outputLen);
	anumber(h.blockLen);
	if (h.outputLen < 1 || h.blockLen < 1) throw new Error("hash blockLen / outputLen must be >= 1");
}
const aobject = (value, label) => {
	if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError((label === "object" ? "" : `"${label}" `) + "expected object, got type=" + typeof value);
};
const aopts = (value, label) => {
	aobject(value, label);
	const proto = Object.getPrototypeOf(value);
	if (proto !== Object.prototype && proto !== null) throw new TypeError(`"${label}" expected plain object`);
	if (Object.hasOwn(value, "__proto__")) throw new TypeError(`"${label}.__proto__" is not allowed`);
};
/**
* Asserts a hash instance has not been destroyed or finished.
* @param instance - hash instance to validate
* @param checkFinished - whether to reject finalized instances
* @throws If the hash instance has already been destroyed or finalized. {@link Error}
* @example
* Validate that a hash instance is still usable.
* ```ts
* import { aexists } from '@noble/hashes/utils.js';
* import { sha256 } from '@noble/hashes/sha2.js';
* const hash = sha256.create();
* aexists(hash);
* ```
*/
function aexists(instance, checkFinished = true) {
	if (instance.destroyed) throw new Error("hash was destroyed");
	if (checkFinished && instance.finished) throw new Error("digest() was already called");
}
/**
* Asserts output is a sufficiently-sized byte array.
* @param out - destination buffer
* @param instance - hash instance providing output length
* Oversized buffers are allowed; downstream code only promises to fill the first `outputLen` bytes.
* @throws On wrong argument types. {@link TypeError}
* @throws On wrong argument ranges or values. {@link RangeError}
* @example
* Validate a caller-provided digest buffer.
* ```ts
* import { aoutput } from '@noble/hashes/utils.js';
* import { sha256 } from '@noble/hashes/sha2.js';
* const hash = sha256.create();
* aoutput(new Uint8Array(hash.outputLen), hash);
* ```
*/
function aoutput(out, instance) {
	abytes(out, void 0, "output");
	const min = instance.outputLen;
	if (!(out.length >= min)) throw new RangeError("\"output\" expected length >= " + min);
}
/**
* Zeroizes typed arrays in place. Warning: JS provides no guarantees.
* @param arrays - arrays to overwrite with zeros
* @example
* Zeroize sensitive buffers in place.
* ```ts
* clean(new Uint8Array([1, 2, 3]));
* ```
*/
function clean(...arrays) {
	for (let i = 0; i < arrays.length; i++) arrays[i].fill(0);
}
/**
* Creates a DataView for byte-level manipulation.
* @param arr - source typed array
* @returns DataView over the same buffer region.
* @example
* Create a DataView over an existing buffer.
* ```ts
* createView(new Uint8Array(4));
* ```
*/
function createView(arr) {
	return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
/**
* Rotate-right operation for uint32 values.
* @param word - source word
* @param shift - shift amount in bits
* @returns Rotated word.
* @example
* Rotate a 32-bit word to the right.
* ```ts
* rotr(0x12345678, 8);
* ```
*/
function rotr(word, shift) {
	return word << 32 - shift | word >>> shift;
}
/**
* Merges default options and passed options.
* @param defaults - base option object
* @param opts - user overrides
* @param title - label included in thrown override errors
* @returns Fresh merged option object with a null prototype.
* @throws On wrong argument types. {@link TypeError}
* @example
* Merge user overrides onto default options.
* ```ts
* checkOpts({ dkLen: 32 }, { asyncTick: 10 });
* ```
*/
function checkOpts(defaults, opts, title = "opts") {
	aopts(defaults, "defaults");
	if (opts !== void 0) aopts(opts, title);
	return Object.assign(Object.create(null), defaults, opts);
}
/**
* Creates a callable hash function from a stateful class constructor.
* @param hashCons - hash constructor or factory
* @param info - optional metadata such as DER OID
* @returns Frozen callable hash wrapper with `.create()`.
*   Wrapper construction eagerly calls `hashCons(undefined)` once to read
*   `outputLen` / `blockLen`, so constructor side effects happen at module
*   init time.
* @throws On wrong argument types. {@link TypeError}
* @example
* Wrap a stateful hash constructor into a callable helper.
* ```ts
* import { createHasher } from '@noble/hashes/utils.js';
* import { sha256 } from '@noble/hashes/sha2.js';
* const wrapped = createHasher(sha256.create, { oid: sha256.oid });
* wrapped(new Uint8Array([1]));
* ```
*/
function createHasher(hashCons, info = {}) {
	if (typeof hashCons !== "function") throw new TypeError("\"hashCons\" expected function, got type=" + typeof hashCons);
	info = checkOpts({}, info, "info");
	const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
	const tmp = hashCons(void 0);
	hashC.outputLen = tmp.outputLen;
	hashC.blockLen = tmp.blockLen;
	hashC.canXOF = tmp.canXOF;
	hashC.create = (opts) => hashCons(opts);
	Object.assign(hashC, info);
	return Object.freeze(hashC);
}
/**
* Creates OID metadata for NIST hashes with prefix `06 09 60 86 48 01 65 03 04 02`.
* @param suffix - final OID byte for the selected hash.
*   The helper accepts any byte even though only the documented NIST hash
*   suffixes are meaningful downstream.
* @returns Object containing the DER-encoded OID.
* @example
* Build OID metadata for a NIST hash.
* ```ts
* oidNist(0x01);
* ```
*/
const oidNist = (suffix) => ({ oid: Uint8Array.from([
	6,
	9,
	96,
	134,
	72,
	1,
	101,
	3,
	4,
	2,
	suffix
]) });
/**
* Internal Merkle-Damgard hash utils.
* @module
*/
/**
* Shared 32-bit conditional boolean primitive reused by SHA-256, SHA-1, and MD5 `F`.
* Returns bits from `b` when `a` is set, otherwise from `c`.
* The XOR form is equivalent to MD5's `F(X,Y,Z) = XY v not(X)Z` because the masked terms never
* set the same bit.
* @param a - selector word
* @param b - word chosen when selector bit is set
* @param c - word chosen when selector bit is clear
* @returns Mixed 32-bit word.
* @example
* Combine three words with the shared 32-bit choice primitive.
* ```ts
* Chi(0xffffffff, 0x12345678, 0x87654321);
* ```
*/
function Chi(a, b, c) {
	return a & b ^ ~a & c;
}
/**
* Shared 32-bit majority primitive reused by SHA-256 and SHA-1.
* Returns bits shared by at least two inputs.
* @param a - first input word
* @param b - second input word
* @param c - third input word
* @returns Mixed 32-bit word.
* @example
* Combine three words with the shared 32-bit majority primitive.
* ```ts
* Maj(0xffffffff, 0x12345678, 0x87654321);
* ```
*/
function Maj(a, b, c) {
	return a & b ^ a & c ^ b & c;
}
/**
* Merkle-Damgard hash construction base class.
* Could be used to create MD5, RIPEMD, SHA1, SHA2.
* Accepts only byte-aligned `Uint8Array` input, even when the underlying spec describes bit
* strings with partial-byte tails.
* @param blockLen - internal block size in bytes
* @param outputLen - digest size in bytes
* @param padOffset - trailing length field size in bytes
* @param isLE - whether length and state words are encoded in little-endian
* @example
* Use a concrete subclass to get the shared Merkle-Damgard update/digest flow.
* ```ts
* import { _SHA1 } from '@noble/hashes/legacy.js';
* const hash = new _SHA1();
* hash.update(new Uint8Array([97, 98, 99]));
* hash.digest();
* ```
*/
var HashMD = class {
	blockLen;
	outputLen;
	canXOF = false;
	padOffset;
	isLE;
	buffer;
	view;
	finished = false;
	length = 0;
	pos = 0;
	destroyed = false;
	constructor(blockLen, outputLen, padOffset, isLE) {
		this.blockLen = blockLen;
		this.outputLen = outputLen;
		this.padOffset = padOffset;
		this.isLE = isLE;
		this.buffer = new Uint8Array(blockLen);
		this.view = createView(this.buffer);
	}
	update(data) {
		aexists(this);
		abytes(data);
		const { view, buffer, blockLen } = this;
		const len = data.length;
		let processed = false;
		for (let pos = 0; pos < len;) {
			const take = Math.min(blockLen - this.pos, len - pos);
			if (take === blockLen) {
				const dataView = createView(data);
				for (; blockLen <= len - pos; pos += blockLen) this.process(dataView, pos);
				processed = true;
				continue;
			}
			buffer.set(pos === 0 && take === len ? data : data.subarray(pos, pos + take), this.pos);
			this.pos += take;
			pos += take;
			if (this.pos === blockLen) {
				this.process(view, 0);
				this.pos = 0;
				processed = true;
			}
		}
		this.length += data.length;
		if (processed) this.roundClean();
		return this;
	}
	digestInto(out) {
		aexists(this);
		aoutput(out, this);
		this.finished = true;
		const { buffer, view, blockLen, isLE } = this;
		let { pos } = this;
		buffer[pos++] = 128;
		buffer.fill(0, pos);
		if (this.padOffset > blockLen - pos) {
			this.process(view, 0);
			buffer.fill(0);
		}
		setU64FromNum(view, blockLen - 8, this.length * 8, isLE);
		this.process(view, 0);
		this.roundClean();
		const oview = out === buffer ? view : createView(out);
		const len = this.outputLen;
		const outLen = len / 4;
		const state = this.get();
		if (len % 4 || outLen > state.length) throw new Error("invalid outputLen");
		for (let i = 0; i < outLen; i++) oview.setUint32(4 * i, state[i], isLE);
	}
	digest() {
		const { buffer, outputLen } = this;
		this.digestInto(buffer);
		const res = buffer.slice(0, outputLen);
		this.destroy();
		return res;
	}
	_cloneIntoMeta(to) {
		const { buffer, length, finished, destroyed, pos } = this;
		to.destroyed = destroyed;
		to.finished = finished;
		to.length = length;
		to.pos = pos;
		if (pos) to.buffer.set(buffer);
		return to;
	}
	clone() {
		return this._cloneInto();
	}
};
/**
* Initial SHA-2 state: fractional parts of square roots of first 16 primes 2..53.
* Check out `test/misc/sha2-gen-iv.js` for recomputation guide.
*/
/** Initial SHA256 state from RFC 6234 §6.1: the first 32 bits of the fractional parts of the
* square roots of the first eight prime numbers. Exported as a shared table; callers must treat
* it as read-only because constructors copy words from it by index. */
const SHA256_IV = /* @__PURE__ */ Uint32Array.from([
	1779033703,
	3144134277,
	1013904242,
	2773480762,
	1359893119,
	2600822924,
	528734635,
	1541459225
]);
/**
* SHA2 hash function. A.k.a. sha256, sha384, sha512, sha512_224, sha512_256.
* SHA256 is the fastest hash implementable in JS, even faster than Blake3.
* Check out {@link https://www.rfc-editor.org/rfc/rfc4634 | RFC 4634} and
* {@link https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf | FIPS 180-4}.
* @module
*/
/**
* SHA-224 / SHA-256 round constants from RFC 6234 §5.1: the first 32 bits
* of the cube roots of the first 64 primes (2..311).
*/
const SHA256_K = /* @__PURE__ */ Uint32Array.from([
	1116352408,
	1899447441,
	3049323471,
	3921009573,
	961987163,
	1508970993,
	2453635748,
	2870763221,
	3624381080,
	310598401,
	607225278,
	1426881987,
	1925078388,
	2162078206,
	2614888103,
	3248222580,
	3835390401,
	4022224774,
	264347078,
	604807628,
	770255983,
	1249150122,
	1555081692,
	1996064986,
	2554220882,
	2821834349,
	2952996808,
	3210313671,
	3336571891,
	3584528711,
	113926993,
	338241895,
	666307205,
	773529912,
	1294757372,
	1396182291,
	1695183700,
	1986661051,
	2177026350,
	2456956037,
	2730485921,
	2820302411,
	3259730800,
	3345764771,
	3516065817,
	3600352804,
	4094571909,
	275423344,
	430227734,
	506948616,
	659060556,
	883997877,
	958139571,
	1322822218,
	1537002063,
	1747873779,
	1955562222,
	2024104815,
	2227730452,
	2361852424,
	2428436474,
	2756734187,
	3204031479,
	3329325298
]);
/** Reusable SHA-224 / SHA-256 message schedule buffer `W_t` from RFC 6234 §6.2 step 1. */
const SHA256_W = /* @__PURE__ */ new Uint32Array(64);
/** Internal SHA-224 / SHA-256 compression engine from RFC 6234 §6.2. */
var SHA2_32B = class extends HashMD {
	A = 0;
	B = 0;
	C = 0;
	D = 0;
	E = 0;
	F = 0;
	G = 0;
	H = 0;
	constructor(outputLen, IV) {
		super(64, outputLen, 8, false);
		this.A = IV[0] | 0;
		this.B = IV[1] | 0;
		this.C = IV[2] | 0;
		this.D = IV[3] | 0;
		this.E = IV[4] | 0;
		this.F = IV[5] | 0;
		this.G = IV[6] | 0;
		this.H = IV[7] | 0;
	}
	get() {
		const { A, B, C, D, E, F, G, H } = this;
		return [
			A,
			B,
			C,
			D,
			E,
			F,
			G,
			H
		];
	}
	set(A, B, C, D, E, F, G, H) {
		this.A = A | 0;
		this.B = B | 0;
		this.C = C | 0;
		this.D = D | 0;
		this.E = E | 0;
		this.F = F | 0;
		this.G = G | 0;
		this.H = H | 0;
	}
	_cloneInto(to) {
		(to ||= new this.constructor()).set(...this.get());
		return this._cloneIntoMeta(to);
	}
	process(view, offset) {
		for (let i = 0; i < 16; i++, offset += 4) SHA256_W[i] = view.getUint32(offset, false);
		for (let i = 16; i < 64; i++) {
			const W15 = SHA256_W[i - 15];
			const W2 = SHA256_W[i - 2];
			const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
			const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
			SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
		}
		let { A, B, C, D, E, F, G, H } = this;
		for (let i = 0; i < 64; i++) {
			const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
			const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
			const T2 = (rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22)) + Maj(A, B, C) | 0;
			H = G;
			G = F;
			F = E;
			E = D + T1 | 0;
			D = C;
			C = B;
			B = A;
			A = T1 + T2 | 0;
		}
		A = A + this.A | 0;
		B = B + this.B | 0;
		C = C + this.C | 0;
		D = D + this.D | 0;
		E = E + this.E | 0;
		F = F + this.F | 0;
		G = G + this.G | 0;
		H = H + this.H | 0;
		this.set(A, B, C, D, E, F, G, H);
	}
	roundClean() {
		clean(SHA256_W);
	}
	destroy() {
		this.destroyed = true;
		this.set(0, 0, 0, 0, 0, 0, 0, 0);
		clean(this.buffer);
	}
};
/** Internal SHA-256 hash class grounded in RFC 6234 §6.2. */
var _SHA256 = class extends SHA2_32B {
	constructor() {
		super(32, SHA256_IV);
	}
};
/**
* SHA2-256 hash function from RFC 4634. In JS it's the fastest: even faster than Blake3. Some info:
*
* - Trying 2^128 hashes would get 50% chance of collision, using birthday attack.
* - BTC network is doing 2^70 hashes/sec (2^95 hashes/year) as per 2025.
* - Each sha256 hash is executing 2^18 bit operations.
* - Good 2024 ASICs can do 200Th/sec with 3500 watts of power, corresponding to 2^36 hashes/joule.
* @param msg - message bytes to hash
* @param opts - Reserved hash options.
* @returns Digest bytes.
* @example
* Hash a message with SHA2-256.
* ```ts
* sha256(new Uint8Array([97, 98, 99]));
* ```
*/
const sha256$1 = /* @__PURE__ */ createHasher(() => new _SHA256(), /* @__PURE__ */ oidNist(1));
/**
* HMAC: RFC2104 message authentication code.
* @module
*/
/**
* Internal class for HMAC.
* Accepts any byte key, although RFC 2104 §3 recommends keys at least
* `HashLen` bytes long.
*/
var _HMAC = class {
	oHash;
	iHash;
	blockLen;
	outputLen;
	canXOF = false;
	finished = false;
	destroyed = false;
	constructor(hash, key) {
		ahash(hash);
		abytes(key, void 0, "key");
		this.iHash = hash.create();
		if (typeof this.iHash.update !== "function") throw new Error("expected Hash instance");
		this.blockLen = this.iHash.blockLen;
		this.outputLen = this.iHash.outputLen;
		const blockLen = this.blockLen;
		const pad = new Uint8Array(blockLen);
		pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
		for (let i = 0; i < pad.length; i++) pad[i] ^= 54;
		this.iHash.update(pad);
		this.oHash = hash.create();
		for (let i = 0; i < pad.length; i++) pad[i] ^= 106;
		this.oHash.update(pad);
		clean(pad);
	}
	update(buf) {
		aexists(this);
		this.iHash.update(buf);
		return this;
	}
	digestInto(out) {
		aexists(this);
		aoutput(out, this);
		this.finished = true;
		const buf = out.subarray(0, this.outputLen);
		this.iHash.digestInto(buf);
		this.oHash.update(buf);
		this.oHash.digestInto(buf);
		this.destroy();
	}
	digest() {
		const out = new Uint8Array(this.oHash.outputLen);
		this.digestInto(out);
		return out;
	}
	_cloneInto(to) {
		to ||= Object.create(Object.getPrototypeOf(this), {});
		const { oHash, iHash, finished, destroyed, blockLen, outputLen, canXOF } = this;
		to = to;
		to.finished = finished;
		to.destroyed = destroyed;
		to.blockLen = blockLen;
		to.outputLen = outputLen;
		to.canXOF = canXOF;
		to.oHash = oHash._cloneInto(to.oHash);
		to.iHash = iHash._cloneInto(to.iHash);
		return to;
	}
	clone() {
		return this._cloneInto();
	}
	destroy() {
		this.destroyed = true;
		this.oHash.destroy();
		this.iHash.destroy();
	}
};
const hmac$1 = /* @__PURE__ */ (() => {
	const hmac_ = ((hash, key, message) => new _HMAC(hash, key).update(message).digest());
	hmac_.create = (hash, key) => new _HMAC(hash, key);
	return hmac_;
})();
const CRC32_TABLE = /* @__PURE__ */ new Uint32Array(256);
for (let i = 0; i < 256; i++) {
	let crc = i;
	for (let j = 0; j < 8; j++) crc = (crc & 1) !== 0 ? crc >>> 1 ^ 3988292384 : crc >>> 1;
	CRC32_TABLE[i] = crc >>> 0;
}
/**
* Calculate HMAC-SHA-256
*/
function hmacSha256(key, message) {
	return hmac$1(sha256$1, key, message);
}
/**
* Securely zero out a typed array.
*
* Mirrors Rust `bc_crypto::memzero<T>(s: &mut [T])`. The Rust impl uses
* `std::ptr::write_volatile()` to guarantee the writes survive optimization;
* JavaScript has no equivalent primitive, so this is **best-effort** — JIT
* compilers may still elide the loop, though the post-hoc verification
* check forces the engine to keep the writes observable.
*
* For truly sensitive cryptographic operations, consider using the Web
* Crypto API's `crypto.subtle` with non-extractable keys when possible, as
* it provides stronger guarantees than what can be achieved with pure
* JavaScript.
*
* Accepts any of the standard numeric typed arrays — `Uint8Array`,
* `Uint8ClampedArray`, `Uint16Array`, `Uint32Array`, `Int8Array`,
* `Int16Array`, `Int32Array`, `Float32Array`, `Float64Array` — matching
* Rust's generic `&mut [T]`. (`BigInt64Array` / `BigUint64Array` are
* excluded because their elements are `bigint`, not `number`; if that
* support is needed, add a dedicated overload.)
*/
function memzero(data) {
	const len = data.length;
	for (let i = 0; i < len; i++) data[i] = 0;
	if (data.length > 0 && data[0] !== 0) throw new Error("memzero failed");
}
/**
* Securely zero out an array of Uint8Arrays.
*/
function memzeroVecVecU8(arrays) {
	for (const arr of arrays) memzero(arr);
}
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*/
/**
* Internal contract guard. Mirrors a Rust `assert!(condition, message)`
* panic on the boundary between hazmat helpers — kept as a bare `Error`
* so it cannot be confused with a `ShamirError` from the public API.
*/
function assertContract(condition, message) {
	if (!condition) throw new Error(message);
}
/**
* Convert an array of bytes into a bitsliced representation.
* Takes the first 32 bytes from x and produces 8 u32 values.
*
* @param r - Output array of 8 u32 values (bitsliced representation)
* @param x - Input array of at least 32 bytes
*/
function bitslice(r, x) {
	assertContract(x.length >= 32, "bitslice: input must be at least 32 bytes");
	assertContract(r.length === 8, "bitslice: output must have 8 elements");
	memzero(r);
	for (let arrIdx = 0; arrIdx < 32; arrIdx++) {
		const cur = x[arrIdx];
		for (let bitIdx = 0; bitIdx < 8; bitIdx++) r[bitIdx] |= (cur & 1 << bitIdx) >>> bitIdx << arrIdx;
	}
}
/**
* Convert a bitsliced representation back to bytes.
*
* @param r - Output array of at least 32 bytes
* @param x - Input array of 8 u32 values (bitsliced representation)
*/
function unbitslice(r, x) {
	assertContract(r.length >= 32, "unbitslice: output must be at least 32 bytes");
	assertContract(x.length === 8, "unbitslice: input must have 8 elements");
	memzero(r.subarray(0, 32));
	for (let bitIdx = 0; bitIdx < 8; bitIdx++) {
		const cur = x[bitIdx];
		for (let arrIdx = 0; arrIdx < 32; arrIdx++) r[arrIdx] |= (cur & 1 << arrIdx) >>> arrIdx << bitIdx;
	}
}
/**
* Set all 32 positions in a bitsliced array to the same byte value.
*
* @param r - Output array of 8 u32 values
* @param x - Byte value to set in all positions
*/
function bitsliceSetall(r, x) {
	assertContract(r.length === 8, "bitsliceSetall: output must have 8 elements");
	for (let idx = 0; idx < 8; idx++) {
		const bit = x >>> idx & 1;
		r[idx] = bit === 1 ? 4294967295 : 0;
	}
}
/**
* Add (XOR) r with x and store the result in r.
* In GF(2^8), addition is XOR.
*
* @param r - First operand and result
* @param x - Second operand
*/
function gf256Add(r, x) {
	assertContract(r.length === 8 && x.length === 8, "gf256Add: arrays must have 8 elements");
	for (let i = 0; i < 8; i++) r[i] ^= x[i];
}
/**
* Safely multiply two bitsliced polynomials in GF(2^8) reduced by
* x^8 + x^4 + x^3 + x + 1. r and a may overlap, but overlapping of r
* and b will produce an incorrect result! If you need to square a polynomial
* use gf256Square instead.
*
* @param r - Result array (8 u32 values)
* @param a - First operand (may overlap with r)
* @param b - Second operand (must NOT overlap with r)
*/
function gf256Mul(r, a, b) {
	assertContract(r.length === 8 && a.length === 8 && b.length === 8, "gf256Mul: arrays must have 8 elements");
	const a2 = new Uint32Array(a);
	r[0] = a2[0] & b[0];
	r[1] = a2[1] & b[0];
	r[2] = a2[2] & b[0];
	r[3] = a2[3] & b[0];
	r[4] = a2[4] & b[0];
	r[5] = a2[5] & b[0];
	r[6] = a2[6] & b[0];
	r[7] = a2[7] & b[0];
	a2[0] ^= a2[7];
	a2[2] ^= a2[7];
	a2[3] ^= a2[7];
	r[0] ^= a2[7] & b[1];
	r[1] ^= a2[0] & b[1];
	r[2] ^= a2[1] & b[1];
	r[3] ^= a2[2] & b[1];
	r[4] ^= a2[3] & b[1];
	r[5] ^= a2[4] & b[1];
	r[6] ^= a2[5] & b[1];
	r[7] ^= a2[6] & b[1];
	a2[7] ^= a2[6];
	a2[1] ^= a2[6];
	a2[2] ^= a2[6];
	r[0] ^= a2[6] & b[2];
	r[1] ^= a2[7] & b[2];
	r[2] ^= a2[0] & b[2];
	r[3] ^= a2[1] & b[2];
	r[4] ^= a2[2] & b[2];
	r[5] ^= a2[3] & b[2];
	r[6] ^= a2[4] & b[2];
	r[7] ^= a2[5] & b[2];
	a2[6] ^= a2[5];
	a2[0] ^= a2[5];
	a2[1] ^= a2[5];
	r[0] ^= a2[5] & b[3];
	r[1] ^= a2[6] & b[3];
	r[2] ^= a2[7] & b[3];
	r[3] ^= a2[0] & b[3];
	r[4] ^= a2[1] & b[3];
	r[5] ^= a2[2] & b[3];
	r[6] ^= a2[3] & b[3];
	r[7] ^= a2[4] & b[3];
	a2[5] ^= a2[4];
	a2[7] ^= a2[4];
	a2[0] ^= a2[4];
	r[0] ^= a2[4] & b[4];
	r[1] ^= a2[5] & b[4];
	r[2] ^= a2[6] & b[4];
	r[3] ^= a2[7] & b[4];
	r[4] ^= a2[0] & b[4];
	r[5] ^= a2[1] & b[4];
	r[6] ^= a2[2] & b[4];
	r[7] ^= a2[3] & b[4];
	a2[4] ^= a2[3];
	a2[6] ^= a2[3];
	a2[7] ^= a2[3];
	r[0] ^= a2[3] & b[5];
	r[1] ^= a2[4] & b[5];
	r[2] ^= a2[5] & b[5];
	r[3] ^= a2[6] & b[5];
	r[4] ^= a2[7] & b[5];
	r[5] ^= a2[0] & b[5];
	r[6] ^= a2[1] & b[5];
	r[7] ^= a2[2] & b[5];
	a2[3] ^= a2[2];
	a2[5] ^= a2[2];
	a2[6] ^= a2[2];
	r[0] ^= a2[2] & b[6];
	r[1] ^= a2[3] & b[6];
	r[2] ^= a2[4] & b[6];
	r[3] ^= a2[5] & b[6];
	r[4] ^= a2[6] & b[6];
	r[5] ^= a2[7] & b[6];
	r[6] ^= a2[0] & b[6];
	r[7] ^= a2[1] & b[6];
	a2[2] ^= a2[1];
	a2[4] ^= a2[1];
	a2[5] ^= a2[1];
	r[0] ^= a2[1] & b[7];
	r[1] ^= a2[2] & b[7];
	r[2] ^= a2[3] & b[7];
	r[3] ^= a2[4] & b[7];
	r[4] ^= a2[5] & b[7];
	r[5] ^= a2[6] & b[7];
	r[6] ^= a2[7] & b[7];
	r[7] ^= a2[0] & b[7];
}
/**
* Square x in GF(2^8) and write the result to r.
* r and x may overlap.
*
* @param r - Result array (8 u32 values)
* @param x - Value to square
*/
function gf256Square(r, x) {
	assertContract(r.length === 8 && x.length === 8, "gf256Square: arrays must have 8 elements");
	const r14 = x[7];
	const r12 = x[6];
	let r10 = x[5];
	let r8 = x[4];
	r[6] = x[3];
	r[4] = x[2];
	r[2] = x[1];
	r[0] = x[0];
	r[7] = r14;
	r[6] ^= r14;
	r10 ^= r14;
	r[4] ^= r12;
	r[5] = r12;
	r[7] ^= r12;
	r8 ^= r12;
	r[2] ^= r10;
	r[3] = r10;
	r[5] ^= r10;
	r[6] ^= r10;
	r[1] = r14;
	r[2] ^= r14;
	r[4] ^= r14;
	r[5] ^= r14;
	r[0] ^= r8;
	r[1] ^= r8;
	r[3] ^= r8;
	r[4] ^= r8;
}
/**
* Invert x in GF(2^8) and write the result to r.
*
* @param r - Result array (8 u32 values)
* @param x - Value to invert (will be modified)
*/
function gf256Inv(r, x) {
	assertContract(r.length === 8 && x.length === 8, "gf256Inv: arrays must have 8 elements");
	const y = /* @__PURE__ */ new Uint32Array(8);
	const z = /* @__PURE__ */ new Uint32Array(8);
	gf256Square(y, x);
	gf256Square(y, new Uint32Array(y));
	gf256Square(r, y);
	gf256Mul(z, r, x);
	gf256Square(r, new Uint32Array(r));
	gf256Mul(r, new Uint32Array(r), z);
	gf256Square(r, new Uint32Array(r));
	gf256Square(z, r);
	gf256Square(z, new Uint32Array(z));
	gf256Mul(r, new Uint32Array(r), z);
	gf256Mul(r, new Uint32Array(r), y);
}
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*/
/**
* Calculate the lagrange basis coefficients for the lagrange polynomial
* defined by the x coordinates xc at the value x.
*
* After the function runs, the values array should hold data satisfying:
*                ---     (x-xc[j])
*   values[i] =  | |   -------------
*              j != i  (xc[i]-xc[j])
*
* @param values - Output array for the lagrange basis values
* @param n - Number of points (length of the xc array, 0 < n <= 32)
* @param xc - Array of x components to use as interpolating points
* @param x - x coordinate to evaluate lagrange polynomials at
*/
function hazmatLagrangeBasis(values, n, xc, x) {
	const xx = /* @__PURE__ */ new Uint8Array(48);
	const xSlice = /* @__PURE__ */ new Uint32Array(8);
	const lxi = [];
	for (let i = 0; i < n; i++) lxi.push(/* @__PURE__ */ new Uint32Array(8));
	const numerator = /* @__PURE__ */ new Uint32Array(8);
	const denominator = /* @__PURE__ */ new Uint32Array(8);
	const temp = /* @__PURE__ */ new Uint32Array(8);
	xx.set(xc.subarray(0, n), 0);
	for (let i = 0; i < n; i++) {
		bitslice(lxi[i], xx.subarray(i));
		xx[i + n] = xx[i];
	}
	bitsliceSetall(xSlice, x);
	bitsliceSetall(numerator, 1);
	bitsliceSetall(denominator, 1);
	for (let i = 1; i < n; i++) {
		temp.set(xSlice);
		gf256Add(temp, lxi[i]);
		gf256Mul(numerator, new Uint32Array(numerator), temp);
		temp.set(lxi[0]);
		gf256Add(temp, lxi[i]);
		gf256Mul(denominator, new Uint32Array(denominator), temp);
	}
	gf256Inv(temp, denominator);
	gf256Mul(numerator, new Uint32Array(numerator), temp);
	unbitslice(xx, numerator);
	values.set(xx.subarray(0, n), 0);
}
/**
* Safely interpolate the polynomial going through
* the points (x0 [y0_0 y0_1 y0_2 ... y0_31]) , (x1 [y1_0 ...]), ...
*
* where
*   xi points to [x0 x1 ... xn-1 ]
*   y contains an array of pointers to 32-bit arrays of y values
*   y contains [y0 y1 y2 ... yn-1]
*   and each of the yi arrays contain [yi_0 yi_i ... yi_31].
*
* @param n - Number of points to interpolate
* @param xi - x coordinates for points (array of length n)
* @param yl - Length of y coordinate arrays
* @param yij - Array of n arrays of length yl
* @param x - Coordinate to interpolate at
* @returns The interpolated result of length yl
*/
function interpolate(n, xi, yl, yij, x) {
	const y = [];
	for (let i = 0; i < n; i++) y.push(/* @__PURE__ */ new Uint8Array(32));
	const values = /* @__PURE__ */ new Uint8Array(32);
	for (let i = 0; i < n; i++) y[i].set(yij[i].subarray(0, yl), 0);
	const lagrange = new Uint8Array(n);
	const ySlice = /* @__PURE__ */ new Uint32Array(8);
	const resultSlice = /* @__PURE__ */ new Uint32Array(8);
	const temp = /* @__PURE__ */ new Uint32Array(8);
	hazmatLagrangeBasis(lagrange, n, xi, x);
	bitsliceSetall(resultSlice, 0);
	for (let i = 0; i < n; i++) {
		bitslice(ySlice, y[i]);
		bitsliceSetall(temp, lagrange[i]);
		gf256Mul(temp, new Uint32Array(temp), ySlice);
		gf256Add(resultSlice, temp);
	}
	unbitslice(values, resultSlice);
	const result = new Uint8Array(yl);
	result.set(values.subarray(0, yl), 0);
	memzero(lagrange);
	memzero(ySlice);
	memzero(resultSlice);
	memzero(temp);
	memzeroVecVecU8(y);
	memzero(values);
	return result;
}
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*/
const SECRET_INDEX = 255;
const DIGEST_INDEX = 254;
function createDigest(randomData, sharedSecret) {
	return hmacSha256(randomData, sharedSecret);
}
function validateParameters(threshold, shareCount, secretLength) {
	if (shareCount > 16) throw new ShamirError("TooManyShares");
	else if (threshold < 1 || threshold > shareCount) throw new ShamirError("InvalidThreshold");
	else if (secretLength > 32) throw new ShamirError("SecretTooLong");
	else if (secretLength < 16) throw new ShamirError("SecretTooShort");
	else if ((secretLength & 1) !== 0) throw new ShamirError("SecretNotEvenLen");
}
/**
* Splits a secret into shares using the Shamir secret sharing algorithm.
*
* @param threshold - The minimum number of shares required to reconstruct the
*   secret. Must be greater than or equal to 1 and less than or equal to
*   shareCount.
* @param shareCount - The total number of shares to generate. Must be at least
*   threshold and less than or equal to MAX_SHARE_COUNT.
* @param secret - A Uint8Array containing the secret to be split. Must be at
*   least MIN_SECRET_LEN bytes long and at most MAX_SECRET_LEN bytes long.
*   The length must be an even number.
* @param randomGenerator - An implementation of the RandomNumberGenerator
*   interface, used to generate random data.
* @returns An array of Uint8Array representing the shares of the secret.
* @throws ShamirError if parameters are invalid
*
* @example
* ```typescript
* import { splitSecret } from "@blockchaincommons/shamir";
* import { SecureRandomNumberGenerator } from "@blockchaincommons/rand";
*
* const threshold = 2;
* const shareCount = 3;
* const secret = new TextEncoder().encode("my secret belongs to me.");
* const rng = new SecureRandomNumberGenerator();
*
* const shares = splitSecret(threshold, shareCount, secret, rng);
* console.log(shares.length); // 3
* ```
*/
function splitSecret(threshold, shareCount, secret, randomGenerator) {
	validateParameters(threshold, shareCount, secret.length);
	if (threshold === 1) {
		const result = [];
		for (let i = 0; i < shareCount; i++) result.push(new Uint8Array(secret));
		return result;
	} else {
		const x = new Uint8Array(shareCount);
		const y = [];
		for (let i = 0; i < shareCount; i++) y.push(new Uint8Array(secret.length));
		let n = 0;
		const result = [];
		for (let i = 0; i < shareCount; i++) result.push(new Uint8Array(secret.length));
		for (let index = 0; index < threshold - 2; index++) {
			randomGenerator.fillRandomData(result[index]);
			x[n] = index;
			y[n].set(result[index]);
			n++;
		}
		const digest = new Uint8Array(secret.length);
		randomGenerator.fillRandomData(digest.subarray(4));
		const d = createDigest(digest.subarray(4), secret);
		digest.set(d.subarray(0, 4), 0);
		x[n] = DIGEST_INDEX;
		y[n].set(digest);
		n++;
		x[n] = SECRET_INDEX;
		y[n].set(secret);
		n++;
		for (let index = threshold - 2; index < shareCount; index++) {
			const v = interpolate(n, x, secret.length, y, index);
			result[index].set(v);
		}
		memzero(digest);
		memzero(x);
		memzeroVecVecU8(y);
		return result;
	}
}
/**
* Recovers the secret from the given shares using the Shamir secret sharing
* algorithm.
*
* @param indexes - An array of indexes of the shares to be used for recovering
*   the secret. These are the indexes of the shares returned by splitSecret.
* @param shares - An array of shares of the secret matching the indexes in
*   indexes. These are the shares returned by splitSecret.
* @returns A Uint8Array representing the recovered secret.
* @throws ShamirError if parameters are invalid or checksum verification fails
*
* @example
* ```typescript
* import { recoverSecret } from "@blockchaincommons/shamir";
*
* const indexes = [0, 2];
* const shares = [
*   new Uint8Array([47, 165, 102, 232, ...]),
*   new Uint8Array([221, 174, 116, 201, ...]),
* ];
*
* const secret = recoverSecret(indexes, shares);
* console.log(new TextDecoder().decode(secret)); // "my secret belongs to me."
* ```
*/
function recoverSecret(indexes, shares) {
	const threshold = shares.length;
	if (threshold === 0 || indexes.length !== threshold) throw new ShamirError("InvalidThreshold");
	const shareLength = shares[0].length;
	validateParameters(threshold, threshold, shareLength);
	if (!shares.every((share) => share.length === shareLength)) throw new ShamirError("SharesUnequalLength");
	if (threshold === 1) return new Uint8Array(shares[0]);
	else {
		const indexesU8 = new Uint8Array(indexes);
		const digest = interpolate(threshold, indexesU8, shareLength, shares, DIGEST_INDEX);
		const secret = interpolate(threshold, indexesU8, shareLength, shares, SECRET_INDEX);
		const verify = createDigest(digest.subarray(4), secret);
		let valid = true;
		for (let i = 0; i < 4; i++) valid = valid && digest[i] === verify[i];
		memzero(digest);
		memzero(verify);
		if (!valid) throw new ShamirError("ChecksumFailure");
		return secret;
	}
}
/**
* Error class for SSKR operations.
*/
var SSKRError = class SSKRError extends Error {
	type;
	shamirError;
	constructor(type, message, shamirError) {
		super(message ?? SSKRError.defaultMessage(type, shamirError));
		this.type = type;
		this.shamirError = shamirError;
		this.name = "SSKRError";
	}
	static defaultMessage(type, shamirError) {
		switch (type) {
			case "DuplicateMemberIndex": return "When combining shares, the provided shares contained a duplicate member index";
			case "GroupSpecInvalid": return "Invalid group specification.";
			case "GroupCountInvalid": return "When creating a split spec, the group count is invalid";
			case "GroupThresholdInvalid": return "SSKR group threshold is invalid";
			case "MemberCountInvalid": return "SSKR member count is invalid";
			case "MemberThresholdInvalid": return "SSKR member threshold is invalid";
			case "NotEnoughGroups": return "SSKR shares did not contain enough groups";
			case "SecretLengthNotEven": return "SSKR secret is not of even length";
			case "SecretTooLong": return "SSKR secret is too long";
			case "SecretTooShort": return "SSKR secret is too short";
			case "ShareLengthInvalid": return "SSKR shares did not contain enough serialized bytes";
			case "ShareReservedBitsInvalid": return "SSKR shares contained invalid reserved bits";
			case "SharesEmpty": return "SSKR shares were empty";
			case "ShareSetInvalid": return "SSKR shares were invalid";
			case "ShamirError": return shamirError != null ? `SSKR Shamir error: ${shamirError.message}` : "SSKR Shamir error";
		}
	}
	static fromShamirError(error) {
		return new SSKRError("ShamirError", void 0, error);
	}
};
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*/
/**
* A secret to be split into shares.
*/
var Secret = class Secret {
	data;
	constructor(data) {
		this.data = data;
	}
	/**
	* Creates a new Secret instance with the given data.
	*
	* @param data - The secret data to be split into shares.
	* @returns A new Secret instance.
	* @throws SSKRError if the length of the secret is less than
	*   MIN_SECRET_LEN, greater than MAX_SECRET_LEN, or not even.
	*/
	static new(data) {
		const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
		const len = bytes.length;
		if (len < 16) throw new SSKRError("SecretTooShort");
		if (len > 32) throw new SSKRError("SecretTooLong");
		if ((len & 1) !== 0) throw new SSKRError("SecretLengthNotEven");
		return new Secret(new Uint8Array(bytes));
	}
	/**
	* Returns the length of the secret.
	*/
	len() {
		return this.data.length;
	}
	/**
	* Returns true if the secret is empty.
	*/
	isEmpty() {
		return this.len() === 0;
	}
	/**
	* Returns a reference to the secret data.
	*
	* Mirrors Rust's `Secret::data(&self) -> &[u8]`
	* (`bc-sskr-rust/src/secret.rs:43`).
	*/
	getData() {
		return this.data;
	}
	/**
	* Returns the secret data as a Uint8Array.
	*
	* Mirrors Rust's `impl AsRef<[u8]> for Secret`
	* (`bc-sskr-rust/src/secret.rs:46-49`). In Rust, `as_ref()` is
	* provided via the `AsRef<[u8]>` trait, which lets the `Secret` flow
	* naturally through any API expecting `impl AsRef<[u8]>`. TypeScript
	* has no equivalent of that trait, so we expose the same backing
	* buffer through both {@link getData} (the field accessor) and
	* `asRef` (the trait-style accessor) for ergonomic parity. Callers
	* may pick whichever name reads better at the call site.
	*/
	asRef() {
		return this.data;
	}
	/**
	* Check equality with another Secret.
	*/
	equals(other) {
		if (this.data.length !== other.data.length) return false;
		for (let i = 0; i < this.data.length; i++) if (this.data[i] !== other.data[i]) return false;
		return true;
	}
	/**
	* Clone the secret.
	*/
	clone() {
		return new Secret(new Uint8Array(this.data));
	}
};
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*/
/**
* Strictly parses a non-negative integer string the way Rust's
* `<usize as FromStr>::from_str` does (`bc-sskr-rust/src/spec.rs:102, 108`).
*
* Accepts an optional leading `+` followed by one or more decimal digits.
* Rejects whitespace, decimals (`"2.5"`), trailing characters (`"2x"`),
* the `-` sign, and the empty string. Returns `undefined` on rejection so
* callers surface the appropriate `GroupSpecInvalid` error in the same
* spot Rust's `?` would.
*/
const STRICT_USIZE_RE = /^\+?\d+$/;
function parseStrictUsize(s) {
	if (!STRICT_USIZE_RE.test(s)) return void 0;
	const n = Number(s);
	return Number.isSafeInteger(n) ? n : void 0;
}
/**
* A specification for a group of shares within an SSKR split.
*/
var GroupSpec = class GroupSpec {
	_memberThreshold;
	_memberCount;
	constructor(memberThreshold, memberCount) {
		this._memberThreshold = memberThreshold;
		this._memberCount = memberCount;
	}
	/**
	* Creates a new GroupSpec instance with the given member threshold and count.
	*
	* @param memberThreshold - The minimum number of member shares required to
	*   reconstruct the secret within the group.
	* @param memberCount - The total number of member shares in the group.
	* @returns A new GroupSpec instance.
	* @throws SSKRError if the member count is zero, if the member count is
	*   greater than the maximum share count, or if the member threshold is
	*   greater than the member count.
	*/
	static new(memberThreshold, memberCount) {
		if (memberCount === 0) throw new SSKRError("MemberCountInvalid");
		if (memberCount > 16) throw new SSKRError("MemberCountInvalid");
		if (memberThreshold > memberCount) throw new SSKRError("MemberThresholdInvalid");
		return new GroupSpec(memberThreshold, memberCount);
	}
	/**
	* Returns the member share threshold for this group.
	*/
	memberThreshold() {
		return this._memberThreshold;
	}
	/**
	* Returns the number of member shares in this group.
	*/
	memberCount() {
		return this._memberCount;
	}
	/**
	* Parses a group specification from a string.
	* Format: `"M-of-N"` where `M` is the threshold and `N` is the count.
	*
	* Mirrors Rust's `GroupSpec::parse` (`bc-sskr-rust/src/spec.rs:97-112`),
	* which calls `parts[0].parse::<usize>()`. Rust's `usize::FromStr` is
	* strict: it rejects whitespace, decimals, trailing characters, and the
	* `-` sign, accepting only an optional `+` prefix followed by digits.
	* We mirror that with the regex `^\+?\d+$` so strings like `"2.5"`,
	* `"2x"`, `" 2"`, `"-2"`, and `""` all surface
	* {@link SSKRErrorType.GroupSpecInvalid} on both sides.
	*/
	static parse(s) {
		const parts = s.split("-");
		if (parts.length !== 3) throw new SSKRError("GroupSpecInvalid");
		const memberThreshold = parseStrictUsize(parts[0]);
		if (memberThreshold === void 0) throw new SSKRError("GroupSpecInvalid");
		if (parts[1] !== "of") throw new SSKRError("GroupSpecInvalid");
		const memberCount = parseStrictUsize(parts[2]);
		if (memberCount === void 0) throw new SSKRError("GroupSpecInvalid");
		return GroupSpec.new(memberThreshold, memberCount);
	}
	/**
	* Creates a default GroupSpec (1-of-1).
	*/
	static default() {
		return GroupSpec.new(1, 1);
	}
	/**
	* Returns a string representation of the group spec.
	*/
	toString() {
		return `${this._memberThreshold}-of-${this._memberCount}`;
	}
};
/**
* A specification for an SSKR split.
*/
var Spec = class Spec {
	_groupThreshold;
	_groups;
	constructor(groupThreshold, groups) {
		this._groupThreshold = groupThreshold;
		this._groups = groups;
	}
	/**
	* Creates a new Spec instance with the given group threshold and groups.
	*
	* @param groupThreshold - The minimum number of groups required to
	*   reconstruct the secret.
	* @param groups - The list of GroupSpec instances that define the groups
	*   and their members.
	* @returns A new Spec instance.
	* @throws SSKRError if the group threshold is zero, if the group threshold
	*   is greater than the number of groups, or if the number of groups is
	*   greater than the maximum share count.
	*/
	static new(groupThreshold, groups) {
		if (groupThreshold === 0) throw new SSKRError("GroupThresholdInvalid");
		if (groupThreshold > groups.length) throw new SSKRError("GroupThresholdInvalid");
		if (groups.length > 16) throw new SSKRError("GroupCountInvalid");
		return new Spec(groupThreshold, groups);
	}
	/**
	* Returns the group threshold.
	*/
	groupThreshold() {
		return this._groupThreshold;
	}
	/**
	* Returns a slice of the group specifications.
	*/
	groups() {
		return this._groups;
	}
	/**
	* Returns the number of groups.
	*/
	groupCount() {
		return this._groups.length;
	}
	/**
	* Returns the total number of shares across all groups.
	*/
	shareCount() {
		return this._groups.reduce((sum, g) => sum + g.memberCount(), 0);
	}
};
/**
* Returns the Web Crypto API for the current environment. Available natively
* in browsers and in Node.js >= 15 via `globalThis.crypto`.
*/
function getCrypto() {
	if (typeof globalThis !== "undefined" && globalThis.crypto != null) return globalThis.crypto;
	throw new Error("No crypto API available in this environment");
}
/**
* Generate a Uint8Array of cryptographically strong random bytes of the given size.
*/
function randomData(size) {
	const data = new Uint8Array(size);
	fillRandomData(data);
	return data;
}
/**
* Fill the given Uint8Array with cryptographically strong random bytes.
*/
function fillRandomData(data) {
	getCrypto().getRandomValues(data);
}
/**
* Returns the next cryptographically strong random 64-bit unsigned integer.
*
* This mirrors Rust's module-private `secure_random::next_u64()` and is not
* re-exported from the package surface (matches Rust `lib.rs` behavior).
*/
function nextU64() {
	const data = /* @__PURE__ */ new Uint8Array(8);
	fillRandomData(data);
	return new DataView(data.buffer).getBigUint64(0, true);
}
/**
* A random number generator that can be used as a source of
* cryptographically-strong randomness.
*
* Uses the Web Crypto API (crypto.getRandomValues) which is available
* in both browsers and Node.js >= 15.
*/
var SecureRandomNumberGenerator = class {
	/**
	* Returns the next random 32-bit unsigned integer.
	*
	* Mirrors Rust's `next_u32` impl which returns `next_u64() as u32` —
	* the low 32 bits of a 64-bit draw.
	*/
	nextU32() {
		return Number(this.nextU64() & 4294967295n) >>> 0;
	}
	/**
	* Returns the next random 64-bit unsigned integer as a bigint.
	*/
	nextU64() {
		return nextU64();
	}
	/**
	* Fills the given Uint8Array with random bytes.
	*/
	fillBytes(dest) {
		fillRandomData(dest);
	}
	/**
	* Returns a Uint8Array of random bytes of the given size.
	*/
	randomData(size) {
		return randomData(size);
	}
	/**
	* Fills the given Uint8Array with random bytes.
	*/
	fillRandomData(data) {
		fillRandomData(data);
	}
};
/**
* A share in the SSKR scheme.
*/
var SSKRShare$1 = class {
	_identifier;
	_groupIndex;
	_groupThreshold;
	_groupCount;
	_memberIndex;
	_memberThreshold;
	_value;
	constructor(identifier, groupIndex, groupThreshold, groupCount, memberIndex, memberThreshold, value) {
		this._identifier = identifier;
		this._groupIndex = groupIndex;
		this._groupThreshold = groupThreshold;
		this._groupCount = groupCount;
		this._memberIndex = memberIndex;
		this._memberThreshold = memberThreshold;
		this._value = value;
	}
	identifier() {
		return this._identifier;
	}
	groupIndex() {
		return this._groupIndex;
	}
	groupThreshold() {
		return this._groupThreshold;
	}
	groupCount() {
		return this._groupCount;
	}
	memberIndex() {
		return this._memberIndex;
	}
	memberThreshold() {
		return this._memberThreshold;
	}
	value() {
		return this._value;
	}
};
/**
* Generates SSKR shares for the given Spec and Secret.
*
* @param spec - The Spec instance that defines the group and member thresholds.
* @param masterSecret - The Secret instance to be split into shares.
* @returns A vector of groups, each containing a vector of shares,
*   each of which is a Uint8Array.
*/
function sskrGenerate(spec, masterSecret) {
	return sskrGenerateUsing(spec, masterSecret, new SecureRandomNumberGenerator());
}
/**
* Generates SSKR shares for the given Spec and Secret using the provided
* random number generator.
*
* @param spec - The Spec instance that defines the group and member thresholds.
* @param masterSecret - The Secret instance to be split into shares.
* @param randomGenerator - The random number generator to use for generating
*   shares.
* @returns A vector of groups, each containing a vector of shares,
*   each of which is a Uint8Array.
*/
function sskrGenerateUsing(spec, masterSecret, randomGenerator) {
	return generateShares(spec, masterSecret, randomGenerator).map((group) => group.map(serializeShare));
}
/**
* Combines the given SSKR shares into a Secret.
*
* @param shares - A array of SSKR shares to be combined.
* @returns The reconstructed Secret.
* @throws SSKRError if the shares do not meet the necessary quorum of groups
*   and member shares within each group.
*/
function sskrCombine(shares) {
	const sskrShares = [];
	for (const share of shares) {
		const sskrShare = deserializeShare(share);
		sskrShares.push(sskrShare);
	}
	return combineShares(sskrShares);
}
function serializeShare(share) {
	const valueData = share.value().getData();
	const result = new Uint8Array(valueData.length + 5);
	const id = share.identifier();
	const gt = share.groupThreshold() - 1 & 15;
	const gc = share.groupCount() - 1 & 15;
	const gi = share.groupIndex() & 15;
	const mt = share.memberThreshold() - 1 & 15;
	const mi = share.memberIndex() & 15;
	const id1 = id >> 8;
	const id2 = id & 255;
	result[0] = id1;
	result[1] = id2;
	result[2] = gt << 4 | gc;
	result[3] = gi << 4 | mt;
	result[4] = mi;
	result.set(valueData, 5);
	return result;
}
function deserializeShare(source) {
	if (source.length < 5) throw new SSKRError("ShareLengthInvalid");
	const groupThreshold = (source[2] >> 4) + 1;
	const groupCount = (source[2] & 15) + 1;
	if (groupThreshold > groupCount) throw new SSKRError("GroupThresholdInvalid");
	const identifier = source[0] << 8 | source[1];
	const groupIndex = source[3] >> 4;
	const memberThreshold = (source[3] & 15) + 1;
	if (source[4] >> 4 !== 0) throw new SSKRError("ShareReservedBitsInvalid");
	return new SSKRShare$1(identifier, groupIndex, groupThreshold, groupCount, source[4] & 15, memberThreshold, Secret.new(source.subarray(5)));
}
function generateShares(spec, masterSecret, randomGenerator) {
	const identifierBytes = /* @__PURE__ */ new Uint8Array(2);
	randomGenerator.fillRandomData(identifierBytes);
	const identifier = identifierBytes[0] << 8 | identifierBytes[1];
	const groupsShares = [];
	let groupSecrets;
	try {
		groupSecrets = splitSecret(spec.groupThreshold(), spec.groupCount(), masterSecret.getData(), randomGenerator);
	} catch (e) {
		if (e instanceof ShamirError) throw SSKRError.fromShamirError(e);
		throw e;
	}
	for (let groupIndex = 0; groupIndex < spec.groups().length; groupIndex++) {
		const group = spec.groups()[groupIndex];
		const groupSecret = groupSecrets[groupIndex];
		let memberSecrets;
		try {
			memberSecrets = splitSecret(group.memberThreshold(), group.memberCount(), groupSecret, randomGenerator);
		} catch (e) {
			if (e instanceof ShamirError) throw SSKRError.fromShamirError(e);
			throw e;
		}
		const memberSSKRShares = memberSecrets.map((memberSecret, memberIndex) => {
			const secret = Secret.new(memberSecret);
			return new SSKRShare$1(identifier, groupIndex, spec.groupThreshold(), spec.groupCount(), memberIndex, group.memberThreshold(), secret);
		});
		groupsShares.push(memberSSKRShares);
	}
	return groupsShares;
}
function combineShares(shares) {
	let identifier = 0;
	let groupThreshold = 0;
	let groupCount = 0;
	if (shares.length === 0) throw new SSKRError("SharesEmpty");
	let nextGroup = 0;
	const groups = [];
	let secretLen = 0;
	for (let i = 0; i < shares.length; i++) {
		const share = shares[i];
		if (i === 0) {
			identifier = share.identifier();
			groupCount = share.groupCount();
			groupThreshold = share.groupThreshold();
			secretLen = share.value().len();
		} else if (share.identifier() !== identifier || share.groupThreshold() !== groupThreshold || share.groupCount() !== groupCount || share.value().len() !== secretLen) throw new SSKRError("ShareSetInvalid");
		let groupFound = false;
		for (const group of groups) if (share.groupIndex() === group.groupIndex) {
			groupFound = true;
			if (share.memberThreshold() !== group.memberThreshold) throw new SSKRError("MemberThresholdInvalid");
			for (const memberIndex of group.memberIndexes) if (share.memberIndex() === memberIndex) throw new SSKRError("DuplicateMemberIndex");
			if (group.memberIndexes.length < group.memberThreshold) {
				group.memberIndexes.push(share.memberIndex());
				group.memberShares.push(share.value().clone());
			}
		}
		if (!groupFound) {
			const g = {
				groupIndex: share.groupIndex(),
				memberThreshold: share.memberThreshold(),
				memberIndexes: [share.memberIndex()],
				memberShares: [share.value().clone()]
			};
			groups.push(g);
			nextGroup++;
		}
	}
	if (nextGroup < groupThreshold) throw new SSKRError("NotEnoughGroups");
	const masterIndexes = [];
	const masterShares = [];
	for (const group of groups) {
		if (group.memberIndexes.length < group.memberThreshold) continue;
		try {
			const memberSharesData = group.memberShares.map((s) => s.getData());
			const groupSecret = recoverSecret(group.memberIndexes, memberSharesData);
			masterIndexes.push(group.groupIndex);
			masterShares.push(groupSecret);
		} catch (e) {
			if (e instanceof ShamirError) continue;
			throw e;
		}
		if (masterIndexes.length === groupThreshold) break;
	}
	if (masterIndexes.length < groupThreshold) throw new SSKRError("NotEnoughGroups");
	let masterSecretData;
	try {
		masterSecretData = recoverSecret(masterIndexes, masterShares);
	} catch (e) {
		if (e instanceof ShamirError) throw SSKRError.fromShamirError(e);
		throw e;
	}
	return Secret.new(masterSecretData);
}
//#endregion
//#region src/sskr.ts
/**
* Copyright © 2023-2026 Blockchain Commons, LLC
* Copyright © 2025-2026 Parity Technologies
*
*
* SSKR Integration - CBOR wrappers for SSKR shares
*
* This module provides CBOR serialization for SSKR (Sharded Secret Key
* Reconstruction) shares. It wraps the core SSKR functionality from
* @blockchaincommons/sskr with CBOR tags.
*
* # CBOR Serialization
*
* SSKRShare is serialized with tag 40309:
* ```
* #6.40309(h'<share-bytes>')
* ```
*
* Legacy tag 309 is also supported for reading.
*
* Ported from bc-components-rust/src/sskr_mod.rs
*/
/** Metadata size in bytes (identifier + thresholds + indices) */
const METADATA_SIZE_BYTES = 5;
/**
* SSKRShareCbor - CBOR/UR wrapper for an SSKR share.
*
* An SSKR share is a binary encoding of:
* - Identifier (2 bytes)
* - Group metadata (1 byte): group_threshold-1 (4 bits) + group_count-1 (4 bits)
* - Member metadata (1 byte): group_index (4 bits) + member_threshold-1 (4 bits)
* - Member index (1 byte): reserved (4 bits, must be 0) + member_index (4 bits)
* - Share value (variable length)
*/
var SSKRShareCbor = class SSKRShareCbor {
	_data;
	constructor(data) {
		if (data.length < METADATA_SIZE_BYTES) throw new Error(`SSKRShare must be at least ${METADATA_SIZE_BYTES} bytes, got ${data.length}`);
		this._data = new Uint8Array(data);
	}
	/**
	* Create an SSKRShareCbor from raw share bytes.
	*
	* @param data - The share bytes (5+ bytes)
	*/
	static fromData(data) {
		return new SSKRShareCbor(data);
	}
	/**
	* Create an SSKRShareCbor from a hex string.
	*
	* @param hex - The share as a hex string
	*/
	static fromHex(hex) {
		return new SSKRShareCbor(hexToBytes(hex));
	}
	/**
	* Returns the raw share bytes.
	*/
	asBytes() {
		return this._data;
	}
	/**
	* Returns a copy of the raw share bytes.
	*/
	data() {
		return new Uint8Array(this._data);
	}
	/**
	* Returns the share as a hex string.
	*/
	hex() {
		return bytesToHex(this._data);
	}
	/**
	* Returns the identifier (2 bytes) as a number.
	*/
	identifier() {
		return this._data[0] << 8 | this._data[1];
	}
	/**
	* Returns the identifier as a hex string.
	*/
	identifierHex() {
		return bytesToHex(this._data.subarray(0, 2));
	}
	/**
	* Returns the group threshold (minimum number of groups needed).
	*/
	groupThreshold() {
		return (this._data[2] >> 4) + 1;
	}
	/**
	* Returns the total number of groups.
	*/
	groupCount() {
		return (this._data[2] & 15) + 1;
	}
	/**
	* Returns this share's group index (0-based).
	*/
	groupIndex() {
		return this._data[3] >> 4;
	}
	/**
	* Returns the member threshold for this share's group.
	*/
	memberThreshold() {
		return (this._data[3] & 15) + 1;
	}
	/**
	* Returns this share's member index within its group (0-based).
	*/
	memberIndex() {
		return this._data[4] & 15;
	}
	/**
	* Returns the share value (the actual secret share data).
	*/
	shareValue() {
		return this._data.subarray(METADATA_SIZE_BYTES);
	}
	/**
	* Compare with another SSKRShareCbor.
	*/
	equals(other) {
		if (this._data.length !== other._data.length) return false;
		for (let i = 0; i < this._data.length; i++) if (this._data[i] !== other._data[i]) return false;
		return true;
	}
	/**
	* Get string representation.
	*/
	toString() {
		return `SSKRShare(${this.identifierHex()}, group ${this.groupIndex() + 1}/${this.groupCount()}, member ${this.memberIndex() + 1}/${this.memberThreshold()})`;
	}
	/**
	* Returns the CBOR tags associated with SSKRShare.
	* Includes both current tag (40309) and legacy tag (309) for compatibility.
	*/
	cborTags() {
		return tagsForValues([SSKR_SHARE.value, SSKR_SHARE_V1.value]);
	}
	/**
	* Returns the untagged CBOR encoding.
	*/
	untaggedCbor() {
		return toByteString(this._data);
	}
	/**
	* Returns the tagged CBOR encoding.
	*/
	taggedCbor() {
		return createTaggedCbor(this);
	}
	/**
	* Returns the tagged value in CBOR binary representation.
	*/
	taggedCborData() {
		return this.taggedCbor().toData();
	}
	/**
	* Creates an SSKRShareCbor by decoding it from untagged CBOR.
	*/
	fromUntaggedCbor(cborValue) {
		const data = expectBytes(cborValue);
		return SSKRShareCbor.fromData(data);
	}
	/**
	* Creates an SSKRShareCbor by decoding it from tagged CBOR.
	* Accepts both tag 40309 and legacy tag 309.
	*/
	fromTaggedCbor(cborValue) {
		const tag = tagValue(cborValue);
		if (tag !== SSKR_SHARE.value && tag !== SSKR_SHARE_V1.value) throw new Error(`Invalid SSKRShare tag: expected ${SSKR_SHARE.value} or ${SSKR_SHARE_V1.value}, got ${tag}`);
		const content = extractTaggedContent(cborValue);
		return this.fromUntaggedCbor(content);
	}
	/**
	* Static method to decode from tagged CBOR.
	*/
	static fromTaggedCbor(cborValue) {
		return new SSKRShareCbor(/* @__PURE__ */ new Uint8Array(21)).fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from tagged CBOR binary data.
	*/
	static fromTaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return SSKRShareCbor.fromTaggedCbor(cborValue);
	}
	/**
	* Static method to decode from untagged CBOR binary data.
	*/
	static fromUntaggedCborData(data) {
		const cborValue = decodeCbor$3(data);
		return new SSKRShareCbor(/* @__PURE__ */ new Uint8Array(21)).fromUntaggedCbor(cborValue);
	}
};
/**
* Create an SSKRShare from raw data.
* This is a convenience function that matches the Rust constructor pattern.
*/
const SSKRShare = {
	fromData: (data) => SSKRShareCbor.fromData(data),
	fromHex: (hex) => SSKRShareCbor.fromHex(hex),
	fromTaggedCbor: (cborValue) => SSKRShareCbor.fromTaggedCbor(cborValue),
	fromTaggedCborData: (data) => SSKRShareCbor.fromTaggedCborData(data),
	fromUntaggedCborData: (data) => SSKRShareCbor.fromUntaggedCborData(data)
};
/**
* Generates SSKR shares for the given spec and secret.
*
* This function matches the Rust `sskr_generate` API by returning wrapped
* SSKRShare objects instead of raw byte arrays.
*
* @param spec - The SSKRSpec instance defining group/member thresholds
* @param masterSecret - The SSKRSecret to be split into shares
* @returns Nested array of SSKRShare instances (groups × members)
*
* @example
* ```typescript
* import { SSKRSecret, SSKRSpec, SSKRGroupSpec, sskrGenerateShares } from '@blockchaincommons/components';
*
* const secret = SSKRSecret.new(new Uint8Array(16).fill(0x42));
* const group = SSKRGroupSpec.new(2, 3); // 2 of 3
* const spec = SSKRSpec.new(1, [group]); // 1 group required
*
* const shares = sskrGenerateShares(spec, secret);
* // shares[0] contains 3 SSKRShare instances
* ```
*/
function sskrGenerateShares(spec, masterSecret) {
	return sskrGenerate(spec, masterSecret).map((group) => group.map((shareData) => SSKRShareCbor.fromData(shareData)));
}
/**
* Generates SSKR shares using a custom random number generator.
*
* This function matches the Rust `sskr_generate_using` API by returning
* wrapped SSKRShare objects and allowing a custom RNG for deterministic
* testing.
*
* @param spec - The SSKRSpec instance defining group/member thresholds
* @param masterSecret - The SSKRSecret to be split into shares
* @param rng - Random number generator (must have fillRandomData method)
* @returns Nested array of SSKRShare instances (groups × members)
*/
function sskrGenerateSharesUsing(spec, masterSecret, rng) {
	return sskrGenerateUsing(spec, masterSecret, rng).map((group) => group.map((shareData) => SSKRShareCbor.fromData(shareData)));
}
/**
* Combines SSKR shares to reconstruct the original secret.
*
* This function matches the Rust `sskr_combine` API by accepting
* wrapped SSKRShare objects.
*
* @param shares - Array of SSKRShare instances to combine
* @returns The reconstructed SSKRSecret
* @throws Error if shares cannot be combined (insufficient shares, mismatched IDs, etc.)
*
* @example
* ```typescript
* import { sskrGenerateShares, sskrCombineShares } from '@blockchaincommons/components';
*
* // Generate shares
* const shares = sskrGenerateShares(spec, secret);
*
* // Combine 2 shares from the first group
* const recoveredSecret = sskrCombineShares([shares[0][0], shares[0][1]]);
* ```
*/
function sskrCombineShares(shares) {
	return sskrCombine(shares.map((share) => share.data()));
}
//#endregion
//#region src/ssh/ssh-certificate.ts
/**
* Copyright © 2025-2026 Parity Technologies
*
* SSH certificate (`cert-v01@openssh.com`) placeholder — parity with
* Rust's `bc-components-rust/src/tags_registry.rs:231-238`, which
* registers a fixed `"SSHCertificate"` summarizer for
* `TAG_SSH_TEXT_CERTIFICATE` (40803) with a `// todo: validation`
* comment. The Rust side does *not* parse certificate fields either —
* it only round-trips the text.
*
* This class therefore stores the OpenSSH certificate text verbatim
* and defers real `cert-v01@openssh.com` parsing to v2 (`SSH_PLAN.md`
* V2.D), only contingent on Rust gaining a real parser upstream.
*/
var SSHCertificate = class SSHCertificate {
	/** The full single-line OpenSSH cert text, e.g.
	*  `ssh-ed25519-cert-v01@openssh.com AAAAI...== user@host`. */
	text;
	constructor(text) {
		this.text = text;
	}
	/** Construct from the canonical OpenSSH certificate text. */
	static fromText(text) {
		const trimmed = text.trim();
		if (trimmed.length === 0) throw new Error("SSHCertificate: empty input");
		return new SSHCertificate(trimmed);
	}
	/** The canonical OpenSSH text — round-trips byte-identically. */
	toText() {
		return this.text;
	}
	/** Fixed summarizer string — matches Rust `tags_registry.rs:236`. */
	toString() {
		return "SSHCertificate";
	}
	digest() {
		return sha256(new TextEncoder().encode(this.text));
	}
};
//#endregion
export { ARID, Argon2idParams, AuthenticationTag, COMPRESSED, Compressed, CryptoError, DEFAULT_PBKDF2_ITERATIONS, DEFAULT_SCRYPT_LOG_N, DEFAULT_SCRYPT_P, DEFAULT_SCRYPT_R, Digest, ECPrivateKey, ECPublicKey, ECUncompressedPublicKey, ENCRYPTED, ENVELOPE, Ed25519PrivateKey, Ed25519PublicKey, EncapsulationCiphertext, EncapsulationPrivateKey, EncapsulationPublicKey, EncapsulationScheme, EncryptedKey, EncryptedMessage, ErrorKind, HKDFParams, HKDFRng, HashType, JSON, KNOWN_VALUE, KeyDerivationMethod, LEAF, MLDSALevel, MLDSAPrivateKey, MLDSAPublicKey, MLDSASignature, MLDSA_KEY_SIZES, MLKEMCiphertext, MLKEMLevel, MLKEMPrivateKey, MLKEMPublicKey, MLKEM_KEY_SIZES, Nonce, PBKDF2Params, PrivateKeyBase, PrivateKeys, PublicKeys, Reference, SALT_LEN, SR25519_DEFAULT_CONTEXT, SR25519_PRIVATE_KEY_SIZE, SR25519_PUBLIC_KEY_SIZE, SR25519_SIGNATURE_SIZE, SSHAgentParams, SSHCertificate, SSHPrivateKey, SSHPublicKey, SSHSignature, SSH_ALGO_ECDSA_NISTP256, SSH_ALGO_ED25519, SSH_CURVE_NISTP256, GroupSpec as SSKRGroupSpec, Secret as SSKRSecret, SSKRShare, SSKRShareCbor, Spec as SSKRSpec, Salt, SchnorrPublicKey, ScryptParams, SealedMessage, Seed, Signature, SignatureScheme, SigningPrivateKey, SigningPublicKey, Sr25519PrivateKey, Sr25519PublicKey, SymmetricKey, URI, UUID, X25519PrivateKey, X25519PublicKey, XID, XID_PREFIX, argon2idParams, bytesEqual, bytesToHex, createEncapsulationKeypair, createEncapsulationKeypairUsing, createKeypair, createKeypairUsing, defaultEncapsulationScheme, defaultKeyDerivationMethod, defaultKeyDerivationParams, defaultSignatureScheme, digestFromBytes, fromBase64, hashTypeFromCbor, hashTypeToCbor, hashTypeToString, hexToBytes, hkdfParams, isCryptoError, isCryptoErrorKind, isDecrypter, isECKey, isECKeyBase, isECPublicKeyBase, isEncrypter, isError, isMldsaScheme, isPasswordBased, isPrivateKeyDataProvider, isReferenceProvider, isSshAgent, isSshScheme, isXIDProvider, keyDerivationMethodFromCbor, keyDerivationMethodFromIndex, keyDerivationMethodIndex, keyDerivationMethodToString, keyDerivationParamsFromCbor, keyDerivationParamsMethod, keyDerivationParamsToCbor, keyDerivationParamsToCborData, keyDerivationParamsToString, keypair, keypairOpt, keypairOptUsing, keypairUsing, lockWithParams, mldsaGenerateKeypair, mldsaGenerateKeypairUsing, mldsaLevelFromValue, mldsaLevelToString, mldsaPrivateKeySize, mldsaPublicKeySize, mldsaSign, mldsaSignatureSize, mldsaVerify, mlkemCiphertextSize, mlkemDecapsulate, mlkemEncapsulate, mlkemGenerateKeypair, mlkemGenerateKeypairUsing, mlkemLevelFromValue, mlkemLevelToString, mlkemPrivateKeySize, mlkemPublicKeySize, mlkemSharedSecretSize, parseSshAlgorithm, pbkdf2Params, scryptParams, sshAgentParams, sshAlgorithmName, sskrCombine, sskrCombineShares, sskrGenerate, sskrGenerateShares, sskrGenerateSharesUsing, sskrGenerateUsing, toBase64 };
