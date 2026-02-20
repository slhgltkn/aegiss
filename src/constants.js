'use strict';

/** Protocol version prefix for tokens */
const PROTOCOL_VERSION = 'v1';

/** Supported token types */
const TOKEN_TYPES = Object.freeze(['public', 'local']);

/** ChaCha20-Poly1305 key length (bytes) */
const CHACHA_KEY_LENGTH = 32;

/** ChaCha20-Poly1305 nonce/IV length (bytes) */
const CHACHA_IV_LENGTH = 12;

/** ChaCha20-Poly1305 auth tag length (bytes) */
const AUTH_TAG_LENGTH = 16;

/** SHA-256 fingerprint length in hex characters */
const FINGERPRINT_HEX_LENGTH = 64;

/** Max token string length to prevent DoS */
const MAX_TOKEN_LENGTH = 4096;

/** Max CBOR payload size (bytes) */
const MAX_PAYLOAD_BYTES = 8192;

/** Max CBOR map entries */
const MAX_MAP_ENTRIES = 64;

/** Max CBOR text/byte string length */
const MAX_STRING_LENGTH = 1024;

/** Default token TTL (seconds) */
const DEFAULT_EXPIRES_IN_SECONDS = 3600;

/** Block duration after failed verification (ms) */
const BLOCK_DURATION_MS = 15 * 60 * 1000;

/** Number of failed verification attempts before blocking the IP */
const MAX_FAILED_ATTEMPTS_BEFORE_BLOCK = 10;

/** Base64url character set for validation */
const BASE64URL_REGEX = /^[A-Za-z0-9_-]*$/;

module.exports = {
  PROTOCOL_VERSION,
  TOKEN_TYPES,
  CHACHA_KEY_LENGTH,
  CHACHA_IV_LENGTH,
  AUTH_TAG_LENGTH,
  FINGERPRINT_HEX_LENGTH,
  MAX_TOKEN_LENGTH,
  MAX_PAYLOAD_BYTES,
  MAX_MAP_ENTRIES,
  MAX_STRING_LENGTH,
  DEFAULT_EXPIRES_IN_SECONDS,
  BLOCK_DURATION_MS,
  MAX_FAILED_ATTEMPTS_BEFORE_BLOCK,
  BASE64URL_REGEX,
};
