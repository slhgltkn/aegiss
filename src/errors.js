'use strict';

/**
 * Thrown when token verification fails. Message is intentionally generic
 * to avoid leaking information (signature vs expired vs fingerprint).
 */
class VerificationError extends Error {
  constructor() {
    super('Invalid token');
    this.name = 'VerificationError';
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, VerificationError);
    }
  }
}

module.exports = { VerificationError };
