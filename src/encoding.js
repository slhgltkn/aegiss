'use strict';

const { BASE64URL_REGEX, MAX_TOKEN_LENGTH } = require('./constants.js');

/**
 * Encode buffer to Base64url (no padding).
 * @param {Buffer|Uint8Array} buf
 * @returns {string}
 */
function toBase64Url(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Decode Base64url string. Rejects invalid length or characters to prevent injection/DoS.
 * @param {string} str
 * @param {number} [maxLength=MAX_TOKEN_LENGTH]
 * @returns {Buffer}
 */
function fromBase64Url(str, maxLength = MAX_TOKEN_LENGTH) {
  if (typeof str !== 'string' || str.length === 0 || str.length > maxLength) {
    throw new Error('Invalid encoding');
  }
  if (!BASE64URL_REGEX.test(str)) {
    throw new Error('Invalid encoding');
  }
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = (4 - (base64.length % 4)) % 4;
  const decoded = Buffer.from(base64 + '='.repeat(pad), 'base64');
  if (decoded.length > maxLength) {
    throw new Error('Invalid encoding');
  }
  return decoded;
}

module.exports = { toBase64Url, fromBase64Url };
