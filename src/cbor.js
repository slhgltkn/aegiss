'use strict';

const { encode: cborEncode, decode: cborDecode } = require('cbor-x');
const { MAX_PAYLOAD_BYTES } = require('./constants.js');

/**
 * Encode object to CBOR using cbor-x for maximum speed.
 * @param {Record<string, unknown>} obj
 * @returns {Buffer}
 */
function encode(obj) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error('Invalid payload');
  }
  const out = cborEncode(obj);
  if (out.length > MAX_PAYLOAD_BYTES) {
    throw new Error('Payload too large');
  }
  return out;
}

/**
 * Decode CBOR buffer to object using cbor-x. Enforces size limits.
 * @param {Buffer|Uint8Array} buf
 * @returns {Record<string, unknown>}
 */
function decode(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  if (b.length === 0 || b.length > MAX_PAYLOAD_BYTES) {
    throw new Error('Invalid payload');
  }
  try {
    const result = cborDecode(b);
    if (result === null || typeof result !== 'object') {
      throw new Error('Invalid payload');
    }
    return result;
  } catch (e) {
    throw new Error('Invalid payload');
  }
}

module.exports = { encode, decode };
