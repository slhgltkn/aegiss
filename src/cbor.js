'use strict';

const {
  MAX_PAYLOAD_BYTES,
  MAX_MAP_ENTRIES,
  MAX_STRING_LENGTH,
} = require('./constants.js');

const MT_UNSIGNED = 0;
const MT_NEGATIVE = 1;
const MT_BYTE_STRING = 2;
const MT_TEXT_STRING = 3;
const MT_MAP = 5;

function encodeUint(value) {
  if (value < 24) return Buffer.from([value]);
  if (value <= 0xff) return Buffer.from([24, value]);
  if (value <= 0xffff) {
    const b = Buffer.alloc(3);
    b[0] = 25;
    b.writeUInt16BE(value, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = 26;
  b.writeUInt32BE(value, 1);
  return b;
}

function encodeLength(major, length) {
  const prefix = major << 5;
  if (length < 24) return Buffer.from([prefix | length]);
  if (length <= 0xff) return Buffer.from([prefix | 24, length]);
  if (length <= 0xffff) {
    const b = Buffer.alloc(3);
    b[0] = prefix | 25;
    b.writeUInt16BE(length, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = prefix | 26;
  b.writeUInt32BE(length, 1);
  return b;
}

/**
 * Encode object to CBOR (map, uint, negint, tstr, bstr only). Deterministic key order.
 * @param {Record<string, number|string|Buffer>} obj
 * @returns {Buffer}
 */
function encode(obj) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error('Invalid payload');
  }
  const keys = Object.keys(obj).sort();
  if (keys.length > MAX_MAP_ENTRIES) {
    throw new Error('Payload too large');
  }
  const chunks = [encodeLength(MT_MAP, keys.length)];
  for (const k of keys) {
    if (Buffer.byteLength(k, 'utf8') > MAX_STRING_LENGTH) {
      throw new Error('Payload too large');
    }
    const v = obj[k];
    chunks.push(encodeLength(MT_TEXT_STRING, Buffer.byteLength(k)));
    chunks.push(Buffer.from(k, 'utf8'));
    if (typeof v === 'number') {
      if (Number.isSafeInteger(v)) {
        if (v >= 0) {
          chunks.push(encodeUint(v));
        } else {
          const negVal = -1 - v;
          if (negVal < 24) chunks.push(Buffer.from([0x20 | negVal]));
          else if (negVal <= 0xff) chunks.push(Buffer.from([0x38, negVal]));
          else chunks.push(Buffer.from([0x39]), Buffer.from(encodeUint(negVal).slice(1)));
        }
      } else {
        const s = String(v);
        chunks.push(encodeLength(MT_TEXT_STRING, Buffer.byteLength(s)));
        chunks.push(Buffer.from(s, 'utf8'));
      }
    } else if (typeof v === 'string') {
      if (Buffer.byteLength(v, 'utf8') > MAX_STRING_LENGTH) {
        throw new Error('Payload too large');
      }
      chunks.push(encodeLength(MT_TEXT_STRING, Buffer.byteLength(v)));
      chunks.push(Buffer.from(v, 'utf8'));
    } else if (Buffer.isBuffer(v)) {
      if (v.length > MAX_STRING_LENGTH) throw new Error('Payload too large');
      chunks.push(encodeLength(MT_BYTE_STRING, v.length));
      chunks.push(v);
    } else {
      const s = String(v);
      if (Buffer.byteLength(s, 'utf8') > MAX_STRING_LENGTH) {
        throw new Error('Payload too large');
      }
      chunks.push(encodeLength(MT_TEXT_STRING, Buffer.byteLength(s)));
      chunks.push(Buffer.from(s, 'utf8'));
    }
  }
  const out = Buffer.concat(chunks);
  if (out.length > MAX_PAYLOAD_BYTES) {
    throw new Error('Payload too large');
  }
  return out;
}

function readUint(buf, offset) {
  if (offset >= buf.length) throw new Error('Invalid payload');
  const ai = buf[offset] & 0x1f;
  if (ai < 24) return { value: ai, bytes: 1 };
  if (ai === 24) {
    if (offset + 2 > buf.length) throw new Error('Invalid payload');
    return { value: buf[offset + 1], bytes: 2 };
  }
  if (ai === 25) {
    if (offset + 3 > buf.length) throw new Error('Invalid payload');
    return { value: buf.readUInt16BE(offset + 1), bytes: 3 };
  }
  if (ai === 26) {
    if (offset + 5 > buf.length) throw new Error('Invalid payload');
    return { value: buf.readUInt32BE(offset + 1), bytes: 5 };
  }
  throw new Error('Invalid payload');
}

function decodeOne(buf, offset, depth) {
  if (depth > 8) throw new Error('Invalid payload');
  if (offset >= buf.length) throw new Error('Invalid payload');
  const initial = buf[offset];
  const major = initial >> 5;
  let ai = initial & 0x1f;
  let len;
  let headerBytes = 1;
  if (ai < 24) {
    len = ai;
  } else {
    const r = readUint(buf, offset);
    len = r.value;
    headerBytes = r.bytes;
  }
  const start = offset + headerBytes;
  if (major === MT_UNSIGNED) return { value: len, bytes: headerBytes };
  if (major === MT_NEGATIVE) return { value: -1 - len, bytes: headerBytes };
  if (major === MT_MAP) {
    if (len > MAX_MAP_ENTRIES) throw new Error('Invalid payload');
    const out = {};
    let pos = start;
    for (let i = 0; i < len; i++) {
      const keyRes = decodeOne(buf, pos, depth + 1);
      pos += keyRes.bytes;
      const key =
        typeof keyRes.value === 'string'
          ? keyRes.value
          : Buffer.isBuffer(keyRes.value)
            ? keyRes.value.toString('utf8')
            : String(keyRes.value);
      if (key.length > MAX_STRING_LENGTH) throw new Error('Invalid payload');
      const valRes = decodeOne(buf, pos, depth + 1);
      pos += valRes.bytes;
      out[key] = valRes.value;
    }
    return { value: out, bytes: pos - offset };
  }
  if (major === MT_BYTE_STRING) {
    if (len > MAX_STRING_LENGTH || start + len > buf.length) {
      throw new Error('Invalid payload');
    }
    return { value: buf.subarray(start, start + len), bytes: headerBytes + len };
  }
  if (major === MT_TEXT_STRING) {
    if (len > MAX_STRING_LENGTH || start + len > buf.length) {
      throw new Error('Invalid payload');
    }
    return {
      value: buf.subarray(start, start + len).toString('utf8'),
      bytes: headerBytes + len,
    };
  }
  throw new Error('Invalid payload');
}

/**
 * Decode CBOR buffer to object. Enforces size limits.
 * @param {Buffer|Uint8Array} buf
 * @returns {Record<string, number|string|Buffer>}
 */
function decode(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  if (b.length === 0 || b.length > MAX_PAYLOAD_BYTES) {
    throw new Error('Invalid payload');
  }
  const result = decodeOne(b, 0, 0);
  return result.value;
}

module.exports = { encode, decode };
