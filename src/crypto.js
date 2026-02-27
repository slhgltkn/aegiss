'use strict';

const crypto = require('crypto');
const { toBase64Url, fromBase64Url } = require('./encoding.js');
const {
  CHACHA_KEY_LENGTH,
  CHACHA_IV_LENGTH,
  AUTH_TAG_LENGTH,
  FINGERPRINT_HEX_LENGTH,
} = require('./constants.js');

const ED25519_SIGNATURE_LENGTH = 64;

/**
 * Generate Ed25519 key pair.
 * @returns {{ publicKey: string, privateKey: string }} Base64url-encoded keys
 */
function generateKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return {
    publicKey: toBase64Url(publicKey),
    privateKey: toBase64Url(privateKey),
  };
}

/**
 * Encrypt with ChaCha20-Poly1305. Key must be 32 bytes.
 * @param {Buffer|Uint8Array} plaintext
 * @param {Buffer|Uint8Array} key
 * @returns {string} iv.ciphertext.authTag (base64url each, dot-separated)
 */
function encrypt(plaintext, key) {
  const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key);
  if (keyBuf.length !== CHACHA_KEY_LENGTH) {
    throw new Error('Invalid key length');
  }
  const iv = crypto.randomBytes(CHACHA_IV_LENGTH);
  const cipher = crypto.createCipheriv('chacha20-poly1305', keyBuf, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return [toBase64Url(iv), toBase64Url(encrypted), toBase64Url(authTag)].join('.');
}

/**
 * Decrypt ChaCha20-Poly1305 payload.
 * @param {string} packed iv.ciphertext.authTag (base64url)
 * @param {Buffer|Uint8Array} key
 * @returns {Buffer}
 */
function decrypt(packed, key) {
  const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key);
  if (keyBuf.length !== CHACHA_KEY_LENGTH) {
    throw new Error('Invalid key length');
  }
  if (typeof packed !== 'string') {
    throw new Error('Invalid input');
  }
  const parts = packed.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid input');
  }
  const [iv, ciphertext, authTag] = parts.map((p) => fromBase64Url(p, 1024));
  const decipher = crypto.createDecipheriv('chacha20-poly1305', keyBuf, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

const privateKeyCache = new Map();
const publicKeyCache = new Map();

function getPrivateKey(keyStrOrObj) {
  if (crypto.KeyObject && keyStrOrObj instanceof crypto.KeyObject) return keyStrOrObj;
  if (privateKeyCache.has(keyStrOrObj)) return privateKeyCache.get(keyStrOrObj);
  const keyBuf = fromBase64Url(keyStrOrObj, 256);
  const key = crypto.createPrivateKey({
    key: keyBuf,
    format: 'der',
    type: 'pkcs8',
  });
  privateKeyCache.set(keyStrOrObj, key);
  return key;
}

function getPublicKey(keyStrOrObj) {
  if (crypto.KeyObject && keyStrOrObj instanceof crypto.KeyObject) return keyStrOrObj;
  if (publicKeyCache.has(keyStrOrObj)) return publicKeyCache.get(keyStrOrObj);
  const keyBuf = fromBase64Url(keyStrOrObj, 256);
  const key = crypto.createPublicKey({
    key: keyBuf,
    format: 'der',
    type: 'spki',
  });
  publicKeyCache.set(keyStrOrObj, key);
  return key;
}

/**
 * Sign data with Ed25519 private key.
 * @param {Buffer|Uint8Array} data
 * @param {string|crypto.KeyObject} privateKeyInput Base64url signature or KeyObject
 * @returns {string} Base64url signature
 */
function sign(data, privateKeyInput) {
  const key = getPrivateKey(privateKeyInput);
  const dataBuf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const sig = crypto.sign(null, dataBuf, key);
  return toBase64Url(sig);
}

/**
 * Verify Ed25519 signature. Uses constant-time comparison internally by Node crypto.verify.
 * @param {Buffer|Uint8Array} data
 * @param {string} signatureBase64Url
 * @param {string|crypto.KeyObject} publicKeyInput Base64url signature or KeyObject
 * @returns {boolean}
 */
function verifySignature(data, signatureBase64Url, publicKeyInput) {
  const sigBuf = fromBase64Url(signatureBase64Url, 256);
  if (sigBuf.length !== ED25519_SIGNATURE_LENGTH) {
    return false;
  }
  const key = getPublicKey(publicKeyInput);
  return crypto.verify(null, data, key, sigBuf);
}

/**
 * Hash for context fingerprint (SHA-256, hex). Used for device binding.
 * @param {string} input e.g. "ip|userAgent"
 * @returns {string} 64-char hex
 */
function hashFingerprint(input) {
  if (typeof input !== 'string') {
    throw new Error('Invalid input');
  }
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Constant-time comparison of two hex strings (e.g. fingerprints).
 * @param {string} a 64-char hex
 * @param {string} b 64-char hex
 * @returns {boolean}
 */
function timingSafeEqualHex(a, b) {
  if (
    typeof a !== 'string' ||
    typeof b !== 'string' ||
    a.length !== FINGERPRINT_HEX_LENGTH ||
    b.length !== FINGERPRINT_HEX_LENGTH
  ) {
    return false;
  }
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  if (bufA.length !== 32 || bufB.length !== 32) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

module.exports = {
  generateKeys,
  encrypt,
  decrypt,
  sign,
  verifySignature,
  hashFingerprint,
  timingSafeEqualHex,
  toBase64Url,
  fromBase64Url,
  CHACHA_KEY_LENGTH,
  CHACHA_IV_LENGTH,
  AUTH_TAG_LENGTH,
};
