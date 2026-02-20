'use strict';

const crypto = require('crypto');
const { VerificationError } = require('./errors.js');
const constants = require('./constants.js');
const { fromBase64Url, toBase64Url } = require('./encoding.js');
const { sign: cryptoSign, verifySignature, hashFingerprint, timingSafeEqualHex } = require('./crypto.js');
const cbor = require('./cbor.js');

const { PROTOCOL_VERSION, TOKEN_TYPES, DEFAULT_EXPIRES_IN_SECONDS, MAX_TOKEN_LENGTH } = constants;

function generateJti() {
  return crypto.randomBytes(16).toString('hex');
}

function validateClientInfo(clientInfo) {
  return (
    clientInfo &&
    typeof clientInfo === 'object' &&
    typeof clientInfo.ip === 'string' &&
    typeof clientInfo.userAgent === 'string'
  );
}

/**
 * Create a signed public token. Payload is CBOR-encoded; iat, exp, jti, fingerprint are added automatically.
 * @param {Record<string, unknown>} payload User claims
 * @param {string} privateKey Base64url Ed25519 private key
 * @param {{ clientInfo: { ip: string, userAgent: string }, expiresInSeconds?: number }} options
 * @returns {string} v1.public.<payload_base64url>.<signature>
 */
function sign(payload, privateKey, options = {}) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('Invalid payload');
  }
  if (!validateClientInfo(options.clientInfo)) {
    throw new Error('clientInfo.ip and clientInfo.userAgent are required');
  }
  const expiresInSeconds =
    typeof options.expiresInSeconds === 'number' && options.expiresInSeconds > 0
      ? options.expiresInSeconds
      : DEFAULT_EXPIRES_IN_SECONDS;
  const now = Math.floor(Date.now() / 1000);
  const fingerprint = hashFingerprint(`${options.clientInfo.ip}|${options.clientInfo.userAgent}`);
  const full = {
    ...payload,
    iat: now,
    exp: now + expiresInSeconds,
    jti: generateJti(),
    fingerprint,
  };
  const payloadCbor = cbor.encode(full);
  const payloadB64 = toBase64Url(payloadCbor);
  const type = 'public';
  const signingInput = `${PROTOCOL_VERSION}.${type}.${payloadB64}`;
  const signature = cryptoSign(Buffer.from(signingInput, 'utf8'), privateKey);
  return `${signingInput}.${signature}`;
}

/**
 * Verify token. All verification failures throw VerificationError with a generic message (no information leak).
 * @param {string} token
 * @param {string} publicKey Base64url Ed25519 public key
 * @param {{ ip: string, userAgent: string }} currentClientInfo
 * @param {{ minIat?: number, revokedJtis?: Set<string>|((jti: string) => boolean) }} options minIat: reject tokens issued before this; revokedJtis: reject these JTIs (revocation)
 * @returns {Record<string, unknown>} Decoded payload
 * @throws {VerificationError}
 */
function verify(token, publicKey, currentClientInfo, options = {}) {
  if (!token || typeof token !== 'string' || token.length > MAX_TOKEN_LENGTH) {
    throw new VerificationError();
  }
  if (!token.startsWith(PROTOCOL_VERSION + '.')) {
    throw new VerificationError();
  }
  if (!validateClientInfo(currentClientInfo)) {
    throw new VerificationError();
  }
  const parts = token.split('.');
  if (parts.length !== 4) {
    throw new VerificationError();
  }
  const [version, type, payloadB64, signatureB64] = parts;
  if (version !== PROTOCOL_VERSION || !TOKEN_TYPES.includes(type) || type !== 'public') {
    throw new VerificationError();
  }
  const signingInput = `${version}.${type}.${payloadB64}`;
  const signingInputBuf = Buffer.from(signingInput, 'utf8');
  let sigBuf;
  let payloadBuf;
  try {
    sigBuf = fromBase64Url(signatureB64, 256);
    payloadBuf = fromBase64Url(payloadB64, MAX_TOKEN_LENGTH);
  } catch (_) {
    throw new VerificationError();
  }
  if (!verifySignature(signingInputBuf, signatureB64, publicKey)) {
    throw new VerificationError();
  }
  let payload;
  try {
    payload = cbor.decode(payloadBuf);
  } catch (_) {
    throw new VerificationError();
  }
  if (!payload || typeof payload !== 'object') {
    throw new VerificationError();
  }
  const exp = payload.exp;
  const iat = payload.iat;
  const tokenFingerprint = typeof payload.fingerprint === 'string' ? payload.fingerprint : '';
  if (
    typeof exp !== 'number' ||
    typeof iat !== 'number' ||
    tokenFingerprint.length !== constants.FINGERPRINT_HEX_LENGTH
  ) {
    throw new VerificationError();
  }
  const now = Math.floor(Date.now() / 1000);
  if (exp < now) {
    throw new VerificationError();
  }
  if (typeof options.minIat === 'number' && iat < options.minIat) {
    throw new VerificationError();
  }
  const revokedJtis = options.revokedJtis;
  if (revokedJtis != null) {
    if (typeof revokedJtis === 'function') {
      if (revokedJtis(payload.jti)) throw new VerificationError();
    } else if (typeof revokedJtis.has === 'function' && revokedJtis.has(payload.jti)) {
      throw new VerificationError();
    }
  }
  const expectedFingerprint = hashFingerprint(`${currentClientInfo.ip}|${currentClientInfo.userAgent}`);
  if (!timingSafeEqualHex(expectedFingerprint, tokenFingerprint)) {
    throw new VerificationError();
  }
  return payload;
}

module.exports = { sign, verify };
