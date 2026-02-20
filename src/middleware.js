'use strict';

const token = require('./token.js');
const { VerificationError } = require('./errors.js');
const constants = require('./constants.js');

const { BLOCK_DURATION_MS, MAX_FAILED_ATTEMPTS_BEFORE_BLOCK } = constants;

/** @type {Map<string, { blockedUntil: number }>} */
const blockStore = new Map();

/** @type {Map<string, { count: number }>} */
const failCountStore = new Map();

/**
 * Extract client IP and User-Agent from request. Safe for proxies (X-Forwarded-For, X-Real-IP).
 * @param {{ headers?: Record<string, string|string[]|undefined>, socket?: { remoteAddress?: string } }} req
 * @returns {{ ip: string, userAgent: string }}
 */
function getClientInfo(req) {
  const raw = req?.headers?.['x-forwarded-for'];
  const first = Array.isArray(raw) ? raw[0] : raw;
  const ip =
    (typeof first === 'string' && first.split(',')[0].trim()) ||
    (req?.headers?.['x-real-ip'] && String(req.headers['x-real-ip'])) ||
    req?.socket?.remoteAddress ||
    '0.0.0.0';
  const ua = req?.headers?.['user-agent'];
  const userAgent = typeof ua === 'string' ? ua : '';
  return { ip, userAgent };
}

/**
 * @param {string} ip
 * @returns {boolean}
 */
function isBlocked(ip) {
  const entry = blockStore.get(ip);
  if (!entry) return false;
  if (Date.now() < entry.blockedUntil) return true;
  blockStore.delete(ip);
  return false;
}

/**
 * @param {string} ip
 */
function blockIp(ip) {
  blockStore.set(ip, { blockedUntil: Date.now() + BLOCK_DURATION_MS });
  failCountStore.delete(ip);
}

/**
 * Increment failed attempt count for IP. Returns true if IP should now be blocked.
 * @param {string} ip
 * @param {number} threshold
 * @returns {boolean}
 */
function recordFailedAttempt(ip, threshold) {
  const entry = failCountStore.get(ip);
  const count = entry ? entry.count + 1 : 1;
  failCountStore.set(ip, { count });
  return count >= threshold;
}

/**
 * Express-compatible middleware. Verifies Authorization: Bearer <token> and attaches payload to req.aegiss.
 * Blocks IP only after maxFailedAttempts failed verifications (default 10), not on missing header.
 * @param {string} publicKey Base64url Ed25519 public key
 * @param {{ minIat?: number, revokedJtis?: Set<string>|((jti: string) => boolean), maxFailedAttempts?: number }} [options] maxFailedAttempts: block after this many failures (default 10)
 * @returns {(req: import('express').Request, res: import('express').Response, next: import('express').NextFunction) => void}
 */
function createVerifyMiddleware(publicKey, options = {}) {
  if (!publicKey || typeof publicKey !== 'string') {
    throw new Error('publicKey is required');
  }
  const maxFailedAttempts =
    typeof options.maxFailedAttempts === 'number' && options.maxFailedAttempts > 0
      ? options.maxFailedAttempts
      : MAX_FAILED_ATTEMPTS_BEFORE_BLOCK;
  return function verifyMiddleware(req, res, next) {
    const { ip, userAgent } = getClientInfo(req);
    if (isBlocked(ip)) {
      res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
      return;
    }
    const auth = req.headers?.authorization;
    if (!auth || typeof auth !== 'string' || !auth.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    const tokenString = auth.slice(7).trim();
    const clientInfo = { ip, userAgent };
    try {
      const payload = token.verify(tokenString, publicKey, clientInfo, options);
      failCountStore.delete(ip);
      req.aegiss = payload;
      next();
    } catch (err) {
      if (err instanceof VerificationError) {
        if (recordFailedAttempt(ip, maxFailedAttempts)) {
          blockIp(ip);
        }
      }
      res.status(401).json({ error: 'Unauthorized' });
    }
  };
}

/**
 * Clear in-memory block list and failure counts (e.g. for tests).
 */
function clearBlockList() {
  blockStore.clear();
  failCountStore.clear();
}

module.exports = {
  createVerifyMiddleware,
  getClientInfo,
  clearBlockList,
  isBlocked,
  BLOCK_DURATION_MS,
};
