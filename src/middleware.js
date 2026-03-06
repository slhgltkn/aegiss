'use strict';

const { VerificationError } = require('./errors.js');

const BLOCK_DURATION_MS = 15 * 60 * 1000;
const MAX_FAILED_ATTEMPTS_BEFORE_BLOCK = 10;

const blockStore = new Map();
const failCountStore = new Map();

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

function isBlocked(ip) {
  const entry = blockStore.get(ip);
  if (!entry) return false;
  if (Date.now() < entry.blockedUntil) return true;
  blockStore.delete(ip);
  return false;
}

function blockIp(ip) {
  blockStore.set(ip, { blockedUntil: Date.now() + BLOCK_DURATION_MS });
  failCountStore.delete(ip);
}

function recordFailedAttempt(ip, threshold) {
  const entry = failCountStore.get(ip);
  const count = entry ? entry.count + 1 : 1;
  failCountStore.set(ip, { count });
  return count >= threshold;
}

function createVerifyMiddleware(publicKeyHex, options = {}) {
  // We need `verify` from index.js eventually, but we can't require index.js directly here to avoid circular dependencies easily if it's imported at the top,
  // so we require native here for actual verification:
  const native = require('../artifacts/index.js');

  if (!publicKeyHex || typeof publicKeyHex !== 'string') {
    throw new Error('publicKeyHex is required');
  }
  const maxFailedAttempts =
    typeof options.maxFailedAttempts === 'number' && options.maxFailedAttempts > 0
      ? options.maxFailedAttempts
      : MAX_FAILED_ATTEMPTS_BEFORE_BLOCK;

  return function verifyMiddleware(req, res, next) {
    const { ip, userAgent } = getClientInfo(req);
    if (isBlocked(ip)) {
      if (res.status) res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
      return;
    }
    const auth = req.headers?.authorization;
    if (!auth || typeof auth !== 'string' || !auth.startsWith('Bearer ')) {
      if (res.status) res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    const tokenString = auth.slice(7).trim();
    const clientInfo = { ip, userAgent };
    
    try {
      const payloadString = native.verify(tokenString, publicKeyHex, clientInfo);
      
      let payload;
      try {
        payload = JSON.parse(payloadString);
      } catch {
        payload = payloadString;
      }
      
      failCountStore.delete(ip);
      req.aegiss = payload;
      if (next) next();
    } catch (err) {
      if (recordFailedAttempt(ip, maxFailedAttempts)) {
        blockIp(ip);
      }
      if (res.status) res.status(401).json({ error: 'Unauthorized' });
    }
  };
}

function clearBlockList() {
  blockStore.clear();
  failCountStore.clear();
}

module.exports = {
  createVerifyMiddleware,
  getClientInfo,
  clearBlockList,
  isBlocked,
  BLOCK_DURATION_MS
};
