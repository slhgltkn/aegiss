'use strict';

const crypto = require('./crypto.js');
const token = require('./token.js');
const middleware = require('./middleware.js');
const { VerificationError } = require('./errors.js');

module.exports = {
  generateKeys: crypto.generateKeys,
  encrypt: crypto.encrypt,
  decrypt: crypto.decrypt,
  sign: token.sign,
  verify: token.verify,
  hashFingerprint: crypto.hashFingerprint,
  toBase64Url: crypto.toBase64Url,
  fromBase64Url: crypto.fromBase64Url,
  createVerifyMiddleware: middleware.createVerifyMiddleware,
  getClientInfo: middleware.getClientInfo,
  clearBlockList: middleware.clearBlockList,
  isBlocked: middleware.isBlocked,
  VerificationError,
  CHACHA_KEY_LENGTH: crypto.CHACHA_KEY_LENGTH,
  CHACHA_IV_LENGTH: crypto.CHACHA_IV_LENGTH,
  AUTH_TAG_LENGTH: crypto.AUTH_TAG_LENGTH,
  BLOCK_DURATION_MS: middleware.BLOCK_DURATION_MS,
};
