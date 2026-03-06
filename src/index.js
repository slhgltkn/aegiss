'use strict';

// We import the loader produced by NAPI-RS, representing the NAPI binary compiled from Rust.
// The index.js file inside the 'artifacts' folder resolves and loads the appropriate binary 
// (e.g., 'aegiss.win32-x64-msvc.node') for the host architecture.
const native = require('../artifacts/index.js'); 
const middleware = require('./middleware.js');
const { VerificationError } = require('./errors.js');

module.exports = {
  // HIGH-PERFORMANCE RUST NATIVE METHODS (Core Engine)
  sign: native.sign,
  verify: native.verify,
  decode: native.decode,

  // MIDDLEWARE AND UTILITIES (For framework integrations like Express.js)
  createVerifyMiddleware: middleware.createVerifyMiddleware,
  getClientInfo: middleware.getClientInfo,
  clearBlockList: middleware.clearBlockList,
  isBlocked: middleware.isBlocked,
  
  // ERRORS AND CONSTANTS
  VerificationError,
  BLOCK_DURATION_MS: middleware.BLOCK_DURATION_MS,
  
  // ENCRYPTION PROTOCOLS
  // Entirely offloaded to Rust utilizing ChaCha20Poly1305 encryption.
  encrypt: native.encrypt,
  decrypt: native.decrypt,
};
