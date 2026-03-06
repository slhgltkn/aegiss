'use strict';

class VerificationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'VerificationError';
  }
}

module.exports = {
  VerificationError
};
