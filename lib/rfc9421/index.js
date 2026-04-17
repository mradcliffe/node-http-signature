const { parseRequest } = require('./parser');
const { signRequest } = require('./signer');
const { verifySignature } = require('./verify');

module.exports = {
  parse: parseRequest,
  parseRequest,

  sign: signRequest,
  signRequest,

  verify: verifySignature,
  verifySignature,
};
