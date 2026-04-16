// Copyright 2015 Joyent, Inc.

var parser = require('./parser');
var signer = require('./signer');
var verify = require('./verify');

///--- API

module.exports = {
  parse: parser.parseRequest,
  parseRequest: parser.parseRequest,

  sign: signer.signRequest,
  signRequest: signer.signRequest,
  createSigner: signer.createSigner,
  isSigner: signer.isSigner,

  verify: verify.verifySignature,
  verifySignature: verify.verifySignature,
  verifyHMAC: verify.verifyHMAC,
};
