// Copyright 2015 Joyent, Inc.

const util = require('util');
const cavage12Draft = require('./cavage12');
const utils = require('./utils');

const {
  parse,
  parseRequest,
  sign,
  signRequest,
  createSigner,
  isSigner,
  verify,
  verifySignature,
  verifyHMAC,
} = cavage12Draft;

///--- API

module.exports = {
  cavage12Draft: cavage12Draft,

  sshKeyToPEM: utils.sshKeyToPEM,
  sshKeyFingerprint: utils.fingerprint,
  pemToRsaSSHKey: utils.pemToRsaSSHKey,

  // @deprecated
  parse: util.deprecate(parse, 'Calling parse directly is deprecated. Use cavage12Draft.parse() instead.'),
  parseRequest: util.deprecate(parseRequest, 'Calling parseRequest is deprecated. Use cavage12Draft.parseRequest() instead.'),
  sign: util.deprecate(sign, 'Calling sign directly is deprecated. Use cavage12Draft.sign() instead.'),
  signRequest: util.deprecate(signRequest, 'Calling signRequest directly is deprecated. Use cavage12Draft.signRequest() instead.'),
  createSigner: util.deprecate(createSigner, 'Calling createSigner directly is deprecated. Use cavage12Draft.createSigner() instead.'),
  isSigner: util.deprecate(isSigner, 'Calling isSigner directly is deprecated. Use cavage12Draft.isSigner() instead.'),
  verify: util.deprecate(verify, 'Calling verify directly is deprecated. Use cavage12Draft.verify() instead.'),
  verifySignature: util.deprecate(verifySignature, 'Calling verifySignature directly is deprecated. Use cavage12Draft.verifySignature() instead.'),
  verifyHMAC: util.deprecate(verifyHMAC, 'Calling verifyHMAC directly is deprecated. Use cavage12Draft.verifyHMAC() instead.'),
};
