const { parseKey, Key } = require('sshpk');
const { extractAlgorithmParts } = require('./alg');

///--- Exported API

module.exports = {

  /**
   * Verify RSA/ECDSA signature against public key.
   *
   * You are expected to pass in an object that was returned from `parse()`.
   *
   * @param {Object} parsedSignature the object you got from `parse`.
   * @param {String} pubkey The RSA/ECDSA private key PEM.
   * @return {Boolean} true if valid, false otherwise.
   * @throws {InvalidAlgorithmError} when algorithm or digest hash type is not
   *                                 supported.
   */
  verifySignature: function verifySignature(parsedSignature, pubkey) {
    assert.object(parsedSignature, 'parsedSignature');
    if (typeof pubkey === 'string' || Buffer.isBuffer(pubkey)) {
      pubkey = parseKey(pubkey);
    }
    assert.ok(Key.isKey(pubkey), 'pubkey must be a sshpk.Key');

    const [alg, hash] = extractAlgorithmParts(parsedSignature.params.alg);

    // The algorithm was already validated by the parser.
    const v = pubkey.createVerify(alg, hash);
    v.update(parsedSignature.signatureBase);
    return (v.verify(parsedSignature.signatureString, 'base64'));
  },

};
