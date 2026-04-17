const { InvalidAlgorithmError } = require('../utils');

const RFC9421_ALGORITHMS = [
  // RSA PKCS#1 v1.5.
  'rsa-v1_5-sha256',
  'rsa-v1_5-sha384',
  'rsa-v1_5-sha512',

  // RSA PSS.
  'rsa-pss-sha256',
  'rsa-pss-sha384',
  'rsa-pss-sha512',

  // ECDSA.
  'ecdsa-p256-sha256',
  'ecdsa-p384-sha384',
  'ecdsa-p512-sha512',

  // Ed25519.
  'ed25519',
];

module.exports = {
  RFC9421_ALGORITHMS,

  /**
   * Extracts the algorithm parts from the algorithm.
   *
   * @param {string} algorithm one of the RFC-9421 algorithms.
   * @return {[string, string]} the algorith pk type and hash.
   */
  extractAlgorithmParts: function extractAlgorithm(algorithm) {
    if (!RFC9421_ALGORITHMS[algorithm]) {
      throw new InvalidAlgorithmError(`${algorithm} is not a valid algorithm`);
    }

    if (algorithm === 'ed25519') {
      return ['ed25519', 'sha512'];
    }

    const [alg,,hash] = algorithm.split('-');
    return [alg, hash];
  },
};
