const { InvalidAlgorithmError, parsePrivateKey, PrivateKey } = require('sshpk');
var util = require('util');
const { HttpSignatureError, PK_ALGOS } = require('../utils');
const { extractAlgorithmParts } = require('./alg');

///--- Specific Errors

function MissingHeaderError(message) {
  HttpSignatureError.call(this, message, MissingHeaderError);
}
util.inherits(MissingHeaderError, HttpSignatureError);

///--- Exported API

module.exports = {

  /**
   * A basic implementaton for signing RFC 9421 requests.
   *
   * @param {Object} request an instance of http.ClientRequest.
   * @param {Object} options signing parameters object:
   *                   - {String} keyId required.
   *                   - {String} key required (PEM).
   *                   - {String} algorithm required algorithm string, which is
   *                              one of RFC9421_ALGORITHMS. This cannot be
   *                              derived from the sshpk library so must be
   *                              passed in by the caller.
   *                   - {Array}  headers optional;
   *                   - {int}    expiresIn optional; defaults to 60. The
   *                              seconds after which the signature should
   *                              expire;
   *                   - {String} keyPassphrase optional; the passphrase to pass
   *                              the sshpk to parse the privateKey.
   *                   - {String} label optional; defaults to "sig1".
   * @return {Boolean} false because Authorization is not added.
   * @throws {TypeError} on bad parameter types.
   * @throws {InvalidAlgorithmError} if algorithm was bad or incompatible with
   *                                 the given key.
   */
  signRequest: function signRequest(request, options) {
    assert.object(request, 'request');
    assert.object(options, 'options');
    assert.string(options.keyId, 'options.keyId');
    assert.string(options.algorithm, 'options.algorithm');
    assert.optionalArrayOfString(options.headers, 'options.headers');
    assert.optionalNumber(options.expiresIn, 'options.expiresIn');
    assert.optionalString(options.keyPassphrase, 'options.keyPassphrase');
    assert.optionalString(options.label, 'options.label');

    const label = options.label || 'sig1';

    // 1. The signer chooses an HTTP signature algorithm and key material.
    const { key } = options;
    let privateKey = null;
    if (typeof key === 'string' || Buffer.isBuffer(key)) {
      privateKey = parsePrivateKey(key, 'auto', {
        passphrase: options.keyPassphrase,
      });
    }
    assert.ok(PrivateKey.isPrivateKey(privateKey), 'options.key must be a sshpk.PrivateKey');

    if (!PK_ALGOS[privateKey.type] || privateKey.type === 'dsa') {
      throw new InvalidAlgorithmError(`${privateKey.type.toUpperCase()} type keys are not supported.`);
    }

    const alg = options.algorithm;
    const [, hash] = extractAlgorithmParts(options.algorithm);

    // 2. The signer sets the signature’s creation tiem to the current time.
    const created = Date.now() / 1000;

    // 3. If applicable, the signer sets the signature’s expiration time to the
    //    time at which the signature is set to expire.
    const expires = options.expiresIn ? created + options.expiresIn : null;

    const parameters = [
      { key: 'created', value: created },
    ];

    if (expires) {
      parameters.push({ key: 'expires', value: expires });
    }

    parameters.push({ key: 'keyid', value: options.keyId });
    parameters.push({ key: 'alg', value: options.algorithm });

    const [path, queryString] = request.path.split('?', 1);

    // 4. The signer creates an ordered set of component identifiers
    //    representing the message components to be covered by the signature and
    //    attached signature metadata parameters to this set. The serialized
    //    value of this set is later used as the value of the Signature-Input
    //    header.
    const coveredComponents = [
      {
        key: '@method',
        value: request.method,
      },
      {
        key: '@authority',
        // @todo this is not accurate, but there does not seem to be a way to
        //       get a non-default port used via node.js ClientRequest object?
        value: request.host,
      },
      {
        key: '@target-uri',
        // @todo see above. Also there is no way to get the scheme from the
        //       ClientRequest object because http and https are 2 different
        //       libraries in node.js (psyduck barfing psyducks).
        value: 'https://' . request.host,
      },
      {
        key: '@request-target',
        // The request-target is both the path and the query string, which
        // actually works in our favor with ClientRequest.
        value: request.path,
      },
      {
        key: '@path',
        value: path,
      }
    ];

    if (queryString.length > 0) {
      coveredComponents.push({
        key: '@query',
        value: `?${queryString}`,
      });
    }

    options.headers.forEach((headerName) => {
      if (!request.hasHeader(headerName)) {
        throw new MissingHeaderError(`${headername} was not in the request`);
      }
      coveredComponents.push({
        key: headerName.toLocaleLowerCase(),
        value: request.getHeader(headerName),
      });
    });

    // 5. The signer creates the signature base using these parameters and the
    //    signature base creation algorithm.
    let signatureParams = coveredComponents.reduce((params, c) => (
      `${params}${c.key} `
    ), '(');
    signatureParams = `${signatureParams.trimEnd()})`;
    signatureParams = parameters.reduce((params, p) => {
      const val = `${params};${p.key}=`;
      if (typeof p.value === 'string') {
        return `${val}"${p.value}"`;
      }

      return `${val}${p.value}`;
    }, signatureParams);

    let signatureBase = coveredComponents.reduce((base, c) => (
      `${base}"${c.key}": ${c.value}\n`
    ), '');
    signatureBase = `${signatureBase}"@signature-params": ${signatureParams}`;

    // 6. The signer uses the HTTP_SIGN primitive function to sign the
    //    signature base with the chosen signing algorithm using the key
    //    material chosen by the signer.
    const signer = PrivateKey.createSign(hash);
    signer.update(signatureBase);
    const sigObj = signer.sign();
    const signature = sigObj.toString();
    assert.notStrictEqual(signature, '', 'empty signature produced');

    // 7. The byte array output of the signature function is the HTTP message
    //    signature output value included in the Signature field.
    request.setHeader('signature-input', `${label}=${signatureParams}`);
    request.setHeader('signature', `${label}=${signature}`);

    return false;
  },

};
