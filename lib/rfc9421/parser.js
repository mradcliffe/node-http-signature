var assert = require('assert-plus');
var util = require('util');
const { HttpSignatureError, InvalidAlgorithmError } = require('../utils');
const { RFC9421_ALGORITHMS } = require('./alg');

const defaultOptions = {
  clockSkew: 300,
  headers: [],
  algorithms: [...RFC9421_ALGORITHMS],
};

///--- Specific Errors

function ExpiredRequestError(message) {
  HttpSignatureError.call(this, message, ExpiredRequestError);
}
util.inherits(ExpiredRequestError, HttpSignatureError);

function InvalidHeaderError(message) {
  HttpSignatureError.call(this, message, InvalidHeaderError);
}
util.inherits(InvalidHeaderError, HttpSignatureError);

function MissingHeaderError(message) {
  HttpSignatureError.call(this, message, MissingHeaderError);
}
util.inherits(MissingHeaderError, HttpSignatureError);

function InvalidParamsError(message) {
  HttpSignatureError.call(this, message, InvalidParamsError);
}
util.inherits(InvalidParamsError, HttpSignatureError);

///--- Exported API

module.exports = {

  /**
   * Parses the signature headers out of an http.ServerRequest object.
   *
   * This may return multiple signatures, and it is up to you to decide which
   * one you will use to validate. Most implementations are providing only one
   * signature.
   *
   *     [
   *       {
   *         "scheme": "Signature-Input",
   *         "label": "",
   *         "params": {
   *           "keyid": "",
   *           "alg": "",
   *         },
   *         "components": [
   *           { key: "", value: "" },
   *         ],
   *         "signatureBase": "",
   *         "signature": "base64"
   *       }
   *     ]
   *
   * @param {Object} request an http.ServeRequest.
   * @param {Object} options an optional options object with:
   *                   - clockSkew: allowed clock skew in seconds (default 300).
   *                   - headers: required header names.
   *                   - algorithms: algorithms to support.
   * @return {Object} parsed out object (see above).
   * @throws {MissingHeaderError} when a required header is missing either
   *                              because it is a covered component or provided
   *                              manually via `options.headers`.
   * @throws {InvalidAlgorithmError} when alg signature parameter does not match
   *                                 supported algorithms.
   * @throws {InvalidHeaderError} when a header value is invalid.
   * @throws {InvalidParamsError} when a signature parameter has an invalid
   *                              value.
   * @throws {ExpiredRequestError} when created or expired has exceeded the
   *                               threshold for acceptable values.
   */
  parseRequest: function parseRequest(request, options) {
    assert.object(request, 'request');
    assert.object(request.headers, 'request.headers');

    const parsedOptions = { ...defaultOptions };
    if (options !== undefined && typeof options === 'object') {
      Object.keys(options).forEach((optionKey) => {
        parsedOptions[optionKey] = options[optionKey];
      });
    }

    assert.object(options, 'options');
    assert.optionalFinite(options.clockSkew, 'options.clockSkew');

    if (!request.headers['signature-input']) {
      throw new MissingHeaderError('no signature-input header present in the request');
    }

    if (!request.headers['signature']) {
      throw new MissingHeaderError('no signature header present in the request');
    }

    if (options.headers.length > 0) {
      options.headers.forEach((headerName) => {
        if (!request.headers[headerName]) {
          throw new MissingHeaderError(`no ${headerName} present in the request`);
        }
      });
    }

    const url = new URL(request.url);

    const now = Date.now();

    // Parse the Signature-Input header in the request.
    const sigInputs = request.headers['signature-input'].split(',');
    if (sigInputs === null || sigInputs.length === 0) {
      throw new InvalidHeaderError('bad signature-input format');
    }

    // Parse the request Signature header in the request.
    const sigs = request.headers['signature'].split(',');
    if (sigs === null || sigs.length === 0) {
      throw new InvalidHeaderError('bad signature format');
    }

    const sigStrings = {};
    sigs.forEach((sig) => {
      const sigMatch = sig.match(/^(a-zA-Z0-9-_]+)=:([^:]+):/);
      if (sigMatch.length !== 2) {
        throw new InvalidHeaderError('bad signature format');
      }
      const [sigLabel, sigString] = sigMatch;
      sigStrings[sigLabel] = sigString;
    });

    // Parses all signature inputs and signatures in the request.
    let parsedSignatures = [];
    sigInputs.forEach((sigInputString) => {
      const parsedSignature = {
        scheme: 'Signature-Input',
        label: "",
        params: {
          keyid: "",
          alg: "",
        },
        components: [],
        signatureBase: "",
        signatureString: "",
      };
      const sigInputParts = sigInputString.split('=');
      if (sigInputParts !== null && sigInputParts.length === 2) {
        const [label, sigInput] = sigInputParts;

        parsedSignature.label = label;
        parsedSignature.signatureString = sigStrings[label];

        // Parse the derived components, components, and signature parameters
        // from the signature input, which are separated by semicolons.
        const inputParams = sigInput.split(';');

        // Parse the values for signature parameters, and extrapolate values for
        // components.
        const sigParams = {};
        inputParams.forEach((inputParam, inputParamIndex) => {
          if (inputParamIndex === 0) {
            const componentNames = inputParam.matchAll(/"(@?[a-z\-]+)"/g);

            // Check the required headers against the component names.
            options.headers.forEach((headerName) => {
              if (!componentNames.includes(headerName)) {
                throw new MissingHeaderError(`no ${headerName} is present in components for ${label}, but it is required.`);
              }
            });

            // Map the component names in order.
            parsedSignature.components = componentNames.map((componentName) => {
              const component = {
                key: componentName,
                value: null,
              };

              if (componentName === '@method') {
                // 2.2.1 Note that the method name is case-sensitive as per HTTP
                // Section 9.1. While conventionally standardized names are
                // uppercase, no transformation to the input method value’s case
                // is performed.
                component.value = request.method;
              } else if (componentName === '@target-uri') {
                // The URL should be considered case-sensitive due to operating
                // system issues and query string percent-encoded octets.
                component.value = url.href;
              } else if (componentName === '@authority') {
                // Normalized to lowercase and the default port is omitted.
                component.value = url.port.length === 0 || url.port === '80' || url.port === '443'
                  ? url.hostname
                  : `${url.hostname}:${url.port}`
              } else if (componentName === '@scheme') {
                // The scheme MUT be normalized to lowercase.
                component.value = url.protocol.toLocaleLowerCase();
              } else if (componentName === '@request-target') {
                component.value = `${request.pathname}${request.search || ''}`;
              } else if (componentName === '@path') {
                component.value = url.pathname;
              } else if (componentName === '@query') {
                component.value = url.search || '';
              } else if (componentName === '@query-param') {
                // @todo 2.2.8 is very annoying.
                throw new InvalidParamsError('@query-param component is not supported');
              } else if (request.headers[componentName]) {
                component.value = request.headers[componentName];
              } else {
                throw new InvalidParamsError(`required ${componentName} is missing from header`);
              }
              return component;
            });
          } else {
            // Parse the rest of the signature parameters.
            const [paramKey, paramValue] = inputParam.split('=');
            sigParams[paramKey] = paramValue;
            parsedSignature.params[paramKey] = paramValue;
          }
        });

        // Confirm signature parameters.
        if (sigParams['created']) {
          // The inclusion of created is RECOMMENDED.
          assert.number(sigParams['created'], 'created');
          const created = sigParams['created'];

          if (created === null ||
              isNaN(created) ||
              !Number.isInteger(created)) {
            throw new InvalidParamsError('created is not valid')
          } else {
            const skew = created - Math.floor(now / 1000);
            if ( skew > options.clockSkew) {
              throw new ExpiredRequestError(`created lies in the future with skew ${skew}s greater than allowed ${options.clockSkew}s`);
            }
          }
        }

        if (sigParams['expires']) {
          assert.number(sigParams['expires'], 'expires');
          const expires = sigParams['expires'];

          if (expires === null ||
              Number.isNaN(expires) ||
              !Number.isInteger(expires)) {
            throw new InvalidParamsHeader('expires is not valid')
          } else {
            const expiredSince = Math.floor(now / 1000) - expires;
            if (expiredSince > options.clockSkew) {
              throw new ExpiredRequestError(`request expired with skew ${expiredSince}s greater than allowed ${options.clockSkew}s`)
            }
          }
        }

        // Extract the keyid.
        if (sigParams['keyid']) {
          parsedSignature.params.keyId = sigParams['keyid'].replace('"', '');
        } else {
          throw new InvalidParamsHeader('keyid was not specified');
        }

        // Determine the algorithm.
        if (sigParams['alg']) {
          const { alg } = sigParams;
          if (!options.algorithms[alg]) {
            throw new InvalidAlgorithmError(`${alg} is not a valid algorithm`);
          }
          parsedSignature.params.algorithm = alg;
        } else {
          throw new InvalidParamsHeader('alg was not specified');
        }

        // Recreate the signature base from the signature parameters and
        // components.
        let signatureBase = parsedSignature.components.reduce((base, component) => {
          const { key, value } = component;
          return `${base}"${key}": ${value}\n`;
        }, '');
        // Append the signature parameters to the signature base.
        parsedSignature.signatureBase = `${signatureBase}"@signature-params": ` . sigInput;
        parsedSignatures = parsedSignatures.concat(parsedSignature);
      }
    });

    return parsedSignatures;
  },

};
