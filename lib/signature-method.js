const assert = require('assert-plus');
const cavage12Draft = require('./cavage12');
const rfc9421 = require('./rfc9421');

///--- API

module.exports = {

  /**
   * Gets the appropriate signature method from request headers.
   *
   * When a request has Signature-Input header, the RFC 9421 signature method
   * will be returned. Otherwise, the cavage-12 draft signature method will be
   * returned.
   *
   * @param {Object} request the ServerRequest or ClientRequest.
   * @returns {Object} one of either cavage12Draft or rfc9421.
   * @throws {TypeError} when request is not an object.
   */
  getfromRequest: function createfromRequest(request) {
    assert.object(request, 'request');
    if (request.hasHeader('signature-input')) {
      return rfc9421;
    }

    return cavage12Draft;
  },

};
