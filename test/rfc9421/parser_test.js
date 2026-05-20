const http = require('http');

const { test } = require('tap');
const uuid = require('uuid').v4;

const httpSignature = require('../../lib/index');

///--- Globals
var options = null;
var server = null;
var socket = null;

//--- Tests

test('setup', function (t) {
  socket = `/tmp/.${uuid()}`;
  options = {
    socketPath: socket,
    path: '/',
    headers: {},
  };

  server = http.createServer(function(req, res) {
    server.tester(req, res);
  });
  server.listen(socket, function() {
    t.end();
  });
});

test('no authorization', function(t) {
  server.tester = function(req, res) {
    try {
      httpSignature.rfc9421.parseRequest(req);
    } catch (e) {
      t.equal(e.name, 'MissingHeaderError');
    }
    res.writeHead(200);
    res.end();
  };

  http.get(options, function(res) {
    t.equal(res.statusCode, 200);
    t.end();
  });
});

test('no key id', function(t) {
  server.tester = function(req, res) {
    try {
      req.url = 'https://example.social';
      httpSignature.rfc9421.parseRequest(req);
    } catch (e) {
      console.error(e);
      t.equal(e.name, 'InvalidParamsError');
      t.equal(e.message, 'keyid was not specified');
    }

    res.writeHead(200);
    res.end();
  };

  options.path = '/foo/bar';
  options.headers.signature = 'sig1=:foo:';
  options.headers[`signature-input`] = 'sig1=("@method" "@target-uri"); created=1618884475';
  http.get(options, function(res) {
    t.equal(res.statusCode, 200);
    t.end();
  });
});

test('key id no value', function (t) {
  server.tester = function (req, res) {
    try {
      req.url = 'https://example.social';
      httpSignature.rfc9421.parseRequest(req);
    } catch (e) {
      console.error(e);
      t.equal(e.name, 'InvalidParamsError');
      t.equal(e.message, 'keyid was not specified');
    }

    res.writeHead(200);
    res.end();
  };

  options.path = '/foo/bar';
  options.headers.signature = 'sig1=:foo:';
  options.headers[`signature-input`] = 'sig1=("@method" "@target-uri");created=1618884475;keyid=http://example.social/users/foo#main-key';
  http.get(options, function (res) {
    t.equal(res.statusCode, 200);
    t.end();
  });
});

test('tearDown', function (t) {
  server.on('close', function () {
    t.end();
  });
  server.close();
});
