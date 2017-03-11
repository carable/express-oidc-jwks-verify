'use strict';

const async = require('async');
const formatCertificate = require('./lib/formatcertificate');
const fs = require('fs');
const jwtVerify = require('./lib/verifyjwt');
const NodeRSA = require('node-rsa');
const path = require('path');
const request = require('request');
const urlJoin = require('url-join');
const x509 = require('x509');

const OIDC_DISCOVERY_PATH = '/.well-known/openid-configuration';

const verify = function (options) {
  if (!options) {
    throw new Error('Options are missing.');
  }

  if (!options.issuer) {
    throw new Error('issuer option is missing.');
  }

  const issuer = options.issuer;
  const OIDC_DISCOVERY_URI = urlJoin(issuer, OIDC_DISCOVERY_PATH);

  let publicKey;

  return function (req, res, next) {
    if (req.method.toLowerCase() === 'options' && !req.header('Authorization')) {
      return next();
    }

    if (!publicKey) {
      async.waterfall(
        [
          callback => request.get(OIDC_DISCOVERY_URI, (err, discoveryResponse) => {
            if (err) {
              return callback(err);
            }

            return callback(null, JSON.parse(discoveryResponse.body).jwks_uri);
          }),
          (jwksUri, callback) => request.get(jwksUri, (err, jwksResponse) => {
            if (err) {
              return callback(err);
            }

            return callback(null, JSON.parse(jwksResponse.body).keys[0].x5c[0]);
          }),
          (x5c, callback) => {
            const x5cFormatted = formatCertificate(x5c);
            const certFilename = path.join(__dirname, 'tmp.crt');

            fs.writeFileSync(certFilename, x5cFormatted, { encoding: 'UTF-8' });
            const parsedKey = x509.parseCert(certFilename);
            const key = new NodeRSA();

            key.importKey({
              n: new Buffer(parsedKey.publicKey.n, 'hex'),
              e: parseInt(parsedKey.publicKey.e, 10)
            }, 'components-public');

            publicKey = key.exportKey('public');

            return callback(null);
          }
        ],
        err => {
          if (err) {
            return res.status(500).send();
          }

          jwtVerify(req, publicKey, errVerify => {
            if (errVerify) {
              return res.status(401).send();
            }

            return next();
          });
        }
      );
    } else {
      jwtVerify(req, publicKey, errVerify => {
        if (errVerify) {
          return res.status(401).send();
        }

        return next();
      });
    }
  };
};

module.exports = verify;
