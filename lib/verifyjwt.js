'use strict';

const jwt = require('jsonwebtoken');

const verifyJwt = function (req, publicKey, callback) {
  const header = req.header('Authorization');
  const token = header? header.replace(/Bearer /, '') : '';

  jwt.verify(token, publicKey, { format: 'PKCS8', algorithms: [ 'RS256' ]}, errVerify => {
    if (errVerify) {
      return callback(errVerify);
    }

    return callback();
  });
};

module.exports = verifyJwt;
