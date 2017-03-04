'use strict';

const assert = require('assert');
const express = require('express');
const request = require('request');
const x5c = require('../index');
const app = express();
const fakeIssuer = express();

describe('x5c middleware', () => {
  describe('when options are missing', () => {
    it('should return an error', done => {
      try {
        x5c();
      } catch (err) {
        assert.equal('Error: Options are missing.', err.toString());

        return done();
      }
    });
  });

  describe('when issuer option is missing', () => {
    it('should return an error', done => {
      try {
        x5c({});
      } catch (err) {
        assert.equal('Error: issuer option is missing.', err.toString());

        return done();
      }
    });
  });
});
