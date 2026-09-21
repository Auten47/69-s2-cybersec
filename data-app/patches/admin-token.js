'use strict';

const crypto = require('crypto');
const _ = require('lodash');
const jwt = require('jsonwebtoken');

// Numeric seconds for numeric strings (jsonwebtoken treats bare strings as ms()),
// unit strings like '2h' pass through unchanged.
const envExpires = process.env.ADMIN_JWT_EXPIRES_IN;
const defaultJwtOptions = {
  expiresIn: /^\d+$/.test(envExpires || '')
    ? parseInt(envExpires, 10)
    : envExpires || '2h',
};

const getTokenOptions = () => {
  const { options, secret } = strapi.config.get('admin.auth', {});

  return {
    secret,
    options: _.merge(defaultJwtOptions, options),
  };
};

/**
 * Create a random token
 * @returns {string}
 */
const createToken = () => {
  return crypto.randomBytes(20).toString('hex');
};

/**
 * Creates a JWT token for an administration user
 * @param {object} user - admin user
 */
const createJwtToken = (user) => {
  const { options, secret } = getTokenOptions();

  return jwt.sign({ id: user.id, jwtVersion: user.jwtVersion }, secret, options);
};

/**
 * Tries to decode a token an return its payload and if it is valid
 * @param {string} token - a token to decode
 * @return {Object} decodeInfo - the decoded info
 */
const decodeJwtToken = (token) => {
  const { secret } = getTokenOptions();

  try {
    const payload = jwt.verify(token, secret);
    return { payload, isValid: true };
  } catch (err) {
    return { payload: null, isValid: false };
  }
};

/**
 * @returns {void}
 */
const checkSecretIsDefined = () => {
  if (strapi.config.serveAdminPanel && !strapi.config.get('admin.auth.secret')) {
    throw new Error(
      `Missing auth.secret. Please set auth.secret in config/admin.js (ex: you can generate one using Node with \`crypto.randomBytes(16).toString('base64')\`).
For security reasons, prefer storing the secret in an environment variable and read it in config/admin.js. See https://docs.strapi.io/developer-docs/latest/setup-deployment-guides/configurations/optional/environment.html#configuration-using-environment-variables.`
    );
  }
};

module.exports = {
  createToken,
  createJwtToken,
  getTokenOptions,
  decodeJwtToken,
  checkSecretIsDefined,
};