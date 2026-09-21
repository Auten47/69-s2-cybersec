'use strict';
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const _ = require('lodash');
const { getAbsoluteAdminUrl } = require('@strapi/utils');
const { ApplicationError } = require('@strapi/utils').errors;
const { getService } = require('../utils');

const SALT_ROUNDS = 12;
const TOKEN_EXPIRY_MINUTES = 15;
const NORMALIZED_DELAY_MS = 500;

const hashPassword = (password) => bcrypt.hash(password, SALT_ROUNDS);
const validatePassword = (password, hash) => bcrypt.compare(password, hash);
const hashToken = (token) => bcrypt.hash(token, SALT_ROUNDS);
const validateToken = (token, hash) => bcrypt.compare(token, hash);

const sha256hex = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');

let pw = {
  sha256hex,
  pushPasswordHistory: () => [],
  isPasswordReused: async () => false,
  isPasswordExpired: () => false,
  checkBreachedPassword: async () => null,
  EXPIRED_MESSAGE: 'Password expired'
};
try {
  ({ ...pw } = { ...pw, ...require('/opt/app/src/extensions/users-permissions/password') });
} catch (err) {
  strapi && strapi.log && strapi.log.error('[auth] shared password module not found:', err.message);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const dummyForgotPasswordWork = async () => {
  await bcrypt.hash(crypto.randomBytes(8).toString('hex'), SALT_ROUNDS);
  await sleep(NORMALIZED_DELAY_MS);
};

const checkCredentials = async ({ email, password }) => {
  const user = await strapi.query('admin::user').findOne({ where: { email } });
  if (!user || !user.password) return [null, false, { message: 'Invalid credentials' }];
  const isValid = await validatePassword(password, user.password);
  if (!isValid) return [null, false, { message: 'Invalid credentials' }];
  if (!(user.isActive === true)) return [null, false, { message: 'User not active' }];
  if (user.blocked) return [null, false, { message: 'User blocked' }];
  if (pw.isPasswordExpired(user.passwordChangedAt)) {
    return [null, false, { message: pw.EXPIRED_MESSAGE }];
  }
  return [null, user];
};

const forgotPassword = async ({ email } = {}) => {
  const startedAt = Date.now();
  const user = await strapi.query('admin::user').findOne({ where: { email, isActive: true } });
  if (!user) {
    await dummyForgotPasswordWork();
    return;
  }
  const resetPasswordToken = getService('token').createToken();
  const resetPasswordTokenExpiry = new Date(Date.now() + TOKEN_EXPIRY_MINUTES * 60 * 1000);
  const hashedToken = await hashToken(resetPasswordToken);
  await getService('user').updateById(user.id, {
    resetPasswordToken: hashedToken,
    resetPasswordTokenHash: sha256hex(resetPasswordToken),
    resetPasswordTokenExpiry
  });

  const publicUrl = process.env.PUBLIC_URL || `http://localhost:${process.env.APP_PORT || 9092}`;
  const resetPageUrl = `${publicUrl}/admin/reset-password`;

  await strapi.plugin('email').service('email').send({
    to: user.email,
    subject: 'Password reset request',
    text: `You requested to reset your password.\n\nYour one-time reset code (expires in ${TOKEN_EXPIRY_MINUTES} minutes):\n\n${resetPasswordToken}\n\nOpen the reset page below and use the code above to set a new password:\n${resetPageUrl}\n\nIf you did not request this, please ignore this email.`,
    html: `<p>You requested to reset your password.</p><p>Your one-time reset code (expires in ${TOKEN_EXPIRY_MINUTES} minutes):</p><p><strong style="font-size:24px;letter-spacing:2px">${resetPasswordToken}</strong></p><p>Open the reset page and enter the code:</p><p><a href="${resetPageUrl}">Go to reset password</a></p><p>If you did not request this, please ignore this email.</p>`
  });

  // Flatten response time: never leak account existence through request duration.
  const elapsed = Date.now() - startedAt;
  if (elapsed < NORMALIZED_DELAY_MS) await sleep(NORMALIZED_DELAY_MS - elapsed);

  return { email: user.email };
};

const resetPassword = async ({ resetPasswordToken, password } = {}) => {
  // Indexed lookup on the derived hash avoids scanning every user with a bcrypt compare.
  const matchingUser = await strapi.query('admin::user').findOne({
    where: { resetPasswordTokenHash: sha256hex(resetPasswordToken), isActive: true }
  });

  if (!matchingUser || !matchingUser.resetPasswordToken) {
    throw new ApplicationError('Invalid or expired reset token');
  }

  const tokenValid = await validateToken(resetPasswordToken, matchingUser.resetPasswordToken);
  if (!tokenValid) throw new ApplicationError('Invalid or expired reset token');

  if (matchingUser.resetPasswordTokenExpiry && new Date(matchingUser.resetPasswordTokenExpiry) < new Date()) {
    throw new ApplicationError('Reset token has expired');
  }

  if (await pw.isPasswordReused(password, matchingUser.passwordHistory, matchingUser.password)) {
    throw new ApplicationError('You cannot reuse a recently used password');
  }

  const breached = await pw.checkBreachedPassword(password);
  if (breached) throw new ApplicationError(breached);

  return getService('user').updateById(matchingUser.id, {
    password,
    resetPasswordToken: null,
    resetPasswordTokenHash: null,
    resetPasswordTokenExpiry: null
  });
};

module.exports = { checkCredentials, validatePassword, hashPassword, forgotPassword, resetPassword };
