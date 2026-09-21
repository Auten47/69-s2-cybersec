'use strict';

const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const PASSWORD_MIN_LENGTH = 8;
// bcrypt only uses the first 72 bytes of the input; silently letting longer
// passwords through would truncate them into equivalent secrets (two distinct
// passwords sharing the first 72 bytes would become the same password).
const PASSWORD_MAX_LENGTH = 128;
const PASSWORD_MAX_BYTES = 72;
const PASSWORD_HISTORY_LIMIT = 5;
const PASSWORD_MAX_AGE_DAYS = parseInt(process.env.PASSWORD_MAX_AGE_DAYS || '180', 10);
const BREACH_CHECK_ENABLED = (process.env.ENABLE_BREACH_CHECK || 'true') === 'true';
const BREACH_CHECK_TIMEOUT_MS = parseInt(process.env.BREACH_CHECK_TIMEOUT_MS || '2000', 10);
// IAAA: fail closed - when the breach service is unreachable, reject the password
// instead of silently accepting it.
const BREACH_CHECK_FAIL_CLOSED = (process.env.BREACH_CHECK_FAIL_CLOSED || 'true') === 'true';

const UNAVAILABLE_MESSAGE =
  'Unable to verify this password against known breach databases. Please try again later.';

const EXPIRED_MESSAGE =
  'Password has expired. Please reset it using the Forgot password flow.';

const validatePasswordStrength = (password) => {
  if (typeof password !== 'string' || password.length < PASSWORD_MIN_LENGTH) {
    return `Password must be at least ${PASSWORD_MIN_LENGTH} characters long`;
  }
  if (Buffer.byteLength(password, 'utf8') > PASSWORD_MAX_BYTES) {
    return `Password must not exceed ${PASSWORD_MAX_BYTES} bytes (bcrypt limit)`;
  }
  if (password.length > PASSWORD_MAX_LENGTH) {
    return `Password must not exceed ${PASSWORD_MAX_LENGTH} characters`;
  }
  if (!/[A-Z]/.test(password)) return 'Password must contain at least one uppercase letter';
  if (!/[a-z]/.test(password)) return 'Password must contain at least one lowercase letter';
  if (!/[0-9]/.test(password)) return 'Password must contain at least one number';
  if (!/[^A-Za-z0-9]/.test(password)) return 'Password must contain at least one special character';
  return null;
};

const sha256hex = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');

const pushPasswordHistory = (history, latestHash) => {
  const list = Array.isArray(history) ? history : [];
  return [latestHash, ...list].slice(0, PASSWORD_HISTORY_LIMIT);
};

const isPasswordReused = async (candidate, history, currentHash) => {
  const list = [];
  if (currentHash) list.push(currentHash);
  if (Array.isArray(history)) list.push(...history);
  for (const hash of list) {
    if (hash && (await bcrypt.compare(candidate, hash))) return true;
  }
  return false;
};

const isPasswordExpired = (passwordChangedAt) => {
  if (!passwordChangedAt) return false;
  const changedAt = new Date(passwordChangedAt).getTime();
  if (Number.isNaN(changedAt)) return false;
  const maxAgeMs = PASSWORD_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;
  return Date.now() - changedAt > maxAgeMs;
};

const checkBreachedPassword = async (password) => {
  if (!BREACH_CHECK_ENABLED) return null;
  if (typeof password !== 'string' || !password) return null;
  try {
    const sh1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = sh1.slice(0, 5);
    const suffix = sh1.slice(5);
    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = controller ? setTimeout(() => controller.abort(), BREACH_CHECK_TIMEOUT_MS) : null;
    try {
      const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { 'Add-Padding': 'true' },
        signal: controller ? controller.signal : undefined
      });
      if (!res.ok) {
        throw new Error(`breach check upstream returned ${res.status}`);
      }
      const text = await res.text();
      const found = text.split(/\r?\n/).some((line) => line.split(':')[0] === suffix);
      return found
        ? 'This password is known to be used in data breaches. Please choose a different password.'
        : null;
    } finally {
      if (timer) clearTimeout(timer);
    }
  } catch (err) {
    strapi && strapi.log && strapi.log.warn('[password] breach check failed:', err && err.message);
    if (BREACH_CHECK_FAIL_CLOSED) return UNAVAILABLE_MESSAGE;
    return null;
  }
};

module.exports = {
  validatePasswordStrength,
  sha256hex,
  pushPasswordHistory,
  isPasswordReused,
  isPasswordExpired,
  checkBreachedPassword,
  PASSWORD_MIN_LENGTH,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MAX_BYTES,
  PASSWORD_HISTORY_LIMIT,
  PASSWORD_MAX_AGE_DAYS,
  EXPIRED_MESSAGE
};