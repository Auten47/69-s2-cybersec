'use strict';

const dbstore = require('./dbstore');

const THRESHOLD = parseInt(process.env.LOGIN_LOCK_THRESHOLD || '5', 10);
const WINDOW_MS = parseInt(process.env.LOGIN_LOCK_WINDOW_MS || '900000', 10);
const LOCK_MS = parseInt(process.env.LOGIN_LOCK_MS || '900000', 10);

const accountKey = (identifier) => `lock:acct:${String(identifier || '').toLowerCase().trim()}`;

const checkLock = async (identifier) => {
  try {
    return await dbstore.checkLock(accountKey(identifier));
  } catch (err) {
    if (strapi && strapi.log) strapi.log.error('[login-lock] check failed:', err.message);
    return 0;
  }
};

const recordFailure = async (identifier) => {
  try {
    return await dbstore.recordFailure({
      key: accountKey(identifier),
      windowMs: WINDOW_MS,
      threshold: THRESHOLD,
      lockMs: LOCK_MS
    });
  } catch (err) {
    if (strapi && strapi.log) strapi.log.error('[login-lock] record failed:', err.message);
    return 0;
  }
};

const clear = async (identifier) => {
  try {
    await dbstore.clear(accountKey(identifier));
  } catch (err) {
    if (strapi && strapi.log) strapi.log.error('[login-lock] clear failed:', err.message);
  }
};

const resetAll = async () => {
  try {
    await dbstore.resetAll();
  } catch (err) {
    if (strapi && strapi.log) strapi.log.error('[login-lock] resetAll failed:', err.message);
  }
};

module.exports = { checkLock, recordFailure, clear, resetAll, THRESHOLD, WINDOW_MS, LOCK_MS };