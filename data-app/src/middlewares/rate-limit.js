'use strict';

const dbstore = require('../extensions/users-permissions/dbstore');

const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || (15 * 60 * 1000), 10);
const RATE_LIMIT_MAX_BY_PATH = {
  default: 5,
  '/admin/users/me': 10,
};

const RATE_LIMITED_PATHS = [
  '/admin/login',
  '/admin/register-admin',
  '/admin/forgot-password',
  '/admin/reset-password',
  '/admin/users/me',
  '/admin/mfa/verify',
  '/api/auth/local',
  '/api/auth/local/register',
  '/api/auth/forgot-password',
  '/api/auth/reset-password',
  '/api/auth/change-password',
  '/api/auth/refresh',
  '/api/auth/mfa/verify'
];

module.exports = () => {
  return async (ctx, next) => {
    const isAuthPath = RATE_LIMITED_PATHS.some(path => ctx.path === path || ctx.path.startsWith(path + '/'));

    if (isAuthPath) {
      const clientIP = ctx.request.ip || ctx.request.socket.remoteAddress;
      const key = `auth:${clientIP}:${ctx.path}`;

      try {
        const { blocked } = await dbstore.hit({
          key,
          windowMs: RATE_LIMIT_WINDOW_MS,
          max: RATE_LIMIT_MAX_BY_PATH[ctx.path] || RATE_LIMIT_MAX_BY_PATH.default
        });

        if (blocked) {
          ctx.status = 429;
          ctx.body = { error: 'Too many requests. Please try again later.' };
          ctx.set('Retry-After', String(Math.ceil(RATE_LIMIT_WINDOW_MS / 1000)));
          return;
        }
      } catch (err) {
        strapi.log.error('[rate-limit] check failed:', err.message);
      }
    }

    await next();
  };
};