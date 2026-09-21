'use strict';

const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const SALT_ROUNDS = 12;
const TOKEN_EXPIRY_MINUTES = 15;

const hashToken = (token) => bcrypt.hash(token, SALT_ROUNDS);
const validateToken = (token, hash) => bcrypt.compare(token, hash);

let audit = { record: async () => {}, context: () => ({}) };
try {
  audit = require('./audit');
} catch (err) {
  strapi && strapi.log && strapi.log.error('[audit] module not found:', err.message);
}

let lock = { checkLock: async () => 0, recordFailure: async () => 0, clear: async () => {} };
try {
  lock = require('./login-lock');
} catch (err) {
  strapi && strapi.log && strapi.log.error('[login-lock] module not found:', err.message);
}

let dbstore = null;
try {
  dbstore = require('./dbstore');
} catch (err) {
  strapi && strapi.log && strapi.log.error('[dbstore] module not found:', err.message);
}

let otp = null;
try {
  otp = require('./otp');
} catch (err) {
  strapi && strapi.log && strapi.log.error('[otp] module not found:', err.message);
}

let refresh = null;
try {
  refresh = require('./refresh-token');
} catch (err) {
  strapi && strapi.log && strapi.log.error('[refresh-token] module not found:', err.message);
}

let validatePasswordStrength = () => null;
let sha256hex = () => null;
let pushPasswordHistory = () => [];
let isPasswordReused = async () => false;
let isPasswordExpired = () => false;
let checkBreachedPassword = async () => null;
let EXPIRED_MESSAGE = 'Password expired';
try {
  ({
    validatePasswordStrength,
    sha256hex,
    pushPasswordHistory,
    isPasswordReused,
    isPasswordExpired,
    checkBreachedPassword,
    EXPIRED_MESSAGE
  } = require('./password'));
} catch (err) {
  strapi && strapi.log && strapi.log.error('[password] module not found:', err.message);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const NORMALIZED_DELAY_MS = 500;

const dummyForgotPasswordWork = async () => {
  await bcrypt.hash(crypto.randomBytes(8).toString('hex'), SALT_ROUNDS);
  await sleep(NORMALIZED_DELAY_MS);
};

// I1: equalize login timing. A real login verifies the candidate against a
// stored bcrypt hash (cost 12). Unknown identifiers must spend a comparable
// amount of CPU so response time does not reveal whether an account exists.
let dummyLoginHash = null;
const dummyLoginWork = async () => {
  if (!dummyLoginHash) {
    dummyLoginHash = await bcrypt.hash(crypto.randomBytes(16).toString('hex'), SALT_ROUNDS);
  }
  await bcrypt.compare(crypto.randomBytes(16).toString('hex'), dummyLoginHash);
};

module.exports = (plugin) => {
  const upService = (name) => strapi.plugin('users-permissions').service(name);

  // A1: shorter access tokens (default 15 minutes) issued by the core jwt service.
  try {
    const raw = process.env.USER_JWT_EXPIRES_IN || '900';
    const expiresIn = /^\d+$/.test(raw) ? parseInt(raw, 10) : raw;
    const jwtCfg = strapi.config.get('plugin.users-permissions.jwt') || {};
    strapi.config.set('plugin.users-permissions.jwt', {
      ...jwtCfg,
      expiresIn
    });
    if (process.env.JWT_SECRET) {
      strapi.config.set('plugin.users-permissions.jwtSecret', process.env.JWT_SECRET);
    }
  } catch (err) {
    strapi.log.error('[jwt] expiry config update failed:', err.message);
  }

  // C2: retention + integrity housekeeping.
  if (audit && audit.startHousekeeping) {
    try {
      audit.startHousekeeping();
    } catch (err) {
      strapi.log.error('[audit] housekeeping init failed:', err.message);
    }
  }

  const reissueJwtWithVersion = async (tokenUserId) => {
    if (!tokenUserId) return null;
    const fresh = await strapi
      .query('plugin::users-permissions.user')
      .findOne({ where: { id: tokenUserId } });
    if (!fresh) return null;
    return upService('jwt').issue({ id: fresh.id, jwtVersion: fresh.jwtVersion });
  };

  const sanitizeUser = (user) => {
    try {
      const base = upService('user').sanitizeUser(user);
      return { ...base, mfaEnabled: !!(user && user.otpEnabled) };
    } catch (err) {
      return {
        id: user.id,
        username: user.username,
        email: user.email,
        provider: user.provider,
        confirmed: user.confirmed,
        blocked: user.blocked,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        mfaEnabled: !!(user && user.otpEnabled)
      };
    }
  };

  const requireUser = async (ctx) => {
    // upService('jwt').getToken(ctx) already resolves to the verified payload.
    let payload = null;
    try {
      payload = await upService('jwt').getToken(ctx);
    } catch (err) {
      payload = null;
    }
    if (!payload || !payload.id) {
      ctx.status = 401;
      ctx.body = { error: 'Invalid or expired authentication token.' };
      return null;
    }
    const user = await strapi
      .query('plugin::users-permissions.user')
      .findOne({ where: { id: payload.id } });
    if (!user || user.blocked) {
      ctx.status = 401;
      ctx.body = { error: 'Invalid or expired authentication token.' };
      return null;
    }
    // Z2: reject tokens issued before the latest password change (stale
    // sessions), matching up-strategy. Otherwise MFA management endpoints
    // would accept a token that no longer works for any other API call.
    if ((payload.jwtVersion || 0) !== (user.jwtVersion || 0)) {
      ctx.status = 401;
      ctx.body = { error: 'Invalid or expired authentication token.' };
      return null;
    }
    return user;
  };

  const originalCallback = plugin.controllers.auth.callback;

  plugin.controllers.auth.callback = async (ctx, next) => {
    const { identifier } = ctx.request.body || {};

    // M4: resolve the identifier to the registered account so the failure
    // counter is shared between the email and the username form, and never
    // created for identifiers that map to no account (which could otherwise
    // pre-lock a future registration or poison counters).
    let acct = null;
    const idn = String(identifier || '').trim().toLowerCase();
    if (idn) {
      acct = await strapi
        .query('plugin::users-permissions.user')
        .findOne({ where: { email: idn } });
      if (!acct) {
        acct = await strapi
          .query('plugin::users-permissions.user')
          .findOne({ where: { username: identifier } });
      }
    }
    const lockSubject = acct ? acct.email || acct.username || idn : null;

    // I1: identifiers that map to no registered account must still spend the
    // same CPU time as a real bcrypt verification, otherwise the response
    // time reveals account existence (enumeration oracle).
    if (!acct && idn) {
      await dummyLoginWork();
    }

    if (lockSubject && (await lock.checkLock(lockSubject)) > 0) {
      await audit.record({
        event_type: 'LOGIN_FAILED',
        actor_type: 'user',
        identity: identifier,
        ...audit.context(ctx, { reason: 'Account temporarily locked', provider: ctx.params.provider || 'local' })
      });
      ctx.status = 429;
      ctx.body = { error: 'Too many failed attempts. Please try again later.' };
      return { error: 'Too many failed attempts. Please try again later.' };
    }

    try {
      const result = await originalCallback(ctx, next);
      if (result && result.user && !ctx.state.user) {
        ctx.state.user = result.user;
      }
      const authedUser = ctx.state.user || (ctx.body && ctx.body.user) || (result && result.user);

      if (authedUser && authedUser.id) {
        await lock.clear(authedUser.email || authedUser.username);
        const fresh = await strapi
          .query('plugin::users-permissions.user')
          .findOne({ where: { id: authedUser.id } });

        if (fresh && isPasswordExpired(fresh.passwordChangedAt)) {
          await audit.record({
            event_type: 'LOGIN_FAILED',
            actor_type: 'user',
            actor_id: authedUser.id,
            identity: authedUser.email || authedUser.username,
            ...audit.context(ctx, { reason: 'Password expired', provider: ctx.params.provider || 'local' })
          });
          ctx.status = 403;
          ctx.body = { error: EXPIRED_MESSAGE };
          return { error: EXPIRED_MESSAGE };
        }

        // I1: second factor required after a successful password check.
        if (fresh && fresh.otpEnabled) {
          await audit.record({
            event_type: 'MFA_CHALLENGE_REQUIRED',
            actor_type: 'user',
            actor_id: fresh.id,
            identity: fresh.email || fresh.username,
            ...audit.context(ctx, { reason: 'OTP required', provider: ctx.params.provider || 'local' })
          });
          // M3: if the account was hard-locked after MFA brute-force, reject even a
          // valid password (prevents re-login from refreshing the MFA challenge
          // token until the hard lock expires).
          if (dbstore) {
            const mfaLockMs = await dbstore.checkLock(`mfalock:usr:${fresh.id}`);
            if (mfaLockMs > 0) {
              await audit.record({
                event_type: 'LOGIN_FAILED',
                actor_type: 'user',
                actor_id: fresh.id,
                identity: fresh.email || fresh.username,
                ...audit.context(ctx, { reason: 'MFA account temporarily locked' })
              });
              ctx.status = 429;
              ctx.body = { error: 'MFA temporarily locked. Try again later.' };
              return ctx.body;
            }
          }
          const mfaToken = otp
            ? otp.mfaJwt({ id: fresh.id, type: 'user', expiresIn: '5m' })
            : null;
          if (mfaToken) {
            ctx.status = 200;
            ctx.body = { mfaRequired: true, mfaToken };
          } else {
            ctx.status = 500;
            ctx.body = { error: 'MFA configuration error.' };
          }
          return ctx.body;
        }
      }

      if (authedUser) {
        await audit.record({
          event_type: 'LOGIN_SUCCESS',
          actor_type: 'user',
          actor_id: authedUser.id,
          identity: authedUser.email || authedUser.username,
          ...audit.context(ctx, { provider: ctx.params.provider || 'local' })
        });

        if (ctx.body && ctx.body.jwt) {
          const reissued = await reissueJwtWithVersion(authedUser.id);
          if (reissued) ctx.body.jwt = reissued;
          const fresh = await strapi
            .query('plugin::users-permissions.user')
            .findOne({ where: { id: authedUser.id } });
          if (fresh && refresh) {
            ctx.body.refreshToken = await refresh.issue('user', fresh.id);
            ctx.body.mfaEnabled = !!(fresh.otpEnabled);
          }
          if (fresh && fresh.otpEnabled) {
            ctx.body.user = { ...(ctx.body.user || {}), mfaEnabled: true };
          }
        }
      }
      return result;
    } catch (err) {
      const msg = (err && err.message) || '';
      const isCredentialFailure =
        (err && (err.status === 401 || err.statusCode === 401 || err.name === 'UnauthorizedError')) ||
        (err && err.name === 'ValidationError' && /^Invalid (identifier|credentials)/.test(msg));
      if (isCredentialFailure) {
        // M4: only registered accounts accumulate lockout failures.
        if (lockSubject) {
          await lock.recordFailure(lockSubject);
        }
        await audit.record({
          event_type: 'LOGIN_FAILED',
          actor_type: 'user',
          identity: identifier,
          ...audit.context(ctx, { reason: err.message, provider: ctx.params.provider || 'local' })
        });
      }
      throw err;
    }
  };

  const originalRegister = plugin.controllers.auth.register;

  plugin.controllers.auth.register = async (ctx) => {
    const { email, username, password } = ctx.request.body || {};
    const identity = email || username;

    const strengthError = validatePasswordStrength(password);
    if (strengthError) {
      return ctx.send({ error: strengthError }, 400);
    }

    const breached = await checkBreachedPassword(password);
    if (breached) {
      return ctx.send({ error: breached }, 400);
    }

    await audit.record({
      event_type: 'REGISTER_REQUESTED',
      actor_type: 'user',
      identity,
      ...audit.context(ctx)
    });

    try {
      const result = await originalRegister(ctx);

      if (ctx.body && ctx.body.jwt && ctx.body.user) {
        const id = ctx.body.user.id;

        const reissued = await reissueJwtWithVersion(id);
        if (reissued) ctx.body.jwt = reissued;

        const fresh = await strapi
          .query('plugin::users-permissions.user')
          .findOne({ where: { id } });
        if (fresh) {
          if (fresh.password) {
            await strapi
              .query('plugin::users-permissions.user')
              .update({
                where: { id },
                data: {
                  passwordChangedAt: new Date(),
                  passwordHistory: pushPasswordHistory(fresh.passwordHistory, fresh.password)
                }
              });
          }
          if (refresh) {
            ctx.body.refreshToken = await refresh.issue('user', id);
          }
        }

        await audit.record({
          event_type: 'REGISTER_SUCCESS',
          actor_type: 'user',
          actor_id: id,
          identity: (ctx.body.user && ctx.body.user.email) || identity,
          ...audit.context(ctx)
        });
      }

      return result;
    } catch (err) {
      const msg = (err && err.message) || '';
      const isDuplicate =
        /already taken|already exists|duplicate|must be unique/i.test(msg) ||
        (err && err.status === 400 && /(^|\s)(email|username)(\s|$)/i.test(msg));

      let reason = msg;
      if (isDuplicate) {
        // I2: never expose *which* field collided.
        reason = 'Email or Username are already taken';
      }

      await audit.record({
        event_type: 'REGISTER_FAILED',
        actor_type: 'user',
        identity,
        ...audit.context(ctx, { reason })
      });

      if (isDuplicate) {
        const dupErr = new Error(reason);
        dupErr.name = 'ValidationError';
        dupErr.status = 400;
        throw dupErr;
      }
      throw err;
    }
  };

  const originalEmailConfirmation = plugin.controllers.auth.emailConfirmation;

  plugin.controllers.auth.emailConfirmation = async (ctx, next, returnUser) => {
    const result = await originalEmailConfirmation(ctx, next, returnUser);

    if (ctx.body && ctx.body.jwt && ctx.body.user) {
      const reissued = await reissueJwtWithVersion(ctx.body.user.id);
      if (reissued) ctx.body.jwt = reissued;
      if (refresh) {
        ctx.body.refreshToken = await refresh.issue('user', ctx.body.user.id);
      }
    }

    return result;
  };

  plugin.controllers.auth.forgotPassword = async (ctx) => {
    const { email } = ctx.request.body;

    if (!email) {
      return ctx.send({ error: 'Email is required' }, 400);
    }

    // A3: per-account throttle (one password-reset email per minute).
    if (dbstore) {
      const throttledKey = `forgot:${String(email).trim().toLowerCase()}`;
      const isThrottled = await dbstore.throttled(throttledKey, 60000);
      if (isThrottled) {
        await audit.record({
          event_type: 'PASSWORD_RESET_REQUESTED',
          actor_type: 'user',
          identity: email,
          ...audit.context(ctx, { status: 'throttled' })
        });
        ctx.status = 204;
        return;
      }
    }

    const user = await strapi
      .query('plugin::users-permissions.user')
      .findOne({ where: { email: email.toLowerCase() } });

    let status = 'no_account';

    if (user && !user.blocked) {
      // I2: 128-bit (16-byte) reset code - high enough entropy to make
      // offline brute-force infeasible within the 15-minute expiry.
      const resetPasswordToken = crypto.randomBytes(16).toString('hex');
      const resetPasswordTokenExpiry = new Date(Date.now() + TOKEN_EXPIRY_MINUTES * 60 * 1000);
      const hashedToken = await hashToken(resetPasswordToken);

      await strapi
        .query('plugin::users-permissions.user')
        .update({
          where: { id: user.id },
          data: {
            resetPasswordToken: hashedToken,
            resetPasswordTokenHash: sha256hex(resetPasswordToken),
            resetPasswordTokenExpiry
          }
        });

      try {
        await strapi.plugin('email').service('email').send({
          to: user.email,
          subject: 'Password reset request',
          text: `You requested to reset your password.\n\nUse this code to set a new password (it expires in ${TOKEN_EXPIRY_MINUTES} minutes):\n\n${resetPasswordToken}\n\nIf you did not request this, please ignore this email.`,
          html: `<p>You requested to reset your password.</p><p>Use this code to set a new password (it expires in ${TOKEN_EXPIRY_MINUTES} minutes):</p><p><strong style="font-size:24px;letter-spacing:2px">${resetPasswordToken}</strong></p><p>If you did not request this, please ignore this email.</p>`
        });
        status = 'sent';
      } catch (err) {
        await audit.record({
          event_type: 'PASSWORD_RESET_FAILED',
          actor_type: 'user',
          ...audit.context(ctx, { reason: 'Email delivery failed: ' + err.message })
        });
      }
    } else {
      // Equalize response time for unknown accounts (timing-oracle mitigation).
      await dummyForgotPasswordWork();
    }

    await audit.record({
      event_type: 'PASSWORD_RESET_REQUESTED',
      actor_type: 'user',
      actor_id: user ? user.id : null,
      identity: email,
      ...audit.context(ctx, { status })
    });

    ctx.status = 204;
  };

  plugin.controllers.auth.resetPassword = async (ctx) => {
    const { code, password, passwordConfirmation } = ctx.request.body;

    const logFailure = (reason) =>
      audit.record({
        event_type: 'PASSWORD_RESET_FAILED',
        actor_type: 'user',
        ...audit.context(ctx, { reason })
      });

    if (!code || !password || !passwordConfirmation) {
      await logFailure('Missing required fields');
      return ctx.send({ error: 'Code, password and passwordConfirmation are required' }, 400);
    }

    if (password !== passwordConfirmation) {
      await logFailure('Passwords do not match');
      return ctx.send({ error: 'Passwords do not match' }, 400);
    }

    const strengthError = validatePasswordStrength(password);
    if (strengthError) {
      await logFailure(strengthError);
      return ctx.send({ error: strengthError }, 400);
    }

    const matchingUser = await strapi
      .query('plugin::users-permissions.user')
      .findOne({ where: { resetPasswordTokenHash: sha256hex(code) } });

    if (!matchingUser || !matchingUser.resetPasswordToken) {
      await logFailure('Invalid or expired reset token');
      return ctx.send({ error: 'Invalid or expired reset token' }, 400);
    }

    const tokenValid = await validateToken(code, matchingUser.resetPasswordToken);
    if (!tokenValid) {
      await logFailure('Invalid or expired reset token');
      return ctx.send({ error: 'Invalid or expired reset token' }, 400);
    }

    if (matchingUser.resetPasswordTokenExpiry && new Date(matchingUser.resetPasswordTokenExpiry) < new Date()) {
      await logFailure('Reset token has expired');
      return ctx.send({ error: 'Reset token has expired' }, 400);
    }

    if (await isPasswordReused(password, matchingUser.passwordHistory, matchingUser.password)) {
      await logFailure('Password reuse is not allowed');
      return ctx.send({ error: 'You cannot reuse a recently used password' }, 400);
    }

    const breached = await checkBreachedPassword(password);
    if (breached) {
      await logFailure(breached);
      return ctx.send({ error: breached }, 400);
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    await strapi
      .query('plugin::users-permissions.user')
      .update({
        where: { id: matchingUser.id },
        data: {
          password: hashedPassword,
          passwordChangedAt: new Date(),
          passwordHistory: pushPasswordHistory(matchingUser.passwordHistory, hashedPassword),
          resetPasswordToken: null,
          resetPasswordTokenHash: null,
          resetPasswordTokenExpiry: null,
          jwtVersion: (matchingUser.jwtVersion || 0) + 1
        }
      });

    // A1: resetting a password invalidates every previously issued refresh token.
    if (refresh) {
      await refresh.revokeAll('user', matchingUser.id);
    }

    await audit.record({
      event_type: 'PASSWORD_RESET',
      actor_type: 'user',
      actor_id: matchingUser.id,
      identity: matchingUser.email,
      ...audit.context(ctx)
    });

    ctx.body = { data: { message: 'Password has been reset successfully' } };
  };

  plugin.controllers.auth.changePassword = async (ctx) => {
    const { currentPassword, password, passwordConfirmation } = ctx.request.body || {};

    const logFailure = (reason) =>
      audit.record({
        event_type: 'PASSWORD_CHANGE_FAILED',
        actor_type: 'user',
        actor_id: ctx.state.user && ctx.state.user.id,
        identity: (ctx.state.user && ctx.state.user.email) || null,
        ...audit.context(ctx, { reason })
      });

    if (!currentPassword || !password || !passwordConfirmation) {
      await logFailure('Missing required fields');
      return ctx.send({ error: 'Current password, new password and password confirmation are required' }, 400);
    }

    if (password !== passwordConfirmation) {
      await logFailure('Passwords do not match');
      return ctx.send({ error: 'Passwords do not match' }, 400);
    }

    const strengthError = validatePasswordStrength(password);
    if (strengthError) {
      await logFailure(strengthError);
      return ctx.send({ error: strengthError }, 400);
    }

    const user = await strapi
      .query('plugin::users-permissions.user')
      .findOne({ where: { id: ctx.state.user.id } });

    if (!user) {
      return ctx.send({ error: 'User not found' }, 400);
    }

    const validCurrentPassword = user.password
      ? await bcrypt.compare(currentPassword, user.password)
      : false;
    if (!validCurrentPassword) {
      await logFailure('Invalid current password');
      return ctx.send({ error: 'The provided current password is invalid' }, 400);
    }

    if (currentPassword === password) {
      await logFailure('New password must be different from current');
      return ctx.send({ error: 'Your new password must be different than your current password' }, 400);
    }

    if (await isPasswordReused(password, user.passwordHistory, user.password)) {
      await logFailure('Password reuse is not allowed');
      return ctx.send({ error: 'You cannot reuse a recently used password' }, 400);
    }

    const breached = await checkBreachedPassword(password);
    if (breached) {
      await logFailure(breached);
      return ctx.send({ error: breached }, 400);
    }

    const newVersion = (user.jwtVersion || 0) + 1;
    const newHash = await bcrypt.hash(password, SALT_ROUNDS);

    await strapi
      .query('plugin::users-permissions.user')
      .update({
        where: { id: user.id },
        data: {
          password: newHash,
          passwordChangedAt: new Date(),
          passwordHistory: pushPasswordHistory(user.passwordHistory, newHash),
          jwtVersion: newVersion
        }
      });

    // A1: changing a password invalidates all refresh tokens.
    if (refresh) {
      await refresh.revokeAll('user', user.id);
    }

    await audit.record({
      event_type: 'PASSWORD_CHANGED',
      actor_type: 'user',
      actor_id: user.id,
      identity: user.email,
      ...audit.context(ctx)
    });

    const refreshedUser = await strapi
      .query('plugin::users-permissions.user')
      .findOne({ where: { id: user.id }, populate: ['role'] });

    ctx.body = {
      jwt: upService('jwt').issue({ id: refreshedUser.id, jwtVersion: newVersion }),
      user: {
        id: refreshedUser.id,
        username: refreshedUser.username,
        email: refreshedUser.email,
        provider: refreshedUser.provider,
        confirmed: refreshedUser.confirmed,
        blocked: refreshedUser.blocked,
        mfaEnabled: !!(refreshedUser.otpEnabled),
        createdAt: refreshedUser.createdAt,
        updatedAt: refreshedUser.updatedAt
      }
    };

    // A1: the previous refresh tokens were revoked on password change - issue
    // a replacement so the client keeps a working session instead of being
    // forced to log in again.
    if (refresh) {
      ctx.body.refreshToken = await refresh.issue('user', user.id);
    }
  };

  // ---- I1: user MFA endpoints ----

  plugin.controllers.auth.mfaVerify = async (ctx) => {
    const { mfaToken, code } = ctx.request.body || {};
    if (!otp) {
      return ctx.send({ error: 'MFA is not available.' }, 500);
    }

    const payload = otp.verifyMfaJwt(mfaToken, 'user');
    if (!payload || !payload.id) {
      await audit.record({
        event_type: 'MFA_FAILED',
        actor_type: 'user',
        identity: (ctx.request.body || {}).email,
        ...audit.context(ctx, { reason: 'Invalid or expired MFA token' })
      });
      return ctx.send({ error: 'Invalid or expired MFA token' }, 401);
    }

    const user = await strapi
      .query('plugin::users-permissions.user')
      .findOne({ where: { id: payload.id } });
    if (!user || !user.otpEnabled) {
      return ctx.send({ error: 'Invalid or expired MFA token' }, 401);
    }
    if (user.blocked) {
      return ctx.send({ error: 'Account is blocked' }, 403);
    }

    // Limit MFA code attempts to 5 per 5 minutes per user.
    try {
      const { blocked } = await dbstore.hit({ key: `mfa:user:${user.id}`, windowMs: 300000, max: 5 });
      if (blocked) {
        // M3: hitting the per-window MFA cap escalates to a hard account lock
        // that blocks even a correct password until it expires (prevents
        // re-login from refreshing the MFA challenge token).
        for (let i = 0; i < lock.THRESHOLD; i++) {
          await dbstore.recordFailure({
            key: `mfalock:usr:${user.id}`,
            windowMs: lock.WINDOW_MS,
            threshold: lock.THRESHOLD,
            lockMs: lock.LOCK_MS
          });
        }
        await audit.record({
          event_type: 'MFA_FAILED',
          actor_type: 'user',
          actor_id: user.id,
          identity: user.email || user.username,
          ...audit.context(ctx, { reason: 'Too many MFA attempts' })
        });
        return ctx.send({ error: 'Too many attempts. Please try again later.' }, 429);
      }
    } catch (err) {
      strapi.log.error('[mfa] attempt counter failed:', err.message);
    }

    const backupRemaining = otp.consumeBackupCode(user.otpBackupCodes, code);
    const totpValid = user.otpSecret && otp.verifyTOTP(user.otpSecret, code);
    if (!backupRemaining && !totpValid) {
      await audit.record({
        event_type: 'MFA_FAILED',
        actor_type: 'user',
        actor_id: user.id,
        identity: user.email || user.username,
        ...audit.context(ctx, { reason: 'Invalid MFA code', provider: 'local' })
      });
      return ctx.send({ error: 'Invalid MFA code' }, 400);
    }

    if (backupRemaining) {
      await strapi
        .query('plugin::users-permissions.user')
        .update({ where: { id: user.id }, data: { otpBackupCodes: backupRemaining } });
    }

    await lock.clear(user.email || user.username);
    if (dbstore) {
      await dbstore.clear(`mfalock:usr:${user.id}`);
    }
    await audit.record({
      event_type: 'LOGIN_SUCCESS',
      actor_type: 'user',
      actor_id: user.id,
      identity: user.email || user.username,
      ...audit.context(ctx, { provider: 'local', via: 'mfa' })
    });

    const jwtToken = await reissueJwtWithVersion(user.id);
    const refreshToken = refresh ? await refresh.issue('user', user.id) : null;

    ctx.body = { jwt: jwtToken, refreshToken, user: sanitizeUser(user) };
  };

  plugin.controllers.auth.mfaEnroll = async (ctx) => {
    const user = await requireUser(ctx);
    if (!user) return null;
    if (user.otpEnabled) {
      return ctx.send({ error: 'MFA is already enabled for this account.' }, 400);
    }
    const secret = otp.generateSecret();
    const account = user.email || user.username;
    const otpauth = otp.otpauthUrl(secret, account, process.env.MFA_ISSUER || 'Authen-IAM');
    ctx.body = { secret, otpauth };
  };

  plugin.controllers.auth.mfaConfirm = async (ctx) => {
    const user = await requireUser(ctx);
    if (!user) return null;
    if (user.otpEnabled) {
      return ctx.send({ error: 'MFA is already enabled for this account.' }, 400);
    }
    const { secret, code } = ctx.request.body || {};

    if (!otp.verifyTOTP(secret, code)) {
      await audit.record({
        event_type: 'MFA_FAILED',
        actor_type: 'user',
        actor_id: user.id,
        identity: user.email || user.username,
        ...audit.context(ctx, { reason: 'Invalid MFA code during enrollment' })
      });
      return ctx.send({ error: 'Invalid MFA code' }, 400);
    }

    const codes = otp.newBackupCodes(parseInt(process.env.MFA_BACKUP_CODE_COUNT || '8', 10));
    const hashes = otp.hashCodes(codes);

    await strapi
      .query('plugin::users-permissions.user')
      .update({
        where: { id: user.id },
        data: {
          otpSecret: secret,
          otpEnabled: true,
          otpBackupCodes: hashes,
          otpUpdatedAt: new Date()
        }
      });

    await audit.record({
      event_type: 'MFA_ENABLED',
      actor_type: 'user',
      actor_id: user.id,
      identity: user.email || user.username,
      ...audit.context(ctx)
    });

    ctx.body = { mfaEnabled: true, backupCodes: codes };
  };

  plugin.controllers.auth.mfaDisable = async (ctx) => {
    const user = await requireUser(ctx);
    if (!user) return null;
    if (!user.otpEnabled) {
      return ctx.send({ error: 'MFA is not enabled for this account.' }, 400);
    }
    const { currentPassword, code } = ctx.request.body || {};

    const validPassword = user.password
      ? await bcrypt.compare(currentPassword || '', user.password)
      : false;
    if (!validPassword) {
      return ctx.send({ error: 'The provided current password is invalid' }, 400);
    }

    const backupRemaining = otp.consumeBackupCode(user.otpBackupCodes, code);
    const totpValid = user.otpSecret && otp.verifyTOTP(user.otpSecret, code);
    if (!backupRemaining && !totpValid) {
      await audit.record({
        event_type: 'MFA_FAILED',
        actor_type: 'user',
        actor_id: user.id,
        identity: user.email || user.username,
        ...audit.context(ctx, { reason: 'Invalid MFA code during disable' })
      });
      return ctx.send({ error: 'Invalid MFA code' }, 400);
    }

    await strapi
      .query('plugin::users-permissions.user')
      .update({
        where: { id: user.id },
        data: { otpSecret: null, otpEnabled: false, otpBackupCodes: null, otpUpdatedAt: null }
      });

    await audit.record({
      event_type: 'MFA_DISABLED',
      actor_type: 'user',
      actor_id: user.id,
      identity: user.email || user.username,
      ...audit.context(ctx)
    });

    ctx.body = { mfaEnabled: false };
  };

  // ---- A1: refresh token rotation for public users ----

  plugin.controllers.auth.refresh = async (ctx) => {
    const { refreshToken } = ctx.request.body || {};
    if (!refresh) {
      return ctx.send({ error: 'Refresh tokens are not available.' }, 500);
    }
    if (!refreshToken) {
      return ctx.send({ error: 'refreshToken is required' }, 400);
    }

    const consumed = await refresh.consume('user', refreshToken);
    if (!consumed) {
      await audit.record({
        event_type: 'REFRESH_FAILED',
        actor_type: 'user',
        ...audit.context(ctx, { reason: 'Invalid or expired refresh token' })
      });
      return ctx.send({ error: 'Invalid or expired refresh token' }, 401);
    }

    const user = await strapi
      .query('plugin::users-permissions.user')
      .findOne({ where: { id: consumed.userId } });
    if (!user || user.blocked) {
      return ctx.send({ error: 'Invalid or expired refresh token' }, 401);
    }
    if (isPasswordExpired(user.passwordChangedAt)) {
      return ctx.send({ error: EXPIRED_MESSAGE }, 403);
    }

    const newRefreshToken = await refresh.issue('user', user.id);
    const jwtToken = await reissueJwtWithVersion(user.id);

    await audit.record({
      event_type: 'TOKEN_REFRESHED',
      actor_type: 'user',
      actor_id: user.id,
      identity: user.email || user.username,
      ...audit.context(ctx)
    });

    ctx.body = {
      jwt: jwtToken,
      refreshToken: newRefreshToken,
      user: sanitizeUser(user)
    };
  };

  // Expose mfaEnabled through the authenticated /users/me endpoint.
  const originalMe = plugin.controllers.user.me;
  if (originalMe) {
    plugin.controllers.user.me = async (ctx) => {
      await originalMe(ctx);
      if (ctx.body && ctx.body.id) {
        const u = await strapi
          .query('plugin::users-permissions.user')
          .findOne({ where: { id: ctx.body.id } });
        ctx.body = { ...ctx.body, mfaEnabled: !!(u && u.otpEnabled) };
      }
    };
  }

  // Note: the /auth/refresh and /auth/mfa/* endpoints are exposed as app-level
// content-api routes under src/api/auth-plus (plugin.routes patching is not
// reliably honoured by the content-api router).

  return plugin;
};