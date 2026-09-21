'use strict';
const passport = require('koa-passport');
const compose = require('koa-compose');
const jwt = require('jsonwebtoken');
const { ApplicationError, ValidationError } = require('@strapi/utils').errors;
const { getService } = require('../utils');
const { validateRegistrationInput, validateAdminRegistrationInput, validateRegistrationInfoQuery, validateForgotPasswordInput, validateResetPasswordInput, validateRenewTokenInput } = require('../validation/authentication');

let audit = { record: async () => {}, context: () => ({}) };
try {
  audit = require('/opt/app/src/extensions/users-permissions/audit');
} catch (err) {
  console.error('[audit] module not found:', err.message);
}

let validatePasswordStrength = () => null;
let checkBreachedPassword = async () => null;
try {
  ({ validatePasswordStrength, checkBreachedPassword } = require('/opt/app/src/extensions/users-permissions/password'));
} catch (err) {
  console.error('[password] module not found:', err.message);
}

let lock = { checkLock: async () => 0, recordFailure: async () => 0, clear: async () => {} };
try {
  lock = require('/opt/app/src/extensions/users-permissions/login-lock');
} catch (err) {
  console.error('[login-lock] module not found:', err.message);
}

let dbstore = null;
try {
  dbstore = require('/opt/app/src/extensions/users-permissions/dbstore');
} catch (err) {
  console.error('[dbstore] module not found:', err.message);
}

let otp = null;
try {
  otp = require('/opt/app/src/extensions/users-permissions/otp');
} catch (err) {
  console.error('[otp] module not found:', err.message);
}

// I1: equalize login timing so an email with no matching account spends the
// same CPU time as a real bcrypt verification (prevents account enumeration
// through response-time measurement).
let dummyLoginHash = null;
const dummyLoginWork = async () => {
  if (!dummyLoginHash) {
    dummyLoginHash = await hashPassword(crypto.randomBytes(16).toString('hex'));
  }
  await validatePassword(crypto.randomBytes(16).toString('hex'), dummyLoginHash);
};

const signAdminMfa = (user) => {
  const { secret, options } = getService('token').getTokenOptions();
  return jwt.sign({ id: user.id, mfa: true, type: 'admin' }, secret, { ...options, expiresIn: '5m' });
};

const verifyAdminMfa = (token) => {
  try {
    const { secret } = getService('token').getTokenOptions();
    const payload = jwt.verify(token, secret);
    if (!payload || payload.mfa !== true || payload.type !== 'admin' || !payload.id) return null;
    return payload;
  } catch (err) {
    return null;
  }
};

const isDuplicateError = (err) => {
  const msg = (err && err.message) || '';
  return /already taken|already exists|duplicate|must be unique|unique constraint/i.test(msg) ||
    (err && (err.code === 23505 || (err.details && err.details.code === 23505)));
};

module.exports = {
  login: compose([async (ctx, next) => {
    const rawEmail = ((ctx.request.body || {}).email || '').trim().toLowerCase();

    // M4: the failure counter is only maintained for registered admin
    // accounts (prevents pre-locking identifiers that have no account).
    let adminAcct = null;
    if (rawEmail) {
      adminAcct = await strapi.query('admin::user').findOne({ where: { email: rawEmail } });
    }
    const lockSubject = adminAcct ? adminAcct.email : null;

    // I1: emails that map to no admin account must still spend the same CPU
    // time as a real bcrypt verification, otherwise the response time reveals
    // account existence (enumeration oracle).
    if (!adminAcct && rawEmail) {
      await dummyLoginWork();
    }

    if (lockSubject && (await lock.checkLock(lockSubject)) > 0) {
      await audit.record({
        event_type: 'LOGIN_FAILED',
        actor_type: 'admin',
        identity: rawEmail,
        ...audit.context(ctx, { reason: 'Account temporarily locked' })
      });
      ctx.status = 429;
      ctx.body = { error: 'Too many failed attempts. Please try again later.' };
      return;
    }

    let outcome = null;

    await new Promise((resolve, reject) => {
      passport.authenticate('local', { session: false }, (err, user, info) => {
        if (err) {
          strapi.eventHub.emit('admin.auth.error', { error: err, provider: 'local' });
          outcome = { err };
          return resolve();
        }
        if (!user) {
          strapi.eventHub.emit('admin.auth.error', { error: new Error(info.message), provider: 'local' });
          outcome = { info };
          return resolve();
        }
        strapi.eventHub.emit('admin.auth.success', { user: getService('user').sanitizeUser(user), provider: 'local' });
        ctx.state.user = user;
        outcome = { user };
        return resolve();
      })(ctx, next).catch((e) => {
        outcome = { err: e };
        resolve();
      });
    });

    if (outcome.err) {
      if (outcome.err.details && outcome.err.details.code === 'LOGIN_NOT_ALLOWED') {
        await audit.record({
          event_type: 'LOGIN_FAILED',
          actor_type: 'admin',
          identity: (ctx.request.body || {}).email,
          ...audit.context(ctx, { reason: outcome.err.message, code: outcome.err.details.code })
        });
        throw outcome.err;
      }
      return ctx.notImplemented();
    }

    if (!outcome.user) {
      if (lockSubject) {
        await lock.recordFailure(lockSubject);
      }
      await audit.record({
        event_type: 'LOGIN_FAILED',
        actor_type: 'admin',
        identity: rawEmail,
        ...audit.context(ctx, { reason: outcome.info.message })
      });
      throw new ApplicationError(outcome.info.message);
    }

    await lock.clear(ctx.state.user.email);

    // I1: admin MFA challenge after a valid password.
    if (ctx.state.user.otpEnabled) {
      // M3: a hard-locked admin cannot refresh the MFA challenge by logging
      // in again until the lock expires.
      if (dbstore) {
        const mfaLockMs = await dbstore.checkLock(`mfalock:adm:${ctx.state.user.id}`);
        if (mfaLockMs > 0) {
          await audit.record({
            event_type: 'LOGIN_FAILED',
            actor_type: 'admin',
            actor_id: ctx.state.user.id,
            identity: ctx.state.user.email,
            ...audit.context(ctx, { reason: 'MFA account temporarily locked' })
          });
          ctx.status = 429;
          ctx.body = { error: 'MFA temporarily locked. Try again later.' };
          return;
        }
      }
      ctx.state.mfaPending = ctx.state.user;
      await audit.record({
        event_type: 'MFA_CHALLENGE_REQUIRED',
        actor_type: 'admin',
        actor_id: ctx.state.user.id,
        identity: ctx.state.user.email,
        ...audit.context(ctx, { reason: 'OTP required' })
      });
      return next();
    }

    await audit.record({
      event_type: 'LOGIN_SUCCESS',
      actor_type: 'admin',
      actor_id: ctx.state.user.id,
      identity: ctx.state.user.email,
      ...audit.context(ctx)
    });

    return next();
  }, (ctx) => {
    if (ctx.state.mfaPending) {
      ctx.body = { data: { mfaRequired: true, mfaToken: signAdminMfa(ctx.state.mfaPending) } };
      return;
    }
    ctx.body = { data: { token: getService('token').createJwtToken(ctx.state.user), user: getService('user').sanitizeUser(ctx.state.user) } };
  }]),

  async mfaVerify(ctx) {
    const { mfaToken, code } = ctx.request.body || {};
    if (!otp) throw new ApplicationError('MFA is not available.');

    const payload = verifyAdminMfa(mfaToken);
    if (!payload) {
      await audit.record({
        event_type: 'MFA_FAILED',
        actor_type: 'admin',
        identity: (ctx.request.body || {}).email,
        ...audit.context(ctx, { reason: 'Invalid or expired MFA token' })
      });
      throw new ValidationError('Invalid or expired MFA token');
    }

    const user = await strapi.query('admin::user').findOne({ where: { id: payload.id } });
    if (!user || user.isActive !== true || user.blocked || !user.otpEnabled) {
      throw new ValidationError('Invalid or expired MFA token');
    }

    try {
      const { blocked } = await dbstore.hit({ key: `mfa:admin:${user.id}`, windowMs: 300000, max: 5 });
      if (blocked) {
        // M3: hitting the per-window MFA cap escalates to a hard account lock
        // that blocks even a correct password until it expires (prevents
        // re-login from refreshing the MFA challenge token).
        for (let i = 0; i < lock.THRESHOLD; i++) {
          await dbstore.recordFailure({
            key: `mfalock:adm:${user.id}`,
            windowMs: lock.WINDOW_MS,
            threshold: lock.THRESHOLD,
            lockMs: lock.LOCK_MS
          });
        }
        await audit.record({
          event_type: 'MFA_FAILED',
          actor_type: 'admin',
          actor_id: user.id,
          identity: user.email,
          ...audit.context(ctx, { reason: 'Too many MFA attempts' })
        });
        ctx.status = 429;
        ctx.body = { error: 'Too many attempts. Please try again later.' };
        return;
      }
    } catch (err) {
      console.error('[mfa] attempt counter failed:', err.message);
    }

    const backupRemaining = otp && otp.consumeBackupCode(user.otpBackupCodes, code);
    const totpValid = user.otpSecret && otp.verifyTOTP(user.otpSecret, code);
    if (!backupRemaining && !totpValid) {
      await audit.record({
        event_type: 'MFA_FAILED',
        actor_type: 'admin',
        actor_id: user.id,
        identity: user.email,
        ...audit.context(ctx, { reason: 'Invalid MFA code' })
      });
      throw new ValidationError('Invalid MFA code');
    }

    if (backupRemaining) {
      await strapi.query('admin::user').update({ where: { id: user.id }, data: { otpBackupCodes: backupRemaining } });
    }

    await lock.clear(user.email);
    if (dbstore) {
      await dbstore.clear(`mfalock:adm:${user.id}`);
    }
    await audit.record({
      event_type: 'LOGIN_SUCCESS',
      actor_type: 'admin',
      actor_id: user.id,
      identity: user.email,
      ...audit.context(ctx, { via: 'mfa' })
    });

    ctx.body = { data: { token: getService('token').createJwtToken(user), user: getService('user').sanitizeUser(user) } };
  },

  async mfaEnroll(ctx) {
    if (!otp) throw new ApplicationError('MFA is not available.');
    const user = ctx.state.user;
    if (user.otpEnabled) throw new ApplicationError('MFA is already enabled for this account.');
    const secret = otp.generateSecret();
    const account = user.email;
    const otpauth = otp.otpauthUrl(secret, account, process.env.MFA_ISSUER || 'Authen-IAM');
    ctx.body = { data: { secret, otpauth } };
  },

  async mfaConfirm(ctx) {
    if (!otp) throw new ApplicationError('MFA is not available.');
    const user = ctx.state.user;
    if (user.otpEnabled) throw new ApplicationError('MFA is already enabled for this account.');
    const { secret, code } = ctx.request.body || {};

    if (!otp.verifyTOTP(secret, code)) {
      await audit.record({
        event_type: 'MFA_FAILED',
        actor_type: 'admin',
        actor_id: user.id,
        identity: user.email,
        ...audit.context(ctx, { reason: 'Invalid MFA code during enrollment' })
      });
      throw new ValidationError('Invalid MFA code');
    }

    const codes = otp.newBackupCodes(parseInt(process.env.MFA_BACKUP_CODE_COUNT || '8', 10));
    const hashes = otp.hashCodes(codes);

    await strapi.query('admin::user').update({
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
      actor_type: 'admin',
      actor_id: user.id,
      identity: user.email,
      ...audit.context(ctx)
    });

    ctx.body = { data: { mfaEnabled: true, backupCodes: codes } };
  },

  async mfaDisable(ctx) {
    if (!otp) throw new ApplicationError('MFA is not available.');
    const user = ctx.state.user;
    if (!user.otpEnabled) throw new ApplicationError('MFA is not enabled for this account.');

    const { currentPassword, code } = ctx.request.body || {};
    const authService = getService('auth');
    const validPassword = await authService.validatePassword(currentPassword || '', user.password);
    if (!validPassword) throw new ValidationError('The provided current password is invalid');

    const backupRemaining = otp.consumeBackupCode(user.otpBackupCodes, code);
    const totpValid = user.otpSecret && otp.verifyTOTP(user.otpSecret, code);
    if (!backupRemaining && !totpValid) {
      await audit.record({
        event_type: 'MFA_FAILED',
        actor_type: 'admin',
        actor_id: user.id,
        identity: user.email,
        ...audit.context(ctx, { reason: 'Invalid MFA code during disable' })
      });
      throw new ValidationError('Invalid MFA code');
    }

    await strapi.query('admin::user').update({
      where: { id: user.id },
      data: { otpSecret: null, otpEnabled: false, otpBackupCodes: null, otpUpdatedAt: null }
    });

    await audit.record({
      event_type: 'MFA_DISABLED',
      actor_type: 'admin',
      actor_id: user.id,
      identity: user.email,
      ...audit.context(ctx)
    });

    ctx.body = { data: { mfaEnabled: false } };
  },

  async renewToken(ctx) {
    await validateRenewTokenInput(ctx.request.body);
    const { token } = ctx.request.body;
    const { isValid, payload } = getService('token').decodeJwtToken(token);
    if (!isValid) throw new ValidationError('Invalid token');
    const user = await strapi.query('admin::user').findOne({ where: { id: payload.id }, populate: ['roles'] });
    if (!user || !(user.isActive === true)) throw new ValidationError('Invalid token');
    if ((payload.jwtVersion || 0) !== (user.jwtVersion || 0)) throw new ValidationError('Invalid token');

    // IAAA: bound how often a single admin session may extend its token.
    try {
      const { blocked } = await dbstore.hit({ key: `renew:admin:${user.id}`, windowMs: 15 * 60 * 1000, max: 3 });
      if (blocked) {
        ctx.status = 429;
        ctx.body = { error: 'Too many token renewals. Please log in again.' };
        return;
      }
    } catch (err) {
      console.error('[renew] counter failed:', err.message);
    }

    ctx.body = { data: { token: getService('token').createJwtToken(user) } };
  },

  async registrationInfo(ctx) {
    await validateRegistrationInfoQuery(ctx.request.query);
    const { registrationToken } = ctx.request.query;
    const info = await getService('user').findRegistrationInfo(registrationToken);
    if (!info) throw new ValidationError('Invalid registrationToken');
    ctx.body = { data: info };
  },

  async register(ctx) {
    const input = ctx.request.body;
    await validateRegistrationInput(input);
    const strengthError = validatePasswordStrength(input.password);
    if (strengthError) throw new ValidationError(strengthError);
    const breached = await checkBreachedPassword(input.password);
    if (breached) throw new ValidationError(breached);

    await audit.record({
      event_type: 'ADMIN_REGISTER_REQUESTED',
      actor_type: 'admin',
      identity: input.email,
      ...audit.context(ctx)
    });

    try {
      const user = await getService('user').register(input);
      await audit.record({
        event_type: 'ADMIN_REGISTERED',
        actor_type: 'admin',
        actor_id: user.id,
        identity: user.email,
        ...audit.context(ctx)
      });
      ctx.body = { data: { token: getService('token').createJwtToken(user), user: getService('user').sanitizeUser(user) } };
    } catch (err) {
      if (isDuplicateError(err)) {
        await audit.record({
          event_type: 'ADMIN_REGISTER_FAILED',
          actor_type: 'admin',
          identity: input.email,
          ...audit.context(ctx, { reason: 'Email or Username are already taken' })
        });
        const dup = new Error('Email or Username are already taken');
        dup.name = 'ValidationError';
        dup.status = 400;
        throw dup;
      }
      throw err;
    }
  },

  async registerAdmin(ctx) {
    const input = ctx.request.body;
    await validateAdminRegistrationInput(input);
    const strengthError = validatePasswordStrength(input.password);
    if (strengthError) throw new ValidationError(strengthError);
    const breached = await checkBreachedPassword(input.password);
    if (breached) throw new ValidationError(breached);
    const hasAdmin = await getService('user').exists();
    if (hasAdmin) throw new ApplicationError('You cannot register a new super admin');
    const superAdminRole = await getService('role').getSuperAdmin();
    if (!superAdminRole) throw new ApplicationError("Cannot register the first admin because the super admin role doesn't exist.");
    const user = await getService('user').create({ ...input, registrationToken: null, isActive: true, roles: superAdminRole ? [superAdminRole.id] : [] });
    strapi.telemetry.send('didCreateFirstAdmin');
    await audit.record({
      event_type: 'ADMIN_REGISTERED',
      actor_type: 'admin',
      actor_id: user.id,
      identity: user.email,
      ...audit.context(ctx, { superAdmin: true })
    });
    ctx.body = { data: { token: getService('token').createJwtToken(user), user: getService('user').sanitizeUser(user) } };
  },

  async forgotPassword(ctx) {
    const input = ctx.request.body;
    await validateForgotPasswordInput(input);

    // A3: per-account throttle (one password-reset email per minute).
    if (dbstore) {
      const throttledKey = `forgot:admin:${String(input.email || '').trim().toLowerCase()}`;
      const isThrottled = await dbstore.throttled(throttledKey, 60000);
      if (isThrottled) {
        await audit.record({
          event_type: 'PASSWORD_RESET_REQUESTED',
          actor_type: 'admin',
          identity: input.email,
          ...audit.context(ctx, { status: 'throttled' })
        });
        ctx.status = 204;
        return;
      }
    }

    const result = await getService('auth').forgotPassword(input);
    await audit.record({
      event_type: 'PASSWORD_RESET_REQUESTED',
      actor_type: 'admin',
      identity: input.email,
      ...audit.context(ctx, { status: result ? 'sent' : 'no_account' })
    });
    ctx.status = 204;
  },

  async resetPassword(ctx) {
    const input = ctx.request.body;
    await validateResetPasswordInput(input);

    const strengthError = validatePasswordStrength(input.password);
    if (strengthError) {
      await audit.record({
        event_type: 'PASSWORD_RESET_FAILED',
        actor_type: 'admin',
        ...audit.context(ctx, { reason: strengthError })
      });
      throw new ValidationError(strengthError);
    }

    let user;
    try {
      user = await getService('auth').resetPassword(input);
    } catch (err) {
      await audit.record({
        event_type: 'PASSWORD_RESET_FAILED',
        actor_type: 'admin',
        ...audit.context(ctx, { reason: err.message })
      });
      throw err;
    }
    await audit.record({
      event_type: 'PASSWORD_RESET',
      actor_type: 'admin',
      actor_id: user.id,
      identity: user.email,
      ...audit.context(ctx)
    });
    ctx.body = { data: { token: getService('token').createJwtToken(user), user: getService('user').sanitizeUser(user) } };
  },

  async logout(ctx) {
    ctx.state.user = null;
    ctx.body = { data: null };
  },
};