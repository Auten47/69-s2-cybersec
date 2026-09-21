'use strict';

/**
 * User.js controller (patched)
 *
 * IAAA hardening on the public user controller:
 *  - PUT /users/:id accepts updates only from the owning account (no third-party edits).
 *  - Changing a password requires the current password, enforces the password policy,
 *    bumps jwtVersion (invalidates other sessions) and audits the change.
 */

const _ = require('lodash');
const bcrypt = require('bcryptjs');
const utils = require('@strapi/utils');
const { getService } = require('../utils');
const { validateCreateUserBody, validateUpdateUserBody } = require('./validation/user');

const { sanitize, validate } = utils;
const { ApplicationError, ValidationError, NotFoundError, ForbiddenError } = utils.errors;

let audit = { record: async () => {}, context: () => ({}) };
try {
  audit = require('/opt/app/src/extensions/users-permissions/audit');
} catch (err) {
  console.error('[audit] module not found:', err.message);
}

let passwordPolicy = {};
try {
  passwordPolicy = require('/opt/app/src/extensions/users-permissions/password');
} catch (err) {
  console.error('[password] module not found:', err.message);
}

const sanitizeOutput = async (user, ctx) => {
  const schema = strapi.getModel('plugin::users-permissions.user');
  const { auth } = ctx.state;

  return sanitize.contentAPI.output(user, schema, { auth });
};

const validateQuery = async (query, ctx) => {
  const schema = strapi.getModel('plugin::users-permissions.user');
  const { auth } = ctx.state;

  return validate.contentAPI.query(query, schema, { auth });
};

const sanitizeQuery = async (query, ctx) => {
  const schema = strapi.getModel('plugin::users-permissions.user');
  const { auth } = ctx.state;

  return sanitize.contentAPI.query(query, schema, { auth });
};

module.exports = {
  /**
   * Create a/an user record.
   * @return {Object}
   */
  async create(ctx) {
    const advanced = await strapi
      .store({ type: 'plugin', name: 'users-permissions', key: 'advanced' })
      .get();

    await validateCreateUserBody(ctx.request.body);

    const { email, username, role } = ctx.request.body;

    try {
      const userWithSameUsername = await strapi
        .query('plugin::users-permissions.user')
        .findOne({ where: { username } });

      if (userWithSameUsername) {
        if (!email) throw new ApplicationError('Username or Email already taken');
      }

      if (advanced.unique_email) {
        const userWithSameEmail = await strapi
          .query('plugin::users-permissions.user')
          .findOne({ where: { email: email.toLowerCase() } });

        if (userWithSameEmail) {
          throw new ApplicationError('Username or Email already taken');
        }
      }

      const user = {
        ...ctx.request.body,
        email: email.toLowerCase(),
        provider: 'local',
      };

      if (!role) {
        const defaultRole = await strapi
          .query('plugin::users-permissions.role')
          .findOne({ where: { type: advanced.default_role } });

        user.role = defaultRole.id;
      }

      const data = await getService('user').add(user);
      const sanitizedData = await sanitizeOutput(data, ctx);

      ctx.created(sanitizedData);
    } catch (error) {
      strapi.log.warn('[user:create] block attempted', error.message);
      throw new ApplicationError('Username or Email already taken');
    }
  },

  /**
   * Update a/an user record. (patched: ownership + password policy)
   * @return {Object}
   */
  async update(ctx) {
    const advancedConfigs = await strapi
      .store({ type: 'plugin', name: 'users-permissions', key: 'advanced' })
      .get();

    const { id } = ctx.params;
    const { email, username, password } = ctx.request.body;

    const user = await getService('user').fetch(id);
    if (!user) {
      throw new NotFoundError(`User not found`);
    }

    // Z2: a user may only update their own account through the public endpoint.
    const currentUser = ctx.state.user;
    if (!currentUser || String(currentUser.id) !== String(user.id)) {
      await audit.record({
        event_type: 'USER_UPDATE_FAILED',
        actor_type: 'user',
        actor_id: currentUser && currentUser.id,
        identity: currentUser && currentUser.email,
        ...audit.context(ctx, { reason: 'Attempted to update another account', targetId: id })
      });
      throw new ForbiddenError('You may only update your own account');
    }

    await validateUpdateUserBody(ctx.request.body);

    if (user.provider === 'local' && _.has(ctx.request.body, 'password') && !password) {
      throw new ValidationError('password.notNull');
    }

    if (_.has(ctx.request.body, 'username')) {
      const userWithSameUsername = await strapi
        .query('plugin::users-permissions.user')
        .findOne({ where: { username } });

      if (userWithSameUsername && _.toString(userWithSameUsername.id) !== _.toString(id)) {
        throw new ApplicationError('Username or Email already taken');
      }
    }

    if (_.has(ctx.request.body, 'email') && advancedConfigs.unique_email) {
      const userWithSameEmail = await strapi
        .query('plugin::users-permissions.user')
        .findOne({ where: { email: email.toLowerCase() } });

      if (userWithSameEmail && _.toString(userWithSameEmail.id) !== _.toString(id)) {
        throw new ApplicationError('Username or Email already taken');
      }
      ctx.request.body.email = ctx.request.body.email.toLowerCase();
    }

    const updateData = _.pick(ctx.request.body, ['email', 'username', 'password']);

    // Password is being changed → require current password + full policy.
    if (_.has(ctx.request.body, 'password') && password) {
      const { currentPassword } = ctx.request.body || {};

      const validCurrent = user.password
        ? await bcrypt.compare(currentPassword || '', user.password)
        : (user.provider !== 'local');
      if (!validCurrent) {
        await audit.record({
          event_type: 'PASSWORD_CHANGE_FAILED',
          actor_type: 'user',
          actor_id: user.id,
          identity: user.email,
          ...audit.context(ctx, { reason: 'Invalid current password', via: 'user-update' })
        });
        return ctx.badRequest('ValidationError', {
          currentPassword: ['The provided current password is invalid'],
        });
      }

      const strengthError = passwordPolicy.validatePasswordStrength
        ? passwordPolicy.validatePasswordStrength(password)
        : null;
      if (strengthError) {
        await audit.record({
          event_type: 'PASSWORD_CHANGE_FAILED',
          actor_type: 'user',
          actor_id: user.id,
          identity: user.email,
          ...audit.context(ctx, { reason: strengthError, via: 'user-update' })
        });
        return ctx.badRequest('ValidationError', { password: [strengthError] });
      }

      if (passwordPolicy.isPasswordReused) {
        const reused = await passwordPolicy.isPasswordReused(password, user.passwordHistory, user.password);
        if (reused) {
          await audit.record({
            event_type: 'PASSWORD_CHANGE_FAILED',
            actor_type: 'user',
            actor_id: user.id,
            identity: user.email,
            ...audit.context(ctx, { reason: 'Password reuse is not allowed', via: 'user-update' })
          });
          return ctx.badRequest('ValidationError', {
            password: ['You cannot reuse a recently used password'],
          });
        }
      }

      if (passwordPolicy.checkBreachedPassword) {
        const breached = await passwordPolicy.checkBreachedPassword(password);
        if (breached) {
          await audit.record({
            event_type: 'PASSWORD_CHANGE_FAILED',
            actor_type: 'user',
            actor_id: user.id,
            identity: user.email,
            ...audit.context(ctx, { reason: breached, via: 'user-update' })
          });
          return ctx.badRequest('ValidationError', { password: [breached] });
        }
      }

      // Invalidate previous access tokens and refresh tokens.
      updateData.jwtVersion = (user.jwtVersion || 0) + 1;
      if (passwordPolicy.sha256hex) {
        const sha256hex = passwordPolicy.sha256hex;
        try {
          const refreshStore = require('/opt/app/src/extensions/users-permissions/refresh-token');
          await refreshStore.revokeAll('user', user.id);
        } catch (err) {
          strapi.log.error('[user:update] refresh revoke failed:', err.message);
        }
      }
    }

    const data = await getService('user').edit(user.id, updateData);
    const sanitizedData = await sanitizeOutput(data, ctx);

    if (_.has(ctx.request.body, 'password') && password) {
      await audit.record({
        event_type: 'PASSWORD_CHANGED',
        actor_type: 'user',
        actor_id: user.id,
        identity: user.email,
        ...audit.context(ctx, { via: 'user-update' })
      });
    }

    await audit.record({
      event_type: 'USER_UPDATED',
      actor_type: 'user',
      actor_id: user.id,
      identity: user.email,
      ...audit.context(ctx, { fields: Object.keys(ctx.request.body || {}) })
    });

    ctx.send(sanitizedData);
  },

  /**
   * Retrieve user records.
   * @return {Object|Array}
   */
  async find(ctx) {
    await validateQuery(ctx.query, ctx);
    const sanitizedQuery = await sanitizeQuery(ctx.query, ctx);
    const users = await getService('user').fetchAll(sanitizedQuery);

    ctx.body = await Promise.all(users.map((user) => sanitizeOutput(user, ctx)));
  },

  /**
   * Retrieve a user record.
   * @return {Object}
   */
  async findOne(ctx) {
    const { id } = ctx.params;
    await validateQuery(ctx.query, ctx);
    const sanitizedQuery = await sanitizeQuery(ctx.query, ctx);

    let data = await getService('user').fetch(id, sanitizedQuery);

    if (data) {
      data = await sanitizeOutput(data, ctx);
    }

    ctx.body = data;
  },

  /**
   * Retrieve user count.
   * @return {Number}
   */
  async count(ctx) {
    await validateQuery(ctx.query, ctx);
    const sanitizedQuery = await sanitizeQuery(ctx.query, ctx);

    ctx.body = await getService('user').count(sanitizedQuery);
  },

  /**
   * Destroy a/an user record.
   * @return {Object}
   */
  async destroy(ctx) {
    const { id } = ctx.params;

    // Safety: prohibit destroying yourself through the public endpoint.
    const currentUser = ctx.state.user;
    if (currentUser && String(currentUser.id) === String(id)) {
      throw new ForbiddenError('You cannot delete your own account through the public endpoint');
    }

    const data = await getService('user').remove({ id });
    const sanitizedUser = await sanitizeOutput(data, ctx);

    ctx.send(sanitizedUser);
  },

  /**
   * Retrieve authenticated user.
   * @return {Object|Array}
   */
  async me(ctx) {
    const authUser = ctx.state.user;
    const { query } = ctx;

    if (!authUser) {
      return ctx.unauthorized();
    }

    await validateQuery(query, ctx);
    const sanitizedQuery = await sanitizeQuery(query, ctx);
    const user = await getService('user').fetch(authUser.id, sanitizedQuery);

    ctx.body = await sanitizeOutput(user, ctx);
  },
};