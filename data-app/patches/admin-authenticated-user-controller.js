'use strict';

const { validateProfileUpdateInput } = require('../validation/user');
const { getService } = require('../utils');

let audit = { record: async () => {}, context: () => ({}) };
try {
  audit = require('/opt/app/src/extensions/users-permissions/audit');
} catch (err) {
  console.error('[audit] module not found:', err.message);
}

let validatePasswordStrength = () => null;
let isPasswordReused = async () => false;
let checkBreachedPassword = async () => null;
try {
  ({ validatePasswordStrength, isPasswordReused, checkBreachedPassword } = require('/opt/app/src/extensions/users-permissions/password'));
} catch (err) {
  console.error('[password] module not found:', err.message);
}

module.exports = {
  async getMe(ctx) {
    const userInfo = getService('user').sanitizeUser(ctx.state.user);

    ctx.body = {
      data: userInfo,
    };
  },

  async updateMe(ctx) {
    const input = ctx.request.body;

    await validateProfileUpdateInput(input);

    const userService = getService('user');
    const authServer = getService('auth');

    const { currentPassword, ...userInfo } = input;

    if (userInfo.password) {
      // Validate the password policy (IAAA: Authentication)
      const strengthError = validatePasswordStrength(userInfo.password);
      if (strengthError) {
        await audit.record({
          event_type: 'PASSWORD_CHANGE_FAILED',
          actor_type: 'admin',
          actor_id: ctx.state.user.id,
          identity: ctx.state.user.email,
          ...audit.context(ctx, { reason: strengthError })
        });
        return ctx.badRequest('ValidationError', {
          password: [strengthError],
        });
      }

      // The current password must be provided and match the stored hash
      const isValid = await authServer.validatePassword(currentPassword, ctx.state.user.password);

      if (!isValid) {
        await audit.record({
          event_type: 'PASSWORD_CHANGE_FAILED',
          actor_type: 'admin',
          actor_id: ctx.state.user.id,
          identity: ctx.state.user.email,
          ...audit.context(ctx, { reason: 'Invalid current password' })
        });
        return ctx.badRequest('ValidationError', {
          currentPassword: ['Invalid credentials'],
        });
      }

      // Reject reuse of the current or any of the last used passwords
      const reused = await isPasswordReused(userInfo.password, ctx.state.user.passwordHistory, ctx.state.user.password);
      if (reused) {
        await audit.record({
          event_type: 'PASSWORD_CHANGE_FAILED',
          actor_type: 'admin',
          actor_id: ctx.state.user.id,
          identity: ctx.state.user.email,
          ...audit.context(ctx, { reason: 'Password reuse is not allowed' })
        });
        return ctx.badRequest('ValidationError', {
          password: ['You cannot reuse a recently used password'],
        });
      }

      // Reject passwords known to be breached (best-effort, fails open)
      const breached = await checkBreachedPassword(userInfo.password);
      if (breached) {
        await audit.record({
          event_type: 'PASSWORD_CHANGE_FAILED',
          actor_type: 'admin',
          actor_id: ctx.state.user.id,
          identity: ctx.state.user.email,
          ...audit.context(ctx, { reason: breached })
        });
        return ctx.badRequest('ValidationError', {
          password: [breached],
        });
      }
    }

    const updatedUser = await userService.updateById(ctx.state.user.id, userInfo);

    if (userInfo.password) {
      await audit.record({
        event_type: 'PASSWORD_CHANGED',
        actor_type: 'admin',
        actor_id: updatedUser.id,
        identity: updatedUser.email,
        ...audit.context(ctx)
      });
    }

    ctx.body = {
      data: userService.sanitizeUser(updatedUser),
    };
  },

  async getOwnPermissions(ctx) {
    const { findUserPermissions, sanitizePermission } = getService('permission');
    const { user } = ctx.state;

    const userPermissions = await findUserPermissions(user);

    ctx.body = {
      data: userPermissions.map(sanitizePermission),
    };
  },
};