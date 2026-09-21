'use strict';

// Thin app-level wrappers for the users-permissions auth endpoints that are
// implemented in the plugin extension (src/extensions/users-permissions/strapi-server.js).
// Registering them here (instead of patching plugin.routes) guarantees they are
// picked up by the content-api router.
const delegate = name => (ctx) => {
  const authController = strapi.plugin('users-permissions').controller('auth');
  if (!authController || typeof authController[name] !== 'function') {
    return ctx.send({ error: `auth.${name} is not available` }, 500);
  }
  return authController[name](ctx);
};

module.exports = {
  refresh: delegate('refresh'),
  verify: delegate('mfaVerify'),
  enroll: delegate('mfaEnroll'),
  confirm: delegate('mfaConfirm'),
  disable: delegate('mfaDisable'),
};