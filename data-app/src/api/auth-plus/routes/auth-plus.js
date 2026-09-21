'use strict';

module.exports = {
  routes: [
    {
      method: 'POST',
      path: '/auth/refresh',
      handler: 'auth-plus.refresh',
      config: { auth: false },
    },
    {
      method: 'POST',
      path: '/auth/mfa/verify',
      handler: 'auth-plus.verify',
      config: { auth: false },
    },
    {
      method: 'POST',
      path: '/auth/mfa/enroll',
      handler: 'auth-plus.enroll',
      config: { auth: false },
    },
    {
      method: 'POST',
      path: '/auth/mfa/confirm',
      handler: 'auth-plus.confirm',
      config: { auth: false },
    },
    {
      method: 'POST',
      path: '/auth/mfa/disable',
      handler: 'auth-plus.disable',
      config: { auth: false },
    },
  ],
};