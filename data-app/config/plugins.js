module.exports = ({ env }) => ({
  email: {
    config: {
      provider: 'smtp',
      providerOptions: {
        host: env('MAIL_HOST', 'mailhog'),
        port: env.int('MAIL_PORT', 1025),
      },
      settings: {
        defaultFrom: env('MAIL_FROM', 'no-reply@authen.local'),
        defaultReplyTo: env('MAIL_REPLY_TO', 'no-reply@authen.local'),
      },
    },
  },
  'users-permissions': {
    config: {
      jwtSecret: env('JWT_SECRET'),
      jwt: {
        // Numeric envs are treated as seconds to avoid jsonwebtoken's ms() parser.
        expiresIn: (() => {
          const v = env('USER_JWT_EXPIRES_IN', '900');
          return /^\d+$/.test(v) ? parseInt(v, 10) : v;
        })(),
      },
      register: {
        allowedFields: [],
      },
    },
  },
});