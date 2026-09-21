'use strict';

/**
 * Lifecycle callbacks for the `Admin` model.
 */

module.exports = {
  collectionName: 'admin_users',
  info: {
    name: 'User',
    description: '',
    singularName: 'user',
    pluralName: 'users',
    displayName: 'User',
  },
  pluginOptions: {
    'content-manager': {
      visible: false,
    },
    'content-type-builder': {
      visible: false,
    },
  },
  attributes: {
    firstname: {
      type: 'string',
      unique: false,
      minLength: 1,
      configurable: false,
      required: false,
    },
    lastname: {
      type: 'string',
      unique: false,
      minLength: 1,
      configurable: false,
      required: false,
    },
    username: {
      type: 'string',
      unique: false,
      configurable: false,
      required: false,
    },
    email: {
      type: 'email',
      minLength: 6,
      configurable: false,
      required: true,
      unique: true,
      private: true,
    },
    password: {
      type: 'password',
      minLength: 6,
      configurable: false,
      required: false,
      private: true,
      searchable: false,
    },
    resetPasswordToken: {
      type: 'string',
      configurable: false,
      private: true,
      searchable: false,
    },
    resetPasswordTokenHash: {
      type: 'string',
      configurable: false,
      private: true,
      searchable: false,
    },
    resetPasswordTokenExpiry: {
      type: 'datetime',
      configurable: false,
      private: true,
    },
    registrationToken: {
      type: 'string',
      configurable: false,
      private: true,
      searchable: false,
    },
    isActive: {
      type: 'boolean',
      default: false,
      configurable: false,
      private: true,
    },
    roles: {
      configurable: false,
      private: true,
      type: 'relation',
      relation: 'manyToMany',
      inversedBy: 'users',
      target: 'admin::role',
      // FIXME: Allow setting this
      collectionName: 'strapi_users_roles',
    },
    blocked: {
      type: 'boolean',
      default: false,
      configurable: false,
      private: true,
    },
    preferedLanguage: {
      type: 'string',
      configurable: false,
      required: false,
      searchable: false,
    },
    jwtVersion: {
      type: 'integer',
      default: 0,
      configurable: false,
      private: true,
    },
    passwordChangedAt: {
      type: 'datetime',
      configurable: false,
      private: true,
    },
    passwordHistory: {
      type: 'json',
      configurable: false,
      private: true,
    },
    otpSecret: {
      type: 'string',
      configurable: false,
      private: true,
      searchable: false,
    },
    otpEnabled: {
      type: 'boolean',
      default: false,
      configurable: false,
      private: true,
    },
    otpBackupCodes: {
      type: 'json',
      configurable: false,
      private: true,
    },
    otpUpdatedAt: {
      type: 'datetime',
      configurable: false,
      private: true,
    },
  },
  config: {
    attributes: {
      resetPasswordToken: {
        hidden: true,
      },
      resetPasswordTokenHash: {
        hidden: true,
      },
      resetPasswordTokenExpiry: {
        hidden: true,
      },
      registrationToken: {
        hidden: true,
      },
      jwtVersion: {
        hidden: true,
      },
      passwordChangedAt: {
        hidden: true,
      },
      passwordHistory: {
        hidden: true,
      },
      otpSecret: {
        hidden: true,
      },
      otpEnabled: {
        hidden: true,
      },
      otpBackupCodes: {
        hidden: true,
      },
      otpUpdatedAt: {
        hidden: true,
      },
    },
  },
};