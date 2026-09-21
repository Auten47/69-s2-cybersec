'use strict';

const crypto = require('crypto');

let ready = false;

const sha256hex = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');

const TTL_DAYS = parseInt(process.env.REFRESH_TOKEN_TTL_DAYS || '30', 10);

const ensure = async () => {
  if (ready) return;
  await strapi.db.connection.raw(
    `CREATE TABLE IF NOT EXISTS refresh_tokens (
      id BIGSERIAL PRIMARY KEY,
      actor_type VARCHAR(16) NOT NULL,
      user_id BIGINT NOT NULL,
      token_hash VARCHAR(64) NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      revoked_at TIMESTAMPTZ,
      replaced_by VARCHAR(64)
    )`
  );
  await strapi.db.connection.raw(
    'CREATE INDEX IF NOT EXISTS idx_refresh_actor_user ON refresh_tokens (actor_type, user_id)'
  );
  ready = true;
};

const rows = (res) => {
  if (!res) return [];
  if (Array.isArray(res)) return res[0] || [];
  if (res.rows) return res.rows;
  return [];
};

const generate = () => {
  const token = crypto.randomBytes(32).toString('base64');
  return { token, hash: sha256hex(token) };
};

const issue = async (actorType, userId) => {
  await ensure();
  const { token, hash } = generate();
  const expiresAt = new Date(Date.now() + TTL_DAYS * 24 * 60 * 60 * 1000);
  await strapi.db.connection.raw(
    `INSERT INTO refresh_tokens (actor_type, user_id, token_hash, expires_at)
     VALUES (?, ?, ?, ?)`,
    [actorType, userId, hash, expiresAt]
  );
  return token;
};

/**
 * Validates + consumes (revokes) a refresh token. Returns { userId } or null.
 * Rotation: the caller issues a new token to replace the consumed one.
 */
const consume = async (actorType, token) => {
  if (!token || typeof token !== 'string') return null;
  await ensure();
  const res = await strapi.db.connection.raw(
    `SELECT id, user_id, expires_at FROM refresh_tokens
     WHERE actor_type = ? AND token_hash = ? AND revoked_at IS NULL`,
    [actorType, sha256hex(token)]
  );
  const row = rows(res)[0];
  if (!row) return null;
  if (new Date(row.expires_at) < new Date()) {
    await strapi.db.connection.raw(`DELETE FROM refresh_tokens WHERE id = ?`, [row.id]);
    return null;
  }
  await strapi.db.connection.raw(
    `UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = ?`,
    [row.id]
  );
  return { userId: Number(row.user_id) };
};

const revokeAll = async (actorType, userId) => {
  await ensure();
  await strapi.db.connection.raw(
    `UPDATE refresh_tokens SET revoked_at = NOW() WHERE actor_type = ? AND user_id = ? AND revoked_at IS NULL`,
    [actorType, userId]
  );
};

module.exports = { issue, consume, revokeAll };