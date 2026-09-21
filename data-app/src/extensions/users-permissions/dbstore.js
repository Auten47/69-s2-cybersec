'use strict';

const TABLE = 'shared_counters';

let ready = false;

const ensure = async () => {
  if (ready) return;
  await strapi.db.connection.raw(
    `CREATE TABLE IF NOT EXISTS ${TABLE} (
      key VARCHAR(255) PRIMARY KEY,
      hits INTEGER NOT NULL DEFAULT 0,
      window_start BIGINT NOT NULL DEFAULT 0,
      locked_until BIGINT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`
  );
  ready = true;
};

const rows = (res) => {
  if (!res) return [];
  if (Array.isArray(res)) return res[0] || [];
  if (res.rows) return res.rows;
  return [];
};

const getRow = async (key) => {
  const res = await strapi.db.connection.raw(`SELECT * FROM ${TABLE} WHERE key = ?`, [key]);
  return rows(res)[0] || null;
};

const now = () => Date.now();

/**
 * Fixed-window counter. Returns true when the count exceeds `max` within `windowMs`.
 */
const hit = async ({ key, windowMs, max }) => {
  await ensure();
  const t = now();
  await strapi.db.connection.raw(
    `INSERT INTO ${TABLE} (key, hits, window_start, locked_until)
     VALUES (?, 1, ?, 0)
     ON CONFLICT (key) DO UPDATE SET
       hits = CASE WHEN ${TABLE}.window_start + ? < ? THEN 1 ELSE ${TABLE}.hits + 1 END,
       window_start = CASE WHEN ${TABLE}.window_start + ? < ? THEN ? ELSE ${TABLE}.window_start END,
       locked_until = CASE WHEN ${TABLE}.window_start + ? < ? THEN 0 ELSE ${TABLE}.locked_until END,
       updated_at = NOW()`,
    [key, t, windowMs, t, windowMs, t, t, windowMs, t]
  );
  const row = await getRow(key);
  return { blocked: max != null && (row.hits || 0) > max, hits: row.hits || 0, row };
};

/**
 * Per-account lockout. Returns remaining lock time in ms (0 = not locked).
 */
const recordFailure = async ({ key, windowMs, threshold, lockMs }) => {
  await ensure();
  const t = now();
  const { row } = await hit({ key, windowMs, max: null });

  if (row.locked_until && row.locked_until > t) return row.locked_until - t;

  if (row.hits >= threshold) {
    const until = t + lockMs;
    await strapi.db.connection.raw(
      `UPDATE ${TABLE} SET locked_until = ? WHERE key = ?`,
      [until, key]
    );
    return lockMs;
  }
  return 0;
};

/**
 * Returns remaining lock time in ms for a key, 0 when not locked.
 */
const checkLock = async (key) => {
  const row = await getRow(key);
  if (!row || !row.locked_until) return 0;
  if (row.locked_until <= now()) {
    await strapi.db.connection.raw(`DELETE FROM ${TABLE} WHERE key = ? AND locked_until <= ?`, [key, now()]);
    return 0;
  }
  return row.locked_until - now();
};

const clear = async (key) => {
  await ensure();
  await strapi.db.connection.raw(`DELETE FROM ${TABLE} WHERE key = ?`, [key]);
};

/**
 * One-shot throttle: returns true when `key` was set within the window (skip the action).
 * First use always returns false (the action is allowed once).
 */
const throttled = async (key, windowMs) => {
  await ensure();
  const t = now();
  const row = await getRow(key);

  if (!row) {
    await strapi.db.connection.raw(
      `INSERT INTO ${TABLE} (key, hits, window_start, locked_until)
       VALUES (?, 0, ?, 0)
       ON CONFLICT (key) DO NOTHING`,
      [key, t]
    );
    return false;
  }

  // BIGINT columns come back from pg as strings; coerce before any arithmetic.
  // window_start + windowMs on a string would concat (e.g. "1782399338000"+60000
  // -> "178239933800060000"), turning the window check into "always throttled".
  const windowStart = Number(row.window_start) || 0;
  const lockedUntil = Number(row.locked_until) || 0;

  if (windowStart + windowMs > t || lockedUntil > t) return true;

  await strapi.db.connection.raw(
    `UPDATE ${TABLE} SET window_start = ?, hits = 0, updated_at = NOW() WHERE key = ?`,
    [t, key]
  );
  return false;
};

const resetAll = async () => {
  await ensure();
  await strapi.db.connection.raw(`TRUNCATE ${TABLE}`);
};

module.exports = { hit, recordFailure, checkLock, clear, throttled, resetAll, getRow, TABLE };