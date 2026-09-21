'use strict';

const crypto = require('crypto');

let tableReady = false;
let backfilled = false;

const HMAC_KEY =
  process.env.AUDIT_HMAC_KEY ||
  process.env.ADMIN_JWT_SECRET ||
  'audit-tamper-evidence-fallback-key';
const RETENTION_DAYS = parseInt(process.env.AUDIT_RETENTION_DAYS || '90', 10);

const rows = (res) => {
  if (!res) return [];
  if (Array.isArray(res)) return res[0] || [];
  if (res.rows) return res.rows;
  return [];
};

const chainHash = (prevHash, values) => {
  const canonical = [
    ...values.map((v) => (v === null || v === undefined ? '' : v)),
    prevHash || ''
  ].join('\x1f');
  return crypto.createHmac('sha256', HMAC_KEY).update(canonical).digest('hex');
};

// Deterministic JSON serialization (stable key order) so the server-side chain
// matches what the verify script recomputes from jsonb-parsed values.
const stableStringify = (value) => {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return JSON.stringify(value.map((v) => (v && typeof v === 'object' ? JSON.parse(stableStringify(v)) : v)));
  if (typeof value === 'object') {
    const sorted = {};
    for (const key of Object.keys(value).sort()) {
      sorted[key] = value[key] && typeof value[key] === 'object' ? JSON.parse(stableStringify(value[key])) : value[key];
    }
    return JSON.stringify(sorted);
  }
  return JSON.stringify(value);
};

const normalizeDetails = (details) => {
  if (details === null || details === undefined) return null;
  if (typeof details === 'string') {
    try {
      return stableStringify(JSON.parse(details));
    } catch (err) {
      return details;
    }
  }
  return stableStringify(details);
};

const ensureTable = async () => {
  if (tableReady) return;

  await strapi.db.connection.raw(
    `CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      event_type VARCHAR(64) NOT NULL,
      actor_type VARCHAR(16) NOT NULL,
      actor_id BIGINT,
      identity VARCHAR(255),
      ip VARCHAR(64),
      user_agent VARCHAR(512),
      details JSONB,
      prev_row_hash VARCHAR(64),
      row_hash VARCHAR(64),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`
  );
  await strapi.db.connection.raw(
    'CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at)'
  );
  await strapi.db.connection.raw(
    'CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs (event_type)'
  );

  tableReady = true;
  await backfillChain();
};

/**
 * Computes a hash chain over every row in id order. Any row whose stored
 * row_hash differs from the recomputed value (or whose prev_row_hash is out of
 * sequence) indicates tampering. Run scripts/audit-verify.js to verify.
 */
const backfillChain = async () => {
  if (backfilled) return;
  backfilled = true;

  const res = await strapi.db.connection.raw(
    `SELECT id, event_type, actor_type, actor_id, identity, ip, user_agent, details, created_at,
            prev_row_hash, row_hash
     FROM audit_logs WHERE row_hash IS NULL ORDER BY id ASC`
  );
  const pending = rows(res);
  if (!pending.length) return;

  const lastHashRes = await strapi.db.connection.raw(
    `SELECT row_hash FROM audit_logs WHERE row_hash IS NOT NULL ORDER BY id DESC LIMIT 1`
  );
  const lastHashRow = rows(lastHashRes)[0];
  let prev = lastHashRow && lastHashRow.row_hash ? lastHashRow.row_hash : '';

  for (const row of pending) {
    const values = [
      row.id,
      row.event_type,
      row.actor_type,
      row.actor_id,
      row.identity,
      row.ip,
      row.user_agent,
      normalizeDetails(row.details),
      row.created_at
    ];
    const hash = chainHash(prev, values);
    await strapi.db.connection.raw(
      `UPDATE audit_logs SET prev_row_hash = ?, row_hash = ? WHERE id = ?`,
      [prev, hash, row.id]
    );
    prev = hash;
  }
};

const canonicalValues = (entry) => {
  const details = normalizeDetails(entry.details);
  return [
    entry.event_type,
    entry.actor_type,
    entry.actor_id || null,
    entry.identity || null,
    entry.ip || null,
    entry.user_agent || null,
    details
  ];
};

const record = async (entry) => {
  try {
    await ensureTable();

    const created_at = new Date();

    const lastRes = await strapi.db.connection.raw(
      `SELECT row_hash FROM audit_logs ORDER BY id DESC LIMIT 1`
    );
    const lastRow = rows(lastRes)[0];
    const prev = lastRow && lastRow.row_hash ? lastRow.row_hash : '';

    const values = canonicalValues(entry);

    const detailsValue = values[6];

    const res = await strapi.db.connection.raw(
      `INSERT INTO audit_logs (event_type, actor_type, actor_id, identity, ip, user_agent, details, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?::jsonb, ?)
       RETURNING id`,
      [
        entry.event_type,
        entry.actor_type,
        entry.actor_id || null,
        entry.identity || null,
        entry.ip || null,
        entry.user_agent || null,
        detailsValue,
        created_at
      ]
    );
    const inserted = rows(res)[0];
    if (!inserted) {
      strapi.log.error('[audit] no row returned on insert');
      return;
    }

    const chainValues = [inserted.id, ...values, created_at];
    const hash = chainHash(prev, chainValues);
    await strapi.db.connection.raw(
      `UPDATE audit_logs SET prev_row_hash = ?, row_hash = ? WHERE id = ?`,
      [prev, hash, inserted.id]
    );

    strapi.log.info(
      `[audit] ${entry.event_type} actor=${entry.actor_type}/${entry.actor_id || entry.identity || '-'} ip=${entry.ip || '-'} id=${inserted.id}`
    );

    if (entry.event_type === 'LOGIN_FAILED') {
      await maybeAlert(entry);
    }
  } catch (err) {
    strapi.log.error('[audit] failed to write audit log:', err.message);
  }
};

const maybeAlert = async (entry) => {
  try {
    const threshold = parseInt(process.env.AUDIT_ALERT_THRESHOLD || '5', 10);
    const windowMs = parseInt(process.env.AUDIT_ALERT_WINDOW_MS || (5 * 60 * 1000), 10);
    const to = process.env.AUDIT_ALERT_EMAIL;
    if (!to) return;

    const now = Date.now();
    const res = await strapi.db.connection.raw(
      `INSERT INTO shared_counters (key, hits, window_start)
       VALUES ('alert:LOGIN_FAILED', 1, ${now})
       ON CONFLICT (key) DO UPDATE SET
         hits = CASE WHEN shared_counters.window_start + ${windowMs} < ${now} THEN 1 ELSE shared_counters.hits + 1 END,
         window_start = CASE WHEN shared_counters.window_start + ${windowMs} < ${now} THEN ${now} ELSE shared_counters.window_start END,
         updated_at = NOW()`
    );
    const row = rows(res)[0];
    if (!row || row.hits < threshold) return;

    const sentRes = await strapi.db.connection.raw(
      `SELECT window_start FROM shared_counters WHERE key = 'alert-sent:LOGIN_FAILED'`
    );
    const sentRow = rows(sentRes)[0];
    const cooldownMs = parseInt(process.env.AUDIT_ALERT_COOLDOWN_MS || (15 * 60 * 1000), 10);
    if (sentRow && sentRow.window_start + cooldownMs > now) return;

    await strapi.db.connection.raw(
      `INSERT INTO shared_counters (key, hits, window_start)
       VALUES ('alert-sent:LOGIN_FAILED', 0, ${now})
       ON CONFLICT (key) DO UPDATE SET window_start = ${now}, updated_at = NOW()`
    );

    await strapi.plugin('email').service('email').send({
      to,
      subject: '[Authen-IAM] Suspicious login activity detected',
      text: `More than ${threshold} failed login attempts were recorded within the alerting window.\nLatest failure: ${entry.identity || 'unknown account'} from ${entry.ip || 'unknown ip'}.\nPlease review the audit log (audit_logs LOGIN_FAILED entries).`,
      html: `<p>More than <strong>${threshold}</strong> failed login attempts were recorded within the alerting window.</p><p>Latest failure: <strong>${entry.identity || 'unknown account'}</strong> from <strong>${entry.ip || 'unknown ip'}</strong>.</p><p>Please review the audit log (LOGIN_FAILED entries).</p>`
    });
    strapi.log.warn('[audit] login-failure alert sent to', to);
  } catch (err) {
    strapi.log.error('[audit] alert failed:', err.message);
  }
};

const startHousekeeping = () => {
  const run = async () => {
    try {
      await ensureTable();
      await strapi.db.connection.raw(
        `DELETE FROM audit_logs WHERE created_at < NOW() - (?::int || ' days')::interval`,
        [RETENTION_DAYS]
      );
      strapi.log.info(`[audit] retention cleanup done (keep ${RETENTION_DAYS}d)`);
    } catch (err) {
      strapi.log.error('[audit] housekeeping failed:', err.message);
    }
  };
  setTimeout(run, 15000);
  setInterval(run, 6 * 60 * 60 * 1000);
};

const context = (ctx, details) => ({
  ip: (ctx && (ctx.request.ip || (ctx.request.socket && ctx.request.socket.remoteAddress))) || null,
  user_agent: (ctx && ctx.request.header && ctx.request.header['user-agent']) || null,
  details
});

module.exports = { record, context, ensureTable, startHousekeeping };