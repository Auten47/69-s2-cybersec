'use strict';

/**
 * Audit chain verifier.
 *
 * Recomputes the HMAC chain over audit_logs and reports any row whose stored
 * row_hash / prev_row_hash does not match the expected value (tamper evidence).
 *
 * Run inside the app container:
 *   docker exec 69-s2-app node scripts/audit-verify.js
 *
 * Exit code 0 = chain intact, 1 = tampering detected, 2 = error.
 */

const crypto = require('crypto');

const getHmacKey = () => {
  const fromEnv = process.env.AUDIT_HMAC_KEY;
  if (fromEnv && fromEnv.length >= 32) return fromEnv;
  const seed = process.env.ADMIN_JWT_SECRET || process.env.APP_KEYS || 'audit-fallback';
  return crypto.createHash('sha256').update('authen-audit:' + seed).digest('hex');
};

const HMAC_KEY = getHmacKey();

const chainHash = (prevHash, values) => {
  const canonical = [
    ...values.map((v) => (v === null || v === undefined ? '' : v)),
    prevHash || ''
  ].join('\x1f');
  return crypto.createHmac('sha256', HMAC_KEY).update(canonical).digest('hex');
};

// Deterministic JSON (stable key order) matching the server-side chain.
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

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

(async () => {
  const { Client } = require('pg');
  const client = new Client({
    host: process.env.DATABASE_HOST || 'db',
    port: parseInt(process.env.DATABASE_PORT || '5432', 10),
    user: process.env.DATABASE_USERNAME,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE_NAME,
  });

  await client.connect();

  const res = await client.query(
    `SELECT id, event_type, actor_type, actor_id, identity, ip, user_agent, details, prev_row_hash, row_hash, created_at
     FROM audit_logs ORDER BY id ASC`
  );

  let prev = '';
  let broken = 0;
  let missing = 0;
  let total = res.rows.length;

  for (const row of res.rows) {
    const values = [
      row.id,
      row.event_type,
      row.actor_type,
      row.actor_id,
      row.identity,
      row.ip,
      row.user_agent,
      row.details instanceof Date ? row.details : normalizeDetails(row.details),
      row.created_at
    ];
    const expected = chainHash(prev, values);

    if (!row.row_hash) {
      missing++;
      console.log(`  [MISSING] #${row.id} ${row.event_type}`);
      prev = '';
      continue;
    } else if ((row.prev_row_hash || '') !== prev) {
      broken++;
      console.log(`  [TAMPER ] #${row.id} ${row.event_type} prev mismatch`);
    } else if (row.row_hash !== expected) {
      broken++;
      console.log(`  [TAMPER ] #${row.id} ${row.event_type} row mismatch`);
    }
    // The chain continues with this row's own hash (record() links prev to the
    // previous row's row_hash), not its prev_row_hash pointer.
    prev = row.row_hash || prev;
  }

  const status = broken === 0 && missing === 0 ? 'INTACT' : 'TAMPERED';
  console.log(`\naudit_logs: ${total} rows | missing chain: ${missing} | broken links: ${broken}`);
  console.log(`CHAIN STATUS: ${status}`);

  await client.end();
  await sleep(100);
  process.exit(broken === 0 && missing === 0 ? 0 : 1);
})().catch(async (err) => {
  console.error('Verify failed:', err.message);
  await sleep(100);
  process.exit(2);
});