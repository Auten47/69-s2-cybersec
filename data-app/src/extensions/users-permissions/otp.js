'use strict';

const crypto = require('crypto');

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

const b32Encode = (buf) => {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
};

const b32Decode = (input) => {
  const cleaned = String(input).toUpperCase().replace(/[\s=]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of cleaned) {
    const idx = BASE32.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
};

const generateSecret = (length = 20) => b32Encode(crypto.randomBytes(length));

const totp = (secret, { step = 30, digits = 6, counterTime = Math.floor(Date.now() / 1000) } = {}) => {
  const key = b32Decode(secret);
  const counter = Math.floor(counterTime / step);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter), 0);
  const h = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = h[h.length - 1] & 0x0f;
  const code = (h.readUInt32BE(offset) & 0x7fffffff) % Math.pow(10, digits);
  return code.toString().padStart(digits, '0');
};

const verifyTOTP = (secret, code, { window = 1, step = 30 } = {}) => {
  if (!secret || !code) return false;
  const clean = String(code).trim();
  if (!/^\d{6}$/.test(clean)) return false;
  const now = Math.floor(Date.now() / 1000);
  for (let w = -window; w <= window; w++) {
    if (totp(secret, { step, counterTime: now + w * step }) === clean) return true;
  }
  return false;
};

const otpauthUrl = (secret, account, issuer) =>
  `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

const newBackupCodes = (count = 8) => {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const raw = crypto.randomBytes(5).toString('hex').toUpperCase();
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  return codes;
};

const sha256hex = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');

/**
 * Signs a short-lived token that proves the password step of a login is complete
 * (used by the MFA challenge flow). Signed with the users-permissions JWT secret.
 */
const mfaJwt = ({ id, type, expiresIn = '5m' }) => {
  const jwt = require('jsonwebtoken');
  const secret = strapi.config.get('plugin.users-permissions.jwtSecret') || process.env.JWT_SECRET;
  return jwt.sign({ id, type, mfa: true }, secret, { expiresIn });
};

const verifyMfaJwt = (token, type) => {
  try {
    const jwt = require('jsonwebtoken');
    const secret = strapi.config.get('plugin.users-permissions.jwtSecret') || process.env.JWT_SECRET;
    const payload = jwt.verify(token, secret);
    if (!payload || payload.mfa !== true || (type && payload.type !== type) || !payload.id) return null;
    return payload;
  } catch (err) {
    return null;
  }
};

const hashCodes = (codes) => (Array.isArray(codes) ? codes.map((c) => sha256hex(c)) : []);

/**
 * Validates a backup code against a stored array of sha256 hashes.
 * Returns the remaining hash list when valid (code consumed), otherwise null.
 */
const consumeBackupCode = (storedHashes, code) => {
  if (!Array.isArray(storedHashes) || !storedHashes.length || !code) return null;
  const clean = String(code).trim().toUpperCase();
  const idx = storedHashes.findIndex((h) => h === sha256hex(clean));
  if (idx === -1) return null;
  const remaining = storedHashes.slice();
  remaining.splice(idx, 1);
  return remaining;
};

module.exports = {
  generateSecret,
  verifyTOTP,
  totp,
  otpauthUrl,
  newBackupCodes,
  consumeBackupCode,
  sha256hex,
  hashCodes,
  mfaJwt,
  verifyMfaJwt,
  b32Decode
};