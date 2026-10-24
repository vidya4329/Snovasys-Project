'use strict';
require('dotenv').config();
const path = require('path');
const crypto = require('crypto');

const isProd = process.env.NODE_ENV === 'production';
let jwtSecret = process.env.JWT_SECRET;

if (!jwtSecret) {
  if (isProd) throw new Error('JWT_SECRET must be set in production');
  jwtSecret = crypto.randomBytes(32).toString('hex');
  console.warn('[config] JWT_SECRET not set - using a random per-process secret (tokens reset on restart).');
}

module.exports = Object.freeze({
  PORT: Number(process.env.PORT) || 3000,
  JWT_SECRET: jwtSecret,
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '1h',
  UPLOAD_DIR: path.resolve(__dirname, '..', process.env.UPLOAD_DIR || 'storage/uploads'),
  MAX_UPLOAD_BYTES: (Number(process.env.MAX_UPLOAD_MB) || 10) * 1024 * 1024,
  LOGIN_RATE_LIMIT: Number(process.env.LOGIN_RATE_LIMIT) || 10,
  REGISTER_RATE_LIMIT: Number(process.env.REGISTER_RATE_LIMIT) || 20,
  TRUST_PROXY: process.env.TRUST_PROXY === 'true',
  FRONTEND_DIR: path.resolve(__dirname, '..', '..', 'frontend'),
});
