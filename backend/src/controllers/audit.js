'use strict';
const { prisma } = require('../db');

function getClientIp(req) {
  return String((req && (req.ip || (req.socket && req.socket.remoteAddress))) || 'unknown').slice(0, 64);
}

/**
 * Append one audit record. INSERT only - this module intentionally exports
 * no update/delete helpers.
 *
 * @param {object} p
 * @param {object} p.req            Express request (IP + user agent)
 * @param {object|null} p.user      authenticated user, if any
 * @param {string|null} p.userEmail attempted email (failed logins)
 * @param {string} p.action         e.g. DOCUMENT_DOWNLOAD
 * @param {'ALLOWED'|'DENIED'} p.status
 * @param {string|null} p.documentId
 * @param {string|null} p.details
 */
async function logAudit({ req, user = null, userEmail = null, action, status, documentId = null, details = null }) {
  if (status !== 'ALLOWED' && status !== 'DENIED') throw new Error('Invalid audit status');
  if (!action) throw new Error('Audit action is required');

  return prisma.auditLog.create({
    data: {
      userId: user ? user.id : null,
      userEmail: user ? user.email : userEmail ? String(userEmail).slice(0, 254) : null,
      action: String(action).slice(0, 64),
      status,
      documentId: documentId ? String(documentId).slice(0, 64) : null,
      ipAddress: getClientIp(req),
      userAgent: req && req.headers ? String(req.headers['user-agent'] || '').slice(0, 255) : null,
      details: details ? String(details).slice(0, 500) : null,
    },
  });
}

module.exports = { logAudit, getClientIp };
