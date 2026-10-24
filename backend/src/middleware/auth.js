'use strict';
const jwt = require('jsonwebtoken');
const { prisma } = require('../db');
const config = require('../config');
const { logAudit } = require('../controllers/audit');

const LEVELS = Object.freeze({ READ: 1, EDIT: 2, OWNER: 3, ADMIN: 4 });

/**
 * Effective access level of `user` on `doc`, computed from LIVE database rows.
 * `doc.permissions` must contain the grant rows for this user.
 */
function computeLevel(user, doc) {
  if (user.role === 'ADMIN') return 'ADMIN';
  if (doc.ownerId === user.id) return 'OWNER';
  const grant = (doc.permissions || []).find((p) => p.userId === user.id);
  if (grant && LEVELS[grant.level]) return grant.level;
  if (doc.isPublic) return 'READ';
  return null;
}

/**
 * Verifies the Bearer JWT, then reloads the user from the database.
 * The token only carries the user id: role / active flag are always read live,
 * so deactivating a user or changing a role takes effect immediately.
 */
async function requireAuth(req, res, next) {
  try {
    const [scheme, token] = String(req.headers.authorization || '').split(' ');
    if (scheme !== 'Bearer' || !token) return res.status(401).json({ error: 'Authentication required' });

    let payload;
    try {
      payload = jwt.verify(token, config.JWT_SECRET, { algorithms: ['HS256'] });
    } catch (_) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    const user = await prisma.user.findUnique({ where: { id: String(payload.sub) } });
    if (!user || !user.active) return res.status(401).json({ error: 'Invalid or expired token' });

    req.user = user;
    return next();
  } catch (err) {
    return next(err);
  }
}

/**
 * Zero-trust document gate. Runs a fresh DB query on EVERY request.
 * - Missing, deleted and unauthorized documents all return the same generic 403
 *   (no metadata, no existence oracle).
 * - Denials are always audited. Allowed access is audited here unless the route
 *   logs its own (more detailed) success record (`logAllowed: false`).
 * - If the ALLOWED audit write fails, the request fails closed (500).
 */
function checkDocumentAccess(required, action, { logAllowed = true } = {}) {
  if (!LEVELS[required]) throw new Error(`Unknown access level: ${required}`);

  return async function documentAccessGuard(req, res, next) {
    try {
      const documentId = String(req.params.id || '').slice(0, 64);
      const doc = await prisma.document.findFirst({
        where: { id: documentId, deletedAt: null },
        include: {
          owner: { select: { id: true, email: true, name: true } },
          permissions: { where: { userId: req.user.id } },
        },
      });

      const level = doc ? computeLevel(req.user, doc) : null;

      if (!level || LEVELS[level] < LEVELS[required]) {
        try {
          await logAudit({ req, user: req.user, action, status: 'DENIED', documentId, details: `required=${required}` });
        } catch (auditErr) {
          console.error('[audit] failed to record DENIED event', auditErr);
        }
        return res.status(403).json({ error: 'Forbidden' });
      }

      if (logAllowed) {
        await logAudit({ req, user: req.user, action, status: 'ALLOWED', documentId, details: `level=${level}` });
      }

      req.document = doc;
      req.accessLevel = level;
      return next();
    } catch (err) {
      return next(err);
    }
  };
}

/** Role gate based on the live DB role (never on a token claim). */
function requireRole(role) {
  return async function roleGuard(req, res, next) {
    if (req.user && req.user.role === role) return next();
    try {
      await logAudit({
        req, user: req.user || null, action: 'ROLE_CHECK', status: 'DENIED',
        details: `required=${role} path=${req.originalUrl.split('?')[0]}`,
      });
    } catch (auditErr) {
      console.error('[audit] failed to record DENIED event', auditErr);
    }
    return res.status(403).json({ error: 'Forbidden' });
  };
}

module.exports = { LEVELS, computeLevel, requireAuth, checkDocumentAccess, requireRole };
