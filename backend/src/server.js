'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const config = require('./config');
const { prisma, ensureAuditTriggers } = require('./db');
const { logAudit } = require('./controllers/audit');
const { LEVELS, computeLevel, requireAuth, checkDocumentAccess, requireRole } = require('./middleware/auth');

fs.mkdirSync(config.UPLOAD_DIR, { recursive: true });

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', config.TRUST_PROXY ? 1 : false);

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'", 'https://cdn.tailwindcss.com'],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", 'data:'],
        'connect-src': ["'self'"],
        'object-src': ["'none'"],
        'frame-ancestors': ["'none'"],
        'upgrade-insecure-requests': null,
      },
    },
  })
);
app.use(express.json({ limit: '10kb' }));

// ---------------------------------------------------------------- helpers
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const ALLOWED_EXTENSIONS = new Set([
  '.pdf', '.txt', '.md', '.csv', '.png', '.jpg', '.jpeg', '.gif', '.docx', '.xlsx', '.pptx',
]);
const DUMMY_HASH = bcrypt.hashSync('timing-equalizer-password', 10);

const publicUser = (u) => ({ id: u.id, email: u.email, name: u.name, role: u.role });

function cleanText(value, max) {
  if (typeof value !== 'string') return '';
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);
}

function serializeDoc(doc, level) {
  return {
    id: doc.id,
    title: doc.title,
    description: doc.description,
    originalName: doc.originalName,
    mimeType: doc.mimeType,
    size: doc.size,
    isPublic: doc.isPublic,
    owner: doc.owner ? { id: doc.owner.id, email: doc.owner.email, name: doc.owner.name } : undefined,
    createdAt: doc.createdAt,
    updatedAt: doc.updatedAt,
    accessLevel: level,
  };
}

// ---------------------------------------------------------------- uploads
const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, config.UPLOAD_DIR),
    filename: (_req, _file, cb) => cb(null, crypto.randomUUID()), // random name, never user-controlled
  }),
  limits: { fileSize: config.MAX_UPLOAD_BYTES, files: 1 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(ext)) return cb(new HttpError(415, 'File type not allowed'));
    return cb(null, true);
  },
});

// ---------------------------------------------------------------- auth
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: config.LOGIN_RATE_LIMIT,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again later.' },
});

app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));

app.post(
  '/api/auth/login',
  loginLimiter,
  wrap(async (req, res) => {
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    if (!email || !password || password.length > 200) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    const passwordOk = await bcrypt.compare(password, user ? user.passwordHash : DUMMY_HASH);

    if (!user || !passwordOk || !user.active) {
      await logAudit({ req, user: null, userEmail: email, action: 'LOGIN', status: 'DENIED', details: 'Invalid credentials' });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    await logAudit({ req, user, action: 'LOGIN', status: 'ALLOWED' });
    const token = jwt.sign({ sub: user.id }, config.JWT_SECRET, {
      algorithm: 'HS256',
      expiresIn: config.JWT_EXPIRES_IN,
    });
    return res.json({ token, user: publicUser(user) });
  })
);

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: config.REGISTER_RATE_LIMIT,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many sign-up attempts. Try again later.' },
});

// Public self-registration. Always creates a normal USER: any "role" sent by the
// client is ignored, so nobody can sign themselves up as an ADMIN.
app.post(
  '/api/auth/register',
  registerLimiter,
  wrap(async (req, res) => {
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const name = cleanText(req.body.name, 100);
    const password = typeof req.body.password === 'string' ? req.body.password : '';

    if (!name) throw new HttpError(400, 'Name is required');
    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(400, 'A valid email is required');
    if (password.length < 8 || password.length > 200 || !/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
      throw new HttpError(400, 'Password must be 8+ characters and contain at least one letter and one number');
    }

    const duplicate = async () => {
      await logAudit({ req, user: null, userEmail: email, action: 'REGISTER', status: 'DENIED', details: 'Email already registered' });
      return res.status(409).json({ error: 'An account with this email already exists' });
    };

    if (await prisma.user.findUnique({ where: { email } })) return duplicate();

    let user;
    try {
      user = await prisma.user.create({
        data: { email, name, passwordHash: await bcrypt.hash(password, 12), role: 'USER' },
      });
    } catch (err) {
      if (err && err.code === 'P2002') return duplicate(); // race: same email registered concurrently
      throw err;
    }

    await logAudit({ req, user, action: 'REGISTER', status: 'ALLOWED' });
    return res.status(201).json({ user: publicUser(user) }); // no token: the user must sign in separately
  })
);

app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));

// ---------------------------------------------------------------- documents
app.post(
  '/api/documents/upload',
  requireAuth,
  upload.single('file'),
  wrap(async (req, res) => {
    if (!req.file) throw new HttpError(400, 'A file is required (field name: "file")');

    const originalName = cleanText(path.basename(req.file.originalname || 'file'), 200) || 'file';
    const title = cleanText(req.body.title, 200) || originalName;
    const description = cleanText(req.body.description, 1000) || null;
    const isPublic = req.body.isPublic === 'true';

    let doc;
    try {
      doc = await prisma.document.create({
        data: {
          title, description, originalName,
          storedName: req.file.filename,
          mimeType: cleanText(req.file.mimetype, 100) || 'application/octet-stream',
          size: req.file.size,
          isPublic,
          ownerId: req.user.id,
        },
        include: { owner: { select: { id: true, email: true, name: true } } },
      });
    } catch (err) {
      fs.promises.unlink(req.file.path).catch(() => {});
      throw err;
    }

    await logAudit({
      req, user: req.user, action: 'DOCUMENT_UPLOAD', status: 'ALLOWED', documentId: doc.id,
      details: `size=${doc.size} public=${doc.isPublic}`,
    });
    return res.status(201).json({ document: serializeDoc(doc, 'OWNER') });
  })
);

app.get(
  '/api/documents',
  requireAuth,
  wrap(async (req, res) => {
    const where = { deletedAt: null };
    if (req.user.role !== 'ADMIN') {
      where.OR = [{ ownerId: req.user.id }, { isPublic: true }, { permissions: { some: { userId: req.user.id } } }];
    }
    const docs = await prisma.document.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      include: {
        owner: { select: { id: true, email: true, name: true } },
        permissions: { where: { userId: req.user.id } },
      },
    });
    const documents = docs
      .map((d) => ({ d, level: computeLevel(req.user, d) }))
      .filter((x) => x.level)
      .map((x) => serializeDoc(x.d, x.level));
    res.json({ documents });
  })
);

app.get(
  '/api/documents/:id',
  requireAuth,
  checkDocumentAccess('READ', 'DOCUMENT_VIEW'),
  wrap(async (req, res) => {
    const body = { document: serializeDoc(req.document, req.accessLevel) };
    if (LEVELS[req.accessLevel] >= LEVELS.OWNER) {
      const grants = await prisma.documentPermission.findMany({
        where: { documentId: req.document.id },
        include: { user: { select: { id: true, email: true, name: true } } },
        orderBy: { createdAt: 'asc' },
      });
      body.permissions = grants.map((g) => ({
        userId: g.user.id, email: g.user.email, name: g.user.name, level: g.level, createdAt: g.createdAt,
      }));
    }
    res.json(body);
  })
);

app.patch(
  '/api/documents/:id',
  requireAuth,
  checkDocumentAccess('EDIT', 'DOCUMENT_EDIT', { logAllowed: false }),
  wrap(async (req, res) => {
    const data = {};
    if (req.body.title !== undefined) {
      const title = cleanText(req.body.title, 200);
      if (!title) throw new HttpError(400, 'Title cannot be empty');
      data.title = title;
    }
    if (req.body.description !== undefined) data.description = cleanText(req.body.description, 1000) || null;

    if (req.body.isPublic !== undefined) {
      if (LEVELS[req.accessLevel] < LEVELS.OWNER) {
        await logAudit({
          req, user: req.user, action: 'DOCUMENT_EDIT', status: 'DENIED', documentId: req.document.id,
          details: 'isPublic requires OWNER',
        });
        return res.status(403).json({ error: 'Forbidden' });
      }
      data.isPublic = req.body.isPublic === true;
    }
    if (!Object.keys(data).length) throw new HttpError(400, 'Nothing to update');

    const updated = await prisma.document.update({
      where: { id: req.document.id },
      data,
      include: { owner: { select: { id: true, email: true, name: true } } },
    });
    await logAudit({
      req, user: req.user, action: 'DOCUMENT_EDIT', status: 'ALLOWED', documentId: updated.id,
      details: `fields=${Object.keys(data).join(',')}`,
    });
    return res.json({ document: serializeDoc(updated, req.accessLevel) });
  })
);

// Authenticated streaming download. No presigned/long-lived URLs exist:
// every request re-checks live grants in checkDocumentAccess.
app.get(
  '/api/documents/:id/download',
  requireAuth,
  checkDocumentAccess('READ', 'DOCUMENT_DOWNLOAD'),
  wrap(async (req, res) => {
    const doc = req.document;
    const filePath = path.join(config.UPLOAD_DIR, path.basename(doc.storedName));

    let stat;
    try {
      stat = await fs.promises.stat(filePath);
    } catch (_) {
      return res.status(404).json({ error: 'File is not available' });
    }

    const asciiName = doc.originalName.replace(/[^A-Za-z0-9._-]/g, '_');
    res.set({
      'Content-Type': doc.mimeType || 'application/octet-stream',
      'Content-Length': String(stat.size),
      'Content-Disposition': `attachment; filename="${asciiName}"; filename*=UTF-8''${encodeURIComponent(doc.originalName)}`,
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; sandbox",
      'Cache-Control': 'no-store',
    });

    const stream = fs.createReadStream(filePath);
    stream.on('error', () => res.destroy());
    stream.pipe(res);
  })
);

app.delete(
  '/api/documents/:id',
  requireAuth,
  checkDocumentAccess('OWNER', 'DOCUMENT_DELETE', { logAllowed: false }),
  wrap(async (req, res) => {
    await prisma.document.update({ where: { id: req.document.id }, data: { deletedAt: new Date() } });
    fs.promises.unlink(path.join(config.UPLOAD_DIR, path.basename(req.document.storedName))).catch(() => {});
    await logAudit({ req, user: req.user, action: 'DOCUMENT_DELETE', status: 'ALLOWED', documentId: req.document.id });
    res.json({ success: true });
  })
);

// ---------------------------------------------------------------- permissions
app.post(
  '/api/documents/:id/permissions',
  requireAuth,
  checkDocumentAccess('OWNER', 'PERMISSION_GRANT', { logAllowed: false }),
  wrap(async (req, res) => {
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const level = req.body.level;
    if (!email) throw new HttpError(400, 'email is required');
    if (level !== 'READ' && level !== 'EDIT') throw new HttpError(400, 'level must be READ or EDIT');

    const target = await prisma.user.findUnique({ where: { email } });
    if (!target || !target.active) throw new HttpError(404, 'User not found');
    if (target.id === req.document.ownerId) throw new HttpError(400, 'The owner already has full access');

    const grant = await prisma.documentPermission.upsert({
      where: { documentId_userId: { documentId: req.document.id, userId: target.id } },
      update: { level, grantedById: req.user.id },
      create: { documentId: req.document.id, userId: target.id, level, grantedById: req.user.id },
    });
    await logAudit({
      req, user: req.user, action: 'PERMISSION_GRANT', status: 'ALLOWED', documentId: req.document.id,
      details: `target=${target.email} level=${level}`,
    });
    res.status(201).json({ permission: { userId: target.id, email: target.email, level: grant.level } });
  })
);

app.delete(
  '/api/documents/:id/permissions/:userId',
  requireAuth,
  checkDocumentAccess('OWNER', 'PERMISSION_REVOKE', { logAllowed: false }),
  wrap(async (req, res) => {
    const targetId = String(req.params.userId).slice(0, 64);
    const result = await prisma.documentPermission.deleteMany({
      where: { documentId: req.document.id, userId: targetId },
    });
    if (result.count === 0) throw new HttpError(404, 'Permission not found');
    await logAudit({
      req, user: req.user, action: 'PERMISSION_REVOKE', status: 'ALLOWED', documentId: req.document.id,
      details: `targetUserId=${targetId}`,
    });
    res.json({ success: true });
  })
);

// ---------------------------------------------------------------- admin
// Read-only on purpose: there is no route that updates or deletes audit rows.
app.get(
  '/api/admin/audit-logs',
  requireAuth,
  requireRole('ADMIN'),
  wrap(async (req, res) => {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
    const where = {};
    if (req.query.status === 'ALLOWED' || req.query.status === 'DENIED') where.status = req.query.status;
    if (typeof req.query.action === 'string' && req.query.action) where.action = req.query.action.slice(0, 64);
    if (typeof req.query.documentId === 'string' && req.query.documentId) where.documentId = req.query.documentId.slice(0, 64);
    if (typeof req.query.userEmail === 'string' && req.query.userEmail) where.userEmail = req.query.userEmail.slice(0, 254);

    const [total, logs] = await Promise.all([
      prisma.auditLog.count({ where }),
      prisma.auditLog.findMany({ where, orderBy: { createdAt: 'desc' }, take: limit, skip: offset }),
    ]);
    await logAudit({ req, user: req.user, action: 'ADMIN_VIEW_AUDIT', status: 'ALLOWED' });
    res.json({ total, limit, offset, logs });
  })
);

app.get(
  '/api/admin/system-stats',
  requireAuth,
  requireRole('ADMIN'),
  wrap(async (req, res) => {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const [users, documents, auditTotal, allowed, denied, denied24h] = await Promise.all([
      prisma.user.count(),
      prisma.document.count({ where: { deletedAt: null } }),
      prisma.auditLog.count(),
      prisma.auditLog.count({ where: { status: 'ALLOWED' } }),
      prisma.auditLog.count({ where: { status: 'DENIED' } }),
      prisma.auditLog.count({ where: { status: 'DENIED', createdAt: { gte: since } } }),
    ]);
    await logAudit({ req, user: req.user, action: 'ADMIN_VIEW_STATS', status: 'ALLOWED' });
    res.json({ users, documents, auditEvents: auditTotal, allowed, denied, deniedLast24h: denied24h });
  })
);

// ---------------------------------------------------------------- static frontend + errors
app.use(express.static(config.FRONTEND_DIR, { index: 'index.html', maxAge: 0 }));
app.use('/api', (_req, res) => res.status(404).json({ error: 'Not found' }));

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    return res.status(status).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'File too large' : 'Invalid upload' });
  }
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'Request too large' });
  console.error('[error]', err);
  return res.status(500).json({ error: 'Internal server error' });
});

if (require.main === module) {
  ensureAuditTriggers()
    .then(() => app.listen(config.PORT, () => console.log(`TrustVault running on http://localhost:${config.PORT}`)))
    .catch((e) => {
      console.error('Startup failed. Did you run "npm run setup"?', e);
      process.exit(1);
    });
}

module.exports = app;
