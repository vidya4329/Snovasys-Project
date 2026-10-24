# TrustVault

Secure document sharing with zero-trust authorization and an append-only audit trail.
Built for the Snovasys Fresher Hiring Challenge.

```
trustvault/
├── backend/            Node.js + Express API, Prisma schema, tests
│   ├── prisma/         schema.prisma, seed.js
│   ├── src/            server.js, config.js, db.js, middleware/, controllers/
│   ├── storage/        uploaded files (git-ignored)
│   └── tests/          Jest + Supertest security suite
├── frontend/           index.html + app.js (Tailwind CDN, vanilla JS), served by Express
├── docs/               THREATS.md, PROMPTS.md
├── runtime.txt
└── README.md
```

## Setup

Requirements: Node.js 18+ (20 recommended).

```bash
cd backend
npm install
cp .env.example .env        # then set JWT_SECRET to a long random string
npm run setup               # prisma generate + db push + seed
npm start                   # http://localhost:3000
```

On Windows PowerShell use `copy .env.example .env`.
Run tests: `npm test` (uses a separate `prisma/test.db`, recreated on every run).

## Seed credentials

| Role | Email | Password |
|---|---|---|
| Admin | admin@trustvault.local | AdminPass123! |
| Document owner | owner@trustvault.local | OwnerPass123! |
| Viewer | viewer@trustvault.local | ViewerPass123! |

Demo documents (owned by the owner): a public handbook, a private financials file (viewer gets 403), and a project plan
shared READ with the viewer (revoke it to see immediate 403).

## Security model

- Every document route calls `checkDocumentAccess`, which reads live ownership/grants/public state from the DB.
- Downloads stream through `GET /api/documents/:id/download`; there are no presigned or static file URLs.
- Missing, deleted and unauthorized documents all return an identical `403 {"error":"Forbidden"}`.
- JWT carries only the user id; role and active flag are loaded from the DB on every request.
- Audit trail records ALLOWED and DENIED attempts (user, action, document, IP, user agent). No update/delete routes, and
  DB triggers block UPDATE/DELETE on `AuditLog`.
- Access levels: READ < EDIT < OWNER < ADMIN. A public document grants READ to every signed-in user.

See `docs/THREATS.md` for the full threat matrix.

## API

All routes except login and health need `Authorization: Bearer <token>`.

| Method | Path | Min. access | Description |
|---|---|---|---|
| POST | `/api/auth/register` | - | `{name, email, password}` -> `{user}` (always role USER; sign in afterwards) |
| POST | `/api/auth/login` | - | `{email, password}` -> `{token, user}` |
| GET | `/api/auth/me` | signed in | Current user |
| POST | `/api/documents/upload` | signed in | multipart: `file`, `title?`, `description?`, `isPublic?` |
| GET | `/api/documents` | signed in | Documents you may access, with your access level |
| GET | `/api/documents/:id` | READ | Metadata (+ grants list for OWNER/ADMIN) |
| PATCH | `/api/documents/:id` | EDIT | `{title?, description?, isPublic?}` (`isPublic` needs OWNER) |
| GET | `/api/documents/:id/download` | READ | Authenticated file stream |
| DELETE | `/api/documents/:id` | OWNER | Soft-delete + remove file |
| POST | `/api/documents/:id/permissions` | OWNER | `{email, level: READ\|EDIT}` |
| DELETE | `/api/documents/:id/permissions/:userId` | OWNER | Revoke |
| GET | `/api/admin/audit-logs` | ADMIN role | Filters: `status, action, userEmail, documentId, limit, offset` |
| GET | `/api/admin/system-stats` | ADMIN role | Counters |
| GET | `/api/health` | - | Liveness |

## Status - honest list

**Implemented**
- All endpoints above, JWT auth, bcrypt, rate-limited login, upload allowlist and size limit
- Live-DB authorization, immediate revocation, generic 403s, append-only audit log (API + DB triggers)
- Frontend: login, explorer, upload, permission manager, admin audit dashboard
- Jest/Supertest security suite, threat model, prompts log

**Not done / known limitations**
- The test suite and app were written without being executed in the authoring environment (no network to install
  packages). Run `npm install && npm test` and fix anything that surfaces before submitting.
- Uses `prisma db push` rather than versioned migrations.
- No UI for editing document titles (the `PATCH` API exists), no admin user management, no password change, no email verification on sign-up.
- JWT stored in `sessionStorage` (XSS-exposed); no refresh tokens or token revocation list.
- Audit log is append-only but not cryptographically tamper-evident (no hash chain).
- No malware scanning, no content-type sniffing of uploads, no encryption at rest, no HTTPS (use a reverse proxy).
- A download already in progress is not interrupted when access is revoked.
- SQLite only; switch the Prisma provider (and drop the SQLite trigger SQL) for PostgreSQL.
