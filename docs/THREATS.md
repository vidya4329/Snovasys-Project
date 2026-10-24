# TrustVault - Threat Model

Method: STRIDE per asset, with the control, where it lives in the code, and how it is verified.
Assets: (1) document files, (2) document metadata, (3) grants/permissions, (4) the audit trail, (5) credentials/sessions.

> Note: the exact Snovasys scoring criteria were not available while writing this file. The matrix below covers the
> threats named in the challenge brief (IDOR, revocation, audit integrity, leakage). Adjust the headings if your
> brief uses different ones.

## Threat matrix

| # | Threat (STRIDE) | Attack scenario | Mitigation | Code | Test | Residual risk |
|---|---|---|---|---|---|---|
| T1 | Information disclosure - IDOR | User B guesses/steals a document id and calls `/api/documents/:id/download` | Every document route runs `checkDocumentAccess`, which queries live owner/grant/public state per request. No client-side checks are trusted. | `src/middleware/auth.js` | `IDOR prevention` | Ids are UUIDs, but authorization does not depend on them being secret. |
| T2 | Information disclosure - enumeration | Attacker distinguishes "exists but forbidden" from "does not exist" | Both return an identical `403 {"error":"Forbidden"}` body; no metadata in errors. | `checkDocumentAccess` | `indistinguishable` test | Response timing differences are not equalised. |
| T3 | Elevation of privilege - stale access | Revoked user keeps downloading via an old link or cached grant | No presigned/long-lived URLs. Files stream through an authenticated controller that re-reads the grants table on each request. | `GET /api/documents/:id/download` | `Grants and immediate revocation` | A download already streaming when revoked is not interrupted. |
| T4 | Elevation of privilege - stale role in token | Demoted/deactivated user keeps a valid JWT | JWT carries only `sub`. `requireAuth` reloads the user (role, `active`) from the DB each request. | `requireAuth`, `requireRole` | `deactivating a user...` | A token for an active user remains valid until expiry (default 1h) - there is no token blacklist. |
| T5 | Repudiation - missing denials | Attacker probes endpoints; failures leave no trace | Guards write a DENIED row before replying 403; failed logins are logged with the attempted email and IP. | `controllers/audit.js`, guards | `Audit trail` tests | If the DB is down, a denial cannot be recorded (the 403 is still returned). |
| T6 | Repudiation - missing allowed access | Insider reads a file and denies it | ALLOWED rows are written before access is granted. If the audit write fails, the request fails closed (500). | `checkDocumentAccess` | ALLOWED download test | Mutating routes log after success, so a crash between the change and the log can lose one entry. |
| T7 | Tampering - audit log editing | Admin or a bug edits/deletes audit rows | No update/delete routes exist; SQLite triggers abort UPDATE and DELETE on `AuditLog`; no FKs so rows survive user/doc deletion. | `src/db.js` | `append-only` tests (API + DB) | Someone with filesystem access can replace the DB file or drop the triggers. Not tamper-evident (no hash chain). |
| T8 | Spoofing - credential attacks | Brute force / credential stuffing on login | bcrypt (cost 12), per-IP login rate limit, constant-time-ish comparison with a dummy hash for unknown users, generic error message. | `server.js` login | wrong-password test | In-memory rate limiter resets on restart and is per-process; no account lockout or MFA. |
| T9 | Spoofing - token forgery | Forged or `alg=none` JWT | HS256 pinned in `jwt.verify`; secret from env (server refuses to start in production without it). | `config.js`, `requireAuth` | forged-token test | Secret leakage compromises all sessions; no rotation scheme. |
| T10 | Tampering/EoP - malicious upload | Stored XSS or server-side execution via uploaded HTML/SVG/script | Extension allowlist, random on-disk names (no user path), size limit, `Content-Disposition: attachment`, `nosniff`, `CSP: sandbox`. | `server.js` upload + download | (manual) | Extension is checked, but content is not scanned (no magic-byte check or antivirus). |
| T11 | Tampering - path traversal | Crafted filename escapes the upload dir | Stored name is a server-generated UUID; the original name is only used in headers after sanitising. | upload handler | - | Low. |
| T12 | Denial of service | Huge uploads or request floods | Upload size cap, JSON body limit, login rate limit. | `server.js` | - | No global rate limit on other endpoints; no disk quota per user. |
| T13 | Information disclosure - XSS in UI | Malicious title/filename executes in the admin's browser | All dynamic values pass through `esc()`; CSP restricts scripts to self + Tailwind CDN; no inline handlers. | `frontend/app.js`, helmet | - | JWT lives in `sessionStorage`, so any XSS could steal it. HttpOnly cookies + CSRF protection would be stronger. |
| T14 | Elevation of privilege - mass assignment | Client sets `ownerId`, `role`, etc. in a request body | Handlers pick specific fields; ownership comes from the token's user. | all routes | - | Low. |
| T15 | Information disclosure - admin over-reach | Admin reads every document | ADMIN is intentionally all-powerful, but every admin access is audited and admin audit views are themselves logged. | `computeLevel` | - | Admin is a trusted role; a compromised admin sees everything. |

## Trust boundaries
- Browser -> API: untrusted. The UI hides buttons but never decides access.
- API -> database: trusted; all authorization state is read here per request.
- API -> disk: trusted; files are only reachable through the authenticated controller (never served statically).

## Out of scope / not done
HTTPS termination (use a reverse proxy), MFA, token revocation list, antivirus scanning, encryption at rest, hash-chained audit log, backups.
