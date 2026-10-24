# PROMPTS.md - AI-assisted development log

**Please read first.** This file records the prompt used and five issues that were identified while reviewing the
AI-generated draft of this codebase on 2026-10-24. Before you submit, edit it so every entry reflects what actually
happened in *your* sessions (add your own prompts, dates, and any other mistakes the AI made). Do not submit entries
that did not happen.

## Master prompt (summary)
Role: Principal Security Engineer + Full-Stack Architect. Build "TrustVault" with zero-trust server-side
authorization, immediate revocation via authenticated streaming downloads, an append-only audit trail of both ALLOWED
and DENIED attempts, and generic 403s to prevent IDOR/leakage. Stack: Node/Express, Prisma, JWT + bcrypt, vanilla JS +
Tailwind frontend, Jest + Supertest. Layout: `backend/`, `frontend/`, `docs/`.

---

## Entry 1 - 2026-10-24 - Authorization: roles/grants baked into the JWT
- **Problem in draft:** A common generated pattern puts `role` (and sometimes document grants) in the JWT and trusts it
  in middleware. After revocation or demotion the old token still works until it expires, violating "revoked 1 ms ago
  must fail".
- **How found:** Reviewed against requirement 2 (immediate revocation).
- **Fix:** Token carries only `sub`. `requireAuth` reloads the user from the DB; `checkDocumentAccess` queries grants on
  every request. Tests: `deactivating a user...` and `grant -> download -> revoke -> 403`.

## Entry 2 - 2026-10-24 - Authorization: 404 for missing, 403 for forbidden (existence leak)
- **Problem in draft:** `findUnique` -> 404 if not found, 403 if found-but-not-allowed. That lets an attacker probe which
  document ids exist (IDOR information leak).
- **How found:** Reviewed against requirement 4.
- **Fix:** One code path: missing, deleted, and unauthorized all return identical `403 {"error":"Forbidden"}`. Test:
  `a real-but-forbidden id and a non-existent id are indistinguishable`.

## Entry 3 - 2026-10-24 - Audit logs: denials not recorded
- **Problem in draft:** Guards that `return res.status(403)` early skip the route handler where logging happened, so
  DENIED attempts (the interesting ones) left no trace; and a failed audit write on success was swallowed.
- **How found:** Traced the 403 code path by hand and asked "who writes the row?".
- **Fix:** Logging lives inside the guards (`checkDocumentAccess`, `requireRole`) before the response is sent; ALLOWED
  audit failures fail closed. Tests: `Audit trail` suite.

## Entry 4 - 2026-10-24 - Audit logs: "append-only" only by convention
- **Problem in draft:** The audit table was append-only only because no route updated it; any future code or a direct
  Prisma call could still `UPDATE`/`DELETE`.
- **How found:** Asked "what stops a bug from editing history?".
- **Fix:** SQLite `BEFORE UPDATE/DELETE` triggers that `RAISE(ABORT)`, plus no FKs so deleting users/docs cannot cascade
  into the log. Tests: `append-only at the database layer`.

## Entry 5 - 2026-10-24 - Downloads: unsafe serving of uploaded files
- **Problem in draft:** Serving uploads with the client-supplied MIME type inline, or from a static directory, allows
  stored XSS and bypasses the authorization controller entirely.
- **How found:** Reviewed the download route against requirement 2.
- **Fix:** Uploads live outside the static root with random names; only the authenticated controller serves them with
  `Content-Disposition: attachment`, `nosniff`, `CSP: sandbox`, and an extension allowlist on upload.
