'use strict';
const request = require('supertest');
const bcrypt = require('bcryptjs');
const app = require('../src/server');
const { prisma, ensureAuditTriggers } = require('../src/db');

const PW = 'TestPass123!';
const SECRET_TEXT = 'TOP-SECRET-CONTENT-12345';

let userA; let userB; let admin;
let tokA; let tokB; let tokAdmin;
let docId; let publicDocId;

const bearer = (t) => ({ Authorization: `Bearer ${t}` });

async function makeUser(email, role = 'USER') {
  return prisma.user.create({
    data: { email, name: email.split('@')[0], role, passwordHash: await bcrypt.hash(PW, 4) },
  });
}

async function login(email) {
  const res = await request(app).post('/api/auth/login').send({ email, password: PW });
  expect(res.status).toBe(200);
  return res.body.token;
}

async function upload(token, title, isPublic = false) {
  const res = await request(app)
    .post('/api/documents/upload')
    .set(bearer(token))
    .field('title', title)
    .field('isPublic', String(isPublic))
    .attach('file', Buffer.from(SECRET_TEXT), { filename: 'secret.txt', contentType: 'text/plain' });
  expect(res.status).toBe(201);
  return res.body.document.id;
}

beforeAll(async () => {
  await ensureAuditTriggers();
  userA = await makeUser('usera@test.local');
  userB = await makeUser('userb@test.local');
  admin = await makeUser('admin@test.local', 'ADMIN');
  tokA = await login('usera@test.local');
  tokB = await login('userb@test.local');
  tokAdmin = await login('admin@test.local');
  docId = await upload(tokA, 'Secret Plan', false);
  publicDocId = await upload(tokA, 'Public Notes', true);
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe('Authentication', () => {
  test('requests without a token get 401', async () => {
    const res = await request(app).get(`/api/documents/${docId}/download`);
    expect(res.status).toBe(401);
  });

  test('garbage / forged tokens get 401', async () => {
    const res = await request(app).get('/api/documents').set(bearer('not.a.jwt'));
    expect(res.status).toBe(401);
  });

  test('wrong password is rejected and audited as DENIED', async () => {
    const res = await request(app).post('/api/auth/login').send({ email: 'usera@test.local', password: 'wrong' });
    expect(res.status).toBe(401);
    const row = await prisma.auditLog.findFirst({ where: { action: 'LOGIN', status: 'DENIED', userEmail: 'usera@test.local' } });
    expect(row).not.toBeNull();
  });

  test('deactivating a user invalidates their existing token immediately', async () => {
    const tmp = await makeUser('temp@test.local');
    const t = await login('temp@test.local');
    expect((await request(app).get('/api/auth/me').set(bearer(t))).status).toBe(200);
    await prisma.user.update({ where: { id: tmp.id }, data: { active: false } });
    expect((await request(app).get('/api/auth/me').set(bearer(t))).status).toBe(401);
  });
});

describe('IDOR prevention', () => {
  test("User B cannot download User A's private file -> 403", async () => {
    const res = await request(app).get(`/api/documents/${docId}/download`).set(bearer(tokB));
    expect(res.status).toBe(403);
    expect(res.text).not.toContain(SECRET_TEXT);
  });

  test('User B cannot read metadata of the private document', async () => {
    const res = await request(app).get(`/api/documents/${docId}`).set(bearer(tokB));
    expect(res.status).toBe(403);
    expect(JSON.stringify(res.body)).not.toContain('Secret Plan');
  });

  test('a real-but-forbidden id and a non-existent id are indistinguishable', async () => {
    const forbidden = await request(app).get(`/api/documents/${docId}`).set(bearer(tokB));
    const missing = await request(app).get('/api/documents/does-not-exist').set(bearer(tokB));
    expect(forbidden.status).toBe(403);
    expect(missing.status).toBe(403);
    expect(forbidden.body).toEqual(missing.body);
    expect(forbidden.body).toEqual({ error: 'Forbidden' });
  });

  test("User B cannot delete, grant on, or edit User A's document", async () => {
    expect((await request(app).delete(`/api/documents/${docId}`).set(bearer(tokB))).status).toBe(403);
    expect(
      (await request(app).post(`/api/documents/${docId}/permissions`).set(bearer(tokB))
        .send({ email: 'userb@test.local', level: 'READ' })).status
    ).toBe(403);
    expect((await request(app).patch(`/api/documents/${docId}`).set(bearer(tokB)).send({ title: 'pwned' })).status).toBe(403);
  });

  test("User B's document list does not include the private document", async () => {
    const res = await request(app).get('/api/documents').set(bearer(tokB));
    expect(res.status).toBe(200);
    const ids = res.body.documents.map((d) => d.id);
    expect(ids).not.toContain(docId);
    expect(ids).toContain(publicDocId);
  });

  test('public document is readable by others but not editable', async () => {
    expect((await request(app).get(`/api/documents/${publicDocId}/download`).set(bearer(tokB))).status).toBe(200);
    expect((await request(app).patch(`/api/documents/${publicDocId}`).set(bearer(tokB)).send({ title: 'x' })).status).toBe(403);
  });
});

describe('Grants and immediate revocation', () => {
  test('grant -> 200 download -> revoke -> next request is 403', async () => {
    const grant = await request(app)
      .post(`/api/documents/${docId}/permissions`)
      .set(bearer(tokA))
      .send({ email: 'userb@test.local', level: 'READ' });
    expect(grant.status).toBe(201);

    const ok = await request(app).get(`/api/documents/${docId}/download`).set(bearer(tokB));
    expect(ok.status).toBe(200);
    expect(ok.text).toBe(SECRET_TEXT);

    const revoke = await request(app).delete(`/api/documents/${docId}/permissions/${userB.id}`).set(bearer(tokA));
    expect(revoke.status).toBe(200);

    // Same still-valid JWT, no waiting: access must already be gone.
    const after = await request(app).get(`/api/documents/${docId}/download`).set(bearer(tokB));
    expect(after.status).toBe(403);
    expect(after.text).not.toContain(SECRET_TEXT);
  });

  test('a READ grant does not allow editing or deleting', async () => {
    await request(app).post(`/api/documents/${docId}/permissions`).set(bearer(tokA)).send({ email: 'userb@test.local', level: 'READ' });
    expect((await request(app).patch(`/api/documents/${docId}`).set(bearer(tokB)).send({ title: 'x' })).status).toBe(403);
    expect((await request(app).delete(`/api/documents/${docId}`).set(bearer(tokB))).status).toBe(403);
    await request(app).delete(`/api/documents/${docId}/permissions/${userB.id}`).set(bearer(tokA));
  });
});

describe('Audit trail', () => {
  test('failed (403) attempts are logged as DENIED with user, document and IP', async () => {
    await request(app).get(`/api/documents/${docId}/download`).set(bearer(tokB));
    const row = await prisma.auditLog.findFirst({
      where: { documentId: docId, userId: userB.id, action: 'DOCUMENT_DOWNLOAD', status: 'DENIED' },
    });
    expect(row).not.toBeNull();
    expect(row.userEmail).toBe('userb@test.local');
    expect(row.ipAddress).toBeTruthy();
  });

  test('successful (200) downloads are logged as ALLOWED', async () => {
    const res = await request(app).get(`/api/documents/${docId}/download`).set(bearer(tokA));
    expect(res.status).toBe(200);
    const row = await prisma.auditLog.findFirst({
      where: { documentId: docId, userId: userA.id, action: 'DOCUMENT_DOWNLOAD', status: 'ALLOWED' },
    });
    expect(row).not.toBeNull();
    expect(row.ipAddress).toBeTruthy();
  });

  test('every attempt creates a new row (one DENIED row per forbidden request)', async () => {
    const before = await prisma.auditLog.count({ where: { documentId: docId, userId: userB.id, status: 'DENIED' } });
    await request(app).get(`/api/documents/${docId}/download`).set(bearer(tokB));
    await request(app).get(`/api/documents/${docId}/download`).set(bearer(tokB));
    const after = await prisma.auditLog.count({ where: { documentId: docId, userId: userB.id, status: 'DENIED' } });
    expect(after - before).toBe(2);
  });

  test('audit log is append-only at the API layer (no update/delete routes)', async () => {
    const row = await prisma.auditLog.findFirst();
    for (const method of ['put', 'patch', 'delete']) {
      const res = await request(app)[method](`/api/admin/audit-logs/${row.id}`).set(bearer(tokAdmin));
      expect([404, 405]).toContain(res.status);
    }
    expect((await request(app).delete('/api/admin/audit-logs').set(bearer(tokAdmin))).status).toBe(404);
  });

  test('audit log is append-only at the database layer (triggers)', async () => {
    const row = await prisma.auditLog.findFirst();
    await expect(prisma.auditLog.update({ where: { id: row.id }, data: { status: 'ALLOWED' } })).rejects.toThrow();
    await expect(prisma.auditLog.delete({ where: { id: row.id } })).rejects.toThrow();
    await expect(prisma.$executeRawUnsafe('DELETE FROM "AuditLog"')).rejects.toThrow();
    await expect(prisma.$executeRawUnsafe(`UPDATE "AuditLog" SET status = 'ALLOWED'`)).rejects.toThrow();
  });
});

describe('Admin endpoints', () => {
  test('non-admin gets 403 and the attempt is audited', async () => {
    const res = await request(app).get('/api/admin/audit-logs').set(bearer(tokB));
    expect(res.status).toBe(403);
    const row = await prisma.auditLog.findFirst({ where: { userId: userB.id, action: 'ROLE_CHECK', status: 'DENIED' } });
    expect(row).not.toBeNull();
  });

  test('admin can read the audit log and stats', async () => {
    const logs = await request(app).get('/api/admin/audit-logs?status=DENIED&limit=10').set(bearer(tokAdmin));
    expect(logs.status).toBe(200);
    expect(logs.body.logs.length).toBeGreaterThan(0);
    expect(logs.body.logs.every((l) => l.status === 'DENIED')).toBe(true);

    const stats = await request(app).get('/api/admin/system-stats').set(bearer(tokAdmin));
    expect(stats.status).toBe(200);
    expect(stats.body.denied).toBeGreaterThan(0);
  });

  test('deleted documents become inaccessible (generic 403)', async () => {
    const tmpId = await upload(tokA, 'To Delete', false);
    expect((await request(app).delete(`/api/documents/${tmpId}`).set(bearer(tokA))).status).toBe(200);
    expect((await request(app).get(`/api/documents/${tmpId}/download`).set(bearer(tokA))).status).toBe(403);
  });
});

describe('Self-registration', () => {
  test('creates a normal USER; no token is issued until they sign in', async () => {
    const res = await request(app).post('/api/auth/register').send({ name: 'New Person', email: 'New.Person@test.local', password: 'Passw0rdOK' });
    expect(res.status).toBe(201);
    expect(res.body.token).toBeUndefined();
    expect(res.body.user.role).toBe('USER');
    expect(res.body.user.email).toBe('new.person@test.local');
    expect(res.body.user.passwordHash).toBeUndefined();

    const signIn = await request(app).post('/api/auth/login').send({ email: 'new.person@test.local', password: 'Passw0rdOK' });
    expect(signIn.status).toBe(200);
    expect((await request(app).get('/api/auth/me').set(bearer(signIn.body.token))).status).toBe(200);
  });

  test('a client-supplied role is ignored (no self-made admins)', async () => {
    const res = await request(app).post('/api/auth/register').send({ name: 'Sneaky', email: 'sneaky@test.local', password: 'Passw0rdOK', role: 'ADMIN' });
    expect(res.status).toBe(201);
    expect(res.body.user.role).toBe('USER');
    const signIn = await request(app).post('/api/auth/login').send({ email: 'sneaky@test.local', password: 'Passw0rdOK' });
    expect((await request(app).get('/api/admin/audit-logs').set(bearer(signIn.body.token))).status).toBe(403);
  });

  test('duplicate email -> 409 and weak password -> 400', async () => {
    const dup = await request(app).post('/api/auth/register').send({ name: 'Dup', email: 'usera@test.local', password: 'Passw0rdOK' });
    expect(dup.status).toBe(409);
    const weak = await request(app).post('/api/auth/register').send({ name: 'Weak', email: 'weak@test.local', password: 'short' });
    expect(weak.status).toBe(400);
  });

  test('registrations are audited', async () => {
    const row = await prisma.auditLog.findFirst({ where: { action: 'REGISTER', status: 'ALLOWED', userEmail: 'new.person@test.local' } });
    expect(row).not.toBeNull();
  });
});
