'use strict';
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const config = require('../src/config');
const { prisma, ensureAuditTriggers } = require('../src/db');

async function upsertUser(email, name, password, role) {
  const passwordHash = await bcrypt.hash(password, 12);
  return prisma.user.upsert({
    where: { email },
    update: { name, passwordHash, role, active: true },
    create: { email, name, passwordHash, role },
  });
}

async function upsertDoc({ id, title, description, content, isPublic, ownerId }) {
  fs.mkdirSync(config.UPLOAD_DIR, { recursive: true });
  const storedName = `${id}.txt`;
  fs.writeFileSync(path.join(config.UPLOAD_DIR, storedName), content, 'utf8');
  const data = {
    title, description, originalName: `${id}.txt`, storedName,
    mimeType: 'text/plain', size: Buffer.byteLength(content), isPublic, ownerId, deletedAt: null,
  };
  return prisma.document.upsert({ where: { id }, update: data, create: { id, ...data } });
}

async function main() {
  await ensureAuditTriggers();

  const admin = await upsertUser('admin@trustvault.local', 'Admin', 'AdminPass123!', 'ADMIN');
  const owner = await upsertUser('owner@trustvault.local', 'Document Owner', 'OwnerPass123!', 'USER');
  const viewer = await upsertUser('viewer@trustvault.local', 'Viewer', 'ViewerPass123!', 'USER');

  await upsertDoc({
    id: 'seed-public-handbook',
    title: 'Company Handbook (Public)',
    description: 'Visible to every authenticated user.',
    content: 'TrustVault demo - public handbook.\nAny signed-in user may read this file.\n',
    isPublic: true,
    ownerId: owner.id,
  });

  await upsertDoc({
    id: 'seed-private-financials',
    title: 'Confidential Financials (Private)',
    description: 'Owner only. The viewer account must receive 403.',
    content: 'TrustVault demo - CONFIDENTIAL.\nOnly the owner and admins may read this file.\n',
    isPublic: false,
    ownerId: owner.id,
  });

  const shared = await upsertDoc({
    id: 'seed-shared-plan',
    title: 'Project Plan (Shared with Viewer)',
    description: 'Private document with a READ grant for the viewer. Revoke it to test immediate revocation.',
    content: 'TrustVault demo - shared project plan.\nThe viewer has a READ grant.\n',
    isPublic: false,
    ownerId: owner.id,
  });

  await prisma.documentPermission.upsert({
    where: { documentId_userId: { documentId: shared.id, userId: viewer.id } },
    update: { level: 'READ', grantedById: owner.id },
    create: { documentId: shared.id, userId: viewer.id, level: 'READ', grantedById: owner.id },
  });

  console.log('Seed complete.');
  console.log(`  admin : ${admin.email} / AdminPass123!`);
  console.log(`  owner : ${owner.email} / OwnerPass123!`);
  console.log(`  viewer: ${viewer.email} / ViewerPass123!`);
}

main()
  .catch((e) => { console.error(e); process.exitCode = 1; })
  .finally(() => prisma.$disconnect());
