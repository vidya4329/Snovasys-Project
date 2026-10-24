'use strict';
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

/**
 * Database-level enforcement of the append-only audit trail.
 * Even code that bypasses the HTTP layer (or a future bug) cannot
 * UPDATE or DELETE rows in "AuditLog" - SQLite aborts the statement.
 */
async function ensureAuditTriggers() {
  await prisma.$executeRawUnsafe(
    `CREATE TRIGGER IF NOT EXISTS auditlog_block_update BEFORE UPDATE ON "AuditLog" BEGIN SELECT RAISE(ABORT, 'AuditLog is append-only'); END;`
  );
  await prisma.$executeRawUnsafe(
    `CREATE TRIGGER IF NOT EXISTS auditlog_block_delete BEFORE DELETE ON "AuditLog" BEGIN SELECT RAISE(ABORT, 'AuditLog is append-only'); END;`
  );
}

module.exports = { prisma, ensureAuditTriggers };
