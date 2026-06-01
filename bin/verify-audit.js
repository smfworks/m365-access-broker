#!/usr/bin/env node
import { resolve } from 'node:path';
import { config } from '../src/config.js';
import { verifyAuditFile } from '../src/audit.js';

// Usage: node bin/verify-audit.js [auditLogPath] [--json]
// Walks the append-only audit log and confirms the hash chain is intact.
// Exit 0 = intact, exit 2 = tamper/break detected, exit 1 = usage error.
const args = process.argv.slice(2);
if (args[0] === '--help') {
  console.log('Usage: node bin/verify-audit.js [auditLogPath] [--json]');
  process.exit(0);
}

const asJson = args.includes('--json');
const pathArg = args.find((a) => !a.startsWith('--'));
const logPath = resolve(pathArg || config.auditLog);

const result = verifyAuditFile(logPath);

if (asJson) {
  console.log(JSON.stringify({ logPath, ...result }, null, 2));
} else if (result.ok) {
  console.log(`audit chain OK — ${result.count} record(s) verified at ${logPath}`);
} else {
  console.error(
    `audit chain BROKEN at record #${result.index} (seq=${result.seq}): ${result.reason} — ${logPath}`
  );
}

process.exit(result.ok ? 0 : 2);
