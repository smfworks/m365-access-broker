#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { lintMemory, renderReport } from '../src/memoryLinter.js';

// Usage: node bin/lint-memory.js <memoryDir> [--out report.md] [--json]
const args = process.argv.slice(2);
if (args.length === 0 || args[0] === '--help') {
  console.log('Usage: node bin/lint-memory.js <memoryDir> [--out <file>] [--json]');
  process.exit(args.length === 0 ? 1 : 0);
}

const dir = resolve(args[0]);
const outIdx = args.indexOf('--out');
const out = outIdx !== -1 ? args[outIdx + 1] : null;
const asJson = args.includes('--json');

const result = lintMemory(dir);

if (asJson) {
  console.log(JSON.stringify(result, null, 2));
} else {
  const report = renderReport(result);
  if (out) {
    writeFileSync(resolve(out), report);
    console.log(`Wrote ${out} — ${result.issues.length} issue(s) across ${result.scanned} note(s).`);
  } else {
    console.log(report);
  }
}

// Non-zero exit if hygiene problems exist, so it can gate CI / promotion.
process.exit(result.issues.length > 0 ? 2 : 0);
