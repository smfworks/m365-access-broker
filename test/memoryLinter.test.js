import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { lintMemory, renderReport, parseFrontmatter } from '../src/memoryLinter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures = resolve(__dirname, 'fixtures/memory');

test('parseFrontmatter extracts keys and body', () => {
  const { frontmatter, body } = parseFrontmatter('---\na: 1\nb: "two"\n---\nhello');
  assert.equal(frontmatter.a, '1');
  assert.equal(frontmatter.b, 'two');
  assert.equal(body.trim(), 'hello');
});

test('lints fixture vault and finds one of each issue class', () => {
  const r = lintMemory(fixtures);
  assert.equal(r.scanned, 8);
  assert.equal(r.byCheck.missing_provenance, 1);
  assert.equal(r.byCheck.hoarding, 1);
  assert.equal(r.byCheck.stale, 1);
  assert.equal(r.byCheck.secret, 1);
  assert.equal(r.byCheck.contradiction, 1);
  assert.equal(r.byCheck.unreviewed_external, 1);
});

test('clean note produces no issues', () => {
  const r = lintMemory(fixtures);
  assert.ok(!r.issues.some((i) => i.file === 'clean.md'));
});

test('note with YAML-array provenance is not flagged missing_provenance', () => {
  const r = lintMemory(fixtures);
  assert.ok(!r.issues.some((i) => i.file === 'multi-source.md'));
});

test('renderReport includes all check sections and counts', () => {
  const r = lintMemory(fixtures);
  const report = renderReport(r, { now: new Date('2026-05-30T18:00:00Z') });
  assert.match(report, /# Memory Hygiene Report/);
  assert.match(report, /Notes scanned: 8/);
  assert.match(report, /## Missing provenance \(1\)/);
  assert.match(report, /## Secrets in memory \(1\)/);
  assert.match(report, /## Contradiction markers \(1\)/);
});

test('staleDays option is configurable', () => {
  // With a huge threshold nothing is stale.
  const r = lintMemory(fixtures, { staleDays: 100000 });
  assert.equal(r.byCheck.stale, undefined);
});
