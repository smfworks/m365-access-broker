import { readdirSync, readFileSync, statSync } from 'node:fs';
import { resolve, join, relative } from 'node:path';

// Memory hygiene linter for OpenClaw's agent memory layer.
// Forked in spirit from the SecondBrain vault linter (justin-lint), but tuned
// to the broker's memory-promotion rules: summarize don't hoard, attach
// provenance, decay stale facts, never store secrets, surface contradictions.
//
// Operates on a directory of Markdown memory notes with simple `key: value`
// frontmatter delimited by `---`.

const DEFAULTS = Object.freeze({
  staleDays: 180,
  hoardChars: 600, // verbatim body longer than this is "hoarding"
});

const SECRET_PATTERNS = [
  { id: 'bearer_token', re: /\bBearer\s+[A-Za-z0-9._-]{12,}/ },
  { id: 'api_key', re: /\b(api[_-]?key|secret|password|client_secret)\b\s*[:=]\s*\S{6,}/i },
  { id: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/ },
  { id: 'dotenv_line', re: /^[A-Z][A-Z0-9_]{2,}=.+$/m },
];

const PROVENANCE_KEYS = ['source', 'sources', 'src', 'provenance'];
const EXTERNAL_SOURCE = /\b(email|mail|web|chat|teams|external|attachment|file)\b/i;

export function parseFrontmatter(text) {
  const fm = {};
  let body = text;
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(text);
  if (m) {
    body = m[2];
    const lines = m[1].split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const idx = line.indexOf(':');
      if (idx === -1) continue;
      const key = line.slice(0, idx).trim();
      if (!key) continue;
      let val = line.slice(idx + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      // Inline array: key: [a, b]
      if (val.startsWith('[') && val.endsWith(']')) {
        val = val
          .slice(1, -1)
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
          .join(', ');
      }
      // Block array: key: followed by indented "- item" lines.
      if (val === '') {
        const items = [];
        while (i + 1 < lines.length && /^\s*-\s+/.test(lines[i + 1])) {
          items.push(lines[++i].replace(/^\s*-\s+/, '').trim());
        }
        if (items.length) val = items.join(', ');
      }
      fm[key] = val;
    }
  }
  return { frontmatter: fm, body };
}

function daysAgo(dateStr) {
  const t = Date.parse(dateStr);
  if (Number.isNaN(t)) return null;
  return Math.floor((Date.now() - t) / 86_400_000);
}

function hasProvenance(fm) {
  return PROVENANCE_KEYS.some((k) => fm[k] && String(fm[k]).trim() !== '' && String(fm[k]).trim() !== '[]');
}

function listMarkdown(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) out.push(...listMarkdown(full));
    else if (name.endsWith('.md')) out.push(full);
  }
  return out;
}

/**
 * Lint a memory directory. Read-only; flags, never resolves.
 * @returns {{scanned:number, issues:object[], byCheck:object}}
 */
export function lintMemory(memoryDir, options = {}) {
  const opts = { ...DEFAULTS, ...options };
  const root = resolve(memoryDir);
  const files = listMarkdown(root);
  const issues = [];

  for (const file of files) {
    const rel = relative(root, file).replace(/\\/g, '/');
    const text = readFileSync(file, 'utf8');
    const { frontmatter: fm, body } = parseFrontmatter(text);

    // 1. Missing provenance
    if (!hasProvenance(fm)) {
      issues.push({ check: 'missing_provenance', file: rel, detail: 'no source/provenance frontmatter' });
    }

    // 2. Hoarding raw content
    const raw = String(fm.raw || '').toLowerCase() === 'true';
    if (raw || body.trim().length > opts.hoardChars) {
      issues.push({
        check: 'hoarding',
        file: rel,
        detail: raw ? 'flagged raw:true' : `body ${body.trim().length} chars > ${opts.hoardChars} (summarize, don't hoard)`,
      });
    }

    // 3. Stale facts (decay)
    const updated = fm.updated || fm.date;
    const status = String(fm.status || '').toLowerCase();
    if (updated && (status === 'durable' || status === 'evergreen')) {
      const age = daysAgo(updated);
      if (age != null && age > opts.staleDays) {
        issues.push({ check: 'stale', file: rel, detail: `updated ${updated} (${age}d ago), status=${status}` });
      }
    }

    // 4. Secrets stored in memory (scan body only — our own frontmatter keys
    // are structured metadata, not secret material).
    for (const p of SECRET_PATTERNS) {
      if (p.re.test(body)) {
        issues.push({ check: 'secret', file: rel, detail: `possible secret (${p.id})` });
        break;
      }
    }

    // 5. Contradictions
    const contra = /<!--\s*CONTRADICTION/i.exec(text);
    if (contra) {
      issues.push({ check: 'contradiction', file: rel, detail: 'CONTRADICTION marker present' });
    }

    // 6. External source treated as authoritative without review
    if (hasProvenance(fm)) {
      const srcVal = PROVENANCE_KEYS.map((k) => fm[k]).filter(Boolean).join(' ');
      const reviewed = String(fm.reviewed || '').toLowerCase() === 'true';
      if (EXTERNAL_SOURCE.test(srcVal) && (status === 'durable' || status === 'evergreen') && !reviewed) {
        issues.push({ check: 'unreviewed_external', file: rel, detail: `external source "${srcVal}" marked ${status} but reviewed!=true` });
      }
    }
  }

  const byCheck = {};
  for (const i of issues) byCheck[i.check] = (byCheck[i.check] || 0) + 1;
  return { scanned: files.length, issues, byCheck };
}

const CHECK_TITLES = {
  missing_provenance: 'Missing provenance',
  hoarding: 'Hoarding raw content',
  stale: 'Stale facts (decay)',
  secret: 'Secrets in memory',
  contradiction: 'Contradiction markers',
  unreviewed_external: 'Unreviewed external facts',
};

export function renderReport(result, { now = new Date() } = {}) {
  const stamp = now.toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
  const lines = [];
  lines.push('---');
  lines.push('title: "Memory Hygiene Report"');
  lines.push('type: report');
  lines.push(`generated: ${stamp}`);
  lines.push('auto_generated: true');
  lines.push('---');
  lines.push('');
  lines.push('# Memory Hygiene Report');
  lines.push('');
  lines.push(`Run: ${stamp}`);
  lines.push(`Notes scanned: ${result.scanned}`);
  lines.push(`Issues found: ${result.issues.length}`);
  lines.push('');
  for (const [check, title] of Object.entries(CHECK_TITLES)) {
    const items = result.issues.filter((i) => i.check === check);
    lines.push(`## ${title} (${items.length})`);
    for (const i of items) lines.push(`- \`${i.file}\` — ${i.detail}`);
    lines.push('');
  }
  return lines.join('\n');
}
