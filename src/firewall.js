// Injection firewall. Retrieved Microsoft 365 / web content is EVIDENCE, never
// instruction. This module scans untrusted text for instruction-like and
// exfiltration patterns, scores risk, and wraps content so the agent loop
// treats it as data.
//
// It does not "clean" prose by rewriting it — neutralization here means
// (1) tagging the content as external data and (2) surfacing findings so the
// broker/agent can refuse to act on embedded commands.

export const SEVERITY = Object.freeze({ LOW: 1, MEDIUM: 2, HIGH: 3 });

// Each rule: id, severity, regex, why.
export const RULES = Object.freeze([
  // Direct instruction overrides
  { id: 'ignore_previous', severity: SEVERITY.HIGH, re: /\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b[^.\n]{0,20}\b(instruction|prompt|message|context|rule)s?\b/i, why: 'instruction override' },
  { id: 'new_instructions', severity: SEVERITY.HIGH, re: /\b(new|updated|revised)\s+(instruction|directive|system\s+prompt)s?\b\s*[:\-]/i, why: 'instruction injection' },
  { id: 'role_override', severity: SEVERITY.HIGH, re: /\byou\s+are\s+now\b|\bact\s+as\b[^.\n]{0,30}\b(admin|root|developer|system)\b|\bfrom\s+now\s+on\b/i, why: 'role/persona override' },
  { id: 'system_prompt_probe', severity: SEVERITY.MEDIUM, re: /\b(reveal|print|show|repeat|output)\b[^.\n]{0,30}\b(system\s+prompt|instructions|rules|your\s+prompt)\b/i, why: 'prompt-extraction attempt' },
  { id: 'pretend_developer', severity: SEVERITY.MEDIUM, re: /\b(developer|debug|maintenance)\s+mode\b|\bDAN\b|\bjailbreak\b/i, why: 'jailbreak framing' },

  // Coercive / consequential actions
  { id: 'send_to_everyone', severity: SEVERITY.HIGH, re: /\bsend\b[^.\n]{0,30}\b(everyone|all\s+(contacts|users|recipients|staff))\b|\bforward\b[^.\n]{0,20}\bto\s+(everyone|all)\b/i, why: 'mass-send command' },
  { id: 'delete_command', severity: SEVERITY.HIGH, re: /\b(delete|remove|wipe|erase)\b[^.\n]{0,30}\b(file|message|email|all|original|everything|record)s?\b/i, why: 'destructive command' },
  { id: 'approve_immediately', severity: SEVERITY.MEDIUM, re: /\bapprove\b[^.\n]{0,20}\b(immediately|now|this|without\s+(review|asking|confirmation))\b/i, why: 'forced-approval command' },
  { id: 'secrecy', severity: SEVERITY.HIGH, re: /\b(do\s+not|don't|never)\b[^.\n]{0,20}\b(tell|inform|notify|mention\s+to|alert)\b[^.\n]{0,20}\b(michael|the\s+user|anyone|owner)\b/i, why: 'secrecy / hide-from-user' },

  // Exfiltration
  { id: 'exfil_credentials', severity: SEVERITY.HIGH, re: /\b(send|email|post|upload|exfiltrate|leak)\b[^\n]{0,40}(password|secret|token|api[_-]?key|credential|cookie|\.env)\b/i, why: 'credential exfiltration' },
  { id: 'exfil_url', severity: SEVERITY.MEDIUM, re: /\b(curl|wget|fetch|POST)\b[^.\n]{0,30}https?:\/\//i, why: 'outbound request to attacker URL' },
  { id: 'tool_call_injection', severity: SEVERITY.HIGH, re: /<tool_call|<function_call|```tool|"tool"\s*:\s*"|invoke\s+(the\s+)?(send_email|delete_file|share_file)/i, why: 'forged tool-call markup' },

  // Obfuscation
  { id: 'zero_width', severity: SEVERITY.MEDIUM, re: /[\u200B-\u200D\uFEFF\u2060]/, why: 'zero-width/hidden characters' },
  { id: 'base64_blob', severity: SEVERITY.LOW, re: /\b[A-Za-z0-9+/]{120,}={0,2}\b/, why: 'large base64 blob (possible hidden payload)' },
  { id: 'html_comment_instruction', severity: SEVERITY.MEDIUM, re: /<!--[^>]*\b(ignore|send|delete|approve|system\s+prompt|instruction)\b[^>]*-->/i, why: 'instruction hidden in HTML comment' },
]);

const ZERO_WIDTH = /[\u200B-\u200D\uFEFF\u2060]/g;
// Null bytes can split trigger words to bypass bounded [^.​\n] patterns:
// "ignore\u0000 previous instructions" would not match without this.
const NULL_BYTES = /\u0000/g;
// Homoglyphs: confusable Unicode that looks like ASCII letters/digits.
// Normalize Cyrillic, Greek, and fullwidth look-alikes to ASCII equivalents
// so injection patterns cannot evade detection via visual substitution.
const HOMOGLYPHS = [
  [/\u0430/g, 'a'], // Cyrillic а
  [/\u0435/g, 'e'], // Cyrillic е
  [/\u043E/g, 'o'], // Cyrillic о
  [/\u0440/g, 'p'], // Cyrillic р
  [/\u0441/g, 'c'], // Cyrillic с
  [/\u0443/g, 'y'], // Cyrillic у
  [/\u0445/g, 'x'], // Cyrillic х
  [/\u0410/g, 'A'], // Cyrillic А
  [/\u0415/g, 'E'], // Cyrillic Е
  [/\u041E/g, 'O'], // Cyrillic О
  [/\u0420/g, 'P'], // Cyrillic Р
  [/\u0421/g, 'C'], // Cyrillic С
  [/\uFF21/g, 'A'], // Fullwidth A
  [/\uFF41/g, 'a'], // Fullwidth a
  [/\uFF2F/g, 'O'], // Fullwidth O
  [/\uFF4F/g, 'o'], // Fullwidth o
];

function riskFromScore(score) {
  if (score >= SEVERITY.HIGH) return 'high';
  if (score >= SEVERITY.MEDIUM) return 'medium';
  if (score >= SEVERITY.LOW) return 'low';
  return 'none';
}

/**
 * Scan untrusted text. Returns findings + a max-severity risk label.
 *
 * To defeat trivial evasions, every rule is evaluated against three views of the
 * text: the original (so zero-width/base64/HTML-comment rules still see their
 * markers), a copy with zero-width characters removed (so hidden separators
 * cannot downgrade risk), and a newline-flattened copy (so line breaks inserted
 * between trigger words cannot slip past bounded `[^.\n]` patterns).
 * @param {string} text
 */
export function scanContent(text) {
  const findings = [];
  if (typeof text !== 'string' || text.length === 0) {
    return { risk: 'none', score: 0, findings };
  }
  // Build evasion-resistant variants:
  // 1. Original (so zero-width/null/base64/HTML-comment markers are visible).
  // 2. Zero-width stripped (hidden separators can't downgrade risk).
  // 3. Null-byte stripped (split words rejoined).
  // 4. Homoglyph-normalized (Cyrillic/etc. → ASCII so word patterns match).
  // 5. Newline-flattened (line breaks can't slip past [^.\n] patterns).
  const zwStripped = text.replace(ZERO_WIDTH, '');
  const nullStripped = zwStripped.replace(NULL_BYTES, '');
  let homoStripped = nullStripped;
  for (const [re, replacement] of HOMOGLYPHS) {
    homoStripped = homoStripped.replace(re, replacement);
  }
  const flattened = homoStripped.replace(/[\r\n]+/g, ' ');
  const variants = [text, zwStripped, nullStripped, homoStripped, flattened];
  const seen = new Set();
  let maxScore = 0;
  for (const rule of RULES) {
    for (const variant of variants) {
      const m = rule.re.exec(variant);
      if (!m) continue;
      if (!seen.has(rule.id)) {
        seen.add(rule.id);
        findings.push({
          id: rule.id,
          severity: rule.severity,
          why: rule.why,
          match: m[0].slice(0, 80),
        });
      }
      if (rule.severity > maxScore) maxScore = rule.severity;
      break;
    }
  }
  return { risk: riskFromScore(maxScore), score: maxScore, findings };
}

/**
 * Wrap retrieved content as external data and attach a security verdict.
 * Strips zero-width characters. Never executes or rewrites the prose.
 * @returns {{wrapped:string, risk:string, findings:object[], source:string}}
 */
export function sanitize(text, { source = 'unknown', maxLen = 100_000 } = {}) {
  const raw = typeof text === 'string' ? text : JSON.stringify(text ?? '');
  const verdict = scanContent(raw);
  const cleaned = raw.replace(ZERO_WIDTH, '').replace(NULL_BYTES, '').slice(0, maxLen);
  // Escape the source so it cannot break out of the attribute, and neutralize
  // any wrapper tags inside the body so untrusted content cannot forge an early
  // </external_content> and escape the evidence envelope.
  const safeSource = String(source)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
  const safeBody = cleaned.replace(/<(\/?)(external_content)/gi, '&lt;$1$2');
  const wrapped =
    `<external_content source="${safeSource}" risk="${verdict.risk}">\n` +
    `${safeBody}\n` +
    `</external_content>`;
  return { wrapped, risk: verdict.risk, findings: verdict.findings, source };
}

/**
 * Convenience policy hook: should the broker block auto-actions derived from
 * this content? High-risk content should never trigger autonomous writes.
 */
export function shouldBlockAutoAction(verdict) {
  return verdict.risk === 'high';
}
