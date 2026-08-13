// Shared argument validators for tool handlers and the live Graph client.
// Fail closed with BAD_ARGS so the broker never forwards attacker-controlled
// query/path fragments to Microsoft Graph.

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_RECIPIENTS = 50;
const MAX_TOP = 50;

export function badArgs(message) {
  const err = new Error(message);
  err.code = 'BAD_ARGS';
  return err;
}

export function requireArg(args, name) {
  if (args[name] === undefined || args[name] === null || args[name] === '') {
    throw badArgs(`missing_required_arg:${name}`);
  }
}

// Single Graph URL path segment. Rejects empty values and delimiters that
// could change the request target (/ ? #).
export function safeId(id, kind = 'id') {
  if (typeof id !== 'string' || id.trim() === '') {
    throw badArgs(`invalid_${kind}`);
  }
  if (/[/?#]/.test(id)) {
    throw badArgs(`invalid_${kind}`);
  }
  return id;
}

export function encodePathSegment(id, kind = 'id') {
  return encodeURIComponent(safeId(id, kind));
}

// $top must be a finite integer in [1, MAX_TOP]. Non-numeric / out-of-range
// values are rejected rather than interpolated into the query string.
export function safeTop(limit, fallback = 5) {
  if (limit === undefined || limit === null || limit === '') return fallback;
  const n = typeof limit === 'number' ? limit : Number(limit);
  if (!Number.isInteger(n) || n < 1 || n > MAX_TOP) {
    throw badArgs(`invalid_limit:${limit}`);
  }
  return n;
}

export function safeQuery(query) {
  if (query == null) return '';
  if (typeof query !== 'string') throw badArgs('invalid_query');
  return query;
}

export function safeEmails(value, kind = 'to') {
  const list = Array.isArray(value) ? value : typeof value === 'string' ? [value] : null;
  if (!list || list.length === 0) throw badArgs(`invalid_${kind}`);
  if (list.length > MAX_RECIPIENTS) throw badArgs(`too_many_${kind}`);
  const out = [];
  for (const item of list) {
    if (typeof item !== 'string' || !EMAIL.test(item.trim())) {
      throw badArgs(`invalid_${kind}`);
    }
    out.push(item.trim());
  }
  return out;
}

export { MAX_TOP, MAX_RECIPIENTS };
