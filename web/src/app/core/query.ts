import { Api, Filters } from './api';
import { FILTER_FIELDS } from './format';

// Helpers for the query language (docs/QUERIES.md). The appliance parses
// queries; these only write them.

/** Filter keys older links use, which are converted to a query on arrival. */
export const LEGACY_KEYS = FILTER_FIELDS.map((f) => f.id);

const KEYWORDS = ['and', 'or', 'not', 'to'];

/** A value as it must appear in a query: bare when it can be, else quoted. */
export function quoteValue(v: string): string {
  const plain = v !== '' && !/[\s()[\]"!<>&|{}]/.test(v);
  const bare = plain && !v.includes(':') && !KEYWORDS.includes(v.toLowerCase());
  // Addresses and MACs contain colons but read back as one value.
  const network = plain && /^[0-9a-f:.]+(\/\d+)?$/i.test(v) && v.includes(':');
  return bare || network ? v : '"' + v.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

/** One field's term: field:v, field:(a OR b), NOT … when negated. */
export function term(field: string, value: string, negate = false): string {
  let neg = negate;
  if (value.startsWith('!')) {
    neg = !neg;
    value = value.slice(1);
  }
  const vals = value
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean)
    .map(quoteValue);
  if (!vals.length) return '';
  const t = field + ':' + (vals.length > 1 ? '(' + vals.join(' OR ') + ')' : vals[0]);
  return neg ? 'NOT ' + t : t;
}

/** Combines queries with AND; empty ones are skipped. */
export function andQuery(...qs: string[]): string {
  const parts = qs.map((q) => q.trim()).filter(Boolean);
  return parts.length > 1 ? parts.map((q) => '(' + q + ')').join(' AND ') : (parts[0] ?? '');
}

/** Classic filters (field → comma-separated values, ! negating) as a query. */
export function filtersToQuery(f: Filters, negate = false): string {
  return Object.keys(f)
    .filter((k) => k !== 'q' && f[k])
    .sort()
    .map((k) => term(k, f[k], negate))
    .filter(Boolean)
    .join(' AND ');
}

/** The query a page starts with: q, plus any classic filters in the URL. */
export function queryFromParams(params: Record<string, string>, skip: string[] = []): string {
  const legacy: Filters = {};
  for (const k of LEGACY_KEYS) if (params[k] && !skip.includes(k)) legacy[k] = params[k];
  return andQuery(params['q'] ?? '', filtersToQuery(legacy));
}

/** URL parameters that clear the classic filter keys (now part of q). */
export function clearedLegacyParams(skip: string[] = []): Record<string, null> {
  const out: Record<string, null> = {};
  for (const k of LEGACY_KEYS) if (!skip.includes(k)) out[k] = null;
  return out;
}

/** Adds terms to a query with AND, in the appliance's canonical form. */
export async function narrow(api: Api, query: string, add: string): Promise<string> {
  const q = andQuery(query, add);
  if (!add) return query;
  const r = await api.checkQuery(q);
  return r.query ?? q;
}
