import { RULES } from './rules';
import { Change, DecodedJwt, LabeledJwt, Rule, SanitizeResult } from './types';

// Shorter values are only replaced where a rule matched, so a short password doesn't clobber ordinary words.
const MIN_COPY_LENGTH = 8;

// Values that point at a secret instead of holding one: shell and Windows variables, command substitution,
// template variables, placeholders, masks, and labels from an earlier pass.
const REFERENCE =
  /^(?:\$\w+|\$\{[^}]*\}|\$\([^)]*\)|%\w+%|\{\{[^}]*\}\}|<[^<>]+>|\*+|\[(?:redacted|filtered|hidden|masked|removed)\])$/i;

interface Hit {
  rule: string;
  by: Rule['by'];
  start: number;
  end: number;
  kind: string;
  reason: string;
  value: string;
  jwt?: DecodedJwt;
}

interface Span {
  start: number;
  end: number;
  value: string;
  hit?: Hit;
}

export function sanitize(input: string, rules: readonly Rule[] = RULES): SanitizeResult {
  const taken = resolveOverlaps(findAll(input, rules));
  const spans: Span[] = [...taken.map((hit) => ({ start: hit.start, end: hit.end, value: hit.value, hit })), ...findCopies(input, taken)];
  spans.sort((a, b) => a.start - b.start);

  const firstHit = new Map<string, Hit>();
  for (const hit of [...taken].sort((a, b) => a.start - b.start)) if (!firstHit.has(hit.value)) firstHit.set(hit.value, hit);

  const labels = new Map<string, string>();
  const changes: Change[] = [];
  const jwts: LabeledJwt[] = [];
  let output = '';
  let pos = 0;
  let line = 1;
  for (const span of spans) {
    let label = labels.get(span.value);
    const source = firstHit.get(span.value)!;
    if (!label) {
      label = `${source.kind}#${labels.size + 1}`;
      labels.set(span.value, label);
      if (source.jwt) jwts.push({ label, ...source.jwt });
    }
    line += countNewlines(input, pos, span.start);
    output += `${input.slice(pos, span.start)}<${label}>`;
    const hit = span.hit;
    changes.push({
      label,
      kind: source.kind,
      rule: hit?.rule ?? source.rule,
      reason: hit?.reason ?? `same value as ${label}`,
      line,
      start: span.start,
      end: span.end,
      value: span.value,
    });
    line += countNewlines(input, span.start, span.end);
    pos = span.end;
  }
  return { output: output + input.slice(pos), changes, jwts };
}

function findAll(input: string, rules: readonly Rule[]): Hit[] {
  return rules.flatMap((rule) =>
    rule
      .find(input)
      .map((f) => ({ ...f, rule: rule.name, by: rule.by, value: input.slice(f.start, f.end) }))
      .filter((hit) => hit.value !== '' && !REFERENCE.test(hit.value)),
  );
}

// Most specific wins: format before context, then the longer span. A finding that overlaps one already
// taken merges into it, so the union is replaced and nothing next to the specific match leaks.
function resolveOverlaps(hits: Hit[]): Hit[] {
  const rank = (hit: Hit) => (hit.by === 'format' ? 0 : 1);
  const ordered = [...hits].sort((a, b) => rank(a) - rank(b) || b.end - b.start - (a.end - a.start) || a.start - b.start);
  const taken: Hit[] = [];
  for (const hit of ordered) {
    const overlapping = taken.filter((t) => hit.start < t.end && t.start < hit.end);
    if (overlapping.length === 0) taken.push({ ...hit });
    else if (overlapping.length === 1) {
      const t = overlapping[0]!;
      t.start = Math.min(t.start, hit.start);
      t.end = Math.max(t.end, hit.end);
    }
  }
  return taken;
}

function findCopies(input: string, taken: Hit[]): Span[] {
  const covered: Span[] = [...taken];
  const copies: Span[] = [];
  const values = [...new Set(taken.map((hit) => hit.value))]
    .filter((value) => value.length >= MIN_COPY_LENGTH)
    .sort((a, b) => b.length - a.length);
  for (const value of values) {
    for (let at = input.indexOf(value); at !== -1; at = input.indexOf(value, at + value.length)) {
      const end = at + value.length;
      if (covered.some((s) => at < s.end && s.start < end)) continue;
      const copy = { start: at, end, value };
      covered.push(copy);
      copies.push(copy);
    }
  }
  return copies;
}

function countNewlines(text: string, from: number, to: number): number {
  let n = 0;
  for (let i = text.indexOf('\n', from); i !== -1 && i < to; i = text.indexOf('\n', i + 1)) n++;
  return n;
}
