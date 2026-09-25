import { RULES } from './rules';
import { Change, DecodedJwt, LabeledJwt, Rule, SanitizeResult } from './types';

// Shorter values are only replaced where a rule matched, so a short password doesn't clobber ordinary words.
const MIN_COPY_LENGTH = 8;

// Values that point at a secret instead of holding one: shell and Windows variables, command substitution,
// template variables, placeholders, masks, and labels from an earlier pass. Also values that hold nothing.
const REFERENCE =
  /^(?:\$\w+|\$\{[^}]*\}|\$\([^)]*\)|%\w+%|\{\{[^}]*\}\}|<[^<>]+>|\*+|\[(?:redacted|filtered|hidden|masked|removed)\]|null|undefined|true|false|none|nil)$/i;
// Output of an earlier pass: labels with only punctuation between them, such as <jwt#1>|<jwt#2>.
const LABELS = /^(?=.*<[^<>\s]+#\d+>)(?:<[^<>\s]+#\d+>|[^\p{L}\p{N}<>])+$/u;
const FREE = -1;
const COPY = -2;

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
  // Which taken finding (by index) or copy covers each character of the input.
  const owner = new Int32Array(input.length).fill(FREE);
  const taken = resolveOverlaps(input, findAll(input, rules), owner);
  const spans: Span[] = [
    ...taken.map((hit) => ({ start: hit.start, end: hit.end, value: hit.value, hit })),
    ...findCopies(input, taken, owner),
  ];
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
      .filter((hit) => hit.value !== '' && !REFERENCE.test(hit.value) && !LABELS.test(hit.value)),
  );
}

// Most specific wins: format before context, then the longer span. A finding that overlaps one already
// taken merges into it, so the union is replaced and nothing next to the specific match leaks. When it
// overlaps several, each keeps its label and the letters and digits between them go to a neighbour.
function resolveOverlaps(input: string, hits: Hit[], owner: Int32Array): Hit[] {
  const rank = (hit: Hit) => (hit.by === 'format' ? 0 : 1);
  const ordered = [...hits].sort((a, b) => rank(a) - rank(b) || b.end - b.start - (a.end - a.start) || a.start - b.start);
  const taken: Hit[] = [];
  const claim = (id: number, start: number, end: number) => {
    owner.fill(id, start, end);
    const t = taken[id]!;
    t.start = Math.min(t.start, start);
    t.end = Math.max(t.end, end);
  };
  for (const hit of ordered) {
    const ids = new Set<number>();
    for (let i = hit.start; i < hit.end; i++) if (owner[i]! >= 0) ids.add(owner[i]!);
    if (ids.size === 0) owner.fill(taken.push({ ...hit }) - 1, hit.start, hit.end);
    else if (ids.size === 1) claim([...ids][0]!, hit.start, hit.end);
    else {
      for (let i = hit.start; i < hit.end; ) {
        if (owner[i]! >= 0) {
          i++;
          continue;
        }
        let end = i;
        while (end < hit.end && owner[end]! < 0) end++;
        if (/[\p{L}\p{N}]/u.test(input.slice(i, end))) claim(i > hit.start ? owner[i - 1]! : owner[end]!, i, end);
        i = end;
      }
    }
  }
  return taken;
}

// Scans once. Values often share a prefix (every JWT starts eyJhbGci), so a prefix leads to the lengths
// worth trying rather than to every value.
function findCopies(input: string, taken: Hit[], owner: Int32Array): Span[] {
  const values = new Set(taken.map((hit) => hit.value).filter((value) => value.length >= MIN_COPY_LENGTH));
  const lengthsByPrefix = new Map<string, number[]>();
  for (const value of values) {
    const prefix = value.slice(0, MIN_COPY_LENGTH);
    const lengths = lengthsByPrefix.get(prefix) ?? [];
    if (!lengths.includes(value.length)) lengthsByPrefix.set(prefix, [...lengths, value.length].sort((a, b) => b - a));
  }
  const copies: Span[] = [];
  if (values.size === 0) return copies;
  const isFree = (start: number, end: number) => owner.subarray(start, end).every((id) => id === FREE);
  for (let at = 0; at + MIN_COPY_LENGTH <= input.length; at++) {
    if (owner[at] !== FREE) continue;
    const lengths = lengthsByPrefix.get(input.slice(at, at + MIN_COPY_LENGTH));
    const length = lengths?.find((n) => values.has(input.slice(at, at + n)) && isFree(at, at + n));
    if (length === undefined) continue;
    owner.fill(COPY, at, at + length);
    copies.push({ start: at, end: at + length, value: input.slice(at, at + length) });
    at += length - 1;
  }
  return copies;
}

function countNewlines(text: string, from: number, to: number): number {
  let n = 0;
  for (let i = text.indexOf('\n', from); i !== -1 && i < to; i = text.indexOf('\n', i + 1)) n++;
  return n;
}
