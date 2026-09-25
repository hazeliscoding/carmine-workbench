export interface DiffLine {
  op: 'same' | 'del' | 'add';
  text: string;
  a?: number;
  b?: number;
}

export interface Segment {
  text: string;
  hit: boolean;
}

// Line diff by longest common subsequence. Removed lines come before the added lines that replace them.
export function diffLines(before: string, after: string): DiffLine[] {
  const a = before.split('\n');
  const b = after.split('\n');
  const lcs = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j]) out.push({ op: 'same', text: a[i], a: ++i, b: ++j });
    else if (i < a.length && (j >= b.length || lcs[i + 1][j] >= lcs[i][j + 1])) out.push({ op: 'del', text: a[i], a: ++i });
    else out.push({ op: 'add', text: b[j], b: ++j });
  }
  return out;
}

// Splits text so each occurrence of a needle becomes its own segment.
export function segments(text: string, needles: string[]): Segment[] {
  const found = needles.filter(Boolean);
  if (!found.length) return [{ text, hit: false }];
  const escaped = found.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  return text
    .split(new RegExp(`(${escaped.join('|')})`))
    .filter(Boolean)
    .map((part) => ({ text: part, hit: found.includes(part) }));
}
