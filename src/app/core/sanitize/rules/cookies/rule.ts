import { Finding, Rule } from '../../types';

// A Cookie or Set-Cookie header name, optionally quoted as a JSON or Python key, then a colon and an
// optional opening quote.
const HEADER = /(?<![\w-])(["']?)(set-cookie|cookie)\1[ \t]*:[ \t]*["']?/gi;
const CURL = /(?<!\S)(?:-b[ \t]*|--cookie(?:=|[ \t]+))["']?/g;
// One name=value pair. A cookie value can't hold whitespace, quotes, commas, semicolons or backslashes,
// except for a pair of double quotes around the whole value.
const PAIR = /[ \t]*([^\s=;,"']+)=("?)([^\s;,"'\\]*)\2/dy;

export const cookies: Rule = {
  name: 'cookies',
  by: 'context',
  find: (text) => [
    // Set-Cookie holds one cookie; the pairs after it are attributes such as Path and Expires.
    ...[...text.matchAll(HEADER)].flatMap((m) => pairs(text, m.index + m[0].length, m[2]!.toLowerCase() === 'set-cookie')),
    ...[...text.matchAll(CURL)].flatMap((m) => pairs(text, m.index + m[0].length, false)),
  ],
};

function pairs(text: string, at: number, firstOnly: boolean): Finding[] {
  const found: Finding[] = [];
  for (let pos = at; ; ) {
    PAIR.lastIndex = pos;
    const p = PAIR.exec(text);
    if (!p) break;
    const [name, value] = [p[1]!, p[3]!];
    const [start, end] = p.indices![3]!;
    if (value && !isPlainShort(value)) found.push({ start, end, kind: `cookie:${name}`, reason: `${name} cookie` });
    pos = p.index + p[0].length;
    if (firstOnly || text[pos] !== ';') break;
    pos++;
  }
  return found;
}

// Preferences such as theme=dark or lang=en-US help debugging and grant nothing.
function isPlainShort(value: string): boolean {
  return value.length < 8 && /^[\w.-]+$/.test(value);
}
