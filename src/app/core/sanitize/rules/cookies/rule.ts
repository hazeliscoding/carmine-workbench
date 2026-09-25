import { Finding, Rule } from '../../types';
import { START } from '../shared';

// A Cookie or Set-Cookie header name, optionally quoted as a JSON or Python key (escaped when the JSON
// sits inside a log string, or a Python b'' string), then a colon and an optional opening quote or Go
// map bracket.
const HEADER = new RegExp(
  String.raw`${START}(?:[bBrRuUfF]{0,2}(\\?["']))?(set-cookie|cookie)\1[ \t]*:[ \t]*\[?(?:[bBrRuUfF]{0,2}\\?["'])?`,
  'gi',
);
const CURL = /(?<!\S)(?:-b[ \t]*|--cookie(?:=|[ \t]+))["']?/g;
// One name=value pair. The name is an RFC 6265 token, and the value can't hold whitespace, quotes, commas,
// semicolons or backslashes, except for a pair of double quotes around the whole value.
const PAIR = /[ \t]*([^\s=;,"'\\[\]()<>@:/?{}]+)=("?)([^\s;,"'\\[\]]*)\2/dy;
const NEXT_PAIR = /[ \t]*;/y;
// Set-Cookie attributes such as Path and Expires. The comma in "Expires=Thu, 24 Sep …" comes before a digit.
const ATTRIBUTES = /(?:[ \t]*;[ \t]*[^;,\r\n\\'"]*(?:,[ \t]*\d[^;,\r\n\\'"]*)?)*/y;
// What can come between two cookies of one header: list brackets, commas and quotes, as in Node's
// [ 'a=1; Path=/', 'b=2' ], or the ", " that joins repeated Set-Cookie headers.
const GAP = /(?:[ \t,[\]]|[bBrRuUfF]{0,2}\\?["'])*/y;

export const cookies: Rule = {
  name: 'cookies',
  by: 'context',
  find: (text) => [
    ...[...text.matchAll(HEADER)].flatMap((m) => pairs(text, m.index + m[0].length, m[2]!.toLowerCase() === 'set-cookie')),
    ...[...text.matchAll(CURL)].flatMap((m) => pairs(text, m.index + m[0].length, false)),
  ],
};

function pairs(text: string, at: number, setCookie: boolean): Finding[] {
  const found: Finding[] = [];
  const skip = (pattern: RegExp, from: number) => {
    pattern.lastIndex = from;
    return pattern.exec(text) ? pattern.lastIndex : from;
  };
  for (let pos = at; ; ) {
    PAIR.lastIndex = skip(GAP, pos);
    const p = PAIR.exec(text);
    if (!p) break;
    const [name, value] = [p[1]!, p[3]!];
    const [start, end] = p.indices![3]!;
    if (value && !isPlainShort(value)) found.push({ start, end, kind: `cookie:${name}`, reason: `${name} cookie` });
    pos = skip(setCookie ? ATTRIBUTES : NEXT_PAIR, p.index + p[0].length);
  }
  return found;
}

// Preferences such as theme=dark or lang=en-US help debugging and grant nothing.
function isPlainShort(value: string): boolean {
  return value.length < 8 && /^[\w.-]+$/.test(value);
}
