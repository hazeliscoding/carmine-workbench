import { Finding, Rule } from '../../types';
import { kindFromName, looksLikeCode } from '../shared';

// A key, optionally quoted (escaped when the JSON sits inside a log string, or a Python b'' string) or
// written as a --flag, then an assignment: = : := or =>. An = followed by another = is a comparison, and a
// name right after ${ is a shell default such as ${TOKEN:-unset}. As with START, a key may follow an
// escape such as \t but not a lone backslash. Right after :// is a URL's user name (https://token:…@host),
// which url-params reads.
const KEY =
  /(?:(?<![\w.$\\%-])|(?<=\\[nrt]))(?<!\$\{|:\/\/)(?:--)?(?:[bBrRuUfF]{0,2}(\\?["']))?([A-Za-z_][\w.-]*)\1[ \t]*(:=|=>|:|=(?!=))[ \t]*/g;
// Python's b'', f'' and similar string prefixes.
const STRING_PREFIX = /[bBrRuUfF]{1,2}(?=\\?["'`])/y;
// The closing quote may be missing when a log cuts the JSON off mid-value; the value then runs to the line
// end. Backticks are JavaScript template strings.
const QUOTED = /(["'`])((?:\\.|(?!\1)[^\\\r\n])*)(?:\1|(?=[\r\n]|$))/dy;
// Quoted with escaped quotes, as JSON inside a log string is.
const ESCAPED_QUOTED = /\\(["'])((?:(?!\\\1)[^\r\n])*)(?:\\\1|(?=[\r\n]|$))/dy;
// A shell or template reference is taken whole so the engine can skip it.
const BARE = /\$\([^)]*\)|\$\{[^}]*\}|\{\{[^}]*\}\}|[^\s,;&'"(){}[\]\\]+/y;
// Matched against the key lowercased with separators removed, so api_key, apiKey and API-KEY all match.
// Only the plural "credentials": AWS's Credential= is a key ID and a scope.
const SENSITIVE =
  /(?:password|passwd|passphrase|secret|token|apikey|privatekey|secretkey|secretaccesskey|accountkey|signingkey|encryptionkey|masterkey|sessionid|credentials)$|^(?:pwd|pass)$/;
// Pagination cursors and token_type end like secrets but grant nothing.
const NOT_SENSITIVE = /(?:tokentype|(?:next|page|continuation|pagination)token)$/;
// A command-line flag with its value after a space, as in docker login --password …
const FLAG = /(?<!\S)--([A-Za-z][\w-]*)[ \t]+(?=[^\s-])/g;
// A YAML block scalar indicator (| or >, with optional chomping), the value on the lines below.
const BLOCK = /[|>][+-]?[ \t]*(?=\r?\n)/y;

export const sensitiveKeys: Rule = {
  name: 'sensitive-keys',
  by: 'context',
  find: (text) =>
    [
      ...[...text.matchAll(KEY)].map((m) => ({ key: m[2]!, separator: m[3]!, at: m.index + m[0].length })),
      ...[...text.matchAll(FLAG)].map((m) => ({ key: m[1]!, separator: ' ', at: m.index + m[0].length })),
    ].flatMap(({ key, separator, at }) => valueOf(text, key, separator, at)),
};

function valueOf(text: string, key: string, separator: string, from: number): Finding[] {
  const normalized = key.toLowerCase().replace(/[^a-z\d]/g, '');
  if (!SENSITIVE.test(normalized) || NOT_SENSITIVE.test(normalized)) return [];
  STRING_PREFIX.lastIndex = from;
  const at = from + (STRING_PREFIX.exec(text)?.[0].length ?? 0);
  const kind = kindFromName(key.split('.').pop()!);
  const reason = `${key} value`;

  BLOCK.lastIndex = at;
  if (separator === ':' && BLOCK.test(text)) return blockValue(text, at, kind, reason);
  ESCAPED_QUOTED.lastIndex = at;
  QUOTED.lastIndex = at;
  const quoted = ESCAPED_QUOTED.exec(text) ?? QUOTED.exec(text);
  if (quoted) {
    const [start, end] = quoted.indices![2]!;
    return end > start ? [{ start, end, kind, reason }] : [];
  }
  BARE.lastIndex = at;
  const bare = BARE.exec(text)?.[0];
  if (!bare) return [];
  const end = at + bare.length;
  // A JSON number is a flag or a count. Code such as os.environ["X"] or os.Getenv("X") reads the
  // secret from somewhere else.
  if ((separator === ':' && /^-?\d+(?:\.\d+)?$/.test(bare)) || /[([]/.test(text[end] ?? '') || looksLikeCode(bare)) return [];
  return [{ start: at, end, kind, reason }];
}

// The lines after the key that are indented deeper than it, from the first content to the last.
function blockValue(text: string, from: number, kind: string, reason: string): Finding[] {
  const indentOf = (line: string) => /^[ \t]*/.exec(line)![0].length;
  const keyLineStart = text.lastIndexOf('\n', from - 1) + 1;
  const keyIndent = indentOf(text.slice(keyLineStart, from));
  let start = -1;
  let end = -1;
  for (let pos = text.indexOf('\n', from) + 1; pos > 0 && pos < text.length; ) {
    const next = text.indexOf('\n', pos);
    const line = text.slice(pos, next === -1 ? text.length : next).replace(/\r$/, '');
    if (line.trim()) {
      if (indentOf(line) <= keyIndent) break;
      if (start === -1) start = pos + indentOf(line);
      end = pos + line.length;
    }
    pos = next + 1;
  }
  return start === -1 ? [] : [{ start, end, kind, reason }];
}
