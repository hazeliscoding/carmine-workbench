import { Rule } from '../../types';
import { kindFromName } from '../shared';

// A key, optionally quoted (escaped when the JSON sits inside a log string) or written as a --flag, then an
// assignment: = : := or =>. An = followed by another = is a comparison, and a name right after ${ is a
// shell default such as ${TOKEN:-unset}. As with START, a key may follow an escape such as \t but not a
// lone backslash.
const KEY = /(?:(?<![\w.$\\%-])|(?<=\\[nrt]))(?<!\$\{)(?:--)?((?:\\?["'])?)([A-Za-z_][\w.-]*)\1[ \t]*(:=|=>|:|=(?!=))[ \t]*/g;
// The closing quote may be missing when a log cuts the JSON off mid-value; the value then runs to the line end.
const QUOTED = /(["'])((?:\\.|(?!\1)[^\\\r\n])*)(?:\1|(?=[\r\n]|$))/dy;
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

export const sensitiveKeys: Rule = {
  name: 'sensitive-keys',
  by: 'context',
  find: (text) =>
    [...text.matchAll(KEY)].flatMap((m) => {
      const key = m[2]!;
      const normalized = key.toLowerCase().replace(/[^a-z\d]/g, '');
      if (!SENSITIVE.test(normalized) || NOT_SENSITIVE.test(normalized)) return [];
      const at = m.index + m[0].length;
      const kind = kindFromName(key.split('.').pop()!);
      const reason = `${key} value`;

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
      if ((m[3] === ':' && /^-?\d+(?:\.\d+)?$/.test(bare)) || /[([]/.test(text[end] ?? '')) return [];
      return [{ start: at, end, kind, reason }];
    }),
};
