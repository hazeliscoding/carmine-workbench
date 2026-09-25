import { Finding, Rule } from '../../types';
import { START, kindFromName, looksLikeCredential } from '../shared';

// A header name, optionally quoted as a JSON or Python key (escaped when the JSON sits inside a log
// string, or a Python b'' string), then a separator and an optional opening quote or Go map bracket. It
// matches only up to the value, so the next header on the same line is still found. The separator is a
// colon, or = and => as in PowerShell and Ruby hashes; := is an assignment in code (token := …).
const HEADER = new RegExp(
  String.raw`${START}(?:[bBrRuUfF]{0,2}(\\?["']))?([A-Za-z][\w-]*)\1[ \t]*(?::(?!=)|=>|=(?![=>]))[ \t]*\[?(?:[bBrRuUfF]{0,2}\\?["'\`])?`,
  'g',
);
// A shell or template reference is taken whole so the engine can skip it; anything else runs up to
// whitespace, a quote, a delimiter, a bracket or an escape. A value that opens an object or array isn't a
// credential.
const CREDENTIAL = /\$\([^)]*\)|\$\{[^}]*\}|\{\{[^}]*\}\}|[^\s'"`,;{}()[\]\\]+/y;
const SCHEME = /[A-Za-z][\w-]*[ \t]+(?=\S)/y;
// Names that hold a credential. Most other *-key headers (X-Cache-Key, Sort-Key, X-Stripe-Publishable-Key)
// don't, and their values then spread through the paste as copies.
const KEY_HEADER = /(?:^|-)(?:api-?key|access-key|auth-key|functions-key|subscription-key|token|secret)$/;
const NOT_KEY_HEADER = /^(?:idempotency-key|sec-websocket-key)$|(?:page|next|continuation)-token$/;
const SCHEMES = new Set(['bearer', 'basic', 'token', 'bot', 'ssws', 'apikey', 'api-key', 'key', 'negotiate', 'ntlm', 'hmac', 'dpop', 'jwt', 'sharedkey', 'mac']);
// Schemes whose credentials are name=value parameters. Only these parameters carry the secret.
const PARAM_SCHEME = /^(?:digest|oauth|aws4-[\w-]+)$/;
const PARAM = /(?<![\w-])([\w-]+)=(?:\\?"((?:(?!\\?")[^\r\n])*)\\?"|([^\s,"'\\]+))/dg;
const SECRET_PARAM = /^(?:response|signature|oauth_signature|oauth_token|token)$/i;
// curl's short flags take the value attached or after spaces; the long ones after = or spaces.
const CURL_USER = /(?<!\S)(?:(-u|-U)[ \t]*|(--user|--proxy-user)(?:=|[ \t]+))(["']?)/g;
const CURL_BEARER = /(?<!\S)--oauth2-bearer(?:=|[ \t]+)["']?/g;

export const authorizationHeaders: Rule = {
  name: 'authorization-headers',
  by: 'context',
  find: (text) => [...headers(text), ...curlUsers(text), ...curlBearers(text)],
};

function headers(text: string): Finding[] {
  return [...text.matchAll(HEADER)].flatMap((m) => {
    const name = m[2]!;
    const lower = name.toLowerCase();
    const at = m.index + m[0].length;
    const reason = `${name} header`;
    if (lower === 'authorization' || lower === 'proxy-authorization') return authorization(text, at, reason);
    if (KEY_HEADER.test(lower) && !NOT_KEY_HEADER.test(lower)) {
      return credential(text, at, kindFromName(name), reason, looksLikeCredential);
    }
    return [];
  });
}

function authorization(text: string, at: number, reason: string): Finding[] {
  const scheme = matchAt(SCHEME, text, at);
  if (!scheme) return credential(text, at, 'authorization', reason, looksLikeCredential);
  const name = scheme.trim().toLowerCase();
  const rest = at + scheme.length;
  if (PARAM_SCHEME.test(name)) return params(text, rest, name.startsWith('aws4-') ? 'aws-signature' : name, reason);
  if (name === 'token' && matchAt(/token=/iy, text, rest)) return params(text, rest, name, reason);
  return credential(text, rest, name, reason, (value) => SCHEMES.has(name) || looksLikeCredential(value));
}

function params(text: string, from: number, kind: string, reason: string): Finding[] {
  const end = text.slice(from).search(/[\r\n]|\\[rn]|$/) + from;
  return [...text.slice(from, end).matchAll(PARAM)].flatMap((p) => {
    const [start, stop] = p.indices![2] ?? p.indices![3]!;
    return SECRET_PARAM.test(p[1]!) && stop > start ? [{ start: from + start, end: from + stop, kind, reason }] : [];
  });
}

function curlUsers(text: string): Finding[] {
  return [...text.matchAll(CURL_USER)].flatMap((m) => {
    const quote = m[3]!;
    // A colon followed by // is a URL scheme (redis-cli -u redis://host), not user:password.
    const userPass =
      quote === '"' ? /[^":\s]*:(?!\/\/)([^"\r\n]+)/dy : quote === "'" ? /[^':\s]*:(?!\/\/)([^'\r\n]+)/dy : /[^\s:'"]*:(?!\/\/)(\S+)/dy;
    userPass.lastIndex = m.index + m[0].length;
    const u = userPass.exec(text);
    // docker and ps take -u uid:gid.
    if (!u || /^\d+:\d+$/.test(u[0])) return [];
    const [start, end] = u.indices![1]!;
    return [{ start, end, kind: 'password', reason: `curl ${m[1] ?? m[2]} password` }];
  });
}

function curlBearers(text: string): Finding[] {
  return [...text.matchAll(CURL_BEARER)].flatMap((m) => credential(text, m.index + m[0].length, 'bearer', 'curl --oauth2-bearer'));
}

function credential(text: string, at: number, kind: string, reason: string, accept = (_: string) => true): Finding[] {
  const value = matchAt(CREDENTIAL, text, at);
  return value && accept(value) ? [{ start: at, end: at + value.length, kind, reason }] : [];
}

function matchAt(pattern: RegExp, text: string, at: number): string | undefined {
  pattern.lastIndex = at;
  return pattern.exec(text)?.[0];
}
