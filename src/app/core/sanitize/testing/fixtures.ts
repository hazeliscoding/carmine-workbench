import { Change } from '../types';

// Fake secrets are built at test time, so the repo never holds a string that GitHub secret scanning or a
// vendor's partner program would match. Prefixes are split for the same reason.

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const ALNUM = UPPER + UPPER.toLowerCase() + DIGITS;
const B64URL = ALNUM + '-_';
const B64 = ALNUM + '+/';

// Seeded (FNV-1a into mulberry32), so a fixture builds the same values on every run.
function chars(seed: string, length: number, alphabet = ALNUM): string {
  let state = [...seed].reduce((h, c) => Math.imul(h ^ c.charCodeAt(0), 16777619), 2166136261);
  let out = '';
  while (out.length < length) {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t ^= t + Math.imul(t ^ (t >>> 7), 61 | t);
    out += alphabet[((t ^ (t >>> 14)) >>> 0) % alphabet.length];
  }
  return out;
}

const base64url = (json: object) => btoa(JSON.stringify(json)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function jwt(header: object, n: number, signature: string): string {
  const claims = {
    iss: 'https://auth.example.com',
    sub: `usr_0${33 + n}`,
    aud: 'orders-api',
    scope: 'orders:read',
    iat: 1790234340,
    exp: 1790237940,
  };
  return `${base64url(header)}.${base64url(claims)}.${signature}`;
}

function pem(type: string, n: number, newline: string, withEnd = true): string {
  const armor = (edge: string) => `-----${edge} ${type}PRIVATE KEY-----`;
  const body = chars(`pem${type}${n}`, 300, B64).match(/.{1,64}/g)!;
  return [armor('BEGIN'), ...body, ...(withEnd ? [armor('END')] : [])].join(newline);
}

const FAKES: Record<string, (n: number) => string> = {
  jwt: (n) => jwt({ alg: 'RS256', typ: 'JWT', kid: 'orders-2026-09' }, n, chars(`jwt${n}`, 43, B64URL)),
  'jwt-none': (n) => jwt({ alg: 'none', typ: 'JWT' }, n, ''),
  'private-key': (n) => pem('RSA ', n, '\n'),
  // As it sits inside a JSON string, such as a Google service-account file: newlines escaped as \n.
  'private-key-json': (n) => pem('', n, '\\n'),
  // Indented under a YAML key.
  'private-key-yaml': (n) => pem('EC ', n, '\n    '),
  // Pasted without its END line.
  'private-key-truncated': (n) => pem('OPENSSH ', n, '\n', false),
  'aws-access-key-id': (n) => 'AK' + 'IA' + chars(`aws${n}`, 16, UPPER + DIGITS),
  'aws-secret-access-key': (n) => chars(`awss${n}`, 40, B64),
  'github-token': (n) => 'gh' + 'p_' + chars(`gh${n}`, 36),
  'stripe-key': (n) => ['sk', 'live', chars(`stripe${n}`, 24)].join('_'),
  'slack-token': (n) => ['xo' + 'xb', chars(`sa${n}`, 12, DIGITS), chars(`sb${n}`, 12, DIGITS), chars(`sc${n}`, 24)].join('-'),
  // The path after https://hooks.slack.com/services/, which is the secret part of the URL.
  'slack-webhook': (n) => `T${chars(`wa${n}`, 8, UPPER + DIGITS)}/B${chars(`wb${n}`, 10, UPPER + DIGITS)}/${chars(`wc${n}`, 24)}`,
  'google-api-key': (n) => 'AI' + 'za' + chars(`gk${n}`, 35, B64URL),
  'google-token': (n) => 'ya' + '29.' + chars(`gt${n}`, 60, B64URL),
};

export function fake(spec: string): string {
  const [name, n = '1'] = spec.split(':');
  const build = FAKES[name!];
  if (!build) throw new Error(`unknown fake: ${spec}`);
  return build(Number(n));
}

// {{secret:value}} marks a literal secret; {{fake:name}} or {{fake:name:n}} builds one. Other {{…}} is input.
export function expand(text: string): { text: string; secrets: string[] } {
  const secrets = new Set<string>();
  const expanded = text.replace(/\{\{(secret|fake):([^}]+)\}\}/g, (_, type: string, arg: string) => {
    const value = type === 'secret' ? arg : fake(arg);
    secrets.add(value);
    return value;
  });
  return { text: expanded, secrets: [...secrets] };
}

export function leaks(text: string, secrets: string[]): string[] {
  return secrets.filter((secret) => text.includes(secret));
}

export function undeclared(changes: Change[], secrets: string[]): string[] {
  return [...new Set(changes.map((change) => change.value))].filter((value) => !secrets.includes(value));
}

// Anything but a relative import. The engine and rules stay free of Angular and I/O, so a CLI can reuse them.
export function impurities(source: string): string[] {
  return [...source.matchAll(/\b(?:from|import)\s*\(?\s*['"]([^'"]+)['"]|\brequire\s*\(/g)]
    .map((m) => m[1] ?? 'require(')
    .filter((spec) => !spec.startsWith('.'));
}
