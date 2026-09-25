// Canned sample for the static M0 screen. The engine (M1) will produce this shape from real input.
// Secret values are cut short with … so they are not real secrets and do not match secret scanners.

export interface Finding {
  label: string;
  kind: string;
  where: string;
  line: number;
  value: string;
}

export interface Field {
  key: string;
  value: string;
  type: 'string' | 'number';
  note?: string;
  alert?: boolean;
}

export interface JwtExplain {
  label: string;
  alg: string;
  expired: boolean;
  header: Field[];
  claims: Field[];
}

export interface Sample {
  format: string;
  input: string;
  output: string;
  findings: Finding[];
  jwt: JwtExplain;
}

export const SAMPLE: Sample = {
  format: 'curl',
  input: [
    'curl https://api.example.com/v1/orders \\',
    "  -H 'Authorization: Bearer eyJhbGciOiJSUzI1NiIs…' \\",
    "  -H 'X-Api-Key: 3f9a8c2e…' \\",
    "  -b 'sid=9f3e1c7a…; theme=dark'",
  ].join('\n'),
  output: [
    'curl https://api.example.com/v1/orders \\',
    "  -H 'Authorization: Bearer <jwt#1>' \\",
    "  -H 'X-Api-Key: <api-key#2>' \\",
    "  -b 'sid=<cookie:sid#3>; theme=dark'",
    '',
    '# jwt#1 · RS256 · signature removed',
    '#   sub  usr_034',
    '#   aud  orders-api',
    '#   exp  2026.09.24 08:19 (expired 12m ago)',
  ].join('\n'),
  findings: [
    { label: 'jwt#1', kind: 'JWT', where: 'Authorization header', line: 2, value: 'eyJhbGciOiJSUzI1NiIs…' },
    { label: 'api-key#2', kind: 'API key', where: 'X-Api-Key header', line: 3, value: '3f9a8c2e…' },
    { label: 'cookie:sid#3', kind: 'Cookie', where: 'sid cookie', line: 4, value: '9f3e1c7a…' },
  ],
  jwt: {
    label: 'jwt#1',
    alg: 'RS256',
    expired: true,
    header: [
      { key: 'alg', value: 'RS256', type: 'string' },
      { key: 'typ', value: 'JWT', type: 'string' },
      { key: 'kid', value: 'orders-2026-09', type: 'string' },
    ],
    claims: [
      { key: 'iss', value: 'https://auth.example.com', type: 'string', note: 'Issuer' },
      { key: 'sub', value: 'usr_034', type: 'string', note: 'Subject' },
      { key: 'aud', value: 'orders-api', type: 'string', note: 'Audience' },
      { key: 'scope', value: 'orders:read', type: 'string' },
      { key: 'iat', value: '1790234340', type: 'number', note: '2026.09.24 07:19' },
      { key: 'exp', value: '1790237940', type: 'number', note: '2026.09.24 08:19 · expired 12m ago', alert: true },
    ],
  },
};
