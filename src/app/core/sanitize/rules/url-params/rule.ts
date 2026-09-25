import { Rule } from '../../types';

const NAMES = [
  'access_token',
  'id_token',
  'refresh_token',
  'token',
  'code',
  'client_secret',
  'api_key',
  'apikey',
  'password',
  'pass',
  'pwd',
  'secret',
  'auth',
  'sig',
  'signature',
  'x-amz-signature',
  'x-amz-security-token',
  'x-goog-signature',
];
// A parameter at the start of a query, fragment or form body, or after a separator. Requiring one of these
// before the name keeps logfmt such as "status code=500" out.
const PARAM = new RegExp(`(?<=^|[?&#;'"])(${NAMES.join('|')})=([^\\s&#;'"<>)\\]]+)`, 'dgim');
// Names that also carry ordinary values (code=SKU-12345, auth=required), so their value must look random.
const GENERIC = /^(?:code|auth|sig|signature)$/i;
// user:password@host after ://. The user name stays. Anchoring on :// rather than the scheme keeps the
// scan linear on long dotted text.
const USERINFO = /:\/\/[^\s/:@'"]*:([^\s/@'"]+)@/dg;

export const urlParams: Rule = {
  name: 'url-params',
  by: 'context',
  find: (text) => [
    ...[...text.matchAll(PARAM)].flatMap((m) => {
      const [start, end] = m.indices![2]!;
      if (GENERIC.test(m[1]!) && !looksRandom(m[2]!)) return [];
      const kind = m[1]!.toLowerCase().replace(/^x-/, '').replace(/_/g, '-');
      return [{ start, end, kind, reason: `${m[1]} parameter` }];
    }),
    ...[...text.matchAll(USERINFO)].map((m) => {
      const [start, end] = m.indices![1]!;
      return { start, end, kind: 'password', reason: 'password in URL' };
    }),
  ],
};

// Authorization codes and signatures are long, or mix digits with upper- and lowercase letters.
function looksRandom(value: string): boolean {
  return value.length >= 16 || (value.length >= 10 && /\d/.test(value) && /[a-z]/.test(value) && /[A-Z]/.test(value));
}
