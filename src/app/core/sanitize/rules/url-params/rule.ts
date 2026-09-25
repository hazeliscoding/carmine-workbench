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
const PARAM = new RegExp(`(?<=^|[?&#;'"])(${NAMES.join('|')})=([^\\s&#'"<>)\\]]+)`, 'dgim');
// scheme://user:password@host. The user name stays.
const USERINFO = /\b[a-z][a-z\d+.-]*:\/\/[^\s/:@'"]*:([^\s/@'"]+)@/dgi;

export const urlParams: Rule = {
  name: 'url-params',
  by: 'context',
  find: (text) => [
    ...[...text.matchAll(PARAM)].map((m) => {
      const [start, end] = m.indices![2]!;
      const kind = m[1]!.toLowerCase().replace(/^x-/, '').replace(/_/g, '-');
      return { start, end, kind, reason: `${m[1]} parameter` };
    }),
    ...[...text.matchAll(USERINFO)].map((m) => {
      const [start, end] = m.indices![1]!;
      return { start, end, kind: 'password', reason: 'password in URL' };
    }),
  ],
};
