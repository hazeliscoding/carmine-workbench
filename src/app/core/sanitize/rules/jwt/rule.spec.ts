import { fake } from '../../testing/fixtures';
import { jwt } from './rule';

const b64url = (text: string) =>
  btoa(String.fromCharCode(...new TextEncoder().encode(text)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

describe('jwt rule', () => {
  it('decodes the header and claims of the token it finds', () => {
    const token = fake('jwt');
    expect(jwt.find(`Bearer ${token}`)).toEqual([
      {
        start: 7,
        end: 7 + token.length,
        kind: 'jwt',
        reason: 'JWT',
        jwt: {
          header: { alg: 'RS256', typ: 'JWT', kid: 'orders-2026-09' },
          claims: {
            iss: 'https://auth.example.com',
            sub: 'usr_034',
            aud: 'orders-api',
            scope: 'orders:read',
            iat: 1790234340,
            exp: 1790237940,
          },
        },
      },
    ]);
  });

  it('finds an unsigned token with alg none', () => {
    const token = fake('jwt-none');
    expect(token.endsWith('.')).toBe(true);
    expect(jwt.find(`token ${token} rejected`).map((f) => [f.start, f.end, f.jwt?.header['alg']])).toEqual([[6, 6 + token.length, 'none']]);
  });

  it('decodes UTF-8 claims', () => {
    const token = `${b64url('{"alg":"HS256"}')}.${b64url('{"name":"Zoë Ångström"}')}.c2lnbmF0dXJl`;
    expect(jwt.find(token)[0]?.jwt?.claims).toEqual({ name: 'Zoë Ångström' });
  });

  it('keeps an empty claims object when the payload is not JSON', () => {
    const token = `${b64url('{"alg":"HS256"}')}.${b64url('not json')}.c2lnbmF0dXJl`;
    expect(jwt.find(token)[0]?.jwt).toEqual({ header: { alg: 'HS256' }, claims: {} });
  });

  it('takes all five segments of an encrypted token and keeps its claims empty', () => {
    const token = fake('jwe');
    expect(jwt.find(`session=${token}; Path=/`).map((f) => [f.start, f.end, f.reason, f.jwt])).toEqual([
      [8, 8 + token.length, 'JWE', { header: { alg: 'dir', enc: 'A256GCM' }, claims: {} }],
    ]);
  });

  it('finds a token right after an escape or a URL-encoded character', () => {
    const token = fake('jwt');
    for (const before of ['msg\\t', 'line\\n', 'id_token%3D', '%22']) {
      expect(jwt.find(`${before}${token}%22`).map((f) => f.end - f.start)).toEqual([token.length]);
    }
  });

  it('finds a token glued to a preceding word with a dot', () => {
    const token = fake('jwt');
    expect(jwt.find(`orders.example.${token}`).map((f) => [f.start, f.end])).toEqual([[15, 15 + token.length]]);
  });

  it('skips three-part base64url strings whose header has no alg', () => {
    const token = `${b64url('{"typ":"JWT","x":1}')}.${b64url('{"sub":"a"}')}.c2lnbmF0dXJl`;
    expect(jwt.find(token)).toEqual([]);
  });
});
