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

  it('skips three-part base64url strings whose header has no alg', () => {
    const token = `${b64url('{"typ":"JWT","x":1}')}.${b64url('{"sub":"a"}')}.c2lnbmF0dXJl`;
    expect(jwt.find(token)).toEqual([]);
  });
});
