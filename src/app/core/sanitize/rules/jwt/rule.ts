import { DecodedJwt, Rule } from '../../types';

// Three base64url segments; the signature is empty for alg "none". Decoding the header is the real test,
// so hostnames and version strings that fit this shape are rejected there.
const CANDIDATE = /(?<![\w-])[\w-]{10,}\.[\w-]{2,}\.[\w-]*/g;

export const jwt: Rule = {
  name: 'jwt',
  by: 'format',
  find: (text) =>
    [...text.matchAll(CANDIDATE)].flatMap((m) => {
      const decoded = decode(m[0]);
      return decoded ? [{ start: m.index, end: m.index + m[0].length, kind: 'jwt', reason: 'JWT', jwt: decoded }] : [];
    }),
};

function decode(token: string): DecodedJwt | undefined {
  const [header, claims] = token.split('.').map(parseSegment);
  if (!isObject(header) || typeof header['alg'] !== 'string') return undefined;
  return { header, claims: isObject(claims) ? claims : {} };
}

function parseSegment(segment: string): unknown {
  try {
    const binary = atob(segment.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(binary, (c) => c.charCodeAt(0))));
  } catch {
    return undefined;
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
