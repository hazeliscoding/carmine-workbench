import { Finding, Rule } from '../../types';
import { START } from '../shared';

// Base64url segments joined by dots: three for a signed token (the signature is empty for alg "none"),
// five for an encrypted one (the key segment is empty for alg "dir"). Decoding the header is the real
// test, so hostnames and version strings that fit this shape are rejected there.
const CANDIDATE = new RegExp(String.raw`${START}[\w-]{10,}(?:\.[\w-]*){2,}`, 'g');

export const jwt: Rule = {
  name: 'jwt',
  by: 'format',
  find: (text) => [...text.matchAll(CANDIDATE)].flatMap((m) => tokensIn(m[0], m.index)),
};

// A run of dotted segments can start with something else, such as a hostname glued on with a dot, so each
// segment gets a turn as the header.
function tokensIn(run: string, at: number): Finding[] {
  const parts = run.split('.');
  const found: Finding[] = [];
  let offset = at;
  for (let i = 0; i + 2 < parts.length; ) {
    const header = parseSegment(parts[i]!);
    if (!isObject(header) || typeof header['alg'] !== 'string') {
      offset += parts[i]!.length + 1;
      i++;
      continue;
    }
    // An encrypted token keeps every segment it has, even when cut short; its payload can't be read.
    const encrypted = typeof header['enc'] === 'string';
    const segments = parts.slice(i, i + (encrypted ? 5 : 3));
    const token = segments.join('.');
    const claims = encrypted ? {} : parseSegment(parts[i + 1]!);
    found.push({
      start: offset,
      end: offset + token.length,
      kind: 'jwt',
      reason: encrypted ? 'JWE' : 'JWT',
      jwt: { header, claims: isObject(claims) ? claims : {} },
    });
    offset += token.length + 1;
    i += segments.length;
  }
  return found;
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
