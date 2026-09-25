import { Finding, Rule } from '../../types';
import { START } from '../shared';

const BEGIN = /-----BEGIN ((?:[A-Z\d]+ )*)PRIVATE KEY( BLOCK)?-----/g;
// The key itself is a long base64 run. Lines can be flattened, prefixed by a log or split into string
// literals, so the body isn't checked line by line; docs that name both armor lines have no such run.
const KEY_MATERIAL = /[A-Za-z\d+/]{40,}/;
// One more whole base64 line, for a block pasted without its END line.
const NEXT_LINE = /(?:\r?\n|(?:\\r)?\\n)[ \t]*[A-Za-z\d+/=]{16,}[ \t]*(?=\r?\n|(?:\\r)?\\n|["']|$)/y;
// A PEM block that was itself base64-encoded, as kubeconfig client-key-data is: "-----BEGIN " encodes to
// LS0tLS1CRUdJTi. Certificates encode the same way, so the decoded start decides.
const BASE64_PEM = new RegExp(String.raw`${START}LS0tLS1CRUdJTi[A-Za-z\d+/]*={0,2}`, 'g');

export const privateKeys: Rule = {
  name: 'private-keys',
  by: 'format',
  find: (text) => {
    const begins = [...text.matchAll(BEGIN)];
    return [...begins.flatMap((m, i) => block(text, m, begins[i + 1]?.index ?? text.length)), ...base64Blocks(text)];
  },
};

// Looks for END only up to the next BEGIN, so a paste full of armor lines stays linear.
function block(text: string, begin: RegExpExecArray, limit: number): Finding[] {
  const start = begin.index;
  const bodyStart = start + begin[0].length;
  const endArmor = `-----END ${begin[1]}PRIVATE KEY${begin[2] ?? ''}-----`;
  const reason = `${begin[1]}private key`;
  const endAt = text.slice(bodyStart, limit).indexOf(endArmor);
  if (endAt !== -1 && KEY_MATERIAL.test(text.slice(bodyStart, bodyStart + endAt))) {
    return [{ start, end: bodyStart + endAt + endArmor.length, kind: 'private-key', reason }];
  }
  let end = bodyStart;
  NEXT_LINE.lastIndex = end;
  while (NEXT_LINE.test(text)) end = NEXT_LINE.lastIndex;
  // The armor line alone, as in docs that mention it, holds no key.
  return end > bodyStart ? [{ start, end, kind: 'private-key', reason }] : [];
}

function base64Blocks(text: string): Finding[] {
  return [...text.matchAll(BASE64_PEM)].flatMap((m) => {
    let head: string;
    try {
      head = atob(m[0].slice(0, 80));
    } catch {
      return [];
    }
    return /PRIVATE KEY/.test(head) ? [{ start: m.index, end: m.index + m[0].length, kind: 'private-key', reason: 'base64 private key' }] : [];
  });
}
