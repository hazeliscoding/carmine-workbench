import { Finding, Rule } from '../../types';

const BEGIN = /-----BEGIN ((?:[A-Z\d]+ )*)PRIVATE KEY( BLOCK)?-----/g;
// Lines split on real newlines or on \n escaped inside a JSON string.
const LINE_BREAK = /\r?\n|(?:\\r)?\\n/;
// A body line: base64, or a header such as "Proc-Type: 4,ENCRYPTED". YAML indents every line.
const BODY_LINE = /^[ \t]*(?:[A-Za-z\d+/=]*|[\w-]+: [\w ,-]+)[ \t]*$/;
// One more whole base64 line, for a block pasted without its END line.
const NEXT_LINE = /(?:\r?\n|(?:\\r)?\\n)[ \t]*[A-Za-z\d+/=]{16,}[ \t]*(?=\r?\n|(?:\\r)?\\n|["']|$)/y;

export const privateKeys: Rule = {
  name: 'private-keys',
  by: 'format',
  find: (text) => [...text.matchAll(BEGIN)].flatMap((m) => block(text, m)),
};

function block(text: string, begin: RegExpExecArray): Finding[] {
  const start = begin.index;
  const bodyStart = start + begin[0].length;
  const endArmor = `-----END ${begin[1]}PRIVATE KEY${begin[2] ?? ''}-----`;
  const reason = `${begin[1]}private key`;
  const endAt = text.indexOf(endArmor, bodyStart);
  if (endAt !== -1 && text.slice(bodyStart, endAt).split(LINE_BREAK).every((line) => BODY_LINE.test(line))) {
    return [{ start, end: endAt + endArmor.length, kind: 'private-key', reason }];
  }
  let end = bodyStart;
  NEXT_LINE.lastIndex = end;
  while (NEXT_LINE.test(text)) end = NEXT_LINE.lastIndex;
  // The armor line alone, as in docs that mention it, holds no key.
  return end > bodyStart ? [{ start, end, kind: 'private-key', reason }] : [];
}
