import { sanitize } from './engine';
import { Finding, Rule } from './types';

// Stand-in rules: each reports capture group 1 of its pattern (which needs the d and g flags).
function rule(name: string, by: Rule['by'], pattern: RegExp, kind = name, extra: (value: string) => Partial<Finding> = () => ({})): Rule {
  return {
    name,
    by,
    find: (text) =>
      [...text.matchAll(pattern)].map((m) => {
        const [start, end] = m.indices![1]!;
        return { start, end, kind, reason: `${name} value`, ...extra(m[1]) };
      }),
  };
}

const header = rule('header', 'context', /Auth: \w+ ([^\r\n]+)/dg, 'bearer');
const kv = rule('kv', 'context', /key=(\S+)/dg, 'key');
const quoted = rule('quoted', 'context', /"secret": "([^"]*)"/dg, 'secret');
const token = rule('token', 'format', /(tok_\w+)/dg);

describe('sanitize', () => {
  it('replaces a finding with a typed, numbered label and reports the change', () => {
    const result = sanitize('GET /\nAuth: Bearer s3cr3tvalue\n', [header]);
    expect(result.output).toBe('GET /\nAuth: Bearer <bearer#1>\n');
    expect(result.changes).toEqual([
      { label: 'bearer#1', kind: 'bearer', rule: 'header', reason: 'header value', line: 2, start: 19, end: 30, value: 's3cr3tvalue' },
    ]);
  });

  it('leaves text without findings unchanged', () => {
    expect(sanitize('plain text', [header])).toEqual({ output: 'plain text', changes: [], jwts: [] });
  });

  it('numbers labels across kinds in order of appearance', () => {
    expect(sanitize('tok_aaaaaaaa key=first tok_bbbbbbbb', [kv, token]).output).toBe('<token#1> key=<key#2> <token#3>');
  });

  it('gives a repeated value the same label', () => {
    expect(sanitize('key=abc key=abc', [kv]).output).toBe('key=<key#1> key=<key#1>');
  });

  it('gives every copy of a value of 8+ characters the same label, even where no rule matches', () => {
    const result = sanitize('log: retry with s3cr3tvalue\nAuth: Bearer s3cr3tvalue\nid=xs3cr3tvaluex', [header]);
    expect(result.output).toBe('log: retry with <bearer#1>\nAuth: Bearer <bearer#1>\nid=x<bearer#1>x');
    expect(result.changes.map((c) => [c.label, c.line, c.reason])).toEqual([
      ['bearer#1', 1, 'same value as bearer#1'],
      ['bearer#1', 2, 'header value'],
      ['bearer#1', 3, 'same value as bearer#1'],
    ]);
  });

  it('numbers a value by its first copy when the copy comes before the rule match', () => {
    expect(sanitize('s3cr3tvalue tok_aaaaaaaa\nAuth: Bearer s3cr3tvalue', [header, token]).output).toBe(
      '<bearer#1> <token#2>\nAuth: Bearer <bearer#1>',
    );
  });

  it('leaves copies of values under 8 characters alone', () => {
    expect(sanitize('Auth: Bearer hunter2\npassword hunter2', [header]).output).toBe('Auth: Bearer <bearer#1>\npassword hunter2');
  });

  it('lets a format finding win over a context finding on the same span', () => {
    const result = sanitize('Auth: Bearer tok_abcdefgh', [header, token]);
    expect(result.output).toBe('Auth: Bearer <token#1>');
    expect(result.changes).toEqual([
      { label: 'token#1', kind: 'token', rule: 'token', reason: 'token value', line: 1, start: 13, end: 25, value: 'tok_abcdefgh' },
    ]);
  });

  it('replaces the union when a context finding contains a format finding', () => {
    const result = sanitize('"secret": "Bearer tok_abcdefgh"', [quoted, token]);
    expect(result.output).toBe('"secret": "<token#1>"');
    expect(result.changes).toEqual([
      { label: 'token#1', kind: 'token', rule: 'token', reason: 'token value', line: 1, start: 11, end: 30, value: 'tok_abcdefgh' },
    ]);
  });

  it('keeps each label when a context finding overlaps two format findings, and removes what lies between', () => {
    const rules = [quoted, token];
    const once = sanitize('"secret": "lead9xyz tok_aaaaaaaa|tok_bbbbbbbb|leftover9"', rules).output;
    expect(once).toBe('"secret": "<token#1>|<token#2>"');
    expect(sanitize(once, rules).output).toBe(once);
  });

  it('keeps up with a 1 MB input full of findings', () => {
    const input = Array.from({ length: 40_000 }, (_, i) => `key=s3cr3t${i.toString(16).padStart(8, '0')}`).join('\n');
    const started = performance.now();
    const result = sanitize(input, [kv]);
    expect(result.changes.length).toBe(40_000);
    expect(performance.now() - started).toBeLessThan(3000);
  });

  it('lets the longer span win between rules of the same rank', () => {
    const short = rule('short', 'context', /key=(\w{3})/dg);
    expect(sanitize('key=abcdef', [short, kv]).output).toBe('key=<key#1>');
  });

  it.each(['$TOKEN', '${TOKEN}', '$(cat token.txt)', '%TOKEN%', '{{token}}', '<token>', '<jwt#1>', '***', '[REDACTED]', '[FILTERED]'])(
    'leaves the reference %s alone',
    (reference) => {
      const input = `Auth: Bearer ${reference}`;
      expect(sanitize(input, [header]).output).toBe(input);
    },
  );

  it.each(['null', 'undefined', 'true', 'False', 'None', 'nil'])('leaves the empty value %s alone', (empty) => {
    const input = `Auth: Bearer ${empty}`;
    expect(sanitize(input, [header]).output).toBe(input);
  });

  it('keeps CRLF line endings and counts lines across them', () => {
    const result = sanitize('a\r\nb\r\nAuth: Bearer s3cr3tvalue\r\n', [header]);
    expect(result.output).toBe('a\r\nb\r\nAuth: Bearer <bearer#1>\r\n');
    expect(result.changes[0].line).toBe(3);
  });

  it('returns each labeled JWT once with its decoded header and claims', () => {
    const jwt = rule('jwt', 'format', /(eyJ\w+)/dg, 'jwt', (value) => ({
      jwt: { header: { alg: 'none' }, claims: { sub: value.slice(3) } },
    }));
    const result = sanitize('eyJaaaaaaaa eyJaaaaaaaa eyJbbbbbbbb', [jwt]);
    expect(result.output).toBe('<jwt#1> <jwt#1> <jwt#2>');
    expect(result.jwts).toEqual([
      { label: 'jwt#1', header: { alg: 'none' }, claims: { sub: 'aaaaaaaa' } },
      { label: 'jwt#2', header: { alg: 'none' }, claims: { sub: 'bbbbbbbb' } },
    ]);
  });

  it('changes nothing when run on its own output', () => {
    const rules = [header, kv, token];
    const once = sanitize('tok_aaaaaaaa key=first\nAuth: Bearer s3cr3tvalue', rules).output;
    expect(once).toBe('<token#1> key=<key#2>\nAuth: Bearer <bearer#3>');
    expect(sanitize(once, rules).output).toBe(once);
  });
});
