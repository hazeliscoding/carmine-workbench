import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { sanitize } from './engine';
import { RULES } from './rules';
import { Change } from './types';
import { expand, fake, impurities, leaks, undeclared } from './testing/fixtures';

const ROOT = join(process.cwd(), 'src/app/core/sanitize');
const read = (path: string) => readFileSync(join(ROOT, path), 'utf8');
const files = readdirSync(ROOT, { recursive: true, encoding: 'utf8' }).map((path) => path.replace(/\\/g, '/'));

const cases = files
  .filter((path) => /(^|\/)fixtures\/[^/]+\.in\.txt$/.test(path))
  .map((path) => path.replace(/\.in\.txt$/, ''))
  .sort();

function run(name: string) {
  const { text, secrets } = expand(read(`${name}.in.txt`));
  const expected = existsSync(join(ROOT, `${name}.out.txt`)) ? read(`${name}.out.txt`) : text;
  return { secrets, expected, result: sanitize(text) };
}

describe('fixtures', () => {
  it('finds the fixture cases', () => {
    expect(cases).toContain('fixtures/log-no-secrets');
  });

  it.each(cases)('%s', (name) => {
    const { secrets, expected, result } = run(name);
    expect(leaks(expected, secrets), 'declared secrets in the expected output').toEqual([]);
    expect(result.output).toBe(expected);
    expect(undeclared(result.changes, secrets), 'removed values the fixture does not declare').toEqual([]);
    expect(sanitize(result.output).output, 'sanitizing the output again').toBe(result.output);
  });

  it.each(RULES.map((rule) => rule.name))('has a case where %s removes something', (rule) => {
    const own = cases.filter((name) => name.startsWith(`rules/${rule}/fixtures/`));
    expect(own.some((name) => run(name).result.changes.some((change) => change.rule === rule))).toBe(true);
  });

  it('keeps the engine and rules free of package and Node imports', () => {
    const sources = files.filter((path) => path.endsWith('.ts') && !path.endsWith('.spec.ts') && !path.startsWith('testing/'));
    expect(sources).toContain('engine.ts');
    expect(sources.flatMap((path) => impurities(read(path)).map((spec) => `${path}: ${spec}`))).toEqual([]);
  });
});

describe('fixture checks', () => {
  const change = (value: string) => ({ value }) as Change;

  it('expands placeholders and declares their values as secrets', () => {
    const { text, secrets } = expand('a={{secret:s3cr3tvalue}} b={{fake:github-token}} c={{fake:github-token:2}}');
    const [one, two] = [fake('github-token'), fake('github-token:2')];
    expect(text).toBe(`a=s3cr3tvalue b=${one} c=${two}`);
    expect(secrets).toEqual(['s3cr3tvalue', one, two]);
  });

  it('builds the same fake for the same name and number, and a different one for another number', () => {
    expect(fake('jwt')).toBe(fake('jwt:1'));
    expect(fake('jwt:2')).not.toBe(fake('jwt'));
  });

  it('leaves other double-brace text alone', () => {
    expect(expand('Bearer {{token}}')).toEqual({ text: 'Bearer {{token}}', secrets: [] });
  });

  it('rejects an unknown fake', () => {
    expect(() => expand('{{fake:nope}}')).toThrowError(/nope/);
  });

  it('finds a declared secret left in the output', () => {
    expect(leaks('Bearer s3cr3tvalue', ['s3cr3tvalue', 'other'])).toEqual(['s3cr3tvalue']);
  });

  it('finds a removed value the fixture did not declare', () => {
    expect(undeclared([change('s3cr3tvalue'), change('hunter2'), change('hunter2')], ['s3cr3tvalue'])).toEqual(['hunter2']);
  });

  it('flags package, Node and require imports but not relative ones', () => {
    const source = [
      "import { Component } from '@angular/core';",
      "import { readFileSync } from 'node:fs';",
      "const os = require('os');",
      "import { Rule } from '../../types';",
      "import './side-effect';",
    ].join('\n');
    expect(impurities(source)).toEqual(['@angular/core', 'node:fs', 'require(']);
  });
});
