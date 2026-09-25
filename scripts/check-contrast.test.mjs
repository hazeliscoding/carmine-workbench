// Positive controls for the contrast check: it must catch the failures ROADMAP.md lists for directive//01.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { contrast, failures, parseThemes, resolveColor } from './check-contrast.mjs';

const ORIGINAL = `
:root { --paper: #f2ede2; --surface-page: var(--paper); --text-meta: #7d7460; --amber: #a17b22; --auburn: #7e4a33; --directive-red: #9e2b2b; }
@media (prefers-color-scheme: dark) { :root { --paper: #191712; --text-meta: #8a8271; --amber: #c09a3e; --directive-red: #b84740; } }`;

test('measures the known extremes', () => {
  assert.equal(contrast([0, 0, 0], [255, 255, 255]), 21);
  assert.equal(contrast([9, 9, 9], [9, 9, 9]), 1);
});

test('resolves var() chains and color-mix in srgb', () => {
  const vars = { '--a': '#ffffff', '--b': 'var(--a)', '--c': 'color-mix(in srgb, var(--b) 50%, #000000)' };
  assert.deepEqual(resolveColor(vars, 'var(--c)'), [127.5, 127.5, 127.5]);
  assert.throws(() => resolveColor(vars, 'var(--missing)'));
});

test('catches the four directive//01 failures', () => {
  const pairs = ['--text-meta', '--amber', '--directive-red'].map((fg) => [fg, '--surface-page', 4.5]);
  const found = failures(parseThemes(ORIGINAL), [...pairs, ['--auburn', '--surface-page', 3]]);
  assert.deepEqual(
    found.map((f) => `${f.theme} ${f.fg} ${f.ratio}`),
    ['light --text-meta 3.96', 'light --amber 3.34', 'dark --directive-red 3.42', 'dark --auburn 2.48'],
  );
});

test('the app tokens pass', () => {
  assert.deepEqual(failures(parseThemes(readFileSync(new URL('../src/styles/tokens.css', import.meta.url), 'utf8'))), []);
});
