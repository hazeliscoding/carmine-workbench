// Positive controls for the network guard: each banned thing must make it fail.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { checkCsp, scanCargoTree, scanPackageLock, scanSource } from './check-network.mjs';

const CSP = "default-src 'self'; connect-src ipc: http://ipc.localhost; style-src 'self' 'unsafe-inline'";
const script = join(dirname(fileURLToPath(import.meta.url)), 'check-network.mjs');

test('flags each browser networking API', () => {
  const samples = [
    "fetch('https://example.com')",
    'await window.fetch (url)',
    'const x = new XMLHttpRequest();',
    'const ws = new WebSocket(url);',
    'const es = new EventSource(url);',
    'navigator.sendBeacon(url, body);',
    "import { HttpClient } from '@angular/common/http';",
  ];
  for (const s of samples) assert.equal(scanSource(s).length, 1, s);
});

test('ignores lookalikes', () => {
  assert.deepEqual(scanSource('prefetch(); const fetched = true; // WebSockets2'), []);
});

test('reports the line number', () => {
  assert.deepEqual(scanSource('const a = 1;\n\nfetch(u);'), [{ line: 3, name: 'fetch(' }]);
});

test('flags HTTP crates and plugins', () => {
  const tree = 'carmine-workbench v0.0.0 (C:\\code)\ntauri v2.11.6\nreqwest v0.13.5\nhyper v1.11.1\nreqwest v0.13.5 (*)\n';
  assert.deepEqual(scanCargoTree(tree), ['reqwest', 'hyper']);
  assert.deepEqual(scanCargoTree('tauri-plugin-updater v2.0.0\n'), ['tauri-plugin-updater']);
  assert.deepEqual(scanCargoTree('http v1.3.1\nhttparse v1.10.1\n'), []);
  assert.deepEqual(scanPackageLock('"node_modules/@tauri-apps/plugin-http": {'), ['@tauri-apps/plugin-http']);
});

test('cargo tree sees the mobile-only reqwest, so the desktop check is not blind', () => {
  const manifest = join(dirname(fileURLToPath(import.meta.url)), '../src-tauri/Cargo.toml');
  const args = ['tree', '--manifest-path', manifest, '--locked', '--target', 'aarch64-linux-android', '--prefix', 'none', '--format', '{p}'];
  const run = spawnSync('cargo', args, { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  assert.ok(scanCargoTree(run.stdout).includes('reqwest'));
});

test('accepts the app CSP and rejects remote sources', () => {
  assert.deepEqual(checkCsp(CSP), []);
  assert.ok(checkCsp(null).length);
  assert.ok(checkCsp("default-src 'self'").some((p) => p.includes('connect-src is missing')));
  assert.ok(checkCsp(`${CSP} https://api.example.com`).some((p) => p.includes('https://api.example.com')));
  assert.ok(checkCsp(`${CSP}; img-src *`).some((p) => p.includes('img-src allows *')));
  assert.ok(checkCsp("default-src *; connect-src ipc:").length);
});

test('the CLI exits 1 on a planted fetch( and 0 without it', () => {
  const root = mkdtempSync(join(tmpdir(), 'carmine-guard-'));
  try {
    mkdirSync(join(root, 'src/app'), { recursive: true });
    mkdirSync(join(root, 'src-tauri'));
    writeFileSync(join(root, 'src-tauri/tauri.conf.json'), JSON.stringify({ app: { security: { csp: CSP } } }));
    writeFileSync(join(root, 'src/app/ok.ts'), 'export const ok = 1;\n');
    assert.equal(spawnSync(process.execPath, [script, root]).status, 0);

    writeFileSync(join(root, 'src/app/leak.ts'), "export const leak = () =>\n  fetch('https://example.com');\n");
    const run = spawnSync(process.execPath, [script, root], { encoding: 'utf8', env: { ...process.env, GITHUB_ACTIONS: '' } });
    assert.equal(run.status, 1);
    assert.match(run.stderr, /src\/app\/leak\.ts:2 {2}networking API fetch\(/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
