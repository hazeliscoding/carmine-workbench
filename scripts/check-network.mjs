// Network guard: fails when networking code, an HTTP dependency or a permissive CSP appears.
// It enforces the "no network" line of the privacy contract in README.md.
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { extname, join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const WEB_APIS = [
  { pattern: /\bfetch\s*\(/, name: 'fetch(' },
  { pattern: /\bXMLHttpRequest\b/, name: 'XMLHttpRequest' },
  { pattern: /\bWebSocket\b/, name: 'WebSocket' },
  { pattern: /\bEventSource\b/, name: 'EventSource' },
  { pattern: /\bsendBeacon\b/, name: 'sendBeacon' },
  { pattern: /@angular\/common\/http/, name: '@angular/common/http' },
];

const HTTP_CRATES = new Set([
  'attohttpc', 'curl', 'hyper', 'isahc', 'reqwest', 'surf', 'tungstenite', 'ureq',
  'tauri-plugin-http', 'tauri-plugin-updater', 'tauri-plugin-upload', 'tauri-plugin-websocket',
]);

// Cargo.lock lists crates for every platform (tauri pulls reqwest on mobile only), so ask cargo what desktop builds compile.
const DESKTOP_TARGETS = ['x86_64-pc-windows-msvc', 'x86_64-unknown-linux-gnu', 'aarch64-apple-darwin'];

const NPM_PLUGINS = /node_modules\/@tauri-apps\/plugin-(http|updater|upload|websocket)"/g;

// IPC is Tauri's in-process channel. On Windows it is served as http://ipc.localhost and never leaves the machine.
const ALLOWED_CONNECT = new Set(['ipc:', 'http://ipc.localhost']);

export function scanSource(text) {
  const hits = [];
  text.split('\n').forEach((line, i) => {
    for (const api of WEB_APIS) {
      if (api.pattern.test(line)) hits.push({ line: i + 1, name: api.name });
    }
  });
  return hits;
}

export function scanCargoTree(text) {
  return [...new Set(text.split('\n').map((line) => line.split(' ')[0]))].filter((n) => HTTP_CRATES.has(n));
}

export function scanPackageLock(text) {
  return [...new Set([...text.matchAll(NPM_PLUGINS)].map((m) => `@tauri-apps/plugin-${m[1]}`))];
}

export function checkCsp(csp) {
  if (typeof csp !== 'string' || !csp.trim()) return ['app.security.csp is not set'];
  const directives = new Map(
    csp.split(';').map((d) => d.trim().split(/\s+/)).filter((d) => d[0]).map(([k, ...v]) => [k, v]),
  );
  const problems = [];
  if (!directives.get('default-src')?.every((s) => s === "'self'" || s === "'none'")) {
    problems.push("default-src must be 'self' or 'none'");
  }
  const connect = directives.get('connect-src');
  if (!connect) problems.push('connect-src is missing');
  else for (const s of connect) if (!ALLOWED_CONNECT.has(s)) problems.push(`connect-src allows ${s}`);
  for (const [name, sources] of directives) {
    if (name === 'connect-src') continue;
    for (const s of sources) {
      if (s === '*' || /^(https?|wss?):/.test(s)) problems.push(`${name} allows ${s}`);
    }
  }
  return problems;
}

function sourceFiles(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true, recursive: true })
    .filter((e) => e.isFile() && ['.ts', '.js', '.mjs', '.html'].includes(extname(e.name)))
    .map((e) => join(e.parentPath, e.name));
}

function cargoTree(manifest, target) {
  const args = ['tree', '--manifest-path', manifest, '--locked', '--target', target, '--edges', 'normal,build', '--prefix', 'none', '--format', '{p}'];
  return spawnSync('cargo', args, { encoding: 'utf8' });
}

export function check(root) {
  const errors = [];
  const report = (file, line, message) => errors.push({ file: relative(root, file).replaceAll('\\', '/'), line, message });

  for (const file of sourceFiles(join(root, 'src'))) {
    for (const hit of scanSource(readFileSync(file, 'utf8'))) report(file, hit.line, `networking API ${hit.name}`);
  }

  const manifest = join(root, 'src-tauri/Cargo.toml');
  if (existsSync(manifest)) {
    for (const target of DESKTOP_TARGETS) {
      const run = cargoTree(manifest, target);
      if (run.status !== 0) report(manifest, 1, `cargo tree failed for ${target}: ${(run.stderr || String(run.error)).trim()}`);
      else for (const crate of scanCargoTree(run.stdout)) report(manifest, 1, `HTTP crate ${crate} on ${target}`);
    }
  }

  const lock = join(root, 'package-lock.json');
  if (existsSync(lock)) {
    for (const plugin of scanPackageLock(readFileSync(lock, 'utf8'))) report(lock, 1, `plugin ${plugin}`);
  }

  const conf = join(root, 'src-tauri/tauri.conf.json');
  if (!existsSync(conf)) report(conf, 1, 'tauri.conf.json is missing');
  else for (const problem of checkCsp(JSON.parse(readFileSync(conf, 'utf8')).app?.security?.csp)) report(conf, 1, `CSP: ${problem}`);

  return errors;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const root = resolve(process.argv[2] ?? '.');
  const errors = check(root);
  for (const e of errors) {
    console.error(process.env.GITHUB_ACTIONS ? `::error file=${e.file},line=${e.line}::${e.message}` : `${e.file}:${e.line}  ${e.message}`);
  }
  if (errors.length) {
    console.error(`\nNetwork check failed: ${errors.length} problem(s). Carmine has no networking code.`);
    process.exit(1);
  }
  console.log('Network check passed.');
}
