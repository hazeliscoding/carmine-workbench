// Contrast check: every text and focus color pair the UI uses must pass WCAG 2.2 AA, in both themes.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const TEXT = ['--text-primary', '--text-secondary', '--text-meta', '--text-link', '--amber', '--directive-red', '--authorized'];
const SURFACES = ['--surface-page', '--surface-card', '--surface-inset'];

// [foreground, background, minimum ratio]. 4.5 for text (SC 1.4.3), 3 for focus indicators (SC 1.4.11).
export const PAIRS = [
  ...TEXT.flatMap((fg) => SURFACES.map((bg) => [fg, bg, 4.5])),
  ...SURFACES.map((bg) => ['--auburn', bg, 3]),
  ...['--text-primary', '--text-secondary', '--text-link'].flatMap((fg) => [
    [fg, '--diff-del-bg', 4.5],
    [fg, '--diff-add-bg', 4.5],
  ]),
  ['--text-primary', '--mark-bg', 4.5],
];

// Reads the light :root block and the dark block inside @media (prefers-color-scheme: dark).
export function parseThemes(css) {
  const text = css.replace(/\/\*[\s\S]*?\*\//g, '');
  const darkAt = text.indexOf('@media (prefers-color-scheme: dark)');
  const decls = (s) => Object.fromEntries([...s.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)].map((m) => [m[1], m[2].trim()]));
  const light = decls(darkAt < 0 ? text : text.slice(0, darkAt));
  const dark = { ...light, ...(darkAt < 0 ? {} : decls(text.slice(darkAt))) };
  return { light, dark };
}

export function resolveColor(vars, value) {
  const v = value.trim();
  const ref = v.match(/^var\((--[\w-]+)\)$/);
  if (ref) {
    if (!(ref[1] in vars)) throw new Error(`unknown token ${ref[1]}`);
    return resolveColor(vars, vars[ref[1]]);
  }
  const hex = v.match(/^#([0-9a-f]{6})$/i);
  if (hex) return [0, 2, 4].map((i) => parseInt(hex[1].slice(i, i + 2), 16));
  const mix = v.match(/^color-mix\(in srgb,\s*(.+?)\s+(\d+(?:\.\d+)?)%,\s*(.+)\)$/);
  if (mix) {
    const a = resolveColor(vars, mix[1]);
    const b = resolveColor(vars, mix[3]);
    const p = Number(mix[2]) / 100;
    return a.map((c, i) => c * p + b[i] * (1 - p));
  }
  throw new Error(`cannot resolve color "${v}"`);
}

function luminance(rgb) {
  const [r, g, b] = rgb.map((c) => {
    const s = c / 255;
    return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function contrast(a, b) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

export function failures(themes, pairs = PAIRS) {
  const out = [];
  for (const [theme, vars] of Object.entries(themes)) {
    for (const [fg, bg, min] of pairs) {
      const ratio = contrast(resolveColor(vars, `var(${fg})`), resolveColor(vars, `var(${bg})`));
      if (ratio < min) out.push({ theme, fg, bg, ratio: Math.floor(ratio * 100) / 100, min });
    }
  }
  return out;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const file = process.argv[2] ?? 'src/styles/tokens.css';
  const found = failures(parseThemes(readFileSync(file, 'utf8')));
  for (const f of found) console.error(`${f.theme}: ${f.fg} on ${f.bg} is ${f.ratio}, needs ${f.min}`);
  if (found.length) {
    console.error(`\nContrast check failed: ${found.length} pair(s) below WCAG 2.2 AA.`);
    process.exit(1);
  }
  console.log(`Contrast check passed: ${PAIRS.length} pairs in 2 themes.`);
}
