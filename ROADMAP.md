# Roadmap

Carmine is a local-first desktop app (Angular + Tauri v2) that sanitizes auth and integration debugging material before you share it. This file tracks what gets built, in what order, and the decisions already made.

## Decisions (2026-09-24)

- **Labels, not blanks.** Each distinct secret becomes a typed, numbered label (`<jwt#1>`, `<cookie:sid#3>`). Labels stay the same within one document, so a reader can still follow a value across requests.
- **JWTs** are replaced whole with `<jwt#1>`, and the signature is always dropped. The decoded header and claims appear in an Explain panel and as a readable claims block in the copied output. The block has a toggle and is on by default.
- **Personal claims** such as `email` or `name` are kept by default, because they don't grant access. An optional personal-data rule comes later.
- **Rules are plain TypeScript** under `src/app/core/sanitize/`. They have no Angular imports and do no I/O, so tests and a future CLI can reuse them.
- **No auto-updater.** An updater is networking code. Updates come from GitHub Releases.
- **UI** uses the directive//01 design system and the shell of the Devbox demo mockup, re-skinned as a single Sanitize screen.
- **Brand** is option 1A, "Caliper": two measuring jaws holding a single datum. The wordmark is Barlow Semi Condensed, converted to vector paths. The assets are in `docs/brand/`, with `-dark` files for dark backgrounds.

## Decisions (2026-09-25)

- **Fonts** come from Fontsource packages and are bundled into the app, with their OFL licenses under `licenses/`. Source Serif 4 is dropped, because Carmine has no personal voice.
- **Colors** keep the directive//01 palette. Five tokens changed to pass WCAG 2.2 AA on every surface the UI uses, not only the page. The `AA` notes in `src/styles/tokens.css` give the old values, and `scripts/check-contrast.mjs` checks each pair in CI.

## M0: Placeholder (as soon as possible)

- [x] Add `LICENSE` (Apache-2.0).
- [x] Scaffold Angular + Tauri v2.
- [x] Generate the app and installer icons from `docs/brand/mark.svg`. Put the mark on a paper-colored tile, because its dark strokes disappear on a dark taskbar.
- [x] Adapt the directive//01 tokens:
  - [x] Self-host the fonts under OFL licenses (Public Sans, Barlow Semi Condensed, JetBrains Mono) instead of loading Google Fonts.
  - [x] Drop the Lucide icons loaded from a CDN.
  - [x] Fix the colors that fail WCAG AA: light `--text-meta` (3.96), light `--amber` (3.35), dark `--directive-red` (3.42) and the dark focus ring (2.49).
- [x] Build a static Sanitize screen with a canned sample: findings list, input, sanitized output with diff, JWT panel, and a `LOCAL · NO NETWORK` status bar.
- [ ] Turn on the privacy guardrails from the first commit:
  - [x] a Content Security Policy that blocks outbound connections;
  - [x] no HTTP or updater plugins;
  - [x] a CI check that fails on `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource` or `sendBeacon` in `src/`, and on HTTP crates in `src-tauri/`.
- [x] Add a screenshot to the README.

**Done when:** CI builds the app, the sample screen renders, and a test PR that adds `fetch(` fails the network check.

## M1: Sanitize engine

- [ ] Engine: runs all rules, resolves overlaps (the most specific finding wins), assigns labels, and returns the output plus a change list.
- [ ] Rule contract: one folder per rule, containing `rule.ts` (findings with position, kind and reason) and `fixtures/` (input and expected-output pairs).
- [ ] Fixture runner, plus a **no-leak check**: no secret value from a fixture may appear in its output.
- [ ] Keep fake secrets in fixtures from tripping GitHub secret scanning. Either build them at test time or scope an allowlist.
- [ ] The seven rules:

| Rule | Covers |
|---|---|
| `jwt` | Three-part base64url tokens with a JSON header; decodes the claims |
| `authorization-headers` | `Authorization` (Bearer, Basic, Digest), `Proxy-Authorization`, `X-Api-Key` and similar; curl `-H` and `-u` |
| `cookies` | `Cookie` and `Set-Cookie` values, curl `-b`; keeps the cookie names |
| `url-params` | `access_token`, `code`, `client_secret`, `sig` and similar; `user:pass@host` in URLs |
| `sensitive-keys` | JSON, form and env keys such as `password`, `secret`, `token`, `api_key`, `refresh_token` |
| `private-keys` | PEM `PRIVATE KEY` blocks |
| `known-secret-formats` | Vendor key prefixes (AWS, GitHub, Stripe, Slack, Google, …) |

**Done when:** every fixture passes, across curl commands, raw headers, logs and JSON bodies.

## M2: v0.1.0

- [ ] Wire the UI to the engine: sanitize as you type, findings list, diff toggle, and **Copy sanitized** (Ctrl/⌘+Shift+C).
- [ ] JWT Explain panel:
  - [ ] alg and kid; iss, sub and aud; exp, iat and nbf in dotted time with relative age;
  - [ ] warnings for `alg: none`, a missing `exp`, and very long lifetimes;
  - [ ] the label "decoded, not verified".
- [ ] Claims block in the copied output, with its toggle.
- [ ] Input stays in memory only. No history. The clipboard is written only on Copy.
- [ ] Wording never says "clean". It says "4 secrets removed, review before sharing".
- [ ] Release workflow: Windows, macOS and Linux builds on GitHub Releases, unsigned, with SHA-256 checksums.
- [ ] Dogfooding log: real debugging sessions, noting anything that was missed.

**Done when:** in a released build, you can paste a curl command, see its secrets removed, and copy the result.

## M3: v0.2, ready for contributors

- [ ] `CONTRIBUTING.md`: how to add a rule in one folder, with a rule template.
- [ ] `SECURITY.md`, plus a privacy contract document that lists each promise and how it is enforced.
- [ ] A "Missed a secret" issue template. It asks for the format, never the real value.
- [ ] Good-first-issue list of secret formats.
- [ ] HAR support.
- [ ] Review flags: leftover high-entropy strings are flagged for review, not silently removed.

## Later

- SAML assertions
- Optional personal-data rules (emails, IPs, names in claims)
- A CLI on the same engine
- Signed builds with build provenance
- Open files or drag and drop them in
- JWT signature check with a key pasted locally

## Not planned

- General utility tools such as JSON formatting, Base64 or UUIDs. DevToys and CyberChef cover these.
- Scanning repositories for secrets. gitleaks and trufflehog do this.
- Accounts, sync, telemetry or anything hosted.

## How we'll know it works

Evidence comes from dogfooding (n=1, recorded in the log). After release it also comes from public signals: "missed a secret" issues, new-rule PRs and downloads.
