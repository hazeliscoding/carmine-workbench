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
- **HTTP crates** are checked with `cargo tree` for the three desktop targets. `Cargo.lock` also lists crates for mobile, where tauri pulls in `reqwest`, so scanning it gives false positives.
- **CI** builds on Linux only until the M2 release workflow adds Windows and macOS.
- **The engine scans raw text.** It doesn't detect or parse formats, because real pastes mix curl, headers, logs and cut-off JSON. Output bytes stay the same outside the removed values, and the input's line endings are kept.
- **Overlaps:** format rules (`jwt`, `private-keys`, `known-secret-formats`) outrank context rules (headers, cookies, parameters, keys), and then the longer span wins. An overlapping finding merges into the winner, and the union of both spans is replaced under the winner's label. When it overlaps several, each keeps its label, and any letters or digits between them go to a neighbour.
- **Labels** are numbered across all kinds in order of first appearance. A label belongs to the value, whichever rule found it. Every other copy of a removed value of 8 or more characters gets the same label, even where no rule matches.
- **Kept on purpose:** references (`$TOKEN`, `{{token}}`, `<token>`, `***`, existing labels), plain cookie values under 8 characters (`theme=dark`), `token_type`, pagination tokens and Stripe `pk_` keys. Sanitizing twice changes nothing.
- **Where a name alone isn't proof, the value must look like a credential.** Examples are header names such as `token`, a bare word after `Authorization:`, `Bearer` outside a header, and generic parameters such as `code`, `auth` and `sig`. Code that reads a secret (`await getToken()`, `password: string`) is left alone. Values under sensitive key names such as `password` are always removed.
- **Performance:** the engine and rules stay linear, because M2 sanitizes as you type. A test holds a 1 MB input under 3 s; it takes about 0.3 s.
- **Fake secrets** are built at test time. Fixture inputs write every secret as `{{secret:…}}` or `{{fake:<format>}}`. GitHub's partner scanning of public repos can't be scoped, so an allowlist would only hide the alerts here while vendors still got notified.
- **Claims:** the engine returns the decoded claims. Writing the claims block into the copied output is M2, along with its toggle.
- **Input** is a native textarea. Removed values are marked only in the diff, which is built from change positions, not by matching values. Input marks or CodeMirror come back only if the dogfooding log asks for them.
- **Sanitize as you type** runs on the main thread, with no Web Worker. Paste runs at once, typing waits 150 ms, and Copy always sanitizes the current input first.
- **The textarea turns CRLF into LF**, so text copied from the app uses LF. The engine still keeps CRLF for callers that pass it, such as the tests and the future CLI.
- **Times** are UTC, written with the zone: `2026.09.24 08:19 UTC`. The Explain panel shows live ages. The copied block has one `as of` stamp, and its ages count from it (`expired 12m earlier`), so it stays true when read later.
- **The claims block** lists every header field and claim as `#   key: <JSON value>`. It is sanitized in one pass with the input, so a claim equal to a removed value becomes that value's label, whatever its length. Copy writes nothing if that pass fails.
- **Summary wording:** "1 secret removed, review before sharing", or "Nothing removed, review before sharing" when there are none. The count is distinct labels.
- **Copy** calls `navigator.clipboard.writeText` inside the click or key handler, with no clipboard plugin. Only `copy.ts` writes the clipboard, and nothing reads it.
- **The webview** runs incognito with autofill off. On Windows the app creates its own WebView2 environment with crash reporting off, because a crash dump can hold pasted input. It clears leftover dumps at startup and limits navigation to the app.
- **Installers** don't download anything. Windows uses `webviewInstallMode: skip`, since every other mode ships download code or adds 127 MB or more. The app shows Microsoft's download link when WebView2 is missing.
- **Release builds:** a per-user NSIS installer, one universal `.dmg` with an ad-hoc signature, and `.deb` and `.rpm` built in an `ubuntu:22.04` container for a glibc 2.35 baseline. There is no AppImage: it bundles a WebKitGTK that gets no security updates, and its build tools are downloaded without a hash check. Without the ad-hoc signature, Apple Silicon reports the unsigned app as damaged.
- **Release workflow:** written by hand, not tauri-action. Build jobs are read-only, and one tag-only job with write access runs no repo code. Actions are pinned by SHA, one `SHA256SUMS` covers the assets, and the release starts as a draft. PR CI stays on Linux.
- **Release checks:** an agent runs a CDP and SendKeys probe against the Windows draft, with the clipboard stubbed. CI installs the `.deb` under Xvfb, pastes and copies with xdotool and xclip, and reads the real clipboard. The macOS build is launched on arm64 and Intel runners. Nothing automated checks Copy on macOS.
- **The dogfooding log** is `docs/dogfooding.md`, in public. Entries name formats, never values, hosts or employers. A test fails if sanitizing the log would change it, or if it names a host outside `example.com`, `.test` or `localhost`.

## M0: Placeholder (as soon as possible)

- [x] Add `LICENSE` (Apache-2.0).
- [x] Scaffold Angular + Tauri v2.
- [x] Generate the app and installer icons from `docs/brand/mark.svg`. Put the mark on a paper-colored tile, because its dark strokes disappear on a dark taskbar.
- [x] Adapt the directive//01 tokens:
  - [x] Self-host the fonts under OFL licenses (Public Sans, Barlow Semi Condensed, JetBrains Mono) instead of loading Google Fonts.
  - [x] Drop the Lucide icons loaded from a CDN.
  - [x] Fix the colors that fail WCAG AA: light `--text-meta` (3.96), light `--amber` (3.35), dark `--directive-red` (3.42) and the dark focus ring (2.49).
- [x] Build a static Sanitize screen with a canned sample: findings list, input, sanitized output with diff, JWT panel, and a `LOCAL · NO NETWORK` status bar.
- [x] Turn on the privacy guardrails from the first commit:
  - [x] a Content Security Policy that blocks outbound connections;
  - [x] no HTTP or updater plugins;
  - [x] a CI check that fails on `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource` or `sendBeacon` in `src/`, and on HTTP crates in `src-tauri/`.
- [x] Add a screenshot to the README.

**Done when:** CI builds the app, the sample screen renders, and a test PR that adds `fetch(` fails the network check.

## M1: Sanitize engine

- [x] Engine: runs all rules, resolves overlaps (the most specific finding wins), assigns labels, and returns the output plus a change list.
- [x] Rule contract: one folder per rule, containing `rule.ts` (findings with position, kind and reason) and `fixtures/` (input and expected-output pairs).
- [x] Fixture runner, plus a **no-leak check**: no secret value from a fixture may appear in its output. Also check that every removed value is declared, and that sanitizing a second time changes nothing.
- [x] Keep fake secrets in fixtures from tripping GitHub secret scanning by building them at test time from placeholders.
- [x] The seven rules:

| Rule | Covers |
|---|---|
| `jwt` | Three-part base64url tokens with a JSON header; decodes the claims |
| `authorization-headers` | `Authorization` (Bearer, Basic, Digest), `Proxy-Authorization`, `X-Api-Key` and similar; curl `-H` and `-u` |
| `cookies` | `Cookie` and `Set-Cookie` values, curl `-b`; keeps the cookie names |
| `url-params` | `access_token`, `code`, `client_secret`, `sig` and similar; `user:pass@host` in URLs |
| `sensitive-keys` | JSON, form and env keys such as `password`, `secret`, `token`, `api_key`, `refresh_token` |
| `private-keys` | PEM `PRIVATE KEY` blocks |
| `known-secret-formats` | Vendor key prefixes: AWS, GitHub, Stripe, Slack and Google. More vendors come as good first issues in M3 |

**Done when:** every fixture passes, across curl commands, raw headers, logs and JSON bodies.

## M2: v0.1.0

- [ ] Engine fixes before sanitizing as you type:
  - [ ] Keep the rules linear on one long line: Digest, AWS4 and OAuth parameters, HTTPie `-a`, `mysql -p`. A 200 KB line of Digest headers takes 6.4 s today.
  - [ ] Never give a new value a label number that the input already holds.
- [ ] Wire the UI to the engine:
  - [ ] A pure review model in `src/app/core/review/`: output offsets, a diff from change positions with unchanged lines folded, findings rows and the summary. It replaces `text.ts`, whose line diff is quadratic. The purity check covers all of `src/app/core`.
  - [ ] Before the UI code lands, the network guard also fails on storage, worker, clipboard-read and URL or title APIs, allows clipboard writes only in `copy.ts`, and scans the built bundle.
  - [ ] Sanitize as you type in a textarea, with the findings list, an empty state and **Load sample**. The sample is assembled at runtime, like the fixtures.
  - [ ] Diff and Output toggle.
  - [ ] **Copy sanitized** (Ctrl/⌘+Shift+C), always from the current input.
- [ ] Dogfooding log: real debugging sessions, noting anything that was missed. It starts once Copy works.
- [ ] JWT Explain panel, for one JWT or several:
  - [ ] alg and kid; iss, sub and aud; exp, iat and nbf in dotted UTC time with relative age;
  - [ ] warnings for `alg: none`, a missing `exp`, lifetimes over 24 h, `exp` in milliseconds, and `nbf` or `iat` in the future;
  - [ ] the label "decoded, not verified".
- [ ] Claims block in the copied output, with its toggle. The README's before-and-after is regenerated from it.
- [ ] Wording never says "clean". It says "4 secrets removed, review before sharing". A test checks every status line.
- [ ] Input stays in memory only. No history. The clipboard is written only on Copy.
  - [ ] Incognito window with autofill off. The guard checks every Tauri config, capability and Cargo feature.
  - [ ] Windows: the app's own WebView2 environment, with crash reporting off, leftover dumps cleared, a message when WebView2 is missing, and navigation limited to the app.
- [ ] Release workflow: Windows, macOS and Linux builds on GitHub Releases, unsigned, with SHA-256 checksums.
  - [ ] Bundle config: installer formats, `webviewInstallMode: skip`, the ad-hoc signature, app metadata and the third-party notices.
  - [ ] Windows acceptance probe: paste, check and copy over CDP and SendKeys against the installer, then scan the disk for a planted value.
  - [ ] Linux smoke test in CI and a macOS launch check.
  - [ ] The workflow itself, with `ci.yml`'s actions pinned by SHA too.
  - [ ] Version 0.1.0, and a README with install steps, notes on unsigned builds and screenshots of the live app.

**Done when:** in a released build, you can paste a curl command, see its secrets removed, and copy the result. The Windows probe checks this against the draft release before it is published.

## M3: v0.2, ready for contributors

- [ ] `CONTRIBUTING.md`: how to add a rule in one folder, with a rule template.
- [ ] `SECURITY.md`, plus a privacy contract document that lists each promise and how it is enforced. It also names what happens outside the app's control: WebView2's own updates, Windows clipboard history, and crash handlers on Linux and macOS.
- [ ] A "Missed a secret" issue template. It asks for the format, never the real value.
- [ ] Good-first-issue list of secret formats. Start with the gaps found in the M1 review: XML (`<password>`, `<add key="ApiKey" value="…"/>`), `.netrc`, Docker config `auth`, `?key=` for vendors other than Google, `?subscription-key=`, and Google `1//` refresh tokens.
- [ ] HAR support.
- [ ] Review flags: leftover high-entropy strings are flagged for review, not silently removed. That includes readable identifiers and unknown custom claims in the copied claims block, such as `nonce`, `jti` or `pin`.
- [ ] Crate license notices in the bundle, next to Angular's and the fonts'.
- [ ] Label kinds come from key names, so a secret glued into a name (`AWS_AKIA…_SECRET=…`) shows up inside its label. Fall back to a generic kind when that happens.

## Later

- SAML assertions
- Optional personal-data rules (emails, IPs, names in claims)
- A CLI on the same engine
- Signed builds with build provenance
- Open files or drag and drop them in
- JWT signature check with a key pasted locally
- Values split across lines: curl `\` line continuations and folded headers
- Copies across encodings, such as a value that appears both raw and URL-encoded (`+` and `%2B`), or both inside and outside a Basic header
- Marks and line numbers in the input pane, or CodeMirror 6, if the dogfooding log asks for them
- Sanitizing in a Web Worker, if the log records typing lag
- Click a finding to find it in the text
- AppImage or Flatpak on request; MSI, a portable exe, and ARM64 builds for Windows and Linux

## Not planned

- General utility tools such as JSON formatting, Base64 or UUIDs. DevToys and CyberChef cover these.
- Scanning repositories for secrets. gitleaks and trufflehog do this.
- Accounts, sync, telemetry or anything hosted.
- Automated UI tests on macOS. The only WebDriver route there embeds an HTTP server in the app.

## How we'll know it works

Evidence comes from dogfooding (n=1, recorded in the log). After release it also comes from public signals: "missed a secret" issues, new-rule PRs and downloads.
