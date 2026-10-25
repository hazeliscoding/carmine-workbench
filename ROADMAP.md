# Roadmap

Carmine is a local-first desktop app (.NET 10 + Avalonia 12) that sanitizes auth and integration debugging material before you share it. This file tracks what gets built, in what order, and the decisions already made.

## Decisions (2026-09-24)

- **Labels, not blanks.** Each distinct secret becomes a typed, numbered label (`<jwt#1>`, `<cookie:sid#3>`). Labels stay the same within one document, so a reader can still follow a value across requests.
- **JWTs** are replaced whole with `<jwt#1>`, and the signature is always dropped. The decoded header and claims appear in an Explain panel and as a readable claims block in the copied output. The block has a toggle and is on by default.
- **Personal claims** such as `email` or `name` are kept by default, because they don't grant access. An optional personal-data rule comes later.
- **Rules are plain TypeScript** under `src/app/core/sanitize/`. They have no Angular imports and do no I/O, so tests and a future CLI can reuse them. *Superseded 2026-10-24: the rules are plain C# in `Carmine.Core`, with the same limits.*
- **No auto-updater.** An updater is networking code. Updates come from GitHub Releases. *Superseded 2026-10-24: Velopack updates from GitHub Releases, as in Prompuff.*
- **UI** uses the directive//01 design system and the shell of the Devbox demo mockup, re-skinned as a single Sanitize screen.
- **Brand** is option 1A, "Caliper": two measuring jaws holding a single datum. The wordmark is Barlow Semi Condensed, converted to vector paths. The assets are in `docs/brand/`, with `-dark` files for dark backgrounds.

## Decisions (2026-09-25)

- **Fonts** come from Fontsource packages and are bundled into the app, with their OFL licenses under `licenses/`. Source Serif 4 is dropped, because Carmine has no personal voice. *Superseded in part 2026-10-24: the files are static TTFs from each family's own releases.*
- **Colors** keep the directive//01 palette. Five tokens changed to pass WCAG 2.2 AA on every surface the UI uses, not only the page. The `AA` notes in `src/styles/tokens.css` give the old values, and `scripts/check-contrast.mjs` checks each pair in CI. *Superseded in part 2026-10-24: the tokens are in `Themes/Tokens.axaml`, and the check is a test.*
- **HTTP crates** are checked with `cargo tree` for the three desktop targets. `Cargo.lock` also lists crates for mobile, where tauri pulls in `reqwest`, so scanning it gives false positives. *Superseded 2026-10-24: there is no Rust. The network guard checks the app's NuGet graph against an allowlist.*
- **CI** builds on Linux only until the M2 release workflow adds Windows and macOS.
- **The engine scans raw text.** It doesn't detect or parse formats, because real pastes mix curl, headers, logs and cut-off JSON. Output bytes stay the same outside the removed values, and the input's line endings are kept.
- **Overlaps:** format rules (`jwt`, `private-keys`, `known-secret-formats`) outrank context rules (headers, cookies, parameters, keys), and then the longer span wins. An overlapping finding merges into the winner, and the union of both spans is replaced under the winner's label. When it overlaps several, each keeps its label, and any letters or digits between them go to a neighbour.
- **Labels** are numbered across all kinds in order of first appearance. A label belongs to the value, whichever rule found it. Every other copy of a removed value of 8 or more characters gets the same label, even where no rule matches.
- **Kept on purpose:** references (`$TOKEN`, `{{token}}`, `<token>`, `***`, existing labels), plain cookie values under 8 characters (`theme=dark`), `token_type`, pagination tokens and Stripe `pk_` keys. Sanitizing twice changes nothing.
- **Where a name alone isn't proof, the value must look like a credential.** Examples are header names such as `token`, a bare word after `Authorization:`, `Bearer` outside a header, and generic parameters such as `code`, `auth` and `sig`. Code that reads a secret (`await getToken()`, `password: string`) is left alone. Values under sensitive key names such as `password` are always removed.
- **Performance:** the engine and rules stay linear, because M2 sanitizes as you type. A test holds a 1 MB input under 3 s; it takes about 0.3 s. *2026-10-25: through all seven rules, the C# engine takes 0.3 to 0.5 s on that input, against 0.08 s in V8.*
- **Fake secrets** are built at test time. Fixture inputs write every secret as `{{secret:…}}` or `{{fake:<format>}}`. GitHub's partner scanning of public repos can't be scoped, so an allowlist would only hide the alerts here while vendors still got notified.
- **Claims:** the engine returns the decoded claims. Writing the claims block into the copied output is M2, along with its toggle.
- **Input** is a native textarea. Removed values are marked only in the diff, which is built from change positions, not by matching values. Input marks or CodeMirror come back only if the dogfooding log asks for them. *Superseded in part 2026-10-24: the input is an Avalonia TextBox, and AvaloniaEdit takes CodeMirror's place.*
- **Sanitize as you type** runs on the main thread, with no Web Worker. Paste runs at once, typing waits 150 ms, and Copy always sanitizes the current input first. *Superseded in part 2026-10-24: it runs on the UI thread, with no background thread.*
- **The textarea turns CRLF into LF**, so text copied from the app uses LF. The engine still keeps CRLF for callers that pass it, such as the tests and the future CLI. *Superseded 2026-10-24: there is no textarea. M2 decides what the TextBox does with CRLF.*
- **Times** are UTC, written with the zone: `2026.09.24 08:19 UTC`. The Explain panel shows live ages. The copied block has one `as of` stamp, and its ages count from it (`expired 12m earlier`), so it stays true when read later.
- **The claims block** lists every header field and claim as `#   key: <JSON value>`. It is sanitized in one pass with the input, so a claim equal to a removed value becomes that value's label, whatever its length. Copy writes nothing if that pass fails.
- **Summary wording:** "1 secret removed, review before sharing", or "Nothing removed, review before sharing" when there are none. The count is distinct labels.
- **Copy** calls `navigator.clipboard.writeText` inside the click or key handler, with no clipboard plugin. Only `copy.ts` writes the clipboard, and nothing reads it. *Superseded in part 2026-10-24: Copy uses Avalonia's clipboard from one service, which only writes.*
- **The webview** runs incognito with autofill off. On Windows the app creates its own WebView2 environment with crash reporting off, because a crash dump can hold pasted input. It clears leftover dumps at startup and limits navigation to the app. *Superseded 2026-10-24: there is no webview.*
- **Installers** don't download anything. Windows uses `webviewInstallMode: skip`, since every other mode ships download code or adds 127 MB or more. The app shows Microsoft's download link when WebView2 is missing. *Superseded 2026-10-24: there is no WebView2, and Velopack's Setup carries the whole app.*
- **Release builds:** a per-user NSIS installer, one universal `.dmg` with an ad-hoc signature, and `.deb` and `.rpm` built in an `ubuntu:22.04` container for a glibc 2.35 baseline. There is no AppImage: it bundles a WebKitGTK that gets no security updates, and its build tools are downloaded without a hash check. Without the ad-hoc signature, Apple Silicon reports the unsigned app as damaged. *Superseded 2026-10-24: Velopack packages, as in Prompuff.*
- **Release workflow:** written by hand, not tauri-action. Build jobs are read-only, and one tag-only job with write access runs no repo code. Actions are pinned by SHA, one `SHA256SUMS` covers the assets, and the release starts as a draft. PR CI stays on Linux.
- **Release checks:** an agent runs a CDP and SendKeys probe against the Windows draft, with the clipboard stubbed. CI installs the `.deb` under Xvfb, pastes and copies with xdotool and xclip, and reads the real clipboard. The macOS build is launched on arm64 and Intel runners. Nothing automated checks Copy on macOS. *Superseded in part 2026-10-24: the Windows probe drives the app through UI Automation instead of CDP, and Linux checks the AppImage instead of the `.deb`.*
- **The dogfooding log** is `docs/dogfooding.md`, in public. Entries name formats, never values, hosts or employers. A test fails if sanitizing the log would change it, or if it names a host outside `example.com`, `.test` or `localhost`.

## Decisions (2026-10-24)

- **The app is rewritten in .NET 10 and Avalonia 12, published with NativeAOT.** It is laid out like the owner's other Avalonia apps: `Carmine.Core` holds the engine, `Carmine.Desktop` the app, `Carmine.Tests` the tests, and `tools/Carmine.Screenshots` renders the screens headless. The owner builds their desktop apps in Avalonia. Without a webview, most of the privacy hardening M2 planned has nothing left to harden: the CSP, incognito mode and autofill, WebView2's crash dumps and runtime install, and the guard against browser storage APIs. NativeAOT keeps start-up and memory low (Sweepling idles at 8 MB). This gives up the Angular and Tauri code of M0 and M1, the smallest Windows download (Tauri borrows the system's WebView2, while Avalonia ships Skia), and the Tauri bundler.
- **The engine is ported, not redesigned.** The fixtures move unchanged and stay the contract: every case must come out byte for byte as it does from the TypeScript engine. Before the TypeScript engine goes, both engines run over the fixtures and generated variants of them, and every difference is fixed or recorded here. .NET regexes differ from JavaScript's in ways no fixture covers: `\w` and `\d` match letters and digits in every script, `.` matches CR, `\s` includes NEL, and case-insensitive matching folds more characters. The M2 engine fixes wait until the port is done, so any difference means the port is wrong.
- **Updates come through Velopack, as in Prompuff.** An installed copy asks GitHub Releases for a newer version each time it opens. A found update waits in the window until the user chooses Update and Restart, and a switch in Settings turns the check off. The request carries nothing the user pasted. It is the only network code, and the network guard allows it in one file. The owner wants Carmine to update the way their other apps do, and a rule that closes a leak only helps once it reaches users. This gives up the "no networking code" promise; the README now names the one request. The switch is the first thing Carmine stores on disk. Settings hold preferences, never input.
- **Packages follow Prompuff:** a Windows x64 Setup signed with the owner's Artifact Signing profile in a job of its own, ad-hoc signed macOS packages for Intel and Apple Silicon that aren't notarized, and a Linux x64 AppImage. The AppImage was ruled out because it bundles a WebKitGTK, which no longer applies. This gives up the `.deb` and `.rpm`, which can't update themselves, and the universal `.dmg`.
- **The rewrite lives on the `rewrite/avalonia` branch** until M1.5's "Done when" passes, then replaces `main`. As in Gil Sweep's rewrite, `main` keeps a working app and green CI meanwhile.
- **The checks are tests.** The network guard, the engine's purity check and the contrast check run in `Carmine.Tests`, each with its positive control, so CI needs no Node. The network guard fails on network APIs outside the updater's file, and on any package in the app's dependency graph that isn't on its allowlist.
- **Fonts** stay the same three OFL families, bundled as static TTF files from each family's own releases. Avalonia reads neither WOFF2 nor variable fonts, which is what Fontsource ships.
- **The status bar says `LOCAL · IN MEMORY ONLY`** instead of `LOCAL · NO NETWORK`, which the update check would make untrue.

## Decisions (2026-10-25)

- **Avalonia's build telemetry is off.** Avalonia 12 pulls in Avalonia.BuildServices, which sends usage data from every build. An empty `AvaloniaStats` target in `Directory.Build.targets` replaces its target, CI also sets `AVALONIA_TELEMETRY_OPTOUT`, and a test fails if the override stops winning. It sends from the build machine, not the app, but a privacy tool shouldn't send anything its contributors didn't choose. This gives up Avalonia's usage data from this repo; their README asks for support in other ways instead.
- **The app project names no runtime identifiers.** A plain restore already carries every platform's native libraries, and NativeAOT can't build for another OS, so each platform publishes on its own runner, as in Prompuff and Gil Sweep.
- **Regexes never use `IgnoreCase`.** Words are spelled as `[Aa]` classes, and whole-value tests run on an ASCII-lowered copy, which is all JavaScript's `i` flag folds. `\w`, `\d`, `\b` and `\s` are spelled out as JavaScript's sets.
- **The first NativeAOT build** (win-x64) is an 18 MB exe, and 36 MB with its native libraries; the publish folder also holds 172 MB of symbol files. It opened with a 110 MB working set. M2's packaging leaves the symbols and XML docs out.
- **The network guard scans raw text,** comments and strings included, because stripping comments needs a C# lexer and a mistake there would hide code. A comment that names `Process`, `Socket` or `Ping` gets reworded. P/Invoke is banned everywhere in `src/` until a native call gets a reviewed exception.
- **Parity with the TypeScript engine holds.** Two runs put both engines through 6.8 million inputs: the fixtures, generated variants and hand-built edge cases. No difference comes from the port, and three are recorded:
  - Newly assigned letters such as U+A7CE are letters in Node 24 (Unicode 17) but not in .NET 10 (Unicode 16).
  - TypeScript throws on a single run of about 1.5 to 8.4 million characters, when V8's regex backtrack stack fills up. C# returns a result.
  - After an earlier parse, Node 24's `JSON.parse` can return a cached key for an escaped one (`\/`, `\"`, `alg`). TypeScript's claims, and whether it finds a token at all, could depend on an earlier paste. C# reads the JSON as written.

  None of them can be a fixture, because an `.out.txt` can't hold an exception or a result that changes from run to run. The test helper also rejects `{{fake:toString}}` and placeholder numbers that `int.Parse` can't read, both of which `fixtures.ts` accepted. No fixture uses either.

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

## M1.5: Port to .NET and Avalonia

- [x] Solution: `Carmine.Core`, `Carmine.Desktop`, `Carmine.Tests` and `tools/Carmine.Screenshots`, with central package versions, and NativeAOT for the app.
- [x] The engine and the seven rules in C#, with the fixtures moved unchanged and the runner's three checks: no leak, declared, idempotent.
- [x] Parity: both engines over the fixtures and generated variants. Every difference is fixed or recorded, and each kind of difference found gets a fixture. *2026-10-25: no difference comes from the port; the three that remain are recorded under the decisions.*
- [x] Guards as tests, each with a positive control: network APIs only in the updater's file, a package allowlist, the engine's purity, and the contrast pairs.
- [x] The static Sanitize screen in Avalonia: the canned sample, the tokens and the bundled fonts, rendered headless to the README screenshots.
- [x] CI on Linux: build, tests, format, a NativeAOT publish that stays open under Xvfb, and the screenshots.
- [x] The Angular and Tauri app removed, and `AGENTS.md` and the README updated.

**Done when:** every fixture passes byte for byte in C#, the parity run finds no difference that isn't recorded, the 1 MB test holds, CI is green, and a NativeAOT build opens the Sanitize screen.

## M2: v0.1.0

- [ ] Engine fixes before sanitizing as you type:
  - [ ] Keep the rules linear on one long line: Digest, AWS4 and OAuth parameters, HTTPie `-a`, `mysql -p`. A 200 KB line of Digest headers takes 6.4 s today.
  - [ ] Never give a new value a label number that the input already holds.
  - [ ] Close the leaks a security review found in the M1 engine, each with a fixture: a reference that only starts the value (`{{name}}` or `$(cat f)` followed by the secret), a secret shaped like a reference (`$…`, `%…%`, `<…>`) that looks like a credential, and a URL password holding `/` or `@`.
  - [ ] Close the leaks the 2026-10-25 parity review found in both engines, each with a fixture:
    - Separators: a no-break space after a header's colon, a scheme or a key. Whitespace around `=` in auth-params. Doubled separators such as `password = = …`.
    - Escapes: JSON's `\/` (PHP) and `&` (Go). A JWT right after `"` or nginx's `\x22`. A `\"` cookie value. Double-escaped JSON. A URL nested URL-encoded inside another (`next=%2Fcb%3Faccess_token%3D…`).
    - Commands: combined short flags (`curl -sSb`, `-su`, `-fsSLu`), Chrome's `^"` cmd escaping, a quoted `mysql -p` password holding a space, and `MySQL` in another case.
    - Cookies: the scan stops at the first pair it can't read, such as one with no `=`, an empty segment, `@` or `:` in a name, or a space in a value. A name that starts with a digit after a comma reads as an Expires date. Cookie strings without a `Cookie:` header, such as `document.cookie`.
    - JWTs: padded segments, a token joined to a word by `-` or `_`, and a token wrapped across lines.
    - Keys:
      - YAML `|2` and `| # comment` blocks, anchors and tags.
      - `user[password]` form keys, and a value on the next line.
      - `${VAR:-default}` defaults, numeric passwords after `:`, and dotted values like `correct.horse.battery`.
      - Missing names: `password_confirmation`, `passcode`, `SECRET_KEY_BASE`, `APP_KEY`, `oauth_signature`, and `sig` after `\n`.
    - Private keys:
      - Truncated PEM and PGP blocks with headers or a blank line, and truncated ones with a short last line.
      - One-line PEMs, and base64 PEMs wrapped at 76 columns or not first in a bundle.
      - RFC 4716 armor.
      - Slack webhooks with escaped slashes, and `/triggers/` URLs.
    - The engine:
      - When two different secrets overlap, the tail of the second one stays.
      - A value found inside a wider finding isn't replaced where it appears again. In `password="Bearer …"`, the token stays on a later line.
- [ ] Wire the UI to the engine:
  - [ ] A pure review model in `Carmine.Core/Review`: output offsets, a diff from change positions with unchanged lines folded, findings rows and the summary. It replaces the static screen's canned diff. The purity check covers all of `Carmine.Core`.
  - [ ] Before the UI code lands, the guard also fails on file writes outside the settings file, clipboard reads, and opening URLs, and allows clipboard writes only in the copy service.
  - [ ] Sanitize as you type in a TextBox, with the findings list, an empty state and **Load sample**. The sample is assembled at runtime, like the fixtures.
  - [ ] Diff and Output toggle.
  - [ ] **Copy sanitized** (Ctrl/⌘+Shift+C), always from the current input.
- [ ] Dogfooding log: real debugging sessions, noting anything that was missed. It starts once Copy works.
- [ ] JWT Explain panel, for one JWT or several:
  - [ ] alg and kid; iss, sub and aud; exp, iat and nbf in dotted UTC time with relative age;
  - [ ] warnings for `alg: none`, a missing `exp`, lifetimes over 24 h, `exp` in milliseconds, and `nbf` or `iat` in the future;
  - [ ] the label "decoded, not verified".
- [ ] Claims block in the copied output, with its toggle. The README's before-and-after is regenerated from it. The writer is iterative or caps the depth, because recursion over a deeply nested header overflows .NET's stack, which no catch stops.
- [ ] Wording never says "clean". It says "4 secrets removed, review before sharing". A test checks every status line.
- [ ] Input stays in memory only. No history. The clipboard is written only on Copy, and settings hold preferences only.
- [ ] Updates, as in Prompuff: Velopack checks GitHub Releases when Carmine opens, a found update waits in the window until **Update and Restart**, and a Settings switch turns the check off. The network guard allows this in `Services/Updates.cs` only, and Velopack and its packages join the allowlist. The sidebar's `Network NONE` then names the one request.
- [ ] Release workflow: Velopack packages for Windows, macOS and Linux on GitHub Releases, with SHA-256 checksums.
  - [ ] Pack settings: pack ID, icons, app metadata and the third-party notices. The Windows Setup is signed in a job of its own; macOS gets the ad-hoc signature.
  - [ ] Windows acceptance probe: paste, check and copy through UI Automation against the installed draft, then scan the disk for a planted value.
  - [ ] AppImage smoke test under Xvfb in CI, and a macOS launch check.
  - [ ] An update check workflow, as in Prompuff: the previous release finds the new one on all three platforms.
  - [ ] The workflow itself, with its actions pinned by SHA.
  - [ ] Version 0.1.0, and a README with install steps, notes on the unsigned macOS build and screenshots of the live app. Also a GIF of about 5 seconds: paste a curl command, watch the labels appear, copy. The screenshots tool renders its frames headless from the fake sample and ffmpeg encodes them, so it is regenerated like the PNGs and adds no package.

**Done when:** in a released build, you can paste a curl command, see its secrets removed, and copy the result. The Windows probe checks this against the draft release before it is published.

## M3: v0.2, ready for contributors

- [ ] `CONTRIBUTING.md`: how to add a rule in one folder, with a rule template.
- [x] XML docs on the public API of `Carmine.Core`, which rules, tests and the CLI build on. They cover what a member promises that its name and types can't, such as what an offset counts or when a label number repeats. The comment rule in `AGENTS.md` changes to match: still no docs that restate a name. *Done 2026-10-25, ahead of M3.*
- [ ] `SECURITY.md`, plus a privacy contract document that lists each promise and how it is enforced. It also names what happens outside the app's control: Windows clipboard history, Windows Error Reporting, crash handlers on Linux and macOS, and on Linux the local D-Bus services that can see input text (the AT-SPI accessibility bus and input methods), along with a session bus set up over TCP.
- [ ] A "Missed a secret" issue template. It asks for the format, never the real value.
- [ ] Good-first-issue list of secret formats. Start with the gaps found in the M1 review: XML (`<password>`, `<add key="ApiKey" value="…"/>`), `.netrc`, Docker config `auth`, `?key=` for vendors other than Google, `?subscription-key=`, and Google `1//` refresh tokens. Then AI provider keys, which coding agents and AI chats see most: Anthropic `sk-ant-`, OpenAI `sk-proj-`, `sk-svcacct-` and `sk-admin-`, OpenRouter `sk-or-v1-`, Hugging Face `hf_`, Perplexity `pplx-`, Replicate `r8_` and Supabase `sb_secret_` (keeping `sb_publishable_`, as Stripe `pk_` is kept). Also an MCP config whose flag and value are separate `args` items.
- [ ] HAR support.
- [ ] Review flags: leftover high-entropy strings are flagged for review, not silently removed. That includes readable identifiers and unknown custom claims in the copied claims block, such as `nonce`, `jti` or `pin`.
- [ ] Package license notices in the bundle, next to the fonts'.
- [ ] Label kinds come from key names, so a secret glued into a name (`AWS_AKIA…_SECRET=…`) shows up inside its label. Fall back to a generic kind when that happens.

## Later

- SAML assertions
- Optional personal-data rules (emails, IPs, names in claims)
- A CLI on the same engine: text from stdin or a named file, sanitized text on stdout, the summary on stderr, and `--json` for the changes and claims. It is its own NativeAOT console project, because the app is a GUI program that can't write to a terminal. It fits a pipe into an agent (`npm test 2>&1 | carmine | claude -p "why does this fail"`), and the agent items below build on it.
- For coding agents, once the CLI exists:
  - A skill that tells an agent to run `carmine` on logs, curl commands and tokens before posting them to an issue, PR or chat. It only advises, so the README won't call it protection.
  - `carmine hook` for an agent's PreToolUse event: secrets in what a posting tool is about to send, such as an issue body or an MCP chat message, become labels. A shell command is denied with the findings instead, because a shell reads `<jwt#1>` as a redirection. It waits for a dogfooding-log entry where an agent posted a secret.
  - `carmine hook` for PostToolUse, where the agent allows it (Claude Code, Copilot CLI, and Cursor for MCP tools): secrets in a tool's output become labels before the model reads them, and JWT claims stay readable. Each agent gets an end-to-end test first, because Claude Code issues report the replacement ignored for Bash.
  - Agent sessions as input: Claude Code `/export` text and transcript `.jsonl` lines, with fixtures. Sensitive keys in JSON escaped twice, as when a transcript holds a tool's JSON output, are missed today. Carmine reads only what the user pastes or opens; it never looks for transcripts.
  - A stdio MCP server with one `sanitize_file` tool, if issues ask for it. Agents with a shell can run the CLI instead, and a tool that takes text receives secrets the model has already read. The official C# SDK ships HTTP client code, so it needs the package rule reopened or a hand-written stdio server.
  - When one of these ships, the README says where Carmine's output goes in that mode: to the agent and its model provider.
- Build provenance for the release files
- Open files or drag and drop them in
- JWT signature check with a key pasted locally
- Values split across lines: curl `\` line continuations and folded headers
- Copies across encodings, such as a value that appears both raw and URL-encoded (`+` and `%2B`), or both inside and outside a Basic header
- Marks and line numbers in the input pane, or AvaloniaEdit, if the dogfooding log asks for them
- Sanitizing on a background thread, if the log records typing lag
- Click a finding to find it in the text
- `.deb`, `.rpm` or Flatpak on request; a portable zip, and ARM64 builds for Windows and Linux

## Not planned

- General utility tools such as JSON formatting, Base64 or UUIDs. DevToys and CyberChef cover these.
- Scanning repositories for secrets. gitleaks and trufflehog do this.
- Hooks that only block a prompt or tool call holding a secret. ggshield and SonarQube CLI do this, and no agent lets a prompt hook hand back a sanitized prompt.
- A proxy between an agent and its model API that masks secrets and restores them in replies. PasteGuard does this, and it needs a listener and a stored mapping.
- An MCP gateway that filters every tool call. Microsoft's Agent Governance Toolkit covers this.
- Cleaning agent session histories in place. agentsweep does this offline.
- Redacting inside AI chat web pages. Browser extensions such as Nightfall's do this.
- Keeping `.env` files away from an agent. The agent's own deny rules and `dotenvx run --redact` do this.
- Accounts, sync, telemetry or anything hosted.
- Automated UI tests on macOS. The only WebDriver route there embeds an HTTP server in the app. *No longer holds 2026-10-24: Avalonia's headless tests need no WebDriver.*

## How we'll know it works

Evidence comes from dogfooding (n=1, recorded in the log). After release it also comes from public signals: "missed a secret" issues, new-rule PRs and downloads.
