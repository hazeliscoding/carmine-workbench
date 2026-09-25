# AGENTS.md

These are the working rules for agents in this repo. Carmine Workbench is a local-first desktop app (Angular + Tauri v2, Apache-2.0) that sanitizes curl commands, headers, logs, JSON bodies and tokens before they are shared.

## Sources of truth

- `README.md`: the pitch and the privacy contract.
- `ROADMAP.md`: decisions already made, the milestones, and what is out of scope. Check it before proposing features. Respect those decisions unless the owner reopens them.
- The repo is still in planning. Don't build past the current milestone without asking.

## The privacy contract (hard rules)

The product's promise is only as good as these rules. Never break them, not even in dev tooling that ships.

- **No networking code.** No `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource` or `sendBeacon`. No Tauri HTTP or updater plugins. No HTTP crates in `src-tauri/`.
- **No remote assets.** Fonts and icons are self-hosted. Nothing loads from a CDN or Google Fonts.
- **No persistence of input.** No history, telemetry or crash reporting. Write to the clipboard only when the user explicitly copies.
- **No real secrets anywhere.** That covers fixtures, tests, issues, commits and docs. Build fake secrets so that GitHub secret scanning doesn't match them, for example by assembling them at test time or cutting them short with `…`.

## Sanitize engine

- Rules are plain TypeScript under `src/app/core/sanitize/`. They have no Angular imports and do no I/O.
- Each rule is one folder: `rule.ts` plus `fixtures/`. The fixtures are input and expected-output pairs.
- Every fixture must also pass the no-leak check: none of its secret values may appear in the output.
- A removed value becomes a typed, numbered label (`<jwt#1>`, `<cookie:sid#3>`), and the label stays the same within one document.
- For JWTs, replace the whole token and always drop the signature. The claims go to the Explain panel and to the copied output.
- Line endings are normalized to LF (`.gitattributes`), and fixtures are compared byte-for-byte. If a fixture has to keep CRLF (raw HTTP), give it a `-text` override in `.gitattributes`.

## UI and copy

- The UI follows the directive//01 design system, adapted: self-hosted fonts, theme from `prefers-color-scheme`, and colors corrected to pass WCAG 2.2 AA.
- Voice is calm, short and declarative. No exclamation marks, no emoji. Never tell the user output is "clean". Say "4 secrets removed, review before sharing".
- Dates are written `2026.09.24` and times use the 24-hour clock.

## Brand

- The assets are in `docs/brand/`. `-dark` files are for dark backgrounds.
- The wordmark is Barlow Semi Condensed SemiBold, uppercase, with 0.08em letter spacing, converted to vector paths. Use the SVGs; don't re-typeset the wordmark with a web font.
- App icons need the mark on a paper-colored tile (`#f2ede2`), because the dark strokes disappear on dark taskbars.

## Working style

- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `chore:`, `test:`, `ci:`, `build:`, `refactor:`). Keep each commit atomic, and use a scope when it adds clarity (`feat(rules): …`).
- **No AI attribution** in commits or PRs. That means no `Co-Authored-By` trailers, no "Generated with" lines and no session links.
- **Checks:** automate acceptance checks instead of handing manual steps to the owner. Give every check that tests for an absence a positive control. For example, the network guard must fail on a deliberate `fetch(`.
- **Validation:** evidence comes from dogfooding (the log) and public async signals (issues, PRs, downloads). Don't plan interviews, recruiting or outreach.
- **Docs:** short and concise. Prefer editing `ROADMAP.md` over creating new planning documents.
- **Code comments:** explain why, not what. Only comment on what the code can't say for itself: a non-obvious constraint, a workaround and its cause, what a regex is meant to match, or a line that keeps the privacy contract. Don't restate names or types, don't add boilerplate JSDoc, and don't leave commented-out code or change notes. If code needs a comment to say what it does, rename or split it first. A rule's fixtures are its documentation.
- Local Playwright output goes to `.playwright-mcp/`, which git ignores.
