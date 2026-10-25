# AGENTS.md

These are the working rules for agents in this repo. Carmine Workbench is a local-first desktop app (.NET 10 + Avalonia 12, Apache-2.0) that sanitizes curl commands, headers, logs, JSON bodies and tokens before they are shared.

## Sources of truth

- `README.md`: the pitch and the privacy contract.
- `ROADMAP.md`: decisions already made, the milestones, and what is out of scope. Check it before proposing features. Respect those decisions unless the owner reopens them.
- Work from the next unchecked item in `ROADMAP.md`. Don't build past the current milestone without asking.

## The privacy contract (hard rules)

The product's promise is only as good as these rules. Never break them, not even in dev tooling that ships.

- **One network call, for updates.** Velopack's update check against GitHub Releases, in `src/Carmine.Desktop/Services/Updates.cs`, is the only network code. Nothing else may use `HttpClient`, sockets, `WebRequest`, DNS or a WebSocket, or open a URL. The check never carries input. A package that can reach the network is never added, Velopack aside. `NetworkGuardTests` scans raw text, comments included, so reword a comment that names `Process`, `Socket` or `Ping`. P/Invoke is banned in `src/` until a native call gets a reviewed exception.
- **No remote assets.** Fonts and icons are bundled. Nothing loads from a CDN or a font service.
- **No persistence of input.** No history, telemetry or crash reporting. Settings hold preferences, never input. Write to the clipboard only when the user explicitly copies, and never read it.
- **No real secrets anywhere.** That covers fixtures, tests, issues, commits and docs. Build fake secrets so that GitHub secret scanning doesn't match them, for example by assembling them at test time or cutting them short with `…`.

## Sanitize engine

- Rules are plain C# under `src/Carmine.Core/Sanitize/`. `Carmine.Core` references no package and no other project, and does no I/O, so tests and a future CLI can reuse it. `CorePurityTests` enforces this.
- Each rule is one folder under `Sanitize/Rules/`: `<Name>Rule.cs` plus `fixtures/`. It is also listed in `Sanitize/Rules/RuleList.cs`.
- A fixture case is `<case>.in.txt` plus `<case>.out.txt`. If there is no `.out.txt`, the input must come out unchanged: use that for false-positive guards. Start each case name with its input format, such as `curl-`, `http-`, `log-`, `json-` or `yaml-`.
- Every secret in an `.in.txt` is a placeholder. `{{secret:value}}` marks a literal. `{{fake:<format>}}` has `tests/Carmine.Tests/Sanitize/Fakes.cs` build a vendor key, PEM block or JWT at test time, and `{{fake:<format>:2}}` builds a second one.
- The runner checks every case:
  - **No leak:** no declared secret may appear in the output.
  - **Declared:** every removed value must be declared.
  - **Idempotent:** sanitizing the output again must change nothing.
- A removed value becomes a typed, numbered label (`<jwt#1>`, `<cookie:sid#3>`), and the label stays the same within one document.
- For JWTs, replace the whole token and always drop the signature. The claims go to the Explain panel and to the copied output.
- Cases that test the engine rather than one rule live in `Sanitize/fixtures/` and run as `engine/<case>`.
- Regexes are `[GeneratedRegex]`, so NativeAOT gets compiled matchers. .NET regexes differ from JavaScript's, so spell classes out: `\w` and `\d` match letters and digits in every script, `\s` includes NEL (U+0085), and `.` matches CR. Use `Shared.Space` for whitespace. Never use `IgnoreCase`, which lets `k` match `K` (the Kelvin sign): write `[Aa]` classes, or compare an ASCII-lowered copy.
- Line endings are normalized to LF (`.gitattributes`), and fixtures are compared byte-for-byte. A raw HTTP case that has to keep CRLF is named `*.crlf.in.txt` / `*.crlf.out.txt`, and `.gitattributes` keeps its bytes.

## UI and copy

- The UI follows the directive//01 design system, adapted: bundled fonts, the theme follows the OS setting, and colors are corrected to pass WCAG 2.2 AA.
- Tokens live in `src/Carmine.Desktop/Themes/Tokens.axaml`. When the UI puts a new text or focus color on a surface, add the pair to `Pairs` in `tests/Carmine.Tests/Desktop/ContrastTests.cs`.
- Every control a screen reader reaches has a name: text content or `AutomationProperties.Name`.
- Voice is calm, short and declarative. No exclamation marks, no emoji. Never tell the user output is "clean". Say "4 secrets removed, review before sharing".
- Dates are written `2026.09.24` and times use the 24-hour clock.

## Brand

- The assets are in `docs/brand/`. `-dark` files are for dark backgrounds.
- The wordmark is Barlow Semi Condensed SemiBold, uppercase, with 0.08em letter spacing, converted to vector paths. Use the SVGs; don't re-typeset the wordmark with a font.
- App icons need the mark on a paper-colored tile (`#f2ede2`), because the dark strokes disappear on dark taskbars.

## Dependencies

- Versions live in `Directory.Packages.props`. Every package must work under NativeAOT and trimming.
- You may add a special-purpose library on your own, such as a parser for one format. Add a general-purpose helper only when nothing in the project or the .NET library already does the job. Never add a framework (MVVM, DI, reactive or UI kits beyond Avalonia and CommunityToolkit.Mvvm) without asking.
- Every package the app ships, including transitive ones, is on the allowlist in `NetworkGuardTests`, with its reason. Adding one means adding it there.

## Commands

- `dotnet build` and `dotnet test --project tests/Carmine.Tests` from the repo root run the build and every test, the guards included.
- `dotnet format --verify-no-changes` is the CI style check. Run `dotnet format` before committing.
- `dotnet run --project src/Carmine.Desktop` runs the app.
- `dotnet run --project tools/Carmine.Screenshots -- <folder>` renders every screen headless to PNG, in light and dark. Check UI changes with it; `docs/screenshot-*.png` come from it.
- `dotnet publish src/Carmine.Desktop -c Release -r <rid>` makes the NativeAOT build. On Windows, put `%ProgramFiles(x86)%\Microsoft Visual Studio\Installer` on `PATH` first, or the link step fails.

## Working style

- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `chore:`, `test:`, `ci:`, `build:`, `refactor:`). Keep each commit atomic, and use a scope when it adds clarity (`feat(rules): …`).
- **No AI attribution** in commits or PRs. That means no `Co-Authored-By` trailers, no "Generated with" lines and no session links.
- **Checks:** automate acceptance checks instead of handing manual steps to the owner. Give every check that tests for an absence a positive control. For example, the network guard must fail on a deliberate `new HttpClient(` outside the updater.
- **Validation:** evidence comes from dogfooding (the log) and public async signals (issues, PRs, downloads). Don't plan interviews, recruiting or outreach.
- **Docs:** short and concise. Prefer editing `ROADMAP.md` over creating new planning documents.
- **Code comments:** explain why, not what. Only comment on what the code can't say for itself: a non-obvious constraint, a workaround and its cause, what a regex is meant to match, or a line that keeps the privacy contract. Don't restate names or types, don't add boilerplate XML docs, and don't leave commented-out code or change notes. If code needs a comment to say what it does, rename or split it first. A rule's fixtures are its documentation.
