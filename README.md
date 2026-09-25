<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/lockup-dark.svg">
    <img alt="Carmine Workbench" src="docs/brand/lockup.svg" height="40">
  </picture>
</h1>

**Sanitize before you share.** Paste a curl command and the tokens disappear. The debugging detail stays.

When an integration breaks, you paste curl commands, headers, logs and tokens into tickets, chats and vendor support portals. That is how credentials leak. In 2023, attackers took HAR files from Okta's support system and used the session tokens inside them against Okta's customers.

Carmine removes what grants access, keeps what helps debugging, and shows you every change. It has no networking code.

> **Status:** planning. There is nothing to install yet. See [ROADMAP.md](ROADMAP.md).

## Before and after

```sh
curl https://api.example.com/v1/orders \
  -H 'Authorization: Bearer eyJhbGciOiJSUzI1NiIs…' \
  -H 'X-Api-Key: 3f9a8c2e…' \
  -b 'sid=9f3e1c7a…; theme=dark'
```

```sh
curl https://api.example.com/v1/orders \
  -H 'Authorization: Bearer <jwt#1>' \
  -H 'X-Api-Key: <api-key#2>' \
  -b 'sid=<cookie:sid#3>; theme=dark'

# jwt#1 · RS256 · signature removed
#   sub  usr_034
#   aud  orders-api
#   exp  2026.09.24 08:19 (expired 12m ago)
```

## What it does

- **Removes** bearer tokens, cookies, API keys, secret URL parameters, sensitive JSON keys, private keys and known key formats.
- **Keeps** the structure. The same secret gets the same label everywhere, so readers can still follow it across requests.
- **Explains** any JWT it finds: decoded claims, expiry in plain time, and warnings. It decodes tokens but does not verify them.
- **Shows** every change in a diff before you copy.

## The privacy contract

- **No network.** There is no networking code and no auto-updater. The app's Content Security Policy blocks outbound connections, and CI rejects network calls.
- **Nothing kept.** Input stays in memory only. There is no history and no telemetry.
- **Open source**, so you can check all of this instead of trusting it.

## Contributing

Each rule is one folder: a small detector plus fixtures. Adding a new secret format is a good first contribution. A contributor guide arrives with v0.2.

## License

[Apache-2.0](LICENSE)
