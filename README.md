[![GitHub release](https://img.shields.io/github/v/release/ContrailRisks/SnipGuard)](https://github.com/ContrailRisks/SnipGuard/releases)

# SnipGuard — paste protection for AI prompts

**SnipGuard** is a lightweight, on-device DLP for AI prompts. It detects and warns (or blocks) when you paste API keys, PII, or proprietary code into ChatGPT, Claude, Gemini, and other AI tools — before the text lands in the input. All detection runs **locally**; no content leaves your machine.

## Demo
![SnipGuard blocks a risky paste showing options to Mask & paste, Paste anyway (hold to confirm), or Cancel.](img/snipguard-paste-warning.png)

> Example on an AI prompt box: SnipGuard detects an API key and PII before the text is shared.

## Features

**Interception**
- Pre-paste interception on ChatGPT, Claude, Gemini, Copilot, Perplexity, Poe.
- Drag-and-drop file scanning (`.txt`, `.log`, `.json`, `.env`, source files).
- File upload scanning for `<input type="file">` on AI sites.
- Multi-paste chunking: detects secrets spread across pastes within a 10 s window.

**Detection**
- API key signatures: OpenAI, GitHub PAT, AWS AKID, Stripe, Azure Storage, Discord, Firebase, Cloudflare, Postgres connection URLs.
- PII: email, phone (E.164 / formatted), credit card (Luhn), IBAN (Mod-97).
- Code heuristics: line-count threshold + language keywords + config file patterns.
- Organisation markers: custom strings configured in Options.
- High-entropy fallback for unknown secrets (Shannon H > 3.2).

**Policy & UX**
- Per-site modes: `block`, `warn`, or `ignore` — configurable per hostname.
- Domain allowlist to skip trusted internal sites.
- "Mask & paste" automatic redaction with format-preserving output.
- "Paste anyway" requires a 1.2 s hold to prevent accidental bypass.
- Zero telemetry by default.

## Install (developer mode)
1. Download the latest release zip or clone and build from source.
2. Open **chrome://extensions** → enable **Developer mode**.
3. Click **Load unpacked** and select the `snipguard/` folder.
4. Visit any supported AI site and paste a test secret to see the warning.

## Build & test
```sh
npm test        # run detector unit tests
npm run build   # package extension zip
```

## Privacy
SnipGuard processes text **only in-page** using content scripts. It does not send data anywhere. Settings are stored via `chrome.storage.sync`. No logs or analytics are collected by default.

## Contributing
See [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to add detectors, report bugs, and submit pull requests.

## Roadmap

See [`ROADMAP.md`](ROADMAP.md) for the full plan. Up next: Firefox/Edge builds, more secret providers (Twilio, Telegram, Anthropic, HuggingFace, Slack), and enterprise policy controls.

## License
Apache-2.0 — see [`LICENSE`](LICENSE).
