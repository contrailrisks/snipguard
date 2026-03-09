# SnipGuard Roadmap

SnipGuard protects developers and teams from accidentally pasting secrets, PII, and proprietary code into AI tools. Detection runs entirely on-device — no content ever leaves your machine.

---

## Shipped

### v0.1.2 — Foundation (Oct 2025)

First public release.

- Pre-paste interception on ChatGPT, Claude, Gemini, Copilot, Perplexity, Poe
- Modular detector architecture (`src/detectors/`)
- API key detection: OpenAI, GitHub PAT, AWS AKID, Stripe
- PII detection: email, phone (E.164), credit card (Luhn), IBAN (Mod-97)
- Code heuristics + organisation markers
- Mask & paste, per-site modes (block / warn / ignore), domain allowlist
- Drag-and-drop and `<input type=file>` scanning
- Multi-paste chunking (10 s rolling window)
- CI pipeline with preview artifact

### v0.1.3 — Architecture docs (Oct 2025)

Added `ARCHITECTURE.md`. No behavioural changes.

---

## In progress

### v0.2.0 — Reliability & expansion

Expanded provider coverage, reliability fixes, hardened supply chain, and a full documentation refresh.

**Detection**
- New providers: Azure Storage, Discord, Firebase/Google, Cloudflare, Postgres connection URIs
- High-entropy catch-all promoted to first-class registered detector
- Phone detector tightened to E.164 / formatted-only (eliminates order-ID false positives)
- Code heuristic import keyword anchored to line start

**Reliability**
- Fixed sanitize/chunked-detection index mismatch in content script
- Policy fetched once per 5 s (no redundant storage reads on rapid pastes)
- Warning summary hides zero-count categories

**Supply chain** (closes #15)
- CodeQL scanning on push, PRs, and weekly schedule
- SBOM (SPDX 2.3 JSON via syft) attached to every release
- Cosign keyless OIDC signing — zip verifiable with `cosign verify-blob`
- Release automation via release-please + GitHub App token

**Docs**
- Rewrote README, CONTRIBUTING.md, ARCHITECTURE.md to reflect modular architecture

---

## Planned

### v0.3 — Reach & polish

Wider browser support, more providers, and UX improvements.

**Browser reach**
- Firefox build (WebExtension polyfill)
- Edge build

**More providers**
- Twilio auth tokens (`SK…`)
- Telegram bot tokens
- Anthropic API keys (`sk-ant-…`)
- HuggingFace tokens (`hf_…`)
- Slack tokens (`xoxb-` / `xoxp-`)
- npm publish tokens (`npm_…`)

**UX**
- Configurable hold-to-confirm duration (currently fixed at 1.2 s)
- Alt+Paste bypass toggle (skip warning for a single paste without holding)
- Shadow DOM / rich editor support (Notion, Linear, Confluence)
- Detection summary shows matched snippet preview

### v0.4 — Enterprise foundations

Controls for teams and organisations deploying SnipGuard at scale.

- Managed policy via `chrome.storage.managed` (MDM / admin push); locked fields shown read-only in Options UI
- Bypass with justification: short text required before "Paste anyway"
- Content-free audit log: counts, host, action — stored locally with JSON export
- Org JSON policy import for self-managed deployments
- Per-role allowlist support

### v1.0 — GA

Production-ready across browsers and enterprise environments.

- Firefox + Edge at feature parity with Chrome
- Enterprise features complete and documented
- Local on-device model for code / sensitive-text classification
- Chrome Web Store listing

---

## Principles

- **Local-first** — detection runs in-page; no content ever leaves the machine.
- **Precision over recall** — a missed detection is better than a false positive that disrupts a developer's flow.
- **Minimal footprint** — no external runtime dependencies, small content script, no background network calls.
- **Open core** — the extension stays Apache-2.0; enterprise delivery options may be offered separately.
