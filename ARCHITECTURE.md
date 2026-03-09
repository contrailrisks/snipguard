# Architecture

SnipGuard is a privacy-first, on-device browser extension that intercepts pastes (and optionally file drops) before content lands in AI chat inputs. It runs entirely in the page context — no network calls, no telemetry by default.

## High-level components

```mermaid
flowchart LR
  A[User paste / drop] --> B(Content Script)
  B --> C(Detectors: API/PII/Code)
  C -->|matches| D(UI Toast)
  C -->|no match| E[Let paste through]
  D -->|Mask & paste| F[Sanitize]
  D -->|Paste anyway| G[Insert original]
  D -->|Cancel| H[Do nothing]
  subgraph Storage
    I[(chrome.storage.sync)]:::sync
    J[(chrome.storage.managed)]:::managed
    K[(chrome.storage.local)]:::local
  end
  B <-- policy --> I
  B <-- admin policy --> J
  B -. content-free events .-> K

  classDef sync fill:#e6f3ff,stroke:#5B93FF,color:#111
  classDef managed fill:#e9ffe6,stroke:#3fb950,color:#111
  classDef local fill:#f6f8fa,stroke:#aaa,color:#111
```

## Files & responsibilities

- **`src/content.js`**
  - Hooks: `paste`, `drop`, `change` (`<input type=file>`) on target sites.
  - Loads policy from `chrome.storage.sync`; merges admin overrides from `chrome.storage.managed`.
  - Calls `window.SG.detectAll()` and decides: block, warn, or ignore (per-site mode).
  - Inserts text into textarea / input / contentEditable (Shadow DOM-aware as we improve).
  - Emits content-free audit events to `chrome.storage.local` (optional).
  - Caches policy for 5 s to avoid redundant storage reads on rapid pastes.

- **`src/detectors/registry.js`**
  - Provides `window.SG_DETECTORS` — a simple `{ register(det), list[] }` object.
  - Each detector file calls `register()` on load; `index.js` iterates `list` to run them.

- **`src/detectors/core.js`**
  - Shared pure helpers used by multiple detectors: `shannonH`, `luhnOk`, `mod97`, `escapeForRx`.

- **`src/detectors/secrets/`** — API key detectors
  - `openai.js` — `sk-` + 48 base58 chars
  - `github.js` — `github_pat_` + 80 chars
  - `aws.js` — `AKIA`/`ASIA` 20-char AKID
  - `stripe.js` — `sk_live_` / `sk_test_` / `rk_live_` keys
  - `azure.js` — Storage account connection strings (`AccountKey=…`)
  - `discord.js` — bot token (base64 user ID + timestamp + HMAC)
  - `firebase.js` — `AIza` prefix (Google API key)
  - `cloudflare.js` — context-scoped: only matches when paired with a `CF_API_TOKEN` env name
  - `postgres.js` — connection URIs with embedded credentials (`postgres://user:pass@host`)
  - `high-entropy.js` — catch-all; 32+ char base64/hex strings with Shannon H > 3.2; **loaded last**

- **`src/detectors/pii/`** — personal data detectors
  - `email.js` — RFC 5321 simplified regex
  - `phone.js` — E.164 international (`+` prefix) or formatted numbers; rejects bare digit strings
  - `credit-card.js` — 13–19 digit sequences passing Luhn checksum
  - `iban.js` — 15–34 char IBANs passing Mod-97 (ISO 13616)

- **`src/detectors/code/`** — code / proprietary-content heuristics
  - `heuristic.js` — line-count threshold + language keywords + config file patterns
  - `org-markers.js` — user-configured strings (internal codenames, project names)

- **`src/detectors/index.js`**
  - `detectAll(text, cfg)` — iterates the registry; respects `cfg.enabled` / `cfg.disabled` lists; returns a flat array of match objects.
  - `sanitize(text, detections)` — calls each detector's `redact()` for format-preserving replacement; falls back to `[[REDACTED_KEY]]`.
  - Exposed on `window.SG`.

- **`src/ui.js` + `src/ui.css`**
  - Lightweight toast/modal (single DOM node, removed after action).
  - Actions: **Mask & paste**, **Paste anyway** (1.2 s hold-to-confirm), **Cancel**.
  - Optional: require justification text for bypass (policy-controlled).

- **`sw.js`** (service worker)
  - First-run defaults and lightweight upgrade tasks.
  - No network, no alarms — kept minimal.

- **`options.html` + `options.js`**
  - User settings: block types, allowlist, org markers, per-site modes.
  - Shows read-only badges for managed (admin-locked) fields.

- **Storage**
  - `chrome.storage.sync` — user settings.
  - `chrome.storage.managed` — admin policy (read-only, optional).
  - `chrome.storage.local` — content-free audit ring buffer (optional).

- **`tests/detectors.spec.mjs`**
  - Node.js `vm` sandbox; loads all detector files in the same order as `manifest.json`.
  - Calls `window.SG.detectAll()` / `window.SG.sanitize()` directly — no browser required.
  - 27 test cases covering all detectors, false-positive guards, and redaction output.

## Data flow

```mermaid
sequenceDiagram
  participant U as User
  participant CS as Content Script
  participant DET as Detectors
  participant UI as Toast UI

  U->>CS: paste/drop text
  CS->>CS: load policy (sync + managed, 5 s cache)
  CS->>DET: detectAll(text, cfg)
  DET-->>CS: flat array of match objects
  alt hasRisk & mode=block|warn
    CS->>UI: show toast (summary + sanitized preview)
    alt Mask & paste
      UI->>CS: sanitize
      CS->>U: insert sanitized text
    else Paste anyway (hold 1.2 s)
      UI->>CS: proceed
      CS->>U: insert original text
    else Cancel
      UI-->>CS: close
    end
  else (no risk or mode=ignore)
    CS->>U: insert original text
  end
  note over CS: Optionally log content-free event to storage.local
```

## Policy model

SnipGuard merges three layers (lowest → highest precedence):

1. **Defaults** — hardcoded safe values in `content.js`
2. **User settings** — `chrome.storage.sync`
3. **Managed policy** — `chrome.storage.managed` (authoritative; admin-pushed via enterprise/MDM)

If a key is present in managed policy, the Options UI shows it as locked (read-only). Managed keys may include: `blockOn`, `modeByHost`, `orgMarkers`, `customPatterns[]`, `bypass.{allowed,holdMs,requireReason}`, `logging.{enabled,contentFree,maxEvents}`.

## Detection pipeline

1. **Provider signatures** — deterministic regex for known API key formats: OpenAI, GitHub PAT, AWS AKID, Stripe, Azure Storage, Discord, Firebase/Google, Cloudflare, Postgres.
2. **PII validators** — email, E.164 phone, credit card (Luhn), IBAN (Mod-97).
3. **Code heuristics** — line count threshold + language/config markers; org markers escalate severity.
4. **Entropy fallback** — high-entropy substrings (32+ chars, Shannon H > 3.2) catch unknown secrets.
5. **Chunked pastes** — 10 s rolling buffer (`SG_RECENT`) detects secrets split across multiple paste events.
6. **Sanitization** — format-preserving replacement for recognized tokens (`sk_live_… → sk_live_[REDACTED]`); generic `[[REDACTED_*]]` otherwise.

Design goal: precision over recall for secrets. Users can always choose **Mask & paste** if a false positive is blocked.

## Privacy & security

- **Zero exfiltration** — no network calls; all checks run in-page.
- **Minimal permissions** — `storage`, `scripting`, and host patterns for supported AI sites.
- **Audit log (optional)** — content-free events only (counts, host, action taken); exportable by user/admin.
- **Bypass governance** — hold-to-confirm (1.2 s default); optionally require a short justification (stored content-free).
- **Supply-chain** — signed releases, CodeQL on push/PR (see `.github/workflows/`).

## Performance notes

- Content script loads tiny code paths; all detection is string/regex with no I/O.
- Incremental Mod-97 for IBAN avoids BigInt.
- Entropy runs after deterministic matches; candidate strings are capped on very large pastes.
- UI toast is a single DOM node, removed immediately after any action.
- Policy is cached for 5 s — no storage read on every keystroke/paste.

## Extensibility

### Adding a detector

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full step-by-step guide and a minimal file template. In summary:

1. Create `src/detectors/{kind}/your-detector.js` using the IIFE + `window.SG_DETECTORS.register()` pattern.
2. Add the path to `manifest.json` (before `high-entropy.js` and `index.js`).
3. Add the path to the loader in `tests/detectors.spec.mjs`.
4. Write at least one match case and one false-positive guard in the spec.

### Per-site modes

`modeByHost`: `block` | `warn` | `ignore`. Suggested defaults: public AI sites → `block`, internal docs → `warn`, localhost → `ignore`.

### Enterprise features (optional)

- **Managed policy** — `chrome.storage.managed` merge (admin-controlled keys are read-only in UI).
- **Bypass with justification** — UI text input gating "Paste anyway".
- **Content-free audit events** — ring buffer in `storage.local` with JSON export.

## Error handling

- **DOM failures** (exotic editors) — fall back to `document.execCommand('insertText', …)` or show "copy sanitized to clipboard".
- **Storage errors** — continue with defaults; surface a non-blocking notice in Options only.
- **Regex safety** — avoid backtracking traps; prefer linear-time patterns.

## Build, test, release

- **Dev**: load unpacked at `chrome://extensions`.
- **Tests**: `npm test` — lightweight Node VM runner, no browser required.
- **CI** (`ci.yml`): runs on push and PRs to `main`; executes tests and uploads a preview zip artifact (7-day retention).
- **CodeQL** (`codeql.yml`): static analysis on push, PRs, and weekly schedule.
- **Release** (`release.yml`): triggered by `vX.Y.Z` tags; runs tests, generates artifacts, then publishes a GitHub Release.
- **Release automation** (`release-please.yml`): opens a version-bump PR automatically after each `feat:` or `fix:` commit lands on `main`; merging the PR creates the tag and triggers the release workflow.

## Supply chain security

Every release includes:

| Artifact | Purpose |
|---|---|
| `snipguard-vX.Y.Z.zip` | Extension bundle (loads unpacked in Chrome) |
| `snipguard-vX.Y.Z.sha256` | SHA-256 checksum for integrity verification |
| `snipguard-vX.Y.Z.sbom.spdx.json` | Software Bill of Materials (SPDX 2.3, generated by syft) |
| `snipguard-vX.Y.Z.zip.sig` | Cosign signature (keyless OIDC, recorded in Rekor) |
| `snipguard-vX.Y.Z.zip.pem` | Fulcio certificate for signature verification |

**Verifying a release:**
```sh
cosign verify-blob \
  --certificate snipguard-vX.Y.Z.zip.pem \
  --signature   snipguard-vX.Y.Z.zip.sig \
  --certificate-identity-regexp \
    "https://github.com/ContrailRisks/snipguard/.github/workflows/release.yml" \
  --certificate-oidc-issuer \
    "https://token.actions.githubusercontent.com" \
  snipguard-vX.Y.Z.zip
```

## Threat model

### In scope
- Accidental/naïve leaks via paste or file drop.
- Common API key formats, obvious PII, heuristic code detection.

### Out of scope
- Intentional exfiltration, steganography, or novel encoding tricks.
- OCR of screenshots, images, or PDFs (future enhancement).
- Editors/browsers outside the supported host list.

## Glossary

- **DLP** — Data Loss Prevention: controls that prevent sensitive data from leaving a boundary.
- **PII** — Personally Identifiable Information.
- **Managed policy** — admin-pushed settings via enterprise/MDM (read-only to users).
- **Shannon entropy** — information-theoretic measure of randomness; used to catch unknown high-entropy secrets.

## Appendix: Key entry points

| Entry point | Location | Description |
|---|---|---|
| `document.addEventListener('paste', …)` | `src/content.js` | Main paste hook |
| `document.addEventListener('drop', …)` | `src/content.js` | Drag-and-drop hook |
| `window.SG.detectAll(text, cfg)` | `src/detectors/index.js` | Run all detectors; returns flat match array |
| `window.SG.sanitize(text, detections)` | `src/detectors/index.js` | Format-preserving redaction |
| `window.SG_DETECTORS.register(det)` | `src/detectors/registry.js` | Detector registration |
| `chrome.storage.sync / managed / local` | `src/content.js`, `sw.js`, `options.js` | Settings, policy, audit log |
