# Contributing to SnipGuard

Thanks for helping keep prompts safe!

## How to build

```sh
npm test        # run detector unit tests
npm run build   # package extension zip
```

Load `snipguard/` as an unpacked extension in any Chromium-based browser (`chrome://extensions` → Developer mode → Load unpacked). Content scripts live in `src/`. No external network calls are permitted.

## Project layout

```
src/
  content.js              # paste/drop interception, policy merge, UI trigger
  detectors/
    index.js              # detectAll() + sanitize() — orchestrates the registry
    core.js               # shared helpers: shannonH, luhnOk, escapeForRx, mod97
    registry.js           # window.SG_DETECTORS.register / .list
    secrets/              # API key detectors
      openai.js
      github.js
      aws.js
      stripe.js
      azure.js
      discord.js
      firebase.js
      cloudflare.js
      postgres.js
      high-entropy.js     # catch-all; loaded last
    pii/                  # personal data detectors
      email.js
      phone.js
      credit-card.js
      iban.js
    code/                 # code / proprietary-content heuristics
      heuristic.js
      org-markers.js
  ui.js / ui.css          # toast modal
  sw.js                   # service worker (first-run defaults only)
tests/
  detectors.spec.mjs      # Node VM sandbox — mirrors manifest load order
```

## Adding a detector

Each detector is a self-contained IIFE file that calls `window.SG_DETECTORS.register()`. The registry runs them all in order; `index.js` gathers and deduplicates results.

### 1. Create the file

Pick the right subfolder (`secrets/`, `pii/`, or `code/`) and add a new file. Use this template:

```js
(function(){
  // One-line description of what this matches.
  // Ref: https://link-to-docs-or-spec (if applicable)
  const rx = /your-pattern-here/g;
  const det = {
    name: 'detector_name',  // snake_case, unique across all detectors
    kind: 'api',            // one of: 'api' | 'pii' | 'code'
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'detector_name', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact(match) { return 'PREFIX_[REDACTED]'; }  // omit if generic [[REDACTED_*]] is fine
  };
  window.SG_DETECTORS.register(det);
})();
```

Rules:
- Use `matchAll` (not `exec` / `indexOf`) so multi-occurrence detection is correct.
- Return a flat array of match objects — one entry per occurrence.
- `severity` must be `'high'` or `'medium'`. Reserve `'low'` for future use.
- Prefer deterministic signatures (prefix + length + structure). Use entropy only as a fallback.
- Add a `redact()` function when a format-preserving replacement is possible (e.g., keep the recognizable prefix).

### 2. Register it in `manifest.json`

Add the script path inside `content_scripts[0].js` **before** `src/detectors/secrets/high-entropy.js` and `src/detectors/index.js`:

```json
"src/detectors/secrets/your-detector.js",
```

`high-entropy.js` must stay last among the detector files so specific patterns always take precedence over the catch-all.

### 3. Add tests

Open `tests/detectors.spec.mjs` and add the file to the loader array (same order as `manifest.json`), then write at least two test cases:

```js
// ✓ match
{ label: 'your_detector – match', text: 'your-synthetic-test-string', key: 'detector_name' },
// ✗ no match (false-positive guard)
{ label: 'your_detector – no match', text: 'innocuous-similar-string', key: null },
```

**Never use real secrets in tests.** Construct synthetic examples that pass structural checks (e.g., Luhn, Mod-97, length) but are clearly test values.

Run `npm test` before opening a PR. All tests must pass.

## UX guidelines

- Keep warning messages short and actionable.
- Always offer: **Mask & paste**, **Paste anyway** (hold-to-confirm), **Cancel**.
- Avoid blocking user workflows without a clear reason.

## Reporting security issues

Please follow `SECURITY.md` — no public issues for vulnerabilities; email first.
