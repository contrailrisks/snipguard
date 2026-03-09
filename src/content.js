// src/content.js
// SnipGuard content script — modular-detectors edition
// - Intercepts paste BEFORE text lands in inputs on AI sites
// - Runs modular detectors (window.SG.detectAll) on-device
// - Warns/blocks per policy; offers Mask & paste / Paste anyway / Cancel

/***** Site targeting (light heuristic; policy can override) *****/
const SG_TARGETS = [
  /chat\.openai\.com/,
  /claude\.ai/,
  /gemini\.google\.com|bard\.google\.com/,
  /copilot\.microsoft\.com/,
  /perplexity\.ai/,
  /poe\.com/
];
function sgIsTarget() { return SG_TARGETS.some(r => r.test(location.hostname)); }

/***** Policy loader (user sync + optional managed merge) *****/
let _policyCache = null;
let _policyCacheTs = 0;
const POLICY_TTL_MS = 5000;

async function sgGetPolicy() {
  const now = Date.now();
  if (_policyCache && now - _policyCacheTs < POLICY_TTL_MS) return _policyCache;

  // NOTE: managed policy merge will override user values when that feature lands.
  const defaults = {
    allowlist: [],
    blockOn: { api: true, pii: true, code: true },
    orgMarkers: [],
    modeByHost: {},               // host -> "block" | "warn" | "ignore"
    bypass: { allowed: true, holdMs: 1200, requireReason: false }
  };
  const user = await chrome.storage.sync.get(defaults);
  // If chrome.storage.managed is available, merge it (admin overrides).
  let policy;
  try {
    // Not all channels expose storage.managed; swallow errors.
    const managed = (chrome.storage && chrome.storage.managed)
      ? await chrome.storage.managed.get({})
      : {};
    policy = Object.assign({}, defaults, user, managed);
  } catch {
    policy = Object.assign({}, defaults, user);
  }

  _policyCache = policy;
  _policyCacheTs = now;
  return policy;
}

/***** Active element & insertion helpers (inputs, CE, shadow DOM) *****/
function sgActiveEditable() {
  // Try current focus
  let el = document.activeElement;
  // Traverse into open shadow roots if focus is inside one
  try {
    while (el && el.shadowRoot && el.shadowRoot.activeElement) {
      el = el.shadowRoot.activeElement;
    }
  } catch (_) {}
  if (!el) return null;

  // input/textarea
  if (/^(textarea|input)$/i.test(el.tagName) && !el.readOnly && !el.disabled) return el;

  // contentEditable
  if (el.isContentEditable) return el;

  // Search common editors by attribute if nothing focused (rare)
  const fallback = document.querySelector('[contenteditable=""],[contenteditable="true"],textarea,input[type="text"]');
  return fallback || null;
}

function sgInsertText(el, txt) {
  if (!el) return;
  if (el.isContentEditable) {
    // Use execCommand for broad CE support (Monaco/ProseMirror often listen to input)
    el.focus();
    document.execCommand('insertText', false, txt);
    // Fire an input event for frameworks that rely on it
    el.dispatchEvent(new InputEvent('input', { bubbles: true }));
    return;
  }
  if (/^(textarea|input)$/i.test(el.tagName)) {
    const start = el.selectionStart ?? el.value.length;
    const end = el.selectionEnd ?? el.value.length;
    const before = el.value.slice(0, start), after = el.value.slice(end);
    el.value = before + txt + after;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.selectionStart = el.selectionEnd = start + txt.length;
    return;
  }
  // Fallback: append to body (unlikely)
  const ta = document.createElement('textarea');
  ta.value = txt;
  document.body.appendChild(ta);
  ta.select();
}

/***** Risk evaluation & summary *****/
function sgSummarizeDetections(detections) {
  const counts = {
    api: detections.filter(d => d.type === 'api').length,
    pii: detections.filter(d => d.type === 'pii').length,
    code: detections.filter(d => d.type === 'code').length
  };
  const parts = [];
  if (counts.api)  parts.push(`${counts.api} API key${counts.api  > 1 ? 's' : ''}`);
  if (counts.pii)  parts.push(`${counts.pii} PII item${counts.pii  > 1 ? 's' : ''}`);
  if (counts.code) parts.push(`${counts.code} code block${counts.code > 1 ? 's' : ''}`);
  const summary = `Detected: ${parts.join(', ')}. Click title to preview sanitized output.`;
  return { counts, summary };
}

/***** Chunked paste heuristic (combine multiple pastes within 10s) *****/
const SG_RECENT = { buf: '', ts: 0 };
function sgAccumulateRecent(text) {
  const now = Date.now();
  if (now - SG_RECENT.ts < 10000) {
    SG_RECENT.buf += ' ' + text;
  } else {
    SG_RECENT.buf = text;
  }
  SG_RECENT.ts = now;
  return SG_RECENT.buf;
}

/***** Main paste handler *****/
async function sgHandlePaste(e) {
  const clipboardText = (e.clipboardData || window.clipboardData)?.getData('text') || '';
  if (!clipboardText) return;

  const policy = await sgGetPolicy();
  const host = location.hostname;

  // Allowlist short-circuit
  if ((policy.allowlist || []).some(dom => host === dom || host.endsWith('.' + dom))) return;

  // Site mode: block/warn/ignore
  const hostMode = (policy.modeByHost && policy.modeByHost[host])
    || (sgIsTarget() ? 'block' : 'warn');

  // Run detectors
  const recent = sgAccumulateRecent(clipboardText);
  const detections = window.SG.detectAll(clipboardText, { orgMarkers: policy.orgMarkers });
  // If single paste looks clean, also check recent buffer for chunked secrets.
  // Use buffer detections only to determine risk — sanitize always uses detections
  // from the current paste so indices and match strings remain consistent.
  const bufferDetections = detections.length ? detections : window.SG.detectAll(recent, { orgMarkers: policy.orgMarkers });

  const { counts, summary } = sgSummarizeDetections(bufferDetections);

  const hasRisk =
    (policy.blockOn.api && counts.api) ||
    (policy.blockOn.pii && counts.pii) ||
    (policy.blockOn.code && counts.code);

  if (!hasRisk) return;

  // Intercept the paste; we’ll decide what to insert
  e.stopPropagation(); e.preventDefault();

  const el = sgActiveEditable();
  // Always sanitize against the current paste text using its own detections.
  const sanitized = window.SG.sanitize(clipboardText, detections);

  if (hostMode === 'ignore') {
    sgInsertText(el, clipboardText);
    return;
  }

  // Show toast with actions
  window.SG_UI.toast({
    summary,
    detail: sanitized,
    onSanitize: () => sgInsertText(el, sanitized),
    onProceed: () => sgInsertText(el, clipboardText)
  });
}

/***** Drag & drop: scan text-like files dropped into editors *****/
async function sgHandleDrop(e) {
  const el = sgActiveEditable();
  if (!el) return;

  const dt = e.dataTransfer;
  if (!dt || !dt.files || !dt.files.length) return;

  const file = dt.files[0];
  const name = (file.name || '').toLowerCase();
  const isTextyExt = /\.(txt|log|md|json|yaml|yml|env|py|js|ts|java|go|rb|rs|cs|sql|sh)$/i.test(name);
  const isTextType = !!file.type && file.type.startsWith('text/');
  if (!isTextyExt && !isTextType) return; // allow images/zips to pass

  // We’ll handle the drop (to avoid uploading secrets)
  e.stopPropagation(); e.preventDefault();

  const text = await file.text();
  const policy = await sgGetPolicy();
  const detections = window.SG.detectAll(text, { orgMarkers: policy.orgMarkers });
  if (!detections.length) {
    sgInsertText(el, text);
    return;
  }

  const { counts, summary } = sgSummarizeDetections(detections);
  const sanitized = window.SG.sanitize(text, detections);
  window.SG_UI.toast({
    summary: `File "${name}" flagged: ${counts.api} API, ${counts.pii} PII, ${counts.code} code.`,
    detail: sanitized,
    onSanitize: () => sgInsertText(el, sanitized),
    onProceed: () => sgInsertText(el, text)
  });
}

/***** Intercept <input type="file"> for text-like uploads (block with warning) *****/
async function sgHandleFileInput(e) {
  const t = e.target;
  if (!(t instanceof HTMLInputElement) || t.type !== 'file' || !t.files?.[0]) return;
  const f = t.files[0];
  const name = (f.name || '').toLowerCase();
  const isTextyExt = /\.(txt|log|md|json|yaml|yml|env)$/i.test(name);
  const isTextType = !!f.type && f.type.startsWith('text/');
  if (!isTextyExt && !isTextType) return;

  const text = await f.text();
  const policy = await sgGetPolicy();
  const detections = window.SG.detectAll(text, { orgMarkers: policy.orgMarkers });
  if (!detections.length) return;

  // Block upload by clearing selection and show warning
  t.value = '';
  const { counts } = sgSummarizeDetections(detections);
  const sanitized = window.SG.sanitize(text, detections);
  window.SG_UI.toast({
    summary: `Upload blocked: found ${counts.api} API, ${counts.pii} PII, ${counts.code} code in "${name}".`,
    detail: sanitized,
    onSanitize: null,
    onProceed: null
  });
}

/***** Wiring *****/
document.addEventListener('paste', sgHandlePaste, true);
document.addEventListener('drop', sgHandleDrop, true);
document.addEventListener('change', sgHandleFileInput, true);

// Invalidate policy cache immediately when the user changes settings,
// so the new policy takes effect on the very next paste rather than
// waiting out the TTL.
chrome.storage.onChanged.addListener(() => { _policyCache = null; });

// Optional keyboard bypass (Alt+V) — feature-flagged when we add options
// document.addEventListener('keydown', (e) => {
//   if (e.altKey && (e.key === 'v' || e.key === 'V')) {
//     // set a short-lived "bypass once" flag if policy allows
//   }
// }, true);
