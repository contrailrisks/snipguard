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
    bypass: { allowed: true, holdMs: 1200, requireReason: false, altPaste: false }
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
  // Traverse active element through open shadow roots (handles nested shadow DOM)
  let el = document.activeElement;
  try {
    while (el && el.shadowRoot && el.shadowRoot.activeElement) {
      el = el.shadowRoot.activeElement;
    }
  } catch (_) {}
  if (!el) return null;

  // Plain input / textarea
  if (/^(textarea|input)$/i.test(el.tagName) && !el.readOnly && !el.disabled) return el;

  // ContentEditable (ProseMirror, Quill, Tiptap, CodeMirror 6, etc.)
  if (el.isContentEditable) return el;

  // ARIA textbox (some rich editors mark the root with role="textbox")
  if (el.getAttribute?.('role') === 'textbox') return el;

  // Monaco editor: its .inputarea textarea receives clipboard events but its
  // value is managed internally — fall through to the execCommand path below.
  const monacoInput = document.querySelector('.monaco-editor .inputarea');
  if (monacoInput && !monacoInput.readOnly && !monacoInput.disabled) return monacoInput;

  // Generic fallback: first visible editable element in the document
  const fallback = document.querySelector(
    '[contenteditable=""],[contenteditable="true"],[role="textbox"],textarea,input[type="text"]'
  );
  return fallback || null;
}

function sgInsertText(el, txt) {
  if (!el) return;

  // Monaco's .inputarea is a <textarea> but its content is model-driven.
  // execCommand('insertText') is the only reliable way to feed text into it.
  const isMonaco = !!el.closest?.('.monaco-editor');

  if (el.isContentEditable || isMonaco || el.getAttribute?.('role') === 'textbox') {
    el.focus();
    // execCommand works for ProseMirror, Quill, Tiptap, CodeMirror 6, and Monaco.
    document.execCommand('insertText', false, txt);
    el.dispatchEvent(new InputEvent('input', { bubbles: true, data: txt }));
    return;
  }
  if (/^(textarea|input)$/i.test(el.tagName)) {
    // Standard textarea / input: direct value manipulation
    const start = el.selectionStart ?? el.value.length;
    const end = el.selectionEnd ?? el.value.length;
    const before = el.value.slice(0, start), after = el.value.slice(end);
    el.value = before + txt + after;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.selectionStart = el.selectionEnd = start + txt.length;
    return;
  }
  // Last resort: synthesise a clipboard event targeted at the active element
  const dt = new DataTransfer();
  dt.setData('text/plain', txt);
  (el || document.body).dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true }));
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

/***** Alt+V one-shot bypass *****/
let _altBypassArmed = false;
let _altBypassTimer = null;

function sgArmAltBypass() {
  _altBypassArmed = true;
  clearTimeout(_altBypassTimer);
  // Expire after 5 s if no paste follows
  _altBypassTimer = setTimeout(() => { _altBypassArmed = false; }, 5000);
}

/***** Main paste handler *****/
async function sgHandlePaste(e) {
  const clipboardText = (e.clipboardData || window.clipboardData)?.getData('text') || '';
  if (!clipboardText) return;

  // Alt+V bypass: consume the flag and allow this paste through unchanged
  if (_altBypassArmed) {
    _altBypassArmed = false;
    clearTimeout(_altBypassTimer);
    return;
  }

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
    holdMs: policy.bypass?.holdMs ?? 1200,
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
    holdMs: policy.bypass?.holdMs ?? 1200,
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

// Alt+V one-shot bypass — only active when bypass.altPaste is enabled in policy.
document.addEventListener('keydown', async (e) => {
  if (!e.altKey || (e.key !== 'v' && e.key !== 'V')) return;
  const policy = await sgGetPolicy();
  if (policy.bypass?.altPaste) sgArmAltBypass();
}, true);
