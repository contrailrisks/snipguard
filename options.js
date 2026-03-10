/* SnipGuard Options — settings, custom patterns (#27), detection playground (#24) */

const PRESETS = {
  ai: [
    'chat.openai.com: block',
    'claude.ai: block',
    'gemini.google.com: block',
    'copilot.microsoft.com: block',
    'perplexity.ai: block',
    'poe.com: block',
    // #26 — expanded AI sites
    'chat.mistral.ai: block',
    'groq.com: block',
    'together.ai: block',
    'coral.cohere.com: block',
    'replicate.com: block',
    'aistudio.google.com: block',
    'phind.com: block',
    'kagi.com: block',
    'grok.com: block'
  ],
  docs: [
    'readthedocs.io: warn',
    'developer.mozilla.org: warn',
    'stackoverflow.com: warn',
    'docs.github.com: warn'
  ],
  dev: [
    'localhost: ignore',
    '127.0.0.1: ignore'
  ]
};

function mergePreset(lines) {
  const existing = document.getElementById('modeByHost').value
    .split(/\n+/).map(s => s.trim()).filter(Boolean);
  const map = {};
  [...existing, ...lines].forEach(line => {
    const [h, ...rest] = line.split(':');
    if (h && rest.length) map[h.trim()] = rest.join(':').trim();
  });
  document.getElementById('modeByHost').value =
    Object.entries(map).map(([h, m]) => `${h}: ${m}`).join('\n');
}

/***** Custom patterns rendering & management (#27) *****/
let _customPatterns = [];

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderCustomPatterns(patterns) {
  _customPatterns = patterns;
  const empty = document.getElementById('cp-empty');
  const table = document.getElementById('cp-table');
  const body  = document.getElementById('cp-body');

  if (!patterns.length) {
    empty.style.display = '';
    table.style.display = 'none';
    return;
  }
  empty.style.display = 'none';
  table.style.display = '';

  body.innerHTML = patterns.map((p, i) => `
    <tr>
      <td>${esc(p.name)}</td>
      <td><code>${esc(p.regex)}</code></td>
      <td><code>${esc(p.redactPrefix || '')}</code></td>
      <td>
        <input type="checkbox" data-idx="${i}" class="cp-toggle"
          ${p.enabled !== false ? 'checked' : ''}>
      </td>
      <td>
        <button class="danger-btn cp-del" data-idx="${i}">Delete</button>
      </td>
    </tr>
  `).join('');

  // Toggle enabled
  body.querySelectorAll('.cp-toggle').forEach(cb => {
    cb.addEventListener('change', async () => {
      const idx = Number(cb.dataset.idx);
      _customPatterns[idx].enabled = cb.checked;
      await chrome.storage.sync.set({ customPatterns: _customPatterns });
    });
  });

  // Delete
  body.querySelectorAll('.cp-del').forEach(btn => {
    btn.addEventListener('click', async () => {
      const idx = Number(btn.dataset.idx);
      _customPatterns.splice(idx, 1);
      await chrome.storage.sync.set({ customPatterns: _customPatterns });
      renderCustomPatterns(_customPatterns);
    });
  });
}

// Add pattern button
document.getElementById('cp-add').addEventListener('click', async () => {
  const nameEl  = document.getElementById('cp-name');
  const regexEl = document.getElementById('cp-regex');
  const prefEl  = document.getElementById('cp-prefix');
  const errEl   = document.getElementById('cp-error');

  const name  = nameEl.value.trim();
  const regex = regexEl.value.trim();
  const redactPrefix = prefEl.value.trim();

  errEl.style.display = 'none';
  if (!name) { errEl.textContent = 'Name is required.'; errEl.style.display = ''; return; }
  if (!regex) { errEl.textContent = 'Regex is required.'; errEl.style.display = ''; return; }
  try { new RegExp(regex); } catch (ex) {
    errEl.textContent = `Invalid regex: ${ex.message}`;
    errEl.style.display = '';
    return;
  }

  const newPattern = { name, regex, redactPrefix, enabled: true };
  const { customPatterns = [] } = await chrome.storage.sync.get({ customPatterns: [] });
  customPatterns.push(newPattern);
  await chrome.storage.sync.set({ customPatterns });
  renderCustomPatterns(customPatterns);
  nameEl.value = ''; regexEl.value = ''; prefEl.value = '';
});

/***** Load & Save *****/
async function load() {
  const defaults = {
    allowlist: [], blockOn: { api: true, pii: true, code: true },
    orgMarkers: [], modeByHost: {},
    bypass: { holdMs: 1200, altPaste: false },
    customPatterns: []
  };
  const p = await chrome.storage.sync.get(defaults);
  document.getElementById('api').checked  = p.blockOn.api;
  document.getElementById('pii').checked  = p.blockOn.pii;
  document.getElementById('code').checked = p.blockOn.code;
  document.getElementById('allowlist').value   = (p.allowlist  || []).join('\n');
  document.getElementById('orgMarkers').value  = (p.orgMarkers || []).join('\n');
  const hostLines = Object.entries(p.modeByHost || {}).map(([h, m]) => `${h}: ${m}`);
  document.getElementById('modeByHost').value  = hostLines.join('\n');
  const holdMs = p.bypass?.holdMs ?? 1200;
  document.getElementById('holdMs').value = holdMs;
  document.getElementById('holdMs-label').textContent = holdMs;
  document.getElementById('altPaste').checked = p.bypass?.altPaste ?? false;
  renderCustomPatterns(p.customPatterns || []);
}

async function save() {
  const blockOn = {
    api:  document.getElementById('api').checked,
    pii:  document.getElementById('pii').checked,
    code: document.getElementById('code').checked
  };
  const allowlist = document.getElementById('allowlist').value
    .split(/\n+/).map(s => s.trim()).filter(Boolean);
  const orgMarkers = document.getElementById('orgMarkers').value
    .split(/\n+/).map(s => s.trim()).filter(Boolean);
  const modeByHost = {};
  document.getElementById('modeByHost').value.split(/\n+/).forEach(line => {
    const [h, ...rest] = line.split(':');
    if (h && rest.length) modeByHost[h.trim()] = rest.join(':').trim();
  });
  const holdMs   = Number(document.getElementById('holdMs').value);
  const altPaste = document.getElementById('altPaste').checked;
  const bypass   = { allowed: true, holdMs, requireReason: false, altPaste };
  await chrome.storage.sync.set({ blockOn, allowlist, orgMarkers, modeByHost, bypass });
  const s = document.getElementById('status');
  s.textContent = 'Saved ✔';
  setTimeout(() => { s.textContent = ''; }, 1200);
}

/***** Slider live label *****/
document.getElementById('holdMs').addEventListener('input', e => {
  document.getElementById('holdMs-label').textContent = e.target.value;
});

/***** Preset buttons *****/
document.getElementById('preset-ai').addEventListener('click',   () => mergePreset(PRESETS.ai));
document.getElementById('preset-docs').addEventListener('click', () => mergePreset(PRESETS.docs));
document.getElementById('preset-dev').addEventListener('click',  () => mergePreset(PRESETS.dev));

document.getElementById('save').addEventListener('click', save);

/***** Detection playground (#24) *****/
let _pgTimer = null;
document.getElementById('playground').addEventListener('input', () => {
  clearTimeout(_pgTimer);
  _pgTimer = setTimeout(runPlayground, 200);
});

function runPlayground() {
  const text    = document.getElementById('playground').value;
  const results = document.getElementById('playground-results');
  if (!text.trim()) { results.innerHTML = ''; return; }

  // window.SG is available because all detector scripts are loaded before options.js
  const detections = window.SG.detectAll(text, {});
  if (!detections.length) {
    results.innerHTML = '<span class="pg-clean">✓ No sensitive content detected.</span>';
    return;
  }

  const sanitized = window.SG.sanitize(text, detections);
  const html = detections.map(d => {
    const sev = d.severity || 'medium';
    return `<div class="pg-hit ${sev}">
      <strong>${esc(d.key || d.type)}</strong>
      &nbsp;·&nbsp;<span style="font-size:12px;color:#6b7280">${sev}</span>
      &nbsp;·&nbsp;<code>${esc(d.match.slice(0, 60))}${d.match.length > 60 ? '…' : ''}</code>
    </div>`;
  }).join('');

  results.innerHTML = html + `
    <details style="margin-top:8px;font-size:12px">
      <summary style="cursor:pointer;color:#374151">Sanitized preview</summary>
      <pre style="background:#f3f4f6;padding:8px;border-radius:4px;white-space:pre-wrap;margin-top:4px">${esc(sanitized)}</pre>
    </details>`;
}

load();
