const PRESETS = {
  ai: [
    'chat.openai.com: block',
    'claude.ai: block',
    'gemini.google.com: block',
    'copilot.microsoft.com: block',
    'perplexity.ai: block',
    'poe.com: block'
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

async function load(){
  const defaults = {
    allowlist: [], blockOn: {api:true, pii:true, code:true},
    orgMarkers: [], modeByHost: {}, bypass: { holdMs: 1200 }
  };
  const p = await chrome.storage.sync.get(defaults);
  document.getElementById('api').checked = p.blockOn.api;
  document.getElementById('pii').checked = p.blockOn.pii;
  document.getElementById('code').checked = p.blockOn.code;
  document.getElementById('allowlist').value = (p.allowlist||[]).join('\n');
  document.getElementById('orgMarkers').value = (p.orgMarkers||[]).join('\n');
  const hostLines = Object.entries(p.modeByHost||{}).map(([h,m])=>`${h}: ${m}`);
  document.getElementById('modeByHost').value = hostLines.join('\n');
  const holdMs = p.bypass?.holdMs ?? 1200;
  document.getElementById('holdMs').value = holdMs;
  document.getElementById('holdMs-label').textContent = holdMs;
}

async function save(){
  const blockOn = {
    api: document.getElementById('api').checked,
    pii: document.getElementById('pii').checked,
    code: document.getElementById('code').checked
  };
  const allowlist = document.getElementById('allowlist').value.split(/\n+/).map(s=>s.trim()).filter(Boolean);
  const orgMarkers = document.getElementById('orgMarkers').value.split(/\n+/).map(s=>s.trim()).filter(Boolean);
  const modeByHost = {};
  document.getElementById('modeByHost').value.split(/\n+/).forEach(line=>{
    const [h, ...rest] = line.split(':');
    if (h && rest.length) modeByHost[h.trim()] = rest.join(':').trim();
  });
  const holdMs = Number(document.getElementById('holdMs').value);
  const bypass = { allowed: true, holdMs, requireReason: false };
  await chrome.storage.sync.set({ blockOn, allowlist, orgMarkers, modeByHost, bypass });
  const s = document.getElementById('status'); s.textContent = 'Saved ✔'; setTimeout(()=> s.textContent='', 1200);
}

// Live label update for slider
document.getElementById('holdMs').addEventListener('input', e => {
  document.getElementById('holdMs-label').textContent = e.target.value;
});

// Preset buttons merge without overwriting unrelated entries
document.getElementById('preset-ai').addEventListener('click', () => mergePreset(PRESETS.ai));
document.getElementById('preset-docs').addEventListener('click', () => mergePreset(PRESETS.docs));
document.getElementById('preset-dev').addEventListener('click', () => mergePreset(PRESETS.dev));

document.getElementById('save').addEventListener('click', save);
load();
