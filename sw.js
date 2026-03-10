// SnipGuard service worker: manages default policy, upgrades, and badge counter.

chrome.runtime.onInstalled.addListener(async () => {
  const defaults = {
    allowlist: [],
    blockOn: { api: true, pii: true, code: true },
    orgMarkers: [],
    modeByHost: {} // e.g., {"chat.openai.com": "block"|"warn"|"ignore"}
  };
  const current = await chrome.storage.sync.get(null);
  if (!current || Object.keys(current).length === 0) {
    await chrome.storage.sync.set(defaults);
  }
  // Pre-set badge style so the colour is right on first intercept.
  chrome.action.setBadgeBackgroundColor({ color: '#EF4444' });
});

/***** Badge counter (#25) *****/
// In-memory only; resets naturally when the service worker restarts (i.e. new session).
let _interceptCount = 0;

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type !== 'SG_INTERCEPT') return;
  _interceptCount += 1;
  chrome.action.setBadgeText({ text: String(_interceptCount) });
  chrome.action.setBadgeBackgroundColor({ color: '#EF4444' });
});
