(function(){
  // Firebase / Google API keys share the AIza prefix + 35 base64url chars.
  // Ref: https://firebase.google.com/docs/projects/api-keys
  const rx = /AIza[0-9A-Za-z_-]{35}/g;
  const det = {
    name: 'firebase', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'firebase', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact() { return 'AIza[REDACTED]'; }
  };
  window.SG_DETECTORS.register(det);
})();
