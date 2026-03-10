(function(){
  // Google / Firebase OAuth 2.0 short-lived access tokens (ya29. prefix).
  // Ref: https://developers.google.com/identity/protocols/oauth2
  const rx = /\bya29\.[A-Za-z0-9_-]{20,}\b/g;
  const det = {
    name: 'google_oauth', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'google_oauth', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact() { return 'ya29.[REDACTED]'; }
  };
  window.SG_DETECTORS.register(det);
})();
