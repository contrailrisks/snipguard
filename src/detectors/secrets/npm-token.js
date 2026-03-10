(function(){
  // npm automation / publish tokens.
  // Ref: https://docs.npmjs.com/creating-and-viewing-access-tokens
  const rx = /\bnpm_[A-Za-z0-9]{36}\b/g;
  const det = {
    name: 'npm_token', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'npm_token', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact() { return 'npm_[REDACTED]'; }
  };
  window.SG_DETECTORS.register(det);
})();
