(function(){
  // Generic catch-all for high-entropy strings that don't match any known
  // provider pattern (unknown API keys, bearer tokens, random secrets, etc.).
  // Loaded last so specific detectors always take precedence.
  const { shannonH } = window.SG_CORE;
  const rx = /[A-Za-z0-9+/=_-]{32,}/g;
  const det = {
    name: 'high_entropy', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx)) {
        if (shannonH(m[0]) > 3.2)
          out.push({ type: 'api', key: 'high_entropy', match: m[0], index: m.index ?? 0, severity: 'medium' });
      }
      return out;
    },
    redact() { return '[[REDACTED_HIGH_ENTROPY]]'; }
  };
  window.SG_DETECTORS.register(det);
})();
