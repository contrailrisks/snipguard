(function(){
  // Stripe secret API keys (test and live).
  // Ref: https://stripe.com/docs/keys
  const rx = /sk_(?:test|live)_[A-Za-z0-9]{20,}/g;
  const det = {
    name: 'stripe', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'stripe', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact(match) {
      const prefix = (match.match(/^sk_(?:test|live)_/i) || [])[0] || 'sk_';
      return prefix + '[REDACTED]';
    }
  };
  window.SG_DETECTORS.register(det);
})();
