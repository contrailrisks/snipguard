(function(){
  // Email addresses (RFC 5321 simplified).
  const rx = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
  const det = {
    name: 'email', kind: 'pii',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'pii', key: 'email', match: m[0], index: m.index ?? 0, severity: 'medium' });
      return out;
    },
    redact(match) {
      // Preserve domain so context is retained; hide local part for privacy.
      const at = match.indexOf('@');
      return '[REDACTED]' + (at > -1 ? match.slice(at) : '@[REDACTED]');
    }
  };
  window.SG_DETECTORS.register(det);
})();
