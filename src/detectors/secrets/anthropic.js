(function(){
  // Anthropic API keys (Claude API).
  // Ref: https://docs.anthropic.com/en/api/getting-started
  const rx = /\bsk-ant-(?:api\d+-)?[A-Za-z0-9_-]{40,}\b/g;
  const det = {
    name: 'anthropic', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'anthropic', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact(match) {
      // Preserve version prefix (sk-ant-api03-) for auditability.
      const prefix = match.match(/^sk-ant-(?:api\d+-)?/)?.[0] || 'sk-ant-';
      return prefix + '[REDACTED]';
    }
  };
  window.SG_DETECTORS.register(det);
})();
