(function(){
  // HuggingFace user access tokens and API keys.
  // Ref: https://huggingface.co/docs/hub/security-tokens
  const rx = /\bhf_[A-Za-z0-9]{34,}\b/g;
  const det = {
    name: 'huggingface', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'huggingface', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact() { return 'hf_[REDACTED]'; }
  };
  window.SG_DETECTORS.register(det);
})();
