(function(){
  // Twilio API Key SIDs (SK…) — distinct from Account SIDs (AC…).
  // Ref: https://www.twilio.com/docs/iam/api-keys
  const rx = /\bSK[0-9a-f]{32}\b/g;
  const det = {
    name: 'twilio', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'twilio', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact() { return 'SK[REDACTED]'; }
  };
  window.SG_DETECTORS.register(det);
})();
