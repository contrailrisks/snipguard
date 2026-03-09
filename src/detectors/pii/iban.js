(function(){
  // International Bank Account Numbers — Mod-97 checksum validation.
  // Ref: https://www.iso13616.org/
  const rx = /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g;
  const { ibanOk } = window.SG_CORE;
  const det = {
    name: 'iban', kind: 'pii',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx)) {
        if (ibanOk(m[0]))
          out.push({ type: 'pii', key: 'iban', match: m[0], index: m.index ?? 0, severity: 'medium' });
      }
      return out;
    },
    redact() { return '[[REDACTED_IBAN]]'; }
  };
  window.SG_DETECTORS.register(det);
})();
