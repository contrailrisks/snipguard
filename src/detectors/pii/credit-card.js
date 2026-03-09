(function(){
  // Credit/debit card numbers (13–19 digits, with optional spaces or dashes).
  // Luhn checksum validation reduces false positives.
  const rx = /\b(?:\d[ -]*?){13,19}\b/g;
  const { luhnOk } = window.SG_CORE;
  const det = {
    name: 'credit_card', kind: 'pii',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx)) {
        const raw = m[0].replace(/\D/g, '');
        if (luhnOk(raw))
          out.push({ type: 'pii', key: 'credit_card', match: m[0], index: m.index ?? 0, severity: 'high' });
      }
      return out;
    },
    redact(match) {
      const digits = match.replace(/\D/g, '');
      return `[[REDACTED_CREDIT_CARD_${digits.slice(0, 6)}...${digits.slice(-4)}]]`;
    }
  };
  window.SG_DETECTORS.register(det);
})();
