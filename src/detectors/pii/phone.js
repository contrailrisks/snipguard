(function(){
  // Require either E.164 international format (+country code + min 8 digits)
  // or a formatted number with separators (e.g. (555) 123-4567).
  // Plain unformatted digit strings (order IDs, timestamps) will not match.
  const rx = /(?:\+[1-9]\d{8,13}|\b\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4})\b/g;
  const det = {
    name:'phone', kind:'pii',
    test(text){ const out=[]; for (const m of text.matchAll(rx)) out.push({type:'pii', key:'phone', match:m[0], index:m.index??0, severity:'low'}); return out; },
    redact(){ return '[[REDACTED_PHONE]]'; }
  };
  window.SG_DETECTORS.register(det);
})();
