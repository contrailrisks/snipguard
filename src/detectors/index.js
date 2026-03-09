(function(){
  const { escapeForRx } = window.SG_CORE;

  function detectAll(text, cfg) {
    const enabled = new Set((cfg && cfg.enabled) || window.SG_DETECTORS.list.map(d => d.name));
    (cfg && cfg.disabled || []).forEach(n => enabled.delete(n));
    const out = [];
    for (const d of window.SG_DETECTORS.list) {
      if (!enabled.has(d.name)) continue;
      out.push(...d.test(text, cfg));
    }
    return out;
  }

  function sanitize(text, detections) {
    let out = text;
    for (const det of detections) {
      const d = window.SG_DETECTORS.list.find(x => x.name === det.key);
      const replacement = (d && d.redact) ? d.redact(det.match) : `[[REDACTED_${det.key.toUpperCase()}]]`;
      out = out.replace(new RegExp(escapeForRx(det.match), 'g'), replacement);
    }
    return out;
  }

  window.SG = Object.assign(window.SG || {}, { detectAll, sanitize });
})();
