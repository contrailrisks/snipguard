(function(){
  // Discord bot tokens: base64(user_id).timestamp_hmac.signature
  // Ref: https://discord.com/developers/docs/reference#authentication
  const rx = /\b[MNO][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b/g;
  const det = {
    name: 'discord', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'discord', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact(match) {
      // Preserve the user-id segment (before the first dot); redact the rest.
      const dot = match.indexOf('.');
      return (dot > -1 ? match.slice(0, dot) : match.slice(0, 8)) + '.[REDACTED]';
    }
  };
  window.SG_DETECTORS.register(det);
})();
