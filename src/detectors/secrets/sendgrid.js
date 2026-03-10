(function(){
  // SendGrid API keys: SG. + 22-char key ID + . + 43-char secret.
  // Ref: https://docs.sendgrid.com/ui/account-and-settings/api-keys
  const rx = /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g;
  const det = {
    name: 'sendgrid', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'sendgrid', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact(match) {
      // Preserve the key ID segment; redact the secret segment.
      return match.replace(/(\.[A-Za-z0-9_-]{22})\.[A-Za-z0-9_-]{43}$/, '$1.[REDACTED]');
    }
  };
  window.SG_DETECTORS.register(det);
})();
