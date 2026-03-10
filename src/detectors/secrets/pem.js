(function(){
  // PEM-encoded private keys (RSA, EC, OPENSSH, DSA, PKCS8).
  // Ref: https://www.rfc-editor.org/rfc/rfc7468
  const rx = /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]{40,}?-----END (?:[A-Z ]+ )?PRIVATE KEY-----/g;
  const det = {
    name: 'pem_private_key', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'pem_private_key', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact(match) {
      // Preserve the header and footer lines; redact the base64 body.
      const header = match.match(/-----BEGIN [^-]+-----/)?.[0] || '-----BEGIN PRIVATE KEY-----';
      const footer = match.match(/-----END [^-]+-----/)?.[0] || '-----END PRIVATE KEY-----';
      return `${header}\n[REDACTED]\n${footer}`;
    }
  };
  window.SG_DETECTORS.register(det);
})();
