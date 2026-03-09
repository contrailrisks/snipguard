(function(){
  // AWS IAM access key IDs.
  // Ref: https://docs.aws.amazon.com/IAM/latest/UserGuide/security-creds.html
  const rx = /AKIA[0-9A-Z]{16}/g;
  const det = {
    name: 'aws_akid', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'aws_akid', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact() { return 'AKIA[REDACTED]'; }
  };
  window.SG_DETECTORS.register(det);
})();
