(function(){
  // GitHub fine-grained personal access tokens.
  // Ref: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
  const rx = /github_pat_[A-Za-z0-9_]{80,}/g;
  const det = {
    name: 'github', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'github', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact() { return 'github_pat_[REDACTED]'; }
  };
  window.SG_DETECTORS.register(det);
})();
