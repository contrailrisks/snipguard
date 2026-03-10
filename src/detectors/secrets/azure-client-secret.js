(function(){
  // Azure AD / Entra ID application client secrets (env-var name–scoped to reduce FPs).
  // Ref: https://learn.microsoft.com/entra/identity-platform/how-to-add-credentials
  const rx = /(?:AZURE_CLIENT_SECRET|AZURE_CLIENT_KEY)\s*[:=]\s*['"]?([A-Za-z0-9._~+\-/]{16,})['"]?/gi;
  const det = {
    name: 'azure_client_secret', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'azure_client_secret', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact(match) {
      return match.replace(/([:=]\s*['"]?)[A-Za-z0-9._~+\-/]{16,}(['"]?)$/, '$1[REDACTED]$2');
    }
  };
  window.SG_DETECTORS.register(det);
})();
