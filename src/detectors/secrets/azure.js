(function(){
  // Azure Storage account connection strings.
  // Ref: https://learn.microsoft.com/azure/storage/common/storage-configure-connection-string
  const rx = /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}[^;\s]*/gi;
  const det = {
    name: 'azure_storage', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'azure_storage', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact(match) { return match.replace(/(AccountKey=)[^;]+/, '$1[REDACTED]'); }
  };
  window.SG_DETECTORS.register(det);
})();
