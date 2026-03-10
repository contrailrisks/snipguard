(function(){
  // Azure SQL / Azure Database connection strings with embedded credentials.
  // Ref: https://learn.microsoft.com/azure/azure-sql/database/connect-query-content-reference-guide
  const rx = /Server=tcp:[A-Za-z0-9.\-]+(?:,\d+)?;[^;]*Database=[A-Za-z0-9_\-]+;[^;]*(?:User ID|Uid)=[^;]+;[^;]*Password=[^;]+;/gi;
  const det = {
    name: 'azure_sql', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'azure_sql', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact(match) {
      return match.replace(/(Password=)[^;]+/, '$1[REDACTED]');
    }
  };
  window.SG_DETECTORS.register(det);
})();
