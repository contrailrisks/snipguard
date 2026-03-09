(function(){
  // PostgreSQL / libpq connection URIs with embedded credentials.
  // Ref: https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING-URIS
  const rx = /postgres(?:ql)?:\/\/[^:@\s]+:[^@\s]+@[^\s/'"]+/gi;
  const det = {
    name: 'postgres_url', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'postgres_url', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact(match) {
      return match.replace(/(postgres(?:ql)?:\/\/[^:]+:)[^@]+(@)/, '$1[REDACTED]$2');
    }
  };
  window.SG_DETECTORS.register(det);
})();
