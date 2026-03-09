(function(){
  // Cloudflare API tokens (40-char base64url) and Global API Keys (37 hex chars).
  // Context-scoped: only matches when paired with a known env-var name to avoid
  // false positives on arbitrary 40-char strings.
  // Ref: https://developers.cloudflare.com/fundamentals/api/get-started/create-token/
  const rx = /(?:CF_API_TOKEN|CLOUDFLARE_API_TOKEN|CLOUDFLARE_GLOBAL_API_KEY)\s*[=:]\s*['"]?([0-9a-f]{37}|[A-Za-z0-9_-]{40})['"]?/gi;
  const det = {
    name: 'cloudflare', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'cloudflare', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact(match) {
      return match.replace(/([=:\s]+['"]?)([0-9a-f]{37}|[A-Za-z0-9_-]{40})(['"]?)$/, '$1[REDACTED]$3');
    }
  };
  window.SG_DETECTORS.register(det);
})();
