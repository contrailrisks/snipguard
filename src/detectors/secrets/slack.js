(function(){
  // Slack bot / user / app tokens (xox* family).
  // Ref: https://api.slack.com/authentication/token-types
  const tokenRx = /\bxox[bpas]-[0-9A-Za-z-]{10,}\b/g;
  const tokenDet = {
    name: 'slack_token', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(tokenRx))
        out.push({ type: 'api', key: 'slack_token', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact(match) {
      const prefix = match.slice(0, 5); // e.g. "xoxb-"
      return prefix + '[REDACTED]';
    }
  };

  // Slack incoming webhook URLs.
  // Ref: https://api.slack.com/messaging/webhooks
  const webhookRx = /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g;
  const webhookDet = {
    name: 'slack_webhook', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(webhookRx))
        out.push({ type: 'api', key: 'slack_webhook', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact(match) {
      // Keep the workspace portion (T…/B…) and redact the signing secret.
      return match.replace(/\/[A-Za-z0-9]+$/, '/[REDACTED]');
    }
  };

  window.SG_DETECTORS.register(tokenDet);
  window.SG_DETECTORS.register(webhookDet);
})();
