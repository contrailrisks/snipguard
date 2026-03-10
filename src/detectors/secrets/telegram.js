(function(){
  // Telegram bot tokens: <bot_id>:<random_token>
  // Ref: https://core.telegram.org/bots/api#authorizing-your-bot
  const rx = /\b(\d{8,10}):([A-Za-z0-9_-]{35})\b/g;
  const det = {
    name: 'telegram_bot', kind: 'api',
    test(text) {
      const out = [];
      for (const m of text.matchAll(rx))
        out.push({ type: 'api', key: 'telegram_bot', match: m[0], index: m.index ?? 0, severity: 'high' });
      return out;
    },
    redact(match) {
      // Preserve the bot ID segment (non-sensitive); redact the token.
      const colon = match.indexOf(':');
      return (colon > -1 ? match.slice(0, colon) : match) + ':[REDACTED]';
    }
  };
  window.SG_DETECTORS.register(det);
})();
