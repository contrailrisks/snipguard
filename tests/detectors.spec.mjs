import fs from 'fs';
import vm from 'vm';
import path from 'path';
import url from 'url';

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const srcDir = path.resolve(__dirname, '../src/detectors');

// Load modular detectors in manifest order into a shared sandbox
const sandbox = { window: {}, console };
vm.createContext(sandbox);

const detectorFiles = [
  'types.js',
  'core.js',
  'secrets/openai.js',
  'secrets/github.js',
  'secrets/aws.js',
  'secrets/stripe.js',
  'secrets/azure.js',
  'secrets/azure-sql.js',
  'secrets/azure-client-secret.js',
  'secrets/discord.js',
  'secrets/firebase.js',
  'secrets/google-oauth.js',
  'secrets/cloudflare.js',
  'secrets/postgres.js',
  'secrets/pem.js',
  'secrets/anthropic.js',
  'secrets/huggingface.js',
  'secrets/slack.js',
  'secrets/twilio.js',
  'secrets/telegram.js',
  'secrets/npm-token.js',
  'secrets/sendgrid.js',
  'pii/email.js',
  'pii/phone.js',
  'pii/credit-card.js',
  'pii/iban.js',
  'code/heuristic.js',
  'code/org-markers.js',
  'secrets/high-entropy.js',
  'index.js',
];

for (const f of detectorFiles) {
  const code = fs.readFileSync(path.join(srcDir, f), 'utf8');
  vm.runInContext(code, sandbox);
}

const { detectAll, sanitize } = sandbox.window.SG;

// ---------------------------------------------------------------------------
// API key detection — original providers
// ---------------------------------------------------------------------------
describe('API key detection', () => {
  it('detects OpenAI keys', () => {
    const t = 'here is my key sk-ABCDEFGHIJKLMNOPQRST123456';
    const r = detectAll(t, {});
    expect(r.some(d => d.type === 'api' && d.key === 'openai')).toBeTruthy();
  });

  it('detects Stripe test keys', () => {
    const t = 'sk_test_51H1234567890ABCDEFGHIJKLMNOP';
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'stripe')).toBeTruthy();
  });

  it('detects Stripe live keys', () => {
    // Constructed at runtime so static scanners don't flag the test file itself.
    const t = ['sk', 'live', 'FAKEKEYFAKEKEYFAKEKEYFAKE123'].join('_');
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'stripe')).toBeTruthy();
  });

  it('detects GitHub PAT', () => {
    const pat = 'github_pat_' + 'A'.repeat(82);
    const r = detectAll(pat, {});
    expect(r.some(d => d.key === 'github')).toBeTruthy();
  });

  it('detects AWS access key', () => {
    const t = 'AKIAIOSFODNN7EXAMPLE';
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'aws_akid')).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// API key detection — provider pack (#9)
// ---------------------------------------------------------------------------
describe('Provider pack detection', () => {
  it('detects Azure Storage connection string', () => {
    const t = 'DefaultEndpointsProtocol=https;AccountName=devstoreaccount1;AccountKey=' + 'A'.repeat(88) + '==';
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'azure_storage')).toBeTruthy();
  });

  it('redacts Azure AccountKey but preserves AccountName', () => {
    const t = 'DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=' + 'A'.repeat(88) + '==';
    const r = detectAll(t, {});
    const s = sanitize(t, r);
    expect(s.includes('myaccount')).toBeTruthy();
    expect(s.includes('AccountKey=[REDACTED]')).toBeTruthy();
  });

  it('detects Discord bot token', () => {
    // Format: [MNO] + 23 alphanum . 6 alphanum/dash . 27 alphanum/dash
    const t = 'M' + 'A'.repeat(23) + '.' + 'B'.repeat(6) + '.' + 'C'.repeat(27);
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'discord')).toBeTruthy();
  });

  it('detects Firebase/Google API key', () => {
    const t = 'apiKey: AIza' + 'A'.repeat(35);
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'firebase')).toBeTruthy();
  });

  it('detects Cloudflare API token via env var name', () => {
    const t = 'CF_API_TOKEN=' + 'a'.repeat(40);
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'cloudflare')).toBeTruthy();
  });

  it('does not flag arbitrary 40-char strings without Cloudflare context', () => {
    const t = 'some_random_value=' + 'a'.repeat(40);
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'cloudflare')).toBeFalsy();
  });

  it('detects Postgres URL with credentials', () => {
    const t = 'DATABASE_URL=postgres://admin:s3cr3tpassword@db.example.com:5432/mydb';
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'postgres_url')).toBeTruthy();
  });

  it('redacts Postgres password but preserves host', () => {
    const t = 'postgres://admin:s3cr3tpassword@db.example.com/mydb';
    const r = detectAll(t, {});
    const s = sanitize(t, r);
    expect(s.includes('s3cr3tpassword')).toBeFalsy();
    expect(s.includes('db.example.com')).toBeTruthy();
  });

  it('does not flag Postgres URL without credentials', () => {
    const t = 'postgres://db.example.com/mydb';
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'postgres_url')).toBeFalsy();
  });
});

// ---------------------------------------------------------------------------
// PII detection
// ---------------------------------------------------------------------------
describe('PII detection', () => {
  it('detects email', () => {
    const r = detectAll('contact me at alice@example.com', {});
    expect(r.some(d => d.key === 'email')).toBeTruthy();
  });

  it('detects international phone (+E.164)', () => {
    const r = detectAll('call me at +491234567890', {});
    expect(r.some(d => d.key === 'phone')).toBeTruthy();
  });

  it('detects formatted NA phone', () => {
    const r = detectAll('my number is (555) 123-4567', {});
    expect(r.some(d => d.key === 'phone')).toBeTruthy();
  });

  it('does not flag plain unformatted digit strings as phone', () => {
    const r = detectAll('order id 1234567890 tracking 9876543210', {});
    expect(r.some(d => d.key === 'phone')).toBeFalsy();
  });

  it('detects credit card with valid Luhn', () => {
    const r = detectAll('4111 1111 1111 1111', {});
    expect(r.some(d => d.key === 'credit_card')).toBeTruthy();
  });

  it('rejects credit card with invalid Luhn', () => {
    const r = detectAll('4111 1111 1111 1112', {});
    expect(r.some(d => d.key === 'credit_card')).toBeFalsy();
  });

  it('detects a valid IBAN', () => {
    // GB29 NWBK 6016 1331 9268 19 — real test IBAN, passes Mod-97
    const r = detectAll('pay to GB29NWBK60161331926819', {});
    expect(r.some(d => d.key === 'iban')).toBeTruthy();
  });

  it('rejects an IBAN with invalid checksum', () => {
    const r = detectAll('GB00NWBK60161331926819', {});
    expect(r.some(d => d.key === 'iban')).toBeFalsy();
  });
});

// ---------------------------------------------------------------------------
// Code heuristic
// ---------------------------------------------------------------------------
describe('Code heuristic', () => {
  it('flags actual code (function + enough lines)', () => {
    const code = Array(30).fill('x = 1;').join('\n') + '\nfunction foo() { return x; }';
    const r = detectAll(code, {});
    expect(r.some(d => d.type === 'code')).toBeTruthy();
  });

  it('does not flag prose that mentions "import" mid-sentence', () => {
    const prose = Array(30).fill('I want to import this concept from philosophy.').join('\n');
    const r = detectAll(prose, {});
    expect(r.some(d => d.type === 'code')).toBeFalsy();
  });
});

// ---------------------------------------------------------------------------
// Sanitization
// ---------------------------------------------------------------------------
describe('Sanitization', () => {
  it('redacts email address', () => {
    const t = 'email alice@example.com here';
    const r = detectAll(t, {});
    const s = sanitize(t, r);
    expect(s.includes('alice@example.com')).toBeFalsy();
  });

  it('redacts OpenAI key and preserves sk- prefix', () => {
    const key = 'sk-ABCDEFGHIJKLMNOPQRST123456';
    const t = `key is ${key}`;
    const r = detectAll(t, {});
    const s = sanitize(t, r);
    expect(s.includes(key)).toBeFalsy();
    expect(s.includes('sk-')).toBeTruthy();
  });

  it('output does not contain any original secrets', () => {
    const t = 'email a@b.co and key sk-ABCDEFGHIJKLMNOPQRST123456';
    const r = detectAll(t, {});
    const s = sanitize(t, r);
    expect(s.includes('a@b.co')).toBeFalsy();
    expect(s.includes('sk-ABCDEFGHIJKLMNOPQRST123456')).toBeFalsy();
  });

  it('email redaction preserves domain', () => {
    const t = 'contact alice@example.com for help';
    const r = detectAll(t, {});
    const s = sanitize(t, r);
    expect(s.includes('alice')).toBeFalsy();
    expect(s.includes('@example.com')).toBeTruthy();
  });

  it('IBAN redaction preserves country code and check digits', () => {
    const t = 'send to GB29NWBK60161331926819';
    const r = detectAll(t, {});
    const s = sanitize(t, r);
    expect(s.includes('GB29NWBK60161331926819')).toBeFalsy();
    expect(s.includes('GB29')).toBeTruthy();
  });

  it('phone redaction preserves E.164 country code', () => {
    const t = 'call +14155552671 now';
    const r = detectAll(t, {});
    const s = sanitize(t, r);
    expect(s.includes('+14155552671')).toBeFalsy();
    expect(s.includes('+1')).toBeTruthy();
  });

  it('Discord token redaction preserves user-id segment', () => {
    // Format: [MNO] + 23 alphanum . 6 alphanum . 27 alphanum
    const userSegment = 'M' + 'A'.repeat(23);
    const token = userSegment + '.' + 'B'.repeat(6) + '.' + 'C'.repeat(27);
    const t = `token: ${token}`;
    const r = detectAll(t, {});
    const s = sanitize(t, r);
    expect(s.includes(token)).toBeFalsy();
    expect(s.includes(userSegment)).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// Provider pack 2 — PR #18 extractions + #23 new providers
// ---------------------------------------------------------------------------
describe('Provider pack 2 detection', () => {
  // --- PR #18 extractions ---

  it('detects Azure SQL connection string', () => {
    const t = 'Server=tcp:myserver.database.windows.net,1433;Database=mydb;User ID=admin;Password=s3cr3t!;';
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'azure_sql')).toBeTruthy();
  });

  it('Azure SQL redaction preserves everything except Password value', () => {
    const t = 'Server=tcp:myserver.database.windows.net,1433;Database=mydb;User ID=admin;Password=s3cr3t!;';
    const r = detectAll(t, {});
    const s = sanitize(t, r);
    expect(s.includes('s3cr3t!')).toBeFalsy();
    expect(s.includes('Password=[REDACTED]')).toBeTruthy();
    expect(s.includes('mydb')).toBeTruthy();
  });

  it('detects Azure client secret via env var', () => {
    const t = 'AZURE_CLIENT_SECRET=' + 'a'.repeat(16);
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'azure_client_secret')).toBeTruthy();
  });

  it('detects Google OAuth ya29 token', () => {
    const t = 'ya29.' + 'A'.repeat(20);
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'google_oauth')).toBeTruthy();
  });

  it('Google OAuth redaction replaces token with placeholder', () => {
    const t = 'Bearer ya29.' + 'A'.repeat(25);
    const r = detectAll(t, {});
    const s = sanitize(t, r);
    expect(s.includes('ya29.' + 'A'.repeat(25))).toBeFalsy();
    expect(s.includes('ya29.[REDACTED]')).toBeTruthy();
  });

  it('detects PEM private key block', () => {
    const body = 'A'.repeat(60);
    const t = `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----`;
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'pem_private_key')).toBeTruthy();
  });

  it('PEM redaction removes key body but preserves header/footer', () => {
    const body = 'A'.repeat(60);
    const t = `-----BEGIN RSA PRIVATE KEY-----\n${body}\n-----END RSA PRIVATE KEY-----`;
    const r = detectAll(t, {});
    const s = sanitize(t, r);
    expect(s.includes(body)).toBeFalsy();
    expect(s.includes('-----BEGIN RSA PRIVATE KEY-----')).toBeTruthy();
    expect(s.includes('-----END RSA PRIVATE KEY-----')).toBeTruthy();
  });

  // --- #23 Provider pack 2 ---

  it('detects Anthropic API key', () => {
    const t = 'sk-ant-api03-' + 'A'.repeat(40);
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'anthropic')).toBeTruthy();
  });

  it('Anthropic key redaction preserves sk-ant- prefix', () => {
    const t = 'sk-ant-api03-' + 'A'.repeat(40);
    const r = detectAll(t, {});
    const s = sanitize(t, r);
    expect(s.includes('A'.repeat(40))).toBeFalsy();
    expect(s.includes('sk-ant-')).toBeTruthy();
  });

  it('detects HuggingFace token', () => {
    const t = 'hf_' + 'A'.repeat(34);
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'huggingface')).toBeTruthy();
  });

  it('detects Slack bot token', () => {
    const t = 'xoxb-123456789-abcdefghij';
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'slack_token')).toBeTruthy();
  });

  it('detects Slack webhook URL', () => {
    const t = 'https://hooks.slack.com/services/T01ABCDEF/B01ABCDEF/ABCDEFabcdef123456';
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'slack_webhook')).toBeTruthy();
  });

  it('detects Twilio API key', () => {
    const t = 'SK' + 'a'.repeat(32);
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'twilio')).toBeTruthy();
  });

  it('detects Telegram bot token', () => {
    const t = '123456789:' + 'A'.repeat(35);
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'telegram_bot')).toBeTruthy();
  });

  it('Telegram token redaction preserves bot ID', () => {
    const t = '123456789:' + 'A'.repeat(35);
    const r = detectAll(t, {});
    const s = sanitize(t, r);
    expect(s.includes('A'.repeat(35))).toBeFalsy();
    expect(s.includes('123456789')).toBeTruthy();
  });

  it('detects npm token', () => {
    const t = 'npm_' + 'A'.repeat(36);
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'npm_token')).toBeTruthy();
  });

  it('detects SendGrid API key', () => {
    const t = 'SG.' + 'A'.repeat(22) + '.' + 'B'.repeat(43);
    const r = detectAll(t, {});
    expect(r.some(d => d.key === 'sendgrid')).toBeTruthy();
  });
});
