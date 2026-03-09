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
  'secrets/discord.js',
  'secrets/firebase.js',
  'secrets/cloudflare.js',
  'secrets/postgres.js',
  'pii/email.js',
  'pii/phone.js',
  'pii/credit-card.js',
  'pii/iban.js',
  'code/heuristic.js',
  'code/org-markers.js',
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
});
