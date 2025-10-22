import fs from 'fs';
import vm from 'vm';
import path from 'path';
import url from 'url';

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const detectorsPath = path.resolve(__dirname, '../src/detectors.js');
const code = fs.readFileSync(detectorsPath, 'utf8');

const sandbox = { window: {}, console };
vm.createContext(sandbox);
vm.runInContext(code, sandbox);

const { sgDetectAll, sgSanitize } = sandbox.window.SG;

describe('API key detection', () => {
  it('detects OpenAI keys', () => {
    const t = 'here is a test sk-ABCDEFGHIJKLMNOPQRST123456';
    const r = sgDetectAll(t);
    expect(r.api.length > 0).toBeTruthy();
  });
  it('detects Stripe keys', () => {
    const t = 'sk_test_51H1234567890ABCDEFGHIJKLMNOP';
    const r = sgDetectAll(t);
    expect(r.api.some(m => m.key.includes('stripe'))).toBeTruthy();
  });
});

describe('PII detection', () => {
  it('detects email and phone', () => {
    const t = 'contact me at a@b.co or +491234567890';
    const r = sgDetectAll(t);
    expect(r.pii.length >= 2).toBeTruthy();
  });
  it('detects credit card (Luhn)', () => {
    const visa = '4111 1111 1111 1111';
    const r = sgDetectAll(visa);
    expect(r.pii.some(m => m.key === 'credit_card')).toBeTruthy();
  });
});

describe('Sanitization', () => {
  it('replaces matches with redacted tags', () => {
    const t = 'email a@b.co and key sk-ABCDEFGHIJKLMNOPQRST123456';
    const r = sgDetectAll(t);
    const s = sgSanitize(t, r);
    expect(s.includes('[[REDACTED_EMAIL]]')).toBeTruthy();
    expect(s.includes('[[REDACTED_OPENAI]]') || s.includes('[[REDACTED_HIGH_ENTROPY]]')).toBeTruthy();
  });
});

// New Provider Regex Pack Tests (Azure, Discord, Firebase, Cloudflare, Postgres)

describe('Provider regex pack (doc-backed)', () => {
  it('detects Discord bot tokens', () => {
    const t = 'discord token 123456789012345678901234.AbCdEf.ghIjKlMnOpQrStUvWxYz123';
    const r = sgDetectAll(t);
    expect(r.api.length > 0).toBeTruthy();
  });

  it('detects Firebase OAuth access tokens (ya29 prefix)', () => {
    const t = 'Authorization: Bearer ya29.A0AVA9yAbCdEfGhIjKlMnOpQrStUvWxYz_123456';
    const r = sgDetectAll(t);
    expect(r.api.length > 0).toBeTruthy();
  });

  it('detects Azure client secret', () => {
    const t = 'AZURE_CLIENT_SECRET=AbCdEfGhIjKlMnOp_QrSt+UvWx~';
    const r = sgDetectAll(t);
    expect(r.api.length > 0).toBeTruthy();
  });

  it('detects Azure Storage connection strings', () => {
    const t = 'DefaultEndpointsProtocol=https;AccountName=storacctdemo;AccountKey=QWErTYuIOpASDFGhJKLzxcvbNm1234567890abcd=;EndpointSuffix=core.windows.net';
    const r = sgDetectAll(t);
    expect(r.api.length > 0).toBeTruthy();
  });

  it('detects Azure SAS tokens', () => {
    const t = 'https://mystorage.blob.core.windows.net/container/file.txt?sv=2023-11-03&ss=bfqt&srt=sco&sp=rwdlacupiytfx&se=2030-01-01T00:00:00Z&st=2025-01-01T00:00:00Z&spr=https&sig=AbCdEfGhIjKlMnOpQrSt';
    const r = sgDetectAll(t);
    expect(r.api.length > 0).toBeTruthy();
  });

  it('detects Azure SQL connection strings', () => {
    const t = 'Server=tcp:myserver.database.windows.net,1433;Database=appdb;User ID=appuser@tenant;Password=Sup3r$ecret!;Encrypt=true;';
    const r = sgDetectAll(t);
    expect(r.api.length > 0).toBeTruthy();
  });

  it('detects Cloudflare API tokens', () => {
    const t = 'CLOUDFLARE_API_TOKEN=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd';
    const r = sgDetectAll(t);
    expect(r.api.length > 0).toBeTruthy();
  });

  it('detects PostgreSQL URLs with embedded credentials', () => {
    const t = 'postgres://appuser:Sup3r%24ecret@db.internal.local:5432/appdb?sslmode=require';
    const r = sgDetectAll(t);
    expect(r.api.length > 0).toBeTruthy();
  });
});

