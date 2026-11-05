import { SourceFile } from '../src/common/types';
import { languageOf } from '../src/scanners/files';
import { entropy, isPlaceholder, mask } from '../src/scanners/secrets/patterns';
import { SecretsScanner } from '../src/scanners/secrets/secrets.scanner';

// Test secrets are assembled at runtime so this file never contains a
// provider-shaped token that push protection or other scanners would flag.
const rnd = (n: number, alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567') =>
  Array.from({ length: n }, (_, i) => alphabet[(i * 7 + 3) % alphabet.length]).join('');
const AWS_ID = 'AK' + 'IA' + rnd(16);
const GH = 'gh' + 'p_' + rnd(36, 'abcdefghijkmnopqrstuvwxyzABCDEFGH0123456789');
const STRIPE = 'sk' + '_live_' + rnd(24, 'abcdefghijkmnopqrstuvwxyz0123456789');

const file = (path: string, content: string): SourceFile => ({
  path,
  absPath: '/x/' + path,
  content,
  lines: content.split('\n'),
  language: languageOf(path),
});
const scan = (path: string, content: string) => new SecretsScanner().scan({ options: { root: '/x' }, files: [file(path, content)] });

describe('secrets scanner', () => {
  it('detects provider tokens and masks them in the snippet', async () => {
    const fs = await scan(
      'config.js',
      [`const aws = '${AWS_ID}';`, `const gh = "${GH}";`, `stripe(${JSON.stringify(STRIPE)});`].join('\n'),
    );
    expect(fs.map((f) => f.ruleId)).toEqual(['secret.aws-access-key-id', 'secret.github-token', 'secret.stripe-live-key']);
    for (const f of fs) {
      expect(f.severity).toBe('critical');
      expect(f.cwe).toEqual(['CWE-798']);
      expect(f.location.snippet).toContain('****');
    }
    expect(fs[0].location.snippet).not.toContain(AWS_ID);
  });

  it('detects generic credentials and connection strings, ignores placeholders', async () => {
    const fs = await scan(
      'db.ts',
      [
        'const JWT_SECRET = "supersecret-shop-key-2026";',
        "const url = 'postgres://admin:Pr0dPassw0rd!@db.internal:5432/shop';",
        'const password = "changeme";',
        'const apiKey = process.env.API_KEY;',
        'const token = "${TOKEN}";',
        'const secretName = "orders.payment.key";',
      ].join('\n'),
    );
    expect(fs.map((f) => f.ruleId)).toEqual(['secret.generic-credential', 'secret.connection-string']);
    expect(fs[0].confidence).toBe('medium');
  });

  it('reads .env files but skips .env.example and lockfiles', async () => {
    const env = await scan('.env', 'PORT=3000\nDB_PASSWORD=h7Gk2pQz9wLm\nAPI_KEY=your_api_key_here\n');
    expect(env).toHaveLength(1);
    expect(env[0].message).toContain('DB_PASSWORD');
    expect(await scan('.env.example', 'DB_PASSWORD=h7Gk2pQz9wLm')).toHaveLength(0);
  });

  it('detects private key blocks', async () => {
    const fs = await scan('id_rsa', '-----BEGIN RSA ' + 'PRIVATE KEY-----\nMIIE...\n');
    expect(fs[0]).toMatchObject({ ruleId: 'secret.private-key', severity: 'critical' });
  });

  it('helpers behave', () => {
    expect(entropy('aaaa')).toBe(0);
    expect(entropy('abcd')).toBe(2);
    expect(isPlaceholder('your_token_here')).toBe(true);
    expect(isPlaceholder('h7Gk2pQz9wLm')).toBe(false);
    expect(mask('abcdefghijkl')).toBe('abcd******kl');
  });
});
