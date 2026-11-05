import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Finding } from '../src/common/types';
import { KnowledgeService } from '../src/knowledge/knowledge.service';
import { ExternalScanner, parseGitleaks, parseSemgrep, parseTrivy } from '../src/scanners/external/external';
import { makeFinding } from '../src/scanners/scanner';
import { dedupe, disambiguate, ScannersService } from '../src/scanners/scanners.service';
import { SastScanner } from '../src/scanners/sast/sast.scanner';

describe('external adapters', () => {
  it('parses semgrep json', () => {
    const fs = parseSemgrep(
      JSON.stringify({
        results: [
          {
            check_id: 'javascript.express.security.injection.tainted-sql-string',
            path: '/repo/src/db.js',
            start: { line: 12 },
            end: { line: 12 },
            extra: { severity: 'ERROR', message: 'Tainted SQL', lines: 'db.query(q)', metadata: { cwe: ['CWE-89: SQL Injection'], owasp: ['A03:2021 - Injection'] } },
          },
        ],
      }),
      '/repo',
    );
    expect(fs[0]).toMatchObject({ severity: 'high', cwe: ['CWE-89'], owasp: ['A03:2021'], scanner: 'semgrep' });
    expect(fs[0].location).toMatchObject({ file: 'src/db.js', line: 12 });
  });

  it('parses gitleaks and masks the secret', () => {
    const fs = parseGitleaks(JSON.stringify([{ RuleID: 'generic-api-key', Description: 'Generic API Key', File: 'a.js', StartLine: 3, Match: 'key = "abc123secret"', Secret: 'abc123secret', Commit: 'deadbeefcafe' }]));
    expect(fs[0].location.snippet).toBe('key = "****"');
    expect(fs[0].message).toContain('deadbeef');
  });

  it('parses trivy vulnerabilities and misconfigurations', () => {
    const fs = parseTrivy(
      JSON.stringify({
        Results: [
          { Target: 'package-lock.json', Type: 'npm', Vulnerabilities: [{ VulnerabilityID: 'CVE-2021-23337', PkgName: 'lodash', InstalledVersion: '4.17.15', FixedVersion: '4.17.21', Severity: 'HIGH', CweIDs: ['CWE-94'] }] },
          { Target: 'Dockerfile', Misconfigurations: [{ ID: 'DS002', Title: 'Image user should not be root', Severity: 'HIGH', CauseMetadata: { StartLine: 1 } }] },
        ],
      }),
    );
    expect(fs.map((f) => f.category)).toEqual(['dependency', 'config']);
    expect(fs[0].package).toMatchObject({ name: 'lodash', fixedIn: '4.17.21' });
  });
});

const base = {
  title: 't',
  message: 'm',
  confidence: 'high' as const,
  location: { file: 'a.js', line: 3, snippet: 'x' },
};

describe('orchestration', () => {
  it('dedupes the same issue reported by two tools, keeping the stronger one', () => {
    const a = makeFinding({ ...base, ruleId: 'js.sqli', category: 'sast', severity: 'high', cwe: ['CWE-89'], scanner: 'builtin-sast' });
    const b = makeFinding({ ...base, ruleId: 'semgrep.sqli', category: 'sast', severity: 'high', cwe: ['CWE-89'], scanner: 'semgrep' });
    const c = makeFinding({ ...base, ruleId: 'js.sqli', category: 'sast', severity: 'high', cwe: ['CWE-89'], scanner: 'builtin-sast' });
    const out = dedupe([b, a, c]);
    expect(out).toHaveLength(1);
    expect(out[0].scanner).toBe('builtin-sast');
    expect(out[0].triageNotes![0]).toContain('semgrep');
  });

  it('gives identical vulnerable lines in one file distinct identities', () => {
    const mk = (line: number) =>
      makeFinding({ ...base, location: { file: 'a.js', line, snippet: 'same()' }, ruleId: 'r', category: 'sast', severity: 'high', cwe: ['CWE-89'], scanner: 'builtin-sast' });
    const out = disambiguate([mk(9), mk(3)]);
    expect(new Set(out.map((f) => f.fingerprint)).size).toBe(2);
    expect(out.find((f) => f.location.line === 3)!.fingerprint).toBe(mk(3).fingerprint);
    expect(dedupe(out)).toHaveLength(2);
  });

  it('scans a directory end-to-end with enrichment, runs and skipped tools', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'so-'));
    mkdirSync(join(dir, 'src'));
    writeFileSync(join(dir, 'src/app.js'), 'const app = express();\ndb.query("SELECT * FROM t WHERE id = " + req.query.id);\n');
    writeFileSync(join(dir, 'Dockerfile'), 'FROM node:latest\nCMD ["node","src/app.js"]\n');
    writeFileSync(join(dir, 'requirements.txt'), 'flask==2.2.2\n');
    const broken: ExternalScanner = new ExternalScanner('semgrep', 'semgrep', () => [], () => [], async () => '', () => false);
    const svc = new ScannersService(new KnowledgeService());
    const res = await svc.scan({ root: dir, osv: false, external: false });
    expect(res.filesScanned).toBe(3);
    expect(res.findings[0]).toMatchObject({ ruleId: 'js.sqli.string-built-query', severity: 'critical', owasp: ['A03:2021'] });
    expect(new Set(res.findings.map((f) => f.category))).toEqual(new Set(['sast', 'config', 'dependency']));
    expect(res.scanners.find((r) => r.name === 'builtin-deps')!.detail).toBe('advisories: offline');
    expect(res.scanners.filter((r) => r.status === 'skipped').map((r) => r.name)).toEqual(['semgrep', 'gitleaks', 'trivy']);

    const custom = new ScannersService(new KnowledgeService(), [new SastScanner(), broken]);
    const r2 = await custom.scan({ root: dir });
    expect(r2.scanners.map((r) => `${r.name}:${r.status}`)).toEqual(['builtin-sast:ok', 'semgrep:skipped']);
  });

  it('records scanner errors without failing the scan', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'so-'));
    const failing = { name: 'boom', scan: async (): Promise<Finding[]> => { throw new Error('exploded'); } };
    const res = await new ScannersService(new KnowledgeService(), [failing]).scan({ root: dir });
    expect(res.scanners[0]).toMatchObject({ status: 'error', detail: 'exploded' });
  });
});
