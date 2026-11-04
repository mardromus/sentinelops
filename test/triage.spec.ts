import { Finding, ScanResult } from '../src/common/types';
import { makeFinding } from '../src/scanners/scanner';
import { diffScans, priorityFor, scoreFinding, TriageService } from '../src/triage/triage.service';

const f = (over: Partial<Parameters<typeof makeFinding>[0]> & { file?: string; line?: number } = {}): Finding =>
  makeFinding({
    ruleId: over.ruleId || 'js.sqli.string-built-query',
    title: 'x',
    message: over.message || 'SQL built from strings.',
    category: over.category || 'sast',
    severity: over.severity || 'high',
    confidence: over.confidence || 'high',
    cwe: ['CWE-89'],
    location: { file: over.file || 'src/db.js', line: over.line || 1, snippet: over.ruleId || 'q' },
    scanner: 'builtin-sast',
    package: over.package,
  });

const result = (findings: Finding[]): ScanResult => ({ id: 'r', root: '/nonexistent', startedAt: '', finishedAt: '', filesScanned: 1, findings, scanners: [] });

describe('triage', () => {
  it('scores with explainable adjustments', () => {
    const tainted = scoreFinding(f({ severity: 'critical', message: 'x. The value comes straight from the HTTP request.' }));
    expect(tainted.risk).toBe(100);
    expect(tainted.notes.join()).toContain('request input');

    const inTests = scoreFinding(f({ file: 'test/db.spec.js' }));
    expect(inTests.risk).toBe(32);
    expect(inTests.notes.join()).toContain('test/example');

    const devDep = scoreFinding(
      f({ category: 'dependency', severity: 'critical', file: 'package-lock.json', package: { name: 'minimist', version: '1.2.5', ecosystem: 'npm', dev: true, fixedIn: '1.2.6' } }),
    );
    expect(devDep.risk).toBe(70);
  });

  it('maps risk to priority', () => {
    expect([95, 80, 79, 60, 35, 34, 0].map(priorityFor)).toEqual(['P1', 'P1', 'P2', 'P2', 'P3', 'P4', 'P4']);
  });

  it('applies the baseline and sorts suppressed findings last', () => {
    const a = f({ ruleId: 'a', severity: 'critical' });
    const b = f({ ruleId: 'b', severity: 'low' });
    const svc = new TriageService();
    const r = svc.triage(result([a, b]), { baseline: [{ fingerprint: a.fingerprint, reason: 'accepted risk JIRA-12' }] });
    expect(r.findings.map((x) => x.ruleId)).toEqual(['b', 'a']);
    expect(r.findings[1].suppressReason).toBe('baseline: accepted risk JIRA-12');

    const expired = svc.triage(result([f({ ruleId: 'c' })]), { baseline: [{ fingerprint: f({ ruleId: 'c' }).fingerprint, reason: 'tmp', until: '2020-01-01' }] });
    expect(expired.findings[0].suppressed).toBeFalsy();
  });

  it('gates and summarises', () => {
    const svc = new TriageService();
    const r = svc.triage(result([f({ severity: 'high' }), f({ ruleId: 'z', severity: 'low' })]));
    expect(svc.gate(r, 'high').pass).toBe(false);
    expect(svc.gate(r, 'critical').pass).toBe(true);
    const s = svc.summary(r);
    expect(s).toMatchObject({ total: 2, active: 2, bySeverity: { high: 1, low: 1 } });
    expect(s.riskScore).toBeGreaterThan(40);
  });

  it('diffs scans by fingerprint', () => {
    const a = f({ ruleId: 'a' });
    const b = f({ ruleId: 'b' });
    const c = f({ ruleId: 'c' });
    const d = diffScans([a, b], [b, c]);
    expect(d.introduced.map((x) => x.ruleId)).toEqual(['c']);
    expect(d.fixed.map((x) => x.ruleId)).toEqual(['a']);
    expect(d.unchanged.map((x) => x.ruleId)).toEqual(['b']);
  });
});
