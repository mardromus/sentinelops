import { Finding, ScanResult } from '../src/common/types';
import { KnowledgeService } from '../src/knowledge/knowledge.service';
import { toHtml, safeJson } from '../src/reports/html';
import { COMMENT_MARKER, toMarkdown } from '../src/reports/markdown';
import { toSarif } from '../src/reports/sarif';
import { makeFinding } from '../src/scanners/scanner';
import { TriageService } from '../src/triage/triage.service';

const k = new KnowledgeService();
function finding(over: Partial<Parameters<typeof makeFinding>[0]>): Finding {
  return k.enrich(
    makeFinding({
      ruleId: 'js.sqli.string-built-query',
      title: 'SQL query built from strings',
      message: 'The SQL text is concatenated with values.',
      category: 'sast',
      severity: 'critical',
      confidence: 'high',
      cwe: ['CWE-89'],
      location: { file: 'src/app.js', line: 7, snippet: 'db.query("SELECT * FROM t WHERE id = " + req.params.id)' },
      scanner: 'builtin-sast',
      remediation: 'Use parameters.',
      ...over,
    }),
  );
}

function scan(): ScanResult {
  const a = finding({});
  a.fix = { findingId: a.id, strategy: 'rule', description: 'Parameterised the SQL query.', file: 'src/app.js', diff: '--- a/src/app.js\n+++ b/src/app.js\n@@ -7,1 +7,1 @@\n-db.query("x" + id)\n+db.query("x ?", [id])\n', verified: true };
  const b = finding({ ruleId: 'js.xss.reflected-response', title: 'XSS </script><script>alert(1)</script>', severity: 'high', cwe: ['CWE-79'], location: { file: 'src/app.js', line: 9, snippet: 'res.send(`<b>${req.query.n}</b>`) </script>' } });
  const c = finding({ ruleId: 'dep.CVE-2021-23337', title: 'lodash@4.17.15: Command injection', category: 'dependency', severity: 'high', cwe: ['CWE-94'], owasp: ['A06:2021'], location: { file: 'package-lock.json', line: 12, snippet: 'lodash@4.17.15' }, package: { name: 'lodash', version: '4.17.15', ecosystem: 'npm', fixedIn: '4.17.21', advisory: 'CVE-2021-23337', aliases: ['CVE-2021-23337'] } });
  const d = finding({ ruleId: 'js.crypto.weak-hash', title: 'Weak hash', severity: 'medium', cwe: ['CWE-328'], location: { file: 'src/x.js', line: 1, snippet: 'md5' } });
  d.suppressed = true;
  d.suppressReason = 'inline sentinelops-ignore';
  const r: ScanResult = { id: '0123456789abcdef', root: '/repo/shop', startedAt: '2026-11-05T06:00:00.000Z', finishedAt: '2026-11-05T06:00:01.000Z', filesScanned: 12, findings: [a, b, c, d], scanners: [{ name: 'builtin-sast', status: 'ok', findings: 3, durationMs: 4 }, { name: 'semgrep', status: 'skipped', findings: 0, durationMs: 0, detail: 'not installed' }] };
  return new TriageService().triage(r, { baseline: [] });
}

describe('SARIF', () => {
  it('produces a valid-looking 2.1.0 log for code scanning', () => {
    const log: any = toSarif(scan());
    expect(log.version).toBe('2.1.0');
    const run = log.runs[0];
    expect(run.tool.driver.name).toBe('SentinelOps');
    expect(run.tool.driver.rules).toHaveLength(4);
    const sqli = run.results.find((r: any) => r.ruleId === 'js.sqli.string-built-query');
    expect(sqli.level).toBe('error');
    expect(run.tool.driver.rules[sqli.ruleIndex].id).toBe(sqli.ruleId);
    expect(run.tool.driver.rules[sqli.ruleIndex].properties['security-severity']).toBe('9.5');
    expect(run.tool.driver.rules[sqli.ruleIndex].properties.tags).toEqual(expect.arrayContaining(['external/cwe/cwe-89', 'owasp-a03:2021']));
    expect(sqli.locations[0].physicalLocation).toMatchObject({ artifactLocation: { uri: 'src/app.js', uriBaseId: '%SRCROOT%' }, region: { startLine: 7 } });
    expect(sqli.partialFingerprints['sentinelops/v1']).toHaveLength(64);
    expect(sqli.message.text).toContain('verified fix');
    const sup = run.results.find((r: any) => r.ruleId === 'js.crypto.weak-hash');
    expect(sup.suppressions[0]).toMatchObject({ kind: 'inSource' });
    expect(run.invocations[0].toolExecutionNotifications[0].message.text).toContain('semgrep: skipped');
  });
});

describe('Markdown PR comment', () => {
  it('has the marker, gate, counts, OWASP line and fix diffs', () => {
    const md = toMarkdown(scan(), { gate: { pass: false, failOn: 'high' } });
    expect(md.startsWith(COMMENT_MARKER)).toBe(true);
    expect(md).toContain('**❌ Failed**');
    expect(md).toMatch(/\| 1 \| 2 \| 0 \| 0 \| 0 \| 1 \| 1 \|/);
    expect(md).toContain('A03 Injection (3)'); // the lodash advisory is CWE-94 (code injection) too
    expect(md).toContain('```diff\n--- a/src/app.js');
    expect(md).toContain('XSS &lt;/script>&lt;script>alert(1)&lt;/script>');
    expect(md).not.toContain('<script>alert(1)');
  });

  it('celebrates a clean scan', () => {
    const r = scan();
    r.findings = [];
    expect(toMarkdown(r, { gate: { pass: true, failOn: 'high' } })).toContain('No active findings');
  });
});

describe('HTML report', () => {
  it('embeds the data safely and makes no network requests', () => {
    const html = toHtml(scan(), { gate: { pass: false, failOn: 'high' } });
    expect(html).toContain('<title>SentinelOps security report · shop</title>');
    const json = /<script type="application\/json" id="so-data">([\s\S]*?)<\/script>/.exec(html)![1];
    expect(json).not.toMatch(/<\/script/i);
    const data = JSON.parse(json);
    expect(data.findings).toHaveLength(4);
    expect(data.heatmap.find((c: any) => c.id === 'A03:2021').count).toBe(3);
    expect(html).not.toMatch(/<script[^>]+src=|<link[^>]+href=["']https?:/);
    expect(html).toContain("default-src 'none'");
  });

  it('escapes script terminators in JSON', () => {
    expect(safeJson({ a: '</script><b>&' })).toBe('{"a":"\\u003c/script\\u003e\\u003cb\\u003e\\u0026"}');
  });
});
