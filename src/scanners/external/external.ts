/**
 * Adapters for well-known open-source scanners. Each one is optional: when
 * the binary is not on PATH the adapter reports "skipped" and the built-in
 * scanners still cover the same OWASP categories.
 *
 *   semgrep  - SAST with the community rule registry
 *   gitleaks - secrets, including git history
 *   trivy    - dependencies, OS packages and IaC misconfiguration
 */
import { execFile, spawnSync } from 'node:child_process';
import { relative } from 'node:path';
import { Finding, Severity } from '../../common/types';
import { makeFinding, ScanContext, Scanner } from '../scanner';

export type Runner = (cmd: string, args: string[], cwd: string) => Promise<string>;

export const defaultRunner: Runner = (cmd, args, cwd) =>
  new Promise((resolve, reject) => {
    execFile(cmd, args, { cwd, maxBuffer: 64 * 1024 * 1024, timeout: 10 * 60 * 1000 }, (err, stdout) => {
      // semgrep/gitleaks/trivy exit non-zero when they find something; stdout is still the report
      if (err && !stdout) reject(err);
      else resolve(stdout);
    });
  });

export function isInstalled(cmd: string): boolean {
  try {
    return spawnSync(cmd, ['--version'], { stdio: 'ignore', timeout: 5000 }).status === 0;
  } catch {
    return false;
  }
}

const sev = (s: string | undefined, fallback: Severity = 'medium'): Severity => {
  const v = String(s || '').toUpperCase();
  if (v === 'CRITICAL') return 'critical';
  if (v === 'ERROR' || v === 'HIGH') return 'high';
  if (v === 'WARNING' || v === 'MEDIUM' || v === 'MODERATE') return 'medium';
  if (v === 'INFO' || v === 'LOW') return 'low';
  return fallback;
};
const cwes = (xs: unknown): string[] =>
  (Array.isArray(xs) ? xs : xs ? [xs] : []).map((x) => /CWE-\d+/.exec(String(x))?.[0]).filter((x): x is string => !!x);
const owasps = (xs: unknown): string[] =>
  (Array.isArray(xs) ? xs : xs ? [xs] : []).map((x) => /A(\d{2}):2021/.exec(String(x))?.[0]).filter((x): x is string => !!x);

export function parseSemgrep(json: string, root: string): Finding[] {
  const doc = JSON.parse(json || '{}');
  return (doc.results || []).map((r: any) =>
    makeFinding({
      ruleId: `semgrep.${r.check_id}`,
      title: String(r.check_id).split('.').pop() || r.check_id,
      message: r.extra?.message || r.check_id,
      category: 'sast',
      severity: sev(r.extra?.severity),
      confidence: sev(r.extra?.metadata?.confidence, 'medium') === 'high' ? 'high' : 'medium',
      cwe: cwes(r.extra?.metadata?.cwe),
      owasp: owasps(r.extra?.metadata?.owasp),
      location: {
        file: relative(root, r.path) || r.path,
        line: r.start?.line || 1,
        endLine: r.end?.line,
        snippet: String(r.extra?.lines || '')
          .trim()
          .slice(0, 240),
      },
      scanner: 'semgrep',
      references: r.extra?.metadata?.references,
    }),
  );
}

export function parseGitleaks(json: string): Finding[] {
  const doc = JSON.parse(json || '[]');
  return (Array.isArray(doc) ? doc : []).map((r: any) =>
    makeFinding({
      ruleId: `gitleaks.${r.RuleID}`,
      title: r.Description || r.RuleID,
      message: `${r.Description || 'Secret'} found${r.Commit ? ` in commit ${String(r.Commit).slice(0, 8)}` : ''}.`,
      category: 'secret',
      severity: 'high',
      confidence: 'high',
      cwe: ['CWE-798'],
      location: {
        file: r.File,
        line: r.StartLine || 1,
        snippet: String(r.Match || '')
          .replace(r.Secret || '\u0000', '****')
          .slice(0, 240),
      },
      scanner: 'gitleaks',
      remediation: 'Revoke and rotate the credential, then remove it from history.',
    }),
  );
}

export function parseTrivy(json: string): Finding[] {
  const doc = JSON.parse(json || '{}');
  const out: Finding[] = [];
  for (const res of doc.Results || []) {
    for (const v of res.Vulnerabilities || []) {
      out.push(
        makeFinding({
          ruleId: `dep.${v.VulnerabilityID}`,
          title: `${v.PkgName}@${v.InstalledVersion}: ${v.Title || v.VulnerabilityID}`,
          message: `${v.PkgName} ${v.InstalledVersion} is affected by ${v.VulnerabilityID}.`,
          category: 'dependency',
          severity: sev(v.Severity),
          confidence: 'high',
          cwe: cwes(v.CweIDs).length ? cwes(v.CweIDs) : ['CWE-937'],
          owasp: ['A06:2021'],
          location: { file: res.Target, line: 1, snippet: `${v.PkgName}@${v.InstalledVersion}` },
          scanner: 'trivy',
          remediation: v.FixedVersion ? `Upgrade ${v.PkgName} to ${v.FixedVersion}.` : undefined,
          references: v.PrimaryURL ? [v.PrimaryURL] : undefined,
          package: {
            name: v.PkgName,
            version: v.InstalledVersion,
            ecosystem: /pip|python|requirements/i.test(res.Type || res.Target) ? 'PyPI' : 'npm',
            fixedIn: v.FixedVersion ? String(v.FixedVersion).split(',')[0].trim() : undefined,
            advisory: v.VulnerabilityID,
            aliases: [v.VulnerabilityID],
          },
        }),
      );
    }
    for (const m of res.Misconfigurations || []) {
      out.push(
        makeFinding({
          ruleId: `trivy.${m.ID}`,
          title: m.Title || m.ID,
          message: m.Message || m.Description || m.Title,
          category: 'config',
          severity: sev(m.Severity),
          confidence: 'high',
          cwe: [],
          location: { file: res.Target, line: m.CauseMetadata?.StartLine || 1, snippet: m.ID },
          scanner: 'trivy',
          remediation: m.Resolution,
          references: m.PrimaryURL ? [m.PrimaryURL] : undefined,
        }),
      );
    }
  }
  return out;
}

export class ExternalScanner implements Scanner {
  constructor(
    readonly name: string,
    private readonly cmd: string,
    private readonly args: (root: string) => string[],
    private readonly parse: (stdout: string, root: string) => Finding[],
    private readonly runner: Runner = defaultRunner,
    private readonly available: () => boolean = () => isInstalled(cmd),
  ) {}

  isAvailable(): boolean {
    return this.available();
  }

  async scan(ctx: ScanContext): Promise<Finding[]> {
    const stdout = await this.runner(this.cmd, this.args(ctx.options.root), ctx.options.root);
    return this.parse(stdout, ctx.options.root);
  }
}

export function externalScanners(runner?: Runner): ExternalScanner[] {
  return [
    new ExternalScanner(
      'semgrep',
      'semgrep',
      () => ['scan', '--config', 'p/owasp-top-ten', '--json', '--quiet', '--metrics=off', '.'],
      parseSemgrep,
      runner,
    ),
    new ExternalScanner(
      'gitleaks',
      'gitleaks',
      () => ['detect', '--source', '.', '--report-format', 'json', '--report-path', '/dev/stdout', '--no-banner', '--exit-code', '0'],
      (s) => parseGitleaks(s),
      runner,
    ),
    new ExternalScanner(
      'trivy',
      'trivy',
      () => ['fs', '--format', 'json', '--quiet', '--scanners', 'vuln,misconfig', '.'],
      (s) => parseTrivy(s),
      runner,
    ),
  ];
}
