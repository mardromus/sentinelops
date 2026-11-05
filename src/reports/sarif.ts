/**
 * SARIF 2.1.0 export (OASIS standard), accepted by GitHub code scanning,
 * Azure DevOps, GitLab and most security dashboards.
 *
 * GitHub reads `properties.security-severity` (0-10) to rank alerts and
 * `partialFingerprints` to track an alert across commits.
 */
import { Finding, ScanResult, Severity } from '../common/types';
import { CWE } from '../knowledge/cwe';
import { OWASP_TOP10_2021 } from '../knowledge/owasp';

export const TOOL_VERSION = '1.0.0';
const INFO_URI = 'https://github.com/mardromus/sentinelops';

const SECURITY_SEVERITY: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '0.0' };
const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};
const PRECISION = { high: 'very-high', medium: 'high', low: 'medium' } as const;

function helpText(f: Finding): string {
  const parts = [f.remediation || ''];
  for (const o of f.owasp) {
    const cat = OWASP_TOP10_2021.find((c) => c.id === o);
    if (cat) parts.push(`${cat.id} ${cat.name}: ${cat.url}`);
  }
  for (const c of f.cwe) if (CWE[c]) parts.push(`${c} ${CWE[c].name}: https://cwe.mitre.org/data/definitions/${c.slice(4)}.html`);
  return parts.filter(Boolean).join('\n');
}

export function toSarif(result: ScanResult): object {
  const ruleIds: string[] = [];
  const rules: object[] = [];
  for (const f of result.findings) {
    if (ruleIds.includes(f.ruleId)) continue;
    ruleIds.push(f.ruleId);
    rules.push({
      id: f.ruleId,
      name: f.ruleId.replace(/[^A-Za-z0-9]+(.)?/g, (_m, c: string | undefined) => (c ? c.toUpperCase() : '')),
      shortDescription: { text: f.category === 'dependency' ? `Vulnerable dependency (${f.package?.advisory})` : f.title },
      fullDescription: { text: f.message.replace(/ The value comes straight from the HTTP request\./, '') },
      helpUri: f.references?.[0] || OWASP_TOP10_2021.find((c) => c.id === f.owasp[0])?.url || INFO_URI,
      help: { text: helpText(f), markdown: helpText(f).replace(/\n/g, '\n\n') },
      defaultConfiguration: { level: LEVEL[f.severity] },
      properties: {
        tags: [
          'security',
          f.category,
          ...f.cwe.map((c) => `external/cwe/${c.toLowerCase()}`),
          ...f.owasp.map((o) => `owasp-${o.toLowerCase()}`),
        ],
        'security-severity': SECURITY_SEVERITY[f.severity],
        precision: PRECISION[f.confidence],
        'problem.severity': LEVEL[f.severity] === 'note' ? 'recommendation' : LEVEL[f.severity],
      },
    });
  }

  const results = result.findings.map((f) => ({
    ruleId: f.ruleId,
    ruleIndex: ruleIds.indexOf(f.ruleId),
    level: LEVEL[f.severity],
    message: { text: `${f.message}${f.fix?.verified ? ' A verified fix is available from SentinelOps.' : ''}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.location.file, uriBaseId: '%SRCROOT%' },
          region: {
            startLine: Math.max(1, f.location.line),
            ...(f.location.column ? { startColumn: f.location.column } : {}),
            ...(f.location.endLine ? { endLine: f.location.endLine } : {}),
            ...(f.location.snippet ? { snippet: { text: f.location.snippet } } : {}),
          },
        },
      },
    ],
    partialFingerprints: { 'sentinelops/v1': f.fingerprint },
    ...(f.suppressed
      ? { suppressions: [{ kind: /inline/.test(f.suppressReason || '') ? 'inSource' : 'external', justification: f.suppressReason }] }
      : {}),
    properties: {
      id: f.id,
      severity: f.severity,
      confidence: f.confidence,
      risk: f.risk,
      priority: f.priority,
      cwe: f.cwe,
      owasp: f.owasp,
      scanner: f.scanner,
      ...(f.package ? { package: f.package } : {}),
      ...(f.verdict ? { verdict: f.verdict } : {}),
      ...(f.fix ? { fix: { strategy: f.fix.strategy, verified: f.fix.verified, description: f.fix.description, diff: f.fix.diff } } : {}),
    },
  }));

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'SentinelOps', semanticVersion: TOOL_VERSION, version: TOOL_VERSION, informationUri: INFO_URI, rules } },
        automationDetails: { id: `sentinelops/${result.id}` },
        invocations: [
          {
            executionSuccessful: result.scanners.every((s) => s.status !== 'error'),
            startTimeUtc: result.startedAt,
            endTimeUtc: result.finishedAt,
            toolExecutionNotifications: result.scanners
              .filter((s) => s.status !== 'ok')
              .map((s) => ({
                level: s.status === 'error' ? 'error' : 'note',
                message: { text: `${s.name}: ${s.status}${s.detail ? ` (${s.detail})` : ''}` },
              })),
          },
        ],
        results,
      },
    ],
  };
}
