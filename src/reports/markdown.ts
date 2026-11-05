/**
 * Markdown report for pull-request comments and job summaries.
 * The hidden marker lets the GitHub integration update its own comment
 * instead of posting a new one on every push.
 */
import { Finding, ScanResult, Severity } from '../common/types';
import { OWASP_TOP10_2021 } from '../knowledge/owasp';
import type { AgentReport } from '../agent/agent.service';

export const COMMENT_MARKER = '<!-- sentinelops:report -->';
const ICON: Record<Severity, string> = { critical: '🟥', high: '🟧', medium: '🟨', low: '🟦', info: '⬜' };
const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const esc = (s: string) => s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').replace(/</g, '&lt;');
const code = (s: string) => '`' + s.replace(/`/g, "'") + '`';

export interface MarkdownOptions {
  gate?: { pass: boolean; failOn: Severity };
  agent?: AgentReport;
  maxFindings?: number;
  title?: string;
  diff?: { introduced: number; fixed: number };
}

/** Code block whose fence is longer than any backtick run inside (repository text cannot break out). */
function block(text: string, lang: string): string {
  const longest = Math.max(2, ...(text.match(/`+/g) || []).map((m) => m.length));
  const f = '`'.repeat(longest + 1);
  return `${f}${lang}\n${text.trimEnd()}\n${f}`;
}

function findingDetails(f: Finding): string {
  const lines = [
    `<details><summary>${ICON[f.severity]} <b>${f.id}</b> ${esc(f.title)} <code>${esc(f.location.file)}:${f.location.line}</code></summary>`,
    '',
    `**${f.severity.toUpperCase()}** · ${f.priority || ''} · risk ${f.risk ?? '-'} · ${f.cwe.join(', ')} · ${f.owasp.join(', ')} · rule ${code(f.ruleId)}`,
    '',
    esc(f.message),
  ];
  if (f.location.snippet && f.category !== 'dependency') lines.push('', block(f.location.snippet, 'text'));
  if (f.verdict)
    lines.push(
      '',
      `**Agent verdict:** ${f.verdict.status.replace(/_/g, ' ')} (${f.verdict.confidence}) — ${esc(f.verdict.rationale)}${f.verdict.guardrail ? ` _(${esc(f.verdict.guardrail)})_` : ''}`,
    );
  if (f.fix) {
    lines.push(
      '',
      `**Fix${f.fix.verified ? ' ✅ verified' : ' ⚠️ unverified'}** (${f.fix.strategy}): ${esc(f.fix.description)}`,
      '',
      block(f.fix.diff, 'diff'),
    );
  } else if (f.remediation) lines.push('', `**How to fix:** ${esc(f.remediation)}`);
  lines.push('', '</details>');
  return lines.join('\n');
}

export function toMarkdown(result: ScanResult, opts: MarkdownOptions = {}): string {
  const active = result.findings.filter((f) => !f.suppressed);
  const count = (s: Severity) => active.filter((f) => f.severity === s).length;
  const out: string[] = [COMMENT_MARKER, `## 🛡️ ${opts.title || 'SentinelOps security review'}`, ''];

  if (opts.gate)
    out.push(
      opts.gate.pass
        ? `**✅ Passed** — no active findings at or above \`${opts.gate.failOn}\`.`
        : `**❌ Failed** — active findings at or above \`${opts.gate.failOn}\` must be fixed or triaged.`,
      '',
    );
  if (opts.diff) out.push(`This change introduces **${opts.diff.introduced}** and fixes **${opts.diff.fixed}** finding(s).`, '');

  out.push('| ' + ORDER.map((s) => `${ICON[s]} ${s}`).join(' | ') + ' | suppressed | fixes ready |');
  out.push('|' + ' :-: |'.repeat(ORDER.length + 2));
  out.push(
    '| ' +
      ORDER.map((s) => String(count(s))).join(' | ') +
      ` | ${result.findings.length - active.length} | ${active.filter((f) => f.fix?.verified).length} |`,
    '',
  );

  const owasp = OWASP_TOP10_2021.map((c) => ({ c, n: active.filter((f) => f.owasp.includes(c.id)).length })).filter((x) => x.n);
  if (owasp.length) out.push('**OWASP Top 10:** ' + owasp.map(({ c, n }) => `${c.id.slice(0, 3)} ${c.name} (${n})`).join(' · '), '');

  if (opts.agent?.summary) {
    out.push(
      `### 🤖 Agent briefing (${opts.agent.mode === 'llm' ? opts.agent.model : 'offline planner'}, ${opts.agent.policy})`,
      '',
      opts.agent.summary
        .split('\n')
        .map((l) => `> ${l}`)
        .join('\n'),
      '',
    );
  }

  if (active.length) {
    const max = opts.maxFindings ?? 25;
    out.push('### Findings', '', '| | id | priority | finding | location | fix |', '|---|---|---|---|---|---|');
    for (const f of active.slice(0, max)) {
      out.push(
        `| ${ICON[f.severity]} | ${f.id} | ${f.priority || ''} | ${esc(f.title)} | ${code(`${f.location.file}:${f.location.line}`)} | ${f.fix ? (f.fix.verified ? '✅' : '⚠️') : ''} |`,
      );
    }
    if (active.length > max) out.push('', `_…and ${active.length - max} more in the full report._`);
    out.push('', '### Details', '', ...active.slice(0, Math.min(max, 15)).map(findingDetails));
  } else {
    out.push('No active findings. 🎉');
  }

  out.push(
    '',
    `<sub>${result.filesScanned} files · scanners: ${result.scanners.map((s) => `${s.name} ${s.status === 'ok' ? '✓' : s.status}`).join(', ')} · scan ${result.id.slice(0, 8)}</sub>`,
  );
  return out.join('\n') + '\n';
}
