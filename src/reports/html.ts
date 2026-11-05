/**
 * Self-contained HTML report: one file, no network requests, data embedded
 * as JSON and rendered with textContent only (a security report must not be
 * an XSS vector for the code it describes).
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ScanResult, Severity } from '../common/types';
import { KnowledgeService } from '../knowledge/knowledge.service';
import type { AgentReport } from '../agent/agent.service';
import { TOOL_VERSION } from './sarif';

export function assetPath(name: string): string {
  for (const p of [join(__dirname, '..', '..', 'assets', name), join(process.cwd(), 'assets', name)]) if (existsSync(p)) return p;
  throw new Error(`asset not found: ${name}`);
}

/** JSON that is safe inside <script type="application/json">. */
export function safeJson(v: unknown): string {
  return JSON.stringify(v)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

export interface HtmlOptions {
  gate?: { pass: boolean; failOn: Severity };
  agent?: AgentReport;
  summary?: Record<string, unknown>;
  title?: string;
}

export function toHtml(result: ScanResult, opts: HtmlOptions = {}): string {
  const knowledge = new KnowledgeService();
  const data = {
    version: TOOL_VERSION,
    generatedAt: new Date().toISOString(),
    title: opts.title || 'SentinelOps security report',
    gate: opts.gate,
    summary: opts.summary,
    heatmap: knowledge.heatmap(result.findings),
    owasp: knowledge.allOwasp().map((c) => ({ id: c.id, name: c.name, url: c.url })),
    agent: opts.agent
      ? {
          mode: opts.agent.mode,
          model: opts.agent.model,
          policy: opts.agent.policy,
          summary: opts.agent.summary,
          injections: opts.agent.injections,
          errors: opts.agent.errors,
          steps: opts.agent.steps,
          toolCalls: opts.agent.toolCalls,
        }
      : null,
    scan: {
      id: result.id,
      root: result.root.split(/[\\/]/).filter(Boolean).pop() || result.root,
      startedAt: result.startedAt,
      finishedAt: result.finishedAt,
      filesScanned: result.filesScanned,
      scanners: result.scanners,
    },
    findings: result.findings.map((f) => ({ ...f, fix: f.fix ? { ...f.fix, newContent: undefined } : undefined })),
  };
  const template = readFileSync(assetPath('report.html'), 'utf8');
  return template
    .replace('"__SENTINELOPS_DATA__"', () => safeJson(data))
    .replace('<title>SentinelOps report</title>', () => `<title>${escapeHtml(data.title)} · ${escapeHtml(data.scan.root)}</title>`);
}

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);
}
