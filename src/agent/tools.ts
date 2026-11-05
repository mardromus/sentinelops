/**
 * The tools the model can call. Each tool is a narrow, audited capability:
 * reads are sandboxed and redacted, writes only ever produce *proposals*,
 * and every call is checked against the autonomy policy first.
 */
import { Finding, FixProposal, ScanResult, SourceFile, Verdict, VerdictStatus } from '../common/types';
import { KnowledgeService } from '../knowledge/knowledge.service';
import { unifiedDiff } from '../remediation/diff';
import { fixerFor } from '../remediation/fixers';
import { RemediationService, Workspace } from '../remediation/remediation.service';
import { verifyFix } from '../remediation/verify';
import { loadFiles } from '../scanners/files';
import { AuditLog } from './audit';
import { detectInjection, PathSandbox, untrusted } from './guard';
import { ToolSpec } from './llm.client';
import { AgentAction, Policy } from './policy';

export interface InjectionWarning {
  source: string;
  labels: string[];
  excerpt?: string;
}

export interface AgentSession {
  result: ScanResult;
  sandbox: PathSandbox;
  ws: Workspace;
  policy: Policy;
  audit: AuditLog;
  knowledge: KnowledgeService;
  remediation: RemediationService;
  verdicts: Map<string, Verdict>;
  fixes: Map<string, FixProposal>;
  injections: InjectionWarning[];
  files?: SourceFile[];
  finished?: string;
}

export const TOOL_SPECS: ToolSpec[] = [
  {
    name: 'list_findings',
    description:
      'List active findings, highest risk first. Returns id, priority, severity, rule, location, title and whether a deterministic fix exists.',
    parameters: {
      type: 'object',
      properties: {
        severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
        category: { type: 'string', enum: ['sast', 'secret', 'dependency', 'config'] },
        limit: { type: 'integer', minimum: 1, maximum: 50 },
      },
    },
  },
  {
    name: 'get_finding',
    description: 'Full details for one finding: message, CWE/OWASP guidance, triage notes and the surrounding code.',
    parameters: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] },
  },
  {
    name: 'read_file',
    description: 'Read up to 200 lines of a repository file (relative path). Credential files are not readable.',
    parameters: {
      type: 'object',
      properties: { path: { type: 'string' }, start_line: { type: 'integer', minimum: 1 }, end_line: { type: 'integer', minimum: 1 } },
      required: ['path'],
    },
  },
  {
    name: 'search_code',
    description:
      'Case-sensitive literal search across the repository. Use it to check whether a value is validated or sanitised elsewhere.',
    parameters: {
      type: 'object',
      properties: { query: { type: 'string', minLength: 2 }, max_results: { type: 'integer', minimum: 1, maximum: 50 } },
      required: ['query'],
    },
  },
  {
    name: 'propose_fix',
    description: 'Run the deterministic fixer for a finding. Returns a unified diff and whether a re-scan verified it.',
    parameters: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] },
  },
  {
    name: 'write_patch',
    description:
      'Propose your own minimal patch for a finding that has no deterministic fixer: replace lines start_line..end_line (within 15 lines of the finding) with `replacement`. The patch is re-scanned; it is never applied without human approval.',
    parameters: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        start_line: { type: 'integer', minimum: 1 },
        end_line: { type: 'integer', minimum: 1 },
        replacement: { type: 'string' },
        rationale: { type: 'string' },
      },
      required: ['id', 'start_line', 'end_line', 'replacement', 'rationale'],
    },
  },
  {
    name: 'set_verdict',
    description: 'Record your triage verdict for a finding, with a one-sentence rationale grounded in the code you read.',
    parameters: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        status: { type: 'string', enum: ['true_positive', 'likely_false_positive', 'needs_review'] },
        confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
        rationale: { type: 'string' },
      },
      required: ['id', 'status', 'confidence', 'rationale'],
    },
  },
  {
    name: 'finish',
    description: 'End the session with a short briefing for the developers (most urgent first, reference finding ids).',
    parameters: { type: 'object', properties: { summary: { type: 'string' } }, required: ['summary'] },
  },
];

const ACTION: Record<string, AgentAction> = {
  list_findings: 'read',
  get_finding: 'read',
  read_file: 'read',
  search_code: 'read',
  propose_fix: 'suggest_fix',
  write_patch: 'suggest_fix',
  set_verdict: 'verdict',
  finish: 'read',
};

const MAX_RESULT = 6000;
const clip = (s: string) => (s.length > MAX_RESULT ? s.slice(0, MAX_RESULT) + '\n...[truncated]' : s);

function findingOrThrow(s: AgentSession, id: unknown): Finding {
  const f = s.result.findings.find((x) => x.id === id);
  if (!f) throw new Error(`unknown finding id ${String(id)}; use list_findings`);
  return f;
}

function noteInjection(s: AgentSession, source: string, text: string): void {
  const r = detectInjection(text);
  if (!r.flagged) return;
  const file = source.replace(/:\d+-\d+$/, '');
  const seen = s.injections.find((i) => i.source.replace(/:\d+-\d+$/, '') === file);
  if (seen) seen.labels = [...new Set([...seen.labels, ...r.labels])];
  else s.injections.push({ source, labels: r.labels, excerpt: r.excerpt });
}

const TAINTED = /straight from the HTTP request/;

/**
 * The model may not dismiss strong evidence. A "likely false positive" is
 * downgraded to "needs review" when the finding is high-confidence with
 * request taint, a provider-format secret, a known-vulnerable dependency,
 * or when injected instructions were seen in the same file.
 */
export function guardVerdict(s: AgentSession, f: Finding, v: Verdict): Verdict {
  if (v.status !== 'likely_false_positive') return v;
  const injected = s.injections.find((i) => i.source.startsWith(f.location.file));
  let why: string | undefined;
  if (injected) why = `prompt-injection text (${injected.labels.join(', ')}) found in ${f.location.file}`;
  else if (f.confidence === 'high' && TAINTED.test(f.message)) why = 'high-confidence finding with request input reaching the sink';
  else if (f.category === 'secret' && f.confidence === 'high') why = 'provider-format credential';
  else if (f.category === 'dependency' && f.confidence === 'high' && !f.package?.dev)
    why = 'installed version is inside a published advisory range';
  return why ? { ...v, status: 'needs_review', guardrail: `dismissal blocked: ${why}` } : v;
}

function context(s: AgentSession, f: Finding, radius = 8): string {
  if (f.category === 'dependency') return `${f.package?.name}@${f.package?.version} (${f.location.file})`;
  try {
    const rel = s.sandbox.check(f.location.file);
    const content = s.ws.read(rel);
    if (content === null) return '(file not available)';
    const lines = content.split('\n');
    const lo = Math.max(1, f.location.line - radius);
    const hi = Math.min(lines.length, f.location.line + radius);
    const text = lines
      .slice(lo - 1, hi)
      .map((l, i) => `${String(lo + i).padStart(4)}${lo + i === f.location.line ? '>' : ' '} ${l}`)
      .join('\n');
    noteInjection(s, `${rel}:${lo}-${hi}`, text);
    return untrusted(`${rel}:${lo}-${hi}`, text);
  } catch (e) {
    return `(context unavailable: ${(e as Error).message})`;
  }
}

type Impl = (s: AgentSession, a: Record<string, any>) => Promise<unknown> | unknown;

const IMPL: Record<string, Impl> = {
  list_findings: (s, a) =>
    s.result.findings
      .filter((f) => !f.suppressed && (!a.severity || f.severity === a.severity) && (!a.category || f.category === a.category))
      .slice(0, Math.min(50, Number(a.limit) || 20))
      .map((f) => ({
        id: f.id,
        priority: f.priority,
        risk: f.risk,
        severity: f.severity,
        rule: f.ruleId,
        location: `${f.location.file}:${f.location.line}`,
        title: f.title,
        fixAvailable: !!fixerFor(f),
      })),

  get_finding: (s, a) => {
    const f = findingOrThrow(s, a.id);
    const meta = {
      id: f.id,
      rule: f.ruleId,
      title: f.title,
      severity: f.severity,
      confidence: f.confidence,
      category: f.category,
      cwe: f.cwe,
      owasp: f.owasp,
      message: f.message,
      remediation: f.remediation,
      triageNotes: f.triageNotes,
      package: f.package,
      guidance: s.knowledge.guidance(f),
    };
    // code goes after the JSON, unescaped, so the untrusted block stays readable
    return `${JSON.stringify(meta, null, 1)}\n\nCode:\n${context(s, f)}`;
  },

  read_file: (s, a) => {
    const rel = s.sandbox.check(String(a.path));
    const content = s.ws.read(rel);
    if (content === null) throw new Error(`no such file: ${rel}`);
    const lines = content.split('\n');
    const start = Math.max(1, Number(a.start_line) || 1);
    const end = Math.min(lines.length, Number(a.end_line) || start + 199, start + 199);
    const text = lines
      .slice(start - 1, end)
      .map((l, i) => `${String(start + i).padStart(4)}  ${l}`)
      .join('\n');
    noteInjection(s, `${rel}:${start}-${end}`, text);
    return untrusted(`${rel}:${start}-${end}`, text) + (end < lines.length ? `\n(${lines.length - end} more lines)` : '');
  },

  search_code: (s, a) => {
    const q = String(a.query || '');
    if (q.length < 2) throw new Error('query too short');
    s.files ??= loadFiles(s.result.root);
    const hits: string[] = [];
    for (const f of s.files) {
      try {
        s.sandbox.check(f.path);
      } catch {
        continue;
      }
      f.lines.forEach((l, i) => {
        if (hits.length < Math.min(50, Number(a.max_results) || 20) && l.includes(q))
          hits.push(`${f.path}:${i + 1}: ${l.trim().slice(0, 200)}`);
      });
    }
    const text = hits.join('\n') || '(no matches)';
    noteInjection(s, `search:${q}`, text);
    return untrusted(`search "${q}"`, text);
  },

  propose_fix: async (s, a) => {
    const f = findingOrThrow(s, a.id);
    const p = await s.remediation.propose(f, s.ws);
    if (!p) return { available: false, reason: 'no deterministic fixer for this finding, or the code does not have the expected shape' };
    s.fixes.set(f.id, p);
    return { available: true, description: p.description, verified: p.verified, verification: p.verification, diff: p.diff };
  },

  write_patch: async (s, a) => {
    const f = findingOrThrow(s, a.id);
    if (f.category === 'dependency') throw new Error('dependency findings are fixed with propose_fix');
    const rel = s.sandbox.check(f.location.file);
    const before = s.ws.read(rel);
    if (before === null) throw new Error('file not available');
    const lines = before.split('\n');
    const start = Number(a.start_line);
    const end = Number(a.end_line);
    if (!(start >= 1 && end >= start && end <= lines.length)) throw new Error('invalid line range');
    if (Math.abs(start - f.location.line) > 15 || Math.abs(end - f.location.line) > 15)
      throw new Error('patch must stay within 15 lines of the finding');
    const replacement = String(a.replacement ?? '').replace(/\r\n/g, '\n');
    if (replacement.split('\n').length > 40) throw new Error('patch too large (max 40 lines)');
    const after = [...lines.slice(0, start - 1), ...replacement.split('\n'), ...lines.slice(end)].join('\n');
    const v = await verifyFix(f, rel, before, after);
    const p: FixProposal = {
      findingId: f.id,
      strategy: 'ai',
      description: `AI-proposed patch: ${String(a.rationale || '').slice(0, 300)}`,
      file: rel,
      diff: unifiedDiff(rel, before, after),
      newContent: after,
      verified: v.ok,
      verification: v.detail,
    };
    if (!s.fixes.has(f.id) || !s.fixes.get(f.id)!.verified) s.fixes.set(f.id, p);
    return { verified: v.ok, verification: v.detail, diff: p.diff, note: 'AI patches always require human approval' };
  },

  set_verdict: (s, a) => {
    const f = findingOrThrow(s, a.id);
    const status = (
      ['true_positive', 'likely_false_positive', 'needs_review'].includes(a.status) ? a.status : 'needs_review'
    ) as VerdictStatus;
    const confidence = (['high', 'medium', 'low'].includes(a.confidence) ? a.confidence : 'medium') as Verdict['confidence'];
    const v = guardVerdict(s, f, { status, confidence, rationale: String(a.rationale || '').slice(0, 500), by: 'llm' });
    s.verdicts.set(f.id, v);
    return v.guardrail ? { recorded: v.status, guardrail: v.guardrail } : { recorded: v.status };
  },

  finish: (s, a) => {
    s.finished = String(a.summary || '').slice(0, 4000);
    return { ok: true };
  },
};

/** Execute one tool call through policy + audit. Errors are returned to the model, not thrown. */
export async function runTool(s: AgentSession, name: string, args: Record<string, any>): Promise<string> {
  const impl = IMPL[name];
  if (!impl) {
    s.audit.append({ actor: 'agent', action: `tool:${name}`, allowed: false, reason: 'unknown tool' });
    return JSON.stringify({ error: `unknown tool ${name}` });
  }
  const decision = s.policy.decide(ACTION[name]);
  const target = typeof args.id === 'string' ? args.id : typeof args.path === 'string' ? args.path : undefined;
  if (!decision.allowed) {
    s.audit.append({ actor: 'agent', action: `tool:${name}`, target, allowed: false, reason: decision.reason });
    return JSON.stringify({ error: `not allowed: ${decision.reason}` });
  }
  try {
    const out = await impl(s, args);
    s.audit.append({ actor: 'agent', action: `tool:${name}`, target, allowed: true, reason: decision.reason });
    return clip(typeof out === 'string' ? out : JSON.stringify(out, null, 1));
  } catch (e) {
    s.audit.append({ actor: 'agent', action: `tool:${name}`, target, allowed: false, reason: (e as Error).message });
    return JSON.stringify({ error: (e as Error).message });
  }
}
