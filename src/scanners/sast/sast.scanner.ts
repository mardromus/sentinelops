import { Finding, Severity, SourceFile } from '../../common/types';
import { isCommentLine, isSuppressedInline } from '../files';
import { makeFinding, ScanContext, Scanner, snippetAt } from '../scanner';
import { Rule, RULES, TAINT_JS, TAINT_PY } from './rules';

const BUMP: Record<Severity, Severity> = {
  info: 'low',
  low: 'medium',
  medium: 'high',
  high: 'critical',
  critical: 'critical',
};

export function runRule(rule: Rule, file: SourceFile): Finding[] {
  if (!rule.languages.includes(file.language)) return [];
  if (rule.fileRequires && !rule.fileRequires.test(file.content)) return [];
  if (rule.fileUnless && rule.fileUnless.test(file.content)) return [];
  const out: Finding[] = [];
  const taintRe = file.language === 'py' ? TAINT_PY : TAINT_JS;
  file.lines.forEach((line, idx) => {
    if (line.length > 2000 || isCommentLine(line)) return;
    if (!rule.patterns.some((p) => p.test(line))) return;
    if (rule.unless && rule.unless.test(line)) return;
    if (rule.lineRequires && !rule.lineRequires.test(line)) return;
    const tainted = taintRe.test(line);
    const severity = rule.escalateOnTaint && tainted ? BUMP[rule.severity] : rule.severity;
    const suppressed = isSuppressedInline(file.lines, idx);
    out.push(
      makeFinding({
        ruleId: rule.id,
        title: rule.title,
        message: rule.message + (tainted ? ' The value comes straight from the HTTP request.' : ''),
        category: 'sast',
        severity,
        confidence: tainted && rule.confidence === 'medium' ? 'high' : rule.confidence,
        cwe: rule.cwe,
        location: { file: file.path, line: idx + 1, snippet: snippetAt(file, idx + 1) },
        scanner: 'builtin-sast',
        remediation: rule.remediation,
        suppressed,
        suppressReason: suppressed ? 'inline sentinelops-ignore' : undefined,
      }),
    );
  });
  return out;
}

/** Pattern-based static analysis with OWASP/CWE-mapped rules (no external tools needed). */
export class SastScanner implements Scanner {
  readonly name = 'builtin-sast';

  constructor(private readonly rules: Rule[] = RULES) {}

  async scan(ctx: ScanContext): Promise<Finding[]> {
    const out: Finding[] = [];
    for (const file of ctx.files) for (const rule of this.rules) out.push(...runRule(rule, file));
    return out;
  }

  ruleById(id: string): Rule | undefined {
    return this.rules.find((r) => r.id === id);
  }
}
