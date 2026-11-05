/**
 * Autonomy levels. The level caps what the agent may do on its own; every
 * decision (allowed or not) goes to the audit log with its reason.
 *
 *   L0 observe   scan and report; no external side effects
 *   L1 advise    + triage verdicts, PR comments and suggested patches       (default)
 *   L2 assist    + push verified fixes to a branch and open a draft PR for a human to merge
 *   L3 autonomous+ open ready-for-review fix PRs for low-risk verified fixes without asking
 *
 * Invariants at every level:
 *   - the agent never merges, never pushes to the default branch, never force-pushes
 *   - the agent never suppresses a finding; it can only recommend it to a human
 *   - unverified or AI-written patches always need human approval
 */
import { AutonomyLevel } from '../config/config';
import { compareVersions } from '../scanners/deps/version';
import { diffStats } from '../remediation/diff';
import { Finding, FixProposal } from '../common/types';

export type AgentAction =
  'read' | 'verdict' | 'comment' | 'suggest_fix' | 'commit_fix' | 'open_pr' | 'suppress' | 'merge' | 'push_default_branch';

export interface Decision {
  allowed: boolean;
  needsApproval: boolean;
  reason: string;
}

export const LEVEL_NAMES: Record<AutonomyLevel, string> = { 0: 'observe', 1: 'advise', 2: 'assist', 3: 'autonomous' };

const MIN_LEVEL: Record<AgentAction, AutonomyLevel | null> = {
  read: 0,
  verdict: 1,
  comment: 1,
  suggest_fix: 1,
  commit_fix: 2,
  open_pr: 2,
  suppress: null, // humans only
  merge: null,
  push_default_branch: null,
};

/** A fix is "low risk" when it is verified, deterministic and small (or a same-major dependency bump). */
export function isLowRiskFix(fix: FixProposal, finding?: Finding): { low: boolean; why: string } {
  if (!fix.verified) return { low: false, why: 'fix is not verified' };
  if (fix.strategy === 'ai') return { low: false, why: 'AI-written patches need human review' };
  if (fix.strategy === 'dependency' && finding?.package?.fixedIn) {
    const major = (v: string) => v.replace(/^[^\d]*/, '').split('.')[0];
    if (
      major(finding.package.version) !== major(finding.package.fixedIn) &&
      compareVersions(finding.package.fixedIn, finding.package.version) > 0
    )
      return { low: false, why: `major version change ${finding.package.version} -> ${finding.package.fixedIn}` };
    return { low: true, why: 'same-major dependency upgrade outside the affected range' };
  }
  const { added, removed } = diffStats(fix.diff);
  if (added + removed > 30) return { low: false, why: `large change (${added + removed} lines)` };
  return { low: true, why: `verified rule-based fix, ${added + removed} changed lines` };
}

export class Policy {
  constructor(readonly level: AutonomyLevel) {}

  get name(): string {
    return `L${this.level} ${LEVEL_NAMES[this.level]}`;
  }

  decide(action: AgentAction, ctx: { fix?: FixProposal; finding?: Finding } = {}): Decision {
    const min = MIN_LEVEL[action];
    if (min === null) return { allowed: false, needsApproval: true, reason: `${action} is reserved for humans at every autonomy level` };
    if (this.level < min) return { allowed: false, needsApproval: true, reason: `${action} requires L${min}, running at ${this.name}` };
    if (action === 'commit_fix' || action === 'open_pr') {
      if (!ctx.fix) return { allowed: false, needsApproval: true, reason: 'no fix proposal' };
      const risk = isLowRiskFix(ctx.fix, ctx.finding);
      if (!ctx.fix.verified) return { allowed: false, needsApproval: true, reason: risk.why };
      if (this.level === 3 && risk.low) return { allowed: true, needsApproval: false, reason: `L3: ${risk.why}` };
      // L2 (or L3 with a riskier fix): prepare it, but a human must approve / merge
      return { allowed: true, needsApproval: true, reason: `${this.name}: ${risk.why}; draft PR for human approval` };
    }
    return { allowed: true, needsApproval: false, reason: `${action} allowed at ${this.name}` };
  }
}
