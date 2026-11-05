/**
 * Triage turns raw findings into a work queue.
 *
 *   risk (0-100) = severity base x confidence
 *                  + exposure (request input reaches the sink, production path, direct dependency)
 *                  - discounts (test/example code, dev-only dependency)
 *   priority     = P1 (>= 80) fix now, P2 (>= 60) this sprint, P3 (>= 35) backlog, P4 informational
 *
 * Every adjustment is written to triageNotes so a developer can see why a
 * finding landed where it did. Nothing here is a black box.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Injectable } from '@nestjs/common';
import { Confidence, Finding, Priority, ScanResult, Severity } from '../common/types';

const BASE: Record<Severity, number> = { critical: 90, high: 70, medium: 45, low: 22, info: 5 };
const CONF: Record<Confidence, number> = { high: 1, medium: 0.85, low: 0.65 };

export const NON_PRODUCTION_PATH =
  /(^|\/)(tests?|__tests__|spec|specs|fixtures?|examples?|samples?|docs?|mocks?|__mocks__|testdata|e2e)(\/|$)|\.(test|spec)\.[jt]sx?$|_test\.py$|(^|\/)test_[^/]+\.py$/i;
const PRODUCTION_PATH = /(^|\/)(src|app|server|api|lib|routes|controllers|services)(\/|$)/i;

export interface BaselineEntry {
  fingerprint: string;
  reason: string;
  until?: string; // ISO date; expired entries stop suppressing
}

export function priorityFor(risk: number): Priority {
  if (risk >= 80) return 'P1';
  if (risk >= 60) return 'P2';
  if (risk >= 35) return 'P3';
  return 'P4';
}

export function scoreFinding(f: Finding): { risk: number; notes: string[] } {
  const notes: string[] = [];
  let risk = BASE[f.severity] * CONF[f.confidence];
  const path = f.location.file;

  if (/straight from the HTTP request/.test(f.message)) {
    risk += 8;
    notes.push('+8 request input flows directly into the sink');
  }
  if (f.category === 'secret' && f.confidence === 'high') {
    risk += 5;
    notes.push('+5 provider-format credential (usable as-is)');
  }
  if (f.category === 'dependency' && f.package) {
    if (f.package.dev) {
      risk -= 20;
      notes.push('-20 dev-only dependency (not shipped to production)');
    } else if (f.package.direct) {
      risk += 5;
      notes.push('+5 direct dependency');
    }
    if (!f.package.fixedIn) notes.push('no fixed version published yet');
  }
  if (NON_PRODUCTION_PATH.test(path)) {
    risk *= 0.45;
    notes.push('x0.45 test/example/docs path, likely not deployed');
  } else if (PRODUCTION_PATH.test(path) && f.category !== 'dependency') {
    risk += 4;
    notes.push('+4 application source path');
  }
  return { risk: Math.max(0, Math.min(100, Math.round(risk))), notes };
}

export function loadBaseline(root: string): BaselineEntry[] {
  const p = join(root, '.sentinelops', 'baseline.json');
  if (!existsSync(p)) return [];
  try {
    const doc = JSON.parse(readFileSync(p, 'utf8'));
    return Array.isArray(doc) ? doc : doc.entries || [];
  } catch {
    return [];
  }
}

export interface ScanDiff {
  introduced: Finding[];
  fixed: Finding[];
  unchanged: Finding[];
}

/** Compare two scans by fingerprint: what a pull request introduces or fixes. */
export function diffScans(before: Finding[], after: Finding[]): ScanDiff {
  const b = new Map(before.map((f) => [f.fingerprint, f]));
  const a = new Map(after.map((f) => [f.fingerprint, f]));
  return {
    introduced: after.filter((f) => !b.has(f.fingerprint)),
    fixed: before.filter((f) => !a.has(f.fingerprint)),
    unchanged: after.filter((f) => b.has(f.fingerprint)),
  };
}

@Injectable()
export class TriageService {
  triage(result: ScanResult, opts: { baseline?: BaselineEntry[]; now?: Date } = {}): ScanResult {
    const now = opts.now ?? new Date();
    const baseline = new Map((opts.baseline ?? loadBaseline(result.root)).map((e) => [e.fingerprint, e]));
    for (const f of result.findings) {
      const { risk, notes } = scoreFinding(f);
      f.risk = risk;
      f.priority = priorityFor(risk);
      f.triageNotes = [...(f.triageNotes || []).filter((n) => /^also reported by/.test(n)), ...notes];
      const b = baseline.get(f.fingerprint);
      if (b && !f.suppressed && (!b.until || new Date(b.until) > now)) {
        f.suppressed = true;
        f.suppressReason = `baseline: ${b.reason}`;
      }
    }
    result.findings.sort(
      (x, y) =>
        Number(!!x.suppressed) - Number(!!y.suppressed) ||
        (y.risk ?? 0) - (x.risk ?? 0) ||
        x.location.file.localeCompare(y.location.file) ||
        x.location.line - y.location.line,
    );
    return result;
  }

  summary(result: ScanResult) {
    const active = result.findings.filter((f) => !f.suppressed);
    const count = <K extends string>(key: (f: Finding) => K) =>
      active.reduce<Record<string, number>>((acc, f) => ((acc[key(f)] = (acc[key(f)] || 0) + 1), acc), {});
    return {
      total: result.findings.length,
      active: active.length,
      suppressed: result.findings.length - active.length,
      bySeverity: count((f) => f.severity),
      byPriority: count((f) => f.priority || 'P4'),
      byCategory: count((f) => f.category),
      riskScore: active.length
        ? Math.round(Math.max(...active.map((f) => f.risk ?? 0)) * 0.6 + Math.min(40, active.reduce((s, f) => s + (f.risk ?? 0), 0) / 25))
        : 0,
    };
  }

  /** CI gate: fail when any active finding is at or above the threshold. */
  gate(result: ScanResult, failOn: Severity): { pass: boolean; blocking: Finding[] } {
    const order: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
    const blocking = result.findings.filter((f) => !f.suppressed && order.indexOf(f.severity) >= order.indexOf(failOn));
    return { pass: blocking.length === 0, blocking };
  }
}
