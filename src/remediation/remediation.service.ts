import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Injectable } from '@nestjs/common';
import { Finding, FixProposal, ScanResult } from '../common/types';
import { lineMapper, unifiedDiff } from './diff';
import { FIXERS, fixerFor } from './fixers';
import { verifyFix } from './verify';

export interface ApplyResult {
  applied: FixProposal[];
  resolved: { findingId: string; by: string }[]; // fixed as a side effect of an earlier fix in the same run
  skipped: { findingId: string; reason: string }[];
  files: { path: string; diff: string; content: string }[];
}

/** Reads/writes files relative to a scan root; swappable in tests and for PR branches. */
export interface Workspace {
  read(path: string): string | null;
  write(path: string, content: string): void;
}

export const diskWorkspace = (root: string): Workspace => ({
  read: (p) => (existsSync(join(root, p)) ? readFileSync(join(root, p), 'utf8') : null),
  write: (p, c) => writeFileSync(join(root, p), c),
});

export const memoryWorkspace = (files: Record<string, string>): Workspace & { files: Record<string, string> } => ({
  files,
  read: (p) => files[p] ?? null,
  write: (p, c) => {
    files[p] = c;
  },
});

@Injectable()
export class RemediationService {
  /** A verified (or explicitly unverified) fix for one finding, computed against `content`. */
  async propose(f: Finding, ws: Workspace, content?: string): Promise<FixProposal | null> {
    const target = fixerFor(f);
    if (!target) return null;
    const before = content ?? ws.read(target.file);
    if (before === null) return null;
    const out = FIXERS[target.id]({ finding: f, path: target.file, content: before });
    if (!out || out.content === before) return null;
    const v = await verifyFix(f, target.file, before, out.content);
    return {
      findingId: f.id,
      strategy: f.category === 'dependency' ? 'dependency' : 'rule',
      description: out.description + (out.notes?.length ? ` Note: ${out.notes.join(' ')}` : ''),
      file: target.file,
      diff: unifiedDiff(target.file, before, out.content),
      newContent: out.content,
      verified: v.ok,
      verification: v.detail,
    };
  }

  /** Attach a proposed fix to every active finding that has a deterministic fixer. */
  async proposeAll(result: ScanResult, ws: Workspace): Promise<number> {
    let n = 0;
    for (const f of result.findings) {
      if (f.suppressed) continue;
      const p = await this.propose(f, ws);
      if (p) {
        f.fix = p;
        n++;
      }
    }
    return n;
  }

  /** Did an earlier fix in this run already remove this finding? Returns the id of that fix. */
  private async resolvedBy(f: Finding, file: string, original: string, current: string, applied: FixProposal[]): Promise<string | null> {
    const earlier = applied.filter((p) => p.file === file);
    if (!earlier.length) return null;
    if (f.category === 'dependency' && f.package?.fixedIn) {
      const want = f.package.fixedIn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const pinned = new RegExp(`"${f.package.name.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}"\\s*:\\s*"\\^?${want}"|^${f.package.name}==${want}\\b`, 'mi');
      return pinned.test(current) ? earlier[earlier.length - 1].findingId : null;
    }
    const v = await verifyFix(f, file, original, current);
    return v.ok ? earlier[earlier.length - 1].findingId : null;
  }

  /**
   * Apply fixes for the selected findings. Fixes for the same file are
   * applied one after another on the evolving content (each fixer re-locates
   * its line), and only verified fixes are kept unless `allowUnverified`.
   */
  async apply(findings: Finding[], ws: Workspace, opts: { allowUnverified?: boolean; dryRun?: boolean } = {}): Promise<ApplyResult> {
    const res: ApplyResult = { applied: [], resolved: [], skipped: [], files: [] };
    const original = new Map<string, string>();
    const current = new Map<string, string>();
    const moves = new Map<string, ((line: number) => number)[]>(); // line maps of fixes already applied per file
    for (const f of findings) {
      const target = fixerFor(f);
      if (!target) {
        res.skipped.push({ findingId: f.id, reason: 'no deterministic fixer for this rule' });
        continue;
      }
      if (!current.has(target.file)) {
        const c = ws.read(target.file);
        if (c === null) {
          res.skipped.push({ findingId: f.id, reason: `${target.file} not found` });
          continue;
        }
        original.set(target.file, c);
        current.set(target.file, c);
      }
      // earlier fixes in the same file may have moved this finding's line
      const line = (moves.get(target.file) || []).reduce((l, m) => m(l), f.location.line);
      const located = target.file === f.location.file ? { ...f, location: { ...f.location, line } } : f;
      const prev = current.get(target.file)!;
      const p = await this.propose(located, ws, prev);
      if (!p) {
        const by = prev !== original.get(target.file) ? await this.resolvedBy(located, target.file, original.get(target.file)!, prev, res.applied) : null;
        if (by) res.resolved.push({ findingId: f.id, by });
        else res.skipped.push({ findingId: f.id, reason: 'no fix for this exact code shape; needs a manual change' });
        continue;
      }
      if (!p.verified && !opts.allowUnverified) {
        res.skipped.push({ findingId: f.id, reason: `verification failed: ${p.verification}` });
        continue;
      }
      current.set(target.file, p.newContent!);
      moves.set(target.file, [...(moves.get(target.file) || []), lineMapper(prev, p.newContent!)]);
      p.applied = !opts.dryRun;
      f.fix = p;
      res.applied.push(p);
    }
    for (const [path, content] of current) {
      const before = original.get(path)!;
      if (content === before) continue;
      if (!opts.dryRun) ws.write(path, content);
      res.files.push({ path, diff: unifiedDiff(path, before, content), content });
    }
    return res;
  }
}
