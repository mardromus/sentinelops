/**
 * GitHub event handling.
 *
 *   pull_request (opened / synchronize / reopened / ready_for_review)
 *       -> scan the head commit, comment, set the "sentinelops" status,
 *          and at L2+ open a fix PR into the PR branch (same-repo PRs only)
 *   issue_comment "/sentinelops rescan" | "/sentinelops fix [SO-xxxxxxxx]"
 *       -> ChatOps, only for users with write access
 *   push to the default branch -> scan and record (no comment)
 */
import { execFile } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { Policy } from '../agent/policy';
import { Finding } from '../common/types';
import { APP_CONFIG, AppConfig } from '../config/config';
import { AuditService } from '../pipeline/audit.service';
import { PipelineService } from '../pipeline/pipeline.service';
import { diskWorkspace, RemediationService } from '../remediation/remediation.service';
import { toMarkdown } from '../reports/markdown';
import { StoredScan } from '../store/scan.store';
import { GithubService } from './github.service';
import { Job, JobsService } from './jobs.service';

const run = promisify(execFile);

export const REPO_FETCHER = Symbol('REPO_FETCHER');
/** Materialise `repo` at `sha` into `dest`. */
export type RepoFetcher = (repo: string, sha: string, ref: string, dest: string, token: string) => Promise<void>;

/** git fetch of exactly one commit; the token travels in the environment, not in argv. */
export const gitFetcher: RepoFetcher = async (repo, sha, ref, dest, token) => {
  const env = { ...process.env, GIT_TERMINAL_PROMPT: '0' } as NodeJS.ProcessEnv;
  if (token) {
    env.GIT_CONFIG_COUNT = '1';
    env.GIT_CONFIG_KEY_0 = 'http.https://github.com/.extraheader';
    env.GIT_CONFIG_VALUE_0 = 'AUTHORIZATION: basic ' + Buffer.from(`x-access-token:${token}`).toString('base64');
  }
  const url = `https://github.com/${repo}.git`;
  await run('git', ['init', '-q', dest], { env });
  try {
    await run('git', ['-C', dest, 'fetch', '-q', '--depth', '1', url, sha], { env, timeout: 300_000 });
  } catch {
    await run('git', ['-C', dest, 'fetch', '-q', '--depth', '1', url, ref], { env, timeout: 300_000 });
  }
  await run('git', ['-C', dest, 'checkout', '-q', 'FETCH_HEAD'], { env });
};

interface PrContext {
  owner: string;
  repo: string;
  number: number;
  sha: string;
  headRef: string;
  headRepo: string;
  baseRef: string;
  sameRepo: boolean;
}

const WRITE = new Set(['admin', 'maintain', 'write']);
const COMMAND = /^\/sentinelops\s+(rescan|fix)(?:\s+(SO-[0-9a-f]{8}))?\s*$/m;

@Injectable()
export class WebhookService {
  private readonly log = new Logger('webhook');
  private readonly fetcher: RepoFetcher;

  constructor(
    private readonly pipeline: PipelineService,
    private readonly github: GithubService,
    private readonly jobs: JobsService,
    private readonly audit: AuditService,
    private readonly remediation: RemediationService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
    @Optional() @Inject(REPO_FETCHER) fetcher?: RepoFetcher,
  ) {
    this.fetcher = fetcher ?? gitFetcher;
  }

  handle(event: string, payload: any): { status: number; body: Record<string, unknown> } {
    if (event === 'ping') return { status: 200, body: { pong: true, zen: payload?.zen } };
    if (event === 'pull_request' && ['opened', 'synchronize', 'reopened', 'ready_for_review'].includes(payload?.action)) {
      const ctx = this.prContext(payload.repository, payload.pull_request);
      const job = this.jobs.enqueue('pull_request', async (j) => {
        await this.reviewPr(j, ctx);
      });
      return { status: 202, body: { queued: true, job: job.id } };
    }
    if (event === 'issue_comment' && payload?.action === 'created' && payload.issue?.pull_request) {
      const m = COMMAND.exec(String(payload.comment?.body || ''));
      if (!m) return { status: 202, body: { ignored: 'not a sentinelops command' } };
      const job = this.jobs.enqueue('command', (j) => this.command(j, payload, m[1] as 'rescan' | 'fix', m[2]));
      return { status: 202, body: { queued: true, job: job.id, command: m[1] } };
    }
    if (event === 'push' && payload?.ref === `refs/heads/${payload?.repository?.default_branch}` && payload.after && !/^0+$/.test(payload.after)) {
      const full = payload.repository.full_name as string;
      const job = this.jobs.enqueue('push', async (j) => {
        await this.withCheckout(full, payload.after, payload.ref, async (dir) => {
          const { stored } = await this.pipeline.run({ root: dir, ai: false, fix: 'propose', source: { kind: 'webhook', repo: full, ref: payload.ref, sha: payload.after } });
          j.scanId = stored.result.id;
        });
      });
      return { status: 202, body: { queued: true, job: job.id } };
    }
    return { status: 202, body: { ignored: `${event}${payload?.action ? '.' + payload.action : ''}` } };
  }

  private prContext(repository: any, pr: any): PrContext {
    const [owner, repo] = String(repository.full_name).split('/');
    return {
      owner,
      repo,
      number: pr.number,
      sha: pr.head.sha,
      headRef: pr.head.ref,
      headRepo: pr.head.repo?.full_name || repository.full_name,
      baseRef: pr.base.ref,
      sameRepo: (pr.head.repo?.full_name || repository.full_name) === repository.full_name,
    };
  }

  private async withCheckout<T>(repo: string, sha: string, ref: string, fn: (dir: string) => Promise<T>): Promise<T> {
    const dir = mkdtempSync(join(tmpdir(), 'sentinelops-'));
    try {
      await this.fetcher(repo, sha, ref, dir, this.config.github.token);
      return await fn(dir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  async reviewPr(job: Job, ctx: PrContext, requestedBy?: string): Promise<StoredScan> {
    const { owner, repo, number, sha } = ctx;
    const target = `${owner}/${repo}#${number}`;
    await this.github.setStatus(owner, repo, sha, 'pending', 'Security review in progress').catch((e) => this.log.warn(e.message));
    return this.withCheckout(ctx.headRepo, sha, `refs/pull/${number}/head`, async (dir) => {
      const { stored } = await this.pipeline.run({
        root: dir,
        ai: true,
        fix: 'propose',
        source: { kind: 'webhook', repo: `${owner}/${repo}`, pr: number, sha, ref: ctx.headRef },
      });
      job.scanId = stored.result.id;
      const link = `${this.config.publicUrl}/api/scans/${stored.result.id}/report.html`;
      const fixPr = await this.maybeOpenFixPr(ctx, stored, dir, requestedBy).catch((e) => {
        this.log.warn(`fix PR for ${target} failed: ${e.message}`);
        return null;
      });
      let body = toMarkdown(stored.result, { gate: stored.gate, agent: stored.agent, diff: stored.diff, title: `SentinelOps security review of ${sha.slice(0, 7)}` });
      if (fixPr) body += `\n🔧 Verified fixes are in ${fixPr.url} (${fixPr.draft ? 'draft, needs your review' : 'ready for review'}).\n`;
      body += `\n[Full report](${link})\n`;
      await this.github.upsertComment(owner, repo, number, body);
      const active = stored.summary.active;
      await this.github.setStatus(owner, repo, sha, stored.gate.pass ? 'success' : 'failure', stored.gate.pass ? `${active} finding(s), none at or above ${stored.gate.failOn}` : `${stored.gate.blocking} blocking finding(s) at or above ${stored.gate.failOn}`, link);
      this.audit.append({ actor: 'agent', action: 'github:review', target, allowed: true, details: { scan: stored.result.id, gate: stored.gate, fixPr: fixPr?.url } });
      return stored;
    });
  }

  /** Policy-gated: L2 drafts, L3 ready-for-review for low-risk fixes; a human "/sentinelops fix" counts as approval. */
  private async maybeOpenFixPr(ctx: PrContext, stored: StoredScan, dir: string, requestedBy?: string, only?: string): Promise<{ url: string; draft: boolean } | null> {
    const target = `${ctx.owner}/${ctx.repo}#${ctx.number}`;
    if (!ctx.sameRepo) {
      this.audit.append({ actor: 'agent', action: 'github:open_pr', target, allowed: false, reason: 'pull request comes from a fork; fixes are suggested in the comment only' });
      return null;
    }
    const policy = new Policy(this.config.autonomy);
    const candidates = stored.result.findings.filter((f) => !f.suppressed && f.fix?.verified && (!only || f.id === only));
    const chosen: Finding[] = [];
    let draft = false;
    for (const f of candidates) {
      const d = requestedBy ? { allowed: this.config.autonomy >= 1, needsApproval: false, reason: `requested by @${requestedBy}` } : policy.decide('open_pr', { fix: f.fix, finding: f });
      this.audit.append({ actor: requestedBy ? 'human' : 'agent', action: 'github:open_pr', target: f.id, allowed: d.allowed, reason: d.reason });
      if (!d.allowed) continue;
      chosen.push(f);
      draft ||= d.needsApproval;
    }
    if (!chosen.length) return null;
    const res = await this.remediation.apply(chosen, diskWorkspace(dir), { dryRun: true });
    if (!res.files.length) return null;
    const branch = `sentinelops/fix-${ctx.number}-${ctx.sha.slice(0, 7)}`;
    const lines = res.applied.map((p) => `- **${p.findingId}** ${p.description} _(verified: ${p.verification})_`);
    const pr = await this.github.openFixPr(ctx.owner, ctx.repo, {
      base: ctx.headRef,
      branch,
      files: res.files.map((f) => ({ path: f.path, content: f.content })),
      title: `SentinelOps: ${res.applied.length} verified security fix(es) for #${ctx.number}`,
      body: [
        `Fixes for findings in #${ctx.number} (${ctx.sha.slice(0, 7)}). Each change was re-scanned and syntax-checked before this PR was opened.`,
        '',
        ...lines,
        '',
        requestedBy ? `Requested by @${requestedBy}.` : `Opened by the SentinelOps agent at autonomy ${policy.name}. A human must review and merge.`,
      ].join('\n'),
      draft,
    });
    this.audit.append({ actor: requestedBy ? 'human' : 'agent', action: 'github:pr_opened', target, allowed: true, details: { url: pr.url, branch, draft, fixes: res.applied.map((p) => p.findingId) } });
    return { url: pr.url, draft };
  }

  private async command(job: Job, payload: any, cmd: 'rescan' | 'fix', findingId?: string): Promise<void> {
    const [owner, repo] = String(payload.repository.full_name).split('/');
    const user = String(payload.comment.user?.login || '');
    const perm = await this.github.permission(owner, repo, user);
    const allowed = WRITE.has(perm);
    this.audit.append({ actor: 'human', action: `github:command:${cmd}`, target: `${owner}/${repo}#${payload.issue.number}`, allowed, reason: `@${user} has ${perm} access`, details: { findingId } });
    if (!allowed) {
      job.detail = `@${user} needs write access (has ${perm})`;
      return;
    }
    // issue_comment payloads do not carry the PR head: look it up
    const pr = await this.github.getPull(owner, repo, payload.issue.number);
    const ctx = this.prContext(payload.repository, pr);
    if (cmd === 'rescan') {
      await this.reviewPr(job, ctx);
      return;
    }
    await this.withCheckout(ctx.headRepo, ctx.sha, `refs/pull/${ctx.number}/head`, async (dir) => {
      const { stored } = await this.pipeline.run({ root: dir, ai: false, fix: 'propose', source: { kind: 'webhook', repo: `${owner}/${repo}`, pr: ctx.number, sha: ctx.sha } });
      job.scanId = stored.result.id;
      const fixPr = await this.maybeOpenFixPr(ctx, stored, dir, user, findingId);
      const msg = fixPr ? `🔧 @${user} opened ${fixPr.url} with the verified fix(es).` : `@${user} no verified fix is available${findingId ? ` for ${findingId}` : ''}${ctx.sameRepo ? '' : ' (fork PRs only get suggestions)'}.`;
      await this.github.comment(owner, repo, ctx.number, msg);
    });
  }
}
