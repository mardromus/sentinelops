/**
 * GitHub REST integration: webhook signatures, PR comments, commit
 * statuses, permission checks and fix pull requests (via the Git data API,
 * so no local push credentials are needed).
 *
 * Invariant: fixes always go to a new "sentinelops/..." branch. This service
 * has no method that writes to an existing branch.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { Inject, Injectable, Optional } from '@nestjs/common';
import { APP_CONFIG, AppConfig } from '../config/config';
import { COMMENT_MARKER } from '../reports/markdown';

export const GITHUB_HTTP = Symbol('GITHUB_HTTP');
export type HttpFn = (url: string, init: { method: string; headers: Record<string, string>; body?: string }) => Promise<{ ok: boolean; status: number; json(): Promise<any>; text(): Promise<string> }>;

/** X-Hub-Signature-256 check (HMAC-SHA256 of the raw body), constant time. */
export function verifySignature(secret: string, rawBody: Buffer | string, header: string | undefined): boolean {
  if (!secret || !header || !header.startsWith('sha256=')) return false;
  const expected = Buffer.from('sha256=' + createHmac('sha256', secret).update(rawBody).digest('hex'));
  const got = Buffer.from(header);
  return got.length === expected.length && timingSafeEqual(got, expected);
}

export class GithubError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

@Injectable()
export class GithubService {
  private readonly http: HttpFn;

  constructor(
    @Inject(APP_CONFIG) private readonly config: AppConfig,
    @Optional() @Inject(GITHUB_HTTP) http?: HttpFn,
  ) {
    this.http = http ?? (fetch as unknown as HttpFn);
  }

  get configured(): boolean {
    return !!this.config.github.token;
  }

  private async api<T = any>(method: string, path: string, body?: unknown): Promise<T> {
    if (!this.config.github.token) throw new GithubError(401, 'GITHUB_TOKEN is not configured');
    const res = await this.http(this.config.github.apiUrl + path, {
      method,
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${this.config.github.token}`,
        'x-github-api-version': '2022-11-28',
        'user-agent': 'sentinelops',
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) throw new GithubError(res.status, `GitHub ${method} ${path} -> ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return res.status === 204 ? (undefined as T) : ((await res.json()) as T);
  }

  /** Create or update the single SentinelOps comment on a pull request. */
  async upsertComment(owner: string, repo: string, pr: number, body: string): Promise<{ id: number; updated: boolean }> {
    const comments = await this.api<any[]>('GET', `/repos/${owner}/${repo}/issues/${pr}/comments?per_page=100`);
    const mine = comments.find((c) => typeof c.body === 'string' && c.body.includes(COMMENT_MARKER));
    if (mine) {
      await this.api('PATCH', `/repos/${owner}/${repo}/issues/comments/${mine.id}`, { body });
      return { id: mine.id, updated: true };
    }
    const created = await this.api<{ id: number }>('POST', `/repos/${owner}/${repo}/issues/${pr}/comments`, { body });
    return { id: created.id, updated: false };
  }

  async comment(owner: string, repo: string, issue: number, body: string): Promise<void> {
    await this.api('POST', `/repos/${owner}/${repo}/issues/${issue}/comments`, { body });
  }

  async getPull(owner: string, repo: string, n: number): Promise<any> {
    return this.api('GET', `/repos/${owner}/${repo}/pulls/${n}`);
  }

  async setStatus(owner: string, repo: string, sha: string, state: 'pending' | 'success' | 'failure' | 'error', description: string, targetUrl?: string): Promise<void> {
    await this.api('POST', `/repos/${owner}/${repo}/statuses/${sha}`, { state, context: 'sentinelops', description: description.slice(0, 140), target_url: targetUrl });
  }

  /** "admin" | "maintain" | "write" | "triage" | "read" | "none" */
  async permission(owner: string, repo: string, user: string): Promise<string> {
    try {
      const r = await this.api<{ permission: string; role_name?: string }>('GET', `/repos/${owner}/${repo}/collaborators/${encodeURIComponent(user)}/permission`);
      return r.role_name === 'maintain' ? 'maintain' : r.permission;
    } catch (e) {
      if (e instanceof GithubError && e.status === 404) return 'none';
      throw e;
    }
  }

  /** Commit `files` on top of `base` in a new branch and open a pull request into `base`. */
  async openFixPr(
    owner: string,
    repo: string,
    opts: { base: string; branch: string; files: { path: string; content: string }[]; title: string; body: string; draft: boolean },
  ): Promise<{ number: number; url: string; branch: string }> {
    if (!opts.branch.startsWith('sentinelops/')) throw new Error('fix branches must live under sentinelops/');
    if (opts.branch === opts.base) throw new Error('refusing to write to the base branch');
    if (!opts.files.length) throw new Error('no files to commit');
    const base = await this.api<{ object: { sha: string } }>('GET', `/repos/${owner}/${repo}/git/ref/heads/${encodeURIComponent(opts.base)}`);
    const baseSha = base.object.sha;
    const baseCommit = await this.api<{ tree: { sha: string } }>('GET', `/repos/${owner}/${repo}/git/commits/${baseSha}`);
    const tree = [];
    for (const f of opts.files) {
      const blob = await this.api<{ sha: string }>('POST', `/repos/${owner}/${repo}/git/blobs`, { content: Buffer.from(f.content).toString('base64'), encoding: 'base64' });
      tree.push({ path: f.path, mode: '100644', type: 'blob', sha: blob.sha });
    }
    const newTree = await this.api<{ sha: string }>('POST', `/repos/${owner}/${repo}/git/trees`, { base_tree: baseCommit.tree.sha, tree });
    const commit = await this.api<{ sha: string }>('POST', `/repos/${owner}/${repo}/git/commits`, { message: opts.title, tree: newTree.sha, parents: [baseSha] });
    await this.api('POST', `/repos/${owner}/${repo}/git/refs`, { ref: `refs/heads/${opts.branch}`, sha: commit.sha });
    const pr = await this.api<{ number: number; html_url: string }>('POST', `/repos/${owner}/${repo}/pulls`, { title: opts.title, head: opts.branch, base: opts.base, body: opts.body, draft: opts.draft });
    return { number: pr.number, url: pr.html_url, branch: opts.branch };
  }

  cloneUrl(fullName: string): string {
    const t = this.config.github.token;
    return t ? `https://x-access-token:${t}@github.com/${fullName}.git` : `https://github.com/${fullName}.git`;
  }
}
