/**
 * End-to-end: the real Nest application over HTTP, scanning the bundled
 * vulnerable demo. GitHub and git are replaced by in-memory fakes so the
 * whole pull-request flow (status -> scan -> comment -> fix PR) is exercised
 * without network access.
 */
import { createHmac } from 'node:crypto';
import { cpSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { AppConfig, loadConfig } from '../src/config/config';
import { GITHUB_HTTP } from '../src/github/github.service';
import { JobsService } from '../src/github/jobs.service';
import { REPO_FETCHER } from '../src/github/webhook.service';
import { configureApp } from '../src/main';

const REPO = resolve(__dirname, '..');
const DEMO = join(REPO, 'demo', 'vulnerable-shop');
const SECRET = 'webhook-test-secret';

interface Call {
  method: string;
  path: string;
  body?: any;
}

function fakeGithub(perm = 'write') {
  const calls: Call[] = [];
  let n = 0;
  const http = async (url: string, init: { method: string; body?: string }) => {
    const path = url.replace('https://api.github.test', '');
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method: init.method, path, body });
    const ok = (json: unknown, status = 200) => ({ ok: true, status, json: async () => json, text: async () => JSON.stringify(json) });
    if (init.method === 'GET' && /\/issues\/\d+\/comments/.test(path)) return ok([]);
    if (init.method === 'GET' && /\/collaborators\/.+\/permission$/.test(path)) return ok({ permission: perm });
    if (init.method === 'GET' && /\/pulls\/7$/.test(path)) return ok(pr());
    if (init.method === 'GET' && /\/git\/ref\/heads\//.test(path)) return ok({ object: { sha: 'b'.repeat(40) } });
    if (init.method === 'GET' && /\/git\/commits\//.test(path)) return ok({ tree: { sha: 't'.repeat(40) } });
    if (/\/git\/(blobs|trees|commits)$/.test(path)) return ok({ sha: `sha${++n}` }, 201);
    if (/\/git\/refs$/.test(path)) return ok({}, 201);
    if (/\/pulls$/.test(path)) return ok({ number: 8, html_url: 'https://github.test/acme/shop/pull/8' }, 201);
    return ok({ id: ++n }, 201);
  };
  return { calls, http };
}

const pr = () => ({
  number: 7,
  head: { sha: 'a'.repeat(40), ref: 'feature/cart', repo: { full_name: 'acme/shop' } },
  base: { ref: 'main' },
});
const sign = (body: string) => 'sha256=' + createHmac('sha256', SECRET).update(body).digest('hex');

async function boot(overrides: Partial<AppConfig>, github = fakeGithub()) {
  const dataDir = mkdtempSync(join(tmpdir(), 'so-e2e-'));
  const base = loadConfig({});
  const moduleRef = await Test.createTestingModule({
    imports: [
      AppModule.forRoot({
        dataDir,
        scanRoots: [REPO],
        osv: false,
        external: false,
        github: { token: 'test-token', webhookSecret: SECRET, apiUrl: 'https://api.github.test' },
        llm: { ...base.llm, apiKey: '' },
        apiToken: '',
        ...overrides,
      }),
    ],
  })
    .overrideProvider(GITHUB_HTTP)
    .useValue(github.http)
    .overrideProvider(REPO_FETCHER)
    .useValue(async (_repo: string, _sha: string, _ref: string, dest: string) => cpSync(DEMO, dest, { recursive: true }))
    .compile();
  const app = configureApp(moduleRef.createNestApplication<NestExpressApplication>({ rawBody: true, logger: false }));
  await app.init();
  return { app, http: request(app.getHttpServer()), github, jobs: app.get(JobsService) };
}

describe('HTTP API (e2e)', () => {
  let ctx: Awaited<ReturnType<typeof boot>>;
  beforeAll(async () => {
    ctx = await boot({ autonomy: 1 });
  });
  afterAll(async () => ctx.app.close());

  it('reports health and security headers', async () => {
    const res = await ctx.http.get('/api/health').expect(200);
    expect(res.body).toMatchObject({ status: 'ok', autonomy: 'L1 advise', llm: { configured: false } });
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  it('scans the demo and serves every report format', async () => {
    const res = await ctx.http.post('/api/scans').send({ path: 'demo/vulnerable-shop', ai: true }).expect(201);
    expect(res.body.gate).toMatchObject({ pass: false, failOn: 'high' });
    expect(res.body.summary.active).toBeGreaterThan(50);
    expect(res.body.agent).toMatchObject({ mode: 'offline' });
    const id = res.body.id;

    const html = await ctx.http.get(`/api/scans/${id}/report.html`).expect(200);
    expect(html.headers['content-type']).toContain('text/html');
    expect(html.headers['x-frame-options']).toBe('SAMEORIGIN');
    expect(html.text).toContain('so-data');

    const sarif = await ctx.http.get(`/api/scans/${id}/sarif`).expect(200);
    expect(JSON.parse(sarif.text).version).toBe('2.1.0');
    const md = await ctx.http.get(`/api/scans/${id}/report.md`).expect(200);
    expect(md.text).toContain('<!-- sentinelops:report -->');

    const full = await ctx.http.get(`/api/scans/${id}`).expect(200);
    const fixed = full.body.result.findings.find((f: any) => f.fix?.verified);
    const diff = await ctx.http.get(`/api/scans/${id}/findings/${fixed.id}/fix.diff`).expect(200);
    expect(diff.text).toMatch(/^--- a\//);

    const list = await ctx.http.get('/api/scans').expect(200);
    expect(list.body[0].id).toBe(id);
    const audit = await ctx.http.get('/api/audit').expect(200);
    expect(audit.body.valid).toBe(true);
    expect(audit.body.entries.some((e: any) => e.action === 'session:end')).toBe(true);
  });

  it('refuses paths outside the scan roots and unknown ids', async () => {
    await ctx.http.post('/api/scans').send({ path: '../../../etc' }).expect(403);
    await ctx.http.get('/api/scans/../../etc/passwd').expect(404);
    await ctx.http.get('/api/scans/not-a-uuid').expect(404);
    await ctx.http.post('/api/scans').send({ failOn: 'whenever' }).expect(400);
  });

  it('lists rules with OWASP mapping and autofix flags', async () => {
    const res = await ctx.http.get('/api/rules').expect(200);
    const sqli = res.body.find((r: any) => r.id === 'js.sqli.string-built-query');
    expect(sqli).toMatchObject({ owasp: ['A03:2021'], autofix: true });
  });

  it('serves the dashboard', async () => {
    const res = await ctx.http.get('/').expect(200);
    expect(res.text).toContain('<title>SentinelOps</title>');
    expect(res.headers['content-security-policy']).toContain("default-src 'self'");
  });
});

describe('API token guard (e2e)', () => {
  it('requires the bearer token for scans when configured', async () => {
    const ctx = await boot({ apiToken: 's3cret-token' });
    await ctx.http.post('/api/scans').send({ path: 'demo/vulnerable-shop' }).expect(401);
    await ctx.http.post('/api/scans').set('authorization', 'Bearer wrong-token!').send({ path: 'demo/vulnerable-shop' }).expect(401);
    await ctx.http
      .post('/api/scans')
      .set('authorization', 'Bearer s3cret-token')
      .send({ path: 'demo/vulnerable-shop', fix: false })
      .expect(201);
    await ctx.app.close();
  });
});

describe('GitHub webhook (e2e)', () => {
  it('rejects unsigned and mis-signed deliveries, answers ping', async () => {
    const ctx = await boot({});
    const ping = JSON.stringify({ zen: 'Keep it logically awesome.' });
    await ctx.http.post('/webhooks/github').set('x-github-event', 'ping').set('content-type', 'application/json').send(ping).expect(401);
    await ctx.http
      .post('/webhooks/github')
      .set('x-github-event', 'ping')
      .set('x-hub-signature-256', sign(ping + ' '))
      .set('content-type', 'application/json')
      .send(ping)
      .expect(401);
    const ok = await ctx.http
      .post('/webhooks/github')
      .set('x-github-event', 'ping')
      .set('x-hub-signature-256', sign(ping))
      .set('content-type', 'application/json')
      .send(ping)
      .expect(200);
    expect(ok.body.pong).toBe(true);
    await ctx.app.close();
  });

  it('reviews a pull request: status, comment and (at L2) a draft fix PR into the PR branch', async () => {
    const ctx = await boot({ autonomy: 2 });
    const body = JSON.stringify({ action: 'opened', repository: { full_name: 'acme/shop', default_branch: 'main' }, pull_request: pr() });
    const res = await ctx.http
      .post('/webhooks/github')
      .set('x-github-event', 'pull_request')
      .set('x-hub-signature-256', sign(body))
      .set('content-type', 'application/json')
      .send(body)
      .expect(202);
    expect(res.body.queued).toBe(true);
    await ctx.jobs.idle();
    const job = ctx.jobs.get(res.body.job)!;
    expect(job).toMatchObject({ status: 'done' });

    const calls = ctx.github.calls;
    const statuses = calls.filter((c) => /\/statuses\//.test(c.path)).map((c) => c.body.state);
    expect(statuses).toEqual(['pending', 'failure']);
    const comment = calls.find((c) => c.method === 'POST' && /\/issues\/7\/comments$/.test(c.path))!;
    expect(comment.body.body).toContain('<!-- sentinelops:report -->');
    expect(comment.body.body).toContain('https://github.test/acme/shop/pull/8');
    const pull = calls.find((c) => c.method === 'POST' && /\/pulls$/.test(c.path))!;
    expect(pull.body).toMatchObject({ base: 'feature/cart', head: 'sentinelops/fix-7-aaaaaaa', draft: true });
    const ref = calls.find((c) => /\/git\/refs$/.test(c.path))!;
    expect(ref.body.ref).toBe('refs/heads/sentinelops/fix-7-aaaaaaa');
    expect(calls.filter((c) => /\/git\/blobs$/.test(c.path)).length).toBeGreaterThan(5);
    // never a write to an existing branch
    expect(calls.some((c) => c.method === 'PATCH' && /\/git\/refs\//.test(c.path))).toBe(false);
    await ctx.app.close();
  });

  it('at L1 only comments, and ignores ChatOps from users without write access', async () => {
    const gh = fakeGithub('read');
    const ctx = await boot({ autonomy: 1 }, gh);
    const body = JSON.stringify({
      action: 'synchronize',
      repository: { full_name: 'acme/shop', default_branch: 'main' },
      pull_request: pr(),
    });
    await ctx.http
      .post('/webhooks/github')
      .set('x-github-event', 'pull_request')
      .set('x-hub-signature-256', sign(body))
      .set('content-type', 'application/json')
      .send(body)
      .expect(202);
    const cmd = JSON.stringify({
      action: 'created',
      repository: { full_name: 'acme/shop' },
      issue: { number: 7, pull_request: {} },
      comment: { body: '/sentinelops fix', user: { login: 'mallory' } },
    });
    const r = await ctx.http
      .post('/webhooks/github')
      .set('x-github-event', 'issue_comment')
      .set('x-hub-signature-256', sign(cmd))
      .set('content-type', 'application/json')
      .send(cmd)
      .expect(202);
    await ctx.jobs.idle();
    expect(gh.calls.some((c) => /\/pulls$/.test(c.path) && c.method === 'POST')).toBe(false);
    expect(ctx.jobs.get(r.body.job)!.detail).toContain('needs write access');
    const audit = await ctx.http.get('/api/audit').expect(200);
    expect(audit.body.entries.find((e: any) => e.action === 'github:command:fix')).toMatchObject({ allowed: false });
    expect(audit.body.entries.find((e: any) => e.action === 'github:open_pr')).toMatchObject({ allowed: false });
    await ctx.app.close();
  });
});
