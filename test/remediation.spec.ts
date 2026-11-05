import { Finding, SourceFile } from '../src/common/types';
import { KnowledgeService } from '../src/knowledge/knowledge.service';
import { diffStats, unifiedDiff } from '../src/remediation/diff';
import { fixerFor } from '../src/remediation/fixers';
import { memoryWorkspace, RemediationService } from '../src/remediation/remediation.service';
import { checkSyntax } from '../src/remediation/verify';
import { ConfigScanner } from '../src/scanners/config/config.scanner';
import { DependencyScanner } from '../src/scanners/deps/deps.scanner';
import { languageOf } from '../src/scanners/files';
import { SastScanner } from '../src/scanners/sast/sast.scanner';
import { SecretsScanner } from '../src/scanners/secrets/secrets.scanner';
import { Scanner } from '../src/scanners/scanner';

const APP = [
  "const express = require('express');",
  "const { exec } = require('child_process');",
  "const crypto = require('crypto');",
  "const cors = require('cors');",
  '',
  'const app = express();',
  'app.use(cors());',
  'const JWT_SECRET = "supersecret-shop-key-2026";',
  '',
  "app.get('/users/:id', (req, res) => {",
  '  db.query("SELECT * FROM users WHERE id = " + req.params.id, (err, rows) => res.json(rows));',
  '});',
  "app.get('/search', (req, res) => {",
  "  db.all(`SELECT * FROM products WHERE name LIKE '%${req.query.q}%'`, (e, rows) => res.json(rows));",
  '});',
  "app.get('/thumb', (req, res) => {",
  '  exec(`convert ${req.query.file} thumb.png`, () => res.sendFile(__dirname + "/thumb.png"));',
  '});',
  "app.post('/calc', (req, res) => res.json({ result: eval(req.body.expr) }));",
  "app.get('/hello', (req, res) => res.send(`<h1>Hello ${req.query.name}</h1>`));",
  "app.get('/go', (req, res) => res.redirect(req.query.next));",
  "app.get('/proxy', async (req, res) => res.send(await (await fetch(req.query.url)).text()));",
  "app.get('/file', (req, res) => res.sendFile(req.query.name, { root: 'public' }));",
  "const hash = (pw) => crypto.createHash('md5').update(pw).digest('hex');",
  'const resetToken = () => Math.random().toString(36).slice(2);',
  "app.post('/login', (req, res) => { res.cookie('session', 'x', { httpOnly: false }); res.json({ user: jwt.decode(req.body.token) }); });",
  'app.listen(3000);',
  '',
].join('\n');

const file = (path: string, content: string): SourceFile => ({
  path,
  absPath: path,
  content,
  lines: content.split('\n'),
  language: languageOf(path),
});
async function findingsFor(scanner: Scanner, path: string, content: string): Promise<Finding[]> {
  const k = new KnowledgeService();
  return (await scanner.scan({ options: { root: '.', osv: false }, files: [file(path, content)] })).map((f) => k.enrich(f));
}

describe('unified diff', () => {
  it('produces git-style hunks', () => {
    const d = unifiedDiff('a.js', 'one\ntwo\nthree\nfour\n', 'one\n2\nthree\nfour\nfive\n');
    expect(d).toBe(['--- a/a.js', '+++ b/a.js', '@@ -1,5 +1,6 @@', ' one', '-two', '+2', ' three', ' four', '+five', ' ', ''].join('\n'));
    expect(diffStats(d)).toEqual({ added: 2, removed: 1 });
    expect(unifiedDiff('a', 'x', 'x')).toBe('');
  });
});

describe('rule fixers', () => {
  const svc = new RemediationService();

  it('fixes every SAST finding in a vulnerable express app and the result re-scans clean', async () => {
    const fs = await findingsFor(new SastScanner(), 'src/app.js', APP);
    expect(fs.length).toBeGreaterThanOrEqual(14);
    expect(fs.every((f) => fixerFor(f))).toBe(true);

    const ws = memoryWorkspace({ 'src/app.js': APP });
    const res = await svc.apply(fs, ws);
    expect(res.skipped).toEqual([]);
    expect(res.applied).toHaveLength(fs.length);
    expect(res.applied.every((p) => p.verified)).toBe(true);

    const fixed = ws.files['src/app.js'];
    expect(checkSyntax('src/app.js', fixed).status).toBe('ok');
    expect(await findingsFor(new SastScanner(), 'src/app.js', fixed)).toEqual([]);

    expect(fixed).toContain('db.query("SELECT * FROM users WHERE id = ?", [req.params.id], (err, rows)');
    expect(fixed).toContain('db.all("SELECT * FROM products WHERE name LIKE ?", [`%${req.query.q}%`]');
    expect(fixed).toContain("execFile('convert', [req.query.file, 'thumb.png']");
    expect(fixed).toContain("const { exec, execFile } = require('child_process');");
    expect(fixed).toContain('JSON.parse(req.body.expr)');
    expect(fixed).toContain('${escapeHtml(req.query.name)}');
    expect(fixed).toContain('res.redirect(safeRedirect(req.query.next))');
    expect(fixed).toContain('fetch(assertAllowedUrl(req.query.url))');
    expect(fixed).toContain("res.sendFile(path.basename(String(req.query.name)), { root: 'public' })".replace('path.basename', 'basename'));
    expect(fixed).toContain("createHash('sha256')");
    expect(fixed).toContain("crypto.randomBytes(16).toString('hex')");
    expect(fixed).toContain('httpOnly: true');
    expect(fixed).toContain("jwt.verify(req.body.token, JWT_SECRET, { algorithms: ['HS256'] })");
    expect(fixed).toContain("cors({ origin: (process.env.CORS_ORIGINS || 'http://localhost:3000').split(',') })");
    expect(fixed).toMatch(/const helmet = require\('helmet'\);[\s\S]*app\.use\(helmet\(\)\);/);
  });

  it('uses $n placeholders for node-postgres and supports TypeScript helpers', async () => {
    const src = [
      "import { Pool } from 'pg';",
      'const pool = new Pool();',
      'export const byId = (req: any) => pool.query(`SELECT * FROM t WHERE a = ${req.query.a} AND b = ${req.query.b}`);',
      'export const hi = (req: any, res: any) => res.send(`<p>${req.query.n}</p>`);',
      '',
    ].join('\n');
    const fs = await findingsFor(new SastScanner(), 'src/q.ts', src);
    const ws = memoryWorkspace({ 'src/q.ts': src });
    const res = await svc.apply(fs, ws);
    expect(res.skipped).toEqual([]);
    expect(ws.files['src/q.ts']).toContain('pool.query("SELECT * FROM t WHERE a = $1 AND b = $2", [req.query.a, req.query.b])');
    expect(ws.files['src/q.ts']).toContain('function escapeHtml(value: unknown): string');
  });

  it('refuses shell commands it cannot rewrite safely', async () => {
    const src = 'exec(`tar czf - ${req.query.dir} | gzip > out.tgz`);\n';
    const [f] = await findingsFor(new SastScanner(), 'a.js', src);
    expect(await svc.propose(f, memoryWorkspace({ 'a.js': src }))).toBeNull();
  });

  it('fixes python findings', async () => {
    const src = [
      'import sqlite3, yaml, requests',
      'cur.execute(f"SELECT * FROM users WHERE name = \'{name}\'")',
      'cfg = yaml.load(text)',
      'requests.get(url, verify=False)',
      'app.run(debug=True)',
      '',
    ].join('\n');
    const fs = await findingsFor(new SastScanner(), 'app.py', src);
    const ws = memoryWorkspace({ 'app.py': src });
    const res = await svc.apply(fs, ws);
    expect(res.applied).toHaveLength(4);
    const out = ws.files['app.py'];
    expect(out).toContain('cur.execute("SELECT * FROM users WHERE name = ?", (name,))');
    expect(out).toContain('yaml.safe_load(text)');
    expect(out).toContain('requests.get(url)');
    expect(out).toContain('debug=os.environ.get("FLASK_DEBUG") == "1"');
    expect(out.startsWith('import os\n')).toBe(true);
  });
});

describe('supply-chain fixers', () => {
  const svc = new RemediationService();

  it('moves secrets to environment variables', async () => {
    const src = "const JWT_SECRET = 'supersecret-shop-key-2026';\nconst db = connect('postgres://admin:Pr0dPassw0rd!@db:5432/shop');\n";
    const fs = await findingsFor(new SecretsScanner(), 'src/config.js', src);
    const ws = memoryWorkspace({ 'src/config.js': src });
    const res = await svc.apply(fs, ws);
    expect(res.applied).toHaveLength(2);
    expect(ws.files['src/config.js']).toBe('const JWT_SECRET = process.env.JWT_SECRET;\nconst db = connect(process.env.DATABASE_URL);\n');
  });

  it('bumps direct and transitive npm dependencies in package.json', async () => {
    const pkg = JSON.stringify({ name: 'shop', dependencies: { lodash: '^4.17.15', express: '4.17.1' } }, null, 2) + '\n';
    const lock = JSON.stringify(
      {
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { lodash: '^4.17.15', express: '4.17.1' } },
          'node_modules/lodash': { version: '4.17.15' },
          'node_modules/express': { version: '4.17.1' },
          'node_modules/minimist': { version: '1.2.5' },
        },
      },
      null,
      2,
    );
    const fs = await findingsFor(new DependencyScanner(), 'package-lock.json', lock);
    const ws = memoryWorkspace({ 'package.json': pkg, 'package-lock.json': lock });
    const res = await svc.apply(fs, ws);
    const doc = JSON.parse(ws.files['package.json']);
    expect(doc.dependencies).toEqual({ lodash: '^4.17.21', express: '^4.19.2' });
    expect(doc.overrides).toEqual({ minimist: '^1.2.6' });
    expect(res.files.map((f) => f.path)).toEqual(['package.json']);
    expect(res.skipped).toEqual([]);
    expect(res.resolved).toHaveLength(1); // the second lodash advisory is fixed by the same bump
  });

  it('pins requirements and hardens Dockerfiles / manifests', async () => {
    const ws = memoryWorkspace({
      'requirements.txt': 'flask==2.2.2\nrequests==2.25.0  # http\n',
      Dockerfile: 'FROM node:20-alpine\nENV API_TOKEN=abcd1234efgh\nCOPY . .\nCMD ["node", "server.js"]\n',
      'k8s/pod.yaml': 'apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        privileged: true\n',
    });
    const deps = await findingsFor(new DependencyScanner(), 'requirements.txt', ws.files['requirements.txt']);
    const cfg = [
      ...(await findingsFor(new ConfigScanner(), 'Dockerfile', ws.files.Dockerfile)),
      ...(await findingsFor(new ConfigScanner(), 'k8s/pod.yaml', ws.files['k8s/pod.yaml'])),
    ];
    await svc.apply([...deps, ...cfg], ws);
    expect(ws.files['requirements.txt']).toBe('flask==2.2.5\nrequests==2.31.0  # http\n');
    expect(ws.files.Dockerfile).toContain('USER node\nCMD');
    expect(ws.files.Dockerfile).not.toContain('abcd1234efgh');
    expect(ws.files['k8s/pod.yaml']).toContain('privileged: false');
  });
});

describe('more fixers', () => {
  const svc = new RemediationService();

  it('rewrites multi-line exec callbacks and quoted SQL concatenation', async () => {
    const src = [
      "const { exec } = require('child_process');",
      "router.post('/t', (req, res) => {",
      '  exec(`convert ${req.body.image} -resize 200x200 thumb.png`, (err) => {',
      '    if (err) return res.status(500).send(err.message);',
      '  });',
      '  db.query("UPDATE users SET token = \'" + tok + "\' WHERE email = \'" + req.body.email + "\'", () => res.json({}));',
      '});',
      '',
    ].join('\n');
    const fs = await findingsFor(new SastScanner(), 'src/r.js', src);
    expect(fs.map((f) => f.ruleId).sort()).toEqual([
      'js.cmdi.shell-command-from-input',
      'js.error.stack-trace-exposed',
      'js.sqli.string-built-query',
    ]);
    const ws = memoryWorkspace({ 'src/r.js': src });
    const res = await svc.apply(fs, ws);
    expect(res.skipped).toEqual([]);
    const out = ws.files['src/r.js'];
    expect(out).toContain("execFile('convert', [req.body.image, '-resize', '200x200', 'thumb.png'], (err) => {");
    expect(out).toContain('db.query("UPDATE users SET token = ? WHERE email = ?", [tok, req.body.email], () => res.json({}));');
    expect(out).toContain("res.status(500).send('Internal Server Error')");
  });

  it('strips prototype keys before deep merges', async () => {
    const src = "app.post('/p', (req, res) => res.json(_.merge({}, req.body)));\n";
    const fs = await findingsFor(new SastScanner(), 'a.js', src);
    const ws = memoryWorkspace({ 'a.js': src });
    await svc.apply(fs, ws);
    expect(ws.files['a.js']).toContain('_.merge({}, withoutProtoKeys(req.body))');
    const helper = new Function(ws.files['a.js'].split('\n').slice(2).join('\n') + '; return withoutProtoKeys;')();
    const clean = helper(JSON.parse('{"a":1,"__proto__":{"admin":true},"b":{"constructor":{"x":1}}}'));
    expect(Object.keys(clean)).toEqual(['a', 'b']);
    expect(({} as any).admin).toBeUndefined();
  });

  it('turns shell=True into an argument list', async () => {
    const src = 'import subprocess\nsubprocess.run(f"tar czf /tmp/{name}.tgz /var/reports", shell=True, check=True)\n';
    const fs = await findingsFor(new SastScanner(), 'w.py', src);
    const ws = memoryWorkspace({ 'w.py': src });
    const res = await svc.apply(fs, ws);
    expect(res.applied).toHaveLength(1);
    expect(ws.files['w.py']).toContain('subprocess.run(["tar", "czf", f"/tmp/{name}.tgz", "/var/reports"], check=True)');
  });

  it('moves untrusted workflow expressions into env', async () => {
    const wf = [
      'on: pull_request',
      'jobs:',
      '  build:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: echo "Building ${{ github.event.pull_request.title }} from ${{ github.head_ref }}"',
      '      - run: |',
      '          echo "${{ github.event.issue.body }}"',
      '        env:',
      '          SAFE: ${{ github.event.issue.body }}',
      '',
    ].join('\n');
    const fs = await findingsFor(new ConfigScanner(), '.github/workflows/ci.yml', wf);
    expect(fs.map((f) => f.location.line)).toEqual([6, 8]); // env: values are data, not script
    const ws = memoryWorkspace({ '.github/workflows/ci.yml': wf });
    const res = await svc.apply(fs, ws);
    expect(res.applied).toHaveLength(1); // the multi-line block is left to a human
    expect(ws.files['.github/workflows/ci.yml']).toContain(
      [
        '      - run: echo "Building $PR_TITLE from $HEAD_REF"',
        '        env:',
        '          PR_TITLE: ${{ github.event.pull_request.title }}',
        '          HEAD_REF: ${{ github.head_ref }}',
      ].join('\n'),
    );
  });

  it('keeps python header comments above inserted imports', async () => {
    const src = '# service header\n# second line\nimport sqlite3\napp.run(debug=True)\n';
    const fs = await findingsFor(new SastScanner(), 's.py', src);
    const ws = memoryWorkspace({ 's.py': src });
    await svc.apply(fs, ws);
    expect(ws.files['s.py'].split('\n').slice(0, 4)).toEqual(['# service header', '# second line', 'import os', 'import sqlite3']);
  });
});
