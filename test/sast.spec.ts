import { SourceFile } from '../src/common/types';
import { languageOf } from '../src/scanners/files';
import { RULES } from '../src/scanners/sast/rules';
import { SastScanner } from '../src/scanners/sast/sast.scanner';

const file = (path: string, content: string): SourceFile => ({
  path,
  absPath: '/x/' + path,
  content,
  lines: content.split('\n'),
  language: languageOf(path),
});

async function scan(path: string, content: string) {
  return new SastScanner().scan({ options: { root: '/x' }, files: [file(path, content)] });
}

const rules = (fs: { ruleId: string }[]) => fs.map((f) => f.ruleId).sort();

describe('builtin SAST rules', () => {
  it('flags string-built SQL and escalates when input comes from the request', async () => {
    const fs = await scan(
      'db.js',
      [
        'db.query("SELECT * FROM users WHERE id = " + req.params.id);',
        'db.all(`SELECT * FROM orders WHERE user = ${userId}`);',
        'db.query("SELECT * FROM users WHERE id = ?", [req.params.id]);',
      ].join('\n'),
    );
    expect(fs).toHaveLength(2);
    expect(fs[0]).toMatchObject({ ruleId: 'js.sqli.string-built-query', severity: 'critical', cwe: ['CWE-89'] });
    expect(fs[1].severity).toBe('high');
    expect(fs[0].location).toMatchObject({ file: 'db.js', line: 1 });
  });

  it('covers command injection, eval, ssrf, traversal, redirect and xss sinks', async () => {
    const fs = await scan(
      'app.ts',
      [
        'exec(`convert ${req.query.file} out.png`);',
        'const cfg = eval(req.body.expr);',
        'const r = await fetch(req.query.url);',
        'res.sendFile(path.join(__dirname, req.params.name));',
        'res.redirect(req.query.next);',
        'res.send(`<h1>Hello ${req.query.name}</h1>`);',
      ].join('\n'),
    );
    expect(rules(fs)).toEqual([
      'js.cmdi.shell-command-from-input',
      'js.code-injection.eval',
      'js.open-redirect',
      'js.path-traversal.fs-from-input',
      'js.ssrf.fetch-from-input',
      'js.xss.reflected-response',
    ]);
  });

  it('flags crypto, jwt, cookie, cors and missing helmet', async () => {
    const fs = await scan(
      'server.js',
      [
        'const app = express();',
        'app.use(cors());',
        "const h = crypto.createHash('md5').update(pw).digest('hex');",
        'const resetToken = Math.random().toString(36).slice(2);',
        'const payload = jwt.decode(token);',
        "res.cookie('session', id, { httpOnly: false });",
        'const x = Math.random() * 10; // dice roll',
      ].join('\n'),
    );
    expect(rules(fs)).toEqual([
      'js.cookie.insecure-flags',
      'js.cors.wildcard',
      'js.crypto.insecure-random',
      'js.crypto.weak-hash',
      'js.express.no-security-headers',
      'js.jwt.decode-without-verify',
    ]);
  });

  it('respects comments, safe variants and inline suppressions', async () => {
    const fs = await scan(
      'safe.js',
      [
        '// db.query("SELECT * FROM t WHERE a = " + b)',
        'const app = express(); app.use(helmet());',
        'res.sendFile(path.basename(req.params.name), { root: PUBLIC });',
        'eval("2 + 2");',
        'const p = jwt.decode(token); // sentinelops-ignore: only reading the header',
      ].join('\n'),
    );
    expect(fs.filter((f) => !f.suppressed)).toHaveLength(0);
    expect(fs).toHaveLength(1);
    expect(fs[0].suppressReason).toMatch(/inline/);
  });

  it('only flags real NODE_TLS_REJECT_UNAUTHORIZED assignments', async () => {
    const fs = await scan(
      'tls.js',
      [
        "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';",
        "process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = 0;",
        "const msg = 'Removed the NODE_TLS_REJECT_UNAUTHORIZED=0 override';",
      ].join('\n'),
    );
    expect(fs.map((f) => f.location.line)).toEqual([1, 2]);
  });

  it('has python rules', async () => {
    const fs = await scan(
      'app.py',
      [
        'cur.execute(f"SELECT * FROM users WHERE name = \'{name}\'")',
        'subprocess.run(cmd, shell=True)',
        'data = pickle.loads(blob)',
        'requests.get(url, verify=False)',
        'app.run(debug=True)',
        'yaml.load(text, Loader=yaml.SafeLoader)',
      ].join('\n'),
    );
    expect(rules(fs)).toEqual([
      'py.cmdi.shell',
      'py.deserialization.unsafe',
      'py.flask.debug',
      'py.sqli.string-built-query',
      'py.tls.verify-disabled',
    ]);
  });

  it('every rule has CWE, remediation and a unique id', () => {
    const ids = new Set<string>();
    for (const r of RULES) {
      expect(r.cwe.length).toBeGreaterThan(0);
      expect(r.remediation.length).toBeGreaterThan(10);
      expect(ids.has(r.id)).toBe(false);
      ids.add(r.id);
    }
  });
});
