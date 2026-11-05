/**
 * Built-in SAST rules for JavaScript / TypeScript and Python.
 *
 * Rules are line oriented with optional file-level conditions. They are tuned
 * for precision: a rule fires on the dangerous *shape* (string-built SQL, a
 * shell command built from a template, user input flowing straight into a
 * sink) rather than on every use of an API. `taint` marks lines that read
 * request input directly (req.query / req.body / request.args ...), which
 * raises severity and confidence.
 */
import { Confidence, Severity, SourceFile } from '../../common/types';

export type Lang = SourceFile['language'];

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  cwe: string[];
  languages: Lang[];
  patterns: RegExp[];
  unless?: RegExp; // line is safe when this matches
  fileRequires?: RegExp; // only check files containing this
  fileUnless?: RegExp; // skip files containing this
  lineRequires?: RegExp; // the matching line must also match this
  message: string;
  remediation: string;
  fixer?: string; // id of a deterministic fixer in remediation/fixers.ts
  escalateOnTaint?: boolean;
}

const JS: Lang[] = ['js', 'ts'];
const PY: Lang[] = ['py'];
export const TAINT_JS = /\breq(uest)?\.(query|body|params|headers|cookies)\b|\bctx\.(query|request)\b/;
export const TAINT_PY = /\brequest\.(args|form|values|json|data|GET|POST|cookies|headers)\b/;

export const RULES: Rule[] = [
  // ---- A03 Injection -------------------------------------------------------
  {
    id: 'js.sqli.string-built-query',
    title: 'SQL query built from strings',
    severity: 'high',
    confidence: 'high',
    cwe: ['CWE-89'],
    languages: JS,
    patterns: [
      /\.(query|execute|exec|raw|all|get|run)\s*\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*\+/,
      /\.(query|execute|exec|raw|all|get|run)\s*\(\s*`[^`]*\$\{/,
    ],
    lineRequires: /\b(select|insert|update|delete)\b[\s\S]*\b(from|into|set|where)\b/i,
    message: 'The SQL text is concatenated with values, so input can change the query (SQL injection).',
    remediation: 'Pass values as parameters: db.query("SELECT ... WHERE id = ?", [id]).',
    fixer: 'sql-parameterize',
    escalateOnTaint: true,
  },
  {
    id: 'js.cmdi.shell-command-from-input',
    title: 'Shell command built from variables',
    severity: 'high',
    confidence: 'high',
    cwe: ['CWE-78'],
    languages: JS,
    patterns: [/\b(exec|execSync)\s*\(\s*`[^`]*\$\{/, /\b(exec|execSync)\s*\(\s*['"][^'"]*['"]\s*\+/],
    message: 'A shell command string contains interpolated values; input can inject extra commands.',
    remediation: 'Use execFile/spawn with an argument array and no shell.',
    fixer: 'exec-to-execfile',
    escalateOnTaint: true,
  },
  {
    id: 'js.code-injection.eval',
    title: 'Dynamic code evaluation',
    severity: 'high',
    confidence: 'medium',
    cwe: ['CWE-95'],
    languages: JS,
    patterns: [/(^|[^.\w])eval\s*\(\s*[^'"`)]/, /\bnew\s+Function\s*\(/, /\bvm\.runIn(New|This)?Context\s*\(/],
    message: 'Evaluating dynamic strings executes attacker-controlled code if any part comes from input.',
    remediation: 'Parse data with JSON.parse or a dedicated parser instead of evaluating it.',
    fixer: 'eval-to-json-parse',
    escalateOnTaint: true,
  },
  {
    id: 'js.xss.reflected-response',
    title: 'Request input written into the HTML response',
    severity: 'high',
    confidence: 'medium',
    cwe: ['CWE-79'],
    languages: JS,
    patterns: [
      /res\.(send|write|end)\s*\(\s*(`[^`]*\$\{[^}]*req(uest)?\.(query|body|params)|req(uest)?\.(query|body|params))/,
      /res\.(send|write|end)\s*\(\s*(['"])[^'"]*<[^'"]*\2\s*\+\s*req(uest)?\.(query|body|params)/,
    ],
    unless: /res\.send\(\s*\{|escape(Html)?\(|sanitize|DOMPurify/,
    message: 'User input is reflected in the response without encoding (cross-site scripting).',
    remediation: 'HTML-encode the value or render it through a template engine that escapes by default.',
    fixer: 'xss-escape',
  },
  {
    id: 'js.xss.inner-html',
    title: 'Assignment to innerHTML',
    severity: 'medium',
    confidence: 'low',
    cwe: ['CWE-79'],
    languages: JS,
    patterns: [/\.innerHTML\s*=\s*[^'"`\s;]/, /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*[^'"`]/],
    message: 'Dynamic HTML is inserted into the DOM; untrusted content becomes script.',
    remediation: 'Use textContent, or sanitise with DOMPurify before inserting HTML.',
  },
  {
    id: 'js.nosqli.query-object-from-input',
    title: 'Database query object taken directly from request',
    severity: 'high',
    confidence: 'medium',
    cwe: ['CWE-89'],
    languages: JS,
    patterns: [/\.(find|findOne|deleteMany|updateOne|updateMany)\s*\(\s*req(uest)?\.(body|query)\s*[,)]/],
    message: 'Passing the request object as a query lets clients inject operators such as $ne / $gt.',
    remediation: 'Build the filter from validated fields (e.g. { email: String(req.body.email) }).',
  },
  // ---- A01 Broken access control --------------------------------------------
  {
    id: 'js.path-traversal.fs-from-input',
    title: 'File path from request input',
    severity: 'high',
    confidence: 'high',
    cwe: ['CWE-22'],
    languages: JS,
    patterns: [/\b(readFile|readFileSync|createReadStream|sendFile|download|unlink|writeFile)\w*\s*\([^;]*req(uest)?\.(query|params|body)/],
    unless: /\bbasename\(|safeJoin|resolveInside/,
    message: 'A filesystem path is built from input, so "../" sequences can reach any file.',
    remediation: 'Resolve against a base directory and reject paths that escape it.',
    fixer: 'path-basename',
  },
  {
    id: 'js.open-redirect',
    title: 'Redirect to a user-supplied URL',
    severity: 'medium',
    confidence: 'high',
    cwe: ['CWE-601'],
    languages: JS,
    patterns: [/res\.redirect\s*\(\s*(\d+\s*,\s*)?req(uest)?\.(query|params|body)/],
    message: 'Redirecting to a URL from the request enables phishing via a trusted domain.',
    remediation: 'Only redirect to relative paths or to hosts on an allow-list.',
    fixer: 'safe-redirect',
  },
  {
    id: 'js.cors.wildcard',
    title: 'CORS allows any origin',
    severity: 'medium',
    confidence: 'medium',
    cwe: ['CWE-942'],
    languages: JS,
    patterns: [/\bcors\s*\(\s*\)/, /origin\s*:\s*(['"]\*['"]|true)\b/, /Access-Control-Allow-Origin['"]?\s*,\s*['"]\*['"]/],
    message: 'Any website can call this API from a browser.',
    remediation: 'Pass an explicit list of trusted origins to cors({ origin: [...] }).',
    fixer: 'cors-allowlist',
  },
  // ---- A10 SSRF -----------------------------------------------------------------
  {
    id: 'js.ssrf.fetch-from-input',
    title: 'Server-side request to a user-supplied URL',
    severity: 'high',
    confidence: 'high',
    cwe: ['CWE-918'],
    languages: JS,
    patterns: [/\b(fetch|axios(\.(get|post|put|request))?|got|needle|request|https?\.get)\s*\(\s*req(uest)?\.(query|params|body)/],
    message: 'The server fetches whatever URL the client sends: internal services and cloud metadata become reachable.',
    remediation: 'Validate the URL, allow-list hosts and block private / link-local address ranges.',
    fixer: 'ssrf-allowlist',
  },
  // ---- A02 Crypto ---------------------------------------------------------------
  {
    id: 'js.crypto.weak-hash',
    title: 'Weak hash algorithm (MD5/SHA-1)',
    severity: 'medium',
    confidence: 'high',
    cwe: ['CWE-328'],
    languages: JS,
    patterns: [/createHash\s*\(\s*['"](md5|sha1)['"]\s*\)/i],
    message: 'MD5 and SHA-1 are broken for security purposes and trivially brute-forced for passwords.',
    remediation: 'Use sha256 for integrity; bcrypt/scrypt/argon2 for passwords.',
    fixer: 'weak-hash',
  },
  {
    id: 'js.crypto.insecure-random',
    title: 'Math.random() used for a security value',
    severity: 'medium',
    confidence: 'medium',
    cwe: ['CWE-330'],
    languages: JS,
    patterns: [/Math\.random\s*\(/],
    lineRequires: /token|secret|password|passwd|session|nonce|otp|salt|api[_-]?key|reset/i,
    message: 'Math.random is predictable; tokens derived from it can be guessed.',
    remediation: 'Use crypto.randomBytes(32).toString("hex") or crypto.randomUUID().',
    fixer: 'secure-random',
  },
  {
    id: 'js.tls.verification-disabled',
    title: 'TLS certificate verification disabled',
    severity: 'high',
    confidence: 'high',
    cwe: ['CWE-295'],
    languages: JS,
    patterns: [/rejectUnauthorized\s*:\s*false/, /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/],
    message: 'Disabling certificate checks allows man-in-the-middle attacks.',
    remediation: 'Remove the override; trust a custom CA via the ca option if needed.',
    fixer: 'tls-verify',
  },
  // ---- A07 Auth -----------------------------------------------------------------
  {
    id: 'js.jwt.decode-without-verify',
    title: 'JWT decoded without signature verification',
    severity: 'high',
    confidence: 'medium',
    cwe: ['CWE-347'],
    languages: JS,
    patterns: [/\bjwt\.decode\s*\(/, /algorithms\s*:\s*\[[^\]]*['"]none['"]/i],
    message: 'jwt.decode does not check the signature, so anyone can forge a token.',
    remediation: 'Use jwt.verify(token, secret, { algorithms: ["HS256"] }).',
    fixer: 'jwt-verify',
  },
  // ---- A05 Misconfiguration ------------------------------------------------------
  {
    id: 'js.cookie.insecure-flags',
    title: 'Session cookie without HttpOnly/Secure',
    severity: 'medium',
    confidence: 'high',
    cwe: ['CWE-614', 'CWE-1004'],
    languages: JS,
    patterns: [/(httpOnly|secure)\s*:\s*false/],
    lineRequires: /cookie|session/i,
    message: 'The cookie is readable by scripts or sent over plain HTTP.',
    remediation: 'Set { httpOnly: true, secure: true, sameSite: "lax" }.',
    fixer: 'cookie-flags',
  },
  {
    id: 'js.express.no-security-headers',
    title: 'Express app without security headers (helmet)',
    severity: 'low',
    confidence: 'medium',
    cwe: ['CWE-693'],
    languages: JS,
    patterns: [/=\s*express\s*\(\s*\)/],
    fileUnless: /helmet/,
    message: 'No helmet middleware: missing CSP, HSTS, X-Content-Type-Options and friends.',
    remediation: 'app.use(helmet()) right after creating the app.',
    fixer: 'add-helmet',
  },
  {
    id: 'js.error.stack-trace-exposed',
    title: 'Error details sent to the client',
    severity: 'low',
    confidence: 'medium',
    cwe: ['CWE-200'],
    languages: JS,
    patterns: [/res\.(status\(\d+\)\.)?(send|json)\s*\(\s*(err|error|e)(\.stack|\.message)?\s*\)/],
    message: 'Stack traces and internal messages help attackers map the system.',
    remediation: 'Log the error server-side and return a generic message with a request id.',
    fixer: 'generic-error',
  },
  // ---- A08 Integrity -------------------------------------------------------------
  {
    id: 'js.prototype-pollution.merge-input',
    title: 'Deep merge of request input',
    severity: 'high',
    confidence: 'medium',
    cwe: ['CWE-1321'],
    languages: JS,
    patterns: [/(_|lodash|merge|deepmerge|extend)\.?(merge|defaultsDeep|extend)?\s*\(\s*[\w.{}[\]]+\s*,\s*req(uest)?\.(body|query)/],
    message: 'Merging client objects deeply lets "__proto__" keys pollute every object in the process.',
    remediation: 'Copy only expected fields, or merge into Object.create(null) after rejecting __proto__/constructor.',
    fixer: 'strip-proto-keys',
  },
  // ---- A09 Logging ---------------------------------------------------------------
  {
    id: 'js.logging.secret-in-log',
    title: 'Secret written to logs',
    severity: 'low',
    confidence: 'low',
    cwe: ['CWE-532'],
    languages: JS,
    patterns: [/console\.(log|info|debug)\s*\([^)]*\b(password|passwd|token|secret|apiKey|api_key)\b/i],
    message: 'Credentials in logs end up in log storage, dashboards and support tickets.',
    remediation: 'Remove the value or log a masked version.',
  },
  // ---- Python --------------------------------------------------------------------
  {
    id: 'py.sqli.string-built-query',
    title: 'SQL query built from strings',
    severity: 'high',
    confidence: 'high',
    cwe: ['CWE-89'],
    languages: PY,
    patterns: [/\.execute\(\s*f("|')/, /\.execute\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*(%|\+|\.format\()/],
    lineRequires: /\b(select|insert|update|delete)\b/i,
    message: 'The SQL text is built with string formatting, so input can change the query.',
    remediation: 'cursor.execute("SELECT ... WHERE id = %s", (id,))',
    fixer: 'py-sql-parameterize',
    escalateOnTaint: true,
  },
  {
    id: 'py.cmdi.shell',
    title: 'Shell command execution with a built string',
    severity: 'high',
    confidence: 'high',
    cwe: ['CWE-78'],
    languages: PY,
    patterns: [/subprocess\.\w+\([^)]*shell\s*=\s*True/, /\bos\.(system|popen)\s*\(\s*(f["']|[^"')]+\+|["'][^"']*["']\s*%)/],
    message: 'The command runs through a shell with interpolated values.',
    remediation: 'subprocess.run([...args], shell=False) with an argument list.',
    fixer: 'py-shell-to-list',
    escalateOnTaint: true,
  },
  {
    id: 'py.code-injection.eval',
    title: 'eval/exec on dynamic input',
    severity: 'high',
    confidence: 'medium',
    cwe: ['CWE-95'],
    languages: PY,
    patterns: [/(^|[^.\w])(eval|exec)\s*\(\s*[^'")]/],
    message: 'eval/exec runs arbitrary code.',
    remediation: 'Use ast.literal_eval or json.loads.',
  },
  {
    id: 'py.deserialization.unsafe',
    title: 'Unsafe deserialisation (pickle / yaml.load)',
    severity: 'high',
    confidence: 'high',
    cwe: ['CWE-502'],
    languages: PY,
    patterns: [/\bpickle\.loads?\s*\(/, /\byaml\.load\s*\((?![^)]*SafeLoader)/],
    message: 'Deserialising untrusted data can execute code.',
    remediation: 'Use json, or yaml.safe_load.',
    fixer: 'yaml-safe-load',
  },
  {
    id: 'py.crypto.weak-hash',
    title: 'Weak hash algorithm (MD5/SHA-1)',
    severity: 'medium',
    confidence: 'high',
    cwe: ['CWE-328'],
    languages: PY,
    patterns: [/hashlib\.(md5|sha1)\s*\(/],
    message: 'MD5 and SHA-1 are broken for security purposes.',
    remediation: 'hashlib.sha256 for integrity; bcrypt/argon2 for passwords.',
    fixer: 'weak-hash',
  },
  {
    id: 'py.tls.verify-disabled',
    title: 'TLS verification disabled',
    severity: 'high',
    confidence: 'high',
    cwe: ['CWE-295'],
    languages: PY,
    patterns: [/verify\s*=\s*False/],
    message: 'Certificate checks are disabled for this request.',
    remediation: 'Remove verify=False; pass a CA bundle if needed.',
    fixer: 'tls-verify',
  },
  {
    id: 'py.flask.debug',
    title: 'Flask debug mode enabled',
    severity: 'medium',
    confidence: 'high',
    cwe: ['CWE-489'],
    languages: PY,
    patterns: [/\.run\([^)]*debug\s*=\s*True/],
    message: 'The Werkzeug debugger allows remote code execution if exposed.',
    remediation: 'Never enable debug in production; read it from configuration.',
    fixer: 'flask-debug',
  },
];
