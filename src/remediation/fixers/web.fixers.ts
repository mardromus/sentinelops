/**
 * Fixers for web-layer findings: XSS, redirects, SSRF, path traversal,
 * CORS, cookies, security headers, JWT verification and crypto choices.
 */
import { ensureHelper, ensureImport, ensurePyImport, locate, matchParen } from '../code';
import { Fixer, FixOutput, isTs } from './types';

/**
 * Reference a function from a core module whatever import style the file uses:
 * a namespace binding (path.basename), an existing destructure, or a new import.
 */
export function useExport(lines: string[], mod: string, fn: string, ns: string): { lines: string[]; ref: string } {
  const content = lines.join('\n');
  const nsRe = new RegExp(
    `(const|let|var)\\s+${ns}\\s*=\\s*require\\(['"](node:)?${mod}['"]\\)|import\\s+\\*\\s+as\\s+${ns}\\s+from\\s+['"](node:)?${mod}['"]|import\\s+${ns}\\s+from\\s+['"](node:)?${mod}['"]`,
  );
  if (nsRe.test(content)) return { lines, ref: `${ns}.${fn}` };
  return { lines: ensureImport(lines, mod, fn), ref: fn };
}

function edit(content: string, finding: Parameters<Fixer>[0]['finding'], fn: (line: string, lines: string[]) => string | null) {
  const lines = content.split('\n');
  const idx = locate(lines, finding);
  if (idx < 0) return null;
  const next = fn(lines[idx], lines);
  if (next === null || next === lines[idx]) return null;
  lines[idx] = next;
  return lines;
}

const TAINT = /\breq(?:uest)?\.(?:query|params|body)(?:\.[A-Za-z_$][\w$]*|\[[^\]]+\])*/g;

export const xssEscape: Fixer = ({ finding, content, path }) => {
  const lines = edit(content, finding, (line) => {
    const m = /res\.(?:send|write|end)\s*\(/.exec(line);
    if (!m) return null;
    const open = m.index + m[0].length - 1;
    const close = matchParen(line, open);
    if (close < 0) return null;
    // wrap every request value inside the response body, unless it is already encoded
    const inner = line.slice(open + 1, close).replace(TAINT, (t, at: number, all: string) => (/escapeHtml\(\s*$/.test(all.slice(0, at)) ? t : `escapeHtml(${t})`));
    return line.slice(0, open + 1) + inner + line.slice(close);
  });
  if (!lines) return null;
  const sig = isTs(path) ? 'function escapeHtml(value: unknown): string' : 'function escapeHtml(value)';
  const out = ensureHelper(
    lines,
    'escapeHtml',
    `// HTML-encode untrusted text before it is placed in markup (added by SentinelOps)
${sig} {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]${isTs(path) ? ' as string' : ''});
}`,
  );
  return { content: out.join('\n'), description: 'HTML-encoded the request value before writing it into the response.' };
};

export const safeRedirect: Fixer = ({ finding, content, path }) => {
  const lines = edit(content, finding, (line) => line.replace(/(res\.redirect\s*\(\s*(?:\d+\s*,\s*)?)(req(?:uest)?\.(?:query|params|body)(?:\.[\w$]+|\[[^\]]+\])*)/, '$1safeRedirect($2)'));
  if (!lines) return null;
  const sig = isTs(path) ? "function safeRedirect(target: unknown, fallback = '/'): string" : "function safeRedirect(target, fallback = '/')";
  const out = ensureHelper(
    lines,
    'safeRedirect',
    `// Only allow same-site relative paths: "/orders" ok, "//evil.example" and "https://evil.example" not (added by SentinelOps)
${sig} {
  const url = String(target || '');
  return url.startsWith('/') && !url.startsWith('//') && !url.startsWith('/\\\\') ? url : fallback;
}`,
  );
  return { content: out.join('\n'), description: 'Restricted the redirect target to same-site relative paths.' };
};

export const ssrfAllowlist: Fixer = ({ finding, content, path }) => {
  const lines = edit(content, finding, (line) =>
    line.replace(/(\b(?:fetch|axios(?:\.(?:get|post|put|request))?|got|needle|request|https?\.get)\s*\(\s*)(req(?:uest)?\.(?:query|params|body)(?:\.[\w$]+|\[[^\]]+\])*)/, '$1assertAllowedUrl($2)'),
  );
  if (!lines) return null;
  const sig = isTs(path) ? 'function assertAllowedUrl(raw: unknown): string' : 'function assertAllowedUrl(raw)';
  const out = ensureHelper(
    lines,
    'assertAllowedUrl',
    `// Outbound requests may only go to hosts listed in OUTBOUND_ALLOWLIST (added by SentinelOps)
${sig} {
  const allowed = (process.env.OUTBOUND_ALLOWLIST || '').split(',').map((h) => h.trim()).filter(Boolean);
  const url = new URL(String(raw));
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('blocked URL scheme: ' + url.protocol);
  if (!allowed.includes(url.hostname)) throw new Error('host not in OUTBOUND_ALLOWLIST: ' + url.hostname);
  return url.toString();
}`,
  );
  return {
    content: out.join('\n'),
    description: 'Outbound URL is now validated against an allow-list (OUTBOUND_ALLOWLIST) before the request.',
    notes: ['Set OUTBOUND_ALLOWLIST to the hosts this endpoint is meant to reach.'],
  };
};

export const pathBasename: Fixer = ({ finding, content }) => {
  let lines = content.split('\n');
  const idx = locate(lines, finding);
  if (idx < 0) return null;
  const u = useExport(lines, 'path', 'basename', 'path');
  lines = u.lines;
  const shift = lines.length - content.split('\n').length;
  const i = idx + shift;
  const line = lines[i];
  const m = /\b(readFile|readFileSync|createReadStream|sendFile|download|unlink|writeFile)\w*\s*\(/.exec(line);
  if (!m) return null;
  const open = m.index + m[0].length - 1;
  const close = matchParen(line, open);
  if (close < 0) return null;
  const inner = line.slice(open + 1, close).replace(TAINT, (t) => `${u.ref}(String(${t}))`);
  if (inner === line.slice(open + 1, close)) return null;
  lines[i] = line.slice(0, open + 1) + inner + line.slice(close);
  return {
    content: lines.join('\n'),
    description: 'Reduced the user-supplied name to its basename so "../" sequences cannot leave the intended directory.',
  };
};

export const corsAllowlist: Fixer = ({ finding, content }) => {
  const expr = "(process.env.CORS_ORIGINS || 'http://localhost:3000').split(',')";
  const lines = edit(content, finding, (line) =>
    line
      .replace(/\bcors\s*\(\s*\)/, `cors({ origin: ${expr} })`)
      .replace(/origin\s*:\s*(['"]\*['"]|true)\b/, `origin: ${expr}`)
      .replace(/(Access-Control-Allow-Origin['"]?\s*,\s*)['"]\*['"]/, "$1process.env.CORS_ORIGIN || 'http://localhost:3000'"),
  );
  if (!lines) return null;
  return { content: lines.join('\n'), description: 'Replaced the wildcard CORS policy with an explicit origin list (CORS_ORIGINS).' };
};

export const cookieFlags: Fixer = ({ finding, content }) => {
  const lines = edit(content, finding, (line) => line.replace(/httpOnly\s*:\s*false/, 'httpOnly: true').replace(/secure\s*:\s*false/, 'secure: true'));
  if (!lines) return null;
  return { content: lines.join('\n'), description: 'Turned on HttpOnly and Secure for the cookie.' };
};

export const addHelmet: Fixer = ({ finding, content }) => {
  let lines = content.split('\n');
  const idx = locate(lines, finding);
  if (idx < 0) return null;
  const m = /(\w+)\s*=\s*express\s*\(\s*\)/.exec(lines[idx]);
  if (!m) return null;
  const indent = /^\s*/.exec(lines[idx])![0];
  lines.splice(idx + 1, 0, `${indent}${m[1]}.use(helmet());`);
  lines = ensureImport(lines, 'helmet', 'helmet', { default: true });
  return {
    content: lines.join('\n'),
    description: 'Added helmet middleware for standard security headers (CSP, HSTS, X-Content-Type-Options, ...).',
    notes: ['Run "npm install helmet" to add the dependency.'],
  };
};

export const jwtVerify: Fixer = ({ finding, content }) => {
  const secretName = /\b(?:const|let|var)\s+([A-Z_]*SECRET[A-Z_]*|jwtSecret)\s*=/.exec(content)?.[1] || 'process.env.JWT_SECRET';
  const lines = edit(content, finding, (line) => {
    const m = /\bjwt\.decode\s*\(/.exec(line);
    if (m) {
      const open = m.index + m[0].length - 1;
      const close = matchParen(line, open);
      if (close < 0) return null;
      const token = line.slice(open + 1, close).split(',')[0].trim();
      return line.slice(0, m.index) + `jwt.verify(${token}, ${secretName}, { algorithms: ['HS256'] })` + line.slice(close + 1);
    }
    return line.replace(/(algorithms\s*:\s*\[)[^\]]*['"]none['"][^\]]*\]/i, "$1'HS256']");
  });
  if (!lines) return null;
  return {
    content: lines.join('\n'),
    description: `Verify the token signature with ${secretName} and pin the algorithm to HS256 instead of trusting decoded claims.`,
    notes: ['jwt.verify throws on an invalid token; make sure the caller handles that (401).'],
  };
};

export const weakHash: Fixer = ({ finding, content }) => {
  const lines = edit(content, finding, (line) => line.replace(/createHash\s*\(\s*(['"])(md5|sha1)\1\s*\)/i, "createHash('sha256')").replace(/hashlib\.(md5|sha1)\s*\(/, 'hashlib.sha256('));
  if (!lines) return null;
  return {
    content: lines.join('\n'),
    description: 'Switched the hash to SHA-256.',
    notes: ['If this hashes passwords, use bcrypt/scrypt/argon2 instead; existing stored hashes need a migration.'],
  };
};

export const secureRandom: Fixer = ({ finding, content }) => {
  let lines = content.split('\n');
  const idx = locate(lines, finding);
  if (idx < 0) return null;
  const before = lines.length;
  const toString36 = /Math\.random\(\)\.toString\(36\)\.(?:slice|substring|substr)\([^)]*\)/;
  const fn = toString36.test(lines[idx]) ? 'randomBytes' : 'randomInt';
  const u = useExport(lines, 'crypto', fn, 'crypto');
  lines = u.lines;
  const i = idx + (lines.length - before);
  const next = lines[i].replace(toString36, `${u.ref}(16).toString('hex')`).replace(/Math\.random\(\)/g, `(${u.ref}(0, 2 ** 48) / 2 ** 48)`);
  if (next === lines[i]) return null;
  lines[i] = next;
  return { content: lines.join('\n'), description: `Generated the value with crypto.${fn} (CSPRNG) instead of Math.random.` };
};

export const tlsVerify: Fixer = ({ finding, content }): FixOutput | null => {
  const lines = content.split('\n');
  const idx = locate(lines, finding);
  if (idx < 0) return null;
  const line = lines[idx];
  if (/NODE_TLS_REJECT_UNAUTHORIZED/.test(line)) {
    lines.splice(idx, 1);
    return { content: lines.join('\n'), description: 'Removed the global NODE_TLS_REJECT_UNAUTHORIZED=0 override.' };
  }
  const next = line
    .replace(/rejectUnauthorized\s*:\s*false/, 'rejectUnauthorized: true')
    .replace(/,\s*verify\s*=\s*False/, '')
    .replace(/verify\s*=\s*False/, 'verify=True');
  if (next === line) return null;
  lines[idx] = next;
  return { content: lines.join('\n'), description: 'Re-enabled TLS certificate verification.', notes: ['For private CAs pass the CA bundle (ca: / verify="ca.pem") rather than disabling checks.'] };
};

export const yamlSafeLoad: Fixer = ({ finding, content }) => {
  const lines = edit(content, finding, (line) => line.replace(/\byaml\.load\s*\(([^,)]+)(?:,\s*Loader\s*=\s*[\w.]+)?\)/, 'yaml.safe_load($1)'));
  if (!lines) return null;
  return { content: lines.join('\n'), description: 'Switched to yaml.safe_load, which only builds plain data types.' };
};

export const flaskDebug: Fixer = ({ finding, content }) => {
  const lines = edit(content, finding, (line) => line.replace(/debug\s*=\s*True/, 'debug=os.environ.get("FLASK_DEBUG") == "1"'));
  if (!lines) return null;
  return { content: ensurePyImport(lines, 'os').join('\n'), description: 'Debug mode is now opt-in through FLASK_DEBUG=1 instead of always on.' };
};

/** _.merge({}, req.body) -> _.merge({}, withoutProtoKeys(req.body)) */
export const stripProtoKeys: Fixer = ({ finding, content, path }) => {
  const lines = edit(content, finding, (line) => line.replace(/(,\s*)(req(?:uest)?\.(?:body|query)(?:\.[\w$]+)*)/, '$1withoutProtoKeys($2)'));
  if (!lines) return null;
  const sig = isTs(path) ? 'function withoutProtoKeys<T>(value: T): T' : 'function withoutProtoKeys(value)';
  const out = ensureHelper(
    lines,
    'withoutProtoKeys',
    `// Deep copy of client JSON without "__proto__" / "constructor" / "prototype" keys (added by SentinelOps)
${sig} {
  return JSON.parse(JSON.stringify(value ?? {}), (key, v) => (key === '__proto__' || key === 'constructor' || key === 'prototype' ? undefined : v));
}`,
  );
  return { content: out.join('\n'), description: 'Strip prototype-polluting keys from client input before the deep merge.' };
};

/** res.status(500).send(err.stack) -> res.status(500).send('Internal Server Error') */
export const genericError: Fixer = ({ finding, content }) => {
  const lines = edit(content, finding, (line) =>
    line.replace(/(res\.(?:status\(\d+\)\.)?(?:send|json)\s*\(\s*)(err|error|e)(\.stack|\.message)?(\s*\))/, (_m, pre: string, _v: string, _p: string, post: string) => `${pre}${/json\s*\($/.test(pre) ? "{ error: 'Internal Server Error' }" : "'Internal Server Error'"}${post}`),
  );
  if (!lines) return null;
  return { content: lines.join('\n'), description: 'Clients get a generic error message instead of the stack trace / internal error text.', notes: ['Log the error server-side (with a request id) so it can still be debugged.'] };
};
