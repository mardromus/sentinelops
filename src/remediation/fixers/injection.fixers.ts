/**
 * Fixers for injection-class findings (OWASP A03): SQL parameterisation,
 * shell-free process execution and eval removal.
 */
import { ensureImport, firstArgEnd, locate, splitTopLevel } from '../code';
import { Fixer } from './types';

const MARK = '\u0000';
const MARKS = new RegExp(MARK, 'g');

function isStringLiteral(s: string): boolean {
  return /^(['"]).*\1$/s.test(s) && !/^(['"]).*\1\s*\+/.test(s);
}

/** Template literal or "a" + b + "c" concatenation -> text with MARKs where expressions were. */
function explode(arg: string): { marked: string; exprs: string[] } | null {
  const exprs: string[] = [];
  if (/^`[\s\S]*`$/.test(arg)) {
    return { marked: arg.slice(1, -1).replace(/\$\{([^}]*)\}/g, (_x, e: string) => (exprs.push(e.trim()), MARK)), exprs };
  }
  const parts = splitTopLevel(arg, '+').map((p) => p.trim());
  if (parts.length < 2 || !parts.some(isStringLiteral)) return null;
  let marked = '';
  for (const p of parts) {
    if (isStringLiteral(p)) marked += p.slice(1, -1);
    else {
      exprs.push(p);
      marked += MARK;
    }
  }
  return { marked, exprs };
}

/**
 * Turn the pieces of a built SQL string into (sql, params). A value wrapped in
 * quotes inside the SQL ('...${x}...') becomes a bare placeholder; any text
 * around it inside the quotes (LIKE '%x%') moves into the parameter.
 */
function buildSql(sqlWithMarks: string, exprs: string[], placeholder: (n: number) => string): { sql: string; params: string[] } {
  const params: string[] = [];
  let k = 0;
  let n = 0;
  const sql = sqlWithMarks.replace(/'([^'\u0000]*)\u0000([^']*)'|\u0000/g, (_m, pre?: string, post?: string) => {
    const expr = exprs[k++];
    n++;
    if (pre === undefined) params.push(expr);
    else params.push(pre || post ? '`' + `${pre}\${${expr}}${post}` + '`' : expr);
    return placeholder(n);
  });
  return { sql, params };
}

function placeholderStyle(content: string, py = false): (n: number) => string {
  if (py) return /\bsqlite3\b/.test(content) ? () => '?' : () => '%s';
  if (/require\(['"]pg['"]\)|from ['"]pg['"]|new (Pool|Client)\(/.test(content)) return (n) => `$${n}`;
  return () => '?';
}

export const sqlParameterize: Fixer = ({ finding, content }) => {
  const lines = content.split('\n');
  const idx = locate(lines, finding);
  if (idx < 0) return null;
  const line = lines[idx];
  const call = /\.(query|execute|exec|raw|all|get|run)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = call.exec(line))) {
    const open = m.index + m[0].length - 1;
    const arg = firstArgEnd(line, open);
    if (!arg) continue;
    const first = line.slice(open + 1, arg.end).trim();
    if (!arg.closed && /^\s*\[/.test(line.slice(arg.end + 1))) continue; // already has a parameter array
    const ex = explode(first);
    if (!ex || !ex.exprs.length || !/\b(select|insert|update|delete)\b/i.test(ex.marked)) continue;
    const { sql, params } = buildSql(ex.marked, ex.exprs, placeholderStyle(content));
    const rebuilt = `"${sql.replace(/"/g, '\\"')}", [${params.join(', ')}]`;
    lines[idx] = line.slice(0, open + 1) + rebuilt + line.slice(arg.end);
    return {
      content: lines.join('\n'),
      description: `Parameterised the SQL query: ${params.length} value(s) are now sent separately from the SQL text.`,
    };
  }
  return null;
};

export const pySqlParameterize: Fixer = ({ finding, content }) => {
  const lines = content.split('\n');
  const idx = locate(lines, finding);
  if (idx < 0) return null;
  const line = lines[idx];
  const m = /\.execute\(\s*f(["'])(.*?)\1\s*\)/.exec(line);
  if (!m) return null;
  const exprs: string[] = [];
  const marked = m[2].replace(/\{([^}]+)\}/g, (_x, e: string) => (exprs.push(e.trim()), MARK));
  if (!exprs.length) return null;
  const { sql, params } = buildSql(marked, exprs, placeholderStyle(content, true));
  const pyParams = params.map((p) => (p.startsWith('`') ? `f"${p.slice(1, -1).replace(/\$\{/g, '{')}"` : p));
  const tuple = `(${pyParams.join(', ')}${pyParams.length === 1 ? ',' : ''})`;
  lines[idx] = line.slice(0, m.index) + `.execute("${sql.replace(/"/g, '\\"')}", ${tuple})` + line.slice(m.index + m[0].length);
  return { content: lines.join('\n'), description: `Parameterised the SQL query (${params.length} bound value(s)).` };
};

/** Split "prog a ${x} b" into argv tokens; null when the command needs a real shell. */
function argv(cmd: string, exprs: string[], literal: (t: string) => string, interp: (t: string) => string): string[] | null {
  if (/[|&;<>$`'"\\*?(){}~]/.test(cmd.replace(MARKS, ''))) return null; // pipes, redirects, quoting, globs: leave to a human
  const raw = cmd.trim().split(/\s+/);
  if (!raw[0] || raw[0].includes(MARK)) return null; // the program itself must be fixed
  let k = 0;
  return raw.map((tok) => {
    if (tok === MARK) return exprs[k++];
    if (tok.includes(MARK)) return interp(tok.replace(MARKS, () => `\u0001${exprs[k++]}\u0002`));
    return literal(tok);
  });
}

/** exec(`convert ${f} out.png`, cb) -> execFile('convert', [f, 'out.png'], cb) */
export const execToExecFile: Fixer = ({ finding, content }) => {
  let lines = content.split('\n');
  const idx = locate(lines, finding);
  if (idx < 0) return null;
  const line = lines[idx];
  const m = /(\.?)\b(exec|execSync)\s*\(/.exec(line);
  if (!m) return null;
  const open = m.index + m[0].length - 1;
  const arg = firstArgEnd(line, open);
  if (!arg) return null;
  const ex = explode(line.slice(open + 1, arg.end).trim());
  if (!ex) return null;
  const tokens = argv(
    ex.marked,
    ex.exprs,
    (t) => `'${t}'`,
    (t) => '`' + t.replace(/\u0001/g, '${').replace(/\u0002/g, '}') + '`',
  );
  if (!tokens) return null;
  const fn = m[2] === 'exec' ? 'execFile' : 'execFileSync';
  lines[idx] = line.slice(0, m.index) + m[1] + fn + '(' + `${tokens[0]}, [${tokens.slice(1).join(', ')}]` + line.slice(arg.end);
  if (!m[1]) lines = ensureImport(lines, 'child_process', fn);
  return {
    content: lines.join('\n'),
    description: `Replaced ${m[2]} (runs through /bin/sh) with ${fn} and an argument array, so input can no longer add shell commands.`,
  };
};

/** subprocess.run(f"tar czf {name}.tgz dir", shell=True) -> subprocess.run(["tar", "czf", f"{name}.tgz", "dir"]) */
export const pyShellToList: Fixer = ({ finding, content }) => {
  const lines = content.split('\n');
  const idx = locate(lines, finding);
  if (idx < 0) return null;
  const line = lines[idx];
  const m = /\b(subprocess\.(?:run|call|check_call|check_output|Popen))\(\s*(f?)(["'])(.*?)\3\s*,([^)]*)\bshell\s*=\s*True\b([^)]*)\)/.exec(
    line,
  );
  if (!m) return null;
  const exprs: string[] = [];
  const marked = m[2] ? m[4].replace(/\{([^}]+)\}/g, (_x, e: string) => (exprs.push(e.trim()), MARK)) : m[4];
  const tokens = argv(
    marked,
    exprs,
    (t) => `"${t}"`,
    (t) => 'f"' + t.replace(/\u0001/g, '{').replace(/\u0002/g, '}') + '"',
  );
  if (!tokens) return null;
  const rest = (m[5] + m[6])
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
  const call = `${m[1]}([${tokens.join(', ')}]${rest.length ? ', ' + rest.join(', ') : ''})`;
  lines[idx] = line.slice(0, m.index) + call + line.slice(m.index + m[0].length);
  return {
    content: lines.join('\n'),
    description: 'Run the program directly with an argument list instead of through a shell (shell=True removed).',
  };
};

export const evalToJsonParse: Fixer = ({ finding, content }) => {
  const lines = content.split('\n');
  const idx = locate(lines, finding);
  if (idx < 0 || !/(^|[^.\w])eval\s*\(/.test(lines[idx])) return null;
  lines[idx] = lines[idx].replace(/(^|[^.\w])eval\s*\(/, '$1JSON.parse(');
  return {
    content: lines.join('\n'),
    description: 'Replaced eval with JSON.parse: the input is parsed as data and can no longer execute code.',
    notes: ['This changes behaviour if the value was an expression: use a dedicated expression parser for that.'],
  };
};
