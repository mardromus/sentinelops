/**
 * Fixers for injection-class findings (OWASP A03): SQL parameterisation,
 * shell-free process execution and eval removal.
 */
import { ensureImport, locate, matchParen, splitTopLevel } from '../code';
import { Fixer } from './types';

const MARK = '\u0000';

function isStringLiteral(s: string): boolean {
  return /^(['"]).*\1$/s.test(s) && !/^(['"]).*\1\s*\+/.test(s);
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
    const close = matchParen(line, open);
    if (close < 0) continue;
    const args = splitTopLevel(line.slice(open + 1, close), ',');
    const first = args[0].trim();
    if (args.length > 1 && args[1].trim().startsWith('[')) continue; // already has a parameter array
    let marked = '';
    const exprs: string[] = [];
    if (/^`[\s\S]*`$/.test(first)) {
      marked = first.slice(1, -1).replace(/\$\{([^}]*)\}/g, (_x, e: string) => (exprs.push(e.trim()), MARK));
    } else {
      const parts = splitTopLevel(first, '+').map((p) => p.trim());
      if (parts.length < 2 || !parts.some(isStringLiteral)) continue;
      for (const p of parts) {
        if (isStringLiteral(p)) marked += p.slice(1, -1);
        else {
          exprs.push(p);
          marked += MARK;
        }
      }
    }
    if (!exprs.length || !/\b(select|insert|update|delete)\b/i.test(marked)) continue;
    const { sql, params } = buildSql(marked, exprs, placeholderStyle(content));
    const rebuilt = [`"${sql.replace(/"/g, '\\"')}"`, `[${params.join(', ')}]`, ...args.slice(1).map((a) => a.trim())].join(', ');
    lines[idx] = line.slice(0, open + 1) + rebuilt + line.slice(close);
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

/** exec(`convert ${f} out.png`, cb) -> execFile('convert', [f, 'out.png'], cb) */
export const execToExecFile: Fixer = ({ finding, content }) => {
  let lines = content.split('\n');
  const idx = locate(lines, finding);
  if (idx < 0) return null;
  const line = lines[idx];
  const m = /(\.?)\b(exec|execSync)\s*\(/.exec(line);
  if (!m) return null;
  const open = m.index + m[0].length - 1;
  const close = matchParen(line, open);
  if (close < 0) return null;
  const args = splitTopLevel(line.slice(open + 1, close), ',');
  const first = args[0].trim();
  const exprs: string[] = [];
  let cmd: string;
  if (/^`[\s\S]*`$/.test(first)) cmd = first.slice(1, -1).replace(/\$\{([^}]*)\}/g, (_x, e: string) => (exprs.push(e.trim()), MARK));
  else {
    cmd = '';
    for (const p of splitTopLevel(first, '+').map((x) => x.trim())) {
      if (isStringLiteral(p)) cmd += p.slice(1, -1);
      else {
        exprs.push(p);
        cmd += MARK;
      }
    }
  }
  // only rewrite simple "program arg arg" commands: no pipes, redirects, quoting or substitutions
  if (/[|&;<>$`'"\\*?(){}]/.test(cmd.replace(new RegExp(MARK, 'g'), ''))) return null;
  let k = 0;
  const tokens = cmd.trim().split(/\s+/).map((tok) => {
    if (tok === MARK) return exprs[k++];
    if (tok.includes(MARK)) return '`' + tok.replace(new RegExp(MARK, 'g'), () => '${' + exprs[k++] + '}') + '`';
    return `'${tok}'`;
  });
  if (!tokens.length || tokens[0].startsWith('`') || !tokens[0].startsWith("'")) return null;
  const fn = m[2] === 'exec' ? 'execFile' : 'execFileSync';
  const callArgs = [tokens[0], `[${tokens.slice(1).join(', ')}]`, ...args.slice(1).map((a) => a.trim())].join(', ');
  lines[idx] = line.slice(0, m.index) + m[1] + fn + '(' + callArgs + line.slice(close);
  if (!m[1]) lines = ensureImport(lines, 'child_process', fn);
  return {
    content: lines.join('\n'),
    description: `Replaced ${m[2]} (runs through /bin/sh) with ${fn} and an argument array, so input can no longer add shell commands.`,
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
    notes: ['Assumes the evaluated value is JSON. If it was an expression, use a dedicated parser instead.'],
  };
};
