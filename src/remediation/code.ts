/**
 * Small source-editing helpers shared by the rule fixers: locating the
 * finding's line after earlier edits moved it, splitting call arguments,
 * and adding imports / helper functions idempotently.
 */
import { Finding } from '../common/types';

/** Find the finding's line: exact line first, then the snippet within +-30 lines. */
export function locate(lines: string[], f: Finding): number {
  const idx = f.location.line - 1;
  const snip = (f.location.snippet || '').trim();
  // secret snippets are masked ("abcd****yz"): match the masked run as a wildcard
  const masked = /\*{4,}/.test(snip)
    ? new RegExp(
        '^' +
          snip
            .split(/\*{4,}/)
            .map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
            .join('.+?') +
          '$',
      )
    : null;
  const same = (line: string | undefined) => {
    if (line === undefined) return false;
    const t = line.trim();
    if (masked) return masked.test(t) || masked.test(t.slice(0, 240));
    return t === snip || (snip.length >= 240 && t.startsWith(snip));
  };
  if (!snip || same(lines[idx])) return idx;
  for (let d = 1; d <= 30; d++) {
    for (const k of [idx + d, idx - d]) if (k >= 0 && k < lines.length && same(lines[k])) return k;
  }
  return lines[idx] !== undefined ? idx : -1;
}

/** Index of the parenthesis that closes the one at `open`, honouring strings and template literals. */
export function matchParen(s: string, open: number): number {
  let depth = 0;
  let quote: string | null = null;
  for (let i = open; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') quote = c;
    else if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/**
 * End of the first call argument after the "(" at `open`: the index of the
 * top-level "," or ")" that ends it. Works when the rest of the call (for
 * example a multi-line callback) continues on later lines.
 */
export function firstArgEnd(s: string, open: number): { end: number; closed: boolean } | null {
  let depth = 0;
  let quote: string | null = null;
  for (let i = open + 1; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') quote = c;
    else if ('([{'.includes(c)) depth++;
    else if (')]}'.includes(c)) {
      if (depth === 0) return { end: i, closed: true };
      depth--;
    } else if (c === ',' && depth === 0) return { end: i, closed: false };
  }
  return null;
}

/** Add "import <mod>" to a Python file, below any header comments / docstring, above the first import. */
export function ensurePyImport(lines: string[], mod: string): string[] {
  if (lines.some((l) => new RegExp(`^\\s*import\\s+([\\w.]+\\s*,\\s*)*${mod}\\b|^\\s*from\\s+${mod}\\s+import`).test(l))) return lines;
  let at = lines.findIndex((l) => /^\s*(import|from)\s+\w/.test(l));
  if (at < 0) {
    at = 0;
    while (at < lines.length && (/^\s*#/.test(lines[at]) || lines[at].trim() === '')) at++;
  }
  return [...lines.slice(0, at), `import ${mod}`, ...lines.slice(at)];
}

/** Split on a separator at nesting depth 0 (outside strings/brackets). */
export function splitTopLevel(s: string, sep: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let cur = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      cur += c;
      if (c === '\\') cur += s[++i] ?? '';
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') quote = c;
    if ('([{'.includes(c)) depth++;
    if (')]}'.includes(c)) depth--;
    if (c === sep && depth === 0) {
      out.push(cur);
      cur = '';
      continue;
    }
    cur += c;
  }
  out.push(cur);
  return out;
}

export function isEsm(content: string): boolean {
  return /^\s*import\s.+from\s+['"]/m.test(content) || /^\s*export\s/m.test(content);
}

/** Ensure `name` is importable from `mod`; returns the updated lines. */
export function ensureImport(lines: string[], mod: string, name: string, opts: { default?: boolean } = {}): string[] {
  const content = lines.join('\n');
  const esc = mod.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  const modRe = `['"](?:node:)?${esc}['"]`;
  if (new RegExp(`(require\\(${modRe}\\)|from\\s+${modRe})`).test(content)) {
    // module is imported already: add a named import to an existing destructure if needed
    if (opts.default) return lines;
    if (new RegExp(`\\b${name}\\b`).test(content.match(new RegExp(`.*(require\\(${modRe}\\)|from\\s+${modRe}).*`))?.[0] || ''))
      return lines;
    return lines.map((l) =>
      new RegExp(`(require\\(${modRe}\\)|from\\s+${modRe})`).test(l) && /\{[^}]*\}/.test(l)
        ? l.replace(/\{\s*([^}]*?)\s*\}/, (_m, inner) => `{ ${inner}, ${name} }`)
        : l,
    );
  }
  const stmt = isEsm(content)
    ? opts.default
      ? `import ${name} from '${mod}';`
      : `import { ${name} } from '${mod}';`
    : opts.default
      ? `const ${name} = require('${mod}');`
      : `const { ${name} } = require('${mod}');`;
  // after the last top-of-file import/require, else after a shebang / 'use strict'
  let at = 0;
  for (let i = 0; i < Math.min(lines.length, 80); i++) {
    if (/^\s*(import\s|const .*=\s*require\(|let .*=\s*require\(|var .*=\s*require\()/.test(lines[i])) at = i + 1;
  }
  if (at === 0 && lines[0] && /^(#!|['"]use strict['"])/.test(lines[0])) at = 1;
  return [...lines.slice(0, at), stmt, ...lines.slice(at)];
}

/** Append a helper function once (identified by its name). */
export function ensureHelper(lines: string[], name: string, source: string): string[] {
  if (new RegExp(`function\\s+${name}\\s*\\(`).test(lines.join('\n'))) return lines;
  const trimmed = [...lines];
  while (trimmed.length && trimmed[trimmed.length - 1].trim() === '') trimmed.pop();
  return [...trimmed, '', ...source.trim().split('\n'), ''];
}

export function envName(identifier: string): string {
  return identifier
    .replace(/^.*\./, '')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase();
}
