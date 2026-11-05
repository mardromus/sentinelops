import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, extname, join, relative, sep } from 'node:path';
import { SourceFile } from '../common/types';

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'coverage',
  'vendor',
  '.venv',
  'venv',
  '__pycache__',
  '.next',
  '.nuxt',
  'out',
  '.cache',
  '.terraform',
  'target',
  '.sentinelops',
]);

export const DEFAULT_MAX_BYTES = 1_000_000;

export function languageOf(path: string): SourceFile['language'] {
  const name = basename(path).toLowerCase();
  const ext = extname(name);
  if (name === 'dockerfile' || name.startsWith('dockerfile.') || ext === '.dockerfile') return 'docker';
  if (name === '.env' || name.startsWith('.env.')) return 'env';
  if (['.js', '.jsx', '.mjs', '.cjs'].includes(ext)) return 'js';
  if (['.ts', '.tsx', '.mts', '.cts'].includes(ext)) return 'ts';
  if (ext === '.py') return 'py';
  if (['.yml', '.yaml'].includes(ext)) return 'yaml';
  if (ext === '.json') return 'json';
  return 'other';
}

function isBinary(buf: Buffer): boolean {
  const n = Math.min(buf.length, 8000);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

/** Walk a directory tree and load every text file worth scanning. */
export function loadFiles(root: string, opts: { exclude?: string[]; maxFileBytes?: number } = {}): SourceFile[] {
  const max = opts.maxFileBytes ?? DEFAULT_MAX_BYTES;
  const exclude = (opts.exclude || []).map((e) => e.replace(/\\/g, '/'));
  const out: SourceFile[] = [];
  const walk = (dir: string) => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries.sort()) {
      const abs = join(dir, name);
      const rel = relative(root, abs).split(sep).join('/');
      if (exclude.some((e) => rel === e || rel.startsWith(e.endsWith('/') ? e : e + '/'))) continue;
      let st;
      try {
        st = statSync(abs);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(name)) walk(abs);
        continue;
      }
      if (!st.isFile() || st.size > max) continue;
      const buf = readFileSync(abs);
      if (isBinary(buf)) continue;
      const content = buf.toString('utf8');
      out.push({ path: rel, absPath: abs, content, lines: content.split(/\r?\n/), language: languageOf(rel) });
    }
  };
  walk(root);
  return out;
}

/** Stable identity of a finding: survives line moves, changes when the code changes. */
export function fingerprint(ruleId: string, file: string, snippet: string): string {
  const norm = snippet.replace(/\s+/g, ' ').trim();
  return createHash('sha256').update(`${ruleId}\u0000${file}\u0000${norm}`).digest('hex');
}

export function shortId(fp: string): string {
  return 'SO-' + fp.slice(0, 8);
}

/** Inline suppression: "sentinelops-ignore" on the line or the line above. */
export function isSuppressedInline(lines: string[], lineIdx: number): boolean {
  const re = /sentinelops-ignore/;
  return re.test(lines[lineIdx] || '') || (lineIdx > 0 && re.test(lines[lineIdx - 1] || ''));
}

export function isCommentLine(line: string): boolean {
  const t = line.trim();
  return t.startsWith('//') || t.startsWith('#') || t.startsWith('*') || t.startsWith('/*');
}
