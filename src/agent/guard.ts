/**
 * Guardrails between the model and the repository.
 *
 * The agent reads attacker-controllable text (source code, PR titles,
 * comments). Everything from the repository is treated as data:
 *   - wrapped in <untrusted> blocks with markup neutralised,
 *   - scanned for prompt-injection phrasing (flagged and reported, never obeyed),
 *   - secrets masked before any of it leaves the machine,
 *   - file access confined to the scan root, with credential files off limits.
 */
import { realpathSync } from 'node:fs';
import { basename, dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { SourceFile } from '../common/types';
import { languageOf } from '../scanners/files';
import { mask } from '../scanners/secrets/patterns';
import { lineHits } from '../scanners/secrets/secrets.scanner';

const INJECTION: { re: RegExp; label: string }[] = [
  { re: /\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|all|earlier|system)\b.{0,20}\b(instructions?|prompts?|rules?|messages?)/i, label: 'instruction override' },
  { re: /\byou are now\b|\bnew (system )?instructions?\b|\bact as (an?|the)\b/i, label: 'role reassignment' },
  { re: /<\|?(im_start|im_end|system|endoftext)\|?>|\[\/?INST\]|^\s*(system|assistant)\s*:/im, label: 'chat-template tokens' },
  { re: /\b(mark|classify|report|treat)\b.{0,40}\b(as )?(a )?(false[ -]positive|safe|not (a )?vulnerab)/i, label: 'verdict steering' },
  { re: /\b(do not|don't|never)\b.{0,30}\b(report|flag|mention|scan)\b/i, label: 'suppression request' },
  { re: /\b(print|reveal|show|output|send)\b.{0,30}\b(system prompt|api key|token|secret|credentials?|env(ironment)? var)/i, label: 'exfiltration request' },
  { re: /\b(curl|wget|fetch)\b.{0,60}https?:\/\/.{0,80}\$\{?\w*(key|token|secret)/i, label: 'exfiltration command' },
];

export interface InjectionReport {
  flagged: boolean;
  labels: string[];
  excerpt?: string;
}

export function detectInjection(text: string): InjectionReport {
  const labels: string[] = [];
  let excerpt: string | undefined;
  for (const { re, label } of INJECTION) {
    const m = re.exec(text);
    if (m) {
      labels.push(label);
      excerpt ??= text.slice(Math.max(0, m.index - 20), m.index + m[0].length + 20).replace(/\s+/g, ' ').trim();
    }
  }
  return { flagged: labels.length > 0, labels, excerpt };
}

/** Mask anything the secrets scanner recognises before text is sent to a model. */
export function redactSecrets(text: string, path = 'snippet.txt'): string {
  const lines = text.split('\n');
  const file: SourceFile = { path, absPath: path, content: text, lines, language: languageOf(path) };
  return lines
    .map((line) => {
      let out = line;
      for (const h of lineHits(line, file)) out = out.split(h.secret).join(mask(h.secret));
      return out;
    })
    .join('\n');
}

/** Wrap repository text so the model can tell data from instructions. */
export function untrusted(source: string, text: string, max = 4000): string {
  const clean = redactSecrets(text, source).slice(0, max).replace(/<\/?untrusted[^>]*>/gi, '[tag removed]');
  return `<untrusted source="${source.replace(/"/g, "'")}">\n${clean}\n</untrusted>`;
}

const BLOCKED_FILES = /(^|\/)(\.env(\..*)?|id_rsa|id_ed25519|.*\.pem|.*\.key|.*\.p12|.*\.pfx|credentials(\.json)?|\.npmrc|\.pypirc|\.netrc|\.git-credentials)$/i;
const BLOCKED_DIRS = /(^|\/)(\.git|node_modules|\.ssh|\.aws|\.gnupg)(\/|$)/;

export class PathSandbox {
  private readonly root: string;

  constructor(root: string) {
    this.root = resolve(root);
  }

  /** Resolve a model-supplied path or throw; returns the path relative to the root. */
  check(p: string): string {
    if (typeof p !== 'string' || !p || p.includes('\0')) throw new Error('invalid path');
    const abs = isAbsolute(p) ? resolve(p) : resolve(this.root, p);
    const rel = relative(this.root, abs);
    if (rel.startsWith('..') || isAbsolute(rel)) throw new Error(`path escapes the repository: ${p}`);
    const real = realpathDeepest(abs);
    const realRel = relative(realpathSafe(this.root), real);
    if (realRel.startsWith('..') || isAbsolute(realRel)) throw new Error(`symlink escapes the repository: ${p}`);
    const norm = rel.split(sep).join('/');
    if (BLOCKED_DIRS.test(norm) || BLOCKED_FILES.test(norm)) throw new Error(`access to ${norm} is not allowed for the agent`);
    return norm;
  }

  abs(rel: string): string {
    return resolve(this.root, rel);
  }
}

/** realpath of the deepest existing ancestor + the rest, so links inside non-existent paths are still resolved. */
function realpathDeepest(abs: string): string {
  let cur = abs;
  const rest: string[] = [];
  for (;;) {
    try {
      return resolve(realpathSync(cur), ...rest.reverse());
    } catch {
      const parent = dirname(cur);
      if (parent === cur) return abs;
      rest.push(basename(cur));
      cur = parent;
    }
  }
}

function realpathSafe(p: string): string {
  try {
    return realpathSync(p);
  } catch {
    return p;
  }
}
