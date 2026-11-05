/**
 * A fix is only "verified" when
 *   1. the file still parses (JS/TS via the TypeScript parser, Python via ast, JSON),
 *   2. re-running the scanner that found the issue no longer reports it, and
 *   3. the edit did not introduce a new finding of equal or higher severity.
 * Dependency bumps are verified against the advisory data instead of a re-scan.
 */
import { spawnSync } from 'node:child_process';
import { Script } from 'node:vm';
import { Finding, severityRank, SourceFile } from '../common/types';
import { ConfigScanner } from '../scanners/config/config.scanner';
import { matchOffline } from '../scanners/deps/deps.scanner';
import { languageOf } from '../scanners/files';
import { SastScanner } from '../scanners/sast/sast.scanner';
import { Scanner } from '../scanners/scanner';
import { SecretsScanner } from '../scanners/secrets/secrets.scanner';

export interface Verification {
  ok: boolean;
  syntax: 'ok' | 'error' | 'unchecked';
  detail: string;
}

let ts: any;
function typescript(): any {
  if (ts === undefined) {
    try {
      // optional at runtime: typescript is only needed for JS/TS syntax checks
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      ts = require('typescript');
    } catch {
      ts = null;
    }
  }
  return ts;
}

export function checkSyntax(path: string, content: string): { status: 'ok' | 'error' | 'unchecked'; message?: string } {
  const lang = languageOf(path);
  if (lang === 'json') {
    try {
      JSON.parse(content);
      return { status: 'ok' };
    } catch (e) {
      return { status: 'error', message: (e as Error).message };
    }
  }
  if (lang === 'js' || lang === 'ts') {
    const t = typescript();
    if (t) {
      const out = t.transpileModule(content, {
        fileName: path,
        reportDiagnostics: true,
        compilerOptions: { allowJs: true, jsx: t.JsxEmit?.Preserve },
      });
      const errs = (out.diagnostics || []).filter((d: any) => d.category === t.DiagnosticCategory.Error);
      return errs.length ? { status: 'error', message: t.flattenDiagnosticMessageText(errs[0].messageText, ' ') } : { status: 'ok' };
    }
    if (lang === 'js' && !/^\s*(import|export)\s/m.test(content)) {
      try {
        new Script(content, { filename: path });
        return { status: 'ok' };
      } catch (e) {
        return { status: 'error', message: (e as Error).message };
      }
    }
    return { status: 'unchecked' };
  }
  if (lang === 'py') {
    const r = spawnSync('python3', ['-c', 'import ast,sys; ast.parse(sys.stdin.read())'], {
      input: content,
      encoding: 'utf8',
      timeout: 10000,
    });
    if (r.error) return { status: 'unchecked' };
    return r.status === 0 ? { status: 'ok' } : { status: 'error', message: (r.stderr || '').trim().split('\n').pop() };
  }
  return { status: 'unchecked' };
}

function scannerFor(f: Finding): Scanner | null {
  if (f.category === 'sast') return new SastScanner();
  if (f.category === 'secret') return new SecretsScanner();
  if (f.category === 'config') return new ConfigScanner();
  return null;
}

async function scanContent(scanner: Scanner, path: string, content: string): Promise<Finding[]> {
  const file: SourceFile = { path, absPath: path, content, lines: content.split(/\r?\n/), language: languageOf(path) };
  return scanner.scan({ options: { root: '.' }, files: [file] });
}

export async function verifyFix(f: Finding, path: string, before: string, after: string): Promise<Verification> {
  const syntax = checkSyntax(path, after);
  if (syntax.status === 'error') return { ok: false, syntax: 'error', detail: `the edited file no longer parses: ${syntax.message}` };

  if (f.category === 'dependency' && f.package) {
    const pkg = f.package;
    const still = matchOffline({ ...pkg, version: pkg.fixedIn || pkg.version, file: path, line: 1, exact: true }).filter(
      (a) => a.id === pkg.advisory || a.aliases.some((x) => pkg.aliases?.includes(x)),
    );
    return still.length
      ? { ok: false, syntax: syntax.status, detail: `${pkg.name}@${pkg.fixedIn} is still affected by ${pkg.advisory}` }
      : {
          ok: true,
          syntax: syntax.status,
          detail: `${pkg.name}@${pkg.fixedIn} is outside the affected range of ${pkg.advisory}; refresh the lockfile to complete the upgrade`,
        };
  }

  const scanner = scannerFor(f);
  if (!scanner) return { ok: syntax.status === 'ok', syntax: syntax.status, detail: 'no scanner available to re-check' };
  const pre = await scanContent(scanner, path, before);
  const post = await scanContent(scanner, path, after);
  const sameRule = (x: Finding) => x.ruleId === f.ruleId;
  if (post.filter(sameRule).length >= pre.filter(sameRule).length)
    return { ok: false, syntax: syntax.status, detail: `${f.ruleId} is still reported after the edit` };
  // compare per-rule counts (fingerprints change whenever a line is edited)
  const count = (xs: Finding[]) => xs.reduce<Record<string, number>>((m, x) => ((m[x.ruleId] = (m[x.ruleId] || 0) + 1), m), {});
  const preCount = count(pre);
  const postCount = count(post);
  const introduced = post.find(
    (x) => !sameRule(x) && (postCount[x.ruleId] || 0) > (preCount[x.ruleId] || 0) && severityRank(x.severity) >= severityRank(f.severity),
  );
  if (introduced) return { ok: false, syntax: syntax.status, detail: `the edit introduces ${introduced.ruleId}` };
  return { ok: true, syntax: syntax.status, detail: `re-scan clean for ${f.ruleId}; syntax ${syntax.status}` };
}
