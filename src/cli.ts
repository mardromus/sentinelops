#!/usr/bin/env node
/**
 * sentinelops CLI
 *
 *   sentinelops scan <path> [options]   scan, triage, review, report (exit 1 when the gate fails)
 *   sentinelops baseline <path>         accept current findings (writes .sentinelops/baseline.json)
 *   sentinelops serve [--port 3000]     API, dashboard and GitHub webhook
 *   sentinelops rules                   built-in rule catalogue
 *   sentinelops audit                   verify the audit trail
 */
import 'reflect-metadata';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { NestFactory } from '@nestjs/core';
import { AuditLog } from './agent/audit';
import { LEVEL_NAMES } from './agent/policy';
import { CliModule } from './app.module';
import { Finding, Severity } from './common/types';
import { AutonomyLevel, loadConfig } from './config/config';
import { PipelineService } from './pipeline/pipeline.service';
import { hasFixer } from './remediation/fixers';
import { toHtml } from './reports/html';
import { toMarkdown } from './reports/markdown';
import { toSarif, TOOL_VERSION } from './reports/sarif';
import { RULES } from './scanners/sast/rules';
import { ScannersService } from './scanners/scanners.service';
import { BaselineEntry } from './triage/triage.service';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export interface Args {
  cmd: string;
  positional: string[];
  flags: Record<string, string | boolean>;
}

export function parseArgs(argv: string[]): Args {
  const [cmd = 'help', ...rest] = argv;
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a.startsWith('--no-')) flags[a.slice(5)] = false;
    else if (a.startsWith('--')) {
      const [k, v] = a.slice(2).split('=', 2);
      if (v !== undefined) flags[k] = v;
      else if (rest[i + 1] !== undefined && !rest[i + 1].startsWith('--')) flags[k] = rest[++i];
      else flags[k] = true;
    } else positional.push(a);
  }
  return { cmd, positional, flags };
}

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string) => (s: string) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const C = {
  bold: paint('1'),
  dim: paint('2'),
  red: paint('31'),
  green: paint('32'),
  yellow: paint('33'),
  blue: paint('34'),
  magenta: paint('35'),
  cyan: paint('36'),
};
const SEV_PAINT: Record<Severity, (s: string) => string> = {
  critical: (s) => C.bold(C.red(s)),
  high: C.red,
  medium: C.yellow,
  low: C.blue,
  info: C.dim,
};

function write(path: string, content: string): string {
  const p = resolve(path);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, content);
  return p;
}

const HELP = `${C.bold('sentinelops')} ${TOOL_VERSION} - autonomous DevSecOps agent (OWASP Top 10, CWE, OSV)

${C.bold('Usage')}
  sentinelops scan <path> [options]
  sentinelops baseline <path> [--reason "accepted risk"]
  sentinelops serve [--port 3000]
  sentinelops rules
  sentinelops audit

${C.bold('scan options')}
  --sarif <file>       write SARIF 2.1.0 (GitHub code scanning)
  --html <file>        write the self-contained HTML report
  --md <file>          write the Markdown summary (PR comment / job summary)
  --json <file>        write the raw result
  --fail-on <sev>      gate threshold: critical | high | medium | low (default: high)
  --ai                 agent review (LLM when SENTINELOPS_LLM_API_KEY is set, else offline planner)
  --offline            force the offline planner
  --fix                apply verified fixes (in place, or into --out-dir)
  --out-dir <dir>      write a fixed copy of the project here instead of editing it
  --autonomy <0-3>     agent autonomy level (default: SENTINELOPS_AUTONOMY or 1)
  --exclude <a,b>      paths to skip
  --no-osv             offline advisory snapshot only (no OSV.dev requests)
  --no-external        do not run semgrep / gitleaks / trivy even if installed
  --no-baseline        ignore .sentinelops/baseline.json
  --top <n>            findings to list in the terminal (default: 12)
`;

function printScan(stored: Awaited<ReturnType<PipelineService['run']>>['stored'], top: number): void {
  const { result, summary, gate, agent } = stored;
  const active = result.findings.filter((f) => !f.suppressed);
  console.log('');
  console.log(`${C.bold('SentinelOps')} scanned ${C.bold(String(result.filesScanned))} files in ${result.root}`);
  console.log(
    '  ' +
      result.scanners
        .map(
          (s) =>
            `${s.name} ${s.status === 'ok' ? C.green('✓') : s.status === 'skipped' ? C.dim('skipped') : C.red('error')}${s.detail && s.status === 'ok' ? C.dim(` (${s.detail})`) : ''}`,
        )
        .join('  '),
  );
  console.log('');
  console.log(
    '  ' +
      SEVERITIES.map((s) => SEV_PAINT[s](`${summary.bySeverity[s] || 0} ${s}`)).join('  ') +
      C.dim(`   ${summary.suppressed} suppressed · risk score ${summary.riskScore}/100`),
  );
  if (stored.diff) console.log(C.dim(`  vs previous scan: +${stored.diff.introduced} introduced, -${stored.diff.fixed} fixed`));
  console.log('');
  for (const f of active.slice(0, top)) printFinding(f);
  if (active.length > top) console.log(C.dim(`  … ${active.length - top} more (see the HTML/SARIF report)`));
  if (agent) {
    console.log('');
    console.log(C.bold(`  Agent (${agent.mode === 'llm' ? agent.model : 'offline planner'}, ${agent.policy})`));
    for (const line of wrap(agent.summary, 96)) console.log('  ' + C.cyan(line));
    for (const e of agent.errors) console.log('  ' + C.dim(e));
  }
  console.log('');
  console.log(
    gate.pass
      ? C.green(`  ✔ gate passed (no active findings at or above ${gate.failOn})`)
      : C.red(`  ✖ gate failed: ${gate.blocking} active finding(s) at or above ${gate.failOn}`),
  );
}

function printFinding(f: Finding): void {
  const fix = f.fix ? (f.fix.verified ? C.green(' [fix ✓]') : C.yellow(' [fix ?]')) : '';
  console.log(`  ${SEV_PAINT[f.severity](f.severity.padEnd(8))} ${C.dim(f.priority || '  ')} ${C.bold(f.id)} ${f.title}${fix}`);
  console.log(`  ${' '.repeat(12)}${C.dim(`${f.location.file}:${f.location.line}  ${f.cwe.join(',')}  ${f.owasp.join(',')}`)}`);
  if (f.verdict && f.verdict.status !== 'true_positive')
    console.log(`  ${' '.repeat(12)}${C.magenta(`agent: ${f.verdict.status.replace(/_/g, ' ')} — ${f.verdict.rationale}`)}`);
}

function wrap(text: string, width: number): string[] {
  const out: string[] = [];
  for (const para of text.split('\n')) {
    let line = '';
    for (const w of para.split(/\s+/)) {
      if ((line + ' ' + w).trim().length > width) {
        out.push(line.trim());
        line = w;
      } else line += ' ' + w;
    }
    out.push(line.trim());
  }
  return out;
}

async function context(overrides: Parameters<typeof CliModule.forRoot>[0] = {}) {
  return NestFactory.createApplicationContext(CliModule.forRoot(overrides), { logger: false });
}

export async function main(argv: string[]): Promise<number> {
  const { cmd, positional, flags } = parseArgs(argv);
  const base = loadConfig();

  if (cmd === 'help' || flags.help || cmd === '--help' || cmd === '-h') {
    console.log(HELP);
    return 0;
  }
  if (cmd === 'version' || cmd === '--version' || cmd === '-v') {
    console.log(TOOL_VERSION);
    return 0;
  }

  if (cmd === 'scan') {
    const root = resolve(positional[0] || '.');
    const failOn = (flags['fail-on'] as Severity) || base.failOn;
    if (!SEVERITIES.includes(failOn)) throw new Error(`--fail-on must be one of ${SEVERITIES.join(', ')}`);
    const autonomy = flags.autonomy !== undefined ? (Math.max(0, Math.min(3, Number(flags.autonomy))) as AutonomyLevel) : base.autonomy;
    const app = await context({ autonomy, failOn });
    try {
      const pipeline = app.get(PipelineService);
      const { stored, applied } = await pipeline.run({
        root,
        exclude: typeof flags.exclude === 'string' ? flags.exclude.split(',') : undefined,
        osv: flags.osv !== false && base.osv,
        external: flags.external !== false && base.external,
        ai: flags.offline ? 'offline' : flags.ai ? true : false,
        fix: flags.fix ? 'apply' : 'propose',
        outDir: typeof flags['out-dir'] === 'string' ? flags['out-dir'] : undefined,
        autonomy,
        failOn,
        baseline: flags.baseline !== false,
        source: { kind: 'cli' },
      });
      printScan(stored, Number(flags.top) || 12);
      const outs: string[] = [];
      if (typeof flags.sarif === 'string') outs.push(write(flags.sarif, JSON.stringify(toSarif(stored.result), null, 2)));
      if (typeof flags.html === 'string')
        outs.push(write(flags.html, toHtml(stored.result, { gate: stored.gate, agent: stored.agent, summary: stored.summary })));
      if (typeof flags.md === 'string')
        outs.push(write(flags.md, toMarkdown(stored.result, { gate: stored.gate, agent: stored.agent, diff: stored.diff })));
      if (typeof flags.json === 'string') outs.push(write(flags.json, JSON.stringify(stored, null, 2)));
      if (applied) {
        console.log(
          C.green(`  ✔ applied ${applied.applied.length} verified fix(es) to ${applied.files.length} file(s) in ${applied.root}`) +
            (applied.skipped.length ? C.dim(` (${applied.skipped.length} skipped)`) : ''),
        );
        for (const f of applied.files) console.log(C.dim(`      ${f.path}`));
        // the patch sits next to the fixed tree, never inside a scanned directory (it contains the removed lines)
        const patch =
          typeof flags['out-dir'] === 'string'
            ? resolve(flags['out-dir']).replace(/[\\/]+$/, '') + '.diff'
            : join(root, '.sentinelops', 'fixes.diff');
        if (applied.files.length) outs.push(write(patch, applied.files.map((f) => f.diff).join('\n')));
      }
      for (const o of outs) console.log(C.dim(`  wrote ${o}`));
      console.log('');
      return stored.gate.pass ? 0 : 1;
    } finally {
      await app.close();
    }
  }

  if (cmd === 'baseline') {
    const root = resolve(positional[0] || '.');
    const app = await context();
    try {
      const res = await app.get(ScannersService).scan({ root, osv: false, external: false });
      const reason = typeof flags.reason === 'string' ? flags.reason : 'accepted at baseline';
      const entries: BaselineEntry[] = res.findings
        .filter((f) => !f.suppressed)
        .map((f) => ({ fingerprint: f.fingerprint, reason: `${reason} (${f.ruleId} ${f.location.file}:${f.location.line})` }));
      const p = write(
        join(root, '.sentinelops', 'baseline.json'),
        JSON.stringify({ createdAt: new Date().toISOString(), entries }, null, 2) + '\n',
      );
      console.log(`baselined ${entries.length} finding(s) -> ${p}\nFuture scans only report new issues. Review the baseline like code.`);
      return 0;
    } finally {
      await app.close();
    }
  }

  if (cmd === 'serve') {
    const { bootstrap } = await import('./main');
    await bootstrap(Number(flags.port) || base.port);
    return new Promise<number>(() => undefined); // keep running
  }

  if (cmd === 'rules') {
    for (const r of RULES) {
      const fix = hasFixer(r.id) ? C.green('autofix') : '       ';
      console.log(`${SEV_PAINT[r.severity](r.severity.padEnd(8))} ${fix} ${r.id.padEnd(40)} ${C.dim(r.cwe.join(','))}  ${r.title}`);
    }
    console.log(
      C.dim(
        `\n${RULES.length} SAST rules + secrets, dependency (OSV) and IaC/pipeline checks. Autonomy levels: ${Object.entries(LEVEL_NAMES)
          .map(([k, v]) => `L${k} ${v}`)
          .join(', ')}`,
      ),
    );
    return 0;
  }

  if (cmd === 'audit') {
    const log = new AuditLog(join(base.dataDir, 'audit.jsonl'));
    const v = log.verify();
    for (const e of log.tail(Number(flags.tail) || 20))
      console.log(
        `${C.dim(String(e.seq).padStart(5))} ${C.dim(e.ts)} ${e.actor.padEnd(6)} ${e.action.padEnd(24)} ${e.target || ''} ${e.allowed === false ? C.red('denied') : ''} ${C.dim(e.reason || '')}`,
      );
    console.log(v.valid ? C.green(`audit chain intact (${v.count} entries)`) : C.red(`audit chain BROKEN at entry ${v.brokenAt}`));
    return v.valid ? 0 : 1;
  }

  console.error(`unknown command "${cmd}"\n`);
  console.log(HELP);
  return 2;
}

if (require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      console.error(C.red(`sentinelops: ${(e as Error).message}`));
      process.exit(2);
    },
  );
}
