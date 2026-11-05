import { createHash, randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { Inject, Injectable, Optional } from '@nestjs/common';
import { Finding, ScannerRun, ScanOptions, ScanResult, severityRank } from '../common/types';
import { KnowledgeService } from '../knowledge/knowledge.service';
import { ConfigScanner } from './config/config.scanner';
import { DependencyScanner } from './deps/deps.scanner';
import { OsvClient } from './deps/osv.client';
import { ExternalScanner, externalScanners } from './external/external';
import { loadFiles, shortId } from './files';
import { SastScanner } from './sast/sast.scanner';
import { Scanner } from './scanner';
import { SecretsScanner } from './secrets/secrets.scanner';

export const SCANNERS = Symbol('SCANNERS');

export function defaultScanners(): Scanner[] {
  return [new SastScanner(), new SecretsScanner(), new DependencyScanner(new OsvClient()), new ConfigScanner(), ...externalScanners()];
}

/**
 * Identical vulnerable lines in one file would share a fingerprint. Give the
 * 2nd, 3rd ... occurrence its own identity (stable while their order holds).
 */
export function disambiguate(findings: Finding[]): Finding[] {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) groups.set(`${f.scanner}|${f.fingerprint}`, [...(groups.get(`${f.scanner}|${f.fingerprint}`) || []), f]);
  for (const g of groups.values()) {
    if (g.length < 2) continue;
    g.sort((a, b) => a.location.line - b.location.line);
    g.slice(1).forEach((f, i) => {
      if (f.location.line === g[0].location.line) return;
      f.fingerprint = createHash('sha256')
        .update(`${f.fingerprint}#${i + 2}`)
        .digest('hex');
      f.id = shortId(f.fingerprint);
    });
  }
  return findings;
}

/**
 * Two findings are the same issue when the fingerprint matches, or when two
 * different tools report the same CWE (or advisory) at the same place.
 * The higher-severity / built-in one wins and records who else saw it.
 */
export function dedupe(findings: Finding[]): Finding[] {
  const key = (f: Finding) =>
    f.category === 'dependency' && f.package
      ? `dep|${f.package.name}|${f.package.version}|${[...(f.package.aliases || [f.package.advisory])].sort().find((a) => a?.startsWith('CVE-')) || f.package.advisory}`
      : `${f.category}|${f.location.file}|${f.location.line}|${f.cwe[0] || f.ruleId}`;
  const byFp = new Map<string, Finding>();
  for (const f of findings) if (!byFp.has(f.fingerprint)) byFp.set(f.fingerprint, f);
  const out = new Map<string, Finding>();
  for (const f of byFp.values()) {
    const k = key(f);
    const prev = out.get(k);
    if (!prev) {
      out.set(k, f);
      continue;
    }
    const better =
      severityRank(f.severity) > severityRank(prev.severity) ||
      (f.severity === prev.severity && f.scanner.startsWith('builtin') && !prev.scanner.startsWith('builtin'));
    const [keep, drop] = better ? [f, prev] : [prev, f];
    keep.triageNotes = [...(keep.triageNotes || []), `also reported by ${drop.scanner} (${drop.ruleId})`];
    out.set(k, keep);
  }
  return [...out.values()];
}

export function sortFindings(fs: Finding[]): Finding[] {
  return fs.sort(
    (a, b) =>
      Number(!!a.suppressed) - Number(!!b.suppressed) ||
      (b.risk ?? 0) - (a.risk ?? 0) ||
      severityRank(b.severity) - severityRank(a.severity) ||
      a.location.file.localeCompare(b.location.file) ||
      a.location.line - b.location.line,
  );
}

@Injectable()
export class ScannersService {
  private readonly scanners: Scanner[];

  constructor(
    private readonly knowledge: KnowledgeService,
    @Optional() @Inject(SCANNERS) scanners?: Scanner[],
  ) {
    this.scanners = scanners ?? defaultScanners();
  }

  list(): string[] {
    return this.scanners.map((s) => s.name);
  }

  async scan(opts: ScanOptions): Promise<ScanResult> {
    const startedAt = new Date().toISOString();
    const root = resolve(opts.root);
    const options = { ...opts, root };
    const files = loadFiles(root, { exclude: opts.exclude, maxFileBytes: opts.maxFileBytes });
    const runs: ScannerRun[] = [];
    const all: Finding[] = [];

    await Promise.all(
      this.scanners.map(async (s) => {
        const t0 = Date.now();
        if (s instanceof ExternalScanner && (opts.external === false || !s.isAvailable())) {
          runs.push({
            name: s.name,
            status: 'skipped',
            findings: 0,
            durationMs: 0,
            detail: opts.external === false ? 'disabled' : 'not installed',
          });
          return;
        }
        try {
          const fs = await s.scan({ options, files });
          all.push(...fs);
          const detail = s instanceof DependencyScanner ? `advisories: ${s.lastSource}` : undefined;
          runs.push({ name: s.name, status: 'ok', findings: fs.length, durationMs: Date.now() - t0, detail });
        } catch (e) {
          runs.push({
            name: s.name,
            status: 'error',
            findings: 0,
            durationMs: Date.now() - t0,
            detail: (e as Error).message.slice(0, 300),
          });
        }
      }),
    );

    const findings = sortFindings(dedupe(disambiguate(all)).map((f) => this.knowledge.enrich(f)));
    runs.sort((a, b) => this.list().indexOf(a.name) - this.list().indexOf(b.name));
    return {
      id: randomUUID(),
      root,
      startedAt,
      finishedAt: new Date().toISOString(),
      filesScanned: files.length,
      findings,
      scanners: runs,
    };
  }
}
