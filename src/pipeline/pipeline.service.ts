/**
 * The end-to-end flow shared by the CLI, the HTTP API and the GitHub webhook:
 *
 *   scan -> triage -> propose fixes -> agent review -> gate -> (apply) -> store
 */
import { cpSync, mkdirSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import { Inject, Injectable } from '@nestjs/common';
import { AgentReport, AgentService } from '../agent/agent.service';
import { ScanOptions, Severity } from '../common/types';
import { APP_CONFIG, AppConfig, AutonomyLevel } from '../config/config';
import { ApplyResult, diskWorkspace, RemediationService } from '../remediation/remediation.service';
import { ScannersService } from '../scanners/scanners.service';
import { ScanSource, ScanStore, StoredScan } from '../store/scan.store';
import { diffScans, TriageService } from '../triage/triage.service';
import { AuditService } from './audit.service';

export interface PipelineOptions extends ScanOptions {
  ai?: boolean | 'llm' | 'offline';
  fix?: 'none' | 'propose' | 'apply';
  outDir?: string; // with fix=apply: write a fixed copy here instead of editing in place
  autonomy?: AutonomyLevel;
  failOn?: Severity;
  baseline?: boolean;
  source?: ScanSource;
  persist?: boolean;
}

export interface PipelineResult {
  stored: StoredScan;
  applied?: ApplyResult & { root: string };
}

const COPY_SKIP = /(^|[\\/])(node_modules|\.git|dist|coverage|\.venv|venv|__pycache__)$/;

@Injectable()
export class PipelineService {
  constructor(
    private readonly scanners: ScannersService,
    private readonly triage: TriageService,
    private readonly remediation: RemediationService,
    private readonly agent: AgentService,
    private readonly store: ScanStore,
    private readonly audit: AuditService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  async run(opts: PipelineOptions): Promise<PipelineResult> {
    const failOn = opts.failOn ?? this.config.failOn;
    const source = opts.source ?? { kind: 'cli' };
    const raw = await this.scanners.scan({ ...opts, osv: opts.osv ?? this.config.osv, external: opts.external ?? this.config.external });
    const result = this.triage.triage(raw, opts.baseline === false ? { baseline: [] } : {});
    const ws = diskWorkspace(result.root);
    this.audit.append({
      actor: 'system',
      action: 'scan',
      target: result.id,
      details: {
        root: result.root,
        source,
        findings: result.findings.length,
        scanners: result.scanners.map((s) => `${s.name}:${s.status}`),
      },
    });

    if (opts.fix && opts.fix !== 'none') await this.remediation.proposeAll(result, ws);

    let agent: AgentReport | undefined;
    if (opts.ai) {
      const mode = opts.ai === true ? 'auto' : opts.ai;
      agent = await this.agent.run(result, { ws, autonomy: opts.autonomy, audit: this.audit, mode });
    }

    const gate = this.triage.gate(result, failOn);
    const summary = this.triage.summary(result);
    const stored: StoredScan = {
      result,
      agent,
      gate: { pass: gate.pass, failOn, blocking: gate.blocking.length },
      summary,
      source,
      createdAt: new Date().toISOString(),
    };
    const prev = opts.persist === false ? null : this.store.previous(source, result.root, result.id);
    if (prev) {
      const d = diffScans(prev.result.findings, result.findings);
      stored.diff = { introduced: d.introduced.length, fixed: d.fixed.length, previousId: prev.result.id };
    }

    let applied: PipelineResult['applied'];
    if (opts.fix === 'apply') {
      let root = result.root;
      if (opts.outDir) {
        root = resolve(opts.outDir);
        if (root === result.root || root.startsWith(result.root + sep)) throw new Error('--out-dir must be outside the scanned directory');
        mkdirSync(root, { recursive: true });
        cpSync(result.root, root, { recursive: true, filter: (src) => !COPY_SKIP.test(src) });
      }
      const targets = result.findings.filter((f) => !f.suppressed && f.fix?.verified);
      const res = await this.remediation.apply(targets, diskWorkspace(root));
      // a human asked for this (CLI --fix / API call), so it is recorded as a human action
      this.audit.append({
        actor: 'human',
        action: 'fix:apply',
        target: result.id,
        details: { root, applied: res.applied.map((p) => p.findingId), skipped: res.skipped.length },
      });
      applied = { ...res, root };
    }

    if (opts.persist !== false) this.store.save(stored);
    return { stored, applied };
  }
}
