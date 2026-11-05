/**
 * File-backed scan history (one JSON document per scan). Small, inspectable
 * and good enough for a single agent instance; swap for a database by
 * implementing the same four methods.
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Inject, Injectable } from '@nestjs/common';
import type { AgentReport } from '../agent/agent.service';
import { ScanResult, Severity } from '../common/types';
import { APP_CONFIG, AppConfig } from '../config/config';

export interface ScanSource {
  kind: 'cli' | 'api' | 'webhook';
  repo?: string;
  ref?: string;
  sha?: string;
  pr?: number;
}

export interface StoredScan {
  result: ScanResult;
  agent?: AgentReport;
  gate: { pass: boolean; failOn: Severity; blocking: number };
  summary: {
    total: number;
    active: number;
    suppressed: number;
    bySeverity: Record<string, number>;
    byPriority: Record<string, number>;
    byCategory: Record<string, number>;
    riskScore: number;
  };
  diff?: { introduced: number; fixed: number; previousId: string };
  source: ScanSource;
  createdAt: string;
}

export interface ScanListItem {
  id: string;
  createdAt: string;
  root: string;
  source: ScanSource;
  gate: StoredScan['gate'];
  summary: StoredScan['summary'];
}

const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

@Injectable()
export class ScanStore {
  private readonly dir: string;

  constructor(@Inject(APP_CONFIG) config: AppConfig) {
    this.dir = join(config.dataDir, 'scans');
  }

  save(s: StoredScan): void {
    mkdirSync(this.dir, { recursive: true });
    writeFileSync(join(this.dir, `${s.result.id}.json`), JSON.stringify(s));
  }

  get(id: string): StoredScan | null {
    if (!ID.test(id)) return null; // ids are UUIDs: never build a path from anything else
    const p = join(this.dir, `${id}.json`);
    return existsSync(p) ? (JSON.parse(readFileSync(p, 'utf8')) as StoredScan) : null;
  }

  list(limit = 50): ScanListItem[] {
    if (!existsSync(this.dir)) return [];
    return readdirSync(this.dir)
      .filter((f) => f.endsWith('.json'))
      .map((f) => ({ f, t: statSync(join(this.dir, f)).mtimeMs }))
      .sort((a, b) => b.t - a.t)
      .slice(0, limit)
      .map(({ f }) => {
        const s = JSON.parse(readFileSync(join(this.dir, f), 'utf8')) as StoredScan;
        return { id: s.result.id, createdAt: s.createdAt, root: s.result.root, source: s.source, gate: s.gate, summary: s.summary };
      });
  }

  /** Most recent earlier scan of the same repository (or local root), for "introduced / fixed" diffs. */
  previous(source: ScanSource, root: string, excludeId?: string): StoredScan | null {
    for (const item of this.list(200)) {
      if (item.id === excludeId) continue;
      const same = source.repo ? item.source.repo === source.repo && item.source.pr === source.pr : !item.source.repo && item.root === root;
      if (same) return this.get(item.id);
    }
    return null;
  }
}
