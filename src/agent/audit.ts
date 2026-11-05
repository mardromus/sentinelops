/**
 * Append-only, hash-chained audit log (JSON Lines).
 *
 * Each entry stores the hash of the previous entry, so deleting or editing
 * any line breaks the chain and `verify()` reports where. This is what lets
 * an autonomous agent be reviewed after the fact.
 */
import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';

export interface AuditEntry {
  seq: number;
  ts: string;
  actor: 'agent' | 'human' | 'system';
  action: string;
  target?: string;
  allowed?: boolean;
  reason?: string;
  details?: Record<string, unknown>;
  prev: string;
  hash: string;
}

const GENESIS = '0'.repeat(64);

function digest(e: Omit<AuditEntry, 'hash'>): string {
  const { seq, ts, actor, action, target, allowed, reason, details, prev } = e;
  return createHash('sha256').update(JSON.stringify({ seq, ts, actor, action, target, allowed, reason, details, prev })).digest('hex');
}

export class AuditLog {
  private entries: AuditEntry[] = [];

  /** `path` = null keeps the log in memory (tests, dry runs). */
  constructor(private readonly path: string | null = null) {
    if (path && existsSync(path)) {
      this.entries = readFileSync(path, 'utf8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l));
    }
  }

  append(e: { actor: AuditEntry['actor']; action: string; target?: string; allowed?: boolean; reason?: string; details?: Record<string, unknown> }): AuditEntry {
    const last = this.entries[this.entries.length - 1];
    const base = { seq: (last?.seq ?? 0) + 1, ts: new Date().toISOString(), ...e, prev: last?.hash ?? GENESIS };
    const entry: AuditEntry = { ...base, hash: digest(base) };
    this.entries.push(entry);
    if (this.path) {
      mkdirSync(dirname(this.path), { recursive: true });
      appendFileSync(this.path, JSON.stringify(entry) + '\n');
    }
    return entry;
  }

  all(): AuditEntry[] {
    return [...this.entries];
  }

  tail(n = 50): AuditEntry[] {
    return this.entries.slice(-n);
  }

  verify(entries: AuditEntry[] = this.entries): { valid: boolean; brokenAt?: number; count: number } {
    let prev = GENESIS;
    for (const e of entries) {
      const { hash, ...rest } = e;
      if (e.prev !== prev || digest(rest) !== hash) return { valid: false, brokenAt: e.seq, count: entries.length };
      prev = hash;
    }
    return { valid: true, count: entries.length };
  }
}
