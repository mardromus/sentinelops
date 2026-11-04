/**
 * Minimal OSV.dev client (https://google.github.io/osv.dev/api/).
 *
 * querybatch returns only ids per package; details (ranges, severity,
 * aliases) come from /v1/vulns/{id}. Results are cached per process.
 */
import { Severity } from '../../common/types';
import { Advisory } from './advisories';
import { Range } from './version';

export interface OsvQuery {
  name: string;
  version: string;
  ecosystem: 'npm' | 'PyPI';
}

export type FetchLike = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) => Promise<{ ok: boolean; status: number; json(): Promise<any> }>;

const SEV: Record<string, Severity> = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };

export function severityFromOsv(v: any): Severity {
  const s = String(v?.database_specific?.severity || v?.affected?.[0]?.ecosystem_specific?.severity || '').toUpperCase();
  if (SEV[s]) return SEV[s];
  const vec = v?.severity?.find((x: any) => /CVSS/.test(x.type))?.score as string | undefined;
  if (vec) {
    // rough CVSS 3.x estimate from impact metrics, enough for prioritisation
    const high = (vec.match(/[CIA]:H/g) || []).length;
    const net = /AV:N/.test(vec);
    if (high >= 3 && net) return 'critical';
    if (high >= 1) return 'high';
    return 'medium';
  }
  return 'medium';
}

export function advisoryFromOsv(v: any, q: OsvQuery): Advisory {
  const ranges: Range[] = [];
  for (const aff of v.affected || []) {
    if (aff.package?.name?.toLowerCase() !== q.name.toLowerCase()) continue;
    for (const r of aff.ranges || []) {
      if (r.type === 'GIT') continue;
      let cur: Range = {};
      for (const ev of r.events || []) {
        if (ev.introduced !== undefined) cur = { introduced: ev.introduced };
        if (ev.fixed !== undefined) {
          ranges.push({ ...cur, fixed: ev.fixed });
          cur = {};
        }
      }
      if (cur.introduced !== undefined) ranges.push(cur);
    }
  }
  const cve = (v.aliases || []).find((a: string) => a.startsWith('CVE-'));
  return {
    id: v.id,
    aliases: [...new Set([v.id, ...(v.aliases || [])])],
    ecosystem: q.ecosystem,
    package: q.name,
    ranges,
    severity: severityFromOsv(v),
    summary: v.summary || (v.details || '').split('\n')[0].slice(0, 160) || cve || v.id,
    cwe: v.database_specific?.cwe_ids || [],
    references: [`https://osv.dev/vulnerability/${v.id}`, ...(v.references || []).slice(0, 3).map((r: any) => r.url)],
  };
}

export class OsvClient {
  private cache = new Map<string, any>();

  constructor(
    private readonly base = 'https://api.osv.dev',
    private readonly http: FetchLike = (globalThis.fetch as unknown as FetchLike),
    private readonly timeoutMs = 15000,
  ) {}

  private async call(path: string, body?: unknown): Promise<any> {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), this.timeoutMs);
    try {
      const res = await this.http(this.base + path, {
        method: body ? 'POST' : 'GET',
        headers: { 'content-type': 'application/json' },
        body: body ? JSON.stringify(body) : undefined,
        signal: ctl.signal,
      });
      if (!res.ok) throw new Error(`OSV ${path} -> HTTP ${res.status}`);
      return await res.json();
    } finally {
      clearTimeout(t);
    }
  }

  /** Advisories affecting each query, in the same order as the input. */
  async query(queries: OsvQuery[]): Promise<Advisory[][]> {
    const out: Advisory[][] = [];
    for (let i = 0; i < queries.length; i += 500) {
      const chunk = queries.slice(i, i + 500);
      const res = await this.call('/v1/querybatch', {
        queries: chunk.map((q) => ({ package: { name: q.name, ecosystem: q.ecosystem }, version: q.version })),
      });
      for (let j = 0; j < chunk.length; j++) {
        const ids: string[] = (res.results?.[j]?.vulns || []).map((v: any) => v.id);
        const advs: Advisory[] = [];
        for (const id of ids) {
          if (!this.cache.has(id)) this.cache.set(id, await this.call(`/v1/vulns/${encodeURIComponent(id)}`));
          advs.push(advisoryFromOsv(this.cache.get(id), chunk[j]));
        }
        out.push(advs);
      }
    }
    return out;
  }
}
