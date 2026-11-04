import { Injectable } from '@nestjs/common';
import { Finding } from '../common/types';
import { CWE, CweEntry, owaspForCwe } from './cwe';
import { OWASP_TOP10_2021, OwaspCategory } from './owasp';

/** Read-only OWASP / CWE knowledge base used by scanners, the agent and reports. */
@Injectable()
export class KnowledgeService {
  owasp(id: string): OwaspCategory | undefined {
    return OWASP_TOP10_2021.find((c) => c.id === id);
  }

  allOwasp(): OwaspCategory[] {
    return OWASP_TOP10_2021;
  }

  cwe(id: string): CweEntry | undefined {
    return CWE[id];
  }

  /** Fill owasp[] from cwe[] when a scanner only reported CWE ids. */
  enrich(f: Finding): Finding {
    const owasp = new Set(f.owasp);
    for (const c of f.cwe) {
      const o = owaspForCwe(c);
      if (o) owasp.add(o);
    }
    if (!owasp.size && f.category === 'dependency') owasp.add('A06:2021');
    if (!owasp.size && f.category === 'secret') owasp.add('A07:2021');
    if (!owasp.size && f.category === 'config') owasp.add('A05:2021');
    f.owasp = [...owasp].sort();
    if (!f.remediation) f.remediation = f.cwe.map((c) => CWE[c]?.remediation).find(Boolean);
    return f;
  }

  /** Guidance block the agent can quote to developers. */
  guidance(f: Finding): string {
    const lines: string[] = [];
    for (const o of f.owasp) {
      const cat = this.owasp(o);
      if (cat) lines.push(`${cat.id} ${cat.name}: ${cat.summary}`, ...cat.prevention.map((p) => `- ${p}`));
    }
    for (const c of f.cwe) {
      const e = CWE[c];
      if (e) lines.push(`${e.id} ${e.name}: ${e.remediation}`);
    }
    return lines.join('\n');
  }

  /** Count findings per OWASP category (all ten, zero-filled). */
  heatmap(findings: Finding[]): { id: string; name: string; count: number; worst: string | null }[] {
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    return OWASP_TOP10_2021.map((c) => {
      const fs = findings.filter((f) => !f.suppressed && f.owasp.includes(c.id));
      const worst = fs.length ? order.find((s) => fs.some((f) => f.severity === s)) || null : null;
      return { id: c.id, name: c.name, count: fs.length, worst };
    });
  }
}
