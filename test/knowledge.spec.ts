import { Finding } from '../src/common/types';
import { loadConfig } from '../src/config/config';
import { CWE } from '../src/knowledge/cwe';
import { KnowledgeService } from '../src/knowledge/knowledge.service';
import { OWASP_TOP10_2021 } from '../src/knowledge/owasp';

const base = (over: Partial<Finding>): Finding => ({
  id: 'x',
  fingerprint: 'x',
  ruleId: 'r',
  title: 't',
  message: 'm',
  category: 'sast',
  severity: 'high',
  confidence: 'high',
  cwe: [],
  owasp: [],
  location: { file: 'a.js', line: 1 },
  scanner: 's',
  ...over,
});

describe('knowledge base', () => {
  const kb = new KnowledgeService();

  it('has all ten OWASP 2021 categories and every CWE maps to one of them', () => {
    expect(OWASP_TOP10_2021.map((c) => c.id)).toEqual(
      Array.from({ length: 10 }, (_, i) => `A${String(i + 1).padStart(2, '0')}:2021`),
    );
    const ids = new Set(OWASP_TOP10_2021.map((c) => c.id));
    for (const e of Object.values(CWE)) expect(ids.has(e.owasp)).toBe(true);
  });

  it('enriches findings with OWASP categories and remediation', () => {
    const f = kb.enrich(base({ cwe: ['CWE-89'] }));
    expect(f.owasp).toEqual(['A03:2021']);
    expect(f.remediation).toMatch(/parameterised/);
    expect(kb.enrich(base({ category: 'dependency' })).owasp).toEqual(['A06:2021']);
    expect(kb.guidance(f)).toContain('Injection');
  });

  it('builds a zero-filled OWASP heatmap ignoring suppressed findings', () => {
    const hm = kb.heatmap([
      kb.enrich(base({ cwe: ['CWE-89'], severity: 'critical' })),
      kb.enrich(base({ cwe: ['CWE-78'] })),
      kb.enrich(base({ cwe: ['CWE-22'], suppressed: true })),
    ]);
    expect(hm).toHaveLength(10);
    expect(hm.find((h) => h.id === 'A03:2021')).toMatchObject({ count: 2, worst: 'critical' });
    expect(hm.find((h) => h.id === 'A01:2021')).toMatchObject({ count: 0, worst: null });
  });

  it('loads configuration from the environment with safe defaults', () => {
    const c = loadConfig({ SENTINELOPS_AUTONOMY: '7', GROQ_API_KEY: 'k' } as any);
    expect(c.autonomy).toBe(3);
    expect(c.llm.apiKey).toBe('k');
    expect(c.llm.baseUrl).toContain('groq');
    expect(loadConfig({ OPENAI_API_KEY: 'o' } as any).llm.model).toBe('gpt-4o-mini');
    expect(loadConfig({} as any).autonomy).toBe(1);
  });
});
