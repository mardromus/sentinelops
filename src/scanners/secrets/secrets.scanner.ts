import { Finding, SourceFile } from '../../common/types';
import { isSuppressedInline } from '../files';
import { makeFinding, ScanContext, Scanner } from '../scanner';
import {
  entropy,
  ENV_LINE,
  GENERIC_PATTERN,
  isPlaceholder,
  mask,
  PROVIDER_PATTERNS,
  SECRETISH_KEY,
  SecretPattern,
} from './patterns';

const SKIP_FILES = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|\.env\.example|\.env\.sample|\.env\.template)$/;
const REMEDIATION =
  'Revoke and rotate the credential now (it is in git history), then load it from the environment or a secret manager.';

interface Hit {
  pattern: SecretPattern;
  secret: string;
  index: number;
  key?: string;
}

export function lineHits(line: string, file: SourceFile): Hit[] {
  const hits: Hit[] = [];
  for (const p of PROVIDER_PATTERNS) {
    const m = p.re.exec(line);
    if (!m) continue;
    const secret = m[1] ?? m[0];
    if (p.minEntropy && entropy(secret) < p.minEntropy) continue;
    if (p.id !== 'secret.private-key' && isPlaceholder(secret)) continue;
    hits.push({ pattern: p, secret, index: m.index });
  }
  if (hits.length) return hits;

  if (file.language === 'env') {
    const m = ENV_LINE.exec(line);
    if (m && SECRETISH_KEY.test(m[1]) && m[2].length >= 6 && !isPlaceholder(m[2]) && entropy(m[2]) >= 2.5) {
      hits.push({ pattern: { ...GENERIC_PATTERN, id: 'secret.env-file-value' }, secret: m[2], index: line.indexOf(m[2]), key: m[1] });
    }
    return hits;
  }

  const g = GENERIC_PATTERN.re.exec(line);
  if (g) {
    const [, key, value] = g;
    const looksLikeCode = /^[a-z]+(\.[a-z]+)+$/i.test(value) || /^[A-Z_]+$/.test(value) || value.includes('(');
    if (!looksLikeCode && !isPlaceholder(value) && entropy(value) >= (GENERIC_PATTERN.minEntropy || 3)) {
      hits.push({ pattern: GENERIC_PATTERN, secret: value, index: g.index, key });
    }
  }
  return hits;
}

/** Finds hard-coded credentials; snippets are masked so the report itself does not leak them. */
export class SecretsScanner implements Scanner {
  readonly name = 'builtin-secrets';

  async scan(ctx: ScanContext): Promise<Finding[]> {
    const out: Finding[] = [];
    for (const file of ctx.files) {
      if (SKIP_FILES.test(file.path)) continue;
      file.lines.forEach((line, idx) => {
        if (line.length > 4000) return;
        for (const h of lineHits(line, file)) {
          const masked = line.trim().replace(h.secret, mask(h.secret)).slice(0, 240);
          const suppressed = isSuppressedInline(file.lines, idx);
          out.push(
            makeFinding({
              ruleId: h.pattern.id,
              title: h.pattern.title,
              message:
                `${h.pattern.title} committed in ${file.path}` +
                (h.key ? ` (assigned to ${h.key})` : '') +
                '. Anyone with read access to the repository or its history can use it.',
              category: 'secret',
              severity: h.pattern.severity,
              confidence: h.pattern === GENERIC_PATTERN ? 'medium' : 'high',
              cwe: ['CWE-798'],
              location: { file: file.path, line: idx + 1, column: h.index + 1, snippet: masked },
              scanner: this.name,
              remediation: REMEDIATION,
              suppressed,
              suppressReason: suppressed ? 'inline sentinelops-ignore' : undefined,
            }),
          );
        }
      });
    }
    return out;
  }
}
