/**
 * Secret detection patterns.
 *
 * Provider patterns have a recognisable prefix/shape and are reported with
 * high confidence. The generic pattern catches `password = "..."` style
 * assignments and is filtered by entropy and a placeholder list so that
 * examples like "changeme" or "${DB_PASSWORD}" do not page anyone.
 */
import { Severity } from '../../common/types';

export interface SecretPattern {
  id: string;
  title: string;
  severity: Severity;
  re: RegExp; // capture group 1 (if present) is the secret, otherwise the whole match
  minEntropy?: number;
}

export const PROVIDER_PATTERNS: SecretPattern[] = [
  { id: 'secret.aws-access-key-id', title: 'AWS access key id', severity: 'critical', re: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/ },
  {
    id: 'secret.aws-secret-access-key',
    title: 'AWS secret access key',
    severity: 'critical',
    re: /aws.{0,20}secret.{0,20}['"]([A-Za-z0-9/+=]{40})['"]/i,
    minEntropy: 4,
  },
  { id: 'secret.github-token', title: 'GitHub token', severity: 'critical', re: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b/ },
  { id: 'secret.gitlab-token', title: 'GitLab personal access token', severity: 'critical', re: /\b(glpat-[A-Za-z0-9_-]{20})\b/ },
  { id: 'secret.slack-token', title: 'Slack token', severity: 'high', re: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/ },
  { id: 'secret.slack-webhook', title: 'Slack webhook URL', severity: 'medium', re: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+)/ },
  { id: 'secret.stripe-live-key', title: 'Stripe live secret key', severity: 'critical', re: /\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b/ },
  { id: 'secret.google-api-key', title: 'Google API key', severity: 'high', re: /\b(AIza[0-9A-Za-z_-]{35})\b/ },
  { id: 'secret.openai-key', title: 'OpenAI API key', severity: 'high', re: /\b(sk-(?:proj-)?[A-Za-z0-9_-]{32,})\b/ },
  { id: 'secret.sendgrid-key', title: 'SendGrid API key', severity: 'high', re: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/ },
  { id: 'secret.npm-token', title: 'npm access token', severity: 'high', re: /\b(npm_[A-Za-z0-9]{36})\b/ },
  { id: 'secret.private-key', title: 'Private key block', severity: 'critical', re: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----)/ },
  {
    id: 'secret.connection-string',
    title: 'Credentials in connection string',
    severity: 'high',
    re: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?|mssql):\/\/[^:/\s'"]+:([^@/\s'"]{4,})@/i,
  },
  {
    id: 'secret.jwt',
    title: 'Hard-coded JSON Web Token',
    severity: 'medium',
    re: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/,
  },
];

export const GENERIC_PATTERN: SecretPattern = {
  id: 'secret.generic-credential',
  title: 'Hard-coded credential',
  severity: 'high',
  re: /([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key|signing[_-]?key)[A-Za-z0-9_]*)['"]?\s*[:=]\s*['"]([^'"\s]{8,200})['"]/i,
  minEntropy: 3.0,
};

/** KEY=value lines in .env files. */
export const ENV_LINE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['"]?([^'"#\s]+)['"]?/;
export const SECRETISH_KEY = /(password|passwd|pwd|secret|token|api_?key|access_?key|private_?key|client_?secret|credentials?|dsn|database_url)/i;

const PLACEHOLDER = [
  /^(x+|\*+|\.+|-+|_+|0+|1234\w*|abc\w*)$/i,
  /example|sample|dummy|placeholder|changeme|change_me|replace|your[_-]|<[^>]*>|\{\{|\$\{|%\(|\btodo\b|redacted|fake|not[_-]?a[_-]?real|insert|xxxx/i,
  /^(true|false|null|none|undefined|password|secret|token)$/i,
  /^process\.env|^os\.environ|^env\(/i,
];

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER.some((re) => re.test(value));
}

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Keep the first 4 and last 2 characters so a reviewer can recognise the value without leaking it. */
export function mask(secret: string): string {
  if (secret.length <= 8) return '*'.repeat(secret.length);
  return secret.slice(0, 4) + '*'.repeat(Math.min(16, secret.length - 6)) + secret.slice(-2);
}
