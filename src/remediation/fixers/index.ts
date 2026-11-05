import { Finding } from '../../common/types';
import { RULES } from '../../scanners/sast/rules';
import { evalToJsonParse, execToExecFile, pySqlParameterize, sqlParameterize } from './injection.fixers';
import { dependencyBump, dockerNonRoot, dockerSecretEnv, manifestFor, secretToEnv, yamlHarden } from './supply.fixers';
import { Fixer } from './types';
import {
  addHelmet,
  cookieFlags,
  corsAllowlist,
  flaskDebug,
  jwtVerify,
  pathBasename,
  safeRedirect,
  secureRandom,
  ssrfAllowlist,
  tlsVerify,
  weakHash,
  xssEscape,
  yamlSafeLoad,
} from './web.fixers';

export const FIXERS: Record<string, Fixer> = {
  'sql-parameterize': sqlParameterize,
  'py-sql-parameterize': pySqlParameterize,
  'exec-to-execfile': execToExecFile,
  'eval-to-json-parse': evalToJsonParse,
  'xss-escape': xssEscape,
  'safe-redirect': safeRedirect,
  'ssrf-allowlist': ssrfAllowlist,
  'path-basename': pathBasename,
  'cors-allowlist': corsAllowlist,
  'cookie-flags': cookieFlags,
  'add-helmet': addHelmet,
  'jwt-verify': jwtVerify,
  'weak-hash': weakHash,
  'secure-random': secureRandom,
  'tls-verify': tlsVerify,
  'yaml-safe-load': yamlSafeLoad,
  'flask-debug': flaskDebug,
  'dependency-bump': dependencyBump,
  'docker-non-root': dockerNonRoot,
  'docker-secret-env': dockerSecretEnv,
  'yaml-harden': yamlHarden,
  'secret-to-env': secretToEnv,
};

const RULE_FIXER = new Map(RULES.filter((r) => r.fixer).map((r) => [r.id, r.fixer!]));
const CONFIG_FIXER: Record<string, string> = {
  'config.docker.runs-as-root': 'docker-non-root',
  'config.docker.secret-in-env': 'docker-secret-env',
  'config.container.privileged': 'yaml-harden',
  'config.k8s.privilege-escalation': 'yaml-harden',
  'config.k8s.runs-as-root': 'yaml-harden',
};

/** Which fixer handles a finding, and which file it edits. */
export function fixerFor(f: Finding): { id: string; file: string } | null {
  if (f.category === 'dependency') return f.package?.fixedIn ? { id: 'dependency-bump', file: manifestFor(f.location.file) } : null;
  if (f.category === 'secret') return f.ruleId === 'secret.private-key' || f.ruleId === 'secret.env-file-value' ? null : { id: 'secret-to-env', file: f.location.file };
  const id = RULE_FIXER.get(f.ruleId) || CONFIG_FIXER[f.ruleId];
  return id ? { id, file: f.location.file } : null;
}

export { Fixer, FixContext, FixOutput } from './types';
