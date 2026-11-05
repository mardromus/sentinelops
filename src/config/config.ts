/**
 * Runtime configuration, read once from the environment (see .env.example).
 */
import { Severity } from '../common/types';

export type AutonomyLevel = 0 | 1 | 2 | 3;

export interface AppConfig {
  port: number;
  dataDir: string;
  autonomy: AutonomyLevel;
  failOn: Severity;
  osv: boolean;
  external: boolean;
  llm: { baseUrl: string; apiKey: string; model: string; maxSteps: number };
  github: { token: string; webhookSecret: string; apiUrl: string };
  apiToken: string; // bearer token required for mutating API calls when set
  scanRoots: string[]; // directories the HTTP API is allowed to scan
  publicUrl: string; // base URL used in links (commit statuses, PR comments)
}

export const APP_CONFIG = Symbol('APP_CONFIG');

function int(v: string | undefined, d: number): number {
  const n = v === undefined || v === '' ? NaN : Number(v);
  return Number.isFinite(n) ? n : d;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const openai = !env.SENTINELOPS_LLM_API_KEY && !env.GROQ_API_KEY && !!env.OPENAI_API_KEY;
  const autonomy = Math.min(3, Math.max(0, int(env.SENTINELOPS_AUTONOMY, 1))) as AutonomyLevel;
  return {
    port: int(env.PORT, 3000),
    dataDir: env.SENTINELOPS_DATA_DIR || './data',
    autonomy,
    failOn: ((env.SENTINELOPS_FAIL_ON as Severity) || 'high') as Severity,
    osv: env.SENTINELOPS_OSV !== '0',
    external: env.SENTINELOPS_EXTERNAL !== '0',
    llm: {
      baseUrl: (
        env.SENTINELOPS_LLM_BASE_URL ||
        (openai ? 'https://api.openai.com/v1' : 'https://api.groq.com/openai/v1')
      ).replace(/\/$/, ''),
      apiKey: env.SENTINELOPS_LLM_API_KEY || env.GROQ_API_KEY || env.OPENAI_API_KEY || '',
      model: env.SENTINELOPS_LLM_MODEL || (openai ? 'gpt-4o-mini' : 'llama-3.3-70b-versatile'),
      maxSteps: int(env.SENTINELOPS_LLM_MAX_STEPS, 8),
    },
    github: {
      token: env.GITHUB_TOKEN || '',
      webhookSecret: env.GITHUB_WEBHOOK_SECRET || '',
      apiUrl: (env.GITHUB_API_URL || 'https://api.github.com').replace(/\/$/, ''),
    },
    apiToken: env.SENTINELOPS_API_TOKEN || '',
    scanRoots: (env.SENTINELOPS_SCAN_ROOTS || process.cwd())
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    publicUrl: (env.SENTINELOPS_PUBLIC_URL || `http://localhost:${int(env.PORT, 3000)}`).replace(/\/$/, ''),
  };
}
