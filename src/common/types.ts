/**
 * Domain model shared by scanners, triage, remediation, the agent and reports.
 * Every scanner (built-in or external) produces the same normalised Finding so
 * the rest of the pipeline never cares where a problem came from.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';
export type Category = 'sast' | 'secret' | 'dependency' | 'config';
export type Priority = 'P1' | 'P2' | 'P3' | 'P4';

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.length - SEVERITY_ORDER.indexOf(s); // critical = 5 ... info = 1
}

export function atLeast(s: Severity, threshold: Severity): boolean {
  return severityRank(s) >= severityRank(threshold);
}

export interface Location {
  file: string; // relative to the scan root, forward slashes
  line: number; // 1-based
  column?: number;
  endLine?: number;
  snippet?: string;
}

export interface PackageRef {
  name: string;
  version: string;
  ecosystem: 'npm' | 'PyPI';
  fixedIn?: string;
  advisory?: string; // GHSA / CVE id
  aliases?: string[];
  direct?: boolean;
  dev?: boolean;
}

export interface Finding {
  id: string; // short stable id derived from the fingerprint
  fingerprint: string;
  ruleId: string;
  title: string;
  message: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  cwe: string[];
  owasp: string[]; // e.g. "A03:2021"
  location: Location;
  scanner: string;
  package?: PackageRef;
  remediation?: string;
  references?: string[];
  // filled by triage
  risk?: number; // 0-100
  priority?: Priority;
  suppressed?: boolean;
  suppressReason?: string;
  triageNotes?: string[];
  // filled by remediation
  fix?: FixProposal;
}

export interface FixProposal {
  findingId: string;
  strategy: 'rule' | 'dependency' | 'ai';
  description: string;
  file: string;
  diff: string; // unified diff
  newContent?: string;
  verified?: boolean;
  verification?: string;
  applied?: boolean;
}

export interface ScanOptions {
  root: string;
  exclude?: string[];
  osv?: boolean; // query OSV.dev online
  external?: boolean; // run semgrep / gitleaks / trivy when installed
  maxFileBytes?: number;
}

export interface ScannerRun {
  name: string;
  status: 'ok' | 'skipped' | 'error';
  findings: number;
  durationMs: number;
  detail?: string;
}

export interface ScanResult {
  id: string;
  root: string;
  startedAt: string;
  finishedAt: string;
  filesScanned: number;
  findings: Finding[];
  scanners: ScannerRun[];
}

export interface SourceFile {
  path: string; // relative
  absPath: string;
  content: string;
  lines: string[];
  language: 'js' | 'ts' | 'py' | 'docker' | 'yaml' | 'json' | 'env' | 'other';
}
