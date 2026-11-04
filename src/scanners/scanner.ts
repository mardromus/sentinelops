import { Category, Confidence, Finding, Location, ScanOptions, Severity, SourceFile } from '../common/types';
import { fingerprint, shortId } from './files';

export interface ScanContext {
  options: ScanOptions;
  files: SourceFile[];
}

/** A scanner turns files into findings. External tools implement the same interface. */
export interface Scanner {
  readonly name: string;
  scan(ctx: ScanContext): Promise<Finding[]>;
}

export interface FindingInput {
  ruleId: string;
  title: string;
  message: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  cwe: string[];
  owasp?: string[];
  location: Location;
  scanner: string;
  remediation?: string;
  references?: string[];
  package?: Finding['package'];
  suppressed?: boolean;
  suppressReason?: string;
}

export function makeFinding(i: FindingInput): Finding {
  const fp = fingerprint(i.ruleId, i.location.file, i.location.snippet || `${i.location.line}`);
  return { id: shortId(fp), fingerprint: fp, ...i, owasp: i.owasp ?? [] };
}

export function snippetAt(file: SourceFile, line: number): string {
  return (file.lines[line - 1] || '').trim().slice(0, 240);
}
