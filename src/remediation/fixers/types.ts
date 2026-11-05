import { Finding } from '../../common/types';

export interface FixContext {
  finding: Finding;
  path: string; // file to edit (relative to the scan root)
  content: string;
}

export interface FixOutput {
  content: string;
  description: string;
  notes?: string[];
}

/** A deterministic fixer: returns the edited file, or null when the line does not have the expected shape. */
export type Fixer = (ctx: FixContext) => FixOutput | null;

export const isTs = (path: string) => /\.(ts|tsx|mts|cts)$/.test(path);
