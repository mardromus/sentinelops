import { PackageRef, SourceFile } from '../../common/types';
import { minVersionOf, normalizeName } from './version';

export interface Dependency extends PackageRef {
  file: string;
  line: number;
  exact: boolean; // false when the version came from a range in a manifest
}

function lineOf(file: SourceFile, needle: string): number {
  const i = file.lines.findIndex((l) => l.includes(needle));
  return i >= 0 ? i + 1 : 1;
}

/** package-lock.json lockfileVersion 2/3 ("packages") and 1 ("dependencies"). */
export function parsePackageLock(file: SourceFile): Dependency[] {
  let doc: any;
  try {
    doc = JSON.parse(file.content);
  } catch {
    return [];
  }
  const out: Dependency[] = [];
  const directNames = new Set<string>(Object.keys({ ...(doc.packages?.['']?.dependencies || {}), ...(doc.packages?.['']?.devDependencies || {}) }));
  if (doc.packages) {
    for (const [path, meta] of Object.entries<any>(doc.packages)) {
      if (!path || !meta?.version || meta.link) continue;
      const name = meta.name || path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
      out.push({
        name,
        version: meta.version,
        ecosystem: 'npm',
        file: file.path,
        line: lineOf(file, `"${path}"`),
        exact: true,
        direct: directNames.has(name) && path === `node_modules/${name}`,
        dev: !!meta.dev,
      });
    }
  } else if (doc.dependencies) {
    const walk = (deps: Record<string, any>, top: boolean) => {
      for (const [name, meta] of Object.entries<any>(deps)) {
        if (meta?.version) {
          out.push({
            name,
            version: meta.version,
            ecosystem: 'npm',
            file: file.path,
            line: lineOf(file, `"${name}"`),
            exact: true,
            direct: top,
            dev: !!meta.dev,
          });
        }
        if (meta?.dependencies) walk(meta.dependencies, false);
      }
    };
    walk(doc.dependencies, true);
  }
  return out;
}

/** package.json ranges; used only when no lockfile sits next to it. */
export function parsePackageJson(file: SourceFile): Dependency[] {
  let doc: any;
  try {
    doc = JSON.parse(file.content);
  } catch {
    return [];
  }
  const out: Dependency[] = [];
  for (const [section, dev] of [['dependencies', false], ['devDependencies', true]] as const) {
    for (const [name, spec] of Object.entries<string>(doc[section] || {})) {
      if (typeof spec !== 'string' || /^(file:|link:|git|http|workspace:)/.test(spec)) continue;
      const version = minVersionOf(spec);
      if (!version) continue;
      out.push({ name, version, ecosystem: 'npm', file: file.path, line: lineOf(file, `"${name}"`), exact: false, direct: true, dev });
    }
  }
  return out;
}

/** requirements*.txt: "name==1.2.3", "name>=1.2" (min version), ignores -r / -e / URLs. */
export function parseRequirements(file: SourceFile): Dependency[] {
  const out: Dependency[] = [];
  file.lines.forEach((raw, idx) => {
    const line = raw.split('#')[0].trim();
    if (!line || line.startsWith('-') || line.includes('://')) return;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(==|>=|~=|===)\s*([0-9][^\s,;]*)/.exec(line);
    if (!m) return;
    out.push({
      name: normalizeName(m[1], 'PyPI'),
      version: m[4],
      ecosystem: 'PyPI',
      file: file.path,
      line: idx + 1,
      exact: m[3] === '==' || m[3] === '===',
      direct: true,
    });
  });
  return out;
}

export function collectDependencies(files: SourceFile[]): Dependency[] {
  const deps: Dependency[] = [];
  const dirOf = (p: string) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');
  const lockDirs = new Set(files.filter((f) => /(^|\/)package-lock\.json$/.test(f.path)).map((f) => dirOf(f.path)));
  for (const f of files) {
    if (/(^|\/)package-lock\.json$/.test(f.path)) deps.push(...parsePackageLock(f));
    else if (/(^|\/)package\.json$/.test(f.path) && !lockDirs.has(dirOf(f.path))) deps.push(...parsePackageJson(f));
    else if (/(^|\/)requirements[^/]*\.txt$/.test(f.path)) deps.push(...parseRequirements(f));
  }
  // one entry per (ecosystem, name, version, file)
  const seen = new Set<string>();
  return deps.filter((d) => {
    const k = `${d.ecosystem}|${d.name}|${d.version}|${d.file}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
