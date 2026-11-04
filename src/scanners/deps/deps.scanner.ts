import { Finding } from '../../common/types';
import { makeFinding, ScanContext, Scanner } from '../scanner';
import { Advisory, OFFLINE_ADVISORIES } from './advisories';
import { collectDependencies, Dependency } from './manifests';
import { OsvClient } from './osv.client';
import { compareVersions, inRange, normalizeName } from './version';

export function matchOffline(dep: Dependency, db: Advisory[] = OFFLINE_ADVISORIES): Advisory[] {
  const name = normalizeName(dep.name, dep.ecosystem);
  return db.filter((a) => a.ecosystem === dep.ecosystem && a.package === name && a.ranges.some((r) => inRange(dep.version, r)));
}

/** Smallest fixed version above the installed one across all advisories (what to bump to). */
export function fixedVersion(dep: Dependency, advs: Advisory[]): string | undefined {
  const fixes = advs
    .flatMap((a) => a.ranges.filter((r) => inRange(dep.version, r)).map((r) => r.fixed))
    .filter((v): v is string => !!v);
  if (!fixes.length) return undefined;
  return fixes.sort(compareVersions)[fixes.length - 1];
}

/** Software composition analysis: lockfiles/manifests checked against OSV.dev or the offline snapshot. */
export class DependencyScanner implements Scanner {
  readonly name = 'builtin-deps';
  lastSource: 'osv' | 'offline' = 'offline';

  constructor(private readonly osv?: OsvClient) {}

  async scan(ctx: ScanContext): Promise<Finding[]> {
    const deps = collectDependencies(ctx.files);
    if (!deps.length) return [];
    let matches: Advisory[][];
    if (this.osv && ctx.options.osv !== false) {
      try {
        matches = await this.osv.query(deps.map((d) => ({ name: d.name, version: d.version, ecosystem: d.ecosystem })));
        this.lastSource = 'osv';
      } catch {
        matches = deps.map((d) => matchOffline(d));
        this.lastSource = 'offline';
      }
    } else {
      matches = deps.map((d) => matchOffline(d));
      this.lastSource = 'offline';
    }

    const out: Finding[] = [];
    deps.forEach((dep, i) => {
      const advs = matches[i];
      if (!advs?.length) return;
      const fixedIn = fixedVersion(dep, advs);
      for (const adv of advs) {
        const cve = adv.aliases.find((a) => a.startsWith('CVE-')) || adv.id;
        out.push(
          makeFinding({
            ruleId: `dep.${adv.id}`,
            title: `${dep.name}@${dep.version}: ${adv.summary}`,
            message:
              `${dep.name} ${dep.version} is affected by ${cve} (${adv.summary}).` +
              (dep.direct ? '' : ' It is a transitive dependency.') +
              (dep.exact ? '' : ' Version inferred from a manifest range; add a lockfile for exact results.'),
            category: 'dependency',
            severity: adv.severity,
            confidence: dep.exact ? 'high' : 'medium',
            cwe: adv.cwe.length ? adv.cwe : ['CWE-937'],
            owasp: ['A06:2021'],
            location: { file: dep.file, line: dep.line, snippet: `${dep.name}@${dep.version}` },
            scanner: this.name,
            remediation: fixedIn ? `Upgrade ${dep.name} to ${fixedIn} or later.` : `No fixed release yet: replace ${dep.name} or mitigate.`,
            references: adv.references,
            package: {
              name: dep.name,
              version: dep.version,
              ecosystem: dep.ecosystem,
              fixedIn,
              advisory: adv.id,
              aliases: adv.aliases,
              direct: dep.direct,
              dev: dep.dev,
            },
          }),
        );
      }
    });
    return out;
  }
}
