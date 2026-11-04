import { SourceFile } from '../src/common/types';
import { DependencyScanner, fixedVersion, matchOffline } from '../src/scanners/deps/deps.scanner';
import { collectDependencies, parsePackageLock, parseRequirements } from '../src/scanners/deps/manifests';
import { advisoryFromOsv, OsvClient, severityFromOsv } from '../src/scanners/deps/osv.client';
import { compareVersions, inRange, minVersionOf } from '../src/scanners/deps/version';
import { languageOf } from '../src/scanners/files';

const file = (path: string, content: string): SourceFile => ({
  path,
  absPath: '/x/' + path,
  content,
  lines: content.split('\n'),
  language: languageOf(path),
});

const LOCK = JSON.stringify(
  {
    name: 'shop',
    lockfileVersion: 3,
    packages: {
      '': { name: 'shop', dependencies: { lodash: '^4.17.15', express: '^4.17.1' }, devDependencies: { jest: '^29.0.0' } },
      'node_modules/lodash': { version: '4.17.15' },
      'node_modules/express': { version: '4.17.1' },
      'node_modules/minimist': { version: '1.2.5', dev: true },
      'node_modules/jest': { version: '29.7.0', dev: true },
    },
  },
  null,
  2,
);

describe('version helpers', () => {
  it('compares versions', () => {
    expect(compareVersions('1.2.3', '1.2.10')).toBe(-1);
    expect(compareVersions('2.0', '2.0.0')).toBe(0);
    expect(compareVersions('1.0.0-beta.1', '1.0.0')).toBe(-1);
    expect(compareVersions('1.0.post1', '1.0')).toBe(1);
    expect(compareVersions('v4.17.21', '4.17.20')).toBe(1);
  });
  it('evaluates ranges and manifest specs', () => {
    expect(inRange('1.2.5', { introduced: '1.0.0', fixed: '1.2.6' })).toBe(true);
    expect(inRange('1.2.6', { introduced: '1.0.0', fixed: '1.2.6' })).toBe(false);
    expect(inRange('0.9.0', { introduced: '1.0.0', fixed: '1.2.6' })).toBe(false);
    expect(minVersionOf('^4.17')).toBe('4.17.0');
    expect(minVersionOf('>=2.0,<3')).toBe('2.0.0');
    expect(minVersionOf('latest')).toBeUndefined();
  });
});

describe('manifest parsing', () => {
  it('reads lockfile v3 with direct/dev flags and line numbers', () => {
    const deps = parsePackageLock(file('package-lock.json', LOCK));
    const lodash = deps.find((d) => d.name === 'lodash')!;
    expect(lodash).toMatchObject({ version: '4.17.15', direct: true, dev: false, exact: true });
    expect(lodash.line).toBeGreaterThan(1);
    expect(deps.find((d) => d.name === 'minimist')).toMatchObject({ direct: false, dev: true });
  });

  it('reads requirements.txt and normalises names', () => {
    const deps = parseRequirements(file('requirements.txt', 'Flask==2.2.2\nPyYAML>=5.1  # config\n-r base.txt\nrequests\n'));
    expect(deps.map((d) => [d.name, d.version, d.exact])).toEqual([
      ['flask', '2.2.2', true],
      ['pyyaml', '5.1', false],
    ]);
  });

  it('prefers the lockfile over package.json in the same directory', () => {
    const pkg = file('package.json', JSON.stringify({ dependencies: { lodash: '^4.17.15' } }));
    const deps = collectDependencies([pkg, file('package-lock.json', LOCK)]);
    expect(deps.every((d) => d.file === 'package-lock.json')).toBe(true);
    expect(collectDependencies([pkg])).toHaveLength(1);
  });
});

describe('dependency scanner', () => {
  it('matches the offline snapshot and computes the bump target', async () => {
    const fs = await new DependencyScanner().scan({ options: { root: '/x' }, files: [file('package-lock.json', LOCK)] });
    const ids = fs.map((f) => f.package!.advisory).sort();
    expect(ids).toEqual(['CVE-2020-8203', 'CVE-2021-23337', 'CVE-2021-44906', 'CVE-2024-29041']);
    const lodash = fs.find((f) => f.package!.name === 'lodash')!;
    expect(lodash.package!.fixedIn).toBe('4.17.21');
    expect(lodash.owasp).toEqual(['A06:2021']);
    expect(lodash.remediation).toContain('4.17.21');
  });

  it('works for PyPI', () => {
    const d = { name: 'Flask', version: '2.2.2', ecosystem: 'PyPI' as const, file: 'r.txt', line: 1, exact: true };
    const advs = matchOffline(d);
    expect(advs.map((a) => a.id)).toEqual(['CVE-2023-30861']);
    expect(fixedVersion(d, advs)).toBe('2.2.5');
  });

  it('uses OSV when available and falls back offline when it fails', async () => {
    const calls: string[] = [];
    const fake = async (url: string) => {
      calls.push(url);
      if (url.endsWith('/v1/querybatch'))
        return { ok: true, status: 200, json: async () => ({ results: [{ vulns: [{ id: 'GHSA-test-0001' }] }, {}, {}, {}] }) };
      return {
        ok: true,
        status: 200,
        json: async () => ({
          id: 'GHSA-test-0001',
          aliases: ['CVE-2099-0001'],
          summary: 'Test advisory',
          database_specific: { severity: 'HIGH', cwe_ids: ['CWE-79'] },
          affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.18.0' }] }] }],
        }),
      };
    };
    const scanner = new DependencyScanner(new OsvClient('https://osv.test', fake));
    const fs = await scanner.scan({ options: { root: '/x' }, files: [file('package-lock.json', LOCK)] });
    expect(scanner.lastSource).toBe('osv');
    expect(fs).toHaveLength(1);
    expect(fs[0]).toMatchObject({ severity: 'high', cwe: ['CWE-79'] });
    expect(fs[0].package!.fixedIn).toBe('4.18.0');

    const broken = new DependencyScanner(new OsvClient('https://osv.test', async () => ({ ok: false, status: 503, json: async () => ({}) })));
    const off = await broken.scan({ options: { root: '/x' }, files: [file('package-lock.json', LOCK)] });
    expect(broken.lastSource).toBe('offline');
    expect(off.length).toBe(4);
  });

  it('maps OSV severities', () => {
    expect(severityFromOsv({ database_specific: { severity: 'MODERATE' } })).toBe('medium');
    expect(severityFromOsv({ severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] })).toBe('critical');
    const adv = advisoryFromOsv(
      { id: 'X', affected: [{ package: { name: 'a' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '1.0' }, { fixed: '1.5' }, { introduced: '2.0' }] }] }] },
      { name: 'a', version: '1.1', ecosystem: 'npm' },
    );
    expect(adv.ranges).toEqual([{ introduced: '1.0', fixed: '1.5' }, { introduced: '2.0' }]);
  });
});
