/**
 * Version comparison good enough for npm semver and common PyPI versions.
 * "1.2.3" < "1.2.10", "1.0.0-beta.1" < "1.0.0", "2.0" == "2.0.0".
 */
function parts(v: string): { nums: number[]; pre: string } {
  const clean = v.trim().replace(/^[v=]+/, '').split('+')[0];
  const m = /^(\d+(?:\.\d+)*)(.*)$/.exec(clean);
  if (!m) return { nums: [0], pre: clean };
  const nums = m[1].split('.').map((n) => parseInt(n, 10));
  const pre = m[2].replace(/^[-.]/, '');
  return { nums, pre };
}

export function compareVersions(a: string, b: string): number {
  const A = parts(a);
  const B = parts(b);
  const len = Math.max(A.nums.length, B.nums.length);
  for (let i = 0; i < len; i++) {
    const d = (A.nums[i] || 0) - (B.nums[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  // a release sorts after its pre-releases; ".post1" style suffixes sort after the release
  const rank = (p: string) => (!p ? 1 : /^post/i.test(p) ? 2 : 0);
  const ra = rank(A.pre);
  const rb = rank(B.pre);
  if (ra !== rb) return ra < rb ? -1 : 1;
  if (A.pre === B.pre) return 0;
  return A.pre < B.pre ? -1 : 1;
}

export interface Range {
  introduced?: string; // inclusive, default "0"
  fixed?: string; // exclusive; undefined = no fix yet
}

export function inRange(version: string, r: Range): boolean {
  if (r.introduced && r.introduced !== '0' && compareVersions(version, r.introduced) < 0) return false;
  if (r.fixed && compareVersions(version, r.fixed) >= 0) return false;
  return true;
}

/** Lowest version a manifest range can resolve to: "^4.17.0" -> "4.17.0", ">=2.0,<3" -> "2.0". */
export function minVersionOf(spec: string): string | undefined {
  const m = /(\d+(?:\.\d+){0,3}(?:[-.][0-9A-Za-z.]+)?)/.exec(spec);
  if (!m) return undefined;
  const nums = m[1].split('.');
  while (nums.length < 3 && /^\d+$/.test(nums[nums.length - 1])) nums.push('0');
  return nums.join('.');
}

export function normalizeName(name: string, ecosystem: 'npm' | 'PyPI'): string {
  return ecosystem === 'PyPI' ? name.toLowerCase().replace(/[-_.]+/g, '-') : name;
}
