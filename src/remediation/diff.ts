/**
 * Unified diff (git style) between two versions of a file.
 * Common prefix/suffix are trimmed first so the LCS only runs on the
 * changed window, which keeps it cheap for the small edits fixers make.
 */
type Op = { t: ' ' | '-' | '+'; s: string };

function lcsOps(a: string[], b: string[]): Op[] {
  const n = a.length;
  const m = b.length;
  const dp: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const ops: Op[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      ops.push({ t: ' ', s: a[i] });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) ops.push({ t: '-', s: a[i++] });
    else ops.push({ t: '+', s: b[j++] });
  }
  while (i < n) ops.push({ t: '-', s: a[i++] });
  while (j < m) ops.push({ t: '+', s: b[j++] });
  return ops;
}

export function diffOps(before: string, after: string): Op[] {
  const a = before.split('\n');
  const b = after.split('\n');
  let pre = 0;
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
  let suf = 0;
  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  return [
    ...a.slice(0, pre).map((s) => ({ t: ' ' as const, s })),
    ...lcsOps(a.slice(pre, a.length - suf), b.slice(pre, b.length - suf)),
    ...a.slice(a.length - suf).map((s) => ({ t: ' ' as const, s })),
  ];
}

export function unifiedDiff(path: string, before: string, after: string, context = 3): string {
  if (before === after) return '';
  const ops = diffOps(before, after);
  const changed = ops.map((o, i) => (o.t !== ' ' ? i : -1)).filter((i) => i >= 0);
  // group changes whose context windows overlap into hunks
  const hunks: [number, number][] = [];
  for (const i of changed) {
    const lo = Math.max(0, i - context);
    const hi = Math.min(ops.length - 1, i + context);
    const last = hunks[hunks.length - 1];
    if (last && lo <= last[1] + 1) last[1] = Math.max(last[1], hi);
    else hunks.push([lo, hi]);
  }
  const out = [`--- a/${path}`, `+++ b/${path}`];
  for (const [lo, hi] of hunks) {
    let aStart = 1;
    let bStart = 1;
    for (let k = 0; k < lo; k++) {
      if (ops[k].t !== '+') aStart++;
      if (ops[k].t !== '-') bStart++;
    }
    const body = ops.slice(lo, hi + 1);
    const aLen = body.filter((o) => o.t !== '+').length;
    const bLen = body.filter((o) => o.t !== '-').length;
    out.push(`@@ -${aLen ? aStart : aStart - 1},${aLen} +${bLen ? bStart : bStart - 1},${bLen} @@`);
    for (const o of body) out.push(o.t + o.s);
  }
  return out.join('\n') + '\n';
}

/**
 * Map 1-based line numbers of `before` onto `after`. A replaced line maps to
 * the position of its replacement, so findings on later lines can be
 * re-located after an earlier fix inserted imports or helpers.
 */
export function lineMapper(before: string, after: string): (line: number) => number {
  const map: number[] = [];
  let a = 0;
  let b = 0;
  for (const o of diffOps(before, after)) {
    if (o.t === ' ') map[a++] = b++;
    else if (o.t === '-') map[a++] = b;
    else b++;
  }
  return (line) => (map[line - 1] ?? line - 1) + 1;
}

export function diffStats(diff: string): { added: number; removed: number } {
  let added = 0;
  let removed = 0;
  for (const l of diff.split('\n')) {
    if (l.startsWith('+++') || l.startsWith('---')) continue;
    if (l.startsWith('+')) added++;
    else if (l.startsWith('-')) removed++;
  }
  return { added, removed };
}
