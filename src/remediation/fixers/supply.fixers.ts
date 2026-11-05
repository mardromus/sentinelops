/**
 * Fixers for dependency, container and secret findings.
 */
import { SourceFile } from '../../common/types';
import { lineHits } from '../../scanners/secrets/secrets.scanner';
import { normalizeName } from '../../scanners/deps/version';
import { ensurePyImport, envName, locate } from '../code';
import { Fixer, FixOutput } from './types';

// ------------------------------------------------------------ dependencies

/** The manifest to edit for a dependency finding (lockfiles are regenerated, not edited). */
export function manifestFor(lockOrManifest: string): string {
  if (/package-lock\.json$/.test(lockOrManifest)) return lockOrManifest.replace(/package-lock\.json$/, 'package.json');
  return lockOrManifest;
}

export const dependencyBump: Fixer = ({ finding, content, path }) => {
  const pkg = finding.package;
  if (!pkg?.fixedIn) return null;
  if (/package\.json$/.test(path)) {
    let doc: any;
    try {
      doc = JSON.parse(content);
    } catch {
      return null;
    }
    const indent = /^(\s+)"/m.exec(content)?.[1] || '  ';
    const range = `^${pkg.fixedIn}`;
    let where = '';
    for (const section of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      if (doc[section]?.[pkg.name] !== undefined) {
        if (doc[section][pkg.name] === range) return null;
        doc[section][pkg.name] = range;
        where = section;
      }
    }
    if (!where) {
      // transitive: force the patched version for the whole tree (npm >= 8.3)
      doc.overrides = { ...(doc.overrides || {}) };
      if (doc.overrides[pkg.name] === range) return null;
      doc.overrides[pkg.name] = range;
      where = 'overrides';
    }
    return {
      content: JSON.stringify(doc, null, indent) + (content.endsWith('\n') ? '\n' : ''),
      description: `Bumped ${pkg.name} ${pkg.version} -> ${range} in ${where}${where === 'overrides' ? ' (transitive dependency)' : ''}.`,
      notes: ['Run "npm install" to refresh package-lock.json, then run the test suite.'],
    };
  }
  if (/requirements[^/]*\.txt$/.test(path)) {
    const lines = content.split('\n');
    let changed = false;
    const out = lines.map((l) => {
      const m = /^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(==|>=|~=)\s*([^\s,;#]+)(.*)$/.exec(l);
      if (!m || normalizeName(m[2], 'PyPI') !== normalizeName(pkg.name, 'PyPI') || m[5] === pkg.fixedIn) return l;
      changed = true;
      return `${m[1]}${m[2]}${m[3] || ''}==${pkg.fixedIn}${m[6]}`;
    });
    if (!changed) return null;
    return { content: out.join('\n'), description: `Pinned ${pkg.name} to ${pkg.fixedIn}.`, notes: ['Reinstall with "pip install -r" and run the tests.'] };
  }
  return null;
};

// ------------------------------------------------------------ Dockerfile

export const dockerNonRoot: Fixer = ({ content }) => {
  const lines = content.split('\n');
  const froms = lines.map((l, i) => (/^\s*FROM\s/i.test(l) ? i : -1)).filter((i) => i >= 0);
  if (!froms.length) return null;
  const last = froms[froms.length - 1];
  const image = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)/i.exec(lines[last])![1];
  const rootUser = lines.findIndex((l, i) => i > last && /^\s*USER\s+(root|0)\b/i.test(l));
  const isNode = /^(docker\.io\/)?(library\/)?node(:|$)/.test(image);
  const isAlpine = /alpine/.test(image);
  const user = isNode ? 'node' : 'app';
  const create = isNode ? [] : [isAlpine ? 'RUN addgroup -S app && adduser -S app -G app' : 'RUN useradd --create-home --uid 10001 app'];
  if (rootUser >= 0) {
    lines.splice(rootUser, 1, ...create, `USER ${user}`);
  } else {
    let at = lines.findIndex((l, i) => i > last && /^\s*(CMD|ENTRYPOINT)\b/i.test(l));
    if (at < 0) at = lines.length;
    lines.splice(at, 0, ...create, `USER ${user}`);
  }
  return {
    content: lines.join('\n'),
    description: `The final stage now runs as the unprivileged "${user}" user.`,
    notes: ['Check that the app does not write to root-owned paths or bind ports below 1024.'],
  };
};

export const dockerSecretEnv: Fixer = ({ finding, content }) => {
  const lines = content.split('\n');
  const idx = locate(lines, finding);
  const m = idx >= 0 ? /^\s*(ENV|ARG)\s+([A-Za-z_][A-Za-z0-9_]*)/i.exec(lines[idx]) : null;
  if (!m) return null;
  lines[idx] = `# ${m[2]} is provided at runtime (docker run -e / orchestrator secret), not baked into the image`;
  return { content: lines.join('\n'), description: `Removed ${m[2]} from the image; supply it at runtime.`, notes: ['Rotate the old value: it is still present in earlier image layers and git history.'] };
};

export const yamlHarden: Fixer = ({ finding, content }) => {
  const lines = content.split('\n');
  const idx = locate(lines, finding);
  if (idx < 0) return null;
  const next = lines[idx]
    .replace(/(privileged\s*:\s*)true\b/, '$1false')
    .replace(/(allowPrivilegeEscalation\s*:\s*)true\b/, '$1false')
    .replace(/(runAsUser\s*:\s*)0\b/, '$110001')
    .replace(/(runAsNonRoot\s*:\s*)false\b/, '$1true');
  if (next === lines[idx]) return null;
  lines[idx] = next;
  return { content: lines.join('\n'), description: 'Hardened the container securityContext.' };
};

// ------------------------------------------------------------ secrets

const ENV_FOR_RULE: Record<string, string> = {
  'secret.aws-access-key-id': 'AWS_ACCESS_KEY_ID',
  'secret.aws-secret-access-key': 'AWS_SECRET_ACCESS_KEY',
  'secret.github-token': 'GITHUB_TOKEN',
  'secret.gitlab-token': 'GITLAB_TOKEN',
  'secret.slack-token': 'SLACK_TOKEN',
  'secret.slack-webhook': 'SLACK_WEBHOOK_URL',
  'secret.stripe-live-key': 'STRIPE_SECRET_KEY',
  'secret.google-api-key': 'GOOGLE_API_KEY',
  'secret.openai-key': 'OPENAI_API_KEY',
  'secret.sendgrid-key': 'SENDGRID_API_KEY',
  'secret.npm-token': 'NPM_TOKEN',
  'secret.connection-string': 'DATABASE_URL',
  'secret.jwt': 'SERVICE_TOKEN',
};

export const secretToEnv: Fixer = ({ finding, content, path }): FixOutput | null => {
  const lang = /\.py$/.test(path) ? 'py' : /\.[cm]?[jt]sx?$/.test(path) ? 'js' : null;
  if (!lang) return null;
  let lines = content.split('\n');
  const idx = locate(lines, finding);
  if (idx < 0) return null;
  const file: SourceFile = { path, absPath: path, content, lines, language: lang === 'py' ? 'py' : 'js' };
  const hit = lineHits(lines[idx], file).find((h) => h.pattern.id === finding.ruleId) || lineHits(lines[idx], file)[0];
  if (!hit) return null;
  const line = lines[idx];
  // the whole string literal that contains the secret
  const lit = new RegExp(`(['"\`])[^'"\`]*${hit.secret.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}[^'"\`]*\\1`).exec(line);
  if (!lit) return null;
  const name = hit.key ? envName(hit.key) : ENV_FOR_RULE[finding.ruleId] || 'APP_SECRET';
  const ref = lang === 'py' ? `os.environ["${name}"]` : `process.env.${name}`;
  lines[idx] = line.slice(0, lit.index) + ref + line.slice(lit.index + lit[0].length);
  if (lang === 'py') lines = ensurePyImport(lines, 'os');
  return {
    content: lines.join('\n'),
    description: `Moved the hard-coded credential out of the source: it is now read from ${name}.`,
    notes: [`Revoke and rotate the exposed value, then set ${name} in the environment or secret manager.`, 'The old value remains in git history.'],
  };
};

// ------------------------------------------------------------ GitHub Actions

const EVENT_PREFIX: Record<string, string> = { pull_request: 'PR', issue: 'ISSUE', comment: 'COMMENT', review: 'REVIEW', head_commit: 'COMMIT' };

/**
 * run: echo "${{ github.event.pull_request.title }}"
 *   ->
 * run: echo "$PR_TITLE"
 * env:
 *   PR_TITLE: ${{ github.event.pull_request.title }}
 * The value reaches the script as data in an environment variable instead of being pasted into its source.
 */
export const ghaEnvIndirection: Fixer = ({ finding, content }) => {
  const lines = content.split('\n');
  const idx = locate(lines, finding);
  if (idx < 0) return null;
  const line = lines[idx];
  const run = /^(\s*)(-\s*)?run\s*:\s*(?![|>])/.exec(line);
  if (!run) return null; // multi-line run blocks are left to a human
  const keyIndent = run[1].length + (run[2] ? run[2].length : 0);
  // the step must not already declare env (we would need to merge)
  for (let i = idx + 1; i < lines.length; i++) {
    const ind = /^(\s*)/.exec(lines[i])![1].length;
    if (lines[i].trim() === '') continue;
    if (ind < keyIndent || (ind === keyIndent && /^\s*-/.test(lines[i]))) break;
    if (ind === keyIndent && /^\s*env\s*:/.test(lines[i])) return null;
  }
  const vars: [string, string][] = [];
  const next = line.replace(/\$\{\{\s*(github\.(?:event\.(\w+)\.[\w.]+|head_ref))\s*\}\}/g, (_m, expr: string, scope?: string) => {
    const name = scope ? `${EVENT_PREFIX[scope] || scope.toUpperCase()}_${expr.split('.').pop()!.toUpperCase()}` : 'HEAD_REF';
    if (!vars.some(([n]) => n === name)) vars.push([name, expr]);
    return `$${name}`;
  });
  if (!vars.length) return null;
  const pad = ' '.repeat(keyIndent);
  lines.splice(idx, 1, next, `${pad}env:`, ...vars.map(([n, e]) => `${pad}  ${n}: \${{ ${e} }}`));
  return { content: lines.join('\n'), description: `Pass ${vars.map(([n]) => n).join(', ')} to the script through env instead of interpolating it into the shell source.` };
};
