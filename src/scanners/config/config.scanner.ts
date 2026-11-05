/**
 * Infrastructure-as-code and pipeline checks: Dockerfiles, docker-compose,
 * Kubernetes manifests, GitHub Actions workflows and committed .env files.
 */
import { Confidence, Finding, Severity, SourceFile } from '../../common/types';
import { isSuppressedInline } from '../files';
import { makeFinding, ScanContext, Scanner, snippetAt } from '../scanner';

export interface ConfigHit {
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  cwe: string[];
  line: number;
  message: string;
  remediation: string;
}

type Check = (file: SourceFile) => ConfigHit[];

const SECRET_KEY = /(password|passwd|secret|token|api_?key|access_?key|private_?key)/i;

export function isEnvFile(path: string): boolean {
  return /(^|\/)\.env(\.[A-Za-z0-9_-]+)?$/.test(path) && !/\.(example|sample|template|dist)$/.test(path);
}
export function isWorkflow(path: string): boolean {
  return /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(path);
}
export function isCompose(path: string): boolean {
  return /(^|\/)(docker-)?compose[^/]*\.ya?ml$/.test(path);
}
export function isKubernetes(file: SourceFile): boolean {
  return file.language === 'yaml' && /^\s*apiVersion\s*:/m.test(file.content) && /^\s*kind\s*:/m.test(file.content);
}

// ---------------------------------------------------------------- Dockerfile
export const dockerfileChecks: Check = (file) => {
  if (file.language !== 'docker') return [];
  const hits: ConfigHit[] = [];
  const stages = new Set<string>();
  const state: { lastFrom: number; lastUser: { line: number; user: string } | null } = { lastFrom: 0, lastUser: null };

  file.lines.forEach((raw, i) => {
    const line = raw.trim();
    const n = i + 1;
    const from = /^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i.exec(line);
    if (from) {
      state.lastFrom = n;
      state.lastUser = null;
      const image = from[1];
      if (from[2]) stages.add(from[2].toLowerCase());
      const isStage = stages.has(image.toLowerCase()) && !from[2];
      if (!isStage && image !== 'scratch' && !image.includes('@sha256:') && (/:latest$/.test(image) || !/:[^/]+$/.test(image))) {
        hits.push({
          ruleId: 'config.docker.unpinned-base-image',
          title: 'Base image not pinned',
          severity: 'low',
          confidence: 'high',
          cwe: ['CWE-829'],
          line: n,
          message: `"${image}" floats to whatever is published next, so builds are not reproducible and can pull a compromised image.`,
          remediation: 'Pin to a specific version tag, ideally with a digest: node:20.11-alpine@sha256:...',
        });
      }
    }
    const user = /^USER\s+(\S+)/i.exec(line);
    if (user) state.lastUser = { line: n, user: user[1] };
    const env = /^(ENV|ARG)\s+([A-Za-z_][A-Za-z0-9_]*)[=\s]+["']?([^"'\s]+)/i.exec(line);
    if (env && SECRET_KEY.test(env[2]) && env[3].length >= 6 && !/^\$/.test(env[3])) {
      hits.push({
        ruleId: 'config.docker.secret-in-env',
        title: 'Secret baked into the image',
        severity: 'high',
        confidence: 'medium',
        cwe: ['CWE-798'],
        line: n,
        message: `${env[1]} ${env[2]} stores a credential in an image layer; anyone who can pull the image can read it.`,
        remediation: 'Inject secrets at runtime (env, mounted secret) or use BuildKit --mount=type=secret.',
      });
    }
    if (/^RUN\b.*\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b/i.test(line)) {
      hits.push({
        ruleId: 'config.docker.curl-pipe-shell',
        title: 'Remote script piped into a shell',
        severity: 'medium',
        confidence: 'high',
        cwe: ['CWE-494'],
        line: n,
        message: 'The build executes whatever the remote server returns at build time.',
        remediation: 'Download, verify a checksum or signature, then execute.',
      });
    }
    if (/^ADD\s+https?:\/\//i.test(line)) {
      hits.push({
        ruleId: 'config.docker.add-remote-url',
        title: 'ADD from a remote URL',
        severity: 'low',
        confidence: 'high',
        cwe: ['CWE-494'],
        line: n,
        message: 'ADD fetches remote content without integrity checks.',
        remediation: 'Use RUN curl with checksum verification, or ADD --checksum=sha256:...',
      });
    }
  });

  const u = state.lastUser;
  if (state.lastFrom && (!u || /^(root|0)(:|$)/.test(u.user))) {
    hits.push({
      ruleId: 'config.docker.runs-as-root',
      title: 'Container runs as root',
      severity: 'medium',
      confidence: 'high',
      cwe: ['CWE-250'],
      line: u ? u.line : state.lastFrom,
      message: 'The final stage has no non-root USER, so a compromise of the app is a compromise of the container as root.',
      remediation: 'Add a non-root user and switch to it: RUN adduser -D app && USER app (node images ship "node").',
    });
  }
  return hits;
};

// ------------------------------------------------------- compose / kubernetes
export const containerYamlChecks: Check = (file) => {
  if (file.language !== 'yaml' || isWorkflow(file.path) || !(isCompose(file.path) || isKubernetes(file))) return [];
  const hits: ConfigHit[] = [];
  const add = (n: number, ruleId: string, title: string, severity: Severity, cwe: string[], message: string, remediation: string) =>
    hits.push({ ruleId, title, severity, confidence: 'high', cwe, line: n, message, remediation });
  file.lines.forEach((raw, i) => {
    const line = raw.replace(/#.*$/, '');
    const n = i + 1;
    if (/^\s*privileged\s*:\s*true\b/.test(line))
      add(
        n,
        'config.container.privileged',
        'Privileged container',
        'high',
        ['CWE-250'],
        'A privileged container has full access to the host kernel and devices.',
        'Remove privileged: true; grant only the specific capabilities needed.',
      );
    if (/^\s*(hostNetwork|hostPID|hostIPC)\s*:\s*true\b/.test(line) || /^\s*(network_mode|pid)\s*:\s*["']?host\b/.test(line))
      add(
        n,
        'config.container.host-namespace',
        'Container shares host namespaces',
        'medium',
        ['CWE-668'],
        'Sharing host network/PID/IPC namespaces removes container isolation.',
        'Use the default isolated namespaces and publish ports explicitly.',
      );
    if (/docker\.sock/.test(line) && /^\s*-|\bpath\s*:/.test(line))
      add(
        n,
        'config.container.docker-socket',
        'Docker socket mounted into container',
        'high',
        ['CWE-668'],
        'Access to docker.sock is root on the host.',
        'Do not mount the Docker socket; use a restricted API proxy if unavoidable.',
      );
    if (/^\s*allowPrivilegeEscalation\s*:\s*true\b/.test(line))
      add(
        n,
        'config.k8s.privilege-escalation',
        'Privilege escalation allowed',
        'medium',
        ['CWE-250'],
        'Processes can gain more privileges than their parent (setuid binaries).',
        'Set allowPrivilegeEscalation: false in the securityContext.',
      );
    if (/^\s*runAsUser\s*:\s*0\b/.test(line) || /^\s*runAsNonRoot\s*:\s*false\b/.test(line))
      add(
        n,
        'config.k8s.runs-as-root',
        'Pod runs as root',
        'medium',
        ['CWE-250'],
        'The container is explicitly configured to run as UID 0.',
        'Set runAsNonRoot: true and a non-zero runAsUser.',
      );
  });
  return hits;
};

// ------------------------------------------------------------ GitHub Actions
/** Event fields an outside contributor controls (titles, bodies, branch names, commit messages). */
export const UNTRUSTED_EXPR =
  /\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|head_commit|discussion|commits)[\w.[\]*]*\.(title|body|message|name|label|ref|email|default_branch)\b[\w.]*|github\.head_ref)\s*\}\}/;

export const workflowChecks: Check = (file) => {
  if (!isWorkflow(file.path)) return [];
  const hits: ConfigHit[] = [];
  const prTarget = /^\s*pull_request_target\s*:?/m.test(file.content) || /on\s*:\s*\[?[^\]\n]*pull_request_target/.test(file.content);
  let runBlock: number | null = null; // indentation of a `run: |` key while inside its script
  file.lines.forEach((raw, i) => {
    const line = raw.replace(/\s#.*$/, '');
    const n = i + 1;
    const indent = /^(\s*)/.exec(raw)![1].length;
    if (runBlock !== null && raw.trim() && indent <= runBlock) runBlock = null;
    const runKey = /^(\s*)(-\s*)?run\s*:/.exec(raw);
    const inScript = runBlock !== null || !!runKey;
    if (runKey && /run\s*:\s*[|>][-+]?\s*$/.test(raw)) runBlock = runKey[1].length + (runKey[2]?.length || 0);
    const uses = /^\s*-?\s*uses\s*:\s*["']?([^@\s"']+)@([^\s"']+)/.exec(line);
    if (uses && !uses[1].startsWith('./') && !/^(actions|github)\//.test(uses[1]) && !/^[0-9a-f]{40}$/.test(uses[2])) {
      hits.push({
        ruleId: 'config.gha.unpinned-action',
        title: 'Third-party action not pinned to a commit',
        severity: 'low',
        confidence: 'high',
        cwe: ['CWE-829'],
        line: n,
        message: `${uses[1]}@${uses[2]} can be re-tagged by its owner; the workflow runs whatever the tag points to.`,
        remediation: 'Pin to a full commit SHA and keep the version in a comment: uses: org/action@<sha> # v2.1.0',
      });
    }
    if (prTarget && /github\.event\.pull_request\.head\.(sha|ref)|refs\/pull\//.test(line)) {
      hits.push({
        ruleId: 'config.gha.pull-request-target-checkout',
        title: 'pull_request_target checks out untrusted code',
        severity: 'high',
        confidence: 'high',
        cwe: ['CWE-829'],
        line: n,
        message: 'pull_request_target runs with repository secrets; checking out the PR head lets a fork execute code with them.',
        remediation: 'Use the pull_request trigger for untrusted code, or split into a privileged workflow_run that never runs PR code.',
      });
    }
    if (inScript && UNTRUSTED_EXPR.test(line)) {
      hits.push({
        ruleId: 'config.gha.script-injection',
        title: 'Untrusted event data interpolated into a shell script',
        severity: 'high',
        confidence: 'medium',
        cwe: ['CWE-94'],
        line: n,
        message: 'A crafted issue/PR title or body becomes shell code in the runner.',
        remediation: 'Pass the value through env: (TITLE: ${{ github.event.issue.title }}) and use "$TITLE" in the script.',
      });
    }
    if (/^\s*permissions\s*:\s*write-all\b/.test(line)) {
      hits.push({
        ruleId: 'config.gha.write-all-permissions',
        title: 'Workflow token has write-all permissions',
        severity: 'medium',
        confidence: 'high',
        cwe: ['CWE-250'],
        line: n,
        message: 'Every job gets a token that can push code, create releases and change settings.',
        remediation: 'Declare least-privilege permissions per job (contents: read, pull-requests: write, ...).',
      });
    }
  });
  return hits;
};

// --------------------------------------------------------- committed .env
export const envFileChecks: Check = (file) =>
  isEnvFile(file.path)
    ? [
        {
          ruleId: 'config.repo.env-file-committed',
          title: '.env file committed to the repository',
          severity: 'medium',
          confidence: 'high',
          cwe: ['CWE-538'],
          line: 1,
          message: `${file.path} holds environment configuration and usually credentials; it should never be versioned.`,
          remediation:
            'git rm --cached the file, add it to .gitignore, commit a .env.example with placeholders and rotate any secrets it contained.',
        },
      ]
    : [];

export const CONFIG_CHECKS: Check[] = [dockerfileChecks, containerYamlChecks, workflowChecks, envFileChecks];

export class ConfigScanner implements Scanner {
  readonly name = 'builtin-config';

  async scan(ctx: ScanContext): Promise<Finding[]> {
    const out: Finding[] = [];
    for (const file of ctx.files) {
      for (const check of CONFIG_CHECKS) {
        for (const h of check(file)) {
          const suppressed = isSuppressedInline(file.lines, h.line - 1);
          out.push(
            makeFinding({
              ruleId: h.ruleId,
              title: h.title,
              message: h.message,
              category: 'config',
              severity: h.severity,
              confidence: h.confidence,
              cwe: h.cwe,
              location: {
                file: file.path,
                line: h.line,
                snippet: h.ruleId === 'config.repo.env-file-committed' ? file.path : snippetAt(file, h.line),
              },
              scanner: this.name,
              remediation: h.remediation,
              suppressed,
              suppressReason: suppressed ? 'inline sentinelops-ignore' : undefined,
            }),
          );
        }
      }
    }
    return out;
  }
}
