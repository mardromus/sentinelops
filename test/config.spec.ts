import { SourceFile } from '../src/common/types';
import { ConfigScanner } from '../src/scanners/config/config.scanner';
import { languageOf } from '../src/scanners/files';

const file = (path: string, content: string): SourceFile => ({
  path,
  absPath: '/x/' + path,
  content,
  lines: content.split('\n'),
  language: languageOf(path),
});
const scan = (...files: SourceFile[]) => new ConfigScanner().scan({ options: { root: '/x' }, files });
const ids = (fs: { ruleId: string }[]) => fs.map((f) => f.ruleId).sort();

describe('config scanner', () => {
  it('checks Dockerfiles', async () => {
    const fs = await scan(
      file(
        'Dockerfile',
        [
          'FROM node:latest',
          'ENV JWT_SECRET=supersecret-shop-key-2026',
          'RUN curl -fsSL https://get.example.dev/install.sh | bash',
          'ADD https://example.dev/tool.tgz /opt/',
          'COPY . /app',
          'CMD ["node", "server.js"]',
        ].join('\n'),
      ),
    );
    expect(ids(fs)).toEqual([
      'config.docker.add-remote-url',
      'config.docker.curl-pipe-shell',
      'config.docker.runs-as-root',
      'config.docker.secret-in-env',
      'config.docker.unpinned-base-image',
    ]);
  });

  it('accepts a hardened multi-stage Dockerfile', async () => {
    const fs = await scan(
      file(
        'api/Dockerfile',
        [
          'FROM node:20.11-alpine AS build',
          'RUN npm ci',
          'FROM node:20.11-alpine',
          'COPY --from=build /app /app',
          'ENV NODE_ENV=production',
          'USER node',
          'CMD ["node", "dist/main.js"]',
        ].join('\n'),
      ),
    );
    expect(fs).toHaveLength(0);
  });

  it('checks compose and kubernetes manifests', async () => {
    const compose = file(
      'docker-compose.yml',
      ['services:', '  app:', '    privileged: true', '    network_mode: host', '    volumes:', '      - /var/run/docker.sock:/var/run/docker.sock'].join('\n'),
    );
    const k8s = file(
      'k8s/deploy.yaml',
      ['apiVersion: apps/v1', 'kind: Deployment', 'spec:', '  template:', '    spec:', '      hostNetwork: true', '      containers:', '        - securityContext:', '            allowPrivilegeEscalation: true', '            runAsUser: 0'].join('\n'),
    );
    const other = file('config/app.yaml', 'privileged: true\n'); // not a container manifest
    expect(ids(await scan(compose, k8s, other))).toEqual([
      'config.container.docker-socket',
      'config.container.host-namespace',
      'config.container.host-namespace',
      'config.container.privileged',
      'config.k8s.privilege-escalation',
      'config.k8s.runs-as-root',
    ]);
  });

  it('checks GitHub Actions workflows', async () => {
    const wf = file(
      '.github/workflows/pr.yml',
      [
        'on:',
        '  pull_request_target:',
        'permissions: write-all',
        'jobs:',
        '  build:',
        '    runs-on: ubuntu-latest',
        '    steps:',
        '      - uses: actions/checkout@v4',
        '        with:',
        '          ref: ${{ github.event.pull_request.head.sha }}',
        '      - uses: some-org/deploy-action@v2',
        '      - uses: other-org/lint@0123456789abcdef0123456789abcdef01234567',
        '      - run: echo "${{ github.event.pull_request.title }}"',
      ].join('\n'),
    );
    expect(ids(await scan(wf))).toEqual([
      'config.gha.pull-request-target-checkout',
      'config.gha.script-injection',
      'config.gha.unpinned-action',
      'config.gha.write-all-permissions',
    ]);
  });

  it('flags committed .env files but not templates', async () => {
    const fs = await scan(file('.env', 'A=1'), file('.env.production', 'A=1'), file('.env.example', 'A='));
    expect(fs.map((f) => f.location.file)).toEqual(['.env', '.env.production']);
    expect(fs[0].cwe).toEqual(['CWE-538']);
  });
});
