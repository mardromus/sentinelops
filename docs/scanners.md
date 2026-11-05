# Scanners

| Scanner | Finds | Data source | Output category |
|---|---|---|---|
| `builtin-sast` | injection, XSS, traversal, SSRF, redirects, crypto, JWT, cookies, headers, deserialisation (JS/TS, Python) | [26 rules](rules.md) | `sast` |
| `builtin-secrets` | provider tokens (AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, SendGrid, npm), private keys, credentials in connection strings, JWTs, generic `password = "…"` assignments, `.env` values | regex + Shannon entropy + placeholder filter | `secret` |
| `builtin-deps` | known-vulnerable packages | `package-lock.json` (v1-v3), `package.json` ranges, `requirements*.txt` → [OSV.dev](https://osv.dev) batch API, offline snapshot as fallback | `dependency` |
| `builtin-config` | IaC and pipeline misconfiguration | Dockerfile, docker-compose, Kubernetes manifests, GitHub Actions workflows, committed `.env` files | `config` |
| `semgrep` / `gitleaks` / `trivy` | community SAST, git-history secrets, OS packages | used when installed (`--no-external` to skip) | as reported |

## Secrets

- Snippets are masked in every report (`abcd************yz`).
- Placeholders are ignored: `changeme`, `your_api_key`, `${TOKEN}`, `process.env.X`, `<secret>`, `xxxx`, …
- `.env.example`, `.env.sample`, `.env.template` and lockfiles are skipped.
- Remediation: rotate first (the value is in git history), then the `secret-to-env` fixer replaces the literal with `process.env.NAME` / `os.environ["NAME"]`.

## Dependencies

- Versions come from the lockfile when there is one; ranges in `package.json` are used only without a lockfile and are marked medium confidence.
- Direct, transitive and dev-only dependencies are told apart (dev-only lowers the risk score).
- The fix target is the smallest version that leaves **every** matching advisory range; direct dependencies are bumped in `package.json`, transitive ones get an npm `overrides` entry, Python pins are rewritten in place.
- `--no-osv` (or `SENTINELOPS_OSV=0`) keeps everything offline.

## Configuration checks

| Rule | File | Why it matters | Autofix |
|---|---|---|---|
| `config.docker.unpinned-base-image` | Dockerfile | `:latest` / untagged images change under you | |
| `config.docker.runs-as-root` | Dockerfile | no non-root `USER` in the final stage | yes |
| `config.docker.secret-in-env` | Dockerfile | `ENV`/`ARG` credentials live in image layers | yes |
| `config.docker.curl-pipe-shell` | Dockerfile | executes whatever the server returns | |
| `config.docker.add-remote-url` | Dockerfile | `ADD https://…` without integrity check | |
| `config.container.privileged` | compose / k8s | full host access | yes |
| `config.container.host-namespace` | compose / k8s | host network / PID / IPC | |
| `config.container.docker-socket` | compose / k8s | docker.sock = root on the host | |
| `config.k8s.privilege-escalation` | k8s | setuid escalation allowed | yes |
| `config.k8s.runs-as-root` | k8s | `runAsUser: 0` / `runAsNonRoot: false` | yes |
| `config.gha.unpinned-action` | workflow | third-party action on a movable tag | |
| `config.gha.pull-request-target-checkout` | workflow | fork code runs with repository secrets | |
| `config.gha.script-injection` | workflow | `${{ github.event.*.title }}` inside `run:` | yes (single-line `run`) |
| `config.gha.write-all-permissions` | workflow | token can push and release | |
| `config.repo.env-file-committed` | `.env*` | environment files in version control | |

## Suppressing findings

- Inline: `// sentinelops-ignore: reason` on the line or the line above.
- Baseline: `sentinelops baseline .` writes `.sentinelops/baseline.json`; entries can carry `until` (ISO date) to expire. Review it like code.
- The agent never suppresses anything; it can only recommend.
