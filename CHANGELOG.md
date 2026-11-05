# Changelog

## 1.0.0

First release.

- **Scanners**: 26 OWASP/CWE-mapped SAST rules for JavaScript/TypeScript and Python; secrets (provider formats, entropy-filtered generic credentials, `.env` files); dependencies from `package-lock.json`, `package.json` and `requirements*.txt` against OSV.dev with an offline advisory snapshot; Dockerfile, docker-compose, Kubernetes and GitHub Actions checks; optional semgrep / gitleaks / trivy adapters with cross-tool de-duplication.
- **Triage**: explainable 0-100 risk score, P1-P4 priorities, baselines with expiry, scan diffs and a CI gate.
- **Remediation**: 26 deterministic fixers (parameterised SQL, `execFile`, HTML encoding, SSRF allow-list, safe redirects, JWT verification, crypto, cookies, helmet, CORS, dependency bumps and overrides, non-root containers, secrets to env, Actions env indirection, ...). Every fix is syntax-checked and re-scanned before it counts as verified.
- **Agent**: OpenAI-compatible tool-calling loop with an offline planner fallback; autonomy levels L0-L3; prompt-injection detection, secret redaction, path sandbox, verdict guardrails, summary validation and a hash-chained audit log.
- **Reports**: SARIF 2.1.0, Markdown PR comment, self-contained HTML report with an OWASP Top 10 heatmap.
- **Integrations**: NestJS API and dashboard, GitHub webhooks (PR review, commit status, fix PRs, `/sentinelops` ChatOps), CLI, GitHub Action, Docker image.
