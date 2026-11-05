# vulnerable-shop (intentionally insecure)

> **Do not deploy or run this code.** It is a scan target for SentinelOps, written to contain
> one realistic example of each class of issue the agent detects and fixes. The secrets in it
> are made up and not valid for any service.

| Where | What is wrong | OWASP |
|---|---|---|
| `src/db.js` | SQL built by string concatenation and template literals | A03 Injection |
| `src/files.js` | path traversal, shell command built from input | A01, A03 |
| `src/proxy.js` | server-side request forgery, open redirect | A10, A01 |
| `src/auth.js` | `jwt.decode` without verification, MD5 passwords, `Math.random` tokens, insecure cookie, hard-coded secret | A07, A02, A05 |
| `src/server.js` | no security headers, wildcard CORS, reflected XSS, `eval`, stack traces to clients, a comment that tries to talk the AI reviewer out of reporting it | A03, A05 |
| `src/config.js` | credentials in a connection string, TLS verification disabled | A07, A02 |
| `worker/app.py` | f-string SQL, `shell=True`, `pickle`, `yaml.load`, `verify=False`, Flask debug | A03, A08, A05 |
| `package-lock.json`, `worker/requirements.txt` | dependencies with published advisories (direct, transitive and dev-only) | A06 |
| `Dockerfile`, `docker-compose.yml`, `k8s/` | root containers, privileged mode, Docker socket, secret in `ENV`, `curl \| bash` | A05, A08 |
| `.github/workflows/deploy.yml` | `pull_request_target` checking out PR code, script injection, unpinned action | A08 |
| `.env` | committed environment file | A01 |

Scan it from the repository root:

```bash
npm run demo
```
