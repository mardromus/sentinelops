# GitHub integration

Two ways to use SentinelOps on GitHub.

## 1. GitHub Action (no server)

```yaml
# .github/workflows/security.yml
name: security
on: [pull_request]
permissions:
  contents: read
  security-events: write   # to upload SARIF
jobs:
  sentinelops:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mardromus/sentinelops@main
        with:
          fail-on: high
        env:
          SENTINELOPS_LLM_API_KEY: ${{ secrets.SENTINELOPS_LLM_API_KEY }}   # optional
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: sentinelops.sarif
```

Findings appear in **Security → Code scanning** (ranked by `security-severity`), the Markdown report lands in the job summary, and the step fails when the gate fails. Pin `@main` to a commit SHA for production use (SentinelOps would flag it otherwise).

## 2. Webhook server (comments, statuses, fix PRs, ChatOps)

1. Run the server somewhere GitHub can reach:
   ```bash
   docker build -t sentinelops .
   docker run -p 3000:3000 -v so-data:/data \
     -e GITHUB_TOKEN=... -e GITHUB_WEBHOOK_SECRET=... \
     -e SENTINELOPS_AUTONOMY=2 -e SENTINELOPS_PUBLIC_URL=https://sentinelops.example.com \
     sentinelops
   ```
2. Token permissions (fine-grained PAT or GitHub App): **Contents** read & write (fix branches), **Pull requests** read & write, **Issues** read & write (comments), **Commit statuses** read & write, **Metadata** read.
3. Repository → Settings → Webhooks → Add webhook:
   - Payload URL: `https://<host>/webhooks/github`
   - Content type: `application/json`
   - Secret: the same value as `GITHUB_WEBHOOK_SECRET`
   - Events: *Pull requests*, *Issue comments*, *Pushes*

### What happens on a pull request

1. Commit status `sentinelops` → *pending*.
2. The head commit is fetched (one commit, token in an HTTP header, never in argv) and run through the full pipeline with the agent.
3. One PR comment is created and then updated on every push (hidden marker `<!-- sentinelops:report -->`): gate, counts, OWASP categories, agent briefing, top findings with fix diffs, link to the HTML report.
4. Status → *success* / *failure* with the number of blocking findings.
5. At **L2** verified fixes are committed to `sentinelops/fix-<pr>-<sha>` and opened as a **draft** PR into the PR branch. At **L3** low-risk fixes go out ready for review. Fork PRs only get suggestions.

### ChatOps

Comment on a pull request (requires write access to the repository):

| Command | Effect |
|---|---|
| `/sentinelops rescan` | run the review again |
| `/sentinelops fix` | open a PR with all verified fixes (counts as human approval) |
| `/sentinelops fix SO-1a2b3c4d` | open a PR with that one fix |

Every command, permission check and PR is recorded in the audit log.

## Local testing of the webhook

```bash
export GITHUB_WEBHOOK_SECRET=dev-secret
npm run start:dev &
body='{"zen":"hi"}'
sig="sha256=$(printf '%s' "$body" | openssl dgst -sha256 -hmac "$GITHUB_WEBHOOK_SECRET" | cut -d' ' -f2)"
curl -s localhost:3000/webhooks/github -H 'x-github-event: ping' -H "x-hub-signature-256: $sig" \
     -H 'content-type: application/json' -d "$body"
```
