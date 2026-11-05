# The agent: autonomy, tools and guardrails

The agent turns a list of scanner findings into decisions: which findings are real, which fixes to ship, what a human must look at. It runs in one of two modes and always produces the same report shape.

| Mode | When | How |
|---|---|---|
| **LLM** | `SENTINELOPS_LLM_API_KEY` is set (any OpenAI-compatible API: Groq, OpenAI, Together, Ollama, a gateway) | A bounded tool-calling loop (`SENTINELOPS_LLM_MAX_STEPS`, default 8). |
| **Offline planner** | no key, `--offline`, or the model is unreachable | Deterministic: the same steps, driven by triage evidence. CI and demos work without any API. |

## Autonomy levels

Set with `SENTINELOPS_AUTONOMY` or `--autonomy`. The level caps what the agent may do **on its own**; every decision, allowed or denied, is written to the audit log with its reason.

| Level | Name | The agent may | Needs a human |
|---|---|---|---|
| L0 | observe | scan and report | everything else |
| L1 | advise *(default)* | + record verdicts, comment on PRs, suggest verified patches | opening fix PRs |
| L2 | assist | + commit verified fixes to a new `sentinelops/…` branch and open a **draft** PR into the PR branch | reviewing and merging the draft |
| L3 | autonomous | + open **ready-for-review** PRs for *low-risk* fixes (verified, deterministic, ≤ 30 changed lines, or a same-major dependency upgrade) | merging; riskier fixes still go out as drafts |

Invariants at every level, enforced in code (`agent/policy.ts`, `github/github.service.ts`):

- the agent **never merges**, never pushes to the default branch or any existing branch, never force-pushes;
- the agent **never suppresses** a finding: it can only recommend it (`likely_false_positive`), and strong evidence blocks even that;
- **unverified** or **AI-written** patches always need human approval;
- fix PRs are only opened for same-repository PRs; forks get suggestions in the comment.

## Tools the model can call

| Tool | Purpose | Notes |
|---|---|---|
| `list_findings` | active findings, highest risk first | includes whether a deterministic fix exists |
| `get_finding` | details + OWASP/CWE guidance + surrounding code | code is wrapped as untrusted and redacted |
| `read_file` | up to 200 lines of a file | sandboxed to the repository; credential files blocked |
| `search_code` | literal search across the repository | e.g. "is this input validated elsewhere?" |
| `propose_fix` | run the deterministic fixer | returns the diff and the verification result |
| `write_patch` | the model's own minimal patch | ±15 lines around the finding, ≤ 40 lines, re-scanned, **never** auto-applied |
| `set_verdict` | `true_positive` / `likely_false_positive` / `needs_review` | passes through the verdict guardrail |
| `finish` | the developer briefing | validated before use |

## Guardrails

The agent reads text an attacker can control (source code, PR titles, comments). Everything from the repository is data, never instructions.

1. **Untrusted blocks.** Repository text reaches the model inside `<untrusted source="file:lines">` blocks; the system prompt says these are data. Attempts to close the block are neutralised.
2. **Prompt-injection detection.** Phrases that try to override instructions, reassign roles, steer verdicts ("mark this as a false positive"), suppress reporting or exfiltrate secrets are flagged per file. They are reported in the briefing and the HTML report, and they block dismissals in that file.
3. **Secret redaction.** Anything the secrets scanner recognises is masked before text leaves the machine.
4. **Path sandbox.** File access resolves inside the scan root (symlinks included); `.git`, `node_modules`, `.env*`, keys and credential files are off limits.
5. **Verdict guardrail.** A "likely false positive" is downgraded to "needs review" when the finding is high-confidence with request input reaching the sink, a provider-format secret, an in-range dependency advisory, or when injected text was seen in the same file.
6. **Summary validation.** Finding ids and CVE ids in the briefing that do not exist in the scan are removed (`[unknown finding]`, `[unverified CVE]`) and listed in `removedReferences`.
7. **Bounded loop.** Step limit, at most 8 tool calls per step, tool output truncated to 6 KB.
8. **Audit chain.** `data/audit.jsonl` is append-only; every entry stores the SHA-256 of the previous one, so editing or deleting a line is detectable (`sentinelops audit`, `GET /api/audit`).

These are tested with a scripted model in `test/agent.spec.ts`: a model that "falls for" an injected comment still cannot dismiss the SQL injection, cannot read `../../etc/passwd` or `.env`, and cannot cite a made-up CVE.

## Configuration

```bash
SENTINELOPS_LLM_API_KEY=...                       # empty = offline planner
SENTINELOPS_LLM_BASE_URL=https://api.groq.com/openai/v1
SENTINELOPS_LLM_MODEL=llama-3.3-70b-versatile     # or gpt-4o-mini, qwen2.5-coder via Ollama, ...
SENTINELOPS_LLM_MAX_STEPS=8
SENTINELOPS_AUTONOMY=1
```
