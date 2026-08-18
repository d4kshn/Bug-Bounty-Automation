# Operations and human gates

## Gate behavior

| Gate | Implemented behavior | Your involvement |
|---|---|---|
| Enrollment | Policy file hash and full manifest hash must both match; absent/changed configuration pauses the program | Mandatory on enrollment and every policy/scope change |
| Scan authorization | Adapters accept only configured target types, exclusions, safe presets/profiles, rates, methods, ports, and paths; DNS/private-IP checks run before active HTTP work | Review every initial canary and any new recipe/profile |
| Signal value | Events are redacted, deduplicated, diffed, and deterministically scored; unchanged/low-value observations stay out of LLM queues | Tune `llm.trigger_score` during the pilot |
| Hypothesis | One event and relevant cards enter one fresh schema-bound planner process | Inspect candidates, especially ambiguity/manual prerequisites |
| Safe plan | Model steps compile only to three read-only HTTP primitives and a strict request budget | Everything else becomes `manual_required` |
| Evidence/critic | Verifier rechecks scope immediately before each request; a fresh critic tries to disprove the candidate | Manually reproduce every non-rejected candidate |
| Report readiness | Candidate, evidence IDs, verification, critique, and your notes remain distinct | Check duplicates, scope, impact, cleanup, severity, and redaction |
| Submission | API only records your decision after validation; there is no platform submission adapter | Submit manually, then mark the record submitted |

## Routine commands

```bash
sudo docker compose ps
sudo docker compose logs --tail=200 scanner
sudo docker compose logs --tail=200 codex-worker claude-worker
sudo docker compose run --rm --no-deps api doctor
sudo docker compose --profile llm run --rm --no-deps claude-worker llm-check --provider claude
sudo docker compose --profile llm run --rm --no-deps codex-worker llm-check --provider codex
sudo ./scripts/api.sh /api/v1/programs | jq
sudo ./scripts/api.sh '/api/v1/jobs?limit=50' | jq
sudo ./scripts/api.sh '/api/v1/events?min_score=70' | jq
sudo ./scripts/api.sh '/api/v1/findings?status=awaiting_human' | jq
sudo ./scripts/api.sh '/api/v1/evidence?program_id=your-program' | jq
```

Enqueue only an approved adapter:

```bash
sudo ./scripts/api.sh /api/v1/jobs -X POST \
  --data '{"program_id":"your-program","kind":"shodan"}' | jq
```

Cancel a pending/running job cooperatively:

```bash
sudo ./scripts/api.sh /api/v1/jobs/JOB_ID/cancel -X POST | jq
```

Cancellation prevents a queued job from starting; it cannot interrupt an external scanner process already executing. Stop the scanner container if immediate interruption is required, then inspect scope and job state before restarting.

## Manual finding workflow

1. Open the candidate in Grafana and retrieve the full record through the API.
2. Read the original program policy again. Confirm the asset and vulnerability class are eligible.
3. Reproduce manually in a clean session using only approved research accounts. Do not trust the model's impact statement.
4. Check a negative control, benign explanations, duplicate likelihood, affected roles/tenants, and cleanup.
5. Redact tokens, cookies, personal data, and unnecessary response content.
6. Record a concise, redacted reproduction. This stores it as evidence and queues the separate critic:

```bash
sudo ./scripts/api.sh /api/v1/findings/FINDING_ID/action -X POST \
  --data '{"action":"record_manual_verification","notes":"Clean account and negative control.","verification":{"reproduced":true,"control":"Unaffected control returned 403","impact":"Read-only metadata exposure"}}' | jq
```

7. Wait for the fresh critic, review its benign explanations and missing evidence, then accept or reject the candidate:

```bash
sudo ./scripts/api.sh /api/v1/findings/FINDING_ID/action -X POST \
  --data '{"action":"validate","notes":"Critique reviewed; manually confirmed scope and impact."}' | jq
```

8. Submit on the bounty platform yourself. Only afterward record that external action:

```bash
sudo ./scripts/api.sh /api/v1/findings/FINDING_ID/action -X POST \
  --data '{"action":"mark_submitted","notes":"Submitted manually as platform report 12345."}' | jq
```

A finding cannot be marked submitted before human validation. The API never logs in to a platform or sends a report.

## Evidence, retention, and backup

Evidence is redacted before durable storage, written atomically with mode `0600`, addressed by an evidence ID/SHA-256 record, and expires after the program retention period (90 days by default). Retrieve a bounded excerpt or place a retention hold through the private API:

```bash
sudo ./scripts/api.sh '/api/v1/evidence/EVIDENCE_ID?include_excerpt=true&excerpt_bytes=8192' | jq
sudo ./scripts/api.sh /api/v1/evidence/EVIDENCE_ID/action -X POST \
  --data '{"action":"hold","notes":"Preserve for submitted report 12345."}' | jq
```

Release the hold with `{"action":"release"}` after the report/appeal lifecycle ends.

Create a local protected backup:

```bash
sudo ./scripts/backup.sh
```

It captures PostgreSQL, evidence, and configuration, but intentionally excludes secrets. Encrypt backups before copying them off-host and test restoration on an isolated host. The repository does not automate cloud upload because destination, residency, and key management are user-specific.

## Failure handling

- Jobs use leases and retry up to their configured attempt limit with exponential backoff.
- Exhausted failures create a redacted Discord alert.
- Scanner collection continues when LLM workers are offline; LLM jobs remain queued.
- A missing/edited manifest or policy snapshot pauses new jobs for that program at worker preflight.
- A manifest that no longer parses or validates pauses only its own program; other programs keep running and the API, scheduler, and workers keep starting. `validate-config` and `doctor` list the offending files under `invalid_manifests`, and two manifests claiming the same `program_id` pause both.
- An LLM cannot authorize a request. Invalid output fails schema parsing; unsafe steps become manual.
- Rotate any secret that may have reached logs or evidence, then inspect and delete the affected artifact under a documented incident procedure.

Before upgrades: back up, inspect release notes, change one pin, rebuild, run tests, canary one program, and only then restart scheduled work.
