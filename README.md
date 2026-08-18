# Bug Bounty Automation Pipeline

This repository contains a deployable, policy-first v1 pipeline for a Debian VPS. It automates permitted reconnaissance, change detection, repository secret-candidate scanning, passive intelligence, prioritization, bounded LLM reasoning, evidence retention, and notifications. It does not autonomously exploit targets or submit reports.

The safe default is inert: the example manifest is ignored, Nuclei and automatic HTTP verification are disabled, no schedules exist, and the API/Grafana ports bind to loopback. A scan can run only after a saved policy snapshot and the complete program manifest both match their human-approved hashes.

## Runtime flow

```text
saved policy + reviewed scope
          |
          v
 human approval hash (mandatory)
          |
          v
 scheduler/API -> scope preflight -> BBOT | GitHub/Gitleaks | Shodan | Nuclei
                                      |
                                      v
                         normalize -> redact -> dedupe -> score
                                      |
                           valuable new/change only
                                      |
                                      v
             one event + triage skill + relevant TTP cards (<=32 KiB)
                                      |
                     fresh no-tool triage/planner process
                                      |
                         deterministic plan compiler
                             |                 |
                    manual-only plan     approved HTTP recipe
                             |                 |
                             +------> evidence + fresh critic
                                               |
                                   Discord + Grafana candidate
                                               |
                                  manual reproduction (mandatory)
                                               |
                               human platform submission (mandatory)
```

## Included components

- BBOT as the primary discovery engine, using only the v1 safe preset allow-list.
- Nuclei through a named, hash-approved, low-rate profile; disabled by default.
- GitHub discovery and Gitleaks history scanning. Candidate secrets are fully redacted and never exercised automatically.
- Shodan hostname searches filtered back to manifest scope.
- PostgreSQL-backed jobs with leases, retries, deduplication, schedules, and audit records.
- A redacted evidence volume with SHA-256 records, 90-day default expiry, and legal holds.
- Optional Codex and Claude Code workers using fresh, schema-bound, no-tool tasks.
- A provider-neutral scanner-finding triage skill with source-specific references,
  explicit false-positive dispositions, and no recon or target-discovery role.
- A separate planner and critic, with deterministic compilation between model prose and requests.
- A token-protected control API, a read-only Grafana dashboard, and redacted Discord alerts.
- Docker isolation: only scanner/LLM workers get egress; administration binds to loopback or Tailscale.

## Start here

1. Read [VPS deployment](docs/VPS-DEPLOYMENT.md).
2. Enroll a target with [Program onboarding](docs/PROGRAM-ONBOARDING.md).
3. Operate and review findings with [Operations and human gates](docs/OPERATIONS.md).
4. Understand the limits in [Threat model](docs/THREAT-MODEL.md).

The original architecture decision is preserved in [the final pipeline plan](docs/FINAL-PIPELINE-PLAN.md).

## Repository map

```text
bbpipeline/                 Python control plane and adapters
config/programs/            human-approved manifests
config/policies/            saved program-policy snapshots
config/nuclei/profiles/     hash-approved template profiles
methodology/ttp_cards/      small task-retrieved reasoning cards
skills/bug-bounty-review/   model-neutral scanner-finding triage methodology
schemas/                    strict planner/critic output contracts
docker/                     pinned worker/control images and init scripts
deploy/grafana/             read-only operational dashboard
scripts/                    deployment, auth, hashing, API, tests, backup
tests/                      policy and safety invariant tests
compose.yml                 VPS service topology
install.sh                  Debian 12/13 host bootstrap
```

Use this system only on assets for which the applicable program explicitly permits the chosen automation. Platform membership or a public hostname alone is not authorization.
