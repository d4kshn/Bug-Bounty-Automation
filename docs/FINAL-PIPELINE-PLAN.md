# Bug Bounty Automation Pipeline — v1 Plan

> Implementation status (2026-08-17): v1 is now implemented in this repository.
> The Python components were consolidated into the `bbpipeline/` package; deployment
> and operating instructions are in [README](../README.md),
> [VPS deployment](VPS-DEPLOYMENT.md), and [Operations](OPERATIONS.md).

## 1. Final decision

Build a policy-first control plane around BBOT rather than writing another reconnaissance framework. BBOT is the primary discovery engine; Nuclei is a constrained validation engine; Python services handle scope enforcement, scheduling, event normalization, evidence, LLM job routing, and reporting. PostgreSQL stores structured state, object storage or the local encrypted evidence volume stores artifacts, Grafana provides the dashboard, Discord carries alerts, and Tailscale is the only route to administrative interfaces.

The pipeline is intentionally not an autonomous exploit agent. It autonomously collects, correlates, prioritizes, and safely reproduces pre-approved checks. It asks an LLM to reason only when a deterministic signal is worth investigating. A human approves each program and submits each report, and manually validates every candidate finding.

For the first 30 days, run two or three public programs with the existing ChatGPT Plus/Codex and Claude Pro/Claude Code subscriptions. Do not buy API credits yet. Subscription-backed workers are opportunistic: if their allowance or authentication is unavailable, jobs wait in the queue and scanning continues. Add metered APIs in phase 2 only if the pilot demonstrates useful findings and the queue, latency, or unattended-auth friction justifies them.

## 2. Operating principles

1. The current program policy is the authority. Public reports, skills, templates, and LLM output never expand scope.
2. Deny by default. Every network action is checked immediately before execution, even if an earlier component approved it.
3. Reconnaissance is deterministic. LLMs neither invent targets nor receive unrestricted network, shell, browser, or credential access.
4. One job, one hypothesis, one fresh context. No persistent hunting conversation is carried between targets.
5. Store evidence, not model memory. Reproducible observations live in the evidence store and are cited by immutable IDs.
6. Separate observation, hypothesis, test plan, execution, criticism, and submission.
7. Passive and low-impact checks run first. Loud, authenticated, state-changing, or costly checks require explicit policy recipes and often a human.
8. A finding is not a report until a human reproduces it and accepts the scope, impact, and evidence.

## 3. Planned repository and deployment structure

The implementation phase should grow into this shape:

```text
.
├── install.sh                       # Debian VPS host bootstrap
├── compose.yml                      # pinned runtime services (implementation phase)
├── config/
│   ├── programs/                    # one reviewed scope manifest per program
│   ├── policies/                    # rate, method, port, path, and test constraints
│   ├── schedules/                   # per-program scan cadence
│   └── scoring/                     # event value and LLM trigger rules
├── control_plane/
│   ├── scope_compiler/              # policy snapshot -> executable allow-list
│   ├── scheduler/                   # queues bounded scan jobs
│   ├── authorization/               # last-mile scope/impact guard
│   ├── event_router/                # normalize, deduplicate, diff, score
│   ├── llm_router/                  # builds minimal context and selects a worker
│   ├── verifier/                    # executes approved deterministic recipes
│   ├── evidence/                    # immutable artifacts and retention
│   └── notifications/               # Discord and dashboard events
├── adapters/
│   ├── bbot/
│   ├── nuclei/
│   ├── github/
│   ├── shodan/
│   ├── codex/
│   └── claude/
├── methodology/
│   ├── ttp_cards/                   # small, versioned reasoning/test cards
│   ├── report_cards/                # normalized lessons from disclosed reports
│   └── evals/                       # labeled positive/negative test cases
├── schemas/                         # event, hypothesis, plan, critique, finding
├── dashboards/
├── tests/
└── docs/
```

Runtime state stays outside the repository:

```text
/etc/bug-bounty-automation/          # reviewed configuration and secrets
/var/lib/bug-bounty-automation/      # jobs, evidence, exports, backups
/var/log/bug-bounty-automation/      # service logs
/opt/bug-bounty-automation/          # immutable application releases
```

### v1 tool map

| Responsibility | v1 choice | Reason |
|---|---|---|
| Asset discovery and correlation | BBOT full container | Mature modular engine and a single event model; it already composes many common recon tools |
| Web probing/crawling | BBOT modules and their pinned container dependencies | Avoid a second orchestration layer around `subfinder`, `httpx`, `dnsx`, crawlers, and similar tools |
| Template checks | Nuclei, invoked only through named allow-listed profiles | Useful breadth without permitting an arbitrary template set or unbounded rate |
| Repository secret candidates | GitHub API plus Gitleaks in offline/no-verification mode | Detect candidates without exercising discovered credentials |
| External asset intelligence | Existing Shodan account; optional free sources after yield testing | Adds historical/external observations while keeping the policy manifest authoritative |
| Workflow and policy | Python control-plane containers | Straightforward schemas, policy tests, and provider adapters without adopting a second automation platform |
| Durable state and job queue | PostgreSQL | One backed-up data system is sufficient for the pilot; avoid Redis until throughput demonstrates a need |
| Evidence | Protected filesystem volume plus optional encrypted object-storage backup | Simple 90-day retention and explicit evidence IDs |
| Dashboard | Grafana querying PostgreSQL | Useful operational and finding views without building a custom frontend in v1 |
| Private administration | Tailscale | No public dashboard or management API |
| Reasoning workers | Codex and Claude Code adapters, then APIs if justified | Provider-independent packets/schemas and graceful subscription-worker downtime |
| Notifications | Discord webhook/bot with redaction | Matches the chosen workflow; dashboard remains the source of detail |

Do not add reconFTW in v1. Its coverage overlaps much of the selected engine and would add another scheduler, state model, and policy boundary. Benchmark it later as an isolated worker only if BBOT misses a demonstrated class of useful assets. Full authenticated browser automation is also deferred; v1 uses manually bootstrapped accounts and pre-approved HTTP recipes. A narrowly sandboxed browser worker can be evaluated in phase 2.

## 4. End-to-end flow

```text
Program policy snapshot
        |
        v
[G0 human enrollment approval]
        |
        v
Scope compiler -> signed/hashed scope manifest
        |
        v
Scheduler -> [G1 authorization] -> BBOT/passive APIs/repository checks
                                      |
                                      v
                         normalize + deduplicate + diff
                                      |
                                      v
                           [G2 signal-value gate]
                            |                 |
                      low value          valuable event
                    store/index only           |
                                               v
                              minimal immutable context packet
                                               |
                                               v
                                  [G3 LLM hypothesis gate]
                                               |
                                               v
                                [G4 safe-plan compiler]
                                               |
                                               v
                              deterministic bounded verifier
                                               |
                                               v
                               [G5 evidence + critic gate]
                                               |
                                  Discord + dashboard candidate
                                               |
                                               v
                                  human manual reproduction
                                               |
                                               v
                                  [G6 report-readiness gate]
                                               |
                                               v
                                   [G7 human submission]
```

### Collection lanes

- Web: BBOT for asset discovery and correlation, HTTP probing/crawling, technology and change signals, and carefully selected Nuclei templates.
- Repositories: GitHub organization/repository discovery, history and secret-candidate detection, dependency/configuration signals, and source-to-live-asset correlation. A secret candidate is never exercised automatically.
- Cloud: DNS, certificates, object-storage names, public cloud metadata, dangling-resource candidates, and exposed service configuration. Ownership and non-destructive proof rules are mandatory.
- External intelligence: the existing Shodan account supplements discovery. GitHub tokens support repository and organization metadata. These sources produce leads; they do not override the program allow-list.

## 5. Gates

| Gate | Purpose | Pass condition | Human involvement |
|---|---|---|---|
| G0 — Enrollment | Turn a platform policy into a local contract | In-scope assets, exclusions, allowed automation, rate limits, headers, researcher identity, test-account rules, and disclosure rules are captured; a human approves the snapshot hash | Mandatory when adding a program and whenever material policy/scope changes |
| G1 — Authorization | Prevent an unsafe request from leaving the system | Target, resolved IP/CNAME, port, method, path, headers, identity, test recipe, concurrency, and current program window all match the compiled manifest | None for pre-approved low-impact recipes; otherwise approval required |
| G2 — Signal value | Keep routine recon away from LLMs | A rule identifies a material delta or high-value signal and assigns enough confidence/value to spend a reasoning job | Threshold tuning during the pilot |
| G3 — Hypothesis | Convert evidence into a falsifiable security question | The model returns schema-valid trust boundary, prerequisites, expected/observed behavior, possible impact, test steps, stop conditions, and falsifiers, all tied to evidence IDs | Review only when the model flags an ambiguity or risky prerequisite |
| G4 — Safe-plan compiler | Make model proposals executable without trusting model prose | Every proposed step maps to a versioned, allow-listed test primitive with a request/time/rate/side-effect budget | Mandatory for new recipes and all state-changing or multi-user tests |
| G5 — Evidence and critique | Suppress false positives | A deterministic verifier reproduces the observation with a control; a fresh-context critic checks scope, alternative explanations, missing evidence, and impact | Candidate is sent to the hunter, who reproduces it manually |
| G6 — Report readiness | Produce a clean candidate report | Scope, eligibility, duplicate search notes, exact reproduction, impact, redaction, evidence, severity rationale, and cleanup status are complete | Human edits and accepts the report |
| G7 — Submission | Keep disclosure accountable | The hunter chooses the platform, final text, severity, and timing | Always mandatory; no automatic submission in v1 |

G0 and G7 are the two universal human gates. G4 and G5 add human involvement only when the recipe or evidence warrants it.

## 6. What is valuable enough for an LLM

An LLM job is created only for a bounded event such as:

- a newly exposed authenticated/API surface with a meaningful trust boundary;
- a material application, JavaScript bundle, endpoint, technology, or access-control delta;
- a repository secret/configuration candidate tied to an in-scope live asset;
- a likely cloud ownership, public-access, or dangling-resource condition;
- a high-confidence scanner observation that needs business-logic or exploitability reasoning;
- a cross-source correlation that deterministic rules cannot safely classify;
- a previously dismissed signal whose underlying evidence materially changed.

No LLM is called for unchanged assets, ordinary DNS discoveries, generic informational headers, routine tool health, raw crawl output, or low-confidence template noise.

### Minimal context contract

Each job starts a fresh, ephemeral model process and contains at most one program, one primary asset, and one hypothesis. A target ceiling of 32 KiB of textual context keeps jobs narrow; larger bodies are stored by evidence ID and only relevant excerpts are included.

The packet contains:

1. an exact task and JSON output schema;
2. the applicable policy excerpt, policy hash, and action constraints;
3. the event delta—not the complete scan history;
4. the smallest request/response, code, or metadata excerpts needed to reason;
5. the provider-neutral triage skill, one source/finding-family reference, and any
   small TTP cards relevant to this exact signal;
6. available test primitives, budgets, and explicit stop conditions;
7. immutable evidence IDs so conclusions can be audited.

It excludes unrelated targets, prior chats, broad recon dumps, credentials, cookies unless strictly required and scoped, and any permission to execute arbitrary commands.

Do not pre-feed researcher email addresses or account credentials to a model. Store them under the protected secrets path and refer to accounts in a packet by opaque role, such as `researcher_account_A` and `researcher_account_B`. The authorization/verifier layer—not the model—injects a platform-required contact header, cookie, token, or address immediately before an approved request. Even when account identity matters to access-control reasoning, the model normally needs roles and ownership relationships, not the real addresses.

### Model roles

- Triage/planner: classifies exactly one scanner event as a candidate, not a finding,
  inconclusive, or needing manual validation; only a candidate receives a bounded plan.
- Critic: receives the evidence and proposed finding in a separate fresh context, not the planner transcript. It tries to disprove scope, reproducibility, and impact.
- Reporter: is optional and runs only after verification. It formats existing facts; it cannot add facts or submit.

Codex and Claude adapters should implement the same schemas so either can take a queued job. Do not require both for every low-risk job. Use a second provider for high-value candidates or disagreement resolution.

## 7. Skill and public reports

The repository contains a provider-neutral skill at `skills/bug-bounty-review/`. It is
loaded explicitly into JSON packets, so both Claude and Codex use the same reasoning
contract without relying on either provider's native skill discovery. Its role begins
after a scanner emits a concrete event. It does not perform reconnaissance, discover
targets, conduct an open-ended code review, or hunt for adjacent vulnerabilities.

The core skill defines scope precedence, evidence states, falsification, dispositions,
safe validation planning, impact calibration, and independent criticism. The packet
loader adds only the relevant source/finding-family reference. Existing TTP cards remain
small overlays for specific signals; they do not authorize actions or expand the task.

Normalize disclosed public reports into compact, licensed evaluation cases rather than
putting a report corpus into every prompt or training model weights. Keep positive and
negative cases out of the methodology used to score them. Measure false-positive kill
rate, manual-confirmation rate, duplicate rate, cost per accepted candidate, and unsafe-
plan rejection rate.

The skill improves consistency, but deterministic scope and plan gates remain the safety
boundary. A prompt is never an authorization mechanism.

## 8. When the hunter jumps in

Human action is required for:

1. enrolling a program and approving a policy/scope hash;
2. creating researcher aliases, program-approved test accounts, and any CAPTCHA/2FA or initial authenticated session;
3. reviewing a material policy/scope diff before jobs resume;
4. approving any new test recipe, state-changing action, multi-account/tenant test, social interaction, cost-incurring cloud action, or potentially disruptive validation;
5. manually reproducing every candidate finding in a clean session and confirming cleanup;
6. resolving model disagreement or an ambiguous ownership/scope condition;
7. final duplicate review, report editing, severity choice, redaction, and submission;
8. refreshing subscription authentication or starting an optional LLM worker when a subscription session expires or reaches a usage cap.

The hunter can work in parallel from the same evidence/event dashboard. Manual notes and evidence should use the same IDs so agent and human work converge without sharing a long chat context.

## 9. Program safety profile

Each program manifest should include, at minimum:

```yaml
program_id: example
platform: hackerone
policy_url: https://example.invalid/policy
policy_snapshot_hash: sha256:...
approved_at: 2026-08-17T00:00:00Z
researcher_identity:
  required_header: null
scope:
  include: []
  exclude: []
network:
  allowed_ports: [80, 443]
  allowed_methods: [GET, HEAD, OPTIONS]
  requests_per_second: 1
  concurrency: 2
  nuclei_profiles: []
authentication:
  permitted: false
  accounts: []
forbidden:
  - denial_of_service
  - social_engineering
  - destructive_data_change
  - accessing_other_users_data
retention_days: 90
```

This example is deliberately restrictive. The compiler may only narrow a platform policy, never broaden it. Authenticated recipes, extra methods/ports, and higher rates are added per program after review.

## 10. Suggested schedules for the pilot

- Policy/scope snapshot check: every 6 hours; pause affected jobs on a material diff.
- Passive sources and certificates: every 6–12 hours.
- DNS/subdomain delta: daily.
- Live HTTP and lightweight technology checks: daily or every 48 hours, within program limits.
- Crawling and selected Nuclei templates: weekly initially, then tune per program.
- Repository delta: webhook/poll every 1–6 hours where allowed; full history scan only on enrollment and major changes.
- Evidence expiry: daily; delete unheld artifacts after 90 days and record the deletion event.
- Backups: encrypted daily database/config backup, with evidence storage handled according to sensitivity and cost.

Use jitter and per-program queues. Never let a global schedule accidentally concentrate traffic on one target.

## 11. Dashboard and notification behavior

Grafana should bind only to localhost or the VPS Tailscale address. Do not publish it on `0.0.0.0`. PostgreSQL, queues, evidence storage, and internal service APIs remain on a Docker-internal network with no host port.

Dashboard views:

- program policy health and paused programs;
- asset and endpoint deltas;
- queue depth and scan budgets;
- LLM trigger/accept/reject counts and subscription availability;
- candidates awaiting human validation;
- evidence age and retention status;
- tool health and last successful runs.

Discord receives concise events, never raw secrets or full response bodies: policy changed, scan failed repeatedly, valuable signal queued, candidate needs validation, and retention/backup failure. Each message links over Tailscale to the dashboard record.

## 12. Purchases and accounts

### Buy now

- One Debian 12 or 13 VPS. A sensible starting size is 8 vCPU, 16 GiB RAM, and 200–300 GiB NVMe. Downsize only after observing BBOT/crawler peaks; add worker VPSs instead of removing safety limits if several programs overlap.
- Optional encrypted object-storage backup if losing 90 days of evidence would be unacceptable. Keep it in the same legal/data-residency posture you choose for the VPS.

### Already sufficient for v1

- ChatGPT Plus with Codex access, used as an opportunistic authenticated worker.
- Claude Pro with Claude Code access, used the same way.
- Existing Shodan Developer subscription.
- A fine-grained GitHub token or GitHub App scoped to public metadata/repositories needed for the selected programs.
- Discord webhook or bot.
- Tailscale personal account for private administration.

### Obtain free keys only if a selected adapter needs them

- Censys, urlscan.io, and ProjectDiscovery Chaos/community services. Add one at a time and benchmark unique in-scope yield; more feeds are not automatically better.

### Defer to phase 2

- OpenAI API and Anthropic API billing. Purchase when unattended subscription auth, usage caps, queue latency, accounting, or schema/reliability requirements become a demonstrated bottleneck.
- SecurityTrails or other paid asset-intelligence feeds. Buy only after a four-week A/B comparison shows unique, actionable assets not supplied by BBOT, certificates, Shodan, and free sources.
- A second VPS/worker pool, managed PostgreSQL, and dedicated object storage. Add when two or three programs no longer fit the pilot host or operational isolation becomes valuable.
- Commercial vulnerability scanners. They are not required to validate the v1 architecture and may introduce noisy or policy-sensitive traffic.

Monthly chat subscriptions are not API entitlements. The control plane must therefore tolerate interactive login refresh, limits, and unavailable workers. When phase 2 starts, replace only the model adapter credentials/configuration; the evidence packet and schemas remain unchanged.

## 13. VPS installation and rollout

`install.sh` bootstraps a clean Debian VPS with official Docker Engine/Compose and Tailscale repositories, creates a non-login service account and protected directories, and performs version/daemon checks. It does not install tools on the development machine, start a scan, open a firewall port, run `tailscale up`, add a person to the root-equivalent `docker` group, or deploy unfinished services.

On the future VPS:

```bash
sudo bash ./install.sh --dry-run
sudo bash ./install.sh
sudo tailscale up
```

The implementation phase will add a pinned `compose.yml`. Re-running the installer will validate it if present; `--pull-images` will also fetch the pinned images but will not start them. Pin images by digest after testing, including the BBOT full image and Nuclei version. Never deploy mutable `latest` tags.

Deployment order:

1. Bootstrap the host and join Tailscale.
2. Deploy the database/evidence/control-plane services with no public ports.
3. Load one program manifest and run policy/scope unit tests.
4. Run passive collection only and inspect deltas.
5. Enable bounded active web checks and selected Nuclei profiles.
6. Enable one subscription-backed LLM worker for valuable events.
7. Add the independent critic after collecting a baseline of false positives.
8. Complete the 30-day/two-to-three-program pilot and decide whether API billing is justified.

## 14. Acceptance criteria for v1

- An out-of-scope target cannot reach a scanner or verifier, including after DNS resolution changes.
- A program policy change pauses affected work until the hash is reviewed.
- Unchanged routine recon generates no LLM job.
- Every LLM conclusion cites evidence IDs and a schema-valid falsifiable hypothesis.
- Model text cannot create a raw shell/network action; only allow-listed primitives execute.
- Candidate findings have a deterministic reproduction and negative/control result or are explicitly marked incomplete.
- Dashboard and internal services are unreachable from the public Internet.
- Discord contains no credentials, raw secrets, or sensitive full bodies.
- Subscription worker outage does not stop recon or lose jobs.
- Every submitted report was manually reproduced and explicitly submitted by the hunter.
- Evidence expires after 90 days unless placed on a documented hold.

## 15. Primary references

- BBOT documentation and container usage: <https://www.blacklanternsecurity.com/bbot/Dev/>
- BBOT releases: <https://github.com/blacklanternsecurity/bbot/releases>
- Nuclei documentation: <https://docs.projectdiscovery.io/tools/nuclei/overview>
- Docker Engine on Debian: <https://docs.docker.com/engine/install/debian/>
- Docker Compose plugin: <https://docs.docker.com/compose/install/linux/>
- Tailscale on Linux: <https://tailscale.com/docs/install/linux>
- Codex authentication: <https://developers.openai.com/codex/auth>
- Codex non-interactive operation: <https://developers.openai.com/codex/noninteractive>
- Claude Code with Pro/Max: <https://support.claude.com/en/articles/11145838-use-claude-code-with-your-pro-or-max-plan>
- OWASP Web Security Testing Guide: <https://owasp.org/www-project-web-security-testing-guide/>
- PortSwigger Web Security Academy: <https://portswigger.net/web-security>
