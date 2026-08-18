# Threat model and v1 limits

## Protected assets

The system protects program scope/authorization, researcher identity headers and test sessions, API/provider tokens, target evidence, unpublished findings, LLM authentication, and the reputation/availability of target systems.

## Trust boundaries

- Manifests and policy snapshots are trusted only after a human hash approval.
- Scanner output, target content, repository content, public reports, methodology cards, and LLM output are untrusted data.
- The planner and critic are advisory. Pydantic/JSON schemas and the deterministic plan compiler enforce structure and action limits.
- Only the scanner and LLM networks have outbound connectivity. The API, scheduler, database, and Grafana stay on an internal network; only API/Grafana have private host binds.
- Scanner and LLM workers do not share provider credentials. Models never receive GitHub, Shodan, Discord, or researcher-header secrets.

## Enforced safety properties

- Exclusions override inclusions; active HTTP targets are resolved and non-global addresses are denied unless explicitly approved by CIDR.
- Automatic verifier requests are limited to GET/HEAD/OPTIONS, an allow-listed role, path/port/rate policy, a small request budget, no redirects, no environment proxy, and a fresh last-mile authorization check.
- BBOT accepts only reviewed presets. Nuclei accepts only a hash-pinned profile and blocks code, headless, fuzz/DAST, intrusive, DoS, brute-force/default-login, unsigned, and OAST behavior.
- Gitleaks clones exact approved public GitHub repositories without embedding the GitHub token and never validates detected credentials.
- Raw tool artifacts and normalized events are redacted before durable storage; Discord gets only short redacted metadata.
- Administrative ports cannot pass preflight when bound to all interfaces.
- Container root filesystems are read-only where practical, Linux capabilities are dropped, privileges cannot be gained, resources/PIDs are limited, and logs rotate.

## Important residual risks

1. BBOT and Nuclei are third-party engines. Their internal requests cannot be reauthorized one-by-one by this Python process; safety relies on job-level target/blacklist checks, safe preset/profile selection, rate limits, container isolation, and program permission. Review module/template behavior before every upgrade.
2. DNS can change after a preflight check. The deterministic HTTP verifier resolves immediately before each request, but third-party scanners manage their own later connections. Avoid ambiguous/shared/internal targets and stop on ownership uncertainty.
3. A malicious target can poison scanner text. Packets label target data as untrusted, minimize it, redact it, and give models no tools, but model output can still be wrong. The compiler and human review remain mandatory boundaries.
4. Pattern redaction is not a proof that arbitrary sensitive data is absent. Keep evidence private, minimize collection, and manually inspect artifacts before sharing them.
5. Docker port publishing can bypass some host firewall expectations. Bind only to loopback/Tailscale and verify from an external network that ports 3000/8080 are unreachable.
6. Consumer subscription CLI sessions can expire, hit quotas, or become unsuitable for unattended use. Workers fail/retry without broadening permissions; move to metered APIs only after reviewing terms and operational need. `llm-check` verifies a worker's credential through the production adapter before it is relied on. On a subscription login the Claude worker cannot use `--bare`, so it uses `--safe-mode` to preserve authentication while disabling customizations, backed by explicit no-tools, no-MCP, no-skills, and single-turn restrictions. Managed policy can still apply under safe mode; treat the worker's config volume and host policy as trusted inputs.
7. PostgreSQL schema creation is v1-only and does not include migration tooling. Before code upgrades, back up and test against a cloned database.
8. Cancellation is not process preemption. Stop the scanner service for an immediate emergency halt.
9. Public program policy pages are not fetched automatically. You must refresh the saved snapshot and reapprove scope when the platform announces or displays a change.

## Explicitly out of scope for v1

- automatic bounty-platform enrollment or report submission;
- automatic use/verification of discovered credentials or secret candidates;
- browser automation, CAPTCHA/2FA, login/session bootstrap, or token exchange;
- state-changing, destructive, denial-of-service, social, payment, cloud-provisioning, resource-claiming, or real-user tests;
- arbitrary shell commands, arbitrary Nuclei templates, arbitrary BBOT modules, model-selected targets, or model network access;
- a public dashboard/API, public reverse proxy, or direct database exposure;
- model fine-tuning on reports. TTP cards are small retrieval aids, not an authorization source.

When a program needs a capability outside these boundaries, handle it manually or add a narrow, versioned recipe with tests, a policy field, and a fresh approval hash. Do not weaken a global guard for one program.
