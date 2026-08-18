# VPS deployment

## Baseline

The installer supports Debian 12 and 13. The checked-in defaults target your
4-vCPU, 8-GiB RAM, 100-GB pilot VPS: one serialized scanner lane is capped at
2 CPUs/3 GiB, PostgreSQL at 1 GiB, each LLM worker at 1 GiB, and the remaining
control/dashboard services have smaller ceilings. Two to four programs are
practical when schedules are staggered; this is not capacity for overlapping
active scanner containers or broad unbounded scans.

The host installer installs Docker Engine/Compose and Tailscale from their official repositories, creates protected directories, and validates Compose. It does not start the stack, start a scan, authenticate a service, alter firewall rules, or add a human user to the Docker group.

## 1. Bootstrap the host

Run these commands from the cloned repository:

```bash
sudo ./install.sh
cp .env.example .env
sudo ./scripts/bootstrap-secrets.sh
```

Join your tailnet explicitly:

```bash
sudo tailscale up
tailscale ip -4
```

Keep `API_BIND` and `DASHBOARD_BIND` as `127.0.0.1`, or replace them in `.env` with that exact Tailscale IPv4 address. The preflight rejects `0.0.0.0` and `::`. PostgreSQL has no host port.

All deployment scripts should be run with `sudo` unless your operating model deliberately grants Docker and secret-file access to another administrator. Membership in the `docker` group is root-equivalent and the installer does not grant it.

## 2. Populate integrations

Edit these root-only files under `/etc/bug-bounty-automation/secrets/`:

- `discord_webhook`: one Discord webhook URL; optional but recommended.
- `github_token`: a fine-grained token with read-only access to public repository metadata/content needed for the chosen programs. Do not grant write scope.
- `shodan_api_key`: the existing Shodan API key.
- `researcher_headers.json`: verifier-only contact headers or approved test-session headers, described in program onboarding.
- `hackerone_api_token`: HackerOne Hacker API token for researcher username `d4kshn`.
- `intigriti_api_token`: Intigriti Researcher API bearer token.
- `yeswehack_access_token`: OAuth access token for an approved YesWeHack Apps API application.
- `bugcrowd_session_cookie`: the current `_bugcrowd_session` value or complete Cookie header used only by the pinned BBscope adapter.
- `anthropic_api_key` / `openai_api_key`: optional. Leave empty to use the subscription logins from step 4. Populate one to move that worker to metered API billing; see step 4 for how the choice changes sandboxing.

Leave unused platform files empty. The generated database, Grafana, and API
credentials are ready without editing. Never put secret values in `.env`,
manifests, model packets, Discord, shell command arguments, or Git. See
[Platform scope synchronization](PLATFORM-SCOPE-SYNC.md) for expiry and renewal.

## 3. Validate and build

```bash
sudo ./scripts/preflight.sh
sudo ./scripts/test.sh
sudo ./scripts/preflight.sh --build
```

The test command builds an isolated test image and uses only SQLite under a temporary container filesystem. It performs no target network calls. `preflight --build` downloads and builds images but starts no service or scan. The scanner image verifies release checksums for Nuclei/Gitleaks, builds BBscope from an exact commit, and fails its build if Gitleaks cannot detect a synthetic fake token.

No Go or security scanner is installed on the host. Docker build stages contain
Go, and the final scanner image contains BBOT, Nuclei, Gitleaks, BBscope, and the
cookie helper. The application/LLM tools remain isolated in their own images.

After the first successful pilot build, replace mutable image tags in `.env` with reviewed `tag@sha256:digest` references where the registry supports them. Treat tool/template upgrades like code changes: read release notes, build, run tests, perform one manually reviewed canary, then roll forward.

## 4. Authenticate optional subscription workers

The two LLM workers are an optional Compose profile. Their credentials live in separate Docker volumes and are never mounted into the scanner.

```bash
sudo ./scripts/login-llms.sh codex
sudo ./scripts/login-llms.sh claude
```

Each command opens the provider's supported login flow. Re-run it when a session expires. Confirm that your current plan and provider terms permit the CLI usage pattern. The pipeline continues collecting/scoring if a worker is offline; its queue waits.

These flows store a subscription OAuth session in each worker's config volume.

Each worker chooses its credential automatically. Leaving `anthropic_api_key` and `openai_api_key` empty uses the subscription login above. Writing a key into either file switches that worker to metered API authentication on its next job, with no other configuration change.

The choice affects sandboxing for Claude. Claude Code's `--bare` flag skips hooks, plugins, skills, MCP servers, auto-memory, and `CLAUDE.md` discovery, but it authenticates *only* through `ANTHROPIC_API_KEY` and never reads an OAuth session. The adapter therefore uses `--bare` when a key is configured. With subscription OAuth it uses `--safe-mode`, which disables customizations while keeping authentication available. Both paths also receive explicit no-tools, no-MCP, no-skills, and single-turn restrictions as defense in depth.

Verify each worker before relying on it. This runs a real task through the production adapter — same flags, environment, and output parsing as a live job — so an expired login, a missing binary, or a rejected schema surfaces now instead of on your first finding:

```bash
sudo docker compose --profile llm run --rm --no-deps codex-worker llm-check --provider codex
sudo docker compose --profile llm run --rm --no-deps claude-worker llm-check --provider claude
```

Each prints the credential actually in use and exits non-zero on failure:

```json
{"provider": "claude", "auth_mode": "subscription_oauth", "authenticated": true,
 "output": {"ok": true, "note": "..."}}
```

`"Not logged in · Please run /login"` means the session did not persist; re-run the login command above. `"401 API key is invalid"` means the key file is wrong.

The adapters start one fresh process per task. Codex runs ephemeral and read-only with repository/user instructions ignored; Claude receives no tools or MCP access and one turn. Both must return the repository's strict JSON schema.

## 5. Select programs, review candidates, then start

Use `scripts/platforms.sh discover` and `enroll` as described in
[Program onboarding](PROGRAM-ONBOARDING.md). Select only two to four initial
programs, export their candidates, compare each with the live brief, and approve
the final manifest. With no approved `.yml` manifest, the stack is intentionally
idle.

```bash
sudo ./scripts/start.sh --with-llm
sudo docker compose logs --tail=100 api scheduler scanner
```

Dashboard: `http://<DASHBOARD_BIND>:<GRAFANA_PORT>`

API health: `http://<API_BIND>:<API_PORT>/healthz`

Do not expose either through a public reverse proxy. Use a local SSH tunnel if keeping loopback binds:

```bash
ssh -L 3000:127.0.0.1:3000 -L 8080:127.0.0.1:8080 user@vps
```

## 6. First canary

Start with one program, no schedules, Nuclei disabled, and automatic verification disabled. Enqueue a single BBOT or passive-source job and inspect all outputs before expanding:

```bash
sudo ./scripts/api.sh /api/v1/jobs \
  -X POST \
  --data '{"program_id":"your-program","kind":"bbot","targets":["example.com"]}' | jq
```

Only add a staggered UTC cron after the canary is compliant and useful. Example: `bbot: "17 3 * * *"`. A deterministic per-program jitter of up to 300 seconds is applied by default. Scheduled BBOT and Nuclei runs require a concrete in-scope domain, URL, or CIDR because the scheduler does not invent targets; a wildcard-only manifest may still schedule passive discovery and may enqueue later scans with explicit discovered subdomains.

For two to four programs, place active BBOT/Nuclei windows on different UTC
hours, keep each manifest's concurrency at 1–2 and initial target cap near 25,
and avoid full-history repository scans during web scans. The single scanner
worker guarantees these jobs do not execute concurrently. Watch `docker stats`,
disk use, job age, and PostgreSQL/evidence growth for the first month. If queues
remain delayed, add a worker VPS; do not increase target concurrency on this host.

## Purchases

Buy only the VPS now. Optional encrypted off-host backup storage is worthwhile if losing the 30-day evidence window is unacceptable. Existing ChatGPT Plus/Codex, Claude Pro/Claude Code, Shodan Developer, GitHub, Discord, and Tailscale accounts are enough for the pilot.

Defer OpenAI/Anthropic API billing, paid asset feeds, managed PostgreSQL, a second worker VPS, and commercial scanners until a 30-day/two-to-three-program pilot demonstrates a real queue, reliability, or unique-yield bottleneck.
