# Program onboarding and approval

Enrollment is the first mandatory human gate. The platform adapters remove most
scope transcription, but they do not turn platform membership into scan
authorization. The current platform policy—not a generated candidate,
methodology card, public report, scanner result, or model—is authoritative.

## 1. Discover and enroll a platform source

After populating the applicable root-only credential described in
[Platform scope synchronization](PLATFORM-SCOPE-SYNC.md), list the programs the
credential can access:

```bash
sudo ./scripts/platforms.sh discover hackerone
sudo ./scripts/platforms.sh discover intigriti
sudo ./scripts/platforms.sh discover yeswehack
sudo ./scripts/platforms.sh discover bugcrowd
```

Choose only the two to four pilot programs you intend to hunt. Enroll one by its
exact returned identifier and a local lowercase program ID:

```bash
sudo ./scripts/platforms.sh enroll hackerone acme-handle acme-h1
sudo ./scripts/platforms.sh enroll intigriti PROGRAM-UUID acme-it
sudo ./scripts/platforms.sh enroll yeswehack acme-slug acme-ywh
sudo ./scripts/platforms.sh enroll bugcrowd /engagements/acme acme-bc
```

This creates a small selector under `config/platform-sources/` and fetches a
pending candidate. It does not create an active program or authorize a scan.
Export the result for review:

```bash
sudo ./scripts/platforms.sh status
sudo ./scripts/platforms.sh export PLATFORM-PROGRAM_ID
```

The export appears under `config/candidates/<source-id>/`. Compare every scope
rule, wildcard, exclusion, unsupported asset, and automation restriction against
the live brief. Generated first-enrollment candidates disable all scanners and
contain no schedules. Existing programs retain their locally reviewed operational
limits, but any platform revision still pauses them until reapproval.

## 2. Review and save the policy

Join the public program through the platform. Confirm that automated scanning is permitted, then save a plain-text snapshot containing at least:

- exact in-scope assets and wildcard semantics;
- explicit exclusions and third-party/shared infrastructure rules;
- allowed/prohibited test classes and automation wording;
- rate/concurrency or timing limits;
- researcher email/header requirements;
- test-account and multi-account rules;
- denial-of-service, social engineering, data access, and cleanup restrictions;
- disclosure/reporting requirements and snapshot timestamp.

The generated policy JSON captures the platform response and normalization
decisions. Add any program text or restrictions that the platform API omitted,
or use a manually saved plain-text snapshot instead. Move the reviewed file into
`config/policies/`, then hash the exact saved bytes:

```bash
sudo ./scripts/config-hash.sh policy config/policies/<program-id>-policy.txt
```

The pipeline checks this file on every manifest sync. If it is missing or its hash changes, the program pauses.

## 3. Review the generated manifest

Move the candidate manifest into `config/programs/<program-id>.yml`. For a
platform-managed program, keep its `source` block unchanged: it binds the local
approval to the exact remote revision. A fully manual manifest remains supported
by copying `config/programs/example.yml.disabled`, but then scope drift cannot be
detected through this gate.

Edit every field. Key semantics:

- A `domain: "*.example.com"` rule does not include `example.com`; list the apex separately only when policy permits it. BBOT and Nuclei need a concrete seed, and seeding them with an unauthorized apex would put every request out of scope. An enabled scheduled BBOT/Nuclei job is therefore rejected at manifest-validation time unless scope contains a concrete domain, URL, or CIDR. Wildcard-only programs can schedule passive discovery, then enqueue explicit in-scope subdomains as scan targets.
- Exclusions always win.
- URL rules constrain scheme, host, port, and path prefix.
- CIDRs can explicitly authorize non-global targets, but only add them when the policy does.
- Repository patterns support exact `owner/name` or public organization expansion as `owner/*`.
- CIDR inputs are capped by `network.max_cidr_addresses` (256 by default); Nuclei expands and rechecks each address so nested exclusions still win.
- Keep rates at or below program limits. The v1 verifier only supports `GET`, `HEAD`, and `OPTIONS`.
- BBOT accepts only `subdomain-enum`, `web`, `spider`, and `web-screenshots` presets in v1.
- BBOT web presets and Nuclei require host-wide path permission. The manifest is rejected if they are enabled alongside denied/restricted paths because those third-party engines cannot provide the verifier's per-request path guard.
- Leave Nuclei disabled until a separate canary is reviewed.
- Leave `verification.auto_http: false` initially. Browser/login/state-changing work is always manual in v1.
- Start with `schedules: {}`.

If the program requires a contact header for all research traffic, define an opaque role:

```yaml
identity:
  required_header: X-Bug-Bounty
  default_account_role: public-researcher
  approved_account_roles: [public-researcher]
```

Then put the real value only in `/etc/bug-bounty-automation/secrets/researcher_headers.json`:

```json
{
  "your-program": {
    "public-researcher": {
      "X-Bug-Bounty": "researcher-alias@example.net"
    }
  }
}
```

The model sees only the opaque role. The last-mile verifier injects the real header. BBOT/Nuclei do not receive this header in v1, so do not enable those tools where the policy requires identification on every scanner request unless the program explicitly gives another acceptable identification mechanism.

## 4. Pin optional Nuclei policy

The starter profile runs only the one-request `tech-detect` template and is intended as a canary, not a vulnerability sweep. For useful checks, copy the profile and add only template IDs you have inspected at the pinned template version; avoid broad tag selections. Compute its hash:

```bash
sudo ./scripts/config-hash.sh profile config/nuclei/profiles/safe-observation.yml
```

Paste it into `nuclei.profile_hash`, update `enabled: true` only after review, and reapprove the manifest. Code, headless, fuzz/DAST, intrusive, DoS, brute-force, default-login, unsigned, and OAST/interactsh execution are blocked by the adapter. Only HTTP/SSL/DNS profiles are accepted by the schema.

## 5. Human approval hash

First set the policy snapshot hash and every final policy/scope value. Then compute:

```bash
sudo ./scripts/config-hash.sh manifest config/programs/<program-id>.yml
```

Review the manifest one final time, paste that value into `approval.approved_hash`, record yourself and the actual UTC approval time, then validate:

```bash
sudo docker compose run --rm --no-deps api validate-config
```

Approval metadata is excluded from the manifest hash, so pasting the hash does not change it. Any later material manifest edit does change it and pauses the program until a fresh review. Updating the saved policy requires a new policy hash and therefore a new manifest approval too.

## 6. Suggested pilot cadence

After manual canaries, introduce schedules slowly and stagger them across programs. Cron expressions run in UTC and receive deterministic jitter.

```yaml
schedules:
  shodan: "7 */12 * * *"
  github: "23 */6 * * *"
  bbot: "41 2 * * *"
```

Do not schedule Gitleaks for `owner/*`; the GitHub discovery job automatically queues exact public repositories. A global evidence-retention job is queued once per UTC day, independent of program schedules.

For a wildcard-only program, omit `bbot` and `nuclei` from this block. Schedule an applicable passive source such as Shodan (and GitHub only when repository scope is present), review the discovered assets, and enqueue an explicit authorized subdomain for BBOT/Nuclei. The validator fails closed instead of allowing an empty scheduled job to retry repeatedly.
