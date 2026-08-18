# Platform scope synchronization

Platform synchronization is a read-only enrollment and drift-detection layer. It
does not scan targets, accept invitations, change a platform program, submit a
report, or automatically approve generated YAML.

## Supported sources

| Platform | Interface | Credential | Imported data |
|---|---|---|---|
| HackerOne | Hacker API v1 | API token with Basic auth; username is `d4kshn` by default | accessible program metadata, policy, structured scopes, submission/bounty eligibility, and scope exclusions |
| Intigriti | Researcher API v1 | researcher bearer token | program status, domain endpoints, tiers, rules of engagement, and explicit automated-tooling/user-agent requirements |
| YesWeHack | Apps API | OAuth access token | hunter access, current program detail/rules, scopes, and textual exclusions |
| Bugcrowd | pinned BBscope commit | authenticated Bugcrowd session cookie | accessible program handles and in/out-of-scope target groups |

The Bugcrowd official API uses `Authorization: Token`, not OAuth, and its
resources depend on the account role. This pipeline intentionally uses the
researcher session cookie only through the pinned BBscope extraction code. The
cookie is read from a file by a small helper; it never appears in process
arguments, YAML, job payloads, Discord, or Git.

## Credential setup

Run `sudo ./scripts/bootstrap-secrets.sh`, then populate only the integrations
you use with `sudoedit`:

```text
/etc/bug-bounty-automation/secrets/hackerone_api_token
/etc/bug-bounty-automation/secrets/intigriti_api_token
/etc/bug-bounty-automation/secrets/yeswehack_access_token
/etc/bug-bounty-automation/secrets/bugcrowd_session_cookie
```

The Bugcrowd file may contain only the `_bugcrowd_session` value or a complete
Cookie header. Do not pass it on a command line or paste it into chat. Session
cookies and YesWeHack access tokens expire; replace their files and run a manual
sync after renewal. YesWeHack Apps API access requires approval from YesWeHack,
an OAuth application, and its authorization-code flow. The v1 pipeline consumes
the resulting access token but does not host an OAuth callback or persist refresh
tokens.

`BB_RESEARCHER_HANDLE=d4kshn` is the default HackerOne API username. Change it in
`.env` only if your platform identity changes.

## State machine and gates

```text
selected remote program
        |
        v
read-only authenticated fetch
        |
        v
canonical snapshot + conservative normalization
        |
        +---- unsupported/ambiguous asset ---> manual review marker
        |
        v
pending candidate in PostgreSQL ----> Discord + Grafana
        |
        v
human compares live brief, edits limits, saves policy, hashes manifest
        |
        v
approved manifest revision == latest remote revision
        |
        v
program may become active
```

The scheduler checks each enabled source every six hours by default. A changed
canonical revision immediately pauses only that program and produces a new
candidate. An explicitly rejected/expired credential also pauses immediately.
Transient transport failures preserve the last good decision for at most
`BB_PLATFORM_SOURCE_MAX_STALE_SECONDS` (24 hours by default); after that the
program fails closed. One malformed source selector does not stop other programs.

The normalizer accepts only representations the policy engine can enforce:
plain/wildcard domains, plain HTTP(S) URL prefixes, CIDR/IP values, exact GitHub
repositories, and recognizable cloud identifiers. It never turns HackerOne's
`open_scope` into a scanner wildcard, never treats a reward exclusion as a target
exclusion, and leaves ambiguous wildcard URLs/mobile/hardware/free-form entries
in `unsupported` for human handling.

## Commands

```bash
sudo ./scripts/platforms.sh discover PLATFORM
sudo ./scripts/platforms.sh enroll PLATFORM REMOTE PROGRAM_ID [SOURCE_ID]
sudo ./scripts/platforms.sh sync [SOURCE_ID]
sudo ./scripts/platforms.sh status
sudo ./scripts/platforms.sh export SOURCE_ID
sudo ./scripts/api.sh /api/v1/platform-sources | jq
```

Export refuses to overwrite an existing review directory. Promotion into
`config/programs/` and `config/policies/`, policy hashing, final manifest hashing,
and approval remain explicit human actions.

Primary interface references: [HackerOne Hacker API](https://api.hackerone.com/getting-started-hacker-api/),
[Intigriti Researcher API](https://api.intigriti.com/external/researcher/swagger/index.html),
[YesWeHack Apps API](https://apps.yeswehack.com/doc), and
[BBscope](https://github.com/sw33tLie/bbscope).
