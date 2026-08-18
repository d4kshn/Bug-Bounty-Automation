# Scanner signal triage

## Universal checks

Interpret scanner output as a measurement with failure modes. Before accepting its label, ask:

1. What exact value was measured?
2. Which matcher, rule, module, or correlation produced the label?
3. Is the event first-hand or derived from another observation?
4. Is the asset exact and in scope?
5. Is the timestamp sufficiently recent?
6. Could a CDN, wildcard DNS, generic error page, sinkhole, honeypot, shared service, redirect, or cached response explain it?
7. What smallest control would distinguish the security claim from those explanations?

Scanner confidence is input quality metadata, not confidence that a bounty-eligible vulnerability exists. Scanner severity is a prioritization hint, not demonstrated business impact.

## BBOT events

Use `event_type`, `module`, `tags`, `scope_distance`, `resolved_hosts`, and structured `details` to identify what was actually observed. BBOT commonly emits inventory and correlation events. A URL, DNS name, technology, open port, or HTTP response is normally reconnaissance output, not a finding.

Accept a security candidate only when the event contains a specific security-relevant behavior or exposure. Do not use a BBOT event as permission to explore the discovered asset beyond the supplied validation target.

Treat module names and tags as scanner assertions. Check wildcard DNS, duplicated endpoints, redirects, shared IPs, and generic responses as likely false-positive families.

## Nuclei events

Use `template_id`, template name, tags, matcher name, protocol type, and exact matched asset. A template match establishes only that its matcher condition succeeded. It does not automatically establish the template title, severity, exploitability, authorization bypass, data sensitivity, software version, or business impact.

Prefer validation that observes the same narrow condition and a benign negative control. Account for weak word matchers, status-only matchers, generic fingerprints, stale version banners, error pages, intermediary headers, and unauthenticated pages intentionally exposed.

Do not reconstruct or execute an unknown template payload from its identifier. If the packet omits the request/response fact required to interpret a match, choose `inconclusive` or `needs_manual_validation`.

## Gitleaks events

A rule hit establishes that text matched a secret-detection rule at a repository location. It does not establish that the value is complete, live, privileged, target-owned, non-test, or accepted by a provider. Preserve redaction and use repository context rather than the secret value.

Never validate a secret automatically. Do not authenticate, query account metadata, enumerate permissions, incur cost, or send the value to an endpoint. Route any program-permitted validation to a human.

## Shodan events

A Shodan result establishes historical third-party observation of a service associated with reported hostnames and an IP/port. It can be stale or affected by shared hosting, reassignment, proxying, or incomplete attribution. An open service is not itself a vulnerability.

Require current ownership and exact scope linkage before treating it as a candidate. Require evidence of an unintended exposure or unsafe capability; a product name, version banner, or uncommon port alone is inventory.

## GitHub repository events

A repository discovery event establishes inventory and selected public metadata. It is not a vulnerability and must not trigger an LLM code review or broader repository search. Only a later scanner event containing a concrete security signal should enter finding triage.
