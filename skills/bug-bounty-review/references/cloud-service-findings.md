# Cloud, DNS, and exposed-service findings

## Observation classes

Keep these states separate:

- A service was historically observed
- A service is currently reachable
- A banner or provider signature matches
- A resource is publicly readable
- A resource permits listing
- A resource is publicly writable
- A name points to an unbound provider resource
- The resource can be claimed
- The asset is owned by and eligible for the target program

One state does not prove the next.

## Shodan and exposed services

Treat IP, port, hostname, product, version, organization, and timestamp as discovery metadata. Check freshness and attribution before security meaning. Shared infrastructure, reverse proxies, CDNs, reassigned IPs, honeypots, and provider-managed services can invalidate ownership assumptions.

An administrative product, database port, development banner, or old version string is not enough. Require a supplied observation of unintended public access or a narrowly defined manual check. Do not attempt login, default credentials, protocol negotiation beyond approved primitives, enumeration, or version-specific exploitation.

## Cloud storage and service endpoints

Separate metadata visibility, public object readability, listing, and write capability. A public object can be intentional; its sensitivity and program eligibility must be demonstrated. Do not bulk-download, enumerate keys, upload, overwrite, delete, change permissions, invoke workloads, or generate cost.

If the exact read-only URL and observation are supplied, a bounded GET or HEAD may be proposed only when the manifest permits it. Anything requiring provider credentials, SDK operations, signed requests, listings, or mutation is manual.

## DNS and dangling-resource signals

Record the complete supplied DNS chain, provider error signature, timestamps, and scope link. Wildcard DNS, temporary provider errors, parking pages, stale passive data, and custom-domain misconfiguration are common benign explanations.

Do not claim, register, attach, or provision a resource to prove takeover. Treat apparent claimability as `needs_manual_validation` unless existing non-destructive evidence is sufficient under the program policy.

## Impact

Base impact on what an unauthorized actor can demonstrably read, alter, impersonate, or control. Do not elevate severity from provider brand, service category, port number, product version, or hypothetical resource contents. Route tenant ambiguity, third-party ownership, or shared-infrastructure questions to human scope review.
