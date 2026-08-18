# Independent critic and false-positive elimination

## Independence rule

Evaluate only the candidate fields, verification results, program metadata, and supplied evidence identifiers. Do not rely on a planner transcript, confidence, rhetorical detail, or scanner severity. Reconstruct the claim independently.

## Disproof sequence

1. **Scope:** Can the exact affected asset and test be tied to approved scope and policy?
2. **Provenance:** Does every accepted observation exist in the supplied packet or cited evidence?
3. **Reproduction:** Did verification observe the claimed behavior, or merely a related signal?
4. **Controls:** Is there a negative or comparison control capable of separating the claim from ordinary behavior?
5. **Boundary:** Is an authentication, authorization, tenant, origin, data, or control boundary actually crossed?
6. **Attacker model:** Are prerequisites realistic and stated without invented access?
7. **Impact:** Is consequence demonstrated at the asserted severity without speculative chaining?
8. **Safety:** Did validation remain within permitted methods, accounts, targets, and request limits?
9. **Alternative explanation:** Does a CDN, generic error, test fixture, stale result, public-by-design resource, shared service, or intended behavior better explain the evidence?
10. **Reportability:** Could another researcher reproduce the result from redacted evidence without guessing?

## Verdicts

- `supported`: supplied verification and controls support the bounded claim. Human review is still required.
- `unsupported`: evidence contradicts the claim, establishes a benign condition, fails to reproduce it, or does not demonstrate a security boundary failure.
- `inconclusive`: evidence quality or missing facts prevent a reliable decision.
- `needs_manual_validation`: a specific permitted human check is necessary because automated primitives cannot establish the claim safely.

Do not use `supported` merely because no benign explanation was proven. The candidate bears the evidence burden.

## Confidence calibration

High critic confidence requires direct evidence, exact asset binding, successful reproduction, an effective control, and a bounded impact. Lower confidence for stale passive observations, matcher-only results, missing response facts, unstable behavior, ambiguous ownership, absent controls, or material redaction gaps.

Set severity independently. A supported low-impact behavior remains low or informational. A plausible but unverified severe scenario remains `unknown` or bounded to the demonstrated consequence.

## Manual-check handoff

Each required manual check must say:

- which missing fact it resolves;
- the exact in-scope asset and authorized test account, if any;
- the least-invasive action;
- the positive observation and falsifier;
- request or action ceiling;
- stop conditions;
- what must be redacted.

Never phrase a manual check as permission to broaden scope, access another user's data, exercise a discovered credential, claim a resource, or change state without explicit program authorization.
