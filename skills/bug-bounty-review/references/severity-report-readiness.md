# Severity and report readiness

## Severity discipline

Use program-specific severity rules when supplied. Otherwise assess the demonstrated security consequence and prerequisites; do not treat a generic taxonomy as a substitute for program policy.

Consider:

- affected confidentiality, integrity, authorization, or availability;
- sensitivity and quantity actually shown;
- actor privileges and user interaction required;
- tenant, account, or asset reach actually demonstrated;
- repeatability and reliability;
- whether controls rule out intended behavior;
- environmental and business context present in evidence.

Keep severity `unknown` when validation has not established a security boundary failure. Use `info` for useful security observations without demonstrated exploitable impact. Avoid hypothetical escalation such as assuming an exposed service has default credentials, a secret has broad permissions, a version is exploitable, or a single-object issue applies tenant-wide.

## Confidence is not severity

Confidence describes evidence quality. Severity describes demonstrated consequence. A high-confidence minor exposure can be low severity; a potentially critical but unverified chain should have low confidence and unknown or evidence-bounded severity.

## Duplicate and eligibility caveat

The LLM packet does not contain a platform's private duplicate database and may not contain current program exclusions. Never claim uniqueness or bounty eligibility. Require the human reviewer to check the live policy, known issues, prior submissions, and platform state before submission.

## Report-readiness gate

A candidate is ready for human report review only when it contains:

- a concise title naming the actual boundary failure;
- exact in-scope asset and affected component;
- prerequisites and attacker role;
- numbered, reproducible steps that were actually performed;
- expected versus actual behavior;
- a negative or comparison control where meaningful;
- minimal redacted evidence with stable identifiers and timestamps;
- impact no broader than demonstrated;
- proposed severity with rationale and uncertainty;
- policy, scope, and safety notes;
- known benign explanations and why evidence rejects them;
- no secrets, session material, personal data, or unnecessary sensitive content.

Do not convert planned validation steps into reproduction steps. Do not describe an inferred result as observed. The final submit action remains manual.
