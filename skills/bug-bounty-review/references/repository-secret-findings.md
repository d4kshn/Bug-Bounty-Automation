# Repository and secret scanner findings

## Repository-event boundary

Do not turn a discovered repository into an LLM code-audit task. This skill reviews only a concrete normalized signal already emitted by a scanner, such as a Gitleaks candidate. Do not search additional files, commits, branches, organizations, forks, packages, contributors, CI systems, deployments, or linked infrastructure.

## Secret-candidate ledger

Establish from supplied fields:

- exact in-scope repository;
- commit, file, and line location;
- detector rule and description;
- redacted fingerprint or stable identifier;
- public reachability and timestamp if known;
- surrounding context already included in evidence;
- apparent provider and intended environment, if directly stated;
- whether the value appears complete or is a placeholder, fixture, example, checksum, public identifier, or generated test string.

Do not reconstruct a redacted value. Do not request the full value in an LLM packet.

## Classification

Use `not_a_finding` when supplied context clearly establishes a documented example, inert fixture, placeholder, public identifier, invalid format, or target-unrelated artifact. Use `inconclusive` when context is insufficient to distinguish those conditions.

Use `needs_manual_validation` when the candidate appears plausibly real and target-owned but validity, privileges, or exposure impact cannot be established safely from static evidence. Pattern shape alone cannot justify `candidate` with demonstrated high impact.

## Validation boundary

Never authenticate with, transmit, redeem, rotate, revoke, enumerate, or otherwise exercise a discovered secret. Never test cloud credentials, API tokens, private keys, session material, signing secrets, database strings, or webhook URLs automatically.

A human may use a provider-documented, non-destructive validation method only when the program explicitly permits it. The handoff must identify the provider-specific risk, stop conditions, and the minimum fact needed; it must not include the secret itself.

## Impact and reporting

Distinguish:

- Public exposure of a secret-shaped value
- Confirmed validity
- Confirmed target ownership
- Demonstrated permissions
- Demonstrated access to sensitive target data or operations

Do not infer later stages from earlier ones. Report evidence should identify repository, commit, path, line, detector rule, redacted fingerprint, scope lineage, and human validation notes when authorized. Avoid copying secret material into reports, logs, Discord, or LLM outputs.
