# Web and API scanner findings

## Claim boundaries

Bind the hypothesis to the exact URL, method-independent observation, or scanner matcher that was supplied. Do not crawl, fuzz, mutate parameters, enumerate objects, follow redirects to another origin, or infer neighboring endpoints.

Distinguish these commonly conflated states:

- Reachable versus unintentionally exposed
- Authenticated versus authorized
- Identifier visible versus object accessible to the wrong actor
- Header absent versus exploitable browser behavior
- Version disclosed versus a vulnerable version actually running
- Error response versus sensitive information disclosure
- Cross-origin header present versus a browser-readable sensitive response
- Cached response versus private data served across users
- DNS/TLS mismatch versus an exploitable trust failure

## Minimum evidence by claim family

### Sensitive exposure or debug artifact

Require exact path, response status, content type, a small redacted excerpt or reliable structured fact, and why the content is sensitive. Compare with a nonexistent or ordinary path to rule out a generic response. A suggestive filename or `200` status is insufficient.

### Authentication or session boundary

Require the expected identity state, actual identity state, protected operation, and a comparison showing the boundary was crossed. Token decoding, cookie presence, login-page behavior, or a redirect alone is not a bypass. Browser flows, token exchanges, and authenticated checks are manual unless explicitly provisioned and permitted.

### Authorization or object access

Require actor, role, tenant or ownership, object, operation, and expected authorization. A proper control normally needs approved test accounts and objects owned by those accounts. Never test against a real user's object. Route cross-account or stateful validation to a human.

### Security header or TLS configuration

Require an affected security property and practical consequence in the supplied context. Missing hardening headers, deprecated compatibility, certificate metadata, and banners often merit informational classification unless evidence demonstrates a usable attack condition.

### CORS or cross-origin behavior

Require that an attacker-controlled origin can cause a browser to expose sensitive, authorized response data under realistic credential behavior. A reflected origin or wildcard header without sensitive readable data does not prove impact. Browser validation is manual.

### Redirect behavior

Require attacker control over a destination and a relevant security consequence. Do not follow the redirect automatically, especially across origins. Query-dependent validation is manual in this pipeline.

## Minimal safe controls

When the manifest permits automatic verification, restrict it to the exact asset and plain path using GET, HEAD, or OPTIONS within the packet's request ceiling. Suitable controls include an adjacent nonexistent path on the same origin, repetition of the exact read-only observation, or a no-credential request when no credentials are present.

Do not claim a control was performed merely because it is listed in a plan. Record it as a required step until verification evidence exists.

## Automatic stop conditions

Stop and require a human when validation needs a query string, request body, non-approved method, login or browser state, redirect following, WebSocket interaction, file upload, object mutation, account comparison, rate-limit probing, password reset, invitation flow, payment, messaging, or any action involving another person or tenant.
