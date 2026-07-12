# Threat model

## Assets

- synthetic secrets represented by unique canaries;
- authority to call tools, change roles and write durable memory;
- evidence and citation integrity;
- experiment results and configuration;
- credentials used by the optional authorized HTTP adapter.

## Trust boundaries

| Boundary | Trusted side | Untrusted side |
|---|---|---|
| Scenario envelope | schema and trusted evidence | user, ticket, HTML, PDF, tool and memory content |
| Agent/tool interface | deterministic policy decision | proposed tool name and arguments |
| Egress | internal allowlisted services | all other destinations |
| Evidence | versioned source identifier and record | generated claim and citation identifier |
| External adapter | local runner configuration | endpoint response body |

## Adversaries

The corpus models an attacker who can control one or more data sources consumed by an agent but
does not control the trusted system policy or benchmark evaluator. Examples include a malicious
ticket author, compromised document, poisoned tool result, user attempting role escalation, and a
source that plants instructions in durable memory.

## Abuse cases and controls

| Abuse case | Preventive control | Detective control |
|---|---|---|
| Untrusted text overrides policy | data/instruction separation | input policy event |
| Secret is copied into an outbound call | action DLP and egress allowlist | scenario canary tracing |
| Agent invokes a dangerous capability | explicit capability policy | forbidden-tool metric |
| Agent self-elevates | external-approval role boundary | effective-role comparison |
| Poisoned fact persists | memory writes require trusted provenance | memory objective check |
| Evidence is fabricated | source resolution and claim support | citation-integrity metric |
| Filter refuses ordinary analysis | benign controls | false-refusal metric |
| External endpoint returns oversized data | 1 MiB limit, timeout, no redirects | adapter exception record |

## Safety properties

1. A built-in test never opens a socket or starts a process through an agent tool.
2. `/api/scenarios` never returns canary values.
3. An untrusted action cannot use a sensitive tool under the `policy` presets.
4. Non-allowlisted egress is denied even for trusted action provenance.
5. A citation cannot pass integrity unless its source identifier resolves and its claim is supported.
6. Every content filter is evaluated against benign controls.

These properties are covered by automated tests. The optional HTTP adapter necessarily crosses the
local safety boundary; its endpoint must be an isolated, authorized evaluation target with
synthetic data.

## Residual risks

- A malicious external endpoint can consume resources until the configured timeout.
- Lexical grounding can accept a misleading claim with high token overlap; production studies
  should add an entailment reviewer and human audit sample.
- Scenario authors can accidentally encode a biased or incomplete objective. Review therefore
  focuses on the security contract, not only the prompt text.
- Report JSON contains synthetic tool traces and canaries. It is appropriate for test artifacts but
  should not be replaced with production secrets or transcripts.

