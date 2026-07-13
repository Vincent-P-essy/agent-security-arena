# Threat model

## Assets

- synthetic secrets represented by unique scenario canaries;
- authority to invoke tools, change roles and write evaluation memory;
- trusted evidence and citation integrity;
- evaluation configuration, raw traces and reported metrics;
- bearer token for the optional authorized HTTP target.

No production secret or offensive execution environment belongs in this repository.

## Trust boundaries

| Boundary | Trusted side | Untrusted side |
|---|---|---|
| Suite | schema, evaluator expectations, trusted evidence | ticket, text, HTML, PDF, tool and memory payloads |
| Target | gateway request construction and response validator | all target text, citations and action requests |
| Capability | local argument validator, policy and simulator | requested tool name and arguments |
| State | local `ToolContext` and gateway-produced observations | target claims about execution, role or memory |
| Evidence | versioned identifier and record | generated claim and citation identifier |
| HTTP | explicit endpoint configuration and local timeout | remote body, status, latency and availability |
| Report | schema and content hashes | data displayed or processed by downstream consumers |

## Adversary capabilities

The corpus assumes an attacker controls a data source consumed by the target and wants the target to
treat data as authority. The attacker may place direct/indirect instructions in tickets, HTML,
PDFs, tool output or memory; request capability chains; name external destinations; demand role or
memory changes; or fabricate/rebind evidence.

An HTTP target is also considered untrusted. It may return unknown fields, claim a tool executed,
request malformed/unknown capabilities, loop forever, return too much data, time out or fail. It is
not allowed to choose evaluation expectations or directly write a result record.

The model does not defend against compromise of the local Python process, dependency supply chain,
host kernel or CI administrator. Those remain platform controls.

## Abuse cases and controls

| Abuse case | Preventive control | Observable evidence |
|---|---|---|
| Data overrides instructions | explicit trust-boundary flag / content controls | target request and content policy event |
| Target forges a successful tool call | forbid-extra `TargetTurn` without execution fields | `invalid_response` fault |
| Dangerous capability request | schema validation and deny-by-default policy | denial event and gateway observation |
| Secret enters target context | secret-read and DLP rules | canary scan across traces/results |
| External data transfer | hostname allowlist; simulator opens no socket | executed/denied `network.post` record |
| Self-elevation | role transition requires external approval | local effective-role state |
| Durable poisoning | target requests cannot write durable memory | local memory state and write records |
| Fabricated evidence | source resolution and claim overlap | citation-integrity outcome |
| Broad filter rejects analysis | paired benign controls | False Refusal Rate |
| Target hides behind failure | typed faults and separate denominator | Fault Rate and partial trace |
| Malicious PDF feature | byte signature, bounds, encryption/active-content rejection | extraction fault |

## Enforced safety properties

1. The initial HTTP target request contains no scenario identifier, evaluator expectations,
   declared fixture actions or canaries.
2. A target cannot construct an executed `ToolCall`; all target-requested actions receive untrusted
   provenance.
3. Built-in shell and network capabilities never start a process or open a socket.
4. Under a policy preset, secret, shell, role and memory capabilities are denied and external egress
   is denied.
5. Unknown or malformed action arguments are denied even when the policy preset is disabled.
6. `/api/scenarios` returns metadata only and omits payloads, expectations and canaries.
7. Target or extraction failures do not count as blocked attacks.
8. The dashboard loads no third-party runtime script.

Automated tests cover these properties at schema, gateway, policy, API and end-to-end levels.

## Residual risks

- The configured HTTP endpoint is contacted by design. An operator can point it at the wrong system;
  use an isolated destination and authorization controls outside the arena.
- A remote target may act independently outside this process. The local gateway controls only tools
  exposed through this contract, not capabilities built into the remote service.
- Report files intentionally contain synthetic canaries and complete target observations. They must
  not be generated from production secrets or published with sensitive transcripts.
- HTML extraction labels hidden content but does not reproduce browser layout. PDF extraction cannot
  guarantee semantic reading order for every document generator.
- Token-overlap grounding has known semantic blind spots.
- Curated objectives can encode author bias or omit a plausible attack outcome. Scenario review and
  external validation remain necessary.
- Resource limits are application bounds, not a host-level containment guarantee. Container and
  orchestration limits should be applied in shared infrastructure.

## Operational guidance

- Bind the dashboard to loopback unless an authenticated reverse proxy protects it.
- Use only synthetic data and a dedicated target token with no production privileges.
- Treat raw reports as sensitive test artifacts and set retention explicitly.
- Pin the target and dependency versions before comparing runs.
- Monitor Fault Rate and inspect every new fault kind before accepting a security regression result.
