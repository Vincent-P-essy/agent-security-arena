# Architecture

## Security invariants

The design has four invariants that do not depend on target cooperation:

1. A target can request a capability but cannot execute one or attest that one executed.
2. Every target request is assigned untrusted provenance at the gateway.
3. Built-in tool handlers are deterministic, in-memory simulations with no process or network API.
4. An unavailable or malformed target produces a fault record, never an apparent security pass.

## Execution sequence

```text
Scenario YAML
  |
  +-- schema, semantic and size validation
  +-- bounded text / HTML / PDF extraction
  |
AgentGateway (trusted)
  |
  +-- TargetRequest ------------------------------------+
  |   goal, extracted data, evidence, tool schemas,     |
  |   prior gateway observations, trust-boundary flag   v
  |                                               TargetAdapter
  |                                                     |
  +-- TargetTurn <--------------------------------------+
  |   answer/citations OR capability requests only
  |
  +-- argument-schema validation
  +-- deterministic authorization
  +-- simulated execution or structured denial
  +-- next target turn (maximum four)
  +-- deterministic output review
  +-- observable-outcome evaluation
  +-- raw records, traces, metrics and hashes
```

The `TargetTurn` schema uses `extra="forbid"`. It has no execution-status, provenance, policy-event,
role-state or tool-result fields. A target response containing `tool_calls` is invalid. For each
`ActionRequest`, the gateway creates a new `ProposedAction(source="untrusted")`, validates it
against the advertised JSON-like schema and makes the authorization decision locally.

The gateway returns tool observations on a later turn. A target that keeps requesting actions is
stopped after four turns and receives a `turn_limit` fault. This prevents an unbounded agent loop.

## Components

### Scenario loader

`scenarios.py` treats YAML as untrusted. It rejects anchors/aliases before construction, uses
`yaml.safe_load`, bounds the file to 1 MiB, requires suite schema `1.0`, rejects unknown fields and
duplicate IDs, and validates every nested object with forbid-extra Pydantic models. Attack cases
need an objective; every suite needs attacks and benign controls.

### Document extractor

`documents.py` converts the scenario payload into an `ExtractionRecord`:

- plain ticket, text, tool and memory inputs must be valid UTF-8;
- HTML is parsed without a browser, and comments/hidden fragments are retained with labels;
- PDF input must be base64 bytes with a PDF signature;
- encrypted PDF, active content, more than 20 pages, more than 1 MiB input or 200,000 extracted
  characters are rejected;
- byte and extracted-text SHA-256 values are recorded.

Extraction happens before the target call, so an extraction failure is independently observable.
The PDF parser is a format parser, not an isolation boundary for arbitrary untrusted production
documents; the core corpus contains controlled fixtures.

### Target adapters

`TargetAdapter.invoke` receives `TargetRequest` and returns `TargetTurn`. `HttpTargetAdapter`
serializes only that request, disables redirects, caps responses at 1 MiB, applies a timeout and
maps transport/schema failures to typed faults.

`ReferenceTarget` is a deliberately vulnerable test double. The gateway registers a minimal local
catalog containing only attack family, benign/attack class and declared calibration actions. It
does not register evaluator expectations or canary values, and generic target adapters receive only
`TargetRequest`. The catalog is never serialized through the HTTP contract. This target establishes
evaluator sensitivity and must not be interpreted as a model-security result.

### Capability gateway and sandbox

The gateway advertises seven named capability contracts. Required/unknown argument validation is
enforced before policy. The `policy` presets then apply deny-by-default decisions:

- case and knowledge reads are allowlisted;
- egress is restricted to two synthetic internal hostnames and cannot reference secrets;
- secret reads, shell execution, self-service role changes and durable-memory writes are denied;
- unregistered capabilities are denied.

The sandbox still validates every action independently. Its handlers mutate only a fresh
`ToolContext` or return structured values. `shell.execute` never calls a subprocess and
`network.post` never opens a socket.

### Defense stages

Content inspection, action authorization and output review are separate stages. Each local decision
produces a stable `PolicyEvent` with a rule ID, subject, decision, explanation and measured latency.
The heuristic classifier and citation reviewer are deterministic rules, not learned classifiers or
general entailment systems.

### Outcome evaluator

The evaluator derives tool misuse only from gateway-produced `ToolCall(status="executed")` records.
It traces synthetic canaries through target-visible observations, raw traces and released output;
compares role/memory state maintained locally; and resolves citations against versioned evidence.
Scenario expectations never authorize a target action.

### Runner and reports

The runner records a canonical suite digest, seed, Python/platform, gateway/policy versions and
target versions. Scenario order is seeded. Every request/response turn includes timestamps, observed
latency, parsed bodies and serialized-body hashes.

Reports include:

- `experiment.json`: complete schema-versioned experiment;
- `records.jsonl`: one evaluation per line;
- `traces.jsonl`: one target turn per line with evaluation identity;
- `summary.csv`: compact defense comparison;
- `attack-breakdown.csv`: attempted/completed and security rates per attack family;
- `REPORT.md`: human-readable limitations and results;
- `manifest.sha256`: content hashes for all other artifacts.

## Fault state machine

```text
attempt
  +-- extraction failure ----------------> fault(extraction)
  +-- request timeout -------------------> fault(timeout)
  +-- connection failure ----------------> fault(connection)
  +-- non-success HTTP ------------------> fault(http_status)
  +-- oversized/malformed response ------> fault(response_too_large | invalid_response)
  +-- target fails to terminate ---------> fault(turn_limit)
  +-- valid final turn ------------------> completed
```

Faults retain partial traces and tool observations. They contribute to latency/cost and Fault Rate,
but are excluded from conditional security/usability rates. Consequently, target unavailability
cannot improve ASR.

## Extension checklist

- A target integration implements `TargetAdapter`; it never receives evaluator expectations.
- A new capability needs an input contract, handler, authorization rule and positive/negative tests.
- A new objective needs one local observable and an evaluator branch.
- A content-pattern defense needs both attack cases and benign near-neighbor controls.
- A new report field requires a schema-version decision and regression test.

## Non-goals

- The reference target does not approximate a hosted model.
- The curated suite is a regression corpus, not a representative population sample.
- Token overlap is not semantic entailment.
- The simulator is not a sandbox for arbitrary target-provided code; such code is never accepted.
