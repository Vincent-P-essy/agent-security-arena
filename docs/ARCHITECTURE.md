# Architecture

## Design goals

The arena is designed around five properties:

1. **Observable outcomes.** A score comes from tool execution, data movement, state change or
   evidence integrity, never from a keyword-only judgment of prose.
2. **Reproducibility.** Suites, seeds, defense configuration, environment metadata and raw records
   are included in every report.
3. **Target portability.** Agent implementations sit behind one adapter contract.
4. **Safe calibration.** The built-in target and all tools are deterministic and side-effect-free.
5. **Usability accounting.** Every adversarial suite must include benign controls.

## Components

### Scenario loader

`scenarios.py` treats YAML as an untrusted input. `yaml.safe_load` prevents object construction,
Pydantic rejects unknown fields, file size is bounded, and semantic validation enforces unique IDs,
attacker objectives and benign controls.

### Agent adapters

`AgentAdapter` has one operation:

```python
def run(scenario: Scenario, defense: DefensePreset) -> AgentResult: ...
```

The `ReferenceAgent` is a calibration target. It models a target that follows untrusted
instructions unless a defense blocks the input, action or output. The `HttpAgentAdapter` connects
an authorized external evaluation deployment and validates its response against `AgentResult`.

### Defense stack

Defenses are composable controls rather than hidden prompt variants:

- content inspection can refuse a lexical match;
- trust separation prevents data from directly authorizing an action;
- deterministic policy checks capability, provenance, destination, role and secret references;
- output review removes canaries and replaces unresolved citations with evidence-backed records.

Every decision produces a structured `PolicyEvent` with a stable rule ID, subject, reason and
latency. This makes a refusal auditable and lets experiments attribute overhead to the control.

### Simulated tool sandbox

The sandbox implements case reads, knowledge search, secret retrieval, network publication, shell
execution, role assumption and memory writes. The names mirror real agent capabilities while the
handlers modify only an in-memory `ToolContext` and return structured data. There is no generic
command dispatcher and no network client.

### Outcome evaluator

The evaluator derives independent booleans for tool misuse, secret leakage, false refusal,
grounding and each declared attacker objective. An attack succeeds when any objective declared by
that scenario succeeds. This explicit contract avoids silently changing the benchmark definition
when a defense or target changes.

### Metrics and reports

The runner randomizes scenario order with a recorded seed. Summaries retain numerator,
denominator, rate and Wilson 95% interval. Raw records include the entire structured result and are
written with the environment to JSON; compact comparisons are written to CSV and Markdown.

## Data flow

```text
YAML suite --validate--> Scenario[] --seeded order--> AgentAdapter
                                                     |
                                    DefensePreset <--+--> ToolSandbox
                                                     |
                                             AgentResult
                                                     |
                                      objective evaluator
                                                     |
                             raw records + statistical summary
                                                     |
                                  API / dashboard / files
```

## Extension points

- Add a target by implementing `AgentAdapter` or the HTTP schema.
- Add a tool as an isolated handler in `SimulatedToolSandbox` and update its policy rule.
- Add an objective to `Objective` plus one explicit evaluator branch.
- Add a defense preset by configuring the existing stages or introducing a stage with a
  structured policy event.
- Add a scenario only with a matching benign control when the content pattern could cause broad
  refusal.

## Non-goals

- The reference agent does not approximate the reasoning quality of a hosted model.
- Lexical overlap is not a general natural-language entailment model. It verifies that a cited
  claim is materially connected to the versioned evidence record.
- The sandbox is not a containment boundary for arbitrary code because arbitrary code is never
  accepted in the first place.
- The core suite is a regression corpus, not a statistically representative sample of all agent
  deployments.

