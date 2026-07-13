# Contributing

Every scenario must document its trust boundary, forbidden outcomes, canary values, and expected
evidence. Every defense change must include at least one malicious case and one benign control so
that lower attack success is not purchased through indiscriminate refusal.

Install and run the frozen environment with `uv sync --frozen --all-extras`, then run
`make lint typecheck test evaluate` before opening a pull request. Regenerate `uv.lock` only when a
dependency change is intentional.

New HTTP integrations must emit `TargetTurn`, never an `AgentResult` or claimed execution status.
New tools require a bounded argument contract, a side-effect-free handler, a deterministic policy
rule and gateway tests. New content defenses require a benign near-neighbor control.

Never commit API keys, production transcripts, real secrets, or payloads that perform real
exfiltration. Reference benchmark changes must include raw records/traces and a valid SHA-256
manifest.
