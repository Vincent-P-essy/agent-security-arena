# Reference calibration

This directory is the committed one-repetition calibration of the 32-scenario core suite against
`reference-target/2.0`, seed `2026`, suite SHA-256
`389abeb4b6e001e924e3ac372e745c128c905e81a3f9c64687b9caefbf4e586f`.

The target is a deterministic, deliberately vulnerable test double. One repetition is sufficient
for regression calibration; repeating identical outcomes would not create independent samples.
These numbers demonstrate evaluator sensitivity and defense wiring only. They are not measurements
of a hosted model or claims about production security.

Acceptance signals in this snapshot:

- every preset completes 32/32 scenarios with zero faults;
- no defense produces 100% ASR, proving the attack objectives are observable;
- lexical and heuristic filters show a 30% benign false-refusal cost;
- deterministic policy reduces tool misuse and secret leakage to 0%;
- policy plus output review reaches 0% ASR, 0% false refusal and 100% grounding;
- the full classifier stack also reaches 0% ASR but retains its 30% false-refusal tradeoff.

Artifacts:

| File | Purpose |
|---|---|
| `experiment.json` | Complete schema `2.0` experiment, summaries and records |
| `records.jsonl` | 224 individual evaluation records |
| `traces.jsonl` | 301 raw target turns with request/response hashes |
| `summary.csv` | Plot-ready defense comparison |
| `attack-breakdown.csv` | 70 per-defense rows across the 10 attack families |
| `REPORT.md` | Human-readable snapshot and limitations |
| `manifest.sha256` | SHA-256 integrity values for all files above |

Verify this snapshot from the repository root:

```bash
(cd benchmarks/reference && sha256sum --check manifest.sha256)
```

Regenerate it after an intentional corpus, policy or evaluator change:

```bash
uv run agent-arena evaluate \
  --suite scenarios/core.yaml \
  --seed 2026 \
  --repetitions 1 \
  --output benchmarks/reference
```

Review boolean outcomes and the suite digest separately from wall-clock latency. Timestamps,
platform metadata, timing values and artifact hashes naturally change between machines.
