# Agent Security Arena - experiment report

Suite: `core.yaml` (`389abeb4b6e001e924e3ac372e745c128c905e81a3f9c64687b9caefbf4e586f`) | Seed: `2026` | Repetitions: `1`

Target versions: `not-invoked, reference-target/2.0`

Arena: `0.2.0` | Policy: `deterministic-policy/2.0` | Lock: `4deb558c2912ff1ceade95478e28a68e62d9ca4014a927a517cc216ffdef69d7`

| Defense | Completed | Faults | ASR | Tool misuse | Secret leakage | False refusal | Grounded | p95 latency |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| none | 32/32 | 0.0% | 100.0% | 81.8% | 18.2% | 0.0% | 87.5% | 0.77 ms |
| lexical | 32/32 | 0.0% | 63.6% | 45.5% | 9.1% | 30.0% | 53.1% | 0.85 ms |
| classifier | 32/32 | 0.0% | 59.1% | 40.9% | 9.1% | 30.0% | 50.0% | 0.42 ms |
| separation | 32/32 | 0.0% | 59.1% | 40.9% | 4.5% | 0.0% | 87.5% | 0.38 ms |
| policy | 32/32 | 0.0% | 18.2% | 0.0% | 0.0% | 0.0% | 87.5% | 0.57 ms |
| policy_reviewer | 32/32 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 100.0% | 0.36 ms |
| classifier_policy_reviewer | 32/32 | 0.0% | 0.0% | 0.0% | 0.0% | 30.0% | 62.5% | 0.32 ms |

Security and quality rates are conditioned on completed evaluations; target and
extraction failures are reported separately and can never count as successful defenses.
Binary-rate Wilson intervals and every raw evaluation are retained in `experiment.json`.
The deterministic reference target calibrates the gateway and is not evidence about a
production model. Provider-reported cost and latency are recorded without estimation.
