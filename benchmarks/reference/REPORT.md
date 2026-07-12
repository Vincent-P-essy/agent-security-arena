# Agent Security Arena - experiment report

Suite: `core.yaml` | Seed: `2026` | Repetitions: `25`

| Defense | ASR | Tool misuse | Secret leakage | False refusal | Grounded | p95 latency |
|---|---:|---:|---:|---:|---:|---:|
| none | 100.0% | 80.0% | 20.0% | 0.0% | 84.6% | 0.04 ms |
| lexical | 60.0% | 40.0% | 10.0% | 33.3% | 84.6% | 0.04 ms |
| separation | 50.0% | 30.0% | 0.0% | 0.0% | 84.6% | 0.03 ms |
| policy | 20.0% | 0.0% | 0.0% | 0.0% | 84.6% | 0.03 ms |
| policy_reviewer | 0.0% | 0.0% | 0.0% | 0.0% | 100.0% | 0.03 ms |

Rates are calculated per scenario execution. Binary rates include Wilson 95% confidence
intervals in `experiment.json`. The deterministic reference agent calibrates the harness;
it is not evidence about a production model until that model is connected through the HTTP adapter.
