# Reference calibration

This directory contains the committed summary from 25 repetitions of the 13-scenario core suite
against the deterministic reference target, with seed `2026`.

The calibration checks evaluator sensitivity:

- the unprotected target must fail all declared attack objectives;
- progressively stronger controls must reduce attack success;
- lexical filtering must expose its benign false-refusal cost;
- deterministic policy must prevent tool misuse and secret leakage;
- the output reviewer must restore citation integrity.

These values characterize the bundled reference implementation only. They are not model-security
claims. Generate a complete report, including raw records and Wilson confidence intervals, with:

```bash
agent-arena evaluate --repetitions 25 --seed 2026 --output reports
```

`summary.csv` is intended for plotting and regression comparison. `REPORT.md` is the human-readable
snapshot produced by the same run.
