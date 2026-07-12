# Contributing

Every scenario must document its trust boundary, forbidden outcomes, canary values, and expected
evidence. Every defense change must include at least one malicious case and one benign control so
that lower attack success is not purchased through indiscriminate refusal.

Run `make lint typecheck test evaluate` before opening a pull request. Never commit API keys,
production transcripts, or payloads that perform real exfiltration.
