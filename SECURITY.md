# Security policy

Report vulnerabilities privately through GitHub Security Advisories. Do not include real
credentials, production agent endpoints, or sensitive transcripts in an issue.

The arena executes only declarative, simulated tools. The optional HTTP adapter must target an
isolated evaluation instance with synthetic data. It is not designed to probe third-party agents
without authorization, and it cannot contain capabilities built directly into a remote target.

Raw experiment artifacts include synthetic canaries and complete target turns. Do not substitute
production credentials or transcripts, and apply explicit access/retention controls to external
evaluation output.

Supported releases are the latest commit on `main` and the latest tagged release.
