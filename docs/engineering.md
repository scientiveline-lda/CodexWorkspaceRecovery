# Engineering gate

Pinned Ruff formatting/lint, strict application/critical-helper mypy, Bandit release-blocking findings, fresh dependency audit, strict documentation, safety-invariant mapping, branch evidence and targeted mutations are required. There is no arbitrary global coverage percentage.

Application code must not import tests/tools/packaging. The standalone verifier must remain independent of application adapters. Suppressions require a specific justified boundary; untested safety outcomes cannot pass merely because total test count is high.

Provision quality tools separately. Never add them to the recovery package. Update exact required-test and public-file inventories deliberately, recording removed requirements in private implementation evidence.
