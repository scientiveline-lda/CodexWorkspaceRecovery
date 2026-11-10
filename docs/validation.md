# Candidate-bound local validation

Freeze source and run the locally executable phases with new private evidence directories:

```powershell
python tools/validate_release.py --phase baseline --workspace C:\Validation\candidate --candidate C:\Validation\candidate\candidate.json
# Repeat with phases fixtures, engineering, faults, package, acceptance, report.
```

Engineering takes `--dependency-audit` pointing to fresh lock-bound pip-audit evidence. The quality environment is build/development tooling, not an end-user dependency. Every phase records source/candidate identity, evidence hashes and results. Changed source requires a new candidate; changed/missing evidence cannot satisfy reporting.

Technical GO requires required tests with no skips, engineering checks, nine termination cases, two byte-identical unsigned builds and packaged export/import acceptance. Publication approval is separate. No VM, image authority, external signer, second operator or large retained benchmark is required.

Earlier infrastructure-based NO-GO reports describe a superseded release objective. They remain preserved unchanged privately and do not certify this revision. Never publish raw evidence or recovery keys; publish only reviewed aggregate results.
