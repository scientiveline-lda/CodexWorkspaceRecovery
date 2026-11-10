# Installation and developer setup

## Operators

Extract the complete Windows ZIP into a short versioned local directory. Verify its supplied SHA-256 through a trusted delivery channel. Run `bin/cwm.cmd doctor`; do not copy only the launcher. Python, crypto tools and MinGit are included. No setup downloads, PATH edits or user-configuration modifications occur.

Upgrade side-by-side into a new directory. Keep the previous version while verifying recovery. Uninstall by removing application files only; archives, keys, plan workspaces and retained evidence are separate user-owned data.

Follow the [operator guide](operator-runbook.md). The public command sequence is:

```powershell
$cwm = 'C:\Tools\Cwm\bin\cwm.cmd'
& $cwm doctor
& $cwm keys init --output C:\Recovery\keys
& $cwm keys export-recovery --keys C:\Recovery\keys --output C:\Recovery\recovery-keys
# Close all source desktop/CLI/IDE writers first. All output directories below must be new.
& $cwm export --home C:\Data\CodexSource --project C:\Data\Project --source-closed --keys C:\Recovery\keys --workspace C:\Recovery\export-work --output C:\Recovery\workspace.age
& $cwm verify C:\Recovery\workspace.age --keys C:\Recovery\recovery-keys --workspace C:\Recovery\verify-work
& $cwm import plan C:\Recovery\workspace.age --keys C:\Recovery\recovery-keys --target C:\Recovery\recovered --workspace C:\Recovery\plan-work
& $cwm import apply C:\Recovery\plan-work\restore-plan.json
& $cwm import verify C:\Recovery\plan-work\restore-plan.json
```
 Read [security](security.md) before handling confidential content.

## Developers

Use Python 3.14 x64. Create `.venv`, install `requirements-win-py314.lock` with `pip --require-hashes`, then install the application with `--no-deps --no-build-isolation -e .`. Create a separate `.quality` environment using both hash-locked requirements files. `tools/provision_dev_tools.py --download` and `tools/provision_validation_inputs.py --download` explicitly fetch pinned public build inputs. They are never called by recovery.

Run `python -m unittest discover -s tests -t . -v` for diagnostics and the required-test runner for release evidence. Follow [validation](validation.md) for the frozen campaign.
