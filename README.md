# Codex Workspace Recovery

Windows portable export/import for local Codex history and selected projects, by scientiveline-lda.

Preserve engineering conversations, attachment bytes and project working state in an encrypted package. Verify its signed inventory, reconstruct it into a separate directory, then verify the recovered content. **Import creates a portable filesystem representation; it does not restore the Codex sidebar or transfer accounts/cloud history.**

## Use the Windows distribution

Extract the complete distribution into a short versioned directory. Its embedded Python, age, Minisign and MinGit are included; normal operations require no downloads, installed Python or developer Git. The distribution is unsigned; compare its SHA-256 through your trusted delivery channel. Checksums alone do not authenticate a publisher.

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

Existing parents must exist. Keep recovery keys separate from the archive; losing them makes decryption impossible. The signing private key is excluded from recovery-key copies. Key files are ACL-protected, not passphrase-encrypted.

## Supported content

- Active/archived plain and Zstandard conversation rollouts, exact raw bytes, ordered events and supported inherited history.
- Available local/embedded attachments and explicit missing/external dispositions.
- Selected database records and project associations; unknown schemas are reported, not copied indiscriminately.
- Ordinary project files, empty directories, and tested Git working state: staged/unstaged edits, conflicts, flags, detached HEAD, refs and selected linked worktrees.
- New-directory import plans, verification, idempotent reapplication and interruption recovery that preserves later work.

Supported runtime: Windows 11 x64, local NTFS, portable Windows names and checked paths shorter than 248 characters. Source writers must be closed. Read guards and comparisons establish observed content integrity, **not an atomic application-wide snapshot**.

No native application activation, account/cloud migration, active-home merge, remote/WSL recovery, automatic network retrieval or imported setup execution. Sparse/split indexes, shallow/partial repositories and alternates are refused. Submodule/LFS and filesystem metadata limitations are explicit. See [compatibility](docs/compatibility.md).

## Data protection and verification

Every package is age-encrypted. A canonical manifest signed with the locally provisioned Minisign key covers payload membership, byte sizes and SHA-256 hashes. The independent verifier does not import acquisition/deployment adapters. Semantic admission checks histories, attachment relationships and project references before import. A trusted signature does not establish that imported content is safe to execute.

Plaintext staging and destinations have restricted ACLs. Volume encryption is recommended, not automatically configured or required. Authentication stores are excluded; secret findings never silently redact conversations. Pattern scans cannot prove absence of secrets. See [security](docs/security.md).

## Documentation and development

[Operator guide](docs/operator-runbook.md) | [CLI reference](docs/cli-reference.md) | [Architecture](docs/architecture.md) | [Format](docs/CWMF.md) | [Testing](docs/testing.md) | [Release validation](docs/validation.md)

Developer setup uses Python 3.14 and the hash-locked runtime/quality requirements. Provisioning scripts download pinned build inputs only when explicitly requested; recovery never invokes them. See [installation](docs/installation.md).

This repository is a scientiveline-lda engineering showcase, provided without warranty or support commitment. Users are responsible for their use and backups; liability is excluded to the extent permitted by applicable law. All rights reserved; see [LICENSE](LICENSE). This independent project is not affiliated with or endorsed by OpenAI. Public visibility does not grant a reuse license. No archives, private keys, real conversations or workstation diagnostics belong in this repository.
