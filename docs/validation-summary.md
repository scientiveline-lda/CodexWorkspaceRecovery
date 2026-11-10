# Public validation summary

## Scope and provenance

This page summarizes the **v0.3.0 portable-filesystem reference campaign executed on 9 November 2026**, followed by publication on 10 November. It contains synthetic aggregate results only: no real conversations, workstation paths, archive keys or private diagnostic reports.

The tested runtime is the runtime published in initial commit `654eb4b496dd8e0f54db1c50bb3a9915d66bba59`. The historical source inventory SHA-256 was `b4d3e23378e739d7498decb6b5fc76deae07b595e7eddeb13f5e90cfa1c6d280`. Subsequent showcase-license and README changes are documentation changes; these historical measurements must not be relabeled as a newly executed full campaign.

The [Windows validation run](https://github.com/scientiveline-lda/CodexWorkspaceRecovery/actions/runs/42797575169) and [CodeQL run](https://github.com/scientiveline-lda/CodexWorkspaceRecovery/actions/runs/42797575212) passed on the initial published commit. Current workflow badges report current CI status, not the status of every historical platform or workload.

## Recorded reference results

| Scenario | Result and interpretation |
| --- | --- |
| Required fixture inventory | 110 passed; zero skipped tests, failures, errors, expected failures or unexpected successes. |
| Independent packaged recovery | Three runs passed: a 685-session/128-MiB project workload, repeated selection, and recovery with an explicitly missing attachment. |
| Reference workload duration | 713.519 seconds for the 685-session run on the local reference environment; not a performance SLA or cross-machine benchmark. |
| Expected-state comparison | A separate oracle inventoried source history, attachment bytes/references, selected database relationships, project files/directories and supported Git state before export. Recovery matched; source and unrelated content remained unchanged. |
| Negative verification controls | Deliberate omissions/substitutions were detected. Corrupt packages were refused; changed destinations and unsafe rollback attempts did not become successful recovery results. |
| Real interruption campaign | Nine real child-process termination boundaries passed; a supplemental packaged CLI kill/resume/reapply also passed. |
| Safety mutations | Four detected: trust expiry, containment, completeness reporting and rollback baseline. |
| Reproducibility and privacy | Two unsigned Windows builds matched byte-for-byte. Windows, wheel and source-distribution privacy canaries were excluded. |
| Windows entry points | Thirteen CMD/PowerShell calls passed, including paths with spaces, packaged imports and restricted child PATH. |
| Engineering checks | Formatting/lint, strict types, architecture rules, documentation, dependency checks and mapped safety outcomes passed. No unresolved medium/high Bandit findings; low subprocess findings remained visible. |

The packaged campaign ran outside the checkout using an embedded runtime and real public CLI subprocesses. Network controls used a Python audit-denial hook and package/system executable allowlist; they were not an operating-system firewall certification. No recovery-time downloads were required.

## README demonstration

On **10 November 2026**, a fresh synthetic run of the packaged distribution passed export, independent cryptographic verification, semantic verification, import, recovered-state verification, reapplication and rollback. Its independent oracle compared recovered history, an attachment, directory membership, file bytes and selected dirty Git state. The source inventory remained unchanged.

The README illustrations contain abbreviated commands and selected actual JSON fields from this run. The mobile illustration presents the same results at a larger relative text size. They are illustrations of recorded CLI output, not a graphical application or invented native Codex integration.

The documentation-reference regression added for this presentation is separate from the historical 110-test baseline. Use the [required inventory](https://github.com/scientiveline-lda/CodexWorkspaceRecovery/blob/main/tests/required-tests.json) for the current suite and [validation procedure](validation.md) for a new candidate.

## What this establishes

Technical recovery evidence applies to the documented Windows 11 x64/local NTFS portable filesystem workflow and selected supported content. It does not establish native Codex discoverability, account ownership transfer, cloud-history migration, an atomic application-wide snapshot, universal Git/filesystem support, clean-VM certification, or absence of all defects.

Capture requires closed writers. Import uses a new destination. A result with missing content remains a partial recovery with explicit dispositions. Distribution artifacts are unsigned, and no public binary release is offered by this summary. See [compatibility](compatibility.md), [security](security.md) and [LICENSE](https://github.com/scientiveline-lda/CodexWorkspaceRecovery/blob/main/LICENSE).
