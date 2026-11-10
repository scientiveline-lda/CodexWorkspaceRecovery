# Export, import and recovery

## Preparation

Use a terminal outside the selected source. Close Codex desktop/background engines, CLI sessions, IDE extensions, editors and builds that write selected roots. The utility does not kill processes. `--source-closed` records your confirmation; guarded handles reject conflicting existing writers and membership/byte comparisons detect observed changes. Transient changes cannot all be excluded.

Run `cwm doctor` using the extracted distribution. It must find every pinned bundled executable. Choose short, independent local NTFS paths and existing parents. Keep keys, original sources, archive output, working directories and import destinations separate. Source authentication stores are never imported.

Use the exact quickstart in [installation quickstart](installation.md). Each export/verification/planning workspace must be new. `--sqlite-home` overrides configured and environment locations; otherwise `sqlite_home` configuration precedes `CODEX_SQLITE_HOME`, then the effective Codex home. Launch-specific configuration must be declared explicitly.

## Selection and recovery profiles

Repeat `--thread` to select complete conversations; history ancestors are included. `--archived yes|no`, `--since` and `--until` filter conversations rather than truncating them. Dates require timezone-aware ISO timestamps; until is exclusive. Projects are explicit repeated `--project` roots. Referenced but uncaptured roots are gaps, never automatically crawled.

`--profile recovery` preserves selected working bytes and supported Git state, excluding ignored files by default. `--include-ignored` or `--profile full` includes ignored bytes except identified credential-like files. `references` preserves references only and reports the missing working-state guarantee. Shared supporting configuration is inert evidence, not installed configuration.

## Import outputs

`import plan` authenticates the archive and records target, mappings, expected writes and completeness. Optional `--mappings` is a JSON map from recorded project roots to unique nonoverlapping directories inside the new target's `projects` directory.

`import apply` authenticates again, builds new staging and publishes the destination through rename only after verification. Original evidence lives under `evidence/`; projects live under `projects/`. Raw rollouts remain content-addressed; transcripts and structured logical events are under `evidence/portable/threads`. Attachments are resolved through the asset inventories to exact objects, not guessed original paths.

`import verify` checks authenticated archive expectations and the protected deployment baseline. Retain the plan workspace, archive and recovery keys for verification, resume and rollback.

## Interrupted operations

Do not treat partial archives or uncompleted capture reports as successful exports. Export failures retain protected working evidence; inspect it and rerun into new paths. No export resume is promised.

For interrupted deployment use `recover resume <plan>`. It reconciles completed publication or retains abandoned staging before retrying. `recover rollback <plan>` renames unchanged utility-owned recovery into retained evidence; it refuses later work. Never delete lock/staging files belonging to a running operation. Export sentinel locks left by a killed process require confirming the old process is gone before removing the exact lock.

## Outcomes

JSON results go to stdout; progress/errors to stderr. Exit codes: 0 complete selected-content success; 2 refusal/validation error; 3 operational failure; 4 successful recovery with declared gaps; 5 changed destination. Inspect completeness and exclusions even with exit 0. Atomicity is a separate limitation, not missing bytes.

Temporary plaintext is ACL-protected and may be retained after errors. Remove only confirmed operation-owned data after retaining necessary evidence. There is no secure-erasure or physical power-loss guarantee.
