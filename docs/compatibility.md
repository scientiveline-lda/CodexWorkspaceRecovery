# Compatibility and limitations

| Capability | Supported result |
|---|---|
| Windows 11 x64 / local NTFS | Embedded runtime, bundled tools, no development checkout needed |
| Source capture | Writers closed; guarded files and before/after byte/membership verification; no atomic application snapshot |
| Rollouts | Initial session metadata, newline-complete JSONL, plain/Zstandard, unknown events retained, supported byte/ordinal ancestor boundaries |
| Attachments | Managed local bytes, embedded evidence, references into selected projects; external/missing bytes explicitly reported |
| Databases | Recovered staging copies only; selected allowlisted columns/ownership; unknown structures remain explicit gaps |
| Projects | File bytes and directory membership, including empty entries; profiles and exclusions recorded |
| Git | Repositories with an available committed HEAD; staged/unstaged/untracked/binary state, conflict stages, flags, detached HEAD, local refs; selected linked worktrees recovered as independent repositories |
| Advanced Git | Bare/unborn repositories, sparse/split indexes, shallow/partial clones and alternates refused. Submodule objects require separate selection; available LFS bytes only, no filters/fetch |
| Paths | Windows-portable names and checked I/O paths below 248 characters; reparse/symlinks, reserved names and collisions refused |
| Filesystem metadata | ACL/SID recreation, timestamps, alternate streams, hard-link topology and installed environment are not recovery guarantees |
| Existing target | No merge/overwrite. Same unchanged plan reapply is a verified no-op |
| Native/accounts/cloud | Not implemented in this product |

Export requires at least one supported rollout; empty selections are refused. Database-named project files and attachments remain opaque file bytes; SQLite recovery is restricted to declared Codex state locations.

Only the identified candidate's executed acceptance matrix establishes tested behavior. Parser safety ceilings are not workload benchmarks or universal compatibility guarantees. The package has no recovery-time network requirement and never installs imported hooks, services, MCP configuration or plugins.
