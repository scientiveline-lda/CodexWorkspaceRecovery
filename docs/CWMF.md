# CWMF 1.0 draft revision 3

The outer age ciphertext contains a ZIP64 package. `manifest.json` is RFC 8785 canonical JSON; `manifest.minisig` signs those exact bytes. Its externally supplied local trust key authorizes producer/scope. Every payload member has exact SHA-256/size coverage; undeclared, duplicate, unsafe and colliding members are rejected.

Draft 3 removes laboratory/authority activation policy and adds portable project-directory inventories. Older draft packages remain historical evidence with their old candidate; this reader rejects unsupported revisions rather than silently transforming them.

| Namespace | Meaning |
|---|---|
| inventory/source.json, capture.json | Declared roots, acquisition hashes, coverage and observed consistency |
| inventory/sessions.json, rollouts.json | Selected identities, ancestor roles and exact original rollout object mappings |
| inventory/database-records.json, storage-adapters.json | Selected records, reader provenance and schema gaps |
| inventory/assets.json, asset-references.json | Available bytes and typed reference dispositions |
| inventory/projects.json | Root mapping, selected files/directories, Git/index/refs and limitations |
| objects/sha256/ | Exact content-addressed raw rollouts, assets and project bytes |
| portable/threads/ | Metadata, events, original/combined readable history |
| portable/projects/ | Project controls and Git bundles |
| portable/configuration/ | Reviewed inert preferences/instructions/supporting material |
| continuation/ | Evidence-linked repository inspection instructions, no invented semantic summary |
| reports/ | Completeness, exclusions and secret findings without secret values |

Capture class `guarded_validated` means observed guarded bytes/membership; atomic application-wide consistency remains unestablished. Completeness is selected-state equivalence, not a whole-machine/account backup.

Current admission ceilings: 100 GiB archive/expanded payload, 16 GiB member, 200,000 members, 32 MiB central directory, 4 MiB manifest/signature controls, 1000:1 member ratio. Rollout lines: 32 MiB; expanded rollout: 4 GiB. Selected database row: 32 MiB; aggregate controls: 64 MiB. Failures are explicit, never truncation. Source capture has a 100,000-file ceiling. Free-space checks retain a 2 GiB reserve.

History order follows original records/byte boundaries, not timestamps; supported ordinal boundaries must agree. Readable views do not claim to reproduce a provider's compacted model context. Unknown events retain raw evidence. Incrementals and native/account activation are not implemented.
