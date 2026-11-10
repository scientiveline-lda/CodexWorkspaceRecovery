# Security and privacy

## Trust boundaries

Age encrypts every workspace package. Minisign authenticates its canonical manifest against locally provisioned signer trust; trust is never acquired from the archive itself. SHA-256 and sizes cover every declared member. Unknown/revoked/expired keys, undeclared entries and payload substitutions are rejected. A valid producer can still sign malformed content, so semantic/path validation remains mandatory.

`keys init` generates separate encryption and signing keys in a new restricted directory. `keys export-recovery` omits the signing private key. One recipient is sufficient; additional recipients are alternative decryption paths, not threshold custody. Profiles default to validity through 2099; operators may shorten validity or revoke a signer in their separately stored trust file. Expiry/revocation is checked at use and changed trust invalidates existing plans.

Export refuses overlap between its recovery-key directory and any source root. Identified `.agekey` files elsewhere in selected content are excluded with explicit recovery gaps.

Private key files are ACL-protected and not passphrase-encrypted. Back them up separately from archives. No organizational identity or signing authority is implied. A lost decryption key cannot be recovered by the utility.

## Plaintext and source protection

Key/staging directories and recovered roots restrict access to the operator and SYSTEM. Volume encryption is recommended but not required or configured. Administrators, malware acting as the user, compromised hosts and storage remanence remain outside this boundary. Cleanup does not guarantee secure erasure.

Original databases are never opened by SQLite; copied WAL/journal sets are recovered on staging. Git never operates on original repositories. Closed writers, read guards and inventory checks establish observed content integrity, not an atomic transaction across stores.

Authentication stores and identified credential-like operational files are excluded with dispositions. Conversation text is not silently redacted. Pattern scans report finding locations/rules without secret values; packed objects and opaque content have explicit scan limitations. Review archives before sharing across company/account boundaries.

## Untrusted imports

Bounded ZIP/ZIP64 metadata, decompression limits, canonical controls, duplicate/collision checks, reparse refusal and semantic containment protect extraction/deployment. Imports require a new target; imported hooks, filters, setup code and configuration are not executed. Resource ceilings are documented in the format specification. This is not a sandbox for running imported projects.

Recovery has no automatic uploads, telemetry or downloads. Build provisioning uses explicitly requested, pinned public inputs. Unsigned application distributions have checksums but no claimed organizational publisher authentication.
