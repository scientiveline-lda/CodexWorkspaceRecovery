# Packaging and technical release

Build only from the explicit public-file allowlist with pinned Python wheels/runtime, age/age-keygen/Minisign and MinGit inputs. The builder validates input hashes and Git membership. End-user packages contain application/runtime/tools/docs/notices, not fixtures, native engines or validation controllers.

Two unsigned builds must have identical ZIP bytes and file inventories. Preserve ZIP digest separately from the distribution inventory digest. Validate package-only imports and run the actual public export/import campaign before technical GO. SBOM and third-party notices accompany the distribution; bundled Git includes its component license evidence.

No build creates a company signature or uploads artifacts. Unsigned status is explicit. Company redistribution/privacy/ownership review and publication authorization remain separate from technical functionality. CI actions are pinned and have minimal permissions; CI does not upload raw recovery evidence.
