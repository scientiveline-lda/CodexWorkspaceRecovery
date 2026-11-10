# Architecture decisions

1. Preserve original evidence separately from readable derivations; unknown events remain lossless.
2. Keep a portable format independent of Codex internal native databases; selected schema readers report gaps.
3. Use established age/Minisign tools and operator-owned keys; do not implement cryptography or adopt archive-supplied trust.
4. Deploy only into new directories with journaled rename and protected expected state.
5. The portable product supersedes the earlier infrastructure/native certification objective. Historical candidate/source/reports remain privately archived unchanged. Native activation, VM orchestration, external acquisition/transfer authorities and mandatory organizational signing were removed because they are outside portable filesystem recovery.
6. Keep source capture limitations explicit: guarded byte verification is not application-wide atomicity. Missing content and selection exclusions are separate outcomes.
