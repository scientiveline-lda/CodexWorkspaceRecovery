# Testing

Use synthetic fixtures only. Expected state is recorded before export by `tools/independent_oracle.py`, without calling application preservation, verification or comparison functions. It records raw/logical history, attachment membership/bytes, database relationships, directories and Git state.

`tools/test_report.py` requires exact discovered/required test IDs and rejects skips, expected failures and unexpected successes. `tests/safety-invariants.json` maps safety outcomes. Retained adversarial cases include correctly signed semantic corruption and changed destination metadata.

The central acceptance tool runs the public CLI with the extracted embedded interpreter and bundled executables outside the checkout. It performs three fresh round trips, including a 685-session/128-MiB project workload, independent comparison, omission/substitution detection, collisions, idempotence and later-work protection. Python network events are denied and subprocess paths restricted; this is not an OS firewall or clean-machine certification.

Nine real termination boundaries cover acquisition, archive creation, signing, encryption, verification, extraction, deployment and before/after final rename. Injected storage errors supplement real locks; no physical disk-failure certification is claimed. Measurements are disclosed rather than converted to an SLA.
