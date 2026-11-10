# Residual risks

| Risk | Control / limitation |
|---|---|
| Active or transient source changes | Closed-writer requirement, guarded handles and inventory checks; atomicity not guaranteed |
| Lost/stolen keys | Separate ACL-protected backup; no key recovery service or disk-encryption claim |
| Malformed/authentic malicious archive | Independent crypto inventory plus semantic/path/resource admission; imported code remains untrusted |
| Missing provider/external/Git content | Explicit refusal/gaps, no automatic fetch or invented reconstruction |
| Interrupted writes | Journaled new-target staging, exclusive publication, retained evidence and tested resume/rollback |
| Later user work | Changed destination detected; rollback refuses it |
| Compromised host/same-user tampering | Outside full isolation boundary; local ACLs are not an administrative sandbox |
| Secret scan blind spots | Transparent limitations; no clean-content guarantee or silent transcript redaction |
| Untested Windows/storage configuration | Document tested environment; do not imply clean-OS or physical-failure certification |
