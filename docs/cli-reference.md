# CLI reference

Generated from the command parser. JSON results use stdout; errors and progress use stderr.

## cwm

```text
usage: cwm [-h] [--version]
           {keys,discover,export,verify,import,recover,continuation,doctor} ...

Encrypted portable Codex workspace export/import. No application or account
activation.

positional arguments:
  {keys,discover,export,verify,import,recover,continuation,doctor}
    keys                Create local keys or a separate recovery-key copy.
    discover            Inventory declared local sources; never opens source
                        databases.
    export              Acquire a closed workspace and publish a verified
                        encrypted package.
    verify              Decrypt, authenticate and reconcile package content
                        without deployment.
    import              Plan/apply/verify reconstruction into a new filesystem
                        destination.
    recover             Resume interrupted deployment or retain rollback
                        evidence.
    continuation        Copy historical continuation instructions; no model is
                        invoked.
    doctor              Check embedded runtime and pinned bundled executables
                        without downloads.

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
```

## cwm keys

```text
usage: cwm keys [-h] {init,export-recovery} ...

positional arguments:
  {init,export-recovery}
    init                Generate locally trusted signing/encryption keys;
                        output must be new.
    export-recovery     Copy decryption/trust material, excluding signing
                        private key.

options:
  -h, --help            show this help message and exit
```

## cwm keys init

```text
usage: cwm keys init [-h] --output OUTPUT

options:
  -h, --help       show this help message and exit
  --output OUTPUT
```

## cwm keys export-recovery

```text
usage: cwm keys export-recovery [-h] --keys KEYS --output OUTPUT

options:
  -h, --help       show this help message and exit
  --keys KEYS
  --output OUTPUT
```

## cwm discover

```text
usage: cwm discover [-h] [--home HOME] [--sqlite-home SQLITE_HOME]
                    [--output OUTPUT]

options:
  -h, --help            show this help message and exit
  --home HOME
  --sqlite-home SQLITE_HOME
  --output OUTPUT
```

## cwm export

```text
usage: cwm export [-h] --home HOME [--sqlite-home SQLITE_HOME]
                  [--project PROJECT] --source-closed --output OUTPUT
                  --workspace WORKSPACE --keys KEYS [--thread THREAD]
                  [--archived {yes,no}] [--since SINCE] [--until UNTIL]
                  [--profile {references,recovery,full}]
                  [--include-supporting] [--include-ignored]

options:
  -h, --help            show this help message and exit
  --home HOME
  --sqlite-home SQLITE_HOME
  --project PROJECT
  --source-closed       Confirm all writers are closed. This is not proof of
                        atomicity.
  --output OUTPUT
  --workspace WORKSPACE
  --keys KEYS
  --thread THREAD
  --archived {yes,no}
  --since SINCE
  --until UNTIL
  --profile {references,recovery,full}
  --include-supporting
  --include-ignored
```

## cwm verify

```text
usage: cwm verify [-h] --keys KEYS --workspace WORKSPACE archive

positional arguments:
  archive

options:
  -h, --help            show this help message and exit
  --keys KEYS
  --workspace WORKSPACE
```

## cwm import

```text
usage: cwm import [-h] {plan,apply,verify} ...

positional arguments:
  {plan,apply,verify}
    plan               Verify package and enumerate writes before deployment.

options:
  -h, --help           show this help message and exit
```

## cwm import plan

```text
usage: cwm import plan [-h] --keys KEYS --target TARGET --workspace WORKSPACE
                       [--mappings MAPPINGS]
                       archive

positional arguments:
  archive

options:
  -h, --help            show this help message and exit
  --keys KEYS
  --target TARGET
  --workspace WORKSPACE
  --mappings MAPPINGS   Optional JSON source-root to destination-root mapping
                        inside target/projects
```

## cwm import apply

```text
usage: cwm import apply [-h] plan

positional arguments:
  plan

options:
  -h, --help  show this help message and exit
```

## cwm import verify

```text
usage: cwm import verify [-h] plan

positional arguments:
  plan

options:
  -h, --help  show this help message and exit
```

## cwm recover

```text
usage: cwm recover [-h] {resume,rollback} ...

positional arguments:
  {resume,rollback}

options:
  -h, --help         show this help message and exit
```

## cwm recover resume

```text
usage: cwm recover resume [-h] plan

positional arguments:
  plan

options:
  -h, --help  show this help message and exit
```

## cwm recover rollback

```text
usage: cwm recover rollback [-h] plan

positional arguments:
  plan

options:
  -h, --help  show this help message and exit
```

## cwm continuation

```text
usage: cwm continuation [-h] {build} ...

positional arguments:
  {build}

options:
  -h, --help  show this help message and exit
```

## cwm continuation build

```text
usage: cwm continuation build [-h] --project PROJECT --output OUTPUT recovery

positional arguments:
  recovery

options:
  -h, --help         show this help message and exit
  --project PROJECT
  --output OUTPUT
```

## cwm doctor

```text
usage: cwm doctor [-h]

options:
  -h, --help  show this help message and exit
```
