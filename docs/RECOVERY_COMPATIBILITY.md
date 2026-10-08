# Recovery compatibility and file-set safety

## Original evidence and migrated state are different

Restoration authenticates the original staged database before opening it for migration. A separate same-key probe checks the original schema, encrypted records, application invariants and audit chain against the authorized manifest. The original backup checksum must match the copied input bytes.

Only the private staging copy is migrated. The resulting schema must equal the current application's supported schema. For a format-v2 backup, the migrated chain must still contain the original audit anchor. The candidate image and installed database must match the migrated audit head exactly. The report preserves the source checksum/audit head separately from the restored schema version. A migration's own audit event is not incorrectly treated as source tampering.

An isolated recovery drill uses the restored schema from the restore report and verifies preservation of the source audit anchor. The original backup and live workspace are not migrated during a drill.

## SQLite file-set handling

Every member of the live SQLite/WAL/SHM set is checked before any file moves. Directories and dangling or ordinary symlinks are rejected. Each path is checked again during installation, and every installation failure passes through rollback handling rather than returning midway through a moved file set.

Staging files, sidecars and migration snapshots live in one private temporary directory so ordinary error returns clean up partial staging state. Previous live files remain in the private recovery directory. A failed installed image is quarantined as a complete available SQLite/WAL/SHM set before originals are restored. A rollback failure is reported as incomplete, not as a successful rollback.

A private `.restore-in-progress` marker is synced before the first live-file move. Normal startup checks for any such marker before opening the vault or database and refuses to proceed while it exists. Successful installation or completed rollback removes it; errors, panics and abrupt termination retain it. An explicitly authorized recovery may retry a valid interrupted transaction, while malformed markers fail closed. This prevents a half-replaced or absent live database from silently becoming a new empty workspace. Unix directory entries are synced as well; filesystem and hardware durability still require deployment testing.

These controls do not make multiple filesystem renames power-loss atomic and cannot protect against a fully compromised operating system. If a restore or rollback is interrupted, stop the worker, preserve the complete workspace and recovery directory, and inspect the available images before proceeding. Successful restoration still requires explicit delivery reauthorization on the next normal startup.

## Regression coverage

The `recovery::restore::tests` module covers schema-v4 to current-schema restoration, an isolated legacy recovery drill, source-byte preservation, incorrect schema/audit manifests, unsafe later sidecars, dangling symlinks on Unix, staging cleanup and explicit rollback failures. It uses synthetic encrypted databases and no live email account. Existing recovery tests remain in place, and the extracted restore module remains in the mutation-test scope.

Run the targeted suite with `cargo test --locked --lib --no-default-features recovery::`. A successful test run is software evidence, not evidence of a real disaster-recovery exercise on the owner's machine.
