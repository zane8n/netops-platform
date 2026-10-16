# Netrune Name and State Migration

Netrune is the canonical product name beginning with `8.5.0b3`. The rename is
designed as a non-destructive compatibility migration.

## Canonical Names

| Surface | Canonical value |
|---|---|
| Console | `netrune` |
| Python distribution | `netrune` |
| Python API | `netrune` |
| Environment prefix | `NETRUNE_` |
| Plugin groups | `netrune.ingest`, `netrune.device_drivers`, `netrune.parsers`, `netrune.exporters` |
| XDG application directory | `netrune` |
| SQLite file | `netrune.sqlite3` |

The `netops` and `netop` console commands, `netops_platform` imports,
`NETOPS_*` environment variables, and `netops.*` plugin groups remain accepted
through the v8 compatibility window. `NETRUNE_*` wins when both environment
forms are set.

## Automatic State Copy

On the first launch without explicit profile-path environment variables,
Netrune checks the XDG config, state, cache, and data roots for the former
application directory. If a Netrune destination root does not already exist,
the complete root is copied atomically. SQLite databases are copied with the
SQLite backup API and validated with `PRAGMA quick_check`, including committed
WAL data. The destination database is named `netrune.sqlite3`.

The source directories and database are not deleted or modified. A migration
record is written to:

```text
$XDG_STATE_HOME/netrune/migration-from-netops.json
```

Migration is idempotent and never merges into or overwrites an existing
Netrune root. Set `NETRUNE_DISABLE_LEGACY_STATE_MIGRATION=true` to suppress the
automatic copy. Explicit `NETRUNE_*_DIR` or legacy `NETOPS_*_DIR` paths are
used in place and are not automatically moved.

## Verification

```bash
netrune profile list
netrune profile show default
netrune db status
netrune inventory list
netrune path history
```

Keep the former XDG roots until the migrated profile, inventory, chronology,
vault references, and known-hosts file have been verified. Cleanup is always
an explicit operator action and is not performed by the installer.
