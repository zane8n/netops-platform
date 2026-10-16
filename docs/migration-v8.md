# Migrating to Netrune 8.5

## Scope

Netrune 8.5 changes local state ownership from shared legacy directories to
isolated XDG profiles, generalizes the SSH vault into named secrets, adds schema
12 evidence tables, and replaces environment-specific defaults with neutral
configuration. Existing noun-first commands and the command-first TUI remain.

Migration is copy-first and idempotent. Source configuration and state are not
deleted. Cleanup is a separate, explicit operator decision after acceptance and
rollback rehearsal.

## Before Upgrade

1. Stop `netrune serve` and finish or cancel active jobs.
2. Record `netrune version`, `netrune db status`, and
   `netrune db integrity --json` in the change record.
3. Back up SQLite consistently, including WAL/SHM only after writers stop or by
   using the SQLite backup API.
4. Back up legacy config, cache, known hosts, encrypted vault, matching
   root-owned vault key, and device-configuration backups.
5. Record the installed artifact digest and active Python/runtime path.
6. Inventory site-specific aliases, target shorthand, identity rewrites, WLC
   filters, and custom helper settings that must move to `legacy-local`.

Do not place plaintext credentials in the migration bundle.

## Install the Beta Alongside the Old Runtime

Use a new virtual environment and keep the old one intact:

```bash
python3 -m venv "$HOME/.local/share/netrune/runtime-8.5"
"$HOME/.local/share/netrune/runtime-8.5/bin/python" -m pip install netrune-8.5.0b3-py3-none-any.whl
"$HOME/.local/share/netrune/runtime-8.5/bin/netrune" version
"$HOME/.local/share/netrune/runtime-8.5/bin/netrune" --help
```

## Create and Import the Legacy Profile

```bash
netrune profile migrate-legacy legacy-local
netrune --profile legacy-local profile show
netrune --profile legacy-local config validate
```

Migration copies legacy non-secret files and database state when safe, merges
public compatibility configuration, records `legacy-migration.json`, lists
plaintext secret names as pending, and leaves originals unchanged. Re-running
the command must not duplicate history or overwrite an existing customized
destination.

The SSH login name is public configuration, not a secret. Migration imports a
non-empty legacy `ssh_user` from `.env` into `netsnmp.conf` and records it under
`imported_public_keys`; it is excluded from `pending_secret_names`. If the old
file did not contain it, configure it explicitly before testing device access:

```bash
netrune --profile legacy-local config set ssh_user operator
netrune --profile legacy-local config validate
```

The command also handles a profile database that was initialized before the
legacy copy. If that destination contains schema only, Netrune validates both
databases, stores a timestamped copy under `migration-backups/`, and atomically
replaces it with the legacy database. A destination containing any operator or
history rows is never replaced automatically. Inspect
`database_migration.action` in JSON output to distinguish `copied`,
`replaced-schema-only-destination`, and `skipped-populated-destination`.

Do not run a fresh initialization merely because inventory appears empty after
an upgrade. First compare the active profile and database paths:

```bash
netrune profile list
netrune --profile legacy-local db status
netrune --profile legacy-local db integrity
```

If the legacy source still exists, re-run `profile migrate-legacy`, validate
the recovered profile, and activate it explicitly with
`netrune profile use legacy-local`.

Place former operator aliases in the profile's `aliases.yaml`. Put address
abbreviation and identity-prefix rules in profile configuration. Do not restore
those values to tracked defaults.

## Convert SSH and Other Secrets

Inspect without prompting:

```bash
netrune --profile legacy-local secrets status
netrune --profile legacy-local vault status
```

Import the existing SSH value:

```bash
netrune --profile legacy-local secrets import-ssh
netrune --profile legacy-local secrets list
```

The original vault remains unchanged. New named values are set interactively:

```bash
netrune --profile legacy-local secrets set ingest/netbox/token
netrune --profile legacy-local secrets list
```

The named store uses sudo/PAM authentication and a root-only random key. Netrune
never stores or reuses the sudo password. On WSL2, a separately configured and
reviewed Windows Hello PAM module can satisfy sudo authentication; this is an
operating-system integration, not a Netrune feature.

## Database Migration

The first stateful command applies schema 13 idempotently. It preserves all
existing inventory, relationship, health, topology, diagnostic, job, audit,
and backup chronology and adds:

- ingest channels, runs, observations, fields, and rejects;
- capability evidence;
- path runs, hops, and findings;
- plugin state metadata;
- audited and reversible manual device lifecycle merges.

Validate:

```bash
netrune --profile legacy-local db status
netrune --profile legacy-local db integrity
netrune --profile legacy-local ingest history
netrune --profile legacy-local path history
```

Do not point an older process at the schema 13 database. Rollback restores the
entire pre-upgrade database, not selected tables.

## Behavioral Changes

- Fresh profiles have no target shorthand, organization prefix removal, WLC
  filters, aliases, SNMP communities, SSH username, or remote credential sync.
- Configuration precedence is CLI, environment, selected profile, global
  configuration, neutral defaults.
- `--profile` affects one command and does not change the active profile.
- New SSH password writes map to `ssh/default/password`; lifecycle estimates
  remain based on the last successful replacement time.
- Plugins are disabled until explicitly enabled and compatibility checked.
- Declarative and third-party device drivers are read-only.
- Device writes require explicit enablement and a certified built-in firmware
  profile in addition to the existing guarded change lifecycle.
- `path inspect`/`ghoster` stores chronological path evidence in schema 13.

## Acceptance Checks

1. `netrune version` reports the expected beta without creating profile state.
2. `netrune init --profile acceptance` creates private XDG directories.
3. Fresh-profile config has neutral defaults and does not expand a short IP.
4. Legacy migration run twice is idempotent and source checksums do not change.
5. Named-secret import leaves the old vault intact and never logs the value.
6. SQLite reaches schema 13 and integrity is `ok` with prior chronology intact.
7. Inventory, topology, health, diagnostics, backup, and strict SSH reads work
   against fixtures or an authorized lab target.
8. Ingest duplicate delivery creates one observation; stale/partial input does
   not erase newer trusted fields.
9. Disabled plugins are not imported; incompatible plugins fail enablement.
10. Cached Ghoster returns bounded partial/unknown evidence; an authorized
    hybrid lab path returns the expected hop and blocker state.
11. Direct helper writes remain denied, and guarded writes remain blocked unless
    every firmware/profile/change gate is satisfied.
12. TUI opens on the Action Hub in light/monochrome mode and hides optional
    views until invoked.

## Rollback

1. Stop 8.5 jobs, TUI, API, and all state writers.
2. Archive redacted migration and failure evidence.
3. Restore the prior runtime links or executable path.
4. Restore the complete pre-upgrade config, cache, and SQLite backup.
5. Restore the matching legacy encrypted vault and root key if they changed.
6. Verify prior version, database integrity, inventory counts, and one read-only
   fixture or lab operation.

Profile migration leaves sources intact specifically to make this rollback
possible. Delete legacy files only after stable promotion and an approved
retention period.
