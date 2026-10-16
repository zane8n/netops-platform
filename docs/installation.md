# Installation and First Run

Netrune 8.5 supports Linux and WSL2 with Python 3.11 or newer. macOS is
experimental. Use an isolated environment; do not install the package into the
system Python.

## Recommended CLI/TUI Installation

Install a downloaded GitHub release wheel with `pipx`:

```bash
pipx install ./netrune-8.5.0b3-py3-none-any.whl
netrune init
netrune diagnose doctor
```

After PyPI publication, use `pipx install netrune`. A conventional
`pip install netrune` is supported inside an activated virtual
environment. Before PyPI publication, install the signed GitHub wheel rather
than assuming a similarly named package is this project.

## Wheel Installation

```bash
./install.sh netrune-8.5.0b3-py3-none-any.whl
```

The installer builds an unpublished release environment, verifies it, then
atomically changes `runtime/current`. A prior release becomes
`runtime/previous`. It never edits profile data. Add `$HOME/.local/bin` to
`PATH`, then verify:

```bash
netrune version
netrune diagnose doctor
netrune profile paths
netrune commands list
```

The canonical console command is `netrune`; `netops` and `netop` remain v8
compatibility aliases.

## Source Installation

```bash
git clone https://github.com/zane8n/netrune.git
cd netrune
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/netrune init
```

## WSL2 Notes

Install Linux dependencies inside WSL2, not on the Windows host. Keep active
profile data in the Linux filesystem for correct permissions and SQLite file
locking. Windows Hello can authenticate sudo only when the operator has
separately installed and reviewed a compatible PAM module; Netrune itself does
not configure PAM.

## Vault Sessions

Every vault read normally costs one sudo authentication. On a Windows Hello PAM
stack that means a biometric prompt per process, which is tedious across a scan
or a backup run. `netrune vault unlock` authenticates once and holds the vault
open for a bounded window:

```bash
netrune vault unlock              # uses vault_session_ttl_minutes, default 15
netrune vault unlock --ttl 60     # one hour, maximum 480
netrune vault status              # shows the remaining window; never prompts
netrune vault lock                # end it early and erase the cached key
```

Understand the tradeoff before using it. During the window the vault key is
held in a file readable by your user, rather than only by root. Anything running
as you, or as root, can read it until the window ends. That is why a session is
never started implicitly, is capped at eight hours, and is recorded in the audit
log with its duration.

Three rails keep the exposure bounded. The key is refused unless its directory
is a memory-backed tmpfs owned by you at mode `0700`, so it cannot reach a disk
or survive a reboot. Any permission or ownership drift purges the session and
falls back to sudo. And expiry is checked on every read, so a stale session is
erased rather than served.

`XDG_RUNTIME_DIR` normally supplies that directory. Where it is absent, set
`NETRUNE_VAULT_SESSION_DIR` to a tmpfs path you own; without one, sessions are
unavailable and each command authenticates as before.

Sessions are separate from sudo's own credential cache. If you would rather
widen that instead, `timestamp_timeout` in `sudoers` is the setting, and it
applies to all of your sudo use rather than just Netrune.

## System Capabilities

`netrune init` and `netrune diagnose doctor` report missing capabilities. Common
tools are OpenSSH, GnuPG, ping, traceroute or tracepath, curl, jq, iproute2,
SNMP clients, `iperf3`, and a supported speed-test CLI. Optional tools unlock
only their related features.

## Profile Initialization

```bash
netrune init --profile lab
netrune profile use lab
netrune config set ssh_user operator
netrune config show
netrune config validate
```

Configuration precedence is:

```text
CLI > environment > selected profile > global config > neutral defaults
```

`--profile NAME` selects a profile for one invocation without changing the
active profile. Each profile has independent config, state, cache, data,
known-hosts, aliases, channels, drivers, and secrets.

## Upgrade from Legacy State

```bash
netrune profile migrate-legacy legacy-local
netrune --profile legacy-local profile show
netrune --profile legacy-local secrets import-ssh
```

Migration is idempotent, records a manifest, and leaves source files unchanged.
Plaintext legacy secrets are listed by name as pending and are not copied into
profile configuration. The non-secret legacy `ssh_user` value is imported into
the profile compatibility configuration when present. Otherwise set it with
`netrune --profile legacy-local config set ssh_user <username>`. Review the
destination before deleting any legacy data.

## Uninstall and Rollback

```bash
./install.sh --rollback
./uninstall.sh
./uninstall.sh --remove-runtime
```

Rollback swaps the verified `current` and `previous` release pointers. Normal
uninstall removes only managed console links. `--remove-runtime` additionally
removes installed release environments. Both modes retain XDG profile config,
state, cache, data, secrets, and evidence. A software rollback does not reverse
a SQLite migration; restore only a tested schema-compatible backup and never
downgrade the only copy of a migrated database.
