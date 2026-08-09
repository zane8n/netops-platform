# Installation and First Run

NetOps 8.5 supports Linux and WSL2 with Python 3.11 or newer. macOS is
experimental. Use an isolated environment; do not install the package into the
system Python.

## Recommended CLI/TUI Installation

Install a downloaded GitHub release wheel with `pipx`:

```bash
pipx install ./netops_platform-8.5.0b2-py3-none-any.whl
netops init
netops diagnose doctor
```

After PyPI publication, use `pipx install netops-platform`. A conventional
`pip install netops-platform` is supported inside an activated virtual
environment. Do not install the unrelated `netops` distribution.

## Wheel Installation

```bash
./install.sh netops_platform-8.5.0b2-py3-none-any.whl
```

The installer builds an unpublished release environment, verifies it, then
atomically changes `runtime/current`. A prior release becomes
`runtime/previous`. It never edits profile data. Add `$HOME/.local/bin` to
`PATH`, then verify:

```bash
netops version
netops diagnose doctor
netops profile paths
netops commands list
```

The wheel includes compiled WebUI assets under the environment's
`share/netops-platform/webui/dist` directory. `netops serve` resolves that
installed location automatically; Node.js is not required to operate the
packaged loopback UI.

The console commands remain `netops` and `netop`.

## Source Installation

```bash
git clone https://github.com/zane8n/netops-platform.git
cd netops-platform
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/netops init
```

## WSL2 Notes

Install Linux dependencies inside WSL2, not on the Windows host. Keep active
profile data in the Linux filesystem for correct permissions and SQLite file
locking. Windows Hello can authenticate sudo only when the operator has
separately installed and reviewed a compatible PAM module; NetOps itself does
not configure PAM.

## System Capabilities

`netops init` and `netops diagnose doctor` report missing capabilities. Common
tools are OpenSSH, GnuPG, ping, traceroute or tracepath, curl, jq, iproute2,
SNMP clients, `iperf3`, and a supported speed-test CLI. Optional tools unlock
only their related features.

## Profile Initialization

```bash
netops init --profile lab
netops profile use lab
netops config set ssh_user operator
netops config show
netops config validate
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
netops profile migrate-legacy legacy-local
netops --profile legacy-local profile show
netops --profile legacy-local secrets import-ssh
```

Migration is idempotent, records a manifest, and leaves source files unchanged.
Plaintext legacy secrets are listed by name as pending and are not copied into
profile configuration. The non-secret legacy `ssh_user` value is imported into
the profile compatibility configuration when present. Otherwise set it with
`netops --profile legacy-local config set ssh_user <username>`. Review the
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
