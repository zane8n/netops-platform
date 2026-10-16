# Netrune - Public Beta

Netrune 8.5 is a public beta. It is not a production-certified or
general-availability release; review the capability matrix and remaining
promotion gates before using it against operational infrastructure.

Netrune is a local-first network operations platform for inventory, topology,
VLAN analysis, endpoint path inspection, diagnostics, device access, evidence
history, and guarded changes. Every operator interface is the CLI; the same
registry drives it, the Markdown reference, the man page, and Bash, Zsh, and
Fish completions.

The 8.5 beta introduces isolated XDG profiles, named encrypted secrets,
provenance-preserving ingest channels, disabled-by-default trusted plugins,
capability-specific device drivers, and the Ghoster L2/L3 path inspector.
Defaults contain no site-specific aliases, address shorthand, credentials, or
vendor-wide support claims.

## Install

For the GitHub beta wheel, use `pipx` so the CLI runs in an isolated
environment:

```bash
pipx install ./netrune-8.5.0b3-py3-none-any.whl
netrune init
netrune config set ssh_user operator
netrune diagnose doctor
```

After this distribution is published on PyPI, use `pipx install netrune`.
Use `pip install netrune` only inside a virtual environment. Until publication,
install the signed GitHub release wheel rather than assuming a package with a
similar name is this project.

Linux and WSL2 are supported; macOS is experimental. See
[installation.md](docs/installation.md) for wheel installation, migration, and
rollback.

## Start

```bash
netrune inventory list
netops version  # v8 compatibility alias
netrune inventory merge OLD-SW01 CURRENT-SW01 --reason "approved replacement" --dry-run
netrune device support
netrune ingest channels
netrune path inspect 02:00:00:00:00:25 --vlan 120 --cached
netrune diagnose speed --profile quick
```

The Python distribution and canonical console command are both `netrune`.
The former `netops` and `netop` commands remain compatibility aliases through
v8. Netrune itself is a terminal tool with no web interface. `netrune traffic
stack init` can optionally provision a local metrics stack (VictoriaMetrics,
Grafana or Perses) for interface dashboards; the one endpoint Netrune runs to
feed it binds loopback by default and stays behind `--confirm` for anything
wider. See [poller-arch.md](docs/poller-arch.md).

## Documentation

- [Operator and Maintainer Handbook](docs/NETRUNE_TOOLSET_HANDBOOK.md)
- [Generated Command Reference](docs/reference/commands.md)
- [Profiles and Extensibility](docs/extensibility.md)
- [Name and State Migration](docs/migration-netrune.md)
- [Ghoster Path Inspector](docs/ghoster.md)
- [Device Support Matrix](docs/device-support.md)
- [Release Status and Gates](docs/releasing.md)
- [Security Policy](.github/SECURITY.md)
- [Contribution Guide](.github/CONTRIBUTING.md)

Device support is advertised per capability, model, and firmware evidence.
Configuration writes require a certified built-in profile, explicit enablement,
preview, backup, confirmation, verification, and audit. Third-party and
declarative drivers are read-only in 8.5.

Licensed under Apache-2.0. Product and vendor names describe interoperability;
see [Third-Party Notices](docs/THIRD_PARTY_NOTICES.md).
