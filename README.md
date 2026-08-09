# NetOps Platform - Public Beta

NetOps Platform 8.5 is a public beta. It is not a production-certified or
general-availability release; review the capability matrix and remaining
promotion gates before using it against operational infrastructure.

NetOps is a local-first network operations platform for inventory, topology,
VLAN analysis, endpoint path inspection, diagnostics, device access, evidence
history, and guarded changes. Its first screen is an uncluttered command hub;
the same registry drives the CLI, TUI actions, Markdown reference, man page,
and Bash, Zsh, and Fish completions.

The 8.5 beta introduces isolated XDG profiles, named encrypted secrets,
provenance-preserving ingest channels, disabled-by-default trusted plugins,
capability-specific device drivers, and the Ghoster L2/L3 path inspector.
Defaults contain no site-specific aliases, address shorthand, credentials, or
vendor-wide support claims.

## Install

For the GitHub beta wheel, use `pipx` so the CLI and TUI run in an isolated
environment:

```bash
pipx install ./netops_platform-8.5.0b2-py3-none-any.whl
netops init
netops config set ssh_user operator
netops diagnose doctor
```

After the distribution is published on PyPI, use
`pipx install netops-platform`. Use `pip install netops-platform` only inside a
virtual environment. Do not install the unrelated `netops` distribution.

Linux and WSL2 are supported; macOS is experimental. See
[installation.md](docs/installation.md) for wheel installation, migration, and
rollback.

## Start

```bash
netop tui
netops tui
netops inventory list
netops inventory merge OLD-SW01 CURRENT-SW01 --reason "approved replacement" --dry-run
netops device support
netops ingest channels
netops path inspect 02:00:00:00:00:25 --vlan 120 --cached
netops diagnose speed --profile quick
```

The PyPI distribution is `netops-platform`; both `netops` and `netop` are
console commands. `netops serve` is experimental, single-user, and
loopback-only.

## Documentation

- [Operator and Maintainer Handbook](NETOPS_TOOLSET_HANDBOOK.md)
- [Generated Command Reference](docs/reference/commands.md)
- [Profiles and Extensibility](docs/extensibility.md)
- [Ghoster Path Inspector](docs/ghoster.md)
- [Device Support Matrix](docs/device-support.md)
- [Release Status and Gates](docs/releasing.md)
- [Security Policy](SECURITY.md)
- [Contribution Guide](CONTRIBUTING.md)

Device support is advertised per capability, model, and firmware evidence.
Configuration writes require a certified built-in profile, explicit enablement,
preview, backup, confirmation, verification, and audit. Third-party and
declarative drivers are read-only in 8.5.

Licensed under Apache-2.0. Product and vendor names describe interoperability;
see [Third-Party Notices](THIRD_PARTY_NOTICES.md).
