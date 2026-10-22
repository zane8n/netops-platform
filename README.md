# Netrune

**A local-first network operations console for the people who keep networks running.**

[![CI](https://github.com/zane8n/netops-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/zane8n/netops-platform/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/github/license/zane8n/netops-platform)](LICENSE)
![Python 3.11 to 3.14](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)
[![Good first issues](https://img.shields.io/github/issues/zane8n/netops-platform/good%20first%20issue?label=good%20first%20issues&color=7057ff)](https://github.com/zane8n/netops-platform/labels/good%20first%20issue)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](.github/CONTRIBUTING.md)

Netrune is one CLI that inventories your switches and access points, maps
LLDP/CDP topology, reads your wireless controllers, remembers what changed
and when, traces endpoints across VLANs, runs diagnostics, and makes
configuration changes only through a preview, backup, confirm, verify, and
audit lifecycle. No server, no web UI, no cloud: one SQLite database per
profile, on your machine.

> **Public beta (8.5).** Read-only features are in daily use; configuration
> writes need a certified device profile and explicit enablement. Review the
> [device support matrix](docs/device-support.md) before pointing it at
> production.

## What a morning looks like

```text
$ netrune workflow morning-check
[1/8] Import legacy caches (SUCCESS)
[2/8] Check reachability (SUCCESS)
...
3 decision(s) are waiting for you. Go through them now? [Y/n]

[1/3] SITE-A-AP12 -> SITE-A-AP12: same AP, or a replacement?
  was  SITE-A-AP12  02:00:00:00:0e:01  192.0.2.60  SITE-A-SW01 Gi1/0/14  last seen 2026-10-20
  now  SITE-A-AP12  02:00:00:00:0e:7c  192.0.2.60  SITE-A-SW01 Gi1/0/14  since 2026-10-22
  [y] yes, the same AP (merge the old record into it)   [n] no, different APs   [s] skip   [q] stop:
```

- **Inventory and identity**: switches and APs with model, serial, and MAC,
  matched across renames, readdressing, and hardware swaps, with history.
- **Wireless controllers**: Ruckus SmartZone and Cisco Catalyst 9800/AireOS
  read in bulk (MAC, model, serial, uptime, join state, unjoined APs), with a
  site filter for shared controllers.
- **Topology and paths**: LLDP/CDP maps, AP-to-port evidence from the
  switches themselves, and the Ghoster L2/L3 endpoint path inspector.
- **Excel, both ways**: sync an existing asset register (confidence-shaded
  cells, remarks, free-IP checks) or generate reports.
- **Safe changes**: batch config, VLAN, and backup runs behind
  `--dry-run`/`--confirm`, firmware certification, and an audit trail.
- **Traffic**: optional collector and VictoriaMetrics/Grafana dashboards,
  loopback-only unless you say otherwise.

## Install

```bash
git clone https://github.com/zane8n/netops-platform && cd netops-platform
./install.sh
```

The installer checks the system tools Netrune drives (SNMP, SSH, GPG,
Expect, jq, and friends) and offers to install the missing ones, installs
Netrune into its own environment, and sets up PATH, completions, and man
pages. It asks before each change to your system. Linux and WSL2 are
supported; macOS is experimental. Details: [installation.md](docs/installation.md).

Moving to a new laptop? `netrune profile export ~/site.tgz.gpg --with-state --with-secrets`
on the old one, then `./install.sh --import ~/site.tgz.gpg` on the new one.

## A quick tour

```bash
netrune init                        # a private profile
netrune inventory scan 192.0.2.0/24 # find switches
netrune ap scan                     # controllers + switch neighbour tables
netrune ap controller T300          # what the controller says about each AP
netrune health review               # settle what is waiting for you
netrune path inspect 02:00:00:00:00:25 --vlan 120
netrune excel sync ~/switches.xlsx --dry-run
netrune help                        # everything else
```

## Contributing: we'd love your help

Netrune grows from people running networks different from ours. Things we
would especially welcome:

- **Wireless controllers**: UniFi, Aruba Instant/Central, Meraki, Mist, or
  a SmartZone/AireOS version we read wrongly (`netops_platform/wlc.py`).
- **Switch drivers and evidence**: Juniper, MikroTik, Arista, or firmware
  we have not certified yet. Redacted `show version` output is a real
  contribution.
- **Packaging**: AUR, Homebrew, .deb.
- **Docs**: walkthroughs, screenshots, clearer explanations.

Start with a [good first issue](https://github.com/zane8n/netops-platform/labels/good%20first%20issue),
ask anything in [Discussions](https://github.com/zane8n/netops-platform/discussions),
and read the [contribution guide](.github/CONTRIBUTING.md) (five-minute
setup, no network needed). If Netrune is useful to you, a star helps others
find it.

## Documentation

- [Operator handbook](docs/NETRUNE_TOOLSET_HANDBOOK.md): walkthroughs for every domain
- [Command reference](docs/reference/commands.md): generated from the command registry
- [Technical reference](docs/CLAUDE_REFERENCE.md): every command's exact behaviour
- [Device support matrix](docs/device-support.md)
- [Profiles and extensibility](docs/extensibility.md)
- [Ghoster path inspector](docs/ghoster.md)
- [Architecture decisions](docs/adr/)
- [Release status and gates](docs/releasing.md)
- [Security policy](.github/SECURITY.md) and [Code of conduct](.github/CODE_OF_CONDUCT.md)

The `netops` and `netop` commands remain compatibility aliases through v8.
Licensed under Apache-2.0. Product and vendor names describe
interoperability; see [Third-Party Notices](docs/THIRD_PARTY_NOTICES.md).
