# Contributing to Netrune

Thank you for being here. Netrune is a terminal tool for people who run
networks: it inventories switches and APs, maps topology, reads wireless
controllers, keeps history, and makes guarded changes. It grows best from
people who run *different* networks than ours, so your hardware, your
questions, and your fixes are all genuinely useful.

You don't need to be a Python developer to help.

## Ways to help

| You have... | You can... |
| --- | --- |
| 5 minutes | Star the repo, try `netrune --help`, and tell us what confused you in [Discussions](https://github.com/zane8n/netops-platform/discussions). |
| A switch, AP, or controller we don't cover well | Open a [device support issue](https://github.com/zane8n/netops-platform/issues/new?template=device_support.yml) with redacted `show version` or `snmpwalk -On` output. Real evidence is how support gets built. |
| An afternoon | Pick a [good first issue](https://github.com/zane8n/netops-platform/labels/good%20first%20issue). Each says where in the code to start. |
| More time | Take a [help wanted](https://github.com/zane8n/netops-platform/labels/help%20wanted) issue: a new controller, a driver, packaging. |
| A writer's eye | Improve the [handbook](../docs/NETRUNE_TOOLSET_HANDBOOK.md): a walkthrough, a screenshot, a clearer sentence. |

Not sure where to start? Comment on any issue saying you'd like to take it,
and a maintainer will point you in the right direction.

## Five-minute setup

Python 3.11+ on Linux, WSL2, or (experimentally) macOS:

```bash
git clone https://github.com/zane8n/netops-platform && cd netops-platform
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev,excel]'
.venv/bin/python -m pytest -q        # the full suite runs in about a minute
.venv/bin/netrune --help
```

You can try every read-only command against a throwaway profile without
touching a real network: `netrune --profile sandbox init`.

## Before you open a pull request

The same checks run in CI:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python scripts/generate_reference.py --check   # drop --check to regenerate
.venv/bin/python scripts/privacy_check.py --root .
```

- **Commands and help text** live in `command_registry()` and `HELP_TOPICS`
  in `netops_platform/core.py`. The command reference, man pages, and
  shell completions are generated from them, so regenerate after changing
  either.
- **Tests and docs use documentation addresses** (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`) and neutral names like
  `SITE-A-SW01`. The privacy check fails on anything that looks like a real
  site, credential, or person.
- **Show it working.** A command you ran and what it printed is worth more
  than a passing test. Many of this project's bugs were found that way.

Small, focused pull requests are reviewed fastest. Draft PRs are welcome
when you want early feedback.

## Finding your way around

- `netops_platform/core.py`: the `App` (dispatch and most domains) and the
  SQLite `State`. Bigger domains live in their own `*_cli.py` files.
- `netops_platform/wlc.py`: wireless controllers (Ruckus SmartZone, Cisco
  9800/AireOS). Adding a controller means a parser beside the existing ones;
  the tests in `tests/test_netops_wlc.py` show the shape.
- `netops_platform/devices.py`: switch drivers and capability detection.
- `docs/CLAUDE_REFERENCE.md`: the exhaustive technical reference, every
  command's exact behaviour. Read it before guessing.
- `docs/adr/`: why things are the way they are.

## Rules that keep operators safe

- Defaults stay neutral: nothing site-specific, no bundled credentials.
- Device operations stay read-only unless the write gates in
  `docs/device-support.md` are met (certified firmware, preview, backup,
  confirmation, verification, audit).
- Never commit credentials, raw inventory, support bundles, known-hosts
  data, production addresses, personal paths, or operator history.
- Changes to stored state or configuration come with a migration and a way
  back.

## Code of conduct and licence

Everyone here follows the [Code of Conduct](CODE_OF_CONDUCT.md).
Contributions are licensed under Apache-2.0; by submitting one, you confirm
you have the right to provide it under that licence.
