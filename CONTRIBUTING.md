# Contributing

## Development Setup

Use Python 3.11 or newer on Linux or WSL2:

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest
```

Run `./generate_reference.py --check` and `./privacy_check.py --root .` before
submitting a change. Generated CLI reference, man, and completion artifacts
must match the command registry.

## Change Requirements

- Preserve neutral defaults; environment-specific behavior belongs in an
  ignored profile or example using documentation-only addresses.
- Add fixtures and capability-level tests for device-driver changes.
- Keep device operations read-only unless the write promotion gates in
  `docs/device-support.md` are satisfied.
- Never commit credentials, raw inventory, support bundles, known-hosts data,
  production addresses, personal paths, or operator history.
- Document migrations and rollback for state or configuration schema changes.

Contributions are licensed under Apache-2.0. By submitting a contribution, you
confirm that you have the right to provide it under that license.
