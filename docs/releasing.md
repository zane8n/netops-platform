# Release Procedure

## Beta Scope Freeze

`8.5.0b1` freezes the 8.5 feature set. Later beta builds may correct defects,
tests, documentation, packaging, or compatibility evidence but may not add new
scope. Stable promotion uses the same feature set.

The current public-beta publication candidate is `8.5.0b2`.

## Build

```bash
python generate_reference.py --check
python privacy_check.py --root .
python -m pytest
python -m build
python -m twine check dist/*
python privacy_check.py --root . dist/*.whl dist/*.tar.gz
bash scripts/smoke_wheel.sh dist/*.whl
bash scripts/smoke_install.sh dist/*.whl
python build_release.py dist --output .release
python -m pip_audit --strict .
```

Before packaging, run `npm ci && npm run build` under `webui/` and require
`git diff --exit-code -- webui/dist`. The source distribution includes the
frontend source and compiled output; the wheel installs the compiled files
under `share/netops-platform/webui/dist`. The isolated wheel smoke starts the
loopback server and fetches both the page and its JavaScript asset.

Audit the project path, not the current editable environment. Strict
environment audits attempt to resolve the unpublished beta distribution itself
and fail before assessing its dependencies.

`build_release.py` emits SHA-256 checksums, an SBOM, and provenance metadata.
When a release signing identity is configured, add detached signatures without
placing private-key material in the repository or command arguments.

## Stable Promotion Gates

- Clean Linux and WSL2 wheel installation and uninstall/rollback rehearsal.
- No unresolved critical or high security/privacy findings.
- Accepted read fixtures for every advertised device family.
- One authorized real-lab Ghoster path with retained redacted evidence.
- XDG and named-secret migration rehearsal, rollback, and idempotency proof.
- TUI snapshots in light and monochrome modes and loopback WebUI build tests.
- Generated-reference drift, dependency audit, SBOM, checksums, provenance, and
  archive privacy checks all pass.
- Documentation examples are executed or fixture-verified.

The localhost API/WebUI remains experimental and loopback-only. Authenticated
remote and multi-user service operation is not part of 8.5.
