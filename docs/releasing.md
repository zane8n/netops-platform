# Release Procedure

## Beta Scope Freeze

`8.5.0b1` freezes the 8.5 feature set. Later beta builds may correct defects,
tests, documentation, packaging, or compatibility evidence but may not add new
scope. Stable promotion uses the same feature set.

The current public-beta publication candidate is `8.5.0b3`.

On 2026-08-09, the exact PyPI project API for `netrune` and the GitHub API for
`zane8n/netrune` both returned `404`, indicating that those project/repository
names were not allocated at that time. Namespace availability can change and
does not establish trademark or company-name rights. `netrune.com` is already
registered/in use and must not be represented as this project's domain.

## Build

```bash
python scripts/generate_reference.py --check
python scripts/privacy_check.py --root .
python -m pytest
python -m build
python -m twine check dist/*
python scripts/privacy_check.py --root . dist/*.whl dist/*.tar.gz
bash scripts/smoke_wheel.sh dist/*.whl
bash scripts/smoke_install.sh dist/*.whl
python scripts/build_release.py dist --output .release
python -m pip_audit --strict .
```

Audit the project path, not the current editable environment. Strict
environment audits attempt to resolve the unpublished beta distribution itself
and fail before assessing its dependencies.

`scripts/build_release.py` emits SHA-256 checksums, an SBOM, and provenance
metadata.
When a release signing identity is configured, add detached signatures without
placing private-key material in the repository or command arguments.

## Stable Promotion Gates

- Clean Linux and WSL2 wheel installation and uninstall/rollback rehearsal.
- No unresolved critical or high security/privacy findings.
- Accepted read fixtures for every advertised device family.
- One authorized real-lab Ghoster path with retained redacted evidence.
- XDG and named-secret migration rehearsal, rollback, and idempotency proof.
- Generated-reference drift, dependency audit, SBOM, checksums, provenance, and
  archive privacy checks all pass.
- Documentation examples are executed or fixture-verified.
- Owner/legal review confirms that the Netrune name can be published and used
  in intended jurisdictions; engineering checks do not establish trademark
  clearance.

Every operator interface is the CLI. The one listener Netrune runs -- the
traffic metrics exposition endpoint -- is loopback-only by default and stays
behind `--confirm` for anything wider; see [poller-arch.md](poller-arch.md).
