## What this changes

<!-- One or two sentences: what an operator will notice. Link the issue if there is one ("Closes #12"). -->

## How I checked it

<!-- A real command you ran and what it showed is worth more than a passing test. -->

## Checklist

- [ ] `python -m pytest -q` passes
- [ ] `python scripts/generate_reference.py --check` passes (run it without `--check` to regenerate after changing commands or help text)
- [ ] `python scripts/privacy_check.py --root .` passes: tests and docs use documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and neutral names like `SITE-A-SW01`
- [ ] Docs updated where behaviour changed (`docs/NETRUNE_TOOLSET_HANDBOOK.md`, `docs/CLAUDE_REFERENCE.md`)

New here? Don't worry about getting every box ticked on the first try; open the pull request and we'll get it over the line together.
