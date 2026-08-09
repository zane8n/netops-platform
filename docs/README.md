# NetOps 8.5 Engineering Documentation

This directory records the platform architecture, safety decisions, operating
procedures, and extension contracts that must remain true as NetOps evolves.
The root handbook is the complete learning path; the generated command
reference is canonical for syntax and registry metadata.

## Document map

| Document | Purpose | Authority |
|---|---|---|
| `architecture-v8.md` | Runtime layers, contracts, data flow, safety boundaries, and extension process | Normative for v8 application code |
| `operator-console.md` | Zero-to-productive TUI operating guide | Normative for console behavior |
| `ui-design-system.md` | Layout, status, interaction, responsive, and accessibility rules | Normative for TUI changes |
| `migration-v8.md` | Upgrade, validation, rollback, and behavior changes from v7.3 | Normative for deployment |
| `device-support.md` | Device-driver architecture, Cisco/Aruba/RUCKUS matrix, ingest, identity, MAC registry, and extension procedure | Normative for device support |
| `maturity-roadmap.md` | Ordered compatibility, provider, security, and extensibility work with promotion gates | Normative planning baseline |
| `installation.md` | Clean Linux/WSL2 installation, profiles, migration, uninstall, and rollback | Normative deployment guide |
| `extensibility.md` | Profile, ingest, named-secret, plugin, and declarative-driver contracts | Normative extension guide |
| `ghoster.md` | Endpoint path-inspection modes, evidence, statuses, and limitations | Normative Ghoster guide |
| `privacy-and-publication.md` | Sanitization, clean export, history and artifact privacy gates | Normative publication process |
| `releasing.md` | Beta freeze, package build, signing metadata, and stable promotion | Normative release process |
| `reference/commands.md` | Registry-generated CLI syntax and examples | Generated; never edit manually |
| `adr/` | Accepted decisions and their consequences | Immutable except for superseding ADRs |

## Reading order

New operators should read `installation.md`, the handbook safety and first-run
chapters, then `operator-console.md`. Maintainers should read
`architecture-v8.md`, `extensibility.md`, every accepted ADR, and
`ui-design-system.md`. Device work additionally requires `device-support.md`,
`ghoster.md`, and `maturity-roadmap.md`.

## Documentation rule

A new operator-facing capability is incomplete until all applicable items are
updated:

1. The command registry and generated argument metadata.
2. A versioned result adapter or an explicit terminal-only classification.
3. Safety class, effects, preview, and confirmation policy.
4. Tests for the headless service contract and the visible workflow.
5. The handbook and any affected v8 document.
6. Regenerated Markdown, man, JSON registry, and shell completions.

Timestamps shown to operators use ISO 8601 UTC. Stored epoch values remain a
compatibility detail and must not be the only time representation in a public
result.
