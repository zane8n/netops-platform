# ADR 0001: Local-First Operator Console

> **Superseded 2026-08-15.** The Textual console was removed. Its local-first
> premise still holds and is now met by the CLI, the collector daemon, and a
> loopback metrics exposition. See handbook 21 and 22.

- Status: Superseded 2026-08-15
- Date: 2026-08-02

## Context

Netrune had capable noun-first commands and a localhost WebUI, but routine work
still required memorizing commands and mentally joining separate outputs. The
primary deployment environment is a network engineer's terminal with local
state and controlled access to network adapters.

## Decision

An interactive `netrune` invocation opens a full-screen Textual console;
`netrune tui` is the shortest explicit form. The startup surface is a searchable
Action Hub rather than a dashboard. Functions, metrics, advanced result tabs,
Inspector, and Activity remain available on demand. Explicit CLI commands
remain stable, and `--no-tui` or `--plain` retains no-argument help. The console
performs only bounded local state reads until an operator previews and runs an
action. It uses the existing core and does not become a second network
controller.

## Consequences

- Operators gain one discoverable workspace without losing scriptable CLI use.
- Textual and Rich become package dependencies for the console.
- Headless/non-TTY execution never opens the console.
- The legacy localhost WebUI remains available but is no longer the reference
  implementation for new operator interactions.
