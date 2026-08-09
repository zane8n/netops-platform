# ADR 0005: Guarded Configuration Lifecycle

- Status: Accepted
- Date: 2026-08-02

## Context

A confirmation flag alone does not bind approval to an exact target and
operation, prove a backup exists, or verify post-change state. Direct helper
execution could also bypass public policy.

## Decision

Background configuration begins with typed VLAN assignment only. Approval is
bound to normalized arguments through a preview hash and exact phrase, and
requires reason and ticket. Execution performs preflight, changed-only backup,
apply, read-back verification, and audit. Direct helper writes require an
internal marker supplied by the core. Arbitrary device configuration remains
preview-only outside the synchronous guarded CLI.

## Consequences

- A changed form invalidates prior approval.
- Backup or preflight failure prevents apply.
- Verification failure is reported as partial with manual rollback evidence.
- Additional write actions must implement the same lifecycle before becoming
  runnable from the console or job API.
