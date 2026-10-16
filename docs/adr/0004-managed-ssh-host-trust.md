# ADR 0004: Managed SSH Host Trust

- Status: Accepted
- Date: 2026-08-02

## Context

Disabling SSH host-key verification permits credential disclosure and silent
device impersonation. Network equipment replacement also makes unmanaged user
known-hosts behavior operationally confusing.

## Decision

Netrune owns a private known-hosts file and passes it to every SSH adapter.
`accept-new` is the compatibility default; `strict` is the production target.
Enrollment requires an exact SHA-256 fingerprint comparison and writes an audit
event. Changed keys fail closed. Insecure break-glass use requires an explicit
session acknowledgement and cannot be enabled silently by old configuration.

## Consequences

- Existing first connections can continue under `accept-new`.
- Production rollout can pre-enroll keys and switch to `strict`.
- Device replacement requires an audited forget/re-enroll procedure.
- All future SSH adapters must consume the same trust options.
