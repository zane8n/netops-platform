# ADR 0007: Identity Continuity Candidates

- Status: Accepted
- Date: 2026-10-05

## Context

Reconciliation (`identity.reconcile_device_rows`/`reconcile_ap_rows`, run on
every scan) already merges observations of the same device/AP when enough
identity signal survives: a matching MAC, serial, IP, AP attachment, or a
name similar enough to clear a configurable threshold. It deliberately treats
a MAC/serial conflict as disqualifying, because its job is "is this the same
observation of one device," not "did one device get replaced by another."

That leaves a real gap. A switch or AP replaced with different-vendor
hardware (Aruba→Cisco, Ruckus→Cisco), possibly under a new naming scheme, or
physically moved and renamed, or a whole site renamed and cascading across
many devices at once, changes enough signals at once that reconciliation
cannot and should not merge the old and new records automatically. Today the
old identity simply goes quiet and the new hardware appears as an unrelated
record: nothing links them, nothing tells an operator to look, and for APs
there was no manual override path at all (`inventory merge`/`unmerge`
existed only for devices).

## Decision

Detect, never auto-merge. During `sync_derived_state()` (and therefore
automatically inside `inventory scan`, `ap scan`, `health check`, and the
`morning-check`/`ap-audit`/`refresh-inventory` workflows that already call
those), propose that a newly-appeared device/AP continues one that just
disappeared, using signals beyond pairwise identity: attachment continuity,
a location+role-number match across differing naming conventions, a bare
role-number match (the move/rename/site-rename case), and a temporal-
proximity bonus that can never by itself justify a candidate — at least one
structural signal is required first, so unrelated same-day churn never pairs
up on coincidence.

Candidates are stored as one more managed relationship
(`rel_type='identity_swap_candidate'`) in the existing generic
`relationships_current`/`relationship_events` model rather than a new table.
That gets auto-retraction for free: the instant either side resolves (the
old one reappears, or the new one itself vanishes), the existing "not in
this tick's desired state → mark disappeared" loop retracts the candidate
with no new code. A pair already covered by an active manual merge is
excluded from being re-proposed.

Surfacing applies a confidence floor, but only at display time
(`health attention`), not at write time. A cluster of several candidate
pairs that all preserve the same asset number while moving from one location
prefix to another (a site rename) is surfaced as one item regardless of each
member's own confidence, since the recurring pattern across members is
itself the evidence; an isolated single still must clear the floor on its
own. A separate TTL controls how long a candidate keeps *appearing* in
`health attention` — the underlying relationship is retained indefinitely
either way, matching how `ap_move_events` is never pruned by this path.

Every candidate, however confident, requires a human `--confirm` through
`inventory merge` or the new `netrune ap merge`/`ap unmerge` (which close the
pre-existing gap: devices could already be manually retired this way, APs
could not). The existing device-merge machinery (`State._device_merge_key`,
`_device_matches_snapshot`, `_active_device_merges`, `create_device_merge`,
`revoke_device_merge`) was generalized to take an `entity_type`, since
`inventory_merges`' schema already carried a generic `entity_type` column —
only the methods were hardcoded to `"device"`. Table-specific effects
(`_apply_manual_merges`/`_overlay_manual_device_merges`, which mutate/read
`devices` directly) got real AP counterparts rather than being parametrized,
since substituting a table name by string is the wrong kind of generalization.

If a replacement changes vendor, naming scheme, *and* attachment all at
once, no signal survives and this cannot detect it — unchanged from before
this feature existed. The manual merge commands remain the only path there.

## Consequences

- `health attention` (and therefore `ask`'s "what needs attention") gains two
  new item kinds, `identity_swap_candidate` and `identity_rename_cluster`,
  each with a copy-pasteable confirming command already filled in.
- Four new profile config keys under `[identity]`:
  `continuity_window_days`, `continuity_confidence_floor`,
  `continuity_cluster_min_members`, `continuity_attention_ttl_days`.
- AP identity now has the same guarded manual-override lifecycle devices
  already had: preview/confirm, audit trail, reversible via `ap unmerge`.
- No new table, no new auto-apply path, no change to how
  `identity_match_evidence` itself scores a pairwise match.
