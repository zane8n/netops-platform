# ADR 0009: A Declared Network Map Beside the Discovered Topology

- Status: Accepted
- Date: 2026-11-03
- Related: ADR 0005 (guarded lifecycle), ADR 0008 (shared evidence)

## Context

Every picture of the network Netrune held was discovered: LLDP/CDP
neighbours, spanning tree, controller polls, MAC tables. Discovery cannot say
what *should* be there. A switch that is dark, a cable moved to another port,
a closet's location, a phone that was never patched: none of these is a fact
any scan reports. Operators keep that knowledge in drawings (Visio, draw.io),
spreadsheets of uplinks, or their heads, and compared it with the network by
eye.

Two further facts shaped the decision. On 2026-11-01 a scheduled weekly run
started from off the site network, the neighbour scan found nothing, and the
empty result was committed: every one of 754 links was recorded as removed
and the topology stayed empty until the next on-site scan (the same happened
on 2026-10-19). Discovery alone could not tell "the network vanished" from
"we could not see it". And operators add switches many at a time, so any
declared picture has to be cheap to write in bulk and to bring in from what
they already have.

## Decision

- The operator's map is a separate, declared source: one plain-text file per
  profile (`<config dir>/network-map.txt`), in a format meant to be typed by
  hand (a device per line, its ports indented beneath it, port ranges,
  `[Location]` sections). It is the operator's file: Netrune adds to it
  (marked with a dated comment) and fills blanks, and never deletes,
  reorders, or reformats what the operator wrote.
- Maps come in as they are: the text format, CSV/Excel sheets of devices and
  links, draw.io diagrams, and Visio `.vsdx` drawings all import into the
  same model, merging into an existing map rather than replacing it.
- `map check` correlates declared and discovered without letting either
  overwrite the other. Devices match by serial, MAC, name, then IP (a typed
  name is more trustworthy than a typed address); links are judged by
  LLDP/CDP from both ends, spanning tree only where LLDP/CDP is silent;
  results are named states (OK, DIFFERENT, NOT SEEN, NO MATCH, NOT ON MAP,
  STALE, UNKNOWN, INFO) with the evidence and a next step. Disagreement exits
  PARTIAL and leads the attention queue.
- Writing discoveries back is `map update`, under the ADR 0005 lifecycle
  applied to a local file: preview (a diff), `--confirm`, backup, atomic
  write, read-back verification, audit.
- The weekly workflow reviews the week's topology (`topology changes --since
  7d`, with the net change and a call-out for mass removals) and runs `map
  check`, so the declared/discovered comparison happens on a schedule.
- The neighbour scan refuses to commit a result with no links, or under half
  of those known before, unless the operator accepts the drop
  (`NETRUNE_TOPOLOGY_ACCEPT_DROP=1`).

## Consequences

- A map that covers only part of a site is useful from the first line;
  what the network shows beyond it is information (INFO), not a failure.
- The map is organisation data: it lives in the profile (mode 0600), travels
  with profile export/pack, and is never in the repository or a public
  export. Examples use documentation names and addresses.
- Phones, printers, cameras, and PCs that do not speak CDP/LLDP cannot be
  confirmed from neighbour data; the check says UNKNOWN rather than guessing.
- Pictures and PDFs are not parsed; they are transcribed into the text
  format.
- A real shrink of more than half the topology needs the explicit override.
