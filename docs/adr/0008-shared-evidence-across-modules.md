# ADR 0008: Shared Evidence Across Modules

- Status: Accepted (phases 1-3 implemented 2026-10-21; AP history from observations remains)
- Date: 2026-10-21
- Extends: ADR 0007 (identity continuity candidates)

## Context

Netrune grew one domain at a time. Each domain learned to collect and judge
its own evidence, so the same question is often answered in several places,
by different rules, from different copies of the data:

| Question | Where it was answered | Problem |
| --- | --- | --- |
| Is this neighbour a switch or an AP? | `is_ap_device` (shell AP scan), `is_switch_device` (shell topology scan), `is_switch_row` (reports) | Three rules. The AP scan's matched "ARUBA"/"RUCKUS" and read any "4" in the LLDP capability bits as WLAN, so 63 switches and some phones were stored as APs. |
| Which port is an AP on? | Controller (WLC/vSZ), SNMP LLDP/CDP walk, now SSH CDP/LLDP + MAC table | Merged in awk by MAC only, with no notion of which source is stronger. The controller's radio MAC and LLDP's Ethernet MAC never met, so one AP became two rows. |
| What is this AP's model? | Controller platform vs LLDP system description | The switch's software banner overwrote the controller's model, so the model flapped between scans. |
| Is this the same switch? | `reconcile_device_rows` | Fuzzy name scoring (similar names, same role/number, same model) merged records even when the addresses were all answering in the same scan. Four C2960S switches named `…-SW01`, none with a MAC or serial yet, were fused into one record for a week, and a real replacement's serial then spread to all four. The raw scans had each switch's own hostname throughout. |
| Was it replaced? | `excel_reports.replacements` (field history), ADR 0007 continuity (naming), topology events (nobody) | The strongest evidence, the neighbour port that used to see the old switch now seeing the new one, was recorded by the topology scan and used by nothing. |
| What is the serial? | SSH `show version` (Motherboard serial), SNMP ENTITY-MIB (System serial) | The two alternated, producing false "serial changed" history and false replacements. |

Measured on the production store (672 inventory rows, 500 MB): building the
reconciled inventory takes 0.11 s and a full `sync_derived_state` 0.84 s, so
repeated *computation* is not the cost. The cost is *disagreement*: modules
judging the same thing differently, and evidence that one module has but
another needs and never gets.

## Decision

One question, one answer, one place, used by every module that needs it.
Evidence flows forward into the shared engine rather than being judged at the
edge where it was collected.

### Phase 1 (this change)

- **Device classification** lives in `devices.py` (`is_switch_row`,
  `ap_model`, next to `device_manufacturer` and driver detection). The
  reports, `ap neighbors`, and the `db coherence` check share it. The shell AP
  scan's rule is aligned with it: maker names are not evidence, a self-described
  switch or phone is not an AP, and `lldpRemSysCapEnabled` is decoded as BITS.
- **AP source precedence** is fixed and stated once:
  - *what it is and what it is called* come from the controller;
  - *where it is plugged in* comes from the switch;
  - the model comes from whichever source names one, the controller first;
  - switch and controller records join by MAC, then hostname, then IP.
  `ap neighbors` confirms each LLDP/CDP reading against the port's MAC table
  (retried when empty), and learns the MAC of CDP-only APs from the port.
- **Identity** refuses a name-only merge of two switch records whose
  different addresses were both online in the same scan
  (`identity.concurrently_distinct`, conflict `concurrent-addresses`). `db
  coherence` reports such names (`shared_names`) for the operator to fix at
  the source.
- **Topology feeds identity.** `identity.neighbor_port_transitions` reads the
  topology scan's link events. A port that lost neighbour A and gained B in one
  scan (or within three days, with nothing in between) is a swap, scored by how
  still the rest of that switch was. A name that left one port and appeared on
  another is a move. The swaps are a structural signal in
  `continuity_match_evidence` (ADR 0007), so they produce merge candidates for
  `inventory merge`/`ap merge` even when name, address, and hardware all
  changed. The same function feeds the Transitions and History reports.
- **Serial semantics.** The Motherboard serial is the serial Netrune keeps:
  - SNMP never replaces a stored Cisco serial for the same model, only fills a blank one;
  - SSH supplies the Motherboard serial (`device inventory --all`, weekly);
  - a serial seen at more than one switch is not evidence;
  - a replacement needs the base MAC to change too.
- **One coherence pass** in the morning check (`db coherence --realign`)
  realigns rather than each module cleaning up after itself. It now also
  removes switch rows from the AP inventory.
- **Long-running work in one place.** `workflow weekly` runs every scan, then
  the SSH reads that need the vault under one session, then realignment. A
  persistent systemd timer schedules it. Anything that could not authenticate
  is deferred to `--resume` and surfaced in the attention queue rather than
  failing one switch at a time.

### Phase 2 (implemented)

- **The AP merge is Python.** `netops-discovery` still collects the controller
  and switch readings; `netops_ingest.py merge-ap-scan` (`ap_merge.py`) merges
  them with the precedence above. It reproduces the old awk merge exactly on
  the same input, plus the hostname/address join and model precedence.
- **Confirmed attachments outlive the next scan.** `ap neighbors` records
  every port it read, with its MAC-table verdict, in `ap_attachments.db` next
  to the AP cache. The merge keeps a `confirmed`/`learned` port (≤14 days old)
  over an SNMP reading of another port on the same switch, because SNMP's
  ifIndex mapping is the weak step. It also gives that port to a
  controller-only AP. A reading on a different switch is newer evidence of a
  move, and wins.
- **One name key.** `identity.name_key` (host label, upper-case, letters and
  digits) is what the reports, the workbook sync, and `ap neighbors` match
  names by. `normalize_asset_name` stays the fuzzy identity key, since it
  strips configured prefixes on purpose.

### Phase 3 (implemented for switches)

- **Switch history from observations.** `State.device_observation_history`
  rebuilds switch field changes from the raw per-address `observations`,
  before any reconciliation, and the reports read it instead of
  `inventory_history`. A reconciliation mistake therefore can no longer
  appear as hardware or naming history. On the production store the glued
  week's serial events are gone (723 raw events against 3,048 merged), and the
  Aruba→Cisco migration of 2026-10-17 shows as nine replacements at their
  addresses.
- **Remaining:** AP history still comes from `inventory_history`. AP
  observations arrive from three channels (controller WLC, SmartZone, switch
  scan), each keyed differently, so a per-AP raw history needs those joined
  first. `memory`/`timeline` views also still read the merged history.

## Consequences

- Modules ask the shared functions instead of re-deciding. A new rule, such as
  another vendor's AP banner, is made once and every view agrees.
- The continuity engine now has topology evidence, so a switch replaced
  under a new name and address is proposed for merge instead of appearing as
  an unrelated new device. Candidates are still never applied automatically.
- Phase 2 needs a schema change (attachment observations) and a rewrite of
  the AP merge out of awk. It is deliberately not part of this change.
