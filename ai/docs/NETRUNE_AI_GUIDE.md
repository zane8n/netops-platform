# Netrune AI Guide

## Purpose
Netrune AI is a separate local assistant layer for retrieving facts and preparing operations safely. It translates user intent into approved workflows, invokes only the public `netrune` command, and treats the core Ask engine as authoritative for broad retrieval and command planning.

This AI layer is separate from the Netrune toolset:

- it lives under `ai/`;
- it does not import or patch `netrune.core` or its `netrune_core.py`
  compatibility alias;
- it does not call `netrune-control`, `netrune-discovery`, `netrune-probe`, `netrune-connect`, or `netrune-legacy` directly;
- it executes only approved wrapper workflows from `ai/config/tools.yaml`;
- it never executes the command plan returned by `netrune ask`;
- it may read Netrune data, logs, inventory, and output only through approved read-only workflows or explicit RAG indexing.

## Core rule
The assistant must never invent network status. Network facts must come from one of these sources:

- live Netrune command output;
- verified saved Netrune result files;
- inventory files;
- approved logs/history files;
- retrieved documentation that explains workflow behavior, not live status.

If the tool output is missing, failed, stale, or unparseable, say that directly.

## Native state model
Treat the public Netrune state engine as the assistant's source of truth for current and historical knowledge. The assistant should know how to query, summarize, and cross-reference:

- canonical device and AP inventory, including names, IPs, MACs, platform/model, serials where present, status, aliases, and last-seen timestamps;
- LLDP/CDP topology neighbor rows and topology change events;
- relationship memory, including AP attachments, port occupancy, IP/MAC identity ownership, neighbor links, and core lookup observations;
- relationship confidence scores, source names, first-seen/last-seen timestamps, and current relationship status;
- inventory history, identity history, health history, AP move history, backup history, diagnostic history, and relationship timelines.

The model should not memorize these facts in its prompt. It should retrieve them through approved workflows every time, so answers reflect current Netrune state.

## Public Netrune boundary
Use the audited v8.5 public interface:

```text
netrune <domain> <action> [arguments] [global flags]
```

Do not run helper binaries directly from the AI layer. The handbook explicitly marks helper commands as internal or dangerous when called outside the public boundary.

## Assistant entry point
Use `netrune ai "<question>"` for one request or `netrune ai` for an interactive session. The launcher delegates directly to the separate `ai/` layer before the Netrune core starts.

The default fast router selects configured wrapper workflows and does not load Ollama. Broad retrieval and command language is sent to `answer_from_netrune_state`; narrow live interface/VLAN summaries retain dedicated show workflows. Use `--ollama-select` only when model-assisted selection is needed and a local model is installed.

## Authoritative Ask command center
The broad workflow executes:

```bash
netrune --json ask <question>
```

For retrieval, preserve the answer, evidence rows, source workflow, and ISO timestamp companions. For operations, preserve every `command_plan` field: action, arguments, exact preview, status, missing inputs, risk/safety class, state effects, confirmation requirement, restriction reason, and execution hint.

The statuses are hard boundaries:

- `ready`: core validation passed; a separate CLI/WebUI action is still required;
- `needs_clarification`: ask for the listed fields;
- `preview_only`: report the preview/restriction and do not execute;
- `blocked`: report the validation failure and do not suggest bypassing it.

The wrapper must explicitly state that it prepared the plan and did not execute it.

### Bounded network-operation plans

The core planner recognizes recursive VLAN propagation/location, core-origin point-of-truth ping, and MAC inspect/locate/profile/history/vendor language. Preserve explicit bounds such as `depth`, `max_nodes`, `count`, switch scope, and `refresh_neighbors` in the rendered preview.

Examples:

```text
Check VLAN propagation from site-a-core for VLAN 131 to depth 5
Point-of-truth ping 192.0.2.50 from core CORE01 five times
Profile MAC 02:00:00:00:00:25 at ZONE34
Show the history of MAC 02:00:00:00:00:25
```

Do not route propagation, locate, trunk, uplink, cascade, or depth language to the narrow `show vlan brief` workflow. Those requests require the registry-backed core plan. Do not claim that a MAC forwarding-table hit proves current power or that an OUI identifies an exact model.

## Device aliases
Start with these operator aliases. Keep this list synchronized with `ai/config/aliases.yaml`.

- site-a-core switch = `SITE-A-SITE-A-CORE-SW01`
- site-a-core = `SITE-A-SITE-A-CORE-SW01`
- dmz switch = `SITEADMZSW02`
- dmz = `SITEADMZSW02`

## Available workflows

### get_down_interfaces
Use when the user asks:

- which interfaces are down;
- what ports are offline;
- check down ports;
- interface status for a switch with down/offline wording.

Input:

- switch name or alias.

Approved command:

```bash
netrune device show <switch> "show interface status"
```

Output meaning:

- interface: port name;
- description: connected device, user, circuit, or location label if present;
- status: operational state parsed from the command output;
- vlan: assigned VLAN if available.

Response format:

- summarize the count of down/non-active interfaces;
- render a table with interface, description, VLAN, and status;
- mention parser uncertainty if the output did not match a known interface-status table.

Down/non-active statuses include `down`, `notconnect`, `disabled`, `err-disabled`, `inactive`, and `suspended`.

### get_interface_summary
Use when the user asks:

- show interfaces;
- interface summary;
- port status;
- switch port overview.

Approved command:

```bash
netrune device show <switch> "show interface status"
```

Response format:

- summarize parsed interface rows;
- render a table with interface, description, VLAN, status, speed, and type where available.

### get_vlan_summary
Use when the user asks:

- show VLANs on a switch;
- VLAN summary;
- what VLANs exist on a switch.

Approved command:

```bash
netrune device show <switch> "show vlan brief"
```

Response format:

- summarize the raw Netrune output unless a parser is later added;
- do not infer VLAN propagation from this workflow.

### get_device_details
Use when the user asks:

- what is the IP/model/serial/status of a device;
- show details for a switch;
- tell me about a device.

Approved command:

```bash
netrune inventory details <switch> --json
```

Response format:

- summarize the current inventory record and any health/history facts returned by Netrune.

### get_health_offline
Use when the user asks:

- what is offline;
- current outages;
- down devices or APs generally.

Approved command:

```bash
netrune health offline --json
```

Response format:

- summarize offline records returned by Netrune;
- include timestamps only when present in the data.

### get_aps_on_switch
Use when the user asks:

- which APs are on a switch;
- APs attached to a switch;
- wireless units connected to a switch.

Approved command:

```bash
netrune ap list <switch> --json
```

Response format:

- summarize AP rows and attachment fields;
- warn when the source does not prove physical cabling.

### get_topology_neighbors
Use when the user asks:

- neighbors of a switch;
- LLDP/CDP neighbors;
- what is connected upstream/downstream.

Approved command:

```bash
netrune topology show <switch> --json
```

Response format:

- summarize neighbor rows and source protocol if returned.

### get_memory_switch
Use when the user asks:

- switch summary;
- what do we know about a switch;
- memory/context for a switch.

Approved command:

```bash
netrune memory switch <switch> --json
```

Response format:

- summarize AP, neighbor, relationship, and timeline records returned by Netrune.

### get_relationship_confidence
Use when the user asks:

- what confidence scores exist for a target;
- what sources support a relationship;
- explain lookup or relationship confidence.

Approved command:

```bash
netrune --json memory explain <target>
```

Response format:

- summarize relationship type, source, count, and average confidence;
- do not upgrade confidence beyond the value returned by Netrune.

### get_relationship_timeline
Use when the user asks:

- relationship history for a target;
- timeline of an IP, MAC, switch, AP, or port relationship;
- previous relationship state or movement.

Approved command:

```bash
netrune --json memory timeline <target>
```

Response format:

- summarize event type, relationship type, subject/object, source, confidence, detail, and timestamp;
- preserve `disappeared`, `changed`, and `first_seen` semantics from Netrune.

### answer_from_netrune_state
Use when the user asks a broad state question or requests any operation/command plan, especially questions about:

- device/AP inventory lists, IPs, MACs, aliases, platform/model, health, and last-seen values;
- topology connections, topology changes, AP moves, or relationship timelines;
- lookup confidence scores, relationship sources, and evidence provenance;
- memory, inventory history, identity history, health history, backup history, or diagnostic history.
- scans, refreshes, probes, speed/filtering/interface diagnostics, backups, lookups, workflows, database maintenance, SSH/show requests, VLAN operations, or configuration previews.
- bounded VLAN cascades, core-origin pings, and MAC evidence/location/profile/history requests.

Approved command:

```bash
netrune --json ask <question>
```

Response format:

- lead with the deterministic `answer` returned by Netrune;
- include evidence rows when returned, preserving confidence/source/history fields;
- if Netrune marks the question ambiguous or unresolved, ask for the specific clarification instead of guessing.
- for `command_plan`, render the exact preview and execution boundary; never run the hinted command from the AI wrapper.

## Clarification rules
Ask for clarification only when:

- switch name cannot be resolved;
- multiple devices match the alias or target;
- the requested workflow is not in `ai/config/tools.yaml`;
- the returned command plan lists missing arguments or ambiguity.

## Safety rules
Allowed:

- show/query/read commands through the public `netrune` v7 interface;
- parsing previous result files;
- summarizing logs and history;
- indexing documentation and approved result directories for retrieval.
- displaying registry-backed command and configuration dry-run plans produced by core Ask.

Not allowed without explicit human confirmation and a separate change workflow:

- configuration changes;
- `shutdown` or `no shutdown`;
- VLAN changes;
- deleting files;
- credential changes;
- direct helper execution that bypasses v7 policy gates.

The current AI wrapper intentionally blocks plan execution and config-changing workflows entirely. Core Ask may describe a safe dry-run, but only the guarded CLI/WebUI boundary can execute supported non-config plans.

## Retrieval/RAG scope
Index documentation and data sources separately from the permanent model prompt. Suggested local index inputs:

```text
ai/docs/NETRUNE_AI_GUIDE.md
docs/NETRUNE_TOOLSET_HANDBOOK.md
*.py
*.sh
*.yaml
results/
logs/
inventory/
README.md
```

RAG output may explain which workflow to run or where definitions live. RAG output alone is not live network truth unless it is a verified saved result.
