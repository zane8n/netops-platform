# NetOps Device Support and Extension Guide

## Purpose

This document defines what "device support" means in NetOps, how current
Cisco, Aruba, and RUCKUS support is implemented, and how another vendor or
device family must be added without scattering vendor conditionals throughout
the application.

It is normative for device detection, command generation, inventory ingest,
parser fixtures, and capability claims. The operator handbook remains the
command reference.

## Support vocabulary

- **Vendor** is the organization, such as Cisco, HPE Aruba Networking, or
  RUCKUS Networks.
- **Family** is the stable internal behavior key, such as `aruba-aos-cx` or
  `ruckus-fastiron`. Code and stored capability reports use family IDs, not
  display labels.
- **Driver** maps semantic operations such as `neighbors`, `mac_lookup`, or
  `cable_status` to vendor CLI commands.
- **Parser** converts untrusted command output into a vendor-neutral result.
- **Observation** is one time-stamped report from SNMP, SSH, ICMP, a controller,
  topology, or another provider.
- **Ingest** normalizes and merges observations without allowing sparse data to
  erase richer current data.
- **Capability** records a precise state such as `supported`,
  `firmware-gated`, `model-dependent`, `manual-confirmation`, `optics-only`,
  `reference-only`, `inventory-only`, `probe-only`, or `unsupported`.
- **Established** means a family has accepted automated fixtures and authorized
  field evidence. It does not mean every model and release produced by a vendor.
- **Broad read, field validation** means official command families are covered
  and synthetic fixtures pass, but representative sanitized output from every
  deployed firmware line is still required.

## Architecture

The supported data path is:

```text
public CLI/TUI/API action
  -> netops_platform/core.py policy and target resolution
  -> netops_platform/devices.py family detection and semantic command plan
  -> netops-control/netops-lib.sh SSH transport
  -> netops_platform/network.py pure parser
  -> netops_platform/inventory_ingest.py normalized observation merge
  -> SQLite current state, relationships, and append-only history
```

Ownership is deliberate:

| Module | Owns | Must not own |
|---|---|---|
| `netops_platform/devices.py` | Family detection, capability declarations, command templates, registration | SQLite, SSH credentials, result history |
| `netops_platform/network.py` | Pure output parsing and normalization | Network access, device writes |
| `netops_platform/inventory_ingest.py` | Compatibility-observation normalization, per-field merge, source union, scan commit contract | Vendor command syntax |
| `netops_platform/ingest.py` | Versioned channel delivery, provenance, quarantine, and current-state materialization | Vendor command syntax |
| `netops_platform/identity.py` | Alias normalization, physical identity conflicts, confidence evidence | Device transport |
| `netops_platform/core.py` | Public grammar, safety policy, orchestration, structured results, persistence | Ad hoc vendor command strings where a driver operation exists |
| Shell/Expect helpers | SNMP/SSH execution, compatibility transport, bounded legacy adapters | Public authorization policy |

Each profile receives a clone of the built-in `DeviceDriverRegistry`, then
loads its own declarative drivers. The registry accepts another driver without a core change. A
driver is data-oriented: a stable family ID, metadata, semantic command
templates, capability states, and notes. The `unknown` driver always exists and
fails closed for operations that require known syntax.

## Current families

| Family | Kind | Support level | Intended scope |
|---|---|---|---|
| `cisco-ios` | Switch | Established read | IOS and IOS-XE CLI read paths; model/firmware validation still applies |
| `cisco-nxos` | Switch | Built-in broad read | NX-OS/Nexus read paths, selected independently from IOS |
| `aruba-aos-switch` | Switch | Broad read, field validation | ProCurve and Aruba AOS-Switch generations |
| `aruba-aos-cx` | Switch | Broad read, field validation | Aruba CX platforms running AOS-CX |
| `ruckus-fastiron` | Switch | Broad read, field validation | Brocade/Foundry/RUCKUS ICX FastIron families |
| `ruckus-smartzone` | Controller | Inventory only | SmartZone/vSZ controller observations |
| `ruckus-ap` | Access point | Inventory only | RUCKUS AP inventory/controller observations |
| `unknown` | Unknown | Unclassified | Probe and evidence collection only |

### Capability matrix

| Capability | Cisco IOS/XE | Cisco NX-OS | Aruba AOS-S | Aruba AOS-CX | FastIron | SmartZone/AP |
|---|---|---|---|---|---|---|
| Inventory read | Supported | Supported | Supported | Supported | Supported | Inventory only |
| Configuration backup | Supported | Supported | Supported | Supported | Supported | Unsupported |
| VLAN definition/read | Supported | Supported | Supported | Supported | Supported | Unsupported |
| FDB/MAC table | Supported | Supported | Supported | Supported | Supported | Unsupported |
| ARP/ND and route reads | Supported | Supported | Supported, model-dependent VRF | Supported | Supported | Unsupported |
| LLDP | Supported | Supported | Supported | Supported | Supported | Unsupported |
| CDP | Supported | Supported | Unsupported | Unsupported | Unsupported | Unsupported |
| STP/LAG/SVI reads | Supported | Supported | Supported | Supported | Supported | Unsupported |
| Interface policy | Reference only | Reference only | Reference only | Reference only | Reference only | Unsupported |
| Interface health | Supported | Supported | Supported | Supported | Supported | Unsupported |
| Cable status | Supported | Optics only | Supported | Supported | Supported | Unsupported |
| Start cable test | Supported | Unsupported | Supported | Manual confirmation | Supported | Unsupported |
| Device-origin ping | Supported | Supported | Supported | Supported | Supported | Unsupported |
| Arbitrary configuration | Firmware/profile gated | Firmware/profile gated | Blocked | Blocked | Blocked | Blocked |
| VLAN write | Firmware/profile gated | Firmware/profile gated | Blocked | Blocked | Blocked | Blocked |

`netops device support` prints the registry. `netops device support <target>`
shows the target's detected family and exact capability values. A blocked
capability is a policy result, not a transport failure.

## Detection rules

Detection consumes platform, model, `sysDescr`, hostname, and optional device
kind evidence. Precedence prevents broad vendor words from hiding a specific
family:

1. RUCKUS SmartZone markers.
2. RUCKUS wireless/AP markers.
3. FastIron, Foundry, Brocade, RUCKUS ICX markers.
4. Explicit Aruba AOS-CX/CX platform markers.
5. Generic Aruba, ProCurve, or HPE switch markers, interpreted as AOS-S.
6. Cisco NX-OS/Nexus markers.
7. Cisco IOS/IOS-XE/Catalyst markers.
8. `unknown`.

Profile-local declarative drivers run before built-in signatures only when all
configured `[match]` evidence fields match. Their confidence is explicitly
declared and capped at 95. They cannot replace a built-in family.

Detection returns its confidence and reasons. It does not silently choose
Cisco for an unclassified device before a write. When a live read begins with
an unknown platform, NetOps may run `show version`, classify the output, and
then select a read plan. If classification still fails, vendor-specific
operations return unsupported.

## Semantic command plans

Callers request meanings rather than spelling commands:

```python
driver = driver_for(platform=row["platform"], model=row["model"])
commands = driver.command_plan("mac_lookup", mac="02:00:00:00:00:25")
```

Current semantic operations include:

- `inventory`
- `backup`
- `vlan_inspect`
- `vlan_locate`
- `arp_lookup`
- `mac_lookup`
- `core_lookup`
- `neighbors`
- `fdb`
- `vlan_membership`
- `stp`
- `lag`
- `svi`
- `vrf`
- `routes`
- `arp_nd`
- `interface_policy`
- `interface_health`
- `cable_status`
- `cable_start`
- `ping`
- `show`
- guarded `config`

The plan includes paging setup and logout. MAC formatting is selected by the
driver: Cisco dotted, AOS-S six-plus-six hyphen, AOS-CX colon, and FastIron
plain hexadecimal.

The public `lookup core` workflow now performs vendor-neutral ARP, forwarding
table, and interface-description stages using this registry. The compatibility
`netops-control core-lookup` entry point delegates back to that public workflow.

`netops path inspect` consumes the same semantic capability names. A read
command being present is not enough to claim a path blocker: the parsed evidence
must be time stamped and bound to the selected interface, VLAN, or endpoint.

## Parser contract

All device output is untrusted and version dependent. Parsers must:

1. Accept a complete raw string and have no network or filesystem side effect.
2. Return an explicit `parsed`/unknown state rather than inventing zero values.
3. Preserve a bounded raw line or excerpt for diagnosis.
4. Normalize interfaces and MAC addresses only for comparison; retain useful
   display forms.
5. Treat command errors, paging text, and banners as input cases.
6. Have sanitized fixtures for every promoted firmware family.

Current common parsers cover:

- Cisco CDP and LLDP detail;
- AOS-S LLDP summary;
- AOS-CX fixed-column LLDP output;
- Cisco, Aruba, and FastIron forwarding-table forms;
- Cisco/Unix/Aruba/FastIron ping summaries;
- Cisco, AOS-S, AOS-CX, and FastIron interface state/rates/errors;
- Cisco, Aruba, and FastIron cable-pair status;
- the stable NetOps VLAN helper report.

Synthetic output proves parser behavior, not a firmware support claim. A
family remains at broad-read validation until representative real output is
captured and accepted.

## Inventory ingest and updates

`netops-discovery` emits a normalized pipe record:

```text
ip|hostname|platform|model|serial|mac|source|last_seen|status
```

`netops_platform/inventory_ingest.py` is the compatibility merge boundary. It
applies these rules:

- A current meaningful SNMP hostname replaces an old hostname.
- Current status and poll time always replace the prior status/poll time.
- `N/A`, `unknown`, blank, and similar placeholders never erase model, serial,
  MAC, platform, or hostname.
- Sources are accumulated, for example `SSH+SNMP+ICMP`.
- A ping-responsive device with unavailable SNMP is recorded `ONLINE` from
  ICMP while retaining its last trusted inventory fields.
- A target absent from all current observations is recorded `OFFLINE` at the
  poll time.
- A new target is inserted as `first_seen`.

The resulting flat file is committed atomically under a lock, then imported
into SQLite. Derived identity, health, and relationship history records the
change. Operators can therefore distinguish current status, the latest poll,
and historical values.

## Hostname changes and identity confidence

Switch and AP observations retain aliases and addresses. Neutral separators and
role terms are normalized; deployment prefixes and rewrite rules come from the
selected profile. For example, configured rules may correlate
`SITE-A-BUILDING-1-AP190` with `SITEABUILDING1AP190`.

Candidate name thresholds are:

- AP: 85 percent.
- Switch: 75 percent.

These thresholds generate identity candidates. An automatic merge is allowed
when normalized identity is exact, or when a candidate is corroborated by a
matching valid MAC, serial, IP, AP attachment, or same role/asset number plus
model. Conflicting valid MACs, serials, or different AP/switch asset numbers
block a merge.

Reconciliation uses indexed candidate blocks for MAC, serial, IP, normalized
name, attachment, and role/model evidence. It does not compare every device or
AP with every other record. This preserves the evidence rules while keeping
inventory reads and post-ingest reconciliation bounded as the estate grows.

This distinction is intentional. Names such as neighboring `BUILDING-1` and `BUILDING-2`
switches can exceed 75 percent similarity but are not the same device. A name
threshold alone is not permitted to destroy history.

When a hostname changes on the same corroborated device:

- the latest meaningful hostname becomes current;
- the old name remains an alias in identity history;
- both old and new names resolve to the current canonical row;
- `device_alias` relationships retain chronological evidence;
- `netops device identity <old-or-first> <new-or-second>` explains signals,
  conflicts, threshold, and confidence.

Automatic reconciliation is applied by inventory/AP/topology imports and by
successful declarative ingest runs that materialize current device state.

For a verified hardware replacement that intentionally has conflicting MAC or
serial evidence, use the guarded lifecycle workflow:

```bash
netops inventory merge OLD-SW01 CURRENT-SW01 \
  --reason "approved hardware replacement" --dry-run
netops inventory merge OLD-SW01 CURRENT-SW01 \
  --reason "approved hardware replacement" --confirm
netops inventory merges
```

The source leaves active inventory but remains chronological history and a
historical alias of the target. Matching stale observations are suppressed on
later refreshes. `inventory unmerge <merge-id> --reason TEXT --confirm` is the
audited rollback and refuses restoration if another device owns the old IP.

## Multi-root, multi-VLAN scans

Both locate and propagation accept one or many roots and VLANs:

```bash
netops vlan locate SW1 131
netops vlan locate SW1 10,20-22 --depth 3
netops vlan propagation SW1,SW2 10,20 --depth 5
netops vlan propagation --target SW1 --target SW2 --vlan 10,20-22 --depth 5
```

Limits are 16 roots, 128 distinct VLANs, depth 10, and 256 nodes per
root/VLAN traversal. The result is a root-by-VLAN matrix plus per-run nodes,
edges, findings, completeness, health, and timestamps. Each cell independently
performs bounded breadth-first traversal; results are not reused across VLANs
because the carried-VLAN state differs.

Live progress goes to stderr. The final table/JSON remains readable on stdout.
Root is layer 0; depth is the maximum number of switch-link hops.

## Online MAC registration lookup

`netops lookup mac online <mac>` queries a private local cache of the official
IEEE Registration Authority public MA-L, MA-M, and MA-S CSV registries. Longest
prefix wins, so a 36-bit MA-S assignment is preferred over a matching 28-bit or
24-bit assignment.

```bash
netops lookup mac registry status
netops lookup mac registry refresh
netops lookup mac online 00:00:5e:00:53:01
netops lookup mac online 00:00:5e:00:53:01 --refresh
netops lookup mac online 00:00:5e:00:53:01 --offline
netops lookup mac vendor 00:00:5e:00:53:01 --online
```

The cache is mode `0700`; files and manifest are mode `0600`. Downloads are
size bounded, UTF-8 CSV schema validated, atomically replaced, hashed with
SHA-256, and time stamped in ISO 8601 UTC. If refresh fails, an existing stale
cache remains usable and the result identifies the refresh error.

IEEE assignment data identifies the registered organization and block. It
does not identify an exact model. Locally administered/randomized addresses
have no authoritative manufacturer assignment and are reported as such.

## Legacy SSH compatibility

`netops device ssh --legacy <target>` does not enable a fixed blind bundle. It
asks the installed OpenSSH client which KEX, host-key, cipher, and MAC
algorithms still exist, then appends only supported legacy algorithms while
preserving modern defaults. The same filtered options are passed to generic
SSH and the prompt-aware Aruba/RUCKUS Expect wrapper.

Negotiation failures are classified as KEX, host key, cipher, MAC, generic
negotiation, SSHv1, authentication, or host-trust failure. Offered algorithms
are displayed when OpenSSH provides them. SSHv1 is never enabled.

## Adding another family

For a local read-only family, start with
`examples/drivers/example-switch.toml`. The manifest must declare at least one
`[match]` pattern, parser IDs, semantic commands, and capability states. NetOps
rejects control characters, shell metacharacters, unknown read prefixes,
configuration entry, save/reload/erase, duplicate families, and all write
claims. Profile-local manifests are suitable for operator customization but do
not become an advertised built-in support claim.

For a built-in or packaged Python driver:

1. Choose a stable lowercase family ID. Do not encode a transient firmware
   patch in the family name.
2. Add narrow, ordered detection evidence and tests that prove it does not
   steal another family's devices.
3. Register a `DeviceDriver` with display metadata, support level, pager,
   logout, semantic templates, capabilities, and explicit limitations.
4. Start every write capability as unsupported.
5. Add normalized platform labeling in
   `netops_platform/inventory_ingest.py`.
6. Add pure parser fixtures for each output shape. Include malformed, wrapped,
   paged, empty, denied, and timeout examples.
7. Add command-plan tests for every claimed capability and MAC/interface form.
8. Add a source-only integration test proving the public core selects the new
   driver without a vendor conditional.
9. Capture sanitized output from representative deployed models and releases.
10. Run authorized read-only lab acceptance, then update the support level.
11. Design preview, preflight, backup, apply, exact verification, rollback, and
    audit before proposing any write capability.
12. Update this matrix, the handbook, changelog, and maturity roadmap.

## Compatibility evidence baseline

The implementation was checked against primary vendor references:

- [IEEE Registration Authority public listings](https://standards.ieee.org/products-programs/regauth/)
- [Aruba AOS-S `show mac-address`](https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MCG/YC/content/common%20files/vie-mac-add-con-dev.htm)
- [Aruba AOS-S LLDP remote-device output](https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MCG/KB/content/kb/sho-lld-inf-rem-dev.htm)
- [Aruba AOS-S cable diagnostics](https://arubanetworking.hpe.com/techdocs/AOS-S/16.10/MCG/KB/content/kb/cab-dia.htm)
- [Aruba AOS-CX `show interface`](https://arubanetworking.hpe.com/techdocs/AOS-CX/AOSCX-CLI-Bank/cli_832x/Content/Chp_IfaceCfg/Iface_cmds/sho-int-10.htm)
- [Aruba AOS-CX LLDP neighbor information](https://arubanetworking.hpe.com/techdocs/AOS-CX/10.13/HTML/fundamentals_4100i-6000-6100/Content/Chp_Dev_disc/LLDP_cmds/sho-lld-nei-inf-10.htm)
- [RUCKUS FastIron 10.0.20 command reference](https://support.ruckuswireless.com/documents/4694-fastiron-10-0-20-ga-command-reference-guide)
- [OpenSSH legacy options guidance](https://www.openssh.org/legacy.html)

Official documentation establishes command families and release intent. Only
accepted real-output fixtures establish NetOps parser compatibility with a
specific deployed firmware build.
