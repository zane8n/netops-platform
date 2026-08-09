# Ghoster Path Inspector

`netops path inspect` reconstructs and validates the bounded path of an endpoint
on a VLAN. `netops ghoster` is an alias.

```bash
netops path inspect 02:00:00:00:00:25 --vlan 120
netops ghoster 192.0.2.25 --vlan 120 --from SITE-A-CORE-01 --explain
netops path inspect endpoint-25 --vlan 120 --cached
```

## Operating Modes

- Default hybrid mode plans from cached topology and then performs bounded,
  read-only live validation.
- `--cached` performs no live device reads.
- `--refresh` refreshes relevant evidence before assessment.
- `--depth` defaults to 8 and has a hard maximum of 16.
- `--max-nodes` defaults to 64 and has a hard maximum of 256.

## Evidence Model

The inspector resolves endpoint IP/MAC identity and attachment evidence, then
correlates forwarding-table learning, VLAN definition and membership, trunk and
native mode, LAG state, STP role, and neighbors at each Layer-2 hop. At a
Layer-3 boundary it reports SVI state, VRF, ARP/ND, route and next-hop evidence,
and attached interface policy references when the driver supports them.

ACL or policy references are not interpreted as a confirmed blocker unless a
supported parser provides that semantic evidence. Unsupported policy semantics
remain `UNKNOWN`.

## Results

- `COMPLETE`: the bounded evidence supports a continuous path.
- `BLOCKED`: a specific validated finding breaks the path.
- `PARTIAL`: a path is plausible but one or more hops could not be validated.
- `UNKNOWN`: the endpoint or path cannot be resolved from available evidence.

Output includes hop order, device/interface, Layer-2/Layer-3 role, state,
confidence, evidence age, RFC 3339 timestamps, and focused findings. Every run,
hop, and finding is stored chronologically:

```bash
netops path history
netops path show <run-id>
```

Ghoster is an evidence tool, not a packet capture or forwarding simulator.
Stale topology, asymmetric routing, tunnels, overlays, policy-based routing,
wireless/controller forwarding, and unsupported firmware can produce partial
results. Use `--explain` and inspect evidence age before acting.
