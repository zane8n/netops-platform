"""Which switch port each AP is on, read from the switches' own CDP/LLDP tables.

`ap scan` learns attachments from SNMP walks of LLDP-MIB and CISCO-CDP-MIB.
That path has two weak spots: lldpRemTable is indexed by LLDP's local port
number, which is not always the ifIndex it is resolved through, and CDP over
SNMP carries no MAC, so a CDP-found AP cannot be joined to the controller's
record of it. The switch CLI has neither problem: `show cdp neighbors detail`
and `show lldp neighbors detail` (Cisco), or `show lldp info remote-device`
and `show cdp neighbors detail` (Aruba AOS-S), name the local port as the
operator would type it and carry the AP's own name, address, platform, and
capabilities.

A free-function module with one caller boundary (`App.cmd_ap`): read every
chosen switch in parallel over one SSH login each, decide which neighbours
are APs, then record the attachments on the main thread through the same
flat-file import `ap scan` uses, so AP moves and observations are derived
exactly as they are for a scan.
"""

from __future__ import annotations

import concurrent.futures
import re
import threading
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from netops_platform.devices import ap_model, is_switch_row
from netops_platform.identity import _host_label, name_key, normalize_mac
from netops_platform.network import normalize_interface, parse_neighbor_detail_output


USAGE = "netrune ap neighbors (<switch>[,<switch>...] | --all) [--dry-run]"
MAX_DETAIL_PORTS = 64
# A port's MAC table can come back empty when the AP has been quiet. The
# first login reads the whole table; for an AP port still empty, Netrune
# pings the AP from this host (its reply crosses that port, so the switch
# learns the MAC again) and re-reads just those ports, at most this many times.
MAC_CHECK_ROUNDS = 2
MAC_CHECK_PAUSE = 1.0
FULL_TABLE_COMMANDS = {
    "cisco-ios": "show mac address-table", "cisco-nxos": "show mac address-table",
    "aruba-aos-switch": "show mac-address", "aruba-aos-cx": "show mac-address-table", "ruckus-fastiron": "show mac-address",
}
# Where the port sits on a MAC-table line: last (Cisco, NX-OS, AOS-CX) or
# straight after the MAC (AOS-S, FastIron).
PORT_AFTER_MAC = {"aruba-aos-switch", "ruckus-fastiron"}
PORT_MAC_COMMANDS = {
    "cisco-ios": "show mac address-table interface {interface}",
    "cisco-nxos": "show mac address-table interface {interface}",
    "aruba-aos-switch": "show mac-address {interface}",
    "aruba-aos-cx": "show mac-address-table port {interface}",
    "ruckus-fastiron": "show mac-address ethernet {interface}",
}
_MAC_TOKEN = re.compile(r"\b(?:[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}|(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})\b")

_SHORT_PORTS = (
    ("twentyfivegigabitethernet", "Twe"), ("fortygigabitethernet", "Fo"), ("hundredgigabitethernet", "Hu"),
    ("tengigabitethernet", "Te"), ("gigabitethernet", "Gi"), ("fastethernet", "Fa"),
)
_AP_BANNER = re.compile(r"\bAP Software\b|Wireless AP|Aironet|Access Point|\bUAP\b|Multimedia Hotzone|\bAP\d{3,4}\b", re.I)
_PHONE = re.compile(r"\bphone\b|\btelephone\b", re.I)


def short_port(value: Any) -> str:
    """GigabitEthernet1/0/5 -> Gi1/0/5, the form the inventory already holds."""
    text = str(value or "").strip()
    lowered = text.lower()
    for long_name, short in _SHORT_PORTS:
        if lowered.startswith(long_name):
            return short + text[len(long_name):]
    return text


def neighbor_commands(family: str, templates: Mapping[str, Sequence[str]]) -> List[str]:
    """The switch-wide neighbour reads for one driver family, in one batch."""
    if family in {"cisco-ios", "cisco-nxos"}:
        return ["show cdp neighbors detail", "show lldp neighbors detail"]
    if family == "aruba-aos-switch":
        return ["show lldp info remote-device", "show cdp neighbors detail"]
    return list(templates.get("neighbors") or ())


def wlan_capable(capabilities: Any) -> bool:
    text = str(capabilities or "")
    return bool(re.search(r"wlan|\bW\b", text, re.I))


def classify(record: Mapping[str, Any], switches: Mapping[str, str]) -> Tuple[bool, str]:
    """Is this neighbour an AP? Returns (verdict, the evidence it rests on).

    Not an AP: a switch Netrune already knows (by address, name, or MAC), or
    one describing itself as a switch without the WLAN capability; a phone.
    An AP: the WLAN-access-point capability, an AP model number, or an AP
    software banner in its platform/description.
    """
    name = _host_label(record.get("remote_name") or "").lower()
    keys = [str(record.get("remote_ip") or ""), name, normalize_mac(record.get("remote_mac"))]
    for key in keys:
        if key and key in switches:
            return False, f"known switch {switches[key]}"
    platform = str(record.get("platform") or "")
    wlan = wlan_capable(record.get("capabilities"))
    if _PHONE.search(platform) and not wlan:
        return False, "phone"
    if is_switch_row({"platform": platform}) and not wlan:
        return False, "describes itself as a switch"
    if wlan:
        return True, "WLAN capability"
    model = ap_model(platform)
    if model:
        return True, f"AP model {model}"
    if _AP_BANNER.search(platform):
        return True, "AP platform text"
    return False, "no AP evidence"


def port_macs(output: Any) -> List[str]:
    """Every MAC address a port's MAC-table output lists."""
    return sorted({normalize_mac(token) for token in _MAC_TOKEN.findall(str(output or "")) if normalize_mac(token)})


def table_port_macs(output: Any, family: str) -> Dict[str, List[str]]:
    """A whole MAC table as {normalized port: [MACs]}."""
    ports: Dict[str, set] = {}
    for line in str(output or "").splitlines():
        match = _MAC_TOKEN.search(line)
        if not match:
            continue
        rest = line[match.end():].split()
        tokens = line.split()
        port = (rest[0] if rest else "") if family in PORT_AFTER_MAC else (tokens[-1] if tokens else "")
        key = normalize_interface(port)
        if key and key != normalize_interface(match.group(0)):
            ports.setdefault(key, set()).add(normalize_mac(match.group(0)))
    return {port: sorted(macs) for port, macs in ports.items()}


SAME_HARDWARE_SPAN = 64


def same_hardware(left: str, right: str) -> bool:
    """One AP's MACs (Ethernet, radios, BSSIDs) sit within a few dozen
    addresses of each other; other APs from the same batch share the prefix
    but not the neighbourhood."""
    try:
        return abs(int(left, 16) - int(right, 16)) <= SAME_HARDWARE_SPAN
    except (TypeError, ValueError):
        return False


def locally_administered(mac: str) -> bool:
    """A randomized client MAC (phones and laptops): the second hex digit is 2, 6, A, or E."""
    return len(mac) == 12 and mac[1].lower() in "26ae"


def _ping_from_here(addresses: Sequence[str]) -> None:
    import subprocess
    def one(address: str) -> None:
        try:
            subprocess.run(["ping", "-c", "2", "-i", "0.3", "-W", "1", address], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=6)
        except (OSError, subprocess.TimeoutExpired):
            pass
    addresses = [address for address in dict.fromkeys(addresses) if address]
    if addresses:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(addresses))) as pool:
            list(pool.map(one, addresses))


def verify_on_ports(app: Any, target: str, family: str, ports: Sequence[str], timeout: int,
                    *, rounds: Optional[int] = None, pause: Optional[float] = None,
                    found: Optional[Dict[str, List[str]]] = None,
                    push: Optional[Mapping[str, Sequence[str]]] = None,
                    expect: Optional[Mapping[str, Sequence[str]]] = None) -> Dict[str, List[str]]:
    """The MACs each port's table lists, asking again for ports not yet satisfied.

    `found` is what the whole-table read already gave; `push` maps a port to
    the AP addresses to ping from here before asking again; `expect` maps a
    port to the AP's own MACs, so a port showing only other MACs is asked
    again too (the AP's own entry may have aged out). MACs seen in any read
    are kept.
    """
    def satisfied(port: str) -> bool:
        wanted = [mac for mac in (expect or {}).get(port, ()) if mac]
        if not wanted:
            return bool(result[port])
        return any(same_hardware(mac, seen) for mac in wanted for seen in result[port])
    import time
    rounds = MAC_CHECK_ROUNDS if rounds is None else rounds
    pause = MAC_CHECK_PAUSE if pause is None else pause
    template = PORT_MAC_COMMANDS.get(family, "")
    result: Dict[str, List[str]] = {port: list((found or {}).get(port) or []) for port in ports}
    if not template:
        return result
    pending = [port for port in ports if not satisfied(port)] if found is not None else list(ports)
    for attempt in range(rounds):
        if not pending:
            break
        if push:
            _ping_from_here([address for port in pending for address in push.get(port, ())])
        if attempt or push:
            time.sleep(pause)
        commands = [template.format(interface=port) for port in pending]
        for port, (_, output) in zip(pending, app.capture_batch(target, commands, timeout)):
            result[port] = sorted(set(result[port]) | set(port_macs(output)))
        pending = [port for port in pending if not satisfied(port)]
    return result


def read_switch(app: Any, device: Mapping[str, Any], timeout: int, switches: Optional[Mapping[str, str]] = None,
                ap_addresses: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """One switch's neighbour records, or the error that stopped the read.

    Each record that classifies as an AP is then checked against the MAC
    table of the port it was read on (`port_macs` on the record).
    """
    target = str(device.get("ip") or "")
    driver = app.driver_for(platform=device.get("platform"), model=device.get("model"), hostname=device.get("hostname"))
    commands = neighbor_commands(driver.family, driver.command_templates)
    result = {"switch_ip": target, "switch_name": _host_label(device.get("hostname") or device.get("name") or target),
              "family": driver.family, "records": [], "error": ""}
    if not commands:
        result["error"] = f"no neighbour command for {driver.family}"
        return result
    # The whole MAC table rides along in the first login, so most AP ports
    # are checked without another one.
    table_command = FULL_TABLE_COMMANDS.get(driver.family, "")
    outputs = dict(app.capture_batch(target, commands + ([table_command] if table_command else []), timeout))
    table = table_port_macs(outputs.get(table_command, ""), driver.family) if table_command else None
    records: List[Dict[str, Any]] = []
    for command in commands:
        records.extend(parse_neighbor_detail_output(outputs.get(command, "")))
    if driver.family == "aruba-aos-switch":
        # The AOS-S LLDP summary has no capabilities or address; read the
        # detail for the ports it listed, in one more login.
        template = (driver.command_templates.get("neighbor_detail") or ("",))[0]
        ports = sorted({str(row["local_port"]) for row in records if row.get("protocol") == "lldp"
                        and re.fullmatch(r"[A-Za-z]?\d{1,3}(?:/\d{1,3})?", str(row.get("local_port") or ""))})[:MAX_DETAIL_PORTS]
        if template and ports:
            detail_commands = [template.format(interface=port) for port in ports]
            for _, output in app.capture_batch(target, detail_commands, timeout):
                records.extend(parse_neighbor_detail_output(output))
    if not records and not any(str(text).strip() for text in outputs.values()):
        result["error"] = "no output (login failed or timed out)"
    # Detail beats summary for the same port and neighbour.
    merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for record in records:
        key = (normalize_interface(record.get("local_port")), _host_label(record.get("remote_name") or "").lower() or str(record.get("remote_ip") or ""))
        current = merged.setdefault(key, dict(record))
        for field_name, value in record.items():
            if value and not current.get(field_name):
                current[field_name] = value
    result["records"] = list(merged.values())
    ap_ports = sorted({str(record.get("local_port") or "") for record in result["records"]
                       if record.get("local_port") and classify(record, switches or {})[0]})
    if ap_ports:
        ap_records = [record for record in result["records"] if str(record.get("local_port") or "") in ap_ports]
        push: Dict[str, List[str]] = {}
        expect: Dict[str, List[str]] = {}
        for record in ap_records:
            if normalize_mac(record.get("remote_mac")):
                expect.setdefault(str(record["local_port"]), []).append(normalize_mac(record.get("remote_mac")))
            address = str(record.get("remote_ip") or "") or (ap_addresses or {}).get(name_key(record.get("remote_name")), "") \
                or (ap_addresses or {}).get(normalize_mac(record.get("remote_mac")), "")
            if address:
                push.setdefault(str(record["local_port"]), []).append(address)
        found = None if table is None else {port: table.get(normalize_interface(port), []) for port in ap_ports}
        macs = verify_on_ports(app, target, driver.family, ap_ports, timeout, found=found, push=push, expect=expect)
        for record in result["records"]:
            if str(record.get("local_port") or "") in macs:
                record["port_macs"] = macs[str(record["local_port"])]
    return result


def mac_verdict(entry: Mapping[str, Any], known_macs: Sequence[str], port_mac_list: Optional[Sequence[str]]) -> Tuple[str, str]:
    """(verdict, MAC learned from the port) for one AP reading.

    confirmed: the AP's MAC is in its port's table. learned: Netrune had no
    MAC for it and the port holds exactly one. elsewhere: the port lists
    other MACs only (an unmanaged switch below, or a radio/Ethernet MAC
    mismatch). clients: only randomized client MACs, i.e. wireless clients the
    AP bridges on this port. empty: the table stayed empty after every retry.
    The AP's own MAC counts within SAME_HARDWARE_SPAN (its radio MACs).
    """
    if port_mac_list is None:
        return "not checked", ""
    if not port_mac_list:
        return "empty", ""
    known = {mac for mac in known_macs if mac}
    if any(same_hardware(mac, seen) for mac in known for seen in port_mac_list):
        return "confirmed", ""
    hardware = [mac for mac in port_mac_list if not locally_administered(mac)]
    if not known and len(hardware) == 1:
        return "learned", hardware[0]
    if not hardware:
        # Only randomized client MACs: wireless clients bridged by the AP on
        # this port. They support the attachment; the AP's own entry aged out.
        return "clients", ""
    return "elsewhere", ""


def _ap_index(rows: Sequence[Mapping[str, Any]]) -> Dict[str, Dict[str, List[Mapping[str, Any]]]]:
    index: Dict[str, Dict[str, List[Mapping[str, Any]]]] = {"mac": {}, "name": {}, "ip": {}}
    for row in rows:
        mac = normalize_mac(row.get("mac"))
        if mac:
            index["mac"].setdefault(mac, []).append(row)
        name = name_key(row.get("name"))
        if name and not normalize_mac(row.get("name")):
            index["name"].setdefault(name, []).append(row)
        if row.get("ip"):
            index["ip"].setdefault(str(row["ip"]), []).append(row)
    return index


def plan_attachments(reads: Sequence[Mapping[str, Any]], ap_rows: Sequence[Mapping[str, Any]],
                     switches: Mapping[str, str]) -> Dict[str, Any]:
    """What the reads say about each AP: updates, new APs, and records left out."""
    index = _ap_index([row for row in ap_rows if not is_switch_row(row)])
    seen: Dict[str, Dict[str, Any]] = {}
    found: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    for read in reads:
        for record in read.get("records") or []:
            verdict, evidence = classify(record, switches)
            name = _host_label(record.get("remote_name") or "")
            entry = {"switch_ip": read["switch_ip"], "switch_name": read["switch_name"],
                     "switch_port": short_port(record.get("local_port")), "name": name,
                     "ip": str(record.get("remote_ip") or ""), "mac": normalize_mac(record.get("remote_mac")),
                     "platform": str(record.get("platform") or "")[:160], "protocol": record.get("protocol") or "",
                     "evidence": evidence, "port_macs": record.get("port_macs")}
            if not verdict:
                if evidence not in {"no AP evidence"} and not evidence.startswith("known switch"):
                    skipped.append(entry)
                continue
            matches: List[Mapping[str, Any]] = []
            matched_by = ""
            for kind, value in (("mac", entry["mac"]), ("name", name_key(name)), ("ip", entry["ip"])):
                if value and index[kind].get(value):
                    matches, matched_by = index[kind][value], kind
                    break
            entry["matched_by"] = matched_by
            known_macs = [entry["mac"], *(normalize_mac(row.get("mac")) for row in matches)]
            entry["mac_check"], learned = mac_verdict(entry, known_macs, entry.get("port_macs"))
            if learned:
                entry["mac"] = learned
            if matches and matched_by != "name" and name and name_key(matches[0].get("name")) not in {"", name_key(name)}:
                entry["mac_check"] += f"; named {matches[0].get('name')} on the controller"
            key = str(matches[0].get("ip")) if matches else (entry["ip"] or f"{name}@{entry['switch_ip']}")
            if key in seen and (seen[key]["switch_ip"], seen[key]["switch_port"]) != (entry["switch_ip"], entry["switch_port"]):
                # One AP on two switches: keep the CDP/LLDP reading that names
                # it by MAC, else the first, and say so.
                seen[key].setdefault("also_on", []).append(f"{entry['switch_name']} {entry['switch_port']}")
                continue
            entry["rows"] = list(matches)
            seen[key] = entry
            found.append(entry)
    updates, new, unchanged = [], [], []
    for entry in found:
        if entry["rows"]:
            row = entry["rows"][0]
            before = (str(row.get("switch_ip") or ""), normalize_interface(row.get("switch_port")))
            after = (entry["switch_ip"], normalize_interface(entry["switch_port"]))
            entry["previous"] = f"{row.get('switch_name') or row.get('switch_ip') or '-'} {row.get('switch_port') or ''}".strip()
            entry["ap"] = str(row.get("name") or entry["name"])
            (unchanged if before == after else updates).append(entry)
        elif entry["ip"]:
            entry["ap"], entry["previous"] = entry["name"] or entry["ip"], "not in inventory"
            new.append(entry)
        else:
            entry["ap"], entry["previous"] = entry["name"], "not in inventory, no address"
            skipped.append({**entry, "evidence": "AP without a management address"})
    return {"updates": updates, "new": new, "unchanged": unchanged, "skipped": skipped}


def record(app: Any, plan: Mapping[str, Any], observed_at: int) -> int:
    """Write the attachments and re-import, so moves and observations follow as for `ap scan`."""
    written = 0
    for entry in list(plan["updates"]) + list(plan["unchanged"]):
        for row in entry["rows"]:
            app.state.execute("UPDATE aps SET switch_ip=?,switch_name=?,switch_port=?,last_seen=?,status='ONLINE',"
                              "mac=CASE WHEN COALESCE(mac,'')='' THEN ? ELSE mac END "
                              "WHERE ip=? AND COALESCE(name,'')=?",
                              (entry["switch_ip"], entry["switch_name"], entry["switch_port"], observed_at,
                               entry["mac"] or "", row.get("ip"), row.get("name") or ""))
            written += 1
    for entry in plan["new"]:
        app.state.execute("INSERT OR IGNORE INTO aps(ip,name,platform,switch_ip,switch_name,switch_port,mac,last_seen,status) "
                          "VALUES(?,?,?,?,?,?,?,?,'ONLINE')",
                          (entry["ip"], entry["name"], entry["platform"], entry["switch_ip"], entry["switch_name"],
                           entry["switch_port"], entry["mac"], observed_at))
        written += 1
    # What the switch itself confirmed survives the next `ap scan`: its merge
    # keeps these ports over an SNMP reading of the same switch (ap_merge).
    from netops_platform.ap_merge import write_attachments
    found = list(plan["updates"]) + list(plan["unchanged"]) + list(plan["new"])
    write_attachments(app.paths.aps_file.with_name("ap_attachments.db"), [
        {"mac": entry.get("mac") or "", "name": entry.get("ap") or entry.get("name") or "", "ip": entry.get("ip") or "",
         "switch_ip": entry["switch_ip"], "switch_name": entry["switch_name"], "switch_port": entry["switch_port"],
         "verdict": str(entry.get("mac_check") or "").split(";")[0], "observed_at": str(observed_at)}
        for entry in found])
    if written:
        app.state.export_flat_files()
        app.import_flat_state(("ap",), "ssh-lldp-cdp-scan")
    return written


def run(app: Any, args: List[str], opts: Any) -> int:
    from netops_platform.core import GlobalOptions, PARTIAL, SUCCESS, VALIDATION, now
    switches_rows = [row for row in app.inventory_rows("", GlobalOptions(limit=1_000_000)) if row.get("kind") == "device"]
    wanted = [item.strip() for part in args for item in part.split(",") if item.strip()]
    if not wanted and not opts.all:
        return app.usage_error("ap", "neighbors", opts, "Name the switch(es) to read, or add --all for every switch.", USAGE, VALIDATION)
    if opts.all and wanted:
        return app.usage_error("ap", "neighbors", opts, "--all reads every switch; drop the switch list or drop --all.", USAGE, VALIDATION)
    if opts.all:
        targets = [row for row in switches_rows if str(row.get("status") or "").upper() == "ONLINE"]
    else:
        targets, missing = [], []
        for item in wanted:
            resolved, choices = app.resolve_device_record(item)
            if resolved:
                targets.append(resolved)
            else:
                missing.append(item if not choices else f"{item} (matches {len(choices)})")
        if missing:
            return app.usage_error("ap", "neighbors", opts, "No single inventory switch matches: " + ", ".join(missing), USAGE, VALIDATION)
    if opts.dry_run:
        rows = []
        for row in targets:
            driver = app.driver_for(platform=row.get("platform"), model=row.get("model"), hostname=row.get("hostname"))
            commands = neighbor_commands(driver.family, driver.command_templates)
            rows.append({"switch": _host_label(row.get("hostname") or row.get("name") or ""), "ip": row.get("ip"),
                         "commands": " ; ".join(commands) or f"(none for {driver.family}; it will be skipped)"})
        app.emit({"ok": True, "switches": rows}, opts,
                 f"Would read CDP/LLDP neighbours from {len(rows)} switch(es) over SSH and record the APs on them.\n"
                 + app.render_table(rows[:opts.limit], ["switch", "ip", "commands"]))
        return SUCCESS
    switch_keys: Dict[str, str] = {}
    for row in switches_rows:
        label = _host_label(row.get("hostname") or row.get("name") or row.get("ip") or "")
        for key in [row.get("ip"), *(row.get("addresses") or []), _host_label(row.get("hostname") or "").lower(),
                    *(_host_label(alias).lower() for alias in row.get("aliases") or []), normalize_mac(row.get("mac")),
                    *(normalize_mac(mac) for mac in row.get("macs") or [])]:
            if key:
                switch_keys[str(key)] = label
    # Where to ping an AP from here when its port's MAC table is empty (LLDP
    # often does not advertise the AP's address).
    ap_addresses: Dict[str, str] = {}
    for row in app.state.rows("SELECT ip, name, mac FROM aps WHERE COALESCE(ip,'')<>''"):
        for key in (name_key(row.get("name")), normalize_mac(row.get("mac"))):
            if key:
                ap_addresses.setdefault(key, str(row["ip"]))
    timeout = min(int(getattr(opts, "timeout", 0) or 120), 180)
    workers = max(1, min(int(app._default_stp_jobs()), 32, len(targets) or 1))
    reads: List[Dict[str, Any]] = []
    lock = threading.Lock()
    with app.vault_session_scope(opts, minutes=30):
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ap-neighbors") as pool:
                futures = {pool.submit(read_switch, app, device, timeout, switch_keys, ap_addresses): device for device in targets}
                for future in concurrent.futures.as_completed(futures):
                    device = futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:  # one switch failing must not lose the others
                        result = {"switch_ip": device.get("ip"), "switch_name": _host_label(device.get("hostname") or ""),
                                  "records": [], "error": str(exc)}
                    with lock:
                        reads.append(result)
                        app._progress_step("ap neighbors", f"{result['switch_name']} | {workers} parallel", len(reads), len(targets), opts)
        finally:
            app._progress_clear(opts)
    ap_rows = app.state.rows("SELECT * FROM aps")
    plan = plan_attachments(sorted(reads, key=lambda read: str(read.get("switch_name") or "")), ap_rows, switch_keys)
    written = record(app, plan, now())
    failed = [{"switch": read["switch_name"], "ip": read["switch_ip"], "error": read["error"]} for read in reads if read.get("error")]
    columns = ["ap", "switch_name", "switch_port", "previous", "evidence", "mac_check"]
    payload = {"ok": not failed, "switches_read": len(reads) - len(failed), "failed": failed,
               "moved": plan["updates"], "new": plan["new"], "unchanged": len(plan["unchanged"]),
               "skipped": plan["skipped"], "written": written}
    for key in ("moved", "new"):
        payload[key] = [{name: entry.get(name) for name in columns + ["ip", "mac", "matched_by", "also_on", "protocol"]} for entry in payload[key]]
    found = list(plan["updates"]) + list(plan["new"]) + list(plan["unchanged"])
    checks = {verdict: len([entry for entry in found if str(entry.get("mac_check") or "").startswith(verdict)])
              for verdict in ("confirmed", "learned", "clients", "elsewhere", "empty")}
    payload["mac_checks"] = checks
    lines = [f"Read CDP/LLDP neighbours from {len(reads) - len(failed)} of {len(reads)} switch(es): "
             f"{len(plan['updates'])} AP(s) on a different port than recorded, {len(plan['new'])} new, "
             f"{len(plan['unchanged'])} confirmed where recorded.",
             f"MAC table on the AP's port: {checks['confirmed']} confirmed, {checks['learned']} learned (CDP gave no MAC), "
             f"{checks['clients']} with only its wireless clients, {checks['elsewhere']} showing other hardware, "
             f"{checks['empty']} empty even after pinging the AP."]
    if plan["updates"]:
        lines += ["", "Attachment corrected", app.render_table(payload["moved"][:opts.limit], columns)]
    if plan["new"]:
        lines += ["", "APs Netrune did not have", app.render_table(payload["new"][:opts.limit], ["ap", "ip", "switch_name", "switch_port", "evidence"])]
    if plan["skipped"]:
        lines += ["", f"Neighbours left out ({len(plan['skipped'])})",
                  app.render_table(plan["skipped"][:opts.limit], ["name", "switch_name", "switch_port", "evidence"])]
    if failed:
        lines += ["", "Switches not read", app.render_table(failed, ["switch", "ip", "error"])]
    app.emit(payload, opts, "\n".join(lines))
    return PARTIAL if failed else SUCCESS
