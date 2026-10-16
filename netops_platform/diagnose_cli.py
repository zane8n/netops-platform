"""Command surface for the diagnose domain.

Kept out of core.py as a mixin for the same reason vlan_cli.py/topology_cli.py/
lookup_cli.py are. Unlike those, this one also depends on core.py's
SSH-known-hosts helpers (_host_key_fingerprint, _known_host_alias_matches,
_known_host_rows, used by diagnostics_doctor's readiness check) -- those stay
in core.py rather than moving here because device_cli.py's cmd_device_trust
depends on them too, and per the shared-helper rule a helper used by two or
more extracted domains stays central. self._known_host_rows(...) still
resolves fine via MRO either way.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shlex
import shutil
import socket
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from netops_platform.network import (
    clean_network_output,
    parse_cable_diagnostics_output,
    parse_interface_health_output,
    parse_iperf3_output,
    parse_ping_output,
)
from netops_platform.profiles import environment_value


class DiagnoseCommandsMixin:

    def resolve_one(self,target:str)->str:
        from netops_platform.core import IP_RE, normalize_target_literal
        target = normalize_target_literal(target)
        if IP_RE.fullmatch(target.strip()): return target.strip()
        device, choices = self.resolve_device_record(target)
        if device and len(choices) == 1:
            return str(device.get("ip") or "")
        row=self.state.one("SELECT ip FROM aps WHERE lower(name)=lower(?) OR lower(name) LIKE lower(?) ORDER BY name LIMIT 1",(target,f"%{target}%"))
        if row: return row["ip"]
        with contextlib.suppress(Exception): return socket.gethostbyname(target)
        return ""

    def point_of_truth_ping(
        self,
        target: str,
        opts: GlobalOptions,
        core_target: str = "",
        count: int = 5,
        packet_timeout: int = 2,
    ) -> int:
        from netops_platform.core import PARTIAL, SUCCESS, UNREACHABLE, VALIDATION, fmt_time, is_ipv4_literal, normalize_target_literal, now
        destination = normalize_target_literal(target)
        if not is_ipv4_literal(destination):
            destination = self.resolve_one(target)
        if not is_ipv4_literal(destination):
            return self.usage_error("diagnose", "core-ping", opts, f"Could not resolve destination to a device IP: {target}", "netrune diagnose core-ping 192.0.2.50", VALIDATION)

        configured_core = str(
            core_target
            or self.config.public.get("core_switch_ip")
            or self.config.public.get("core_switch")
            or ""
        ).strip()
        if not configured_core:
            return self.usage_error("diagnose", "core-ping", opts, "No core switch is configured. Set core_switch_ip or pass --core.", "netrune diagnose core-ping 192.0.2.50 --core CORE01", VALIDATION)
        core, choices = self.resolve_device_record(configured_core)
        if not core:
            normalized_core = normalize_target_literal(configured_core)
            if is_ipv4_literal(normalized_core):
                core = {"ip": normalized_core, "hostname": configured_core, "platform": "Unknown", "model": "", "status": "UNKNOWN"}
            else:
                labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
                return self.usage_error("diagnose", "core-ping", opts, f"Core switch could not be resolved safely: {configured_core}" + (f" ({labels})" if labels else ""), "netrune inventory list <core>", VALIDATION)

        count = max(1, min(int(count or 5), 20))
        packet_timeout = max(1, min(int(packet_timeout or 2), 10))
        detection = self.detect_device_family(platform=core.get("platform"), model=core.get("model"), hostname=core.get("hostname"))
        driver = self.driver_for(family=detection.family)
        core_ip = str(core.get("ip") or configured_core)
        if opts.dry_run:
            payload = {
                "ok": True,
                "dry_run": True,
                "mode": "core-ping",
                "source": {"ip": core_ip, "name": core.get("hostname") or core_ip, "platform": core.get("platform") or "Unknown"},
                "target": target,
                "target_ip": destination,
                "count": count,
                "packet_timeout": packet_timeout,
                "note": "Vendor-specific read-only ping syntax is selected at execution time.",
            }
            self.emit(payload, opts, f"Dry run: point-of-truth ping {core.get('hostname') or core_ip} ({core_ip}) -> {destination}; count={count}")
            return SUCCESS
        if driver.family == "unknown":
            self.live_log("core-ping", f"{core_ip}: detect platform before selecting ping syntax")
            _, version_out, version_err = self.capture(self.legacy_cmd("netrune-control", "show", core_ip, "show version"), opts.timeout or 90)
            version_text = (version_out or "") + (version_err or "")
            detection = self.detect_device_family(platform=core.get("platform"), model=core.get("model"), sysdescr=version_text, hostname=core.get("hostname"))
            driver = self.driver_for(family=detection.family)
            if driver.family != "unknown":
                core["platform"] = f"{driver.vendor} {driver.os_name}"
        if driver.family == "unknown":
            driver = self.driver_for(family="cisco-ios")
        ping_templates = driver.command_templates.get("ping") or ("ping {destination} repeat {count} timeout {timeout}",)
        device_command = ping_templates[0].format(destination=destination, count=count, timeout=packet_timeout)
        self.live_log("core-ping", f"{core.get('hostname') or core_ip} ({core_ip}) -> {destination}; count={count}")
        rc, stdout, stderr = self.capture(
            self.legacy_cmd("netrune-control", "show", core_ip, device_command),
            opts.timeout or (count * packet_timeout + 45),
        )
        raw = (stdout or "") + (stderr or "")
        parsed = parse_ping_output(raw, count)
        observed = now()
        payload = {
            "ok": bool(parsed.get("parsed") and int(parsed.get("received") or 0) > 0),
            "healthy": parsed.get("status") == "REACHABLE",
            "mode": "core-ping",
            "source": {"ip": core_ip, "name": core.get("hostname") or core_ip, "platform": core.get("platform") or "Unknown"},
            "driver_family": driver.family,
            "target": target,
            "target_ip": destination,
            "command": device_command,
            "exit_code": rc,
            "helper_exit_ignored": bool(rc not in {0, None} and parsed.get("parsed")),
            **parsed,
            "observed_at": observed,
            "observed_at_iso": fmt_time(observed),
            "output_excerpt": " ".join(clean_network_output(raw).split())[:1000],
        }
        with contextlib.suppress(Exception):
            self.state.record_probe_result(destination, f"core-ping:{core_ip}", payload)
        self.live_log(
            "core-ping",
            f"status={payload['status']} received={payload['received']}/{payload['transmitted']} loss={payload.get('packet_loss_pct')}% avg={payload.get('avg_ms')} ms",
        )
        text = (
            f"Point-of-truth ping from {payload['source']['name']} ({core_ip}) to {destination}\n"
            f"Status: {payload['status']} | Received: {payload['received']}/{payload['transmitted']} | Loss: {payload.get('packet_loss_pct')}%\n"
            f"Latency min/avg/max: {payload.get('min_ms')} / {payload.get('avg_ms')} / {payload.get('max_ms')} ms\n"
            f"Recorded: {payload['observed_at_iso']}"
        )
        self.emit(payload, opts, text)
        if not parsed.get("parsed"):
            return PARTIAL
        if int(parsed.get("received") or 0) <= 0:
            return UNREACHABLE
        return PARTIAL if float(parsed.get("packet_loss_pct") or 0) > 0 else SUCCESS

    def internet_speed_diagnostic(self, runs: int, ca_file: str, opts: GlobalOptions, profile: str = "balanced") -> int:
        from netops_platform.core import INTERNAL, PARTIAL, SUCCESS, fmt_time, now
        profile = (profile or "balanced").lower()
        profile_defaults = {"quick": 1, "balanced": 2, "thorough": 3}
        if profile not in profile_defaults:
            profile = "balanced"
        runs = max(1, min(int(runs or profile_defaults[profile]), 5))
        if profile != "quick" and runs < 2:
            runs = 2
        cmd = self.legacy_cmd("netrune-probe", "-s", "--profile", profile, "--speed-runs", str(runs), "--json")
        if ca_file:
            cmd += ["--ca-file", ca_file]
        if opts.dry_run:
            payload = {
                "ok": True,
                "dry_run": True,
                "scope": "netops-host-to-internet",
                "profile": profile,
                "servers": runs,
                "command": shlex.join(cmd),
                "note": "No traffic was generated. Quick uses one complete server by default; balanced uses two; thorough uses three or more for stronger agreement.",
            }
            self.emit(payload, opts, f"Dry run: {payload['command']}")
            return SUCCESS
        rc, stdout, stderr = self.capture_streamed(cmd, opts.timeout or 1800)
        try:
            payload = json.loads(stdout)
        except (TypeError, ValueError, json.JSONDecodeError):
            detail = " ".join((stderr or stdout or "speed backend returned no structured result").split())[:1000]
            blocked = bool(re.search(r"\b401\b|authorization required|access denied|blocked|filter(?:ed|ing)?", detail, re.I))
            status = "BLOCKED" if blocked else "ERROR"
            error = {
                "ok": False,
                "status": status,
                "exit_code": rc,
                "error": detail,
                "failure_class": "UPSTREAM_AUTH_OR_POLICY" if blocked else "BACKEND_OR_CONNECTIVITY",
                "remediation": "Use an organization-approved authenticated benchmark path or a controlled iperf3 server; do not disable TLS verification." if blocked else "Run 'netrune diagnose doctor --online' and inspect route, TLS trust, DNS, and upstream availability.",
                "observed_at": now(),
            }
            error["observed_at_iso"] = fmt_time(error["observed_at"])
            with contextlib.suppress(Exception):
                error["record_id"] = self.state.record_diagnostic_run("internet-speed", "internet", "netops-host", status, detail, error)
            self.emit(error, opts, f"Internet speed test {status.lower()}: {detail}\n{error['remediation']}\nRecorded: {error['observed_at_iso']}")
            return rc if rc else INTERNAL
        payload.setdefault("observed_at", now())
        payload["observed_at_iso"] = fmt_time(payload["observed_at"])
        reliability = payload.get("reliability") or {}
        rating = str(reliability.get("rating") or "unknown").upper()
        status = "PASS" if payload.get("ok") and rating in {"HIGH", "MEDIUM"} else ("ATTENTION" if payload.get("ok") else "ERROR")
        download = (payload.get("download_mbps") or {}).get("sustained")
        upload = (payload.get("upload_mbps") or {}).get("sustained")
        summary = f"{download} Mbps down, {upload} Mbps up, reliability {rating.lower()}"
        with contextlib.suppress(Exception):
            payload["speed_test_id"] = self.state.record_speed_result(payload)
            payload["record_id"] = self.state.record_diagnostic_run("internet-speed", "internet", "netops-host", status, summary, payload)
        text = (
            "Internet speed from this Netrune host\n"
            f"Profile: {payload.get('profile') or profile} | Servers: {payload.get('servers_completed')}/{payload.get('servers_attempted')}\n"
            f"Download: {download} Mbps | Upload: {upload} Mbps | Reliability: {rating}\n"
            f"Idle/loaded latency: {(payload.get('latency_ms') or {}).get('idle')} / "
            f"{(payload.get('latency_ms') or {}).get('loaded_download')} down / {(payload.get('latency_ms') or {}).get('loaded_upload')} up ms\n"
            f"TLS: verified via {(payload.get('tls') or {}).get('trust_source')} | Interface: {(payload.get('path') or {}).get('interface')}\n"
            f"Recorded: {payload['observed_at_iso']}\n"
            "Scope: the machine running Netrune to the Internet; this is not a measurement of an arbitrary endpoint."
        )
        self.emit(payload, opts, text)
        return rc if rc in {SUCCESS, PARTIAL} else (SUCCESS if payload.get("ok") else INTERNAL)

    def _diagnostic_device(self, target: str) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        from netops_platform.core import is_ipv4_literal, normalize_target_literal
        device, choices = self.resolve_device_record(target)
        if device:
            return device, choices
        normalized = normalize_target_literal(target)
        if is_ipv4_literal(normalized):
            return {"ip": normalized, "hostname": normalized, "platform": "Unknown", "model": "", "status": "UNKNOWN"}, []
        return None, choices

    def port_health_diagnostic(
        self,
        target: str,
        interface: str,
        sample_seconds: int,
        expected_speed: int,
        opts: GlobalOptions,
    ) -> int:
        from netops_platform.core import PARTIAL, SUCCESS, VALIDATION, fmt_time, now
        device, choices = self._diagnostic_device(target)
        if not device:
            labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
            return self.usage_error("diagnose", "port-health", opts, f"Device could not be resolved: {target}" + (f" ({labels})" if labels else ""), "netrune diagnose port-health <device> on <interface>", VALIDATION)
        interface = str(interface or "").strip()
        if not interface or not re.fullmatch(r"[A-Za-z][A-Za-z0-9./:_-]{0,63}|\d{1,4}", interface):
            return self.usage_error("diagnose", "port-health", opts, "Interface name is invalid.", "netrune diagnose port-health ZONE34 on Gi1/0/7", VALIDATION)
        sample_seconds = max(0, min(int(sample_seconds or 0), 60))
        expected_speed = max(0, min(int(expected_speed or 0), 400000))
        ip = str(device.get("ip") or "")
        driver = self.driver_for(platform=device.get("platform"), model=device.get("model"), hostname=device.get("hostname"))
        commands = [template.format(interface=interface) for template in driver.command_templates.get("interface_health") or (f"show interfaces {interface}",)]
        helpers = [self.legacy_cmd("netrune-control", "show", ip, command) for command in commands]
        if opts.dry_run:
            rendered_commands = [shlex.join(helper) for helper in helpers]
            payload = {"ok": True, "dry_run": True, "device": device, "driver_family": driver.family, "interface": interface, "sample_seconds": sample_seconds, "expected_speed_mbps": expected_speed or None, "commands": rendered_commands}
            self.emit(payload, opts, f"Dry run: inspect {device.get('hostname') or ip} {interface} twice, {sample_seconds}s apart")
            return SUCCESS

        def snapshot() -> Tuple[int, str, str, Dict[str, Any]]:
            # One SSH login for every command the driver's interface_health
            # template has, rather than one per command -- otherwise this
            # diagnostic authenticates (len(commands) * 2) times for what is
            # conceptually one baseline read and one current read.
            if len(commands) > 1:
                rc, raw_out, raw_err = self.capture(
                    self.legacy_cmd("netrune-control", "show-batch", ip, *commands), opts.timeout or 120)
                text = (raw_out or "") + (raw_err or "")
                if self.CMD_MARKER_RE.search(text):
                    pieces = self.CMD_MARKER_RE.split(text)
                    bodies = {int(pieces[i]): pieces[i + 1] for i in range(1, len(pieces) - 1, 2)}
                    offset = len(bodies) - len(commands)
                    output = "\n".join(bodies.get(index + 1 + max(0, offset), "") for index in range(len(commands)))
                else:
                    output = text
                error = ""
            else:
                rc, output, error = self.capture(helpers[0], opts.timeout or 120)
            return rc, output, error, parse_interface_health_output((output or "") + (error or ""))

        self.live_log("port-health", f"read baseline counters on {device.get('hostname') or ip} {interface}")
        rc1, out1, err1, baseline = snapshot()
        if not baseline.get("parsed"):
            self.live_log("port-health", "baseline is unusable; retry immediately instead of waiting for a delta sample")
            sample_seconds = 0
        elif sample_seconds:
            self.live_log("port-health", f"observe for {sample_seconds}s before reading counter deltas")
            time.sleep(sample_seconds)
        self.live_log("port-health", f"read current counters on {device.get('hostname') or ip} {interface}")
        rc2, out2, err2, current = snapshot()
        deltas: Dict[str, Optional[int]] = {}
        counter_resets: List[str] = []
        first_counters = baseline.get("counters") or {}
        last_counters = current.get("counters") or {}
        for key in sorted(set(first_counters) | set(last_counters)):
            if key not in first_counters or key not in last_counters:
                deltas[key] = None
                continue
            delta = int(last_counters[key]) - int(first_counters[key])
            if delta < 0:
                deltas[key] = None
                counter_resets.append(key)
            else:
                deltas[key] = delta

        findings: List[Dict[str, Any]] = []
        if not baseline.get("parsed"):
            findings.append({"severity": "warning", "code": "BASELINE_UNAVAILABLE", "detail": "The baseline output was not recognized, so active counter deltas could not be measured."})
        if not current.get("parsed"):
            findings.append({"severity": "critical", "code": "OUTPUT_UNPARSED", "detail": "Switch interface output was not recognized."})
        if current.get("admin_status") == "DOWN":
            findings.append({"severity": "critical", "code": "ADMIN_DOWN", "detail": "The switch port is administratively disabled."})
        elif current.get("oper_status") == "DOWN":
            findings.append({"severity": "critical", "code": "LINK_DOWN", "detail": "The physical/link protocol state is down."})
        if current.get("duplex") == "HALF":
            findings.append({"severity": "warning", "code": "HALF_DUPLEX", "detail": "The link negotiated half duplex; check both endpoints and cabling."})
        actual_speed = current.get("speed_mbps")
        if expected_speed and actual_speed is not None and float(actual_speed) < expected_speed:
            findings.append({"severity": "warning", "code": "SPEED_BELOW_EXPECTED", "detail": f"Negotiated {actual_speed} Mbps; expected at least {expected_speed} Mbps."})
        meaningful = {
            "crc_errors", "frame_errors", "input_errors", "output_errors", "collisions",
            "late_collisions", "excessive_collisions", "runts", "giants", "rx_errors",
        }
        for key in sorted(meaningful):
            value = deltas.get(key)
            if value and value > 0:
                severity = "critical" if key in {"crc_errors", "late_collisions", "excessive_collisions"} else "warning"
                findings.append({"severity": severity, "code": "COUNTER_INCREASE", "counter": key, "delta": value, "detail": f"{key.replace('_', ' ')} increased by {value} during the sample."})
        if counter_resets:
            findings.append({"severity": "warning", "code": "COUNTER_RESET", "detail": "Counters reset or wrapped during the sample: " + ", ".join(counter_resets)})
        status = "ERROR" if not current.get("parsed") else ("DOWN" if current.get("oper_status") == "DOWN" else ("ATTENTION" if findings else "HEALTHY"))
        speed_bps = float(actual_speed or 0) * 1_000_000
        utilization = round(max(float(current.get("input_bps") or 0), float(current.get("output_bps") or 0)) / speed_bps * 100, 3) if speed_bps else None
        observed = now()
        payload = {
            "ok": status not in {"ERROR"},
            "healthy": status == "HEALTHY",
            "status": status,
            "device": device.get("hostname") or ip,
            "device_ip": ip,
            "platform": device.get("platform") or "Unknown",
            "driver_family": driver.family,
            "interface": interface,
            "sample_seconds": sample_seconds,
            "baseline_exit_code": rc1,
            "current_exit_code": rc2,
            "helper_exit_ignored": bool(current.get("parsed") and rc2 not in {0, None}),
            "expected_speed_mbps": expected_speed or None,
            "baseline": baseline,
            "current": current,
            "counter_deltas": deltas,
            "utilization_pct": utilization,
            "findings": findings,
            "observed_at": observed,
            "observed_at_iso": fmt_time(observed),
            "interpretation": "Cumulative totals show history; only sampled increases indicate errors during this observation window.",
            "output_excerpt": " ".join(clean_network_output((out2 or "") + (err2 or "")).split())[:1200],
        }
        summary = f"{status}; link={current.get('oper_status')}; speed={actual_speed}; findings={len(findings)}"
        with contextlib.suppress(Exception):
            payload["interface_sample_id"] = self.state.record_interface_result(payload)
            payload["record_id"] = self.state.record_diagnostic_run("port-health", f"{ip}:{interface}", "switch", status, summary, payload)
        findings_text = self.render_table(findings, ["severity", "code", "counter", "delta", "detail"]) if findings else "No active link or counter-delta findings."
        text = (
            f"Port health: {device.get('hostname') or ip} ({ip}) {interface}\n"
            f"Status: {status} | Admin/oper: {current.get('admin_status')}/{current.get('oper_status')} | Speed/duplex: {actual_speed or 'unknown'} Mbps/{current.get('duplex')}\n"
            f"Sample: {sample_seconds}s | Utilization: {utilization if utilization is not None else 'unknown'}% | Recorded: {payload['observed_at_iso']}\n\n"
            f"Findings\n{findings_text}\n\nCumulative counters: {json.dumps(last_counters, sort_keys=True)}\n"
            f"Sampled deltas: {json.dumps(deltas, sort_keys=True)}"
        )
        self.emit(payload, opts, text)
        return PARTIAL if status in {"ATTENTION", "DOWN", "ERROR"} else SUCCESS

    def cable_diagnostic(
        self,
        target: str,
        interface: str,
        start_test: bool,
        wait_seconds: int,
        opts: GlobalOptions,
    ) -> int:
        from netops_platform.core import CONFIRM_REQUIRED, INTERNAL, PARTIAL, SUCCESS, UNSUPPORTED, VALIDATION, fmt_time, now
        device, choices = self._diagnostic_device(target)
        if not device:
            labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
            return self.usage_error("diagnose", "cable", opts, f"Device could not be resolved: {target}" + (f" ({labels})" if labels else ""), "netrune diagnose cable <device> on <interface>", VALIDATION)
        interface = str(interface or "").strip()
        if not interface or not re.fullmatch(r"[A-Za-z][A-Za-z0-9./:_-]{0,63}|\d{1,4}", interface):
            return self.usage_error("diagnose", "cable", opts, "Interface name is invalid.", "netrune diagnose cable ZONE34 on Gi1/0/7", VALIDATION)
        wait_seconds = max(2, min(int(wait_seconds or 8), 60))
        ip = str(device.get("ip") or "")
        driver = self.driver_for(platform=device.get("platform"), model=device.get("model"), hostname=device.get("hostname"))
        if driver.family == "unknown":
            driver = self.driver_for(family="cisco-ios")
        family = driver.family
        status_templates = driver.command_templates.get("cable_status") or ()
        test_templates = driver.command_templates.get("cable_start") or ()
        if not status_templates:
            payload = {"ok": False, "status": "UNSUPPORTED", "device": device, "interface": interface, "platform_family": family, "reason": f"Cable diagnostics are not supported by the {family} driver."}
            self.emit(payload, opts, payload["reason"])
            return UNSUPPORTED
        status_command = status_templates[0].format(interface=interface)
        test_command = test_templates[0].format(interface=interface) if test_templates else ""
        if start_test and not test_command:
            payload = {"ok": False, "status": "UNSUPPORTED", "device": device, "interface": interface, "platform_family": family, "reason": f"Starting cable diagnostics is not supported by the {family} driver."}
            self.emit(payload, opts, payload["reason"])
            return UNSUPPORTED

        if start_test and not (opts.dry_run or opts.confirm):
            return self.usage_error(
                "diagnose", "cable", opts,
                "Starting cable diagnostics may interrupt a live copper link. Review with --dry-run or execute with --confirm.",
                f"netrune diagnose cable {target} on {interface} --test --dry-run",
                CONFIRM_REQUIRED,
            )
        if opts.dry_run:
            commands = [test_command, f"wait {wait_seconds}s", status_command] if start_test else [status_command]
            payload = {
                "ok": True, "dry_run": True, "device": device, "interface": interface,
                "platform_family": family, "start_test": start_test, "commands": commands,
                "disruptive": start_test,
                "warning": "An active TDR can briefly interrupt copper traffic and cannot validate fiber or every intermittent defect.",
            }
            self.emit(payload, opts, "Cable diagnostic preview\n" + "\n".join(f"  {item}" for item in commands) + ("\nNo command executed." if start_test else ""))
            return SUCCESS

        if start_test and family == "aruba-aos-cx":
            payload = {"ok": False, "status": "UNSUPPORTED", "device": device, "interface": interface, "reason": "Aruba CX interactive confirmation is not automated; run the preview and execute directly on the switch during a maintenance window."}
            self.emit(payload, opts, payload["reason"])
            return UNSUPPORTED
        precheck_exit_code: Optional[int] = None
        precheck_exit_ignored = False
        test_start_exit_code: Optional[int] = None
        test_start_exit_ignored = False
        if start_test:
            self.live_log("cable", f"verify {interface} is copper before starting the disruptive TDR")
            interface_out = ""; interface_err = ""; precheck_exit_code = 0
            precheck_commands = [template.format(interface=interface) for template in driver.command_templates.get("interface_health") or (f"show interfaces {interface}",)]
            for precheck_command in precheck_commands:
                check_rc, check_out, check_err = self.capture(self.legacy_cmd("netrune-control", "show", ip, precheck_command), opts.timeout or 120)
                precheck_exit_code = precheck_exit_code or check_rc
                interface_out += ("\n" if interface_out else "") + (check_out or "")
                interface_err += ("\n" if interface_err else "") + (check_err or "")
            interface_state = parse_interface_health_output((interface_out or "") + (interface_err or ""))
            if not interface_state.get("parsed"):
                detail = " ".join(clean_network_output((interface_out or "") + (interface_err or "")).split())[:800] or "interface media precheck returned no recognizable output"
                observed = now()
                payload = {
                    "ok": False,
                    "status": "ERROR",
                    "device": device.get("hostname") or ip,
                    "device_ip": ip,
                    "interface": interface,
                    "platform_family": family,
                    "precheck_exit_code": precheck_exit_code,
                    "error": detail,
                    "reason": "Active TDR was not started because Netrune could not verify the interface media.",
                    "observed_at": observed,
                    "observed_at_iso": fmt_time(observed),
                }
                with contextlib.suppress(Exception):
                    payload["record_id"] = self.state.record_diagnostic_run("cable", f"{ip}:{interface}", family, "ERROR", detail, payload)
                self.emit(payload, opts, f"{payload['reason']}\n{detail}\nRecorded: {payload['observed_at_iso']}")
                return PARTIAL
            precheck_exit_ignored = bool(precheck_exit_code not in {0, None})
            media = str(interface_state.get("media") or "").lower()
            if re.search(r"sfp|fiber|fibre|(?:^|[^a-z])\d*(?:sx|lx|zx|er|lr|sr)(?:$|[^a-z])|base-(?:sx|lx|zx|er|lr|sr)", media):
                payload = {"ok": False, "status": "UNSUPPORTED", "device": device, "interface": interface, "media": interface_state.get("media"), "reason": "TDR is a copper diagnostic and this port reports optical/removable media."}
                self.emit(payload, opts, payload["reason"])
                return UNSUPPORTED
            self.live_log("cable", f"start TDR on {device.get('hostname') or ip} {interface}")
            test_rc, test_out, test_err = self.capture(self.legacy_cmd("netrune-control", "show", ip, test_command), opts.timeout or 120)
            test_start_exit_code = test_rc
            test_raw = clean_network_output((test_out or "") + (test_err or ""))
            rejected = bool(re.search(r"invalid input|unknown command|not supported|permission denied|authorization failed|authentication failed|connection (?:failed|timed out)|timed out|unable to|failed to|cannot|can't", test_raw, re.I))
            accepted = bool(re.search(r"(?:tdr|cable(?: diagnostic)?).{0,60}\b(?:started|initiated|running|scheduled|in progress)\b|\b(?:started|initiated|running|scheduled)\b.{0,60}(?:tdr|cable)", test_raw, re.I))
            if rejected or (test_rc and not accepted):
                detail = " ".join(test_raw.split())[:800] or f"cable test helper exited {test_rc} without an acknowledgement"
                failure_status = "UNSUPPORTED" if re.search(r"invalid input|unknown command|not supported", test_raw, re.I) else "ERROR"
                payload = {
                    "ok": False,
                    "status": failure_status,
                    "device": device,
                    "interface": interface,
                    "exit_code": test_rc,
                    "error": detail,
                    "observed_at": now(),
                }
                payload["observed_at_iso"] = fmt_time(payload["observed_at"])
                with contextlib.suppress(Exception):
                    payload["record_id"] = self.state.record_diagnostic_run("cable", f"{ip}:{interface}", family, failure_status, detail, payload)
                self.emit(payload, opts, f"Cable test could not be started: {detail}")
                return UNSUPPORTED if failure_status == "UNSUPPORTED" else PARTIAL
            test_start_exit_ignored = bool(test_rc and accepted)
            self.live_log("cable", f"wait {wait_seconds}s for TDR result")
            time.sleep(wait_seconds)

        self.live_log("cable", f"read {'new' if start_test else 'previous'} TDR result on {device.get('hostname') or ip} {interface}")
        rc, stdout, stderr = self.capture(self.legacy_cmd("netrune-control", "show", ip, status_command), opts.timeout or 120)
        raw = (stdout or "") + (stderr or "")
        parsed = parse_cable_diagnostics_output(raw)
        # Some Aruba inventory records do not distinguish AOS-Switch from CX.
        if family == "aruba-aos-switch" and not parsed.get("parsed") and re.search(r"invalid input|unknown command", raw, re.I):
            fallback = f"diag cable-diagnostic show {interface}"
            rc, stdout, stderr = self.capture(self.legacy_cmd("netrune-control", "show", ip, fallback), opts.timeout or 120)
            raw = (stdout or "") + (stderr or "")
            parsed = parse_cable_diagnostics_output(raw)
            status_command = fallback
            family = "aruba-aos-cx"
        observed = now()
        parsed_status = str(parsed.get("status") or "UNKNOWN")
        status = parsed_status if parsed.get("parsed") else "ERROR"
        payload = {
            "ok": bool(parsed.get("parsed")),
            "healthy": parsed.get("healthy"),
            "device": device.get("hostname") or ip,
            "device_ip": ip,
            "interface": interface,
            "platform_family": family,
            "test_started": start_test,
            "command": status_command,
            **parsed,
            "status": status,
            "exit_code": rc,
            "helper_exit_ignored": bool(parsed.get("parsed") and rc not in {0, None}),
            "precheck_exit_code": precheck_exit_code,
            "precheck_exit_ignored": precheck_exit_ignored,
            "test_start_exit_code": test_start_exit_code,
            "test_start_exit_ignored": test_start_exit_ignored,
            "observed_at": observed,
            "observed_at_iso": fmt_time(observed),
            "limitations": [
                "TDR applies to copper pairs, not fiber.",
                "A clean result does not prove application throughput or rule out intermittent movement-related faults.",
                "Pair mapping and fault distance are estimates; repeat suspicious tests during a maintenance window.",
            ],
            "output_excerpt": " ".join(clean_network_output(raw).split())[:1200],
        }
        summary = f"{status}; pairs={len(parsed.get('pairs') or [])}; active_test={start_test}"
        with contextlib.suppress(Exception):
            payload["record_id"] = self.state.record_diagnostic_run("cable", f"{ip}:{interface}", family, status, summary, payload)
        pair_text = self.render_table(parsed.get("pairs") or [], ["pair", "status", "distance_m"]) if parsed.get("pairs") else parsed.get("message")
        text = (
            f"Cable diagnostic: {device.get('hostname') or ip} ({ip}) {interface}\n"
            f"Status: {status} | Result: {'new active test' if start_test else 'previous stored test'} | Recorded: {payload['observed_at_iso']}\n"
            f"{pair_text}\n"
            "Note: TDR assesses copper pair continuity/impedance. Port error deltas and an iperf test are still required for end-to-end quality."
        )
        self.emit(payload, opts, text)
        if status == "HEALTHY":
            return SUCCESS
        if status == "UNSUPPORTED":
            return UNSUPPORTED
        if parsed.get("parsed"):
            return PARTIAL
        return PARTIAL if rc not in {0, None} else INTERNAL

    def throughput_diagnostic(
        self,
        server: str,
        port: int,
        seconds: int,
        parallel: int,
        direction: str,
        bind: str,
        opts: GlobalOptions,
    ) -> int:
        from netops_platform.core import PARTIAL, SUCCESS, UNSUPPORTED, VALIDATION, fmt_time, now
        server = str(server or "").strip()
        if server.lower() == "core":
            server = str(self.config.public.get("core_iperf_server") or self.config.public.get("core_switch_ip") or self.config.public.get("core_switch") or "").strip()
        resolved, _ = self._diagnostic_device(server)
        if resolved:
            server = str(resolved.get("ip") or server)
        if not server:
            return self.usage_error("diagnose", "throughput", opts, "Missing iperf3 server. Configure core_iperf_server or supply a host/IP.", "netrune diagnose throughput 203.0.113.20", VALIDATION)
        if not 1 <= port <= 65535 or not 1 <= seconds <= 300 or not 1 <= parallel <= 16:
            return self.usage_error("diagnose", "throughput", opts, "Use port 1-65535, seconds 1-300, and parallel streams 1-16.", "netrune diagnose throughput 203.0.113.20 --seconds 10 --parallel 2", VALIDATION)
        if direction not in {"both", "upload", "download"}:
            return self.usage_error("diagnose", "throughput", opts, "Direction must be both, upload, or download.", "netrune diagnose throughput 203.0.113.20 --direction both", VALIDATION)
        phases = ["upload", "download"] if direction == "both" else [direction]
        commands: List[List[str]] = []
        for phase in phases:
            cmd = ["iperf3", "-c", server, "-p", str(port), "-t", str(seconds), "-P", str(parallel), "-O", "2", "-J"]
            if bind:
                cmd += ["--bind", bind]
            if phase == "download":
                cmd.append("-R")
            commands.append(cmd)
        if opts.dry_run:
            payload = {
                "ok": True, "dry_run": True, "scope": "netops-client-to-controlled-iperf3-server",
                "server": server, "port": port, "seconds": seconds, "parallel": parallel,
                "directions": phases, "commands": [shlex.join(cmd) for cmd in commands],
                "requirement": "An iperf3 server must be listening at the target. To measure a specific endpoint, run this client from that endpoint or its Netrune agent.",
            }
            self.emit(payload, opts, "Throughput preview\n" + "\n".join(f"  {item}" for item in payload["commands"]))
            return SUCCESS
        if not shutil.which("iperf3"):
            self.emit({"ok": False, "error": "iperf3 is not installed"}, opts, "iperf3 is required for controlled endpoint/core throughput testing.")
            return UNSUPPORTED

        results: List[Dict[str, Any]] = []
        for phase, cmd in zip(phases, commands):
            self.live_log("throughput", f"{phase}: this host {'->' if phase == 'upload' else '<-'} {server}:{port}; {seconds}s, {parallel} stream(s)")
            rc, stdout, stderr = self.capture(cmd, opts.timeout or (seconds + 45))
            parsed = parse_iperf3_output(stdout)
            parsed.update({"requested_direction": phase, "exit_code": rc})
            if rc not in {0, None}:
                parsed["backend_reported_ok"] = bool(parsed.get("ok"))
                parsed["ok"] = False
                parsed["error"] = " ".join((stderr or f"iperf3 exited {rc} after emitting a summary").split())[:800]
            if not parsed.get("ok") and stderr and not parsed.get("error"):
                parsed["error"] = " ".join(stderr.split())[:800]
            results.append(parsed)
        observed = now()
        ok = all(row.get("ok") for row in results)
        status = "PASS" if ok else "ERROR"
        payload = {
            "ok": ok,
            "status": status,
            "scope": "netops-client-to-controlled-iperf3-server",
            "server": server,
            "port": port,
            "seconds": seconds,
            "parallel": parallel,
            "bind": bind or None,
            "results": results,
            "observed_at": observed,
            "observed_at_iso": fmt_time(observed),
            "interpretation": "This is TCP receiver goodput between this client and a controlled iperf3 server. Run the client on the endpoint attached to the port for endpoint-specific results.",
        }
        metrics = ", ".join(f"{row.get('requested_direction')}={row.get('megabits_per_second')} Mbps" for row in results if row.get("ok")) or "no completed direction"
        with contextlib.suppress(Exception):
            payload["record_id"] = self.state.record_diagnostic_run("throughput", f"{server}:{port}", "netops-host", status, metrics, payload)
        rows = [{"direction": row.get("requested_direction"), "mbps": row.get("megabits_per_second"), "retransmits": row.get("retransmits"), "seconds": row.get("seconds"), "status": "PASS" if row.get("ok") else "ERROR", "error": row.get("error") or ""} for row in results]
        text = (
            f"Controlled throughput: this Netrune client <-> {server}:{port}\n"
            f"Status: {status} | Recorded: {payload['observed_at_iso']}\n"
            f"{self.render_table(rows, ['direction','mbps','retransmits','seconds','status','error'])}\n"
            "Scope: run this command on the endpoint connected to the switch port for an endpoint-to-core measurement."
        )
        self.emit(payload, opts, text)
        return SUCCESS if ok else PARTIAL

    def diagnostics_doctor(self, online: bool, opts: GlobalOptions) -> int:
        from netops_platform.core import PARTIAL, SUCCESS, fmt_time, now, valid_ssh_username
        checks: List[Dict[str, Any]] = []
        def add(name: str, status: str, detail: str) -> None:
            checks.append({"check": name, "status": status, "detail": detail})
        for command, required in (
            ("python3", True), ("jq", True), ("ping", True), ("ip", True),
            ("timeout", True), ("awk", True), ("perl", True), ("ssh", True),
            ("flock", True), ("mktemp", True), ("pgrep", True), ("realpath", True),
            ("grep", True), ("sed", True), ("sort", True), ("tr", True),
            ("xargs", True),
            ("ssh-keyscan", False), ("ssh-keygen", False),
            ("sshpass", False), ("expect", False), ("gpg", False), ("sudo", False),
            ("curl", False), ("traceroute", False), ("iperf3", False),
            ("ethtool", False), ("iw", False),
        ):
            path = shutil.which(command)
            add(command, "PASS" if path else ("FAIL" if required else "WARN"), path or ("required" if required else "optional capability unavailable"))
        for helper_name in ("netrune-probe", "netrune-control", "netrune-connect"):
            helper_path = Path(self.paths.tool(helper_name))
            add(helper_name, "PASS" if helper_path.is_file() and os.access(helper_path, os.X_OK) else "FAIL", str(helper_path))
        ping_rc, ping_out, ping_err = self.capture(["ping", "-n", "-c", "1", "-W", "1", "127.0.0.1"], 5)
        ping_detail = " ".join((ping_err or ping_out).split())[:500]
        add("ICMP capability", "PASS" if ping_rc == 0 else "FAIL", "loopback probe succeeded" if ping_rc == 0 else (ping_detail or f"ping exited {ping_rc}"))
        rc, _, speed_error = self.capture([sys.executable, "-c", "import netops_platform.speed, speedtest"], 15)
        add("speed backend", "PASS" if rc == 0 else "FAIL", "netops_platform.speed" if rc == 0 else (speed_error or "speedtest module/helper missing"))
        route_rc, route_out, route_err = self.capture(["ip", "route", "get", "1.1.1.1"], 10)
        route = " ".join((route_out or route_err).split())
        add("Internet route", "PASS" if route_rc == 0 and " dev " in f" {route} " else "FAIL", route or "no route")
        is_wsl = False
        with contextlib.suppress(OSError):
            is_wsl = "microsoft" in Path("/proc/version").read_text(errors="ignore").lower()
        add("host environment", "WARN" if is_wsl else "PASS", "WSL: local ethtool data describes a virtual adapter, not the physical cable" if is_wsl else sys.platform)
        add("configuration directory", "PASS" if os.access(self.paths.config_dir, os.R_OK | os.X_OK) else "FAIL", str(self.paths.config_dir))
        add("cache directory", "PASS" if os.access(self.paths.cache_dir, os.R_OK | os.W_OK | os.X_OK) else "FAIL", str(self.paths.cache_dir))
        for label, path in (
            ("credential config permissions", self.paths.env_file),
            ("SSH vault permissions", Path(environment_value("NETRUNE_PASSWORD_FILE", "NETOPS_PASSWORD_FILE", str(self.paths.home / ".ssh" / "sshpass_cache.gpg")))),
        ):
            if not path.exists():
                add(label, "WARN", f"not initialized: {path}")
                continue
            try:
                mode = path.stat().st_mode & 0o777
            except OSError as exc:
                add(label, "FAIL", f"could not inspect {path}: {exc}")
                continue
            add(label, "PASS" if mode & 0o077 == 0 else "FAIL", f"{path} mode={mode:04o}; expected no group/other access")
        vault_status = self.vault_status_payload()
        vault_mode = str(vault_status.get("mode") or "missing")
        if vault_mode == "sudo-gpg-v1":
            key_state = str(vault_status.get("root_key") or "not-checked")
            status = "PASS" if key_state == "available" else "FAIL" if key_state in {"missing", "insecure"} else "WARN"
            add("SSH vault mode", status, f"{vault_mode}; sudo={vault_status.get('sudo_session')}; root-key={key_state}; graphical-pinentry=disabled")
        elif vault_mode == "legacy-gpg":
            add("SSH vault mode", "WARN", "legacy-gpg; run 'netrune vault migrate' for terminal sudo authentication without graphical pinentry")
        else:
            add("SSH vault mode", "WARN", vault_mode)
        host_key_mode = str(environment_value("NETRUNE_SSH_HOST_KEY_MODE", "NETOPS_SSH_HOST_KEY_MODE") or self.config.public.get("ssh_host_key_mode") or "accept-new").lower()
        mode_status = "PASS" if host_key_mode == "strict" else "WARN" if host_key_mode in {"accept-new", "accept_new", "managed"} else "FAIL"
        mode_detail = "strict verification; unknown hosts are rejected" if mode_status == "PASS" else "trust on first use; changed keys are rejected" if mode_status == "WARN" else "unsupported or insecure host-key policy"
        add("SSH host-key mode", mode_status, f"{host_key_mode}: {mode_detail}")
        ssh_user = str(environment_value("NETRUNE_SSH_USER", "NETOPS_SSH_USER") or self.config.public.get("ssh_user") or self.config.secret.get("ssh_user") or "")
        add("SSH username", "PASS" if valid_ssh_username(ssh_user) else "FAIL", "configured" if valid_ssh_username(ssh_user) else "set a 1-255 character value without whitespace: netrune config set ssh_user <username>")
        known_hosts = self.paths.ssh_known_hosts_file
        if known_hosts.exists():
            mode = known_hosts.stat().st_mode & 0o777
            add("SSH trust store", "PASS" if mode & 0o077 == 0 else "FAIL", f"{known_hosts} mode={mode:04o}; keys={len(self._known_host_rows())}")
        else:
            add("SSH trust store", "WARN", f"not initialized: {known_hosts}; use netrune device trust scan/enroll")
        integrity = self.state.integrity_check()
        add("SQLite integrity", "PASS" if integrity.get("ok") else "FAIL", ", ".join(integrity.get("integrity_check") or ["unknown result"]))
        scan_limits = (
            ("scan workers", environment_value("NETRUNE_SCAN_WORKERS", "NETOPS_SCAN_WORKERS", self.config.public.get("scan_workers", "30")), 1, 256),
            ("scan host limit", environment_value("NETRUNE_SCAN_MAX_HOSTS", "NETOPS_SCAN_MAX_HOSTS", self.config.public.get("scan_max_hosts", "4096")), 1, 65536),
            ("scan host timeout", environment_value("NETRUNE_SCAN_HOST_TIMEOUT", "NETOPS_SCAN_HOST_TIMEOUT", self.config.public.get("scan_host_timeout", "20")), 1, 300),
        )
        for label, configured, minimum, maximum in scan_limits:
            value = str(configured or "").strip()
            valid = value.isdigit() and minimum <= int(value) <= maximum
            add(label, "PASS" if valid else "FAIL", f"configured={value or 'missing'}; allowed={minimum}..{maximum}")
        core = str(self.config.public.get("core_switch_ip") or self.config.public.get("core_switch") or "").strip()
        add("core switch", "PASS" if core else "WARN", core or "set core_switch_ip for core-origin ping")
        iperf_server = str(self.config.public.get("core_iperf_server") or "").strip()
        add("core iperf3 server", "PASS" if iperf_server else "WARN", iperf_server or "set core_iperf_server or pass a server to diagnose throughput")
        if online and helper.is_file():
            self.live_log("doctor", "verify Speedtest server discovery and TLS trust")
            rc, stdout, stderr = self.capture([sys.executable, str(helper), "--timeout", "30", "servers", "--limit", "1"], opts.timeout or 120)
            try:
                speed_payload = json.loads(stdout)
            except (TypeError, ValueError, json.JSONDecodeError):
                speed_payload = {}
            trust = speed_payload.get("tls_trust") or {}
            add("online TLS/server discovery", "PASS" if rc == 0 and speed_payload.get("ok") and trust.get("verified") else "FAIL", f"trust={trust.get('source')}; servers={len(speed_payload.get('servers') or [])}" if speed_payload else " ".join((stderr or stdout).split())[:500])
        # A helper copy older than the repository silently shadows the working
        # tree: a fixed bug then presents as unfixed, which has already cost a
        # full diagnosis round.
        shadowed: List[str] = []
        helper_names = ("netops-lib.sh", "netops-control", "netops-discovery",
                        "netops-probe", "netops-connect", "netops_aruba_ssh.exp")
        for name in helper_names:
            canonical = self.paths.install_dir / name
            if not canonical.is_file():
                continue
            for directory in (Path(sys.prefix) / "bin", self.paths.install_dir / ".venv" / "bin"):
                shadow = directory / name
                with contextlib.suppress(OSError):
                    if shadow.is_file() and not shadow.samefile(canonical) and shadow.stat().st_mtime < canonical.stat().st_mtime:
                        shadowed.append(f"{shadow} is older than {canonical}")
        add(
            "helper copies match the working tree",
            "PASS" if not shadowed else "WARN",
            "no stale shadow copies" if not shadowed
            else f"{len(shadowed)} stale copy(ies) may run instead of the current code: " + "; ".join(shadowed[:3]),
        )

        observed = now()
        failed = sum(1 for row in checks if row["status"] == "FAIL")
        warnings = sum(1 for row in checks if row["status"] == "WARN")
        status = "PASS" if failed == 0 else "FAIL"
        payload = {"ok": failed == 0, "status": status, "online": online, "checks": checks, "summary": {"passed": sum(1 for row in checks if row['status'] == 'PASS'), "warnings": warnings, "failed": failed}, "observed_at": observed, "observed_at_iso": fmt_time(observed)}
        with contextlib.suppress(Exception):
            payload["record_id"] = self.state.record_diagnostic_run("doctor", "local", "netops-host", status, f"failed={failed}; warnings={warnings}", payload)
        text = f"Netrune diagnostic readiness\nRecorded: {payload['observed_at_iso']}\n{self.render_table(checks, ['check','status','detail'])}"
        self.emit(payload, opts, text)
        return SUCCESS if failed == 0 else PARTIAL

    def cmd_diagnose(self,args:List[str],opts:GlobalOptions)->int:
        from netops_platform.core import SUCCESS, VALIDATION, normalize_target_literal
        if self.handle_help("diagnose", args, opts): return SUCCESS
        verb=args[0] if args else "latency"; rest=args[1:]
        if verb in {"core-ping","point-ping","truth-ping"}:
            if not rest: return self.usage_error("diagnose","core-ping",opts,"Missing destination device/IP.","netrune diagnose core-ping 192.0.2.50 --count 5")
            target=rest[0]; core=opts.source; count=5; packet_timeout=2; i=1
            while i<len(rest):
                if rest[i] in {"--core","--source"} and i+1<len(rest): core=rest[i+1]; i+=2
                elif rest[i] in {"--count","-c"} and i+1<len(rest):
                    try: count=int(rest[i+1])
                    except ValueError: return self.usage_error("diagnose","core-ping",opts,"Count must be an integer.","netrune diagnose core-ping 192.0.2.50 --count 5",VALIDATION)
                    i+=2
                elif rest[i]=="--packet-timeout" and i+1<len(rest):
                    try: packet_timeout=int(rest[i+1])
                    except ValueError: return self.usage_error("diagnose","core-ping",opts,"Packet timeout must be an integer.","netrune diagnose core-ping 192.0.2.50 --packet-timeout 2",VALIDATION)
                    i+=2
                else: return self.usage_error("diagnose","core-ping",opts,f"Unknown option: {rest[i]}","netrune help diagnose core-ping",VALIDATION)
            return self.point_of_truth_ping(target,opts,core,count,packet_timeout)
        if verb=="latency":
            if not rest: return self.usage_error("diagnose","latency",opts,"Missing target.","netrune diagnose latency 1.1.1.1")
            target=normalize_target_literal(rest[0]); extra=[]; i=1
            while i < len(rest):
                if rest[i] in {"--count","-c"} and i+1<len(rest): extra += ["-c",rest[i+1]]; i+=2
                elif rest[i] in {"--port","-p"} and i+1<len(rest): extra += ["-p",rest[i+1]]; i+=2
                else: extra.append(rest[i]); i+=1
            if opts.json and "--json" not in extra: extra.append("--json")
            return self.run_subprocess(self.legacy_cmd("netrune-probe",target,*extra),opts)
        if verb=="speed":
            runs=None; ca_file=""; profile="balanced"; i=0
            while i < len(rest):
                if rest[i] in {"--runs","--speed-runs"} and i+1<len(rest):
                    try: runs=int(rest[i+1])
                    except ValueError: return self.usage_error("diagnose","speed",opts,"Runs must be an integer from 1 to 5.","netrune diagnose speed --profile quick",VALIDATION)
                    i+=2
                elif rest[i]=="--profile" and i+1<len(rest): profile=rest[i+1].lower(); i+=2
                elif rest[i]=="--quick": profile="quick"; i+=1
                elif rest[i]=="--thorough": profile="thorough"; i+=1
                elif rest[i]=="--ca-file" and i+1<len(rest): ca_file=rest[i+1]; i+=2
                else: return self.usage_error("diagnose","speed",opts,f"Unknown option: {rest[i]}","netrune help diagnose speed",VALIDATION)
            if profile not in {"quick","balanced","thorough"}: return self.usage_error("diagnose","speed",opts,"Profile must be quick, balanced, or thorough.","netrune diagnose speed --profile quick",VALIDATION)
            if runs is None: runs={"quick":1,"balanced":2,"thorough":3}[profile]
            if not 1 <= runs <= 5: return self.usage_error("diagnose","speed",opts,"Runs must be from 1 to 5.","netrune diagnose speed --profile quick",VALIDATION)
            if profile != "quick" and runs < 2: return self.usage_error("diagnose","speed",opts,"Balanced/thorough profiles require at least 2 runs; use --profile quick for a one-server check.","netrune diagnose speed --profile quick",VALIDATION)
            return self.internet_speed_diagnostic(runs,ca_file,opts,profile)
        if verb in {"throughput","iperf","iperf3"}:
            if not rest: return self.usage_error("diagnose","throughput",opts,"Missing controlled iperf3 server.","netrune diagnose throughput 203.0.113.20",VALIDATION)
            server=rest[0]; port=5201; seconds=10; parallel=1; direction="both"; bind=opts.source; i=1
            while i<len(rest):
                if rest[i] in {"--port","-p"} and i+1<len(rest):
                    try: port=int(rest[i+1])
                    except ValueError: return self.usage_error("diagnose","throughput",opts,"Port must be an integer.","netrune diagnose throughput 203.0.113.20 --port 5201",VALIDATION)
                    i+=2
                elif rest[i] in {"--seconds","--time","-t"} and i+1<len(rest):
                    try: seconds=int(rest[i+1])
                    except ValueError: return self.usage_error("diagnose","throughput",opts,"Seconds must be an integer.","netrune diagnose throughput 203.0.113.20 --seconds 10",VALIDATION)
                    i+=2
                elif rest[i] in {"--parallel","-P"} and i+1<len(rest):
                    try: parallel=int(rest[i+1])
                    except ValueError: return self.usage_error("diagnose","throughput",opts,"Parallel streams must be an integer.","netrune diagnose throughput 203.0.113.20 --parallel 2",VALIDATION)
                    i+=2
                elif rest[i]=="--direction" and i+1<len(rest): direction=rest[i+1].lower(); i+=2
                elif rest[i] in {"--bind","--source"} and i+1<len(rest): bind=rest[i+1]; i+=2
                else: return self.usage_error("diagnose","throughput",opts,f"Unknown option: {rest[i]}","netrune help diagnose throughput",VALIDATION)
            return self.throughput_diagnostic(server,port,seconds,parallel,direction,bind,opts)
        if verb in {"port-health","port","interface-health"}:
            if len(rest)<3 or rest[1] != "on": return self.usage_error("diagnose","port-health",opts,"Use: netrune diagnose port-health <device> on <interface>","netrune diagnose port-health ZONE34 on Gi1/0/7",VALIDATION)
            target=rest[0]; interface=rest[2]; sample_seconds=5; expected_speed=0; i=3
            while i<len(rest):
                if rest[i] in {"--sample-seconds","--sample","--interval"} and i+1<len(rest):
                    try: sample_seconds=int(rest[i+1])
                    except ValueError: return self.usage_error("diagnose","port-health",opts,"Sample seconds must be an integer.","netrune diagnose port-health ZONE34 on Gi1/0/7 --sample-seconds 5",VALIDATION)
                    i+=2
                elif rest[i] in {"--expected-speed","--speed"} and i+1<len(rest):
                    try: expected_speed=int(rest[i+1])
                    except ValueError: return self.usage_error("diagnose","port-health",opts,"Expected speed must be integer Mbps.","netrune diagnose port-health ZONE34 on Gi1/0/7 --expected-speed 1000",VALIDATION)
                    i+=2
                else: return self.usage_error("diagnose","port-health",opts,f"Unknown option: {rest[i]}","netrune help diagnose port-health",VALIDATION)
            return self.port_health_diagnostic(target,interface,sample_seconds,expected_speed,opts)
        if verb in {"cable","tdr","cable-test"}:
            if len(rest)<3 or rest[1] != "on": return self.usage_error("diagnose","cable",opts,"Use: netrune diagnose cable <device> on <interface>","netrune diagnose cable ZONE34 on Gi1/0/7",VALIDATION)
            target=rest[0]; interface=rest[2]; start_test=verb in {"tdr","cable-test"}; wait_seconds=8; i=3
            while i<len(rest):
                if rest[i] in {"--test","--start"}: start_test=True; i+=1
                elif rest[i]=="--wait" and i+1<len(rest):
                    try: wait_seconds=int(rest[i+1])
                    except ValueError: return self.usage_error("diagnose","cable",opts,"Wait must be an integer number of seconds.","netrune diagnose cable ZONE34 on Gi1/0/7 --test --wait 8 --dry-run",VALIDATION)
                    i+=2
                else: return self.usage_error("diagnose","cable",opts,f"Unknown option: {rest[i]}","netrune help diagnose cable",VALIDATION)
            with self.vault_session_scope(opts, minutes=30):
                return self.cable_diagnostic(target,interface,start_test,wait_seconds,opts)
        if verb=="doctor":
            online=False
            for item in rest:
                if item=="--online": online=True
                else: return self.usage_error("diagnose","doctor",opts,f"Unknown option: {item}","netrune help diagnose doctor",VALIDATION)
            return self.diagnostics_doctor(online,opts)
        if verb=="filtering":
            target=rest[0] if rest else "google.com"; cmd=[self.paths.tool("netrune-legacy"),"check"]
            if opts.json: cmd.append("--json")
            if target: cmd.append(target)
            return self.run_subprocess(cmd,opts)
        if verb=="interface":
            if len(rest)<3 or rest[1] != "on": return self.usage_error("diagnose","interface",opts,"Use: netrune diagnose interface <device> on <interface>","netrune diagnose interface ZONE34 on Gi1/0/7")
            device, choices = self._diagnostic_device(rest[0])
            if not device:
                labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
                return self.usage_error("diagnose", "interface", opts, f"Device could not be resolved: {rest[0]}" + (f" ({labels})" if labels else ""), "netrune diagnose interface <device> on <interface>", VALIDATION)
            cmd=[self.paths.tool("netrune-legacy"),"interface",str(device.get("ip") or rest[0]),*rest[1:]]
            if opts.json and "--json" not in cmd: cmd.append("--json")
            return self.run_subprocess(cmd,opts)
        return self.unknown_action("diagnose", verb, opts)
