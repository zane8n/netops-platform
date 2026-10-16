"""Command surface for the device domain.

Kept out of core.py because the SSH-trust and guarded-config-apply logic here
has no callers outside device's own methods, unlike vlan/topology/lookup
which core.py's registry-execution engine calls into directly. `App` gets
this mixed in rather than delegating, since `apply_device_config_change`
and `cmd_device_trust` are called as `self.<name>(...)` from elsewhere in the
class and MRO resolves that the same regardless of which file defines them.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from netops_platform.identity import identity_match_evidence
from netops_platform.network import clean_network_output
from netops_platform.profiles import environment_value


class DeviceCommandsMixin:

    def _trust_target(self, raw_target: str) -> Tuple[str, str]:
        from netops_platform.core import normalize_target_literal
        raw = str(raw_target or "").strip()
        if not raw:
            raise ValueError("Missing SSH trust target.")
        device, choices = self.resolve_device_record(raw)
        if device:
            return str(device.get("hostname") or raw), str(device.get("ip") or raw)
        if len(choices) > 1:
            names = ", ".join(str(item.get("hostname") or item.get("ip")) for item in choices[:5])
            raise ValueError(f"SSH trust target is ambiguous: {names}")
        normalized = normalize_target_literal(raw)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}", normalized):
            raise ValueError("SSH trust target must be a hostname or IP address.")
        return raw, normalized

    def _scan_host_keys(self, host: str, timeout: int = 8) -> Tuple[List[Dict[str, Any]], str]:
        scanner = shutil.which("ssh-keyscan")
        if not scanner:
            return [], "ssh-keyscan is not installed"
        try:
            completed = subprocess.run(
                [scanner, "-T", str(max(1, min(timeout, 30))), host],
                capture_output=True,
                text=True,
                timeout=max(3, min(timeout, 30)) + 3,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return [], "SSH host-key scan timed out"
        rows: List[Dict[str, Any]] = []
        for raw in completed.stdout.splitlines():
            fields = raw.strip().split()
            if len(fields) < 3 or not fields[1].startswith(("ssh-", "ecdsa-", "sk-")):
                continue
            fingerprint = self._host_key_fingerprint(fields[2])
            if fingerprint:
                rows.append({"host": fields[0], "key_type": fields[1], "fingerprint": fingerprint, "key_line": " ".join(fields[:3])})
        error = "" if rows else (" ".join(completed.stderr.split())[:300] or f"ssh-keyscan exited {completed.returncode} without a usable key")
        return rows, error

    def _write_known_hosts(self, lines: Sequence[str]) -> None:
        path = self.paths.ssh_known_hosts_file
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with contextlib.suppress(OSError):
            path.parent.chmod(0o700)
        descriptor, staged_name = tempfile.mkstemp(prefix=".known-hosts.", suffix=".tmp", dir=str(path.parent))
        staged = Path(staged_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                for line in lines:
                    handle.write(line.rstrip("\n") + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(staged, path)
            path.chmod(0o600)
        finally:
            with contextlib.suppress(OSError):
                staged.unlink()

    def cmd_device_trust(self, args: List[str], opts: GlobalOptions) -> int:
        from netops_platform.core import AUTH, CONFIRM_REQUIRED, SUCCESS, UNREACHABLE, VALIDATION, fmt_time, now
        action = args[0].lower() if args else "status"
        rest = args[1:]
        target = ""
        fingerprints: List[str] = []
        index = 0
        while index < len(rest):
            item = rest[index]
            if item == "--fingerprint" and index + 1 < len(rest):
                fingerprints.extend(part.strip() for part in rest[index + 1].split(",") if part.strip())
                index += 2
            elif item.startswith("--"):
                return self.usage_error("device", f"trust-{action}", opts, f"Unknown SSH trust option: {item}", "netrune help device trust-status", VALIDATION)
            elif not target:
                target = item; index += 1
            else:
                return self.usage_error("device", f"trust-{action}", opts, "SSH trust accepts one target.", "netrune help device trust-status", VALIDATION)
        if action == "status":
            wanted: List[str] = []
            label = "all managed hosts"
            if target:
                try: label, host = self._trust_target(target)
                except ValueError as exc: return self.usage_error("device", "trust-status", opts, str(exc), "netrune device trust status ZONE34", VALIDATION)
                wanted = [host, target]
            rows = self._known_host_rows(wanted)
            mode = environment_value("NETRUNE_SSH_HOST_KEY_MODE", "NETOPS_SSH_HOST_KEY_MODE") or self.config.public.get("ssh_host_key_mode") or "accept-new"
            payload = {"ok": True, "target": label, "mode": mode, "known_hosts_file": str(self.paths.ssh_known_hosts_file), "rows": rows, "count": len(rows)}
            self.emit(payload, opts, f"SSH trust: {label} | mode={mode} | keys={len(rows)}\n" + self.render_table(rows, ["host", "key_type", "fingerprint", "line"]))
            return SUCCESS
        if action not in {"scan", "enroll", "forget"}:
            return self.usage_error("device", "trust-status", opts, f"Unknown SSH trust action: {action}", "netrune device trust status|scan|enroll|forget", VALIDATION)
        if not target:
            return self.usage_error("device", f"trust-{action}", opts, "Missing SSH trust target.", f"netrune device trust {action} ZONE34", VALIDATION)
        try: label, host = self._trust_target(target)
        except ValueError as exc: return self.usage_error("device", f"trust-{action}", opts, str(exc), f"netrune device trust {action} ZONE34", VALIDATION)
        if action == "scan":
            if opts.dry_run:
                self.emit({"ok": True, "dry_run": True, "target": label, "host": host, "command": f"ssh-keyscan -T {opts.timeout or 8} {host}"}, opts, f"Would scan SSH host keys for {label} ({host}); no trust state would change.")
                return SUCCESS
            rows, error = self._scan_host_keys(host, opts.timeout or 8)
            observed = now()
            payload = {"ok": bool(rows), "target": label, "host": host, "observed_at": observed, "observed_at_iso": fmt_time(observed), "trusted": False, "rows": [{k:v for k,v in row.items() if k != "key_line"} for row in rows], "error": error}
            self.emit(payload, opts, self.render_table(payload["rows"], ["host", "key_type", "fingerprint"]) if rows else f"SSH host-key scan failed: {error}")
            return SUCCESS if rows else UNREACHABLE
        if not (opts.dry_run or opts.confirm):
            return self.usage_error("device", f"trust-{action}", opts, "SSH trust changes require --dry-run or --confirm.", f"netrune device trust {action} {target} --dry-run", CONFIRM_REQUIRED)
        if action == "forget":
            existing_lines = self.paths.ssh_known_hosts_file.read_text(encoding="utf-8", errors="ignore").splitlines() if self.paths.ssh_known_hosts_file.is_file() else []
            aliases_to_remove = {host, target}
            retained: List[str] = []
            removed = 0
            for line in existing_lines:
                fields = line.strip().split()
                offset = 1 if fields and fields[0].startswith("@") else 0
                aliases = fields[offset].split(",") if len(fields) > offset else []
                matched = any(self._known_host_alias_matches(alias, wanted) for alias in aliases for wanted in aliases_to_remove)
                if matched:
                    removed += 1
                else:
                    retained.append(line)
            if opts.dry_run:
                self.emit({"ok": True, "dry_run": True, "target": label, "host": host, "would_remove": removed}, opts, f"Would remove {removed} managed SSH key(s) for {label} ({host}).")
                return SUCCESS
            self._write_known_hosts(retained)
            actor = os.environ.get("SUDO_USER") or os.environ.get("USER") or str(os.getuid())
            self.state.record_audit_event("ssh_trust_forgotten", "device-trust-forget", actor=actor, actor_uid=os.getuid(), target=host, result="success", detail={"removed": removed})
            self.emit({"ok": True, "target": label, "host": host, "removed": removed}, opts, f"Removed {removed} managed SSH key(s) for {label} ({host}).")
            return SUCCESS
        if not fingerprints:
            return self.usage_error("device", "trust-enroll", opts, "Enrollment requires at least one independently verified --fingerprint.", f"netrune device trust scan {target}", VALIDATION)
        if opts.dry_run:
            self.emit({"ok": True, "dry_run": True, "target": label, "host": host, "fingerprints": fingerprints}, opts, f"Would rescan {label} ({host}) and enroll only {', '.join(fingerprints)}.")
            return SUCCESS
        rows, error = self._scan_host_keys(host, opts.timeout or 8)
        wanted_fingerprints = {value.casefold() for value in fingerprints}
        matched = [row for row in rows if str(row.get("fingerprint") or "").casefold() in wanted_fingerprints]
        if not matched:
            message = error or "None of the scanned SSH keys matched the verified fingerprint."
            self.emit({"ok": False, "target": label, "host": host, "error": message, "observed_fingerprints": [row.get("fingerprint") for row in rows]}, opts, message)
            return AUTH
        existing_lines = self.paths.ssh_known_hosts_file.read_text(encoding="utf-8", errors="ignore").splitlines() if self.paths.ssh_known_hosts_file.is_file() else []
        retained = []
        for line in existing_lines:
            fields = line.strip().split()
            offset = 1 if fields and fields[0].startswith("@") else 0
            aliases = fields[offset].split(",") if len(fields) > offset else []
            if not any(self._known_host_alias_matches(alias, host) for alias in aliases):
                retained.append(line)
        retained.extend(str(row["key_line"]) for row in matched)
        self._write_known_hosts(retained)
        actor = os.environ.get("SUDO_USER") or os.environ.get("USER") or str(os.getuid())
        self.state.record_audit_event("ssh_trust_enrolled", "device-trust-enroll", actor=actor, actor_uid=os.getuid(), target=host, result="success", detail={"fingerprints": [row["fingerprint"] for row in matched]})
        payload = {"ok": True, "target": label, "host": host, "known_hosts_file": str(self.paths.ssh_known_hosts_file), "rows": [{k:v for k,v in row.items() if k != "key_line"} for row in matched], "count": len(matched)}
        self.emit(payload, opts, f"Enrolled {len(matched)} verified SSH host key(s) for {label} ({host}).")
        return SUCCESS


    def cmd_device(self,args:List[str],opts:GlobalOptions)->int:
        from netops_platform.core import (
            CONFIRM_REQUIRED, PARTIAL, SUCCESS, UNSUPPORTED, VALIDATION,
            clean_display_name, eprint, expand_abbreviated_target, is_ipv4_literal, now,
        )
        if self.handle_help("device", args, opts): return SUCCESS
        verb=args[0] if args else "ssh"; rest=args[1:]
        if verb in {"support", "compatibility"}:
            target = " ".join(rest).strip()
            if not target:
                rows = [driver.report() for driver in self.device_drivers.all()]
                payload = {"ok": True, "target": "", "drivers": rows, "count": len(rows), "observed_at": now()}
                self.emit(payload, opts, self.render_table(rows, ["family", "vendor", "os_name", "device_kind", "support_level"]))
                return SUCCESS
            device, choices = self.resolve_device_record(target)
            if not device:
                labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
                return self.usage_error("device", "support", opts, f"Device could not be resolved: {target}" + (f" ({labels})" if labels else ""), "netrune inventory list <target>", VALIDATION)
            detection = self.detect_device_family(platform=device.get("platform"), model=device.get("model"), hostname=device.get("hostname"))
            driver = self.driver_for(family=detection.family)
            capability_rows = [{"capability": key, "support": value} for key, value in sorted(driver.capabilities.items())]
            text = f"Device support: {device.get('hostname') or device.get('ip')}\nFamily: {driver.family} | OS: {driver.os_name} | Level: {driver.support_level}\n" + self.render_table(capability_rows, ["capability", "support"])
            payload = {"ok": detection.family != "unknown", "device": device, "detection": detection.as_dict(), "driver": driver.report(), "observed_at": now()}
            if "firmware-gated" in driver.capabilities.values():
                certified, certified_via = self.firmware_write_certified(
                    driver, detection,
                    platform=device.get("platform"), model=device.get("model"), hostname=device.get("hostname"),
                )
                raw_evidence = " ".join(str(value or "") for value in (device.get("platform"), device.get("model"), device.get("hostname"))).upper()
                payload["write_certification"] = {
                    "firmware_profile": detection.firmware_profile,
                    "certified": certified,
                    "certified_via": certified_via or None,
                    "built_in_certified_profiles": list(driver.firmware_profiles),
                    "raw_evidence": raw_evidence,
                }
                text += f"\nFirmware: {detection.firmware_profile}"
                if certified:
                    text += f" | Certified for writes (via {certified_via})"
                else:
                    text += (
                        f" | NOT certified for writes. Built-in certified: {', '.join(driver.firmware_profiles) or 'none'}.\n"
                        f"Raw evidence to match: {raw_evidence}\n"
                        f"To certify this exact firmware: netrune config set device_certified_firmware \"{driver.family}:<regex matching the text above>\"\n"
                        f"To certify an entire version range at once (same commands across it): "
                        f"netrune config set device_certified_firmware_min \"{driver.family}:<major.minor floor, e.g. 12.0>\""
                    )
            self.emit(payload, opts, text)
            return SUCCESS if payload["ok"] else UNSUPPORTED
        if verb in {"identity", "compare"}:
            if len(rest) < 2:
                return self.usage_error("device", "identity", opts, "Two device targets are required.", "netrune device identity <first> <second>", VALIDATION)
            left, left_choices = self.resolve_device_record(rest[0])
            right, right_choices = self.resolve_device_record(rest[1])
            if not left or not right:
                return self.usage_error("device", "identity", opts, "Both device targets must resolve unambiguously.", "netrune inventory list <target>", VALIDATION)
            assessment = identity_match_evidence(left, right, "switch")
            payload = {"ok": True, "left": left, "right": right, "assessment": assessment, "observed_at": now()}
            verdict = "same device" if assessment["same_device"] else ("candidate requiring corroboration" if assessment["candidate"] else "different devices")
            self.emit(payload, opts, f"Identity assessment: {verdict}\nConfidence: {assessment['confidence']}% | Name similarity: {assessment['signals']['name_similarity']}% | Required name threshold: {assessment['signals']['name_threshold']}%\nConflicts: {', '.join(assessment['conflicts']) or 'none'}")
            return SUCCESS
        if verb=="ssh":
            legacy = False
            target_parts: List[str] = []
            for item in rest:
                if item in {"-l", "--legacy"}:
                    legacy = True
                elif item.startswith("-"):
                    return self.usage_error("device", "ssh", opts, f"Unknown SSH option: {item}", "netrune device ssh [-l|--legacy] <target>", VALIDATION)
                else:
                    target_parts.append(item)
            target_query = " ".join(target_parts).strip()
            if not target_query: return self.usage_error("device","ssh",opts,"Missing target.","netrune device ssh ZONE34")
            device, choices = self.resolve_device_record(target_query)
            if not device and len(choices) > 1 and sys.stdin.isatty() and sys.stdout.isatty() and not opts.json and not opts.plain:
                def device_label(row: Dict[str, Any]) -> str:
                    name = clean_display_name(row.get("hostname") or "") or "(unnamed)"
                    bits = " ".join(x for x in (str(row.get("platform") or ""), str(row.get("model") or "")) if x)
                    status = str(row.get("status") or "")
                    return f"{name:<24} {str(row.get('ip') or ''):<15} {bits:<24} {status}"
                picked = self._select_row(choices, opts, label=device_label, prompt=f"{len(choices)} devices match '{target_query}':")
                if picked is None:
                    self.emit({"ok": False, "cancelled": True}, opts, "Cancelled.")
                    return SUCCESS
                device = picked
            target = str(device.get("ip") or target_query) if device else target_query
            # Say so when the address being connected to is not the one that was
            # typed. A switch that moved is still the right switch, but an
            # operator who asked for one address and silently reached another has
            # no way to tell that from the tool reaching the wrong box.
            asked = expand_abbreviated_target(
                target_query, self.config.public.get("target_abbreviation_prefix", "")) or target_query
            if device and is_ipv4_literal(asked) and asked != target:
                former = [str(value) for value in (device.get("addresses") or []) if str(value) == asked]
                reason = ("a former address of this device" if former
                          else "recorded for this device")
                eprint(f"Note: {asked} is {reason}. Connecting to its current address {target} "
                       f"({clean_display_name(device.get('hostname') or '')}).")
            helper_args = (["--legacy"] if legacy else []) + [target]
            return self.run_vault_interactive(self.legacy_cmd("netrune-connect", *helper_args),opts)
        if verb=="show":
            if len(rest)<2: return self.usage_error("device","show",opts,"Missing target or show command.","netrune device show ZONE34 show version")
            target=rest[0]; command=" ".join(rest[1:])
            if not self.safe_show_command(command): return self.usage_error("device","show",opts,"Only read-only show/display/get commands are allowed here.","netrune device config <target> <commands> --dry-run",VALIDATION)
            device, choices = self.resolve_device_record(target)
            resolved_target = str(device.get("ip") or target) if device and len(choices) == 1 else target
            return self.run_subprocess(self.legacy_cmd("netrune-control","show",resolved_target,command),opts)
        if verb=="config":
            usage = "netrune device config <target[,target...]> <command> [<command> ...] [--cisco] [--aruba] [--ruckus] (--dry-run | --confirm)"
            file_path=""; commands_file=""; positional=[]; target_specs=[]; danger_skip_verification=False; skip_unverified=False; skip_offline=False; vendors=set()
            i=0
            while i<len(rest):
                if rest[i]=="--file" and i+1<len(rest): file_path=rest[i+1]; i+=2
                elif rest[i] in {"--target","--device"} and i+1<len(rest): target_specs.append(rest[i+1]); i+=2
                elif rest[i]=="--commands-file" and i+1<len(rest): commands_file=rest[i+1]; i+=2
                elif rest[i]=="--danger-skip-verification": danger_skip_verification=True; i+=1
                elif rest[i]=="--skip-unverified": skip_unverified=True; i+=1
                elif rest[i]=="--skip-offline": skip_offline=True; i+=1
                elif rest[i] in {"--cisco","--aruba","--ruckus"}: vendors.add(rest[i][2:]); i+=1
                elif rest[i].startswith("--"):
                    # No switch/AP config command starts with "--", so this is
                    # a mistyped option (or one missing its value) -- refuse it
                    # rather than sending it to the device as a config line.
                    return self.usage_error("device","config",opts,f"Unknown device config option (or missing value): {rest[i]}",usage)
                else: positional.append(rest[i]); i+=1

            target_list: List[str] = []
            if file_path:
                p = Path(file_path).expanduser()
                if not p.exists():
                    return self.usage_error("device","config",opts,f"Device list file not found: {p}","netrune device config --file devices.txt 'show intent' --dry-run",VALIDATION)
                file_targets = [l.strip() for l in p.read_text(encoding="utf-8",errors="ignore").splitlines() if l.strip() and not l.strip().startswith("#")]
                if not file_targets:
                    return self.usage_error("device","config",opts,f"Device list file is empty: {p}",usage,VALIDATION)
                target_list.extend(file_targets)
            if file_path or target_specs:
                # Targets came from --file/--target, so every positional is a command.
                command_tokens = positional
            else:
                if not positional:
                    return self.usage_error("device","config",opts,"Missing target or config command(s).",usage)
                target_specs = [positional[0]]
                command_tokens = positional[1:]
            # Inline targets take the same comma-list form as vlan locate
            # (SW1,SW2), and --target repeats; --file lines are one target each.
            target_list.extend(token.strip() for spec in target_specs for token in spec.split(",") if token.strip())
            target_list = list(dict.fromkeys(target_list))
            if not target_list:
                return self.usage_error("device","config",opts,"Missing target or config command(s).",usage)

            if commands_file:
                p = Path(commands_file).expanduser()
                if not p.exists():
                    return self.usage_error("device","config",opts,f"Commands file not found: {p}","netrune device config <target> --commands-file commands.txt --dry-run",VALIDATION)
                if command_tokens:
                    return self.usage_error("device","config",opts,"Provide config commands inline or with --commands-file, not both.",usage,VALIDATION)
                commands = [l.strip() for l in p.read_text(encoding="utf-8",errors="ignore").splitlines() if l.strip() and not l.strip().startswith("#")]
                if not commands:
                    return self.usage_error("device","config",opts,f"Commands file is empty: {p}",usage,VALIDATION)
            else:
                commands = command_tokens

            if not commands:
                return self.usage_error("device","config",opts,"Missing target or config command(s).",usage)
            if not (opts.dry_run or opts.confirm):
                return self.usage_error("device","config",opts,"Config changes require --dry-run or --confirm.","netrune device config ZONE34 'show intent' --dry-run",CONFIRM_REQUIRED)

            if file_path or len(target_list) > 1 or skip_unverified or skip_offline or vendors:
                # --file or several inline targets supply many devices; validate
                # every one of them before touching any device, rather than
                # discovering a bad target/driver halfway through a batch that's
                # already written config to some switches. --skip-unverified and
                # --skip-offline (and the vendor filters) route even a single
                # target through the same "skip and report instead of
                # hard-failing" logic, rather than duplicating it.
                return self.apply_device_config_batch(target_list, commands, opts, danger_skip_verification=danger_skip_verification, skip_unverified=skip_unverified, skip_offline=skip_offline, vendors=vendors)

            gate = self._device_config_gate(target_list[0], opts, danger_skip_verification=danger_skip_verification)
            if not gate["resolved"]:
                return self.usage_error(
                    "device", "config", opts, gate["reason"],
                    "netrune inventory list <target>", VALIDATION,
                )
            if not gate["approved"]:
                payload = {
                    "ok": False,
                    "status": "UNSUPPORTED",
                    "target": gate["target"],
                    "driver_family": gate["driver_family"],
                    "firmware_profile": gate["firmware_profile"],
                    "firmware_certified": gate["firmware_certified"],
                    "firmware_certified_via": gate["firmware_certified_via"],
                    "writes_enabled": gate["writes_enabled"],
                    "support": gate["support"],
                    "reason": gate["reason"],
                }
                self.emit(payload, opts, gate["reason"])
                return UNSUPPORTED
            device = gate["device"]
            rest = [str(device.get("ip") or gate["target"]), *commands]
            if opts.confirm:
                with self.vault_session_scope(opts, minutes=30):
                    return self.apply_device_config_change(device, rest[0], rest[1:], opts, danger_skip_verification=danger_skip_verification)
            return self.run_subprocess(self.legacy_cmd("netrune-control","config",*rest,*(["--skip-verification"] if danger_skip_verification else [])),opts)
        if verb=="trust": return self.cmd_device_trust(rest,opts)
        if verb=="inventory":
            # The helper writes the flat device cache. Everything the CLI reads
            # -- inventory list, resolving a name, the identity work -- reads
            # SQLite, which is rebuilt from that cache. Without this step the
            # device is enriched and invisible: `connect` finds it, because the
            # shell path reads the flat file, and `inventory list` says there is
            # no such device. `inventory scan` has always done this; this path
            # was simply never given it.
            rc = self.run_subprocess(self.legacy_cmd("netrune-control","inventory",*rest),opts)
            if rc == SUCCESS and not opts.dry_run:
                try:
                    self.import_flat_state(("device",), "device-inventory")
                except Exception as exc:
                    eprint(f"Enriched the device, but recording it failed: {exc}")
                    return PARTIAL
            return rc
        return self.unknown_action("device", verb, opts)

    def _device_config_gate(self, target: str, opts: GlobalOptions, *, danger_skip_verification: bool = False) -> Dict[str, Any]:
        """Resolve one device-config target and evaluate its write-capability
        gate. Always returns a dict with 'target', 'resolved', 'approved',
        and -- whenever either is False -- 'reason'; 'device' carries the
        resolved row once found. Shared by the single-target path and the
        --file batch path so both reject a bad target the same way, and so
        a batch can validate every device before writing to any of them.

        `danger_skip_verification` bypasses firmware certification specifically
        (--danger-skip-verification on the CLI) -- it still requires a
        built-in, firmware-gated-capable driver and device_writes_enabled;
        it only removes the "is this exact firmware trusted" check. The same
        flag has to also reach the actual `netrune-control config` subprocess
        (see apply_device_config_batch/apply_device_config_change) or the
        real command-rendering layer refuses it independently regardless of
        what this preflight decided -- same gap that was already fixed once
        for the normal certification path.
        """
        device, choices = self.resolve_device_record(target)
        if not device:
            labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
            reason = f"Configuration target must resolve to exactly one inventory device: {target}"
            if labels:
                reason += f" ({labels})"
            elif os.environ.get("SUDO_USER") and hasattr(os, "geteuid") and os.geteuid() == 0:
                # Under sudo, netrune reads root's profile and inventory, not
                # the invoking user's, so every target "doesn't exist".
                reason += f" -- running under sudo uses root's netrune profile, not {os.environ['SUDO_USER']}'s; run without sudo"
            return {"target": target, "device": None, "resolved": False, "approved": False, "reason": reason}

        detection = self.detect_device_family(
            platform=device.get("platform"),
            model=device.get("model"),
            hostname=device.get("hostname"),
        )
        driver = self.driver_for(family=detection.family)
        support = driver.capability("configuration")
        built_in = str(getattr(driver, "source", "")) == "built-in"
        writes_enabled = str(
            self.config.public.get("device_writes_enabled") or ""
        ).strip().lower() in {"1", "true", "yes", "on"}
        firmware_profile = str(getattr(detection, "firmware_profile", "") or "")

        # Previewing a built-in, potentially writable driver is safe -- it
        # never reaches the network. Real execution goes through
        # DeviceDriver.command_plan("config", ...) (devices.py): a driver
        # whose capability("configuration") is "supported" (cisco-ios,
        # cisco-nxos, aruba-aos-switch, aruba-aos-cx -- their config_enter/
        # config_exit/save are trusted across the whole product line) only
        # needs device_writes_enabled, no per-firmware certification. A
        # "firmware-gated" driver (none currently registered, kept for a
        # future one whose write syntax genuinely does vary by firmware)
        # additionally requires the detected firmware to be on the driver's
        # own certified allow-list (firmware_profiles) or the operator's own
        # device_certified_firmware/_min config override. Checking that here
        # too means an uncertified firmware-gated driver is refused in
        # preflight, before any device is touched, instead of surfacing
        # confusingly after a real backup already ran.
        preview_approved = built_in and support in {"supported", "firmware-gated"}
        if danger_skip_verification:
            firmware_certified, certified_via = True, "danger-skip-verification"
        else:
            certified, certified_via = self.firmware_write_certified(
                driver, detection,
                platform=device.get("platform"), model=device.get("model"), hostname=device.get("hostname"),
            )
            firmware_certified = support != "firmware-gated" or certified
        confirm_approved = preview_approved and firmware_certified and writes_enabled
        approved = confirm_approved if opts.confirm else preview_approved
        result: Dict[str, Any] = {
            "target": target, "device": device, "resolved": True, "approved": approved,
            "driver_family": driver.family, "firmware_profile": firmware_profile,
            "firmware_certified": firmware_certified, "firmware_certified_via": certified_via,
            "writes_enabled": writes_enabled, "support": support,
        }
        if not approved:
            if not built_in:
                result["reason"] = "Configuration writes are restricted to built-in device drivers."
            elif support not in {"supported", "firmware-gated"}:
                result["reason"] = f"Configuration writes are not approved for the {driver.family} driver."
            elif opts.confirm and not firmware_certified:
                built_in_list = ", ".join(driver.firmware_profiles) or "none"
                evidence = " ".join(str(v or "") for v in (device.get("platform"), device.get("model"), device.get("hostname"))).upper()
                result["reason"] = (
                    f"This device's detected firmware profile ({firmware_profile or 'unverified'}) is not certified for "
                    f"{driver.family} writes (built-in: {built_in_list}); the write helper enforces this too, so the "
                    "change would be refused even if it started. Two ways to certify it yourself: an exact match -- "
                    f"netrune config set device_certified_firmware \"{driver.family}:<regex>\" (match a short, "
                    f"distinctive substring of the evidence below, not a pattern bridging across it -- any character "
                    f"in between, e.g. the '3' in a model number, can break a [^0-9]*-style pattern like the built-in "
                    f"ones use); or a version floor, if this driver's commands don't meaningfully change across a "
                    f"whole range -- netrune config set device_certified_firmware_min \"{driver.family}:<major.minor>\". "
                    f"Evidence: {evidence}"
                )
            else:
                result["reason"] = "Device configuration writes are disabled; set device_writes_enabled=true before confirmation."
        return result

    def _run_guarded_device_config_change(self, device: Optional[Dict[str, Any]], target: str, commands: List[str], opts: GlobalOptions, *, danger_skip_verification: bool = False) -> Dict[str, Any]:
        from netops_platform.core import clean_display_name, fmt_time, now
        """Backup, apply, verify one device's raw config change and return the
        result payload -- does not emit output or return an exit code, so both
        the single-device wrapper and the --file batch path can share the
        network calls and the audit-event bookkeeping without duplicating them.

        Arbitrary commands have no single semantic check the way a VLAN
        assignment does, so this reuses 'netrune-control backup --changed-only'
        as both the pre-change snapshot (apply_vlan_change's preflight+backup
        in one step, since a full running-config capture is the only universal
        "before" for an arbitrary command) and, run again after apply, the
        verification step: a fresh hash proves the running configuration
        actually changed rather than assuming it from a clean exit code alone.

        `danger_skip_verification`, when the caller's own gate already passed
        it through, is forwarded to the actual netrune-control subprocess as
        --skip-verification -- the real command-rendering layer (devices.py's
        command_plan) enforces certification independently of this Python
        preflight, so bypassing one without the other just reproduces the
        exact "approved here, refused there" gap this whole mechanism exists
        to close.
        """
        ip = target
        name = (clean_display_name(device.get("hostname") or "") if device else "") or ip
        steps = [
            {"step": "backup", "purpose": "save changed-only running configuration before the change"},
            {"step": "apply", "purpose": "send the requested commands"},
            {"step": "verify", "purpose": "confirm the running configuration actually changed"},
        ]
        started = now()
        phase_results: List[Dict[str, Any]] = []
        self.live_log("change", f"1/3 backup {name}")
        pre_rc, pre_out, pre_err = self.capture(self.legacy_cmd("netrune-control", "backup", ip, "--online-only", "--changed-only", "--summary"), opts.timeout or 300, opts)
        pre_excerpt = " ".join(clean_network_output((pre_out or "") + (pre_err or "")).split())[:1200]
        phase_results.append({"phase": "backup", "status": "PASS" if pre_rc == 0 else "FAIL", "exit_code": pre_rc, "detail": pre_excerpt})
        if pre_rc != 0:
            return {"ok": False, "status": "BLOCKED", "target": ip, "commands": commands, "steps": steps, "phases": phase_results, "error": "Configuration backup failed; no configuration was applied.", "started_at": started, "finished_at": now()}
        self.live_log("change", f"2/3 apply {len(commands)} command(s) on {name}")
        apply_flags = ["--skip-verification"] if danger_skip_verification else []
        apply_rc, apply_out, apply_err = self.capture(self.legacy_cmd("netrune-control", "config", ip, *commands, *apply_flags), opts.timeout or 300, opts)
        apply_excerpt = " ".join(clean_network_output((apply_out or "") + (apply_err or "")).split())[:1600]
        phase_results.append({"phase": "apply", "status": "PASS" if apply_rc == 0 else "FAIL", "exit_code": apply_rc, "detail": apply_excerpt})
        if apply_rc != 0:
            return {"ok": False, "status": "FAILED", "target": ip, "commands": commands, "steps": steps, "phases": phase_results, "error": "Device rejected one or more commands. Review the pre-change backup before any manual rollback.", "started_at": started, "finished_at": now()}
        self.live_log("change", f"3/3 verify {name}")
        # Every phase is its own from-scratch SSH session (no connection
        # reuse anywhere in this stack) and the apply phase's last two
        # commands are "write memory" then "exit" -- sent back-to-back with
        # no wait for the flash write to actually finish. Reconnecting
        # immediately can race a device that's still settling from that
        # save/session-teardown, especially a compact/low-power switch with
        # little spare I/O headroom; that shows up as a transport-level SSH
        # failure (exit 255), not anything about the config itself. A short
        # settle pause plus one retry resolves the common case instead of
        # reporting UNVERIFIED for what was actually just bad timing.
        time.sleep(2)
        post_rc, post_out, post_err = self.capture(self.legacy_cmd("netrune-control", "backup", ip, "--online-only", "--changed-only", "--summary"), opts.timeout or 300, opts)
        if post_rc != 0:
            self.live_log("change", f"3/3 verify {name} (retrying after a transient SSH failure)")
            time.sleep(4)
            post_rc, post_out, post_err = self.capture(self.legacy_cmd("netrune-control", "backup", ip, "--online-only", "--changed-only", "--summary"), opts.timeout or 300, opts)
        post_raw = (post_out or "") + (post_err or "")
        post_excerpt = " ".join(clean_network_output(post_raw).split())[:1200]
        finished = now()
        if post_rc != 0:
            # The apply phase already succeeded (checked above) -- this is
            # "we couldn't reconnect to confirm it", not "nothing changed".
            # Conflating the two used to report ATTENTION either way, which
            # reads as "verify ran and found something off" even when verify
            # never actually ran at all (e.g. a transient SSH failure right
            # after the apply session closed).
            changed = False
            verify_status = "FAIL"
            status = "UNVERIFIED"
            rollback = "The commands were applied, but verification could not reconnect to confirm the change -- this is not evidence the change failed. Check connectivity and re-run 'netrune device config <target> --dry-run' or a read-only check before assuming a rollback is needed."
        else:
            changed = "unchanged" not in post_raw.lower()
            verify_status = "PASS" if changed else "ATTENTION"
            status = "SUCCESS" if changed else "ATTENTION"
            rollback = "Not required; the running configuration changed as expected." if changed else "Review the pre-change backup before manual rollback."
        phase_results.append({"phase": "verify", "status": verify_status, "exit_code": post_rc, "detail": post_excerpt})
        payload = {
            "ok": changed, "status": status, "target": ip, "commands": commands, "steps": steps,
            "phases": phase_results, "changed": changed,
            "started_at": started, "started_at_iso": fmt_time(started),
            "finished_at": finished, "finished_at_iso": fmt_time(finished),
            "rollback": rollback,
        }
        self.state.record_audit_event("device_config_finished", "device-config", target=ip, result=status.lower(), detail={"commands": commands, "phases": phase_results})
        return payload

    def apply_device_config_change(self, device: Optional[Dict[str, Any]], target: str, commands: List[str], opts: GlobalOptions, *, danger_skip_verification: bool = False) -> int:
        """Guarded lifecycle for `device config --confirm`: backup, apply, verify, audit -- single device."""
        from netops_platform.core import PARTIAL, SUCCESS, clean_display_name
        payload = self._run_guarded_device_config_change(device, target, commands, opts, danger_skip_verification=danger_skip_verification)
        if payload["status"] in {"BLOCKED", "FAILED"}:
            self.emit(payload, opts, payload["error"])
            return PARTIAL
        name = (clean_display_name(device.get("hostname") or "") if device else "") or target
        text = f"Guarded device config: {payload['status']}\nDevice: {name} ({target})\n" + self.render_table(payload["phases"], ["phase", "status", "exit_code", "detail"]) + f"\nRecorded: {payload['finished_at_iso']}\n{payload['rollback']}"
        self.emit(payload, opts, text)
        return SUCCESS if payload["changed"] else PARTIAL

    def apply_device_config_batch(self, targets: List[str], commands: List[str], opts: GlobalOptions, *, danger_skip_verification: bool = False, skip_unverified: bool = False, skip_offline: bool = False, vendors: Optional[Set[str]] = None) -> int:
        """`device config --file <devices.txt>` or `device config SW1,SW2 ...`:
        run the same guarded lifecycle across many devices. Every target is
        resolved and gate-checked up front (see _device_config_gate); two
        targets that resolve to the same device (hostname and IP, say) run
        once.

        Default behavior: the whole batch is refused if any one target fails
        -- a typo in the device list, or one device on an unapproved driver,
        should not be discovered halfway through a batch that already wrote
        config to other switches.

        `skip_unverified` softens that: targets that don't resolve, or that
        fail the write gate (unsupported driver or uncertified firmware),
        are excluded and reported instead of aborting the batch -- the rest
        still run. `danger_skip_verification` (--danger-skip-verification)
        is a different, sharper knob: it bypasses firmware certification
        specifically for every device in the batch (built-in driver,
        firmware-gated capability, and device_writes_enabled are still
        required) -- use it deliberately, not as a way to avoid fixing
        inventory data. The two combine: with both, only a target that
        doesn't resolve at all, or whose driver has no write support
        whatsoever, still gets excluded.

        `skip_offline` pings every device that passed the gate (in parallel,
        the same reachability check `inventory activity` uses) and excludes
        the ones that don't answer, reported as skipped, before any backup
        starts -- otherwise each offline device costs a full SSH timeout in
        its backup phase before being reported BLOCKED. It runs on --dry-run
        too, so the preview shows exactly which devices a real run would
        touch. Live ping rather than the stored inventory status, since that
        can be hours stale.

        `vendors` ({"cisco", "aruba", "ruckus"}, from --cisco/--aruba/--ruckus)
        lets only devices whose detected driver family belongs to one of
        those vendors through. It's applied right after resolution, before
        the approval gate, so a mixed device list run with --cisco isn't
        refused over an Aruba or RUCKUS switch it was never going to touch.
        Filtered devices are listed but, unlike skipped ones, don't make the
        batch PARTIAL: leaving them out is what the operator asked for. A
        target that doesn't resolve can't be classified, so it still goes
        through the normal unresolved handling rather than being filtered.

        Once past preflight, devices are written to one at a time (not in
        parallel -- unlike this codebase's parallel *read* fan-outs such as
        topology stp or lookup mac all, there is no existing precedent for
        concurrent device *writes*, and serial execution keeps the audit
        trail and the vault session straightforward). A runtime failure on
        one device (backup/apply/verify) does not stop the rest of the
        batch; each device's own guarded lifecycle is independent.
        """
        from netops_platform.core import PARTIAL, SUCCESS, UNREACHABLE, UNSUPPORTED, VALIDATION, bounded_int, fmt_time, now

        gates = []
        seen_ips = set()
        for target in targets:
            gate = self._device_config_gate(target, opts, danger_skip_verification=danger_skip_verification)
            ip = str(gate["device"].get("ip") or "") if gate["resolved"] else ""
            if ip in seen_ips:
                continue
            if ip:
                seen_ips.add(ip)
            gates.append(gate)

        filtered: List[Dict[str, Any]] = []
        if vendors:
            wanted = "/".join(sorted(vendors))
            def vendor_of(gate: Dict[str, Any]) -> str:
                return str(gate.get("driver_family") or "unknown").split("-", 1)[0]
            filtered = [{**g, "reason": f"vendor filter: {g['driver_family']} is not {wanted}"} for g in gates if g["resolved"] and vendor_of(g) not in vendors]
            gates = [g for g in gates if not g["resolved"] or vendor_of(g) in vendors]
            if not gates:
                reason = f"No target matched the vendor filter ({wanted}):\n" + "\n".join(f"  {g['target']}: {g['driver_family']}" for g in filtered)
                return self.usage_error("device", "config", opts, reason, "netrune device support <target>", VALIDATION)

        skipped: List[Dict[str, Any]] = []
        if skip_unverified:
            runnable = [g for g in gates if g["resolved"] and g["approved"]]
            skipped = [g for g in gates if not (g["resolved"] and g["approved"])]
        else:
            unresolved = [g for g in gates if not g["resolved"]]
            if unresolved:
                reason = "Configuration batch not started; the following targets did not resolve to exactly one device:\n" + "\n".join(f"  {g['target']}: {g['reason']}" for g in unresolved) + "\nRe-run with --skip-unverified to proceed with the rest instead."
                return self.usage_error("device", "config", opts, reason, "netrune inventory list <target>", VALIDATION)

            unsupported = [g for g in gates if not g["approved"]]
            if unsupported:
                reason = "Configuration batch not started; the following devices are not approved for this write:\n" + "\n".join(f"  {g['target']}: {g['reason']}" for g in unsupported) + "\nRe-run with --skip-unverified to proceed with the rest instead."
                payload = {"ok": False, "status": "UNSUPPORTED", "devices": unsupported, "reason": reason}
                self.emit(payload, opts, reason)
                return UNSUPPORTED
            runnable = gates

        if skip_offline and runnable:
            ips = [str(g["device"].get("ip") or g["target"]) for g in runnable]
            workers = min(len(ips), bounded_int(opts.workers, 20, 1, 64))
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="netops-config-ping") as executor:
                online = list(executor.map(lambda ip: self.ping(ip, opts.timeout), ips))
            skipped.extend({**g, "offline": True, "reason": f"offline: no ping reply from {ip}"} for g, ip, up in zip(runnable, ips, online) if not up)
            runnable = [g for g, up in zip(runnable, online) if up]

        if not runnable:
            all_offline = all(g.get("offline") for g in skipped)
            reason = "Configuration batch not started; every target was skipped:\n" + "\n".join(f"  {g['target']}: {g['reason']}" for g in skipped)
            payload = {"ok": False, "status": "UNREACHABLE" if all_offline else "UNSUPPORTED", "devices": skipped, "reason": reason}
            self.emit(payload, opts, reason)
            return UNREACHABLE if all_offline else UNSUPPORTED

        if opts.dry_run:
            preview_rows = [{"target": g["target"], "ip": str(g["device"].get("ip") or g["target"]), "commands": "; ".join(commands)} for g in runnable]
            skipped_rows = [{"target": g["target"], "reason": g["reason"]} for g in skipped]
            filtered_rows = [{"target": g["target"], "reason": g["reason"]} for g in filtered]
            payload = {"ok": True, "dry_run": True, "targets": targets, "commands": commands, "devices": preview_rows, "skipped": skipped_rows, "filtered": filtered_rows}
            text = f"Would apply {len(commands)} command(s) to {len(runnable)} device(s):\n" + self.render_table(preview_rows, ["target", "ip", "commands"])
            if skipped_rows:
                text += f"\n\nSkipped {len(skipped_rows)} device(s):\n" + self.render_table(skipped_rows, ["target", "reason"])
            if filtered_rows:
                text += f"\n\nFiltered out {len(filtered_rows)} device(s) by vendor:\n" + self.render_table(filtered_rows, ["target", "reason"])
            self.emit(payload, opts, text)
            return SUCCESS

        started = now()
        results: List[Dict[str, Any]] = []
        with self.vault_session_scope(opts, minutes=30):
            for index, gate in enumerate(runnable, 1):
                device = gate["device"]
                ip = str(device.get("ip") or gate["target"])
                self.live_log("change", f"device {index}/{len(runnable)}: {gate['target']}")
                results.append(self._run_guarded_device_config_change(device, ip, commands, opts, danger_skip_verification=danger_skip_verification))
        finished = now()

        status_key = {"SUCCESS": "success", "ATTENTION": "attention", "UNVERIFIED": "unverified", "BLOCKED": "blocked", "FAILED": "failed"}
        counts = {"total": len(results), "success": 0, "attention": 0, "unverified": 0, "blocked": 0, "failed": 0, "skipped": len(skipped), "filtered": len(filtered)}
        for result in results:
            counts[status_key[result["status"]]] += 1
        summary_rows = [
            {"target": result["target"], "status": result["status"], "changed": result.get("changed", False), "detail": result.get("error") or (result["phases"][-1]["detail"] if result.get("phases") else "")}
            for result in results
        ] + [
            {"target": g["target"], "status": "SKIPPED", "changed": False, "detail": g["reason"]}
            for g in skipped
        ] + [
            {"target": g["target"], "status": "FILTERED", "changed": False, "detail": g["reason"]}
            for g in filtered
        ]
        all_succeeded = counts["success"] == counts["total"] and not skipped
        payload = {
            "ok": all_succeeded, "commands": commands, "devices": results,
            "skipped_devices": skipped, "filtered_devices": filtered, "counts": counts,
            "started_at": started, "started_at_iso": fmt_time(started),
            "finished_at": finished, "finished_at_iso": fmt_time(finished),
        }
        headline = f"Guarded device config batch: {counts['success']}/{counts['total']} attempted succeeded"
        if not all_succeeded:
            headline += f" ({counts['attention']} attention, {counts['unverified']} unverified, {counts['blocked']} blocked, {counts['failed']} failed, {counts['skipped']} skipped)"
        if filtered:
            headline += f"; {len(filtered)} filtered out by vendor"
        text = headline + "\n" + self.render_table(summary_rows, ["target", "status", "changed", "detail"])
        self.emit(payload, opts, text)
        return SUCCESS if all_succeeded else PARTIAL
