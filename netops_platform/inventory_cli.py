"""Command surface for the inventory domain.

Kept out of core.py because its handlers (list/details/scan/forget/merge/
unmerge/activity) have no callers outside inventory's own methods, unlike
vlan/topology/lookup which core.py's registry-execution engine calls into
directly. `App` gets this mixed in rather than delegating, since some of
these methods are called as `self.<name>(...)` from each other within the
cluster, and MRO resolves that the same regardless of which file defines
the method.

`resolve_one` is defined right next to this cluster in core.py but stays
there rather than moving here: it has exactly one caller, and that caller
is in the diagnose domain, not this one.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import json
import os
import re
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from netops_platform.identity import identity_match_evidence, reconcile_device_rows


class InventoryCommandsMixin:

    def resolve_raw_device_record(self, target: str) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        from netops_platform.core import expand_abbreviated_target, normalize_target_literal
        raw = self.natural_ask.apply_aliases(str(target or "").strip(), strict=True)
        # An abbreviated address is an address, not a name fragment.
        expanded = expand_abbreviated_target(raw, self.config.public.get("target_abbreviation_prefix", ""))
        if expanded:
            raw = expanded
        normalized = normalize_target_literal(raw)
        if not normalized:
            return None, []
        rows = self.state.rows(
            "SELECT ip,hostname,hostname AS name,platform,model,serial,mac,source,last_seen,status FROM devices ORDER BY hostname,ip"
        )
        exact = [
            row for row in rows
            if str(row.get("ip") or "").lower() == normalized.lower()
            or str(row.get("hostname") or "").lower() == raw.lower()
            or str(row.get("hostname") or "").split(".", 1)[0].lower() == raw.lower()
        ]
        if len(exact) == 1:
            return exact[0], exact
        if len(exact) > 1:
            return None, exact[:20]
        needle = re.sub(r"[^a-z0-9.]", "", raw.lower())
        candidates = [
            row for row in rows
            if needle and needle in re.sub(r"[^a-z0-9.]", "", f"{row.get('hostname') or ''} {row.get('ip') or ''}".lower())
        ]
        return (candidates[0], candidates) if len(candidates) == 1 else (None, candidates[:20])

    MERGE_ROLE_LABELS = {"source": "old-device", "target": "current-device"}

    def _resolve_merge_endpoint(self, target: str) -> Optional[Dict[str, Any]]:
        """Resolve one side of a manual merge to a row in the active devices table.

        A merge writes chronology from the raw record, so the raw table is tried
        first. Falling back to the alias-aware resolver keeps `inventory merge`
        accepting every spelling `inventory list` accepts, then maps the answer
        back to the active row the merge has to operate on.
        """
        row, _ = self.resolve_raw_device_record(target)
        if row:
            return row
        reconciled, choices = self.resolve_device_record(target)
        if not reconciled or len(choices) > 1:
            return None
        addresses = [reconciled.get("ip"), *(reconciled.get("addresses") or [])]
        for address in (str(value or "").strip() for value in addresses):
            if not address:
                continue
            active = self.state.one(
                "SELECT ip,hostname,hostname AS name,platform,model,serial,mac,source,last_seen,status FROM devices WHERE ip=?",
                (address,),
            )
            if active:
                return active
        return None

    def _merge_endpoint_detail(self, target: str, role: str) -> str:
        from netops_platform.core import fmt_time, normalize_target_literal
        """Explain why one side of a manual merge did not resolve to one device."""
        label = self.MERGE_ROLE_LABELS.get(role, role)
        for _, choices in (self.resolve_raw_device_record(target), self.resolve_device_record(target)):
            if len(choices) > 1:
                names = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
                more = "" if len(choices) <= 8 else f", and {len(choices) - 8} more"
                return (
                    f"The {label} '{target}' matched {len(choices)} devices: {names}{more}. "
                    "Use an exact hostname or management IP."
                )
        historical = self.state.one(
            "SELECT ip,name,last_seen FROM inventory_identity_state WHERE entity_type='device' "
            "AND (lower(COALESCE(name,''))=lower(?) OR lower(COALESCE(identity_value,''))=lower(?) OR COALESCE(ip,'')=?) "
            "ORDER BY last_seen DESC LIMIT 1",
            (target, target, normalize_target_literal(target)),
        )
        if historical:
            return (
                f"The {label} '{target}' is historical memory, not an active record. It was last seen as "
                f"{historical.get('name') or historical.get('ip')} ({historical.get('ip')}) on {fmt_time(historical.get('last_seen'))}. "
                "Review 'netrune inventory merges' and revoke an existing merge before retiring it again."
            )
        return f"The {label} '{target}' matched no active or historical device record."

    def cmd_inventory_forget(self, args: List[str], opts: GlobalOptions) -> int:
        from netops_platform.core import SUCCESS, VALIDATION, clean_display_name, now
        """Drop a device's derived state so the next scan adopts it afresh.

        A name recorded wrong stays wrong: every later sighting reconciles
        against the stored identity and inherits it. This is the way out that
        does not involve editing the database by hand.
        """
        rest = [item for item in args if item != "--with-names"]
        forget_identity = "--with-names" in args
        if not rest:
            return self.usage_error("inventory", "forget", opts, "A device is required.",
                                    "netrune inventory forget SITE-A-SW01 --confirm", VALIDATION)
        query = " ".join(rest).strip()
        device, choices = self.resolve_device_record(query)
        if not device:
            labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
            return self.usage_error(
                "inventory", "forget", opts,
                f"'{query}' did not resolve to one device." + (f" Candidates: {labels}" if labels else ""),
                "netrune inventory list <target>", VALIDATION)
        # Every address it has answered on, so a reconciled record is forgotten
        # whole rather than leaving the halves to merge back together.
        addresses = sorted({str(value) for value in
                            [device.get("ip"), *(device.get("addresses") or []),
                             *(device.get("historical_addresses") or [])] if value})
        footprint = self.state.device_footprint(addresses)
        name = clean_display_name(device.get("hostname") or "") or str(device.get("ip"))
        if not opts.confirm:
            lines = [f"Would forget {name} and every address it has answered on:",
                     "  " + ", ".join(addresses), "", "Rows that would be removed:"]
            lines += ([f"  {table:<28} {count}" for table, count in sorted(footprint.items())]
                      or ["  (none)"])
            lines += ["",
                      "Backups, audit events, and collected traffic history are not touched.",
                      "The next 'netrune inventory scan' adopts it again from what it reports.",
                      "Re-run with --confirm."]
            if not forget_identity:
                lines.append("Add --with-names to drop the recorded naming history too, so an old "
                             "name is not re-derived on the next reconciliation.")
            self.emit({"ok": False, "requires_confirm": True, "device": device,
                       "addresses": addresses, "footprint": footprint}, opts, "\n".join(lines))
            return VALIDATION
        removed = self.state.forget_device(addresses, forget_identity=forget_identity)
        self.state.flush_inventory_exports()
        self.state.record_audit_event("inventory", "inventory-forget", result="success",
                                      target=name,
                                      detail={"addresses": addresses, "removed": removed,
                                              "forgot_names": forget_identity})
        lines = [f"Forgot {name} ({len(addresses)} address(es): {', '.join(addresses)})."]
        lines += [f"  {table:<28} {count} row(s) removed" for table, count in sorted(removed.items())]
        lines.append("Run 'netrune inventory scan' to adopt it again from what it reports now.")
        self.emit({"ok": True, "device": name, "addresses": addresses, "removed": removed,
                   "forgot_names": forget_identity}, opts, "\n".join(lines))
        return SUCCESS

    def cmd_inventory_merge(self, args: List[str], opts: GlobalOptions) -> int:
        from netops_platform.core import CONFIRM_REQUIRED, SUCCESS, VALIDATION, fmt_time, timestamp_row
        positional, reason, error = self._manual_merge_arguments(args, expected=2)
        usage = "netrune inventory merge <old-device> <current-device> --reason 'hardware replacement' --dry-run"
        if error:
            return self.usage_error("inventory", "merge", opts, error, usage, VALIDATION)
        if not reason:
            return self.usage_error("inventory", "merge", opts, "A merge reason is required for chronology and audit.", usage, VALIDATION)
        source = self._resolve_merge_endpoint(positional[0])
        target = self._resolve_merge_endpoint(positional[1])
        if not source or not target:
            failed = "source" if not source else "target"
            detail = self._merge_endpoint_detail(positional[0] if not source else positional[1], failed)
            return self.usage_error("inventory", "merge", opts, detail, "netrune inventory list <target>", VALIDATION)
        if str(source.get("ip") or "") == str(target.get("ip") or ""):
            detail = (
                f"'{positional[0]}' and '{positional[1]}' both resolve to {source.get('hostname') or source.get('ip')} "
                f"({source.get('ip')}). They are already one device, so there is nothing to merge."
            )
            return self.usage_error("inventory", "merge", opts, detail, "netrune inventory merges", VALIDATION)
        assessment = identity_match_evidence(source, target, "switch")
        preview = {
            "ok": True,
            "operation": "manual-device-merge",
            "source": self.state._device_snapshot(source),
            "target": self.state._device_snapshot(target),
            "assessment": assessment,
            "reason": reason,
            "effects": [
                "source removed from active inventory",
                "source identities and observations retained in chronological memory",
                "source hostname and address resolve to the current target",
                "future matching source observations are suppressed until merge revocation",
            ],
            "requires_confirmation": True,
        }
        text = (
            f"Manual device merge preview\n"
            f"Historical source: {source.get('hostname') or source.get('ip')} ({source.get('ip')})\n"
            f"Current target: {target.get('hostname') or target.get('ip')} ({target.get('ip')})\n"
            f"Automatic assessment: {'same device' if assessment['same_device'] else 'manual override'} | Confidence: {assessment['confidence']}%\n"
            f"Conflicts retained as evidence: {', '.join(assessment['conflicts']) or 'none'}\n"
            f"Reason: {reason}"
        )
        if opts.dry_run:
            self.emit(preview, opts, text)
            return SUCCESS
        if not opts.confirm:
            return self.usage_error("inventory", "merge", opts, "Manual merge requires --dry-run for review or --confirm to apply.", usage, CONFIRM_REQUIRED)
        actor = os.environ.get("SUDO_USER") or os.environ.get("USER") or str(os.getuid())
        try:
            merge = self.state.create_device_merge(source, target, reason, actor)
            reconciliation = self.state.sync_derived_state()
            compatibility = self.state.export_flat_files()
        except ValueError as exc:
            return self.usage_error("inventory", "merge", opts, str(exc), usage, VALIDATION)
        self.state.record_audit_event(
            "inventory_device_merged", "inventory-merge", actor=actor, actor_uid=os.getuid(),
            target=f"{merge['source_key']}->{merge['target_key']}", result="success", reason=reason,
            detail={"merge_id": merge["merge_id"], "source_ip": merge["source_ip"], "target_ip": merge["target_ip"]},
        )
        payload = {**preview, "merge": timestamp_row(merge), "reconciliation": reconciliation, "compatibility_export": compatibility, "applied": True}
        self.emit(payload, opts, text + f"\nMerge: {merge['merge_id']} | Recorded: {fmt_time(merge['created_at'])}")
        return SUCCESS

    def cmd_inventory_unmerge(self, args: List[str], opts: GlobalOptions) -> int:
        from netops_platform.core import CONFIRM_REQUIRED, SUCCESS, VALIDATION, fmt_time, timestamp_row
        positional, reason, error = self._manual_merge_arguments(args, expected=1)
        usage = "netrune inventory unmerge <merge-id> --reason 'incorrect association' --confirm"
        if error:
            return self.usage_error("inventory", "unmerge", opts, error, usage, VALIDATION)
        if not reason:
            return self.usage_error("inventory", "unmerge", opts, "A revocation reason is required.", usage, VALIDATION)
        if not opts.confirm:
            return self.usage_error("inventory", "unmerge", opts, "Restoring a retired device requires --confirm.", usage, CONFIRM_REQUIRED)
        actor = os.environ.get("SUDO_USER") or os.environ.get("USER") or str(os.getuid())
        try:
            merge = self.state.revoke_device_merge(positional[0], reason, actor)
            reconciliation = self.state.sync_derived_state()
            compatibility = self.state.export_flat_files()
        except ValueError as exc:
            return self.usage_error("inventory", "unmerge", opts, str(exc), usage, VALIDATION)
        self.state.record_audit_event(
            "inventory_device_merge_revoked", "inventory-unmerge", actor=actor, actor_uid=os.getuid(),
            target=str(merge.get("merge_id") or positional[0]), result="success", reason=reason,
            detail={"source_ip": merge.get("source_ip"), "target_ip": merge.get("target_ip")},
        )
        payload = {"ok": True, "merge": timestamp_row(merge), "reconciliation": reconciliation, "compatibility_export": compatibility}
        self.emit(payload, opts, f"Manual merge revoked: {merge['merge_id']}\nHistorical device restored: {merge.get('source_name') or merge.get('source_ip')}\nRecorded: {fmt_time(merge['revoked_at'])}")
        return SUCCESS

    def inventory_rows(self,pattern:str,opts:GlobalOptions)->List[Dict[str,Any]]:
        from netops_platform.core import GlobalOptions, norm_status, pattern_or_all
        pattern = pattern_or_all(pattern)
        with self.state.connect() as con:
            device_observations = [dict(r) for r in con.execute(
                "SELECT ip,hostname,hostname AS name,platform,model,serial,mac,NULL AS switch_ip,NULL AS switch_name,NULL AS switch_port,source,last_seen,status FROM devices"
            )]
            canonical_devices = reconcile_device_rows(device_observations)
            self.state._overlay_manual_device_merges(con, canonical_devices)
        rows = []
        needle = pattern.lower()
        for item in canonical_devices:
            if opts.status and norm_status(item.get("status")) != opts.status:
                continue
            if needle and needle not in json.dumps(item, default=str).lower():
                continue
            item["kind"] = "device"
            rows.append(item)
        ap_opts = GlobalOptions(limit=100000, status=opts.status, site=opts.site)
        for ap in self.reconciled_ap_rows(pattern, ap_opts):
            row = dict(ap)
            row.update({
                "kind": "ap",
                "model": row.get("model") or "",
                "serial": row.get("serial") or "",
                "source": row.get("source") or "AP",
            })
            rows.append(row)
        if opts.site:
            rows=[r for r in rows if opts.site.lower() in json.dumps(r, default=str).lower()]
        rows.sort(key=lambda row: (0 if norm_status(row.get("status")) == "OFFLINE" else 1, str(row.get("kind") or ""), str(row.get("name") or row.get("ip") or "").lower()))
        return rows[:opts.limit]

    def cmd_inventory(self,args:List[str],opts:GlobalOptions)->int:
        from netops_platform.core import CHRONOLOGY, PARTIAL, SUCCESS, eprint, pattern_or_all, timestamp_rows
        if self.handle_help("inventory", args, opts): return SUCCESS
        verb=args[0] if args else "list"; rest=args[1:]
        if verb in {"import-flat","import"}:
            refresh = self.import_flat_state(("device", "ap", "topology"), "flat-import")
            c = refresh["imported"]
            self.emit({"ok":True, **refresh, "db":str(self.paths.sqlite_db)},opts,f"Imported flat caches: devices={c['devices']} aps={c['aps']} neighbors={c['neighbors']}; observation runs={len(refresh['ingest_runs'])}")
            return SUCCESS
        if verb in {"export-flat","export"}: c=self.state.export_flat_files(); self.emit({"ok":True,"exported":c},opts,f"Exported flat caches: devices={c['devices']} aps={c['aps']} neighbors={c['neighbors']}"); return SUCCESS
        if verb=="scan":
            rc=self.run_subprocess(self.legacy_cmd("netrune-discovery","--update",*(rest[:1])),opts)
            if rc==0 and not opts.dry_run:
                try: self.import_flat_state(("device",), "ssh-scan")
                except Exception as exc: eprint(f"Observation recording failed: {exc}"); return PARTIAL
            return rc
        if verb=="activity": return self.inventory_activity(rest,opts)
        if verb in {"forget","readopt"}: return self.cmd_inventory_forget(rest,opts)
        if verb=="merge": return self.cmd_inventory_merge(rest,opts)
        if verb in {"unmerge","merge-revoke"}: return self.cmd_inventory_unmerge(rest,opts)
        if verb in {"merges","merge-history"}:
            rows=timestamp_rows(self.state.list_device_merges(include_revoked=opts.all)); self.emit({"ok":True,"rows":rows,"count":len(rows),"chronology":CHRONOLOGY},opts,self.render_table(rows,["created_at","merge_id","source_name","source_ip","target_name","target_ip","reason","suppressed_observations","revoked_at"])); return SUCCESS
        if verb in {"list","details"}:
            pattern=pattern_or_all(" ".join(rest).strip())
            if verb=="details" and pattern and not opts.json:
                resolved, choices = self.resolve_device_record(pattern)
                detail_target = str(resolved.get("ip") or pattern) if resolved and len(choices) == 1 else pattern
                return self.run_subprocess(self.legacy_cmd("netrune-discovery","--details",detail_target),opts)
            rows=self.inventory_rows(pattern,opts); self.emit({"ok":True,"rows":rows,"count":len(rows)},opts,self.render_table(rows,["kind","ip","name","manufacturer","model","platform","status","last_seen"])); return SUCCESS
        return self.unknown_action("inventory", verb, opts)

    def ping(self,target:str,timeout:int)->bool:
        from netops_platform.core import normalize_target_literal
        target = normalize_target_literal(target)
        return subprocess.run(["ping","-c","1","-W",str(max(1,min(timeout,10))),target],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
    def inventory_activity(self,args:List[str],opts:GlobalOptions)->int:
        from netops_platform.core import GlobalOptions, PARTIAL, SUCCESS, VALIDATION, bounded_int, is_ipv4_literal, normalize_target_literal, now
        file_path=""; targets=[]; i=0
        while i<len(args):
            if args[i]=="--file" and i+1<len(args): file_path=args[i+1]; i+=2
            else: targets.append(args[i]); i+=1
        if file_path:
            p=Path(file_path).expanduser()
            if not p.exists(): return self.usage_error("inventory","activity",opts,f"List file not found: {p}","netrune inventory activity --file devices.txt",VALIDATION)
            targets.extend([l.strip() for l in p.read_text(encoding="utf-8",errors="ignore").splitlines() if l.strip() and not l.strip().startswith("#")])
        if not targets: return self.usage_error("inventory","activity",opts,"Missing target list. Provide --file or one or more targets.","netrune inventory activity --file devices.txt")
        inventory = self.inventory_rows("", GlobalOptions(limit=100000))

        def record_for(target: str) -> Dict[str, Any]:
            normalized = normalize_target_literal(target)
            exact = next(
                (
                    row for row in inventory
                    if normalized.lower() in {
                        str(value or "").lower()
                        for value in (
                            row.get("ip"), row.get("name") or row.get("hostname"),
                            *(row.get("aliases") or []), *(row.get("historical_addresses") or []),
                        )
                    }
                    or str(row.get("name") or row.get("hostname") or "").split(".", 1)[0].lower() == target.lower()
                ),
                None,
            )
            row = exact or {}
            ip = str(row.get("ip") or normalized or target)
            if not is_ipv4_literal(ip):
                with contextlib.suppress(OSError):
                    ip = socket.gethostbyname(ip)
            status = "ONLINE" if self.ping(ip, opts.timeout) else "OFFLINE"
            return {"target":target,"ip":ip,"kind":row.get("kind","unknown"),"name":row.get("name") or row.get("hostname") or "","platform":row.get("platform",""),"status":status,"checked_at":now()}

        workers = min(len(targets), bounded_int(opts.workers, 20, 1, 64))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="netops-activity") as executor:
            results = list(executor.map(record_for, targets))
        results.sort(key=lambda r:(0 if r["status"]=="OFFLINE" else 1,r.get("name") or r.get("ip")))
        self.emit({"ok":True,"rows":results,"count":len(results)},opts,self.render_table(results,["status","target","ip","kind","name","platform","checked_at"])); return SUCCESS if all(r["status"]=="ONLINE" for r in results) else PARTIAL
