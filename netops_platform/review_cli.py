"""`netrune health review`: the decisions waiting for the operator, one at a time.

Everything Netrune holds that only a person can settle, gathered in one
queue so the morning check can end on a clean slate:

- identity swap candidates (a switch or AP that disappeared and one that
  appeared with matching signals: the same hardware, or a replacement?) and
  site-rename clusters of them;
- workbook questions from `excel inspect/sync --free-ips`: an address whose
  row names something Netrune never saw and nothing answers (free?), and a
  row whose keys point at two switches (which is it?).

Each item is a yes/no or a pick-one. Identity answers act at once (a merge,
or the pair is closed and never proposed again); workbook answers are kept
and the next `excel sync` of that workbook writes them, exactly as
--accept-free/--reject-free/--prefer would.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

USAGE = "netrune health review [--list] [--kind identity|excel] | netrune health review answer <id> <choice>"


def _id(prefix: str, *parts: Any) -> str:
    return prefix + hashlib.sha1("|".join(str(part) for part in parts).encode()).hexdigest()[:6]


def _actor() -> str:
    return os.environ.get("SUDO_USER") or os.environ.get("USER") or str(os.getuid())


def _when(epoch: Any) -> str:
    from netops_platform.core import fmt_time
    return (fmt_time(epoch) or "?")[:10]


def _side(record: Dict[str, Any]) -> str:
    mac = str(record.get("mac") or "")
    if len(mac) == 12:
        mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2))
    where = " ".join(part for part in (record.get("switch_name"), record.get("switch_port")) if part)
    return "  ".join(part for part in (record.get("name") or "(no name)", mac, record.get("ip") or "", where) if part)


def _identity_item(single: Dict[str, Any]) -> Dict[str, Any]:
    row = single["row"]
    attrs = json.loads(row.get("attrs_json") or "{}")
    old, new, entity_type = attrs["old"], attrs["new"], attrs.get("entity_type", "device")
    noun = "AP" if entity_type == "ap" else "switch"
    signals = [name.replace("_", " ") for name, on in (attrs.get("signals") or {}).items() if on is True]
    return {
        "id": _id("s", row["rel_key"]), "kind": "identity", "entity_type": entity_type, "rel_keys": [row["rel_key"]],
        "pairs": [(old, new)],
        "question": f"{old.get('name') or old.get('ip') or '?'} -> {new.get('name') or new.get('ip') or '?'}: same {noun}, or a replacement?",
        "detail": [f"was  {_side(old)}  last seen {_when(old.get('last_seen'))}",
                   f"now  {_side(new)}  since {_when(new.get('first_seen'))}",
                   f"matching: {', '.join(signals) or 'see netrune health attention'}; confidence {row.get('confidence')}%"],
        "options": [("y", f"yes, the same {noun} (merge the old record into it)"), ("n", f"no, different {noun}s")],
    }


def _cluster_item(cluster: Dict[str, Any]) -> Dict[str, Any]:
    members = cluster["members"]
    entity_type = members[0].get("entity_type", "device")
    noun = "AP" if entity_type == "ap" else "switch"
    keys = sorted(member["row"]["rel_key"] for member in members)
    examples = [f"{member['old'].get('name')} -> {member['new'].get('name')}" for member in members[:3]]
    return {
        "id": _id("r", *keys), "kind": "identity-cluster", "entity_type": entity_type, "rel_keys": keys,
        "pairs": [(member["old"], member["new"]) for member in members],
        "question": f"{len(members)} {noun}s renamed {cluster['old_location_prefix']} -> {cluster['new_location_prefix']}?",
        "detail": [f"e.g. {example}" for example in examples] + ([f"... and {len(members) - 3} more"] if len(members) > 3 else []),
        "options": [("y", f"yes, the same {noun}s renamed (merge each)"), ("n", "no, different hardware")],
    }


def _excel_items(app: Any) -> List[Dict[str, Any]]:
    from netops_platform.excel_cli import pending_review
    items = []
    for entry in pending_review(app):
        book = Path(entry["workbook"]).name
        where = f"{book} > {entry['sheet']}, row {entry['row']}"
        if entry["kind"] == "excel-free":
            items.append({
                "id": _id("x", entry["workbook"], entry["sheet"], entry["ip"]), "kind": "excel-free", "entry": entry,
                "question": f"{where}: is {entry['ip']} free to use?",
                "detail": [f"The row names '{entry.get('named') or '?'}'; Netrune has never seen it, and nothing answered on the address."],
                "options": [("y", "yes, free to use"), ("n", "no, keep it allocated")],
            })
        elif entry["kind"] == "excel-conflict":
            votes = sorted((entry.get("votes") or {}).items())
            items.append({
                "id": _id("x", entry["workbook"], entry["sheet"], entry["row"], entry.get("label")), "kind": "excel-conflict",
                "entry": entry, "question": f"{where} ('{entry.get('label')}'): which switch is this row?",
                "detail": ["Its keys point at different switches; the row is left alone until you choose."],
                "options": [(str(number), f"the {kind} says {device}") for number, (kind, device) in enumerate(votes, 1)],
                "votes": votes,
            })
    return items


def pending_items(app: Any, kind: str = "") -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    if kind in {"", "identity"}:
        from netops_platform.identity import cluster_rename_candidates
        _, raw = app._identity_candidate_items(300)
        config = app.state._continuity_config()
        parsed = []
        for row in raw:
            try:
                attrs = json.loads(row.get("attrs_json") or "{}")
            except (TypeError, ValueError):
                continue
            if isinstance(attrs.get("old"), dict) and isinstance(attrs.get("new"), dict):
                parsed.append({**attrs, "confidence": row.get("confidence"), "row": row})
        clusters, singles = cluster_rename_candidates(parsed, min_members=config["cluster_min_members"])
        items += [_cluster_item(cluster) for cluster in clusters]
        items += [_identity_item(single) for single in singles if int(single.get("confidence") or 0) >= config["confidence_floor"]]
    if kind in {"", "excel"}:
        items += _excel_items(app)
    return items


def apply(app: Any, item: Dict[str, Any], choice: str) -> Tuple[str, bool]:
    """Act on one answer; returns (what happened, whether derived state must be re-synced)."""
    actor = _actor()
    if item["kind"] in {"identity", "identity-cluster"}:
        if choice == "n":
            for rel_key in item["rel_keys"]:
                app.state.resolve_continuity_candidate(rel_key, "different", actor)
            return "kept apart; not asked again.", False
        merged, closed = 0, 0
        for rel_key, (old, new) in zip(item["rel_keys"], item["pairs"]):
            try:
                merge = app.state.create_manual_merge(item["entity_type"], old, new, "confirmed in health review", actor)
                app.state.record_audit_event(
                    "ap_device_merged" if item["entity_type"] == "ap" else "device_merged", "health-review", actor=actor,
                    actor_uid=os.getuid(), target=f"{merge['source_key']}->{merge['target_key']}", result="success",
                    reason="confirmed in health review", detail={"merge_id": merge["merge_id"]})
                merged += 1
            except ValueError as exc:
                # Two records the merge machinery will not join (they share an
                # address): the old one is already only history, so the
                # verdict is recorded and the question closed.
                app.state.resolve_continuity_candidate(rel_key, "same", actor, note=str(exc))
                closed += 1
        parts = ([f"merged {merged}"] if merged else []) + ([f"recorded {closed} as the same (already one record)"] if closed else [])
        return "; ".join(parts) + ".", bool(merged)
    from netops_platform.excel_cli import record_answer
    entry = item["entry"]
    if item["kind"] == "excel-free":
        record_answer(app, entry["workbook"], entry["sheet"], "free", entry["ip"], "accepted" if choice == "y" else "rejected")
        return ("marked free" if choice == "y" else "kept allocated") + "; the next excel sync writes it.", False
    kind, device = item["votes"][int(choice) - 1]
    record_answer(app, entry["workbook"], entry["sheet"], "prefer", entry["row"], {"kind": kind, "label": entry.get("label", "")})
    return f"row follows its {kind} ({device}); the next excel sync writes it.", False


def _valid(item: Dict[str, Any], choice: str) -> bool:
    return choice in {key for key, _ in item["options"]}


def _finish(app: Any, resync: bool, answered_books: Sequence[str]) -> List[str]:
    lines = []
    if resync:
        app.state.sync_derived_state()
        app.state.export_flat_files()
    for book in sorted(set(answered_books)):
        lines.append(f"Write your answers into {Path(book).name}: netrune excel sync '{book}' --free-ips --confirm")
    return lines


def session(app: Any, opts: Any, items: List[Dict[str, Any]]) -> int:
    """Ask about each item in turn: y/n or a number, s to skip, q to stop."""
    from netops_platform.core import SUCCESS
    counts = {"answered": 0, "skipped": 0}
    resync = False
    books: List[str] = []
    print(f"{len(items)} decision(s) waiting.")
    for number, item in enumerate(items, 1):
        print(f"\n[{number}/{len(items)}] {item['question']}")
        for line in item["detail"]:
            print(f"  {line}")
        choices = "   ".join(f"[{key}] {label}" for key, label in item["options"]) + "   [s] skip   [q] stop"
        while True:
            try:
                answer = input(f"  {choices}: ").strip().lower()
            except EOFError:
                answer = "q"
            if answer in {"s", ""}:
                counts["skipped"] += 1
                break
            if answer == "q":
                counts["skipped"] += len(items) - number + 1
                return _report_session(app, counts, resync, books)
            if _valid(item, answer):
                message, needs_sync = apply(app, item, answer)
                resync = resync or needs_sync
                if item["kind"].startswith("excel"):
                    books.append(item["entry"]["workbook"])
                counts["answered"] += 1
                print(f"  -> {message}")
                break
            print("  Please answer with one of the letters or numbers shown.")
    return _report_session(app, counts, resync, books)


def _report_session(app: Any, counts: Dict[str, int], resync: bool, books: List[str]) -> int:
    from netops_platform.core import PARTIAL, SUCCESS
    lines = _finish(app, resync, books)
    remaining = len(pending_items(app))
    print(f"\nAnswered {counts['answered']}, skipped {counts['skipped']}. "
          + ("Clean slate." if not remaining else f"{remaining} still waiting: netrune health review"))
    for line in lines:
        print(line)
    return SUCCESS if not remaining else PARTIAL


def _rows(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [{"id": item["id"], "kind": item["kind"], "question": item["question"],
             "choices": " / ".join(f"{key}={label}" for key, label in item["options"])} for item in items]


def interactive(opts: Any) -> bool:
    return not (opts.json or opts.plain) and sys.stdin.isatty() and sys.stdout.isatty()


def dispatch(app: Any, args: List[str], opts: Any) -> int:
    from netops_platform.core import PARTIAL, SUCCESS, VALIDATION
    kind = ""
    rest: List[str] = []
    listing = False
    index = 0
    while index < len(args):
        if args[index] == "--kind" and index + 1 < len(args):
            kind = args[index + 1].lower(); index += 2
        elif args[index] == "--list":
            listing = True; index += 1
        else:
            rest.append(args[index]); index += 1
    if kind not in {"", "identity", "excel"}:
        return app.usage_error("health", "review", opts, "--kind is identity or excel.", USAGE, VALIDATION)
    items = pending_items(app, kind)
    if rest and rest[0] == "answer":
        if len(rest) != 3:
            return app.usage_error("health", "review", opts, "answer takes an item id and a choice.", USAGE, VALIDATION)
        item = next((item for item in items if item["id"] == rest[1]), None)
        if not item:
            return app.usage_error("health", "review", opts, f"No waiting decision has id {rest[1]}.", "netrune health review --list", VALIDATION)
        choice = rest[2].lower()
        if not _valid(item, choice):
            return app.usage_error("health", "review", opts, f"{rest[1]} takes: {', '.join(key for key, _ in item['options'])}.", USAGE, VALIDATION)
        message, needs_sync = apply(app, item, choice)
        lines = _finish(app, needs_sync, [item["entry"]["workbook"]] if item["kind"].startswith("excel") else [])
        app.emit({"ok": True, "id": item["id"], "choice": choice, "result": message}, opts, "\n".join([f"{item['id']}: {message}", *lines]))
        return SUCCESS
    if rest:
        return app.usage_error("health", "review", opts, f"Unknown review argument: {rest[0]}", USAGE, VALIDATION)
    if not items:
        app.emit({"ok": True, "items": [], "count": 0}, opts, "Nothing waiting for you: clean slate.")
        return SUCCESS
    if listing or not interactive(opts):
        app.emit({"ok": True, "items": _rows(items), "count": len(items), "summary": f"{len(items)} decision(s) waiting"}, opts,
                 app.render_table(_rows(items), ["id", "kind", "question", "choices"])
                 + f"\n{len(items)} decision(s) waiting. Go through them: netrune health review")
        return PARTIAL
    return session(app, opts, items)
