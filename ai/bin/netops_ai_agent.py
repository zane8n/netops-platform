#!/usr/bin/env python3
"""Standalone NetOps AI workflow wrapper.

The wrapper intentionally does not import NetOps internals. It executes only
approved public `netops` v7 workflows from ai/config/tools.yaml.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

SCRIPT_PATH = Path(__file__).resolve()
AI_DIR = SCRIPT_PATH.parents[1]
NETOPS_ROOT = AI_DIR.parent
CONFIG_DIR = AI_DIR / "config"
LOG_DIR = AI_DIR / "logs"
NETOPS_BIN = Path(os.environ.get("NETOPS_AI_NETOPS_BIN", str(NETOPS_ROOT / "netops"))).expanduser()
TOOLS_FILE = Path(os.environ.get("NETOPS_AI_TOOLS", str(CONFIG_DIR / "tools.yaml"))).expanduser()
ALIASES_FILE = Path(os.environ.get("NETOPS_AI_ALIASES", str(CONFIG_DIR / "aliases.yaml"))).expanduser()
SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
SAFE_TEXT_RE = re.compile(r"^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]{1,500}$")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
FORBIDDEN_BINARIES = {"netops-control", "netops-discovery", "netops-probe", "netops-connect", "netops-legacy"}
DOWN_STATUSES = {"down", "notconnect", "disabled", "err-disabled", "inactive", "suspended"}
STATUS_ALIASES = {
    "connected": "connected",
    "connect": "connected",
    "notconnect": "notconnect",
    "notconnected": "notconnect",
    "not-connected": "notconnect",
    "disabled": "disabled",
    "disable": "disabled",
    "err-disabled": "err-disabled",
    "errdisable": "err-disabled",
    "errdisabled": "err-disabled",
    "down": "down",
    "up": "up",
    "inactive": "inactive",
    "suspended": "suspended",
    "monitoring": "monitoring",
    "routed": "routed",
    "trunk": "trunk",
}


class PolicyError(RuntimeError):
    pass


class ClarificationNeeded(RuntimeError):
    pass


def parse_scalar(value: str) -> Any:
    text = value.strip()
    if text.lower() == "true":
        return True
    if text.lower() == "false":
        return False
    if text.lower() in {"null", "none"}:
        return None
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        text = text[1:-1]
        text = text.replace('\\"', '"').replace("\\'", "'")
        return text
    if re.fullmatch(r"-?\d+", text):
        try:
            return int(text)
        except ValueError:
            return text
    return text


def load_simple_yaml(path: Path) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    current_section: Optional[str] = None
    current_item: Optional[str] = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if indent == 0 and line.endswith(":"):
            current_section = line[:-1].strip()
            current_item = None
            data[current_section] = {}
            continue
        if current_section and indent == 2:
            if line.endswith(":"):
                current_item = line[:-1].strip()
                data[current_section][current_item] = {}
                continue
            if ":" in line:
                key, value = line.split(":", 1)
                data[current_section][key.strip()] = parse_scalar(value)
                current_item = None
                continue
        if current_section and current_item and indent >= 4 and ":" in line:
            key, value = line.split(":", 1)
            data[current_section][current_item][key.strip()] = parse_scalar(value)
            continue
        raise ValueError(f"Unsupported YAML line in {path}: {raw}")
    return data


def load_tools() -> Dict[str, Dict[str, Any]]:
    data = load_simple_yaml(TOOLS_FILE)
    tools = data.get("tools")
    if not isinstance(tools, dict):
        raise ValueError(f"No tools section found in {TOOLS_FILE}")
    return tools


def normalize_phrase(value: str) -> str:
    text = value.lower().replace("-", " ").replace("_", " ")
    text = re.sub(r"[^a-z0-9.:\s]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def load_aliases() -> Dict[str, str]:
    if not ALIASES_FILE.exists():
        return {}
    data = load_simple_yaml(ALIASES_FILE)
    raw_aliases = data.get("aliases", {})
    if not isinstance(raw_aliases, dict):
        return {}
    return {normalize_phrase(str(alias)): str(target).strip() for alias, target in raw_aliases.items()}


def extract_candidate_target(text: str) -> str:
    patterns = [
        r"\b(?:on|for|from|of)\s+(?:the\s+)?([A-Za-z0-9_.:-]+)(?:\s+switch)?\b",
        r"\b(?:switch|device)\s+([A-Za-z0-9_.:-]+)\b",
        r"\b([A-Z][A-Z0-9_.:-]{5,})\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1).strip(".,;:()[]{}")
    return ""


def compact_search_token(value: str) -> str:
    normalized = normalize_phrase(value)
    normalized = re.sub(r"\b(?:switch|device)\b", " ", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return re.sub(r"[^A-Za-z0-9_.:-]+", "", normalized)


def resolve_search_token(value: str, aliases: Dict[str, str]) -> str:
    raw = " ".join(str(value or "").split()).strip()
    if not raw:
        return ""
    normalized = normalize_phrase(raw)
    alias_matches = [
        alias
        for alias in aliases
        if alias and re.search(rf"(?<!\w){re.escape(alias)}(?!\w)", normalized)
    ]
    if alias_matches:
        best = sorted(alias_matches, key=lambda item: (" switch" in item, len(item)))[0]
        return compact_search_token(best)
    reverse_matches = [
        alias
        for alias, target in aliases.items()
        if normalize_phrase(target) == normalized
    ]
    if reverse_matches:
        best = sorted(reverse_matches, key=lambda item: (" switch" in item, len(item)))[0]
        return compact_search_token(best)
    candidate = extract_candidate_target(raw)
    if candidate:
        candidate_normalized = normalize_phrase(candidate)
        if candidate_normalized in aliases:
            return compact_search_token(candidate_normalized)
        if SAFE_TARGET_RE.fullmatch(candidate):
            return compact_search_token(candidate)
    if SAFE_TARGET_RE.fullmatch(raw):
        return compact_search_token(raw)
    return ""


def resolve_switch(value: str, aliases: Dict[str, str]) -> str:
    raw = " ".join(str(value or "").split()).strip()
    if not raw:
        return ""
    normalized = normalize_phrase(raw)
    if normalized in aliases:
        return aliases[normalized]
    for alias, target in sorted(aliases.items(), key=lambda item: len(item[0]), reverse=True):
        if alias and re.search(rf"(?<!\w){re.escape(alias)}(?!\w)", normalized):
            return target
    candidate = extract_candidate_target(raw)
    if candidate:
        candidate_normalized = normalize_phrase(candidate)
        if candidate_normalized in aliases:
            return aliases[candidate_normalized]
        if SAFE_TARGET_RE.fullmatch(candidate):
            return candidate
    if SAFE_TARGET_RE.fullmatch(raw):
        return raw
    return ""


def resolve_tool_switch(tool: Dict[str, Any], value: str, aliases: Dict[str, str]) -> str:
    if str(tool.get("target_resolution") or "").strip().lower() == "search_token":
        return resolve_search_token(value, aliases)
    return resolve_switch(value, aliases)


def alias_regex(alias: str) -> str:
    tokens = [re.escape(token) for token in normalize_phrase(alias).split() if token]
    if not tokens:
        return ""
    return r"(?<!\w)" + r"[-_\s]+".join(tokens) + r"(?!\w)"


def expand_query_aliases(value: str, aliases: Dict[str, str]) -> str:
    text = str(value or "")
    for alias, target in sorted(aliases.items(), key=lambda item: len(item[0]), reverse=True):
        pattern = alias_regex(alias)
        if pattern:
            text = re.sub(pattern, target, text, flags=re.IGNORECASE)
    return text


def native_state_query(value: str, aliases: Dict[str, str]) -> str:
    text = str(value or "").strip()
    expanded = expand_query_aliases(text, aliases)
    normalized = normalize_phrase(text)
    target = resolve_switch(text, aliases)
    if target and any(term in normalized for term in ("inventory history", "identity history", "record history", "older names", "previous names")):
        return f"identity history {target}"
    return expanded


def choose_workflow(question: str) -> Optional[str]:
    text = normalize_phrase(question)
    has_interface = any(term in text for term in ("interface", "interfaces", "port", "ports"))
    has_down = any(term in text for term in ("down", "offline", "not connected", "notconnect", "disabled", "err disabled"))
    if has_interface and has_down:
        return "get_down_interfaces"
    vlan_operation = any(term in text for term in ("propagation", "propagate", "locate", "cascade", "depth", "trunk", "uplink"))
    if "vlan" in text and not vlan_operation and any(term in text for term in ("summary", "show", "list", "what", "which")):
        return "get_vlan_summary"
    if has_interface:
        return "get_interface_summary"
    # The core Ask engine is authoritative for state retrieval and command planning.
    # Narrow live interface/VLAN reads stay here because they execute a device show.
    return "answer_from_netops_state"


def placeholders(template: str) -> List[str]:
    return sorted(set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", template)) - {"netops"})


def validate_target(name: str, value: str) -> None:
    if name in {"switch", "target", "device"} and not SAFE_TARGET_RE.fullmatch(value):
        raise PolicyError(f"Unsafe {name} value: {value!r}")
    if name in {"query", "question"} and not SAFE_TEXT_RE.fullmatch(value):
        raise PolicyError(f"Unsafe {name} value")


def build_argv(tool: Dict[str, Any], params: Dict[str, str]) -> List[str]:
    template = str(tool.get("command") or "").strip()
    if not template:
        raise PolicyError("Tool has no command template")
    values = {"netops": str(NETOPS_BIN), **params}
    for name in placeholders(template):
        value = str(values.get(name) or "").strip()
        if not value:
            raise ClarificationNeeded(f"Missing required value: {name}")
        validate_target(name, value)
        values[name] = shlex.quote(value)
    rendered = template
    for key, value in values.items():
        rendered = rendered.replace("{" + key + "}", str(value))
    argv = shlex.split(rendered)
    validate_argv(argv, tool)
    return argv


def validate_argv(argv: Sequence[str], tool: Dict[str, Any]) -> None:
    if not argv:
        raise PolicyError("Empty command is not allowed")
    try:
        command_path = Path(argv[0]).resolve()
        expected_path = NETOPS_BIN.resolve()
    except OSError as exc:
        raise PolicyError(str(exc)) from exc
    if command_path != expected_path:
        raise PolicyError(f"Workflow must start with public netops launcher: {NETOPS_BIN}")
    names = {Path(part).name for part in argv}
    blocked = names & FORBIDDEN_BINARIES
    if blocked:
        raise PolicyError(f"Direct helper execution is blocked: {', '.join(sorted(blocked))}")
    if len(argv) >= 3 and argv[1] == "device" and argv[2] == "config":
        raise PolicyError("Device configuration workflows are blocked in this AI wrapper")
    if len(argv) >= 3 and argv[1] == "vlan" and argv[2] == "set":
        raise PolicyError("VLAN change workflows are blocked in this AI wrapper")
    if not bool(tool.get("read_only", False)):
        raise PolicyError("Only read-only workflows are enabled")
    if bool(tool.get("requires_confirmation", False)):
        raise PolicyError("Confirmation workflows are not enabled in this wrapper")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def log_run(workflow: str, argv: Sequence[str], result: Dict[str, Any]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    record = {
        "created_at": int(time.time()),
        "workflow": workflow,
        "command": shlex.join(list(argv)),
        "exit_code": result.get("exit_code"),
        "success": result.get("success"),
        "accepted_nonzero_exit": result.get("accepted_nonzero_exit", False),
        "duration_seconds": result.get("duration_seconds"),
        "stdout_excerpt": str(result.get("stdout") or "")[:1000],
        "stderr_excerpt": str(result.get("stderr") or "")[:1000],
    }
    with (LOG_DIR / "agent_runs.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def execute_workflow(workflow: str, tool: Dict[str, Any], params: Dict[str, str], dry_run: bool = False) -> Dict[str, Any]:
    argv = build_argv(tool, params)
    if dry_run:
        return {
            "workflow": workflow,
            "command": shlex.join(argv),
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "duration_seconds": 0.0,
            "dry_run": True,
            "success": True,
            "accepted_nonzero_exit": False,
        }
    started = time.time()
    timeout_seconds = int(tool.get("timeout_seconds") or 120)
    try:
        completed = subprocess.run(
            argv,
            cwd=str(NETOPS_ROOT),
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
        result = {
            "workflow": workflow,
            "command": shlex.join(argv),
            "exit_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "duration_seconds": round(time.time() - started, 3),
            "dry_run": False,
        }
    except subprocess.TimeoutExpired as exc:
        result = {
            "workflow": workflow,
            "command": shlex.join(argv),
            "exit_code": 9,
            "stdout": exc.stdout or "",
            "stderr": f"Workflow timed out after {timeout_seconds} seconds.",
            "duration_seconds": round(time.time() - started, 3),
            "dry_run": False,
        }
    result["success"] = int(result.get("exit_code") or 0) == 0
    result["accepted_nonzero_exit"] = False
    if not result["success"] and bool(tool.get("accept_nonzero_if_parsed", False)) and tool_output_is_usable(tool, result):
        result["success"] = True
        result["accepted_nonzero_exit"] = True
    log_run(workflow, argv, result)
    return result


def normalize_status_token(token: str) -> str:
    key = token.strip().strip("*,").lower()
    return STATUS_ALIASES.get(key, key)


def looks_like_interface_name(value: str) -> bool:
    if re.match(r"^\d+(?:/\d+)+$", value):
        return True
    return bool(re.match(r"^(?:[A-Za-z]+\d|[A-Za-z]+\d+/|[A-Za-z]+[A-Za-z]*\d|Gi|Fa|Te|Twe|Hu|Eth|Po|Vl|Lo|mgmt)", value, re.IGNORECASE))


def parse_interface_status(text: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for raw_line in strip_ansi(text).splitlines():
        line = raw_line.strip()
        if not line or set(line) <= {"-", "=", " "}:
            continue
        lower = line.lower()
        if lower.startswith(("usage:", "error:", "warning:", "[status]")):
            continue
        tokens = line.split()
        if len(tokens) < 3:
            continue
        if "status" in {token.lower() for token in tokens} and any(token.lower() in {"port", "interface"} for token in tokens):
            continue
        interface = tokens[0]
        if not looks_like_interface_name(interface):
            continue
        status_index = None
        status = ""
        for index, token in enumerate(tokens[1:], start=1):
            normalized = normalize_status_token(token)
            if normalized in STATUS_ALIASES.values():
                status_index = index
                status = normalized
                break
        if status_index is None:
            continue
        description = " ".join(tokens[1:status_index]).strip() or "-"
        vlan = tokens[status_index + 1] if status_index + 1 < len(tokens) else ""
        duplex = tokens[status_index + 2] if status_index + 2 < len(tokens) else ""
        speed = tokens[status_index + 3] if status_index + 3 < len(tokens) else ""
        media_type = " ".join(tokens[status_index + 4:]) if status_index + 4 < len(tokens) else ""
        rows.append({
            "interface": interface,
            "description": description,
            "status": status,
            "vlan": vlan,
            "duplex": duplex,
            "speed": speed,
            "type": media_type,
        })
    return rows


def markdown_table(rows: Sequence[Dict[str, Any]], columns: Sequence[str]) -> str:
    labels = {column: column.replace("_", " ").title() for column in columns}
    table: List[List[str]] = [[labels[column] for column in columns]]
    for row in rows:
        table.append([str(row.get(column, "") if row.get(column, "") is not None else "") for column in columns])
    widths = [max(len(line[index]) for line in table) for index in range(len(columns))]
    rendered = []
    rendered.append("| " + " | ".join(table[0][index].ljust(widths[index]) for index in range(len(columns))) + " |")
    rendered.append("| " + " | ".join("-" * widths[index] for index in range(len(columns))) + " |")
    for line in table[1:]:
        rendered.append("| " + " | ".join(line[index].ljust(widths[index]) for index in range(len(columns))) + " |")
    return "\n".join(rendered)


def preferred_columns(rows: Sequence[Dict[str, Any]], preferred: Sequence[str], limit: int = 8) -> List[str]:
    columns = [column for column in preferred if any(column in row for row in rows)]
    for raw in ("first_seen", "last_seen", "last_failed", "created_at", "updated_at", "started_at", "finished_at"):
        if f"{raw}_iso" in columns and raw in columns:
            columns.remove(raw)
    return columns[:limit]


def truncate_text(text: str, max_lines: int = 80, max_chars: int = 6000) -> str:
    clean = strip_ansi(text).strip()
    lines = clean.splitlines()
    if len(lines) > max_lines:
        clean = "\n".join(lines[:max_lines]) + f"\n... truncated after {max_lines} lines"
    if len(clean) > max_chars:
        clean = clean[:max_chars] + f"\n... truncated after {max_chars} characters"
    return clean


def parse_json(text: str) -> Optional[Any]:
    clean = text.strip()
    if not clean:
        return None
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        return None


def tool_output_is_usable(tool: Dict[str, Any], result: Dict[str, Any]) -> bool:
    if int(result.get("exit_code") or 0) in {0, 9}:
        return int(result.get("exit_code") or 0) == 0
    output = str(result.get("stdout") or "")
    parser = str(tool.get("parser") or "text")
    if parser in {"interface_status", "interface_status_down"}:
        return bool(parse_interface_status(output))
    if parser == "json_summary":
        return parse_json(output) is not None
    return False


def first_rows_from_json(data: Any) -> Tuple[List[Dict[str, Any]], str]:
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)], "rows"
    if not isinstance(data, dict):
        return [], ""
    for key in ("rows", "devices", "aps", "neighbors", "current", "timeline", "items", "results"):
        value = data.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)], key
    record = data.get("record") or data.get("device") or data.get("ap")
    if isinstance(record, dict):
        return [record], "record"
    return [], ""


def render_json_summary(workflow: str, result: Dict[str, Any]) -> str:
    text = result.get("stdout") or ""
    data = parse_json(text)
    if data is None:
        return "NetOps completed, but the wrapper could not parse JSON output. Raw output:\n\n" + truncate_text(text)
    rows, key = first_rows_from_json(data)
    if rows:
        preferred = [
            "kind", "name", "hostname", "ip", "mac", "status", "platform", "model", "serial",
            "rel_type", "subject_kind", "subject_id", "object_kind", "object_id",
            "switch_name", "switch_port", "source", "confidence", "avg_confidence",
            "count", "event_type", "detail", "created_at_iso", "last_seen_iso", "created_at", "last_seen",
        ]
        columns = preferred_columns(rows, preferred)
        if not columns:
            columns = list(rows[0].keys())[:6]
        shown = rows[:30]
        suffix = "" if len(rows) <= 30 else f"\n\nShowing 30 of {len(rows)} rows."
        noun = "result" if len(rows) == 1 else "results"
        return f"NetOps returned {len(rows)} {noun} for `{workflow}`.\n\n" + markdown_table(shown, columns) + suffix
    if isinstance(data, dict):
        summary_rows = [{"field": key, "value": value} for key, value in data.items() if not isinstance(value, (dict, list))]
        if summary_rows:
            return f"NetOps returned a summary for `{workflow}`.\n\n" + markdown_table(summary_rows, ["field", "value"])
    return "NetOps returned JSON, but there were no obvious rows to summarize."


def render_memory_switch(result: Dict[str, Any]) -> str:
    data = parse_json(result.get("stdout") or "")
    if not isinstance(data, dict):
        return "NetOps completed, but the wrapper could not parse memory JSON output. Raw output:\n\n" + truncate_text(result.get("stdout") or "")
    target = str(data.get("target") or "target")
    counts = data.get("counts") if isinstance(data.get("counts"), dict) else {}
    attachments = data.get("attachments") if isinstance(data.get("attachments"), dict) else {}
    switches = data.get("switches") if isinstance(data.get("switches"), list) else []
    aps = attachments.get("aps") if isinstance(attachments.get("aps"), list) else []
    neighbors = attachments.get("neighbors") if isinstance(attachments.get("neighbors"), list) else []
    relationships = attachments.get("relationships") if isinstance(attachments.get("relationships"), list) else []
    lines = [
        f"NetOps memory for `{target}`: "
        f"{counts.get('switches', len(switches))} switch match(es), "
        f"{counts.get('aps', len(aps))} AP attachment(s), "
        f"{counts.get('neighbors', len(neighbors))} topology neighbor(s), "
        f"{counts.get('relationships', len(relationships))} current relationship(s)."
    ]
    if switches:
        columns = preferred_columns(switches, ["hostname", "ip", "platform", "status", "last_seen_iso", "last_seen"])
        lines.append("\nSwitch match\n" + markdown_table(switches[:5], columns))
    if aps:
        columns = preferred_columns(aps, ["name", "ip", "mac", "status", "switch_name", "switch_port", "platform", "last_seen_iso", "last_seen"])
        lines.append("\nAP attachments\n" + markdown_table(aps[:30], columns))
    else:
        lines.append("\nAP attachments: none in current memory.")
    if neighbors:
        lines.append("\nTopology neighbors\n" + markdown_table(neighbors[:30], ["local_port", "remote_name", "remote_port", "remote_ip"]))
    else:
        lines.append("\nTopology neighbors: none in current memory.")
    if relationships:
        lines.append("\nCurrent relationships\n" + markdown_table(relationships[:30], ["rel_type", "subject_kind", "subject_id", "object_kind", "object_id", "switch_port", "source", "confidence", "status"]))
    return "\n".join(lines)


def render_ask_json(workflow: str, result: Dict[str, Any]) -> str:
    data = parse_json(result.get("stdout") or "")
    if not isinstance(data, dict):
        return "NetOps completed, but the wrapper could not parse the deterministic ask JSON. Raw output:\n\n" + truncate_text(result.get("stdout") or "")
    answer = str(data.get("answer") or data.get("error") or "NetOps returned no answer.")
    plan = data.get("command_plan")
    if isinstance(plan, dict):
        lines = [answer]
        lines.append(
            f"\nRegistered action: `{plan.get('action')}` | status: `{plan.get('status')}` | "
            f"safety: `{plan.get('safety_class')}`"
        )
        if plan.get("command"):
            lines.append(f"\nExact preview:\n\n`{plan['command']}`")
        if plan.get("missing_args"):
            lines.append("\nStill required: " + ", ".join(str(item) for item in plan["missing_args"]) + ".")
        if plan.get("execution_hint"):
            lines.append(f"\nExplicit CLI execution:\n\n`{plan['execution_hint']}`")
        if plan.get("reason"):
            lines.append(f"\nRestriction: {plan['reason']}")
        lines.append("\nThe AI wrapper only prepared this plan; it did not execute the planned action.")
        return "\n".join(lines)
    rows = []
    result_block = data.get("result")
    if isinstance(result_block, dict) and isinstance(result_block.get("rows"), list):
        rows = [row for row in result_block["rows"] if isinstance(row, dict)]
    if not rows and isinstance(data.get("rows"), list):
        rows = [row for row in data["rows"] if isinstance(row, dict)]
    if rows:
        preferred = [
            "kind", "name", "hostname", "ip", "mac", "status", "rel_type", "subject_kind",
            "subject_id", "object_kind", "object_id", "switch_name", "switch_port",
            "source", "confidence", "avg_confidence", "last_seen_iso", "created_at_iso", "last_seen", "created_at",
        ]
        columns = preferred_columns(rows, preferred)
        if not columns:
            columns = list(rows[0].keys())[:8]
        shown = rows[:30]
        suffix = "" if len(rows) <= 30 else f"\n\nShowing 30 of {len(rows)} evidence rows."
        return answer + "\n\n" + markdown_table(shown, columns) + suffix
    workflow_steps = data.get("workflow")
    if isinstance(workflow_steps, list) and workflow_steps:
        steps = "; ".join(
            f"{step.get('source')}: {step.get('operation')}"
            for step in workflow_steps[:4]
            if isinstance(step, dict)
        )
        if steps:
            return answer + f"\n\nEvidence path: {steps}"
    return answer


def render_interface_result(workflow: str, result: Dict[str, Any], switch: str) -> str:
    rows = parse_interface_status(result.get("stdout") or "")
    if workflow == "get_down_interfaces":
        rows = [row for row in rows if row.get("status", "").lower() in DOWN_STATUSES]
        if rows:
            return f"NetOps reported {len(rows)} down/non-active interface(s) on `{switch}`.\n\n" + markdown_table(rows, ["interface", "description", "vlan", "status"])
        parsed_total = len(parse_interface_status(result.get("stdout") or ""))
        if parsed_total:
            return f"No down/non-active interfaces were found in the parsed NetOps output for `{switch}`."
        return "NetOps completed, but the wrapper could not parse an interface-status table. Raw output:\n\n" + truncate_text(result.get("stdout") or "")
    if rows:
        return f"NetOps returned {len(rows)} interface row(s) for `{switch}`.\n\n" + markdown_table(rows[:60], ["interface", "description", "vlan", "status", "speed", "type"])
    return "NetOps completed, but the wrapper could not parse an interface-status table. Raw output:\n\n" + truncate_text(result.get("stdout") or "")


def render_result(workflow: str, tool: Dict[str, Any], params: Dict[str, str], result: Dict[str, Any]) -> str:
    if result.get("dry_run"):
        return f"Dry run only. Approved workflow `{workflow}` would execute:\n\n`{result['command']}`"
    if not bool(result.get("success", int(result.get("exit_code") or 0) == 0)):
        stderr = truncate_text(str(result.get("stderr") or ""), max_lines=40, max_chars=3000)
        stdout = truncate_text(str(result.get("stdout") or ""), max_lines=40, max_chars=3000)
        details = stderr or stdout or "No output returned."
        return f"Workflow `{workflow}` did not complete successfully. Exit code: {result.get('exit_code')}.\n\n{details}"
    parser = str(tool.get("parser") or "text")
    if parser in {"interface_status", "interface_status_down"}:
        return render_interface_result(workflow, result, params.get("switch", "target"))
    if workflow == "get_memory_switch":
        return render_memory_switch(result)
    if parser == "ask_json":
        return render_ask_json(workflow, result)
    if parser == "json_summary":
        return render_json_summary(workflow, result)
    output = result.get("stdout") or ""
    if output.strip():
        return f"Workflow `{workflow}` completed. NetOps returned:\n\n" + truncate_text(output)
    return f"Workflow `{workflow}` completed successfully, but NetOps returned no output."


def structured_tool_result(workflow: str, tool: Dict[str, Any], params: Dict[str, str], result: Dict[str, Any]) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "ok": bool(result.get("success", int(result.get("exit_code") or 0) == 0)),
        "workflow": workflow,
        "params": params,
        "exit_code": int(result.get("exit_code") or 0),
        "accepted_nonzero_exit": bool(result.get("accepted_nonzero_exit", False)),
        "summary": render_result(workflow, tool, params, result),
    }
    parser = str(tool.get("parser") or "text")
    output = str(result.get("stdout") or "")
    if parser in {"interface_status", "interface_status_down"}:
        rows = parse_interface_status(output)
        if parser == "interface_status_down":
            rows = [row for row in rows if row.get("status", "").lower() in DOWN_STATUSES]
            rows = [
                {
                    "interface": row.get("interface", ""),
                    "description": row.get("description", ""),
                    "vlan": row.get("vlan", ""),
                    "status": row.get("status", ""),
                }
                for row in rows
            ]
        payload["rows"] = rows
        payload["count"] = len(rows)
    elif parser in {"json_summary", "ask_json"}:
        payload["data"] = parse_json(output)
    else:
        payload["output"] = truncate_text(output)
    if not payload["ok"]:
        payload["error"] = truncate_text(str(result.get("stderr") or output), max_lines=40, max_chars=3000)
    return payload


def tool_requires_switch(tool: Dict[str, Any]) -> bool:
    return "{switch}" in str(tool.get("command") or "")


def tool_requires_query(tool: Dict[str, Any]) -> bool:
    command = str(tool.get("command") or "")
    return "{query}" in command or "{question}" in command


def rows_for_tools(tools: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "workflow": name,
            "read_only": str(tool.get("read_only", False)).lower(),
            "confirmation": str(tool.get("requires_confirmation", False)).lower(),
            "description": tool.get("description", ""),
        }
        for name, tool in sorted(tools.items())
    ]


def tool_schemas(tools: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    schemas = []
    for name, tool in sorted(tools.items()):
        properties: Dict[str, Any] = {}
        required: List[str] = []
        if tool_requires_switch(tool):
            properties["switch"] = {"type": "string", "description": "Switch hostname, IP, or configured alias."}
            required.append("switch")
        if tool_requires_query(tool):
            properties["query"] = {"type": "string", "description": "Original read-only NetOps question."}
            required.append("query")
        schemas.append({
            "type": "function",
            "function": {
                "name": name,
                "description": str(tool.get("description") or ""),
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                    "additionalProperties": False,
                },
            },
        })
    return schemas


def print_tool_schemas(tools: Dict[str, Dict[str, Any]]) -> None:
    print(json.dumps(tool_schemas(tools), indent=2, sort_keys=True))


def run_and_print(workflow: str, tool: Dict[str, Any], params: Dict[str, str], dry_run: bool, json_output: bool) -> int:
    result = execute_workflow(workflow, tool, params, dry_run=dry_run)
    response = render_result(workflow, tool, params, result)
    if json_output:
        print(json.dumps({"workflow": workflow, "params": params, "result": result, "response": response}, indent=2, sort_keys=True))
    else:
        print(response)
    if bool(result.get("success", int(result.get("exit_code") or 0) == 0)):
        return 0
    return int(result.get("exit_code") or 1)


def command_tools(args: argparse.Namespace, tools: Dict[str, Dict[str, Any]]) -> int:
    rows = rows_for_tools(tools)
    if args.json:
        print(json.dumps(rows, indent=2, sort_keys=True))
    else:
        print(markdown_table(rows, ["workflow", "read_only", "confirmation", "description"]))
    return 0


def command_run(args: argparse.Namespace, tools: Dict[str, Dict[str, Any]], aliases: Dict[str, str]) -> int:
    tool = tools.get(args.workflow)
    if not tool:
        raise ClarificationNeeded(f"Unknown workflow `{args.workflow}`. Use `tools` to list approved workflows.")
    params: Dict[str, str] = {}
    if tool_requires_switch(tool):
        raw_switch = args.switch or args.target or ""
        switch = resolve_tool_switch(tool, raw_switch, aliases)
        if not switch:
            raise ClarificationNeeded("Which switch should I use? Provide `--switch <name-or-alias>`.")
        params["switch"] = switch
    if tool_requires_query(tool):
        query = str(args.query or args.target or "").strip()
        if not query:
            raise ClarificationNeeded("Which question should I use? Provide `--query <question>`.")
        params["query"] = native_state_query(query, aliases)
    return run_and_print(args.workflow, tool, params, args.dry_run, args.json)


def command_ask(args: argparse.Namespace, tools: Dict[str, Dict[str, Any]], aliases: Dict[str, str]) -> int:
    question = " ".join(args.question).strip()
    workflow = choose_workflow(question)
    if not workflow or workflow not in tools:
        raise ClarificationNeeded("I could not map that request to an approved workflow. Ask for interfaces, VLANs, APs, topology, health, memory, or device details.")
    tool = tools[workflow]
    params: Dict[str, str] = {}
    if tool_requires_switch(tool):
        switch = resolve_tool_switch(tool, question, aliases)
        if not switch:
            raise ClarificationNeeded("Which switch should I use? I could not resolve a switch alias or hostname from the question.")
        params["switch"] = switch
    if tool_requires_query(tool):
        params["query"] = native_state_query(question, aliases)
    return run_and_print(workflow, tool, params, args.dry_run, args.json)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Separate NetOps AI approved-workflow wrapper")
    sub = parser.add_subparsers(dest="command", required=True)

    tools_parser = sub.add_parser("tools", help="List approved workflows")
    tools_parser.add_argument("--json", action="store_true")

    schemas_parser = sub.add_parser("schemas", help="Print function schemas for a tool-calling bridge")
    schemas_parser.set_defaults(json=True)

    run_parser = sub.add_parser("run", help="Run one approved workflow")
    run_parser.add_argument("workflow")
    run_parser.add_argument("--switch", help="Switch hostname, IP, or configured alias")
    run_parser.add_argument("--target", help="Alias for --switch where a switch is required")
    run_parser.add_argument("--query", help="Natural-language question for broad NetOps state workflows")
    run_parser.add_argument("--dry-run", action="store_true", help="Resolve and print the command without executing it")
    run_parser.add_argument("--json", action="store_true")

    ask_parser = sub.add_parser("ask", help="Resolve a natural question to an approved workflow")
    ask_parser.add_argument("question", nargs="+")
    ask_parser.add_argument("--dry-run", action="store_true", help="Resolve and print the command without executing it")
    ask_parser.add_argument("--json", action="store_true")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        tools = load_tools()
        aliases = load_aliases()
        if args.command == "tools":
            return command_tools(args, tools)
        if args.command == "schemas":
            print_tool_schemas(tools)
            return 0
        if args.command == "run":
            return command_run(args, tools, aliases)
        if args.command == "ask":
            return command_ask(args, tools, aliases)
        parser.error("unknown command")
    except ClarificationNeeded as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except PolicyError as exc:
        print(f"Policy blocked request: {exc}", file=sys.stderr)
        return 6
    except FileNotFoundError as exc:
        print(f"Missing file: {exc}", file=sys.stderr)
        return 10
    except Exception as exc:
        print(f"Wrapper error: {exc}", file=sys.stderr)
        return 10
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
