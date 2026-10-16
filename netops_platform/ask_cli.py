"""Command surface for the ask domain.

Kept out of core.py as a free function, matching traffic_cli.py's/
setup_cli.py's/path_cli.py's pattern -- but two of its five original
methods, ask_payload and execute_ask_plan, are called directly by dozens of
test call sites via `self.app.ask_payload(...)`/`self.app.execute_ask_plan(...)`,
not just from within this cluster. Both keep public module-level names here
and core.py keeps matching 2-line delegate methods on App, the same
treatment write_snmp_community got in setup_cli.py. format_ask_text and
cmd_ask_chat have no such external callers and become private
(_format_ask_text/_cmd_ask_chat); format_ask_text also takes no app
parameter since it's a pure function of payload alone.
"""

from __future__ import annotations

import shlex
import sys
from typing import Any, Dict, List, Optional

from rich.style import Style

from netops_platform.ask import QUESTION_PATTERNS
def ask_payload(app: Any, question: str, opts: GlobalOptions, session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return app.natural_ask.ask(question, opts, session=session)

def _format_ask_text(payload: Dict[str, Any]) -> str:
    answer = str(payload.get("answer") or payload.get("error") or "No deterministic answer.")
    plan = payload.get("command_plan") if isinstance(payload.get("command_plan"), dict) else {}
    if plan:
        answer += f"\nPlan: {plan.get('label') or plan.get('action')} [{plan.get('status')}]"
        if plan.get("command"):
            answer += f"\nPreview: {plan['command']}"
        if plan.get("missing_args"):
            answer += "\nNeeds: " + ", ".join(str(item) for item in plan["missing_args"])
        if plan.get("execution_hint"):
            answer += f"\nExecute: {plan['execution_hint']}"
    choices = payload.get("choices") or []
    if choices:
        labels = [str(item.get("name") or item.get("ip") or item) if isinstance(item, dict) else str(item) for item in choices[:12]]
        answer += "\nChoices: " + ", ".join(labels)
    suggestions = payload.get("suggestions") or []
    if suggestions and (not payload.get("ok") or plan):
        answer += "\nTry: " + " | ".join(str(item) for item in suggestions[:4])
    return answer

def execute_ask_plan(app: Any, payload: Dict[str, Any], opts: GlobalOptions) -> int:
    from netops_platform.core import CONFIRM_REQUIRED, VALIDATION
    plan = payload.get("command_plan") if isinstance(payload.get("command_plan"), dict) else None
    if not plan:
        app.emit({**payload, "ok": False, "error": "The question produced a retrieval answer, not an executable command plan."}, opts, _format_ask_text(payload) + "\nNo command plan to execute.")
        return VALIDATION
    action = str(plan.get("action") or "")
    spec = app.command_spec(action)
    if not spec:
        app.emit({**payload, "ok": False, "error": f"Unknown planned action: {action}"}, opts, _format_ask_text(payload))
        return VALIDATION
    missing = list(plan.get("missing_args") or [])
    if missing:
        app.emit({**payload, "ok": False, "error": "Command plan needs more information."}, opts, _format_ask_text(payload))
        return VALIDATION
    if not spec.run_supported or spec.risk_level in {"config", "danger"}:
        app.emit({**payload, "ok": False, "error": plan.get("reason") or "This plan is preview-only."}, opts, _format_ask_text(payload))
        return CONFIRM_REQUIRED
    if spec.effective_safety_class() != "read-only" and not opts.confirm:
        plan["execution_hint"] = f"netrune ask --execute --confirm {shlex.quote(str(payload.get('question') or ''))}"
        app.emit({**payload, "ok": False, "error": "Active or state-changing plans require --confirm in addition to --execute."}, opts, _format_ask_text(payload))
        return CONFIRM_REQUIRED
    try:
        cmd, _, _ = app.command_for_action(action, dict(plan.get("args") or {}))
    except (PermissionError, ValueError) as exc:
        app.emit({**payload, "ok": False, "error": str(exc)}, opts, _format_ask_text(payload))
        return VALIDATION
    return app.run_interactive(cmd, opts) if spec.output_type == "terminal" else app.run_subprocess(cmd, opts)

def _cmd_ask_chat(app: Any, opts: GlobalOptions) -> int:
    from netops_platform.core import SUCCESS, VALIDATION, json_dumps
    if opts.json:
        return app.usage_error("ask", "chat", opts, "Interactive Natural Ask is plain text only.", 'netrune ask "question" --json', VALIDATION)
    session: Dict[str, Any] = {"history": []}
    interactive = sys.stdin.isatty()
    color = app._color_enabled()
    label = Style.parse("bold cyan").render("answer>") if color else "answer>"
    if interactive:
        print(Style.parse("bold").render("Netrune Ask") if color else "Netrune Ask")
        print("Deterministic questions over current inventory and memory. /patterns lists examples; /exit leaves.")
    while True:
        try:
            question = input("ask> ").strip() if interactive else sys.stdin.readline().strip()
            if not question and not interactive:
                break
        except KeyboardInterrupt:
            print("\nInterrupted.")
            return SUCCESS
        except EOFError:
            print("")
            return SUCCESS
        if not question:
            continue
        lower = question.lower()
        if lower in {"/exit", "/quit", "exit", "quit"}:
            break
        if lower in {"/patterns", "/help"}:
            examples = [example for item in QUESTION_PATTERNS for example in item["examples"]]
            print(f"\n{label}\n" + "\n".join(f"  {example}" for example in examples))
            continue
        if lower == "/history":
            print(f"\n{label}\n" + (json_dumps(session.get("history")) if session.get("history") else "No session history."))
            continue
        if lower == "/reset":
            session = {"history": []}
            print(f"\n{label}\nSession context cleared.")
            continue
        if lower.startswith("/alias "):
            value = question[7:].strip()
            if "=" not in value:
                print(f"\n{label}\nUse: /alias phrase = target")
                continue
            phrase, target = [part.strip() for part in value.split("=", 1)]
            payload = app.natural_ask.set_alias(phrase, target)
            print(f"\n{label}\n" + (f"Alias saved: {phrase} -> {target}" if payload.get("ok") else str(payload.get("error"))))
            continue
        payload = ask_payload(app, question, opts, session=session)
        app.natural_ask.update_session(question, payload, session)
        print(f"\n{label}\n" + _format_ask_text(payload))
    return SUCCESS

def dispatch(app: Any, args: List[str], opts: GlobalOptions) -> int:
    from netops_platform.core import SUCCESS, VALIDATION
    if app.handle_help("ask", args, opts):
        return SUCCESS
    if not args:
        return _cmd_ask_chat(app, opts)
    verb = args[0].lower()
    if verb == "patterns":
        payload = app.natural_ask.patterns_payload()
        rows = [{"intent": item["intent"], "purpose": item["purpose"], "examples": " | ".join(item["examples"])} for item in payload["patterns"]]
        app.emit(payload, opts, app.render_table(rows, ["intent", "purpose", "examples"]))
        return SUCCESS
    if verb == "aliases":
        rows = app.natural_ask.aliases()
        app.emit({"ok": True, "rows": rows, "count": len(rows)}, opts, app.render_table(rows, ["phrase", "target", "updated_at"]))
        return SUCCESS
    if verb == "alias":
        action = args[1].lower() if len(args) > 1 else ""
        if action == "set" and len(args) >= 4:
            payload = app.natural_ask.set_alias(args[2], " ".join(args[3:]))
            app.emit(payload, opts, f"Alias saved: {payload.get('phrase')} -> {payload.get('target')}" if payload.get("ok") else str(payload.get("error")))
            return SUCCESS if payload.get("ok") else VALIDATION
        if action in {"remove", "delete", "unset"} and len(args) >= 3:
            payload = app.natural_ask.remove_alias(" ".join(args[2:]))
            app.emit(payload, opts, f"Alias removed: {payload.get('removed', {}).get('phrase')}" if payload.get("ok") else str(payload.get("error")))
            return SUCCESS if payload.get("ok") else VALIDATION
        return app.usage_error("ask", "alias", opts, "Alias action requires set <phrase> <target> or remove <phrase>.", "netrune ask alias set 'engineering office' 'engg ofc'", VALIDATION)
    question = " ".join(args).strip()
    payload = ask_payload(app, question, opts, session={"history": []})
    if opts.execute:
        return execute_ask_plan(app, payload, opts)
    app.emit(payload, opts, _format_ask_text(payload))
    return SUCCESS if payload.get("ok") else VALIDATION
