#!/usr/bin/env python3
"""Ollama chat bridge for the standalone approved NetOps AI workflows."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from netops_ai_agent import (
    ClarificationNeeded,
    PolicyError,
    choose_workflow,
    execute_workflow,
    load_aliases,
    load_tools,
    native_state_query,
    resolve_tool_switch,
    structured_tool_result,
    tool_requires_query,
    tool_requires_switch,
    tool_schemas,
)
from netops_ai_rag import search

SCRIPT_PATH = Path(__file__).resolve()
AI_DIR = SCRIPT_PATH.parents[1]
SYSTEM_PROMPT_FILE = AI_DIR / "config" / "system_prompt.txt"
DEFAULT_MODEL = os.environ.get("NETOPS_AI_MODEL", "netops-ai")
DEFAULT_OLLAMA_URL = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
DEFAULT_OLLAMA_TIMEOUT = int(os.environ.get("NETOPS_AI_OLLAMA_TIMEOUT", "60") or "60")
DEFAULT_KEEP_ALIVE = os.environ.get("NETOPS_AI_KEEP_ALIVE", "0")
MAX_TOOL_ROUNDS = 4


class OllamaError(RuntimeError):
    pass


def guide_context(question: str) -> str:
    snippets = search(question, limit=1, context=1)
    if not snippets:
        return ""
    blocks = []
    for item in snippets:
        blocks.append(f"Source: {item['path']}:{item['line']}\n{item['snippet']}")
    return "\n\n".join(blocks)


def system_prompt(question: str, aliases: Dict[str, str]) -> str:
    base = SYSTEM_PROMPT_FILE.read_text(encoding="utf-8").strip()
    alias_lines = "\n".join(f"- {alias} = {target}" for alias, target in sorted(aliases.items()))
    context = guide_context(question)
    return (
        f"{base}\n\n"
        "Execution boundary:\n"
        "- For current facts or an operational request, call one approved tool. Broad requests go to the core Ask command center.\n"
        "- Tool arguments may contain an exact hostname, IP, or configured alias.\n"
        "- Treat tool output as the only source of current network truth.\n"
        "- You may report a core-generated config dry-run plan, but do not call or execute configuration-changing actions.\n"
        "- Preserve command-plan status, arguments, exact preview, missing inputs, safety class, and confirmation requirements.\n"
        "- If a tool result says ok=false, report the failure without guessing.\n\n"
        f"Configured aliases:\n{alias_lines or '- none'}\n\n"
        f"Relevant guide context:\n{context or 'No additional guide snippet matched.'}"
    )


def ollama_chat(
    url: str,
    model: str,
    messages: List[Dict[str, Any]],
    tools: Optional[List[Dict[str, Any]]],
    timeout_seconds: int = DEFAULT_OLLAMA_TIMEOUT,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "stream": False,
        "keep_alive": DEFAULT_KEEP_ALIVE,
        "options": {"temperature": 0, "num_predict": 512},
    }
    if tools:
        payload["tools"] = tools
    request = urllib.request.Request(
        f"{url}/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise OllamaError(f"Ollama returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise OllamaError(f"Cannot reach Ollama at {url}. Start it with `ollama serve`. Details: {exc.reason}") from exc
    except (TimeoutError, socket.timeout) as exc:
        raise OllamaError(f"Ollama did not respond within {timeout_seconds} seconds. Fast mode does not require Ollama.") from exc
    if not isinstance(data, dict) or not isinstance(data.get("message"), dict):
        raise OllamaError("Ollama returned an invalid chat response.")
    return data


def function_parts(tool_call: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    function = tool_call.get("function")
    if not isinstance(function, dict):
        raise PolicyError("Ollama returned a malformed tool call")
    name = str(function.get("name") or "").strip()
    arguments = function.get("arguments") or {}
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except json.JSONDecodeError as exc:
            raise PolicyError(f"Tool `{name}` returned invalid JSON arguments") from exc
    if not isinstance(arguments, dict):
        raise PolicyError(f"Tool `{name}` arguments must be an object")
    return name, arguments


def content_tool_calls(content: Any) -> List[Dict[str, Any]]:
    text = str(content or "").strip()
    fenced = text.startswith("```") and text.endswith("```")
    if fenced:
        lines = text.splitlines()
        text = "\n".join(lines[1:-1]).strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []
    name = str(payload.get("name") or payload.get("tool") or "").strip()
    arguments = payload.get("arguments")
    if not name or not isinstance(arguments, dict):
        return []
    return [{"function": {"name": name, "arguments": arguments}}]


def execute_tool_call(
    tool_call: Dict[str, Any],
    question: str,
    tools: Dict[str, Dict[str, Any]],
    aliases: Dict[str, str],
) -> Tuple[str, Dict[str, Any]]:
    name, arguments = function_parts(tool_call)
    tool = tools.get(name)
    if not tool:
        raise PolicyError(f"Ollama requested unapproved workflow `{name}`")
    allowed_arguments = set()
    if tool_requires_switch(tool):
        allowed_arguments.add("switch")
    if tool_requires_query(tool):
        allowed_arguments.add("query")
    unexpected = set(arguments) - allowed_arguments
    if unexpected:
        raise PolicyError(f"Tool `{name}` received unsupported arguments: {', '.join(sorted(unexpected))}")
    params: Dict[str, str] = {}
    if tool_requires_switch(tool):
        raw_switch = str(arguments.get("switch") or question).strip()
        switch = resolve_tool_switch(tool, raw_switch, aliases)
        if not switch:
            raise ClarificationNeeded("Which switch should I use? I could not resolve the requested device.")
        params["switch"] = switch
    if tool_requires_query(tool):
        params["query"] = native_state_query(str(arguments.get("query") or question).strip(), aliases)
    result = execute_workflow(name, tool, params, dry_run=False)
    return name, structured_tool_result(name, tool, params, result)


def deterministic_tool_call(question: str, tools: Dict[str, Dict[str, Any]], aliases: Dict[str, str]) -> Optional[Tuple[str, Dict[str, Any]]]:
    name = choose_workflow(question)
    if not name or name not in tools:
        return None
    tool = tools[name]
    arguments: Dict[str, Any] = {}
    if tool_requires_switch(tool):
        switch = resolve_tool_switch(tool, question, aliases)
        if not switch:
            return None
        arguments["switch"] = switch
    if tool_requires_query(tool):
        arguments["query"] = question
    return execute_tool_call({"function": {"name": name, "arguments": arguments}}, question, tools, aliases)


def payload_for_model(payload: Dict[str, Any]) -> Dict[str, Any]:
    keys = ("ok", "workflow", "params", "count", "rows", "data", "output", "error")
    return {key: payload[key] for key in keys if key in payload}


def grounded_answer(answer: str, tool_results: List[Dict[str, Any]]) -> str:
    for payload in tool_results:
        rows = payload.get("rows")
        if not isinstance(rows, list):
            continue
        expected_interfaces = [
            str(row.get("interface") or "")
            for row in rows
            if isinstance(row, dict) and row.get("interface")
        ]
        if expected_interfaces and any(interface not in answer for interface in expected_interfaces):
            return str(payload.get("summary") or answer)
    return answer


def ask_fast(question: str) -> Dict[str, Any]:
    tools = load_tools()
    aliases = load_aliases()
    selected = deterministic_tool_call(question, tools, aliases)
    if not selected:
        raise ClarificationNeeded(
            "I could not map that request to an approved fast workflow. "
            "Ask for interfaces, VLANs, APs, topology, health, memory, or device details; "
            "or add `--ollama-select` for model-assisted selection."
        )
    name, payload = selected
    return {
        "answer": str(payload.get("summary") or ""),
        "model": None,
        "selector": "deterministic_fast",
        "workflow": name,
        "tool_results": [payload],
    }


def ask(
    question: str,
    model: str,
    url: str,
    model_summary: bool = False,
    timeout_seconds: int = DEFAULT_OLLAMA_TIMEOUT,
) -> Dict[str, Any]:
    tools = load_tools()
    aliases = load_aliases()
    candidate = choose_workflow(question)
    schema_tools = {candidate: tools[candidate]} if candidate in tools else tools
    schemas = tool_schemas(schema_tools)
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": system_prompt(question, aliases)},
        {"role": "user", "content": question},
    ]
    tool_results: List[Dict[str, Any]] = []
    last_summary = ""
    selector = "ollama_tool"
    for round_index in range(MAX_TOOL_ROUNDS):
        response = ollama_chat(url, model, messages, schemas, timeout_seconds=timeout_seconds)
        message = response["message"]
        tool_calls = message.get("tool_calls") or []
        if not tool_calls:
            tool_calls = content_tool_calls(message.get("content"))
            if tool_calls:
                selector = "ollama_json_tool"
                message = {"role": "assistant", "content": "", "tool_calls": tool_calls}
        if not tool_calls and round_index == 0:
            fallback = deterministic_tool_call(question, tools, aliases)
            if fallback:
                selector = "deterministic_fallback"
                name, payload = fallback
                tool_results.append(payload)
                last_summary = str(payload.get("summary") or "")
                if not model_summary:
                    return {"answer": last_summary, "model": model, "selector": selector, "tool_results": tool_results}
                messages.append({"role": "assistant", "content": "", "tool_calls": [{"function": {"name": name, "arguments": payload.get("params", {})}}]})
                messages.append({"role": "tool", "tool_name": name, "content": json.dumps(payload_for_model(payload), sort_keys=True)})
                continue
        if not tool_calls:
            content = str(message.get("content") or "").strip()
            answer = content or last_summary or "Ollama returned no answer."
            return {"answer": grounded_answer(answer, tool_results), "model": model, "selector": selector, "tool_results": tool_results}
        messages.append(message)
        for tool_call in tool_calls:
            name, payload = execute_tool_call(tool_call, question, tools, aliases)
            tool_results.append(payload)
            last_summary = str(payload.get("summary") or "")
            messages.append({"role": "tool", "tool_name": name, "content": json.dumps(payload_for_model(payload), sort_keys=True)})
        if tool_results and not model_summary:
            return {"answer": last_summary, "model": model, "selector": selector, "tool_results": tool_results}
    return {"answer": last_summary or "The assistant reached its tool-call limit without a final answer.", "model": model, "selector": selector, "tool_results": tool_results}


def answer_question(args: argparse.Namespace, question: str) -> Dict[str, Any]:
    if args.ollama_select or args.model_summary:
        return ask(
            question,
            args.model,
            args.ollama_url.rstrip("/"),
            model_summary=args.model_summary,
            timeout_seconds=max(1, args.ollama_timeout),
        )
    return ask_fast(question)


def print_result(result: Dict[str, Any], json_output: bool) -> None:
    if json_output:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result["answer"])


def announce(args: argparse.Namespace, question: str) -> None:
    if args.quiet or args.json:
        return
    if args.ollama_select or args.model_summary:
        message = f"NetOps AI: consulting `{args.model}`..."
    else:
        workflow = choose_workflow(question)
        message = f"NetOps AI: running approved workflow `{workflow}`..." if workflow else "NetOps AI: resolving approved workflow..."
    print(message, file=sys.stderr, flush=True)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="netops ai", description="Fast approved-workflow NetOps assistant with optional Ollama selection")
    parser.add_argument("question", nargs="*", help="Natural-language NetOps question; omit for interactive mode")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL)
    parser.add_argument("--ollama-timeout", type=int, default=DEFAULT_OLLAMA_TIMEOUT)
    parser.add_argument("--ollama-select", action="store_true", help="Use Ollama for workflow selection instead of the zero-model fast router")
    parser.add_argument("--model-summary", action="store_true", help="Ask Ollama to reword tool output; complete interface lists are still validated")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress messages")
    args = parser.parse_args(argv)
    question = " ".join(args.question).strip()
    if question:
        try:
            announce(args, question)
            print_result(answer_question(args, question), args.json)
            return 0
        except (ClarificationNeeded, PolicyError, OllamaError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        except KeyboardInterrupt:
            print("\nCancelled.", file=sys.stderr)
            return 130

    if args.json:
        print("Interactive mode does not support --json.", file=sys.stderr)
        return 2
    mode = "Ollama" if args.ollama_select or args.model_summary else "fast"
    print(f"NetOps AI interactive mode ({mode}). Type `exit` to quit.")
    while True:
        try:
            question = input("netops-ai> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not question:
            continue
        if question.lower() in {"exit", "quit", ":q"}:
            return 0
        try:
            announce(args, question)
            print_result(answer_question(args, question), False)
        except (ClarificationNeeded, PolicyError, OllamaError) as exc:
            print(str(exc), file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
