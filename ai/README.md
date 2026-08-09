# NetOps AI Assistant Layer

This directory is a standalone local AI/operator layer for NetOps. It talks to NetOps only through approved public commands in `ai/config/tools.yaml`. The core `netops ask` engine is authoritative for broad retrieval and command planning.

## Files

- `docs/NETOPS_AI_GUIDE.md` is the operating manual and workflow policy.
- `config/system_prompt.txt` is the short permanent model instruction.
- `config/tools.yaml` is the approved workflow registry.
- `config/aliases.yaml` maps operator aliases to device names.
- `bin/netops_ai_agent.py` is the local wrapper/executor.
- `bin/netops_ai_chat.py` connects Ollama tool calls to the approved wrapper.
- `logs/agent_runs.jsonl` is created when real workflows are executed.

## Usage

List approved tools:

```bash
python3 ai/bin/netops_ai_agent.py tools
```

Preview a resolved workflow without touching NetOps:

```bash
python3 ai/bin/netops_ai_agent.py ask "Which interfaces are down on the site-a-core switch?" --dry-run
```

Run a workflow directly:

```bash
python3 ai/bin/netops_ai_agent.py run get_down_interfaces --switch site-a-core
```

Ask a natural question through the wrapper:

```bash
python3 ai/bin/netops_ai_agent.py ask "Which interfaces are down on the site-a-core switch?"
```

Create the Ollama model:

```bash
ollama create netops-ai -f ai/Modelfile.netops
```

Use the fast assistant through the public `netops` launcher:

```bash
netops ai "Which interfaces are down on the site-a-core switch?"
```

The default path uses a deterministic approved-workflow router and does not load Ollama. This minimizes memory and latency. Run `netops ai` without a question for interactive mode.

Broad questions and operational requests use `answer_from_netops_state`, which calls `netops --json ask <question>`. Retrieval can access current inventory, APs, IP/MAC identity, topology, relationships, confidence/source fields, memory, and history. Operational language returns a registry-backed plan, exact preview, missing inputs, and safety policy; this AI wrapper does not execute that plan.

The command planner understands the v7.1 bounded network workflows, for example:

```bash
netops ai "Check VLAN propagation from site-a-core for VLAN 131 to depth 5"
netops ai "Point-of-truth ping 192.0.2.50 from core CORE01 five times"
netops ai "Profile MAC 02:00:00:00:00:25 at ZONE34"
```

These requests return the exact recursive VLAN, core-ping, or MAC-profile preview. They still do not contact a switch from the AI wrapper; execution is a separate guarded CLI/WebUI action.

Progress is written immediately to stderr while live NetOps waits on the device. Add `--quiet` for scripts; `--json` suppresses progress automatically.

Use Ollama only when model-assisted selection is useful:

```bash
netops ai --ollama-select "Which interfaces are down on the site-a-core switch?"
```

Add `--model-summary` to let Ollama reword the tool result. Ollama calls default to `keep_alive=0`, so the model is released from memory after the request. Interface-list completeness is validated and falls back to the deterministic table if the model drops a row.

Do not use `ollama run netops-ai` for live NetOps questions: the Ollama CLI has no executor attached. Use `netops ai`, which delegates directly to the separate AI layer before the NetOps core starts.

Export simple function schemas for an external Ollama/tool-calling bridge:

```bash
python3 ai/bin/netops_ai_agent.py schemas
```

Search the configured guide/source retrieval set:

```bash
python3 ai/bin/netops_ai_rag.py "down interfaces workflow"
```

## Safety boundary

The wrapper validates that every command starts with the local public `netops` launcher and blocks direct helper execution. It may display core-generated config dry-run plans, but cannot run command plans or configuration actions. Execution remains an explicit CLI/WebUI step governed by the core registry.
