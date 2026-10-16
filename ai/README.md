# Netrune AI Assistant Layer

This directory is a standalone local AI/operator layer for Netrune. It talks to Netrune only through approved public commands in `ai/config/tools.yaml`. The core `netrune ask` engine is authoritative for broad retrieval and command planning.

## Files

- `docs/NETRUNE_AI_GUIDE.md` is the operating manual and workflow policy.
- `config/system_prompt.txt` is the short permanent model instruction.
- `config/tools.yaml` is the approved workflow registry.
- `config/aliases.yaml` maps operator aliases to device names.
- `bin/netrune_ai_agent.py` is the local wrapper/executor.
- `bin/netrune_ai_chat.py` connects Ollama tool calls to the approved wrapper.
- `logs/agent_runs.jsonl` is created when real workflows are executed.

## Usage

List approved tools:

```bash
python3 ai/bin/netrune_ai_agent.py tools
```

Preview a resolved workflow without touching Netrune:

```bash
python3 ai/bin/netrune_ai_agent.py ask "Which interfaces are down on the site-a-core switch?" --dry-run
```

Run a workflow directly:

```bash
python3 ai/bin/netrune_ai_agent.py run get_down_interfaces --switch site-a-core
```

Ask a natural question through the wrapper:

```bash
python3 ai/bin/netrune_ai_agent.py ask "Which interfaces are down on the site-a-core switch?"
```

Create the Ollama model:

```bash
ollama create netrune-ai -f ai/Modelfile.netrune
```

Use the fast assistant through the public `netrune` launcher:

```bash
netrune ai "Which interfaces are down on the site-a-core switch?"
```

The default path uses a deterministic approved-workflow router and does not load Ollama. This minimizes memory and latency. Run `netrune ai` without a question for interactive mode.

Broad questions and operational requests use `answer_from_netrune_state`, which calls `netrune --json ask <question>`. Retrieval can access current inventory, APs, IP/MAC identity, topology, relationships, confidence/source fields, memory, and history. Operational language returns a registry-backed plan, exact preview, missing inputs, and safety policy; this AI wrapper does not execute that plan.

The command planner understands the v7.1 bounded network workflows, for example:

```bash
netrune ai "Check VLAN propagation from site-a-core for VLAN 131 to depth 5"
netrune ai "Point-of-truth ping 192.0.2.50 from core CORE01 five times"
netrune ai "Profile MAC 02:00:00:00:00:25 at ZONE34"
```

These requests return the exact recursive VLAN, core-ping, or MAC-profile preview. They still do not contact a switch from the AI wrapper; execution is a separate guarded CLI action.

Progress is written immediately to stderr while live Netrune waits on the device. Add `--quiet` for scripts; `--json` suppresses progress automatically.

Use Ollama only when model-assisted selection is useful. The Modelfile currently pulls `qwen3:8b`, a hybrid-reasoning model; the bridge always disables its "thinking" phase per request (measured ~20x faster on this tool set with no loss of tool-selection or summarization accuracy):

```bash
netrune ai --ollama-select "Which interfaces are down on the site-a-core switch?"
```

Interface-status and VLAN-summary questions still route straight to their dedicated show workflow without consulting the model, because those execute a live device read where the narrow, unambiguous target selection matters more than model judgment. Everything else -- AP lookups, health, topology, memory, relationship confidence/timeline, and the broad Ask center itself -- is offered to the model as real choices among the full approved tool set, so it genuinely selects rather than rubber-stamping a workflow the deterministic router already picked. Add `--model-summary` to let Ollama reword the tool result. Ollama calls keep the model warm for 5 minutes after use (`NETRUNE_AI_KEEP_ALIVE`) so a back-to-back session of questions stays fast, then release it from memory once idle. Interface-list completeness is validated and falls back to the deterministic table if the model drops a row.

Do not use `ollama run netrune-ai` for live Netrune questions: the Ollama CLI has no executor attached. Use `netrune ai`, which delegates directly to the separate AI layer before the Netrune core starts.

Export simple function schemas for an external Ollama/tool-calling bridge:

```bash
python3 ai/bin/netrune_ai_agent.py schemas
```

Search the configured guide/source retrieval set:

```bash
python3 ai/bin/netrune_ai_rag.py "down interfaces workflow"
```

## Safety boundary

The wrapper validates that every command starts with the local public `netrune` launcher and blocks direct helper execution. It may display core-generated config dry-run plans, but cannot run command plans or configuration actions. Execution remains an explicit CLI/WebUI step governed by the core registry.
