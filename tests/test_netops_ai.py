import json
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai" / "bin"))

import netrune_ai_agent as agent
import netrune_ai_chat as chat


class NetruneAITest(unittest.TestCase):
    def test_core_ask_is_authoritative_except_narrow_live_show_workflows(self):
        for question in (
            "all APs that are down",
            "connect to admin-hill",
            "preview setting VLAN 120 on SQ34",
            "list devices connected to camp office switch",
            "what changed in topology today",
        ):
            with self.subTest(question=question):
                self.assertEqual(agent.choose_workflow(question), "answer_from_netrune_state")
        self.assertEqual(agent.choose_workflow("which interfaces are down on SQ34"), "get_down_interfaces")
        self.assertEqual(agent.choose_workflow("show VLAN summary on SQ34"), "get_vlan_summary")

    def test_command_requests_build_only_the_public_ask_argv(self):
        tools = agent.load_tools()
        tool = tools["answer_from_netrune_state"]
        argv = agent.build_argv(tool, {"query": "Run a health check for SQ34"})
        self.assertEqual(Path(argv[0]).resolve(), agent.NETRUNE_BIN.resolve())
        self.assertEqual(argv[1:3], ["--json", "ask"])
        self.assertEqual(argv[3], "Run a health check for SQ34")

    def test_ask_renderer_preserves_plan_and_execution_boundary(self):
        payload = {
            "answer": "Prepared Fast health check.",
            "command_plan": {
                "action": "health-check",
                "status": "ready",
                "safety_class": "network-read/local-write",
                "command": "netrune health check SQ34",
                "execution_hint": "netrune ask --execute --confirm 'Run a health check for SQ34'",
                "missing_args": [],
                "reason": "",
            },
        }
        rendered = agent.render_ask_json("answer_from_netrune_state", {"stdout": json.dumps(payload)})
        self.assertIn("health-check", rendered)
        self.assertIn("netrune health check SQ34", rendered)
        self.assertIn("did not execute", rendered)

    def test_ai_tables_prefer_standard_dates_over_epoch_values(self):
        payload = {
            "answer": "One record.",
            "result": {"rows": [{"name": "SW01", "last_seen": 1704067200, "last_seen_iso": "2024-01-01T00:00:00Z"}]},
        }
        rendered = agent.render_ask_json("answer_from_netrune_state", {"stdout": json.dumps(payload)})
        self.assertIn("2024-01-01T00:00:00Z", rendered)
        self.assertNotIn("1704067200", rendered)


class StopAfterSchemaCapture(Exception):
    """Raised from a fake ollama_chat once it has recorded the tool schemas
    offered, so the test never runs a real tool (subprocess, network)."""


class OllamaSelectionTest(unittest.TestCase):
    """--ollama-select used to always narrow the model to exactly one tool,
    because choose_workflow() never returns None -- it has to always return
    something for the zero-model fast path. That meant "model-assisted
    selection" wasn't actually letting the model select anything; the
    deterministic router had already decided before the model saw the
    question. Only the three narrow live-device-read workflows should still
    be pre-decided; everything else must reach the model as real choices.
    """

    def _captured_tool_names(self, question: str) -> list:
        captured = {}

        def fake_ollama_chat(url, model, messages, tools, timeout_seconds=60):
            captured["names"] = sorted(t["function"]["name"] for t in (tools or []))
            raise StopAfterSchemaCapture

        with mock.patch.object(chat, "ollama_chat", fake_ollama_chat):
            with self.assertRaises(StopAfterSchemaCapture):
                chat.ask(question, "netrune-ai", "http://127.0.0.1:11434")
        return captured["names"]

    def test_narrow_live_reads_still_get_exactly_one_tool(self):
        self.assertEqual(
            self._captured_tool_names("which interfaces are down on SQ34"),
            ["get_down_interfaces"],
        )
        self.assertEqual(
            self._captured_tool_names("show VLAN summary on SQ34"),
            ["get_vlan_summary"],
        )

    def test_broad_questions_get_the_full_tool_set_for_real_model_choice(self):
        all_tool_names = sorted(agent.load_tools().keys())
        for question in (
            "which APs are on the building 9 switch",
            "summarize SQ34",
            "what is offline right now",
        ):
            with self.subTest(question=question):
                self.assertEqual(self._captured_tool_names(question), all_tool_names)


if __name__ == "__main__":
    unittest.main()
