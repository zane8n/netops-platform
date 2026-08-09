import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai" / "bin"))

import netops_ai_agent as agent


class NetOpsAITest(unittest.TestCase):
    def test_core_ask_is_authoritative_except_narrow_live_show_workflows(self):
        for question in (
            "all APs that are down",
            "connect to admin-hill",
            "preview setting VLAN 120 on SQ34",
            "list devices connected to camp office switch",
            "what changed in topology today",
        ):
            with self.subTest(question=question):
                self.assertEqual(agent.choose_workflow(question), "answer_from_netops_state")
        self.assertEqual(agent.choose_workflow("which interfaces are down on SQ34"), "get_down_interfaces")
        self.assertEqual(agent.choose_workflow("show VLAN summary on SQ34"), "get_vlan_summary")

    def test_command_requests_build_only_the_public_ask_argv(self):
        tools = agent.load_tools()
        tool = tools["answer_from_netops_state"]
        argv = agent.build_argv(tool, {"query": "Run a health check for SQ34"})
        self.assertEqual(Path(argv[0]).resolve(), agent.NETOPS_BIN.resolve())
        self.assertEqual(argv[1:3], ["--json", "ask"])
        self.assertEqual(argv[3], "Run a health check for SQ34")

    def test_ask_renderer_preserves_plan_and_execution_boundary(self):
        payload = {
            "answer": "Prepared Fast health check.",
            "command_plan": {
                "action": "health-check",
                "status": "ready",
                "safety_class": "network-read/local-write",
                "command": "netops health check SQ34",
                "execution_hint": "netops ask --execute --confirm 'Run a health check for SQ34'",
                "missing_args": [],
                "reason": "",
            },
        }
        rendered = agent.render_ask_json("answer_from_netops_state", {"stdout": json.dumps(payload)})
        self.assertIn("health-check", rendered)
        self.assertIn("netops health check SQ34", rendered)
        self.assertIn("did not execute", rendered)

    def test_ai_tables_prefer_standard_dates_over_epoch_values(self):
        payload = {
            "answer": "One record.",
            "result": {"rows": [{"name": "SW01", "last_seen": 1704067200, "last_seen_iso": "2024-01-01T00:00:00Z"}]},
        }
        rendered = agent.render_ask_json("answer_from_netops_state", {"stdout": json.dumps(payload)})
        self.assertIn("2024-01-01T00:00:00Z", rendered)
        self.assertNotIn("1704067200", rendered)


if __name__ == "__main__":
    unittest.main()
