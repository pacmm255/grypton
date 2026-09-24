import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from grypton import scenarios


class AutonomousScenarioTests(unittest.TestCase):
    def test_catalog_has_unique_actions_and_rotates_deterministically(self):
        rows = scenarios.load_scenarios()
        self.assertGreaterEqual(len(rows), 10)
        self.assertEqual(len({row["id"] for row in rows}), len(rows))

        actions = scenarios.priority_actions("web")
        self.assertGreaterEqual(len(actions), 10)
        self.assertTrue(all(action for action in actions))
        self.assertEqual(len(set(actions)), len(actions))
        self.assertEqual(scenarios.priority_action("web", 0), actions[0])
        self.assertEqual(scenarios.priority_action("web", len(actions)), actions[0])

    def test_target_selection_keeps_general_and_matching_playbooks(self):
        network_ids = {row["id"] for row in scenarios.selected_scenarios("network")}
        self.assertIn("network-inventory", network_ids)
        self.assertIn("finding-proof", network_ids)
        self.assertNotIn("browser-origin-boundary", network_ids)

    def test_runtime_selection_filters_scenarios_with_missing_prerequisites(self):
        baseline = {
            row["id"] for row in scenarios.selected_scenarios(
                "web", capabilities=set()
            )
        }
        self.assertNotIn("finding-proof", baseline)
        self.assertNotIn("blocked-path-recovery", baseline)
        self.assertNotIn("mobile-artifact-boundary", baseline)

        enabled = {
            row["id"] for row in scenarios.selected_scenarios(
                "web",
                capabilities={"validation_backlog", "blocker", "mobile_artifact"},
            )
        }
        self.assertIn("finding-proof", enabled)
        self.assertIn("blocked-path-recovery", enabled)
        self.assertIn("mobile-artifact-boundary", enabled)

    def test_catalog_validation_rejects_missing_priority_action(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "scenarios.json"
            path.write_text(json.dumps([{
                "id": "incomplete",
                "title": "Incomplete",
                "target_types": ["web"],
                "moves": ["test one thing"],
            }]), encoding="utf-8")
            with patch("grypton.scenarios.config.SCENARIOS_PATH", path):
                with self.assertRaisesRegex(ValueError, "priority_action"):
                    scenarios.load_scenarios()


if __name__ == "__main__":
    unittest.main()
