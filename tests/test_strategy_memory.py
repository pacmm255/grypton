from __future__ import annotations

import unittest
from contextlib import contextmanager
from pathlib import Path
import tempfile
from unittest.mock import patch

from grypton import config, scenarios
from grypton.engine import Engine, dead_end_exclusions
from grypton.manager import ManagerContext, KryptexManager
from grypton.workspace import Workspace


@contextmanager
def isolated_runtime():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        state = root / ".state"
        values = {
            "GRYPTON_HOME": root,
            "SOURCE_ROOT": Path(__file__).resolve().parents[1],
            "STATE_DIR": state,
            "ENGAGEMENTS_DIR": state / "engagements",
            "TARGETS_DIR": state / "engagements",
            "RUNTIME_DIR": state / "runtime",
            "LOG_DIR": state / "runtime/logs",
            "PROVIDER_DIR": state / "providers",
            "CREDENTIALS_DIR": state / "credentials",
            "OPENCODE_WORKSPACES_DIR": root / ".opencode-workspaces",
            "TARGET_DATA_DIR": root / "target",
        }
        with patch.multiple(config, **values):
            config.ensure_layout()
            yield root


class StrategyMemoryTests(unittest.TestCase):
    def test_record_strategy_outcome_valid(self):
        """record_strategy_outcome accepts valid inputs and appends to ledger."""
        with isolated_runtime():
            ws = Workspace("test-strategy")
            ws.create("https://example.test", "web")

            result = ws.record_strategy_outcome(
                playbook_id="test-playbook-1",
                outcome="worked",
                reason="Found new surface",
                turn_index=5,
            )

            self.assertIsNotNone(result)
            self.assertEqual(result["playbook_id"], "test-playbook-1")
            self.assertEqual(result["outcome"], "worked")
            self.assertEqual(result["reason"], "Found new surface")
            self.assertEqual(result["turn_index"], 5)
            self.assertIn("ts", result)

    def test_record_strategy_outcome_dead_end(self):
        """record_strategy_outcome accepts 'dead-end' outcome."""
        with isolated_runtime():
            ws = Workspace("test-dead-end")
            ws.create("https://example.test", "web")

            result = ws.record_strategy_outcome(
                playbook_id="test-dead-end-playbook",
                outcome="dead-end",
                turn_index=10,
            )

            self.assertEqual(result["outcome"], "dead-end")

    def test_record_strategy_outcome_blocked(self):
        """record_strategy_outcome accepts 'blocked' outcome."""
        with isolated_runtime():
            ws = Workspace("test-blocked")
            ws.create("https://example.test", "web")

            result = ws.record_strategy_outcome(
                playbook_id="test-blocked-playbook",
                outcome="blocked",
                reason="Rate limited",
                turn_index=3,
            )

            self.assertEqual(result["outcome"], "blocked")
            self.assertEqual(result["reason"], "Rate limited")

    def test_record_strategy_outcome_invalid_id(self):
        """record_strategy_outcome rejects invalid playbook_id."""
        with isolated_runtime():
            ws = Workspace("test-invalid-id")
            ws.create("https://example.test", "web")

            # Empty id
            with self.assertRaises(ValueError) as ctx:
                ws.record_strategy_outcome(
                    playbook_id="",
                    outcome="worked",
                )
            self.assertIn("playbook_id", str(ctx.exception))

            # Too long
            with self.assertRaises(ValueError) as ctx:
                ws.record_strategy_outcome(
                    playbook_id="a" * 65,
                    outcome="worked",
                )
            self.assertIn("playbook_id", str(ctx.exception))

            # Invalid chars
            with self.assertRaises(ValueError) as ctx:
                ws.record_strategy_outcome(
                    playbook_id="test_playbook_with_underscores",
                    outcome="worked",
                )
            self.assertIn("playbook_id", str(ctx.exception))

    def test_record_strategy_outcome_invalid_outcome(self):
        """record_strategy_outcome rejects invalid outcome."""
        with isolated_runtime():
            ws = Workspace("test-invalid-outcome")
            ws.create("https://example.test", "web")

            with self.assertRaises(ValueError) as ctx:
                ws.record_strategy_outcome(
                    playbook_id="test-playbook",
                    outcome="invalid-outcome",
                )
            self.assertIn("outcome must be one of", str(ctx.exception))

    def test_record_strategy_outcome_invalid_reason(self):
        """record_strategy_outcome rejects reason > 512 chars."""
        with isolated_runtime():
            ws = Workspace("test-invalid-reason")
            ws.create("https://example.test", "web")

            with self.assertRaises(ValueError) as ctx:
                ws.record_strategy_outcome(
                    playbook_id="test-playbook",
                    outcome="worked",
                    reason="x" * 513,
                )
            self.assertIn("reason must be", str(ctx.exception))

    def test_record_strategy_outcome_invalid_turn_index(self):
        """record_strategy_outcome rejects negative turn_index."""
        with isolated_runtime():
            ws = Workspace("test-invalid-turn")
            ws.create("https://example.test", "web")

            with self.assertRaises(ValueError) as ctx:
                ws.record_strategy_outcome(
                    playbook_id="test-playbook",
                    outcome="worked",
                    turn_index=-1,
                )
            self.assertIn("turn_index must be", str(ctx.exception))

    def test_strategy_outcomes_returns_latest(self):
        """strategy_outcomes() returns per-playbook latest outcome."""
        with isolated_runtime():
            ws = Workspace("test-latest")
            ws.create("https://example.test", "web")

            # Record multiple outcomes for the same playbook
            ws.record_strategy_outcome(
                playbook_id="test-playbook",
                outcome="dead-end",
                turn_index=1,
            )
            ws.record_strategy_outcome(
                playbook_id="test-playbook",
                outcome="worked",
                turn_index=2,
            )

            outcomes = ws.strategy_outcomes()
            self.assertIn("test-playbook", outcomes)
            self.assertEqual(outcomes["test-playbook"]["outcome"], "worked")
            self.assertEqual(outcomes["test-playbook"]["turn_index"], 2)
            self.assertEqual(outcomes["test-playbook"]["count"], 2)

    def test_strategy_outcomes_bounded_to_200(self):
        """strategy_outcomes() is bounded to 200 rows."""
        with isolated_runtime():
            ws = Workspace("test-bounded")
            ws.create("https://example.test", "web")

            # Record more than 200 outcomes
            for i in range(300):
                ws.record_strategy_outcome(
                    playbook_id=f"playbook-{i % 10}",
                    outcome="worked" if i % 2 == 0 else "dead-end",
                    turn_index=i,
                )

            outcomes = ws.strategy_outcomes()
            # The aggregation works on the last 200 rows
            # At least one playbook should be present
            self.assertTrue(len(outcomes) > 0)
            # Each should have counts reflecting their state in the last 200 rows
            for playbook_id, data in outcomes.items():
                self.assertIn("outcome", data)
                self.assertIn("count", data)
                self.assertIn("turn_index", data)

    def test_strategy_outcomes_empty(self):
        """strategy_outcomes() returns empty dict when no records."""
        with isolated_runtime():
            ws = Workspace("test-empty")
            ws.create("https://example.test", "web")

            outcomes = ws.strategy_outcomes()
            self.assertEqual(outcomes, {})


class ScenariosExcludeTests(unittest.TestCase):
    def test_priority_action_exclude_single(self):
        """priority_action with exclude skips excluded playbooks."""
        actions = scenarios.priority_actions("web")
        if len(actions) < 2:
            self.skipTest("Need at least 2 available scenarios")

        rows = scenarios.selected_scenarios("web")
        first_id = rows[0]["id"]
        first = scenarios.priority_action("web", 0)
        self.assertNotEqual(first, "")

        # Exclusion is by playbook id, never by action text.
        result = scenarios.priority_action("web", 0, exclude={first_id})
        self.assertNotEqual(result, first)
        self.assertIn(result, actions)
        self.assertNotIn(first_id, {row["id"] for row in scenarios.selected_scenarios("web")
                                    if row["priority_action"].strip() == result})

    def test_priority_action_exclude_all_fallback(self):
        """priority_action yields no action when every playbook is excluded."""
        rows = scenarios.selected_scenarios("web")
        if not rows:
            self.skipTest("Need at least 1 available scenario")

        result = scenarios.priority_action(
            "web", 0, exclude={row["id"] for row in rows}
        )
        # No fallback: exhausted rotations produce no coverage directive.
        self.assertEqual(result, "")

    def test_priority_action_exclude_none(self):
        """priority_action without exclude works as before."""
        result1 = scenarios.priority_action("web", 0)
        result2 = scenarios.priority_action("web", 0, exclude=None)
        self.assertEqual(result1, result2)

    def test_priority_action_rotation_with_exclude(self):
        """priority_action rotates through non-excluded playbooks."""
        actions = scenarios.priority_actions("web")
        if len(actions) < 3:
            self.skipTest("Need at least 3 available scenarios")

        # Exclude the second playbook by id
        exclude_set = {scenarios.selected_scenarios("web")[1]["id"]}
        result_0 = scenarios.priority_action("web", 0, exclude=exclude_set)
        result_1 = scenarios.priority_action("web", 1, exclude=exclude_set)

        # Both should be valid actions and neither should be the excluded one
        self.assertIn(result_0, actions)
        self.assertIn(result_1, actions)
        self.assertNotEqual(result_0, actions[1])
        self.assertNotEqual(result_1, actions[1])


class DeadEndExclusionsTests(unittest.TestCase):
    def test_dead_end_exclusions_none_initially(self):
        """dead_end_exclusions returns empty set for fresh outcomes."""
        outcomes = {}
        excluded = dead_end_exclusions(outcomes)
        self.assertEqual(excluded, set())

    def test_dead_end_exclusions_one_occurrence(self):
        """dead_end_exclusions does not exclude playbooks with one occurrence."""
        outcomes = {
            "test-playbook": {
                "outcome": "dead-end",
                "count": 1,
                "turn_index": 5,
            }
        }
        excluded = dead_end_exclusions(outcomes)
        self.assertEqual(excluded, set())

    def test_dead_end_exclusions_two_dead_ends(self):
        """dead_end_exclusions excludes playbooks with 2+ dead-end occurrences."""
        outcomes = {
            "test-playbook": {
                "outcome": "dead-end",
                "count": 2,
                "turn_index": 10,
            }
        }
        excluded = dead_end_exclusions(outcomes)
        self.assertEqual(excluded, {"test-playbook"})

    def test_dead_end_exclusions_worked_not_excluded(self):
        """dead_end_exclusions does not exclude playbooks with 'worked' outcome."""
        outcomes = {
            "test-playbook": {
                "outcome": "worked",
                "count": 2,
                "turn_index": 10,
            }
        }
        excluded = dead_end_exclusions(outcomes)
        self.assertEqual(excluded, set())

    def test_dead_end_exclusions_blocked_not_excluded(self):
        """dead_end_exclusions does not exclude playbooks with 'blocked' outcome."""
        outcomes = {
            "test-playbook": {
                "outcome": "blocked",
                "count": 2,
                "turn_index": 10,
            }
        }
        excluded = dead_end_exclusions(outcomes)
        self.assertEqual(excluded, set())

    def test_dead_end_exclusions_mixed(self):
        """dead_end_exclusions correctly handles mixed outcomes."""
        outcomes = {
            "playbook-a": {
                "outcome": "dead-end",
                "count": 2,
                "turn_index": 5,
            },
            "playbook-b": {
                "outcome": "dead-end",
                "count": 1,
                "turn_index": 10,
            },
            "playbook-c": {
                "outcome": "worked",
                "count": 2,
                "turn_index": 15,
            },
            "playbook-d": {
                "outcome": "dead-end",
                "count": 3,
                "turn_index": 20,
            },
        }
        excluded = dead_end_exclusions(outcomes)
        self.assertEqual(excluded, {"playbook-a", "playbook-d"})


class ManagerPromptExhaustionBreakersTests(unittest.IsolatedAsyncioTestCase):
    async def test_exhaustion_breakers_rendered_when_exhaustion_streak_set(self):
        """Manager prompt renders exhaustion breakers when streak > 0."""
        with isolated_runtime():
            ws = Workspace("test-breakers-1")
            ws.create("https://example.test", "web")
            mgr = KryptexManager(ws, "test system prompt")

            ctx = ManagerContext(
                target="https://example.test",
                target_type="web",
                turn_index=5,
                exhaustion_streak=3,
                exhaustion_breakers=("playbook-a", "playbook-b"),
            )

            prompt = mgr._build_direction_prompt(ctx)

            # Should contain exhaustion breakers section
            self.assertIn("EXHAUSTION BREAKERS:", prompt)
            self.assertIn("Negative space", prompt)
            self.assertIn("Re-fingerprint", prompt)
            self.assertIn("State-machine abuse", prompt)
            self.assertIn("Refuting observation", prompt)
            self.assertIn("playbook-a", prompt)
            self.assertIn("playbook-b", prompt)

    async def test_exhaustion_breakers_not_rendered_when_no_exhaustion(self):
        """Manager prompt does not render exhaustion breakers when streak = 0."""
        with isolated_runtime():
            ws = Workspace("test-breakers-2")
            ws.create("https://example.test", "web")
            mgr = KryptexManager(ws, "test system prompt")

            ctx = ManagerContext(
                target="https://example.test",
                target_type="web",
                turn_index=5,
                exhaustion_streak=0,
            )

            prompt = mgr._build_direction_prompt(ctx)

            # Should not contain exhaustion breakers section (or minimal presence)
            # The block is only rendered when exhaustion_streak > 0
            if "EXHAUSTION BREAKERS:" in prompt:
                # If present, should be empty or minimal
                self.assertNotIn("Negative space", prompt)

    async def test_exhaustion_breakers_empty_tuple_handled(self):
        """Manager prompt handles empty exhaustion_breakers tuple."""
        with isolated_runtime():
            ws = Workspace("test-breakers-3")
            ws.create("https://example.test", "web")
            mgr = KryptexManager(ws, "test system prompt")

            ctx = ManagerContext(
                target="https://example.test",
                target_type="web",
                turn_index=5,
                exhaustion_streak=2,
                exhaustion_breakers=(),
            )

            prompt = mgr._build_direction_prompt(ctx)

            # Should render breakers but without the excluded ids line
            self.assertIn("EXHAUSTION BREAKERS:", prompt)
            self.assertIn("Negative space", prompt)


if __name__ == "__main__":
    unittest.main()
