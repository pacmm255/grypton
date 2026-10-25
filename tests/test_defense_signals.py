from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from grypton import config
from grypton.engine import (
    Engine,
    _validated_defense_signals,
    classify_defense_signal,
)
from grypton.manager import KryptexManager, ManagerContext
from grypton.workspace import Workspace


DEFENSE_INSTRUCTION = (
    "Challenge pages, CAPTCHA, and rate limits end that probe family; do not "
    "retry or evade them. Plain 401/403 responses are access-control "
    "information: record the boundary fact and continue elsewhere."
)


@contextmanager
def isolated_runtime():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        with patch.multiple(config, **{
            "STATE_DIR": root / ".state",
            "ENGAGEMENTS_DIR": root / ".state/engagements",
            "TARGETS_DIR": root / ".state/engagements",
            "RUNTIME_DIR": root / ".state/runtime",
            "LOG_DIR": root / ".state/runtime/logs",
            "PROVIDER_DIR": root / ".state/providers",
            "OPENCODE_WORKSPACES_DIR": root / ".opencode-workspaces",
            "TARGET_DATA_DIR": root / "target",
        }):
            config.ensure_layout()
            yield root


def workspace(slug):
    ws = Workspace(slug)
    ws.create("127.0.0.1", "web")
    return ws


def engine_stub(turn_index=7):
    engine = Engine.__new__(Engine)
    engine.turn_index = turn_index
    return engine


class ClassifyDefenseSignalTest(unittest.TestCase):
    def test_captcha_text_is_challenge(self):
        signal = classify_defense_signal(
            "http_request", "Please solve the CAPTCHA to continue.")
        self.assertEqual(signal["kind"], "challenge")
        self.assertEqual(signal["tool"], "http_request")
        self.assertIn("captcha marker", signal["detail"])

    def test_waf_marker_without_status_is_challenge(self):
        signal = classify_defense_signal(
            "browse", "Request blocked: attention required (cloudflare ray id 9a).")
        self.assertEqual(signal["kind"], "challenge")
        self.assertEqual(signal["detail"], "attention required marker")

    def test_http_429_is_rate_limit(self):
        signal = classify_defense_signal(
            "http_request", "HTTP/1.1 429 Too Many Requests")
        self.assertEqual(signal["kind"], "rate-limit")
        self.assertEqual(signal["detail"], "too many requests marker with status 429")

    def test_rate_limit_text_is_rate_limit(self):
        signal = classify_defense_signal(
            "goja_request", "Slow down: rate limit exceeded.")
        self.assertEqual(signal["kind"], "rate-limit")
        self.assertEqual(signal["detail"], "rate limit marker")

    def test_json_status_429_is_rate_limit(self):
        signal = classify_defense_signal("http_request", '{"status": 429}')
        self.assertEqual(signal["kind"], "rate-limit")
        self.assertEqual(signal["detail"], "status 429")

    def test_plain_403_is_access_denied(self):
        signal = classify_defense_signal("http_request", "HTTP/1.1 403 Forbidden")
        self.assertEqual(signal["kind"], "access-denied")
        self.assertEqual(
            signal["detail"], "status 403 without challenge marker")

    def test_plain_401_is_access_denied(self):
        signal = classify_defense_signal(
            "authenticated_http_request", 'response status: 401')
        self.assertEqual(signal["kind"], "access-denied")
        self.assertEqual(
            signal["detail"], "status 401 without challenge marker")

    def test_challenge_wins_over_plain_403(self):
        signal = classify_defense_signal(
            "http_request",
            "HTTP/1.1 403 Forbidden\n<h1>Checking your browser (recaptcha)</h1>")
        self.assertEqual(signal["kind"], "challenge")
        self.assertEqual(
            signal["detail"], "captcha marker with status 403")

    def test_no_signal_returns_none(self):
        self.assertIsNone(
            classify_defense_signal("http_request", "HTTP/1.1 200 OK\n{'ok': true}"))
        self.assertIsNone(classify_defense_signal("dns_lookup", ""))
        self.assertIsNone(classify_defense_signal("port_scan", None))

    def test_detail_carries_no_url(self):
        signal = classify_defense_signal(
            "http_request",
            "https://target.test/admin?q=" + "x" * 300 + " turnstile page")
        self.assertEqual(signal["kind"], "challenge")
        self.assertEqual(signal["detail"], "turnstile marker")
        self.assertNotIn("http", signal["detail"])
        self.assertLessEqual(len(signal["detail"]), 120)

    def test_marker_beyond_text_window_is_ignored(self):
        self.assertIsNone(
            classify_defense_signal("http_request", "x" * 4000 + " captcha"))

    def test_status_extraction_is_conservative(self):
        self.assertIsNone(classify_defense_signal(
            "http_request", "error 1403 while rendering"))
        self.assertIsNone(classify_defense_signal(
            "http_request", "HTTP/1.1 200 status tracked"))


class EngineDefenseSignalsTest(unittest.TestCase):
    def _tool(self, name, output):
        return {"name": name, "input": {}, "output": output, "is_error": False}

    def test_signals_bounded_to_twenty_and_stamped(self):
        turn = type("Turn", (), {})()
        turn.tool_uses = [
            self._tool("http_request", "captcha required") for _ in range(25)
        ]
        signals = engine_stub(turn_index=9)._defense_signals(turn)
        self.assertEqual(len(signals), 20)
        self.assertTrue(
            all(s["turn_index"] == 9 and s["kind"] == "challenge"
                for s in signals))

    def test_clean_and_malformed_tool_entries_are_skipped(self):
        turn = type("Turn", (), {})()
        turn.tool_uses = [
            "not-a-dict",
            self._tool("dns_lookup", "normal result"),
            None,
            self._tool("http_request", "HTTP/1.1 403 Forbidden"),
        ]
        signals = engine_stub()._defense_signals(turn)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["kind"], "access-denied")

    def test_non_string_output_is_serialized(self):
        turn = type("Turn", (), {})()
        turn.tool_uses = [
            self._tool("http_request", {"error": "rate limit exceeded"}),
        ]
        signals = engine_stub()._defense_signals(turn)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["kind"], "rate-limit")

    def test_missing_turn_yields_no_signals(self):
        self.assertEqual(engine_stub()._defense_signals(None), [])
        turn = type("Turn", (), {})()
        turn.tool_uses = None
        self.assertEqual(engine_stub()._defense_signals(turn), [])

    def test_tool_name_is_sanitized(self):
        turn = type("Turn", (), {})()
        turn.tool_uses = [self._tool("http\nrequest" + "!" * 200, "waf block")]
        signals = engine_stub()._defense_signals(turn)
        self.assertEqual(len(signals), 1)
        self.assertEqual(len(signals[0]["tool"]), 80)
        self.assertTrue(signals[0]["tool"].startswith("http request"))
        self.assertTrue(signals[0]["tool"].endswith("…"))


class ValidatedDefenseSignalsTest(unittest.TestCase):
    def _entry(self, kind="challenge", turn_index=3, **overrides):
        entry = {
            "kind": kind,
            "tool": "http_request",
            "detail": "captcha marker with status 403",
            "turn_index": turn_index,
        }
        entry.update(overrides)
        return entry

    def test_non_list_fails_closed(self):
        self.assertEqual(_validated_defense_signals(None), [])
        self.assertEqual(_validated_defense_signals("captcha"), [])
        self.assertEqual(_validated_defense_signals({}), [])

    def test_malformed_entries_are_dropped(self):
        signals = _validated_defense_signals([
            "nope",
            self._entry(kind="bypass"),
            self._entry(detail=""),
            self._entry(detail="d" * 121),
            self._entry(tool=""),
            self._entry(tool="t" * 81),
            self._entry(turn_index=True),
            self._entry(turn_index=-1),
            self._entry(turn_index="3"),
            self._entry(),
        ])
        self.assertEqual(signals, [self._entry()])

    def test_most_recent_window_wins(self):
        entries = [
            self._entry(turn_index=index, detail=f"captcha marker {index}")
            for index in range(25)
        ]
        signals = _validated_defense_signals(entries)
        self.assertEqual(len(signals), 20)
        self.assertEqual(signals[0]["turn_index"], 5)
        self.assertEqual(signals[-1]["turn_index"], 24)

    def test_huge_turn_index_is_bounded(self):
        signals = _validated_defense_signals([self._entry(turn_index=10**12)])
        self.assertEqual(signals[0]["turn_index"], 1_000_000_000)


class DirectionPromptDefenseBlockTest(unittest.TestCase):
    def _prompt(self, signals):
        with isolated_runtime():
            ws = workspace("defense-prompt")
            manager = KryptexManager(ws, "system")
            return manager._build_direction_prompt(ManagerContext(
                target="127.0.0.1", target_type="web", turn_index=4,
                defense_signals=signals,
            ))

    def test_block_renders_signals_with_fixed_instruction(self):
        prompt = self._prompt((
            {"kind": "challenge", "tool": "http_request",
             "detail": "captcha marker with status 403", "turn_index": 3},
            {"kind": "access-denied", "tool": "goja_request",
             "detail": "status 401 without challenge marker", "turn_index": 4},
        ))
        self.assertIn("TARGET DEFENSE OBSERVATIONS:", prompt)
        self.assertIn(DEFENSE_INSTRUCTION, prompt)
        self.assertIn(
            "- challenge via http_request: captcha marker with status 403",
            prompt)
        self.assertIn(
            "- access-denied via goja_request: status 401 without challenge "
            "marker", prompt)
        block = prompt.split("TARGET DEFENSE OBSERVATIONS:", 1)[1]
        block = block.split("\n\n", 1)[0]
        self.assertLessEqual(len(block.split("\n")) + 1, 8)

    def test_block_bounded_to_eight_lines(self):
        prompt = self._prompt(tuple(
            {"kind": "rate-limit", "tool": f"tool_{index}",
             "detail": f"status 429 ({index})", "turn_index": index}
            for index in range(9)
        ))
        block = prompt.split("TARGET DEFENSE OBSERVATIONS:", 1)[1]
        block = block.split("\n\n", 1)[0]
        lines = block.split("\n")
        self.assertEqual(len(lines), 8)
        self.assertEqual(lines[0], "")  # split artifact after the title
        self.assertEqual(len(prompt.split(DEFENSE_INSTRUCTION)), 2)

    def test_empty_signals_render_placeholder(self):
        prompt = self._prompt(())
        self.assertIn("TARGET DEFENSE OBSERVATIONS:", prompt)
        self.assertIn(DEFENSE_INSTRUCTION, prompt)
        self.assertIn("(none recorded)", prompt)
        self.assertNotIn("- challenge via", prompt)


class DefenseSignalMetaRoundTripTest(unittest.TestCase):
    def test_meta_round_trip_persists_signals(self):
        signals = [
            {"kind": "challenge", "tool": "http_request",
             "detail": "captcha marker with status 403", "turn_index": 3},
            {"kind": "rate-limit", "tool": "goja_request",
             "detail": "status 429", "turn_index": 4},
        ]
        with isolated_runtime():
            ws = workspace("defense-meta")
            self.assertEqual(ws.load_meta().defense_signals_recent, [])
            ws.update_meta(defense_signals_recent=signals)
            self.assertEqual(ws.load_meta().defense_signals_recent, signals)


if __name__ == "__main__":
    unittest.main()
