"""Read-only differential harness over saved captures (WS7 support tool).

The verify_finding tool checks that a declared single-variable change produces
a visible, replay-stable response difference. All digests are computed locally
from saved captures; no network request is made.

Fixtures here declare changes that GENUINELY differ between the positive and
control captures. Note that ``tools._save_flow`` redacts sensitive request
headers (Authorization, Cookie, ...) to the literal ``[REDACTED]`` placeholder,
so a real single-variable change has to be declared on a header/parameter the
capture preserves (these tests use ``X-Variant``, ``page``, ``color``, ...);
declaring a redacted header is itself rejected as ambiguous, which
``test_redacted_header_declared_rejected`` exercises.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from grypton import config, tools
from grypton.toolserver import REGISTRY, _RESTART_SAFE_READ_ONLY_TOOLS
from grypton.workspace import Workspace

from tests.evidence_helpers import (POSITIVE_BODY, REQUEST_HEADERS, REQUEST_METHOD,
                                    REQUEST_URL)


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


def workspace(slug="verify"):
    ws = Workspace(slug)
    ws.create("https://example.test", "web")
    return ws


def _response(status: int, body: str) -> str:
    reason = {200: "OK", 403: "Forbidden"}.get(status, "Status")
    return (f"HTTP/1.1 {status} {reason}\n"
            "Content-Type: application/json\n"
            "X-Custom-Header: custom-value\n"
            f"\n{body}")


def _variant_headers(value: str) -> dict:
    """Request headers carrying a preserved (non-sensitive) declared variable."""
    return {**REQUEST_HEADERS, "X-Variant": value}


def _set_response_truncated(path: Path) -> None:
    """Flip the on-disk metadata ``response_truncated`` flag to True."""
    text = path.read_text(encoding="utf-8")
    first_line, sep, rest = text.partition("\n")
    prefix = "### GRYPTON FLOW "
    metadata = json.loads(first_line[len(prefix):])
    metadata["response_truncated"] = True
    path.write_text(prefix + json.dumps(metadata, ensure_ascii=False) + sep + rest,
                    encoding="utf-8")


class VerifyFindingTest(unittest.TestCase):
    def test_supported_verdict(self):
        """Declared X-Variant genuinely differs; positive 200 vs control 403."""
        with isolated_runtime():
            ws = workspace()
            positive_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            positive_id = positive_path.stem
            control_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v2"), None,
                _response(403, '{"error": "forbidden"}'), transport="curl", returncode=0)
            replay1_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)
            replay2_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)

            args = {
                "positive_exchange_id": positive_id,
                "control_exchange_id": control_path.stem,
                "replay_exchange_ids": [replay1_path.stem, replay2_path.stem],
                "changed_variable": {"location": "header", "name": "X-Variant"},
            }
            result = tools.verify_finding(ws, args)
            self.assertTrue(result["ok"], result.get("summary"))
            self.assertEqual(result["data"]["verdict"], "supported")
            self.assertTrue(result["data"]["declared_change"]["visible"])
            self.assertTrue(result["data"]["request_comparison"]["only_declared_variable_changed"])
            self.assertEqual(result["data"]["request_comparison"]["unexpected_changes"], [])
            self.assertTrue(result["data"]["positive_vs_control"]["different"])
            self.assertTrue(result["data"]["replay_stability"]["stable"])
            self.assertEqual(result["data"]["replay_stability"]["matching_replays"], 2)

    def test_visible_but_unstable(self):
        """Positive differs from control but one replay differs from positive."""
        with isolated_runtime():
            ws = workspace()
            positive_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            positive_id = positive_path.stem
            control_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v2"), None,
                _response(403, '{"error": "forbidden"}'), transport="curl", returncode=0)
            replay1_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)
            replay2_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(500, '{"error": "server error"}'), transport=f"replay:{positive_id}", returncode=0)

            args = {
                "positive_exchange_id": positive_id,
                "control_exchange_id": control_path.stem,
                "replay_exchange_ids": [replay1_path.stem, replay2_path.stem],
                "changed_variable": {"location": "header", "name": "X-Variant"},
            }
            result = tools.verify_finding(ws, args)
            self.assertTrue(result["ok"])
            self.assertEqual(result["data"]["verdict"], "visible-but-unstable")
            self.assertEqual(result["data"]["replay_stability"]["matching_replays"], 1)
            self.assertEqual(result["data"]["replay_stability"]["total_replays"], 2)

    def test_no_visible_difference(self):
        """Declared variable differs but the response vectors are identical."""
        with isolated_runtime():
            ws = workspace()
            positive_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            positive_id = positive_path.stem
            control_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v2"), None,
                _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            replay1_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)

            args = {
                "positive_exchange_id": positive_id,
                "control_exchange_id": control_path.stem,
                "replay_exchange_ids": [replay1_path.stem],
                "changed_variable": {"location": "header", "name": "X-Variant"},
            }
            result = tools.verify_finding(ws, args)
            self.assertTrue(result["ok"])
            self.assertEqual(result["data"]["verdict"], "no-visible-difference")
            self.assertFalse(result["data"]["declared_change"]["visible"])

    def test_invalid_control_two_differences(self):
        """Declared header differs, but the method also changes undeclared."""
        with isolated_runtime():
            ws = workspace()
            positive_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            positive_id = positive_path.stem
            # Control changes both the declared X-Variant header AND the method.
            control_path = tools._save_flow(
                ws, "POST", REQUEST_URL, _variant_headers("v2"), None,
                _response(403, '{"error": "forbidden"}'), transport="curl", returncode=0)
            replay1_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)

            args = {
                "positive_exchange_id": positive_id,
                "control_exchange_id": control_path.stem,
                "replay_exchange_ids": [replay1_path.stem],
                "changed_variable": {"location": "header", "name": "X-Variant"},
            }
            result = tools.verify_finding(ws, args)
            self.assertTrue(result["ok"])
            self.assertEqual(result["data"]["verdict"], "invalid-control")
            self.assertIn("method",
                          result["data"]["request_comparison"]["unexpected_changes"])
            self.assertFalse(result["data"]["declared_change"]["visible"])

    def test_identical_requests_declared_header_invalid_control(self):
        """Byte-identical requests + declared header => invalid-control.

        The declared header is present in both captures with the SAME value, so
        it does not differ and no single variable was isolated.
        """
        with isolated_runtime():
            ws = workspace()
            positive_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("same"), None,
                _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            positive_id = positive_path.stem
            control_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("same"), None,
                _response(403, '{"error": "forbidden"}'), transport="curl", returncode=0)
            replay1_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("same"), None,
                _response(200, POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)

            args = {
                "positive_exchange_id": positive_id,
                "control_exchange_id": control_path.stem,
                "replay_exchange_ids": [replay1_path.stem],
                "changed_variable": {"location": "header", "name": "X-Variant"},
            }
            result = tools.verify_finding(ws, args)
            self.assertTrue(result["ok"])
            self.assertEqual(result["data"]["verdict"], "invalid-control")
            self.assertFalse(
                result["data"]["request_comparison"]["only_declared_variable_changed"])

    def test_query_extra_undeclared_key_change_invalid_control(self):
        """A second, undeclared query key change makes the control invalid."""
        with isolated_runtime():
            ws = workspace()
            positive_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL + "?page=1&sort=asc", REQUEST_HEADERS,
                None, _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            positive_id = positive_path.stem
            control_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL + "?page=2&sort=desc", REQUEST_HEADERS,
                None, _response(403, '{"error": "forbidden"}'), transport="curl", returncode=0)
            replay1_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL + "?page=1&sort=asc", REQUEST_HEADERS,
                None, _response(200, POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)

            args = {
                "positive_exchange_id": positive_id,
                "control_exchange_id": control_path.stem,
                "replay_exchange_ids": [replay1_path.stem],
                "changed_variable": {"location": "query", "name": "page"},
            }
            result = tools.verify_finding(ws, args)
            self.assertTrue(result["ok"])
            self.assertEqual(result["data"]["verdict"], "invalid-control")
            self.assertIn("query",
                          result["data"]["request_comparison"]["unexpected_changes"])

    def test_query_named_key_change_supported(self):
        """Only the declared query key changes => supported."""
        with isolated_runtime():
            ws = workspace()
            positive_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL + "?page=1&sort=asc", REQUEST_HEADERS,
                None, _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            positive_id = positive_path.stem
            control_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL + "?page=2&sort=asc", REQUEST_HEADERS,
                None, _response(403, '{"error": "forbidden"}'), transport="curl", returncode=0)
            replay1_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL + "?page=1&sort=asc", REQUEST_HEADERS,
                None, _response(200, POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)

            args = {
                "positive_exchange_id": positive_id,
                "control_exchange_id": control_path.stem,
                "replay_exchange_ids": [replay1_path.stem],
                "changed_variable": {"location": "query", "name": "page"},
            }
            result = tools.verify_finding(ws, args)
            self.assertTrue(result["ok"])
            self.assertEqual(result["data"]["verdict"], "supported")
            self.assertEqual(result["data"]["request_comparison"]["unexpected_changes"], [])

    def test_body_form_named_field_change_supported(self):
        """Only the declared urlencoded form field changes => supported."""
        with isolated_runtime():
            ws = workspace()
            positive_path = tools._save_flow(
                ws, "POST", REQUEST_URL, REQUEST_HEADERS, "color=red&size=large",
                _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            positive_id = positive_path.stem
            control_path = tools._save_flow(
                ws, "POST", REQUEST_URL, REQUEST_HEADERS, "color=blue&size=large",
                _response(403, '{"error": "forbidden"}'), transport="curl", returncode=0)
            replay1_path = tools._save_flow(
                ws, "POST", REQUEST_URL, REQUEST_HEADERS, "color=red&size=large",
                _response(200, POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)

            args = {
                "positive_exchange_id": positive_id,
                "control_exchange_id": control_path.stem,
                "replay_exchange_ids": [replay1_path.stem],
                "changed_variable": {"location": "body_form", "name": "color"},
            }
            result = tools.verify_finding(ws, args)
            self.assertTrue(result["ok"])
            self.assertEqual(result["data"]["verdict"], "supported")
            self.assertEqual(result["data"]["request_comparison"]["unexpected_changes"], [])

    def test_selected_header_replay_mismatch_unstable(self):
        """A replay that differs only in a SELECTED response header is unstable."""
        with isolated_runtime():
            ws = workspace()

            def resp(status, shard, body):
                reason = "OK" if status == 200 else "Forbidden"
                return (f"HTTP/1.1 {status} {reason}\n"
                        "Content-Type: application/json\n"
                        f"X-Shard: {shard}\n\n{body}")

            positive_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                resp(200, "node-a", POSITIVE_BODY), transport="curl", returncode=0)
            positive_id = positive_path.stem
            control_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v2"), None,
                resp(403, "node-c", '{"error": "forbidden"}'), transport="curl", returncode=0)
            # Replay: identical status/body/bytes, but a different X-Shard value.
            replay1_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                resp(200, "node-b", POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)

            args = {
                "positive_exchange_id": positive_id,
                "control_exchange_id": control_path.stem,
                "replay_exchange_ids": [replay1_path.stem],
                "changed_variable": {"location": "header", "name": "X-Variant"},
                "selected_response_headers": ["X-Shard"],
            }
            result = tools.verify_finding(ws, args)
            self.assertTrue(result["ok"])
            # Status/body/bytes all match the positive, so the old (partial)
            # comparator would have called this stable; the full-vector rule
            # catches the differing selected header.
            self.assertEqual(result["data"]["verdict"], "visible-but-unstable")
            self.assertEqual(result["data"]["replay_stability"]["matching_replays"], 0)

    def test_duplicate_id_rejection(self):
        """Reject when positive_id == control_id."""
        with isolated_runtime():
            ws = workspace()
            positive_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
                _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            positive_id = positive_path.stem

            args = {
                "positive_exchange_id": positive_id,
                "control_exchange_id": positive_id,  # Same as positive
                "replay_exchange_ids": [positive_id],  # Also duplicated
                "changed_variable": {"location": "header", "name": "X-Variant"},
            }
            result = tools.verify_finding(ws, args)
            self.assertFalse(result["ok"])
            self.assertIn("Duplicate", result["summary"])

    def test_positive_equals_control_distinct_replays_rejected(self):
        """Reject positive == control even when both replay ids are distinct."""
        with isolated_runtime():
            ws = workspace()
            positive_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            positive_id = positive_path.stem
            replay1_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)
            replay2_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)

            args = {
                "positive_exchange_id": positive_id,
                "control_exchange_id": positive_id,  # equal to positive
                "replay_exchange_ids": [replay1_path.stem, replay2_path.stem],
                "changed_variable": {"location": "header", "name": "X-Variant"},
            }
            result = tools.verify_finding(ws, args)
            self.assertFalse(result["ok"])
            self.assertIn("Duplicate", result["summary"])

    def test_unknown_flow_rejection(self):
        """Reject when a flow doesn't exist."""
        with isolated_runtime():
            ws = workspace()
            args = {
                "positive_exchange_id": "flow-9999999",
                "control_exchange_id": "flow-8888888",
                "replay_exchange_ids": ["flow-7777777"],
                "changed_variable": {"location": "header", "name": "X-Variant"},
            }
            result = tools.verify_finding(ws, args)
            self.assertFalse(result["ok"])
            self.assertIn("Unknown flow", result["summary"])

    def test_redacted_header_declared_rejected(self):
        """Declaring a header the capture redacts is ambiguous and rejected."""
        with isolated_runtime():
            ws = workspace()
            headers = {**REQUEST_HEADERS, "Authorization": "Bearer token-a"}
            control_headers = {**REQUEST_HEADERS, "Authorization": "Bearer token-b"}
            positive_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, headers, None,
                _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            positive_id = positive_path.stem
            control_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, control_headers, None,
                _response(403, '{"error": "forbidden"}'), transport="curl", returncode=0)
            replay1_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, headers, None,
                _response(200, POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)

            args = {
                "positive_exchange_id": positive_id,
                "control_exchange_id": control_path.stem,
                "replay_exchange_ids": [replay1_path.stem],
                "changed_variable": {"location": "header", "name": "Authorization"},
            }
            result = tools.verify_finding(ws, args)
            self.assertFalse(result["ok"])
            self.assertIn("redacted", result["summary"].lower())

    def test_truncated_capture_inconclusive(self):
        """A truncated capture yields inconclusive with a naming limitation."""
        with isolated_runtime():
            ws = workspace()
            positive_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            positive_id = positive_path.stem
            control_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v2"), None,
                _response(403, '{"error": "forbidden"}'), transport="curl", returncode=0)
            replay1_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)

            _set_response_truncated(positive_path)

            args = {
                "positive_exchange_id": positive_id,
                "control_exchange_id": control_path.stem,
                "replay_exchange_ids": [replay1_path.stem],
                "changed_variable": {"location": "header", "name": "X-Variant"},
            }
            result = tools.verify_finding(ws, args)
            self.assertTrue(result["ok"])
            self.assertEqual(result["data"]["verdict"], "inconclusive")
            self.assertTrue(any(positive_id in note
                                for note in result["data"]["limitations"]))

    def test_selected_header_presence_digest(self):
        """Track selected_response_headers presence and sha256."""
        with isolated_runtime():
            ws = workspace()
            positive_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            positive_id = positive_path.stem
            # Control response without X-Custom-Header
            control_response = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{}"
            control_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v2"), None,
                control_response, transport="curl", returncode=0)
            replay1_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)

            args = {
                "positive_exchange_id": positive_id,
                "control_exchange_id": control_path.stem,
                "replay_exchange_ids": [replay1_path.stem],
                "changed_variable": {"location": "header", "name": "X-Variant"},
                "selected_response_headers": ["X-Custom-Header", "Content-Type"],
            }
            result = tools.verify_finding(ws, args)
            self.assertTrue(result["ok"])

            exchanges = result["data"]["exchanges"]
            pos_digest = exchanges[0]["response_digest"]["selected_headers"]
            ctl_digest = exchanges[1]["response_digest"]["selected_headers"]

            self.assertTrue(pos_digest["X-Custom-Header"]["present"])
            self.assertIn("sha256", pos_digest["X-Custom-Header"])
            self.assertFalse(ctl_digest["X-Custom-Header"]["present"])
            self.assertNotIn("sha256", ctl_digest["X-Custom-Header"])

            # Both should have Content-Type present
            self.assertTrue(pos_digest["Content-Type"]["present"])
            self.assertTrue(ctl_digest["Content-Type"]["present"])

    def test_tool_in_registry(self):
        """verify_finding is registered as an MCP tool."""
        self.assertIn("verify_finding", REGISTRY)
        description, schema, handler = REGISTRY["verify_finding"]
        self.assertIn("differential", description.lower())
        self.assertEqual(schema["required"],
                         ["positive_exchange_id", "control_exchange_id",
                          "replay_exchange_ids", "changed_variable"])

    def test_tool_in_restart_safe(self):
        """verify_finding is in the restart-safe read-only tools set."""
        self.assertIn("verify_finding", _RESTART_SAFE_READ_ONLY_TOOLS)

    def test_no_raw_header_values_in_output(self):
        """Output contains no raw header values, only digests."""
        with isolated_runtime():
            ws = workspace()
            positive_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            positive_id = positive_path.stem
            control_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v2"), None,
                _response(403, '{"error": "forbidden"}'), transport="curl", returncode=0)
            replay1_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)

            args = {
                "positive_exchange_id": positive_id,
                "control_exchange_id": control_path.stem,
                "replay_exchange_ids": [replay1_path.stem],
                "changed_variable": {"location": "header", "name": "X-Variant"},
                "selected_response_headers": ["X-Custom-Header"],
            }
            result = tools.verify_finding(ws, args)
            self.assertTrue(result["ok"])

            result_json = json.dumps(result)
            # The sentinel value should not be in the output
            self.assertNotIn("custom-value", result_json)
            # But its sha256 should be present
            data = result["data"]
            for ex in data["exchanges"]:
                headers = ex["response_digest"]["selected_headers"]
                if "X-Custom-Header" in headers:
                    h = headers["X-Custom-Header"]
                    if h.get("present"):
                        self.assertIn("sha256", h)

    def test_invalid_changed_variable_schema(self):
        """Reject invalid changed_variable format."""
        with isolated_runtime():
            ws = workspace()
            positive_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
                _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            positive_id = positive_path.stem
            control_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
                _response(403, '{"error": "forbidden"}'), transport="curl", returncode=0)
            replay1_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
                _response(200, POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)

            # Missing "location"
            args = {
                "positive_exchange_id": positive_id,
                "control_exchange_id": control_path.stem,
                "replay_exchange_ids": [replay1_path.stem],
                "changed_variable": {"name": "X-Variant"},
            }
            result = tools.verify_finding(ws, args)
            self.assertFalse(result["ok"])

    def test_one_replay(self):
        """Verify with just one replay."""
        with isolated_runtime():
            ws = workspace()
            positive_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            positive_id = positive_path.stem
            control_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v2"), None,
                _response(403, '{"error": "forbidden"}'), transport="curl", returncode=0)
            replay1_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                _response(200, POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)

            args = {
                "positive_exchange_id": positive_id,
                "control_exchange_id": control_path.stem,
                "replay_exchange_ids": [replay1_path.stem],
                "changed_variable": {"location": "header", "name": "X-Variant"},
            }
            result = tools.verify_finding(ws, args)
            self.assertTrue(result["ok"])
            self.assertEqual(result["data"]["verdict"], "supported")
            self.assertEqual(result["data"]["replay_stability"]["total_replays"], 1)

    def test_invalid_location_enum(self):
        """Reject invalid location value."""
        with isolated_runtime():
            ws = workspace()
            args = {
                "positive_exchange_id": "flow-1",
                "control_exchange_id": "flow-2",
                "replay_exchange_ids": ["flow-3"],
                "changed_variable": {"location": "invalid_location", "name": "test"},
            }
            result = tools.verify_finding(ws, args)
            self.assertFalse(result["ok"])

    def test_all_locations_accepted(self):
        """Each defined location enum value is accepted by the schema.

        Verdict correctness per location is covered by the dedicated tests; here
        we only confirm no location value is rejected as an unknown enum.
        """
        with isolated_runtime():
            ws = workspace()
            positive_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
                _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            positive_id = positive_path.stem
            control_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
                _response(403, '{"error": "forbidden"}'), transport="curl", returncode=0)
            replay1_path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
                _response(200, POSITIVE_BODY), transport=f"replay:{positive_id}", returncode=0)

            locations = ["method", "url_path", "query", "header", "body_form",
                        "body_json_pointer", "body_text"]
            for location in locations:
                args = {
                    "positive_exchange_id": positive_id,
                    "control_exchange_id": control_path.stem,
                    "replay_exchange_ids": [replay1_path.stem],
                    "changed_variable": {"location": location, "name": "test"},
                }
                result = tools.verify_finding(ws, args)
                self.assertIn("ok", result, f"Failed for location={location}")
                self.assertNotIn("must be one of", result.get("summary", ""),
                                 f"Location {location} wrongly rejected as enum")


class ParseHttpFlowTest(unittest.TestCase):
    """Direct coverage of the re-parser's byte exactness and read cap."""

    def test_embedded_crlf_body_byte_count_exact(self):
        """The response body byte count includes embedded CRLF bytes exactly."""
        with isolated_runtime():
            ws = workspace("verify-crlf-body")
            body = "A\r\nB\r\nC"
            response = ("HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/plain\r\n\r\n" + body)
            path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
                response, transport="curl", returncode=0)
            parsed = tools._parse_http_flow(path)
            self.assertEqual(parsed["response"]["body"], body)
            self.assertEqual(parsed["response"]["body_bytes"],
                             len(body.encode("utf-8")))
            self.assertEqual(parsed["response"]["body_bytes"], 7)
            self.assertFalse(parsed["read_truncated"])

    def test_read_cap_truncation_flagged(self):
        """A file larger than the read cap sets read_truncated."""
        with isolated_runtime():
            ws = workspace("verify-readcap")
            path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
                _response(200, POSITIVE_BODY), transport="curl", returncode=0)
            cap = max(1, path.stat().st_size - 1)
            parsed = tools._parse_http_flow(path, max_bytes=cap)
            self.assertTrue(parsed["read_truncated"])


if __name__ == "__main__":
    unittest.main()


class CrlfCaptureRegressionTest(unittest.TestCase):
    """Real curl captures carry CRLF wire bytes; the harness must parse them."""

    def test_crlf_captures_get_supported_verdict(self):
        def crlf(status, body):
            return (f"HTTP/1.1 {status} {'OK' if status == 200 else 'Forbidden'}\r\n"
                    "Content-Type: application/json\r\n\r\n" + body)
        with isolated_runtime():
            ws = workspace("verify-crlf")
            positive = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                crlf(200, POSITIVE_BODY), transport="curl", returncode=0)
            control = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v2"), None,
                crlf(403, '{"error": "no"}'), transport="curl", returncode=0)
            replay = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, _variant_headers("v1"), None,
                crlf(200, POSITIVE_BODY),
                transport=f"replay:{positive.stem}", returncode=0)
            result = tools.verify_finding(ws, {
                "positive_exchange_id": positive.stem,
                "control_exchange_id": control.stem,
                "replay_exchange_ids": [replay.stem],
                "changed_variable": {
                    "location": "header", "name": "X-Variant"},
            })
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["data"]["verdict"], "supported")
            self.assertGreater(
                result["data"]["exchanges"][0]["response_digest"]["body_bytes"], 0)
