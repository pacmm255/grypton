from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from grypton import config
from grypton.toolserver import REGISTRY, dispatch
from grypton.tools import (
    DEFAULT_FLOW_READ_CHARS,
    MAX_FLOW_READ_CHARS,
    flow_read,
    proxy_flows,
)
from grypton.workspace import Workspace


@contextmanager
def isolated_runtime():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        values = {
            "STATE_DIR": root / ".state",
            "ENGAGEMENTS_DIR": root / ".state/engagements",
            "TARGETS_DIR": root / ".state/engagements",
            "RUNTIME_DIR": root / ".state/runtime",
            "LOG_DIR": root / ".state/runtime/logs",
            "PROVIDER_DIR": root / ".state/providers",
            "OPENCODE_WORKSPACES_DIR": root / ".opencode-workspaces",
            "TARGET_DATA_DIR": root / "artifact-data",
        }
        with patch.multiple(config, **values):
            config.ensure_layout()
            yield


def make_flow(workspace: Workspace, name: str, response: str) -> tuple[str, str]:
    text = (
        '### GRYPTON FLOW {"transport":"fixture"}\n'
        "### REQUEST\n"
        "GET https://analysis.test/resource\n\n"
        "### RESPONSE\n"
        "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n"
        + response
        + "\n"
    )
    path = workspace.flows_dir / f"{name}.http"
    path.write_text(text, encoding="utf-8")
    return path.stem, text


class FlowChunkTests(unittest.TestCase):
    def workspace(self) -> Workspace:
        workspace = Workspace("flow-chunks")
        workspace.create("analysis.test", "web")
        return workspace

    def test_flow_read_pages_utf8_capture_without_losing_bytes(self):
        with isolated_runtime():
            workspace = self.workspace()
            flow_id, expected = make_flow(workspace, "flow-unicode", "€abc" * 25_000)

            pieces = []
            offset = 0
            windows = 0
            while True:
                result = flow_read(workspace, flow_id, offset=offset, max_chars=1024)
                self.assertTrue(result["ok"], result)
                data = result["data"]
                self.assertEqual(data["byte_start"], offset)
                self.assertLessEqual(data["byte_end"] - data["byte_start"], 1024)
                self.assertNotIn("\ufffd", data["text"])
                pieces.append(data["text"])
                windows += 1
                if data["next_offset"] is None:
                    self.assertFalse(data["has_more"])
                    break
                self.assertTrue(data["has_more"])
                self.assertGreater(data["next_offset"], offset)
                offset = data["next_offset"]

            self.assertGreater(windows, 10)
            self.assertEqual("".join(pieces), expected)

    def test_flow_read_caps_oversized_output_and_reports_continuation(self):
        with isolated_runtime():
            workspace = self.workspace()
            flow_id, _ = make_flow(workspace, "flow-large", "x" * 100_000)

            result = flow_read(workspace, flow_id, max_chars=500_000)

            self.assertTrue(result["ok"], result)
            data = result["data"]
            self.assertTrue(data["request_capped"])
            self.assertEqual(data["max_chars_applied"], MAX_FLOW_READ_CHARS)
            self.assertEqual(data["byte_end"], MAX_FLOW_READ_CHARS)
            self.assertEqual(data["next_offset"], MAX_FLOW_READ_CHARS)
            self.assertLessEqual(len(data["text"]), MAX_FLOW_READ_CHARS)

            continued = dispatch(workspace, "flow_read", {
                "flow_id": flow_id,
                "offset": data["next_offset"],
                "max_chars": 4096,
            })
            self.assertTrue(continued["ok"], continued)
            self.assertEqual(continued["data"]["byte_start"], MAX_FLOW_READ_CHARS)

    def test_flow_read_rejects_invalid_ranges_and_schema_declares_bounds(self):
        with isolated_runtime():
            workspace = self.workspace()
            flow_id, text = make_flow(workspace, "flow-range", "small")
            self.assertFalse(flow_read(workspace, flow_id, offset=-1)["ok"])
            self.assertFalse(flow_read(
                workspace, flow_id, offset=len(text.encode("utf-8")) + 1,
            )["ok"])
            self.assertFalse(flow_read(workspace, flow_id, max_chars=255)["ok"])

            schema = REGISTRY["flow_read"][1]
            self.assertEqual(schema["properties"]["offset"]["minimum"], 0)
            self.assertNotIn("maximum", schema["properties"]["max_chars"])
            self.assertIn(
                "capped", schema["properties"]["max_chars"]["description"],
            )
            self.assertEqual(DEFAULT_FLOW_READ_CHARS, 16_384)

    def test_proxy_flow_query_streams_across_chunk_boundary(self):
        with isolated_runtime():
            workspace = self.workspace()
            marker = "cross-boundary-marker"
            prefix = (
                '### GRYPTON FLOW {"transport":"fixture"}\n'
                "### REQUEST\nGET https://analysis.test/resource\n\n"
                "### RESPONSE\nHTTP/1.1 200 OK\n\n"
            )
            padding = "a" * (64 * 1024 - len(prefix) - 5)
            path = workspace.flows_dir / "flow-streamed.http"
            path.write_text(prefix + padding + marker, encoding="utf-8")

            result = proxy_flows(workspace, query=marker.upper(), limit=1)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["data"][0]["id"], "flow-streamed")
            self.assertEqual(result["data"][0]["status"], "HTTP/1.1 200 OK")
            self.assertEqual(result["data"][0]["bytes"], path.stat().st_size)
            self.assertFalse(proxy_flows(workspace, query="q" * 4097)["ok"])

    def test_proxy_flow_listing_finds_status_after_large_request_body(self):
        with isolated_runtime():
            workspace = self.workspace()
            path = workspace.flows_dir / "flow-large-request.http"
            path.write_text(
                '### GRYPTON FLOW {"transport":"fixture"}\n'
                "### REQUEST\n"
                "POST https://analysis.test/upload\n\n"
                + ("r" * 300_000)
                + "\n### RESPONSE\nHTTP/1.1 413 Payload Too Large\n\n",
                encoding="utf-8",
            )

            result = proxy_flows(workspace, limit=1)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["data"][0]["id"], "flow-large-request")
            self.assertEqual(
                result["data"][0]["status"], "HTTP/1.1 413 Payload Too Large"
            )

    def test_proxy_flow_listing_skips_external_symlink(self):
        with isolated_runtime():
            workspace = self.workspace()
            outside = workspace.root.parent / "outside.http"
            outside.write_text(
                "### REQUEST\nGET https://outside.test/secret\n\n"
                "### RESPONSE\nHTTP/1.1 200 OK\n\nexternal-marker",
                encoding="utf-8",
            )
            (workspace.flows_dir / "flow-external.http").symlink_to(outside)

            result = proxy_flows(workspace, query="external-marker")

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["data"], [])
            self.assertFalse(flow_read(workspace, "flow-external")["ok"])

    def test_proxy_flow_listing_bounds_a_long_request_line(self):
        with isolated_runtime():
            workspace = self.workspace()
            path = workspace.flows_dir / "flow-long-url.http"
            path.write_text(
                "### REQUEST\nGET https://analysis.test/?q="
                + ("x" * 70_000)
                + "\n\n### RESPONSE\nHTTP/1.1 200 OK\n\n",
                encoding="utf-8",
            )

            result = proxy_flows(workspace, limit=1)

            self.assertTrue(result["ok"], result)
            self.assertEqual(len(result["data"][0]["request"]), 4096)
            self.assertTrue(result["data"][0]["request"].endswith("..."))


if __name__ == "__main__":
    unittest.main()
