from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from grypton import config
from grypton.toolserver import REGISTRY, dispatch
from grypton.tools import local_analyze
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
            "TARGET_DATA_DIR": root / "target",
        }
        with patch.multiple(config, **values):
            config.ensure_layout()
            yield


class LocalAnalyzeSearchTests(unittest.TestCase):
    def workspace(self, name: str = "artifact-search") -> Workspace:
        workspace = Workspace(name)
        workspace.create("analysis.test", "web")
        return workspace

    def test_literal_search_bounds_context_for_one_line_minified_javascript(self):
        with isolated_runtime():
            workspace = self.workspace()
            prefix = b"a" * 100_000
            marker = b'fetch("/api/session")'
            payload = prefix + marker + (b"z" * 100_000)
            (workspace.loot_dir / "app.min.js").write_bytes(payload)

            result = local_analyze(
                workspace, "loot/app.min.js", analyzer="literal",
                pattern='/api/session', context_bytes=24, max_matches=5,
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["data"]["matches_returned"], 1)
            match = result["data"]["matches"][0]
            expected = len(prefix) + len(b'fetch("')
            self.assertEqual(match["byte_start"], expected)
            self.assertEqual(match["byte_end"], expected + len(b"/api/session"))
            self.assertEqual(match["line_start"], 1)
            self.assertEqual(match["line_end"], 1)
            self.assertEqual(match["line_byte_offset"], expected)
            self.assertIn('/api/session', match["context"])
            self.assertLessEqual(
                match["context_byte_end"] - match["context_byte_start"],
                len(b"/api/session") + 48,
            )
            self.assertLess(len(json.dumps(result)), 2_000)

    def test_regex_search_returns_byte_and_line_offsets(self):
        with isolated_runtime():
            workspace = self.workspace("regex-search")
            payload = (
                b"header\nconst first='API/v1/users/42';\n"
                b"const second='api/v1/users/9001';\n"
            )
            (workspace.loot_dir / "routes.js").write_bytes(payload)

            result = local_analyze(
                workspace, "loot/routes.js", analyzer="regex",
                pattern=r"api/v1/users/\d+", ignore_case=True,
                context_bytes=8, max_matches=10,
            )

            self.assertTrue(result["ok"], result)
            matches = result["data"]["matches"]
            self.assertEqual([item["line_start"] for item in matches], [2, 3])
            self.assertEqual(matches[0]["byte_start"], payload.index(b"API/v1/users/42"))
            self.assertEqual(matches[1]["byte_start"], payload.index(b"api/v1/users/9001"))
            self.assertEqual(matches[0]["line_byte_offset"], len(b"const first='"))
            self.assertEqual(matches[1]["line_byte_offset"], len(b"const second='"))
            self.assertFalse(result["data"]["truncated"])

    def test_search_limits_matches_and_large_match_preview(self):
        with isolated_runtime():
            workspace = self.workspace("bounded-search")
            (workspace.loot_dir / "many.txt").write_bytes(b"hit," * 100)
            limited = local_analyze(
                workspace, "loot/many.txt", analyzer="literal", pattern="hit",
                context_bytes=4, max_matches=3,
            )
            self.assertTrue(limited["ok"], limited)
            self.assertEqual(limited["data"]["matches_returned"], 3)
            self.assertTrue(limited["data"]["truncated"])
            self.assertEqual(
                [item["byte_start"] for item in limited["data"]["matches"]],
                [0, 4, 8],
            )

            (workspace.loot_dir / "long.txt").write_bytes(b"A" * 10_000)
            large = local_analyze(
                workspace, "loot/long.txt", analyzer="regex", pattern="A+",
                context_bytes=0, max_matches=1,
            )
            self.assertTrue(large["ok"], large)
            match = large["data"]["matches"][0]
            self.assertEqual(match["match_bytes"], 10_000)
            self.assertTrue(match["match_truncated"])
            self.assertLess(len(match["match_preview"]), 700)

    def test_search_rejects_invalid_input_and_schema_exposes_bounds(self):
        with isolated_runtime():
            workspace = self.workspace("invalid-search")
            (workspace.loot_dir / "sample.txt").write_text("sample")
            self.assertFalse(local_analyze(
                workspace, "loot/sample.txt", analyzer="literal", pattern="",
            )["ok"])
            invalid = local_analyze(
                workspace, "loot/sample.txt", analyzer="regex", pattern="(",
            )
            self.assertFalse(invalid["ok"])
            self.assertIn("invalid regular expression", invalid["summary"])
            self.assertFalse(local_analyze(
                workspace, "loot/sample.txt", analyzer="literal", pattern="x",
                max_matches=51,
            )["ok"])

            schema = REGISTRY["local_analyze"][1]
            self.assertEqual(schema["properties"]["max_matches"]["maximum"], 50)
            self.assertEqual(schema["properties"]["context_bytes"]["maximum"], 2048)
            self.assertIn("literal", schema["properties"]["analyzer"]["enum"])
            self.assertIn("regex", schema["properties"]["analyzer"]["enum"])

            dispatched = dispatch(workspace, "local_analyze", {
                "path": "loot/sample.txt", "analyzer": "literal",
                "pattern": "amp", "context_bytes": 2, "max_matches": 2,
            })
            self.assertTrue(dispatched["ok"], dispatched)
            self.assertEqual(dispatched["data"]["matches"][0]["byte_start"], 1)


if __name__ == "__main__":
    unittest.main()
