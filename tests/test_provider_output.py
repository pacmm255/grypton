from __future__ import annotations

import asyncio
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from grypton import config
from grypton.providers import (MAX_ASSISTANT_TEXT_CHARS, OpenCodeClient,
                               _select_assistant_text)


@contextmanager
def isolated_runtime():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        state = root / ".state"
        values = {
            "STATE_DIR": state,
            "ENGAGEMENTS_DIR": state / "engagements",
            "TARGETS_DIR": state / "engagements",
            "RUNTIME_DIR": state / "runtime",
            "LOG_DIR": state / "runtime/logs",
            "PROVIDER_DIR": state / "providers",
            "OPENCODE_WORKSPACES_DIR": root / ".opencode-workspaces",
            "TARGET_DATA_DIR": root / "target",
        }
        with patch.multiple(config, **values):
            config.ensure_layout()
            yield root


class ProviderOutputTests(unittest.TestCase):
    def test_selects_and_normalizes_substantive_final_text(self):
        final = "\n".join([
            "Observed POST /app/session returned HTTP 401 without a cookie.",
            "Evidence: flow-17 records the response headers.",
            "Evidence: flow-17 records the response headers.",
            "✅ ✅ ✅ ✅",
            "Now I will provide the final answer.",
            "I should emit final response now.",
            "🏁 Done.",
        ])
        parts = ["Pre-tool narration must not enter the result.", final]
        original = list(parts)

        text, metadata = _select_assistant_text(parts)

        self.assertEqual(parts, original)
        self.assertIn("POST /app/session returned HTTP 401", text)
        self.assertEqual(text.count("flow-17 records the response headers"), 1)
        self.assertNotIn("Pre-tool narration", text)
        self.assertNotIn("provide the final answer", text)
        self.assertNotIn("emit final response", text)
        self.assertNotIn("✅", text)
        self.assertEqual(metadata["raw_text_part_count"], 2)
        self.assertEqual(metadata["raw_final_text_chars"], len(final))
        self.assertEqual(metadata["normalized_text_chars"], len(text))
        self.assertEqual(metadata["selected_text_part_index"], 1)
        self.assertTrue(metadata["text_filtered"])
        self.assertFalse(metadata["text_truncated"])

    def test_falls_back_when_final_part_is_only_chatter(self):
        text, metadata = _select_assistant_text([
            "Authentication was not attempted; the login endpoint is still unknown.",
            "✅\nDone.\nNow I will provide the final response.",
        ])

        self.assertIn("login endpoint is still unknown", text)
        self.assertNotIn("provide the final response", text)
        self.assertEqual(metadata["selected_text_part_index"], 0)
        self.assertTrue(metadata["text_filtered"])

    def test_bounds_unique_substantive_output(self):
        raw = "\n".join(
            f"Evidence {index}: GET /app/item/{index} returned HTTP 200."
            for index in range(1000)
        )

        text, metadata = _select_assistant_text([raw])

        self.assertLessEqual(len(text), MAX_ASSISTANT_TEXT_CHARS)
        self.assertIn("normalized response truncated", text)
        self.assertIn("/app/item/0", text)
        self.assertIn("/app/item/999", text)
        self.assertEqual(metadata["raw_final_text_chars"], len(raw))
        self.assertEqual(metadata["normalized_text_chars"], len(text))
        self.assertTrue(metadata["text_filtered"])
        self.assertTrue(metadata["text_truncated"])

    def test_call_keeps_raw_events_and_records_filter_metadata(self):
        class _Input:
            def write(self, value):
                self.value = value

            async def drain(self):
                return None

            def close(self):
                return None

        class _Stream:
            def __init__(self, payload=b""):
                self.payload = payload

            async def read(self, _size):
                payload, self.payload = self.payload, b""
                return payload

        class _Process:
            pid = 43210

            def __init__(self, stdout):
                self.stdin = _Input()
                self.stdout = _Stream(stdout)
                self.stderr = _Stream()
                self.returncode = None

            async def wait(self):
                self.returncode = 0
                return 0

        async def exercise():
            with isolated_runtime():
                workspace = config.ENGAGEMENTS_DIR / "normalized-call"
                workspace.mkdir(parents=True)
                client = OpenCodeClient(
                    role="worker", route=config.WORKER_MODEL, effort="max",
                    workspace=workspace, target_slug="normalized-call",
                    allow_tools=True, agent_prompt="test",
                )
                final = "Useful result: GET /app returned HTTP 200.\n✅\nDone."
                events = [
                    {"type": "text", "sessionID": "ses-fixture",
                     "part": {"text": "Pre-tool narration."}},
                    {"type": "text", "sessionID": "ses-fixture",
                     "part": {"text": final}},
                ]
                payload = b"".join(
                    (json.dumps(event, ensure_ascii=False) + "\n").encode()
                    for event in events
                )
                process = _Process(payload)
                gateway = SimpleNamespace(
                    model_route=f"openclaude/{config.WORKER_MODEL}",
                    drain_events=lambda: [],
                )
                with patch.object(client, "_ensure_gateway", AsyncMock(return_value=gateway)), \
                        patch.object(client, "_environment", return_value=({}, "fixture-secret")), \
                        patch.object(config, "require_binary", return_value="/usr/bin/true"), \
                        patch("grypton.providers.asyncio.create_subprocess_exec",
                              new=AsyncMock(return_value=process)):
                    result = await client.call("bounded prompt")

                self.assertIn("GET /app returned HTTP 200", result.text)
                self.assertNotIn("Pre-tool narration", result.text)
                raw_events = [json.loads(line) for line in (
                    workspace / "transcripts/worker.opencode.events.jsonl"
                ).read_text().splitlines()]
                self.assertEqual(raw_events, events)
                record = json.loads((
                    workspace / "transcripts/provider-calls.jsonl"
                ).read_text().splitlines()[-1])
                self.assertEqual(record["raw_final_text_chars"], len(final))
                self.assertEqual(record["normalized_text_chars"], len(result.text))
                self.assertTrue(record["text_filtered"])

        asyncio.run(exercise())


if __name__ == "__main__":
    unittest.main()
