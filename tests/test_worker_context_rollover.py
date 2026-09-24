from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from grypton import config
from grypton.engine import Engine
from grypton.providers import OpenCodeResult
from grypton.worker import OpenCodeWorker, WorkerSpec, usage_context_tokens
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
            "OPENCODE_WORKSPACES_DIR": state / "opencode-workspaces",
            "TARGET_DATA_DIR": root / "reserved-empty",
        }
        with patch.multiple(config, **values):
            config.ensure_layout()
            yield root


def provider_result(session_id: str, usage: list[dict]) -> OpenCodeResult:
    return OpenCodeResult(
        text="completed turn",
        session_id=session_id,
        events=[],
        tools=[],
        usage=usage,
        duration_s=0.01,
    )


def make_worker(ws: Workspace, session_id: str) -> OpenCodeWorker:
    worker = OpenCodeWorker(WorkerSpec(
        session_uuid=session_id,
        cwd=ws.root,
        system_prompt="fixture static prompt",
        model="fixture/worker",
        effort="max",
        extra_env={"GRYPTON_TARGET": ws.slug},
    ))
    worker._started = True
    return worker


class WorkerContextRolloverTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.old_limit = config.CONFIG.worker_context_rollover_tokens

    def tearDown(self):
        config.CONFIG.worker_context_rollover_tokens = self.old_limit

    def test_default_and_defensive_latest_context_derivation(self):
        self.assertEqual(config.GryptonConfig().worker_context_rollover_tokens, 250_000)
        self.assertEqual(usage_context_tokens([
            {
                "input": 100,
                "output": 20,
                "reasoning": 5,
                "cache": {"read": 10, "write": 2},
                "cost": 999,
            },
            {
                "input": 30,
                "output": 3,
                "reasoning": 7,
                "cache": {"read": 140, "write": 10},
                "total": 999_999,
            },
        ]), 999_999)
        self.assertEqual(usage_context_tokens([{
            "input": 30,
            "output": 3,
            "reasoning": 7,
            "cache": {"read": 140, "write": 10},
            "unknown_numeric_metadata": 123_456,
        }]), 190)
        self.assertIsNone(usage_context_tokens([]))
        self.assertEqual(usage_context_tokens([
            {"input": 10, "output": 2, "reasoning": 1,
             "cache": {"read": 20, "write": 0}},
            {"total": 900_000},
            {"input": "malformed"},
        ]), 900_000)
        self.assertIsNone(usage_context_tokens([{
            "input": "many", "cache": {"read": -1, "write": 0},
        }]))

    async def test_threshold_rollover_persists_only_empty_worker_and_next_call_is_fresh(self):
        with isolated_runtime():
            config.CONFIG.worker_context_rollover_tokens = 250_000
            ws = Workspace("context-rollover")
            ws.create("https://example.test", "web")
            ws.update_meta(
                worker_uuid="worker-session-old",
                manager_session_id="manager-chat-keep",
                worker_model="fixture/worker",
                manager_model="fixture/manager",
            )
            ws.append_progress("durable evidence marker")
            marker = ws.scratch_dir / "keep.txt"
            marker.write_text("keep durable evidence", encoding="utf-8")

            events: list[tuple[str, dict]] = []
            engine = Engine(
                ws.slug,
                backend="real",
                emit=lambda kind, **payload: events.append((kind, payload)),
            )
            engine.turn_index = 8
            worker = make_worker(ws, "worker-session-old")
            worker.client.call = AsyncMock(side_effect=[
                provider_result("worker-session-old", [
                    {"input": 20_000, "output": 5_000, "reasoning": 1_000,
                     "cache": {"read": 80_000, "write": 0}},
                    {"input": 5_000, "output": 15_000, "reasoning": 5_000,
                     "cache": {"read": 195_000, "write": 10_000}},
                ]),
                provider_result("worker-session-old", [
                    {"input": 4_000, "output": 15_000, "reasoning": 5_000,
                     "cache": {"read": 220_000, "write": 5_000}},
                ]),
                provider_result("worker-session-old", [
                    {"input": 5_000, "output": 15_000, "reasoning": 5_000,
                     "cache": {"read": 220_000, "write": 5_000}},
                ]),
                provider_result("worker-session-new", [
                    {"input": 10, "output": 5, "reasoning": 0,
                     "cache": {"read": 0, "write": 0}},
                ]),
            ])
            engine.worker = worker

            first = await worker.run_turn("first action")
            self.assertEqual(first.result["context_tokens"], 230_000)
            self.assertFalse(engine._rollover_worker_session_if_needed(first))
            self.assertEqual(ws.load_meta().worker_uuid, "worker-session-old")

            second = await worker.run_turn("second action")
            self.assertEqual(second.result["context_tokens"], 249_000)
            self.assertFalse(engine._rollover_worker_session_if_needed(second))

            third = await worker.run_turn("third action")
            self.assertEqual(third.result["context_tokens"], 250_000)
            self.assertTrue(engine._rollover_worker_session_if_needed(third))

            persisted = ws.load_meta()
            self.assertEqual(persisted.worker_uuid, "")
            self.assertEqual(persisted.manager_session_id, "manager-chat-keep")
            self.assertEqual(persisted.worker_model, "fixture/worker")
            self.assertEqual(persisted.manager_model, "fixture/manager")
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep durable evidence")
            self.assertEqual(worker.session_id, "")
            self.assertEqual(worker.spec.session_uuid, "")

            rollover_events = [payload for kind, payload in events
                               if kind == "worker_session_rollover"]
            self.assertEqual(rollover_events, [{
                "turn": 8, "context_tokens": 250_000, "threshold": 250_000,
            }])
            self.assertNotIn("worker-session-old", json.dumps(rollover_events))
            self.assertIn("Kraude context rolled over", (
                ws.root / "progress.md"
            ).read_text(encoding="utf-8"))

            await worker.run_turn("next action")
            calls = worker.client.call.await_args_list
            self.assertEqual([call.kwargs["session_id"] for call in calls], [
                "worker-session-old", "worker-session-old",
                "worker-session-old", "",
            ])
            self.assertFalse(bool(calls[-1].kwargs["session_id"]))

    async def test_below_threshold_keeps_resumable_worker_session(self):
        with isolated_runtime():
            config.CONFIG.worker_context_rollover_tokens = 250_000
            ws = Workspace("context-below")
            ws.create("https://example.test", "web")
            ws.update_meta(worker_uuid="worker-session")
            events = []
            engine = Engine(ws.slug, backend="real",
                            emit=lambda kind, **payload: events.append((kind, payload)))
            worker = make_worker(ws, "worker-session")
            worker.client.call = AsyncMock(return_value=provider_result(
                "worker-session", [{
                    "input": 9_999,
                    "output": 500,
                    "reasoning": 100,
                    "cache": {"read": 239_000, "write": 0},
                }],
            ))
            engine.worker = worker

            turn = await worker.run_turn("bounded action")

            self.assertFalse(engine._rollover_worker_session_if_needed(turn))
            self.assertEqual(worker.session_id, "worker-session")
            self.assertEqual(ws.load_meta().worker_uuid, "worker-session")
            self.assertFalse(any(kind == "worker_session_rollover" for kind, _ in events))

    async def test_missing_usage_and_disabled_threshold_never_roll_over(self):
        with isolated_runtime():
            ws = Workspace("context-disabled")
            ws.create("https://example.test", "web")
            ws.update_meta(worker_uuid="worker-session")
            engine = Engine(ws.slug, backend="real")
            worker = make_worker(ws, "worker-session")
            worker.client.call = AsyncMock(side_effect=[
                provider_result("worker-session", []),
                provider_result("worker-session", [{
                    "input": 900_000,
                    "output": 1,
                    "reasoning": 0,
                    "cache": {"read": 0, "write": 0},
                }]),
            ])
            engine.worker = worker

            config.CONFIG.worker_context_rollover_tokens = 250_000
            missing = await worker.run_turn("missing usage")
            self.assertNotIn("context_tokens", missing.result)
            self.assertFalse(engine._rollover_worker_session_if_needed(missing))

            config.CONFIG.worker_context_rollover_tokens = 0
            disabled = await worker.run_turn("disabled rollover")
            self.assertEqual(disabled.result["context_tokens"], 900_001)
            self.assertFalse(engine._rollover_worker_session_if_needed(disabled))
            self.assertEqual(worker.session_id, "worker-session")
            self.assertEqual(ws.load_meta().worker_uuid, "worker-session")

    async def test_restart_uses_current_call_instead_of_accumulating_provider_log(self):
        with isolated_runtime():
            config.CONFIG.worker_context_rollover_tokens = 250_000
            ws = Workspace("context-restore")
            ws.create("https://example.test", "web")
            ws.update_meta(worker_uuid="restored-session")
            calls = ws.transcripts_dir / "provider-calls.jsonl"
            calls.write_text(json.dumps({
                "role": "worker",
                "session_id": "restored-session",
                "ok": True,
                "usage": [{
                    "input": 20_000,
                    "output": 20_000,
                    "reasoning": 1_000,
                    "cache": {"read": 220_000, "write": 0},
                }],
            }) + "\n", encoding="utf-8")

            worker = make_worker(ws, "restored-session")
            worker.client.call = AsyncMock(return_value=provider_result(
                "restored-session", [{
                    "input": 5_000,
                    "output": 5_000,
                    "reasoning": 1_000,
                    "cache": {"read": 214_000, "write": 0},
                }],
            ))
            engine = Engine(ws.slug, backend="real")
            engine.worker = worker

            turn = await worker.run_turn("resume action")

            self.assertEqual(turn.result["context_tokens"], 225_000)
            self.assertFalse(engine._rollover_worker_session_if_needed(turn))
            self.assertEqual(ws.load_meta().worker_uuid, "restored-session")


if __name__ == "__main__":
    unittest.main()
