from __future__ import annotations

import asyncio
from contextlib import contextmanager
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, call, patch

from grypton import config
from grypton.engine import Engine
from grypton.worker import TurnResult, WorkerError
from grypton.workspace import Constraints, Workspace


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


def exhausted_pool_error(*, retry_after_s: int = 60, tool_count: int = 0) -> WorkerError:
    return WorkerError(
        "worker OpenClaude credential pool exhausted (upstream HTTP 429).",
        metadata={
            "source": "openclaude",
            "type": "openclaude_terminal",
            "role": "worker",
            "reason": "credential_pool_exhausted",
            "upstream_status": 429,
            "pool_size": 3,
            "retry_after_s": retry_after_s,
            "tool_count": tool_count,
        },
    )


class DeadlineWorkerRetryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.old_config = {
            name: getattr(config.CONFIG, name)
            for name in (
                "max_turns",
                "max_run_seconds",
                "exhaustion_threshold",
                "passive_stagnation_limit",
                "repetitive_probe_turn_limit",
            )
        }

    def tearDown(self):
        for name, value in self.old_config.items():
            setattr(config.CONFIG, name, value)

    async def test_five_transient_pool_failures_do_not_end_deadline_run(self):
        with isolated_runtime():
            config.CONFIG.max_turns = 1
            config.CONFIG.max_run_seconds = 0
            config.CONFIG.exhaustion_threshold = 99
            config.CONFIG.passive_stagnation_limit = 99
            config.CONFIG.repetitive_probe_turn_limit = 99

            ws = Workspace("deadline-provider-retry")
            ws.create("https://example.test", "web")
            ws.save_constraints(Constraints(in_scope=["https://example.test"]))
            events: list[tuple[str, dict]] = []
            engine = Engine(
                ws.slug,
                backend="mock",
                run_until_deadline=True,
                emit=lambda kind, **payload: events.append((kind, payload)),
            )
            await engine.setup(
                brief="exercise the scoped application",
                target="https://example.test",
                target_type="web",
            )
            engine.worker.run_turn = AsyncMock(side_effect=[
                *(exhausted_pool_error() for _ in range(5)),
                TurnResult(
                    assistant_text="provider recovered and the request completed",
                    tool_uses=[{
                        "name": "http_request",
                        "input": {"method": "GET", "url": "https://example.test/"},
                    }],
                    result={"is_error": False},
                    duration_s=0.01,
                ),
            ])
            engine.worker.ensure_started = AsyncMock()
            engine.manager.direct = AsyncMock(wraps=engine.manager.direct)
            engine._wait_for_worker_retry = AsyncMock(return_value=True)

            await engine.run()

            self.assertEqual(engine.turn_index, 1)
            self.assertIn("max_turns safety ceiling", engine.stop_reason)
            self.assertNotIn("unrecoverable worker fault", engine.stop_reason)
            self.assertEqual(engine.worker.run_turn.await_count, 6)
            self.assertEqual(
                engine._wait_for_worker_retry.await_args_list,
                [call(60), call(60), call(60), call(60), call(60)],
            )
            self.assertEqual(engine.worker.ensure_started.await_count, 5)
            self.assertEqual(engine.manager.direct.await_count, 1)

            retry_events = [
                payload for kind, payload in events
                if kind == "worker_provider_retry"
            ]
            self.assertEqual([event["attempt"] for event in retry_events], [1, 2, 3, 4, 5])
            self.assertTrue(all(event["wait_s"] == 60 for event in retry_events))
            self.assertTrue(all(event["upstream_status"] == 429 for event in retry_events))
            self.assertTrue(all(event["tool_count"] == 0 for event in retry_events))
            self.assertTrue(all(set(event) == {
                "attempt", "wait_s", "reason", "upstream_status", "tool_count",
            } for event in retry_events))
            progress = (ws.root / "progress.md").read_text(encoding="utf-8")
            self.assertEqual(progress.count("transient Kraude provider failure"), 5)

    async def test_partial_tool_failure_resets_session_and_suppresses_replay(self):
        with isolated_runtime():
            config.CONFIG.max_turns = 1
            config.CONFIG.max_run_seconds = 0
            config.CONFIG.exhaustion_threshold = 99
            config.CONFIG.passive_stagnation_limit = 99
            config.CONFIG.repetitive_probe_turn_limit = 99

            ws = Workspace("deadline-partial-tool")
            ws.create("https://example.test", "web")
            ws.save_constraints(Constraints(in_scope=["https://example.test"]))
            events: list[tuple[str, dict]] = []
            engine = Engine(
                ws.slug,
                backend="mock",
                run_until_deadline=True,
                emit=lambda kind, **payload: events.append((kind, payload)),
            )
            opening = "submit the scoped login flow once"
            await engine.setup(
                brief=opening,
                target="https://example.test",
                target_type="web",
            )
            engine.worker.session_id = "incomplete-worker-session"
            engine.worker.spec.session_uuid = "incomplete-worker-session"
            engine.ws.update_meta(
                worker_uuid="incomplete-worker-session",
                manager_session_id="manager-session-keep",
            )
            manager_session = engine.manager.session_id
            engine.worker.run_turn = AsyncMock(side_effect=[
                exhausted_pool_error(retry_after_s=7, tool_count=2),
                TurnResult(
                    assistant_text="continued on another recorded lead",
                    tool_uses=[{
                        "name": "http_request",
                        "input": {"method": "GET", "url": "https://example.test/next"},
                    }],
                    result={"is_error": False},
                    duration_s=0.01,
                ),
            ])
            engine.worker.ensure_started = AsyncMock()
            engine._wait_for_worker_retry = AsyncMock(return_value=True)

            await engine.run()

            directives = [item.args[0] for item in engine.worker.run_turn.await_args_list]
            self.assertEqual(directives[0], opening)
            self.assertNotEqual(directives[1], opening)
            self.assertIn("different highest-impact unresolved lead", directives[1])
            self.assertEqual(engine.turn_index, 1)
            self.assertEqual(engine.worker.session_id, "")
            self.assertEqual(engine.worker.spec.session_uuid, "")
            self.assertEqual(engine.ws.load_meta().worker_uuid, "")
            self.assertEqual(engine.manager.session_id, manager_session)
            engine._wait_for_worker_retry.assert_awaited_once_with(7)

            suppressed = [
                payload for kind, payload in events
                if kind == "worker_replay_suppressed"
            ]
            self.assertEqual(suppressed, [{
                "turn": 1,
                "attempt": 1,
                "tool_count": 2,
                "reason": "credential_pool_exhausted",
                "session_reset": True,
            }])
            self.assertNotIn(opening, str(suppressed))

    async def test_zero_event_provider_failure_cannot_replay_native_action(self):
        with isolated_runtime():
            config.CONFIG.max_turns = 1
            config.CONFIG.max_run_seconds = 0
            config.CONFIG.exhaustion_threshold = 99
            config.CONFIG.passive_stagnation_limit = 99
            config.CONFIG.repetitive_probe_turn_limit = 99

            ws = Workspace("zero-event-native-failure")
            ws.create("https://example.test", "web")
            events: list[tuple[str, dict]] = []
            engine = Engine(
                ws.slug,
                backend="mock",
                run_until_deadline=True,
                emit=lambda kind, **payload: events.append((kind, payload)),
            )
            opening = "perform the one-time scoped native action"
            await engine.setup(
                brief=opening,
                target="https://example.test",
                target_type="web",
            )
            engine.worker.session_id = "possibly-effectful-session"
            engine.worker.spec.session_uuid = "possibly-effectful-session"
            engine.ws.update_meta(worker_uuid="possibly-effectful-session")
            self.assertTrue(engine._worker_failure_replay_unsafe(
                WorkerError("missing provider safety classification")
            ))
            self.assertFalse(engine._worker_failure_replay_unsafe(
                WorkerError("pre-spawn failure", metadata={"replay_safe": True})
            ))
            observed: list[tuple[str, str]] = []
            effect = ws.root / "research" / "native-effect.txt"

            async def run_turn(directive: str):
                observed.append((directive, engine.worker.session_id))
                if len(observed) == 1:
                    effect.write_text("executed once\n", encoding="utf-8")
                    raise WorkerError(
                        "OpenCode exited before flushing a tool event",
                        metadata={
                            "tool_count": 0,
                            "replay_safe": False,
                        },
                    )
                return TurnResult(
                    assistant_text="continued with another recorded lead",
                    tool_uses=[{"name": "http_request", "input": {}}],
                    result={"is_error": False},
                )

            engine.worker.run_turn = AsyncMock(side_effect=run_turn)
            engine.worker.ensure_started = AsyncMock()
            engine._wait_for_worker_retry = AsyncMock(return_value=True)

            await engine.run()

            self.assertEqual(effect.read_text(encoding="utf-8"), "executed once\n")
            self.assertEqual(observed[0], (opening, "possibly-effectful-session"))
            self.assertEqual(observed[1][1], "")
            self.assertNotEqual(observed[1][0], opening)
            self.assertIn("different highest-impact unresolved lead", observed[1][0])
            suppressed = [
                payload for kind, payload in events
                if kind == "worker_replay_suppressed"
            ]
            self.assertEqual(suppressed[0]["tool_count"], 0)
            self.assertTrue(suppressed[0]["session_reset"])

    async def test_unclassified_partial_worker_error_also_suppresses_replay(self):
        with isolated_runtime():
            config.CONFIG.max_turns = 1
            config.CONFIG.max_run_seconds = 0
            config.CONFIG.exhaustion_threshold = 99
            config.CONFIG.passive_stagnation_limit = 99
            config.CONFIG.repetitive_probe_turn_limit = 99

            ws = Workspace("deadline-unclassified-partial")
            ws.create("https://example.test", "web")
            engine = Engine(ws.slug, backend="mock", run_until_deadline=True)
            opening = "perform the one-time scoped action"
            await engine.setup(
                brief=opening,
                target="https://example.test",
                target_type="web",
            )
            engine.worker.session_id = "partial-unclassified-session"
            engine.worker.spec.session_uuid = "partial-unclassified-session"
            engine.ws.update_meta(worker_uuid="partial-unclassified-session")
            engine.worker.run_turn = AsyncMock(side_effect=[
                WorkerError("worker process exited", metadata={"tool_count": 1}),
                TurnResult(
                    assistant_text="recovered through another lead",
                    tool_uses=[{"name": "http_request", "input": {}}],
                    result={"is_error": False},
                ),
            ])
            engine.worker.ensure_started = AsyncMock()
            engine._wait_for_worker_retry = AsyncMock(return_value=True)
            events: list[tuple[str, dict]] = []
            engine.emit = lambda kind, **payload: events.append((kind, payload))

            await engine.run()

            directives = [item.args[0] for item in engine.worker.run_turn.await_args_list]
            self.assertEqual(directives[0], opening)
            self.assertNotEqual(directives[1], opening)
            self.assertEqual(engine.turn_index, 1)
            self.assertEqual(engine.ws.load_meta().worker_uuid, "")
            engine._wait_for_worker_retry.assert_awaited_once_with(2)
            suppressed = [
                payload for kind, payload in events
                if kind == "worker_replay_suppressed"
            ]
            self.assertEqual(suppressed[0]["reason"], "provider_failure")
            self.assertEqual(suppressed[0]["tool_count"], 1)

    async def test_retry_wait_is_immediately_interruptible_by_operator_stop(self):
        with isolated_runtime():
            config.CONFIG.max_run_seconds = 0
            ws = Workspace("interruptible-provider-retry")
            ws.create("https://example.test", "web")
            engine = Engine(ws.slug, backend="mock", run_until_deadline=True)
            engine._start_time = time.time()

            waiting = asyncio.create_task(engine._wait_for_worker_retry(60))
            await asyncio.sleep(0)
            engine.request_stop("operator requested stop")

            result = await asyncio.wait_for(waiting, timeout=0.5)
            self.assertFalse(result)
            self.assertEqual(engine.stop_reason, "operator requested stop")

    async def test_retry_wait_honors_elapsed_run_deadline(self):
        with isolated_runtime():
            config.CONFIG.max_run_seconds = 1
            ws = Workspace("provider-retry-deadline")
            ws.create("https://example.test", "web")
            engine = Engine(ws.slug, backend="mock", run_until_deadline=True)
            engine._start_time = time.time() - 2

            result = await engine._wait_for_worker_retry(60)

            self.assertFalse(result)
            self.assertIn("max_run_seconds safety ceiling", engine.stop_reason)

    async def test_programming_error_fails_deadline_run_without_retry_loop(self):
        with isolated_runtime():
            config.CONFIG.max_turns = 0
            config.CONFIG.max_run_seconds = 0

            ws = Workspace("deadline-programming-error")
            ws.create("https://example.test", "web")
            engine = Engine(ws.slug, backend="mock", run_until_deadline=True)
            await engine.setup(
                brief="exercise the scoped application",
                target="https://example.test",
                target_type="web",
            )
            engine.worker.run_turn = AsyncMock(
                side_effect=TypeError("fixture programming error")
            )
            engine._wait_for_worker_retry = AsyncMock(return_value=True)

            with self.assertRaisesRegex(TypeError, "fixture programming error"):
                await engine.run()

            self.assertEqual(engine.turn_index, 0)
            engine._wait_for_worker_retry.assert_not_awaited()
            self.assertEqual(engine.ws.load_meta().status, "failed")


if __name__ == "__main__":
    unittest.main()
