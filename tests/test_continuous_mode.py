from __future__ import annotations

import asyncio
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from grypton import config
from grypton.cli import _configure_run, build_parser, cmd_run_start
from grypton.engine import Engine
from grypton.manager import Directive
from grypton.runtime import (
    _SUPERVISED_RUN_ENV,
    _astra_completion_count,
    _paths,
    _provider_call_window_begin,
    _write_json,
    public_status,
    run_engine,
    start_background,
    supervise,
)
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
            "OPENCODE_WORKSPACES_DIR": root / ".opencode-workspaces",
            "TARGET_DATA_DIR": root / "input-data",
        }
        with patch.multiple(config, **values):
            config.ensure_layout()
            yield root


class _Process:
    def __init__(self, pid: int = 48100, returncode: int | None = None):
        self.pid = pid
        self.returncode = returncode

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return 0 if self.returncode is None else self.returncode

    def terminate(self):
        self.returncode = -signal.SIGTERM


def _write_supervisor_fixture(ws: Workspace, run_id: str, **overrides) -> dict:
    paths = _paths(ws.slug, run_id)
    spec = {
        "version": 2,
        "slug": ws.slug,
        "run_id": run_id,
        "deadline_at": None,
        "run_mode": "until-finding",
        "until_severity": "P2",
        "health_interval_seconds": 600,
        "restart_limit": None,
        "run_until_stopped": True,
    }
    spec.update(overrides)
    _write_json(paths["spec"], spec)
    _write_json(paths["state"], {
        "version": 2,
        "slug": ws.slug,
        "run_id": run_id,
        "status": "starting",
        "deadline_at": None,
        "run_mode": "until-finding",
        "until_severity": spec["until_severity"],
        "restart_policy": "unlimited-safe",
        "restart_limit": None,
        "restarts": 0,
    })
    _write_json(
        config.RUNTIME_DIR / f"supervisors/{ws.slug}/current.json",
        {"run_id": run_id},
    )
    return paths


class ContinuousRuntimeTests(unittest.TestCase):
    def test_cli_exposes_explicit_indefinite_policy(self):
        parser = build_parser()
        ns = parser.parse_args([
            "run", "start", "saved", "--forever", "--until-severity", "p2",
        ])
        self.assertTrue(ns.forever)
        self.assertEqual(ns.until_severity, "P2")
        self.assertIsNone(ns.duration_seconds)
        self.assertIsNone(ns.restart_limit)

        with patch("grypton.cli.cmd_resume", return_value=0):
            self.assertEqual(cmd_run_start(ns), 0)
        self.assertIsNone(ns.duration_seconds)

        finite = parser.parse_args(["run", "start", "saved"])
        with patch("grypton.cli.cmd_resume", return_value=0):
            self.assertEqual(cmd_run_start(finite), 0)
        self.assertEqual(finite.duration_seconds, 12 * 60 * 60)

    def test_forever_rejects_finite_or_limited_restart_controls(self):
        parser = build_parser()
        for option in (
            ["--duration", "1h"],
            ["--max-seconds", "60"],
            ["--auto-stop-time", "10"],
            ["--max-turns", "4"],
            ["--restart-limit", "4"],
        ):
            ns = parser.parse_args([
                "run", "start", "saved", "--backend", "mock", "--forever", *option,
            ])
            with self.subTest(option=option), self.assertRaisesRegex(
                ValueError, "--forever cannot be combined"
            ):
                _configure_run(ns)

    def test_forever_spec_and_public_status_have_no_deadline(self):
        with isolated_runtime():
            ws = Workspace("forever-start")
            ws.create("example.test", "web")
            fake = _Process(returncode=None)

            def matching(pid, role, slug, run_id):
                return role == "supervise" and pid == fake.pid

            def ready_state(*_args, **_kwargs):
                current = json.loads(
                    (config.RUNTIME_DIR / "supervisors/forever-start/current.json")
                    .read_text(encoding="utf-8")
                )
                path = _paths(ws.slug, current["run_id"])["state"]
                state = json.loads(path.read_text(encoding="utf-8"))
                state.update({"status": "running", "supervisor_pid": fake.pid})
                path.write_text(json.dumps(state), encoding="utf-8")
                return fake

            with patch("grypton.runtime.subprocess.Popen", side_effect=ready_state), \
                    patch("grypton.runtime.pid_matches", side_effect=matching), \
                    patch("grypton.runtime.time.sleep"):
                status = start_background(
                    ws,
                    brief="fixture",
                    backend="mock",
                    max_run_seconds=0,
                    max_turns=0,
                    stop_on_p1=False,
                    worker_model="mock/worker",
                    worker_effort="max",
                    manager_model="mock/manager",
                    manager_effort="xhigh",
                    forever=True,
                    until_severity="P2",
                    health_interval_seconds=600,
                    restart_limit=None,
                )

            self.assertEqual(status["run_mode"], "until-finding")
            self.assertEqual(status["until_severity"], "P2")
            self.assertIsNone(status["deadline_at"])
            self.assertIsNone(status["restart_limit"])
            self.assertEqual(status["restart_policy"], "unlimited-safe")
            spec = json.loads(
                _paths(ws.slug, status["run_id"])["spec"].read_text(encoding="utf-8")
            )
            self.assertTrue(spec["run_until_stopped"])
            self.assertFalse(spec["run_until_deadline"])

    def test_indefinite_engine_child_has_no_time_or_turn_ceiling(self):
        with isolated_runtime():
            ws = Workspace("forever-child")
            ws.create("example.test", "web")
            run_id = "20260924T000000Z-11111111"
            paths = _write_supervisor_fixture(ws, run_id)
            spec = json.loads(paths["spec"].read_text(encoding="utf-8"))
            spec.update({
                "backend": "mock",
                "worker_model": "mock/worker",
                "worker_effort": "max",
                "manager_model": "mock/manager",
                "manager_effort": "xhigh",
            })
            _write_json(paths["spec"], spec)

            with patch("grypton.cli.main", return_value=0) as cli_main:
                self.assertEqual(run_engine(ws.slug, run_id), 0)
            argv = cli_main.call_args.args[0]
            self.assertIn("--run-until-stopped", argv)
            self.assertIn("--until-severity", argv)
            self.assertNotIn("--max-seconds", argv)
            self.assertNotIn("--max-turns", argv)

    def test_astra_verdict_severity_and_provenance_define_completion(self):
        with isolated_runtime():
            ws = Workspace("completion-predicate")
            ws.create("example.test", "web")
            finding = ws.record_finding(title="Claimed critical", severity="P1")
            ws.set_severity_verdict(finding["id"], {
                "finding_id": finding["id"],
                "verdict": "downgrade",
                "severity": "P3",
                "validator_model": config.VALIDATOR_MODEL,
            })
            self.assertEqual(_astra_completion_count(ws.slug, "P2"), 0)

            second = ws.record_finding(title="Claimed medium", severity="P3")
            ws.set_severity_verdict(second["id"], {
                "finding_id": second["id"],
                "verdict": "upgrade",
                "severity": "P2",
                "validator_model": "not-astra",
            })
            self.assertEqual(_astra_completion_count(ws.slug, "P2"), 0)
            ws.set_severity_verdict(second["id"], {
                "finding_id": second["id"],
                "verdict": "upgrade",
                "severity": "P2",
                "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": "low",
            })
            self.assertEqual(_astra_completion_count(ws.slug, "P2"), 0)
            ws.set_severity_verdict(second["id"], {
                "finding_id": second["id"],
                "verdict": "upgrade",
                "severity": "P2",
                "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": config.VALIDATOR_EFFORT,
            })
            self.assertEqual(_astra_completion_count(ws.slug, "P2"), 1)
            self.assertEqual(_astra_completion_count(ws.slug, "P1"), 0)

    def test_premature_clean_exit_restarts_without_a_finite_budget(self):
        with isolated_runtime():
            ws = Workspace("forever-restart")
            ws.create("example.test", "web")
            run_id = "20260924T000000Z-22222222"
            _write_supervisor_fixture(ws, run_id)
            process = _Process(returncode=0)
            completion = iter((0, 0, 1))
            clock = iter(range(1000, 1100))

            with patch("grypton.runtime.subprocess.Popen", return_value=process) as popen, \
                    patch("grypton.runtime._stop_engine", return_value=True), \
                    patch("grypton.runtime._astra_completion_count",
                          side_effect=lambda *_: next(completion)), \
                    patch("grypton.runtime.time.time",
                          side_effect=lambda: float(next(clock))), \
                    patch("grypton.runtime.time.sleep"):
                self.assertEqual(supervise(ws.slug, run_id), 0)

            self.assertEqual(popen.call_count, 1)
            status = public_status(ws.slug)
            self.assertEqual(status["status"], "completed")
            self.assertEqual(status["restarts"], 1)
            self.assertIsNone(status["restart_limit"])
            self.assertIn("Astra confirmed P2", status["stop_reason"])

    def test_indefinite_abnormal_effectful_exit_still_fails_closed(self):
        with isolated_runtime():
            ws = Workspace("forever-effectful")
            ws.create("example.test", "web")
            run_id = "20260924T000000Z-33333333"
            _write_supervisor_fixture(ws, run_id)
            with patch.dict(os.environ, {_SUPERVISED_RUN_ENV: run_id}):
                _provider_call_window_begin(ws.slug, turn=1, attempt=1)
            process = _Process(returncode=7)
            after = {
                "workspace_status": "running",
                "tool_calls": 0,
                "effectful_tool_starts": 1,
            }

            with patch("grypton.runtime.subprocess.Popen", return_value=process) as popen, \
                    patch("grypton.runtime._stop_engine", return_value=True), \
                    patch("grypton.runtime._astra_completion_count", return_value=0), \
                    patch("grypton.runtime._health", return_value=after):
                self.assertEqual(supervise(ws.slug, run_id), 1)

            self.assertEqual(popen.call_count, 1)
            status = public_status(ws.slug)
            self.assertEqual(status["status"], "failed")
            self.assertIn("Kraude provider call", status["stop_reason"])

    def test_safe_abnormal_exit_uses_unlimited_restart_policy(self):
        with isolated_runtime():
            ws = Workspace("forever-safe-restart")
            ws.create("example.test", "web")
            run_id = "20260924T000000Z-44444444"
            _write_supervisor_fixture(ws, run_id)
            process = _Process(returncode=75)
            completion = iter((0, 1))
            clock = iter(range(2000, 2100))
            after = {
                "workspace_status": "failed",
                "tool_calls": 0,
                "effectful_tool_starts": 0,
            }

            with patch("grypton.runtime.subprocess.Popen", return_value=process) as popen, \
                    patch("grypton.runtime._stop_engine", return_value=True), \
                    patch("grypton.runtime._astra_completion_count",
                          side_effect=lambda *_: next(completion)), \
                    patch("grypton.runtime._health", return_value=after), \
                    patch("grypton.runtime.time.time",
                          side_effect=lambda: float(next(clock))), \
                    patch("grypton.runtime.time.sleep"):
                self.assertEqual(supervise(ws.slug, run_id), 0)

            self.assertEqual(popen.call_count, 1)
            status = public_status(ws.slug)
            self.assertEqual(status["status"], "completed")
            self.assertEqual(status["restarts"], 1)
            self.assertIsNone(status["restart_limit"])


class ContinuousEngineTests(unittest.IsolatedAsyncioTestCase):
    async def test_astra_p2_downgrade_stops_before_kryptex(self):
        with isolated_runtime(), patch.multiple(
            config.CONFIG,
            max_turns=0,
            max_run_seconds=0,
            stop_on_p1=False,
            until_severity="P2",
            passive_stagnation_limit=99,
            repetitive_probe_turn_limit=99,
            exhaustion_threshold=99,
        ):
            ws = Workspace("until-p2")
            ws.create("https://example.test", "web")
            ws.save_constraints(Constraints(in_scope=["https://example.test"]))
            engine = Engine("until-p2", backend="mock", run_until_stopped=True)
            await engine.setup(
                brief="test",
                target="https://example.test",
                target_type="web",
            )

            def worker_script(_worker, _directive):
                engine.ws.record_finding(title="Critical claim", severity="P1")
                return "Recorded candidate."

            engine.worker.script = worker_script
            engine.manager.validate_severity = AsyncMock(return_value={
                "finding_id": "F001",
                "verdict": "downgrade",
                "severity": "P2",
                "confidence": 0.97,
                "reasoning": "Astra independently confirmed P2 impact.",
                "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": config.VALIDATOR_EFFORT,
            })
            engine.manager.direct = AsyncMock(return_value=Directive(directive="unused"))

            await engine.run()

            engine.manager.direct.assert_not_awaited()
            self.assertIn("Astra-confirmed", engine.stop_reason)
            self.assertIn("P2", engine.stop_reason)

    async def test_astra_p3_downgrade_does_not_satisfy_p2_threshold(self):
        with isolated_runtime(), patch.multiple(
            config.CONFIG,
            max_turns=1,
            max_run_seconds=0,
            stop_on_p1=False,
            until_severity="P2",
            passive_stagnation_limit=99,
            repetitive_probe_turn_limit=99,
            exhaustion_threshold=99,
        ):
            ws = Workspace("until-p2-p3")
            ws.create("https://example.test", "web")
            engine = Engine("until-p2-p3", backend="mock")
            await engine.setup(
                brief="test",
                target="https://example.test",
                target_type="web",
            )

            def worker_script(_worker, _directive):
                engine.ws.record_finding(title="Critical claim", severity="P1")
                return "Recorded candidate."

            engine.worker.script = worker_script
            engine.manager.validate_severity = AsyncMock(return_value={
                "finding_id": "F001",
                "verdict": "downgrade",
                "severity": "P3",
                "confidence": 0.9,
                "reasoning": "Impact is medium.",
                "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": config.VALIDATOR_EFFORT,
            })
            engine.manager.direct = AsyncMock(return_value=Directive(
                directive="Continue with the next lead."
            ))

            await engine.run()

            engine.manager.direct.assert_awaited_once()
            self.assertEqual(engine.stop_reason, "max_turns safety ceiling reached")

    async def test_non_astra_existing_p2_is_revalidated_after_worker(self):
        with isolated_runtime(), patch.multiple(
            config.CONFIG,
            max_turns=1,
            max_run_seconds=0,
            stop_on_p1=False,
            until_severity="P2",
            passive_stagnation_limit=99,
            repetitive_probe_turn_limit=99,
            exhaustion_threshold=99,
        ):
            ws = Workspace("until-p2-provenance")
            ws.create("https://example.test", "web")
            finding = ws.record_finding(title="High claim", severity="P2")
            ws.set_severity_verdict(finding["id"], {
                "finding_id": finding["id"],
                "verdict": "confirm",
                "severity": "P2",
            })
            engine = Engine("until-p2-provenance", backend="mock")
            await engine.setup(
                brief="test",
                target="https://example.test",
                target_type="web",
            )
            calls = []
            engine.worker.script = lambda *_: calls.append("worker") or "No new candidate."
            engine.manager.validate_severity = AsyncMock(
                wraps=engine.manager.validate_severity
            )
            engine.manager.direct = AsyncMock(return_value=Directive(
                directive="Continue with the next lead."
            ))

            await engine.run()

            self.assertEqual(calls, ["worker"])
            engine.manager.validate_severity.assert_awaited_once()
            engine.manager.direct.assert_not_awaited()
            self.assertIn("Astra-confirmed", engine.stop_reason)

    def test_indefinite_engine_ignores_manager_completion_requests(self):
        with isolated_runtime():
            ws = Workspace("until-p2-manager")
            ws.create("https://example.test", "web")
            engine = Engine("until-p2-manager", backend="mock", run_until_stopped=True)
            directive = SimpleNamespace(
                stop_reason="The recorded target is outside scope.",
            )
            self.assertFalse(engine._manager_stop_is_binding(directive))


if __name__ == "__main__":
    unittest.main()
