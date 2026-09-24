from __future__ import annotations

import asyncio
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import fcntl
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from grypton import config
from grypton.cli import (_duration_seconds, _run_engagement,
                         _run_engagement_unlocked, build_parser, cmd_run_stop)
from grypton.engine import Engine
from grypton.worker import TurnResult, WorkerError
from grypton.runtime import (
    _ProcessIdentity,
    _ProcessSnapshot,
    _SUPERVISED_RUN_ENV,
    _advance_health_deadline,
    _descendant_pgids,
    _engine_argv,
    _paths,
    _provider_call_window_active,
    _provider_call_window_begin,
    _provider_call_window_complete,
    _process_snapshot,
    _safe_error,
    _signal_process_groups,
    engine_lock_is_available,
    engine_lock_path,
    _stop_engine,
    _write_json,
    public_status,
    request_background_stop,
    run_engine,
    start_background,
    supervise,
)
from grypton.workspace import Workspace


@contextmanager
def runtime_home():
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
            "TARGET_DATA_DIR": root / "target",
        }
        with patch.multiple(config, **values):
            config.ensure_layout()
            yield root


class _Process:
    def __init__(self, pid: int = 42420, returncode: int | None = None):
        self.pid = pid
        self.returncode = returncode

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return 0 if self.returncode is None else self.returncode

    def terminate(self):
        self.returncode = -signal.SIGTERM


class _HungProcess:
    pid = 44550

    def __init__(self):
        self.waits = 0

    def poll(self):
        return None

    def wait(self, timeout=None):
        self.waits += 1
        if self.waits < 3:
            raise subprocess.TimeoutExpired("engine", timeout)
        return -signal.SIGKILL

    def send_signal(self, _sig):
        pass


class RuntimeTests(unittest.TestCase):
    def test_health_deadline_stays_anchored_and_skips_missed_slots(self):
        # The first health check is immediate; completing it at t=100 anchors
        # the ten-minute cadence at 700, 1300, 1900, and so on.
        scheduled = _advance_health_deadline(0, 100, 600)
        self.assertEqual(scheduled, 700)

        # A checkpoint delayed by load to t=840 advances from its scheduled
        # slot (700), rather than drifting ten minutes from the late check.
        scheduled = _advance_health_deadline(scheduled, 840, 600)
        self.assertEqual(scheduled, 1300)

        # Longer stalls skip every missed slot in one step and always leave a
        # deadline strictly in the future.
        scheduled = _advance_health_deadline(scheduled, 2600, 600)
        self.assertEqual(scheduled, 3100)
        self.assertGreater(scheduled, 2600)

    def test_duration_and_run_commands_parse(self):
        self.assertEqual(_duration_seconds("12h"), 43_200)
        self.assertEqual(_duration_seconds("10m"), 600)
        with self.assertRaisesRegex(Exception, "too large"):
            _duration_seconds("9" * 400 + "h")
        parser = build_parser()
        start = parser.parse_args(["run", "start", "saved", "--duration", "12h",
                                   "--health-interval", "10m"])
        self.assertEqual(start.duration_seconds, 43_200)
        self.assertEqual(start.health_interval, 600)
        for name in ("status", "stop", "logs"):
            self.assertEqual(parser.parse_args(["run", name, "saved"]).run_command, name)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["run", "start", "saved", "-p"])

    def test_common_engine_lock_blocks_overlap_and_resume_clears_stale_stop(self):
        with runtime_home():
            ws = Workspace("engine-exclusive")
            ws.create("example.test", "web")
            lock_path = engine_lock_path(ws)
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with patch("grypton.cli._run_engagement_unlocked") as launched, \
                        redirect_stderr(io.StringIO()):
                    self.assertEqual(_run_engagement(
                        ws, SimpleNamespace(background=False), brief="", fresh=False
                    ), 2)
                launched.assert_not_called()
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

            stop = ws.root / ".ledger/STOP"
            stop.write_text("stale\n", encoding="utf-8")
            with patch("grypton.cli._run_engagement_unlocked", return_value=17) as launched:
                self.assertEqual(_run_engagement(
                    ws, SimpleNamespace(background=False), brief="resume", fresh=False
                ), 17)
            launched.assert_called_once()
            self.assertFalse(stop.exists())

    def test_supervisor_only_stop_does_not_poison_next_foreground_resume(self):
        with runtime_home():
            ws = Workspace("no-live-supervisor")
            ws.create("example.test", "web")
            with patch("grypton.runtime.request_background_stop", return_value=False), \
                    redirect_stderr(io.StringIO()):
                self.assertEqual(cmd_run_stop(SimpleNamespace(target=ws.slug)), 2)
            self.assertFalse((ws.root / ".ledger/STOP").exists())

    def test_live_supervisor_reserves_engagement_before_engine_child_locks(self):
        with runtime_home():
            ws = Workspace("supervisor-reservation")
            ws.create("example.test", "web")
            with patch("grypton.runtime.public_status", return_value={"alive": True}), \
                    patch("grypton.cli._run_engagement_unlocked") as launched, \
                    redirect_stderr(io.StringIO()):
                self.assertEqual(_run_engagement(
                    ws, SimpleNamespace(background=False), brief="", fresh=False
                ), 2)
            launched.assert_not_called()

    def test_engine_run_always_tears_down_after_failure(self):
        class Harness:
            def __init__(self):
                self.torn_down = False

            async def _run_loop(self):
                raise RuntimeError("synthetic loop failure")

            async def _teardown(self, *, status="stopped"):
                self.torn_down = True
                self.teardown_status = status

        harness = Harness()
        with self.assertRaisesRegex(RuntimeError, "synthetic loop failure"):
            asyncio.run(Engine.run(harness))
        self.assertTrue(harness.torn_down)
        self.assertEqual(harness.teardown_status, "failed")

    def test_partial_provider_setup_failure_is_torn_down(self):
        instances = []

        class FailingEngine:
            def __init__(self, *args, **kwargs):
                self.teardown_status = None
                instances.append(self)

            def current_models(self):
                return {
                    "kraude": {"route": config.WORKER_MODEL, "effort": "max"},
                    "kryptex": {"route": config.MANAGER_MODEL, "effort": "xhigh"},
                    "validator": {"route": config.VALIDATOR_MODEL, "effort": "max"},
                }

            def request_stop(self, reason):
                return None

            async def setup(self, **kwargs):
                raise RuntimeError("synthetic partial setup failure")

            async def _teardown(self, *, status="stopped"):
                self.teardown_status = status

        with runtime_home():
            ws = Workspace("setup-cleanup")
            ws.create("example.test", "web")
            ns = build_parser().parse_args([
                "resume", ws.slug, "--backend", "mock", "-p", "--console", "quiet",
            ])
            with patch("grypton.engine.Engine", FailingEngine), \
                    patch("grypton.chat.print_console_header"), \
                    redirect_stdout(io.StringIO()), \
                    patch.object(config.CONFIG, "backend", "real"):
                with self.assertRaisesRegex(RuntimeError, "partial setup"):
                    _run_engagement_unlocked(ws, ns, brief="smoke", fresh=False)
        self.assertEqual(len(instances), 1)
        self.assertEqual(instances[0].teardown_status, "failed")

    def test_teardown_closes_providers_even_when_metadata_write_fails(self):
        with runtime_home():
            ws = Workspace("teardown-order")
            ws.create("example.test", "web")
            engine = Engine(ws.slug, backend="mock")
            engine.worker = type("Worker", (), {
                "session_id": "", "aclose": AsyncMock(),
            })()
            engine.manager = type("Manager", (), {
                "session_id": "", "aclose": AsyncMock(),
            })()
            with patch.object(engine.ws, "update_meta", side_effect=OSError("fixture")):
                asyncio.run(engine._teardown(status="failed"))
                asyncio.run(engine._teardown(status="stopped"))
            engine.worker.aclose.assert_awaited_once()
            engine.manager.aclose.assert_awaited_once()

    def test_start_keeps_brief_out_of_argv_status_and_events(self):
        with runtime_home():
            ws = Workspace("private-run")
            ws.create("example.test", "web")
            secret = "mission password=never-print-this"
            fake = _Process(returncode=None)

            def matching(pid, role, slug, run_id):
                return role == "supervise" and pid == fake.pid

            with patch("grypton.runtime.subprocess.Popen", return_value=fake) as popen, \
                    patch("grypton.runtime.pid_matches", side_effect=matching), \
                    patch("grypton.runtime.time.sleep"):
                # Model the child's readiness update without starting providers.
                def ready_state(*args, **kwargs):
                    run_id = json.loads((config.RUNTIME_DIR / "supervisors/private-run/current.json")
                                        .read_text())["run_id"]
                    path = _paths("private-run", run_id)["state"]
                    state = json.loads(path.read_text())
                    state.update({"status": "running", "supervisor_pid": fake.pid})
                    path.write_text(json.dumps(state), encoding="utf-8")
                    return fake

                popen.side_effect = ready_state
                state = start_background(
                    ws, brief=secret, backend="mock", max_run_seconds=43_200,
                    max_turns=0, stop_on_p1=False,
                    worker_model="mock/worker", worker_effort="max",
                    manager_model="mock/manager", manager_effort="xhigh",
                    health_interval_seconds=600, restart_limit=2,
                )

            argv = popen.call_args.args[0]
            self.assertNotIn(secret, " ".join(argv))
            self.assertNotIn(secret, json.dumps(state))
            run_id = state["run_id"]
            paths = _paths(ws.slug, run_id)
            self.assertEqual(paths["spec"].stat().st_mode & 0o777, 0o600)
            self.assertEqual(paths["state"].stat().st_mode & 0o777, 0o600)
            for directory in (paths["root"], paths["root"].parent,
                              paths["root"].parent.parent):
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertIn(secret, paths["spec"].read_text())
            self.assertNotIn(secret, paths["events"].read_text())
            self.assertNotIn("brief", json.dumps(public_status(ws.slug)).lower())
            spec = json.loads(paths["spec"].read_text(encoding="utf-8"))
            self.assertTrue(spec["run_until_deadline"])

    def test_engine_child_receives_private_deadline_mode(self):
        with runtime_home():
            ws = Workspace("deadline-child")
            ws.create("example.test", "web")
            run_id = "20260923T000000Z-00000009"
            paths = _paths(ws.slug, run_id)
            _write_json(paths["spec"], {
                "slug": ws.slug,
                "run_id": run_id,
                "deadline_at": time.time() + 60,
                "backend": "mock",
                "worker_model": "mock/worker",
                "worker_effort": "max",
                "manager_model": "mock/manager",
                "manager_effort": "xhigh",
                "run_until_deadline": True,
            })
            with patch("grypton.cli.main", return_value=0) as cli_main:
                self.assertEqual(run_engine(ws.slug, run_id), 0)
            self.assertIn("--run-until-deadline", cli_main.call_args.args[0])

    def test_restarted_engine_does_not_replay_original_brief(self):
        with runtime_home():
            ws = Workspace("restart-brief")
            ws.create("example.test", "web")
            ws.update_meta(
                turn_index=1,
                last_directive="resume with a fresh recorded lead",
            )
            run_id = "20260923T000000Z-00000020"
            paths = _paths(ws.slug, run_id)
            _write_json(paths["spec"], {
                "slug": ws.slug,
                "run_id": run_id,
                "deadline_at": time.time() + 60,
                "backend": "mock",
                "brief": "one-time login mission",
                "starting_turn_index": 0,
            })

            with patch("grypton.cli.main", return_value=0) as cli_main:
                self.assertEqual(run_engine(ws.slug, run_id), 0)

            argv = cli_main.call_args.args[0]
            self.assertNotIn("--brief", argv)
            self.assertNotIn("one-time login mission", argv)

            ws.update_meta(turn_index=0)
            with patch("grypton.cli.main", return_value=0) as first_cli:
                self.assertEqual(run_engine(ws.slug, run_id), 0)
            first_argv = first_cli.call_args.args[0]
            brief_index = first_argv.index("--brief")
            self.assertEqual(first_argv[brief_index + 1], "one-time login mission")

    def test_legacy_supervisor_restart_does_not_replay_original_brief(self):
        with runtime_home():
            ws = Workspace("legacy-restart-brief")
            ws.create("example.test", "web")
            run_id = "20260923T000000Z-00000022"
            paths = _paths(ws.slug, run_id)
            _write_json(paths["spec"], {
                "slug": ws.slug,
                "run_id": run_id,
                "deadline_at": time.time() + 60,
                "backend": "mock",
                "brief": "legacy one-time login mission",
            })
            _write_json(paths["state"], {
                "slug": ws.slug,
                "run_id": run_id,
                "restarts": 1,
            })

            with patch("grypton.cli.main", return_value=0) as cli_main:
                self.assertEqual(run_engine(ws.slug, run_id), 0)

            argv = cli_main.call_args.args[0]
            self.assertNotIn("--brief", argv)
            self.assertNotIn("legacy one-time login mission", argv)

    def test_background_start_rejects_held_foreground_engine_lock(self):
        with runtime_home():
            ws = Workspace("foreground-active")
            ws.create("example.test", "web")
            lock_path = engine_lock_path(ws)
            flags = os.O_CREAT | os.O_RDWR
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(lock_path, flags, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertFalse(engine_lock_is_available(ws))
                with patch("grypton.runtime.subprocess.Popen") as popen,                         self.assertRaisesRegex(RuntimeError, "engine is already running"):
                    start_background(
                        ws, brief="fixture", backend="mock",
                        max_run_seconds=60, max_turns=1, stop_on_p1=False,
                        worker_model="mock/worker", worker_effort="max",
                        manager_model="mock/manager", manager_effort="xhigh",
                        health_interval_seconds=5, restart_limit=1,
                    )
                popen.assert_not_called()
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            self.assertTrue(engine_lock_is_available(ws))

    def test_stop_refuses_unverified_pid(self):
        with runtime_home():
            ws = Workspace("wrong-pid")
            ws.create("example.test", "web")
            run_id = "20260923T000000Z-00000001"
            paths = _paths(ws.slug, run_id)
            _write_json(paths["state"], {"supervisor_pid": 77, "status": "running"})
            _write_json(config.RUNTIME_DIR / "supervisors/wrong-pid/current.json",
                        {"run_id": run_id})
            with patch("grypton.runtime.pid_matches", return_value=False), \
                    patch("grypton.runtime.os.kill") as kill:
                self.assertFalse(request_background_stop(ws.slug))
                kill.assert_not_called()

    def test_process_snapshot_handles_non_ascii_and_closing_parenthesis_in_comm(self):
        fields = [
            b"S", b"41", b"42001", b"42001", b"0", b"-1", b"4194304",
            b"0", b"0", b"0", b"0", b"0", b"0", b"0", b"0", b"20",
            b"0", b"1", b"0", b"777",
        ]
        record = (b"42001 (provider-" + bytes([0xff]) + b")worker) "
                  + b" ".join(fields) + bytes([10]))
        with patch("grypton.runtime.Path.read_bytes", return_value=record):
            snapshot = _process_snapshot(42001)

        self.assertEqual(
            snapshot,
            _ProcessSnapshot(
                identity=_ProcessIdentity(42001, "777", 42001),
                ppid=41,
            ),
        )

    def test_descendant_snapshot_drops_chain_through_reused_pid(self):
        root = _ProcessSnapshot(
            identity=_ProcessIdentity(51000, "100", 51000),
            ppid=1,
        )
        original_parent = _ProcessSnapshot(
            identity=_ProcessIdentity(51001, "200", 51001),
            ppid=51000,
        )
        reused_parent = _ProcessSnapshot(
            identity=_ProcessIdentity(51001, "201", 61001),
            ppid=999,
        )
        unrelated_child = _ProcessSnapshot(
            identity=_ProcessIdentity(51002, "300", 61002),
            ppid=51001,
        )
        entries = [Path(f"/proc/{pid}") for pid in (51000, 51001, 51002)]
        calls: dict[int, int] = {}

        def snapshot(pid):
            calls[pid] = calls.get(pid, 0) + 1
            if pid == 51000:
                return root
            if pid == 51001:
                return original_parent if calls[pid] == 1 else reused_parent
            if pid == 51002:
                return unrelated_child
            return None

        with patch("grypton.runtime.Path.iterdir", return_value=entries), \
                patch("grypton.runtime._process_snapshot", side_effect=snapshot), \
                patch("grypton.runtime.os.getpgrp", return_value=51000):
            groups = _descendant_pgids(51000)

        self.assertEqual(groups, {})
        self.assertNotIn(unrelated_child.identity, {
            identity for identities in groups.values() for identity in identities
        })

    def test_missing_pidfd_support_fails_closed_without_numeric_signal(self):
        recorded = _ProcessIdentity(45554, "200", 45554)
        with patch.object(signal, "pidfd_send_signal", None, create=True), \
                patch.object(os, "pidfd_open", create=True) as pidfd_open, \
                patch("grypton.runtime.os.kill") as kill, \
                patch("grypton.runtime.os.killpg") as killpg:
            _signal_process_groups(
                {recorded.pgid: {recorded}},
                signal.SIGTERM,
            )

        pidfd_open.assert_not_called()
        kill.assert_not_called()
        killpg.assert_not_called()

    def test_forced_stop_routes_observed_provider_identities_through_safe_signal(self):
        process = _HungProcess()
        engine = _ProcessIdentity(process.pid, "100", process.pid)
        provider = _ProcessIdentity(45551, "200", 45551)
        snapshot = {
            process.pid: {engine},
            provider.pgid: {provider},
        }
        with patch("grypton.runtime._descendant_pgids", return_value=snapshot), \
                patch("grypton.runtime._signal_process_groups") as safe_signal, \
                patch("grypton.runtime.os.killpg"):
            _stop_engine(process)
        self.assertEqual(process.waits, 3)
        self.assertTrue(any(
            provider in call.args[0].get(provider.pgid, set())
            for call in safe_signal.call_args_list
        ))
        self.assertTrue(any(
            call.args[1] == signal.SIGKILL
            for call in safe_signal.call_args_list
        ))

    def test_already_exited_engine_still_reaps_verified_provider_identity(self):
        process = _Process(pid=43429, returncode=7)
        provider = _ProcessIdentity(45552, "200", 45552)
        known = {provider.pgid: {provider}}

        def current_identity(pid):
            return provider if pid == provider.pid else None

        with patch("grypton.runtime._descendant_pgids") as descendants, \
                patch("grypton.runtime._process_identity", side_effect=current_identity), \
                patch("grypton.runtime._group_members", return_value={provider}), \
                patch("grypton.runtime.time.sleep"), \
                patch.object(os, "pidfd_open", return_value=987654, create=True), \
                patch.object(signal, "pidfd_send_signal", create=True) as send_signal, \
                patch("grypton.runtime.os.close"), \
                patch("grypton.runtime.os.killpg") as killpg:
            _stop_engine(process, known)

        descendants.assert_not_called()
        killpg.assert_not_called()
        delivered = [call.args[1] for call in send_signal.call_args_list]
        self.assertIn(signal.SIGTERM, delivered)
        self.assertIn(signal.SIGKILL, delivered)

    def test_reused_group_identity_is_never_signaled(self):
        recorded = _ProcessIdentity(45553, "200", 45553)
        reused = _ProcessIdentity(45553, "201", 45553)
        identities = iter((recorded, reused))

        with patch("grypton.runtime._process_identity",
                   side_effect=lambda _pid: next(identities, reused)), \
                patch.object(os, "pidfd_open", return_value=987655, create=True), \
                patch.object(signal, "pidfd_send_signal", create=True) as send_signal, \
                patch("grypton.runtime.os.close") as close, \
                patch("grypton.runtime.os.killpg") as killpg:
            _signal_process_groups({recorded.pgid: {recorded}}, signal.SIGTERM)

        close.assert_called_once_with(987655)
        send_signal.assert_not_called()
        killpg.assert_not_called()

    def test_clean_engine_exit_is_never_restarted(self):
        with runtime_home():
            ws = Workspace("clean-exit")
            ws.create("example.test", "web")
            run_id = "20260923T000000Z-00000002"
            paths = _paths(ws.slug, run_id)
            _write_json(paths["spec"], {
                "slug": ws.slug, "run_id": run_id, "deadline_at": time.time() + 60,
                "health_interval_seconds": 600, "restart_limit": 5,
            })
            _write_json(paths["state"], {"slug": ws.slug, "run_id": run_id,
                                         "status": "starting", "restarts": 0})
            _write_json(config.RUNTIME_DIR / "supervisors/clean-exit/current.json",
                        {"run_id": run_id})
            process = _Process(pid=43430, returncode=0)
            with patch("grypton.runtime.subprocess.Popen", return_value=process) as popen:
                self.assertEqual(supervise(ws.slug, run_id), 0)
            self.assertEqual(popen.call_count, 1)
            self.assertEqual(public_status(ws.slug)["status"], "completed")

    def test_abnormal_exit_after_completed_effectful_turn_is_restarted(self):
        with runtime_home():
            ws = Workspace("no-replay")
            ws.create("example.test", "web")
            run_id = "20260923T000000Z-00000003"
            paths = _paths(ws.slug, run_id)
            _write_json(paths["spec"], {
                "slug": ws.slug,
                "run_id": run_id,
                "deadline_at": time.time() + 60,
                "health_interval_seconds": 600,
                "restart_limit": 5,
            })
            _write_json(paths["state"], {
                "slug": ws.slug, "run_id": run_id, "status": "starting", "restarts": 0,
            })
            _write_json(config.RUNTIME_DIR / "supervisors/no-replay/current.json",
                        {"run_id": run_id})
            processes = [
                _Process(pid=44660, returncode=7),
                _Process(pid=44661, returncode=0),
            ]
            # A cumulative effect count can describe already-completed work.
            # With no active provider window, the durable resume cursor makes
            # this abnormal exit safe to restart.
            after = {
                "workspace_status": "running",
                "tool_calls": 0,
                "effectful_tool_starts": 1,
            }
            with patch("grypton.runtime.subprocess.Popen", side_effect=processes) as popen, \
                    patch("grypton.runtime._health", return_value=after), \
                    patch("grypton.runtime.time.sleep"):
                self.assertEqual(supervise(ws.slug, run_id), 0)
            self.assertEqual(popen.call_count, 2)
            state = public_status(ws.slug)
            self.assertEqual(state["status"], "completed")
            self.assertEqual(state["restarts"], 1)

    def test_abnormal_exit_with_active_native_provider_window_is_not_restarted(self):
        with runtime_home():
            ws = Workspace("native-no-replay")
            ws.create("example.test", "web")
            run_id = "20260923T000000Z-00000013"
            paths = _paths(ws.slug, run_id)
            _write_json(paths["spec"], {
                "slug": ws.slug,
                "run_id": run_id,
                "deadline_at": time.time() + 60,
                "health_interval_seconds": 600,
                "restart_limit": 5,
            })
            _write_json(paths["state"], {
                "slug": ws.slug, "run_id": run_id,
                "status": "starting", "restarts": 0,
            })
            _write_json(
                config.RUNTIME_DIR / "supervisors/native-no-replay/current.json",
                {"run_id": run_id},
            )
            with patch.dict(os.environ, {_SUPERVISED_RUN_ENV: run_id}):
                nonce = _provider_call_window_begin(ws.slug, turn=3, attempt=1)
            self.assertTrue(nonce)
            self.assertTrue(_provider_call_window_active(ws.slug, run_id))

            process = _Process(pid=44665, returncode=7)
            after = {
                "workspace_status": "running",
                "tool_calls": 0,
                "effectful_tool_starts": 0,
            }
            with patch("grypton.runtime.subprocess.Popen", return_value=process) as popen, \
                    patch("grypton.runtime._health", return_value=after):
                self.assertEqual(supervise(ws.slug, run_id), 1)

            self.assertEqual(popen.call_count, 1)
            state = public_status(ws.slug)
            self.assertEqual(state["status"], "failed")
            self.assertIn("Kraude provider call", state["stop_reason"])
            events = [
                json.loads(line)
                for line in paths["events"].read_text(encoding="utf-8").splitlines()
            ]
            suppressed = [row for row in events if row["event"] == "restart_suppressed"]
            self.assertEqual(suppressed[-1]["reason"], "worker_provider_call_active")
            self.assertNotIn("nonce", suppressed[-1])

    def test_real_worker_crash_leaves_window_active_until_turn_persistence(self):
        class NativeProviderCrash(BaseException):
            pass

        with runtime_home():
            ws = Workspace("native-window-crash")
            ws.create("example.test", "web")
            run_id = "20260923T000000Z-00000014"
            paths = _paths(ws.slug, run_id)
            _write_json(paths["spec"], {
                "slug": ws.slug,
                "run_id": run_id,
                "deadline_at": time.time() + 60,
            })
            engine = Engine(ws.slug, backend="real")
            engine.worker = SimpleNamespace(session_id="", aclose=AsyncMock())
            engine.manager = SimpleNamespace(session_id="", aclose=AsyncMock())
            engine._opening_directive = AsyncMock(return_value="exercise native tool")
            engine._apply_pending_model_switches = AsyncMock()
            engine._user_chat_loop = AsyncMock(return_value=None)
            observed = []

            async def crash_during_provider(_directive):
                observed.append(_provider_call_window_active(ws.slug, run_id))
                raise NativeProviderCrash("synthetic crash after native tool")

            engine._run_turn_with_heartbeat = crash_during_provider
            with patch.dict(os.environ, {_SUPERVISED_RUN_ENV: run_id}):
                with self.assertRaises(NativeProviderCrash):
                    asyncio.run(engine.run())

            self.assertEqual(observed, [True])
            self.assertTrue(_provider_call_window_active(ws.slug, run_id))
            self.assertEqual(ws.load_meta().turn_index, 0)

    def test_matching_completed_provider_window_is_removed(self):
        with runtime_home():
            ws = Workspace("native-window-complete")
            ws.create("example.test", "web")
            run_id = "20260923T000000Z-00000015"
            paths = _paths(ws.slug, run_id)
            _write_json(paths["spec"], {
                "slug": ws.slug,
                "run_id": run_id,
                "deadline_at": time.time() + 60,
            })
            with patch.dict(os.environ, {_SUPERVISED_RUN_ENV: run_id}):
                nonce = _provider_call_window_begin(ws.slug, turn=1, attempt=1)
                self.assertTrue(_provider_call_window_active(ws.slug, run_id))
                _provider_call_window_complete(ws.slug, nonce)
            self.assertFalse(_provider_call_window_active(ws.slug, run_id))

    def test_missing_provider_window_is_recreated_before_completion_fails(self):
        with runtime_home():
            ws = Workspace("native-window-missing")
            ws.create("example.test", "web")
            run_id = "20260923T000000Z-00000017"
            paths = _paths(ws.slug, run_id)
            _write_json(paths["spec"], {
                "slug": ws.slug,
                "run_id": run_id,
                "deadline_at": time.time() + 60,
            })
            with patch.dict(os.environ, {_SUPERVISED_RUN_ENV: run_id}):
                nonce = _provider_call_window_begin(ws.slug, turn=1, attempt=1)
                paths["provider_call_window"].unlink()
                with self.assertRaisesRegex(RuntimeError, "changed"):
                    _provider_call_window_complete(ws.slug, nonce)

            self.assertTrue(_provider_call_window_active(ws.slug, run_id))
            recovered = json.loads(
                paths["provider_call_window"].read_text(encoding="utf-8")
            )
            self.assertTrue(recovered["recovered_missing_marker"])

    def test_engine_reuses_window_across_retries_and_begin_never_overwrites(self):
        with runtime_home():
            ws = Workspace("native-window-retry")
            ws.create("example.test", "web")
            run_id = "20260923T000000Z-00000018"
            paths = _paths(ws.slug, run_id)
            _write_json(paths["spec"], {
                "slug": ws.slug,
                "run_id": run_id,
                "deadline_at": time.time() + 60,
            })
            engine = Engine(ws.slug, backend="real")
            with patch.dict(os.environ, {_SUPERVISED_RUN_ENV: run_id}):
                first = engine._begin_worker_provider_window(turn=1, attempt=1)
                second = engine._begin_worker_provider_window(turn=1, attempt=2)
                self.assertEqual(first, second)
                with self.assertRaisesRegex(RuntimeError, "still active"):
                    _provider_call_window_begin(ws.slug, turn=1, attempt=3)

            marker = json.loads(
                paths["provider_call_window"].read_text(encoding="utf-8")
            )
            self.assertEqual(marker["nonce"], first)
            self.assertEqual(marker["attempt"], 1)

    def test_explicit_replay_safe_failure_releases_window_before_retry(self):
        with runtime_home():
            ws = Workspace("native-window-safe-retry")
            ws.create("example.test", "web")
            run_id = "20260923T000000Z-00000019"
            paths = _paths(ws.slug, run_id)
            _write_json(paths["spec"], {
                "slug": ws.slug,
                "run_id": run_id,
                "deadline_at": time.time() + 60,
            })
            engine = Engine(ws.slug, backend="real")
            with patch.dict(os.environ, {_SUPERVISED_RUN_ENV: run_id}):
                first = engine._begin_worker_provider_window(turn=1, attempt=1)
                engine._release_replay_safe_worker_provider_window(first)
                self.assertFalse(_provider_call_window_active(ws.slug, run_id))
                second = engine._begin_worker_provider_window(turn=1, attempt=2)

            self.assertNotEqual(first, second)
            self.assertTrue(_provider_call_window_active(ws.slug, run_id))

            # A later pre-tool failure cannot erase uncertainty from an earlier
            # attempt covered by the same provider window.
            engine._worker_provider_window_tainted = True
            with patch.dict(os.environ, {_SUPERVISED_RUN_ENV: run_id}):
                self.assertFalse(
                    engine._release_replay_safe_worker_provider_window(second)
                )
            self.assertTrue(_provider_call_window_active(ws.slug, run_id))

    def test_real_loop_releases_replay_safe_window_during_backoff(self):
        with runtime_home(), patch.multiple(
            config.CONFIG,
            max_turns=1,
            max_run_seconds=0,
            exhaustion_threshold=99,
            passive_stagnation_limit=99,
            repetitive_probe_turn_limit=99,
        ):
            ws = Workspace("native-window-safe-loop")
            ws.create("example.test", "web")
            run_id = "20260923T000000Z-00000021"
            paths = _paths(ws.slug, run_id)
            _write_json(paths["spec"], {
                "slug": ws.slug,
                "run_id": run_id,
                "deadline_at": time.time() + 60,
            })
            engine = Engine(ws.slug, backend="real", run_until_stopped=True)
            engine.worker = SimpleNamespace(
                session_id="worker-session",
                ensure_started=AsyncMock(),
                aclose=AsyncMock(),
            )
            engine.manager = SimpleNamespace(session_id="", aclose=AsyncMock())
            engine._opening_directive = AsyncMock(return_value="exercise native tool")
            engine._apply_pending_model_switches = AsyncMock()
            engine._user_chat_loop = AsyncMock(return_value=None)
            active_during_provider = []

            async def provider(_directive):
                active_during_provider.append(
                    _provider_call_window_active(ws.slug, run_id)
                )
                if len(active_during_provider) == 1:
                    raise WorkerError(
                        "provider failed before tools",
                        metadata={"tool_count": 0, "replay_safe": True},
                    )
                return TurnResult(
                    assistant_text="completed",
                    tool_uses=[{"name": "bash"}],
                    result={},
                )

            async def wait_for_retry(_seconds):
                self.assertFalse(
                    _provider_call_window_active(ws.slug, run_id)
                )
                return True

            engine._run_turn_with_heartbeat = provider
            engine._wait_for_worker_retry = wait_for_retry
            persist_turn = engine._persist_turn

            def persist_then_stop(turn):
                persist_turn(turn)
                engine.stop_requested = True

            engine._persist_turn = persist_then_stop
            with patch.dict(os.environ, {_SUPERVISED_RUN_ENV: run_id}):
                asyncio.run(engine.run())

            self.assertEqual(active_during_provider, [True, True])
            self.assertFalse(_provider_call_window_active(ws.slug, run_id))

    def test_successful_real_turn_clears_window_after_turn_and_resume_state(self):
        with runtime_home():
            ws = Workspace("native-window-persisted")
            ws.create("example.test", "web")
            run_id = "20260923T000000Z-00000016"
            paths = _paths(ws.slug, run_id)
            _write_json(paths["spec"], {
                "slug": ws.slug,
                "run_id": run_id,
                "deadline_at": time.time() + 60,
            })
            engine = Engine(ws.slug, backend="real")
            engine.worker = SimpleNamespace(
                session_id="worker-completed-session",
                aclose=AsyncMock(),
            )
            engine.manager = SimpleNamespace(session_id="", aclose=AsyncMock())
            engine._opening_directive = AsyncMock(return_value="exercise native tool")
            engine._apply_pending_model_switches = AsyncMock()
            engine._user_chat_loop = AsyncMock(return_value=None)
            checkpoints = []

            async def completed_provider(_directive):
                checkpoints.append((
                    "provider",
                    _provider_call_window_active(ws.slug, run_id),
                ))
                return TurnResult(
                    assistant_text="completed",
                    tool_uses=[{"name": "bash"}],
                    result={},
                )

            engine._run_turn_with_heartbeat = completed_provider
            persist_turn = engine._persist_turn

            def persist_then_stop(turn):
                checkpoints.append((
                    "persist",
                    _provider_call_window_active(ws.slug, run_id),
                ))
                persist_turn(turn)
                engine.stop_requested = True

            engine._persist_turn = persist_then_stop
            complete_window = engine._complete_worker_provider_window

            def complete_after_checkpoint(nonce):
                meta = ws.load_meta()
                checkpoints.append((
                    "complete",
                    _provider_call_window_active(ws.slug, run_id),
                ))
                self.assertEqual(meta.turn_index, 1)
                self.assertEqual(meta.family_stagnation_streak, 1)
                self.assertNotEqual(meta.last_directive, "exercise native tool")
                complete_window(nonce)

            engine._complete_worker_provider_window = complete_after_checkpoint
            with patch.dict(os.environ, {_SUPERVISED_RUN_ENV: run_id}):
                asyncio.run(engine.run())

            self.assertEqual(checkpoints, [
                ("provider", True),
                ("persist", True),
                ("complete", True),
            ])
            self.assertFalse(_provider_call_window_active(ws.slug, run_id))
            meta = ws.load_meta()
            self.assertEqual(meta.turn_index, 1)
            self.assertEqual(meta.family_stagnation_streak, 1)
            self.assertNotEqual(meta.last_directive, "exercise native tool")
            self.assertIn("highest-impact unresolved lead", meta.last_directive)
            turns = (ws.transcripts_dir / "turns.jsonl").read_text(encoding="utf-8")
            self.assertIn('"turn": 1', turns)

    def test_abnormal_pre_tool_failure_is_restarted(self):
        with runtime_home():
            ws = Workspace("retry-safe")
            ws.create("example.test", "web")
            run_id = "20260923T000000Z-00000004"
            paths = _paths(ws.slug, run_id)
            _write_json(paths["spec"], {
                "slug": ws.slug,
                "run_id": run_id,
                "deadline_at": time.time() + 60,
                "health_interval_seconds": 600,
                "restart_limit": 1,
            })
            _write_json(paths["state"], {
                "slug": ws.slug, "run_id": run_id, "status": "starting", "restarts": 0,
            })
            _write_json(config.RUNTIME_DIR / "supervisors/retry-safe/current.json",
                        {"run_id": run_id})
            processes = [
                _Process(pid=44670, returncode=7),
                _Process(pid=44671, returncode=0),
            ]
            # Completed private read-only calls are observable but do not make
            # an otherwise pre-external crash unsafe to retry.
            after = {
                "workspace_status": "failed",
                "tool_calls": 2,
                "effectful_tool_starts": 0,
            }
            with patch("grypton.runtime.subprocess.Popen", side_effect=processes) as popen,                     patch("grypton.runtime._health", return_value=after),                     patch("grypton.runtime.time.sleep"):
                self.assertEqual(supervise(ws.slug, run_id), 0)
            self.assertEqual(popen.call_count, 2)
            state = public_status(ws.slug)
            self.assertEqual(state["status"], "completed")
            self.assertEqual(state["restarts"], 1)

    def test_corrupt_current_run_id_cannot_escape_runtime_directory(self):
        with runtime_home():
            ws = Workspace("corrupt-pointer")
            ws.create("example.test", "web")
            _write_json(config.RUNTIME_DIR / "supervisors/corrupt-pointer/current.json",
                        {"run_id": "../../escape"})
            self.assertEqual(public_status(ws.slug)["status"], "not-started")
            self.assertFalse(request_background_stop(ws.slug))

    def test_error_event_text_redacts_brief_and_credentials(self):
        message = _safe_error(
            RuntimeError("mission password=hunter2 token=abc 15555550123"),
            {"brief": "mission"},
        )
        self.assertNotIn("mission", message)
        self.assertNotIn("hunter2", message)
        self.assertNotIn("abc", message)
        self.assertNotIn("15555550123", message)
        run_id = "20260923T000000Z-00000005"
        self.assertNotIn("private words", " ".join(_engine_argv("slug", run_id)))


if __name__ == "__main__":
    unittest.main()
