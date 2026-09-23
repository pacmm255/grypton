from __future__ import annotations

import asyncio
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
from unittest.mock import patch
import unittest

from grypton import config, prompts
from grypton.cli import build_parser
from grypton.engine import Engine
from grypton.runtime import _engine_argv, _paths, _write_json, public_status, run_engine, start_background
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


class _FakeWorker:
    instances: list["_FakeWorker"] = []

    def __init__(self, spec, on_event=None):
        self.spec = spec
        self.on_event = on_event
        self.session_id = spec.session_uuid
        self.instances.append(self)

    async def start(self):
        return None


class _FakeManager:
    instances: list["_FakeManager"] = []

    def __init__(self, workspace, system_prompt, **kwargs):
        self.ws = workspace
        self.system_prompt = system_prompt
        self.session_id = ""
        self.instances.append(self)


class _Process:
    def __init__(self, pid=42420):
        self.pid = pid

    def poll(self):
        return None

    def terminate(self):
        return None


class FreshWorkerSessionTests(unittest.TestCase):
    def setUp(self):
        _FakeWorker.instances.clear()
        _FakeManager.instances.clear()

    def test_option_is_available_on_resume_and_supervised_start(self):
        parser = build_parser()
        resumed = parser.parse_args([
            "resume", "saved", "--fresh-worker-session",
        ])
        supervised = parser.parse_args([
            "run", "start", "saved", "--fresh-worker-session",
        ])

        self.assertTrue(resumed.fresh_worker_session)
        self.assertTrue(supervised.fresh_worker_session)

    def test_fresh_worker_rejects_only_worker_session_and_keeps_durable_state(self):
        async def exercise():
            with isolated_runtime():
                ws = Workspace("fresh-worker")
                ws.create("https://example.test", "web")
                constraints = Constraints(
                    in_scope=["https://example.test/app"],
                    url_severities={"https://example.test/app": "Critical"},
                    excluded_classes=["informational"],
                    conditional_exclusions=["CORS without demonstrated impact"],
                    standing_instructions=["private operator text"],
                    hard_rules=["private manager rule"],
                    notes="private free-form note",
                )
                ws.save_constraints(constraints)
                # Model a workspace produced by the legacy renderer. Resume
                # must scrub these manager-only fields before Kraude starts.
                (ws.root / "scope-rules.md").write_text(
                    "# Legacy scope\n\n```\n" + constraints.to_prompt_block() + "\n```\n",
                    encoding="utf-8",
                )
                ws.update_meta(
                    worker_uuid="worker-old",
                    manager_session_id="manager-keep",
                    last_directive="exact saved mission",
                    turn_index=17,
                )
                ws.surface.append({"id": "S0001", "item": "/durable"})
                marker = ws.scratch_dir / "keep.txt"
                marker.write_text("durable workspace", encoding="utf-8")

                engine = Engine(
                    ws.slug,
                    backend="real",
                    worker_model="fixture/worker",
                    worker_effort="max",
                    manager_model="fixture/manager",
                    manager_effort="xhigh",
                )
                with patch("grypton.worker.KraudeWorker", _FakeWorker), patch(
                    "grypton.manager.KryptexManager", _FakeManager
                ):
                    await engine.setup(
                        brief="exact current mission",
                        target="https://example.test",
                        target_type="web",
                        fresh_clone=False,
                        fresh_worker_session=True,
                    )

                worker = _FakeWorker.instances[-1]
                manager = _FakeManager.instances[-1]
                self.assertEqual(worker.spec.session_uuid, "")
                expected_static_prompt = prompts.worker_system(
                    target="https://example.test",
                    target_type="web",
                    workspace=ws.root,
                    constraints_block=constraints.to_worker_prompt_block(),
                )
                self.assertEqual(worker.spec.system_prompt, expected_static_prompt)
                self.assertEqual(manager.session_id, "manager-keep")
                self.assertEqual(await engine._opening_directive(), "exact current mission")

                meta = ws.load_meta()
                self.assertEqual(meta.worker_uuid, "")
                self.assertEqual(meta.manager_session_id, "manager-keep")
                self.assertEqual(meta.turn_index, 17)
                surface = ws.surface.all()
                self.assertEqual(len(surface), 1)
                self.assertEqual(surface[0]["id"], "S0001")
                self.assertEqual(surface[0]["item"], "/durable")
                self.assertEqual(marker.read_text(encoding="utf-8"), "durable workspace")

                scope_doc = (ws.root / "scope-rules.md").read_text(encoding="utf-8")
                self.assertIn(constraints.to_worker_prompt_block(), scope_doc)
                for private_value in (
                    "private operator text", "private manager rule", "private free-form note",
                ):
                    self.assertNotIn(private_value, scope_doc)

        asyncio.run(exercise())

    def test_normal_resume_inherits_worker_and_manager_sessions(self):
        async def exercise():
            with isolated_runtime():
                ws = Workspace("ordinary-resume")
                ws.create("https://example.test", "web")
                ws.update_meta(
                    worker_uuid="worker-keep",
                    manager_session_id="manager-keep",
                )
                engine = Engine(
                    ws.slug,
                    backend="real",
                    worker_model="fixture/worker",
                    manager_model="fixture/manager",
                )
                with patch("grypton.worker.KraudeWorker", _FakeWorker), patch(
                    "grypton.manager.KryptexManager", _FakeManager
                ):
                    await engine.setup(
                        brief="",
                        target="https://example.test",
                        target_type="web",
                        fresh_clone=False,
                        fresh_worker_session=False,
                    )

                self.assertEqual(_FakeWorker.instances[-1].spec.session_uuid, "worker-keep")
                self.assertEqual(_FakeManager.instances[-1].session_id, "manager-keep")
                self.assertEqual(ws.load_meta().worker_uuid, "worker-keep")

        asyncio.run(exercise())

    def test_fresh_clone_still_rejects_an_inherited_worker_session(self):
        async def exercise():
            with isolated_runtime():
                ws = Workspace("fresh-clone")
                ws.create("https://example.test", "web")
                ws.update_meta(
                    worker_uuid="worker-old",
                    manager_session_id="manager-keep",
                )
                engine = Engine(
                    ws.slug,
                    backend="real",
                    worker_model="fixture/worker",
                    manager_model="fixture/manager",
                )
                with patch("grypton.worker.KraudeWorker", _FakeWorker), patch(
                    "grypton.manager.KryptexManager", _FakeManager
                ):
                    await engine.setup(
                        brief="new engagement mission",
                        target="https://example.test",
                        target_type="web",
                        fresh_clone=True,
                        fresh_worker_session=False,
                    )

                self.assertEqual(_FakeWorker.instances[-1].spec.session_uuid, "")
                self.assertEqual(_FakeManager.instances[-1].session_id, "manager-keep")
                self.assertEqual(ws.load_meta().worker_uuid, "")

        asyncio.run(exercise())

    def test_background_flag_is_private_one_shot_and_crash_safe(self):
        with isolated_runtime():
            ws = Workspace("background-fresh")
            ws.create("https://example.test", "web")
            ws.update_meta(worker_uuid="worker-old", manager_session_id="manager-keep")
            secret_mission = "mission password=private-value"
            fake = _Process()

            def matching(pid, role, slug, run_id):
                return role == "supervise" and pid == fake.pid

            def ready_state(*args, **kwargs):
                current = json.loads(
                    (config.RUNTIME_DIR / "supervisors/background-fresh/current.json").read_text()
                )
                path = _paths(ws.slug, current["run_id"])["state"]
                state = json.loads(path.read_text(encoding="utf-8"))
                state.update({"status": "running", "supervisor_pid": fake.pid})
                _write_json(path, state)
                return fake

            with patch("grypton.runtime.subprocess.Popen", side_effect=ready_state) as popen, patch(
                "grypton.runtime.pid_matches", side_effect=matching
            ), patch("grypton.runtime.time.sleep"):
                public = start_background(
                    ws,
                    brief=secret_mission,
                    backend="mock",
                    max_run_seconds=3600,
                    max_turns=0,
                    stop_on_p1=False,
                    worker_model="mock/worker",
                    worker_effort="max",
                    manager_model="mock/manager",
                    manager_effort="xhigh",
                    fresh_worker_session=True,
                    health_interval_seconds=600,
                    restart_limit=2,
                )

            run_id = public["run_id"]
            paths = _paths(ws.slug, run_id)
            initial_spec = json.loads(paths["spec"].read_text(encoding="utf-8"))
            self.assertTrue(initial_spec["fresh_worker_session"])
            self.assertFalse(initial_spec["fresh_worker_session_consumed"])
            os_argv = popen.call_args.args[0]
            self.assertNotIn("--fresh-worker-session", os_argv)
            self.assertNotIn(secret_mission, " ".join(os_argv))
            self.assertNotIn(secret_mission, " ".join(_engine_argv(ws.slug, run_id)))
            self.assertNotIn("fresh_worker_session", json.dumps(public_status(ws.slug)))

            # Simulate a process failure after the old UUID is cleared but
            # before the one-shot bit is committed. The next child must retry
            # the fresh launch rather than inherit the old conversation.
            with patch("grypton.runtime._write_json", side_effect=OSError("synthetic crash")):
                with self.assertRaisesRegex(OSError, "synthetic crash"):
                    run_engine(ws.slug, run_id)
            self.assertEqual(ws.load_meta().worker_uuid, "")
            after_crash = json.loads(paths["spec"].read_text(encoding="utf-8"))
            self.assertFalse(after_crash["fresh_worker_session_consumed"])

            first_calls = []

            def first_main(arguments):
                # The old provider session is gone before the one-shot launch
                # is considered consumed, closing the pre-setup crash window.
                self.assertEqual(ws.load_meta().worker_uuid, "")
                consumed = json.loads(paths["spec"].read_text(encoding="utf-8"))
                self.assertTrue(consumed["fresh_worker_session_consumed"])
                first_calls.append(arguments)
                return 0

            with patch("grypton.cli.main", side_effect=first_main):
                self.assertEqual(run_engine(ws.slug, run_id), 0)
            self.assertIn("--fresh-worker-session", first_calls[0])
            self.assertEqual(ws.load_meta().manager_session_id, "manager-keep")

            # Model the first replacement worker turn persisting its new
            # OpenCode session ID. The supervisor's next engine child must
            # retain this ID because the one-shot launch was consumed.
            ws.update_meta(worker_uuid="worker-replacement")
            second_calls = []

            def second_main(arguments):
                self.assertEqual(ws.load_meta().worker_uuid, "worker-replacement")
                second_calls.append(arguments)
                return 0

            with patch("grypton.cli.main", side_effect=second_main):
                self.assertEqual(run_engine(ws.slug, run_id), 0)
            self.assertNotIn("--fresh-worker-session", second_calls[0])
            self.assertEqual(ws.load_meta().worker_uuid, "worker-replacement")


if __name__ == "__main__":
    unittest.main()
