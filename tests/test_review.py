import asyncio
import concurrent.futures
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from grypton.backends import (LiveBackend, MockBackend, clean, codex_command,
                              opencode_environment, opencode_text, run_process)
from grypton.cli import main
from grypton.config import GryptonError, MODELS, Settings, resource
from grypton.contracts import VERDICT, check_references, obj, parse_output
from grypton.engine import resolve_requirements, review, stop
from grypton.presentation import case_summary, markdown_report, state
from grypton.storage import Store
from grypton.web import make_server


class TempStore(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="grypton-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.settings = Settings.load(self.root)
        self.store = Store(self.settings)

    def case(self):
        case = self.store.create("Synthetic configuration", "The configuration explicitly enables a control.")
        evidence = self.root / "evidence.txt"
        evidence.write_text("Synthetic fixture: secure_cookie = true\n")
        return self.store.add_evidence(case["id"], evidence)


class StorageTests(TempStore):
    def test_evidence_snapshot_deduplicates_and_preserves_digest(self):
        case = self.case()
        before = case["evidence"][0]
        (self.root / "evidence.txt").write_text("Changed after import")
        after = self.store.get(case["id"])["evidence"][0]
        self.assertEqual(before, after)
        same = self.root / "same.txt"
        same.write_text(before["text"])
        with self.assertRaisesRegex(GryptonError, "already attached"):
            self.store.add_evidence(case["id"], same)

    def test_concurrent_writers_do_not_lose_updates(self):
        case = self.case()
        self.store.mutate(case["id"], lambda value: value.update(counter=0))
        def increment(_):
            self.store.mutate(case["id"], lambda value: value.update(counter=value["counter"] + 1))
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(increment, range(32)))
        self.assertEqual(self.store.get(case["id"])["counter"], 32)

    def test_corruption_is_visible(self):
        case = self.case()
        (self.store.directory(case["id"]) / "case.json").write_text('{"broken"')
        with self.assertRaisesRegex(GryptonError, "valid state"):
            self.store.list()

    def test_evidence_import_rejects_symlinks_directories_and_targets(self):
        case = self.case()
        linked = self.root / "linked.txt"
        linked.symlink_to(self.root / "evidence.txt")
        for path in (linked, self.root, self.root / "targets" / "never-read.txt", Path("/root/krypton/targets/never-read")):
            with self.subTest(path=path), self.assertRaises(GryptonError):
                self.store.add_evidence(case["id"], path)

    def test_state_symlink_and_path_escape_rejected(self):
        (self.root / ".state").symlink_to(self.root / "outside")
        with self.assertRaises(GryptonError):
            self.store.create("test", "test")
        for value in ("../../escape", "/absolute", "", "UPPER", "x/y"):
            with self.subTest(value=value), self.assertRaises(GryptonError):
                self.store.directory(value)

    def test_original_project_cannot_be_root_even_after_normalization(self):
        for value in ("/root/krypton", "/root/krypton/targets", "/root/grypton/../krypton"):
            with self.subTest(value=value), self.assertRaises(GryptonError):
                Settings.load(value)

    def test_private_state_permissions(self):
        case = self.case()
        directory = self.store.directory(case["id"])
        self.assertEqual((directory.stat().st_mode & 0o077), 0)
        self.assertEqual(((directory / "case.json").stat().st_mode & 0o077), 0)

    def test_oversized_evidence_is_rejected(self):
        case = self.case()
        large = self.root / "large.txt"
        large.write_text("x" * 160_001)
        with self.assertRaisesRegex(GryptonError, "exceeds"):
            self.store.add_evidence(case["id"], large)

    def test_empty_and_binary_evidence_rejected(self):
        case = self.case()
        for data in (b"", b"\x00", b"\xff"):
            (self.root / "bad.txt").write_bytes(data)
            with self.assertRaises(GryptonError):
                self.store.add_evidence(case["id"], self.root / "bad.txt")


class ContractTests(unittest.TestCase):
    def test_rejects_duplicate_keys_trailing_text_and_unknown_fields(self):
        schema = obj({"status": {"type": "string", "enum": ["ok"]}})
        for text in ('{"status":"ok","status":"ok"}', '{"status":"ok"} prose', '{"status":"ok","command":"x"}'):
            with self.subTest(text=text), self.assertRaises(GryptonError):
                parse_output(text, schema)
        self.assertEqual(parse_output('```json\n{"status":"ok"}\n```', schema), {"status": "ok"})

    def test_rejects_fabricated_evidence_and_severity(self):
        for value in ({"assessment": "supported", "evidence_ids": ["invented"]},
                      {"verdict": "supported", "evidence_ids": []},
                      {"verdict": "inconclusive", "severity": "critical", "evidence_ids": ["ev-known"]}):
            with self.subTest(value=value), self.assertRaises(GryptonError):
                check_references(value, [{"id": "ev-known"}])

    def test_output_parser_ignores_reasoning_and_combines_text(self):
        output = "\n".join(json.dumps(e) for e in [
            {"type": "reasoning", "part": {"text": "not public"}},
            {"type": "text", "part": {"text": '{"status":'}},
            {"type": "text", "part": {"text": '"ok"}'}},
            {"type": "step_finish", "part": {"reason": "stop"}}])
        self.assertEqual(opencode_text(output), '{"status":"ok"}')

    def test_successful_exit_with_error_or_tool_event_is_not_success(self):
        for event in ({"type": "error", "error": {"message": "quota exhausted"}}, {"type": "tool_use"}, []):
            with self.subTest(event=event), self.assertRaises(GryptonError):
                opencode_text(json.dumps(event))

    def test_credentials_and_terminal_controls_are_redacted(self):
        text = "hello\x1b[31mred\x1b[0m\x1b]52;c;private\x07 fake_secret_value_123"
        self.assertEqual(clean(text, ["fake_secret_value_123"]), "hellored [REDACTED]")
        with self.assertRaises(GryptonError) as caught:
            opencode_text(json.dumps({"type": "error", "error": {"message": "fake_secret_value_123"}}), "fake_secret_value_123")
        self.assertNotIn("fake_secret_value_123", str(caught.exception))


class BackendConfigTests(TempStore):
    def test_opencode_has_isolated_auth_explicit_plan_and_denied_tools(self):
        for role, provider in (("worker", "zai-coding-plan"), ("manager", "opencode-go")):
            work = self.root / role
            work.mkdir()
            with patch("grypton.backends.credential", return_value={"type": "api", "key": "synthetic-credential"}), \
                 patch("grypton.backends.host_path", return_value=self.root / "missing-cache"), \
                 patch.dict(os.environ, {"OPENCODE_CONFIG_CONTENT": '{"permission":"allow"}'}):
                env, secret = opencode_environment(work, MODELS[role])
            config = json.loads(env["OPENCODE_CONFIG_CONTENT"])
            self.assertEqual(config["permission"], "deny")
            self.assertEqual(config["agent"]["grypton-review"]["permission"], "deny")
            self.assertEqual(config["enabled_providers"], [provider])
            self.assertEqual(config["small_model"], MODELS[role].qualified)
            self.assertNotIn("synthetic-credential", env["OPENCODE_CONFIG_CONTENT"])
            auth = json.loads((work / "data/opencode/auth.json").read_text())
            self.assertEqual(list(auth), [provider])
            self.assertEqual(secret, "synthetic-credential")

    def test_codex_validator_routes_exactly_and_disables_execution(self):
        argv = codex_command(MODELS["validator"], self.root)
        self.assertEqual(argv[argv.index("--model") + 1], "gpt-6-astra")
        self.assertIn('model_reasoning_effort="max"', argv)
        self.assertIn("--ignore-user-config", argv)
        self.assertEqual(argv[argv.index("--sandbox") + 1], "read-only")
        self.assertIn('web_search="disabled"', argv)
        for name in ("shell_tool", "multi_agent", "apps", "plugins", "computer_use"):
            self.assertEqual(argv[argv.index(name) - 1], "--disable")
        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", argv)


class ProcessTests(unittest.IsolatedAsyncioTestCase):
    async def test_timeout_kills_descendant_after_parent_exit(self):
        with tempfile.TemporaryDirectory(prefix="grypton-process-") as name:
            directory = Path(name)
            marker = directory / "should-not-exist"
            child = f"import time; from pathlib import Path; time.sleep(0.5); Path({str(marker)!r}).write_text('leaked')"
            parent = f"import subprocess,sys; subprocess.Popen([sys.executable,'-c',{child!r}])"
            with self.assertRaisesRegex(GryptonError, "timed out"):
                await run_process([sys.executable, "-c", parent], cwd=directory, env=dict(os.environ), timeout=0.15)
            await asyncio.sleep(0.55)
            self.assertFalse(marker.exists())

    async def test_output_is_bounded(self):
        with patch("grypton.backends.MAX_OUTPUT_BYTES", 1000), self.assertRaisesRegex(GryptonError, "output limit"):
            await run_process([sys.executable, "-c", "print('x'*10000)"], cwd=Path("/tmp"), env=dict(os.environ))


class RecordingBackend(MockBackend):
    def __init__(self, fail=None):
        self.calls = []
        self.fail = fail

    async def call(self, role, stage, prompt, schema, payload):
        self.calls.append((role, stage, payload))
        if stage == self.fail:
            raise GryptonError("Synthetic provider failure")
        return await super().call(role, stage, prompt, schema, payload)


class EngineTests(TempStore):
    def test_complete_review_uses_independent_validator(self):
        case = self.case()
        backend = RecordingBackend()
        run = asyncio.run(review(self.store, case["id"], backend))
        self.assertEqual([call[1] for call in backend.calls], ["plan", "assessment", "validation", "summary"])
        validator_payload = backend.calls[2][2]
        self.assertEqual(set(validator_payload), {"claim", "evidence"})
        self.assertEqual(run["status"], "complete")
        self.assertEqual(run["stages"]["validation"]["verdict"], "inconclusive")
        self.assertEqual(state(self.store)["counts"]["supported"], 0)
        self.assertIn("Mode: mock", markdown_report(self.store.get(case["id"])))

    def test_failed_validation_is_saved_and_resume_skips_completed_calls(self):
        case = self.case()
        with self.assertRaisesRegex(GryptonError, "Synthetic provider"):
            asyncio.run(review(self.store, case["id"], RecordingBackend("validation")))
        checkpoint = self.store.get(case["id"])
        self.assertEqual(checkpoint["status"], "failed")
        self.assertNotIn("validation", checkpoint["runs"][-1]["stages"])
        backend = RecordingBackend()
        run = asyncio.run(review(self.store, case["id"], backend, resume=True))
        self.assertEqual([call[1] for call in backend.calls], ["validation", "summary"])
        self.assertEqual(run["status"], "complete")
        self.assertEqual(len(self.store.get(case["id"])["runs"]), 1)

    def test_resume_refuses_changed_evidence(self):
        case = self.case()
        with self.assertRaises(GryptonError):
            asyncio.run(review(self.store, case["id"], RecordingBackend("assessment")))
        extra = self.root / "extra.txt"
        extra.write_text("More evidence.")
        self.store.add_evidence(case["id"], extra)
        with self.assertRaisesRegex(GryptonError, "changed"):
            asyncio.run(review(self.store, case["id"], MockBackend(), resume=True))

    def test_no_evidence_means_no_model_call(self):
        case = self.store.create("Missing", "No evidence")
        backend = RecordingBackend()
        with self.assertRaisesRegex(GryptonError, "Attach"):
            asyncio.run(review(self.store, case["id"], backend))
        self.assertFalse(backend.calls)

    def test_new_evidence_marks_old_verdict_outdated(self):
        case = self.case()
        asyncio.run(review(self.store, case["id"], MockBackend()))
        extra = self.root / "extra.txt"
        extra.write_text("Additional evidence supplied after review.")
        changed = self.store.add_evidence(case["id"], extra)
        summary = case_summary(changed)
        self.assertEqual(summary["verdict"], "outdated")
        self.assertFalse(summary["review_complete"])
        self.assertFalse(summary["validation_complete"])
        self.assertIn("previous result below is historical", markdown_report(changed))

    def test_missing_review_case_does_not_create_broken_state(self):
        with self.assertRaisesRegex(GryptonError, "Unknown case"):
            asyncio.run(review(self.store, "missing", MockBackend()))
        self.assertEqual(self.store.list(), [])

    def test_two_reviews_cannot_run_for_one_case(self):
        case = self.case()
        with self.store.run_lock(case["id"]), self.assertRaisesRegex(GryptonError, "already running"):
            asyncio.run(review(self.store, case["id"], MockBackend()))

    def test_stop_cancels_active_call_and_preserves_plan(self):
        case = self.case()
        async def exercise():
            entered = asyncio.Event()
            class Waiting(MockBackend):
                async def call(self, role, stage, prompt, schema, payload):
                    if stage == "assessment":
                        entered.set()
                        await asyncio.Event().wait()
                    return await super().call(role, stage, prompt, schema, payload)
            task = asyncio.create_task(review(self.store, case["id"], Waiting()))
            await asyncio.wait_for(entered.wait(), 2)
            stop(self.store, case["id"])
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 2)
        asyncio.run(exercise())
        record = self.store.get(case["id"])
        self.assertEqual(record["status"], "interrupted")
        self.assertIn("plan", record["runs"][-1]["stages"])

    def test_local_requirements_are_resolved_and_external_accounts_unavailable(self):
        result = resolve_requirements(["offline_email", "scratch_directory", "external_account"], self.case(), self.root)
        self.assertIn(".invalid", result[0]["detail"])
        self.assertTrue((self.root / "scratch").is_dir())
        self.assertEqual(result[2]["status"], "unavailable")

    def test_worker_followup_is_bounded_and_requests_recorded(self):
        case = self.case()
        class Needy(RecordingBackend):
            async def call(self, role, stage, prompt, schema, payload):
                result = await super().call(role, stage, prompt, schema, payload)
                if role == "worker":
                    result["requirements"] = ["offline_email"]
                return result
        backend = Needy()
        run = asyncio.run(review(self.store, case["id"], backend))
        self.assertEqual(len(backend.calls), 5)
        self.assertEqual(run["resources"][-1]["status"], "unavailable")

    def test_repeated_available_resource_does_not_trigger_another_call(self):
        case = self.case()
        class Repeated(RecordingBackend):
            async def call(self, role, stage, prompt, schema, payload):
                result = await super().call(role, stage, prompt, schema, payload)
                if role == "worker":
                    result["requirements"] = ["existing_evidence"]
                return result
        backend = Repeated()
        asyncio.run(review(self.store, case["id"], backend))
        self.assertEqual(len(backend.calls), 4)


class CliTests(TempStore):
    def call_cli(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["--root", str(self.root), *args])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_json_flags_at_each_parser_level_and_clear_errors(self):
        for args in (("--json", "status"), ("status", "--json")):
            code, stdout, _ = self.call_cli(*args)
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(stdout)["project"], "Grypton")
        code, stdout, stderr = self.call_cli("show", "missing", "--json")
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(stdout)["ok"])
        self.assertNotIn("Traceback", stderr)

    def test_demo_and_dry_run_are_offline(self):
        with patch.object(LiveBackend, "call", side_effect=AssertionError("Unexpected model call")):
            code, stdout, _ = self.call_cli("demo", "--json")
            self.assertEqual(code, 0)
            result = json.loads(stdout)
            self.assertEqual(result["run"]["mode"], "mock")
            code, stdout, _ = self.call_cli("review", result["case"], "--dry-run", "--json")
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(stdout)["max_model_calls"], 5)
            self.assertFalse((self.root / "target").exists())

    def test_all_packaged_scenarios_work_offline(self):
        for scenario in json.loads(resource("scenarios.json")):
            code, stdout, _ = self.call_cli("demo", "--scenario", scenario["id"], "--json")
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(stdout)["run"]["status"], "complete")


class WebTests(TempStore):
    def setUp(self):
        super().setUp()
        self.case_record = self.case()
        self.server = make_server(self.store, 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.base = "http://127.0.0.1:" + str(self.server.server_address[1])

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_dashboard_and_api_have_no_evidence_text_or_credentials(self):
        with urlopen(self.base + "/") as response:
            self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
            self.assertIn("Review desk", response.read().decode())
        with urlopen(self.base + "/api/state") as response:
            payload = response.read().decode()
            self.assertNotIn("secure_cookie = true", payload)
            self.assertNotIn('"key"', payload)
        with urlopen(self.base + "/api/cases/" + self.case_record["id"]) as response:
            self.assertNotIn('"text"', response.read().decode())

    def test_mutations_external_origins_and_arbitrary_files_are_rejected(self):
        requests = [
            (Request(self.base + "/api/state", headers={"Origin": "https://example.invalid"}), 403),
            (Request(self.base + "/api/state", headers={"Host": "example.invalid"}), 403),
            (Request(self.base + "/api/state", method="POST", data=b"{}"), 405),
            (Request(self.base + "/.state/cases/" + self.case_record["id"] + "/case.json"), 404),
            (Request(self.base + "/api/cases/..%2F..%2Fopen"), 400),
        ]
        for request, expected in requests:
            with self.subTest(url=request.full_url), self.assertRaises(HTTPError) as error:
                urlopen(request)
            self.assertEqual(error.exception.code, expected)


if __name__ == "__main__":
    unittest.main()
