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
from grypton.console import Console, PasteParser, _PASSIVE_REFUSAL, _TASK_INTENT
from grypton.contracts import VERDICT, check_references, obj, parse_output
from grypton.engine import resolve_requirements, review, stop, validate_finding
from grypton.integrity import audit_project
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

    def test_scope_records_and_finding_ledger_are_durable(self):
        case = self.case()
        self.store.set_scope(case["id"], {"type": "web", "in_scope": ["owned.example"],
                                          "out_of_scope": ["third-party.example"],
                                          "rules": ["Use supplied artifacts only."]})
        observation = self.store.append_record(case["id"], "observations", "Owner supplied a release note.")
        surface = self.store.append_record(case["id"], "surface", "/account", category="route")
        finding = self.store.add_finding(case["id"], "Synthetic control", "The control is enabled.")
        saved = self.store.get(case["id"])
        self.assertEqual(saved["schema_version"], 2)
        self.assertEqual(saved["scope"]["in_scope"], ["owned.example"])
        self.assertEqual(observation["id"], "obs-0001")
        self.assertEqual(surface["id"], "surface-0001")
        self.assertEqual(finding["evidence_ids"], [case["evidence"][0]["id"]])


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

    def test_bracketed_multiline_paste_is_one_message(self):
        parser = PasteParser()
        self.assertEqual(list(parser.feed("typed message\n")), ["typed message"])
        self.assertEqual(list(parser.feed("\x1b[200~first line\n")), [])
        self.assertEqual(list(parser.feed("second line\x1b[201~\n")),
                         ["first line\nsecond line"])

    def test_task_and_passive_refusal_detection_covers_provider_variants(self):
        for directive in ("pentest demo.invalid", "scan the supplied fixture",
                          "start a bug bounty review", "enumerate the review hypotheses"):
            self.assertRegex(directive, _TASK_INTENT)
        for refusal in ("I can't perform that.", "I'm unable to help.",
                        "We do not have the capability.", "No tools are available."):
            self.assertRegex(refusal, _PASSIVE_REFUSAL)


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
        self.assertEqual(len(run["calls"]), 4)
        self.assertEqual({call["route"]["qualified"] for call in run["calls"]},
                         {MODELS[role].qualified for role in MODELS})
        self.assertEqual(len(run["prompt_fingerprints"]), 3)
        self.assertEqual(run["stages"]["validation"]["verdict"], "inconclusive")
        self.assertEqual(self.store.get(case["id"])["findings"][0]["status"], "inconclusive")
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

    def test_resume_refuses_changed_prompt_bundle(self):
        case = self.case()
        with self.assertRaises(GryptonError):
            asyncio.run(review(self.store, case["id"], RecordingBackend("assessment")))
        changed = {role: "0" * 64 for role in ("manager", "worker", "validator")}
        with patch("grypton.engine.prompt_fingerprints", return_value=changed), \
             self.assertRaisesRegex(GryptonError, "prompts"):
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
        empty = self.store.create("Empty", "No evidence")
        self.assertEqual(resolve_requirements(["existing_evidence"], empty, self.root)[0]["status"],
                         "unavailable")

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

    def test_console_persists_user_intent_and_manager_relays_to_worker(self):
        case = self.store.create("console.example", "Review supplied material.",
                                 stable=True, target="console.example")
        backend = RecordingBackend()
        console = Console(self.store, case["id"], backend)
        responses = asyncio.run(console.message("focus on the supplied authorization notes"))
        self.assertEqual([call[:2] for call in backend.calls],
                         [("manager", "chat"), ("worker", "chat")])
        self.assertEqual([name for name, _ in responses], ["Kryptex", "Kraude"])
        saved = self.store.get(case["id"])
        self.assertIn("focus on the supplied authorization notes", saved["standing_instructions"])
        self.assertTrue(any(item["text"].startswith("Kryptex → Kraude:")
                            for item in saved["messages"]))

    def test_console_kickoff_is_remembered_and_delegated_without_manager_note(self):
        case = self.store.create("kickoff.example", "Review supplied material.",
                                 stable=True, target="kickoff.example")

        class PassiveManager(RecordingBackend):
            async def call(self, role, stage, prompt, schema, payload):
                result = await super().call(role, stage, prompt, schema, payload)
                if role == "manager":
                    result.update(reply="I can't perform this assessment because no tools are available.",
                                  remember="", disposition="reply-only", worker_note="")
                return result

        backend = PassiveManager()
        responses = asyncio.run(Console(self.store, case["id"], backend).message(
            "pentest kickoff.example"))
        self.assertEqual([call[:2] for call in backend.calls],
                         [("manager", "chat"), ("worker", "chat")])
        self.assertEqual([name for name, _ in responses], ["Kryptex", "Kraude"])
        self.assertNotIn("can't", responses[0][1])
        self.assertIn("delegated the kickoff", responses[0][1])
        self.assertIn("pentest kickoff.example",
                      self.store.get(case["id"])["standing_instructions"])

    def test_console_recovers_plaintext_manager_refusal_but_not_transport_failure(self):
        case = self.store.create("recovery.example", "Review supplied material.",
                                 stable=True, target="recovery.example")

        class PlaintextRefusal(RecordingBackend):
            async def call(self, role, stage, prompt, schema, payload):
                self.calls.append((role, stage, payload))
                if role == "manager":
                    raise GryptonError("The model returned invalid JSON; no review result was accepted.")
                return await MockBackend().call(role, stage, prompt, schema, payload)

        recovered = asyncio.run(Console(self.store, case["id"], PlaintextRefusal()).message(
            "scan recovery.example"))
        self.assertEqual([name for name, _ in recovered], ["Kryptex", "Kraude"])
        self.assertIn("delegated the kickoff", recovered[0][1])

        class TransportFailure(MockBackend):
            async def call(self, role, stage, prompt, schema, payload):
                raise GryptonError("OpenCode: quota unavailable")

        with self.assertRaisesRegex(GryptonError, "quota"):
            asyncio.run(Console(self.store, case["id"], TransportFailure()).message(
                "scan recovery.example"))

    def test_console_returns_a_resolved_local_blocker_to_kraude(self):
        case = self.store.create("blocked.example", "Review supplied material.",
                                 stable=True, target="blocked.example")

        class NeedsEmail(RecordingBackend):
            async def call(self, role, stage, prompt, schema, payload):
                result = await super().call(role, stage, prompt, schema, payload)
                if role == "worker" and not payload.get("resolved_resources"):
                    result["requirements"] = ["offline_email"]
                elif role == "worker":
                    result["reply"] = "Used the supplied synthetic email fixture."
                    result["requirements"] = []
                return result

        backend = NeedsEmail()
        with contextlib.redirect_stdout(io.StringIO()):
            responses = asyncio.run(Console(self.store, case["id"], backend).message(
                "Use a local placeholder in the example.", to_worker=True))
        self.assertEqual(len(backend.calls), 2)
        supplied = backend.calls[1][2]["resolved_resources"]
        self.assertEqual([(item["kind"], item["status"]) for item in supplied],
                         [("offline_email", "resolved")])
        self.assertIn("synthetic email fixture", responses[0][1])

    def test_console_resolves_sequential_local_blockers_without_operator(self):
        case = self.store.create("resources.example", "Review supplied material.",
                                 stable=True, target="resources.example")

        class Sequential(RecordingBackend):
            async def call(self, role, stage, prompt, schema, payload):
                result = await super().call(role, stage, prompt, schema, payload)
                kinds = {item["kind"] for item in payload.get("resolved_resources", [])}
                if "offline_email" not in kinds:
                    result["requirements"] = ["offline_email"]
                elif "offline_identity" not in kinds:
                    result["requirements"] = ["offline_identity"]
                else:
                    result["requirements"] = []
                    result["reply"] = "Both local blockers were resolved."
                return result

        backend = Sequential()
        with contextlib.redirect_stdout(io.StringIO()):
            result = asyncio.run(Console(self.store, case["id"], backend).message(
                "Complete the local example.", to_worker=True))
        self.assertEqual(len(backend.calls), 3)
        self.assertIn("Both local blockers", result[0][1])
        self.assertEqual({item["kind"] for item in self.store.get(case["id"])["resource_events"]},
                         {"offline_email", "offline_identity"})

    def test_console_resources_include_staged_review_decisions(self):
        case = self.case()
        asyncio.run(review(self.store, case["id"], MockBackend()))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            asyncio.run(Console(self.store, case["id"], MockBackend()).command("/resources"))
        self.assertIn("review · existing_evidence · resolved", output.getvalue())

    def test_kryptex_coordinates_independent_finding_validation(self):
        case = self.case()
        finding = self.store.add_finding(case["id"], "Candidate", "The control is enabled.")
        backend = RecordingBackend()
        result = asyncio.run(validate_finding(self.store, case["id"], finding["id"], backend))
        self.assertEqual([call[1] for call in backend.calls],
                         ["finding_plan", "finding_validation", "finding_summary"])
        self.assertEqual(set(backend.calls[1][2]), {"claim", "evidence"})
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["severity"], "unknown")
        self.assertEqual(len(result["validation_history"]), 1)
        self.assertEqual([call["role"] for call in result["validation_run"]["calls"]],
                         ["manager", "validator", "manager"])

    def test_stop_cancels_finding_validation_and_restores_engagement(self):
        case = self.case()
        finding = self.store.add_finding(case["id"], "Candidate", "The control is enabled.")

        async def exercise():
            entered = asyncio.Event()

            class Waiting(MockBackend):
                async def call(self, role, stage, prompt, schema, payload):
                    if stage == "finding_validation":
                        entered.set()
                        await asyncio.Event().wait()
                    return await super().call(role, stage, prompt, schema, payload)

            task = asyncio.create_task(validate_finding(
                self.store, case["id"], finding["id"], Waiting()))
            await asyncio.wait_for(entered.wait(), 2)
            stop(self.store, case["id"])
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 2)

        asyncio.run(exercise())
        saved = self.store.get(case["id"])
        self.assertEqual(saved["status"], "draft")
        self.assertEqual(saved["findings"][0]["status"], "candidate")
        self.assertEqual(saved["findings"][0]["validation_run"]["status"], "interrupted")
        self.assertFalse((self.store.directory(case["id"]) / ".stop.json").exists())


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

    def test_init_matches_krypton_shape_without_required_claim(self):
        code, stdout, stderr = self.call_cli("init", "service.example", "--no-interact", "--json")
        self.assertEqual((code, stderr), (0, ""))
        created = json.loads(stdout)
        self.assertEqual(created["id"], "service-example")
        self.assertEqual(created["target"], "service.example")
        record = self.store.get("service-example")
        self.assertIn("service.example", record["claim"])
        self.assertEqual(record["scope"]["in_scope"], ["service.example"])
        code, stdout, _ = self.call_cli("status", "service.example", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["cases"][0]["id"], "service-example")

        code, stdout, stderr = self.call_cli(
            "init", "--target", "option.example", "--no-interact", "--json")
        self.assertEqual((code, stderr), (0, ""))
        self.assertEqual(json.loads(stdout)["id"], "option-example")

    def test_init_reuses_existing_target_and_persists_new_brief(self):
        existing = self.store.create("Existing", "Existing claim")
        code, stdout, stderr = self.call_cli("init", "Existing", "-m", "remember this",
                                             "--no-interact", "--json")
        self.assertEqual((code, stderr), (0, ""))
        self.assertEqual(json.loads(stdout)["id"], existing["id"])
        record = self.store.get(existing["id"])
        self.assertEqual(record["brief"], "remember this")
        self.assertIn("remember this", record["standing_instructions"])

    def test_scope_ledger_validation_and_lab_commands(self):
        code, stdout, _ = self.call_cli(
            "init", "scope.example", "--no-interact", "--type", "web",
            "--in-scope", "scope.example,/owned", "--out-scope", "third-party.example", "--json")
        self.assertEqual(code, 0)
        case_id = json.loads(stdout)["id"]
        evidence = self.root / "scope-evidence.txt"
        evidence.write_text("Synthetic owner-supplied configuration statement.")
        self.assertEqual(self.call_cli("evidence", "add", case_id, str(evidence), "--json")[0], 0)
        code, stdout, _ = self.call_cli("findings", "add", case_id,
                                        "The supplied configuration enables the control.", "--json")
        self.assertEqual(code, 0)
        finding_id = json.loads(stdout)["finding"]["id"]
        code, stdout, _ = self.call_cli("findings", "validate", case_id, finding_id, "--mock", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["status"], "inconclusive")
        code, stdout, _ = self.call_cli("resume", case_id, "-m", "remember this constraint",
                                        "--no-interact", "--json")
        self.assertEqual(code, 0)
        saved = self.store.get(case_id)
        self.assertEqual(saved["scope"]["type"], "web")
        self.assertIn("scope.example", saved["scope"]["in_scope"])
        self.assertIn("remember this constraint", saved["standing_instructions"])
        code, stdout, _ = self.call_cli("lab", "verify", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["turn_count"], 9)
        code, stdout, _ = self.call_cli("lab", "run", "--scenario",
                                        "cookie-release-transition", "--mock", "--json")
        self.assertEqual(code, 0)
        lab_run = json.loads(stdout)
        self.assertEqual(lab_run["turn_count"], 3)
        self.assertEqual(len(lab_run["suite_sha256"]), 64)
        self.assertFalse(lab_run["target_interaction"])
        for run in lab_run["results"]["cookie-release-transition"].values():
            self.assertEqual(run["lab_trace"]["validator_payload_keys"], ["claim", "evidence"])
            self.assertEqual(run["lab_trace"]["tool_calls"], 0)
        saved = self.root / "saved-lab-run.json"
        saved.write_text(json.dumps(lab_run))
        code, stdout, _ = self.call_cli("lab", "score", str(saved), "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["suite_id"], "grypton-offline-review-v1")

    def test_integrity_audit_and_console_history_limit(self):
        (self.root / "target").mkdir()
        audit = audit_project(self.root, source_root=None, check_auth=False)
        self.assertTrue(audit["ok"])
        self.assertFalse(audit["target_interaction"])
        self.assertEqual(audit["coverage"]["kraude_glm_5_3_max"], "verified")
        self.assertEqual(audit["coverage"]["astra_max_finding_validation"], "verified")

        case = self.store.create("history.example", "Review supplied material.",
                                 stable=True, target="history.example")
        with self.assertRaisesRegex(GryptonError, "at least 1"):
            asyncio.run(Console(self.store, case["id"], MockBackend()).command("/history 0"))


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
        self.store.append_message(self.case_record["id"], role="user",
                                  text="private conversation marker")
        self.store.mutate(self.case_record["id"], lambda value: value.update(
            internal_secret="never expose this internal field"))
        with urlopen(self.base + "/") as response:
            self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
            self.assertIn("Operations console", response.read().decode())
        with urlopen(self.base + "/api/state") as response:
            payload = response.read().decode()
            self.assertNotIn("secure_cookie = true", payload)
            self.assertNotIn('"key"', payload)
        with urlopen(self.base + "/api/lab") as response:
            lab = json.loads(response.read().decode())
            self.assertEqual(lab["turn_count"], 9)
            self.assertNotIn('"text"', json.dumps(lab))
        with urlopen(self.base + "/api/audit") as response:
            audit = json.loads(response.read().decode())
            self.assertFalse(audit["target_interaction"])
            self.assertEqual(audit["model_calls"], 0)
            self.assertNotIn('"key"', json.dumps(audit))
        with urlopen(self.base + "/api/cases/" + self.case_record["id"]) as response:
            detail = response.read().decode()
            self.assertNotIn('"text"', detail)
            self.assertNotIn("private conversation marker", detail)
            self.assertNotIn("never expose this internal field", detail)

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
