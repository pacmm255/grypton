from __future__ import annotations

from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from grypton import config
from grypton.cli import build_parser, main
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
            yield root


class ProgramCommandTests(unittest.TestCase):
    def test_parser_exposes_operator_program_command(self):
        parsed = build_parser().parse_args(["program", "example-test", "--json"])
        self.assertEqual(parsed.target, "example-test")
        self.assertTrue(parsed.json)

    def test_json_reads_private_snapshot_without_mutating_or_printing_credentials(self):
        with isolated_runtime():
            ws = Workspace("program-json")
            ws.create("https://example.test", "web")
            ws.save_program_brief(
                "Public scope policy.\n"
                "Bearer authentication and basic authentication are supported.\n"
                "username=researcher@example.test password=hunter2\n"
                "Authorization: Bearer live-token\n"
                "Use Authorization: Bearer inline-live-token for the API.\n"
                'Header JSON: {"Authorization": "Basic U1lOVEhFVElDOlZBTFVF"}.\n'
                "Send Cookie: app_session=inline-cookie-value with requests.\n"
                "Login: https://url-user:url-password@example.test/account",
                {
                    "program": "synthetic-public-program",
                    "credential_requirement": True,
                    "username": "researcher@example.test",
                    "nested": {
                        "api-key": "live-api-key",
                        "note": "session_token=live-session-token",
                    },
                },
            )
            brief_before = ws.program_brief_path.read_bytes()
            profile_before = ws.program_profile_path.read_bytes()

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(["program", ws.slug, "--json"])

            self.assertEqual(code, 0, stderr.getvalue())
            payload = json.loads(stdout.getvalue())
            self.assertTrue(payload["present"])
            self.assertTrue(payload["brief_present"])
            self.assertTrue(payload["profile_present"])
            self.assertEqual(payload["target"], ws.slug)
            self.assertIn("Public scope policy.", payload["brief"])
            self.assertIn(
                "Bearer authentication and basic authentication are supported.",
                payload["brief"],
            )
            self.assertEqual(payload["profile"]["program"], "synthetic-public-program")
            self.assertTrue(payload["profile"]["credential_requirement"])
            self.assertEqual(payload["profile"]["username"], "[REDACTED]")
            self.assertEqual(payload["profile"]["nested"]["api-key"], "[REDACTED]")
            rendered = stdout.getvalue()
            for secret in (
                "researcher@example.test", "hunter2", "live-token",
                "inline-live-token", "U1lOVEhFVElDOlZBTFVF", "inline-cookie-value",
                "url-user", "url-password", "live-api-key", "live-session-token",
            ):
                self.assertNotIn(secret, rendered)
            self.assertEqual(ws.program_brief_path.read_bytes(), brief_before)
            self.assertEqual(ws.program_profile_path.read_bytes(), profile_before)
            self.assertFalse((ws.root / "program-brief.md").exists())
            self.assertFalse((ws.root / ".ledger/program-profile.json").exists())

    def test_plain_output_shows_saved_brief_and_profile(self):
        with isolated_runtime():
            ws = Workspace("program-plain")
            ws.create("https://example.test", "web")
            ws.save_program_brief(
                "Only the listed web URL is in scope.",
                {"program": "plain-fixture", "status": "active"},
            )
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["program", ws.slug])
            self.assertEqual(code, 0)
            rendered = output.getvalue()
            self.assertIn("Program snapshot: program-plain", rendered)
            self.assertIn("Only the listed web URL is in scope.", rendered)
            self.assertIn("Normalized profile", rendered)
            self.assertIn('"program": "plain-fixture"', rendered)

    def test_absent_snapshot_is_a_clean_empty_result(self):
        with isolated_runtime():
            ws = Workspace("program-absent")
            ws.create("https://example.test", "web")
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["program", ws.slug, "--json"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue()), {
                "target": ws.slug,
                "present": False,
                "brief_present": False,
                "profile_present": False,
                "brief": None,
                "profile": None,
            })

    def test_missing_engagement_and_invalid_profile_fail_cleanly(self):
        with isolated_runtime():
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(main(["program", "missing"]), 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("no engagement", stderr.getvalue())

            ws = Workspace("program-invalid")
            ws.create("https://example.test", "web")
            ws.program_profile_path.write_text("not-json", encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                self.assertEqual(main(["program", ws.slug]), 2)
            self.assertIn("stored program snapshot", stderr.getvalue())
            self.assertNotIn("not-json", stderr.getvalue())

    def test_program_command_refuses_a_symlinked_snapshot(self):
        with isolated_runtime() as root:
            ws = Workspace("program-symlink")
            ws.create("https://example.test", "web")
            outside = root / "provider-credential"
            outside.write_text("bare-provider-secret", encoding="utf-8")
            ws.program_profile_path.symlink_to(outside)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(["program", ws.slug])
            self.assertEqual(code, 2)
            self.assertNotIn("bare-provider-secret", stdout.getvalue())
            self.assertNotIn("bare-provider-secret", stderr.getvalue())
            self.assertIn("unreadable", stderr.getvalue())

    def test_program_command_is_unavailable_inside_the_model_runtime(self):
        with isolated_runtime():
            ws = Workspace("program-model-boundary")
            ws.create("https://example.test", "web")
            ws.save_program_brief(
                "Operator-visible program policy.",
                {"program": "private-program-profile"},
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with patch.dict(os.environ, {
                "GRYPTON_ENGAGEMENT_DIR": str(ws.root),
            }), redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(["program", ws.slug, "--json"])
            self.assertEqual(code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("operator shell", stderr.getvalue())
            self.assertNotIn("Operator-visible", stderr.getvalue())
            self.assertNotIn("private-program-profile", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
