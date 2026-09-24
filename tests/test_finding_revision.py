from __future__ import annotations

from contextlib import contextmanager, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from grypton import config
from grypton.toolserver import REGISTRY, cli_main, dispatch
from grypton.workspace import FINDING_NARRATIVE_FIELDS, Workspace


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


def finding_workspace(slug: str = "revision-test") -> tuple[Workspace, dict]:
    ws = Workspace(slug)
    ws.create("https://example.test", "web")
    finding = ws.record_finding(
        title="Persistence proven",
        severity="P4",
        vuln_class="access control",
        surface="/feedback",
        description="The response proves a durable write.",
        poc="Send one request.",
        evidence="flows/original.http",
    )
    return ws, finding


class FindingRevisionTests(unittest.TestCase):
    def test_revision_atomically_updates_record_and_audit_history(self):
        with isolated_runtime():
            ws, finding = finding_workspace()
            revised = ws.revise_finding(
                finding["id"],
                reason="The response proves acceptance but storage was not read back.",
                title="Unauthenticated feedback submission accepted",
                description="The handler accepted the submission; durability is unverified.",
            )

            self.assertEqual(revised["severity"], "P4")
            self.assertEqual(revised["status"], "validation-not-requested")
            self.assertIsNone(revised["manager_verdict"])
            self.assertEqual(len(revised["revisions"]), 1)
            audit = revised["revisions"][0]
            self.assertEqual(audit["id"], "R001")
            self.assertEqual(audit["source"], "worker")
            self.assertEqual(
                audit["changes"]["title"],
                {"before": "Persistence proven",
                 "after": "Unauthenticated feedback submission accepted"},
            )
            on_disk = ws.findings.find(finding["id"])
            self.assertEqual(on_disk, revised)
            rows = (ws.root / ".ledger/findings.jsonl").read_text().splitlines()
            self.assertEqual(len(rows), 1)
            self.assertEqual(json.loads(rows[0])["revisions"], revised["revisions"])

    def test_failed_atomic_replace_leaves_finding_and_markdown_unchanged(self):
        with isolated_runtime():
            ws, finding = finding_workspace("revision-atomic-failure")
            ledger_before = (ws.root / ".ledger/findings.jsonl").read_bytes()
            markdown_before = (ws.root / "findings.md").read_bytes()
            with patch("grypton.workspace._atomic_write", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    ws.revise_finding(
                        finding["id"], reason="Correct an overclaim.",
                        description="Accepted, durability unverified.",
                    )
            self.assertEqual(
                (ws.root / ".ledger/findings.jsonl").read_bytes(), ledger_before
            )
            self.assertEqual((ws.root / "findings.md").read_bytes(), markdown_before)

    def test_revision_appends_clearly_labeled_markdown_amendment(self):
        with isolated_runtime():
            ws, finding = finding_workspace("revision-markdown")
            ws.revise_finding(
                finding["id"], reason="Narrow claim to observed behavior.",
                description="The handler accepted the request.",
                evidence="flows/control.http and flows/probe.http",
            )
            markdown = (ws.root / "findings.md").read_text()
            self.assertIn("F001 — Finding amendment R001", markdown)
            self.assertIn("**Reason:** Narrow claim to observed behavior.", markdown)
            self.assertIn("**Claimed severity unchanged:** P4", markdown)
            self.assertIn("**Amended description:**", markdown)
            self.assertIn("- Previous: The response proves a durable write.", markdown)
            self.assertIn("- Revised: The handler accepted the request.", markdown)

    def test_missing_noop_and_invalid_revisions_are_rejected(self):
        with isolated_runtime():
            ws, finding = finding_workspace("revision-rejections")
            original = ws.findings.find(finding["id"])
            cases = [
                (("F999",), {"reason": "Correct it.", "title": "Changed"}, KeyError),
                ((finding["id"],), {"reason": "", "title": "Changed"}, ValueError),
                ((finding["id"],), {"reason": "Correct it."}, ValueError),
                ((finding["id"],), {"reason": "Correct it.",
                                      "title": finding["title"]}, ValueError),
                ((finding["id"],), {"reason": "Escalate it.", "severity": "P1"},
                 ValueError),
                ((finding["id"],), {"reason": "Invalid type.", "title": 7},
                 ValueError),
            ]
            for args, kwargs, error in cases:
                with self.subTest(kwargs=kwargs), self.assertRaises(error):
                    ws.revise_finding(*args, **kwargs)
            self.assertEqual(ws.findings.find(finding["id"]), original)

    def test_mcp_schema_and_dispatch_enforce_narrative_only_revision(self):
        description, schema, _ = REGISTRY["revise_finding"]
        self.assertIn("durable", description)
        self.assertEqual(schema["required"], ["finding_id", "reason"])
        self.assertFalse(schema["additionalProperties"])
        self.assertNotIn("severity", schema["properties"])
        self.assertEqual(
            {row["required"][0] for row in schema["anyOf"]},
            set(FINDING_NARRATIVE_FIELDS),
        )

        with isolated_runtime():
            ws, finding = finding_workspace("revision-dispatch")
            result = dispatch(ws, "revise_finding", {
                "finding_id": finding["id"],
                "reason": "Remove unsupported persistence wording.",
                "title": "Submission accepted",
            })
            self.assertTrue(result["ok"], result)
            self.assertIn("severity remains P4", result["summary"])
            rejected = dispatch(ws, "revise_finding", {
                "finding_id": finding["id"],
                "reason": "Try to escalate.",
                "severity": "P1",
            })
            self.assertFalse(rejected["ok"])
            self.assertEqual(ws.findings.find(finding["id"])["severity"], "P4")

    def test_matching_cli_command_dispatches_revision(self):
        with isolated_runtime():
            ws, finding = finding_workspace("revision-cli")
            output = io.StringIO()
            with redirect_stdout(output):
                code = cli_main([
                    "--target", ws.slug, "--json", "finding-revise", finding["id"],
                    "--reason", "Clarify observed behavior.",
                    "--description", "The request reached the registered handler.",
                ])
            self.assertEqual(code, 0, output.getvalue())
            payload = json.loads(output.getvalue())
            self.assertTrue(payload["ok"])
            current = ws.findings.find(finding["id"])
            self.assertEqual(
                current["description"], "The request reached the registered handler."
            )


if __name__ == "__main__":
    unittest.main()
