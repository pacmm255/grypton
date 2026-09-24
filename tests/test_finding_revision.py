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
from grypton.workspace import (ASTRA_REVALIDATION_REVISION_FIELD,
                               FINDING_NARRATIVE_FIELDS, Workspace)


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

    def test_new_evidence_reopens_only_needs_more_p1_p2_validation(self):
        with isolated_runtime():
            ws = Workspace("revision-revalidation")
            ws.create("https://example.test", "web")
            finding = ws.record_finding(
                title="High candidate", severity="P2",
                description="Initial observed behavior.",
                evidence="flows/initial.http",
            )
            prior = {
                "finding_id": finding["id"],
                "verdict": "needs-more-evidence",
                "severity": "P2",
                "reasoning": "A positive/control pair is still required.",
            }
            ws.set_severity_verdict(finding["id"], prior)

            description_only = ws.revise_finding(
                finding["id"], reason="Clarify the observation.",
                description="Initial observed behavior, without an impact claim.",
            )
            self.assertEqual(description_only["manager_verdict"], prior)
            self.assertEqual(description_only["status"], "needs-more-evidence")
            self.assertNotIn(
                ASTRA_REVALIDATION_REVISION_FIELD, description_only,
            )
            self.assertFalse(
                description_only["revisions"][-1].get(
                    "automatic_revalidation_requested"
                )
            )

            with self.assertRaisesRegex(ValueError, "does not change"):
                ws.revise_finding(
                    finding["id"], reason="Duplicate the same capture.",
                    evidence="flows/initial.http",
                )

            revised = ws.revise_finding(
                finding["id"], reason="Add the requested positive/control pair.",
                evidence="flows/positive-control.http",
            )
            self.assertIsNone(revised["manager_verdict"])
            self.assertEqual(revised["status"], "validation-pending")
            self.assertEqual(
                revised[ASTRA_REVALIDATION_REVISION_FIELD], "R002",
            )
            self.assertTrue(
                revised["revisions"][-1]["automatic_revalidation_requested"]
            )

            low = ws.record_finding(
                title="Medium candidate", severity="P3",
                evidence="flows/medium-initial.http",
            )
            low_verdict = {
                "finding_id": low["id"], "verdict": "needs-more-evidence",
                "severity": "P3",
            }
            ws.set_severity_verdict(low["id"], low_verdict)
            low_revised = ws.revise_finding(
                low["id"], reason="Add medium-severity evidence.",
                evidence="flows/medium-new.http",
            )
            self.assertEqual(low_revised["manager_verdict"], low_verdict)
            self.assertEqual(low_revised["status"], "needs-more-evidence")
            self.assertNotIn(ASTRA_REVALIDATION_REVISION_FIELD, low_revised)

    def test_revalidation_write_rejects_a_stale_evidence_revision(self):
        with isolated_runtime():
            ws = Workspace("revision-stale-validation")
            ws.create("https://example.test", "web")
            finding = ws.record_finding(
                title="Critical candidate", severity="P1",
                evidence="flows/initial.http",
            )
            ws.set_severity_verdict(finding["id"], {
                "finding_id": finding["id"],
                "verdict": "needs-more-evidence", "severity": "P1",
            })
            first = ws.revise_finding(
                finding["id"], reason="Add the first control.",
                evidence="flows/control-one.http",
            )
            second = ws.revise_finding(
                finding["id"], reason="Replace it with a complete control.",
                evidence="flows/control-two.http",
            )
            self.assertEqual(
                first[ASTRA_REVALIDATION_REVISION_FIELD], "R001",
            )
            self.assertEqual(
                second[ASTRA_REVALIDATION_REVISION_FIELD], "R002",
            )

            verdict = {
                "finding_id": finding["id"], "verdict": "confirm",
                "severity": "P1", "reasoning": "Validated current evidence.",
            }
            _record, stale_applied = ws.set_severity_verdict_if_absent(
                finding["id"], verdict,
                expected_revalidation_revision="R001",
            )
            self.assertFalse(stale_applied)
            still_pending = ws.findings.find(finding["id"])
            self.assertIsNone(still_pending["manager_verdict"])
            self.assertEqual(
                still_pending[ASTRA_REVALIDATION_REVISION_FIELD], "R002",
            )

            current, current_applied = ws.set_severity_verdict_if_absent(
                finding["id"], verdict,
                expected_revalidation_revision="R002",
            )
            self.assertTrue(current_applied)
            self.assertEqual(current["status"], "confirmed")
            self.assertNotIn(ASTRA_REVALIDATION_REVISION_FIELD, current)


if __name__ == "__main__":
    unittest.main()
