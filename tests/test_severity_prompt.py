from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from grypton import config
from grypton.manager import (KryptexManager, ManagerContext, _check_schema,
                             load_severity_rubric)
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
            "CREDENTIALS_DIR": root / ".state/credentials",
            "OPENCODE_WORKSPACES_DIR": root / ".opencode-workspaces",
            "TARGET_DATA_DIR": root / "target",
        }
        with patch.multiple(config, **values):
            config.ensure_layout()
            yield root


def _finding() -> dict:
    return {
        "id": "F001",
        "title": "Object-level access control candidate",
        "severity": "P2",
        "vuln_class": "Broken access control",
        "surface": "web api",
        "description": (
            "Saved positive and control artifacts show an object-owner "
            "differential across two principals."
        ),
        "evidence": "flows/flow-1.http",
        "evidence_package": {
            "package": {
                "positive_flow_id": "flow-101",
                "control_flow_id": "flow-102",
                "replay_flow_id": "flow-103",
                "second_run_flow_id": "flow-104",
            },
            "verified": {
                "evidence_chain_sha256": "c4a7" * 16,
                "digests": {
                    "flow-101": {"response_status": 200,
                                 "response_body_sha256": "a" * 64,
                                 "response_body_bytes": 48},
                    "flow-102": {"response_status": 403,
                                 "response_body_sha256": "b" * 64,
                                 "response_body_bytes": 21},
                    "flow-103": {"response_status": 200,
                                 "response_body_sha256": "a" * 64,
                                 "response_body_bytes": 48},
                    "flow-104": {"response_status": 200,
                                 "response_body_sha256": "a" * 64,
                                 "response_body_bytes": 48},
                },
            },
        },
    }


def _context() -> ManagerContext:
    return ManagerContext(target="127.0.0.1", target_type="web", turn_index=1)


class SeverityRubricTest(unittest.TestCase):
    def test_packaged_rubric_passes_manager_validation(self):
        rubric = load_severity_rubric()
        self.assertEqual(rubric["version"], 1)
        self.assertEqual(rubric["precedence"], [
            "program-specific rule", "pinned vrt node",
            "documented internal fallback",
        ])
        self.assertTrue(rubric["rules"])
        nodes = {row["vrt_node"] for row in rubric["vrt_fallback"]}
        self.assertIn("server_security_misconfiguration > rce", nodes)
        cases = {row["case"] for row in rubric["boundary_rulings"]}
        self.assertIn("self-xss", cases)

    def test_structurally_broken_rubric_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken_rubric.json"
            path.write_text(json.dumps({
                "version": 1,
                "precedence": ["pinned vrt node"],
                "rules": ["Rate the demonstrated operation only."],
                "vrt_fallback": [{
                    "vrt_node": "server_security_misconfiguration > rce",
                    "default_priority": "P1", "cvss4_template": "AV:N",
                }],
                "boundary_rulings": [{"case": "self-xss", "ruling": "P5"}],
            }, indent=2), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "vrt_fallback 0"):
                load_severity_rubric(path)

    def test_unparseable_rubric_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken_rubric.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not valid JSON"):
                load_severity_rubric(path)


class SeverityPromptTest(unittest.TestCase):
    def test_prompt_embeds_procedure_rubric_and_anchoring_control(self):
        with isolated_runtime():
            ws = Workspace("severity-prompt")
            ws.create("127.0.0.1", "web")
            manager = KryptexManager(ws, "system")
            prompt = manager._build_severity_prompt(_finding(), _context())

            self.assertIn("DECISION PROCEDURE", prompt)
            for anchor in (
                "Artifact presence", "Request identity", "Differential",
                "Reproducibility", "Client versus server", "Classify",
            ):
                self.assertIn(anchor, prompt)
            self.assertIn("needs-more-evidence", prompt)
            self.assertIn("THE RUBRIC", prompt)
            self.assertIn("Never convert CVSS score bands directly into P levels", prompt)
            self.assertIn("server_security_misconfiguration > rce", prompt)
            self.assertIn("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", prompt)
            self.assertIn(
                "self-xss: P5 unless an evidenced cross-user boundary exists", prompt
            )
            self.assertIn("ANCHORING CONTROL", prompt)
            self.assertIn("compare only after your independent rating", prompt)
            self.assertIn(
                "Worker-proposed severity (compare only after your independent rating): P2",
                prompt,
            )
            self.assertNotIn('"claimed_severity"', prompt)
            self.assertIn('"evidence_chain_id": "' + "c4a7" * 16 + '"', prompt)
            self.assertIn('"evidence_roles"', prompt)
            self.assertIn('"positive"', prompt)
            self.assertIn("flow-101", prompt)
            self.assertIn("evidence_chain_ack", prompt)
            self.assertIn("Return only JSON matching this schema", prompt)
            # Anchoring control precedes the dossier; the worker's proposal is
            # the last content the reviewer sees, after the evidence block and
            # immediately before the output guidance.
            self.assertLess(
                prompt.index("ANCHORING CONTROL"),
                prompt.index("FINDING DOSSIER:"),
            )
            self.assertGreater(
                prompt.index("Worker-proposed severity"),
                prompt.index("ABSTRACTED REFERENCED EVIDENCE"),
            )
            self.assertLess(
                prompt.index("Worker-proposed severity"),
                prompt.index("OUTPUT GUIDANCE"),
            )

    def test_prompt_hides_worker_severity_when_absent(self):
        with isolated_runtime():
            ws = Workspace("severity-prompt-default")
            ws.create("127.0.0.1", "web")
            manager = KryptexManager(ws, "system")
            finding = _finding()
            finding.pop("severity")
            finding.pop("evidence_package")
            prompt = manager._build_severity_prompt(finding, _context())
            self.assertIn(
                "Worker-proposed severity (compare only after your independent rating): P3",
                prompt,
            )
            self.assertNotIn("evidence_chain_id", prompt)


class SeveritySchemaTest(unittest.TestCase):
    def setUp(self):
        self.schema = json.loads(
            (config.PROMPTS_DIR / "severity_schema.json").read_text(encoding="utf-8")
        )

    def test_legacy_verdict_without_new_fields_validates(self):
        legacy = {
            "finding_id": "F001",
            "verdict": "confirm",
            "severity": "P2",
            "confidence": 0.8,
            "reasoning": "The saved digests prove the object-owner differential.",
            "independent_checks": [],
            "exploitability": "Requires one authenticated session.",
        }
        self.assertEqual(_check_schema(legacy, self.schema), [])

    def test_verdict_with_new_fields_validates(self):
        modern = {
            "finding_id": "F001",
            "verdict": "confirm",
            "severity": "P2",
            "confidence": 0.8,
            "reasoning": "The saved digests prove the object-owner differential.",
            "independent_checks": [],
            "exploitability": "Requires one authenticated session.",
            "vrt_node": "broken_access_control > idor_modify_others",
            "vrt_version": "1.9.3",
            "cvss_vector": "AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:L",
            "cvss_score": 7.7,
            "cvss_severity": "High",
            "severity_basis": "vrt_default: pinned node default P2",
            "evidence_chain_ack": "chain-7",
            "artifact_checklist": [{
                "claim": "One principal modifies another principal's object.",
                "satisfied": True,
                "proving_artifact_ids": ["flow-1.http"],
                "failing_or_missing_artifact_ids": [],
            }],
        }
        self.assertEqual(_check_schema(modern, self.schema), [])

    def test_new_fields_stay_strict(self):
        modern = {
            "finding_id": "F001", "verdict": "reject", "severity": "P5",
            "confidence": 0.7, "reasoning": "No saved differential exists.",
            "independent_checks": [], "exploitability": "",
            "cvss_severity": "catastrophic",
            "artifact_checklist": [{
                "claim": "Unproven claim.", "satisfied": False,
                "proving_artifact_ids": [],
                "failing_or_missing_artifact_ids": ["flow-1.http"],
                "extra": "not allowed",
            }],
        }
        errors = _check_schema(modern, self.schema)
        self.assertTrue(any("cvss_severity" in error for error in errors))
        self.assertTrue(any("artifact_checklist" in error for error in errors))
        extra = {
            "finding_id": "F001", "verdict": "reject", "severity": "P5",
            "confidence": 0.7, "reasoning": "No saved differential exists.",
            "independent_checks": [], "exploitability": "",
            "unexpected": "value",
        }
        self.assertTrue(any("unexpected" in error
                            for error in _check_schema(extra, self.schema)))


if __name__ == "__main__":
    unittest.main()
