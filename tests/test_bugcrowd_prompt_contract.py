from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from grypton import config
from grypton.bugcrowd import analyze_snapshot, structured_scope
from grypton.cli import _constraints, cmd_init
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


def snapshot(*, automation_prohibited: bool = False) -> dict:
    description = (
        "Must use the assigned credentials and follow the program conduct guide."
    )
    if automation_prohibited:
        description += " Use of any automated tools/scanners is strictly prohibited."
    return {
        "id": "synthetic",
        "data": {
            "brief": {"description": description},
            "outOfScopeFindingCategories": ["Clickjacking", "Open Redirect"],
            "conditionalOutOfScopeFindings": ["CORS without demonstrated impact"],
            "scope": [
                {
                    "name": "Critical web",
                    "inScope": True,
                    "maxSeverity": "P1",
                    "targets": [
                        {"name": "app", "uri": "https://example.test/app",
                         "category": "website"},
                        {"name": "help", "uri": "https://example.test/help",
                         "category": "website", "maxSeverity": "P3"},
                    ],
                },
                {
                    "name": "excluded assets",
                    "inScope": False,
                    "targets": [
                        {"name": "admin", "uri": "https://admin.example.test",
                         "category": "website"},
                    ],
                },
            ],
        },
    }


def namespace(path: Path, **overrides) -> SimpleNamespace:
    values = {
        "bugcrowd_brief": str(path), "only": "", "exclude": "", "include": "",
        "in_scope": "", "out_scope": "", "rule": [], "authorization_file": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


class BugcrowdPromptContractTests(unittest.TestCase):
    def test_structured_import_projects_only_allowed_worker_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "brief.json"
            path.write_text(json.dumps(snapshot()), encoding="utf-8")
            profile = analyze_snapshot(path)
            imported = structured_scope(profile)
            self.assertEqual(imported, {
                "in_scope": ["https://example.test/app", "https://example.test/help"],
                "url_severities": {
                    "https://example.test/app": "Critical",
                    "https://example.test/help": "Medium",
                },
                "out_of_scope_finding_categories": ["Clickjacking", "Open Redirect"],
                "conditional_out_of_scope_findings": [
                    "CORS without demonstrated impact"
                ],
            })

            constraints = _constraints(namespace(path), "https://example.test/app")
            self.assertEqual(constraints.in_scope, imported["in_scope"])
            self.assertEqual(constraints.url_severities, imported["url_severities"])
            self.assertEqual(constraints.excluded_classes,
                             imported["out_of_scope_finding_categories"])
            self.assertEqual(constraints.conditional_exclusions,
                             imported["conditional_out_of_scope_findings"])
            self.assertEqual(constraints.out_of_scope, ["https://admin.example.test"])
            self.assertEqual(constraints.hard_rules, [])
            self.assertEqual(constraints.standing_instructions, [])
            self.assertEqual(constraints.notes, "")

            prompt = constraints.to_worker_prompt_block()
            self.assertNotIn("assigned credentials", prompt)
            self.assertNotIn("conduct", prompt.lower())
            self.assertNotIn("admin.example.test", prompt)
            self.assertNotIn("Do not", prompt)
            self.assertEqual(prompt.splitlines(), [
                "=== ENGAGEMENT DATA ===",
                "- In scope: https://example.test/app — severity: Critical",
                "- In scope: https://example.test/help — severity: Medium",
                "- Out-of-scope finding categories: Clickjacking, Open Redirect",
                "- Conditional out-of-scope finding: CORS without demonstrated impact",
            ])

    def test_structured_vrt_rules_become_finding_policy_without_brief_prose(self):
        document = snapshot()
        document["data"]["vrtScopeRules"] = [
            {
                "disposition": "out_of_scope",
                "categories": ["Server-Side Request Forgery"],
                "targets": [{"name": "Public API"}],
            },
            {
                "status": "excluded",
                "vrtItems": [{"name": "Missing Security Headers"}],
            },
            {
                "status": "informational",
                "categories": ["Conduct prose must not be imported"],
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "brief.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            imported = structured_scope(analyze_snapshot(path))
        self.assertIn(
            "Server-Side Request Forgery: applies to Public API",
            imported["conditional_out_of_scope_findings"],
        )
        self.assertIn(
            "Missing Security Headers",
            imported["out_of_scope_finding_categories"],
        )
        self.assertFalse(any(
            "Conduct prose" in value
            for key in ("out_of_scope_finding_categories",
                        "conditional_out_of_scope_findings")
            for value in imported[key]
        ))

    def test_import_rejects_selected_scope_with_missing_severity(self):
        document = snapshot()
        document["data"]["scope"].append({
            "name": "unlabelled web",
            "inScope": True,
            "targets": [{
                "name": "unlabelled",
                "uri": "https://unlabelled.example.test",
                "category": "website",
            }],
        })
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "brief.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError,
                r"missing an explicit severity: https://unlabelled\.example\.test",
            ):
                _constraints(namespace(path), "https://example.test/app")

    def test_free_form_group_title_is_not_inferred_as_severity(self):
        document = snapshot()
        document["data"]["scope"].append({
            "name": "High value web assets",
            "inScope": True,
            "targets": [{
                "name": "unlabelled",
                "uri": "https://unlabelled.example.test",
                "category": "website",
            }],
        })
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "brief.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            profile = analyze_snapshot(path)
            imported = structured_scope(profile)
            self.assertNotIn(
                "https://unlabelled.example.test",
                imported["url_severities"],
            )
            with self.assertRaisesRegex(
                ValueError,
                r"missing an explicit severity: https://unlabelled\.example\.test",
            ):
                _constraints(namespace(path), "https://example.test/app")

    def test_explicit_selection_accepts_only_labelled_program_scope(self):
        document = snapshot()
        document["data"]["scope"].append({
            "name": "unlabelled web",
            "inScope": True,
            "targets": [{
                "name": "unlabelled",
                "uri": "https://unlabelled.example.test",
                "category": "website",
            }],
        })
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "brief.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            constraints = _constraints(namespace(
                path, in_scope="https://example.test/app"
            ), "https://example.test/app")

        self.assertEqual(constraints.in_scope, ["https://example.test/app"])
        self.assertEqual(constraints.url_severities, {
            "https://example.test/app": "Critical",
        })

    def test_automation_incompatibility_is_rejected_before_constraints_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "brief.json"
            path.write_text(json.dumps(snapshot(automation_prohibited=True)), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "incompatible"):
                _constraints(namespace(path), "https://example.test/app")

    def test_init_keeps_raw_program_private_and_worker_projection_sanitized(self):
        with isolated_runtime() as root:
            path = root / "brief.json"
            path.write_text(json.dumps(snapshot()), encoding="utf-8")
            ns = namespace(
                path,
                target="https://example.test/app", target_option="", type="web",
                force=False, brief="Inspect the imported scope.",
            )
            with patch("grypton.cli._run_engagement", return_value=0):
                self.assertEqual(cmd_init(ns), 0)

            ws = Workspace(config.slugify("https://example.test/app"))
            brief = ws.program_brief_path.read_text()
            profile = json.loads(ws.program_profile_path.read_text())
            self.assertIn("assigned credentials", brief)
            self.assertIn("conduct", brief.lower())
            self.assertTrue(profile["credential_requirement"])

            worker_scope = (ws.root / "scope-rules.md").read_text()
            self.assertNotIn("assigned credentials", worker_scope)
            self.assertNotIn("conduct", worker_scope.lower())
            self.assertNotIn("automation", worker_scope.lower())
            self.assertNotIn("admin.example.test", worker_scope)
            self.assertIn(
                "https://example.test/app — severity: Critical", worker_scope
            )
            self.assertIn(
                "Out-of-scope finding categories: Clickjacking, Open Redirect",
                worker_scope,
            )
            self.assertFalse((ws.root / "program-brief.md").exists())
            self.assertFalse((ws.root / ".ledger/program-profile.json").exists())


if __name__ == "__main__":
    unittest.main()
