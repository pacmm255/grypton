import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from grypton import config
from grypton.engine import Engine
from grypton.providers import OpenCodeClient
from grypton.toolserver import REGISTRY, dispatch
from grypton.workspace import Constraints, Workspace


class WorkerContextBoundaryTests(unittest.TestCase):
    def _runtime(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        patches = patch.multiple(
            config,
            STATE_DIR=root / ".state",
            ENGAGEMENTS_DIR=root / ".state/engagements",
            TARGETS_DIR=root / ".state/engagements",
            RUNTIME_DIR=root / ".state/runtime",
            LOG_DIR=root / ".state/runtime/logs",
            PROVIDER_DIR=root / ".state/providers",
            CREDENTIALS_DIR=root / ".state/credentials",
            OPENCODE_WORKSPACES_DIR=root / ".opencode-workspaces",
            TARGET_DATA_DIR=root / "target",
        )
        return temporary, root, patches

    def test_worker_workspace_contains_only_projected_scope(self):
        temporary, root, patches = self._runtime()
        with temporary, patches:
            ws = Workspace("strict-context")
            ws.create("https://example.test/app", "web")
            constraints = Constraints(
                in_scope=["https://example.test/app"],
                url_severities={"https://example.test/app": "High"},
                excluded_classes=["clickjacking"],
                conditional_exclusions=["CORS without demonstrated impact"],
                hard_rules=["manager-only hard rule"],
                standing_instructions=["manager-only standing instruction"],
                notes="manager-only note",
            )
            ws.save_constraints(constraints)
            ws.save_program_brief(
                "manager-only program prose",
                {"brief_text": "manager-only program prose", "program": "fixture"},
            )

            self.assertFalse((ws.root / ".ledger/scope-rules.json").exists())
            self.assertFalse((ws.root / "program-brief.md").exists())
            self.assertFalse((ws.root / ".ledger/program-profile.json").exists())
            self.assertTrue(ws.constraints_path.is_file())
            self.assertTrue(ws.program_brief_path.is_file())
            self.assertTrue(ws.program_profile_path.is_file())
            self.assertFalse(ws.constraints_path.is_relative_to(ws.root))
            for directory in (
                root / ".state/operator",
                root / ".state/operator/engagements",
                ws._operator_state_dir,
            ):
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

            scope = (ws.root / "scope-rules.md").read_text(encoding="utf-8")
            self.assertIn("https://example.test/app — severity: High", scope)
            self.assertIn("clickjacking", scope)
            self.assertIn("CORS without demonstrated impact", scope)
            for private_value in (
                "manager-only hard rule",
                "manager-only standing instruction",
                "manager-only note",
                "manager-only program prose",
            ):
                self.assertNotIn(private_value, scope)

            loaded = ws.load_constraints()
            self.assertEqual(loaded.hard_rules, ["manager-only hard rule"])
            self.assertEqual(
                loaded.standing_instructions,
                ["manager-only standing instruction"],
            )
            self.assertEqual(loaded.notes, "manager-only note")

            scope_result = dispatch(ws, "read_doc", {"name": "scope"})
            self.assertTrue(scope_result["ok"])
            self.assertIn("https://example.test/app", scope_result["data"]["text"])
            program_result = dispatch(ws, "read_doc", {"name": "program"})
            self.assertFalse(program_result["ok"])
            self.assertNotIn(
                "program",
                REGISTRY["read_doc"][1]["properties"]["name"]["enum"],
            )

    def test_ordinary_create_and_save_keep_legacy_process_compatible(self):
        temporary, root, patches = self._runtime()
        with temporary, patches:
            ws = Workspace("legacy-context")
            ws.create("https://legacy.test", "web")
            ws.constraints_path.unlink()
            legacy_constraints = ws.root / ".ledger/scope-rules.json"
            legacy_constraints.write_text(
                json.dumps({
                    "in_scope": ["https://legacy.test"],
                    "hard_rules": ["legacy manager-only rule"],
                }),
                encoding="utf-8",
            )
            legacy_brief = ws.root / "program-brief.md"
            legacy_profile = ws.root / ".ledger/program-profile.json"
            legacy_brief.write_text("legacy private prose", encoding="utf-8")
            legacy_profile.write_text('{"program":"legacy"}', encoding="utf-8")

            # Re-running create may overlap an old-code engine. It mirrors the
            # controls privately without removing the old engine's live files.
            ws.create("https://legacy.test", "web")
            loaded = ws.load_constraints()

            self.assertEqual(loaded.in_scope, ["https://legacy.test"])
            self.assertEqual(loaded.hard_rules, ["legacy manager-only rule"])
            self.assertTrue(legacy_constraints.is_file())
            self.assertTrue(legacy_brief.is_file())
            self.assertTrue(legacy_profile.is_file())
            self.assertEqual(
                ws.program_brief_path.read_text(encoding="utf-8"),
                "legacy private prose",
            )
            self.assertEqual(
                json.loads(ws.program_profile_path.read_text(encoding="utf-8")),
                {"program": "legacy"},
            )

            updated = Constraints(
                in_scope=["https://legacy.test/new"],
                hard_rules=["updated manager-only rule"],
            )
            ws.save_constraints(updated)
            self.assertEqual(
                json.loads(legacy_constraints.read_text(encoding="utf-8")),
                json.loads(ws.constraints_path.read_text(encoding="utf-8")),
            )
            self.assertEqual(
                ws.load_constraints().hard_rules,
                ["updated manager-only rule"],
            )

    def test_native_worker_tools_are_enabled_but_manager_stays_toolless(self):
        worker = OpenCodeClient._permissions(True)
        for name in ("bash", "task"):
            self.assertEqual(worker[name], "allow")
        for name in ("read", "edit", "glob", "grep", "list"):
            self.assertEqual(worker[name]["*"], "deny")
        self.assertEqual(worker["webfetch"], "deny")
        self.assertEqual(worker["websearch"], "deny")
        self.assertEqual(worker["question"], "deny")

        manager = OpenCodeClient._permissions(False)
        self.assertEqual(manager["*"], "deny")
        self.assertEqual(manager["external_directory"], "deny")


class EngineLegacyHandoffTests(unittest.IsolatedAsyncioTestCase):
    async def test_setup_retires_legacy_files_without_losing_controls(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
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
        with temporary, patch.multiple(config, **values):
            ws = Workspace("engine-handoff")
            ws.create("https://handoff.test", "web")
            ws.constraints_path.unlink()
            legacy_constraints = ws.root / ".ledger/scope-rules.json"
            legacy_brief = ws.root / "program-brief.md"
            legacy_profile = ws.root / ".ledger/program-profile.json"
            legacy_constraints.write_text(json.dumps({
                "in_scope": ["https://handoff.test/exact"],
                "url_severities": {
                    "https://handoff.test/exact": "Critical",
                },
                "hard_rules": ["retained manager-only rule"],
            }), encoding="utf-8")
            legacy_brief.write_text("retained private prose", encoding="utf-8")
            legacy_profile.write_text(
                '{"program":"retained"}', encoding="utf-8"
            )

            engine = Engine(ws.slug, backend="mock")
            await engine.setup(
                brief="Assess the exact scope.",
                target="https://handoff.test",
                target_type="web",
                fresh_clone=False,
            )

            self.assertFalse(legacy_constraints.exists())
            self.assertFalse(legacy_brief.exists())
            self.assertFalse(legacy_profile.exists())
            self.assertTrue(ws._legacy_retired_path.is_file())
            loaded = ws.load_constraints()
            self.assertEqual(loaded.in_scope, ["https://handoff.test/exact"])
            self.assertEqual(
                loaded.hard_rules,
                ["retained manager-only rule"],
            )
            self.assertEqual(
                ws.program_brief_path.read_text(encoding="utf-8"),
                "retained private prose",
            )
            self.assertEqual(
                json.loads(ws.program_profile_path.read_text(encoding="utf-8")),
                {"program": "retained"},
            )
            scope = (ws.root / "scope-rules.md").read_text(encoding="utf-8")
            self.assertIn(
                "https://handoff.test/exact — severity: Critical",
                scope,
            )
            self.assertNotIn("retained manager-only rule", scope)

            # An old path recreated after handoff is untrusted worker input,
            # not a reason to reopen compatibility mode or widen scope.
            legacy_constraints.write_text(json.dumps({
                "in_scope": ["https://attacker.invalid"],
            }), encoding="utf-8")
            loaded = ws.load_constraints()
            self.assertEqual(loaded.in_scope, ["https://handoff.test/exact"])
            self.assertFalse(legacy_constraints.exists())


if __name__ == "__main__":
    unittest.main()
