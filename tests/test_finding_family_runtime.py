from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from grypton import config
from grypton.engine import Engine
from grypton.manager import Directive, KryptexManager
from grypton.runtime import _health
from grypton.workspace import Workspace


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
            "OPENCODE_WORKSPACES_DIR": root / ".opencode-workspaces",
            "TARGET_DATA_DIR": root / "target",
        }
        with patch.multiple(config, **values):
            config.ensure_layout()
            yield root


def record_family(ws: Workspace, title: str, root_cause: str, *,
                  severity: str = "P3", family_id: str = "") -> dict:
    return ws.record_finding(
        title=title,
        severity=severity,
        vuln_class="cache poisoning",
        surface=f"/{title.lower().replace(' ', '-')}",
        description="Observed response differs from its control.",
        poc="request then control",
        evidence="flows/case.http",
        root_cause=root_cause,
        family_id=family_id,
        case_kind="host and path variant",
    )


class FindingFamilyRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_existing_family_case_is_not_family_novelty_but_still_validates(self):
        with isolated_runtime(), patch.multiple(
            config.CONFIG,
            max_turns=1,
            max_run_seconds=0,
            stop_on_p1=False,
            passive_stagnation_limit=99,
            repetitive_probe_turn_limit=99,
            exhaustion_threshold=99,
        ):
            ws = Workspace("existing-family-runtime")
            ws.create("https://example.test", "web")
            anchor = record_family(ws, "Anchor case", "Unkeyed forwarding header")
            events: list[tuple[str, dict]] = []
            engine = Engine(
                ws.slug,
                backend="mock",
                emit=lambda kind, **payload: events.append((kind, payload)),
            )
            await engine.setup(
                brief="test related variants",
                target="https://example.test",
                target_type="web",
            )

            def worker_script(_worker, _directive):
                record_family(
                    engine.ws,
                    "Critical path variant",
                    "",
                    severity="P1",
                    family_id=anchor["id"],
                )
                return "Recorded a second evidence case for the existing family."

            validated: list[str] = []

            async def validate(finding, _ctx, *, explicit=False):
                self.assertFalse(explicit)
                validated.append(finding["id"])
                return {
                    "finding_id": finding["id"],
                    "verdict": "confirm",
                    "severity": "P1",
                    "confidence": 0.98,
                    "reasoning": "Independent case-level confirmation.",
                }

            contexts = []
            engine.worker.script = worker_script
            engine.manager.validate_severity = validate
            engine.manager.direct = AsyncMock(side_effect=lambda ctx: (
                contexts.append(ctx) or Directive(directive="Test another route.")
            ))

            await engine.run()

            self.assertEqual(validated, ["F002"])
            self.assertEqual(
                [payload["finding"]["id"] for kind, payload in events
                 if kind == "finding"],
                ["F002"],
            )
            self.assertEqual(contexts[0].novel_finding_families, 0)
            self.assertEqual(len(contexts[0].new_findings), 1)
            self.assertEqual(contexts[0].new_findings[0]["status"], "confirmed")
            self.assertEqual(engine._exhaustion_streak, 1)
            self.assertEqual(engine._passive_stagnation_streak, 1)
            catalog = engine.ws.finding_family_catalog()
            self.assertEqual(len(catalog), 1)
            self.assertEqual(catalog[0]["case_count"], 2)
            self.assertEqual(
                catalog[0]["cases"][1]["astra"],
                {"verdict": "confirm", "severity": "P1"},
            )

    async def test_convergence_waits_for_existing_family_case_validation(self):
        with isolated_runtime(), patch.multiple(
            config.CONFIG,
            max_turns=2,
            max_run_seconds=0,
            stop_on_p1=False,
            passive_stagnation_limit=1,
            repetitive_probe_turn_limit=99,
            exhaustion_threshold=99,
        ):
            ws = Workspace("family-validation-at-convergence")
            ws.create("https://example.test", "web")
            anchor = record_family(ws, "Anchor case", "Shared parser boundary")
            engine = Engine(ws.slug, backend="mock")
            await engine.setup(
                brief="test related variants",
                target="https://example.test",
                target_type="web",
            )

            def worker_script(_worker, _directive):
                record_family(
                    engine.ws,
                    "High impact variant",
                    "",
                    severity="P2",
                    family_id=anchor["id"],
                )
                return "Recorded another case in the existing family."

            validated = []

            async def validate(finding, _ctx, *, explicit=False):
                validated.append(finding["id"])
                return {
                    "finding_id": finding["id"],
                    "verdict": "confirm",
                    "severity": "P2",
                    "confidence": 0.96,
                    "reasoning": "Independent validation completed.",
                }

            engine.worker.script = worker_script
            engine.manager.validate_severity = validate
            engine.manager.direct = AsyncMock(
                return_value=Directive(directive="Test another route.")
            )
            engine._convergence_alerted = True

            await engine.run()

            self.assertEqual(validated, ["F002"])
            engine.manager.direct.assert_not_awaited()
            self.assertIn("convergence guard", engine.stop_reason)
            self.assertEqual(
                engine.ws.findings.find("F002")["manager_verdict"]["severity"],
                "P2",
            )

    async def test_needs_more_evidence_gets_one_manager_verification_turn(self):
        with isolated_runtime(), patch.multiple(
            config.CONFIG,
            max_turns=3,
            max_run_seconds=0,
            stop_on_p1=False,
            passive_stagnation_limit=1,
            repetitive_probe_turn_limit=99,
            exhaustion_threshold=99,
        ):
            ws = Workspace("family-needs-evidence")
            ws.create("https://example.test", "web")
            anchor = record_family(ws, "Anchor case", "Shared parser boundary")
            engine = Engine(ws.slug, backend="mock")
            await engine.setup(
                brief="test related variants",
                target="https://example.test",
                target_type="web",
            )
            worker_turns = []

            def worker_script(_worker, directive):
                worker_turns.append(directive)
                if len(worker_turns) == 1:
                    record_family(
                        engine.ws,
                        "High impact variant",
                        "",
                        severity="P2",
                        family_id=anchor["id"],
                    )
                return "Recorded the current verification state."

            exact_check = "Repeat the control request with the cache-buster removed."

            async def validate(finding, _ctx, *, explicit=False):
                return {
                    "finding_id": finding["id"],
                    "verdict": "needs-more-evidence",
                    "severity": "P2",
                    "confidence": 0.61,
                    "reasoning": "ASTRA_REASONING_MUST_NOT_REACH_SPARK",
                    "independent_checks": [exact_check],
                }

            manager_contexts = []

            async def direct(ctx):
                manager_contexts.append(ctx)
                prompt = engine.manager._build_direction_prompt(ctx)
                self.assertIn(exact_check, prompt)
                self.assertNotIn("ASTRA_REASONING_MUST_NOT_REACH_SPARK", prompt)
                return Directive(
                    directive="Perform Astra's requested control check.",
                    cont=False,
                    stop_reason="convergence: no new family",
                )

            engine.worker.script = worker_script
            engine.manager.validate_severity = validate
            engine.manager.direct = direct

            await engine.run()

            self.assertEqual(engine.turn_index, 2)
            self.assertEqual(len(worker_turns), 2)
            self.assertEqual(len(manager_contexts), 1)
            self.assertEqual(
                manager_contexts[0].new_finding_cases[0]["astra"]
                ["independent_checks"],
                [exact_check],
            )
            self.assertEqual(
                engine.ws.findings.find("F002")["status"],
                "needs-more-evidence",
            )
            self.assertIn("convergence guard", engine.stop_reason)

    def test_new_case_projection_has_strict_per_field_and_check_bounds(self):
        case = Engine._manager_case_projection([{
            "id": "F" * 80,
            "title": "t" * 500,
            "severity": "P2" * 20,
            "status": "needs-more-evidence" * 10,
            "surface": "/" + ("route/" * 100),
            "description": "DESCRIPTION_MUST_NOT_APPEAR",
            "poc": "POC_MUST_NOT_APPEAR",
            "evidence": "EVIDENCE_MUST_NOT_APPEAR",
            "manager_verdict": {
                "verdict": "needs-more-evidence",
                "severity": "P2",
                "independent_checks": ["x" * 500 for _ in range(10)],
                "reasoning": "REASONING_MUST_NOT_APPEAR",
            },
        }])[0]

        self.assertEqual(len(case["id"]), 32)
        self.assertEqual(len(case["title"]), 300)
        self.assertEqual(len(case["severity"]), 16)
        self.assertEqual(len(case["status"]), 64)
        self.assertEqual(len(case["surface"]), 300)
        self.assertEqual(len(case["astra"]["independent_checks"]), 8)
        self.assertTrue(all(
            len(check) == 300
            for check in case["astra"]["independent_checks"]
        ))
        rendered = json.dumps(case)
        for marker in (
            "DESCRIPTION_MUST_NOT_APPEAR", "POC_MUST_NOT_APPEAR",
            "EVIDENCE_MUST_NOT_APPEAR", "REASONING_MUST_NOT_APPEAR",
        ):
            self.assertNotIn(marker, rendered)

    def test_legacy_singleton_is_a_new_active_family(self):
        with isolated_runtime():
            ws = Workspace("legacy-family-runtime")
            ws.create("example.test", "web")
            engine = Engine(ws.slug, backend="mock")
            engine._counts = (0, 0)
            engine._active_family_ids = set()

            finding = ws.record_finding(title="Legacy case", severity="P3")
            cases, new_family_ids, surface = engine._deltas()

            self.assertEqual([row["id"] for row in cases], [finding["id"]])
            self.assertEqual(new_family_ids, {finding["id"]})
            self.assertEqual(surface, 0)
            self.assertTrue(ws.finding_family_catalog()[0]["virtual"])

    def test_relink_merge_cannot_create_false_or_negative_family_novelty(self):
        with isolated_runtime():
            ws = Workspace("family-merge-runtime")
            ws.create("example.test", "web")
            first = record_family(ws, "First anchor", "Parser trust flaw")
            second = record_family(ws, "Second anchor", "Cache key mismatch")
            engine = Engine(ws.slug, backend="mock")
            rows = ws.findings.all()
            engine._counts = (len(rows), 0)
            engine._active_family_ids = engine._finding_family_ids(rows)

            ws.link_finding_family(
                second["id"],
                first["id"],
                reason="Both cases use the same parser boundary.",
                case_kind="alternate host",
            )
            cases, new_family_ids, surface = engine._deltas()

            self.assertEqual(cases, [])
            self.assertEqual(new_family_ids, set())
            self.assertEqual(surface, 0)
            self.assertEqual(engine._active_family_ids, {first["id"]})
            self.assertEqual(ws.finding_family_catalog()[0]["case_count"], 2)

    def test_compact_manager_projection_is_complete_and_excludes_case_secrets(self):
        with isolated_runtime():
            ws = Workspace("compact-family-context")
            ws.create("https://example.test", "web")
            ids = []
            for number in range(24):
                row = ws.record_finding(
                    title=f"Family {number:02d} " + ("long-title-" * 18),
                    severity="P3",
                    vuln_class="cache poisoning",
                    surface=f"/route/{number}/" + ("segment/" * 8),
                    description=f"DESCRIPTION_SECRET_{number}",
                    poc=f"POC_SECRET_{number}",
                    evidence=f"EVIDENCE_SECRET_{number}",
                    root_cause=f"Distinct parser cause {number}",
                    case_kind="host and path variant",
                )
                ids.append(row["id"])
            ws.set_severity_verdict(ids[-1], {
                "finding_id": ids[-1],
                "verdict": "confirm",
                "severity": "P3",
                "confidence": 0.91,
                "reasoning": "ASTRA_REASONING_SECRET",
                "independent_checks": ["Retest with an uncached control."],
            })
            engine = Engine(ws.slug, backend="mock")
            engine.target = "https://example.test"
            engine.target_type = "web"

            ctx = engine._build_context(
                None, [ws.findings.find(ids[-1])], [], False, []
            )
            projection = json.dumps(ctx.finding_families, ensure_ascii=False)
            self.assertGreater(len(projection), 3000)
            self.assertGreater(projection.index(ids[-1]), 3000)
            self.assertEqual(
                {family["family_id"] for family in ctx.finding_families},
                set(ids),
            )
            last_case = ctx.finding_families[-1]["cases"][0]
            self.assertEqual(last_case["astra"], {
                "verdict": "confirm", "severity": "P3",
            })
            for key in ("title", "severity", "status", "surface", "astra"):
                self.assertIn(key, last_case)
            self.assertEqual(
                ctx.new_finding_cases[0]["astra"]["independent_checks"],
                ["Retest with an uncached control."],
            )

            manager = KryptexManager(ws, "static manager prompt")
            direction = manager._build_direction_prompt(ctx)
            chat = manager._build_chat_prompt("continue", ctx)
            for rendered in (projection, direction, chat):
                self.assertIn(ids[0], rendered)
                self.assertIn(ids[-1], rendered)
                self.assertNotIn("EVIDENCE_SECRET", rendered)
                self.assertNotIn("POC_SECRET", rendered)
                self.assertNotIn("DESCRIPTION_SECRET", rendered)
                self.assertNotIn("ASTRA_REASONING_SECRET", rendered)
            self.assertIn("CONFIRMED P1 CASE COUNT", direction)

    def test_runtime_health_preserves_findings_and_adds_family_case_counts(self):
        with isolated_runtime():
            missing_root = config.ENGAGEMENTS_DIR / "missing-health"
            missing = _health("missing-health", 0)
            self.assertEqual(missing["finding_cases"], 0)
            self.assertEqual(missing["finding_families"], 0)
            self.assertFalse(missing_root.exists())

            ws = Workspace("family-runtime-health")
            ws.create("example.test", "web")
            ws.record_finding(title="Legacy singleton", severity="P3")
            anchor = record_family(ws, "Structured anchor", "Shared cache parser")
            record_family(ws, "Structured variant", "", family_id=anchor["id"])

            health = _health(ws.slug, 0)
            self.assertEqual(health["findings"], 3)
            self.assertEqual(health["finding_cases"], 3)
            self.assertEqual(health["finding_families"], 2)

            with patch.object(
                Workspace,
                "finding_family_catalog",
                side_effect=ValueError("damaged family metadata"),
            ):
                degraded = _health(ws.slug, 0)
            self.assertEqual(degraded["findings"], 3)
            self.assertEqual(degraded["finding_cases"], 3)
            self.assertEqual(degraded["finding_families"], 0)

    def test_runtime_health_fails_closed_on_invalid_family_links(self):
        with isolated_runtime():
            ws = Workspace("invalid-family-runtime-health")
            ws.create("example.test", "web")
            finding = record_family(ws, "Broken child", "Shared cache parser")
            rows = ws.findings.all()
            rows[0]["family_id"] = "F999"
            rows[0]["family_history"][-1]["to_family_id"] = "F999"
            ws.findings.path.write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )

            self.assertEqual(finding["id"], "F001")
            with self.assertRaisesRegex(ValueError, "missing family anchor F999"):
                ws.finding_family_catalog()
            health = _health(ws.slug, 0)
            self.assertEqual(health["findings"], 1)
            self.assertEqual(health["finding_cases"], 1)
            self.assertEqual(health["finding_families"], 0)


if __name__ == "__main__":
    unittest.main()
