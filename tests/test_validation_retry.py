from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from grypton import config
from grypton.engine import Engine
from grypton.manager import Directive, KryptexManager, ManagerContext
from grypton.runtime import _health
from grypton.workspace import Workspace


@contextmanager
def isolated_runtime():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        state = root / ".state"
        with patch.multiple(
            config,
            STATE_DIR=state,
            ENGAGEMENTS_DIR=state / "engagements",
            TARGETS_DIR=state / "engagements",
            RUNTIME_DIR=state / "runtime",
            LOG_DIR=state / "runtime/logs",
            PROVIDER_DIR=state / "providers",
            OPENCODE_WORKSPACES_DIR=root / ".opencode-workspaces",
            TARGET_DATA_DIR=root / "input-data",
        ):
            config.ensure_layout()
            yield


class ValidationRetryTests(unittest.TestCase):
    def test_suppressed_findings_do_not_reset_family_progress(self):
        self.assertEqual(
            Engine._finding_family_ids([
                {"id": "F001", "family_id": "F001", "status": "confirmed"},
                {"id": "F002", "family_id": "F002",
                 "status": "suppressed-by-scope"},
                {"id": "F003", "family_id": "F001",
                 "status": "validation-not-requested"},
            ]),
            {"F001"},
        )

    def test_degraded_manager_fallback_honors_active_rotation_then_fairs_backlog(self):
        manager = object.__new__(KryptexManager)
        backlog = [
            {"id": "F001", "independent_checks": ["first check"]},
            {"id": "F002", "independent_checks": ["second check"]},
        ]
        active = manager._fallback_directive(ManagerContext(
            target="example.test", target_type="web", turn_index=2,
            coverage_priority="Exercise the next workflow invariant.",
            validation_backlog=backlog,
        ), "provider unavailable")
        self.assertEqual(
            active.directive, "Exercise the next workflow invariant.",
        )

        proof = manager._fallback_directive(ManagerContext(
            target="example.test", target_type="web", turn_index=2,
            validation_backlog=backlog,
        ), "provider unavailable")
        self.assertIn("F002", proof.directive)
        self.assertIn("second check", proof.directive)

    def test_atomic_retry_replaces_only_degraded_validator_result(self):
        with isolated_runtime():
            ws = Workspace("validator-retry")
            ws.create("https://example.test", "web")
            finding = ws.record_finding(title="High candidate", severity="P2")
            degraded = {
                "finding_id": finding["id"],
                "verdict": "needs-more-evidence",
                "severity": "P2",
                "degraded": True,
            }
            ws.set_severity_verdict(finding["id"], degraded)

            decisive = {
                "finding_id": finding["id"],
                "verdict": "confirm",
                "severity": "P2",
                "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": config.VALIDATOR_EFFORT,
            }
            _record, applied = ws.set_severity_verdict_if_absent(
                finding["id"], decisive,
            )
            self.assertFalse(applied)
            self.assertTrue(ws.findings.find(finding["id"])["manager_verdict"]["degraded"])

            current, applied = ws.set_severity_verdict_if_absent(
                finding["id"], decisive, replace_degraded=True,
            )
            self.assertTrue(applied)
            self.assertEqual(current["status"], "confirmed")
            self.assertEqual(current["manager_verdict"]["verdict"], "confirm")

            later = dict(decisive, verdict="downgrade", severity="P3")
            current, applied = ws.set_severity_verdict_if_absent(
                finding["id"], later, replace_degraded=True,
            )
            self.assertFalse(applied)
            self.assertEqual(current["manager_verdict"]["severity"], "P2")

            malformed = ws.record_finding(
                title="Malformed validator result", severity="P1",
            )
            ws.set_severity_verdict(malformed["id"], {
                "finding_id": malformed["id"],
                "verdict": "unexpected-value",
                "severity": "P1",
                "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": config.VALIDATOR_EFFORT,
            })
            current, applied = ws.set_severity_verdict_if_absent(
                malformed["id"],
                dict(decisive, finding_id=malformed["id"]),
                replace_untrusted_validator=True,
            )
            self.assertTrue(applied)
            self.assertEqual(current["manager_verdict"]["verdict"], "confirm")

            malformed_degraded = ws.record_finding(
                title="Malformed degraded flag", severity="P2",
            )
            ws.set_severity_verdict(malformed_degraded["id"], {
                "finding_id": malformed_degraded["id"],
                "verdict": "confirm",
                "severity": "P2",
                "degraded": "true",
                "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": config.VALIDATOR_EFFORT,
            })
            self.assertEqual(
                [row["id"] for row in Engine._automatic_validation_candidates(
                    [ws.findings.find(malformed_degraded["id"])]
                )],
                [malformed_degraded["id"]],
            )
            current, applied = ws.set_severity_verdict_if_absent(
                malformed_degraded["id"],
                dict(decisive, finding_id=malformed_degraded["id"]),
                replace_degraded=True,
                replace_untrusted_validator=True,
            )
            self.assertTrue(applied)
            self.assertNotIn("degraded", current["manager_verdict"])

    def test_degraded_astra_result_reenters_validation_without_becoming_proof_work(self):
        with isolated_runtime():
            ws = Workspace("validator-transport-retry")
            ws.create("https://example.test", "web")
            evidence_gap = ws.record_finding(
                title="Evidence gap", severity="P2", surface="/account",
            )
            ws.set_severity_verdict(evidence_gap["id"], {
                "finding_id": evidence_gap["id"],
                "verdict": "needs-more-evidence",
                "severity": "P2",
                "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": config.VALIDATOR_EFFORT,
                "independent_checks": [
                    "Repeat with a fresh owner and peer control.",
                ],
            })
            transport_gap = ws.record_finding(
                title="Transport gap", severity="P1", surface="/admin",
            )
            ws.set_severity_verdict(transport_gap["id"], {
                "finding_id": transport_gap["id"],
                "verdict": "needs-more-evidence",
                "severity": "P1",
                "degraded": True,
                "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": config.VALIDATOR_EFFORT,
                "independent_checks": ["Retry Astra."],
            })
            decisive = ws.record_finding(
                title="Downgraded case", severity="P1", surface="/cache",
            )
            ws.set_severity_verdict(decisive["id"], {
                "finding_id": decisive["id"],
                "verdict": "downgrade",
                "severity": "P3",
                "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": config.VALIDATOR_EFFORT,
            })

            engine = Engine(ws.slug, backend="mock")
            retry_ids = [
                row["id"] for row in engine._validation_turn_findings([])
            ]
            self.assertEqual(retry_ids, [transport_gap["id"]])
            self.assertEqual(
                [row["id"] for row in Engine._automatic_validation_candidates(
                    ws.findings.all()
                )],
                [transport_gap["id"]],
            )

            backlog = Engine._high_severity_proof_backlog(ws.findings.all())
            self.assertEqual([row["id"] for row in backlog], [evidence_gap["id"]])
            self.assertEqual(
                backlog[0]["independent_checks"],
                ["Repeat with a fresh owner and peer control."],
            )
            engine.target = "https://example.test"
            engine.target_type = "web"
            context = engine._build_context(None, [], [], False, [])
            self.assertEqual(
                [row["id"] for row in context.validation_backlog],
                [evidence_gap["id"]],
            )

    def test_astra_assessed_lower_severity_is_not_forced_as_proof_work(self):
        with isolated_runtime():
            ws = Workspace("assessed-proof-severity")
            ws.create("https://example.test", "web")
            low = ws.record_finding(
                title="Claimed critical but bounded", severity="P1",
            )
            ws.set_severity_verdict(low["id"], {
                "finding_id": low["id"],
                "verdict": "needs-more-evidence",
                "severity": "P5",
                "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": config.VALIDATOR_EFFORT,
                "independent_checks": ["Obtain an unavailable server-side fact."],
            })
            high = ws.record_finding(
                title="Plausibly high impact", severity="P2",
            )
            ws.set_severity_verdict(high["id"], {
                "finding_id": high["id"],
                "verdict": "needs-more-evidence",
                "severity": "P2",
                "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": config.VALIDATOR_EFFORT,
                "independent_checks": ["Capture one owner/peer control pair."],
            })

            backlog = Engine._high_severity_proof_backlog(ws.findings.all())
            self.assertEqual([row["id"] for row in backlog], [high["id"]])

    def test_degraded_validation_retry_uses_bounded_turn_cadence(self):
        with isolated_runtime():
            ws = Workspace("validation-retry-cadence")
            ws.create("https://example.test", "web")
            finding = ws.record_finding(title="Transport retry", severity="P1")
            ws.set_severity_verdict(finding["id"], {
                "finding_id": finding["id"],
                "verdict": "needs-more-evidence",
                "severity": "P1",
                "degraded": True,
                "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": config.VALIDATOR_EFFORT,
            })
            engine = Engine(ws.slug, backend="mock")

            engine.turn_index = 1
            self.assertEqual(engine._validation_turn_findings([]), [])
            # A new case is still validated immediately rather than waiting for
            # the retry cadence.
            self.assertEqual(
                [row["id"] for row in engine._validation_turn_findings([finding])],
                [finding["id"]],
            )
            engine.turn_index = 12
            self.assertEqual(
                [row["id"] for row in engine._validation_turn_findings([])],
                [finding["id"]],
            )

    def test_proof_dispatch_waits_for_a_materially_changed_astra_contract(self):
        with isolated_runtime():
            ws = Workspace("proof-dispatch-fingerprint")
            ws.create("https://example.test", "web")
            finding = ws.record_finding(
                title="High evidence gap", severity="P2", evidence="initial",
            )
            verdict = {
                "finding_id": finding["id"],
                "verdict": "needs-more-evidence",
                "severity": "P2",
                "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": config.VALIDATOR_EFFORT,
                "independent_checks": ["Capture a peer control."],
            }
            ws.set_severity_verdict(finding["id"], verdict)
            engine = Engine(ws.slug, backend="mock")

            first = engine._scheduled_proof_backlog()
            self.assertEqual([row["id"] for row in first], [finding["id"]])
            fingerprint = first[0]["_proof_fingerprint"]
            engine._proof_dispatch_fingerprints[finding["id"]] = fingerprint
            self.assertEqual(engine._scheduled_proof_backlog(), [])
            self.assertEqual(engine._bounded_proof_backlog(), [])

            ws.revise_finding(
                finding["id"], reason="new paired evidence", evidence="revised",
            )
            # The revision first routes to immediate Astra revalidation.
            self.assertEqual(engine._scheduled_proof_backlog(), [])
            ws.set_severity_verdict_if_absent(
                finding["id"], verdict,
                expected_revalidation_revision="R001",
                replace_degraded=True,
                replace_untrusted_validator=True,
            )
            reopened = engine._scheduled_proof_backlog()
            self.assertEqual([row["id"] for row in reopened], [finding["id"]])
            self.assertNotEqual(reopened[0]["_proof_fingerprint"], fingerprint)

    def test_legacy_evidence_gap_is_revalidated_instead_of_entering_proof_queue(self):
        with isolated_runtime():
            ws = Workspace("legacy-validator-retry")
            ws.create("https://example.test", "web")
            finding = ws.record_finding(
                title="Legacy high claim", severity="P2",
            )
            ws.set_severity_verdict(finding["id"], {
                "finding_id": finding["id"],
                "verdict": "needs-more-evidence",
                "severity": "P2",
                "independent_checks": ["Capture a peer control."],
            })

            engine = Engine(ws.slug, backend="mock")
            self.assertEqual(
                [row["id"] for row in engine._validation_turn_findings([])],
                [finding["id"]],
            )
            self.assertEqual(
                engine._high_severity_proof_backlog(ws.findings.all()),
                [],
            )

    def test_persistent_validator_retry_is_revisited_while_new_failures_arrive(self):
        with isolated_runtime():
            ws = Workspace("validation-retry-epoch")
            ws.create("https://example.test", "web")

            def add_failure(number: int) -> None:
                finding = ws.record_finding(
                    title=f"Retry {number}", severity="P2",
                )
                ws.set_severity_verdict(finding["id"], {
                    "finding_id": finding["id"],
                    "verdict": "needs-more-evidence",
                    "severity": "P2",
                    "degraded": True,
                    "validator_model": config.VALIDATOR_MODEL,
                    "validator_effort": config.VALIDATOR_EFFORT,
                })

            add_failure(0)
            add_failure(1)
            engine = Engine(ws.slug, backend="mock")
            selected_ids = []
            for retry_round in range(5):
                selected = engine._validation_turn_findings([])
                self.assertEqual(len(selected), 1)
                selected_id = selected[0]["id"]
                selected_ids.append(selected_id)
                engine._validation_retry_after_id = selected_id
                engine._validation_retry_epoch_max_id = (
                    engine._selected_validation_retry_epoch_max_id
                )
                engine._validation_retry_cursor += 1
                add_failure(retry_round + 2)

            self.assertEqual(selected_ids[:3], ["F001", "F002", "F001"])
            self.assertIn("F003", selected_ids)

    def test_family_stagnation_rotation_persists_and_schedules_proof_fairly(self):
        with isolated_runtime():
            ws = Workspace("coverage-rotation")
            ws.create("https://example.test", "web")
            for number in range(2):
                finding = ws.record_finding(
                    title=f"High candidate {number}", severity="P2",
                    surface=f"/object/{number}",
                )
                ws.set_severity_verdict(finding["id"], {
                    "finding_id": finding["id"],
                    "verdict": "needs-more-evidence",
                    "severity": "P2",
                    "validator_model": config.VALIDATOR_MODEL,
                    "validator_effort": config.VALIDATOR_EFFORT,
                    "independent_checks": [
                        f"Check owner and peer control {number}.",
                    ],
                })

            engine = Engine(ws.slug, backend="mock")
            engine.target = "https://example.test"
            engine.target_type = "web"
            engine._family_stagnation_streak = 3
            selections = []
            for turn in range(1, 7):
                engine.turn_index = turn
                selection = engine._next_coverage_priority(
                    exhausted=False,
                    worker_was_idle=False,
                    convergence_reason="",
                )
                selections.append(selection)
                if selection.kind == "proof":
                    engine._proof_rotation_cursor += 1
                    engine._proof_rotation_after_id = selection.record_id
                    engine._proof_rotation_epoch_max_id = selection.epoch_max_id
                elif selection.kind == "coverage":
                    engine._coverage_rotation_cursor += 1

            self.assertTrue(all(item.action for item in selections))
            self.assertEqual(
                [item.kind for item in selections],
                ["coverage", "coverage", "proof", "coverage", "coverage", "proof"],
            )
            self.assertIn("For F001", selections[2].action)
            self.assertIn("For F002", selections[5].action)
            self.assertEqual(engine._coverage_rotation_cursor, 4)
            self.assertEqual(engine._proof_rotation_cursor, 2)

    def test_generic_coverage_only_recovers_unusable_manager_directions(self):
        with isolated_runtime():
            ws = Workspace("coverage-recovery-selection")
            ws.create("https://example.test", "web")
            engine = Engine(ws.slug, backend="mock")
            engine.target = "https://example.test"
            engine.target_type = "web"
            engine.turn_index = 4
            engine._family_stagnation_streak = 3
            selection = engine._next_coverage_priority(
                exhausted=False,
                worker_was_idle=False,
                convergence_reason="",
            )
            self.assertEqual(selection.kind, "coverage")

            concrete = Directive(
                directive="Exercise the captured recovery transition with its valid control."
            )
            selected, applied = engine._select_next_directive(
                concrete, selection,
            )
            self.assertEqual(selected, concrete.worker_message())
            self.assertFalse(applied)

            recovery_cases = [
                Directive(directive=""),
                Directive(directive="Remain idle."),
                Directive(directive="Draft a responsible-disclosure report."),
                Directive(directive="Provider fallback.", degraded=True),
            ]
            for manager_directive in recovery_cases:
                with self.subTest(directive=manager_directive.directive):
                    selected, applied = engine._select_next_directive(
                        manager_directive, selection,
                    )
                    self.assertEqual(selected, selection.action)
                    self.assertTrue(applied)

            selected, applied = engine._select_next_directive(
                concrete, selection, force_recovery=True,
            )
            self.assertEqual(selected, selection.action)
            self.assertTrue(applied)

            selected, applied = engine._select_next_directive(
                concrete,
                type(selection)(),
                force_recovery=True,
            )
            self.assertEqual(selected, "")
            self.assertFalse(applied)

    def test_proof_rotation_uses_every_candidate_and_bounds_manager_context(self):
        with isolated_runtime():
            ws = Workspace("proof-window")
            ws.create("https://example.test", "web")
            for number in range(8):
                finding = ws.record_finding(
                    title=f"Candidate {number}", severity="P2",
                )
                ws.set_severity_verdict(finding["id"], {
                    "finding_id": finding["id"],
                    "verdict": "needs-more-evidence",
                    "severity": "P2",
                    "validator_model": config.VALIDATOR_MODEL,
                    "validator_effort": config.VALIDATOR_EFFORT,
                    "independent_checks": [f"Check {number}."],
                })

            engine = Engine(ws.slug, backend="mock")
            engine.target = "https://example.test"
            engine.target_type = "web"
            engine.turn_index = 3
            engine._proof_rotation_cursor = 6
            engine._proof_rotation_after_id = "F006"
            full = engine._high_severity_proof_backlog(ws.findings.all())
            self.assertEqual(len(full), 8)
            self.assertEqual(
                [row["id"] for row in engine._bounded_proof_backlog()],
                ["F007", "F008", "F001", "F002", "F003", "F004"],
            )
            selection = engine._next_coverage_priority(
                exhausted=False,
                worker_was_idle=False,
                convergence_reason="",
            )
            self.assertEqual(selection.kind, "proof")
            self.assertIn("For F007", selection.action)
            context = engine._build_context(None, [], [], False, [])
            self.assertEqual(len(context.validation_backlog), 6)

    def test_growing_proof_queue_advances_by_durable_finding_id(self):
        with isolated_runtime():
            ws = Workspace("growing-proof-queue")
            ws.create("https://example.test", "web")

            def add_gap(number: int) -> dict:
                finding = ws.record_finding(
                    title=f"Gap {number}", severity="P2",
                )
                ws.set_severity_verdict(finding["id"], {
                    "finding_id": finding["id"],
                    "verdict": "needs-more-evidence",
                    "severity": "P2",
                    "validator_model": config.VALIDATOR_MODEL,
                    "validator_effort": config.VALIDATOR_EFFORT,
                    "independent_checks": [f"Check gap {number}."],
                })
                return finding

            for number in range(3):
                add_gap(number)
            engine = Engine(ws.slug, backend="mock")
            engine.target = "https://example.test"
            engine.target_type = "web"
            selected_ids = []
            next_number = 3

            for proof_round in range(4):
                engine.turn_index = (proof_round + 1) * 3
                selection = engine._next_coverage_priority(
                    exhausted=False,
                    worker_was_idle=False,
                    convergence_reason="",
                )
                selected_ids.append(selection.record_id)
                engine._proof_rotation_after_id = selection.record_id
                engine._proof_rotation_epoch_max_id = selection.epoch_max_id
                engine._proof_rotation_cursor += 1
                ws.set_severity_verdict(selection.record_id, {
                    "finding_id": selection.record_id,
                    "verdict": "downgrade",
                    "severity": "P3",
                    "validator_model": config.VALIDATOR_MODEL,
                    "validator_effort": config.VALIDATOR_EFFORT,
                })
                add_gap(next_number)
                add_gap(next_number + 1)
                next_number += 2

            self.assertEqual(selected_ids, ["F001", "F002", "F003", "F004"])

    def test_persistent_old_proof_gap_is_revisited_while_new_gaps_arrive(self):
        with isolated_runtime():
            ws = Workspace("proof-epoch")
            ws.create("https://example.test", "web")

            def add_gap(number: int) -> None:
                finding = ws.record_finding(
                    title=f"Gap {number}", severity="P2",
                )
                ws.set_severity_verdict(finding["id"], {
                    "finding_id": finding["id"],
                    "verdict": "needs-more-evidence",
                    "severity": "P2",
                    "validator_model": config.VALIDATOR_MODEL,
                    "validator_effort": config.VALIDATOR_EFFORT,
                    "independent_checks": [f"Check {number}."],
                })

            add_gap(0)
            add_gap(1)
            engine = Engine(ws.slug, backend="mock")
            engine.target = "https://example.test"
            engine.target_type = "web"
            selected_ids = []
            for proof_round in range(5):
                engine.turn_index = (proof_round + 1) * 3
                selection = engine._next_coverage_priority(
                    exhausted=False,
                    worker_was_idle=False,
                    convergence_reason="",
                )
                selected_ids.append(selection.record_id)
                engine._proof_rotation_after_id = selection.record_id
                engine._proof_rotation_epoch_max_id = selection.epoch_max_id
                engine._proof_rotation_cursor += 1
                add_gap(proof_round + 2)

            self.assertEqual(selected_ids[:3], ["F001", "F002", "F001"])
            self.assertIn("F003", selected_ids)

    def test_each_proof_case_schedules_all_requested_checks_together(self):
        with isolated_runtime():
            ws = Workspace("proof-check-rotation")
            ws.create("https://example.test", "web")
            for number in range(4):
                finding = ws.record_finding(
                    title=f"Candidate {number}", severity="P2",
                )
                ws.set_severity_verdict(finding["id"], {
                    "finding_id": finding["id"],
                    "verdict": "needs-more-evidence",
                    "severity": "P2",
                    "validator_model": config.VALIDATOR_MODEL,
                    "validator_effort": config.VALIDATOR_EFFORT,
                    "independent_checks": [
                        f"check {check} for case {number}"
                        for check in range(4)
                    ],
                })

            engine = Engine(ws.slug, backend="mock")
            engine.target = "https://example.test"
            engine.target_type = "web"
            actions: dict[str, list[str]] = {}
            for proof_round in range(4):
                engine.turn_index = (proof_round + 1) * 3
                selection = engine._next_coverage_priority(
                    exhausted=False,
                    worker_was_idle=False,
                    convergence_reason="",
                )
                actions.setdefault(selection.record_id, []).append(
                    selection.action
                )
                engine._proof_rotation_after_id = selection.record_id
                engine._proof_rotation_epoch_max_id = selection.epoch_max_id
                engine._proof_rotation_cursor += 1

            self.assertEqual(set(actions), {"F001", "F002", "F003", "F004"})
            for case_number, finding_id in enumerate(sorted(actions)):
                for check in range(4):
                    self.assertTrue(any(
                        f"check {check} for case {case_number}" in action
                        for action in actions[finding_id]
                    ))


class FamilyStagnationLoopTests(unittest.IsolatedAsyncioTestCase):
    async def test_new_families_cannot_starve_periodic_proof_work(self):
        with isolated_runtime(), patch.multiple(
            config.CONFIG,
            max_turns=3,
            max_run_seconds=0,
            stop_on_p1=False,
            until_severity="",
            passive_stagnation_limit=99,
            repetitive_probe_turn_limit=99,
            exhaustion_threshold=99,
        ):
            ws = Workspace("proof-cadence-loop")
            ws.create("https://example.test", "web")
            high = ws.record_finding(
                title="High evidence gap", severity="P2", surface="/account",
            )
            ws.set_severity_verdict(high["id"], {
                "finding_id": high["id"],
                "verdict": "needs-more-evidence",
                "severity": "P2",
                "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": config.VALIDATOR_EFFORT,
                "independent_checks": ["Capture the peer control."],
            })
            engine = Engine(ws.slug, backend="mock")
            await engine.setup(
                brief="exercise the surface",
                target="https://example.test",
                target_type="web",
            )

            def worker_script(worker, _directive):
                worker.ws.record_finding(
                    title=f"Low family {worker.counter}",
                    severity="P3",
                    root_cause=f"distinct root {worker.counter}",
                    case_kind="distinct-case",
                )
                return "Recorded another distinct family."

            contexts = []

            async def direct(context):
                contexts.append(context)
                return Directive(directive="Continue discovery.")

            engine.worker.script = worker_script
            engine.manager.direct = AsyncMock(side_effect=direct)
            await engine.run()

            self.assertEqual(
                [context.family_stagnation_streak for context in contexts],
                [0, 0, 0],
            )
            self.assertEqual(contexts[0].coverage_priority, "")
            self.assertEqual(contexts[1].coverage_priority, "")
            self.assertIn("For F001", contexts[2].coverage_priority)
            meta = ws.load_meta()
            self.assertEqual(meta.proof_rotation_cursor, 1)
            self.assertEqual(meta.proof_rotation_after_id, "F001")
            self.assertEqual(meta.proof_rotation_epoch_max_id, "F001")
            self.assertRegex(
                meta.proof_dispatch_fingerprints.get("F001", ""),
                r"^[0-9a-f]{64}$",
            )
            self.assertEqual(meta.coverage_rotation_cursor, 0)
            self.assertEqual(meta.last_directive, contexts[2].coverage_priority)

    async def test_new_routes_without_new_families_trigger_rotation(self):
        with isolated_runtime(), patch.multiple(
            config.CONFIG,
            max_turns=3,
            max_run_seconds=0,
            stop_on_p1=False,
            until_severity="",
            passive_stagnation_limit=99,
            repetitive_probe_turn_limit=99,
            exhaustion_threshold=99,
        ):
            ws = Workspace("family-stagnation-loop")
            ws.create("https://example.test", "web")
            engine = Engine(ws.slug, backend="mock")
            await engine.setup(
                brief="exercise the surface",
                target="https://example.test",
                target_type="web",
            )

            def worker_script(worker, _directive):
                worker.ws.append_attack_surface(
                    item=f"/new-route/{worker.counter}", kind="endpoint",
                )
                return "Recorded a new route."

            contexts = []

            async def direct(context):
                contexts.append(context)
                return Directive(directive="Exercise the next unresolved operation.")

            engine.worker.script = worker_script
            engine.manager.direct = AsyncMock(side_effect=direct)
            await engine.run()

            self.assertEqual(
                [context.family_stagnation_streak for context in contexts],
                [1, 2, 3],
            )
            self.assertEqual(contexts[0].coverage_priority, "")
            self.assertEqual(contexts[1].coverage_priority, "")
            self.assertTrue(contexts[2].coverage_priority)
            meta = ws.load_meta()
            self.assertEqual(meta.family_stagnation_streak, 3)
            self.assertEqual(meta.coverage_rotation_cursor, 1)
            self.assertEqual(meta.proof_rotation_cursor, 0)
            self.assertEqual(
                meta.last_directive,
                "Exercise the next unresolved operation.",
            )
            health = _health(ws.slug, 0)
            self.assertEqual(health["family_stagnation_streak"], 3)
            self.assertEqual(health["coverage_rotation_cursor"], 1)
            self.assertEqual(health["proof_rotation_cursor"], 0)


if __name__ == "__main__":
    unittest.main()
