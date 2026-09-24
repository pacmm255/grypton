from __future__ import annotations

import asyncio
from contextlib import contextmanager
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from grypton import config
from grypton.engine import Engine
from grypton.manager import Directive
from grypton.workspace import Constraints, Workspace


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
            "TARGET_DATA_DIR": root / "input-data",
        }
        with patch.multiple(config, **values):
            config.ensure_layout()
            yield root


class ValidationOrderTests(unittest.IsolatedAsyncioTestCase):
    async def test_astra_verdict_precedes_and_informs_manager_direction(self):
        with isolated_runtime(), patch.multiple(
            config.CONFIG,
            max_turns=1,
            max_run_seconds=0,
            passive_stagnation_limit=99,
            repetitive_probe_turn_limit=99,
            exhaustion_threshold=99,
        ):
            ws = Workspace("validation-order")
            ws.create("https://example.test", "web")
            ws.save_constraints(Constraints(in_scope=["https://example.test"]))
            engine = Engine("validation-order", backend="mock")
            await engine.setup(
                brief="test the application",
                target="https://example.test",
                target_type="web",
            )

            def worker_script(_worker, _directive):
                engine.ws.record_finding(
                    title="Critical candidate",
                    severity="P1",
                    vuln_class="Authentication bypass",
                    surface="/account",
                    description="A reproducible critical candidate.",
                    poc="request and control",
                    evidence="flows/critical.http",
                )
                already_validated = engine.ws.record_finding(
                    title="Previously validated high candidate",
                    severity="P2",
                    vuln_class="Authorization",
                    surface="/profile",
                    description="A separately validated candidate.",
                    poc="request and control",
                    evidence="flows/high.http",
                )
                engine.ws.set_severity_verdict(already_validated["id"], {
                    "finding_id": already_validated["id"],
                    "verdict": "confirm",
                    "severity": "P2",
                    "confidence": 0.88,
                    "reasoning": "Existing independent verdict.",
                })
                engine.ws.record_finding(
                    title="Medium candidate",
                    severity="P3",
                    vuln_class="Information disclosure",
                    surface="/public",
                    description="A medium-severity candidate.",
                    poc="request and control",
                    evidence="flows/medium.http",
                )
                return "Recorded three evidence-backed candidates."

            order: list[str] = []
            captured = {}

            async def validate(finding, _ctx, *, explicit=False):
                self.assertFalse(explicit)
                order.append(f"validate:{finding['id']}")
                # Exercise the role-boundary check after Astra: a queued switch
                # must be consumed before Kryptex receives the context.
                engine._model_switches.put_nowait({"role": "kryptex"})
                return {
                    "finding_id": finding["id"],
                    "verdict": "confirm",
                    "severity": "P1",
                    "confidence": 0.97,
                    "reasoning": "Astra independently confirmed the candidate.",
                    "validator_model": config.VALIDATOR_MODEL,
                    "validator_effort": config.VALIDATOR_EFFORT,
                }

            async def apply_switches():
                while not engine._model_switches.empty():
                    engine._model_switches.get_nowait()
                    order.append("switch")

            async def direct(ctx):
                order.append("manager")
                captured["ctx"] = ctx
                return Directive(
                    directive="Test the next unresolved lead.",
                    # Model-generated grading must not validate the P3.
                    severity_validations=[{
                        "finding_id": "F003",
                        "verdict": "confirm",
                        "severity": "P3",
                    }],
                )

            engine.worker.script = worker_script
            engine.manager.validate_severity = validate
            engine.manager.direct = direct
            engine._apply_pending_model_switches = apply_switches

            await engine.run()

            self.assertEqual(order, ["validate:F001", "switch", "manager"])
            ctx = captured["ctx"]
            findings = {finding["id"]: finding for finding in ctx.new_findings}
            self.assertEqual(findings["F001"]["manager_verdict"]["verdict"], "confirm")
            self.assertEqual(findings["F001"]["status"], "confirmed")
            self.assertEqual(findings["F002"]["manager_verdict"]["verdict"], "confirm")
            self.assertEqual(findings["F003"]["status"], "validation-not-requested")
            self.assertIsNone(findings["F003"]["manager_verdict"])
            self.assertEqual(ctx.p1_count, 1)
            self.assertIn("F001 — Kryptex severity verdict", ctx.findings_summary)
            self.assertIn("Astra independently confirmed", ctx.findings_summary)

            durable = {finding["id"]: finding for finding in engine.ws.findings.all()}
            self.assertIsNone(durable["F003"]["manager_verdict"])
            findings_doc = (engine.ws.root / "findings.md").read_text(encoding="utf-8")
            self.assertEqual(
                findings_doc.count("F002 — Kryptex severity verdict"),
                1,
            )

    async def test_candidate_is_rechecked_before_each_astra_call(self):
        with isolated_runtime(), patch.multiple(
            config.CONFIG,
            max_turns=1,
            max_run_seconds=0,
            stop_on_p1=False,
            passive_stagnation_limit=99,
            repetitive_probe_turn_limit=99,
            exhaustion_threshold=99,
        ):
            ws = Workspace("validation-race")
            ws.create("https://example.test", "web")
            engine = Engine("validation-race", backend="mock")
            await engine.setup(
                brief="test the application",
                target="https://example.test",
                target_type="web",
            )

            finding_ids: list[str] = []

            def worker_script(_worker, _directive):
                finding_ids.append(engine.ws.record_finding(
                    title="First candidate", severity="P1",
                )["id"])
                finding_ids.append(engine.ws.record_finding(
                    title="Second candidate", severity="P2",
                )["id"])
                return "Recorded two candidates."

            calls: list[str] = []

            async def validate(finding, _ctx, *, explicit=False):
                calls.append(finding["id"])
                if len(calls) == 1:
                    engine.ws.set_severity_verdict(finding_ids[1], {
                        "finding_id": finding_ids[1],
                        "verdict": "confirm",
                        "severity": "P2",
                        "confidence": 0.91,
                        "reasoning": "Explicit validation completed concurrently.",
                    })
                return {
                    "finding_id": finding["id"],
                    "verdict": "confirm",
                    "severity": finding["severity"],
                    "confidence": 0.95,
                    "reasoning": "Automatic validation completed.",
                }

            engine.worker.script = worker_script
            engine.manager.validate_severity = validate
            engine.manager.direct = AsyncMock(
                return_value=Directive(directive="Continue with the next lead.")
            )

            await engine.run()

            self.assertEqual(calls, ["F001"])
            second = engine.ws.findings.find("F002")
            self.assertEqual(
                second["manager_verdict"]["reasoning"],
                "Explicit validation completed concurrently.",
            )

    async def test_conditional_verdict_write_has_one_winner(self):
        with isolated_runtime():
            ws = Workspace("validation-atomic")
            ws.create("https://example.test", "web")
            finding = ws.record_finding(title="Candidate", severity="P1")
            verdicts = [
                {
                    "finding_id": finding["id"],
                    "verdict": "confirm",
                    "severity": "P1",
                    "confidence": 0.9,
                    "reasoning": "writer one",
                },
                {
                    "finding_id": finding["id"],
                    "verdict": "downgrade",
                    "severity": "P2",
                    "confidence": 0.8,
                    "reasoning": "writer two",
                },
            ]

            results = await asyncio.gather(*(
                asyncio.to_thread(
                    ws.set_severity_verdict_if_absent,
                    finding["id"],
                    verdict,
                )
                for verdict in verdicts
            ))

            winners = [index for index, (_record, applied) in enumerate(results) if applied]
            self.assertEqual(len(winners), 1)
            durable = ws.findings.find(finding["id"])
            self.assertEqual(durable["manager_verdict"], verdicts[winners[0]])
            findings_doc = (ws.root / "findings.md").read_text(encoding="utf-8")
            self.assertEqual(
                findings_doc.count("F001 — Kryptex severity verdict"),
                1,
            )

    async def test_stop_during_astra_skips_manager_but_keeps_verdict(self):
        with isolated_runtime(), patch.multiple(
            config.CONFIG,
            max_turns=1,
            max_run_seconds=0,
            passive_stagnation_limit=99,
            repetitive_probe_turn_limit=99,
            exhaustion_threshold=99,
        ):
            ws = Workspace("validation-stop")
            ws.create("https://example.test", "web")
            engine = Engine("validation-stop", backend="mock")
            await engine.setup(
                brief="test the application",
                target="https://example.test",
                target_type="web",
            )

            def worker_script(_worker, _directive):
                engine.ws.record_finding(title="Critical candidate", severity="P1")
                return "Recorded a critical candidate."

            async def validate(finding, _ctx, *, explicit=False):
                engine.request_stop("operator stop during validation")
                return {
                    "finding_id": finding["id"],
                    "verdict": "confirm",
                    "severity": "P1",
                    "confidence": 0.9,
                    "reasoning": "Confirmed before the stop arrived.",
                }

            engine.worker.script = worker_script
            engine.manager.validate_severity = validate
            engine.manager.direct = AsyncMock(return_value=Directive(directive="unused"))

            await engine.run()

            engine.manager.direct.assert_not_awaited()
            finding = engine.ws.findings.find("F001")
            self.assertEqual(finding["manager_verdict"]["verdict"], "confirm")
            self.assertEqual(finding["status"], "confirmed")
            self.assertEqual(engine.stop_reason, "operator stop during validation")

    async def test_cancelling_astra_cancels_loop_before_manager_direction(self):
        with isolated_runtime(), patch.multiple(
            config.CONFIG,
            max_turns=1,
            max_run_seconds=0,
            passive_stagnation_limit=99,
            repetitive_probe_turn_limit=99,
            exhaustion_threshold=99,
        ):
            ws = Workspace("validation-cancel")
            ws.create("https://example.test", "web")
            engine = Engine("validation-cancel", backend="mock")
            await engine.setup(
                brief="test the application",
                target="https://example.test",
                target_type="web",
            )

            def worker_script(_worker, _directive):
                engine.ws.record_finding(title="Critical candidate", severity="P1")
                return "Recorded a critical candidate."

            started = asyncio.Event()
            cancelled = asyncio.Event()

            async def validate(_finding, _ctx, *, explicit=False):
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    cancelled.set()

            engine.worker.script = worker_script
            engine.manager.validate_severity = validate
            engine.manager.direct = AsyncMock(return_value=Directive(directive="unused"))

            task = asyncio.create_task(engine.run())
            await asyncio.wait_for(started.wait(), timeout=2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

            self.assertTrue(cancelled.is_set())
            engine.manager.direct.assert_not_awaited()
            finding = engine.ws.findings.find("F001")
            self.assertIsNone(finding["manager_verdict"])
            self.assertEqual(finding["status"], "validation-pending")

    async def test_request_stop_cancels_live_astra_and_cleans_up(self):
        with isolated_runtime(), patch.multiple(
            config.CONFIG,
            max_turns=1,
            max_run_seconds=0,
            stop_on_p1=False,
            passive_stagnation_limit=99,
            repetitive_probe_turn_limit=99,
            exhaustion_threshold=99,
        ):
            ws = Workspace("validation-request-stop")
            ws.create("https://example.test", "web")
            engine = Engine("validation-request-stop", backend="mock")
            await engine.setup(
                brief="test the application",
                target="https://example.test",
                target_type="web",
            )

            def worker_script(_worker, _directive):
                engine.ws.record_finding(title="Critical candidate", severity="P1")
                return "Recorded a critical candidate."

            started = asyncio.Event()
            cancelled = asyncio.Event()

            async def validate(_finding, _ctx, *, explicit=False):
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    cancelled.set()

            provider_cancel = AsyncMock()
            engine.worker.script = worker_script
            engine.manager.validate_severity = validate
            engine.manager.validator = SimpleNamespace(cancel=provider_cancel)
            engine.manager.direct = AsyncMock(return_value=Directive(directive="unused"))

            task = asyncio.create_task(engine.run())
            await asyncio.wait_for(started.wait(), timeout=2)
            engine.request_stop("operator stop during live validation")
            await asyncio.wait_for(task, timeout=2)

            self.assertTrue(cancelled.is_set())
            provider_cancel.assert_awaited_once()
            engine.manager.direct.assert_not_awaited()
            finding = engine.ws.findings.find("F001")
            self.assertIsNone(finding["manager_verdict"])
            self.assertEqual(finding["status"], "validation-pending")
            self.assertEqual(engine.stop_reason, "operator stop during live validation")

    async def test_stop_during_post_validation_switch_skips_manager(self):
        with isolated_runtime(), patch.multiple(
            config.CONFIG,
            max_turns=1,
            max_run_seconds=0,
            stop_on_p1=False,
            passive_stagnation_limit=99,
            repetitive_probe_turn_limit=99,
            exhaustion_threshold=99,
        ):
            ws = Workspace("validation-switch-stop")
            ws.create("https://example.test", "web")
            engine = Engine("validation-switch-stop", backend="mock")
            await engine.setup(
                brief="test the application",
                target="https://example.test",
                target_type="web",
            )
            switch_boundaries = 0

            async def apply_switches():
                nonlocal switch_boundaries
                switch_boundaries += 1
                if switch_boundaries == 3:
                    engine.request_stop("operator stop during model switch")

            engine._apply_pending_model_switches = apply_switches
            engine.manager.direct = AsyncMock(return_value=Directive(directive="unused"))

            await engine.run()

            self.assertEqual(switch_boundaries, 3)
            engine.manager.direct.assert_not_awaited()
            self.assertEqual(engine.stop_reason, "operator stop during model switch")

    async def test_stop_on_p1_happens_before_manager_direction(self):
        with isolated_runtime(), patch.multiple(
            config.CONFIG,
            max_turns=1,
            max_run_seconds=0,
            stop_on_p1=True,
            passive_stagnation_limit=99,
            repetitive_probe_turn_limit=99,
            exhaustion_threshold=99,
        ):
            ws = Workspace("validation-stop-on-p1")
            ws.create("https://example.test", "web")
            engine = Engine("validation-stop-on-p1", backend="mock")
            await engine.setup(
                brief="test the application",
                target="https://example.test",
                target_type="web",
            )

            def worker_script(_worker, _directive):
                engine.ws.record_finding(title="Critical candidate", severity="P1")
                return "Recorded a critical candidate."

            engine.worker.script = worker_script
            engine.manager.direct = AsyncMock(return_value=Directive(directive="unused"))

            await engine.run()

            engine.manager.direct.assert_not_awaited()
            finding = engine.ws.findings.find("F001")
            self.assertEqual(finding["status"], "confirmed")
            self.assertIn("confirmed P1", engine.stop_reason)


if __name__ == "__main__":
    unittest.main()
