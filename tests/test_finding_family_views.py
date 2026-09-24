from __future__ import annotations

from contextlib import contextmanager, redirect_stdout
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from grypton import config
from grypton.chat import (
    Renderer,
    _print_context,
    _print_findings,
    _print_status,
    _print_summary,
)
from grypton.cli import (
    _status,
    cmd_findings,
    cmd_overview,
    cmd_report,
    cmd_run_status,
)
from grypton.finding_views import (
    bounded_family_catalog,
    finding_family_view,
    safe_display_text,
    terminal_family_lines,
)
from grypton.reporting import audit_workspace, render_report
from grypton.web import dashboard_state, engagement_detail, engagement_summary
from grypton.workspace import Constraints, Workspace


@contextmanager
def isolated_runtime():
    with tempfile.TemporaryDirectory(prefix="grypton-family-views-") as directory:
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


def family_workspace(slug: str = "family-view") -> tuple[Workspace, dict, dict]:
    ws = Workspace(slug)
    ws.create("https://example.test", "web")
    ws.save_constraints(Constraints(in_scope=["https://example.test"]))
    anchor = ws.record_finding(
        title="Cached response substitution",
        severity="P3",
        vuln_class="cache poisoning",
        surface="/",
        description="First evidence case.",
        poc="request one",
        evidence="flows/flow-0001.http",
        source="fixture",
        root_cause="Shared cache key omits query",
        case_kind="html page replacement",
    )
    child = ws.record_finding(
        title="Cached feed substitution",
        severity="P2",
        vuln_class="cache poisoning",
        surface="/feed/",
        description="Second evidence case.",
        poc="request two",
        evidence="flows/flow-0002.http",
        source="fixture",
        family_id=anchor["id"],
        case_kind="feed replacement",
    )
    ws.set_severity_verdict(child["id"], {
        "finding_id": child["id"],
        "verdict": "downgrade",
        "severity": "P3",
        "confidence": 0.9,
        "reasoning": "Independent case-level verdict.",
        "independent_checks": [],
        "exploitability": "Reproduced on the feed case.",
        "validator_model": config.VALIDATOR_MODEL,
        "validator_effort": config.VALIDATOR_EFFORT,
    })
    ws.flows_dir.mkdir(parents=True, exist_ok=True)
    for name in ("flow-0001.http", "flow-0002.http"):
        (ws.flows_dir / name).write_text("HTTP/1.1 200 OK\n", encoding="utf-8")
    return ws, anchor, child


class FindingFamilyViewTests(unittest.TestCase):
    def test_status_overview_and_run_status_add_family_counts(self):
        with isolated_runtime():
            ws, _anchor, child = family_workspace()
            status = _status(ws.slug)
            self.assertEqual(status["findings"], 2)
            self.assertEqual(status["finding_cases"], 2)
            self.assertEqual(status["finding_families"], 1)
            self.assertEqual(status["confirmed_findings"], 1)

            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cmd_overview(SimpleNamespace(
                    target=ws.slug, json=True, limit=10,
                )), 0)
            overview = json.loads(output.getvalue())
            self.assertEqual(overview["findings"], 2)
            self.assertEqual(overview["finding_cases"], 2)
            self.assertEqual(overview["finding_families"], 1)
            self.assertEqual(overview["latest_finding"]["id"], child["id"])
            self.assertEqual(overview["latest_finding"]["family_id"], "F001")

            runtime_state = {
                "slug": ws.slug,
                "status": "stopped",
                "alive": False,
                "restarts": 0,
                "restart_limit": 2,
                "last_health": {"findings": 2},
            }
            output = io.StringIO()
            with patch("grypton.runtime.public_status", return_value=runtime_state), \
                    redirect_stdout(output):
                self.assertEqual(cmd_run_status(SimpleNamespace(
                    target=ws.slug, json=True,
                )), 0)
            run_status = json.loads(output.getvalue())
            self.assertEqual(run_status["finding_families"], 1)
            self.assertEqual(run_status["finding_cases"], 2)
            self.assertEqual(run_status["last_health"]["findings"], 2)

    def test_findings_json_remains_raw_while_terminal_groups_cases(self):
        with isolated_runtime():
            ws, _anchor, _child = family_workspace()
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cmd_findings(SimpleNamespace(
                    target=ws.slug, json=True, limit=100,
                )), 0)
            raw = json.loads(output.getvalue())
            self.assertIsInstance(raw, list)
            self.assertEqual(raw, ws.findings.all())
            self.assertIn("evidence", raw[0])
            self.assertIn("reasoning", raw[1]["manager_verdict"])

            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cmd_findings(SimpleNamespace(
                    target=ws.slug, json=False, limit=100,
                )), 0)
            rendered = output.getvalue()
            self.assertEqual(rendered.count("Family F001"), 1)
            self.assertIn("F001: P3 · validation-not-requested · Astra=not-requested", rendered)
            self.assertIn("F002: P3 · confirmed · Astra=downgrade", rendered)
            self.assertNotIn("Family F001 · P", rendered)

    def test_report_and_api_group_cases_without_inheriting_a_family_verdict(self):
        with isolated_runtime():
            ws, _anchor, _child = family_workspace()
            audit = audit_workspace(ws)
            self.assertTrue(audit["ok"], audit)
            self.assertEqual(audit["counts"]["findings"], 2)
            self.assertEqual(audit["counts"]["finding_cases"], 2)
            self.assertEqual(audit["counts"]["finding_families"], 1)
            self.assertEqual(audit["counts"]["confirmed_findings"], 1)
            self.assertEqual(audit["validation_not_requested"], ["F001"])

            markdown = render_report(ws)
            self.assertEqual(markdown.count("### Family F001"), 1)
            self.assertIn("| F001 | validation-not-requested | P3 | not-requested |", markdown)
            self.assertIn("| F002 | confirmed | P3 | downgrade |", markdown)
            family_heading = markdown.split("### Family F001", 1)[1].split("| Case |", 1)[0]
            self.assertNotIn("**Severity:**", family_heading)
            self.assertNotIn("**Verdict:**", family_heading)

            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cmd_report(SimpleNamespace(
                    target=ws.slug, format="json", output="",
                )), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["findings"], ws.findings.all())
            self.assertEqual(len(report["finding_families"]), 1)
            self.assertEqual(report["finding_families"][0]["case_count"], 2)
            compact = report["finding_families"][0]["cases"][1]
            self.assertEqual(compact["astra"], {"verdict": "downgrade", "severity": "P3"})
            self.assertTrue({"evidence", "poc", "description", "reasoning"}.isdisjoint(compact))

            summary = engagement_summary(ws.slug)
            self.assertEqual(summary["findings"], 2)
            self.assertEqual(summary["confirmed"], 1)
            self.assertEqual(summary["finding_cases"], 2)
            self.assertEqual(summary["finding_families"], 1)
            state = dashboard_state()
            self.assertEqual(state["counts"]["findings"], 2)
            self.assertEqual(state["counts"]["confirmed"], 1)
            self.assertEqual(state["counts"]["finding_cases"], 2)
            self.assertEqual(state["counts"]["finding_families"], 1)
            detail = engagement_detail(ws.slug)
            self.assertEqual(len(detail["finding_rows"]), 2)
            self.assertEqual(len(detail["finding_family_rows"]), 1)
            self.assertEqual(detail["finding_family_rows"][0]["case_count"], 2)
            self.assertEqual(len(detail["finding_family_rows"][0]["cases"]), 2)
            self.assertTrue({"evidence", "poc", "description", "reasoning"}.isdisjoint(
                detail["finding_family_rows"][0]["cases"][0]
            ))

            (ws.flows_dir / "flow-0002.http").unlink()
            missing_child = audit_workspace(ws)
            self.assertFalse(missing_child["ok"])
            self.assertEqual(missing_child["missing_canonical_flows"], ["flow-0002.http"])
            (ws.flows_dir / "flow-0002.http").write_text(
                "HTTP/1.1 200 OK\n", encoding="utf-8"
            )

            ws.log_tested_technique(
                surface="/feed/", technique="control replay", result="positive",
                evidence="flows/flow-9999.http", source="fixture",
            )
            missing = audit_workspace(ws)
            self.assertFalse(missing["ok"])
            self.assertEqual(missing["missing_canonical_flows"], ["flow-9999.http"])

    def test_chat_views_show_family_and_case_counts(self):
        with isolated_runtime():
            ws, _anchor, _child = family_workspace()
            engine = SimpleNamespace(ws=ws, turn_index=3, _start_time=0)
            renderer = Renderer("normal")
            output = io.StringIO()
            with redirect_stdout(output):
                _print_status(engine, renderer)
                _print_summary(engine, renderer)
                _print_context(engine)
                _print_findings(engine, 20)
            rendered = output.getvalue()
            self.assertIn("families=1 · cases=2", rendered)
            self.assertIn("confirmed-cases=1", rendered)
            self.assertIn("F002 (family F001)", rendered)
            self.assertIn("Finding families: 1 · evidence cases: 2", rendered)
            self.assertEqual(rendered.count("Family F001"), 1)

    def test_integrity_failure_fails_audit_and_uses_read_only_singletons(self):
        with isolated_runtime():
            ws, _anchor, _child = family_workspace()
            rows = ws.findings.all()
            rows[1]["family_id"] = "F999"
            ws.findings.path.write_text(
                "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
            )
            before = ws.findings.path.read_bytes()
            families, errors = finding_family_view(ws)
            self.assertEqual(ws.findings.path.read_bytes(), before)
            self.assertTrue(errors)
            self.assertEqual([row["family_id"] for row in families], ["F001", "F002"])
            self.assertTrue(all(row["virtual"] for row in families))
            audit = audit_workspace(ws)
            self.assertFalse(audit["ok"])
            self.assertTrue(audit["finding_family_integrity_errors"])
            self.assertEqual(audit["counts"]["findings"], 2)
            self.assertEqual(audit["counts"]["finding_cases"], 2)
            self.assertEqual(audit["counts"]["finding_families"], 2)

            legacy = Workspace("legacy-view")
            legacy.create("https://legacy.example.test", "web")
            legacy.record_finding(title="Legacy", severity="P4")
            before = legacy.findings.path.read_bytes()
            catalog, errors = finding_family_view(legacy)
            self.assertFalse(errors)
            self.assertTrue(catalog[0]["virtual"])
            self.assertEqual(legacy.findings.path.read_bytes(), before)

    def test_non_object_finding_row_fails_audit_without_breaking_views(self):
        with isolated_runtime():
            ws = Workspace("non-object-view")
            ws.create("https://example.test", "web")
            ws.findings.path.write_text("[1]\n", encoding="utf-8")
            before = ws.findings.path.read_bytes()

            families, errors = finding_family_view(ws)
            self.assertEqual(families, [])
            self.assertTrue(errors)
            self.assertIn("not an object", errors[0])
            self.assertEqual(ws.findings.path.read_bytes(), before)

            audit = audit_workspace(ws)
            self.assertFalse(audit["ok"])
            self.assertEqual(audit["counts"]["findings"], 0)
            self.assertTrue(audit["finding_family_integrity_errors"])
            self.assertIn("No finding cases were recorded.", render_report(ws))

            status = _status(ws.slug)
            self.assertEqual(status["findings"], 0)
            self.assertEqual(status["finding_cases"], 0)
            self.assertEqual(status["finding_families"], 0)
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cmd_overview(SimpleNamespace(
                    target=ws.slug, json=True, limit=10,
                )), 0)
            overview = json.loads(output.getvalue())
            self.assertEqual(overview["findings"], 0)
            self.assertIsNone(overview["latest_finding"])
            summary = engagement_summary(ws.slug)
            self.assertEqual(summary["findings"], 0)
            detail = engagement_detail(ws.slug)
            self.assertEqual(detail["finding_rows"], [])
            self.assertTrue(detail["finding_family_integrity_errors"])

            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cmd_report(SimpleNamespace(
                    target=ws.slug, format="json", output="",
                )), 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["findings"], [[1]])
            self.assertEqual(payload["finding_families"], [])
            self.assertFalse(payload["audit"]["ok"])

    def test_family_views_are_bounded_and_terminal_markdown_safe(self):
        with isolated_runtime():
            ws = Workspace("escaped-view")
            ws.create("https://example.test", "web")
            ws.record_finding(
                title=("Header | [split](javascript:alert(1))\x1b[31m "
                       "C1\u009b31m token=secret-value "
                       "Authorization: Bearer supersecret"),
                severity="P4",
                vuln_class="cache poisoning",
                surface="/<unsafe>",
                root_cause="Cache | key api_key=secret-value <tag>",
                case_kind="header\nvariant authorization=Bearer abc.def",
            )
            families, errors = finding_family_view(ws)
            self.assertFalse(errors)
            terminal = "\n".join(terminal_family_lines(families, limit=10))
            markdown = render_report(ws)
            for rendered in (terminal, markdown):
                self.assertNotIn("\x1b", rendered)
                self.assertNotIn("\u009b", rendered)
                self.assertNotIn("secret-value", rendered)
                self.assertNotIn("supersecret", rendered)
                self.assertNotIn("abc.def", rendered)
                self.assertIn("REDACTED", rendered)
            self.assertIn("\\|", markdown)
            self.assertIn("\\[split\\]\\(javascript:alert\\(1\\)\\)", markdown)
            self.assertIn("&lt;tag&gt;", markdown)
            self.assertEqual(
                safe_display_text("Authorization: Bearer supersecret"),
                "Authorization: [REDACTED]",
            )
            self.assertEqual(
                safe_display_text("authorization=Bearer abc.def"),
                "authorization=[REDACTED]",
            )
            self.assertEqual(
                safe_display_text('{"token":"supersecret"}'),
                '{"token":"[REDACTED]"}',
            )
            self.assertEqual(
                safe_display_text('{"api_key": "abc123"}'),
                '{"api_key": "[REDACTED]"}',
            )

            synthetic = []
            for family_number in range(3):
                cases = [{"id": f"F{family_number}{case_number}"}
                         for case_number in range(3)]
                synthetic.append({
                    "family_id": f"F{family_number}", "cases": cases,
                    "case_ids": [row["id"] for row in cases], "case_count": 3,
                })
            bounded, omitted_families, omitted_cases = bounded_family_catalog(
                synthetic, family_limit=2, case_limit=2,
            )
            self.assertEqual(len(bounded), 2)
            self.assertEqual(omitted_families, 1)
            self.assertEqual(sum(len(row["cases"]) for row in bounded), 2)
            self.assertEqual(omitted_cases, 4)


if __name__ == "__main__":
    unittest.main()
