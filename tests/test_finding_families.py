from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from grypton import config
from grypton.engine import Engine
from grypton.toolserver import REGISTRY, cli_main, dispatch
from grypton.workspace import (FINDING_FAMILY_HISTORY_LIMIT,
                               FINDING_FAMILY_LIMITS, FindingFamilyCollision,
                               LedgerFormatError, Workspace)


@contextmanager
def isolated_runtime():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        with patch.multiple(config, **{
            "STATE_DIR": root / ".state",
            "ENGAGEMENTS_DIR": root / ".state/engagements",
            "TARGETS_DIR": root / ".state/engagements",
            "RUNTIME_DIR": root / ".state/runtime",
            "LOG_DIR": root / ".state/runtime/logs",
            "PROVIDER_DIR": root / ".state/providers",
            "OPENCODE_WORKSPACES_DIR": root / ".opencode-workspaces",
            "TARGET_DATA_DIR": root / "target",
        }):
            config.ensure_layout()
            yield root


def workspace(slug="families"):
    ws = Workspace(slug)
    ws.create("https://example.test", "web")
    return ws


def record(ws, title, root, *, severity="P3", family_id="",
           separate_reason="", case_kind="route"):
    return ws.record_finding(
        title=title, severity=severity, vuln_class="cache poisoning",
        surface=f"/{title.lower().replace(' ', '-')}", description="impact",
        poc="steps", evidence=f"flows/{title}.http", root_cause=root,
        family_id=family_id, case_kind=case_kind,
        separate_reason=separate_reason,
    )


def legacy(finding_id, title="Legacy"):
    return {
        "id": finding_id, "title": title, "severity": "P3",
        "vuln_class": "legacy", "surface": "/legacy",
        "description": "old", "poc": "old", "evidence": "flows/old.http",
        "source": "worker", "status": "validation-not-requested",
        "manager_verdict": None,
    }


def structured(finding_id, family_id, root="shared cause"):
    row = legacy(finding_id, finding_id)
    row.update({
        "family_id": family_id, "family_root_cause": root,
        "family_case_kind": "route", "family_history": [{
            "id": "H001", "action": "create", "from_family_id": None,
            "to_family_id": family_id, "reason": "fixture",
        }],
    })
    return row


class FindingFamilyTests(unittest.TestCase):
    def test_legacy_rows_are_virtual_singletons_without_migration_writes(self):
        with isolated_runtime():
            ws = workspace("legacy-catalog")
            ws.findings.append(legacy("F001"))
            before = ws.findings.path.read_bytes()
            catalog = ws.finding_family_catalog()
            self.assertEqual(ws.findings.path.read_bytes(), before)
            self.assertEqual(catalog[0]["family_id"], "F001")
            self.assertEqual(catalog[0]["case_ids"], ["F001"])
            self.assertTrue(catalog[0]["virtual"])
            self.assertEqual(ws.finding_family_integrity_errors(), [])

    def test_old_workspace_and_tool_cli_calls_remain_legacy_compatible(self):
        with isolated_runtime():
            ws = workspace("legacy-api")
            first = ws.record_finding(title="Same title", severity="P3")
            second = ws.record_finding(title="Same title", severity="P3")
            self.assertNotIn("family_id", first)
            self.assertNotIn("family_history", second)
            self.assertEqual([row["virtual"] for row in ws.finding_family_catalog()],
                             [True, True])

            cli_ws = workspace("legacy-cli")
            command = [
                    "--target", cli_ws.slug, "--json", "finding", "CLI case", "P3",
                    "--class", "fixture", "--surface", "/cli",
                    "--description", "impact", "--poc", "steps",
                    "--evidence", "flows/cli.http",
            ]
            payloads = []
            for _ in range(2):
                output = io.StringIO()
                with redirect_stdout(output):
                    code = cli_main(command)
                self.assertEqual(code, 0, output.getvalue())
                payloads.append(json.loads(output.getvalue()))
            self.assertEqual([row["data"]["id"] for row in payloads],
                             ["F001", "F002"])
            self.assertTrue(all("family_id" in row["data"] for row in payloads))
            starts = cli_ws.root / ".ledger/effectful-tool-starts.jsonl"
            calls = cli_ws.root / ".ledger/tool-calls.jsonl"
            self.assertEqual(len(starts.read_text().splitlines()), 2)
            self.assertEqual(len(calls.read_text().splitlines()), 2)
            with patch("grypton.toolserver._record_effectful_tool_start",
                       side_effect=OSError("marker failure")), \
                    redirect_stdout(io.StringIO()) as failed:
                self.assertEqual(cli_main(command), 1)
            self.assertIn("restart-safety marker", failed.getvalue())
            self.assertEqual(len(cli_ws.findings.all()), 2)

    def test_record_creates_and_links_cases_without_combining_case_state(self):
        with isolated_runtime():
            ws = workspace("record-family")
            anchor = record(ws, "Header path", "Unkeyed routing header")
            child = record(
                ws, "Cookie path", "", severity="P2",
                family_id=anchor["id"], case_kind="authenticated delivery",
            )
            ws.set_severity_verdict(child["id"], {
                "verdict": "confirm", "severity": "P2", "reasoning": "private",
            })
            rows = {row["id"]: row for row in ws.findings.all()}
            self.assertEqual(rows[child["id"]]["family_id"], anchor["id"])
            self.assertEqual(rows[anchor["id"]]["status"], "validation-not-requested")
            self.assertEqual(rows[child["id"]]["status"], "confirmed")
            self.assertNotEqual(rows[anchor["id"]]["evidence"], rows[child["id"]]["evidence"])
            catalog = ws.finding_family_catalog()
            self.assertEqual(catalog[0]["case_ids"], ["F001", "F002"])
            self.assertEqual(catalog[0]["cases"][1]["astra"], {
                "verdict": "confirm", "severity": "P2",
            })
            rendered = json.dumps(catalog)
            self.assertNotIn("flows/", rendered)
            self.assertNotIn("private", rendered)

    def test_exact_collision_is_non_destructive_and_override_is_audited(self):
        with isolated_runtime():
            ws = workspace("collision")
            record(ws, "First", "Cache-Key Confusion")
            before = ws.findings.path.read_bytes()
            with self.assertRaises(FindingFamilyCollision) as caught:
                record(ws, "Second", " cache key_confusion!! ")
            self.assertEqual(caught.exception.family_ids, ("F001",))
            self.assertEqual(ws.findings.path.read_bytes(), before)
            with self.assertRaisesRegex(ValueError, "letters or numbers"):
                record(ws, "Empty", "---")
            self.assertEqual(ws.findings.path.read_bytes(), before)
            separate = record(
                ws, "Separate", "cache key confusion",
                separate_reason="Different trust boundary",
            )
            self.assertEqual(separate["id"], "F002")
            self.assertEqual(separate["family_id"], "F002")
            self.assertEqual(separate["family_separate_reason"],
                             "Different trust boundary")
            self.assertEqual(ws.finding_family_integrity_errors(), [])
            self.assertEqual(
                [row["family_id"] for row in ws.finding_family_catalog()],
                ["F001", "F002"],
            )

    def test_relink_is_audited_idempotent_and_preserves_evidence_and_verdict(self):
        with isolated_runtime():
            ws = workspace("relink")
            anchor = record(ws, "Anchor", "Shared backend parser")
            moving = record(ws, "Moving", "Different initial cause", severity="P2")
            ws.set_severity_verdict(moving["id"], {
                "verdict": "reject", "severity": "P3", "reasoning": "kept",
            })
            expected_evidence = ws.findings.find(moving["id"])["evidence"]
            linked = ws.link_finding_family(
                moving["id"], anchor["id"], reason="Same parser proven",
                root_cause="shared backend parser", case_kind="alternate host",
            )
            self.assertEqual(linked["family_id"], anchor["id"])
            self.assertEqual(linked["family_history"][-1]["action"], "relink")
            self.assertEqual(linked["evidence"], expected_evidence)
            self.assertEqual(linked["manager_verdict"]["reasoning"], "kept")
            before_retry = ws.findings.path.read_bytes()
            retried = ws.link_finding_family(
                moving["id"], anchor["id"], reason="retry",
                root_cause="Shared Backend Parser", case_kind="alternate host",
            )
            self.assertEqual(retried["family_history"], linked["family_history"])
            self.assertEqual(ws.findings.path.read_bytes(), before_retry)

    def test_legacy_cases_can_be_grouped_and_anchor_materialized(self):
        with isolated_runtime():
            ws = workspace("legacy-group")
            ws.findings.append(legacy("F001", "Anchor"))
            ws.findings.append(legacy("F002", "Variant"))
            with self.assertRaisesRegex(ValueError, "materialized first"):
                ws.link_finding_family(
                    "F002", "F001", reason="Same parser",
                    root_cause="Shared parser bug", case_kind="second route",
                )
            with self.assertRaisesRegex(ValueError, "materialized first"):
                record(ws, "New variant", "Shared parser bug", family_id="F001")
            anchor = ws.link_finding_family(
                "F001", "F001", reason="Materialize legacy anchor",
                root_cause="Shared parser bug", case_kind="first route",
            )
            self.assertEqual(anchor["family_history"][-1]["action"], "materialize")
            linked = ws.link_finding_family(
                "F002", "F001", reason="Same parser", case_kind="second route",
            )
            child = record(ws, "New variant", "", family_id="F001")
            self.assertEqual(linked["family_history"][-1]["action"], "link")
            self.assertEqual(child["family_id"], "F001")
            self.assertEqual(ws.finding_family_integrity_errors(), [])
            self.assertEqual(ws.finding_family_catalog()[0]["case_count"], 3)

    def test_anchor_with_children_cannot_move(self):
        with isolated_runtime():
            ws = workspace("anchor-move")
            anchor = record(ws, "Anchor", "Cause one")
            record(ws, "Child", "cause-one", family_id=anchor["id"])
            other = record(ws, "Other", "Cause two")
            before = ws.findings.path.read_bytes()
            with self.assertRaisesRegex(ValueError, "child cases"):
                ws.link_finding_family(
                    anchor["id"], other["id"], reason="try move",
                    case_kind="route",
                )
            self.assertEqual(ws.findings.path.read_bytes(), before)

    def test_failed_atomic_relink_leaves_full_finding_unchanged(self):
        with isolated_runtime():
            ws = workspace("atomic-relink")
            first = record(ws, "First", "Cause one")
            second = record(ws, "Second", "Cause two")
            before = ws.findings.path.read_bytes()
            with patch("grypton.workspace._atomic_write", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    ws.link_finding_family(
                        second["id"], first["id"], reason="same cause",
                        case_kind="route",
                    )
            self.assertEqual(ws.findings.path.read_bytes(), before)

    def test_integrity_reports_retained_invariants(self):
        fixtures = [
            ([structured("F001", "F999")], "missing family anchor"),
            ([legacy("F001"), structured("F002", "F001")],
             "legacy family anchor F001 is not materialized"),
            ([structured("F001", "F002"), structured("F002", "F003"),
              structured("F003", "F003")], "does not anchor itself"),
            ([structured("F001", "F001", "one"),
              structured("F002", "F001", "two")], "conflicting root causes"),
            ([{**structured("F001", "F001"), "family_case_kind": ""}],
             "no family case kind"),
            ([{**structured("F001", "F001"), "family_history": [{
                "to_family_id": "F002"}]}], "history target is inconsistent"),
            ([{**structured("F001", "F001"), "family_history": [
                {"id": "H001", "action": "create", "from_family_id": None,
                 "to_family_id": "F001", "reason": "one"},
                {"id": "H001", "action": "relink", "from_family_id": "F001",
                 "to_family_id": "F001", "reason": "two"},
            ]}], "event IDs are invalid"),
            ([{**structured("F001", "F001"), "family_history": [
                {"id": "H001", "action": "merge", "from_family_id": None,
                 "to_family_id": "F001", "reason": "bad"},
            ]}], "event action is invalid"),
            ([{**structured("F001", "F001"), "family_history": [
                {"id": "H001", "action": "create", "from_family_id": None,
                 "to_family_id": "F001", "reason": "one"},
                {"id": "H002", "action": "relink", "from_family_id": "F999",
                 "to_family_id": "F001", "reason": "two"},
            ]}], "history is discontinuous"),
            ([legacy("bad")], "invalid ID"),
            ([legacy("F001"), legacy("F001")], "duplicate finding ID"),
        ]
        for index, (rows, message) in enumerate(fixtures):
            with self.subTest(message=message), isolated_runtime():
                ws = workspace(f"integrity-{index}")
                for row in rows:
                    ws.findings.append(row)
                self.assertIn(message, "\n".join(
                    ws.finding_family_integrity_errors()))

    def test_malformed_json_is_never_silently_skipped(self):
        with isolated_runtime():
            ws = workspace("malformed-family")
            ws.findings.path.write_text(json.dumps(legacy("F001")) + "\n{", encoding="utf-8")
            self.assertIn("line 2 is invalid JSON",
                          ws.finding_family_integrity_errors()[0])
            with self.assertRaises(LedgerFormatError):
                ws.finding_family_catalog()

    def test_catalog_rejects_semantically_invalid_family_state(self):
        with isolated_runtime():
            ws = workspace("invalid-family-catalog")
            ws.findings.append(structured("F001", "F999"))
            before = ws.findings.path.read_bytes()

            with self.assertRaisesRegex(ValueError, "missing family anchor F999"):
                ws.finding_family_catalog()

            self.assertEqual(ws.findings.path.read_bytes(), before)

    def test_duplicate_normalized_root_requires_separate_family_reason(self):
        with isolated_runtime():
            ws = workspace("duplicate-family-root")
            ws.findings.append(structured("F001", "F001", "same parser bug"))
            ws.findings.append(structured("F002", "F002", " Same_parser BUG!! "))
            before = ws.findings.path.read_bytes()

            errors = ws.finding_family_integrity_errors()
            self.assertIn(
                "finding family F002 duplicates a normalized root cause "
                "without a separate reason",
                errors,
            )
            with self.assertRaisesRegex(
                    ValueError, "F002 duplicates a normalized root cause"):
                ws.finding_family_catalog()
            self.assertEqual(ws.findings.path.read_bytes(), before)

        with isolated_runtime():
            ws = workspace("separate-duplicate-family-root")
            ws.findings.append(structured("F001", "F001", "same parser bug"))
            separate = structured("F002", "F002", " Same_parser BUG!! ")
            separate["family_separate_reason"] = "Different trust boundary"
            ws.findings.append(separate)

            self.assertEqual(ws.finding_family_integrity_errors(), [])
            self.assertEqual(
                [row["family_id"] for row in ws.finding_family_catalog()],
                ["F001", "F002"],
            )

    def test_integrity_is_total_over_arbitrary_family_json_types(self):
        invalid_values = ([], {}, True, 7, 1.5)
        event_values = {
            "id": invalid_values,
            "action": invalid_values,
            "from_family_id": invalid_values,
            "to_family_id": invalid_values,
            "reason": (*invalid_values, None, "", "   ",
                       "x" * (FINDING_FAMILY_LIMITS["reason"] + 1)),
            "ts": ([], {}, True, "invalid", -1, float("nan"), float("inf")),
        }
        for field, values in event_values.items():
            for value in values:
                with self.subTest(scope="event", field=field, value=value):
                    row = structured("F001", "F001")
                    row["family_history"][0][field] = value
                    self.assertTrue(Workspace._finding_family_errors([row]))

        for field in ("family_id", "family_root_cause", "family_case_kind",
                      "family_separate_reason"):
            for value in invalid_values:
                with self.subTest(scope="record", field=field, value=value):
                    row = structured("F001", "F001")
                    row[field] = value
                    self.assertTrue(Workspace._finding_family_errors([row]))

        for value in ([], {}, True, 7, 1.5, ["invalid-event"]):
            with self.subTest(scope="history", value=value):
                row = structured("F001", "F001")
                row["family_history"] = value
                self.assertTrue(Workspace._finding_family_errors([row]))

        huge_timestamp = structured("F001", "F001")
        huge_timestamp["family_history"][0]["ts"] = 10 ** 1000
        self.assertEqual(Workspace._finding_family_errors([huge_timestamp]), [])
        bounded_reason = structured("F001", "F001")
        bounded_reason["family_history"][0]["reason"] = (
            "x" * FINDING_FAMILY_LIMITS["reason"]
        )
        self.assertEqual(Workspace._finding_family_errors([bounded_reason]), [])

        with isolated_runtime():
            ws = workspace("unhashable-family-action")
            row = structured("F001", "F001")
            row["family_history"][0]["action"] = []
            ws.findings.append(row)
            errors = ws.finding_family_integrity_errors()
            self.assertIn("family event action is invalid", errors[0])
            with self.assertRaisesRegex(ValueError, "event action is invalid"):
                ws.finding_family_catalog()

    def test_child_separate_reason_and_blank_event_reason_fail_integrity(self):
        with isolated_runtime():
            ws = workspace("child-separate-reason")
            ws.findings.append(structured("F001", "F001"))
            child = structured("F002", "F001")
            child["family_separate_reason"] = "child claims separate"
            ws.findings.append(child)
            before = ws.findings.path.read_bytes()

            errors = ws.finding_family_integrity_errors()
            self.assertIn(
                "finding F002 child case cannot carry a separate reason", errors
            )
            with self.assertRaisesRegex(ValueError, "child case cannot carry"):
                ws.finding_family_catalog()
            self.assertEqual(ws.findings.path.read_bytes(), before)

        with isolated_runtime():
            ws = workspace("blank-family-event-reason")
            row = structured("F001", "F001")
            row["family_history"][0]["reason"] = "   "
            ws.findings.append(row)

            errors = ws.finding_family_integrity_errors()
            self.assertIn("finding F001 family event reason is invalid", errors)
            with self.assertRaisesRegex(ValueError, "event reason is invalid"):
                ws.finding_family_catalog()

    def test_catalog_sorts_family_and_case_ids_numerically_past_999(self):
        with isolated_runtime():
            ws = workspace("numeric-family-order")
            for finding_id in ("F998", "F999", "F1000"):
                ws.findings.append(legacy(finding_id))
            self.assertEqual(
                [row["family_id"] for row in ws.finding_family_catalog()],
                ["F998", "F999", "F1000"],
            )

            grouped = workspace("numeric-case-order")
            for finding_id in ("F998", "F999", "F1000"):
                grouped.findings.append(structured(finding_id, "F998"))
            self.assertEqual(
                grouped.finding_family_catalog()[0]["case_ids"],
                ["F998", "F999", "F1000"],
            )

    def test_confirmed_counts_ignore_non_object_verdicts_and_rows(self):
        with isolated_runtime():
            ws = workspace("corrupt-verdict-counts")
            string_verdict = legacy("F001")
            string_verdict["manager_verdict"] = "confirm"
            list_verdict = legacy("F002")
            list_verdict["manager_verdict"] = ["confirm"]
            invalid_severity = legacy("F003")
            invalid_severity["manager_verdict"] = {
                "verdict": "confirm", "severity": [],
            }
            valid = legacy("F004")
            valid["manager_verdict"] = {
                "verdict": "confirm", "severity": "P1",
            }
            rows = [string_verdict, list_verdict, invalid_severity, valid, [1]]
            ws.findings.path.write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )

            self.assertEqual(
                [row["id"] for row in ws.confirmed_findings()],
                ["F003", "F004"],
            )
            self.assertEqual(
                [row["id"] for row in ws.confirmed_p1s()],
                ["F004"],
            )

    def test_length_and_history_bounds_fail_before_mutation(self):
        with isolated_runtime():
            ws = workspace("family-bounds")
            for keyword, value in (
                ("root_cause", "x" * (FINDING_FAMILY_LIMITS["root_cause"] + 1)),
                ("case_kind", "x" * (FINDING_FAMILY_LIMITS["case_kind"] + 1)),
                ("separate_reason", "x" * (
                    FINDING_FAMILY_LIMITS["separate_reason"] + 1)),
            ):
                kwargs = {"root_cause": "bounded root", "case_kind": "route",
                          keyword: value}
                with self.subTest(keyword=keyword), self.assertRaises(ValueError):
                    ws.record_finding(title=keyword, severity="P3", **kwargs)
            self.assertEqual(ws.findings.all(), [])

            anchor = record(ws, "Anchor", "Anchor root")
            moving = record(ws, "Moving", "Moving root")
            with self.assertRaisesRegex(ValueError, "reason exceeds"):
                ws.link_finding_family(
                    moving["id"], anchor["id"],
                    reason="x" * (FINDING_FAMILY_LIMITS["reason"] + 1),
                    case_kind="route",
                )
            def fill_history(row):
                history = row["family_history"]
                history.extend({
                    "id": f"H{number:03d}", "action": "relink",
                    "from_family_id": moving["id"], "to_family_id": moving["id"],
                    "reason": "bounded",
                } for number in range(2, FINDING_FAMILY_HISTORY_LIMIT + 1))
            ws.findings.update(moving["id"], fill_history, strict=True)
            self.assertEqual(ws.finding_family_integrity_errors(), [])
            self.assertEqual(
                ws.link_finding_family(
                    moving["id"], moving["id"], reason="retry",
                    root_cause="Moving root", case_kind="route",
                )["family_id"], moving["id"],
            )
            before = ws.findings.path.read_bytes()
            with self.assertRaisesRegex(ValueError, "history limit"):
                ws.link_finding_family(
                    moving["id"], anchor["id"], reason="one more",
                    case_kind="route",
                )
            self.assertEqual(ws.findings.path.read_bytes(), before)

    def test_concurrent_records_have_unique_ids_and_collision_decisions(self):
        with isolated_runtime():
            ws = workspace("concurrent-unique")
            with ThreadPoolExecutor(max_workers=8) as pool:
                rows = list(pool.map(
                    lambda number: record(ws, f"Case {number}", f"Cause {number}"),
                    range(16),
                ))
            self.assertEqual(len({row["id"] for row in rows}), 16)
            self.assertEqual(len(ws.findings.all_strict()), 16)
            self.assertEqual(ws.finding_family_integrity_errors(), [])

            collision_ws = workspace("concurrent-collision")
            def attempt(number):
                try:
                    return record(collision_ws, f"Case {number}", "same cause")["id"]
                except FindingFamilyCollision:
                    return "collision"
            with ThreadPoolExecutor(max_workers=8) as pool:
                outcomes = list(pool.map(attempt, range(8)))
            self.assertEqual(sum(value != "collision" for value in outcomes), 1)
            self.assertEqual(len(collision_ws.findings.all_strict()), 1)

    def test_astra_selection_stays_case_scoped_to_p1_and_p2(self):
        with isolated_runtime():
            ws = workspace("astra-family")
            low = record(ws, "Medium", "One cause", severity="P3")
            high = record(ws, "High", "one-cause", severity="P2",
                          family_id=low["id"], case_kind="second route")
            critical = record(ws, "Critical", "one cause", severity="P1",
                              family_id=low["id"], case_kind="third route")
            selected = Engine._automatic_validation_candidates(ws.findings.all())
            self.assertEqual([row["id"] for row in selected],
                             [high["id"], critical["id"]])
            self.assertEqual(low["status"], "validation-not-requested")
            self.assertEqual(high["status"], "validation-pending")
            self.assertEqual(critical["status"], "validation-pending")

    def test_mcp_schema_catalog_collision_and_link(self):
        schema = REGISTRY["record_finding"][1]
        self.assertIn("case_kind", schema["required"])
        self.assertEqual(schema["anyOf"], [
            {"required": ["root_cause"]}, {"required": ["family_id"]},
        ])
        self.assertIn("finding_family_catalog", REGISTRY)
        self.assertIn("link_finding_family", REGISTRY)
        self.assertEqual(schema["properties"]["root_cause"]["maxLength"],
                         FINDING_FAMILY_LIMITS["root_cause"])
        self.assertEqual(REGISTRY["finding_family_catalog"][1]["properties"]
                         ["limit"]["maximum"], 50)
        with isolated_runtime():
            ws = workspace("mcp-family")
            common = {
                "severity": "P3", "vuln_class": "cache poisoning",
                "surface": "/a", "description": "impact", "poc": "steps",
                "evidence": "flows/secret-evidence.http", "case_kind": "route",
            }
            bypass = dispatch(ws, "record_finding", {
                **{key: value for key, value in common.items() if key != "case_kind"},
                "title": "Bypass", "_legacy_family": True,
            })
            self.assertFalse(bypass["ok"])
            self.assertEqual(ws.findings.all(), [])
            first = dispatch(ws, "record_finding", {
                **common, "title": "First", "root_cause": "Unkeyed header",
            })
            self.assertTrue(first["ok"], first)
            whitespace = dispatch(ws, "record_finding", {
                **common, "title": "Whitespace", "root_cause": "   ",
                "family_id": "   ",
            })
            self.assertFalse(whitespace["ok"])
            self.assertIn("root_cause or family_id", whitespace["summary"])
            collision = dispatch(ws, "record_finding", {
                **common, "title": "Duplicate", "root_cause": "unkeyed-header!",
            })
            self.assertFalse(collision["ok"])
            self.assertEqual(collision["data"]["candidate_families"][0]["family_id"],
                             "F001")
            self.assertNotIn("secret-evidence", json.dumps(collision["data"]))
            second = dispatch(ws, "record_finding", {
                **common, "title": "Second", "root_cause": "different cause",
            })
            linked = dispatch(ws, "link_finding_family", {
                "finding_id": second["data"]["id"],
                "family_id": first["data"]["id"], "reason": "same parser",
                "case_kind": "alternate route",
            })
            self.assertTrue(linked["ok"], linked)
            for number in range(19):
                record(ws, f"Preview {number}", "", family_id="F001")
            catalog = dispatch(ws, "finding_family_catalog", {"offset": 0, "limit": 1})
            self.assertTrue(catalog["ok"], catalog)
            family = catalog["data"]["families"][0]
            self.assertEqual(family["case_count"], 21)
            self.assertEqual(len(family["cases"]), 20)
            self.assertEqual(family["cases_returned"], 20)
            self.assertEqual(catalog["data"]["returned"], 1)
            self.assertEqual(catalog["data"]["total_families"], 1)


if __name__ == "__main__":
    unittest.main()
