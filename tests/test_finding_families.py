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
                               FINDING_FAMILY_LIMITS,
                               FINDING_FAMILY_TIMESTAMP_MAX,
                               FindingFamilyCollision, LedgerFormatError,
                               Workspace)


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
            "id": "H001",
            "action": "create" if family_id == finding_id else "link",
            "from_family_id": None,
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
            self.assertEqual(ws.finding_family_integrity_errors(), [])

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
            "ts": ([], {}, True, "invalid", -1, float("nan"), float("inf"),
                   FINDING_FAMILY_TIMESTAMP_MAX + 1, 10 ** 1000),
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
        self.assertIn(
            "family event timestamp is invalid",
            "\n".join(Workspace._finding_family_errors([huge_timestamp])),
        )
        bounded_timestamp = structured("F001", "F001")
        bounded_timestamp["family_history"][0]["ts"] = (
            FINDING_FAMILY_TIMESTAMP_MAX
        )
        self.assertEqual(Workspace._finding_family_errors([bounded_timestamp]), [])
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

    def test_history_transition_state_machine_rejects_impossible_events(self):
        def event(number, action, origin, target):
            return {
                "id": f"H{number:03d}", "action": action,
                "from_family_id": origin, "to_family_id": target,
                "reason": "fixture",
            }

        invalid = [
            ([event(1, "create", "F001", "F001")], "F001", "initial family"),
            ([event(1, "create", None, "F002")], "F002", "initial family"),
            ([event(1, "materialize", None, "F001")], "F001", "initial family"),
            ([event(1, "materialize", "F001", "F002")], "F002", "initial family"),
            ([event(1, "link", "F999", "F002")], "F002", "initial family"),
            ([event(1, "link", None, "F001")], "F001", "initial family"),
            ([event(1, "relink", None, "F001")], "F001", "initial family"),
            ([event(1, "create", None, "F001"),
              event(2, "link", "F001", "F002")], "F002", "family relink"),
            ([event(1, "create", None, "F001"),
              event(2, "relink", "F001", "F001")], "F001", "family relink"),
            ([event(1, "create", None, "F001"),
              event(2, "relink", "F999", "F002")], "F002", "family relink"),
        ]
        for history, family_id, expected in invalid:
            with self.subTest(history=history, expected=expected):
                row = structured("F001", family_id)
                row["family_history"] = history
                self.assertIn(
                    f"{expected} transition is invalid",
                    "\n".join(Workspace._finding_family_errors([row])),
                )

        with isolated_runtime():
            ws = workspace("invalid-noop-relink")
            row = structured("F001", "F001")
            row["family_history"].append(
                event(2, "relink", "F001", "F001")
            )
            ws.findings.append(row)
            self.assertIn(
                "family relink transition is invalid",
                "\n".join(ws.finding_family_integrity_errors()),
            )
            with self.assertRaisesRegex(ValueError, "relink transition is invalid"):
                ws.finding_family_catalog()

    def test_generated_history_forms_satisfy_transition_integrity(self):
        with isolated_runtime():
            ws = workspace("generated-family-history")
            anchor = record(ws, "Anchor", "Anchor root")
            child = record(ws, "Child", "", family_id=anchor["id"])
            ws.findings.append(legacy("F003", "Legacy anchor"))
            ws.findings.append(legacy("F004", "Legacy child"))
            materialized = ws.link_finding_family(
                "F003", "F003", reason="materialize fixture",
                root_cause="Legacy root", case_kind="legacy anchor",
            )
            linked = ws.link_finding_family(
                "F004", anchor["id"], reason="link fixture",
                case_kind="legacy child",
            )
            other = record(ws, "Other", "Other root")
            relinked = ws.link_finding_family(
                child["id"], other["id"], reason="relink fixture",
                case_kind="moved child",
            )

            self.assertEqual(anchor["family_history"][0]["action"], "create")
            self.assertEqual(child["family_history"][0]["action"], "link")
            self.assertEqual(materialized["family_history"][0]["action"], "materialize")
            self.assertEqual(linked["family_history"][0]["action"], "link")
            self.assertEqual(
                [event["action"] for event in relinked["family_history"]],
                ["link", "relink"],
            )
            self.assertEqual(ws.finding_family_integrity_errors(), [])
            self.assertEqual(len(ws.finding_family_catalog()), 3)

    def test_event_metadata_and_api_sources_are_bounded(self):
        extra = structured("F001", "F001")
        extra["family_history"][0]["unexpected"] = "value"
        self.assertIn(
            "family event has unexpected keys",
            "\n".join(Workspace._finding_family_errors([extra])),
        )
        missing = structured("F001", "F001")
        del missing["family_history"][0]["from_family_id"]
        self.assertIn(
            "family event has missing keys",
            "\n".join(Workspace._finding_family_errors([missing])),
        )
        for source in (None, "", "   ", [], {},
                       "x" * (FINDING_FAMILY_LIMITS["source"] + 1)):
            with self.subTest(source=source):
                row = structured("F001", "F001")
                row["family_history"][0]["source"] = source
                self.assertIn(
                    "family event source is invalid",
                    "\n".join(Workspace._finding_family_errors([row])),
                )
        valid = structured("F001", "F001")
        valid["family_history"][0].update({
            "source": "x" * FINDING_FAMILY_LIMITS["source"],
            "ts": FINDING_FAMILY_TIMESTAMP_MAX,
        })
        self.assertEqual(Workspace._finding_family_errors([valid]), [])

        with isolated_runtime():
            ws = workspace("invalid-record-source")
            self.assertFalse(ws.findings.path.exists())
            with self.assertRaisesRegex(ValueError, "source is required"):
                ws.record_finding(title="Invalid source", severity="P3", source="   ")
            with self.assertRaisesRegex(ValueError, "source must be a string"):
                ws.record_finding(title="Invalid source", severity="P3", source=[])
            with self.assertRaisesRegex(ValueError, "source exceeds"):
                ws.record_finding(
                    title="Invalid source", severity="P3",
                    source="x" * (FINDING_FAMILY_LIMITS["source"] + 1),
                )
            self.assertFalse(ws.findings.path.exists())

            ws.findings.append(legacy("F001"))
            before_link = ws.findings.path.read_bytes()
            with self.assertRaisesRegex(ValueError, "source is required"):
                ws.link_finding_family(
                    "F001", "F001", reason="materialize",
                    root_cause="Legacy root", case_kind="legacy", source=" ",
                )
            self.assertEqual(ws.findings.path.read_bytes(), before_link)

    def test_generated_finding_id_overflow_is_non_destructive(self):
        with isolated_runtime():
            ws = workspace("finding-id-overflow")
            maximum_id = "F" + "9" * (FINDING_FAMILY_LIMITS["family_id"] - 1)
            ws.findings.append(legacy(maximum_id))
            self.assertEqual(ws.finding_family_integrity_errors(), [])
            before_ledger = ws.findings.path.read_bytes()
            before_document = (ws.root / "findings.md").read_bytes()

            with self.assertRaisesRegex(ValueError, "generated finding ID exceeds"):
                ws.record_finding(title="Overflow", severity="P3")

            self.assertEqual(ws.findings.path.read_bytes(), before_ledger)
            self.assertEqual((ws.root / "findings.md").read_bytes(), before_document)

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
            alternate = record(ws, "Alternate", "Alternate root")
            with self.assertRaisesRegex(ValueError, "reason exceeds"):
                ws.link_finding_family(
                    moving["id"], anchor["id"],
                    reason="x" * (FINDING_FAMILY_LIMITS["reason"] + 1),
                    case_kind="route",
                )
            def fill_history(row):
                history = row["family_history"]
                previous = moving["id"]
                for number in range(2, FINDING_FAMILY_HISTORY_LIMIT + 1):
                    target = anchor["id"] if number % 2 == 0 else alternate["id"]
                    history.append({
                        "id": f"H{number:03d}", "action": "relink",
                        "from_family_id": previous, "to_family_id": target,
                        "reason": "bounded",
                    })
                    previous = target
                row["family_id"] = previous
                row["family_root_cause"] = "Anchor root"
            ws.findings.update(moving["id"], fill_history, strict=True)
            self.assertEqual(ws.finding_family_integrity_errors(), [])
            self.assertEqual(
                ws.link_finding_family(
                    moving["id"], anchor["id"], reason="retry",
                    root_cause="Anchor root", case_kind="route",
                )["family_id"], anchor["id"],
            )
            before = ws.findings.path.read_bytes()
            with self.assertRaisesRegex(ValueError, "history limit"):
                ws.link_finding_family(
                    moving["id"], alternate["id"], reason="one more",
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
