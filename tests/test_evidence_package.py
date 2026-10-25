"""Mechanical evidence-package verification at record_finding (WS1 Layer 2).

The verifier must accept only packages whose four captures exist, whose
replays were machine-replayed from the positive capture, whose requests
match, whose digests actually support the differential claim, and whose
replays are fresh. Fabricated or hand-authored evidence fails at write time.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from grypton import config, tools
from grypton.toolserver import dispatch
from grypton.workspace import Workspace

from tests.evidence_helpers import (POSITIVE_BODY, REQUEST_HEADERS, REQUEST_METHOD,
                                    REQUEST_URL, write_evidence_package)


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


def workspace(slug="evidence"):
    ws = Workspace(slug)
    ws.create("https://example.test", "web")
    return ws


def make_stale(ws, flow_id: str, offset: float = 10.0) -> None:
    """Rewind one synthesized capture's captured_at, keeping the file valid."""
    path = tools._flow_path(ws, flow_id)
    text = path.read_text(encoding="utf-8")
    head, sep, rest = text.partition("\n")
    metadata = json.loads(head[len("### GRYPTON FLOW "):])
    metadata["captured_at"] -= offset
    path.write_text(
        f"### GRYPTON FLOW {json.dumps(metadata, ensure_ascii=False)}\n{rest}",
        encoding="utf-8")


def _common_args(**overrides):
    args = {"title": "Cross-account IDOR read", "severity": "P2",
            "vuln_class": "IDOR", "surface": "/api/v2/users/{id}",
            "description": "Sequential ids expose other users' profiles.",
            "poc": "GET /api/v2/users/2 while authenticated as user 1.",
            "evidence": "flows/positive.http", "root_cause": "unscoped object id",
            "case_kind": "read"}
    args.update(overrides)
    return args


class EvidencePackageVerificationTest(unittest.TestCase):
    def test_valid_package_verifies_and_record_carries_digests(self):
        with isolated_runtime():
            ws = workspace()
            package = write_evidence_package(ws)
            result = tools.verify_evidence_package(ws, package)
            self.assertTrue(result["ok"], result)
            self.assertEqual(
                sorted(result["digests"]),
                sorted({package[key] for key in
                        ("positive_flow_id", "control_flow_id", "replay_flow_id",
                         "second_run_flow_id")}))
            for digests in result["digests"].values():
                self.assertEqual(
                    sorted(digests),
                    ["artifact_sha256", "request_method", "request_target_sha256",
                     "response_body_bytes", "response_body_sha256",
                     "response_status"])
            record = ws.record_finding(
                severity="P2", vuln_class="IDOR", surface="/api/v2/users/2",
                description="impact", poc="steps", evidence="flows/positive.http",
                root_cause="unscoped object id", case_kind="read",
                evidence_package=package, title="Cross-account IDOR read")
            carried = record["evidence_package"]
            self.assertEqual(carried["package"],
                             {**package, "control_variable": None})
            self.assertEqual(carried["verified"],
                             {"digests": result["digests"],
                              "evidence_chain_sha256":
                                  result["evidence_chain_sha256"]})

    def test_missing_flow_is_rejected(self):
        with isolated_runtime():
            ws = workspace()
            package = write_evidence_package(ws)
            package["control_flow_id"] = "flow-9999999999999999"
            result = tools.verify_evidence_package(ws, package)
            self.assertFalse(result["ok"])
            self.assertIn("existence", result["reason"])

    def test_hand_authored_replay_is_rejected(self):
        with isolated_runtime():
            ws = workspace()
            package = write_evidence_package(ws)
            manual = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
                f"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{POSITIVE_BODY}",
                transport="hand-written", returncode=0)
            package["replay_flow_id"] = manual.stem
            result = tools.verify_evidence_package(ws, package)
            self.assertFalse(result["ok"])
            self.assertIn("replay integrity", result["reason"])

    def test_replay_of_another_flow_is_rejected(self):
        with isolated_runtime():
            ws = workspace()
            package = write_evidence_package(ws)
            other = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
                f"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{POSITIVE_BODY}",
                transport="curl", returncode=0)
            package["second_run_flow_id"] = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
                f"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{POSITIVE_BODY}",
                transport=f"replay:{other.stem}", returncode=0).stem
            result = tools.verify_evidence_package(ws, package)
            self.assertFalse(result["ok"])
            self.assertIn("replay integrity", result["reason"])

    def test_identical_control_with_differs_predicate_is_rejected(self):
        with isolated_runtime():
            ws = workspace()
            package = write_evidence_package(ws, status_positive=200,
                                             status_control=200)
            result = tools.verify_evidence_package(ws, package)
            self.assertFalse(result["ok"])
            self.assertIn("claim support", result["reason"])

    def test_control_target_change_without_declared_variable_is_rejected(self):
        with isolated_runtime():
            ws = workspace()
            package = write_evidence_package(ws)
            control = tools._save_flow(
                ws, REQUEST_METHOD, "https://example.test/api/v2/users/3",
                REQUEST_HEADERS, None,
                "HTTP/1.1 403 Forbidden\nContent-Type: application/json\n\n"
                '{"error": "forbidden"}', transport="curl", returncode=0)
            package["control_flow_id"] = control.stem
            result = tools.verify_evidence_package(ws, package)
            self.assertFalse(result["ok"])
            self.assertIn("control isolation", result["reason"])
            # Prose never authorizes a request change; only the structured
            # declaration does, and only when exactly that input differs.
            package["changed_variable"] = "object id in the request path"
            self.assertFalse(tools.verify_evidence_package(ws, package)["ok"])
            package["control_variable"] = {"location": "url_path",
                                           "name": "path"}
            verified = tools.verify_evidence_package(ws, package)
            self.assertTrue(verified["ok"], verified)

    def test_header_claim_supports_presence_and_value(self):
        with isolated_runtime():
            ws = workspace()
            positive = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
                "HTTP/1.1 200 OK\nX-Cache: MISS\nContent-Type: text/plain\n\nbody",
                transport="curl", returncode=0)
            control = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
                "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nbody",
                transport="curl", returncode=0)
            replay_a = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
                "HTTP/1.1 200 OK\nX-Cache: MISS\nContent-Type: text/plain\n\nbody",
                transport=f"replay:{positive.stem}", returncode=0)
            replay_b = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
                "HTTP/1.1 200 OK\nX-Cache: MISS\nContent-Type: text/plain\n\nbody",
                transport=f"replay:{positive.stem}", returncode=0)
            package = {
                "positive_flow_id": positive.stem,
                "control_flow_id": control.stem,
                "replay_flow_id": replay_a.stem,
                "second_run_flow_id": replay_b.stem,
                "differential_claim": {
                    "dimension": "header_present:X-Cache",
                    "predicate": "differs",
                    "positive_value": "present", "control_value": "absent",
                },
                "changed_variable": "cache state at the edge node",
                "precondition_notes": "same principal on both sides",
                "environment_notes": "shared edge cache, one time window",
            }
            self.assertTrue(tools.verify_evidence_package(ws, package)["ok"])
            package["differential_claim"] = {
                "dimension": "header_value:X-Cache",
                "predicate": "positive_matches",
                "positive_value": "MISS", "control_value": "",
            }
            self.assertTrue(tools.verify_evidence_package(ws, package)["ok"])
            package["differential_claim"]["positive_value"] = "HIT"
            result = tools.verify_evidence_package(ws, package)
            self.assertFalse(result["ok"])
            self.assertIn("claim support", result["reason"])

    def test_unsupported_dimensions_and_predicates_are_rejected(self):
        with isolated_runtime():
            ws = workspace()
            package = write_evidence_package(ws)
            package["differential_claim"]["dimension"] = "timing"
            result = tools.verify_evidence_package(ws, package)
            self.assertFalse(result["ok"])
            self.assertIn("claim support", result["reason"])
            package["differential_claim"]["dimension"] = "smell"
            self.assertFalse(
                tools.verify_evidence_package(ws, package)["ok"])
            package["differential_claim"]["dimension"] = "status"
            package["differential_claim"]["predicate"] = "feels"
            self.assertFalse(
                tools.verify_evidence_package(ws, package)["ok"])

    def test_stale_replay_is_rejected(self):
        with isolated_runtime():
            ws = workspace()
            package = write_evidence_package(ws)
            make_stale(ws, package["replay_flow_id"])
            result = tools.verify_evidence_package(ws, package)
            self.assertFalse(result["ok"])
            self.assertIn("freshness", result["reason"])

    def test_record_finding_raises_on_unverifiable_package(self):
        with isolated_runtime():
            ws = workspace()
            package = write_evidence_package(ws)
            package["positive_flow_id"] = "flow-9999999999999999"
            with self.assertRaises(ValueError) as raised:
                ws.record_finding(title="Claim", severity="P2", vuln_class="IDOR",
                                  surface="/api/v2/users/2", description="impact",
                                  poc="steps", evidence="flows/positive.http",
                                  root_cause="unscoped object id", case_kind="read",
                                  evidence_package=package)
            self.assertIn("evidence package verification failed", str(raised.exception))
            self.assertIn("tested_technique_log", str(raised.exception))
            self.assertEqual(ws.findings.all(), [])
            with self.assertRaises(ValueError):
                ws.record_finding(title="Claim", severity="P2", vuln_class="IDOR",
                                  surface="/api/v2/users/2", description="impact",
                                  poc="steps", evidence="flows/positive.http",
                                  root_cause="unscoped object id", case_kind="read",
                                  evidence_package="flow-0001")

    def test_p3_without_package_still_records(self):
        with isolated_runtime():
            ws = workspace()
            result = dispatch(ws, "record_finding", _common_args(severity="P3"))
            self.assertTrue(result["ok"], result)
            self.assertNotIn("evidence_package", result["data"])
            record = ws.record_finding(title="Direct P3", severity="P3",
                                       vuln_class="IDOR", surface="/x",
                                       description="impact", poc="steps",
                                       evidence="flows/x.http",
                                       root_cause="direct low-severity probe",
                                       case_kind="read")
            self.assertNotIn("evidence_package", record)

    def test_mcp_p2_without_package_is_rejected_with_guidance(self):
        with isolated_runtime():
            ws = workspace()
            result = dispatch(ws, "record_finding", _common_args())
            self.assertFalse(result["ok"])
            self.assertIn(
                "P1/P2 candidates require an evidence package", result["summary"])
            self.assertIn("tested_technique_log", result["summary"])
            self.assertEqual(ws.findings.all(), [])

    def test_mcp_p2_with_structurally_invalid_package_is_rejected(self):
        with isolated_runtime():
            ws = workspace()
            result = dispatch(ws, "record_finding", _common_args(
                evidence_package={"positive_flow_id": "flow-1"}))
            self.assertFalse(result["ok"])
            self.assertIn(
                "P1/P2 candidates require an evidence package", result["summary"])
            malformed = write_evidence_package(ws)
            malformed["differential_claim"]["extra"] = "field"
            result = dispatch(ws, "record_finding", _common_args(
                evidence_package=malformed))
            self.assertFalse(result["ok"])
            self.assertIn(
                "P1/P2 candidates require an evidence package", result["summary"])

    def test_mcp_p2_with_verified_package_records(self):
        with isolated_runtime():
            ws = workspace()
            result = dispatch(ws, "record_finding", _common_args(
                evidence_package=write_evidence_package(ws)))
            self.assertTrue(result["ok"], result)
            self.assertIn("independent Astra validation", result["summary"])
            self.assertIn("evidence_package", result["data"])
            self.assertEqual(result["data"]["status"], "validation-pending")

    def test_mcp_p2_with_failing_verification_maps_value_error(self):
        with isolated_runtime():
            ws = workspace()
            package = write_evidence_package(ws)
            make_stale(ws, package["replay_flow_id"])
            result = dispatch(ws, "record_finding", _common_args(
                evidence_package=package))
            self.assertFalse(result["ok"])
            self.assertTrue(result["summary"].startswith(
                "Evidence verification failed:"))
            self.assertIn("freshness", result["summary"])
            self.assertEqual(ws.findings.all(), [])


class EvidenceHardeningRegressionTest(unittest.TestCase):
    """Regressions for the review findings: CRLF captures, duplicate roles,
    declared-value honesty, and replay stability."""

    @staticmethod
    def _crlf_response(status: int, body: str) -> str:
        reason = {200: "OK", 403: "Forbidden"}.get(status, "Status")
        return (f"HTTP/1.1 {status} {reason}\r\n"
                "Content-Type: application/json\r\n"
                f"\r\n{body}")

    def _write_crlf_package(self, ws, *, second_body=POSITIVE_BODY) -> dict:
        """Mirror real curl captures: LF section markers, CRLF wire content."""
        paths = []
        positive_id = ""
        specs = [("curl", 200, POSITIVE_BODY), ("curl", 403, '{"error": "no"}'),
                 ("replay", 200, POSITIVE_BODY), ("replay", 200, second_body)]
        for transport, status, body in specs:
            prefix = (f"replay:{positive_id}"
                      if transport == "replay" else transport)
            path = tools._save_flow(
                ws, REQUEST_METHOD, REQUEST_URL, REQUEST_HEADERS, None,
                self._crlf_response(status, body), transport=prefix, returncode=0)
            if not positive_id:
                positive_id = path.stem
            paths.append(path)
        return {
            "positive_flow_id": paths[0].stem,
            "control_flow_id": paths[1].stem,
            "replay_flow_id": paths[2].stem,
            "second_run_flow_id": paths[3].stem,
            "differential_claim": {
                "dimension": "status", "predicate": "differs",
                "positive_value": "200", "control_value": "403",
            },
            "changed_variable": "session principal",
            "precondition_notes": "authenticated user 1",
            "environment_notes": "single origin",
        }

    def test_crlf_captures_verify_with_real_body_digests(self):
        with isolated_runtime():
            ws = workspace("crlf-evidence")
            package = self._write_crlf_package(ws)
            result = tools.verify_evidence_package(ws, package)
            self.assertTrue(result["ok"], result)
            digests = result["digests"][package["positive_flow_id"]]
            self.assertEqual(digests["response_body_bytes"], len(POSITIVE_BODY))
            import hashlib
            self.assertEqual(digests["response_body_sha256"],
                             hashlib.sha256(POSITIVE_BODY.encode()).hexdigest())
            record = ws.record_finding(
                title="CRLF capture IDOR", severity="P2",
                vuln_class="broken access control", surface="/api/v2/users/2",
                description="other principal's record returned",
                poc="replay positive vs control with second token",
                evidence="flows referenced by package",
                root_cause="missing object ownership check", case_kind="route",
                evidence_package=package)
            self.assertEqual(record["status"], "validation-pending")

    def test_duplicate_replay_flow_id_rejected(self):
        with isolated_runtime():
            ws = workspace("dup-evidence")
            package = write_evidence_package(ws)
            package["second_run_flow_id"] = package["replay_flow_id"]
            result = tools.verify_evidence_package(ws, package)
            self.assertFalse(result["ok"])
            self.assertIn("distinct", result["reason"])
            with self.assertRaises(ValueError):
                ws.record_finding(title="Dup", severity="P2",
                                  vuln_class="x", surface="/x",
                                  description="d", poc="p", evidence="e",
                                  case_kind="route", root_cause="r",
                                  evidence_package=package)

    def test_declared_value_mismatch_rejected(self):
        with isolated_runtime():
            ws = workspace("declared-evidence")
            package = write_evidence_package(ws)
            package["differential_claim"]["positive_value"] = "418"
            result = tools.verify_evidence_package(ws, package)
            self.assertFalse(result["ok"])
            self.assertIn("declared", result["reason"])

    def test_unstable_replay_rejected(self):
        with isolated_runtime():
            ws = workspace("unstable-evidence")
            package = self._write_crlf_package(
                ws, second_body='{"user": "2", "email": "changed@example.test"}')
            result = tools.verify_evidence_package(ws, package)
            self.assertFalse(result["ok"])
            self.assertIn("replay stability", result["reason"])


if __name__ == "__main__":
    unittest.main()

    def test_symlink_capture_rejected(self):
        with isolated_runtime():
            ws = workspace("symlink-evidence")
            package = write_evidence_package(ws)
            real = ws.flows_dir / f"{package['positive_flow_id']}.http"
            alias = ws.flows_dir / f"flow-999999999{real.stem[5:]}.http"
            alias.symlink_to(real.name)
            package["replay_flow_id"] = alias.stem
            result = tools.verify_evidence_package(ws, package)
            self.assertFalse(result["ok"])
            self.assertIn("regular file", result["reason"])
