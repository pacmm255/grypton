from __future__ import annotations

import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from grypton import config
from grypton.bugcrowd import analyze_snapshot, matching_scope_rules, out_of_scope_rules
from grypton.cli import _constraints, _validate_requested_findings, build_parser
from grypton.engine import Engine
from grypton.hard_lab import HardLab, score_workspace
from grypton.manager import KryptexManager, ManagerContext, _check_schema, _extract_json
from grypton.providers import MCP_TIMEOUT_MS, OpenCodeClient, OpenCodeResult
from grypton.reporting import audit_workspace, render_report
from grypton.toolserver import REGISTRY, dispatch
from grypton.tools import (apk_extract_asset, apk_inspect, artifact_download, check_host_scope,
                           check_url_scope, flow_read, flow_replay, http_request, port_scan,
                           tcp_exchange)
from grypton.worker import OpenCodeWorker, WorkerSpec
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
            "TARGET_DATA_DIR": root / "target",
        }
        with patch.multiple(config, **values):
            config.ensure_layout()
            yield root


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/large":
            payload = ("A" * 20_000 + "END-MARKER").encode()
        else:
            payload = json.dumps({"path": self.path, "marker": "local-lab"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@contextmanager
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class CliTests(unittest.TestCase):
    def test_init_accepts_named_and_positional_targets(self):
        parser = build_parser()
        named = parser.parse_args(["init", "--target", "example.test"])
        positional = parser.parse_args(["init", "example.test"])
        self.assertEqual(named.target_option, "example.test")
        self.assertEqual(positional.target, "example.test")

    def test_exact_routes_are_pinned(self):
        self.assertEqual(config.WORKER_MODEL, "zai-coding-plan/glm-5.3")
        self.assertEqual(config.WORKER_EFFORT, "max")
        self.assertEqual(config.MANAGER_MODEL, "opencode-go/muse-spark-1.3-contributor")
        self.assertEqual(config.MANAGER_EFFORT, "xhigh")
        self.assertEqual(config.VALIDATOR_MODEL, "gpt-6-astra")
        self.assertEqual(config.VALIDATOR_EFFORT, "max")
        self.assertEqual(config.ASTRA_AUTO_SEVERITIES, {"P1", "P2"})
        self.assertTrue(config.astra_auto_validation_required("p1"))
        self.assertTrue(config.astra_auto_validation_required("P2"))
        self.assertFalse(config.astra_auto_validation_required("P3"))
        self.assertEqual(config.PROMPTS_DIR, config.PACKAGE_DIR / "resources" / "prompts")
        self.assertTrue((config.PROMPTS_DIR / "worker_system.md").is_file())

    def test_review_commands_parse(self):
        parser = build_parser()
        for command in ("show", "findings", "surface", "history", "scope", "audit", "report"):
            parsed = parser.parse_args([command, "example-test"])
            self.assertEqual(parsed.target, "example-test")
        validate = parser.parse_args(["validate", "example-test", "F003"])
        self.assertEqual(validate.target, "example-test")
        self.assertEqual(validate.finding_ids, ["F003"])

    def test_hard_benchmark_commands_parse(self):
        parser = build_parser()
        served = parser.parse_args(["benchmark", "serve", "--out", "/tmp/benchmark"])
        scored = parser.parse_args(["benchmark", "score", "/tmp/benchmark/manifest.json", "lab-target"])
        self.assertEqual(served.out, "/tmp/benchmark")
        self.assertEqual(scored.target, "lab-target")

    def test_bugcrowd_brief_preflight_imports_scope_and_blocks_automation(self):
        document = {
            "id": "synthetic",
            "knownIssuesEnabled": True,
            "isLoggedIn": False,
            "data": {
                "brief": {"description": (
                    "Test using only accounts created with @bugcrowdninja.com email addresses."
                )},
                "scope": [
                    {"name": "web", "inScope": True, "targets": [
                        {"name": "*.example.test", "uri": "*.example.test", "category": "website"},
                        {"name": "GraphQL", "uri": "https://api.example.test/graphql", "category": "api"},
                    ]},
                    {"name": "excluded", "inScope": False, "targets": [
                        {"name": "admin.example.test", "uri": "https://admin.example.test", "category": "website"},
                    ]},
                ],
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "brief.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            profile = analyze_snapshot(path)
            self.assertTrue(profile["credential_requirement"])
            self.assertIn("Target [IN SCOPE] GraphQL", profile["brief_text"])
            self.assertIn("Target [OUT OF SCOPE] admin.example.test", profile["brief_text"])
            self.assertEqual(matching_scope_rules(profile, "https://api.example.test/graphql"),
                             ["*.example.test", "https://api.example.test/graphql"])
            self.assertEqual(matching_scope_rules(profile, "https://api.example.test/"),
                             ["*.example.test"])
            self.assertEqual(matching_scope_rules(profile, "https://outside.test/"), [])
            self.assertEqual(out_of_scope_rules(profile), ["https://admin.example.test"])
            ns = SimpleNamespace(
                bugcrowd_brief=str(path), only="", exclude="", include="",
                in_scope="", out_scope="", rule=[], authorization_file=None,
            )
            constraints = _constraints(ns, "https://api.example.test/graphql")
            self.assertIn("*.example.test", constraints.in_scope)
            self.assertIn("https://admin.example.test", constraints.out_of_scope)

            document["data"]["brief"]["description"] += (
                " Use of any automated tools/scanners is strictly prohibited."
            )
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "prohibits automated"):
                _constraints(ns, "https://api.example.test/graphql")

    def test_cli_exits_when_engine_stops_with_stdin_still_open(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            env = {**os.environ, "GRYPTON_HOME": str(home), "PYTHONPATH": str(repo)}
            process = subprocess.Popen(
                [sys.executable, "-m", "grypton", "init", "--target", "shutdown.test",
                 "--backend", "mock", "--max-turns", "1", "--force"],
                cwd=repo, env=env, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                returncode = process.wait(timeout=10)
            finally:
                if process.poll() is None:
                    process.kill()
            stdout, stderr = process.communicate(timeout=2)
            self.assertEqual(returncode, 0, stderr)
            self.assertIn("Engine stopped after 1 turn(s)", stdout)


class ToolTests(unittest.TestCase):
    def test_main_cli_forwards_tool_options(self):
        with patch("grypton.toolserver.cli_main", return_value=17) as tool_main:
            from grypton.cli import main

            self.assertEqual(
                main(["tools", "--target", "example.test", "--json", "inventory"]),
                17,
            )
            tool_main.assert_called_once_with(
                ["--target", "example.test", "--json", "inventory"]
            )

    def test_scope_capture_and_replay(self):
        with isolated_runtime(), local_server() as port:
            ws = Workspace("local-tools")
            ws.create(f"http://127.0.0.1:{port}", "web")
            ws.save_constraints(Constraints(in_scope=["127.0.0.1"],
                                            out_of_scope=["example.com"]))
            allowed, _ = check_host_scope(ws, "127.0.0.1")
            denied, _ = check_host_scope(ws, "example.com")
            self.assertTrue(allowed)
            self.assertFalse(denied)
            first = http_request(ws, f"http://127.0.0.1:{port}/first")
            self.assertTrue(first["ok"], first)
            self.assertIn("local-lab", first["data"]["response"])
            head = http_request(ws, f"http://127.0.0.1:{port}/first", method="HEAD")
            self.assertTrue(head["ok"], head)
            self.assertEqual(head["data"]["returncode"], 0)
            flow_id = Path(first["data"]["flow"]).stem
            self.assertIn("GET http://127.0.0.1", flow_read(ws, flow_id)["data"]["text"])
            replay = flow_replay(ws, flow_id, url=f"http://127.0.0.1:{port}/second")
            self.assertTrue(replay["ok"], replay)
            blocked = http_request(ws, "https://example.com/")
            self.assertFalse(blocked["ok"])
            self.assertIn("Scope blocked", blocked["summary"])

    def test_url_scope_binds_explicit_port_and_blocks_automatic_redirects(self):
        with isolated_runtime(), local_server() as port:
            ws = Workspace("exact-port")
            target = f"http://127.0.0.1:{port}"
            ws.create(target, "web")
            ws.save_constraints(Constraints(in_scope=[target]))
            self.assertTrue(check_url_scope(ws, target + "/")[0])
            self.assertFalse(check_url_scope(ws, f"http://127.0.0.1:{port + 1}/")[0])
            self.assertFalse(port_scan(ws, "127.0.0.1", [port + 1])["ok"])
            redirect = http_request(ws, target + "/", follow_redirects=True)
            self.assertFalse(redirect["ok"])
            self.assertIn("scope-check its Location", redirect["summary"])

    def test_large_http_capture_is_bounded_for_model_but_complete_on_disk(self):
        with isolated_runtime(), local_server() as port:
            ws = Workspace("large-capture")
            target = f"http://127.0.0.1:{port}"
            ws.create(target, "web")
            ws.save_constraints(Constraints(in_scope=[target]))
            result = http_request(ws, target + "/large")
            self.assertTrue(result["ok"], result)
            self.assertTrue(result["data"]["response_truncated"])
            self.assertNotIn("END-MARKER", result["data"]["response"])
            self.assertIn("END-MARKER", Path(result["data"]["flow"]).read_text())

    def test_mcp_registry_has_no_claude_advisor(self):
        self.assertGreaterEqual(len(REGISTRY), 20)
        self.assertIn("http_request", REGISTRY)
        self.assertIn("flow_replay", REGISTRY)
        self.assertIn("goja_stop", REGISTRY)
        self.assertIn("tcp_exchange", REGISTRY)
        self.assertIn("artifact_download", REGISTRY)
        self.assertIn("apk_inspect", REGISTRY)
        self.assertNotIn("advise", REGISTRY)

    def test_dispatch_writes_audit_event(self):
        with isolated_runtime():
            ws = Workspace("audit")
            ws.create("127.0.0.1", "web")
            result = dispatch(ws, "tool_inventory", {})
            self.assertTrue(result["ok"])
            log = ws.root / ".ledger/tool-calls.jsonl"
            self.assertEqual(json.loads(log.read_text().splitlines()[0])["tool"], "tool_inventory")

    def test_record_finding_summary_matches_astra_threshold(self):
        with isolated_runtime():
            ws = Workspace("threshold-summary")
            ws.create("127.0.0.1", "web")
            common = {"vuln_class": "test", "surface": "/local",
                      "description": "Synthetic impact", "poc": "1. Send request",
                      "evidence": "flows/synthetic.http"}
            low = dispatch(ws, "record_finding", {"title": "Low", "severity": "P5", **common})
            high = dispatch(ws, "record_finding", {"title": "High", "severity": "P2", **common})
            self.assertIn("not requested for P5", low["summary"])
            self.assertIn("independent Astra validation", high["summary"])

    def test_record_finding_rejects_incomplete_worker_hypothesis(self):
        with isolated_runtime():
            ws = Workspace("finding-gate")
            ws.create("127.0.0.1", "web")
            result = dispatch(ws, "record_finding", {"title": "Signal", "severity": "P3"})
            self.assertFalse(result["ok"])
            self.assertIn("quality gate", result["summary"])
            self.assertEqual(ws.findings.all(), [])

    def test_read_only_engagement_audit_and_report(self):
        with isolated_runtime() as root, patch.object(config, "GRYPTON_HOME", root):
            ws = Workspace("report")
            ws.create("127.0.0.1", "web")
            ws.save_constraints(Constraints(in_scope=["127.0.0.1"]))
            low = ws.record_finding(title="Low candidate", severity="P3")
            self.assertEqual(low["status"], "validation-not-requested")
            result = audit_workspace(ws)
            self.assertTrue(result["ok"], result)
            self.assertTrue(result["target_dir_empty"])
            self.assertEqual(result["validation_not_requested"], [low["id"]])
            high = ws.record_finding(title="High candidate", severity="P2")
            self.assertEqual(high["status"], "validation-pending")
            result = audit_workspace(ws)
            self.assertFalse(result["ok"])
            self.assertEqual(result["unvalidated_findings"], [high["id"]])
            ws.set_severity_verdict(high["id"], {
                "finding_id": high["id"], "verdict": "confirm", "severity": "P2",
                "confidence": 0.9, "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": config.VALIDATOR_EFFORT,
            })
            result = audit_workspace(ws)
            self.assertTrue(result["ok"], result)
            self.assertIn("# Grypton report", render_report(ws))


@unittest.skipUnless(
    all((Path("/opt/android-sdk/platforms/android-34/android.jar").is_file(),
         Path("/opt/android-sdk/build-tools/34.0.0/d8").is_file(),
         bool(config.find_binary("aapt")), bool(config.find_binary("apksigner")),
         bool(config.find_binary("keytool")))),
    "Android SDK build tools are required for the APK benchmark fixture",
)
class HardBenchmarkTests(unittest.TestCase):
    def test_loopback_benchmark_exposes_only_public_black_box_material(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "benchmark"
            with HardLab(output) as lab:
                manifest = lab.public_manifest()
                public = json.dumps(manifest, sort_keys=True)
                self.assertTrue((output / "manifest.json").is_file())
                self.assertTrue(lab.state.apk_path and lab.state.apk_path.is_file())
                self.assertNotIn(lab.state.key.hex(), public)
                self.assertNotIn("score_key", public)
                self.assertNotIn("receipt", public.lower())
                self.assertEqual(manifest["scope"]["source_audit"], "out of scope")

                with isolated_runtime():
                    ws = Workspace("hard-lab")
                    ws.create(manifest["entrypoints"]["web"], "web")
                    ws.save_constraints(Constraints(in_scope=manifest["engagement"]["in_scope"]))
                    artifact = artifact_download(ws, manifest["entrypoints"]["apk"], "courier.apk")
                    self.assertTrue(artifact["ok"], artifact)
                    inspected = apk_inspect(ws, "courier.apk")
                    self.assertTrue(inspected["ok"], inspected)
                    self.assertTrue(inspected["data"]["has_classes_dex"])
                    self.assertTrue(inspected["data"]["signature"]["verified"], inspected)
                    asset = inspected["data"]["assets"][0]["name"]
                    extracted = apk_extract_asset(ws, "courier.apk", asset)
                    self.assertTrue(extracted["ok"], extracted)
                    host, port = manifest["entrypoints"]["network"].rsplit(":", 1)
                    exchange = tcp_exchange(ws, host, int(port), '{"op":"status"}')
                    self.assertTrue(exchange["ok"], exchange)
                    self.assertIn("Courier Relay", exchange["data"]["banner"])
                    self.assertEqual(score_workspace(output / "manifest.json", ws.root)["score"]["covered"], 0)


class ManagerTests(unittest.IsolatedAsyncioTestCase):
    def test_json_extraction_and_strict_schema(self):
        value = _extract_json("```json\n{\"x\": 1}\n```")
        self.assertEqual(value, {"x": 1})
        errors = _check_schema(value, {"type": "object", "additionalProperties": False,
            "required": ["x"], "properties": {"x": {"type": "number"}}})
        self.assertEqual(errors, [])

    async def test_static_manager_prompt_is_not_reinjected_each_turn(self):
        with isolated_runtime():
            ws = Workspace("manager-prompt")
            ws.create("127.0.0.1", "web")
            marker = "STATIC-MANAGER-MARKER"
            manager = KryptexManager(ws, marker)
            prompt = manager._build_direction_prompt(ManagerContext(
                target="127.0.0.1", target_type="web", turn_index=1,
                convergence_reason="repeated probe convergence",
            ))
            self.assertIn(marker, manager.client.agent_prompt)
            self.assertNotIn(marker, prompt)
            self.assertIn("CONVERGENCE GUARD", prompt)

    async def test_spark_cannot_supply_validation_verdicts(self):
        with isolated_runtime():
            ws = Workspace("manager")
            ws.create("127.0.0.1", "web")
            manager = KryptexManager(ws, "system")
            response = {
                "assessment": "real tool use", "directive": "capture one control request",
                "corrections": [], "new_angles": [], "exhaustion_breaker": "",
                "scope_enforcement": [],
                "severity_validations": [{"finding_id": "F001", "verdict": "confirm",
                    "severity": "P1", "confidence": 1, "reasoning": "self grade"}],
                "to_user": "working", "continue": True, "stop_reason": "", "confidence": 0.8,
            }
            manager.client.call = AsyncMock(return_value=OpenCodeResult(
                text=json.dumps(response), session_id="ses-manager", events=[], tools=[],
                usage=[], duration_s=0.1))
            directive = await manager.direct(ManagerContext(
                target="127.0.0.1", target_type="web", turn_index=1))
            self.assertEqual(directive.severity_validations, [])
            self.assertEqual(manager.session_id, "ses-manager")

    async def test_evidence_snapshot_includes_every_referenced_flow(self):
        with isolated_runtime():
            ws = Workspace("evidence")
            ws.create("127.0.0.1", "web")
            ws.flows_dir.mkdir(parents=True, exist_ok=True)
            names = [f"flow-{index}.http" for index in range(5)]
            for index, name in enumerate(names):
                (ws.flows_dir / name).write_text(
                    f"capture-{index}\n" + (str(index) * 80_000), encoding="utf-8"
                )
            manager = KryptexManager(ws, "system")
            snapshot = manager._evidence_snapshot({
                "evidence": "flows/" + names[0] + ", " + ", ".join(names[1:])
            })
            for index in range(5):
                self.assertIn(f"capture-{index}", snapshot)

    async def test_lower_severity_requires_explicit_astra_request(self):
        with isolated_runtime():
            ws = Workspace("explicit-validation")
            ws.create("127.0.0.1", "web")
            finding = ws.record_finding(title="Medium candidate", severity="P3")
            manager = KryptexManager(ws, "system")
            manager.validator.validate = AsyncMock(return_value={
                "finding_id": finding["id"], "verdict": "confirm", "severity": "P3",
                "confidence": 0.8, "reasoning": "Explicitly reviewed.",
                "independent_checks": [], "exploitability": "Evidence supports the claim.",
            })
            context = ManagerContext(target="127.0.0.1", target_type="web", turn_index=1)
            with self.assertRaisesRegex(ValueError, "limited to P1/P2"):
                await manager.validate_severity(finding, context)
            manager.validator.validate.assert_not_awaited()
            verdict = await manager.validate_severity(finding, context, explicit=True)
            self.assertEqual(verdict["validator_model"], config.VALIDATOR_MODEL)
            manager.validator.validate.assert_awaited_once()

    async def test_explicit_cli_helper_validates_and_persists_lower_severity(self):
        with isolated_runtime():
            ws = Workspace("cli-validation")
            ws.create("127.0.0.1", "web")
            finding = ws.record_finding(title="Low candidate", severity="P4")
            verdict = {
                "finding_id": finding["id"], "verdict": "confirm", "severity": "P4",
                "confidence": 0.9, "reasoning": "Explicit review result.",
                "independent_checks": [], "exploitability": "Low impact.",
                "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": config.VALIDATOR_EFFORT,
            }
            with patch.object(
                KryptexManager, "validate_severity", AsyncMock(return_value=verdict)
            ) as validate:
                results = await _validate_requested_findings(ws, [finding])
            self.assertEqual(results, [verdict])
            self.assertTrue(validate.await_args.kwargs["explicit"])
            self.assertEqual(ws.findings.all()[0]["status"], "confirmed")


class WorkerEventTests(unittest.TestCase):
    def test_opencode_transport_workspace_is_outside_engagement(self):
        with isolated_runtime() as root:
            workspace = config.ENGAGEMENTS_DIR / "transport-test"
            workspace.mkdir(parents=True)
            client = OpenCodeClient(
                role="worker",
                route="zai-coding-plan/glm-5.3",
                effort="max",
                workspace=workspace,
                target_slug="transport-test",
                allow_tools=True,
                agent_prompt="test",
            )
            self.assertEqual(
                client.transport_workspace,
                root / ".opencode-workspaces/transport-test/worker",
            )
            self.assertEqual(
                (client.transport_workspace / "engagement").resolve(),
                workspace.resolve(),
            )
            self.assertEqual(client.transcripts, workspace / "transcripts")

    def test_worker_permissions_force_network_through_captured_tools(self):
        permissions = OpenCodeClient._permissions(True)
        self.assertEqual(permissions["webfetch"], "deny")
        self.assertEqual(permissions["websearch"], "deny")
        self.assertEqual(permissions["bash"]["*"], "allow")
        for command in ("curl *", "*/curl *", "httpx *", "*/nmap *"):
            self.assertEqual(permissions["bash"][command], "deny")

        manager_permissions = OpenCodeClient._permissions(False)
        self.assertEqual(manager_permissions["*"], "deny")

    def test_tool_error_text_is_rendered_and_retained(self):
        with isolated_runtime():
            events = []
            worker = OpenCodeWorker(WorkerSpec(
                session_uuid="", cwd=Path(config.ENGAGEMENTS_DIR) / "events",
                system_prompt="test", extra_env={"GRYPTON_TARGET": "events"},
            ), on_event=events.append)
            worker._translate_event({
                "type": "tool_use",
                "part": {"tool": "grypton_http_request", "callID": "call-1", "state": {
                    "status": "error", "input": {"url": "https://example.test"},
                    "error": "MCP error -32001: Request timed out",
                }},
            })
            result = events[-1]["message"]["content"][0]
            self.assertTrue(result["is_error"])
            self.assertEqual(result["content"], "MCP error -32001: Request timed out")
            self.assertEqual(MCP_TIMEOUT_MS, 120_000)

    def test_static_worker_prompt_is_not_reinjected_each_turn(self):
        with isolated_runtime():
            marker = "STATIC-WORKER-MARKER"
            worker = OpenCodeWorker(WorkerSpec(
                session_uuid="", cwd=Path(config.ENGAGEMENTS_DIR) / "prompt",
                system_prompt=marker, extra_env={"GRYPTON_TARGET": "prompt"},
            ))
            self.assertIn(marker, worker.client.agent_prompt)
            self.assertNotIn(marker, worker._build_prompt("do one bounded check"))


class EngineTests(unittest.IsolatedAsyncioTestCase):
    def test_automatic_validation_candidates_are_only_p1_and_p2(self):
        findings = [
            {"id": "F001", "severity": "P1", "status": "validation-pending"},
            {"id": "F002", "severity": "P2", "status": "validation-pending"},
            {"id": "F003", "severity": "P3", "status": "validation-not-requested"},
            {"id": "F004", "severity": "P1", "status": "suppressed-by-scope"},
        ]
        selected = Engine._automatic_validation_candidates(findings)
        self.assertEqual([finding["id"] for finding in selected], ["F001", "F002"])

    def test_unvalidated_p1_is_not_confirmed(self):
        with isolated_runtime():
            ws = Workspace("pending-p1")
            ws.create("127.0.0.1", "web")
            finding = ws.record_finding(title="Critical candidate", severity="P1")
            self.assertEqual(finding["status"], "validation-pending")
            self.assertEqual(ws.confirmed_p1s(), [])

    def test_network_novelty_collapses_query_values_and_detects_repetition(self):
        with isolated_runtime():
            ws = Workspace("novelty")
            ws.create("https://example.test", "web")
            engine = Engine("novelty", backend="mock")
            first = {"name": "grypton_http_request", "input": {
                "method": "HEAD", "url": "https://EXAMPLE.test/robots.txt?b=1&a=2"}}
            second = {"name": "grypton_http_request", "input": {
                "method": "HEAD", "url": "https://example.test/robots.txt?a=9&b=8"}}
            self.assertEqual(Engine._network_signature(first), Engine._network_signature(second))
            self.assertEqual(engine._network_novelty([first])["novel"], 1)
            repeat = engine._network_novelty([second])
            self.assertEqual(repeat["novel"], 0)
            self.assertEqual(repeat["repeated"], 1)

    def test_surface_novelty_does_not_reward_numbered_sentinels(self):
        first = {"kind": "cache", "item": "Interval sentinel checkpoint #33"}
        second = {"kind": "cache", "item": "Interval sentinel checkpoint #84"}
        self.assertEqual(Engine._surface_key(first), Engine._surface_key(second))
        self.assertTrue(Engine._surface_is_bookkeeping(first))
        self.assertTrue(Engine._surface_is_bookkeeping({
            "kind": "behavior", "item": "Second passive stability checkpoint (turn 14)"}))
        self.assertFalse(Engine._surface_is_bookkeeping({
            "kind": "endpoint", "item": "POST /graphql"}))

    def test_convergence_stop_reasons_are_accepted(self):
        reason = "convergence: no safe novel action remains"
        self.assertFalse(Engine._is_hard_stop(reason))
        self.assertTrue(Engine._is_hard_stop(reason, convergence_allowed=True))
        self.assertTrue(Engine._is_hard_stop("program automation prohibited"))

    async def test_mock_loop_persists_independent_verdict(self):
        with isolated_runtime():
            old_turns, old_seconds = config.CONFIG.max_turns, config.CONFIG.max_run_seconds
            config.CONFIG.max_turns, config.CONFIG.max_run_seconds = 3, 0
            try:
                ws = Workspace("engine-local")
                ws.create("127.0.0.1", "web")
                ws.save_constraints(Constraints(in_scope=["127.0.0.1"]))
                engine = Engine("engine-local", backend="mock")
                await engine.setup(brief="mock integration", target="127.0.0.1",
                                   target_type="web")
                await engine.run()
                finding = engine.ws.findings.all()[0]
                self.assertEqual(finding["id"], "F001")
                self.assertEqual(finding["manager_verdict"]["verdict"], "confirm")
                self.assertEqual(finding["status"], "confirmed")
                self.assertEqual(len(engine.ws.confirmed_findings()), 1)
                self.assertEqual(engine.ws.load_meta().status, "stopped")
            finally:
                config.CONFIG.max_turns, config.CONFIG.max_run_seconds = old_turns, old_seconds

    async def test_convergence_guard_allows_one_pivot_then_stops_churn(self):
        with isolated_runtime():
            fields = ("max_turns", "max_run_seconds", "passive_stagnation_limit",
                      "repetitive_probe_turn_limit", "exhaustion_threshold")
            old = {field: getattr(config.CONFIG, field) for field in fields}
            config.CONFIG.max_turns = 10
            config.CONFIG.max_run_seconds = 0
            config.CONFIG.passive_stagnation_limit = 2
            config.CONFIG.repetitive_probe_turn_limit = 99
            config.CONFIG.exhaustion_threshold = 99
            try:
                ws = Workspace("converged-loop")
                ws.create("127.0.0.1", "web")
                ws.save_constraints(Constraints(in_scope=["127.0.0.1"]))
                engine = Engine("converged-loop", backend="mock")
                await engine.setup(brief="convergence regression", target="127.0.0.1",
                                   target_type="web")
                engine.worker.script = lambda _worker, _directive: "No new evidence."
                await engine.run()
                self.assertEqual(engine.turn_index, 3)
                self.assertIn("convergence guard", engine.stop_reason)
            finally:
                for field, value in old.items():
                    setattr(config.CONFIG, field, value)


if __name__ == "__main__":
    unittest.main()
