from __future__ import annotations

import asyncio
from contextlib import contextmanager
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from grypton import config, prompts
from grypton.bugcrowd import analyze_snapshot, matching_scope_rules, out_of_scope_rules
from grypton.chat import Renderer, _command_limit, _compact_tool_result, _expand_workspace_references, _route_input
from grypton.cli import (_activity_snapshot, _browser_sandbox_check,
                         _claude_style_arguments, _constraints,
                         _opencode_go_key_pool, _validate_requested_findings,
                         build_parser, main)
from grypton.engine import Engine
from grypton.hard_lab import HardLab, score_workspace
from grypton.manager import (Directive, KryptexManager, ManagerContext,
                             _check_schema, _extract_json)
from grypton.openclaude import TOKEN_ENV
from grypton.providers import (MCP_TIMEOUT_MS, OpenCodeClient, OpenCodeResult, ProviderError,
                               _codex_child_environment)
from grypton.reporting import audit_workspace, render_report
from grypton.toolserver import REGISTRY, dispatch
from grypton.tools import (_browser_executable, _isolated_browser_profile,
                           apk_extract_asset, apk_inspect,
                           artifact_download, browse, check_host_scope, check_port_scope,
                           check_research_scope, check_url_scope, flow_read, flow_replay,
                           http_request, httpx_probe, install_tool, local_analyze, port_scan,
                           research, tcp_exchange, MAX_RESPONSE_BYTES)
from grypton.worker import OpenCodeWorker, WorkerError, WorkerSpec
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
            "CREDENTIALS_DIR": root / ".state/credentials",
            "OPENCODE_WORKSPACES_DIR": root / ".opencode-workspaces",
            "TARGET_DATA_DIR": root / "target",
        }
        with patch.multiple(config, **values):
            config.ensure_layout()
            yield root


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/scoped/redirect-in":
            self.send_response(302)
            self.send_header("Location", "/scoped/final")
            self.end_headers()
            return
        if self.path == "/scoped/redirect-out":
            self.send_response(302)
            self.send_header("Location", "/outside")
            self.end_headers()
            return
        if self.path == "/huge":
            payload = b"H" * (MAX_RESPONSE_BYTES + 4096)
        elif self.path == "/large":
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
    def test_normal_console_compacts_mcp_document_and_capture_payloads(self):
        document = json.dumps({"summary": "Read scope-rules.md (42 characters).",
                               "data": {"text": "secretly very long document body"}})
        capture = json.dumps({"summary": "HTTP 200 · captured flow-1.http",
                              "data": {"status_line": "HTTP/1.1 200 OK",
                                       "flow": "/tmp/flows/flow-1.http",
                                       "response": "very long response"}})
        self.assertEqual(_compact_tool_result(document), "Read scope-rules.md (42 characters).")
        self.assertEqual(_compact_tool_result(capture),
                         "HTTP 200 · captured flow-1.http\nHTTP/1.1 200 OK\ncapture: flow-1.http")

    def test_init_accepts_named_and_positional_targets(self):
        parser = build_parser()
        named = parser.parse_args(["init", "--target", "example.test"])
        positional = parser.parse_args(["init", "example.test"])
        self.assertEqual(named.target_option, "example.test")
        self.assertEqual(positional.target, "example.test")

    def test_exact_routes_are_pinned(self):
        self.assertEqual(config.WORKER_MODEL, "zai-coding-plan/glm-5.3")
        self.assertEqual(config.WORKER_EFFORT, "max")
        self.assertEqual(config.MANAGER_MODEL, "go/muse-spark-1.3-contributor")
        self.assertEqual(config.MANAGER_EFFORT, "xhigh")
        self.assertEqual(config.VALIDATOR_MODEL, "gpt-6-astra")
        self.assertEqual(config.VALIDATOR_EFFORT, "max")
        self.assertEqual(config.ASTRA_AUTO_SEVERITIES, {"P1", "P2"})
        self.assertTrue(config.astra_auto_validation_required("p1"))
        self.assertTrue(config.astra_auto_validation_required("P2"))
        self.assertFalse(config.astra_auto_validation_required("P3"))
        self.assertEqual(config.PROMPTS_DIR, config.PACKAGE_DIR / "resources" / "prompts")
        self.assertTrue((config.PROMPTS_DIR / "worker_system.md").is_file())

    def test_astra_route_ignores_environment_and_saved_config_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "grypton.json").write_text(json.dumps({
                "validator_model": "fixture/not-astra",
                "validator_effort": "low",
            }), encoding="utf-8")
            env = dict(os.environ)
            env.update({
                "GRYPTON_HOME": str(root),
                "GRYPTON_VALIDATOR_MODEL": "fixture/environment-model",
                "GRYPTON_VALIDATOR_EFFORT": "minimal",
                "PYTHONPATH": str(config.SOURCE_ROOT),
            })
            result = subprocess.run(
                [sys.executable, "-c", (
                    "import json; from dataclasses import asdict; "
                    "from grypton import config; "
                    "print(json.dumps({"
                    "'model': config.VALIDATOR_MODEL, "
                    "'effort': config.VALIDATOR_EFFORT, "
                    "'effective': config.effective_role_models()['validator'], "
                    "'saved': asdict(config.CONFIG)}))"
                )],
                cwd=str(config.SOURCE_ROOT), env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            value = json.loads(result.stdout)
        self.assertEqual(value["model"], "gpt-6-astra")
        self.assertEqual(value["effort"], "max")
        self.assertEqual(value["effective"], {
            "route": "gpt-6-astra", "effort": "max",
        })
        self.assertNotIn("validator_model", value["saved"])
        self.assertNotIn("validator_effort", value["saved"])

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

    def test_operator_cli_plan_and_activity_parse_without_starting_a_provider(self):
        parser = build_parser()
        plan = parser.parse_args(["plan", "--target", "preview.test", "--type", "web"])
        activity = parser.parse_args(["activity", "preview-test", "--kind", "flows", "--limit", "3"])
        self.assertEqual(plan.target_option, "preview.test")
        self.assertEqual(activity.kind, "flows")
        self.assertEqual(activity.limit, 3)
        def resolve(route, effort, *, require_tools):
            return {"route": route, "effort": effort}

        with isolated_runtime() as root, redirect_stdout(io.StringIO()) as output, \
                patch("grypton.cli._resolve_role_selection", side_effect=resolve) as resolver:
            self.assertEqual(main([
                "plan", "--target", "preview.test", "--type", "web",
                "--in-scope", "preview.test/api", "--out-scope", "preview.test/admin",
                "--only", "P1,P2", "--include", "access-control", "--exclude", "dos",
                "--rule", "no account recovery",
            ]), 0)
            self.assertFalse((root / ".state" / "engagements" / "preview-test").exists())
            rendered = output.getvalue()
            for value in (
                "--in-scope preview.test/api", "--out-scope preview.test/admin",
                "--only P1,P2", "--include access-control", "--exclude dos",
                "--rule 'no account recovery'",
            ):
                self.assertIn(value, rendered)
            self.assertEqual(resolver.call_count, 2)

        with redirect_stderr(io.StringIO()) as error, \
                patch("grypton.cli._resolve_role_selection", side_effect=ValueError("unknown route")):
            self.assertEqual(main(["plan", "--target", "preview.test"]), 2)
        self.assertIn("invalid model selection", error.getvalue())

    def test_explicit_scope_prompt_adds_no_generated_behavior_rules(self):
        parser = build_parser()
        ns = parser.parse_args([
            "init", "--target", "https://example.test/app",
            "--in-scope", "https://example.test/app,https://example.test/main",
            "--exclude", "clickjacking,open-redirect",
            "--rule", "Minimum accepted severity: /app Medium; /main Critical.",
        ])
        constraints = _constraints(ns, "https://example.test/app")
        self.assertEqual(constraints.hard_rules, [
            "Minimum accepted severity: /app Medium; /main Critical."
        ])
        self.assertEqual(constraints.notes, "")
        rendered = constraints.to_prompt_block()
        self.assertIn("In-scope URLs/hosts:", rendered)
        self.assertIn("Out-of-scope finding categories:", rendered)
        self.assertNotIn("Network actions must", rendered)
        self.assertNotIn("NEVER test", rendered)

    def test_claude_style_direct_invocation_translates_to_scoped_commands(self):
        self.assertEqual(
            _claude_style_arguments(["--target", "preview.test", "map the public API", "-p"]),
            ["init", "--target", "preview.test", "-p", "--brief", "map the public API"],
        )
        self.assertEqual(
            _claude_style_arguments(["-r", "preview-test", "--console", "quiet"]),
            ["resume", "preview-test", "--console", "quiet"],
        )
        parser = build_parser()
        parsed = parser.parse_args(["init", "--target", "preview.test", "--model", "glm", "-p"])
        self.assertEqual(parsed.worker_model, "glm")
        self.assertTrue(parsed.print_mode)

    def test_claude_style_print_mode_runs_without_terminal_input(self):
        saved = (config.CONFIG.backend, config.CONFIG.max_turns, config.CONFIG.max_run_seconds)
        try:
            with isolated_runtime(), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main([
                    "-p", "--target", "http://127.0.0.1:1", "map the local API",
                    "--backend", "mock", "--max-turns", "1", "--console", "quiet",
                ]), 0)
                self.assertIn("Grypton Code", output.getvalue())
        finally:
            config.CONFIG.backend, config.CONFIG.max_turns, config.CONFIG.max_run_seconds = saved

    def test_operator_console_commands_persist_note_and_change_view(self):
        with isolated_runtime():
            ws = Workspace("operator-console")
            ws.create("console.test", "web")
            ws.save_constraints(Constraints(in_scope=["console.test"]))
            engine = SimpleNamespace(
                ws=ws, turn_index=2, _start_time=0.0,
                request_stop=lambda reason: None,
                submit_user=lambda text, to_worker=False: None,
            )
            renderer = Renderer()
            with redirect_stdout(io.StringIO()):
                self.assertFalse(_route_input(engine, renderer, "/view quiet"))
                self.assertFalse(_route_input(engine, renderer, "/compact"))
                self.assertFalse(_route_input(engine, renderer, "/note prioritize state transitions"))
                self.assertFalse(_route_input(engine, renderer, "/summary"))
            self.assertEqual(renderer.view, "quiet")
            self.assertIn("prioritize state transitions", "\n".join(
                ws.load_constraints().standing_instructions
            ))
            self.assertEqual(_command_limit("4", 8), 4)
            with self.assertRaises(ValueError):
                _command_limit("0", 8)

    def test_workspace_mentions_are_limited_to_engagement_documents(self):
        with isolated_runtime():
            ws = Workspace("workspace-mentions")
            ws.create("mentions.test", "web")
            engine = SimpleNamespace(ws=ws)
            expanded = _expand_workspace_references(engine, "Review @findings and @surface")
            self.assertIn("findings.md", expanded)
            self.assertIn("attack-surface.md", expanded)
            with self.assertRaisesRegex(ValueError, "unknown @ reference"):
                _expand_workspace_references(engine, "Read @outside")

    def test_activity_snapshot_redacts_inline_secrets(self):
        with isolated_runtime():
            ws = Workspace("activity-redaction")
            ws.create("activity.test", "web")
            ws.save_constraints(Constraints(in_scope=["activity.test"]))
            ledger = ws.root / ".ledger" / "tool-calls.jsonl"
            ledger.write_text(json.dumps({
                "tool": "http_request", "ok": True,
                "summary": "password=do-not-print token=also-hidden",
            }) + "\n", encoding="utf-8")
            snapshot = _activity_snapshot(ws, 1)
            self.assertNotIn("do-not-print", snapshot["tools"][0]["summary"])
            self.assertNotIn("also-hidden", snapshot["tools"][0]["summary"])

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
                    {"name": "web", "inScope": True, "maxSeverity": "P1", "targets": [
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

    def test_go_key_pool_doctor_check_is_private_and_non_disclosing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pool = root / "open"
            key_one = "fixture_key_A_12345678901234567890"
            key_two = "fixture_key_B_12345678901234567890"
            pool.write_text(f"{key_one}\n{key_two}\n{key_one}\n", encoding="utf-8")
            pool.chmod(0o600)
            ok, detail = _opencode_go_key_pool(pool)
            self.assertTrue(ok, detail)
            self.assertEqual(detail, "count=2; mode=0600")
            self.assertNotIn(key_one, detail)
            self.assertNotIn(key_two, detail)
            pool.chmod(0o644)
            self.assertFalse(_opencode_go_key_pool(pool)[0])
            link = root / "open-link"
            link.symlink_to(pool)
            self.assertFalse(_opencode_go_key_pool(link)[0])

    def test_browser_boundary_fails_closed_for_root_without_dedicated_account(self):
        with patch("grypton.cli.os.geteuid", return_value=0), \
                patch("grypton.cli.pwd.getpwnam", side_effect=KeyError):
            ok, detail = _browser_sandbox_check()
        self.assertFalse(ok)
        self.assertIn("grypton-browser", detail)

        with patch("grypton.tools.os.geteuid", return_value=0), \
                patch("grypton.tools.pwd.getpwnam", side_effect=KeyError):
            with self.assertRaisesRegex(RuntimeError, "Run Grypton as an unprivileged"):
                with _isolated_browser_profile("/bin/true"):
                    pass

    def test_browser_doctor_checks_execution_as_dedicated_identity(self):
        account = SimpleNamespace(pw_uid=23456, pw_gid=23456,
                                  pw_name="grypton-browser")
        denied = SimpleNamespace(returncode=1, stdout="", stderr="permission denied")
        with patch("grypton.cli.os.geteuid", return_value=0), \
                patch("grypton.cli.pwd.getpwnam", return_value=account), \
                patch("grypton.tools._browser_executable", return_value="/browser"), \
                patch("grypton.cli.config.find_binary", return_value="/usr/sbin/runuser"), \
                patch("grypton.cli.subprocess.run", return_value=denied):
            ok, detail = _browser_sandbox_check()
        self.assertFalse(ok)
        self.assertIn("cannot traverse or execute", detail)

    def test_root_browser_profile_uses_private_drop_launcher(self):
        account = SimpleNamespace(pw_uid=23456, pw_gid=23456)
        with patch.dict(os.environ, {
            "AWS_SECRET_ACCESS_KEY": "fixture-cloud-secret",
            "HTTPS_PROXY": "http://fixture-proxy.invalid:8080",
        }), patch("grypton.tools.os.geteuid", return_value=0), \
                patch("grypton.tools.pwd.getpwnam", return_value=account), \
                patch("grypton.tools.os.chown") as chown:
            with _isolated_browser_profile("/bin/true") as profile:
                launcher = Path(profile["executable"])
                profile_dir = Path(profile["profile"])
                data_root = profile_dir.parent
                launcher_root = launcher.parent
                script = launcher.read_text(encoding="utf-8")
                self.assertEqual(profile["identity"], "grypton-browser")
                self.assertEqual(launcher.stat().st_mode & 0o777, 0o500)
                self.assertIn("os.setgroups([])", script)
                self.assertIn("os.setgid(23456)", script)
                self.assertIn("os.setuid(23456)", script)
                self.assertNotIn("AWS_SECRET_ACCESS_KEY", profile["environment"])
                self.assertNotIn("HTTPS_PROXY", profile["environment"])
                self.assertEqual(Path(profile["environment"]["HOME"]).parent, data_root)
                self.assertGreaterEqual(chown.call_count, 7)
            self.assertFalse(data_root.exists())
            self.assertFalse(launcher_root.exists())

    def test_browse_enables_chromium_sandbox_and_keeps_scope_interception(self):
        with isolated_runtime():
            ws = Workspace("browser-sandbox")
            ws.create("https://example.test", "web")
            ws.save_constraints(Constraints(in_scope=["example.test"]))
            observed = {}

            class FakePage:
                url = "https://example.test/"

                def on(self, *_args):
                    return None

                def goto(self, *_args, **_kwargs):
                    return SimpleNamespace(status=200)

                def wait_for_timeout(self, _timeout):
                    return None

                def content(self):
                    return "<html>scoped</html>"

            class FakeContext:
                def __init__(self):
                    self.routes = []

                def route_web_socket(self, *_args):
                    return None

                def route(self, pattern, handler):
                    self.routes.append((pattern, handler))

                def new_page(self):
                    return FakePage()

                def close(self):
                    return None

            context = FakeContext()

            class FakeChromium:
                def launch_persistent_context(self, **kwargs):
                    observed.update(kwargs)
                    return context

            @contextmanager
            def fake_playwright():
                yield SimpleNamespace(chromium=FakeChromium())

            @contextmanager
            def fake_profile(_executable):
                yield {
                    "executable": "/safe/launcher",
                    "profile": "/safe/profile",
                    "environment": {"HOME": "/safe/home"},
                    "identity": "grypton-browser",
                }

            with patch("grypton.tools.config.find_binary", return_value="/bin/true"), \
                    patch("grypton.tools._isolated_browser_profile", fake_profile), \
                    patch("playwright.sync_api.sync_playwright", fake_playwright):
                result = browse(ws, "https://example.test/")

            self.assertTrue(result["ok"], result)
            self.assertTrue(observed["chromium_sandbox"])
            self.assertEqual(observed["executable_path"], "/safe/launcher")
            self.assertEqual(observed["user_data_dir"], "/safe/profile")
            unsafe = {"--no-sandbox", "--disable-setuid-sandbox",
                      "--disable-seccomp-filter-sandbox", "--no-zygote",
                      "--single-process"}
            self.assertFalse(unsafe.intersection(observed["args"]))
            self.assertEqual(context.routes[0][0], "**/*")
            self.assertEqual(result["data"]["browser_identity"], "grypton-browser")

    def test_browser_prefers_packaged_real_binary_over_private_cache_wrapper(self):
        def exists(path):
            return str(path) in {
                "/opt/google/chrome/chrome.real",
                "/opt/google/chrome/chrome",
            }

        with patch("grypton.tools.Path.is_file", autospec=True, side_effect=exists), \
                patch("grypton.tools.config.find_binary", return_value="/usr/bin/google-chrome"):
            self.assertEqual(_browser_executable(), "/opt/google/chrome/chrome.real")

    def test_curl_ignores_user_config_proxy_and_unrelated_environment(self):
        with isolated_runtime():
            ws = Workspace("curl-environment")
            ws.create("https://example.test", "web")
            ws.save_constraints(Constraints(in_scope=["example.test"]))

            def fake_run(argv, **kwargs):
                kwargs["stdout"].write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok")
                return SimpleNamespace(returncode=0, stderr=b"")

            with patch.dict(os.environ, {
                "AWS_SECRET_ACCESS_KEY": "fixture-cloud-secret",
                "HTTPS_PROXY": "http://fixture-proxy.invalid:8080",
            }), patch("grypton.tools.config.find_binary", return_value="/usr/bin/curl"), \
                    patch("grypton.tools.subprocess.run", side_effect=fake_run) as run:
                result = http_request(ws, "https://example.test/")
            self.assertTrue(result["ok"], result)
            argv = run.call_args.args[0]
            self.assertEqual(argv[:2], ["/usr/bin/curl", "--disable"])
            child_env = run.call_args.kwargs["env"]
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", child_env)
            self.assertNotIn("HTTPS_PROXY", child_env)
            self.assertEqual(run.call_args.kwargs["umask"], 0o077)

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

    def test_http_and_replay_reject_destination_and_proxy_routing_headers(self):
        with isolated_runtime(), local_server() as port:
            ws = Workspace("routing-headers")
            target = f"http://127.0.0.1:{port}"
            ws.create(target, "web")
            ws.save_constraints(Constraints(in_scope=[target]))
            first = http_request(ws, target + "/first")
            self.assertTrue(first["ok"], first)
            flow_id = Path(first["data"]["flow"]).stem

            for header in ("Host", "hOsT", "Proxy-Authorization", "Proxy-Connection"):
                with self.subTest(tool="http_request", header=header):
                    result = http_request(ws, target + "/blocked", headers={header: "x"})
                    self.assertFalse(result["ok"], result)
                    self.assertIn("not allowed", result["summary"])
                with self.subTest(tool="flow_replay", header=header):
                    result = flow_replay(ws, flow_id, headers={header: "x"})
                    self.assertFalse(result["ok"], result)
                    self.assertIn("not allowed", result["summary"])

            captured = Path(first["data"]["flow"])
            text = captured.read_text()
            request_line = f"GET {target}/first\n"
            captured.write_text(text.replace(
                request_line, request_line + "Host: injected.invalid\n", 1
            ))
            stored = flow_replay(ws, flow_id)
            self.assertFalse(stored["ok"], stored)
            self.assertIn("not allowed", stored["summary"])

    def test_httpx_requires_full_url_for_url_scoped_target(self):
        with isolated_runtime():
            ws = Workspace("httpx-scheme")
            ws.create("https://api.example.test/", "web")
            ws.save_constraints(Constraints(in_scope=["https://api.example.test/"]))
            with patch("grypton.tools.config.find_binary", return_value="/usr/bin/httpx"), \
                    patch("grypton.tools.subprocess.run", return_value=SimpleNamespace(
                        stdout=b"https://api.example.test [200]", returncode=0
                    )) as run:
                full = httpx_probe(ws, "https://api.example.test/")
                bare = httpx_probe(ws, "api.example.test")
            self.assertTrue(full["ok"], full)
            self.assertFalse(bare["ok"])
            self.assertIn("full scoped URL", bare["summary"])
            self.assertEqual(run.call_count, 1)

    def test_artifact_download_disables_config_proxy_and_bounds_size(self):
        with isolated_runtime():
            ws = Workspace("artifact-environment")
            ws.create("https://example.test", "web")
            ws.save_constraints(Constraints(in_scope=["example.test"]))

            def fake_run(argv, **kwargs):
                Path(argv[argv.index("--output") + 1]).write_bytes(b"fixture-apk")
                Path(argv[argv.index("--dump-header") + 1]).write_text(
                    "HTTP/1.1 200 OK\n", encoding="utf-8"
                )
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with patch.dict(os.environ, {
                "AWS_SECRET_ACCESS_KEY": "fixture-cloud-secret",
                "HTTPS_PROXY": "http://fixture-proxy.invalid:8080",
            }), patch("grypton.tools.config.find_binary", return_value="/usr/bin/curl"), \
                    patch("grypton.tools.subprocess.run", side_effect=fake_run) as run:
                result = artifact_download(
                    ws, "https://example.test/app.apk", "app.apk"
                )
            self.assertTrue(result["ok"], result)
            argv = run.call_args.args[0]
            self.assertEqual(argv[:2], ["/usr/bin/curl", "--disable"])
            self.assertIn("--max-filesize", argv)
            self.assertNotIn("--location", argv)
            self.assertNotIn("HTTPS_PROXY", run.call_args.kwargs["env"])
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", run.call_args.kwargs["env"])
            self.assertEqual(run.call_args.kwargs["umask"], 0o077)

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

    def test_url_scope_enforces_canonical_path_subtrees_and_scheme(self):
        with isolated_runtime():
            ws = Workspace("path-scope")
            ws.create("https://api.example.test/app", "web")
            ws.save_constraints(Constraints(in_scope=["https://api.example.test/app"]))

            for url in (
                "https://api.example.test/app",
                "https://api.example.test/app/",
                "https://api.example.test/app/users?id=1#ignored",
                "https://api.example.test/app%2Fusers",
            ):
                self.assertTrue(check_url_scope(ws, url)[0], url)
            for url in (
                "https://api.example.test/",
                "https://api.example.test/apple",
                "https://api.example.test/app/../admin",
                "https://api.example.test/app/%2e%2e/admin",
                "https://api.example.test/app%2f..%2fadmin",
                "https://api.example.test/app/%255c../admin",
                "https://api.example.test/app/%zz",
                "http://api.example.test:443/app",
            ):
                self.assertFalse(check_url_scope(ws, url)[0], url)

            self.assertFalse(check_host_scope(ws, "api.example.test")[0])
            self.assertFalse(check_port_scope(ws, "api.example.test", 443)[0])
            raw = tcp_exchange(ws, "api.example.test", 443, "GET /app HTTP/1.0")
            self.assertFalse(raw["ok"])
            self.assertIn("recorded URL path", raw["summary"])

    def test_scheme_less_host_path_rule_applies_to_both_web_schemes_only(self):
        with isolated_runtime():
            ws = Workspace("scheme-less-path")
            ws.create("milli.gold/app", "web")
            ws.save_constraints(Constraints(in_scope=["milli.gold/app"]))
            self.assertTrue(check_url_scope(ws, "https://milli.gold/app")[0])
            self.assertTrue(check_url_scope(ws, "http://milli.gold/app/child?x=1")[0])
            self.assertFalse(check_url_scope(ws, "https://milli.gold/")[0])
            self.assertFalse(check_url_scope(ws, "https://milli.gold/apple")[0])
            self.assertFalse(check_host_scope(ws, "milli.gold")[0])
            self.assertFalse(check_port_scope(ws, "milli.gold", 443)[0])

            ws.save_constraints(Constraints(in_scope=["10.0.0.0/24"]))
            self.assertTrue(check_host_scope(ws, "10.0.0.7")[0])
            self.assertTrue(check_port_scope(ws, "10.0.0.7", 8443)[0])

    def test_url_path_exclusions_have_boundary_and_raw_tcp_precedence(self):
        with isolated_runtime():
            ws = Workspace("path-deny")
            ws.create("https://api.example.test", "web")
            ws.save_constraints(Constraints(
                in_scope=["api.example.test"],
                out_of_scope=["https://api.example.test/private"],
            ))
            self.assertFalse(check_url_scope(ws, "https://api.example.test/private")[0])
            self.assertFalse(check_url_scope(ws, "https://api.example.test/private/key")[0])
            self.assertTrue(check_url_scope(ws, "https://api.example.test/privateer")[0])
            self.assertTrue(check_host_scope(ws, "api.example.test")[0])
            self.assertTrue(check_port_scope(ws, "api.example.test", 443)[0])
            raw = tcp_exchange(ws, "api.example.test", 443, "GET / HTTP/1.0")
            self.assertFalse(raw["ok"])
            self.assertIn("cannot enforce", raw["summary"])

    def test_path_scope_covers_http_replay_download_httpx_and_research_redirects(self):
        with isolated_runtime(), local_server() as port:
            ws = Workspace("path-transports")
            root = f"http://127.0.0.1:{port}"
            scoped = root + "/scoped"
            ws.create(scoped, "web")
            ws.save_constraints(Constraints(in_scope=[scoped]))

            first = http_request(ws, scoped + "/first")
            self.assertTrue(first["ok"], first)
            flow_id = Path(first["data"]["flow"]).stem
            replay = flow_replay(ws, flow_id, url=root + "/outside")
            self.assertFalse(replay["ok"])
            self.assertFalse(artifact_download(ws, root + "/outside", "outside.bin")["ok"])

            with patch("grypton.tools.config.find_binary", return_value="/fake/httpx"), \
                    patch("grypton.tools.subprocess.run",
                          return_value=SimpleNamespace(stdout=b"", returncode=0)):
                self.assertTrue(httpx_probe(ws, scoped + "/probe")["ok"])
                bare = httpx_probe(ws, f"127.0.0.1:{port}")
                self.assertFalse(bare["ok"])

            self.assertTrue(check_research_scope(ws, scoped + "/guide")[0])
            self.assertFalse(check_research_scope(ws, root + "/outside")[0])
            inside = research(ws, scoped + "/redirect-in")
            self.assertTrue(inside["ok"], inside)
            outside = research(ws, scoped + "/redirect-out")
            self.assertFalse(outside["ok"])
            self.assertIn("Scope blocked research URL", outside["summary"])

    def test_research_does_not_treat_target_domain_relatives_as_public_docs(self):
        with isolated_runtime():
            ws = Workspace("research-relatives")
            ws.create("https://app.milli.gold/app", "web")
            ws.save_constraints(Constraints(in_scope=["https://app.milli.gold/app"]))
            self.assertFalse(check_research_scope(ws, "https://api.milli.gold/docs")[0])
            self.assertFalse(check_research_scope(ws, "https://milli.gold/docs")[0])
            self.assertFalse(check_research_scope(ws, "https://child.app.milli.gold/docs")[0])
            self.assertFalse(check_research_scope(ws, "https://docs.example.org/guide")[0])
            self.assertTrue(check_research_scope(ws, "https://developer.mozilla.org/docs/Web")[0])

    def test_research_rejects_unapproved_hosts_queries_and_private_resolution(self):
        with isolated_runtime():
            ws = Workspace("research-egress")
            ws.create("https://target.example", "web")
            ws.save_constraints(Constraints(in_scope=["target.example"]))
            self.assertFalse(check_research_scope(ws, "https://example.org/guide")[0])
            self.assertFalse(check_research_scope(
                ws, "https://developer.mozilla.org/docs?token=fixture-secret"
            )[0])
            self.assertFalse(check_research_scope(ws, "http://127.0.0.1/metadata")[0])
            self.assertFalse(check_research_scope(ws, "http://[::1]/metadata")[0])
            with patch("grypton.tools.socket.getaddrinfo", return_value=[
                (2, 1, 6, "", ("169.254.169.254", 443)),
            ]), patch("grypton.tools.http.client.HTTPSConnection") as connection:
                result = research(ws, "https://developer.mozilla.org/docs/Web")
            self.assertFalse(result["ok"])
            self.assertIn("private", result["summary"])
            connection.assert_not_called()

    def test_research_connects_to_checked_ip_and_keeps_tls_hostname(self):
        class FakeSocket:
            def __init__(self):
                self.connected_to = None
                self.timeout = None

            def settimeout(self, timeout):
                self.timeout = timeout

            def bind(self, source_address):
                raise AssertionError(f"unexpected source bind: {source_address}")

            def connect(self, socket_address):
                self.connected_to = socket_address

            def close(self):
                pass

        sockets = []
        connections = []

        class FakeResponse:
            status = 200
            reason = "OK"

            @staticmethod
            def getheader(_name):
                return None

            @staticmethod
            def read(_limit):
                return b"official documentation"

        class FakeHTTPSConnection:
            def __init__(self, host, port, *, timeout, context):
                self.host = host
                self.port = port
                self.timeout = timeout
                self.context = context
                self._create_connection = None
                self.path = None
                connections.append(self)

            def request(self, method, path, *, headers):
                self.path = path
                self.socket = self._create_connection(
                    (self.host, self.port), self.timeout, None
                )

            @staticmethod
            def getresponse():
                return FakeResponse()

            def close(self):
                pass

        def fake_socket(*_args):
            instance = FakeSocket()
            sockets.append(instance)
            return instance

        resolved = ("93.184.216.34", 443)
        with isolated_runtime():
            ws = Workspace("research-pinning")
            ws.create("https://target.example", "web")
            ws.save_constraints(Constraints(in_scope=["target.example"]))
            with patch("grypton.tools.socket.getaddrinfo", return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", resolved),
            ]) as resolver, patch("grypton.tools.socket.socket", side_effect=fake_socket), \
                    patch("grypton.tools.http.client.HTTPSConnection",
                          FakeHTTPSConnection):
                result = research(ws, "https://developer.mozilla.org/docs/Web")

        self.assertTrue(result["ok"], result)
        resolver.assert_called_once_with(
            "developer.mozilla.org", 443, type=socket.SOCK_STREAM
        )
        self.assertEqual(len(sockets), 1)
        self.assertEqual(sockets[0].connected_to, resolved)
        self.assertEqual(connections[0].host, "developer.mozilla.org")
        self.assertEqual(connections[0].path, "/docs/Web")
        self.assertTrue(connections[0].context.check_hostname)
        self.assertEqual(connections[0].context.verify_mode, ssl.CERT_REQUIRED)

    def test_installer_is_curated_and_local_analysis_rejects_outside_or_symlink(self):
        denied = install_tool("requests", manager="pip")
        self.assertFalse(denied["ok"])
        self.assertIn("curated apt", denied["summary"])
        with patch.dict(os.environ, {"GITHUB_TOKEN": "fixture-source-secret"}), \
                patch("grypton.tools.config.find_binary", return_value="/usr/bin/apt-get"), \
                patch("grypton.tools.subprocess.run", return_value=SimpleNamespace(
                    returncode=0, stdout=b"", stderr=b""
                )) as run:
            installed = install_tool("jq")
        self.assertTrue(installed["ok"], installed)
        self.assertEqual(run.call_args.args[0], [
            "/usr/bin/apt-get", "install", "-y", "--no-install-recommends", "jq",
        ])
        self.assertNotIn("GITHUB_TOKEN", run.call_args.kwargs["env"])
        self.assertEqual(run.call_args.kwargs["umask"], 0o077)

        with isolated_runtime():
            ws = Workspace("local-analysis")
            ws.create("analysis.test", "web")
            artifact = ws.loot_dir / "sample.bin"
            artifact.write_bytes(b"offline fixture data")
            hashed = local_analyze(ws, "loot/sample.bin", analyzer="sha256")
            self.assertTrue(hashed["ok"], hashed)
            self.assertEqual(len(hashed["data"]["sha256"]), 64)
            transport_alias = local_analyze(
                ws, "engagement/loot/sample.bin", analyzer="sha256"
            )
            self.assertTrue(transport_alias["ok"], transport_alias)
            self.assertEqual(transport_alias["data"]["path"], "loot/sample.bin")
            absolute_inside = local_analyze(ws, str(artifact), analyzer="sha256")
            self.assertTrue(absolute_inside["ok"], absolute_inside)
            self.assertEqual(absolute_inside["data"]["path"], "loot/sample.bin")
            self.assertFalse(local_analyze(ws, "../outside", analyzer="sha256")["ok"])
            self.assertFalse(local_analyze(
                ws, str(ws.root.parent / "outside.bin"), analyzer="sha256"
            )["ok"])
            self.assertFalse(local_analyze(
                ws, "engagement/../outside", analyzer="sha256"
            )["ok"])
            link = ws.loot_dir / "link.bin"
            link.symlink_to(artifact)
            self.assertFalse(local_analyze(ws, "loot/link.bin", analyzer="sha256")["ok"])

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

    def test_flow_capture_persists_byte_limit_and_truncation_metadata(self):
        with isolated_runtime(), local_server() as port:
            ws = Workspace("bounded-capture")
            target = f"http://127.0.0.1:{port}"
            ws.create(target, "web")
            ws.save_constraints(Constraints(in_scope=[target]))
            result = http_request(ws, target + "/huge")
            self.assertTrue(result["ok"], result)
            flow = Path(result["data"]["flow"]).read_text(
                encoding="utf-8", errors="replace"
            )
            first = flow.splitlines()[0]
            metadata = json.loads(first.removeprefix("### GRYPTON FLOW "))
            self.assertGreater(metadata["response_bytes"], MAX_RESPONSE_BYTES)
            self.assertLessEqual(metadata["captured_response_bytes"], MAX_RESPONSE_BYTES)
            self.assertTrue(metadata["response_truncated"])

    def test_mcp_registry_has_no_claude_advisor(self):
        self.assertGreaterEqual(len(REGISTRY), 20)
        self.assertIn("http_request", REGISTRY)
        self.assertIn("flow_replay", REGISTRY)
        self.assertIn("goja_stop", REGISTRY)
        self.assertIn("tcp_exchange", REGISTRY)
        self.assertIn("artifact_download", REGISTRY)
        self.assertIn("apk_inspect", REGISTRY)
        self.assertIn("local_analyze", REGISTRY)
        self.assertNotIn("advise", REGISTRY)

    def test_dispatch_writes_audit_event(self):
        with isolated_runtime():
            ws = Workspace("audit")
            ws.create("127.0.0.1", "web")
            result = dispatch(ws, "tool_inventory", {})
            self.assertTrue(result["ok"])
            log = ws.root / ".ledger/tool-calls.jsonl"
            self.assertEqual(json.loads(log.read_text().splitlines()[0])["tool"], "tool_inventory")

    def test_effectful_dispatch_is_marked_before_handler_runs(self):
        with isolated_runtime():
            ws = Workspace("dispatch-guard")
            ws.create("127.0.0.1", "web")
            original = REGISTRY["http_request"]
            observed = []

            def handler(_workspace, _args):
                guard = ws.root / ".ledger/effectful-tool-starts.jsonl"
                observed.append([
                    json.loads(line) for line in guard.read_text().splitlines()
                ])
                return {"ok": True, "summary": "synthetic handler"}

            with patch.dict(REGISTRY, {
                "http_request": (original[0], original[1], handler),
            }):
                result = dispatch(
                    ws, "http_request", {"url": "http://127.0.0.1/"}
                )

            self.assertTrue(result["ok"], result)
            self.assertEqual(observed[0][0]["tool"], "http_request")

    def test_private_read_only_dispatch_does_not_disable_safe_restart(self):
        with isolated_runtime():
            ws = Workspace("dispatch-read-only")
            ws.create("127.0.0.1", "web")
            result = dispatch(ws, "read_doc", {"name": "scope"})
            self.assertTrue(result["ok"], result)
            self.assertFalse(
                (ws.root / ".ledger/effectful-tool-starts.jsonl").exists()
            )
            self.assertTrue((ws.root / ".ledger/tool-calls.jsonl").exists())

    def test_effectful_dispatch_fails_closed_when_guard_cannot_be_written(self):
        with isolated_runtime():
            ws = Workspace("dispatch-guard-failure")
            ws.create("127.0.0.1", "web")
            called = []
            original = REGISTRY["http_request"]

            def handler(_workspace, _args):
                called.append(True)
                return {"ok": True, "summary": "ran"}

            with patch.dict(REGISTRY, {
                "http_request": (original[0], original[1], handler),
            }), patch(
                "grypton.toolserver._record_effectful_tool_start",
                side_effect=OSError("synthetic marker failure"),
            ):
                result = dispatch(
                    ws, "http_request", {"url": "http://127.0.0.1/"}
                )
            self.assertFalse(result["ok"])
            self.assertIn("restart-safety marker", result["summary"])
            self.assertEqual(called, [])

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

    def test_audit_checks_auth_urls_and_raw_transport_ports(self):
        with isolated_runtime() as root, patch.object(config, "GRYPTON_HOME", root):
            ws = Workspace("audit-auth-scope")
            ws.create("https://api.example.test/app", "web")
            ws.save_constraints(Constraints(in_scope=["https://api.example.test/app"]))
            rows = [
                {"tool": "credential_login", "args": {
                    "url": "https://api.example.test/app/login",
                    "verify_url": "https://api.example.test/outside",
                }, "ok": False},
                {"tool": "authenticated_http_request", "args": {
                    "url": "https://api.example.test/app/account",
                }, "ok": True},
                {"tool": "tcp_exchange", "args": {
                    "host": "api.example.test", "port": 443, "payload": "status",
                }, "ok": False},
            ]
            ledger = ws.root / ".ledger" / "tool-calls.jsonl"
            ledger.write_text(
                "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
            )
            result = audit_workspace(ws)
            self.assertEqual(result["counts"]["network_tool_calls"], 3)
            violations = result["scope_violations"]
            self.assertTrue(any(row["tool"] == "credential_login" for row in violations))
            self.assertTrue(any(row["tool"] == "tcp_exchange" for row in violations))

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

    def test_worker_handoff_keeps_only_affirmative_manager_action(self):
        directive = Directive(
            directive=(
                "DO NOT retry the blocked call. Inspect the saved login bundle and "
                "test the discovered session endpoint. Never brute force OTP values."
            ),
            corrections=["Do not repeat the request."],
            scope_enforcement=["Never leave scope."],
            new_angles=["Probe another route."],
            exhaustion_breaker="Avoid idle work.",
        )
        message = directive.worker_message()
        self.assertEqual(
            message,
            "Inspect the saved login bundle and test the discovered session endpoint.",
        )
        self.assertNotIn("CORRECTIONS", message)
        self.assertNotIn("Never", message)

    def test_worker_handoff_removes_embedded_negative_clauses(self):
        samples = {
            "Use credential_login and do not retry after an error.":
                "Use credential_login",
            "Inspect the profile endpoint; never call the login route again.":
                "Inspect the profile endpoint",
            "Use one control request, but avoid repeating it.":
                "Use one control request",
        }
        for directive, expected in samples.items():
            with self.subTest(directive=directive):
                self.assertEqual(Directive(directive=directive).worker_message(), expected)

    def test_worker_handoff_normalizes_grypton_tool_prefix_typo(self):
        self.assertEqual(
            Directive(directive="Use gryphon_browse on the login page.").worker_message(),
            "Use grypton_browse on the login page.",
        )

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
            manager.session_id = "ses-operator-chat"
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
            self.assertEqual(manager.session_id, "ses-operator-chat")
            self.assertEqual(manager.client.call.await_args.kwargs["session_id"], "")

    async def test_manager_direction_schema_repair_remains_stateless(self):
        with isolated_runtime():
            ws = Workspace("manager-stateless-repair")
            ws.create("127.0.0.1", "web")
            manager = KryptexManager(ws, "system")
            manager.session_id = "ses-operator-chat"
            response = {
                "assessment": "repaired direction", "directive": "check login",
                "corrections": [], "new_angles": [], "exhaustion_breaker": "",
                "scope_enforcement": [], "severity_validations": [],
                "to_user": "working", "continue": True, "stop_reason": "",
                "confidence": 0.9,
            }
            manager.client.call = AsyncMock(side_effect=[
                OpenCodeResult(
                    text="not json", session_id="ses-invalid-direction", events=[],
                    tools=[], usage=[], duration_s=0.1,
                ),
                OpenCodeResult(
                    text=json.dumps(response), session_id="ses-repaired-direction", events=[],
                    tools=[], usage=[], duration_s=0.1,
                ),
            ])

            directive = await manager.direct(ManagerContext(
                target="127.0.0.1", target_type="web", turn_index=2,
            ))

            self.assertEqual(directive.directive, "check login")
            self.assertEqual(manager.session_id, "ses-operator-chat")
            self.assertEqual(
                [call.kwargs["session_id"] for call in manager.client.call.await_args_list],
                ["", ""],
            )

    async def test_manager_direction_circuit_skips_until_one_half_open_probe(self):
        with isolated_runtime():
            ws = Workspace("manager-circuit")
            ws.create("127.0.0.1", "web")
            events = []
            manager = KryptexManager(ws, "system", on_event=events.append)
            exhausted = ProviderError(
                "manager OpenClaude credential pool exhausted (upstream HTTP 429).",
                metadata={
                    "source": "openclaude",
                    "type": "openclaude_terminal",
                    "role": "manager",
                    "reason": "credential_pool_exhausted",
                    "upstream_status": 429,
                    "pool_size": 5,
                    "retry_after_s": 30,
                },
            )
            response = {
                "assessment": "provider recovered", "directive": "check login",
                "corrections": [], "new_angles": [], "exhaustion_breaker": "",
                "scope_enforcement": [], "severity_validations": [],
                "to_user": "working", "continue": True, "stop_reason": "",
                "confidence": 0.9,
            }
            manager.client.call = AsyncMock(side_effect=[
                exhausted,
                OpenCodeResult(
                    text=json.dumps(response), session_id="ses-half-open", events=[],
                    tools=[], usage=[], duration_s=0.1,
                ),
            ])
            context = ManagerContext(
                target="127.0.0.1", target_type="web", turn_index=2,
            )

            with patch("grypton.manager.time.monotonic", return_value=100.0):
                first = await manager.direct(context)
            with patch("grypton.manager.time.monotonic", return_value=110.0):
                skipped = await manager.direct(context)
            with patch("grypton.manager.time.monotonic", return_value=131.0):
                recovered = await manager.direct(context)

            self.assertTrue(first.degraded)
            self.assertTrue(skipped.degraded)
            self.assertIn("20 seconds", skipped.assessment)
            self.assertFalse(recovered.degraded)
            self.assertEqual(recovered.directive, "check login")
            self.assertEqual(manager.client.call.await_count, 2)
            self.assertEqual(manager._provider_circuit_until, 0.0)
            self.assertEqual(
                [event["type"] for event in events],
                ["manager_fallback", "manager_fallback"],
            )

    async def test_operator_chat_bypasses_and_clears_direction_circuit(self):
        with isolated_runtime():
            ws = Workspace("manager-circuit-chat")
            ws.create("127.0.0.1", "web")
            manager = KryptexManager(ws, "system")
            manager.session_id = "ses-chat"
            manager._provider_circuit_until = 130.0
            chat_response = {
                "reply": "Recorded.", "remember": "", "disposition": "apply-next-turn",
                "worker_note": "check login",
            }
            direction_response = {
                "assessment": "available", "directive": "check login",
                "corrections": [], "new_angles": [], "exhaustion_breaker": "",
                "scope_enforcement": [], "severity_validations": [],
                "to_user": "working", "continue": True, "stop_reason": "",
                "confidence": 0.9,
            }
            manager.client.call = AsyncMock(side_effect=[
                OpenCodeResult(
                    text=json.dumps(chat_response), session_id="ses-chat-next", events=[],
                    tools=[], usage=[], duration_s=0.1,
                ),
                OpenCodeResult(
                    text=json.dumps(direction_response), session_id="ses-direction", events=[],
                    tools=[], usage=[], duration_s=0.1,
                ),
            ])
            context = ManagerContext(
                target="127.0.0.1", target_type="web", turn_index=2,
            )

            with patch("grypton.manager.time.monotonic", return_value=100.0):
                reply = await manager.chat("check login", context)
                directive = await manager.direct(context)

            self.assertFalse(reply["degraded"])
            self.assertEqual(reply["worker_note"], "check login")
            self.assertFalse(directive.degraded)
            self.assertEqual(manager.client.call.await_count, 2)
            self.assertEqual(manager.client.call.await_args_list[0].kwargs["session_id"],
                             "ses-chat")
            self.assertEqual(manager.client.call.await_args_list[1].kwargs["session_id"], "")
            self.assertEqual(manager._provider_circuit_until, 0.0)

    async def test_manager_chat_restarts_session_after_thinking_signature_rejection(self):
        with isolated_runtime():
            ws = Workspace("manager-signature")
            ws.create("127.0.0.1", "web")
            manager = KryptexManager(ws, "system")
            manager.session_id = "ses-old-key"
            response = {
                "reply": "I will check login next.", "remember": "",
                "disposition": "apply-next-turn", "worker_note": "check login",
            }
            manager.client.call = AsyncMock(side_effect=[
                ProviderError("capability_rejected: thinking_signature"),
                OpenCodeResult(
                    text=json.dumps(response), session_id="ses-fresh-key", events=[],
                    tools=[], usage=[], duration_s=0.1,
                ),
            ])

            reply = await manager.chat("check login", ManagerContext(
                target="127.0.0.1", target_type="web", turn_index=2,
            ))

            self.assertFalse(reply["degraded"])
            self.assertEqual(reply["worker_note"], "check login")
            self.assertEqual(manager.session_id, "ses-fresh-key")
            self.assertEqual(manager.client.call.await_args_list[0].kwargs["session_id"],
                             "ses-old-key")
            self.assertEqual(manager.client.call.await_args_list[1].kwargs["session_id"], "")

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

    def test_codex_validator_environment_keeps_only_explicit_auth(self):
        with patch.dict(os.environ, {
            "OPENAI_API_KEY": "fixture-openai-key",
            "OPENAI_BASE_URL": "https://redirect.invalid/v1",
            "OPENAI_API_BASE": "https://redirect.invalid/legacy",
            "AZURE_OPENAI_ENDPOINT": "https://redirect.invalid/azure",
            "AWS_SECRET_ACCESS_KEY": "fixture-cloud-secret",
            "GITHUB_TOKEN": "fixture-source-secret",
            "HTTPS_PROXY": "http://fixture-proxy.invalid:8080",
        }):
            env = _codex_child_environment()
        self.assertEqual(env["OPENAI_API_KEY"], "fixture-openai-key")
        self.assertNotIn("OPENAI_BASE_URL", env)
        self.assertNotIn("OPENAI_API_BASE", env)
        self.assertNotIn("AZURE_OPENAI_ENDPOINT", env)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("HTTPS_PROXY", env)

    def test_worker_permissions_enable_native_tools_and_keep_manager_toolless(self):
        permissions = OpenCodeClient._permissions(True)
        for name in ("bash", "task"):
            self.assertEqual(permissions[name], "allow")
        for name in ("read", "edit", "glob", "grep", "list"):
            self.assertIsInstance(permissions[name], dict)
            self.assertEqual(permissions[name]["*"], "deny")
        self.assertEqual(permissions["webfetch"], "deny")
        self.assertEqual(permissions["websearch"], "deny")
        self.assertEqual(permissions["question"], "deny")

        manager_permissions = OpenCodeClient._permissions(False)
        self.assertEqual(manager_permissions["*"], "deny")

    def test_worker_permissions_bind_only_its_engagement_paths(self):
        workspace = Path("/tmp/grypton-engagement")
        transport = Path("/tmp/grypton-transport")
        permissions = OpenCodeClient._permissions(True, workspace, transport)
        for rule_name in (
            "read", "edit", "glob", "grep", "list", "external_directory",
        ):
            rules = permissions[rule_name]
            for public in (
                "/tmp/grypton-engagement/research",
                "/tmp/grypton-transport/engagement/research",
                "engagement/research",
            ):
                self.assertEqual(rules[public], "allow")
                self.assertEqual(rules[public + "/*"], "allow")
            for private in (
                "/tmp/grypton-engagement/transcripts",
                "/tmp/grypton-transport/engagement/.ledger",
                "engagement/transcripts",
            ):
                self.assertEqual(rules[private], "deny")
                self.assertEqual(rules[private + "/*"], "deny")
            for private_file in (
                "/tmp/grypton-engagement/target.json",
                "/tmp/grypton-transport/engagement/target.json",
                "engagement/target.json",
            ):
                self.assertEqual(rules[private_file], "deny")
            self.assertEqual(rules["engagement/AGENTS.md"], "allow")
            self.assertNotIn(
                "/tmp/grypton-transport/arbitrary-private-file", rules
            )
        self.assertEqual(permissions["external_directory"]["*"], "deny")
        self.assertEqual(next(iter(permissions["external_directory"])), "*")

    def test_mcp_subprocess_imports_from_source_when_state_home_is_elsewhere(self):
        with isolated_runtime():
            workspace_state = Workspace("mcp-import")
            workspace_state.create("example.test", "web")
            workspace = workspace_state.root
            client = OpenCodeClient(
                role="worker", route=config.WORKER_MODEL, effort="max",
                workspace=workspace, target_slug="mcp-import", allow_tools=True,
                agent_prompt="test",
            )
            gateway_token = "fixture-local-gateway-token"
            transport_route = f"openclaude/{config.WORKER_MODEL}"
            client.gateway = SimpleNamespace(
                model_route=transport_route,
                token=gateway_token,
                provider_config=lambda provider_id: {
                    provider_id: {
                        "npm": "@ai-sdk/anthropic",
                        "options": {
                            "baseURL": "http://127.0.0.1:32123/v1",
                            "apiKey": "{env:" + TOKEN_ENV + "}",
                        },
                        "models": {config.WORKER_MODEL: {"variants": {"max": {}}}},
                    }
                },
                environment=lambda: {TOKEN_ENV: gateway_token},
            )
            env, secret = client._environment()
            inline = json.loads(env["OPENCODE_CONFIG_CONTENT"])
            paths = env["PYTHONPATH"].split(os.pathsep)
            self.assertEqual(paths[0], str(config.SOURCE_ROOT))
            self.assertEqual(
                inline["mcp"]["grypton"]["environment"]["PYTHONPATH"],
                str(config.SOURCE_ROOT),
            )
            self.assertEqual(inline["enabled_providers"], ["openclaude"])
            self.assertEqual(inline["model"], transport_route)
            self.assertIn("openclaude", inline["provider"])
            self.assertEqual(inline["shell"], str(client.native_shell.launcher))
            self.assertEqual(env[TOKEN_ENV], gateway_token)
            self.assertEqual(secret, gateway_token)
            self.assertNotIn(gateway_token, env["OPENCODE_CONFIG_CONTENT"])
            with patch.dict(os.environ, {
                "AWS_SECRET_ACCESS_KEY": "fixture-cloud-secret",
                "GITHUB_TOKEN": "fixture-source-secret",
            }):
                isolated_env, _ = client._environment()
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", isolated_env)
            self.assertNotIn("GITHUB_TOKEN", isolated_env)

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

    def test_runtime_prompt_adds_no_generated_conduct_rules(self):
        with isolated_runtime():
            worker = OpenCodeWorker(WorkerSpec(
                session_uuid="", cwd=Path(config.ENGAGEMENTS_DIR) / "prompt-reader",
                system_prompt="test", extra_env={"GRYPTON_TARGET": "prompt-reader"},
            ))
            directive = "Use the supplied credential and check whether login succeeds."
            prompt = worker._build_prompt(directive)
            self.assertEqual(prompt, directive)
            self.assertNotIn("MUST", prompt)
            self.assertNotIn("Do not", prompt)

    def test_static_role_prompts_do_not_add_prohibitive_rules(self):
        worker = prompts.worker_system(
            target="https://example.test/app", target_type="web",
            workspace=Path("/tmp/example"), constraints_block="SCOPE DATA",
        )
        manager = prompts.manager_system(
            target="https://example.test/app", target_type="web",
            workspace=Path("/tmp/example"),
        )
        workspace = prompts.worker_workspace_md(
            target="https://example.test/app", target_type="web",
            workspace=Path("/tmp/example"), constraints_block="SCOPE DATA",
        )
        combined = "\n".join((worker, manager, workspace)).lower()
        for generated_rule in ("do not", "never", "must", "hard rules",
                               "embedded operating skills"):
            self.assertNotIn(generated_rule, combined)
        self.assertEqual(worker.strip(), "SCOPE DATA")
        self.assertEqual(workspace.strip(), "SCOPE DATA")

    def test_degraded_manager_actions_do_not_restate_conduct_rules(self):
        manager = object.__new__(KryptexManager)
        contexts = (
            ManagerContext(target="example.test", target_type="web", turn_index=1),
            ManagerContext(target="example.test", target_type="web", turn_index=1,
                           worker_was_idle=True),
            ManagerContext(target="example.test", target_type="web", turn_index=1,
                           exhaustion=True),
        )
        for context in contexts:
            message = manager._fallback_directive(context, "provider unavailable").worker_message()
            lowered = message.lower()
            for generated_rule in ("do not", "don't", "never", "must not",
                                   "refrain from", "only within", "scope"):
                self.assertNotIn(generated_rule, lowered)

    def test_explicit_mission_reaches_kraude_runtime_prompt_verbatim(self):
        with isolated_runtime():
            worker = OpenCodeWorker(WorkerSpec(
                session_uuid="", cwd=Path(config.ENGAGEMENTS_DIR) / "mission-verbatim",
                system_prompt="static role and tool guidance",
                extra_env={"GRYPTON_TARGET": "mission-verbatim"},
            ))
            mission = (
                "Credential alias: primary; check whether authentication succeeds.\n"
                "Scope URLs: https://example.test/app, https://example.test/main.\n"
                "Severity: /app Medium; /main Critical.\n"
                "Out of scope: clickjacking, open redirect."
            )
            prompt = worker._build_prompt(mission)
            self.assertTrue(prompt.endswith(mission))
            self.assertEqual(prompt.count(mission), 1)
            self.assertNotIn("TARGET-TYPE PLAYBOOK OPTIONS", prompt)


class EngineTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _worker_pool_exhausted(status: int = 429, tool_count: int = 0) -> ProviderError:
        return ProviderError(
            f"worker OpenClaude credential pool exhausted (upstream HTTP {status}).",
            metadata={
                "source": "openclaude",
                "type": "openclaude_terminal",
                "role": "worker",
                "reason": "credential_pool_exhausted",
                "upstream_status": status,
                "pool_size": 1,
                "tool_count": tool_count,
            },
        )

    async def test_worker_uses_one_fresh_session_after_429_pool_exhaustion(self):
        with isolated_runtime():
            worker = OpenCodeWorker(WorkerSpec(
                session_uuid="ses-heavy", cwd=config.ENGAGEMENTS_DIR / "worker-429",
                system_prompt="scope projection", extra_env={"GRYPTON_TARGET": "worker-429"},
            ))
            worker.client.call = AsyncMock(side_effect=[
                self._worker_pool_exhausted(tool_count=2),
                self._worker_pool_exhausted(tool_count=1),
            ])
            directive = "Credential alias: primary. Check whether it can authenticate."

            with self.assertRaises(WorkerError) as first:
                await worker.run_turn(directive)
            self.assertEqual(first.exception.metadata["upstream_status"], 429)
            self.assertEqual(first.exception.metadata["tool_count"], 2)
            self.assertEqual(worker.session_id, "")
            self.assertEqual(worker.spec.session_uuid, "")

            # If the failed fresh transport exposes a partial session later,
            # another identical terminal event must not start a reset loop.
            worker.session_id = "ses-fresh-attempt"
            worker.spec.session_uuid = "ses-fresh-attempt"
            with self.assertRaises(WorkerError):
                await worker.run_turn(directive)
            self.assertEqual(worker.session_id, "ses-fresh-attempt")
            self.assertEqual(
                [call.kwargs["session_id"] for call in worker.client.call.await_args_list],
                ["ses-heavy", "ses-fresh-attempt"],
            )
            self.assertTrue(all(
                call.args[0] == directive
                for call in worker.client.call.await_args_list
            ))

    async def test_worker_does_not_reset_session_for_other_terminal_failures(self):
        with isolated_runtime():
            cases = [
                self._worker_pool_exhausted(401),
                self._worker_pool_exhausted(402),
                self._worker_pool_exhausted(403),
                ProviderError("unrelated HTTP 429", metadata={
                    "source": "openclaude", "type": "openclaude_terminal",
                    "role": "worker", "reason": "provider_terminal",
                    "upstream_status": 429,
                }),
                ProviderError("provider-wide HTTP 429"),
            ]
            for index, failure in enumerate(cases):
                worker = OpenCodeWorker(WorkerSpec(
                    session_uuid=f"ses-{index}",
                    cwd=config.ENGAGEMENTS_DIR / f"worker-non429-{index}",
                    system_prompt="scope projection",
                    extra_env={"GRYPTON_TARGET": f"worker-non429-{index}"},
                ))
                worker.client.call = AsyncMock(side_effect=failure)
                with self.assertRaises(WorkerError):
                    await worker.run_turn("same directive")
                self.assertEqual(worker.session_id, f"ses-{index}")
                self.assertEqual(worker.spec.session_uuid, f"ses-{index}")

    async def test_engine_retries_429_pool_exhaustion_with_fresh_nonreplay_directive(self):
        with isolated_runtime():
            engine = Engine("engine-worker-429", backend="mock")
            directive = "Credential alias: primary. Check whether it can authenticate."
            await engine.setup(brief=directive, target="https://example.test", fresh_clone=True)
            worker = OpenCodeWorker(WorkerSpec(
                session_uuid="ses-heavy", cwd=engine.ws.root,
                system_prompt="scope projection",
                extra_env={"GRYPTON_TARGET": engine.slug},
            ))
            worker.client.call = AsyncMock(side_effect=[
                self._worker_pool_exhausted(),
                OpenCodeResult(
                    text="Provider recovered.", session_id="ses-recovered",
                    events=[], tools=[], usage=[], duration_s=0.01,
                ),
            ])
            engine.worker = worker
            previous_turns = config.CONFIG.max_turns
            config.CONFIG.max_turns = 1
            try:
                with patch("grypton.engine.asyncio.sleep", new=AsyncMock()):
                    await engine.run()
            finally:
                config.CONFIG.max_turns = previous_turns

            self.assertEqual(worker.client.call.await_count, 2)
            calls = worker.client.call.await_args_list
            self.assertEqual(calls[0].args[0], directive)
            self.assertNotEqual(calls[1].args[0], directive)
            self.assertIn("durable results already recorded", calls[1].args[0])
            self.assertEqual([call.kwargs["session_id"] for call in calls],
                             ["ses-heavy", ""])
            self.assertEqual(engine.turn_index, 1)
            self.assertIn("max_turns safety ceiling", engine.stop_reason)

    async def test_explicit_operator_brief_is_opening_directive_verbatim(self):
        with isolated_runtime():
            ws = Workspace("verbatim-brief")
            ws.create("https://example.test/app", "web")
            engine = Engine("verbatim-brief", backend="mock")
            engine.target = "https://example.test/app"
            engine.target_type = "web"
            engine.brief = (
                "Credential alias: primary. Scope: https://example.test/app. "
                "Minimum severity: Critical."
            )
            self.assertEqual(await engine._opening_directive(), engine.brief)

    async def test_explicit_operator_brief_is_exact_recovery_directive(self):
        with isolated_runtime():
            ws = Workspace("recovery-brief")
            ws.create("https://example.test/app", "web")
            engine = Engine("recovery-brief", backend="mock")
            mission = "Credential alias: primary. Check whether it can authenticate."
            engine.brief = mission
            self.assertEqual(engine._recovery_directive(), mission)
            self.assertEqual(engine._forced_action_directive_with_user_intent(), mission)
            self.assertEqual(await engine._opening_directive(), mission)

    async def test_default_opening_directive_is_short_affirmative_action(self):
        with isolated_runtime():
            ws = Workspace("default-opening")
            ws.create("https://example.test/app", "web")
            engine = Engine("default-opening", backend="mock")
            prompt = await engine._opening_directive()
            self.assertEqual(prompt, engine._recovery_directive())
            self.assertNotIn("PLAYBOOK", prompt)
            self.assertNotIn("Never", prompt)
            self.assertNotIn("Do not", prompt)

    def test_direct_worker_message_reaches_worker_without_wrapper(self):
        with isolated_runtime():
            ws = Workspace("direct-worker-message")
            ws.create("https://example.test/app", "web")
            engine = Engine("direct-worker-message", backend="mock")
            message = "Credential alias: primary. Check whether it can authenticate."
            engine.submit_user(message, to_worker=True)
            self.assertEqual(engine._prepend_user_to_worker("manager action"), message)
            self.assertEqual(ws.load_constraints().standing_instructions, [message])
            self.assertNotIn(message, ws.load_constraints().to_worker_prompt_block())

    async def test_kryptex_remember_text_is_not_persisted_or_wrapped(self):
        with isolated_runtime():
            ws = Workspace("manager-relay")
            ws.create("https://example.test/app", "web")
            engine = Engine("manager-relay", backend="mock")
            engine.manager = SimpleNamespace(chat=AsyncMock(return_value={
                "reply": "Working.",
                "remember": "Manager-generated standing rule.",
                "disposition": "apply-now",
                "worker_note": "Use credential_status and do not retry.",
                "degraded": False,
            }))
            engine._user_to_manager.put_nowait("Check authentication.")
            task = asyncio.create_task(engine._user_chat_loop())
            for _ in range(100):
                if engine.manager.chat.await_count:
                    break
                await asyncio.sleep(0.01)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

            instructions = ws.load_constraints().standing_instructions
            self.assertEqual(instructions, ["[USER, turn ~0] Check authentication."])
            self.assertNotIn("Manager-generated", "\n".join(instructions))
            self.assertEqual(
                engine._prepend_user_to_worker("manager action"),
                "Use credential_status",
            )

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

    def test_deadline_mode_does_not_treat_authentication_blocker_as_boundary(self):
        with isolated_runtime():
            ws = Workspace("deadline-auth-blocker")
            ws.create("https://app.example.test", "web")
            ws.save_constraints(Constraints(
                in_scope=["https://app.example.test"],
                out_of_scope=["https://admin.example.test"],
            ))
            engine = Engine(
                "deadline-auth-blocker", backend="mock", run_until_deadline=True
            )
            directive = Directive(
                cont=False,
                stop_reason=(
                    "Authorization and convergence boundary: authenticated /app "
                    "testing blocked on enabled:false activation requiring signup/OTP flow"
                ),
            )

            self.assertFalse(engine._manager_stop_is_binding(
                directive, convergence_reason="repeated probe convergence"
            ))

    def test_deadline_mode_honors_exact_recorded_out_of_scope_boundary(self):
        with isolated_runtime():
            ws = Workspace("deadline-recorded-scope")
            ws.create("https://app.example.test", "web")
            ws.save_constraints(Constraints(
                in_scope=["https://app.example.test"],
                out_of_scope=["https://admin.example.test/private"],
            ))
            engine = Engine(
                "deadline-recorded-scope", backend="mock", run_until_deadline=True
            )
            exact = Directive(
                cont=False,
                stop_reason=(
                    "Recorded out-of-scope boundary reached at "
                    "https://admin.example.test/private"
                ),
            )
            canonical_mock_wording = Directive(
                cont=False,
                stop_reason=(
                    "Out-of-scope / authorization boundary reached at "
                    "https://admin.example.test/private"
                ),
            )
            url_first_wording = Directive(
                cont=False,
                stop_reason=(
                    "https://admin.example.test/private is out of scope"
                ),
            )
            endpoint_wording = Directive(
                cont=False,
                stop_reason=(
                    "Out-of-scope endpoint https://admin.example.test/private was reached"
                ),
            )
            invented = Directive(
                cont=False,
                stop_reason="Out-of-scope boundary reached at https://other.example.test",
            )
            lookalike_host = Directive(
                cont=False,
                stop_reason=(
                    "Out-of-scope boundary reached at "
                    "https://admin.example.test.evil/private"
                ),
            )
            lookalike_path = Directive(
                cont=False,
                stop_reason=(
                    "Out-of-scope boundary reached at "
                    "https://admin.example.test/privateer"
                ),
            )
            contextual_only = Directive(
                cont=False,
                stop_reason="Authorization and convergence boundary at the activation gate",
                scope_enforcement=[
                    "Keep requests away from https://admin.example.test/private"
                ],
            )
            negated = Directive(
                cont=False,
                stop_reason=(
                    "Authorization remains blocked; no out-of-scope request was made; "
                    "recorded exclusion URL is https://admin.example.test/private"
                ),
            )

            self.assertTrue(engine._manager_stop_is_binding(exact))
            self.assertTrue(engine._manager_stop_is_binding(canonical_mock_wording))
            self.assertTrue(engine._manager_stop_is_binding(url_first_wording))
            self.assertTrue(engine._manager_stop_is_binding(endpoint_wording))
            self.assertFalse(engine._manager_stop_is_binding(invented))
            self.assertFalse(engine._manager_stop_is_binding(lookalike_host))
            self.assertFalse(engine._manager_stop_is_binding(lookalike_path))
            self.assertFalse(engine._manager_stop_is_binding(contextual_only))
            self.assertFalse(engine._manager_stop_is_binding(negated))

    def test_recorded_url_boundary_citation_uses_url_structure(self):
        root = "https://admin.example.test/"
        self.assertTrue(Engine._boundary_text_contains(
            "Recorded out-of-scope URL https://admin.example.test/private", root
        ))
        self.assertTrue(Engine._boundary_text_contains(
            "Recorded out-of-scope URL https://admin.example.test?view=1", root
        ))
        for lookalike in (
            "https://admin.example.test:444/private",
            "https://admin.example.test@evil.test/private",
            "https://admin.example.test%2eevil/private",
        ):
            with self.subTest(lookalike=lookalike):
                self.assertFalse(Engine._boundary_text_contains(
                    f"Recorded out-of-scope URL {lookalike}", root
                ))
        path_rule = "https://admin.example.test/private/"
        for traversal in (
            "https://admin.example.test/private/../public",
            "https://admin.example.test/private/%2e%2e/public",
            "https://admin.example.test/private/%252e%252e/public",
        ):
            with self.subTest(traversal=traversal):
                self.assertFalse(Engine._boundary_text_contains(
                    f"Recorded out-of-scope URL {traversal}", path_rule
                ))

    def test_deadline_mode_honors_only_recorded_automation_prohibition(self):
        with isolated_runtime():
            ws = Workspace("deadline-automation-ban")
            ws.create("https://app.example.test", "web")
            ws.save_constraints(Constraints(
                in_scope=["https://app.example.test"],
                hard_rules=["Program automation is prohibited."],
            ))
            engine = Engine(
                "deadline-automation-ban", backend="mock", run_until_deadline=True
            )
            directive = Directive(
                cont=False, stop_reason="Program automation prohibited"
            )
            self.assertTrue(engine._manager_stop_is_binding(directive))

            ws.save_constraints(Constraints(in_scope=["https://app.example.test"]))
            self.assertFalse(engine._manager_stop_is_binding(directive))

            ws.save_constraints(Constraints(
                in_scope=["https://app.example.test"],
                hard_rules=["Program automation is not prohibited."],
            ))
            self.assertFalse(engine._manager_stop_is_binding(directive))

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

    async def test_detached_deadline_mode_continues_after_convergence(self):
        with isolated_runtime():
            fields = ("max_turns", "max_run_seconds", "passive_stagnation_limit",
                      "repetitive_probe_turn_limit", "exhaustion_threshold")
            old = {field: getattr(config.CONFIG, field) for field in fields}
            config.CONFIG.max_turns = 5
            config.CONFIG.max_run_seconds = 0
            config.CONFIG.passive_stagnation_limit = 2
            config.CONFIG.repetitive_probe_turn_limit = 99
            config.CONFIG.exhaustion_threshold = 99
            try:
                ws = Workspace("deadline-loop")
                ws.create("127.0.0.1", "web")
                ws.save_constraints(Constraints(in_scope=["127.0.0.1"]))
                engine = Engine(
                    "deadline-loop", backend="mock", run_until_deadline=True
                )
                await engine.setup(brief="deadline regression", target="127.0.0.1",
                                   target_type="web")
                engine.worker.script = lambda _worker, _directive: "No new evidence."
                await engine.run()
                self.assertEqual(engine.turn_index, 5)
                self.assertIn("max_turns safety ceiling", engine.stop_reason)
                self.assertNotIn("convergence guard", engine.stop_reason)
            finally:
                for field, value in old.items():
                    setattr(config.CONFIG, field, value)

    async def test_detached_deadline_loop_overrides_manager_auth_stop(self):
        with isolated_runtime():
            fields = ("max_turns", "max_run_seconds", "passive_stagnation_limit",
                      "repetitive_probe_turn_limit", "exhaustion_threshold")
            old = {field: getattr(config.CONFIG, field) for field in fields}
            config.CONFIG.max_turns = 3
            config.CONFIG.max_run_seconds = 0
            config.CONFIG.passive_stagnation_limit = 99
            config.CONFIG.repetitive_probe_turn_limit = 99
            config.CONFIG.exhaustion_threshold = 99
            events = []
            worker_directives = []
            try:
                ws = Workspace("deadline-manager-auth-stop")
                ws.create("https://app.example.test", "web")
                ws.save_constraints(Constraints(
                    in_scope=["https://app.example.test"],
                    out_of_scope=["https://admin.example.test"],
                ))
                engine = Engine(
                    "deadline-manager-auth-stop", backend="mock",
                    run_until_deadline=True,
                    emit=lambda kind, **payload: events.append((kind, payload)),
                )
                await engine.setup(
                    brief="check authentication", target="https://app.example.test",
                    target_type="web",
                )
                def worker_script(_worker, directive):
                    worker_directives.append(directive)
                    return "Authentication still blocked."

                engine.worker.script = worker_script
                engine.manager.direct = AsyncMock(return_value=Directive(
                    assessment="Activation gate is still closed.",
                    directive="Try the next in-scope authentication path.",
                    cont=False,
                    stop_reason=(
                        "Authorization and convergence boundary: authenticated /app "
                        "testing blocked on enabled:false activation requiring signup/OTP flow"
                    ),
                ))

                await engine.run()

                self.assertEqual(engine.turn_index, 3)
                self.assertIn("max_turns safety ceiling", engine.stop_reason)
                self.assertEqual(engine.manager.direct.await_count, 3)
                self.assertEqual(worker_directives[0], "check authentication")
                self.assertEqual(worker_directives[1:], [
                    "Use the most relevant available tool to test the highest-impact "
                    "unresolved lead in the recorded attack surface and record the "
                    "observed result.",
                    "Use the most relevant available tool to test the highest-impact "
                    "unresolved lead in the recorded attack surface and record the "
                    "observed result.",
                ])
                self.assertTrue(any(
                    kind == "status" and "attempted a soft stop" in payload.get("text", "")
                    for kind, payload in events
                ))
            finally:
                for field, value in old.items():
                    setattr(config.CONFIG, field, value)

    async def test_degraded_manager_preserves_contextual_fallback_action(self):
        with isolated_runtime():
            fields = ("max_turns", "max_run_seconds", "passive_stagnation_limit",
                      "repetitive_probe_turn_limit", "exhaustion_threshold")
            old = {field: getattr(config.CONFIG, field) for field in fields}
            config.CONFIG.max_turns = 2
            config.CONFIG.max_run_seconds = 0
            config.CONFIG.passive_stagnation_limit = 99
            config.CONFIG.repetitive_probe_turn_limit = 99
            config.CONFIG.exhaustion_threshold = 99
            worker_directives = []
            try:
                ws = Workspace("degraded-manager-action")
                ws.create("https://app.example.test", "web")
                ws.save_constraints(Constraints(in_scope=["https://app.example.test"]))
                engine = Engine("degraded-manager-action", backend="mock")
                await engine.setup(
                    brief="initial mission", target="https://app.example.test",
                    target_type="web",
                )

                def worker_script(_worker, directive):
                    worker_directives.append(directive)
                    return "Recorded one concrete request and its control."

                def degraded_direction(ctx):
                    return KryptexManager._fallback_directive(
                        engine.manager, ctx, "fixture provider outage"
                    )

                engine.worker.script = worker_script
                engine.manager.direct = AsyncMock(side_effect=degraded_direction)

                await engine.run()

                self.assertEqual(worker_directives, [
                    "initial mission",
                    "Continue with the highest-impact unresolved lead in the recorded "
                    "attack surface. Use a concrete tool call, compare the response "
                    "against a control, and record the result before ending the turn.",
                ])
                self.assertTrue(engine.manager.direct.await_args.args[0].turn_index >= 1)
            finally:
                for field, value in old.items():
                    setattr(config.CONFIG, field, value)

    async def test_detached_deadline_loop_stops_on_recorded_scope_boundary(self):
        with isolated_runtime():
            fields = ("max_turns", "max_run_seconds", "passive_stagnation_limit",
                      "repetitive_probe_turn_limit", "exhaustion_threshold")
            old = {field: getattr(config.CONFIG, field) for field in fields}
            config.CONFIG.max_turns = 5
            config.CONFIG.max_run_seconds = 0
            config.CONFIG.passive_stagnation_limit = 99
            config.CONFIG.repetitive_probe_turn_limit = 99
            config.CONFIG.exhaustion_threshold = 99
            try:
                ws = Workspace("deadline-manager-recorded-stop")
                ws.create("https://app.example.test", "web")
                ws.save_constraints(Constraints(
                    in_scope=["https://app.example.test"],
                    out_of_scope=["https://admin.example.test/private"],
                ))
                engine = Engine(
                    "deadline-manager-recorded-stop", backend="mock",
                    run_until_deadline=True,
                )
                await engine.setup(
                    brief="check authentication", target="https://app.example.test",
                    target_type="web",
                )
                engine.manager.direct = AsyncMock(return_value=Directive(
                    assessment="Worker crossed the recorded boundary.",
                    cont=False,
                    stop_reason=(
                        "Recorded out-of-scope boundary reached at "
                        "https://admin.example.test/private"
                    ),
                ))

                await engine.run()

                self.assertEqual(engine.turn_index, 1)
                self.assertEqual(
                    engine.stop_reason,
                    "Recorded out-of-scope boundary reached at "
                    "https://admin.example.test/private",
                )
            finally:
                for field, value in old.items():
                    setattr(config.CONFIG, field, value)


if __name__ == "__main__":
    unittest.main()
