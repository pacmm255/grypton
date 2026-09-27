from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import threading
import unittest
import subprocess
from unittest.mock import patch

from grypton import config, credentials, request_policy, tools
from grypton.cli import _claude_style_arguments, build_parser, cmd_policy
from grypton.network_broker import (
    ScopedNetworkBroker,
    curl_wrapper_source,
    httpx_wrapper_source,
)
from grypton.workspace import Constraints, Workspace


class _HeaderHandler(BaseHTTPRequestHandler):
    seen: list[str] = []

    def do_GET(self):
        marker = str(self.headers.get("X-Research-Id") or "")
        type(self).seen.append(marker)
        body = ("reflected=" + marker).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class RequestPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="grypton-policy-")
        root = Path(self.temporary.name)
        state = root / ".state"
        runtime = state / "runtime"
        engagements = state / "engagements"
        credentials_dir = state / "credentials"
        self.config_patch = patch.multiple(
            config,
            GRYPTON_HOME=root,
            STATE_DIR=state,
            RUNTIME_DIR=runtime,
            LOG_DIR=runtime / "logs",
            TARGETS_DIR=engagements,
            ENGAGEMENTS_DIR=engagements,
            CREDENTIALS_DIR=credentials_dir,
        )
        self.config_patch.start()
        self.ws = Workspace("policy-fixture")
        self.ws.create("https://example.test", "web")
        self.ws.save_constraints(Constraints(in_scope=["https://example.test"]))

    def tearDown(self):
        self.config_patch.stop()
        self.temporary.cleanup()

    def test_private_policy_projects_only_names_rate_and_bucket(self):
        secret = "PRIVATE-HEADER-VALUE-7d640c"
        row = request_policy.set_origin_policy(
            self.ws.slug,
            "https://example.test",
            headers={"X-Research-Id": secret},
            max_requests_per_second=5,
            rate_bucket="program",
        )

        self.assertEqual(row["mandatory_header_names"], ["X-Research-Id"])
        self.assertNotIn(secret, repr(row))
        policy_path = (
            config.STATE_DIR / "operator" / "engagements"
            / self.ws.slug / "request-policy.json"
        )
        self.assertEqual(os.stat(policy_path).st_mode & 0o777, 0o600)
        self.assertIn(secret, policy_path.read_text(encoding="utf-8"))
        self.ws.render_scope_document()
        projected = (self.ws.root / "scope-rules.md").read_text(encoding="utf-8")
        self.assertIn("X-Research-Id", projected)
        self.assertIn("maximum 5 requests/second", projected)
        self.assertIn("shared rate bucket: program", projected)
        self.assertNotIn(secret, projected)

    def test_http_request_injects_exact_origin_header_and_redacts_reflection(self):
        _HeaderHandler.seen = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), _HeaderHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            self.ws.save_constraints(Constraints(in_scope=[origin]))
            secret = "PRIVATE-REFLECTED-POLICY-2a884e"
            request_policy.set_origin_policy(
                self.ws.slug,
                origin,
                headers={"X-Research-Id": secret},
                max_requests_per_second=1000,
            )
            result = tools.http_request(self.ws, origin + "/check")
            self.assertTrue(result["ok"], result)
            self.assertEqual(_HeaderHandler.seen, [secret])
            self.assertNotIn(secret, repr(result))
            flow = Path(result["data"]["flow"]).read_text(encoding="utf-8")
            self.assertIn("X-Research-Id: [REDACTED]", flow)
            self.assertNotIn(secret, flow)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_authenticated_http_uses_the_same_private_policy_boundary(self):
        _HeaderHandler.seen = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), _HeaderHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            self.ws.save_constraints(Constraints(in_scope=[origin]))
            secret = "AUTH-POLICY-PRIVATE-d30f39"
            request_policy.set_origin_policy(
                self.ws.slug, origin,
                headers={"X-Research-Id": secret},
                max_requests_per_second=1000,
            )
            credentials.save_credential(
                self.ws.slug, "primary", "fixture-user", "fixture-password"
            )
            credentials.begin_login_attempt(self.ws.slug, "primary")
            credentials.record_login_outcome(
                self.ws.slug, "primary", established=True, origin=origin
            )
            result = tools.authenticated_http_request(
                self.ws, origin + "/authenticated", credential="primary"
            )
            self.assertTrue(result["ok"], result)
            self.assertEqual(_HeaderHandler.seen, [secret])
            self.assertNotIn(secret, repr(result))
            self.assertNotIn(
                secret,
                Path(result["data"]["flow"]).read_text(encoding="utf-8"),
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_shared_bucket_serializes_different_origins_and_rejects_rate_mismatch(self):
        first = request_policy.set_origin_policy(
            self.ws.slug, "https://one.example.test",
            headers={}, max_requests_per_second=2, rate_bucket="program",
        )
        request_policy.set_origin_policy(
            self.ws.slug, "https://two.example.test",
            headers={}, max_requests_per_second=2, rate_bucket="program",
        )
        policies = request_policy.load(self.ws.slug)
        clock = [10.0]
        sleeps: list[float] = []

        def monotonic():
            return clock[0]

        def sleep(value):
            sleeps.append(value)
            clock[0] += value

        with patch.object(request_policy.time, "monotonic", side_effect=monotonic), \
                patch.object(request_policy.time, "sleep", side_effect=sleep):
            request_policy.enforce_rate_limit(
                self.ws.slug, str(first["origin"]), policies[str(first["origin"])]
            )
            second_origin = request_policy.canonical_origin(
                "https://two.example.test"
            )
            request_policy.enforce_rate_limit(
                self.ws.slug, second_origin, policies[second_origin]
            )
        self.assertEqual(sleeps, [0.5])

        with self.assertRaisesRegex(
            request_policy.RequestPolicyError, "same maximum rate"
        ):
            request_policy.set_origin_policy(
                self.ws.slug, "https://three.example.test",
                headers={}, max_requests_per_second=3, rate_bucket="program",
            )

    def test_mailbox_source_resolves_at_send_time_but_is_not_projected(self):
        address = "researcher-fixture@example.invalid"
        credentials.save_mailbox(self.ws.slug, "research", {
            "provider": "mail.tm",
            "account_id": "account-fixture",
            "address": address,
            "mailbox_password": "mailbox-password-fixture",
            "bearer_token": "bearer-token-fixture",
            "target_password": "target-password-fixture",
            "delivered": {},
        })
        request_policy.set_origin_policy(
            self.ws.slug,
            "https://example.test",
            headers={},
            header_sources={
                "X-User-Id": {"kind": "mailbox-address", "alias": "research"},
            },
            max_requests_per_second=5,
        )
        origin, policy = request_policy.policy_for_url(
            self.ws.slug, "https://example.test/account"
        )
        self.assertEqual(origin, "https://example.test:443")
        self.assertEqual(
            request_policy.resolved_headers(self.ws.slug, policy),
            {"X-User-Id": address},
        )
        public = repr(request_policy.public_view(self.ws.slug))
        self.assertIn("X-User-Id", public)
        self.assertNotIn(address, public)

    def test_raw_network_tools_fail_before_opening_policy_bound_host(self):
        request_policy.set_origin_policy(
            self.ws.slug,
            "https://example.test",
            headers={"X-Research-Id": "fixture-secret"},
            max_requests_per_second=5,
        )
        self.ws.save_constraints(Constraints(in_scope=["example.test"]))
        with patch("grypton.tools.socket.create_connection") as connect:
            tls = tools.tls_certificate(self.ws, "example.test")
            scan = tools.port_scan(self.ws, "example.test", [443])
            tcp = tools.tcp_exchange(self.ws, "example.test", 443, "PING")
        self.assertFalse(tls["ok"])
        self.assertFalse(scan["ok"])
        self.assertFalse(tcp["ok"])
        self.assertEqual(connect.call_count, 0)
        self.assertIn("requires HTTP identification", tls["summary"])

    def test_browser_route_injects_policy_before_any_network_continue(self):
        request_policy.set_origin_policy(
            self.ws.slug,
            "https://example.test",
            headers={"X-Research-Id": "BROWSER-PRIVATE-6943a0"},
            max_requests_per_second=5,
        )

        class Context:
            callback = None

            def route(self, _pattern, callback):
                self.callback = callback

        class Chromium:
            def __init__(self, context):
                self.context = context

            def launch_persistent_context(self, **_kwargs):
                return self.context

        class Request:
            url = "https://example.test/page"
            headers = {"Accept": "text/html", "X-Research-Id": "caller-value"}
            post_data = ""

        class Route:
            request = Request()
            continued = None
            aborted = False

            def continue_(self, **kwargs):
                self.continued = kwargs

            def abort(self, _reason):
                self.aborted = True

        context = Context()
        playwright = SimpleNamespace(chromium=Chromium(context))
        launch_profile = {
            "profile": "/tmp/profile-fixture",
            "executable": "/bin/true",
            "environment": {},
        }
        with patch("grypton.tools._private_browser_proxy", return_value=""), \
                patch("grypton.request_policy.enforce_rate_limit") as limited:
            tools._launch_scoped_browser_context(
                playwright, launch_profile, self.ws, []
            )
            route = Route()
            context.callback(route)
        self.assertFalse(route.aborted)
        self.assertEqual(
            route.continued["headers"]["X-Research-Id"],
            "BROWSER-PRIVATE-6943a0",
        )
        limited.assert_called_once()

    def test_goja_request_has_no_transport_path_around_policy_http(self):
        request_policy.set_origin_policy(
            self.ws.slug,
            "https://example.test",
            headers={"X-Research-Id": "GOJA-PRIVATE-4500df"},
            max_requests_per_second=5,
        )
        central = {"ok": True, "summary": "central", "data": {}}
        with patch("grypton.config.private_egress_proxy", return_value=""), \
                patch.object(tools.Goja, "start", return_value={"ok": True}), \
                patch("grypton.tools.http_request", return_value=central) as sent:
            result = tools.Goja.request(
                self.ws, "https://example.test/path", method="GET"
            )
        self.assertIs(result, central)
        sent.assert_called_once()
        self.assertEqual(sent.call_args.kwargs["transport"], "goja")
        self.assertEqual(sent.call_args.args[:2], (
            self.ws, "https://example.test/path",
        ))

    def test_artifact_download_applies_header_and_discards_reflection(self):
        _HeaderHandler.seen = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), _HeaderHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            self.ws.save_constraints(Constraints(in_scope=[origin]))
            secret = "ARTIFACT-PRIVATE-82abc7"
            request_policy.set_origin_policy(
                self.ws.slug, origin,
                headers={"X-Research-Id": secret},
                max_requests_per_second=1000,
            )
            result = tools.artifact_download(
                self.ws, origin + "/artifact", "fixture.bin"
            )
            self.assertFalse(result["ok"])
            self.assertEqual(_HeaderHandler.seen, [secret])
            self.assertIn("discarded", result["summary"])
            self.assertNotIn(secret, repr(result))
            self.assertFalse((self.ws.loot_dir / "fixture.bin").exists())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_policy_cli_is_a_real_command_and_never_prints_values(self):
        self.assertEqual(
            _claude_style_arguments(["policy", "--help"]),
            ["policy", "--help"],
        )
        parsed = build_parser().parse_args(["policy", "show", self.ws.slug])
        self.assertEqual(parsed.command, "policy")
        self.assertEqual(parsed.policy_command, "show")

        secret = "CLI-PRIVATE-POLICY-74264f"
        output = io.StringIO()
        errors = io.StringIO()
        namespace = SimpleNamespace(
            target=self.ws.slug,
            policy_command="set",
            origin="https://example.test",
            max_rps=5.0,
            rate_bucket="engagement",
            header=["X-Research-Id"],
            header_from_mailbox=[],
        )
        with patch("grypton.cli.getpass.getpass", return_value=secret), \
                redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(cmd_policy(namespace), 0)
        self.assertNotIn(secret, output.getvalue() + errors.getvalue())

        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(cmd_policy(SimpleNamespace(
                target=self.ws.slug, policy_command="show", json=True,
            )), 0)
        self.assertNotIn(secret, output.getvalue())
        self.assertIn("X-Research-Id", output.getvalue())

    def test_native_httpx_shim_reaches_only_policy_aware_broker(self):
        _HeaderHandler.seen = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), _HeaderHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        async def exercise():
            origin = f"http://127.0.0.1:{server.server_port}"
            self.ws.save_constraints(Constraints(in_scope=[origin]))
            secret = "NATIVE-HTTPX-POLICY-f46d21"
            request_policy.set_origin_policy(
                self.ws.slug, origin,
                headers={"X-Research-Id": secret},
                max_requests_per_second=1000,
            )
            socket_path = config.RUNTIME_DIR / "native-httpx.sock"
            broker = ScopedNetworkBroker(
                self.ws.root, self.ws.slug, socket_path, os.getuid()
            )
            await broker.start()
            wrapper = config.RUNTIME_DIR / "httpx"
            wrapper.write_text(httpx_wrapper_source(socket_path), encoding="utf-8")
            wrapper.chmod(0o700)
            try:
                completed = await asyncio.to_thread(
                    subprocess.run,
                    [str(wrapper), "-u", origin + "/native"],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=30,
                )
            finally:
                await broker.close()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertNotIn(secret, completed.stdout + completed.stderr)
            self.assertEqual(_HeaderHandler.seen, [secret])

        try:
            asyncio.run(exercise())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_native_curl_shim_reaches_only_policy_aware_broker(self):
        _HeaderHandler.seen = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), _HeaderHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        async def exercise():
            origin = f"http://127.0.0.1:{server.server_port}"
            self.ws.save_constraints(Constraints(in_scope=[origin]))
            secret = "NATIVE-CURL-POLICY-92db17"
            request_policy.set_origin_policy(
                self.ws.slug, origin,
                headers={"X-Research-Id": secret},
                max_requests_per_second=1000,
            )
            socket_path = config.RUNTIME_DIR / "native-curl.sock"
            broker = ScopedNetworkBroker(
                self.ws.root, self.ws.slug, socket_path, os.getuid()
            )
            await broker.start()
            wrapper = config.RUNTIME_DIR / "curl"
            wrapper.write_text(curl_wrapper_source(socket_path), encoding="utf-8")
            wrapper.chmod(0o700)
            try:
                completed = await asyncio.to_thread(
                    subprocess.run,
                    [str(wrapper), "--silent", origin + "/native"],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=30,
                )
            finally:
                await broker.close()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertNotIn(secret, completed.stdout + completed.stderr)
            self.assertEqual(_HeaderHandler.seen, [secret])

        try:
            asyncio.run(exercise())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
