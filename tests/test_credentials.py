from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import threading
import unittest
from urllib.parse import quote, quote_plus
from unittest.mock import patch

from grypton import config, credentials, tools
from grypton.toolserver import REGISTRY, dispatch
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


class _AuthHandler(BaseHTTPRequestHandler):
    username = "named-user@example.test"
    password = "test-password-never-log"
    cookie = "session-cookie-never-log"
    token = "access-token-never-log"
    custom_cookie = "custom-cookie-never-log"
    login_gets = 0
    login_posts = 0
    verification_denied = False

    def _send(self, status: int, value: dict, *, cookie: str = "",
              cookie_name: str = "app_session") -> None:
        payload = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if cookie:
            self.send_header("Set-Cookie", f"{cookie_name}={cookie}; HttpOnly; Path=/")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        if self.path == "/login":
            type(self).login_posts += 1
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode()
        if self.path == "/mfa":
            self._send(202, {"mfa_required": True}, cookie=self.cookie)
            return
        if self.path == "/tracking":
            self._send(200, {"data": {"token": "page-2"}}, cookie="abc",
                       cookie_name="tracking_id")
            return
        try:
            value = json.loads(body)
        except ValueError:
            value = {}
        if value.get("login") != self.username or value.get("passcode") != self.password:
            self._send(401, {"error": "invalid credentials"})
            return
        if self.path == "/custom":
            self._send(200, {"login": "accepted"}, cookie=self.custom_cookie,
                       cookie_name="grant_marker")
            return
        self._send(200, {
            "data": {"access_token": self.token},
            "username": self.username,
        }, cookie=self.cookie)

    def do_GET(self):
        if self.path == "/login":
            type(self).login_gets += 1
        cookie = self.headers.get("Cookie", "")
        authorization = self.headers.get("Authorization", "")
        authenticated = (
            f"app_session={self.cookie}" in cookie
            or authorization == f"Bearer {self.token}"
        )
        custom_authenticated = f"grant_marker={self.custom_cookie}" in cookie
        if self.path == "/custom-me" and custom_authenticated:
            self._send(200, {"authenticated": True})
        elif self.path == "/public-marker":
            self._send(200, {"authenticated": True})
        elif self.path == "/followup-401" and authenticated:
            self._send(
                401,
                {"error": "endpoint denied", "access_token": "denied-token-never-keep"},
                cookie="denied-cookie-never-keep",
            )
        elif self.path == "/followup-403" and authenticated:
            self._send(403, {"error": "session revoked"})
        elif self.path == "/followup-mfa" and authenticated:
            self._send(200, {"mfa_required": True})
        elif self.path == "/followup-captcha" and authenticated:
            self._send(200, {"captcha": True})
        elif self.path == "/followup-limit" and authenticated:
            self._send(429, {"error": "rate limited"})
        elif self.path == "/me" and type(self).verification_denied:
            self._send(401, {"authenticated": False})
        elif self.path in {"/me", "/second"} and authenticated:
            self._send(200, {"authenticated": True, "access_token": self.token})
        else:
            self._send(401, {"authenticated": False})

    def log_message(self, *args):
        pass


@contextmanager
def auth_server():
    _AuthHandler.login_gets = 0
    _AuthHandler.login_posts = 0
    _AuthHandler.verification_denied = False
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AuthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class _CookieGateHandler(BaseHTTPRequestHandler):
    username = "gate-user@example.test"
    password = "gate-password-never-log"
    edge_cookie = "edge-cookie-never-log"
    session_cookie = "gate-session-never-log"
    redirect_location = ""
    login_gets = 0
    login_posts = 0
    posts_without_edge_cookie = 0
    authenticated_verifications = 0
    anonymous_controls = 0

    def _json(self, status: int, value: dict, *, cookie: str = "",
              cookie_name: str = "") -> None:
        payload = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if cookie:
            self.send_header("Set-Cookie", f"{cookie_name}={cookie}; HttpOnly; Path=/")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _edge_redirect(self) -> None:
        self.send_response(307)
        self.send_header("Location", type(self).redirect_location or "/login")
        self.send_header(
            "Set-Cookie",
            f"edge_clearance={self.edge_cookie}; HttpOnly; Path=/",
        )
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        cookie = self.headers.get("Cookie", "")
        has_edge = f"edge_clearance={self.edge_cookie}" in cookie
        has_session = f"app_session={self.session_cookie}" in cookie
        if self.path == "/login":
            type(self).login_gets += 1
            if not has_edge:
                self._edge_redirect()
            else:
                self._json(405, {"error": "method not allowed"})
            return
        if self.path == "/me" and not has_edge:
            self._edge_redirect()
            return
        if self.path == "/me" and has_session:
            type(self).authenticated_verifications += 1
            self._json(200, {"authenticated": True})
            return
        if self.path == "/me" and has_edge:
            type(self).anonymous_controls += 1
        self._json(401, {"authenticated": False})

    def do_POST(self):
        if self.path != "/login":
            self._json(404, {"error": "not found"})
            return
        type(self).login_posts += 1
        cookie = self.headers.get("Cookie", "")
        if f"edge_clearance={self.edge_cookie}" not in cookie:
            type(self).posts_without_edge_cookie += 1
            self._edge_redirect()
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            value = json.loads(self.rfile.read(length).decode())
        except ValueError:
            value = {}
        if value.get("login") != self.username or value.get("passcode") != self.password:
            self._json(401, {"error": "invalid credentials"})
            return
        self._json(
            200, {"login": "accepted"}, cookie=self.session_cookie,
            cookie_name="app_session",
        )

    def log_message(self, *args):
        pass


@contextmanager
def cookie_gate_server(*, redirect_location: str = ""):
    _CookieGateHandler.redirect_location = redirect_location
    _CookieGateHandler.login_gets = 0
    _CookieGateHandler.login_posts = 0
    _CookieGateHandler.posts_without_edge_cookie = 0
    _CookieGateHandler.authenticated_verifications = 0
    _CookieGateHandler.anonymous_controls = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CookieGateHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class _ProbeHandler(BaseHTTPRequestHandler):
    requests = 0
    authorizations: list[str] = []

    def do_GET(self):
        type(self).requests += 1
        type(self).authorizations.append(self.headers.get("Authorization", ""))
        payload = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@contextmanager
def probe_server():
    _ProbeHandler.requests = 0
    _ProbeHandler.authorizations = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ProbeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class CredentialIsolationTests(unittest.TestCase):
    def _workspace(self, port: int) -> Workspace:
        ws = Workspace("credential-test")
        ws.create(f"http://127.0.0.1:{port}", "web")
        ws.save_constraints(Constraints(in_scope=[f"http://127.0.0.1:{port}"]))
        return ws

    def test_verified_login_keeps_all_secrets_out_of_observable_state(self):
        with isolated_runtime() as root, auth_server() as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", _AuthHandler.username, _AuthHandler.password
            )
            credential_file = config.CREDENTIALS_DIR / ws.slug / "primary.json"
            self.assertEqual(stat.S_IMODE(credential_file.stat().st_mode), 0o600)
            self.assertFalse(credential_file.is_relative_to(ws.root))

            observed_argv: list[list[str]] = []
            observed_header_modes: list[int] = []
            real_run = subprocess.run

            def observe(argv, *args, **kwargs):
                values = [str(item) for item in argv]
                observed_argv.append(values)
                for value in values:
                    if value.startswith("@") and value.endswith(".headers"):
                        path = Path(value[1:])
                        self.assertTrue(path.is_relative_to(config.RUNTIME_DIR))
                        self.assertFalse(path.is_relative_to(ws.root))
                        observed_header_modes.append(stat.S_IMODE(path.stat().st_mode))
                return real_run(argv, *args, **kwargs)

            request = {
                "url": f"http://127.0.0.1:{port}/login",
                "credential": "primary",
                "verify_url": f"http://127.0.0.1:{port}/me",
                "success_marker": '"authenticated": true',
                "username_field": "login",
                "password_field": "passcode",
                "encoding": "json",
            }
            with patch("grypton.tools.subprocess.run", side_effect=observe):
                result = dispatch(ws, "credential_login", request)
                followup = dispatch(ws, "authenticated_http_request", {
                    "url": f"http://127.0.0.1:{port}/second",
                    "credential": "primary",
                })
            self.assertTrue(result["ok"], result)
            self.assertTrue(followup["ok"], followup)
            self.assertTrue(credentials.session_status(ws.slug, "primary")["established"])
            self.assertTrue(observed_header_modes)
            self.assertTrue(all(mode == 0o600 for mode in observed_header_modes))

            secrets = (
                _AuthHandler.username, _AuthHandler.password,
                _AuthHandler.cookie, _AuthHandler.token,
            )
            observable = json.dumps([result, followup])
            observable += (ws.root / ".ledger/tool-calls.jsonl").read_text()
            observable += "".join(
                path.read_text(errors="replace") for path in ws.flows_dir.glob("*.http")
            )
            argv_text = json.dumps(observed_argv)
            for secret in secrets:
                self.assertNotIn(secret, observable)
                self.assertNotIn(secret, argv_text)
            self.assertFalse(any((config.RUNTIME_DIR / "http-tmp" / ws.slug).iterdir()))

    def test_iran_e164_username_normalization_variants(self):
        variants = {
            "09123456789": "+989123456789",
            "0912 345-6789": "+989123456789",
            "+98 (912) 345 6789": "+989123456789",
            "0098-912-345-6789": "+989123456789",
            "98 912 345 6789": "+989123456789",
        }
        for stored, expected in variants.items():
            with self.subTest(stored=stored[:4]):
                self.assertEqual(
                    credentials.normalize_login_username(stored, "iran-e164"),
                    expected,
                )
        self.assertEqual(
            credentials.normalize_login_username("  opaque account  ", "stored"),
            "  opaque account  ",
        )
        for invalid in (
            "user@example.test", "9123456789", "+9809123456789",
            "+989123", "09۱۲۳۴۵۶۷۸۹",
        ):
            with self.subTest(invalid=invalid[:4]):
                with self.assertRaises(credentials.CredentialError):
                    credentials.normalize_login_username(invalid, "iran-e164")

    def test_transformed_username_is_private_in_transport_and_status(self):
        stored_username = "0912 345-6789"
        transformed_username = "+989123456789"
        with isolated_runtime(), patch.object(
            _AuthHandler, "username", transformed_username
        ), auth_server() as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "phone", stored_username, _AuthHandler.password
            )
            observed_argv: list[list[str]] = []
            real_run = subprocess.run

            def observe(argv, *args, **kwargs):
                observed_argv.append([str(item) for item in argv])
                return real_run(argv, *args, **kwargs)

            with patch("grypton.tools.subprocess.run", side_effect=observe):
                result = dispatch(ws, "credential_login", {
                    "url": f"http://127.0.0.1:{port}/login",
                    "credential": "phone",
                    "verify_url": f"http://127.0.0.1:{port}/me",
                    "success_marker": '"authenticated": true',
                    "username_field": "login",
                    "password_field": "passcode",
                    "username_transform": "iran-e164",
                    "headers": {"X-Login-Representation": transformed_username},
                })
            self.assertTrue(result["ok"], result)
            status = dispatch(ws, "credential_status", {"credential": "phone"})
            self.assertTrue(status["ok"], status)
            self.assertEqual(status["data"][0]["username_kind"], "iran-local-phone")

            observable = json.dumps([result, status, observed_argv])
            observable += (ws.root / ".ledger/tool-calls.jsonl").read_text()
            observable += "".join(
                path.read_text(errors="replace")
                for path in ws.flows_dir.glob("*.http")
            )
            variants = {
                stored_username,
                transformed_username,
                quote(stored_username, safe=""),
                quote_plus(stored_username, safe=""),
                quote(transformed_username, safe=""),
                quote_plus(transformed_username, safe=""),
            }
            for secret_variant in variants:
                self.assertNotIn(secret_variant, observable)
            self.assertIn("GRYPTON_REDACTED_USERNAME", observable)

    def test_invalid_username_transform_does_not_reserve_an_attempt(self):
        with isolated_runtime(), auth_server() as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "user@example.test", _AuthHandler.password
            )
            result = dispatch(ws, "credential_login", {
                "url": f"http://127.0.0.1:{port}/login",
                "credential": "primary",
                "verify_url": f"http://127.0.0.1:{port}/me",
                "success_marker": '"authenticated": true',
                "username_transform": "iran-e164",
            })
            self.assertFalse(result["ok"], result)
            self.assertIn("Iranian mobile identifier", result["summary"])
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 0
            )
            self.assertEqual(_AuthHandler.login_gets, 0)
            self.assertEqual(_AuthHandler.login_posts, 0)
            self.assertEqual(list(ws.flows_dir.glob("*.http")), [])

    def test_status_classifies_username_without_identifier_details(self):
        with isolated_runtime():
            values = {
                "mail": "person@example.test",
                "local": "0912-345-6789",
                "e164": "+98 912 345 6789",
                "other": "account-handle",
            }
            expected = {
                "mail": "email",
                "local": "iran-local-phone",
                "e164": "iran-e164-phone",
                "other": "opaque",
            }
            for alias, username in values.items():
                credentials.save_credential("target", alias, username, "secret")
            workspace = Workspace("target")
            workspace.create("https://example.test", "web")
            rows = dispatch(
                workspace, "credential_status", {}
            )["data"]
            kinds = {row["name"]: row["username_kind"] for row in rows}
            self.assertEqual(kinds, expected)
            rendered = json.dumps(rows)
            for username in values.values():
                self.assertNotIn(username, rendered)

    def test_credential_login_schema_exposes_username_transform(self):
        schema = REGISTRY["credential_login"][1]
        transform = schema["properties"]["username_transform"]
        self.assertEqual(transform["enum"], ["stored", "iran-e164"])
        self.assertNotIn("username_transform", schema["required"])

    def test_cookie_gate_bootstraps_anonymously_before_single_credential_post(self):
        with isolated_runtime(), cookie_gate_server() as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary",
                _CookieGateHandler.username, _CookieGateHandler.password,
            )
            result = dispatch(ws, "credential_login", {
                "url": f"http://127.0.0.1:{port}/login",
                "credential": "primary",
                "verify_url": f"http://127.0.0.1:{port}/me",
                "success_marker": '"authenticated": true',
                "username_field": "login",
                "password_field": "passcode",
            })

            self.assertTrue(result["ok"], result)
            self.assertEqual(_CookieGateHandler.login_gets, 2)
            self.assertEqual(_CookieGateHandler.login_posts, 1)
            self.assertEqual(_CookieGateHandler.posts_without_edge_cookie, 0)
            self.assertEqual(_CookieGateHandler.authenticated_verifications, 1)
            self.assertEqual(_CookieGateHandler.anonymous_controls, 1)
            status = credentials.session_status(ws.slug, "primary")
            self.assertEqual(status["attempts"], 1)
            self.assertTrue(status["established"])
            self.assertEqual(len(result["data"]["bootstrap_flows"]), 2)

            captures = [
                path.read_text(encoding="utf-8", errors="replace")
                for path in ws.flows_dir.glob("*.http")
            ]
            self.assertEqual(len(captures), 5)
            transports = "\n".join(captures)
            self.assertEqual(transports.count('"transport": "credential-bootstrap:primary"'), 2)
            self.assertIn('"transport": "credential:primary"', transports)
            self.assertIn('"transport": "credential-verify:primary"', transports)
            self.assertIn('"transport": "credential-control:primary"', transports)
            observable = json.dumps(result) + transports
            for secret in (
                _CookieGateHandler.username, _CookieGateHandler.password,
                _CookieGateHandler.edge_cookie, _CookieGateHandler.session_cookie,
            ):
                self.assertNotIn(secret, observable)

    def test_normal_login_uses_one_preflight_and_one_credential_post(self):
        with isolated_runtime(), auth_server() as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", _AuthHandler.username, _AuthHandler.password
            )
            result = dispatch(ws, "credential_login", {
                "url": f"http://127.0.0.1:{port}/login",
                "credential": "primary",
                "verify_url": f"http://127.0.0.1:{port}/me",
                "success_marker": '"authenticated": true',
                "username_field": "login",
                "password_field": "passcode",
            })
            self.assertTrue(result["ok"], result)
            self.assertEqual(_AuthHandler.login_gets, 1)
            self.assertEqual(_AuthHandler.login_posts, 1)
            self.assertEqual(len(result["data"]["bootstrap_flows"]), 1)
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 1
            )

    def test_bootstrap_never_follows_an_off_scope_redirect(self):
        with isolated_runtime(), probe_server() as probe_port:
            redirect = f"http://127.0.0.1:{probe_port}/outside"
            with cookie_gate_server(redirect_location=redirect) as port:
                ws = self._workspace(port)
                credentials.save_credential(
                    ws.slug, "primary",
                    _CookieGateHandler.username, _CookieGateHandler.password,
                )
                result = dispatch(ws, "credential_login", {
                    "url": f"http://127.0.0.1:{port}/login",
                    "credential": "primary",
                    "verify_url": f"http://127.0.0.1:{port}/me",
                    "success_marker": '"authenticated": true',
                    "username_field": "login",
                    "password_field": "passcode",
                })
                self.assertFalse(result["ok"], result)
                self.assertIn("out-of-scope redirect", result["summary"])
                self.assertEqual(_CookieGateHandler.login_gets, 1)
                self.assertEqual(_CookieGateHandler.login_posts, 0)
                self.assertEqual(_ProbeHandler.requests, 0)
                self.assertEqual(
                    credentials.session_status(ws.slug, "primary")["attempts"], 0
                )
                self.assertEqual(len(list(ws.flows_dir.glob("*.http"))), 1)

    def test_cross_origin_verification_and_followup_fail_before_network(self):
        with isolated_runtime(), auth_server() as port, probe_server() as other_port:
            ws = self._workspace(port)
            ws.save_constraints(Constraints(in_scope=[
                f"http://127.0.0.1:{port}",
                f"http://127.0.0.1:{other_port}",
            ]))
            credentials.save_credential(
                ws.slug, "primary", _AuthHandler.username, _AuthHandler.password
            )

            cross_verify = dispatch(ws, "credential_login", {
                "url": f"http://127.0.0.1:{port}/login",
                "credential": "primary",
                "verify_url": f"http://127.0.0.1:{other_port}/me",
                "success_marker": '"authenticated": true',
                "username_field": "login",
                "password_field": "passcode",
            })
            self.assertFalse(cross_verify["ok"], cross_verify)
            self.assertIn("exact origin", cross_verify["summary"])
            self.assertEqual(_ProbeHandler.requests, 0)
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 0
            )

            login = dispatch(ws, "credential_login", {
                "url": f"http://127.0.0.1:{port}/login",
                "credential": "primary",
                "verify_url": f"http://127.0.0.1:{port}/me",
                "success_marker": '"authenticated": true',
                "username_field": "login",
                "password_field": "passcode",
            })
            self.assertTrue(login["ok"], login)
            status = credentials.session_status(ws.slug, "primary")
            expected_origin = f"http://127.0.0.1:{port}"
            self.assertEqual(status["origin"], expected_origin)
            self.assertEqual(
                credentials.token_origin(ws.slug, "primary"), expected_origin
            )
            for private_path in (
                credentials.attempt_path(ws.slug, "primary"),
                credentials.token_path(ws.slug, "primary"),
            ):
                self.assertEqual(stat.S_IMODE(private_path.stat().st_mode), 0o600)
                self.assertFalse(private_path.is_relative_to(ws.root))
                self.assertEqual(
                    json.loads(private_path.read_text(encoding="utf-8"))["origin"],
                    expected_origin,
                )

            followup = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{other_port}/second",
                "credential": "primary",
            })
            self.assertFalse(followup["ok"], followup)
            self.assertIn("exact login origin", followup["summary"])
            self.assertEqual(_ProbeHandler.requests, 0)
            self.assertEqual(_ProbeHandler.authorizations, [])

    def test_custom_login_fields_use_placeholder_capture_for_encoded_secrets(self):
        username = "name+tag@example.test"
        password = 'p"ass\\word\n%+'
        with isolated_runtime(), auth_server() as port:
            ws = self._workspace(port)
            cases = (
                ("json-redact", "json", "account.id", "vault[proof]"),
                ("form-redact", "form", "person-id", "answer.code"),
            )
            for alias, encoding, username_field, password_field in cases:
                with self.subTest(encoding=encoding):
                    credentials.save_credential(ws.slug, alias, username, password)
                    before = set(ws.flows_dir.glob("*.http"))
                    result = dispatch(ws, "credential_login", {
                        "url": f"http://127.0.0.1:{port}/login",
                        "credential": alias,
                        "verify_url": f"http://127.0.0.1:{port}/me",
                        "success_marker": '"authenticated": true',
                        "username_field": username_field,
                        "password_field": password_field,
                        "encoding": encoding,
                        "fields": {"mode": "capture-test"},
                        "headers": {
                            "X-Encoded-Identity": quote_plus(username, safe=""),
                            "X-Escaped-Proof": json.dumps(password)[1:-1],
                        },
                    })
                    self.assertFalse(result["ok"], result)
                    created = set(ws.flows_dir.glob("*.http")) - before
                    self.assertEqual(len(created), 2)
                    captures = [
                        path.read_text(encoding="utf-8") for path in created
                    ]
                    capture = "\n".join(captures)
                    variants = {
                        username, password,
                        quote(username, safe=""), quote_plus(username, safe=""),
                        quote(password, safe=""), quote_plus(password, safe=""),
                        json.dumps(username, ensure_ascii=False)[1:-1],
                        json.dumps(password, ensure_ascii=False)[1:-1],
                        json.dumps(username, ensure_ascii=True)[1:-1],
                        json.dumps(password, ensure_ascii=True)[1:-1],
                    }
                    for secret_variant in variants:
                        self.assertNotIn(secret_variant, capture)
                    self.assertIn("GRYPTON_REDACTED_USERNAME", capture)
                    self.assertIn("GRYPTON_REDACTED_PASSWORD", capture)
                    self.assertIn(username_field, capture)
                    self.assertIn(password_field, capture)
                    self.assertEqual(sum(
                        "GRYPTON_REDACTED_USERNAME" in item for item in captures
                    ), 1)

    def test_invalid_arguments_and_scope_do_not_consume_login_budget(self):
        with isolated_runtime(), auth_server() as port:
            ws = self._workspace(port)
            credentials.save_credential(ws.slug, "primary", "u", "p")
            result = dispatch(ws, "credential_login", {
                "url": "https://outside.example/login",
                "credential": "primary",
                "verify_url": f"http://127.0.0.1:{port}/me",
                "success_marker": "authenticated",
            })
            self.assertFalse(result["ok"])
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 0
            )
            result = dispatch(ws, "credential_login", {
                "url": f"http://127.0.0.1:{port}/login",
                "credential": "primary",
                "verify_url": f"http://127.0.0.1:{port}/me",
                "success_marker": "",
            })
            self.assertFalse(result["ok"])
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 0
            )

    def test_auth_tools_reject_destination_and_proxy_routing_headers(self):
        with isolated_runtime(), auth_server() as port:
            ws = self._workspace(port)
            credentials.save_credential(ws.slug, "primary", "u", "p")
            base = f"http://127.0.0.1:{port}"
            for header in ("Host", "Proxy-Authorization", "Proxy-Connection"):
                with self.subTest(tool="credential_login", header=header):
                    result = dispatch(ws, "credential_login", {
                        "url": base + "/login",
                        "credential": "primary",
                        "verify_url": base + "/me",
                        "success_marker": "authenticated",
                        "headers": {header: "reroute.invalid"},
                    })
                    self.assertFalse(result["ok"], result)
                    self.assertIn("not allowed", result["summary"])
                    self.assertEqual(
                        credentials.session_status(ws.slug, "primary")["attempts"], 0
                    )

                with self.subTest(tool="authenticated_http_request", header=header):
                    result = dispatch(ws, "authenticated_http_request", {
                        "url": base + "/me",
                        "credential": "primary",
                        "headers": {header: "reroute.invalid"},
                    })
                    self.assertFalse(result["ok"], result)
                    self.assertIn("not allowed", result["summary"])

    def test_mfa_is_a_persistent_clean_blocker_without_retry(self):
        with isolated_runtime(), auth_server() as port:
            ws = self._workspace(port)
            credentials.save_credential(ws.slug, "mfa", "u", "p")
            request = {
                "url": f"http://127.0.0.1:{port}/mfa",
                "credential": "mfa",
                "verify_url": f"http://127.0.0.1:{port}/me",
                "success_marker": "authenticated",
            }
            first = dispatch(ws, "credential_login", request)
            second = dispatch(ws, "credential_login", request)
            self.assertFalse(first["ok"])
            self.assertFalse(second["ok"])
            self.assertIn("MFA/OTP", first["summary"])
            status = credentials.session_status(ws.slug, "mfa")
            self.assertEqual(status["attempts"], 1)
            self.assertIn("MFA/OTP", status["blocked_reason"])

    def test_tracking_cookie_and_unrelated_token_remain_unverified(self):
        with isolated_runtime(), auth_server() as port:
            ws = self._workspace(port)
            credentials.save_credential(ws.slug, "tracking", "u", "p")
            result = dispatch(ws, "credential_login", {
                "url": f"http://127.0.0.1:{port}/tracking",
                "credential": "tracking",
                "verify_url": f"http://127.0.0.1:{port}/me",
                "success_marker": "authenticated",
            })
            self.assertFalse(result["ok"])
            status = credentials.session_status(ws.slug, "tracking")
            self.assertFalse(status["established"])
            self.assertFalse(status["has_auth_cookies"])
            self.assertFalse(status["has_bearer_token"])

            credentials.save_credential(ws.slug, "public-marker", "u", "p")
            public = dispatch(ws, "credential_login", {
                "url": f"http://127.0.0.1:{port}/tracking",
                "credential": "public-marker",
                "verify_url": f"http://127.0.0.1:{port}/public-marker",
                "success_marker": "\"authenticated\": true",
            })
            self.assertFalse(public["ok"], public)
            self.assertIn("depend on the session", public["summary"])
            self.assertFalse(
                credentials.session_status(ws.slug, "public-marker")["established"]
            )

    def test_two_failed_attempts_have_exhausted_safe_state(self):
        with isolated_runtime():
            credentials.save_credential("target", "primary", "u", "p")
            for _ in range(2):
                credentials.begin_login_attempt("target", "primary")
                credentials.record_login_outcome("target", "primary")
            status = credentials.session_status("target", "primary")
            self.assertEqual(status["state"], "exhausted")
            self.assertTrue(status["exhausted"])
            self.assertEqual(status["attempts"], 2)
            with self.assertRaisesRegex(credentials.CredentialError, "exhausted"):
                credentials.begin_login_attempt("target", "primary")

    def test_legacy_proven_state_migrates_to_one_refresh_per_generation(self):
        with isolated_runtime():
            target, alias = "legacy-refresh", "primary"
            credentials.save_credential(target, alias, "u", "p")
            path = credentials.attempt_path(target, alias)
            credentials._atomic_private_json(path, {
                "version": 1,
                "attempts": 2,
                "established": True,
                "blocked_reason": "",
                "origin": "https://app.example.test:443",
            })

            migrated = credentials.load_attempt_state(target, alias)
            self.assertTrue(migrated["ever_established"])
            self.assertEqual(migrated["proof_generation"], 1)
            self.assertEqual(migrated["refresh_attempted_generation"], 0)
            credentials.record_session_stale(
                target, alias, generation=1,
                profile_revision="0123456789ab",
            )
            self.assertEqual(
                credentials.begin_refresh_attempt(
                    target, alias, generation=1
                ),
                1,
            )
            with self.assertRaisesRegex(
                credentials.CredentialError, "already attempted"
            ):
                credentials.begin_refresh_attempt(
                    target, alias, generation=1
                )
            with self.assertRaisesRegex(
                credentials.CredentialError, "configured session renewal"
            ):
                credentials.begin_login_attempt(target, alias)
            state = credentials.load_attempt_state(target, alias)
            self.assertEqual(state["attempts"], 2)
            self.assertEqual(state["refresh_attempted_generation"], 1)

    def test_successful_refresh_advances_proof_and_opens_one_new_slot(self):
        with isolated_runtime():
            target, alias = "refresh-generation", "primary"
            credentials.save_credential(target, alias, "u", "p")
            credentials.begin_login_attempt(target, alias)
            credentials.record_login_outcome(
                target, alias, established=True,
                origin="https://app.example.test:443",
                profile_revision="0123456789ab",
            )
            credentials.record_session_stale(
                target, alias, generation=1,
                profile_revision="0123456789ab",
            )
            credentials.begin_refresh_attempt(target, alias, generation=1)
            credentials.record_refresh_outcome(
                target, alias, generation=1, established=True,
                origin="https://app.example.test:443",
                profile_revision="0123456789ab",
            )
            renewed = credentials.load_attempt_state(target, alias)
            self.assertEqual(renewed["attempts"], 1)
            self.assertEqual(renewed["proof_generation"], 2)
            self.assertEqual(renewed["refresh_attempted_generation"], 0)

            credentials.record_session_stale(
                target, alias, generation=2,
                profile_revision="0123456789ab",
            )
            self.assertEqual(
                credentials.begin_refresh_attempt(
                    target, alias, generation=2
                ),
                2,
            )

    def test_failed_refresh_reservation_survives_fresh_interpreter(self):
        with isolated_runtime() as root:
            target, alias = "process-refresh", "primary"
            credentials.save_credential(target, alias, "u", "p")
            credentials.begin_login_attempt(target, alias)
            credentials.record_login_outcome(
                target, alias, established=True,
                origin="https://app.example.test:443",
                profile_revision="0123456789ab",
            )
            credentials.record_session_stale(
                target, alias, generation=1,
                profile_revision="0123456789ab",
            )
            credentials.begin_refresh_attempt(target, alias, generation=1)
            credentials.record_refresh_outcome(
                target, alias, generation=1,
            )

            source_root = Path(__file__).resolve().parents[1]
            environment = dict(os.environ)
            environment.update({
                "GRYPTON_HOME": str(root),
                "GRYPTON_OPENCODE_WORKSPACES_DIR": str(
                    root / ".opencode-workspaces"
                ),
                "PYTHONPATH": str(source_root),
            })
            completed = subprocess.run(
                ["python3", "-c", """
from grypton import credentials
try:
    credentials.begin_refresh_attempt(
        "process-refresh", "primary", generation=1
    )
except credentials.CredentialError as exc:
    if "already attempted" not in str(exc):
        raise
else:
    raise SystemExit("persisted renewal reservation was reopened")
"""],
                cwd=source_root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(
                completed.returncode, 0,
                (completed.stdout, completed.stderr),
            )
            state = credentials.load_attempt_state(target, alias)
            self.assertEqual(state["refresh_attempted_generation"], 1)
            self.assertEqual(state["refresh_submissions"], 1)

    def test_new_custom_cookie_is_accepted_only_after_scoped_verification(self):
        with isolated_runtime(), auth_server() as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "custom", _AuthHandler.username, _AuthHandler.password
            )
            result = dispatch(ws, "credential_login", {
                "url": f"http://127.0.0.1:{port}/custom",
                "credential": "custom",
                "verify_url": f"http://127.0.0.1:{port}/custom-me",
                "success_marker": "\"authenticated\": true",
                "username_field": "login",
                "password_field": "passcode",
            })
            self.assertTrue(result["ok"], result)
            status = credentials.session_status(ws.slug, "custom")
            self.assertEqual(status["state"], "authenticated")
            self.assertTrue(status["has_cookies"])
            self.assertFalse(status["has_auth_cookies"])
            self.assertFalse(status["has_bearer_token"])

    def test_authenticated_endpoint_denials_preserve_proven_session(self):
        cases = (
            ("401", "endpoint-unauthenticated"),
            ("403", "endpoint-forbidden"),
            ("mfa", "step-up-required"),
            ("captcha", "challenge"),
            ("limit", "rate-limited"),
        )
        with isolated_runtime(), auth_server() as port:
            ws = self._workspace(port)
            for suffix, expected in cases:
                with self.subTest(suffix=suffix):
                    alias = f"followup-{suffix}"
                    credentials.save_credential(
                        ws.slug, alias, _AuthHandler.username, _AuthHandler.password
                    )
                    login = dispatch(ws, "credential_login", {
                        "url": f"http://127.0.0.1:{port}/login",
                        "credential": alias,
                        "verify_url": f"http://127.0.0.1:{port}/me",
                        "success_marker": "\"authenticated\": true",
                        "username_field": "login",
                        "password_field": "passcode",
                    })
                    self.assertTrue(login["ok"], login)
                    jar = credentials.cookie_jar_path(ws.slug, alias)
                    cookies_before = jar.read_bytes()
                    tokens_before = credentials.token_path(
                        ws.slug, alias
                    ).read_bytes()
                    result = dispatch(ws, "authenticated_http_request", {
                        "url": f"http://127.0.0.1:{port}/followup-{suffix}",
                        "credential": alias,
                    })
                    self.assertFalse(result["ok"], result)
                    self.assertIn("retained", result["summary"])
                    observation = result["data"]["auth_observation"]
                    self.assertEqual(observation["kind"], expected)
                    self.assertFalse(observation["conclusive_for_session"])
                    self.assertFalse(observation["state_changed"])
                    self.assertNotIn("credential", observation["detail"].lower())
                    self.assertNotIn("auth_blocker", result["data"])
                    status = credentials.session_status(ws.slug, alias)
                    self.assertTrue(status["established"])
                    self.assertEqual(status["state"], "authenticated")
                    self.assertEqual(status["blocked_reason"], "")
                    self.assertEqual(jar.read_bytes(), cookies_before)
                    self.assertEqual(
                        credentials.token_path(ws.slug, alias).read_bytes(),
                        tokens_before,
                    )

                    followup = dispatch(ws, "authenticated_http_request", {
                        "url": f"http://127.0.0.1:{port}/second",
                        "credential": alias,
                    })
                    self.assertTrue(followup["ok"], followup)
                    self.assertTrue(
                        credentials.session_status(ws.slug, alias)["established"]
                    )

    def test_verification_endpoint_denial_requires_complete_reproof(self):
        with isolated_runtime(), auth_server() as port:
            ws = self._workspace(port)
            alias = "verification-denial"
            origin = f"http://127.0.0.1:{port}"
            credentials.save_credential(
                ws.slug, alias, _AuthHandler.username, _AuthHandler.password
            )
            login = dispatch(ws, "credential_login", {
                "url": origin + "/login",
                "credential": alias,
                "verify_url": origin + "/me",
                "success_marker": '"authenticated": true',
                "username_field": "login",
                "password_field": "passcode",
            })
            self.assertTrue(login["ok"], login)
            credentials.save_auth_profile(ws.slug, alias, {
                "version": 1,
                "strategy": "http",
                "login_url": origin + "/login",
                "verify_url": origin + "/me",
                "success_marker": '"authenticated": true',
                "username_transform": "stored",
                "timeout": 30,
                "http": {
                    "encoding": "json",
                    "username_field": "login",
                    "password_field": "passcode",
                    "fields": {},
                    "headers": {},
                },
            })
            jar = credentials.cookie_jar_path(ws.slug, alias)
            cookie_snapshot = jar.read_bytes()
            token_snapshot = credentials.token_path(ws.slug, alias).read_bytes()

            _AuthHandler.verification_denied = True
            denied = dispatch(ws, "authenticated_http_request", {
                "url": origin + "/me",
                "credential": alias,
            })

            self.assertFalse(denied["ok"], denied)
            self.assertIn("complete session proof was not rerun", denied["summary"])
            self.assertTrue(denied["data"]["session_state_retained"])
            status = credentials.session_status(ws.slug, alias)
            self.assertTrue(status["established"])
            self.assertEqual(status["blocked_reason"], "")
            self.assertEqual(jar.read_bytes(), cookie_snapshot)
            self.assertEqual(
                credentials.token_path(ws.slug, alias).read_bytes(),
                token_snapshot,
            )

            _AuthHandler.verification_denied = False
            healthy = dispatch(ws, "authenticated_http_request", {
                "url": origin + "/me",
                "credential": alias,
            })
            self.assertTrue(healthy["ok"], healthy)

    def test_concurrent_denial_rollback_cannot_clobber_successful_rotation(self):
        with isolated_runtime():
            ws = Workspace("credential-concurrency")
            origin = "https://app.example.test"
            ws.create(origin, "web")
            ws.save_constraints(Constraints(in_scope=[origin]))
            alias = "primary"
            credentials.save_credential(ws.slug, alias, "user", "password")
            jar = credentials.cookie_jar_path(ws.slug, alias)

            def cookie_payload(value: str) -> str:
                return (
                    "# Netscape HTTP Cookie File\n"
                    "app.example.test\tFALSE\t/\tTRUE\t0\tapp_session\t"
                    + value + "\n"
                )

            jar.write_text(cookie_payload("initial-session-material"))
            credentials.save_tokens(
                ws.slug, alias, {"access_token": "initial-access-token"},
                origin=origin,
            )
            credentials.record_login_outcome(
                ws.slug, alias, established=True, origin=origin
            )

            denied_entered = threading.Event()
            allow_denied_return = threading.Event()
            success_entered = threading.Event()
            results: dict[str, dict] = {}
            errors: list[BaseException] = []

            def fake_http(_workspace, url, **_kwargs):
                if url.endswith("/denied"):
                    jar.write_text(cookie_payload("denied-session-material"))
                    credentials.save_tokens(
                        ws.slug, alias,
                        {"access_token": "denied-access-token"},
                        origin=origin,
                    )
                    denied_entered.set()
                    if not allow_denied_return.wait(5):
                        raise RuntimeError("timed out waiting to release denial")
                    return {
                        "ok": True,
                        "summary": "HTTP 401",
                        "data": {
                            "status_line": "HTTP/1.1 401 Unauthorized",
                            "auth_blocker": "endpoint denied the request",
                        },
                    }
                success_entered.set()
                jar.write_text(cookie_payload("rotated-session-material"))
                credentials.save_tokens(
                    ws.slug, alias,
                    {"access_token": "rotated-access-token"},
                    origin=origin,
                )
                return {
                    "ok": True,
                    "summary": "HTTP 200",
                    "data": {"status_line": "HTTP/1.1 200 OK"},
                }

            def request(label: str, path: str) -> None:
                try:
                    results[label] = tools.authenticated_http_request(
                        ws, origin + path, credential=alias
                    )
                except BaseException as exc:
                    errors.append(exc)

            with patch("grypton.tools.http_request", side_effect=fake_http):
                denied = threading.Thread(
                    target=request, args=("denied", "/denied"), daemon=True
                )
                denied.start()
                self.assertTrue(denied_entered.wait(5))
                success = threading.Thread(
                    target=request, args=("success", "/success"), daemon=True
                )
                success.start()
                self.assertFalse(success_entered.wait(0.2))
                allow_denied_return.set()
                denied.join(5)
                success.join(5)

            self.assertFalse(denied.is_alive())
            self.assertFalse(success.is_alive())
            self.assertEqual(errors, [])
            self.assertFalse(results["denied"]["ok"])
            self.assertTrue(results["success"]["ok"])
            self.assertIn("rotated-session-material", jar.read_text())
            self.assertEqual(
                credentials.load_tokens(ws.slug, alias),
                {"access_token": "rotated-access-token"},
            )
            self.assertTrue(
                credentials.session_status(ws.slug, alias)["established"]
            )

    def test_credential_replacement_waits_for_transaction_then_clears_material(self):
        with isolated_runtime():
            ws = Workspace("credential-replacement")
            origin = "https://app.example.test"
            ws.create(origin, "web")
            ws.save_constraints(Constraints(in_scope=[origin]))
            alias = "primary"
            credentials.save_credential(ws.slug, alias, "old-user", "old-password")
            jar = credentials.cookie_jar_path(ws.slug, alias)
            jar.write_text(
                "# Netscape HTTP Cookie File\n"
                "app.example.test\tFALSE\t/\tTRUE\t0\tapp_session\t"
                "old-session-material\n"
            )
            credentials.save_tokens(
                ws.slug, alias, {"access_token": "old-access-token"},
                origin=origin,
            )
            credentials.record_login_outcome(
                ws.slug, alias, established=True, origin=origin
            )

            request_entered = threading.Event()
            allow_request_return = threading.Event()
            replacement_done = threading.Event()
            results: dict[str, dict | str] = {}
            errors: list[BaseException] = []

            def denied_http(_workspace, _url, **kwargs):
                Path(kwargs["_cookie_jar"]).write_text("denied-cookie-material")
                credentials.save_tokens(
                    ws.slug, alias, {"access_token": "denied-access-token"},
                    origin=origin,
                )
                request_entered.set()
                if not allow_request_return.wait(5):
                    raise RuntimeError("timed out waiting to release request")
                return {
                    "ok": True,
                    "summary": "HTTP 401",
                    "data": {
                        "status_line": "HTTP/1.1 401 Unauthorized",
                        "response": '{"error":"denied"}',
                        "auth_blocker": "endpoint denied the request",
                    },
                }

            def request() -> None:
                try:
                    results["request"] = tools.authenticated_http_request(
                        ws, origin + "/denied", credential=alias
                    )
                except BaseException as exc:
                    errors.append(exc)

            def replace() -> None:
                try:
                    results["alias"] = credentials.save_credential(
                        ws.slug, alias, "new-user", "new-password"
                    )
                    replacement_done.set()
                except BaseException as exc:
                    errors.append(exc)

            with patch("grypton.tools.http_request", side_effect=denied_http):
                request_thread = threading.Thread(target=request, daemon=True)
                request_thread.start()
                self.assertTrue(request_entered.wait(5))
                replacement_thread = threading.Thread(target=replace, daemon=True)
                replacement_thread.start()
                self.assertFalse(replacement_done.wait(0.2))
                allow_request_return.set()
                request_thread.join(5)
                replacement_thread.join(5)

            self.assertFalse(request_thread.is_alive())
            self.assertFalse(replacement_thread.is_alive())
            self.assertEqual(errors, [])
            self.assertFalse(results["request"]["ok"])
            self.assertEqual(results["alias"], alias)
            self.assertEqual(
                credentials.load_credential(ws.slug, alias),
                {"username": "new-user", "password": "new-password"},
            )
            self.assertFalse(
                credentials.cookie_jar_storage_path(ws.slug, alias).exists()
            )
            self.assertFalse(credentials.token_path(ws.slug, alias).exists())
            self.assertFalse(credentials.attempt_path(ws.slug, alias).exists())
            status = credentials.session_status(ws.slug, alias)
            self.assertFalse(status["established"])
            self.assertFalse(status["has_cookies"])
            self.assertFalse(status["has_bearer_token"])

    def test_credential_replacement_cannot_resurrect_in_flight_attempt_state(self):
        with isolated_runtime():
            target = "attempt-replacement"
            alias = "primary"
            credentials.save_credential(target, alias, "old-user", "old-password")
            attempt_file = credentials.attempt_path(target, alias)
            atomic_write = credentials._atomic_private_json
            attempt_write_entered = threading.Event()
            allow_attempt_write = threading.Event()
            replacement_done = threading.Event()
            results: dict[str, int | str] = {}
            errors: list[BaseException] = []

            def gated_atomic(path, value):
                if path == attempt_file and threading.current_thread().name == "reserve":
                    attempt_write_entered.set()
                    if not allow_attempt_write.wait(5):
                        raise RuntimeError("timed out waiting to write attempt state")
                return atomic_write(path, value)

            def reserve() -> None:
                try:
                    results["attempt"] = credentials.begin_login_attempt(
                        target, alias
                    )
                except BaseException as exc:
                    errors.append(exc)

            def replace() -> None:
                try:
                    results["alias"] = credentials.save_credential(
                        target, alias, "new-user", "new-password"
                    )
                    replacement_done.set()
                except BaseException as exc:
                    errors.append(exc)

            with patch(
                "grypton.credentials._atomic_private_json",
                side_effect=gated_atomic,
            ):
                reserve_thread = threading.Thread(
                    target=reserve, name="reserve", daemon=True
                )
                reserve_thread.start()
                self.assertTrue(attempt_write_entered.wait(5))
                replacement_thread = threading.Thread(target=replace, daemon=True)
                replacement_thread.start()
                self.assertFalse(replacement_done.wait(0.2))
                allow_attempt_write.set()
                reserve_thread.join(5)
                replacement_thread.join(5)

            self.assertFalse(reserve_thread.is_alive())
            self.assertFalse(replacement_thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(results["attempt"], 1)
            self.assertEqual(results["alias"], alias)
            self.assertFalse(attempt_file.exists())
            self.assertEqual(credentials.load_attempt_state(target, alias)["attempts"], 0)
            self.assertEqual(
                credentials.load_credential(target, alias),
                {"username": "new-user", "password": "new-password"},
            )

    def test_non_success_http_responses_roll_back_poisoned_material(self):
        with isolated_runtime():
            ws = Workspace("credential-error-material")
            origin = "https://app.example.test"
            ws.create(origin, "web")
            ws.save_constraints(Constraints(in_scope=[origin]))
            alias = "primary"
            credentials.save_credential(ws.slug, alias, "user", "password")
            jar = credentials.cookie_jar_path(ws.slug, alias)
            original_cookie = (
                "# Netscape HTTP Cookie File\n"
                "app.example.test\tFALSE\t/\tTRUE\t0\tapp_session\t"
                "original-session-material\n"
            ).encode()
            jar.write_bytes(original_cookie)
            credentials.save_tokens(
                ws.slug, alias, {"access_token": "original-access-token"},
                origin=origin,
            )
            token_file = credentials.token_path(ws.slug, alias)
            original_tokens = token_file.read_bytes()
            credentials.record_login_outcome(
                ws.slug, alias, established=True, origin=origin
            )

            for status in (400, 500):
                with self.subTest(status=status):
                    def poisoned_http(_workspace, _url, **kwargs):
                        Path(kwargs["_cookie_jar"]).write_text(
                            "# Netscape HTTP Cookie File\n"
                            "app.example.test\tFALSE\t/\tTRUE\t0\tapp_session\t"
                            "poisoned-session-material\n"
                        )
                        credentials.save_tokens(
                            ws.slug, alias,
                            {"access_token": "poisoned-access-token"},
                            origin=origin,
                        )
                        return {
                            "ok": True,
                            "summary": f"HTTP {status}",
                            "data": {
                                "status_line": f"HTTP/1.1 {status} Error",
                                "response": "{}",
                                "auth_blocker": "",
                            },
                        }

                    with patch(
                        "grypton.tools.http_request", side_effect=poisoned_http
                    ):
                        result = tools.authenticated_http_request(
                            ws, origin + "/verification", credential=alias
                        )

                    self.assertTrue(result["ok"], result)
                    self.assertTrue(result["data"]["session_state_retained"])
                    self.assertTrue(result["data"]["session_material_rollback"])
                    self.assertTrue(result["data"]["session"]["established"])
                    self.assertEqual(jar.read_bytes(), original_cookie)
                    self.assertEqual(token_file.read_bytes(), original_tokens)

    def test_failed_request_restores_absent_cookie_jar_before_reporting_session(self):
        with isolated_runtime():
            ws = Workspace("bearer-only-rollback")
            origin = "https://app.example.test"
            ws.create(origin, "web")
            ws.save_constraints(Constraints(in_scope=[origin]))
            alias = "bearer-only"
            credentials.save_credential(ws.slug, alias, "user", "password")
            credentials.save_tokens(
                ws.slug, alias, {"access_token": "original-access-token"},
                origin=origin,
            )
            credentials.record_login_outcome(
                ws.slug, alias, established=True, origin=origin
            )
            jar = credentials.cookie_jar_storage_path(ws.slug, alias)
            self.assertFalse(jar.exists())

            def poisoned_http(_workspace, _url, **kwargs):
                Path(kwargs["_cookie_jar"]).write_text(
                    "# Netscape HTTP Cookie File\n"
                    "app.example.test\tFALSE\t/\tTRUE\t0\tapp_session\t"
                    "poisoned-session-material\n"
                )
                credentials.save_tokens(
                    ws.slug, alias, {"access_token": "poisoned-access-token"},
                    origin=origin,
                )
                return {
                    "ok": True,
                    "summary": "HTTP 400",
                    "data": {
                        "status_line": "HTTP/1.1 400 Bad Request",
                        "response": "{}",
                        "auth_blocker": "",
                    },
                }

            with patch("grypton.tools.http_request", side_effect=poisoned_http):
                result = tools.authenticated_http_request(
                    ws, origin + "/verification", credential=alias
                )

            self.assertTrue(result["ok"], result)
            self.assertFalse(jar.exists())
            self.assertFalse(result["data"]["session"]["has_cookies"])
            self.assertTrue(result["data"]["session"]["has_bearer_token"])
            self.assertEqual(
                credentials.load_tokens(ws.slug, alias),
                {"access_token": "original-access-token"},
            )

    def test_authenticated_request_exception_restores_material(self):
        with isolated_runtime():
            ws = Workspace("credential-exception-material")
            origin = "https://app.example.test"
            ws.create(origin, "web")
            ws.save_constraints(Constraints(in_scope=[origin]))
            alias = "primary"
            credentials.save_credential(ws.slug, alias, "user", "password")
            jar = credentials.cookie_jar_path(ws.slug, alias)
            jar.write_text(
                "# Netscape HTTP Cookie File\n"
                "app.example.test\tFALSE\t/\tTRUE\t0\tapp_session\t"
                "original-session-material\n"
            )
            credentials.save_tokens(
                ws.slug, alias, {"access_token": "original-access-token"},
                origin=origin,
            )
            cookie_snapshot = jar.read_bytes()
            token_file = credentials.token_path(ws.slug, alias)
            token_snapshot = token_file.read_bytes()
            credentials.record_login_outcome(
                ws.slug, alias, established=True, origin=origin
            )

            def exploding_http(_workspace, _url, **kwargs):
                Path(kwargs["_cookie_jar"]).write_text("poisoned")
                credentials.save_tokens(
                    ws.slug, alias, {"access_token": "poisoned-access-token"},
                    origin=origin,
                )
                raise RuntimeError("post-transport processing failed")

            with patch("grypton.tools.http_request", side_effect=exploding_http):
                result = tools.authenticated_http_request(
                    ws, origin + "/explode", credential=alias
                )

            self.assertFalse(result["ok"], result)
            self.assertIn("restored", result["summary"])
            self.assertEqual(jar.read_bytes(), cookie_snapshot)
            self.assertEqual(token_file.read_bytes(), token_snapshot)
            self.assertTrue(
                credentials.session_status(ws.slug, alias)["established"]
            )

    def test_http_challenge_detection_ignores_false_flags(self):
        for body in (
            '{"otp_required": false}',
            '{"mfa_required": false}',
            '{"captcha": false}',
            '{"captcha": null}',
            "Captcha is not required",
        ):
            with self.subTest(body=body):
                self.assertEqual(
                    tools._authentication_blocker(body, "HTTP/1.1 200 OK"), ""
                )

    def test_cookie_jar_symlink_is_rejected(self):
        with isolated_runtime() as root:
            credentials.save_credential("target", "primary", "u", "p")
            self.assertEqual(credentials.select_bearer({"access_token": "Bearer abc"}), "abc")
            sessions = config.CREDENTIALS_DIR / "target" / ".sessions"
            sessions.mkdir(parents=True, exist_ok=True)
            destination = root / "outside"
            destination.write_text("unchanged")
            (sessions / "primary.cookies").symlink_to(destination)
            with self.assertRaises(credentials.CredentialError):
                credentials.cookie_jar_path("target", "primary")
            self.assertEqual(destination.read_text(), "unchanged")


if __name__ == "__main__":
    unittest.main()
