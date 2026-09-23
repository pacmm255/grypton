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

from grypton import config, credentials
from grypton.toolserver import dispatch
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
        self._send(200, {"data": {"access_token": self.token}}, cookie=self.cookie)

    def do_GET(self):
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
            self._send(401, {"error": "session expired"})
        elif self.path == "/followup-403" and authenticated:
            self._send(403, {"error": "session revoked"})
        elif self.path == "/followup-mfa" and authenticated:
            self._send(200, {"mfa_required": True})
        elif self.path == "/followup-limit" and authenticated:
            self._send(429, {"error": "rate limited"})
        elif self.path in {"/me", "/second"} and authenticated:
            self._send(200, {"authenticated": True, "access_token": self.token})
        else:
            self._send(401, {"authenticated": False})

    def log_message(self, *args):
        pass


@contextmanager
def auth_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AuthHandler)
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
                    self.assertEqual(len(created), 1)
                    capture = created.pop().read_text(encoding="utf-8")
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

    def test_authenticated_followup_blockers_invalidate_the_session(self):
        cases = (
            ("401", "rejected or blocked"),
            ("403", "rejected or blocked"),
            ("mfa", "MFA/OTP"),
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
                    result = dispatch(ws, "authenticated_http_request", {
                        "url": f"http://127.0.0.1:{port}/followup-{suffix}",
                        "credential": alias,
                    })
                    self.assertFalse(result["ok"], result)
                    status = credentials.session_status(ws.slug, alias)
                    self.assertFalse(status["established"])
                    self.assertEqual(status["state"], "blocked")
                    self.assertIn(expected, status["blocked_reason"])

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
