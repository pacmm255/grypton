from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from urllib.parse import quote, quote_plus
from unittest.mock import patch

from grypton import config, credentials
from grypton.toolserver import REGISTRY, _handle, dispatch
from grypton.tools import _browser_auth_blocker
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


class _SpaAuthHandler(BaseHTTPRequestHandler):
    username = "+989123456789"
    password = "browser-password-never-log"
    session = "browser-session-never-log"
    token = "browser-token-never-log"
    mode = "success"
    login_posts = 0
    verify_header_values = []

    def _send(self, status: int, body: bytes, *, content_type: str,
              cookie: str = "") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if cookie:
            self.send_header(
                "Set-Cookie", f"app_session={cookie}; HttpOnly; SameSite=Lax; Path=/"
            )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, value: dict, *, cookie: str = "") -> None:
        self._send(
            status, json.dumps(value).encode(),
            content_type="application/json", cookie=cookie,
        )

    def do_GET(self):
        if self.path == "/login":
            if type(self).mode == "page-denied":
                self._json(401, {"error": "login page unavailable"})
                return
            challenge = (
                "<p id='challenge'>CAPTCHA challenge active</p>"
                if type(self).mode == "captcha" else ""
            )
            disabled_submit = type(self).mode in {
                "disabled-submit", "disabled-submit-never",
            }
            submit_attribute = " disabled" if disabled_submit else ""
            enable_script = """
            <script>
            const loginUsername = document.querySelector('[data-testid="login-username"]');
            const loginPassword = document.querySelector('[data-testid="login-password"]');
            const loginSubmit = document.querySelector('[data-testid="login-submit"]');
            const updateSubmit = () => {
              loginSubmit.disabled = !(loginUsername.value && loginPassword.value);
            };
            loginUsername.addEventListener('input', updateSubmit);
            loginPassword.addEventListener('input', updateSubmit);
            </script>
            """ if type(self).mode == "disabled-submit" else ""
            username_expression = (
                """(() => { const value = document.querySelector(
                '[data-testid="login-username"]').value;
                const compact = value.replace(/[\\s()\\-]/g, '');
                return compact.startsWith('09')
                  ? '+98' + compact.slice(1) : value; })()"""
                if type(self).mode == "client-normalizes" else
                "document.querySelector('[data-testid=\"login-username\"]')"
                ".value"
            )
            identity_console = (
                "console.log(JSON.stringify(value));"
                if type(self).mode == "client-normalizes" else ""
            )
            html = f"""<!doctype html><html><body>
            {challenge}
            <form id="login-form">
              <input data-testid="login-username" type="tel">
              <input data-testid="login-password" type="password">
              <button data-testid="login-submit" type="submit"{submit_attribute}>Sign in</button>
            </form><div id="result"></div>
            {enable_script}
            <script>
            document.getElementById('login-form').addEventListener('submit', async (event) => {{
              event.preventDefault();
              const response = await fetch('/api/login', {{
                method: 'POST', headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{
                  username: {username_expression},
                  password: document.querySelector('[data-testid="login-password"]').value
                }})
              }});
              const value = await response.json();
              document.getElementById('result').textContent = JSON.stringify(value);
              {identity_console}
              if (value.access_token) console.log(value.access_token);
              if (response.ok && !value.otp_required) window.location.assign('/dashboard');
            }});
            </script></body></html>""".encode()
            self._send(
                200, html, content_type="text/html; charset=utf-8",
                cookie=self.session if type(self).mode == "baseline-cookie" else "",
            )
            return
        if self.path == "/dashboard":
            cookie = self.headers.get("Cookie", "")
            if f"app_session={self.session}" in cookie:
                self._send(
                    200,
                    ("<html><body>signed in " + self.token + "</body></html>").encode(),
                    content_type="text/html; charset=utf-8",
                )
            else:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.send_header("Content-Length", "0")
                self.end_headers()
            return
        if self.path == "/me":
            if type(self).mode == "verify-header":
                header = self.headers.get("X-SPA-Client", "")
                type(self).verify_header_values.append(header)
                if header != "milli-web":
                    self._json(400, {"code": "bad_request"})
                    return
            authenticated = (
                f"app_session={self.session}" in self.headers.get("Cookie", "")
                or self.headers.get("Authorization") == f"Bearer {self.token}"
            )
            self._json(
                200 if authenticated else 401,
                {"authenticated": authenticated},
            )
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/api/login":
            self._json(404, {"error": "not found"})
            return
        type(self).login_posts += 1
        length = int(self.headers.get("Content-Length", "0"))
        try:
            value = json.loads(self.rfile.read(length).decode())
        except ValueError:
            value = {}
        if type(self).mode == "otp":
            self._json(202, {"otp_required": True})
            return
        if type(self).mode == "delayed":
            time.sleep(1.5)
        if type(self).mode == "baseline-cookie":
            self._json(200, {"login": "accepted"})
            return
        if (
            type(self).mode == "failed"
            or value.get("username") != self.username
            or value.get("password") != self.password
        ):
            self._json(401, {"error": "invalid credentials"})
            return
        response = {
            "authenticated": True,
            "otp_required": False,
            "captcha": None,
            "username": value.get("username"),
            "access_token": self.token,
        }
        if type(self).mode == "client-normalizes":
            response.update({
                "firstName": "Nika",
                "email": "private-person@example.test",
                "nationalCode": "0012345678",
                "data": {"user": {
                    "userUuid": "private-user-uuid-1234",
                    "invitationCode": "private-invitation-9876",
                    "inviteCode": "private-invite-4567",
                }},
            })
        self._json(200, response, cookie=self.session)

    def log_message(self, *_args):
        pass


@contextmanager
def spa_auth_server(mode: str):
    _SpaAuthHandler.mode = mode
    _SpaAuthHandler.login_posts = 0
    _SpaAuthHandler.verify_header_values = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SpaAuthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class BrowserCredentialTests(unittest.TestCase):
    def _workspace(self, port: int) -> Workspace:
        ws = Workspace("browser-credential-test")
        origin = f"http://127.0.0.1:{port}"
        ws.create(origin, "web")
        ws.save_constraints(Constraints(in_scope=[origin]))
        return ws

    def _request(self, port: int) -> dict:
        return {
            "url": f"http://127.0.0.1:{port}/login",
            "credential": "primary",
            "username_transform": "iran-e164",
            "verify_url": f"http://127.0.0.1:{port}/me",
            "success_marker": '"authenticated": true',
            "timeout": 15,
        }

    def test_spa_login_proves_and_persists_redacted_session(self):
        stored_username = "0912 345-6789"
        with isolated_runtime(), spa_auth_server("success") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", stored_username, _SpaAuthHandler.password
            )

            result = dispatch(ws, "credential_browser_login", self._request(port))

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["data"]["attempt"], 1)
            self.assertTrue(result["data"]["session"]["established"])
            self.assertEqual(
                result["data"]["session"]["origin"],
                f"http://127.0.0.1:{port}",
            )
            self.assertEqual(_SpaAuthHandler.login_posts, 1)
            self.assertTrue(any(
                row.get("status") == 200
                for row in result["data"]["login_api_responses"]
            ))

            followup = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/me",
                "credential": "primary",
            })
            self.assertTrue(followup["ok"], followup)

            observable = json.dumps([result, followup], ensure_ascii=False)
            observable += (ws.root / ".ledger/tool-calls.jsonl").read_text()
            observable += "".join(
                path.read_text(errors="replace")
                for path in ws.flows_dir.glob("*.http")
            )
            observable += "".join(
                path.read_text(errors="replace")
                for path in ws.scratch_dir.glob("browser-auth-*.html")
            )
            for value in (
                stored_username,
                _SpaAuthHandler.username,
                _SpaAuthHandler.password,
                _SpaAuthHandler.session,
                _SpaAuthHandler.token,
                quote(stored_username, safe=""),
                quote_plus(stored_username, safe=""),
                quote(_SpaAuthHandler.username, safe=""),
                quote_plus(_SpaAuthHandler.username, safe=""),
            ):
                self.assertNotIn(value, observable)

    def test_delayed_spa_response_is_captured_without_resubmission(self):
        with isolated_runtime(), spa_auth_server("delayed") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            request = self._request(port)
            request["timeout"] = 5

            result = dispatch(ws, "credential_browser_login", request)

            self.assertTrue(result["ok"], result)
            self.assertEqual(_SpaAuthHandler.login_posts, 1)
            self.assertTrue(any(
                row.get("status") == 200
                for row in result["data"]["login_api_responses"]
            ))

    def test_stored_phone_normalized_by_spa_and_identity_echoes_are_redacted(self):
        stored_username = "09123456789"
        pii_values = (
            stored_username, _SpaAuthHandler.username, "Nika",
            "private-person@example.test", "0012345678",
            "private-user-uuid-1234", "private-invitation-9876",
            "private-invite-4567",
        )
        with isolated_runtime(), spa_auth_server("client-normalizes") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", stored_username, _SpaAuthHandler.password
            )
            request = self._request(port)
            request["username_transform"] = "stored"

            result = dispatch(ws, "credential_browser_login", request)

            self.assertTrue(result["ok"], result)
            response_text = json.dumps(
                result["data"]["login_api_responses"], ensure_ascii=False
            )
            self.assertIn("[REDACTED]", response_text)
            observable = json.dumps(result, ensure_ascii=False)
            observable += (ws.root / ".ledger/tool-calls.jsonl").read_text()
            observable += "".join(
                path.read_text(errors="replace")
                for path in ws.flows_dir.glob("*.http")
            )
            observable += "".join(
                path.read_text(errors="replace")
                for path in ws.scratch_dir.glob("browser-auth-*.html")
            )
            for value in pii_values:
                self.assertNotIn(value, observable)
                self.assertNotIn(quote(value, safe=""), observable)
                self.assertNotIn(quote_plus(value, safe=""), observable)

    def test_verify_protocol_header_is_shared_by_live_replay_and_control(self):
        with isolated_runtime(), spa_auth_server("verify-header") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            request = self._request(port)
            request["verify_headers"] = {"X-SPA-Client": "milli-web"}

            result = dispatch(ws, "credential_browser_login", request)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["data"]["verify_status"], 200)
            self.assertEqual(result["data"]["replay_status"], 200)
            self.assertEqual(result["data"]["control_status"], 401)
            self.assertEqual(
                _SpaAuthHandler.verify_header_values,
                ["milli-web", "milli-web", "milli-web"],
            )

    def test_sensitive_verify_header_is_rejected_before_attempt(self):
        with isolated_runtime(), spa_auth_server("success") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            request = self._request(port)
            request["verify_headers"] = {"Authorization": "secret"}

            result = dispatch(ws, "credential_browser_login", request)

            self.assertFalse(result["ok"], result)
            self.assertIn("cannot contain", result["summary"])
            self.assertEqual(_SpaAuthHandler.login_posts, 0)
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 0
            )

    def test_duplicate_verify_header_is_rejected_before_attempt(self):
        with isolated_runtime(), spa_auth_server("success") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            request = self._request(port)
            request["verify_headers"] = {
                "X-SPA-Client": "one", "x-spa-client": "two",
            }

            result = dispatch(ws, "credential_browser_login", request)

            self.assertFalse(result["ok"], result)
            self.assertIn("case-insensitive duplicate", result["summary"])
            self.assertEqual(_SpaAuthHandler.login_posts, 0)
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 0
            )

    def test_initially_disabled_submit_enables_after_playwright_fill(self):
        with isolated_runtime(), spa_auth_server("disabled-submit") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )

            result = dispatch(ws, "credential_browser_login", self._request(port))

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["data"]["attempt"], 1)
            self.assertEqual(_SpaAuthHandler.login_posts, 1)

    def test_submit_that_never_enables_does_not_reserve_attempt(self):
        with isolated_runtime(), spa_auth_server("disabled-submit-never") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            request = self._request(port)
            request["timeout"] = 5

            result = dispatch(ws, "credential_browser_login", request)

            self.assertFalse(result["ok"], result)
            self.assertIn("remained disabled", result["summary"])
            self.assertEqual(result["data"]["attempt"], 0)
            self.assertEqual(_SpaAuthHandler.login_posts, 0)
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 0
            )

    def test_prelogin_cookie_cannot_prove_credential_session(self):
        with isolated_runtime(), spa_auth_server("baseline-cookie") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )

            result = dispatch(ws, "credential_browser_login", self._request(port))

            self.assertFalse(result["ok"], result)
            self.assertIn("no new reusable", result["summary"])
            self.assertFalse(
                credentials.session_status(ws.slug, "primary")["established"]
            )
            self.assertEqual(_SpaAuthHandler.login_posts, 1)

    def test_otp_and_captcha_are_factual_blockers(self):
        for mode, expected, attempts in (
            ("otp", "MFA/OTP", 1),
            ("captcha", "CAPTCHA", 0),
        ):
            with self.subTest(mode=mode), isolated_runtime(), spa_auth_server(mode) as port:
                ws = self._workspace(port)
                credentials.save_credential(
                    ws.slug, "primary", "09123456789", _SpaAuthHandler.password
                )
                result = dispatch(
                    ws, "credential_browser_login", self._request(port)
                )
                self.assertFalse(result["ok"], result)
                self.assertIn(expected, result["data"]["auth_blocker"])
                self.assertEqual(
                    credentials.session_status(ws.slug, "primary")["attempts"],
                    attempts,
                )
                self.assertEqual(_SpaAuthHandler.login_posts, attempts)

    def test_false_challenge_fields_and_negative_text_are_not_blockers(self):
        for observation in (
            '{"otp_required": false}',
            '{"mfa_required": false}',
            '{"captcha": false}',
            '{"captcha": null}',
            "Captcha is not required",
        ):
            with self.subTest(observation=observation):
                self.assertEqual(_browser_auth_blocker(observation, (200,)), "")
        self.assertIn("MFA/OTP", _browser_auth_blocker('{"otp": true}', (200,)))
        self.assertIn("CAPTCHA", _browser_auth_blocker('{"captcha": true}', (200,)))

    def test_failed_login_is_single_attempt_and_is_not_retried(self):
        with isolated_runtime(), spa_auth_server("failed") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            request = self._request(port)
            first = dispatch(ws, "credential_browser_login", request)
            second = dispatch(ws, "credential_browser_login", request)

            self.assertFalse(first["ok"], first)
            self.assertIn("rejected", first["data"]["auth_blocker"])
            self.assertFalse(second["ok"], second)
            self.assertEqual(_SpaAuthHandler.login_posts, 1)
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 1
            )

    def test_initial_unauthorized_page_is_not_a_credential_rejection(self):
        with isolated_runtime(), spa_auth_server("page-denied") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            result = dispatch(ws, "credential_browser_login", self._request(port))

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["data"]["attempt"], 0)
            self.assertIn("before credential submission", result["data"]["auth_blocker"])
            self.assertNotIn("credential was rejected", result["data"]["auth_blocker"])
            self.assertEqual(_SpaAuthHandler.login_posts, 0)

    def test_scope_and_transform_fail_before_attempt_reservation(self):
        with isolated_runtime(), spa_auth_server("success") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "user@example.test", _SpaAuthHandler.password
            )
            request = self._request(port)
            request["verify_url"] = "http://example.invalid/me"
            blocked = dispatch(ws, "credential_browser_login", request)
            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(_SpaAuthHandler.login_posts, 0)
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 0
            )

            request["verify_url"] = f"http://127.0.0.1:{port}/me"
            invalid_transform = dispatch(
                ws, "credential_browser_login", request
            )
            self.assertFalse(invalid_transform["ok"], invalid_transform)
            self.assertEqual(_SpaAuthHandler.login_posts, 0)
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 0
            )

    def test_mcp_schema_exposes_private_browser_login_defaults(self):
        description, schema, _ = REGISTRY["credential_browser_login"]
        self.assertIn("private credential", description)
        self.assertEqual(
            schema["required"],
            ["credential"],
        )
        self.assertEqual(
            schema["properties"]["username_transform"]["enum"],
            ["stored", "iran-e164"],
        )
        self.assertEqual(
            schema["properties"]["verify_headers"]["additionalProperties"],
            {"type": "string"},
        )
        with isolated_runtime():
            ws = Workspace("browser-schema")
            ws.create("https://example.test", "web")
            response = _handle(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, ws
            )
        names = {item["name"] for item in response["result"]["tools"]}
        self.assertIn("credential_browser_login", names)


if __name__ == "__main__":
    unittest.main()
