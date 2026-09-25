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

from grypton import config, credentials, tools
from grypton.toolserver import REGISTRY, _handle, dispatch
from grypton.tools import (
    _browser_auth_blocker, _browser_auth_persisted_cookies,
    _browser_auth_redirect_contract_matches,
)
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
    verify_requests = 0
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
        if self.path == "/block-dom.js":
            time.sleep(10)
            self._send(
                200, b"/* delayed */",
                content_type="application/javascript",
            )
            return
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
            blocking_script = (
                "<script src='/block-dom.js'></script>"
                if type(self).mode == "login-domcontentloaded-hang" else ""
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
              if (response.ok && !value.otp_required) window.location.assign(
                '{"/dashboard?unexpected=1" if type(self).mode == "status-wrong-terminal" else "/dashboard"}'
              );
            }});
            </script>{blocking_script}</body></html>""".encode()
            self._send(
                200, html, content_type="text/html; charset=utf-8",
                cookie=self.session if type(self).mode == "baseline-cookie" else "",
            )
            return
        if self.path.startswith("/dashboard"):
            cookie = self.headers.get("Cookie", "")
            if (
                f"app_session={self.session}" in cookie
                or type(self).mode == "verify-material-only"
            ):
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
            type(self).verify_requests += 1
            request_number = type(self).verify_requests
            if type(self).mode == "status-verify-redirect":
                self.send_response(302)
                self.send_header("Location", "/me-final")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
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
            if (
                not authenticated
                and request_number == 3
                and type(self).mode in {
                    "status-anon-redirect", "status-anon-redirect-status",
                    "status-anon-redirect-url",
                }
            ):
                self.send_response(
                    302 if type(self).mode == "status-anon-redirect-status" else 307
                )
                self.send_header(
                    "Location",
                    "/me-hop" if type(self).mode == "status-anon-redirect-url" else "/me",
                )
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if type(self).mode == "verify-material-only" and request_number == 1:
                self._json(200, {"authenticated": True}, cookie=self.session)
                return
            status = 200 if authenticated else 401
            if type(self).mode == "status-live-mismatch" and request_number == 1:
                status = 404
            elif type(self).mode == "status-replay-mismatch" and request_number == 2:
                status = 404
            elif type(self).mode == "status-control-mismatch" and not authenticated:
                status = 403
            elif type(self).mode == "status-control-404" and not authenticated:
                status = 404
            elif type(self).mode == "status-control-200" and not authenticated:
                status = 200
            self._json(
                status,
                {"authenticated": authenticated},
            )
            return
        if self.path == "/me-hop" and type(self).mode == "status-anon-redirect-url":
            self.send_response(307)
            self.send_header("Location", "/me")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/me-final":
            authenticated = (
                f"app_session={self.session}" in self.headers.get("Cookie", "")
                or self.headers.get("Authorization") == f"Bearer {self.token}"
            )
            self._json(200 if authenticated else 401, {"authenticated": authenticated})
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
        }
        if type(self).mode != "verify-material-only":
            response["access_token"] = self.token
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
        self._json(
            201 if type(self).mode == "status-login-201" else 200,
            response,
            cookie="" if type(self).mode == "verify-material-only" else self.session,
        )

    def log_message(self, *_args):
        pass


@contextmanager
def spa_auth_server(mode: str):
    _SpaAuthHandler.mode = mode
    _SpaAuthHandler.login_posts = 0
    _SpaAuthHandler.verify_requests = 0
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


class _RenewAuthHandler(BaseHTTPRequestHandler):
    username = "+989123456789"
    password = "renew-password-never-log"
    session = "renew-session-never-log"
    edge = "renew-edge-never-log"
    login_posts = 0
    verify_requests = 0
    resource_requests = 0
    reject_login = False
    inconclusive_control = False
    rotate_on_next_verify = ""
    block_login_page = False
    auto_submit_on_input = False
    delay_login_response = False
    delete_cookie_on_next_verify = False
    fail_renewal_verify = False
    verify_header_values: list[str] = []

    def _send(self, status: int, body: bytes, *, content_type: str,
              cookies: tuple[str, ...] = ()) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for cookie in cookies:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, value: dict,
              *, cookies: tuple[str, ...] = ()) -> None:
        self._send(
            status, json.dumps(value).encode(),
            content_type="application/json", cookies=cookies,
        )

    def _authenticated(self) -> bool:
        return (
            f"app_session={type(self).session}"
            in self.headers.get("Cookie", "")
        )

    def do_GET(self):
        if self.path == "/login":
            if type(self).block_login_page:
                self._json(429, {"error": "rate limited"})
                return
            auto_submit = (
                "document.querySelector('[data-testid=\"login-password\"]')"
                ".addEventListener('input', () => "
                "document.getElementById('login-form').requestSubmit(), {once:true});"
                if type(self).auto_submit_on_input else ""
            )
            html = """<!doctype html><html><body>
            <form id='login-form'>
              <input data-testid='login-username'>
              <input data-testid='login-password' type='password'>
              <button data-testid='login-submit' type='submit'>Sign in</button>
            </form><script>
            document.getElementById('login-form').addEventListener('submit', async (event) => {
              event.preventDefault();
              const response = await fetch('/api/login', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                  username: document.querySelector('[data-testid="login-username"]').value,
                  password: document.querySelector('[data-testid="login-password"]').value
                })
              });
              if (response.ok) window.location.assign('/home');
            });
            __AUTO_SUBMIT__
            </script></body></html>""".replace(
                "__AUTO_SUBMIT__", auto_submit
            ).encode()
            self._send(200, html, content_type="text/html; charset=utf-8")
            return
        if self.path == "/home":
            if self._authenticated():
                self._send(
                    200, b"<html><body>home</body></html>",
                    content_type="text/html; charset=utf-8",
                )
            else:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.send_header("Content-Length", "0")
                self.end_headers()
            return
        if self.path == "/verify":
            type(self).verify_requests += 1
            type(self).verify_header_values.append(
                self.headers.get("X-SPA-Client", "")
            )
            if self.headers.get("X-SPA-Client") != "milli-web":
                self._json(418, {"error": "missing protocol header"})
                return
            if self._authenticated():
                if (
                    type(self).fail_renewal_verify
                    and type(self).login_posts >= 2
                ):
                    self._json(404, {"authenticated": False})
                    return
                cookies: tuple[str, ...] = ()
                if type(self).delete_cookie_on_next_verify:
                    type(self).delete_cookie_on_next_verify = False
                    cookies = ("app_session=; Max-Age=0; HttpOnly; Path=/",)
                elif type(self).rotate_on_next_verify:
                    type(self).session = type(self).rotate_on_next_verify
                    type(self).rotate_on_next_verify = ""
                    cookies = (
                        f"app_session={type(self).session}; HttpOnly; Path=/",
                    )
                self._json(400, {"authenticated": True}, cookies=cookies)
                return
            if f"edge_clearance={type(self).edge}" not in self.headers.get(
                "Cookie", ""
            ):
                self.send_response(307)
                self.send_header("Location", "/verify")
                self.send_header(
                    "Set-Cookie",
                    f"edge_clearance={type(self).edge}; HttpOnly; Path=/",
                )
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            status = 403 if type(self).inconclusive_control else 401
            self._json(status, {"authenticated": False})
            return
        if self.path == "/resource":
            type(self).resource_requests += 1
            self._json(
                200 if self._authenticated() else 401,
                {"resource": self._authenticated()},
            )
            return
        if self.path == "/arbitrary-400":
            self._json(
                400, {"error": "route-specific"},
                cookies=("app_session=poison-cookie-never-keep; HttpOnly; Path=/",),
            )
            return
        if self.path == "/arbitrary-401":
            self._json(401, {"error": "route denied"})
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
        if type(self).delay_login_response:
            # Keep an input-triggered request in flight beyond the point where
            # the browser flow decides whether it needs to click submit.
            time.sleep(1)
        if (
            type(self).reject_login
            or value.get("username") != self.username
            or value.get("password") != self.password
        ):
            self._json(401, {"error": "invalid credentials"})
            return
        self._json(
            200, {"authenticated": True},
            cookies=(
                f"app_session={type(self).session}; HttpOnly; Path=/",
            ),
        )

    def log_message(self, *_args):
        pass


@contextmanager
def renew_auth_server():
    _RenewAuthHandler.session = "renew-session-never-log"
    _RenewAuthHandler.login_posts = 0
    _RenewAuthHandler.verify_requests = 0
    _RenewAuthHandler.resource_requests = 0
    _RenewAuthHandler.reject_login = False
    _RenewAuthHandler.inconclusive_control = False
    _RenewAuthHandler.rotate_on_next_verify = ""
    _RenewAuthHandler.block_login_page = False
    _RenewAuthHandler.auto_submit_on_input = False
    _RenewAuthHandler.delay_login_response = False
    _RenewAuthHandler.delete_cookie_on_next_verify = False
    _RenewAuthHandler.fail_renewal_verify = False
    _RenewAuthHandler.verify_header_values = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RenewAuthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class _BootstrapProofHandler(BaseHTTPRequestHandler):
    def _send(self, status, body=b"", *, cookie="", location=""):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/login":
            self._send(
                200, b"{}", cookie="edge_ready=1; HttpOnly; Path=/"
            )
            return
        if self.path == "/verify":
            cookies = self.headers.get("Cookie", "")
            if "edge_ready=1" not in cookies:
                # Model an edge that leaves direct API navigation with no HTTP
                # response until the same-origin browser entrypoint is visited.
                self.close_connection = True
                return
            if "redirect_ready=1" not in cookies:
                self._send(
                    307, cookie="redirect_ready=1; HttpOnly; Path=/",
                    location="/verify",
                )
                return
            self._send(401, b'{"authenticated":false}')
            return
        self._send(404)

    def log_message(self, *_args):
        pass


@contextmanager
def bootstrap_proof_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BootstrapProofHandler)
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

    def _status_profile(
        self, port: int, *, timeout: int = 15,
        anonymous_redirect_statuses: list[int] | None = None,
    ) -> dict:
        origin = f"http://127.0.0.1:{port}"
        profile = {
            "version": 1,
            "strategy": "browser",
            "login_url": origin + "/login",
            "verify_url": origin + "/me",
            "username_transform": "iran-e164",
            "timeout": timeout,
            "browser": {
                "username_selector": "[data-testid='login-username']",
                "password_selector": "[data-testid='login-password']",
                "submit_selector": "[data-testid='login-submit']",
                "verify_headers": {},
                "verification": {
                    "mode": "status-differential",
                    "login_status": 200,
                    "authenticated_status": 200,
                    "anonymous_status": 401,
                    "expected_post_login_url": origin + "/dashboard",
                },
            },
        }
        if anonymous_redirect_statuses is not None:
            profile["browser"]["verification"][
                "anonymous_redirect_statuses"
            ] = anonymous_redirect_statuses
        return profile

    def _renew_profile(self, port: int) -> dict:
        origin = f"http://127.0.0.1:{port}"
        return {
            "version": 1,
            "strategy": "browser",
            "login_url": origin + "/login",
            "verify_url": origin + "/verify",
            "username_transform": "iran-e164",
            "timeout": 8,
            "browser": {
                "username_selector": "[data-testid='login-username']",
                "password_selector": "[data-testid='login-password']",
                "submit_selector": "[data-testid='login-submit']",
                "verify_headers": {"X-SPA-Client": "milli-web"},
                "verification": {
                    "mode": "status-differential",
                    "login_status": 200,
                    "authenticated_status": 400,
                    "anonymous_status": 401,
                    "expected_post_login_url": origin + "/home",
                    "anonymous_redirect_statuses": [307],
                },
            },
        }

    def _establish_renewable_session(self, ws: Workspace, port: int) -> dict:
        credentials.save_credential(
            ws.slug, "primary", "09123456789", _RenewAuthHandler.password
        )
        credentials.save_auth_profile(
            ws.slug, "primary", self._renew_profile(port)
        )
        result = dispatch(ws, "credential_login", {"credential": "primary"})
        self.assertTrue(result["ok"], result)
        return result

    def _expire_private_cookie(self, ws: Workspace) -> None:
        jar = credentials.cookie_jar_storage_path(ws.slug, "primary")
        rows = credentials._cookie_rows(jar)
        rendered = ["# Netscape HTTP Cookie File"]
        for row in rows:
            columns = list(row)
            if columns[5] == "app_session":
                columns[4] = str(int(time.time()) - 60)
            rendered.append("\t".join(columns))
        jar.write_text("\n".join(rendered) + "\n", encoding="utf-8")

    def test_recent_profile_session_reuses_proof_without_probe_or_submission(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            posts = _RenewAuthHandler.login_posts
            verifies = _RenewAuthHandler.verify_requests

            result = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })

            self.assertTrue(result["ok"], result)
            self.assertEqual(_RenewAuthHandler.login_posts, posts)
            self.assertEqual(_RenewAuthHandler.verify_requests, verifies)
            self.assertEqual(_RenewAuthHandler.resource_requests, 1)
            self.assertEqual(
                result["data"]["session_maintenance"]["action"], "reused"
            )

    def test_expired_session_renews_once_and_discards_stale_bearer(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            proven = credentials.load_attempt_state(ws.slug, "primary")
            credentials._atomic_private_json(
                credentials.attempt_path(ws.slug, "primary"),
                {
                    "version": 1,
                    "attempts": 2,
                    "established": True,
                    "blocked_reason": "",
                    "origin": proven["origin"],
                },
            )
            initial = credentials.load_attempt_state(ws.slug, "primary")
            self._expire_private_cookie(ws)
            credentials.save_tokens(
                ws.slug, "primary", {"access_token": "stale-bearer-never-send"},
                origin=f"http://127.0.0.1:{port}",
            )
            posts = _RenewAuthHandler.login_posts

            result = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })

            self.assertTrue(result["ok"], result)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertEqual(_RenewAuthHandler.resource_requests, 1)
            state = credentials.load_attempt_state(ws.slug, "primary")
            self.assertEqual(state["attempts"], initial["attempts"])
            self.assertEqual(
                state["proof_generation"], initial["proof_generation"] + 1
            )
            self.assertTrue(state["established"])
            self.assertFalse(credentials.token_path(
                ws.slug, "primary"
            ).exists())
            self.assertEqual(
                result["data"]["session_maintenance"]["action"], "renewed"
            )

            self._expire_private_cookie(ws)
            second = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })
            self.assertTrue(second["ok"], second)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 2)
            second_state = credentials.load_attempt_state(ws.slug, "primary")
            self.assertEqual(
                second_state["proof_generation"],
                initial["proof_generation"] + 2,
            )
            self.assertEqual(second_state["attempts"], 2)

    def test_stale_probe_allows_retained_edge_cookie_zero_hop(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            jar = credentials.cookie_jar_storage_path(ws.slug, "primary")
            with jar.open("a", encoding="utf-8") as stream:
                stream.write("\t".join((
                    "127.0.0.1", "FALSE", "/", "FALSE",
                    str(int(time.time()) + 3600),
                    "edge_clearance", _RenewAuthHandler.edge,
                )) + "\n")
            posts = _RenewAuthHandler.login_posts

            result = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })

            self.assertTrue(result["ok"], result)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertEqual(_RenewAuthHandler.resource_requests, 1)
            self.assertEqual(
                result["data"]["session_maintenance"]["action"], "renewed"
            )

    def test_failed_renewal_cannot_repeat_via_restart_or_profile_change(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            jar = credentials.cookie_jar_storage_path(ws.slug, "primary")
            credentials.save_tokens(
                ws.slug, "primary", {"access_token": "old-bearer-never-keep"},
                origin=f"http://127.0.0.1:{port}",
            )
            token_file = credentials.token_path(ws.slug, "primary")
            cookie_before, token_before = jar.read_bytes(), token_file.read_bytes()
            posts = _RenewAuthHandler.login_posts
            _RenewAuthHandler.reject_login = True

            first = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })
            self.assertFalse(first["ok"], first)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertEqual(_RenewAuthHandler.resource_requests, 0)
            self.assertEqual(jar.read_bytes(), cookie_before)
            self.assertEqual(token_file.read_bytes(), token_before)

            restarted = Workspace(ws.slug)
            second = dispatch(restarted, "credential_login", {
                "credential": "primary"
            })
            self.assertFalse(second["ok"], second)
            profile = self._renew_profile(port)
            profile["timeout"] = 9
            credentials.save_auth_profile(ws.slug, "primary", profile)
            third = dispatch(ws, "credential_browser_login", {
                "credential": "primary"
            })
            self.assertFalse(third["ok"], third)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            state = credentials.load_attempt_state(ws.slug, "primary")
            self.assertEqual(state["attempts"], 1)
            self.assertEqual(
                state["refresh_attempted_generation"],
                state["proof_generation"],
            )
            self.assertEqual(state["blocked_reason"], "")

    def test_inconclusive_maintenance_preserves_and_uses_proven_session(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            state = credentials.load_attempt_state(ws.slug, "primary")
            state["verified_at"] = 0
            credentials._atomic_private_json(
                credentials.attempt_path(ws.slug, "primary"),
                {"version": 2, **state},
            )
            posts = _RenewAuthHandler.login_posts
            _RenewAuthHandler.inconclusive_control = True

            result = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })

            self.assertTrue(result["ok"], result)
            self.assertEqual(_RenewAuthHandler.login_posts, posts)
            self.assertEqual(_RenewAuthHandler.resource_requests, 1)
            self.assertTrue(credentials.load_attempt_state(
                ws.slug, "primary"
            )["established"])
            self.assertEqual(
                result["data"]["session_maintenance"]["action"],
                "inconclusive",
            )

    def test_expected_verifier_400_commits_rotation_but_arbitrary_400_rolls_back(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            jar = credentials.cookie_jar_storage_path(ws.slug, "primary")
            _RenewAuthHandler.rotate_on_next_verify = "rotated-session-never-log"

            verifier = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/verify",
                "credential": "primary",
            })
            self.assertTrue(verifier["ok"], verifier)
            rotated = jar.read_bytes()
            self.assertIn(b"rotated-session-never-log", rotated)
            self.assertTrue(all(
                value == "milli-web"
                for value in _RenewAuthHandler.verify_header_values
            ))

            arbitrary = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/arbitrary-400",
                "credential": "primary",
            })
            self.assertTrue(arbitrary["ok"], arbitrary)
            self.assertEqual(jar.read_bytes(), rotated)
            self.assertTrue(arbitrary["data"]["session_material_rollback"])

    def test_concurrent_expired_requests_share_one_renewal(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            posts = _RenewAuthHandler.login_posts
            results: list[dict] = []
            errors: list[BaseException] = []

            def request() -> None:
                try:
                    results.append(dispatch(ws, "authenticated_http_request", {
                        "url": f"http://127.0.0.1:{port}/resource",
                        "credential": "primary",
                    }))
                except BaseException as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=request) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(30)

            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
            self.assertEqual(len(results), 2)
            self.assertTrue(all(result["ok"] for result in results), results)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertEqual(_RenewAuthHandler.resource_requests, 2)

    def test_arbitrary_401_never_starts_renewal(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            posts = _RenewAuthHandler.login_posts

            result = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/arbitrary-401",
                "credential": "primary",
            })

            self.assertFalse(result["ok"], result)
            self.assertEqual(_RenewAuthHandler.login_posts, posts)
            self.assertTrue(credentials.load_attempt_state(
                ws.slug, "primary"
            )["established"])
            self.assertEqual(
                result["data"]["auth_observation"]["kind"],
                "endpoint-unauthenticated",
            )

    def test_capture_failure_keeps_completed_renewal_generation_closed(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            before = credentials.load_attempt_state(ws.slug, "primary")
            posts = _RenewAuthHandler.login_posts

            with patch(
                "grypton.tools._browser_auth_save_capture",
                side_effect=OSError("synthetic capture failure"),
            ):
                result = dispatch(ws, "authenticated_http_request", {
                    "url": f"http://127.0.0.1:{port}/resource",
                    "credential": "primary",
                })

            self.assertTrue(result["ok"], result)
            self.assertEqual(
                result["data"]["session_maintenance"]["action"],
                "renewed-capture-incomplete",
            )
            after = credentials.load_attempt_state(ws.slug, "primary")
            self.assertTrue(after["established"])
            self.assertEqual(
                after["proof_generation"], before["proof_generation"] + 1
            )
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)

            again = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })
            self.assertTrue(again["ok"], again)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)

    def test_refresh_reservation_precedes_input_autosubmit(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            _RenewAuthHandler.auto_submit_on_input = True
            _RenewAuthHandler.delay_login_response = True
            posts = _RenewAuthHandler.login_posts

            result = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })

            self.assertTrue(result["ok"], result)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertEqual(
                result["data"]["session_maintenance"]["action"], "renewed"
            )
            self.assertEqual(
                result["data"]["session_maintenance"][
                    "credential_submission_requests"
                ],
                1,
            )

    def test_refresh_prelogin_blocker_never_fills_or_submits(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            _RenewAuthHandler.block_login_page = True
            posts = _RenewAuthHandler.login_posts

            result = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })

            self.assertFalse(result["ok"], result)
            self.assertEqual(_RenewAuthHandler.login_posts, posts)
            state = credentials.load_attempt_state(ws.slug, "primary")
            self.assertFalse(state["established"])
            self.assertEqual(state["refresh_attempted_generation"], 0)

    def test_full_renewal_proof_failure_restores_material_and_closes_slot(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            credentials.save_tokens(
                ws.slug, "primary", {"access_token": "old-proof-bearer"},
                origin=f"http://127.0.0.1:{port}",
            )
            jar = credentials.cookie_jar_storage_path(ws.slug, "primary")
            token_file = credentials.token_path(ws.slug, "primary")
            old_cookie, old_token = jar.read_bytes(), token_file.read_bytes()
            before = credentials.load_attempt_state(ws.slug, "primary")
            posts = _RenewAuthHandler.login_posts
            _RenewAuthHandler.fail_renewal_verify = True

            first = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })
            self.assertFalse(first["ok"], first)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertEqual(_RenewAuthHandler.resource_requests, 0)
            self.assertEqual(jar.read_bytes(), old_cookie)
            self.assertEqual(token_file.read_bytes(), old_token)
            failed = credentials.load_attempt_state(ws.slug, "primary")
            self.assertEqual(failed["attempts"], before["attempts"])
            self.assertEqual(
                failed["refresh_attempted_generation"],
                failed["proof_generation"],
            )

            second = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })
            self.assertFalse(second["ok"], second)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertEqual(_RenewAuthHandler.resource_requests, 0)

    def test_revalidation_cookie_deletion_does_not_create_empty_fresh_lease(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            state = credentials.load_attempt_state(ws.slug, "primary")
            state["verified_at"] = 0
            credentials._atomic_private_json(
                credentials.attempt_path(ws.slug, "primary"),
                {"version": 2, **state},
            )
            jar = credentials.cookie_jar_storage_path(ws.slug, "primary")
            before = jar.read_bytes()
            _RenewAuthHandler.delete_cookie_on_next_verify = True

            result = tools.ensure_browser_status_session(ws, "primary")

            self.assertFalse(result["ok"], result)
            self.assertIn("no reusable", result["summary"])
            self.assertEqual(jar.read_bytes(), before)
            after = credentials.load_attempt_state(ws.slug, "primary")
            self.assertTrue(after["established"])
            self.assertEqual(after["verified_at"], 0)

    def test_netscape_host_only_cookie_is_not_widened_to_subdomain(self):
        with isolated_runtime():
            ws = Workspace("cookie-domain-flags")
            ws.create("https://app.example.test", "web")
            rows = [
                ("example.test", "FALSE", "/", "TRUE", "0", "host_only", "host-only-value"),
                ("example.test", "TRUE", "/", "TRUE", "0", "domain_cookie", "domain-cookie-value"),
                ("app.example.test", "FALSE", "/", "TRUE", "0", "exact_cookie", "exact-cookie-value"),
            ]
            records = [
                {"columns": row, "http_only": False} for row in rows
            ]
            with patch("grypton.credentials._cookie_records", return_value=records):
                loaded = _browser_auth_persisted_cookies(
                    ws, "primary", "https://app.example.test/login"
                )
            self.assertEqual(
                {cookie["name"] for cookie in loaded},
                {"domain_cookie", "exact_cookie"},
            )

    def test_profile_status_differential_proves_real_browser_session(self):
        with isolated_runtime(), spa_auth_server("success") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            credentials.save_auth_profile(
                ws.slug, "primary", self._status_profile(port)
            )

            result = dispatch(
                ws, "credential_login", {"credential": "primary"}
            )

            self.assertTrue(result["ok"], result)
            self.assertIn("status-differential proof", result["summary"])
            self.assertEqual(result["data"]["verification_mode"], "status-differential")
            self.assertEqual(result["data"]["matched_submission_count"], 1)
            self.assertEqual(result["data"]["matched_submission_status"], 200)
            self.assertTrue(result["data"]["login_session_material"])
            self.assertEqual(result["data"]["verify_status"], 200)
            self.assertEqual(result["data"]["replay_status"], 200)
            self.assertEqual(result["data"]["control_status"], 401)
            self.assertTrue(result["data"]["session"]["established"])
            self.assertEqual(_SpaAuthHandler.login_posts, 1)

    def test_login_form_can_submit_before_domcontentloaded(self):
        with isolated_runtime(), spa_auth_server(
            "login-domcontentloaded-hang"
        ) as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            credentials.save_auth_profile(
                ws.slug, "primary", self._status_profile(port, timeout=5)
            )

            result = dispatch(
                ws, "credential_browser_login", {"credential": "primary"}
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["data"]["matched_submission_status"], 200)
            self.assertEqual(result["data"]["credential_submission_requests"], 1)
            self.assertEqual(_SpaAuthHandler.login_posts, 1)

    def test_transient_control_probe_retries_without_resubmitting_credential(self):
        with isolated_runtime(), spa_auth_server("success") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            credentials.save_auth_profile(
                ws.slug, "primary", self._status_profile(port)
            )
            original_probe = tools._browser_auth_fresh_probe
            control_calls = 0

            def transient_control(*args, **kwargs):
                nonlocal control_calls
                if kwargs.get("phase") == "control":
                    control_calls += 1
                    if control_calls == 1:
                        raise TimeoutError("synthetic transient control timeout")
                return original_probe(*args, **kwargs)

            with patch(
                "grypton.tools._browser_auth_fresh_probe",
                side_effect=transient_control,
            ):
                result = dispatch(
                    ws, "credential_browser_login", {"credential": "primary"}
                )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["data"]["control_probe_attempts"], 2)
            self.assertEqual(result["data"]["replay_probe_attempts"], 1)
            self.assertEqual(_SpaAuthHandler.login_posts, 1)
            self.assertEqual(
                result["data"]["credential_submission_requests"], 1
            )

    def test_control_retry_exhaustion_never_resubmits_renewal(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            original_probe = tools._browser_auth_fresh_probe
            posts = _RenewAuthHandler.login_posts
            control_calls = 0

            def unavailable_control(*args, **kwargs):
                nonlocal control_calls
                if kwargs.get("phase") == "control":
                    control_calls += 1
                    raise TimeoutError("synthetic persistent control timeout")
                return original_probe(*args, **kwargs)

            with patch(
                "grypton.tools._browser_auth_fresh_probe",
                side_effect=unavailable_control,
            ):
                first = dispatch(ws, "authenticated_http_request", {
                    "url": f"http://127.0.0.1:{port}/resource",
                    "credential": "primary",
                })
                second = dispatch(ws, "authenticated_http_request", {
                    "url": f"http://127.0.0.1:{port}/resource",
                    "credential": "primary",
                })

            self.assertFalse(first["ok"], first)
            self.assertFalse(second["ok"], second)
            self.assertEqual(control_calls, 2)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            state = credentials.load_attempt_state(ws.slug, "primary")
            self.assertFalse(state["established"])
            self.assertEqual(
                state["refresh_attempted_generation"],
                state["proof_generation"],
            )

    def test_fresh_api_proof_stops_at_response_commit(self):
        class FakeLocator:
            def __init__(self, selector):
                self.selector = selector

            def evaluate(self, _script, *_args):
                return "<html><body>proof</body></html>" if self.selector == "html" else "proof"

        class FakeRequest:
            method = "GET"
            redirected_from = None

        class FakeResponse:
            status = 401
            request = FakeRequest()

            def __init__(self, url):
                self.url = url

            def body(self):
                return b'{"authenticated":false}'

        class FakePage:
            def __init__(self, url):
                self.url = url
                self.wait_until = []

            def on(self, *_args):
                pass

            def goto(self, url, *, wait_until, timeout):
                self.url = url
                self.wait_until.append(wait_until)
                if wait_until == "domcontentloaded":
                    raise TimeoutError("DOMContentLoaded never fired")
                self.timeout = timeout
                return FakeResponse(url)

            def wait_for_timeout(self, _milliseconds):
                pass

            def locator(self, selector):
                return FakeLocator(selector)

            def evaluate(self, _script, _area):
                return {"valid": True, "entries": []}

        class FakeContext:
            def __init__(self, page):
                self.page = page

            def new_page(self):
                return self.page

            def cookies(self):
                return []

            def close(self):
                pass

        with isolated_runtime():
            ws = Workspace("proof-commit-test")
            origin = "https://app.example.test"
            url = origin + "/api/session"
            ws.create(origin, "web")
            ws.save_constraints(Constraints(in_scope=[origin]))
            page = FakePage(url)
            context = FakeContext(page)
            with patch(
                "grypton.tools._isolated_browser_profile"
            ) as isolated_profile, patch(
                "grypton.tools._launch_scoped_browser_context",
                return_value=context,
            ):
                isolated_profile.return_value.__enter__.return_value = {
                    "identity": "test-browser"
                }
                result = tools._browser_auth_fresh_probe(
                    object(), "/unused/chromium", ws, url,
                    phase="control", denied_requests=[], console=[],
                    timeout_ms=5000,
                )

            self.assertEqual(result["status"], 401)
            self.assertEqual(page.wait_until, ["commit"])

    def test_anonymous_proof_bootstrap_recovers_blank_direct_api_navigation(self):
        from playwright.sync_api import sync_playwright

        with isolated_runtime(), bootstrap_proof_server() as port:
            origin = f"http://127.0.0.1:{port}"
            ws = Workspace("proof-bootstrap-test")
            ws.create(origin, "web")
            ws.save_constraints(Constraints(in_scope=[origin]))
            url = origin + "/verify"
            executable = tools._browser_executable()
            with sync_playwright() as playwright:
                with self.assertRaises(Exception):
                    tools._browser_auth_fresh_probe(
                        playwright, executable, ws, url,
                        phase="direct-control", denied_requests=[], console=[],
                        timeout_ms=3000,
                    )
                result = tools._browser_auth_fresh_probe(
                    playwright, executable, ws, url,
                    phase="bootstrapped-control", denied_requests=[], console=[],
                    timeout_ms=3000, bootstrap_url=origin + "/login",
                )

            self.assertEqual(result["status"], 401)
            self.assertEqual(result["response_url"], url)
            self.assertEqual(result["final_url"], url)
            self.assertEqual(
                [hop["status"] for hop in result["redirect_chain"]], [307]
            )

    def test_status_differential_accepts_configured_anonymous_self_redirect(self):
        with isolated_runtime(), spa_auth_server("status-anon-redirect") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            credentials.save_auth_profile(
                ws.slug, "primary",
                self._status_profile(
                    port, anonymous_redirect_statuses=[307]
                ),
            )

            result = dispatch(
                ws, "credential_browser_login", {"credential": "primary"}
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["data"]["control_status"], 401)
            self.assertEqual(result["data"]["control_redirect_chain"], [{
                "status": 307,
                "method": "GET",
                "request_url_exact": True,
                "location_exact": True,
                "complete": True,
            }])
            self.assertEqual(result["data"]["verify_redirect_chain"], [])
            self.assertEqual(result["data"]["replay_redirect_chain"], [])
            self.assertTrue(result["data"]["session"]["established"])

    def test_status_differential_redirect_contract_fails_closed(self):
        cases = (
            ("success", [307]),
            ("status-anon-redirect", []),
            ("status-anon-redirect-status", [307]),
            ("status-anon-redirect-url", [307, 307]),
        )
        for mode, redirects in cases:
            with self.subTest(mode=mode), isolated_runtime(), spa_auth_server(mode) as port:
                ws = self._workspace(port)
                credentials.save_credential(
                    ws.slug, "primary", "09123456789", _SpaAuthHandler.password
                )
                credentials.save_auth_profile(
                    ws.slug, "primary",
                    self._status_profile(
                        port, anonymous_redirect_statuses=redirects
                    ),
                )

                result = dispatch(
                    ws, "credential_browser_login", {"credential": "primary"}
                )

                self.assertFalse(result["ok"], result)
                self.assertIn("anonymous control", result["summary"])
                self.assertFalse(result["data"]["session"]["established"])
                serialized = json.dumps(result, ensure_ascii=False)
                serialized += "".join(
                    path.read_text(errors="replace")
                    for path in ws.flows_dir.glob("*.http")
                )
                self.assertNotIn("/me-hop", serialized)

    def test_redirect_contract_rejects_wrong_method_status_url_and_ancestry(self):
        verify_url = "https://app.example.test/profile"
        valid = [{
            "status": 307,
            "method": "GET",
            "url": verify_url,
            "location": verify_url,
            "complete": True,
        }]
        self.assertTrue(_browser_auth_redirect_contract_matches(
            valid, [307], verify_url, "GET"
        ))
        mutations = (
            ({**valid[0], "method": "POST"}, [307], "GET"),
            ({**valid[0], "status": 302}, [307], "GET"),
            ({**valid[0], "url": "https://app.example.test/other"}, [307], "GET"),
            ({**valid[0], "location": "/other"}, [307], "GET"),
            ({**valid[0], "complete": False}, [307], "GET"),
            (valid[0], [307], "POST"),
        )
        for hop, statuses, final_method in mutations:
            with self.subTest(hop=hop, final_method=final_method):
                self.assertFalse(_browser_auth_redirect_contract_matches(
                    [hop], statuses, verify_url, final_method
                ))
        self.assertFalse(_browser_auth_redirect_contract_matches(
            [], [307], verify_url, "GET"
        ))

    def test_status_differential_rejects_only_prelogin_material(self):
        with isolated_runtime(), spa_auth_server("baseline-cookie") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            credentials.save_auth_profile(
                ws.slug, "primary", self._status_profile(port)
            )

            result = dispatch(
                ws, "credential_browser_login", {"credential": "primary"}
            )

            self.assertFalse(result["ok"], result)
            self.assertIn("login did not produce", result["summary"])
            self.assertFalse(result["data"]["login_session_material"])
            self.assertFalse(result["data"]["session"]["established"])
            self.assertEqual(_SpaAuthHandler.login_posts, 1)

    def test_status_differential_requires_material_before_live_verification(self):
        with isolated_runtime(), spa_auth_server("verify-material-only") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            credentials.save_auth_profile(
                ws.slug, "primary", self._status_profile(port)
            )

            result = dispatch(
                ws, "credential_login", {"credential": "primary"}
            )

            self.assertFalse(result["ok"], result)
            self.assertIn("login did not produce", result["summary"])
            self.assertFalse(result["data"]["login_session_material"])
            self.assertEqual(result["data"]["verify_status"], 200)
            self.assertEqual(result["data"]["replay_status"], 0)
            self.assertFalse(result["data"]["session"]["established"])

    def test_status_differential_rejects_each_exact_proof_mismatch(self):
        cases = (
            ("status-login-201", "credential submission status"),
            ("status-wrong-terminal", "post-login URL"),
            ("status-live-mismatch", "live verification"),
            ("status-replay-mismatch", "persisted session replay"),
            ("status-control-mismatch", "anonymous control"),
            ("status-control-404", "anonymous control"),
            ("status-control-200", "anonymous control"),
            ("status-verify-redirect", "live verification"),
        )
        for mode, reason in cases:
            with self.subTest(mode=mode), isolated_runtime(), spa_auth_server(mode) as port:
                ws = self._workspace(port)
                credentials.save_credential(
                    ws.slug, "primary", "09123456789", _SpaAuthHandler.password
                )
                credentials.save_auth_profile(
                    ws.slug, "primary", self._status_profile(port, timeout=5)
                )

                result = dispatch(
                    ws, "credential_browser_login", {"credential": "primary"}
                )

                self.assertFalse(result["ok"], result)
                self.assertIn(reason, result["summary"])
                self.assertFalse(result["data"]["session"]["established"])
                self.assertEqual(_SpaAuthHandler.login_posts, 1)

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
        self.assertNotIn("verification", schema["properties"])
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
