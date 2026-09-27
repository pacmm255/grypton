from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qsl, quote, quote_plus
from unittest.mock import patch

from grypton import config, credentials, request_policy, tools
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
    otp = "839201"
    challenge_session = "browser-challenge-session-never-log"
    identifier_csrf = "identifier-csrf-never-log"
    identifier_code = "417263"
    identifier_challenge = "identifier-challenge-never-log"
    identifier_opaque = "identifier-opaque-never-log"
    identifier_dom = "identifier-dom-never-log"
    identifier_console = "identifier-console-never-log"
    mode = "success"
    login_posts = 0
    login_posts_before_reservation = 0
    attempt_reserved = False
    identifier_preflight_posts = 0
    otp_posts = 0
    partial_otp_posts = 0
    onboarding_workspace_posts = 0
    onboarding_name_posts = 0
    onboarding_payloads = []
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
            if type(self).mode in {
                "staged-otp", "staged-otp-dynamic-captcha",
                "staged-otp-identifier-captcha", "staged-otp-split",
                "staged-otp-oninput-header", "staged-otp-armed-timer",
                "staged-otp-partial", "staged-otp-delayed",
                "staged-otp-onboarding", "staged-otp-memory",
            }:
                html = b"""<!doctype html><html><body data-captcha-trigger='DYNAMIC'
                  data-otp-transport='SPLIT' data-pre-submit-request='PRE_SUBMIT'
                  data-post-otp='POST_OTP' data-stage-storage='STAGE_STORAGE'>
                <main id='app'></main>
                <script>
                const app = document.getElementById('app');
                let memoryStage = 'phone';
                const currentStage = () => document.body.dataset.stageStorage === 'memory'
                  ? memoryStage : (sessionStorage.getItem('stage') || 'phone');
                const setStage = (value) => {
                  if (document.body.dataset.stageStorage === 'memory') memoryStage = value;
                  else sessionStorage.setItem('stage', value);
                };
                sessionStorage.setItem('anonymous_id',
                  sessionStorage.getItem('anonymous_id') || 'browser-anonymous-id');
                function render(challenge = {}) {
                  const stage = currentStage();
                  if (stage === 'phone') {
                    app.innerHTML = `<p>Enter your email and we will send a verification code.</p>
                      <form id="phone-form"><input id="phone_number">
                      <input id="terms" type="checkbox"><input id="privacy" type="checkbox">
                      <input id="updates" type="checkbox">
                      <button id="submit-btn" type="submit">Send code</button></form>`;
                    document.getElementById('phone_number').oninput = () => {
                      if (document.body.dataset.captchaTrigger === 'identifier') {
                        const captcha = document.createElement('div');
                        captcha.id = 'dynamic-captcha'; captcha.className = 'g-recaptcha';
                        document.body.appendChild(captcha);
                        fetch('/api/identifier-preflight', {method:'POST',
                          headers:{'Content-Type':'application/json'}, body:JSON.stringify({
                            phone_number:document.getElementById('phone_number').value})
                        }).catch(() => {});
                      } else if (document.body.dataset.preSubmitRequest === 'header') {
                        fetch('/api/identifier-preflight', {method:'POST',
                          headers:{'Content-Type':'application/json',
                            'X-Identifier':document.getElementById('phone_number').value},
                          body:'{}'}).catch(() => {});
                      } else if (
                        document.body.dataset.preSubmitRequest === 'armed-timer'
                      ) {
                        const action = document.getElementById('submit-btn');
                        action.style.pointerEvents = 'none';
                        setTimeout(() => fetch('/api/identifier-preflight', {
                          method:'POST', headers:{'Content-Type':'application/json',
                            'X-Identifier':document.getElementById('phone_number').value},
                          body:'{}'}).catch(() => {}), 200);
                        setTimeout(() => { action.style.pointerEvents = 'auto'; }, 400);
                      }
                    };
                    document.getElementById('privacy').onchange = () => {
                      if (document.body.dataset.captchaTrigger === 'registration') {
                        const captcha = document.createElement('div');
                        captcha.id = 'dynamic-captcha'; captcha.className = 'g-recaptcha';
                        document.body.appendChild(captcha);
                      }
                    };
                    document.getElementById('phone-form').onsubmit = async (event) => {
                      event.preventDefault();
                      const response = await fetch('/api/send-otp', {method:'POST',
                        headers:{'Content-Type':'application/json'}, body:JSON.stringify({
                          phone_number:document.getElementById('phone_number').value,
                          terms:document.getElementById('terms').checked,
                          privacy:document.getElementById('privacy').checked,
                          updates:document.getElementById('updates').checked,
                          anonymous_id:sessionStorage.getItem('anonymous_id')})});
                      if (response.ok) { const value = response.status === 204
                          ? {} : await response.json();
                        console.log(JSON.stringify(value));
                        console.log(value.console_value);
                        setStage('otp'); render(value); }
                    };
                  } else if (stage === 'otp') {
                    app.innerHTML = `<p>Enter verification code</p><form id="otp-form">
                      ${Array.from({length:6}, (_, i) => `<input class="otp__digit"
                        data-index="${i}" name="d${i + 1}"
                        inputmode="numeric" maxlength="1">`).join('')}
                      <input id="otp" type="hidden">
                      <input name="csrf" type="hidden" value="${challenge.csrf || ''}">
                      <input name="challenge_id" type="hidden"
                        value="${challenge.challenge_id || ''}">
                      <input name="code" type="hidden" value="${challenge.code || ''}">
                      <input name="server_context" type="hidden"
                        value="${challenge.dom_value || ''}">
                      </form>`;
                    for (const input of document.querySelectorAll('.otp__digit')) {
                      input.oninput = async () => {
                        const digits = Array.from(document.querySelectorAll('.otp__digit'));
                        const otp = digits.map(item => item.value).join('');
                        document.getElementById('otp').value = otp;
                        if (document.body.dataset.otpTransport === 'partial' && input.value) {
                          const partial = new URLSearchParams();
                          partial.append(`otp-input-${input.dataset.index}`, input.value);
                          fetch('/api/otp-partial', {method:'POST', headers:{
                            'Content-Type':'application/x-www-form-urlencoded'},
                            body:partial.toString()}).catch(() => {});
                        }
                        if (otp.length !== 6) return;
                        let request;
                        if (document.body.dataset.otpTransport === 'split') {
                          const payload = new URLSearchParams();
                          payload.append('year', '2026'); payload.append('attempt', '1');
                          digits.forEach((item, index) => payload.append(
                            `d${index + 1}`, item.value));
                          request = {method:'POST', headers:{
                            'Content-Type':'application/x-www-form-urlencoded'},
                            body:payload.toString()};
                        } else {
                          request = {method:'POST', headers:{
                            'Content-Type':'application/json'}, body:JSON.stringify({
                              phone_number:'09123456789', otp,
                              anonymous_id:sessionStorage.getItem('anonymous_id')})};
                        }
                        const response = await fetch('/api/verify-otp', request);
                        if (response.ok) { const value = await response.json();
                          sessionStorage.setItem('verification_token', value.token);
                          setStage(
                            document.body.dataset.postOtp === 'onboarding'
                              ? 'workspace-intro' : 'password'); render();
                          if (document.body.dataset.otpTransport === 'delayed') {
                            setTimeout(() => fetch('/api/verify-otp', {method:'POST',
                              headers:{'Content-Type':'application/json'},
                              body:JSON.stringify({otp})}).catch(() => {}), 800);
                          } }
                      };
                    }
                  } else if (stage === 'workspace-intro') {
                    app.innerHTML = `<button id="create-workspace" type="button">
                      Create new workspace</button>`;
                    document.getElementById('create-workspace').onclick = () => {
                      setStage('workspace'); render();
                    };
                  } else if (stage === 'workspace') {
                    app.innerHTML = `<form id="workspace-form">
                      <input id="workspace-name" name="workspace_name">
                      <button id="company-size-trigger" role="combobox" type="button"
                        aria-controls="company-options">Choose size</button>
                      <div id="company-options" hidden>
                        <button id="company-small" role="option" type="button">
                          Small</button>
                      </div>
                      <input id="company-size" name="company_size" type="hidden">
                      <button id="workspace-next" type="submit">Next</button></form>`;
                    document.getElementById('company-size-trigger').onclick = () => {
                      document.getElementById('company-options').hidden = false;
                    };
                    document.getElementById('company-small').onclick = () => {
                      document.getElementById('company-size').value = 'small';
                      document.getElementById('company-options').hidden = true;
                    };
                    document.getElementById('workspace-form').onsubmit = async (event) => {
                      event.preventDefault();
                      const response = await fetch('/api/onboarding-workspace', {
                        method:'POST', headers:{'Content-Type':'application/json'},
                        body:JSON.stringify({
                          workspace_name:document.getElementById('workspace-name').value,
                          company_size:document.getElementById('company-size').value})});
                      if (response.ok) { setStage('name'); render(); }
                    };
                  } else if (stage === 'name') {
                    app.innerHTML = `<form id="name-form">
                      <input id="first-name" name="first_name">
                      <input id="last-name" name="last_name">
                      <input id="profile-consent" name="profile_consent" type="checkbox">
                      <button id="name-next" type="submit">Finish</button></form>`;
                    document.getElementById('name-form').onsubmit = async (event) => {
                      event.preventDefault();
                      const response = await fetch('/api/onboarding-name', {
                        method:'POST', headers:{'Content-Type':'application/json'},
                        body:JSON.stringify({
                          first_name:document.getElementById('first-name').value,
                          last_name:document.getElementById('last-name').value,
                          profile_consent:document.getElementById('profile-consent').checked})});
                      if (response.ok) { setStage('invite'); render(); }
                    };
                  } else if (stage === 'invite') {
                    app.innerHTML = `<button id="skip-invites" type="button">
                      Skip invitations</button>`;
                    document.getElementById('skip-invites').onclick = () => {
                      setStage('support'); render();
                    };
                  } else if (stage === 'support') {
                    app.innerHTML = `<button id="skip-support" type="button">
                      Skip support setup</button>`;
                    document.getElementById('skip-support').onclick = () => {
                      setStage('dashboard');
                      location.assign('/dashboard');
                    };
                  } else {
                    app.innerHTML = `<form id="password-form"><input id="verification_token">
                      <input id="password" type="password"><button id="password-submit-btn"
                      type="submit">Sign in</button></form>`;
                    document.getElementById('verification_token').value =
                      sessionStorage.getItem('verification_token') || '';
                    document.getElementById('password-form').onsubmit = async (event) => {
                      event.preventDefault();
                      const response = await fetch('/api/login-stage', {method:'POST',
                        headers:{'Content-Type':'application/json'}, body:JSON.stringify({
                          phone_number:'09123456789', password:document.getElementById('password').value,
                          token:document.getElementById('verification_token').value})});
                      if (response.ok) location.assign('/dashboard');
                    };
                  }
                }
                render();
                </script></body></html>"""
                html = html.replace(
                    b"DYNAMIC",
                    b"registration" if type(self).mode == "staged-otp-dynamic-captcha"
                    else b"identifier" if type(self).mode == "staged-otp-identifier-captcha"
                    else b"none",
                )
                html = html.replace(
                    b"SPLIT",
                    b"split" if type(self).mode == "staged-otp-split"
                    else b"partial" if type(self).mode == "staged-otp-partial"
                    else b"delayed" if type(self).mode == "staged-otp-delayed"
                    else b"joined",
                )
                html = html.replace(
                    b"PRE_SUBMIT",
                    b"header" if type(self).mode in {
                        "staged-otp-oninput-header", "staged-otp-memory",
                    }
                    else b"armed-timer" if type(self).mode == "staged-otp-armed-timer"
                    else b"none",
                )
                html = html.replace(
                    b"POST_OTP",
                    b"onboarding"
                    if type(self).mode == "staged-otp-onboarding" else b"password",
                )
                html = html.replace(
                    b"STAGE_STORAGE",
                    b"memory" if type(self).mode == "staged-otp-memory"
                    else b"session",
                )
                self._send(
                    200, html, content_type="text/html; charset=utf-8",
                    cookie=type(self).challenge_session,
                )
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
            auto_submit_script = (
                "document.querySelector('[data-testid=\"login-password\"]')"
                ".addEventListener('input', () => "
                "document.getElementById('login-form').requestSubmit());"
                if type(self).mode == "login-input-autosubmit" else ""
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
              if (value.otp_required) {{
                sessionStorage.setItem('otp_challenge', 'active');
                document.getElementById('result').innerHTML =
                  '<p>Enter verification code</p>' +
                  '<input class="otp__digit" maxlength="1">'.repeat(6);
              }}
              {identity_console}
              if (value.access_token) console.log(value.access_token);
              if (response.ok && !value.otp_required) window.location.assign(
                '{"/dashboard?unexpected=1" if type(self).mode == "status-wrong-terminal" else "/dashboard"}'
              );
            }});
            {auto_submit_script}
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
        if type(self).mode in {
            "staged-otp", "staged-otp-dynamic-captcha",
            "staged-otp-identifier-captcha", "staged-otp-split",
            "staged-otp-oninput-header", "staged-otp-armed-timer",
            "staged-otp-partial", "staged-otp-delayed",
            "staged-otp-onboarding", "staged-otp-memory",
        } and self.path in {
            "/api/send-otp", "/api/verify-otp", "/api/login-stage",
            "/api/identifier-preflight", "/api/otp-partial",
            "/api/onboarding-workspace", "/api/onboarding-name",
        }:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode()
            if self.path == "/api/identifier-preflight":
                type(self).identifier_preflight_posts += 1
                self._json(200, {"received": True})
                return
            if self.path == "/api/otp-partial":
                type(self).partial_otp_posts += 1
                self._json(200, {"received": True})
                return
            try:
                value = json.loads(raw)
            except ValueError:
                value = dict(parse_qsl(raw, keep_blank_values=True))
            if type(self).mode == "staged-otp-split" and self.path == "/api/verify-otp":
                value["otp"] = "".join(value.get(f"d{index}", "") for index in range(1, 7))
            if self.path == "/api/send-otp":
                type(self).login_posts += 1
                accepted = (
                    value.get("phone_number") == "09123456789"
                    and value.get("terms") is True
                    and value.get("privacy") is True
                )
                if type(self).mode == "staged-otp-memory" and accepted:
                    self._send(204, b"", content_type="application/json")
                    return
                self._json(
                    202 if accepted else 400,
                    {
                        "otp_required": True,
                        "csrf": type(self).identifier_csrf,
                        "code": type(self).identifier_code,
                        "challenge_id": type(self).identifier_challenge,
                        "opaque": type(self).identifier_opaque,
                        "dom_value": type(self).identifier_dom,
                        "console_value": type(self).identifier_console,
                    },
                )
                return
            if self.path == "/api/verify-otp":
                type(self).otp_posts += 1
                self._json(
                    200 if value.get("otp") == type(self).otp else 401,
                    {"token": "stage-verification-token-never-log"}
                    if value.get("otp") == type(self).otp
                    else {"error": "invalid otp code"},
                )
                return
            if self.path == "/api/onboarding-workspace":
                type(self).onboarding_workspace_posts += 1
                type(self).onboarding_payloads.append(value)
                accepted = (
                    value.get("workspace_name") == "Bounded Research"
                    and value.get("company_size") == "small"
                )
                self._json(200 if accepted else 400, {"accepted": accepted})
                return
            if self.path == "/api/onboarding-name":
                type(self).onboarding_name_posts += 1
                type(self).onboarding_payloads.append(value)
                accepted = (
                    value.get("first_name") == "Ada"
                    and value.get("last_name") == "Lovelace"
                    and value.get("profile_consent") is True
                )
                self._json(
                    200 if accepted else 400, {"authenticated": accepted},
                    cookie=type(self).session if accepted else "",
                )
                return
            accepted = (
                value.get("password") == type(self).password
                and value.get("token") == "stage-verification-token-never-log"
            )
            self._json(
                200 if accepted else 401,
                {"authenticated": accepted},
                cookie=type(self).session if accepted else "",
            )
            return
        if self.path != "/api/login":
            self._json(404, {"error": "not found"})
            return
        type(self).login_posts += 1
        if not type(self).attempt_reserved:
            type(self).login_posts_before_reservation += 1
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
    _SpaAuthHandler.login_posts_before_reservation = 0
    _SpaAuthHandler.attempt_reserved = False
    _SpaAuthHandler.identifier_preflight_posts = 0
    _SpaAuthHandler.otp_posts = 0
    _SpaAuthHandler.partial_otp_posts = 0
    _SpaAuthHandler.onboarding_workspace_posts = 0
    _SpaAuthHandler.onboarding_name_posts = 0
    _SpaAuthHandler.onboarding_payloads = []
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
    transient_renewal_verify_status = 0
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
                    type(self).transient_renewal_verify_status
                    and type(self).login_posts >= 2
                ):
                    self._json(
                        type(self).transient_renewal_verify_status,
                        {"error": "temporary verifier failure"},
                    )
                    return
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
    _RenewAuthHandler.transient_renewal_verify_status = 0
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


class _CrossOriginSignupHandler(BaseHTTPRequestHandler):
    email = "researcher@temporary.example"
    otp = "731904"
    primary_port = 0
    api_port = 0
    api_posts = 0
    otp_posts = 0
    preflight_posts = 0
    mandatory_header_values: list[str] = []
    query_secret = False
    redirect_final = False
    redirect_followups = 0
    json_requests = False
    redirect_options = False
    options_requests: list[str] = []
    options_redirect_followups = 0
    request_order: list[str] = []
    post_content_types: list[str] = []

    def _send(self, status: int, body: bytes, *, content_type: str,
              cors: bool = False, location: str = "") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if cors:
            self.send_header(
                "Access-Control-Allow-Origin",
                f"http://127.0.0.1:{type(self).primary_port}",
            )
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        port = int(self.server.server_address[1])
        if port == type(self).primary_port and self.path == "/signup":
            api_url = (
                f"http://127.0.0.1:{type(self).api_port}/auth/signup"
            )
            check_url = (
                f"http://127.0.0.1:{type(self).api_port}/auth/check-email"
            )
            otp_url = (
                f"http://127.0.0.1:{type(self).api_port}/auth/verify-otp"
            )
            query_secret = "yes" if type(self).query_secret else "no"
            json_requests = "yes" if type(self).json_requests else "no"
            body = f"""<!doctype html><html><body data-query-secret='{query_secret}' data-json='{json_requests}'><main id='app'>
              <p>Create your test account</p>
              <form id='signup-form'>
                <input id='email' name='email' type='email'>
                <input id='password' name='password' type='password'>
                <input id='privacy' type='checkbox'>
                <button id='create-account' type='submit'>Create account</button>
              </form></main><script>
              sessionStorage.setItem('anonymous_id', 'uxcam-test-browser');
              sessionStorage.setItem(
                'policy_identity', '{type(self).email}'
              );
              const renderOtp = () => {{
                document.getElementById('app').innerHTML = `
                  <p>Enter verification code</p>
                  <form id="otp-form"><input id="otp" name="otp"
                    autocomplete="one-time-code">
                  <button id="verify" type="submit">Verify</button></form>`;
                document.getElementById('otp-form').onsubmit = async (event) => {{
                  event.preventDefault();
                  const response = await fetch('{otp_url}', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{
                      otp: document.getElementById('otp').value,
                    }}),
                  }});
                  if (response.ok) {{
                    document.cookie = 'signup_session=verified; Path=/; SameSite=Lax';
                    location.assign('/profile');
                  }}
                }};
              }};
              const signupForm = document.getElementById('signup-form');
              if (sessionStorage.getItem('signup_stage') === 'otp') {{
                renderOtp();
              }} else signupForm.onsubmit = async (event) => {{
                event.preventDefault();
                try {{
                  const asJson = document.body.dataset.json === 'yes';
                  const requestBody = (values) => asJson
                    ? JSON.stringify(values) : new URLSearchParams(values);
                  const requestHeaders = {{'Content-Type': asJson
                    ? 'application/json' : 'application/x-www-form-urlencoded'}};
                  const checkResponse = await fetch('{check_url}', {{
                    method: 'POST',
                    headers: requestHeaders,
                    body: requestBody({{
                      email: document.getElementById('email').value,
                    }}),
                  }});
                  if (!checkResponse.ok) return;
                  const endpoint = '{api_url}' + (
                    document.body.dataset.querySecret === 'yes'
                      ? '?email=' + encodeURIComponent(
                          document.getElementById('email').value)
                      : '');
                  const response = await fetch(endpoint, {{
                    method: 'POST',
                    headers: requestHeaders,
                    body: requestBody({{
                      email: document.getElementById('email').value,
                      password: document.getElementById('password').value,
                      privacy: document.getElementById('privacy').checked,
                    }}),
                  }});
                  if (response.ok) {{
                    sessionStorage.setItem('signup_stage', 'otp');
                    renderOtp();
                  }}
                }} catch (_error) {{}}
              }};
              </script></body></html>""".encode()
            self._send(200, body, content_type="text/html")
            return
        if port == type(self).primary_port and self.path == "/profile":
            authenticated = (
                "signup_session=verified" in self.headers.get("Cookie", "")
            )
            self._send(
                200 if authenticated else 401,
                (
                    b'<html><body>Account profile</body></html>'
                    if authenticated else b'{"authenticated":false}'
                ),
                content_type=(
                    "text/html" if authenticated else "application/json"
                ),
            )
            return
        self._send(404, b"", content_type="text/plain")

    def do_OPTIONS(self):
        port = int(self.server.server_address[1])
        request_path = self.path.split("?", 1)[0]
        type(self).mandatory_header_values.append(
            self.headers.get("X-UXCam-Researcher", "")
        )
        type(self).options_requests.append(self.path)
        type(self).request_order.append("OPTIONS " + self.path)
        if port != type(self).api_port:
            self._send(404, b"", content_type="text/plain")
            return
        if request_path == "/auth/redirected":
            type(self).options_redirect_followups += 1
            self._send(204, b"", content_type="text/plain", cors=True)
            return
        if request_path not in {
            "/auth/check-email", "/auth/signup", "/auth/verify-otp",
        }:
            self._send(404, b"", content_type="text/plain", cors=True)
            return
        if type(self).redirect_options:
            self._send(
                307, b"", content_type="text/plain", cors=True,
                location=(
                    f"http://127.0.0.1:{type(self).api_port}/auth/redirected"
                ),
            )
            return
        self.send_response(204)
        self.send_header(
            "Access-Control-Allow-Origin",
            f"http://127.0.0.1:{type(self).primary_port}",
        )
        self.send_header("Access-Control-Allow-Methods", "POST")
        requested_headers = self.headers.get(
            "Access-Control-Request-Headers", "Content-Type"
        )
        self.send_header(
            "Access-Control-Allow-Headers",
            requested_headers + ", X-UXCam-Researcher",
        )
        self.send_header("Access-Control-Max-Age", "0")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        port = int(self.server.server_address[1])
        request_path = self.path.split("?", 1)[0]
        if port != type(self).api_port or request_path not in {
            "/auth/check-email", "/auth/signup", "/auth/verify-otp",
            "/auth/redirected",
        }:
            self._send(404, b"", content_type="text/plain")
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode()
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip() == (
            "application/json"
        ):
            parsed_body = json.loads(raw_body)
            values = parsed_body if isinstance(parsed_body, dict) else {}
        else:
            values = dict(parse_qsl(raw_body, keep_blank_values=True))
        type(self).mandatory_header_values.append(
            self.headers.get("X-UXCam-Researcher", "")
        )
        type(self).request_order.append("POST " + self.path)
        type(self).post_content_types.append(
            self.headers.get("Content-Type", "")
        )
        if request_path == "/auth/redirected":
            type(self).redirect_followups += 1
            self._send(200, b"{}", content_type="application/json", cors=True)
            return
        if request_path == "/auth/check-email":
            type(self).preflight_posts += 1
            status = 200 if values.get("email") == type(self).email else 400
            self._send(
                status, b'{"available":true}',
                content_type="application/json", cors=True,
            )
            return
        if request_path == "/auth/verify-otp":
            type(self).otp_posts += 1
            status = 200 if values.get("otp") == type(self).otp else 401
            self._send(
                status,
                b'{"verified":true}' if status == 200 else b'{"verified":false}',
                content_type="application/json", cors=True,
            )
            return
        type(self).api_posts += 1
        if type(self).redirect_final:
            self._send(
                307, b"", content_type="application/json", cors=True,
                location=(
                    f"http://127.0.0.1:{type(self).api_port}/auth/redirected"
                ),
            )
            return
        status = 202 if (
            values.get("email") == type(self).email
            and values.get("privacy") in {True, "true"}
        ) else 400
        self._send(
            status, b'{"otp_required":true}',
            content_type="application/json", cors=True,
        )

    def log_message(self, *_args):
        pass


@contextmanager
def cross_origin_signup_servers(*, query_secret: bool = False,
                                redirect_final: bool = False,
                                json_requests: bool = False,
                                redirect_options: bool = False):
    primary = ThreadingHTTPServer(("127.0.0.1", 0), _CrossOriginSignupHandler)
    api = ThreadingHTTPServer(("127.0.0.1", 0), _CrossOriginSignupHandler)
    _CrossOriginSignupHandler.primary_port = primary.server_address[1]
    _CrossOriginSignupHandler.api_port = api.server_address[1]
    _CrossOriginSignupHandler.api_posts = 0
    _CrossOriginSignupHandler.otp_posts = 0
    _CrossOriginSignupHandler.preflight_posts = 0
    _CrossOriginSignupHandler.mandatory_header_values = []
    _CrossOriginSignupHandler.query_secret = query_secret
    _CrossOriginSignupHandler.redirect_final = redirect_final
    _CrossOriginSignupHandler.redirect_followups = 0
    _CrossOriginSignupHandler.json_requests = json_requests
    _CrossOriginSignupHandler.redirect_options = redirect_options
    _CrossOriginSignupHandler.options_requests = []
    _CrossOriginSignupHandler.options_redirect_followups = 0
    _CrossOriginSignupHandler.request_order = []
    _CrossOriginSignupHandler.post_content_types = []
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (primary, api)
    ]
    for thread in threads:
        thread.start()
    try:
        yield primary.server_address[1], api.server_address[1]
    finally:
        for server in (primary, api):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


class BrowserCredentialTests(unittest.TestCase):
    def _workspace(self, port: int) -> Workspace:
        ws = Workspace("browser-credential-test")
        origin = f"http://127.0.0.1:{port}"
        ws.create(origin, "web")
        ws.save_constraints(Constraints(in_scope=[origin]))
        return ws

    def _cross_origin_signup_workspace(
        self, primary_port: int, api_port: int, *, api_in_scope: bool = True,
    ) -> Workspace:
        primary_origin = f"http://127.0.0.1:{primary_port}"
        api_origin = f"http://127.0.0.1:{api_port}"
        ws = Workspace("cross-origin-browser-signup")
        ws.create(primary_origin, "web")
        ws.save_constraints(Constraints(in_scope=[
            primary_origin,
            *([api_origin] if api_in_scope else []),
        ]))
        return ws

    def _cross_origin_signup_profile(self, primary_port: int) -> dict:
        origin = f"http://127.0.0.1:{primary_port}"
        return {
            "version": 1,
            "strategy": "browser",
            "login_url": origin + "/signup",
            "verify_url": origin + "/profile",
            "success_marker": "Account profile",
            "username_transform": "stored",
            "timeout": 10,
            "browser": {
                "username_selector": "#email",
                "password_selector": "input[type='password']",
                "submit_selector": "#create-account",
                "verify_headers": {},
            },
        }

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

    def _leave_pending_renewal(self, ws: Workspace, port: int) -> dict:
        original_probe = tools._browser_auth_fresh_probe

        def unavailable_control(*args, **kwargs):
            if kwargs.get("phase") == "control":
                raise TimeoutError("synthetic persistent control timeout")
            return original_probe(*args, **kwargs)

        with patch(
            "grypton.tools._browser_auth_fresh_probe",
            side_effect=unavailable_control,
        ):
            result = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })
        self.assertFalse(result["ok"], result)
        self.assertEqual(
            credentials.session_status(ws.slug, "primary")["state"],
            "renewal-pending",
        )
        return result

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
            second = dispatch(Workspace(ws.slug), "authenticated_http_request", {
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

    def test_unsubmitted_refresh_reservation_is_released(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            before = credentials.load_attempt_state(ws.slug, "primary")
            posts = _RenewAuthHandler.login_posts

            with patch(
                "grypton.tools._browser_auth_wait_for_submit",
                side_effect=RuntimeError("synthetic pre-submit failure"),
            ):
                first = dispatch(ws, "authenticated_http_request", {
                    "url": f"http://127.0.0.1:{port}/resource",
                    "credential": "primary",
                })

            self.assertFalse(first["ok"], first)
            self.assertEqual(_RenewAuthHandler.login_posts, posts)
            self.assertEqual(first["data"]["credential_submission_requests"], 0)
            self.assertTrue(
                first["data"]["session_renewal"]["reservation_released"]
            )
            released = credentials.load_attempt_state(ws.slug, "primary")
            self.assertEqual(released["refresh_attempted_generation"], 0)
            self.assertEqual(
                released["refresh_submissions"], before["refresh_submissions"]
            )

            second = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })

            self.assertTrue(second["ok"], second)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertEqual(_RenewAuthHandler.resource_requests, 1)

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
            self.assertFalse(credentials.load_pending_browser_renewal(
                ws.slug, "primary"
            )["available"])

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

    def test_first_login_reserves_and_captures_before_input_autosubmit(self):
        with isolated_runtime(), spa_auth_server("login-input-autosubmit") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            credentials.save_auth_profile(
                ws.slug, "primary", self._status_profile(port)
            )
            original_begin = credentials.begin_login_attempt

            def marked_begin(*args, **kwargs):
                attempt = original_begin(*args, **kwargs)
                _SpaAuthHandler.attempt_reserved = True
                return attempt

            with patch.object(
                credentials, "begin_login_attempt", side_effect=marked_begin,
            ):
                result = dispatch(
                    ws, "credential_browser_login", {"credential": "primary"}
                )

            self.assertTrue(result["ok"], result)
            self.assertEqual(_SpaAuthHandler.login_posts, 1)
            self.assertEqual(_SpaAuthHandler.login_posts_before_reservation, 0)
            self.assertEqual(result["data"]["credential_submission_requests"], 1)
            self.assertEqual(result["data"]["matched_submission_count"], 1)

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

    def test_control_retry_exhaustion_retains_and_promotes_renewal(self):
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

            self.assertFalse(first["ok"], first)
            self.assertEqual(control_calls, 2)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            pending_state = credentials.load_attempt_state(ws.slug, "primary")
            self.assertFalse(pending_state["established"])
            self.assertEqual(
                pending_state["refresh_attempted_generation"],
                pending_state["proof_generation"],
            )
            pending_status = credentials.session_status(ws.slug, "primary")
            self.assertEqual(pending_status["state"], "renewal-pending")
            self.assertTrue(pending_status["has_pending_renewal"])
            self.assertTrue(credentials.load_pending_browser_renewal(
                ws.slug, "primary"
            )["available"])
            self.assertEqual(_RenewAuthHandler.resource_requests, 0)

            # Promotion also survives a provider/worker restart because the
            # candidate and reservation are durable private state.
            second = dispatch(Workspace(ws.slug), "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })

            self.assertTrue(second["ok"], second)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertEqual(_RenewAuthHandler.resource_requests, 1)
            self.assertEqual(
                second["data"]["session_maintenance"]["action"],
                "renewed-pending-proof",
            )
            self.assertFalse(
                second["data"]["session_maintenance"]["credential_submission"]
            )
            renewed = credentials.load_attempt_state(ws.slug, "primary")
            self.assertTrue(renewed["established"])
            self.assertEqual(
                renewed["proof_generation"],
                pending_state["proof_generation"] + 1,
            )
            self.assertEqual(renewed["refresh_attempted_generation"], 0)
            self.assertFalse(credentials.load_pending_browser_renewal(
                ws.slug, "primary"
            )["available"])

    def test_replay_timeout_retains_and_promotes_renewal(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            original_probe = tools._browser_auth_fresh_probe
            posts = _RenewAuthHandler.login_posts
            replay_calls = 0

            def unavailable_replay(*args, **kwargs):
                nonlocal replay_calls
                if kwargs.get("phase") == "replay":
                    replay_calls += 1
                    raise TimeoutError("synthetic persistent replay timeout")
                return original_probe(*args, **kwargs)

            with patch(
                "grypton.tools._browser_auth_fresh_probe",
                side_effect=unavailable_replay,
            ):
                first = dispatch(ws, "authenticated_http_request", {
                    "url": f"http://127.0.0.1:{port}/resource",
                    "credential": "primary",
                })

            self.assertFalse(first["ok"], first)
            self.assertEqual(replay_calls, 2)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertTrue(
                first["data"]["session_renewal"]["pending_proof"]
            )
            self.assertFalse(
                first["data"]["session_renewal"]["pending_control"]
            )
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["state"],
                "renewal-pending",
            )

            second = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })

            self.assertTrue(second["ok"], second)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertEqual(_RenewAuthHandler.resource_requests, 1)
            self.assertEqual(
                second["data"]["session_maintenance"]["action"],
                "renewed-pending-proof",
            )

    def test_transient_replay_status_retains_and_promotes_renewal(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            original_probe = tools._browser_auth_fresh_probe
            posts = _RenewAuthHandler.login_posts
            replay_calls = 0

            def unavailable_replay(*args, **kwargs):
                nonlocal replay_calls
                if kwargs.get("phase") == "replay":
                    replay_calls += 1
                    storage = kwargs.get("browser_storage") or {}
                    return {
                        "status": 503,
                        "response_url": f"http://127.0.0.1:{port}/verify",
                        "final_url": f"http://127.0.0.1:{port}/verify",
                        "method": "GET", "redirect_chain": [],
                        "body": "", "source": "",
                        "cookies": list(kwargs.get("cookies") or []),
                        "local_storage": dict(storage.get("local_storage") or {}),
                        "session_storage": dict(
                            storage.get("session_storage") or {}
                        ),
                    }
                return original_probe(*args, **kwargs)

            with patch(
                "grypton.tools._browser_auth_fresh_probe",
                side_effect=unavailable_replay,
            ):
                first = dispatch(ws, "authenticated_http_request", {
                    "url": f"http://127.0.0.1:{port}/resource",
                    "credential": "primary",
                })

            self.assertFalse(first["ok"], first)
            self.assertEqual(replay_calls, 2)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertTrue(first["data"]["session_renewal"]["pending_proof"])
            self.assertEqual(
                first["data"]["session_renewal"]["retryable_proof_stage"],
                "replay",
            )

            second = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })

            self.assertTrue(second["ok"], second)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertEqual(_RenewAuthHandler.resource_requests, 1)

    def test_direct_verifier_timeout_retains_rotated_session_and_promotes(self):
        from playwright.sync_api import Page

        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            before = credentials.load_attempt_state(ws.slug, "primary")
            posts = _RenewAuthHandler.login_posts
            origin = f"http://127.0.0.1:{port}"
            rotated = "timeout-rotated-session-never-log"
            original_goto = Page.goto
            timed_out = False

            def timeout_after_rotation(page, url, *args, **kwargs):
                nonlocal timed_out
                if (
                    not timed_out
                    and url == origin + "/verify"
                    and page.url == origin + "/home"
                    and _RenewAuthHandler.login_posts == posts + 1
                ):
                    timed_out = True
                    _RenewAuthHandler.session = rotated
                    page.context.add_cookies([{
                        "name": "app_session", "value": rotated,
                        "url": origin, "httpOnly": True,
                    }])
                    raise TimeoutError("synthetic direct verifier timeout")
                return original_goto(page, url, *args, **kwargs)

            with patch.object(Page, "goto", new=timeout_after_rotation):
                first = dispatch(ws, "authenticated_http_request", {
                    "url": origin + "/resource",
                    "credential": "primary",
                })

            self.assertTrue(timed_out)
            self.assertFalse(first["ok"], first)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertTrue(first["data"]["session_renewal"]["pending_proof"])
            self.assertEqual(
                first["data"]["session_renewal"]["retryable_proof_stage"],
                "verify",
            )
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["state"],
                "renewal-pending",
            )

            second = dispatch(ws, "authenticated_http_request", {
                "url": origin + "/resource",
                "credential": "primary",
            })

            self.assertTrue(second["ok"], second)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertEqual(_RenewAuthHandler.resource_requests, 1)
            self.assertFalse(
                second["data"]["session_maintenance"]["credential_submission"]
            )
            renewed = credentials.load_attempt_state(ws.slug, "primary")
            self.assertEqual(
                renewed["proof_generation"], before["proof_generation"] + 1
            )
            self.assertEqual(renewed["refresh_attempted_generation"], 0)
            self.assertFalse(credentials.load_pending_browser_renewal(
                ws.slug, "primary"
            )["available"])

    def test_transient_verifier_status_retains_without_resubmission(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            posts = _RenewAuthHandler.login_posts
            _RenewAuthHandler.transient_renewal_verify_status = 503

            first = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })

            self.assertFalse(first["ok"], first)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertTrue(first["data"]["session_renewal"]["pending_proof"])
            self.assertEqual(
                first["data"]["session_renewal"]["retryable_proof_stage"],
                "verify",
            )
            _RenewAuthHandler.transient_renewal_verify_status = 0

            second = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })

            self.assertTrue(second["ok"], second)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertEqual(_RenewAuthHandler.resource_requests, 1)

    def test_nonretryable_replay_exception_closes_renewal(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            original_probe = tools._browser_auth_fresh_probe
            posts = _RenewAuthHandler.login_posts
            replay_calls = 0

            def invalid_replay(*args, **kwargs):
                nonlocal replay_calls
                if kwargs.get("phase") == "replay":
                    replay_calls += 1
                    raise RuntimeError("synthetic nonretryable proof error")
                return original_probe(*args, **kwargs)

            with patch(
                "grypton.tools._browser_auth_fresh_probe",
                side_effect=invalid_replay,
            ):
                first = dispatch(ws, "authenticated_http_request", {
                    "url": f"http://127.0.0.1:{port}/resource",
                    "credential": "primary",
                })

            self.assertFalse(first["ok"], first)
            self.assertEqual(replay_calls, 1)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertFalse(credentials.load_pending_browser_renewal(
                ws.slug, "primary"
            )["available"])
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["state"],
                "renewal-blocked",
            )

    def test_probe_transient_result_classification(self):
        complete = {
            "method": "GET", "response_url": "https://example.test/verify",
            "final_url": "https://example.test/verify", "redirect_chain": [],
        }
        for status in (0, 408, 425, 429, 500, 503, 599):
            with self.subTest(status=status):
                self.assertTrue(tools._browser_auth_probe_result_is_transient(
                    status=status, **complete
                ))
        for status in (200, 400, 401, 403, 404):
            with self.subTest(status=status):
                self.assertFalse(tools._browser_auth_probe_result_is_transient(
                    status=status, **complete
                ))
        self.assertTrue(tools._browser_auth_probe_result_is_transient(
            status=400, method="", response_url=complete["response_url"],
            final_url=complete["final_url"], redirect_chain=[],
        ))
        self.assertTrue(tools._browser_auth_probe_result_is_transient(
            status=400, method="GET", response_url=complete["response_url"],
            final_url=complete["final_url"],
            redirect_chain=[{"complete": False}],
        ))

    def test_pending_renewal_profile_change_invalidates_without_probe(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            posts = _RenewAuthHandler.login_posts
            self._leave_pending_renewal(ws, port)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            reserved = credentials.load_attempt_state(ws.slug, "primary")

            changed = self._renew_profile(port)
            changed["timeout"] += 1
            credentials.save_auth_profile(ws.slug, "primary", changed)
            with patch(
                "grypton.tools._browser_auth_fresh_probe"
            ) as probe:
                result = dispatch(ws, "authenticated_http_request", {
                    "url": f"http://127.0.0.1:{port}/resource",
                    "credential": "primary",
                })

            self.assertFalse(result["ok"], result)
            probe.assert_not_called()
            self.assertEqual(
                result["data"]["session_maintenance"]["action"],
                "pending-invalidated-profile-change",
            )
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            state = credentials.load_attempt_state(ws.slug, "primary")
            self.assertFalse(state["established"])
            self.assertEqual(
                state["refresh_attempted_generation"],
                reserved["proof_generation"],
            )
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["state"],
                "renewal-blocked",
            )
            self.assertFalse(
                credentials.pending_browser_renewal_path(
                    ws.slug, "primary"
                ).exists()
            )

    def test_zero_status_control_retains_candidate_without_resubmission(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            posts = _RenewAuthHandler.login_posts
            original_probe = tools._browser_auth_fresh_probe
            control_calls = 0

            def zero_status_control(*args, **kwargs):
                nonlocal control_calls
                if kwargs.get("phase") == "control":
                    control_calls += 1
                    return {
                        "status": 0, "response_url": "", "final_url": "",
                        "method": "", "redirect_chain": [], "body": "",
                        "source": "", "cookies": [], "local_storage": {},
                        "session_storage": {},
                    }
                return original_probe(*args, **kwargs)

            with patch(
                "grypton.tools._browser_auth_fresh_probe",
                side_effect=zero_status_control,
            ):
                first = dispatch(ws, "authenticated_http_request", {
                    "url": f"http://127.0.0.1:{port}/resource",
                    "credential": "primary",
                })

            self.assertFalse(first["ok"], first)
            self.assertEqual(control_calls, 2)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["state"],
                "renewal-pending",
            )

            second = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })
            self.assertTrue(second["ok"], second)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertEqual(_RenewAuthHandler.resource_requests, 1)

    def test_pending_candidate_that_becomes_anonymous_is_invalidated(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            posts = _RenewAuthHandler.login_posts
            self._leave_pending_renewal(ws, port)
            reserved = credentials.load_attempt_state(ws.slug, "primary")
            _RenewAuthHandler.session = "replacement-session-never-log"

            result = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })

            self.assertFalse(result["ok"], result)
            self.assertEqual(
                result["data"]["session_maintenance"]["action"],
                "pending-invalidated-stale",
            )
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            self.assertFalse(credentials.pending_browser_renewal_path(
                ws.slug, "primary"
            ).exists())
            state = credentials.load_attempt_state(ws.slug, "primary")
            self.assertFalse(state["established"])
            self.assertEqual(
                state["refresh_attempted_generation"],
                reserved["proof_generation"],
            )

    def test_pending_promotion_failure_restores_every_private_file(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            posts = _RenewAuthHandler.login_posts
            self._leave_pending_renewal(ws, port)
            paths = (
                credentials.cookie_jar_storage_path(ws.slug, "primary"),
                credentials.token_path(ws.slug, "primary"),
                credentials.browser_storage_path(ws.slug, "primary"),
                credentials.attempt_path(ws.slug, "primary"),
                credentials.pending_browser_renewal_path(ws.slug, "primary"),
            )
            before = {
                path: (path.exists(), path.read_bytes() if path.exists() else b"")
                for path in paths
            }

            with patch(
                "grypton.credentials.record_refresh_outcome",
                side_effect=OSError("synthetic final-commit failure"),
            ):
                failed = dispatch(ws, "authenticated_http_request", {
                    "url": f"http://127.0.0.1:{port}/resource",
                    "credential": "primary",
                })

            self.assertFalse(failed["ok"], failed)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            for path, snapshot in before.items():
                self.assertEqual(path.exists(), snapshot[0], path)
                if snapshot[0]:
                    self.assertEqual(path.read_bytes(), snapshot[1], path)
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["state"],
                "renewal-pending",
            )

            recovered = dispatch(ws, "authenticated_http_request", {
                "url": f"http://127.0.0.1:{port}/resource",
                "credential": "primary",
            })
            self.assertTrue(recovered["ok"], recovered)
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)

    def test_expired_pending_renewal_is_deleted_without_probe(self):
        with isolated_runtime(), renew_auth_server() as port:
            ws = self._workspace(port)
            self._establish_renewable_session(ws, port)
            self._expire_private_cookie(ws)
            posts = _RenewAuthHandler.login_posts
            self._leave_pending_renewal(ws, port)
            pending_path = credentials.pending_browser_renewal_path(
                ws.slug, "primary"
            )
            pending = json.loads(pending_path.read_text(encoding="utf-8"))
            pending["created_at"] = (
                time.time() - tools._PENDING_RENEWAL_MAX_AGE_S - 1
            )
            credentials._atomic_private_json(pending_path, pending)
            reserved = credentials.load_attempt_state(ws.slug, "primary")

            with patch(
                "grypton.tools._browser_auth_fresh_probe"
            ) as probe:
                result = dispatch(ws, "authenticated_http_request", {
                    "url": f"http://127.0.0.1:{port}/resource",
                    "credential": "primary",
                })

            self.assertFalse(result["ok"], result)
            probe.assert_not_called()
            self.assertEqual(
                result["data"]["session_maintenance"]["action"],
                "pending-invalidated-expired",
            )
            self.assertEqual(_RenewAuthHandler.login_posts, posts + 1)
            state = credentials.load_attempt_state(ws.slug, "primary")
            self.assertFalse(state["established"])
            self.assertEqual(
                state["refresh_attempted_generation"],
                reserved["proof_generation"],
            )
            self.assertFalse(pending_path.exists())

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
            def __init__(self, url, *, timeout_bootstrap=""):
                self.url = url
                self.wait_until = []
                self.timeout_bootstrap = timeout_bootstrap
                self.bootstrap_timed_out = False

            def on(self, *_args):
                pass

            def goto(self, url, *, wait_until, timeout):
                self.url = url
                self.wait_until.append(wait_until)
                if (
                    url == self.timeout_bootstrap
                    and not self.bootstrap_timed_out
                ):
                    self.bootstrap_timed_out = True
                    raise TimeoutError("bootstrap commit signal was lost")
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

            bootstrap_url = origin + "/login"
            timeout_page = FakePage(
                bootstrap_url, timeout_bootstrap=bootstrap_url
            )
            timeout_context = FakeContext(timeout_page)
            with patch(
                "grypton.tools._isolated_browser_profile"
            ) as isolated_profile, patch(
                "grypton.tools._launch_scoped_browser_context",
                return_value=timeout_context,
            ):
                isolated_profile.return_value.__enter__.return_value = {
                    "identity": "test-browser"
                }
                recovered = tools._browser_auth_fresh_probe(
                    object(), "/unused/chromium", ws, url,
                    phase="control", denied_requests=[], console=[],
                    timeout_ms=5000, bootstrap_url=bootstrap_url,
                )

            self.assertEqual(recovered["status"], 401)
            self.assertTrue(recovered["bootstrap_timeout_recovered"])
            self.assertEqual(timeout_page.wait_until, ["commit", "commit"])

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

    def test_profile_candidate_commits_only_with_successful_browser_proof(self):
        for mode, succeeds in (
            ("success", True), ("failed", False), ("captcha", False),
        ):
            with self.subTest(mode=mode), isolated_runtime(), spa_auth_server(mode) as port:
                ws = self._workspace(port)
                credentials.save_credential(
                    ws.slug, "primary", "09123456789", _SpaAuthHandler.password
                )
                request = self._request(port)
                profile = {
                    "version": 1,
                    "strategy": "browser",
                    "login_url": request["url"],
                    "verify_url": request["verify_url"],
                    "success_marker": request["success_marker"],
                    "username_transform": request["username_transform"],
                    "timeout": request["timeout"],
                    "browser": {
                        "username_selector": "[data-testid='login-username']",
                        "password_selector": "[data-testid='login-password']",
                        "submit_selector": "[data-testid='login-submit']",
                        "verify_headers": {},
                    },
                }

                result = tools.credential_browser_login(
                    ws, **request, _profile_candidate=profile
                )

                self.assertEqual(result["ok"], succeeds, result)
                saved = credentials.load_auth_profile_optional(
                    ws.slug, "primary"
                )
                if succeeds:
                    canonical = credentials.validate_auth_profile(profile)
                    self.assertEqual(saved, canonical)
                    self.assertEqual(
                        credentials.load_attempt_state(ws.slug, "primary")[
                            "proof_profile_revision"
                        ],
                        credentials.auth_profile_revision(canonical),
                    )
                else:
                    self.assertIsNone(saved)

    def test_profile_candidate_preflight_failure_does_not_persist(self):
        with isolated_runtime(), spa_auth_server("success") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            request = self._request(port)
            request["timeout"] = 5
            profile = {
                "version": 1,
                "strategy": "browser",
                "login_url": request["url"],
                "verify_url": request["verify_url"],
                "success_marker": request["success_marker"],
                "username_transform": request["username_transform"],
                "timeout": request["timeout"],
                "browser": {
                    "username_selector": "[data-testid='login-username']",
                    "password_selector": "[data-testid='login-password']",
                    "submit_selector": "[data-testid='login-submit']",
                    "verify_headers": {},
                },
            }
            result = tools.credential_browser_login(
                ws, **request, registration_fields={"#name": 42},
                _profile_candidate=profile,
            )

            self.assertFalse(result["ok"], result)
            self.assertIsNone(
                credentials.load_auth_profile_optional(ws.slug, "primary")
            )
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 0
            )

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

    def test_identifier_signup_allows_one_declared_secondary_origin(self):
        with isolated_runtime(), cross_origin_signup_servers() as ports:
            primary_port, api_port = ports
            ws = self._cross_origin_signup_workspace(primary_port, api_port)
            api_origin = f"http://127.0.0.1:{api_port}"
            credentials.save_credential(
                ws.slug, "signup", _CrossOriginSignupHandler.email,
                "target-password-never-log",
            )
            request_policy.set_origin_policy(
                ws.slug, api_origin,
                headers={
                    "X-UXCam-Researcher": _CrossOriginSignupHandler.email,
                },
                max_requests_per_second=20,
                rate_bucket="uxcam-signup",
            )

            result = tools.credential_browser_begin_step_up(
                ws, credential="signup",
                registration_checkboxes=["#privacy"], timeout=10,
                _profile_candidate=self._cross_origin_signup_profile(
                    primary_port
                ),
                _additional_submission_origins=[api_origin],
                _submission_url=api_origin + "/auth/signup",
                _submission_preflight_urls=[
                    api_origin + "/auth/check-email"
                ],
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["data"]["identifier_submission_requests"], 1)
            self.assertEqual(_CrossOriginSignupHandler.preflight_posts, 1)
            self.assertEqual(_CrossOriginSignupHandler.api_posts, 1)
            self.assertEqual(
                _CrossOriginSignupHandler.mandatory_header_values,
                [
                    _CrossOriginSignupHandler.email,
                    _CrossOriginSignupHandler.email,
                ],
            )
            pending = credentials.load_pending_browser_step_up(
                ws.slug, "signup"
            )
            self.assertEqual(pending["submission_origins"], [
                f"http://127.0.0.1:{primary_port}", api_origin,
            ])
            self.assertNotIn(
                _CrossOriginSignupHandler.email, json.dumps(result)
            )

    def test_identifier_signup_allows_exact_json_cors_preflights(self):
        with isolated_runtime(), cross_origin_signup_servers(
            json_requests=True
        ) as ports:
            primary_port, api_port = ports
            ws = self._cross_origin_signup_workspace(primary_port, api_port)
            api_origin = f"http://127.0.0.1:{api_port}"
            credentials.save_credential(
                ws.slug, "signup", _CrossOriginSignupHandler.email,
                "target-password-never-log",
            )
            request_policy.set_origin_policy(
                ws.slug, api_origin,
                headers={
                    "X-UXCam-Researcher": _CrossOriginSignupHandler.email,
                },
                max_requests_per_second=20,
                rate_bucket="uxcam-json-signup",
            )

            result = tools.credential_browser_begin_step_up(
                ws, credential="signup",
                registration_checkboxes=["#privacy"], timeout=10,
                _profile_candidate=self._cross_origin_signup_profile(
                    primary_port
                ),
                _additional_submission_origins=[api_origin],
                _submission_url=api_origin + "/auth/signup",
                _submission_preflight_urls=[
                    api_origin + "/auth/check-email"
                ],
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(_CrossOriginSignupHandler.preflight_posts, 1)
            self.assertEqual(_CrossOriginSignupHandler.api_posts, 1)
            routed_order = _CrossOriginSignupHandler.request_order
            self.assertIn(routed_order, (
                ["POST /auth/check-email", "POST /auth/signup"],
                [
                    "OPTIONS /auth/check-email", "POST /auth/check-email",
                    "OPTIONS /auth/signup", "POST /auth/signup",
                ],
            ))
            self.assertEqual(
                _CrossOriginSignupHandler.mandatory_header_values,
                [_CrossOriginSignupHandler.email] * len(routed_order),
            )
            self.assertNotIn(
                _CrossOriginSignupHandler.email, json.dumps(result)
            )

    def test_real_chromium_emits_exact_json_cors_sequence(self):
        from playwright.sync_api import sync_playwright

        with cross_origin_signup_servers(json_requests=True) as ports:
            primary_port, api_port = ports
            primary_origin = f"http://127.0.0.1:{primary_port}"
            api_origin = f"http://127.0.0.1:{api_port}"
            check_endpoint = api_origin + "/auth/check-email"
            final_endpoint = api_origin + "/auth/signup"
            cors_state = {
                "active": True,
                "preflight_active": True,
                "preflight_seen": {},
                "cors_preflight_seen": {},
                "seen": 0,
            }
            validation_errors = []

            executable = tools._browser_executable()
            self.assertTrue(executable)
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    headless=True, executable_path=executable,
                    args=["--no-sandbox"],
                )
                try:
                    page = browser.new_page()
                    session = page.context.new_cdp_session(page)

                    def observe_request(event):
                        request = event.get("request") or {}
                        method = str(request.get("method") or "").upper()
                        url = str(request.get("url") or "")
                        try:
                            if method == "OPTIONS":
                                _endpoint, counter_key = (
                                    tools._browser_cors_preflight_contract(
                                        url, method,
                                        str(request.get("postData") or ""),
                                        request.get("headers") or {},
                                        primary_origin=primary_origin,
                                        final_endpoint=final_endpoint,
                                        preflight_endpoints=(check_endpoint,),
                                        state=cors_state,
                                    )
                                )
                                cors_state["cors_preflight_seen"][
                                    counter_key
                                ] = 1
                        except Exception as exc:
                            validation_errors.append(str(exc))

                    session.on("Network.requestWillBeSent", observe_request)
                    session.send("Network.enable")
                    page.goto(primary_origin + "/signup")
                    page.fill("#email", _CrossOriginSignupHandler.email)
                    page.fill("#password", "target-password-never-log")
                    page.check("#privacy")
                    page.click("#create-account")
                    page.locator("#otp").wait_for(timeout=5000)
                finally:
                    browser.close()

            self.assertEqual(validation_errors, [])
            self.assertEqual(_CrossOriginSignupHandler.request_order, [
                "OPTIONS /auth/check-email", "POST /auth/check-email",
                "OPTIONS /auth/signup", "POST /auth/signup",
            ])
            self.assertEqual(cors_state["cors_preflight_seen"], {
                "preflight:" + check_endpoint: 1,
                "final:" + final_endpoint: 1,
            })

    def test_one_page_signup_keeps_email_check_separate_from_final_match(self):
        with isolated_runtime(), cross_origin_signup_servers() as ports:
            primary_port, api_port = ports
            ws = self._cross_origin_signup_workspace(primary_port, api_port)
            primary_origin = f"http://127.0.0.1:{primary_port}"
            api_origin = f"http://127.0.0.1:{api_port}"
            credentials.save_credential(
                ws.slug, "signup", _CrossOriginSignupHandler.email,
                "target-password-never-log",
            )

            result = tools.credential_browser_login(
                ws, primary_origin + "/signup", credential="signup",
                username_selector="#email", password_selector="#password",
                submit_selector="#create-account",
                verify_url=primary_origin + "/profile",
                success_marker="Account profile",
                registration_checkboxes=["#privacy"], timeout=10,
                _profile_candidate=self._cross_origin_signup_profile(
                    primary_port
                ),
                _additional_submission_origins=[api_origin],
                _submission_url=api_origin + "/auth/signup",
                _submission_preflight_urls=[
                    api_origin + "/auth/check-email"
                ],
            )

            self.assertFalse(result["ok"], result)
            self.assertEqual(_CrossOriginSignupHandler.preflight_posts, 1)
            self.assertEqual(_CrossOriginSignupHandler.api_posts, 1)
            self.assertEqual(result["data"]["matched_submission_count"], 1)
            self.assertEqual(
                result["data"]["credential_submission_requests"], 1
            )
            self.assertTrue(result["data"]["step_up"]["pending"])

    def test_identifier_signup_denies_undeclared_and_out_of_scope_origins(self):
        cases = (
            (True, None, "undeclared"),
            (True, "declare", "missing-final-endpoint"),
            (False, "declare", "out-of-scope"),
        )
        for api_in_scope, declaration, label in cases:
            with self.subTest(case=label), isolated_runtime(), \
                    cross_origin_signup_servers() as ports:
                primary_port, api_port = ports
                ws = self._cross_origin_signup_workspace(
                    primary_port, api_port, api_in_scope=api_in_scope
                )
                api_origin = f"http://127.0.0.1:{api_port}"
                credentials.save_credential(
                    ws.slug, "signup", _CrossOriginSignupHandler.email,
                    "target-password-never-log",
                )
                kwargs = {}
                if declaration:
                    kwargs["_additional_submission_origins"] = [api_origin]
                result = tools.credential_browser_begin_step_up(
                    ws, credential="signup",
                    registration_checkboxes=["#privacy"], timeout=5,
                    _profile_candidate=self._cross_origin_signup_profile(
                        primary_port
                    ),
                    **kwargs,
                )

                self.assertFalse(result["ok"], result)
                self.assertEqual(_CrossOriginSignupHandler.preflight_posts, 0)
                self.assertEqual(_CrossOriginSignupHandler.api_posts, 0)
                self.assertEqual(
                    credentials.session_status(ws.slug, "signup")["attempts"],
                    0,
                )

    def test_identifier_signup_blocks_credentials_in_secondary_query(self):
        with isolated_runtime(), \
                cross_origin_signup_servers(query_secret=True) as ports:
            primary_port, api_port = ports
            ws = self._cross_origin_signup_workspace(primary_port, api_port)
            api_origin = f"http://127.0.0.1:{api_port}"
            credentials.save_credential(
                ws.slug, "signup", _CrossOriginSignupHandler.email,
                "target-password-never-log",
            )

            result = tools.credential_browser_begin_step_up(
                ws, credential="signup",
                registration_checkboxes=["#privacy"], timeout=5,
                _profile_candidate=self._cross_origin_signup_profile(
                    primary_port
                ),
                _additional_submission_origins=[api_origin],
                _submission_url=api_origin + "/auth/signup",
                _submission_preflight_urls=[
                    api_origin + "/auth/check-email"
                ],
            )

            self.assertFalse(result["ok"], result)
            self.assertEqual(_CrossOriginSignupHandler.preflight_posts, 1)
            self.assertEqual(_CrossOriginSignupHandler.api_posts, 0)
            self.assertEqual(
                credentials.session_status(ws.slug, "signup")["attempts"], 0
            )
            self.assertNotIn(
                _CrossOriginSignupHandler.email, json.dumps(result)
            )

    def test_identifier_signup_does_not_follow_secondary_redirect(self):
        with isolated_runtime(), cross_origin_signup_servers(
            redirect_final=True
        ) as ports:
            primary_port, api_port = ports
            ws = self._cross_origin_signup_workspace(primary_port, api_port)
            api_origin = f"http://127.0.0.1:{api_port}"
            credentials.save_credential(
                ws.slug, "signup", _CrossOriginSignupHandler.email,
                "target-password-never-log",
            )

            result = tools.credential_browser_begin_step_up(
                ws, credential="signup",
                registration_checkboxes=["#privacy"], timeout=5,
                _profile_candidate=self._cross_origin_signup_profile(
                    primary_port
                ),
                _additional_submission_origins=[api_origin],
                _submission_url=api_origin + "/auth/signup",
                _submission_preflight_urls=[
                    api_origin + "/auth/check-email"
                ],
            )

            self.assertFalse(result["ok"], result)
            self.assertEqual(_CrossOriginSignupHandler.preflight_posts, 1)
            self.assertEqual(_CrossOriginSignupHandler.api_posts, 1)
            self.assertEqual(_CrossOriginSignupHandler.redirect_followups, 0)

    def test_identifier_signup_does_not_follow_cors_preflight_redirect(self):
        from playwright.sync_api import sync_playwright

        with isolated_runtime(), cross_origin_signup_servers(
            json_requests=True, redirect_options=True
        ) as ports:
            primary_port, api_port = ports
            ws = self._cross_origin_signup_workspace(primary_port, api_port)
            primary_origin = f"http://127.0.0.1:{primary_port}"
            api_origin = f"http://127.0.0.1:{api_port}"
            executable = tools._browser_executable()
            self.assertTrue(executable)
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    headless=True, executable_path=executable,
                    args=["--no-sandbox"],
                )
                try:
                    context = browser.new_context()
                    page = context.new_page()
                    capture, _responses = (
                        tools._browser_auth_enable_response_capture(
                            context, page, ws, [],
                            (_CrossOriginSignupHandler.email,),
                            ("target-password-never-log",),
                            submission_url=api_origin + "/auth/signup",
                            preflight_urls=(
                                api_origin + "/auth/check-email",
                            ),
                            reject_submission_redirects=True,
                        )
                    )
                    page.goto(primary_origin + "/signup")
                    page.fill("#email", _CrossOriginSignupHandler.email)
                    page.fill("#password", "target-password-never-log")
                    page.check("#privacy")
                    page.click("#create-account")
                    page.wait_for_timeout(500)
                    capture.send("Fetch.disable")
                finally:
                    browser.close()

            self.assertEqual(
                _CrossOriginSignupHandler.options_requests,
                ["/auth/check-email"],
            )
            self.assertEqual(
                _CrossOriginSignupHandler.options_redirect_followups, 0
            )
            self.assertEqual(_CrossOriginSignupHandler.preflight_posts, 0)
            self.assertEqual(_CrossOriginSignupHandler.api_posts, 0)

    def test_private_cli_style_staged_otp_continuation_reuses_one_attempt(self):
        with isolated_runtime(), spa_auth_server("staged-otp") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            profile = self._status_profile(port)
            profile["username_transform"] = "stored"
            profile["browser"].update({
                "username_selector": "#phone_number",
                "password_selector": "#password",
                "submit_selector": "#submit-btn",
            })
            profile["browser"]["verification"]["login_status"] = 202
            credentials.save_auth_profile(ws.slug, "primary", profile)

            started = tools.credential_browser_begin_step_up(
                ws, credential="primary",
                registration_checkboxes=["#terms", "#privacy"],
                timeout=10,
            )
            self.assertTrue(started["ok"], started)
            self.assertTrue(started["data"]["otp_control_discovered"])
            self.assertEqual(started["data"]["otp_fields"], 6)
            for row in started["data"]["login_api_responses"]:
                self.assertNotIn("body", row)
                self.assertNotIn("url", row)
            serialized_started = json.dumps(started)
            for private in (
                _SpaAuthHandler.identifier_csrf,
                _SpaAuthHandler.identifier_code,
                _SpaAuthHandler.identifier_challenge,
                _SpaAuthHandler.identifier_opaque,
                _SpaAuthHandler.identifier_dom,
                _SpaAuthHandler.identifier_console,
            ):
                self.assertNotIn(private, serialized_started)
                for path in ws.root.rglob("*"):
                    if path.is_file():
                        self.assertNotIn(
                            private,
                            path.read_text(encoding="utf-8", errors="ignore"),
                            path,
                        )

            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["state"],
                "step-up-pending",
            )
            pending = credentials.load_pending_browser_step_up(
                ws.slug, "primary"
            )
            self.assertEqual(pending["attempt"], 1)
            self.assertEqual(pending["profile_revision"],
                             credentials.auth_profile_revision(profile))

            not_submitted = tools.credential_browser_step_up(
                ws, credential="primary", otp=_SpaAuthHandler.otp,
                otp_selector="#missing-otp-control", timeout=10,
            )
            self.assertFalse(not_submitted["ok"], not_submitted)
            self.assertNotIn(_SpaAuthHandler.otp, json.dumps(not_submitted))
            self.assertTrue(
                credentials.load_pending_browser_step_up(
                    ws.slug, "primary"
                )["available"]
            )

            completed = tools.credential_browser_step_up(
                ws, credential="primary", otp=_SpaAuthHandler.otp,
                password_submit_selector="#password-submit-btn", timeout=10,
            )
            self.assertTrue(completed["ok"], completed)
            self.assertEqual(completed["data"]["otp_submission_requests"], 1)
            self.assertEqual(completed["data"]["password_submission_requests"], 1)
            self.assertTrue(completed["data"]["session"]["established"])
            self.assertEqual(completed["data"]["session"]["attempts"], 1)
            self.assertFalse(
                credentials.pending_browser_step_up_path(
                    ws.slug, "primary"
                ).exists()
            )
            for root in (ws.root, config.CREDENTIALS_DIR / ws.slug):
                for path in root.rglob("*"):
                    if path.is_file():
                        self.assertNotIn(
                            _SpaAuthHandler.otp,
                            path.read_text(encoding="utf-8", errors="ignore"),
                            path,
                        )

    def test_memory_only_otp_challenge_is_rebuilt_without_second_identifier_post(self):
        with isolated_runtime(), spa_auth_server("staged-otp-memory") as port:
            ws = self._workspace(port)
            origin = f"http://127.0.0.1:{port}"
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            profile = self._status_profile(port)
            profile["username_transform"] = "stored"
            profile["browser"].update({
                "username_selector": "#phone_number",
                "password_selector": "#password",
                "submit_selector": "#submit-btn",
            })
            profile["browser"]["verification"]["login_status"] = 204
            credentials.save_auth_profile(ws.slug, "primary", profile)

            started = tools.credential_browser_begin_step_up(
                ws, credential="primary",
                registration_checkboxes=["#terms", "#privacy"],
                timeout=10,
                _additional_submission_origins=[],
                _submission_url=origin + "/api/send-otp",
            )

            self.assertTrue(started["ok"], started)
            self.assertEqual(_SpaAuthHandler.login_posts, 1)
            self.assertEqual(_SpaAuthHandler.identifier_preflight_posts, 0)
            pending = credentials.load_pending_browser_step_up(
                ws.slug, "primary"
            )
            self.assertEqual(pending["identifier_replay"]["status"], 204)
            self.assertEqual(
                pending["identifier_replay"]["url"],
                origin + "/api/send-otp",
            )
            completed = tools.credential_browser_step_up(
                ws, credential="primary", otp=_SpaAuthHandler.otp,
                password_submit_selector="#password-submit-btn",
                otp_submission_url=origin + "/api/verify-otp",
                timeout=10,
            )

            self.assertTrue(completed["ok"], completed)
            self.assertTrue(completed["data"]["identifier_replay_used"])
            self.assertEqual(_SpaAuthHandler.login_posts, 1)
            self.assertEqual(_SpaAuthHandler.identifier_preflight_posts, 0)
            self.assertEqual(_SpaAuthHandler.otp_posts, 1)
            self.assertEqual(completed["data"]["session"]["attempts"], 1)
            self.assertTrue(completed["data"]["session"]["established"])

    def test_memory_only_replay_fingerprint_mismatch_never_reposts_identifier(self):
        with isolated_runtime(), spa_auth_server("staged-otp-memory") as port:
            ws = self._workspace(port)
            origin = f"http://127.0.0.1:{port}"
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            profile = self._status_profile(port)
            profile["username_transform"] = "stored"
            profile["browser"].update({
                "username_selector": "#phone_number",
                "password_selector": "#password",
                "submit_selector": "#submit-btn",
            })
            profile["browser"]["verification"]["login_status"] = 204
            credentials.save_auth_profile(ws.slug, "primary", profile)
            started = tools.credential_browser_begin_step_up(
                ws, credential="primary",
                registration_checkboxes=["#terms", "#privacy"], timeout=10,
                _additional_submission_origins=[],
                _submission_url=origin + "/api/send-otp",
            )
            self.assertTrue(started["ok"], started)
            path = credentials.pending_browser_step_up_path(
                ws.slug, "primary"
            )
            record = json.loads(path.read_text(encoding="utf-8"))
            record["identifier_replay"]["body_sha256"] = "0" * 64
            path.write_text(json.dumps(record), encoding="utf-8")

            failed = tools.credential_browser_step_up(
                ws, credential="primary", otp=_SpaAuthHandler.otp,
                password_submit_selector="#password-submit-btn",
                otp_submission_url=origin + "/api/verify-otp", timeout=5,
            )

            self.assertFalse(failed["ok"], failed)
            self.assertEqual(_SpaAuthHandler.login_posts, 1)
            self.assertEqual(_SpaAuthHandler.otp_posts, 0)
            pending = credentials.load_pending_browser_step_up(
                ws.slug, "primary"
            )
            self.assertTrue(pending["available"])
            self.assertFalse(pending["reserved"])

    def test_discovers_grouped_numeric_otp_without_maxlength(self):
        from playwright.sync_api import sync_playwright

        executable = tools._browser_executable()
        self.assertTrue(executable)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True, executable_path=executable,
                args=["--no-sandbox"],
            )
            try:
                page = browser.new_page()
                for challenge_text in (
                    "Enter the verification code",
                    "We sent a code to your email",
                ):
                    page.set_content(
                        f"<form><p>{challenge_text}</p>" + (
                            '<input type="text" inputmode="numeric">' * 6
                        ) + "</form>"
                    )
                    controls = tools._browser_auth_discover_step_up_controls(page)
                    self.assertEqual(
                        controls["otp_selector"],
                        "input[type='text'][inputmode='numeric']",
                    )
                    self.assertEqual(controls["otp_fields"], 6)

                page.set_content(
                    '<input type="text" inputmode="numeric" name="company_size">'
                )
                controls = tools._browser_auth_discover_step_up_controls(page)
                self.assertEqual(controls["otp_selector"], "")
                self.assertEqual(controls["otp_fields"], 0)

                page.set_content(
                    "<p>Enter the verification code</p>"
                    "<form>" + (
                        '<input type="text" inputmode="numeric">' * 3
                    ) + "</form><form>" + (
                        '<input type="text" inputmode="numeric">' * 3
                    ) + "</form>"
                )
                controls = tools._browser_auth_discover_step_up_controls(page)
                self.assertEqual(controls["otp_selector"], "")
                self.assertEqual(controls["otp_fields"], 0)
            finally:
                browser.close()

    def test_step_up_combines_persisted_origin_with_declared_otp_endpoint(self):
        with isolated_runtime(), cross_origin_signup_servers() as ports:
            primary_port, api_port = ports
            ws = self._cross_origin_signup_workspace(primary_port, api_port)
            primary_origin = f"http://127.0.0.1:{primary_port}"
            api_origin = f"http://127.0.0.1:{api_port}"
            credentials.save_credential(
                ws.slug, "signup", _CrossOriginSignupHandler.email,
                "target-password-never-log",
            )
            started = tools.credential_browser_begin_step_up(
                ws, credential="signup",
                registration_checkboxes=["#privacy"], timeout=10,
                _profile_candidate=self._cross_origin_signup_profile(
                    primary_port
                ),
                _additional_submission_origins=[api_origin],
                _submission_url=api_origin + "/auth/signup",
                _submission_preflight_urls=[api_origin + "/auth/check-email"],
            )
            self.assertTrue(started["ok"], started)
            pending = credentials.load_pending_browser_step_up(
                ws.slug, "signup"
            )
            self.assertEqual(
                pending["submission_origins"],
                [primary_origin, api_origin],
            )
            request_policy.set_origin_policy(
                ws.slug, api_origin,
                headers={"X-Researcher": _CrossOriginSignupHandler.email},
                max_requests_per_second=20,
                rate_bucket="otp-matcher-separation",
            )
            expected = {"ok": True, "summary": "continued privately"}
            with patch(
                "grypton.tools._credential_browser_step_up_locked",
                return_value=expected,
            ) as locked:
                continued = tools.credential_browser_step_up(
                    ws, credential="signup", otp="123456", timeout=10,
                    otp_submission_url=api_origin + "/auth/verify-otp",
                )

            self.assertEqual(continued, expected)
            self.assertEqual(
                locked.call_args.kwargs["submission_origins"],
                (primary_origin, api_origin),
            )
            self.assertEqual(
                locked.call_args.kwargs["otp_submission_url"],
                api_origin + "/auth/verify-otp",
            )
            self.assertIn(
                _CrossOriginSignupHandler.email,
                locked.call_args.kwargs["code_secrets"],
            )
            self.assertNotIn(
                _CrossOriginSignupHandler.email,
                locked.call_args.kwargs["code_match_values"],
            )

    def test_step_up_sends_otp_to_distinct_declared_cross_origin_endpoint(self):
        with isolated_runtime(), cross_origin_signup_servers(
            json_requests=True
        ) as ports:
            primary_port, api_port = ports
            ws = self._cross_origin_signup_workspace(primary_port, api_port)
            api_origin = f"http://127.0.0.1:{api_port}"
            credentials.save_credential(
                ws.slug, "signup", _CrossOriginSignupHandler.email,
                "target-password-never-log",
            )
            request_policy.set_origin_policy(
                ws.slug, api_origin,
                headers={
                    "X-UXCam-Researcher": _CrossOriginSignupHandler.email,
                },
                max_requests_per_second=20,
                rate_bucket="cross-origin-otp",
            )
            started = tools.credential_browser_begin_step_up(
                ws, credential="signup",
                registration_checkboxes=["#privacy"], timeout=10,
                _profile_candidate=self._cross_origin_signup_profile(
                    primary_port
                ),
                _additional_submission_origins=[api_origin],
                _submission_url=api_origin + "/auth/signup",
                _submission_preflight_urls=[
                    api_origin + "/auth/check-email"
                ],
            )
            self.assertTrue(started["ok"], started)

            undeclared = tools.credential_browser_step_up(
                ws, credential="signup", otp=_CrossOriginSignupHandler.otp,
                otp_selector="#otp", submit_selector="#verify", timeout=10,
            )
            self.assertFalse(undeclared["ok"], undeclared)
            self.assertEqual(_CrossOriginSignupHandler.otp_posts, 0)
            self.assertTrue(
                credentials.load_pending_browser_step_up(
                    ws.slug, "signup"
                )["available"]
            )

            completed = tools.credential_browser_step_up(
                ws, credential="signup", otp=_CrossOriginSignupHandler.otp,
                otp_selector="#otp", submit_selector="#verify",
                otp_submission_url=api_origin + "/auth/verify-otp",
                timeout=10,
            )

            self.assertTrue(completed["ok"], completed)
            self.assertEqual(
                completed["data"]["otp_submission_requests"], 1
            )
            self.assertTrue(completed["data"]["session"]["established"])
            self.assertEqual(_CrossOriginSignupHandler.otp_posts, 1)
            self.assertIn(
                "POST /auth/verify-otp",
                _CrossOriginSignupHandler.request_order,
            )
            self.assertEqual(
                _CrossOriginSignupHandler.mandatory_header_values[-1],
                _CrossOriginSignupHandler.email,
            )
            self.assertFalse(
                credentials.pending_browser_step_up_path(
                    ws.slug, "signup"
                ).exists()
            )

    def test_unsubmitted_otp_reservation_is_released_for_retry(self):
        with isolated_runtime(), spa_auth_server("staged-otp") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            profile = self._status_profile(port)
            profile["username_transform"] = "stored"
            profile["browser"].update({
                "username_selector": "#phone_number",
                "password_selector": "#password",
                "submit_selector": "#submit-btn",
            })
            profile["browser"]["verification"]["login_status"] = 202
            credentials.save_auth_profile(ws.slug, "primary", profile)

            started = tools.credential_browser_begin_step_up(
                ws, credential="primary",
                registration_checkboxes=["#terms", "#privacy"],
                timeout=10,
            )
            self.assertTrue(started["ok"], started)

            real_step_up_input = tools._browser_step_up_input

            def fail_reserved_fill(page, selector, code, timeout_ms, *, fill=True):
                if fill:
                    raise RuntimeError("synthetic pre-submit failure")
                return real_step_up_input(
                    page, selector, code, timeout_ms, fill=False
                )

            with patch(
                "grypton.tools._browser_step_up_input",
                side_effect=fail_reserved_fill,
            ):
                not_submitted = tools.credential_browser_step_up(
                    ws, credential="primary", otp=_SpaAuthHandler.otp,
                    timeout=10,
                )

            self.assertFalse(not_submitted["ok"], not_submitted)
            self.assertEqual(
                not_submitted["data"]["otp_submission_requests"], 0
            )
            pending = credentials.load_pending_browser_step_up(
                ws.slug, "primary"
            )
            self.assertTrue(pending["available"])
            self.assertFalse(pending["reserved"])

            completed = tools.credential_browser_step_up(
                ws, credential="primary", otp=_SpaAuthHandler.otp,
                password_submit_selector="#password-submit-btn", timeout=10,
            )
            self.assertTrue(completed["ok"], completed)
            self.assertEqual(completed["data"]["otp_submission_requests"], 1)

    def test_temporary_mail_retry_keeps_same_otp_after_zero_transmission(self):
        with isolated_runtime(), spa_auth_server("staged-otp") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            profile = self._status_profile(port)
            profile["username_transform"] = "stored"
            profile["browser"].update({
                "username_selector": "#phone_number",
                "password_selector": "#password",
                "submit_selector": "#submit-btn",
            })
            profile["browser"]["verification"]["login_status"] = 202
            credentials.save_auth_profile(ws.slug, "primary", profile)
            started = tools.credential_browser_begin_step_up(
                ws, credential="primary",
                registration_checkboxes=["#terms", "#privacy"], timeout=10,
            )
            self.assertTrue(started["ok"], started)

            mailbox = {"delivered": False, "polls": 0}

            def poll(*_args, **_kwargs):
                mailbox["polls"] += 1
                if mailbox["delivered"]:
                    return {"ok": True, "data": {"ready": False}}
                return {
                    "ok": True,
                    "data": {
                        "ready": True, "value": _SpaAuthHandler.otp,
                        "_message_id": "same-mail-message",
                    },
                }

            def mark_delivered(*_args):
                mailbox["delivered"] = True

            real_step_up_input = tools._browser_step_up_input

            def fail_reserved_fill(page, selector, code, timeout_ms, *, fill=True):
                if fill:
                    raise RuntimeError("synthetic pre-submit failure")
                return real_step_up_input(
                    page, selector, code, timeout_ms, fill=False
                )

            with patch(
                "grypton.toolserver.temporary_mail.require_mailbox"
            ), patch(
                "grypton.toolserver.temporary_mail.poll", side_effect=poll
            ), patch(
                "grypton.toolserver.temporary_mail.mark_delivered",
                side_effect=mark_delivered,
            ) as mark:
                with patch(
                    "grypton.tools._browser_step_up_input",
                    side_effect=fail_reserved_fill,
                ):
                    first = dispatch(
                        ws, "temporary_account_browser_continue",
                        {"alias": "primary", "browser_timeout": 10},
                    )
                self.assertFalse(first["ok"], first)
                self.assertFalse(mailbox["delivered"])
                mark.assert_not_called()
                self.assertTrue(
                    credentials.load_pending_browser_step_up(
                        ws.slug, "primary"
                    )["available"]
                )

                second = dispatch(
                    ws, "temporary_account_browser_continue", {
                        "alias": "primary", "browser_timeout": 10,
                        "password_submit_selector": "#password-submit-btn",
                    },
                )

            self.assertTrue(second["ok"], second)
            self.assertEqual(mailbox["polls"], 2)
            self.assertTrue(mailbox["delivered"])
            mark.assert_called_once_with(
                ws, "primary", "same-mail-message", "otp"
            )
            self.assertEqual(_SpaAuthHandler.otp_posts, 1)

    def test_temporary_mail_consumes_otp_after_post_send_exception(self):
        with isolated_runtime(), spa_auth_server("staged-otp") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            profile = self._status_profile(port)
            profile["username_transform"] = "stored"
            profile["browser"].update({
                "username_selector": "#phone_number",
                "password_selector": "#password",
                "submit_selector": "#submit-btn",
            })
            profile["browser"]["verification"]["login_status"] = 202
            credentials.save_auth_profile(ws.slug, "primary", profile)
            started = tools.credential_browser_begin_step_up(
                ws, credential="primary",
                registration_checkboxes=["#terms", "#privacy"], timeout=10,
            )
            self.assertTrue(started["ok"], started)

            mailbox = {"delivered": False}

            def poll(*_args, **_kwargs):
                return {
                    "ok": True,
                    "data": {
                        "ready": True, "value": _SpaAuthHandler.otp,
                        "_message_id": "transmitted-mail-message",
                    },
                }

            def mark_delivered(*_args):
                mailbox["delivered"] = True

            real_step_up_input = tools._browser_step_up_input

            def fail_after_transmission(
                page, selector, code, timeout_ms, *, fill=True,
            ):
                result = real_step_up_input(
                    page, selector, code, timeout_ms, fill=fill
                )
                if fill:
                    deadline = time.monotonic() + 5
                    while (
                        _SpaAuthHandler.otp_posts < 1
                        and time.monotonic() < deadline
                    ):
                        page.wait_for_timeout(50)
                    if _SpaAuthHandler.otp_posts != 1:
                        raise AssertionError("OTP request did not cross the route")
                    raise RuntimeError("synthetic post-transmission failure")
                return result

            with patch(
                "grypton.toolserver.temporary_mail.require_mailbox"
            ), patch(
                "grypton.toolserver.temporary_mail.poll", side_effect=poll
            ), patch(
                "grypton.toolserver.temporary_mail.mark_delivered",
                side_effect=mark_delivered,
            ) as mark, patch(
                "grypton.tools._browser_step_up_input",
                side_effect=fail_after_transmission,
            ):
                failed = dispatch(
                    ws, "temporary_account_browser_continue",
                    {"alias": "primary", "browser_timeout": 10},
                )

            self.assertFalse(failed["ok"], failed)
            self.assertEqual(failed["data"]["otp_submission_requests"], 1)
            self.assertEqual(_SpaAuthHandler.otp_posts, 1)
            self.assertTrue(mailbox["delivered"])
            mark.assert_called_once_with(
                ws, "primary", "transmitted-mail-message", "otp"
            )
            self.assertFalse(
                credentials.pending_browser_step_up_path(
                    ws.slug, "primary"
                ).exists()
            )
            self.assertFalse(
                credentials.load_pending_browser_step_up(
                    ws.slug, "primary"
                )["available"]
            )

    def test_ordered_post_otp_onboarding_completes_same_origin_signup(self):
        with isolated_runtime(), spa_auth_server("staged-otp-onboarding") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            profile = self._status_profile(port)
            profile["username_transform"] = "stored"
            profile["browser"].update({
                "username_selector": "#phone_number",
                "password_selector": "#password",
                "submit_selector": "#submit-btn",
            })
            profile["browser"]["verification"]["login_status"] = 202
            credentials.save_auth_profile(ws.slug, "primary", profile)
            started = tools.credential_browser_begin_step_up(
                ws, credential="primary",
                registration_checkboxes=["#terms", "#privacy"], timeout=10,
            )
            self.assertTrue(started["ok"], started)

            stages = [{
                "action_only": True,
                "submit_selector": "#create-workspace",
            }, {
                "fields": {
                    "#workspace-name": "Bounded Research",
                },
                "choice_selectors": [
                    "#company-size-trigger", "#company-small",
                ],
                "submit_selector": "#workspace-next",
            }, {
                "fields": {
                    "#first-name": "Ada",
                    "#last-name": "Lovelace",
                },
                "checkboxes": ["#profile-consent"],
                "submit_selector": "#name-next",
            }, {
                "action_only": True,
                "submit_selector": "#skip-invites",
            }, {
                "action_only": True,
                "submit_selector": "#skip-support",
            }]
            completed = tools.credential_browser_step_up(
                ws, credential="primary", otp=_SpaAuthHandler.otp,
                post_otp_stages=stages, timeout=10,
            )

            self.assertTrue(completed["ok"], completed)
            self.assertEqual(completed["data"]["otp_submission_requests"], 1)
            self.assertEqual(completed["data"]["password_submission_requests"], 0)
            self.assertEqual(completed["data"]["post_otp_stages_completed"], 5)
            self.assertEqual(
                completed["data"]["post_otp_stage_submission_requests"],
                [0, 1, 1, 0, 0],
            )
            self.assertEqual(_SpaAuthHandler.otp_posts, 1)
            self.assertEqual(_SpaAuthHandler.onboarding_workspace_posts, 1)
            self.assertEqual(_SpaAuthHandler.onboarding_name_posts, 1)
            serialized = json.dumps(completed)
            for private in (
                _SpaAuthHandler.otp, "Bounded Research", "Ada", "Lovelace",
            ):
                self.assertNotIn(private, serialized)
            self.assertTrue(completed["data"]["session"]["established"])

    def test_identifier_otp_preflight_defers_profile_and_allows_corrected_retry(self):
        with isolated_runtime(), spa_auth_server("staged-otp") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            profile = self._status_profile(port)
            profile["username_transform"] = "stored"
            profile["browser"].update({
                "username_selector": "#phone_number",
                "password_selector": "#password",
                "submit_selector": "#submit-btn",
            })
            profile["browser"]["verification"]["login_status"] = 202
            result = tools.credential_browser_begin_step_up(
                ws, credential="primary",
                registration_fields={"#missing-registration-field": "research"},
                timeout=5,
                _profile_candidate=profile,
            )

            self.assertFalse(result["ok"], result)
            self.assertIsNone(
                credentials.load_auth_profile_optional(ws.slug, "primary")
            )
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 0
            )
            self.assertEqual(_SpaAuthHandler.login_posts, 0)

            corrected = tools.credential_browser_begin_step_up(
                ws, credential="primary",
                registration_checkboxes=["#terms", "#privacy"],
                timeout=10,
                _profile_candidate=profile,
            )
            self.assertTrue(corrected["ok"], corrected)
            saved = credentials.load_auth_profile_optional(ws.slug, "primary")
            self.assertEqual(saved, credentials.validate_auth_profile(profile))
            pending = credentials.load_pending_browser_step_up(
                ws.slug, "primary"
            )
            self.assertEqual(
                pending["profile_revision"], credentials.auth_profile_revision(saved)
            )
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 1
            )
            self.assertEqual(_SpaAuthHandler.login_posts, 1)

    def test_identifier_otp_rechecks_dynamic_captcha_before_profile_or_attempt(self):
        with isolated_runtime(), spa_auth_server("staged-otp-dynamic-captcha") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            profile = self._status_profile(port)
            profile["username_transform"] = "stored"
            profile["browser"].update({
                "username_selector": "#phone_number",
                "password_selector": "#password",
                "submit_selector": "#submit-btn",
            })
            profile["browser"]["verification"]["login_status"] = 202

            result = tools.credential_browser_begin_step_up(
                ws, credential="primary",
                registration_checkboxes=["#terms", "#privacy"],
                timeout=5,
                _profile_candidate=profile,
            )

            self.assertFalse(result["ok"], result)
            self.assertIn("CAPTCHA", result["summary"])
            self.assertIsNone(
                credentials.load_auth_profile_optional(ws.slug, "primary")
            )
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 0
            )
            self.assertEqual(_SpaAuthHandler.login_posts, 0)

    def test_identifier_otp_rechecks_captcha_after_identifier_fill_before_click(self):
        with isolated_runtime(), spa_auth_server("staged-otp-identifier-captcha") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            profile = self._status_profile(port)
            profile["username_transform"] = "stored"
            profile["browser"].update({
                "username_selector": "#phone_number",
                "password_selector": "#password",
                "submit_selector": "#submit-btn",
            })
            profile["browser"]["verification"]["login_status"] = 202

            result = tools.credential_browser_begin_step_up(
                ws, credential="primary",
                registration_checkboxes=["#terms", "#privacy"],
                timeout=5,
                _profile_candidate=profile,
            )

            self.assertFalse(result["ok"], result)
            self.assertIn("CAPTCHA", result["summary"])
            self.assertEqual(result["data"]["identifier_submission_requests"], 0)
            self.assertEqual(result["data"]["blocked_pre_submit_requests"], 1)
            self.assertEqual(_SpaAuthHandler.identifier_preflight_posts, 0)
            self.assertEqual(_SpaAuthHandler.login_posts, 0)
            self.assertIsNone(
                credentials.load_auth_profile_optional(ws.slug, "primary")
            )
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 0
            )

    def test_identifier_gate_blocks_all_requests_until_expected_submission(self):
        for mode in ("staged-otp-oninput-header", "staged-otp-armed-timer"):
            with self.subTest(mode=mode), isolated_runtime(), spa_auth_server(mode) as port:
                ws = self._workspace(port)
                credentials.save_credential(
                    ws.slug, "primary", "09123456789", _SpaAuthHandler.password
                )
                profile = self._status_profile(port)
                profile["username_transform"] = "stored"
                profile["browser"].update({
                    "username_selector": "#phone_number",
                    "password_selector": "#password",
                    "submit_selector": "#submit-btn",
                })
                profile["browser"]["verification"]["login_status"] = 202

                result = tools.credential_browser_begin_step_up(
                    ws, credential="primary",
                    registration_checkboxes=["#terms", "#privacy"],
                    timeout=10, _profile_candidate=profile,
                )

                self.assertTrue(result["ok"], result)
                self.assertEqual(_SpaAuthHandler.identifier_preflight_posts, 0)
                self.assertEqual(_SpaAuthHandler.login_posts, 1)
                self.assertGreaterEqual(
                    result["data"]["blocked_pre_submit_requests"], 1
                )
                self.assertEqual(
                    result["data"]["identifier_submission_requests"], 1
                )
                self.assertEqual(
                    credentials.session_status(ws.slug, "primary")["state"],
                    "step-up-pending",
                )

    def test_split_otp_fields_are_counted_as_one_submission(self):
        with isolated_runtime(), spa_auth_server("staged-otp-split") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            profile = self._status_profile(port)
            profile["username_transform"] = "stored"
            profile["browser"].update({
                "username_selector": "#phone_number",
                "password_selector": "#password",
                "submit_selector": "#submit-btn",
            })
            profile["browser"]["verification"]["login_status"] = 202
            credentials.save_auth_profile(ws.slug, "primary", profile)
            started = tools.credential_browser_begin_step_up(
                ws, credential="primary",
                registration_checkboxes=["#terms", "#privacy"], timeout=10,
            )
            self.assertTrue(started["ok"], started)

            completed = tools.credential_browser_step_up(
                ws, credential="primary", otp=_SpaAuthHandler.otp,
                password_submit_selector="#password-submit-btn", timeout=10,
            )

            self.assertTrue(completed["ok"], completed)
            self.assertEqual(completed["data"]["otp_submission_requests"], 1)
            self.assertEqual(_SpaAuthHandler.otp_posts, 1)

    def test_split_otp_blocks_per_digit_input_requests(self):
        with isolated_runtime(), spa_auth_server("staged-otp-partial") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            profile = self._status_profile(port)
            profile["username_transform"] = "stored"
            profile["browser"].update({
                "username_selector": "#phone_number",
                "password_selector": "#password",
                "submit_selector": "#submit-btn",
            })
            profile["browser"]["verification"]["login_status"] = 202
            credentials.save_auth_profile(ws.slug, "primary", profile)
            started = tools.credential_browser_begin_step_up(
                ws, credential="primary",
                registration_checkboxes=["#terms", "#privacy"], timeout=10,
            )
            self.assertTrue(started["ok"], started)

            completed = tools.credential_browser_step_up(
                ws, credential="primary", otp=_SpaAuthHandler.otp,
                password_submit_selector="#password-submit-btn", timeout=10,
            )

            self.assertTrue(completed["ok"], completed)
            self.assertEqual(_SpaAuthHandler.partial_otp_posts, 0)
            self.assertEqual(_SpaAuthHandler.otp_posts, 1)
            self.assertEqual(completed["data"]["otp_submission_requests"], 1)

    def test_password_stage_blocks_delayed_old_otp_submission(self):
        with isolated_runtime(), spa_auth_server("staged-otp-delayed") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            profile = self._status_profile(port)
            profile["username_transform"] = "stored"
            profile["browser"].update({
                "username_selector": "#phone_number",
                "password_selector": "#password",
                "submit_selector": "#submit-btn",
            })
            profile["browser"]["verification"]["login_status"] = 202
            credentials.save_auth_profile(ws.slug, "primary", profile)
            started = tools.credential_browser_begin_step_up(
                ws, credential="primary",
                registration_checkboxes=["#terms", "#privacy"], timeout=10,
            )
            self.assertTrue(started["ok"], started)

            completed = tools.credential_browser_step_up(
                ws, credential="primary", otp=_SpaAuthHandler.otp,
                password_submit_selector="#password-submit-btn", timeout=10,
            )

            self.assertTrue(completed["ok"], completed)
            self.assertEqual(_SpaAuthHandler.otp_posts, 1)
            self.assertEqual(completed["data"]["password_submission_requests"], 1)

    def test_split_otp_matcher_rejects_unrelated_numeric_fields(self):
        state = {
            "username_values": (_SpaAuthHandler.otp,),
            "password_values": (_SpaAuthHandler.otp,),
            "ordered_digit_values": tuple(_SpaAuthHandler.otp),
        }
        self.assertTrue(tools._browser_submission_matches(
            "https://example.test/verify",
            "year=2026&attempt=1&d1=8&d2=3&d3=9&d4=2&d5=0&d6=1",
            state,
        ))
        self.assertFalse(tools._browser_submission_matches(
            "https://example.test/verify",
            "year=8&month=3&day=9&hour=2&minute=0&attempt=1",
            state,
        ))

    def test_submission_matcher_requires_exact_body_scalars_and_rejects_query(self):
        state = {
            "username_values": ("app",),
            "password_values": ("secret",),
        }
        self.assertFalse(tools._browser_submission_matches(
            "https://app.example.test/app/login", "", state,
        ))
        self.assertFalse(tools._browser_submission_matches(
            "https://app.example.test/login?identifier=app&password=secret",
            "", state, method="GET",
        ))
        self.assertFalse(tools._browser_submission_matches(
            "https://app.example.test/login",
            '{"username":"happy-app-user","password":"mysecretvalue"}',
            state, content_type="application/json",
        ))
        self.assertTrue(tools._browser_submission_matches(
            "https://app.example.test/login",
            '{"username":"app","password":"secret"}', state,
            content_type="application/json",
        ))
        self.assertFalse(tools._browser_submission_matches(
            "https://app.example.test/login",
            '--x\r\nContent-Disposition: form-data; name="username"\r\n\r\n'
            'app\r\n--x\r\nContent-Disposition: form-data; name="password"'
            '\r\n\r\nsecret\r\n--x--\r\n', state,
            content_type="multipart/form-data; boundary=x",
        ))

    def test_identifier_gate_stays_armed_when_request_policy_blocks_submit(self):
        class Context:
            callback = None

            def route(self, _pattern, callback):
                self.callback = callback

        class Chromium:
            def __init__(self, context):
                self.context = context

            def launch_persistent_context(self, **_kwargs):
                return self.context

        class Playwright:
            def __init__(self, context):
                self.chromium = Chromium(context)

        class Request:
            url = "https://example.test/submit"
            post_data = '{"identifier":"app"}'
            headers = {"Content-Type": "application/json"}

        class Route:
            request = Request()
            aborted = False
            continued = False

            def abort(self, _reason):
                self.aborted = True

            def continue_(self, **_kwargs):
                self.continued = True

        context = Context()
        workspace = type(
            "WorkspaceStub", (), {"slug": "browser-gate-policy-test"}
        )()
        state = {
            "active": True,
            "username_values": ("app",),
            "password_values": ("app",),
            "seen": 0,
            "blocked": 0,
            "block_all_until_submission": True,
            "blocked_before_active": 0,
        }
        with (
            patch("grypton.tools._private_browser_proxy", return_value=""),
            patch("grypton.tools.check_url_scope", return_value=(True, "")),
            patch(
                "grypton.tools.request_policy.policy_for_url",
                side_effect=tools.request_policy.RequestPolicyError(
                    "synthetic policy failure"
                ),
            ),
        ):
            tools._launch_scoped_browser_context(
                Playwright(context), {
                    "profile": "/tmp/profile-fixture",
                    "executable": "/bin/true",
                    "environment": {},
                }, workspace, [],
                credential_submission_state=state,
            )
            route = Route()
            context.callback(route)

        self.assertTrue(route.aborted)
        self.assertFalse(route.continued)
        self.assertEqual(state["seen"], 0)
        self.assertTrue(state["block_all_until_submission"])

    def test_cors_preflight_route_is_exact_bounded_and_one_shot(self):
        class Context:
            callback = None

            def route(self, _pattern, callback):
                self.callback = callback

        class Chromium:
            def __init__(self, context):
                self.context = context

            def launch_persistent_context(self, **_kwargs):
                return self.context

        class Playwright:
            def __init__(self, context):
                self.chromium = Chromium(context)

        class Request:
            def __init__(self, url, *, headers=None, body="",
                         method="OPTIONS", public_headers=None):
                self.url = url
                self.post_data = body
                self.method = method
                self.headers = dict(
                    public_headers
                    if public_headers is not None else {"Accept": "*/*"}
                )
                self._complete_headers = dict(headers or {})
                self.redirected_from = None

            def all_headers(self):
                return dict(self._complete_headers)

        class Route:
            def __init__(self, url, *, headers=None, body="",
                         method="OPTIONS", public_headers=None):
                self.request = Request(
                    url, headers=headers, body=body, method=method,
                    public_headers=public_headers,
                )
                self.aborted = False
                self.continued = False
                self.continue_headers = None

            def abort(self, _reason):
                self.aborted = True

            def continue_(self, **kwargs):
                self.continued = True
                self.continue_headers = kwargs.get("headers")

        primary_origin = "https://primary.example:443"
        api_origin = "https://api.example:443"
        check_endpoint = api_origin + "/auth/check-email"
        final_endpoint = api_origin + "/auth/signup"
        valid_headers = {
            "Origin": primary_origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
            "Sec-Fetch-Mode": "cors",
        }
        state = {
            "active": True,
            "preflight_active": True,
            "preflight_seen": {},
            "cors_preflight_seen": {},
            "username_values": ("researcher@example.test",),
            "password_values": ("researcher@example.test",),
            "preflight_matcher": {
                "username_values": ("researcher@example.test",),
                "password_values": ("researcher@example.test",),
            },
            "preflight_forbidden_values": ("private-password",),
            "seen": 0,
            "blocked": 0,
            "block_all_until_submission": True,
            "block_before_active": True,
            "blocked_before_active": 0,
            "blocked_retired": 0,
            "retired_matchers": [],
            "reject_unsupported": True,
        }
        context = Context()
        workspace = type("WorkspaceStub", (), {"slug": "cors-route-test"})()
        with (
            patch("grypton.tools._private_browser_proxy", return_value=""),
            patch("grypton.tools.check_url_scope", return_value=(True, "")),
            patch(
                "grypton.tools.request_policy.policy_for_url",
                return_value=(api_origin, {}),
            ),
            patch(
                "grypton.tools.request_policy.resolved_headers",
                return_value={"X-UXCam-Researcher": "private-policy-value"},
            ),
            patch(
                "grypton.tools.request_policy.enforce_rate_limit"
            ) as enforce_rate_limit,
        ):
            tools._launch_scoped_browser_context(
                Playwright(context), {
                    "profile": "/tmp/profile-fixture",
                    "executable": "/bin/true",
                    "environment": {},
                }, workspace, [], credential_submission_state=state,
                credential_submission_origins=(primary_origin, api_origin),
                credential_submission_url=final_endpoint,
                credential_preflight_urls=(check_endpoint,),
                exact_origin=primary_origin,
            )

            allowed = Route(check_endpoint, headers=valid_headers)
            context.callback(allowed)
            repeated = Route(check_endpoint, headers=valid_headers)
            context.callback(repeated)
            undeclared_endpoint = Route(
                api_origin + "/auth/other", headers=valid_headers
            )
            context.callback(undeclared_endpoint)
            undeclared_origin = Route(
                "https://other.example/auth/check-email", headers=valid_headers
            )
            context.callback(undeclared_origin)
            malformed_headers = Route(check_endpoint, headers={
                **valid_headers,
                "Access-Control-Request-Headers": (
                    "content-type, Content-Type"
                ),
            })
            context.callback(malformed_headers)
            query = Route(check_endpoint + "?probe=1", headers=valid_headers)
            context.callback(query)
            body = Route(check_endpoint, headers=valid_headers, body="probe=1")
            context.callback(body)
            credential_header = Route(check_endpoint, headers={
                **valid_headers, "Cookie": "renderer-session=secret",
            })
            context.callback(credential_header)
            secret_header = Route(
                check_endpoint,
                headers={
                    "Content-Type": "application/json",
                    "X-Leak": "prefix-private-password-suffix",
                },
                public_headers={
                    "Content-Type": "application/json",
                    "X-Leak": "prefix-private-password-suffix",
                },
                body=json.dumps({"email": "researcher@example.test"}),
                method="POST",
            )
            context.callback(secret_header)
            self.assertEqual(state["seen"], 0)
            self.assertTrue(state["block_all_until_submission"])

            state.update({
                "active": True,
                "preflight_active": False,
                "username_values": ("later-stage-private-value",),
                "password_values": ("later-stage-private-value",),
                "seen": 0,
                "blocked": 0,
                "block_all_until_submission": True,
                "blocked_before_active": 0,
                "blocked_retired": 0,
                "retired_matchers": [],
                "submission_url": "",
                "primary_origin_only": True,
            })
            retired_secondary = Route(
                api_origin + "/arbitrary/exfil",
                headers={"Content-Type": "application/json"},
                public_headers={"Content-Type": "application/json"},
                body=json.dumps({
                    "password": "later-stage-private-value",
                }),
                method="POST",
            )
            context.callback(retired_secondary)
            allowed_primary = Route(
                primary_origin + "/onboarding/profile",
                headers={"Content-Type": "application/json"},
                public_headers={"Content-Type": "application/json"},
                body=json.dumps({
                    "password": "later-stage-private-value",
                }),
                method="POST",
            )
            context.callback(allowed_primary)

        self.assertTrue(allowed.continued)
        self.assertFalse(allowed.aborted)
        self.assertEqual(
            allowed.continue_headers["X-UXCam-Researcher"],
            "private-policy-value",
        )
        self.assertEqual(
            allowed.continue_headers["Origin"], primary_origin
        )
        self.assertEqual(
            allowed.continue_headers["Access-Control-Request-Method"],
            "POST",
        )
        self.assertEqual(
            allowed.continue_headers["Access-Control-Request-Headers"],
            "content-type",
        )
        self.assertEqual(state["preflight_seen"], {})
        self.assertEqual(
            state["cors_preflight_seen"],
            {"preflight:" + check_endpoint: 1},
        )
        self.assertTrue(all(route.aborted for route in (
            repeated, undeclared_endpoint, undeclared_origin,
            malformed_headers, query, body, credential_header, secret_header,
            retired_secondary,
        )))
        self.assertTrue(allowed_primary.continued)
        self.assertFalse(allowed_primary.aborted)
        self.assertEqual(state["seen"], 1)
        self.assertEqual(enforce_rate_limit.call_count, 2)

    def test_one_shot_route_gate_rejects_partial_unsupported_and_retired_stages(self):
        class Context:
            callback = None

            def route(self, _pattern, callback):
                self.callback = callback

        class Chromium:
            def __init__(self, context):
                self.context = context

            def launch_persistent_context(self, **_kwargs):
                return self.context

        class Playwright:
            def __init__(self, context):
                self.chromium = Chromium(context)

        class Request:
            def __init__(self, url, body, *, method="POST", content_type=""):
                self.url = url
                self.post_data = body
                self.method = method
                self.headers = {
                    "User-Agent": "Chromium/149.2",
                    "Referer": "https://example.test:8392/form",
                }
                if content_type:
                    self.headers["Content-Type"] = content_type

        class Route:
            def __init__(self, *args, **kwargs):
                self.request = Request(*args, **kwargs)
                self.aborted = False
                self.continued = False

            def abort(self, _reason):
                self.aborted = True

            def continue_(self, **_kwargs):
                self.continued = True

        context = Context()
        workspace = type("WorkspaceStub", (), {"slug": "one-shot-gate-test"})()
        state = {
            "active": True,
            "username_values": (_SpaAuthHandler.otp,),
            "password_values": (_SpaAuthHandler.otp,),
            "ordered_digit_values": tuple(_SpaAuthHandler.otp),
            "seen": 0,
            "blocked": 0,
            "block_all_until_submission": True,
            "block_before_active": True,
            "blocked_before_active": 0,
            "blocked_retired": 0,
            "retired_matchers": [],
            "reject_unsupported": True,
        }
        with (
            patch("grypton.tools._private_browser_proxy", return_value=""),
            patch("grypton.tools.check_url_scope", return_value=(True, "")),
            patch(
                "grypton.tools.request_policy.policy_for_url",
                return_value=("https://example.test:443", {}),
            ),
            patch("grypton.tools.request_policy.resolved_headers", return_value={}),
            patch("grypton.tools.request_policy.enforce_rate_limit"),
        ):
            tools._launch_scoped_browser_context(
                Playwright(context), {
                    "profile": "/tmp/profile-fixture",
                    "executable": "/bin/true",
                    "environment": {},
                }, workspace, [], credential_submission_state=state,
                exact_origin="https://example.test:443",
            )

            partials = []
            for index, character in enumerate(_SpaAuthHandler.otp):
                route = Route(
                    "https://example.test/otp",
                    f"otp-input-{index}={character}",
                    content_type="application/x-www-form-urlencoded",
                )
                context.callback(route)
                partials.append(route)
            query = Route(
                "https://example.test/otp?otp=" + _SpaAuthHandler.otp,
                "", method="GET",
            )
            context.callback(query)
            multipart = Route(
                "https://example.test/otp",
                "--x\r\nContent-Disposition: form-data; name=\"otp\"\r\n\r\n"
                + _SpaAuthHandler.otp + "\r\n--x--\r\n",
                content_type="multipart/form-data; boundary=x",
            )
            context.callback(multipart)
            expected = Route(
                "https://example.test/otp",
                '{"otp":["8","3","9","2","0","1"]}',
                content_type="application/json",
            )
            context.callback(expected)
            multipart_after_submission = Route(
                "https://example.test/otp",
                "--x\r\nContent-Disposition: form-data; name=\"otp\"\r\n\r\n"
                + _SpaAuthHandler.otp + "\r\n--x--\r\n",
                content_type="multipart/form-data; boundary=x",
            )
            context.callback(multipart_after_submission)
            duplicate = Route(
                "https://example.test/otp", "otp=" + _SpaAuthHandler.otp,
                content_type="application/x-www-form-urlencoded",
            )
            context.callback(duplicate)

            tools._browser_retarget_submission_state(
                state, (_SpaAuthHandler.password,)
            )
            state["active"] = True
            delayed_otp = Route(
                "https://example.test/otp", "otp=" + _SpaAuthHandler.otp,
                content_type="application/x-www-form-urlencoded",
            )
            context.callback(delayed_otp)
            substring = Route(
                "https://example.test/password",
                '{"telemetry":"prefix-browser-password-never-log-suffix"}',
                content_type="application/json",
            )
            context.callback(substring)
            password = Route(
                "https://example.test/password",
                json.dumps({"password": _SpaAuthHandler.password}),
                content_type="application/json",
            )
            context.callback(password)

        self.assertTrue(all(route.aborted for route in partials))
        self.assertEqual(state["seen"], 1)
        self.assertTrue(query.aborted)
        self.assertTrue(multipart.aborted)
        self.assertTrue(expected.continued)
        self.assertTrue(multipart_after_submission.aborted)
        self.assertTrue(duplicate.aborted)
        self.assertTrue(delayed_otp.aborted)
        self.assertTrue(substring.aborted)
        self.assertTrue(password.continued)

    def test_identifier_otp_candidate_rolls_back_when_pending_save_fails(self):
        with isolated_runtime(), spa_auth_server("staged-otp") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            profile = self._status_profile(port)
            profile["username_transform"] = "stored"
            profile["browser"].update({
                "username_selector": "#phone_number",
                "password_selector": "#password",
                "submit_selector": "#submit-btn",
            })
            profile["browser"]["verification"]["login_status"] = 202

            with patch.object(
                credentials, "save_pending_browser_step_up",
                side_effect=credentials.CredentialError(
                    "synthetic pending failure"
                ),
            ):
                result = tools.credential_browser_begin_step_up(
                    ws, credential="primary",
                    registration_checkboxes=["#terms", "#privacy"],
                    timeout=10, _profile_candidate=profile,
                )

            self.assertFalse(result["ok"], result)
            self.assertIsNone(
                credentials.load_auth_profile_optional(ws.slug, "primary")
            )
            self.assertFalse(
                credentials.pending_browser_step_up_path(
                    ws.slug, "primary"
                ).exists()
            )
            state = credentials.load_attempt_state(ws.slug, "primary")
            self.assertEqual(state["attempts"], 1)
            self.assertIn("MFA/OTP", state["blocked_reason"])

    def test_split_otp_matcher_orders_indices_and_accepts_alphanumeric_codes(self):
        self.assertEqual(
            tools._browser_split_code_values("AB12", 4), tuple("AB12")
        )
        with self.assertRaisesRegex(ValueError, "ASCII letters or digits"):
            tools._browser_split_code_values("A-12", 4)
        state = {
            "username_values": ("AB12",),
            "password_values": ("AB12",),
            "ordered_digit_values": tuple("AB12"),
        }
        self.assertTrue(tools._browser_submission_matches(
            "https://example.test/verify",
            "code4=2&code2=B&code1=A&code3=1",
            state,
        ))
        for post_data, content_type in (
            (
                "otp-input-0=A&otp-input-1=B&otp-input-2=1&otp-input-3=2",
                "application/x-www-form-urlencoded",
            ),
            (
                "otp-input-3=A&otp-input-2=B&otp-input-1=1&otp-input-0=2",
                "application/x-www-form-urlencoded",
            ),
            ('{"otp":["A","B","1","2"]}', "application/json"),
        ):
            with self.subTest(post_data=post_data):
                self.assertTrue(tools._browser_submission_matches(
                    "https://example.test/verify", post_data, state,
                    content_type=content_type,
                ))
        for post_data in (
            "code1=A&code1=B&code3=1&code4=2",
            "code1=A&code2=B&code4=1&code5=2",
            "code0=2&code1=1&code2=B&code3=A",
            '{"code":["2","1","B","A"]}',
        ):
            with self.subTest(post_data=post_data):
                self.assertFalse(tools._browser_submission_matches(
                    "https://example.test/verify", post_data, state,
                ))

    def test_password_submission_state_does_not_reuse_split_otp_matcher(self):
        state = {
            "active": False,
            "username_values": ("AB12",),
            "password_values": ("AB12",),
            "ordered_digit_values": tuple("AB12"),
            "seen": 1,
            "blocked": 0,
        }
        tools._browser_retarget_submission_state(
            state, (_SpaAuthHandler.password,)
        )

        self.assertFalse(tools._browser_submission_matches(
            "https://example.test/password",
            "code1=A&code2=B&code3=1&code4=2",
            state,
        ))

    def test_browser_login_retains_discovered_step_up_for_private_cli(self):
        with isolated_runtime(), spa_auth_server("otp") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            profile = self._status_profile(port)
            profile["browser"]["verification"]["login_status"] = 202
            browser = profile["browser"]

            result = tools.credential_browser_login(
                ws, profile["login_url"], credential="primary",
                username_transform=profile["username_transform"],
                username_selector=browser["username_selector"],
                password_selector=browser["password_selector"],
                submit_selector=browser["submit_selector"],
                verify_url=profile["verify_url"],
                verification=browser["verification"], timeout=profile["timeout"],
                _profile_candidate=profile,
            )

            self.assertFalse(result["ok"], result)
            self.assertTrue(result["data"]["step_up"]["pending"])
            saved = credentials.load_auth_profile_optional(ws.slug, "primary")
            self.assertEqual(saved, credentials.validate_auth_profile(profile))
            self.assertTrue(
                result["data"]["step_up"]["otp_control_discovered"]
            )
            self.assertEqual(result["data"]["step_up"]["otp_fields"], 6)
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["state"],
                "step-up-pending",
            )

    def test_profile_candidate_rolls_back_when_pending_step_up_save_fails(self):
        with isolated_runtime(), spa_auth_server("otp") as port:
            ws = self._workspace(port)
            credentials.save_credential(
                ws.slug, "primary", "09123456789", _SpaAuthHandler.password
            )
            profile = self._status_profile(port)
            profile["browser"]["verification"]["login_status"] = 202
            browser = profile["browser"]
            with patch.object(
                credentials, "save_pending_browser_step_up",
                side_effect=credentials.CredentialError("synthetic pending failure"),
            ):
                result = tools.credential_browser_login(
                    ws, profile["login_url"], credential="primary",
                    username_transform=profile["username_transform"],
                    username_selector=browser["username_selector"],
                    password_selector=browser["password_selector"],
                    submit_selector=browser["submit_selector"],
                    verify_url=profile["verify_url"],
                    verification=browser["verification"],
                    timeout=profile["timeout"], _profile_candidate=profile,
                )

            self.assertFalse(result["ok"], result)
            self.assertFalse(result["data"]["step_up"]["pending"])
            self.assertIsNone(
                credentials.load_auth_profile_optional(ws.slug, "primary")
            )
            self.assertFalse(
                credentials.pending_browser_step_up_path(
                    ws.slug, "primary"
                ).exists()
            )

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

    def test_private_browser_proxy_separates_credentials_from_server(self):
        with patch.dict(os.environ, {
            "GRYPTON_EGRESS_PROXY": (
                "http://proxy-user:proxy-password@127.0.0.1:8097"
            ),
        }):
            proxy = tools._private_browser_proxy()
            safe_error = tools._browser_safe_error(RuntimeError(
                "proxy-user proxy-password 127.0.0.1:8097"
            ))
        self.assertEqual(proxy["server"], "http://127.0.0.1:8097")
        self.assertEqual(proxy["username"], "proxy-user")
        self.assertEqual(proxy["password"], "proxy-password")
        self.assertNotIn("proxy-user", proxy["server"])
        self.assertNotIn("proxy-password", proxy["server"])
        self.assertNotIn("proxy-user", safe_error)
        self.assertNotIn("proxy-password", safe_error)
        self.assertNotIn("127.0.0.1", safe_error)

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
        self.assertNotIn("credential_browser_step_up", names)
        self.assertNotIn("credential_browser_begin_step_up", names)


if __name__ == "__main__":
    unittest.main()
