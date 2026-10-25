from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
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
            yield


class FakeLocator:
    def __init__(self, page, selector):
        self.page = page
        self.selector = selector

    def click(self):
        self.page.calls.append(("click", self.selector))

    def fill(self, value):
        self.page.calls.append(("fill", self.selector, value))
        self.page.echo = value

    def select_option(self, values):
        self.page.calls.append(("select", self.selector, list(values)))

    def check(self):
        self.page.calls.append(("check", self.selector))

    def uncheck(self):
        self.page.calls.append(("uncheck", self.selector))

    def press(self, key):
        self.page.calls.append(("press", self.selector, key))

    def inner_text(self):
        return self.page.inspect_text or f"visible {self.page.echo}"

    def set_input_files(self, files):
        self.page.uploads = files


class FakePage:
    def __init__(self, context):
        self.context = context
        self.url = "about:blank"
        self.calls = []
        self.echo = ""
        self.inspect_text = ""
        self.title_text = "Workflow page"
        self.uploads = []

    def set_default_timeout(self, value):
        self.calls.append(("timeout", value))

    def goto(self, url, **_kwargs):
        self.url = url
        if url.endswith("/secret"):
            self.inspect_text = '{"token":"prior-inspect-secret"}'
            self.title_text = '{"token":"prior-title-secret"}'
        elif url.endswith("/clean"):
            self.echo = ""
            self.inspect_text = "clean"
            self.title_text = "Clean page"
        request = SimpleNamespace(method="GET", url=url, resource_type="document")
        response = SimpleNamespace(status=200, request=request)
        self.context.emit("request", request)
        self.context.emit("response", response)
        return response

    def locator(self, selector):
        return FakeLocator(self, selector)

    def wait_for_timeout(self, value):
        self.calls.append(("wait", value))

    def title(self):
        return self.title_text

    def content(self):
        if not self.context.transport_alive:
            raise RuntimeError("browser transport is closed")
        return f"<html><body>{self.echo}</body></html>"

    def evaluate(self, _script, area):
        if area not in {"localStorage", "sessionStorage"}:
            raise AssertionError(area)
        return {"valid": True, "entries": []}


class FakeContext:
    def __init__(self, cookies=None):
        self.callbacks = {}
        self.transport_alive = True
        self.saved_cookies = list(cookies or [])
        self.page = FakePage(self)
        self.pages = [self.page]
        self.added_cookies = []

    def on(self, event, callback):
        self.callbacks[event] = callback

    def emit(self, event, value):
        callback = self.callbacks.get(event)
        if callback:
            callback(value)

    def new_page(self):
        return self.page

    def add_cookies(self, cookies):
        self.added_cookies = list(cookies)

    def add_init_script(self, **_kwargs):
        return None

    def cookies(self):
        if not self.transport_alive:
            raise RuntimeError("browser transport is closed")
        return list(self.saved_cookies)

    def close(self):
        if not self.transport_alive:
            raise RuntimeError("browser transport is closed")
        self.closed = True


@contextmanager
def fake_profile(_executable):
    yield {
        "executable": "/safe/chromium",
        "profile": "/safe/profile",
        "environment": {"HOME": "/safe/home"},
        "identity": "grypton-browser",
    }


@contextmanager
def fake_playwright(context):
    try:
        yield SimpleNamespace()
    finally:
        context.transport_alive = False


class BrowserWorkflowTests(unittest.TestCase):
    def workspace(self, name="workflow"):
        workspace = Workspace(name)
        workspace.create("https://example.test", "web")
        workspace.save_constraints(Constraints(in_scope=["example.test"]))
        return workspace

    def patches(self, context):
        return (
            patch("grypton.tools._browser_executable", return_value="/safe/chromium"),
            patch("grypton.tools._isolated_browser_profile", fake_profile),
            patch(
                "playwright.sync_api.sync_playwright",
                new=lambda: fake_playwright(context),
            ),
            patch("grypton.tools._launch_scoped_browser_context", return_value=context),
        )

    def test_anonymous_workflow_executes_declarative_actions_and_safe_upload(self):
        with isolated_runtime():
            workspace = self.workspace()
            upload = workspace.loot_dir / "proof.txt"
            upload.write_bytes(b"bounded upload")
            context = FakeContext()
            actions = [
                {"action": "goto", "url": "https://example.test/form"},
                {"action": " FILL ", "selector": "#name", "value": "private-input"},
                {"action": "SeLeCt", "selector": "#kind", "value": "admin"},
                {"action": "check", "selector": "#agree"},
                {"action": "press", "selector": "#name", "key": "Enter"},
                {"action": "wait", "milliseconds": 10},
                {"action": "inspect", "selector": "body", "max_chars": 100},
                {"action": "upload", "selector": "#file", "path": "loot/proof.txt"},
                {"action": "snapshot"},
            ]
            managers = self.patches(context)
            with managers[0], managers[1], managers[2], managers[3]:
                result = dispatch(workspace, "browser_workflow", {"actions": actions})

            self.assertTrue(result["ok"], result)
            self.assertTrue(context.closed)
            self.assertEqual(result["data"]["actions_completed"], len(actions))
            self.assertEqual(result["data"]["network_request_count"], 0)
            self.assertEqual(result["data"]["network_requests"][0]["status"], 200)
            self.assertTrue(Path(result["data"]["html_path"]).is_file())
            self.assertEqual(context.page.uploads[0]["buffer"], b"bounded upload")
            self.assertEqual(context.page.uploads[0]["name"], "proof.txt")
            rendered = repr(result)
            self.assertNotIn("private-input", rendered)
            self.assertNotIn("admin", rendered)
            self.assertNotIn("private-input", Path(result["data"]["html_path"]).read_text())
            audit = (workspace.root / ".ledger" / "tool-calls.jsonl").read_text()
            self.assertNotIn("private-input", audit)
            self.assertNotIn('"admin"', audit)

    def test_validation_rejects_script_actions_and_unbounded_sequences_before_launch(self):
        with isolated_runtime():
            workspace = self.workspace("workflow-validation")
            script = tools.browser_workflow(workspace, [
                {"action": "goto", "url": "https://example.test/"},
                {"action": "evaluate", "value": "document.cookie"},
            ])
            too_many = tools.browser_workflow(
                workspace,
                [{"action": "goto", "url": "https://example.test/"}] * 21,
            )
            self.assertFalse(script["ok"])
            self.assertIn("unsupported type", script["summary"])
            self.assertFalse(too_many["ok"])
            self.assertIn("1-20", too_many["summary"])
            with self.assertRaisesRegex(ValueError, "relative file"):
                tools._browser_workflow_upload_payload(
                    workspace, "loot/../scope-rules.md"
                )

    def test_prior_inspect_and_title_secrets_are_redacted_after_navigation(self):
        with isolated_runtime():
            workspace = self.workspace("workflow-prior-secret")
            context = FakeContext()
            actions = [
                {"action": "goto", "url": "https://example.test/secret"},
                {"action": "inspect", "selector": "body"},
                {"action": "snapshot"},
                {"action": "goto", "url": "https://example.test/clean"},
            ]
            managers = self.patches(context)
            with managers[0], managers[1], managers[2], managers[3]:
                result = tools.browser_workflow(workspace, actions)

            self.assertTrue(result["ok"], result)
            rendered = repr(result)
            self.assertNotIn("prior-inspect-secret", rendered)
            self.assertNotIn("prior-title-secret", rendered)
            self.assertIn("[REDACTED]", rendered)
            self.assertNotIn(
                "prior-inspect-secret",
                Path(result["data"]["html_path"]).read_text(encoding="utf-8"),
            )

    def test_authenticated_workflow_restores_cookie_file_when_storage_commit_fails(self):
        with isolated_runtime():
            workspace = self.workspace("workflow-auth")
            credential = "primary"
            old_cookie = "# Netscape HTTP Cookie File\n"
            cookie_path = credentials.cookie_jar_path(workspace.slug, credential)
            cookie_path.write_text(old_cookie, encoding="utf-8")
            state = {
                "established": True,
                "ever_established": True,
                "origin": "https://example.test:443",
                "proof_generation": 3,
                "proof_profile_revision": "abc123abc123",
            }
            rich = {
                "available": True,
                "origin": "https://example.test:443",
                "proof_generation": 3,
                "profile_revision": "abc123abc123",
                "cookies": [], "local_storage": {}, "session_storage": {},
            }
            context = FakeContext(cookies=[{
                "name": "sid", "value": "rotated-cookie-value", "domain": "example.test",
                "path": "/", "secure": True, "httpOnly": True, "sameSite": "Strict",
            }])

            def replace_cookie(_workspace, _credential, _cookies, _origin):
                cookie_path.write_text("new private cookie", encoding="utf-8")

            managers = self.patches(context)
            with managers[0], managers[1], managers[2], managers[3], \
                    patch("grypton.credentials.load_auth_profile_optional", return_value={"strategy": "browser"}), \
                    patch("grypton.credentials.auth_profile_revision", return_value="abc123abc123"), \
                    patch("grypton.credentials.load_attempt_state", return_value=state), \
                    patch("grypton.credentials.load_browser_storage", return_value=rich), \
                    patch("grypton.credentials.load_credential", return_value={"username": "user", "password": "secret-pass"}), \
                    patch("grypton.credentials.load_tokens", return_value={}), \
                    patch("grypton.credentials.session_status", return_value={"state": "established"}), \
                    patch("grypton.tools._browser_auth_install_cookies", side_effect=replace_cookie), \
                    patch("grypton.credentials.save_browser_storage", side_effect=credentials.CredentialError("synthetic commit failure")):
                result = tools.browser_workflow(
                    workspace,
                    [{"action": "goto", "url": "https://example.test/account"}],
                    credential=credential,
                )

            self.assertFalse(result["ok"], result)
            self.assertIsInstance(result.get("data"), dict, result)
            self.assertTrue(result["data"]["session_material_rollback"])
            self.assertFalse(result["data"]["session_material_committed"])
            self.assertEqual(cookie_path.read_text(encoding="utf-8"), old_cookie)
            self.assertNotIn("secret-pass", repr(result))

    def test_real_browser_login_state_reaches_authenticated_account_workflow(self):
        from tests.test_browser_credentials import (
            BrowserCredentialTests, _SpaAuthHandler, spa_auth_server,
        )

        with isolated_runtime(), spa_auth_server("success") as port:
            fixture = BrowserCredentialTests()
            workspace = fixture._workspace(port)
            credentials.save_credential(
                workspace.slug, "primary",
                _SpaAuthHandler.username, _SpaAuthHandler.password,
            )
            credentials.save_auth_profile(
                workspace.slug, "primary", fixture._status_profile(port)
            )

            login = dispatch(
                workspace, "credential_browser_login", {"credential": "primary"}
            )
            rich_state = credentials.load_browser_storage(
                workspace.slug, "primary"
            )
            workflow = dispatch(workspace, "browser_workflow", {
                "credential": "primary",
                "actions": [
                    {
                        "action": "goto",
                        "url": f"http://127.0.0.1:{port}/dashboard",
                    },
                    {"action": "inspect", "selector": "body"},
                    {"action": "snapshot"},
                ],
                "timeout": 30,
            })

            self.assertTrue(login["ok"], login.get("summary"))
            self.assertTrue(rich_state.get("available"))
            self.assertTrue(workflow["ok"], workflow.get("summary"))
            data = workflow["data"]
            self.assertEqual(data["actions_completed"], 3)
            self.assertTrue(data["final_url"].endswith("/dashboard"))
            self.assertEqual(
                [row["status"] for row in data["network_requests"]], [200]
            )
            self.assertEqual(data["blocked_request_count"], 0)
            self.assertTrue(data["session_material_committed"])
            inspected = next(
                row["text"] for row in data["actions"]
                if row["action"] == "inspect"
            )
            self.assertIn("[REDACTED]", inspected)
            serialized = repr((login, workflow))
            self.assertNotIn(_SpaAuthHandler.password, serialized)
            self.assertNotIn(_SpaAuthHandler.session, serialized)
            self.assertNotIn(_SpaAuthHandler.token, serialized)
            self.assertNotIn(
                _SpaAuthHandler.token,
                Path(data["html_path"]).read_text(encoding="utf-8"),
            )

    def test_schema_exposes_only_declarative_actions(self):
        description, schema, _handler = REGISTRY["browser_workflow"]
        self.assertIn("declarative", description)
        self.assertEqual(schema["properties"]["actions"]["maxItems"], 20)
        rendered = repr(schema).lower()
        self.assertNotIn("javascript", rendered.replace("no script or javascript", ""))
        self.assertNotIn("evaluate", rendered)

    def test_network_novelty_uses_full_safe_workflow_shape(self):
        first = Engine._network_signature({
            "name": "grypton_browser_workflow",
            "input": {"actions": [
                {"action": "goto", "url": "https://example.test/one"},
                {"action": "click", "selector": "#first-path"},
                {"action": "goto", "url": "https://example.test/two?id=secret"},
            ]},
        })
        second = Engine._network_signature({
            "name": "grypton_browser_workflow",
            "input": {"actions": [
                {"action": "goto", "url": "https://example.test/one"},
                {"action": "click", "selector": "#other-path"},
                {"action": "goto", "url": "https://example.test/other?id=other"},
            ]},
        })
        self.assertTrue(first)
        self.assertTrue(second)
        self.assertNotEqual(first, second)

        value_a = Engine._network_signature({
            "name": "grypton_browser_workflow",
            "input": {"actions": [
                {"action": "goto", "url": "https://example.test/form"},
                {"action": "fill", "selector": "#password", "value": "secret-a"},
                {"action": "select", "selector": "#role", "value": "admin"},
            ]},
        })
        value_b = Engine._network_signature({
            "name": "grypton_browser_workflow",
            "input": {"actions": [
                {"action": "goto", "url": "https://example.test/form"},
                {"action": "fill", "selector": "#password", "value": "secret-b"},
                {"action": "select", "selector": "#role", "value": "viewer"},
            ]},
        })
        self.assertEqual(value_a, value_b)

        normalized_a = Engine._network_signature({
            "name": "grypton_browser_workflow",
            "input": {"actions": [
                {"action": " GOTO ", "url": "https://example.test/form"},
                {"action": " INSPECT ", "selector": "  body  "},
            ]},
        })
        normalized_b = Engine._network_signature({
            "name": "grypton_browser_workflow",
            "input": {"actions": [
                {"action": "goto", "url": "https://example.test/form"},
                {"action": "inspect", "selector": "body", "max_chars": 4000},
            ]},
        })
        self.assertEqual(normalized_a, normalized_b)


if __name__ == "__main__":
    unittest.main()
