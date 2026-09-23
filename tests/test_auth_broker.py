from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from grypton import config, credentials
from grypton.toolserver import REGISTRY, _handle, dispatch
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


def browser_profile(origin: str) -> dict:
    return {
        "version": 1,
        "strategy": "browser",
        "login_url": origin + "/private-login-path",
        "verify_url": origin + "/private-profile-path",
        "success_marker": "private-browser-marker",
        "username_transform": "iran-e164",
        "timeout": 37,
        "browser": {
            "username_selector": "[data-private='username']",
            "password_selector": "[data-private='password']",
            "submit_selector": "button[data-private='submit']",
            "verify_headers": {"X-Private-Client": "private-header-value"},
        },
    }


def http_profile(origin: str) -> dict:
    return {
        "version": 1,
        "strategy": "http",
        "login_url": origin + "/private-api-login",
        "verify_url": origin + "/private-api-profile",
        "success_marker": "private-http-marker",
        "username_transform": "stored",
        "timeout": 29,
        "http": {
            "encoding": "form",
            "username_field": "private_identity",
            "password_field": "private_proof",
            "fields": {"private_channel": "private-web-value"},
            "headers": {"X-Private-Platform": "private-platform-value"},
        },
    }


def status_browser_profile(origin: str) -> dict:
    value = browser_profile(origin)
    value.pop("success_marker")
    value["browser"]["verification"] = {
        "mode": "status-differential",
        "login_status": 200,
        "authenticated_status": 200,
        "anonymous_status": 401,
        "expected_post_login_url": origin + "/private-home-path",
    }
    return value


class AuthBrokerTests(unittest.TestCase):
    def test_status_profile_routes_both_aliases_with_private_internal_contract(self):
        origin = "https://app.example.test"
        with isolated_runtime():
            ws = self._workspace(origin)
            configured = status_browser_profile(origin)
            configured["browser"]["verification"][
                "anonymous_redirect_statuses"
            ] = [307]
            profile = credentials.save_auth_profile(
                ws.slug, "primary", configured
            )
            revision = credentials.auth_profile_revision(profile)
            with (
                patch("grypton.toolserver.tools.credential_browser_login") as browser,
                patch("grypton.toolserver.tools.credential_login") as http,
            ):
                browser.return_value = {
                    "ok": True, "summary": "status delegated", "data": {}
                }
                for requested in ("credential_login", "credential_browser_login"):
                    with self.subTest(requested=requested):
                        browser.reset_mock()
                        result = dispatch(ws, requested, self._wrong_transport_args())
                        self.assertTrue(result["ok"], result)
                        browser.assert_called_once_with(
                            ws, profile["login_url"], credential="primary",
                            username_transform=profile["username_transform"],
                            username_selector=profile["browser"]["username_selector"],
                            password_selector=profile["browser"]["password_selector"],
                            submit_selector=profile["browser"]["submit_selector"],
                            verify_url=profile["verify_url"], success_marker="",
                            verify_headers=profile["browser"]["verify_headers"],
                            verification=profile["browser"]["verification"],
                            timeout=profile["timeout"],
                        )
                        http.assert_not_called()
                        self._assert_dispatch(
                            result, requested, "credential_browser_login", revision
                        )

    def test_status_profile_terminal_url_is_scope_checked_before_delegate(self):
        origin = "https://app.example.test"
        with isolated_runtime():
            ws = self._workspace(origin)
            credentials.save_auth_profile(
                ws.slug, "primary", status_browser_profile(origin)
            )
            ws.save_constraints(Constraints(in_scope=[
                origin + "/private-login-path",
                origin + "/private-profile-path",
            ]))
            with patch(
                "grypton.toolserver.tools.credential_browser_login"
            ) as browser:
                result = dispatch(
                    ws, "credential_login", {"credential": "primary"}
                )
            self.assertFalse(result["ok"], result)
            self.assertIn("outside the engagement scope", result["summary"])
            browser.assert_not_called()
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 0
            )

    def _workspace(self, origin: str = "https://app.example.test") -> Workspace:
        ws = Workspace("auth-broker-test")
        ws.create(origin, "web")
        ws.save_constraints(Constraints(in_scope=[origin]))
        credentials.save_credential(
            ws.slug, "primary", "0912 345-6789", "private-password"
        )
        return ws

    def _wrong_transport_args(self) -> dict:
        return {
            "credential": "primary",
            "url": "https://wrong.example.invalid/model-login",
            "verify_url": "https://wrong.example.invalid/model-profile",
            "success_marker": "wrong-model-marker",
            "username_transform": "stored",
            "username_field": "wrong_user",
            "password_field": "wrong_password",
            "encoding": "json",
            "fields": {"wrong": "model-field"},
            "headers": {"X-Wrong": "model-header"},
            "username_selector": "#wrong-user",
            "password_selector": "#wrong-password",
            "submit_selector": "#wrong-submit",
            "verify_headers": {"X-Wrong-Verify": "model-verify-header"},
            "timeout": 5,
        }

    def _assert_dispatch(self, result: dict, requested: str,
                         effective: str, revision: str,
                         configured: bool = True) -> None:
        metadata = result["data"]["auth_dispatch"]
        self.assertEqual(metadata, {
            "requested_tool": requested,
            "effective_tool": effective,
            "profile_configured": configured,
            "profile_revision": revision,
        })

    def test_browser_profile_routes_both_public_tools_and_ignores_overrides(self):
        origin = "https://app.example.test"
        with isolated_runtime():
            ws = self._workspace(origin)
            profile = credentials.save_auth_profile(
                ws.slug, "primary", browser_profile(origin)
            )
            revision = credentials.auth_profile_revision(profile)
            with (
                patch("grypton.toolserver.tools.credential_browser_login") as browser,
                patch("grypton.toolserver.tools.credential_login") as http,
            ):
                browser.return_value = {
                    "ok": True, "summary": "browser delegated", "data": {}
                }
                for requested in ("credential_login", "credential_browser_login"):
                    with self.subTest(requested=requested):
                        browser.reset_mock()
                        http.reset_mock()
                        result = dispatch(
                            ws, requested, self._wrong_transport_args()
                        )
                        self.assertTrue(result["ok"], result)
                        browser.assert_called_once_with(
                            ws, profile["login_url"], credential="primary",
                            username_transform=profile["username_transform"],
                            username_selector=profile["browser"]["username_selector"],
                            password_selector=profile["browser"]["password_selector"],
                            submit_selector=profile["browser"]["submit_selector"],
                            verify_url=profile["verify_url"],
                            success_marker=profile["success_marker"],
                            verify_headers=profile["browser"]["verify_headers"],
                            timeout=profile["timeout"],
                        )
                        http.assert_not_called()
                        self._assert_dispatch(
                            result, requested, "credential_browser_login", revision
                        )

            ledger_text = (ws.root / ".ledger/tool-calls.jsonl").read_text()
            audit = json.loads(ledger_text.splitlines()[-1])
            self.assertEqual(
                audit["auth_dispatch"], result["data"]["auth_dispatch"]
            )
            observable = json.dumps(result, ensure_ascii=False) + ledger_text
            for private_value in (
                "/private-login-path", "/private-profile-path",
                "private-browser-marker", "[data-private='username']",
                "private-header-value", "0912 345-6789", "private-password",
            ):
                self.assertNotIn(private_value, observable)

    def test_http_profile_routes_both_public_tools_and_ignores_overrides(self):
        origin = "https://api.example.test"
        with isolated_runtime():
            ws = self._workspace(origin)
            profile = credentials.save_auth_profile(
                ws.slug, "primary", http_profile(origin)
            )
            revision = credentials.auth_profile_revision(profile)
            with (
                patch("grypton.toolserver.tools.credential_browser_login") as browser,
                patch("grypton.toolserver.tools.credential_login") as http,
            ):
                http.return_value = {
                    "ok": False, "summary": "HTTP delegated failure"
                }
                for requested in ("credential_login", "credential_browser_login"):
                    with self.subTest(requested=requested):
                        browser.reset_mock()
                        http.reset_mock()
                        result = dispatch(
                            ws, requested, self._wrong_transport_args()
                        )
                        self.assertFalse(result["ok"], result)
                        http.assert_called_once_with(
                            ws, profile["login_url"], credential="primary",
                            verify_url=profile["verify_url"],
                            success_marker=profile["success_marker"],
                            username_field=profile["http"]["username_field"],
                            password_field=profile["http"]["password_field"],
                            username_transform=profile["username_transform"],
                            encoding=profile["http"]["encoding"],
                            fields=profile["http"]["fields"],
                            headers=profile["http"]["headers"],
                            timeout=profile["timeout"],
                        )
                        browser.assert_not_called()
                        self._assert_dispatch(
                            result, requested, "credential_login", revision
                        )

    def test_unprofiled_calls_keep_their_requested_transport_arguments(self):
        origin = "https://app.example.test"
        with isolated_runtime():
            ws = self._workspace(origin)
            http_args = {
                "credential": "primary",
                "url": origin + "/login",
                "verify_url": origin + "/me",
                "success_marker": "marker",
                "username_field": "identity",
                "password_field": "proof",
                "username_transform": "stored",
                "encoding": "form",
                "fields": {"channel": "web"},
                "headers": {"X-Client": "web"},
                "timeout": 22,
            }
            with patch(
                "grypton.toolserver.tools.credential_login",
                return_value={"ok": True, "summary": "legacy", "data": {}},
            ) as http:
                result = dispatch(ws, "credential_login", http_args)
            http.assert_called_once_with(
                ws, http_args["url"], credential="primary",
                verify_url=http_args["verify_url"],
                success_marker="marker", username_field="identity",
                password_field="proof", username_transform="stored",
                encoding="form", fields={"channel": "web"},
                headers={"X-Client": "web"}, timeout=22,
            )
            self._assert_dispatch(
                result, "credential_login", "credential_login", "",
                configured=False,
            )

            browser_args = {
                "credential": "primary",
                "url": origin + "/login",
                "verify_url": origin + "/me",
                "success_marker": "marker",
                "username_transform": "stored",
                "username_selector": "#user",
                "password_selector": "#password",
                "submit_selector": "#submit",
                "verify_headers": {"X-Client": "web"},
                "timeout": 23,
            }
            with patch(
                "grypton.toolserver.tools.credential_browser_login",
                return_value={"ok": True, "summary": "legacy", "data": {}},
            ) as browser:
                result = dispatch(
                    ws, "credential_browser_login", browser_args
                )
            browser.assert_called_once_with(
                ws, browser_args["url"], credential="primary",
                username_transform="stored", username_selector="#user",
                password_selector="#password", submit_selector="#submit",
                verify_url=browser_args["verify_url"], success_marker="marker",
                verify_headers={"X-Client": "web"}, timeout=23,
            )
            self._assert_dispatch(
                result, "credential_browser_login",
                "credential_browser_login", "", configured=False,
            )

    def test_malformed_profile_fails_closed_before_delegate_or_attempt(self):
        with isolated_runtime():
            ws = self._workspace()
            path = credentials.auth_profile_path(ws.slug, "primary")
            path.write_text(
                '{"private-profile-field":"private-profile-value"}\n',
                encoding="utf-8",
            )
            os.chmod(path, 0o600)
            with (
                patch("grypton.toolserver.tools.credential_browser_login") as browser,
                patch("grypton.toolserver.tools.credential_login") as http,
            ):
                result = dispatch(ws, "credential_login", {
                    "credential": "primary",
                    "url": "https://app.example.test/fallback",
                    "verify_url": "https://app.example.test/fallback-proof",
                    "success_marker": "fallback-marker",
                })
            self.assertFalse(result["ok"], result)
            browser.assert_not_called()
            http.assert_not_called()
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 0
            )
            self._assert_dispatch(result, "credential_login", "", "")
            observable = json.dumps(result, ensure_ascii=False)
            self.assertNotIn("private-profile-field", observable)
            self.assertNotIn("private-profile-value", observable)
            self.assertNotIn("fallback", observable)

    def test_out_of_scope_profile_fails_before_delegate_or_attempt(self):
        with isolated_runtime():
            ws = self._workspace()
            profile = credentials.save_auth_profile(
                ws.slug, "primary", browser_profile("https://outside.example")
            )
            revision = credentials.auth_profile_revision(profile)
            with (
                patch("grypton.toolserver.tools.credential_browser_login") as browser,
                patch("grypton.toolserver.tools.credential_login") as http,
            ):
                result = dispatch(
                    ws, "credential_browser_login", {"credential": "primary"}
                )
            self.assertFalse(result["ok"], result)
            browser.assert_not_called()
            http.assert_not_called()
            self.assertEqual(
                credentials.session_status(ws.slug, "primary")["attempts"], 0
            )
            self._assert_dispatch(
                result, "credential_browser_login",
                "credential_browser_login", revision,
            )
            observable = json.dumps(result, ensure_ascii=False)
            self.assertNotIn("outside.example", observable)
            self.assertNotIn("private-login-path", observable)

    def test_profile_creation_is_linearized_before_broker_route_selection(self):
        origin = "https://app.example.test"
        with isolated_runtime():
            ws = self._workspace(origin)
            profile = browser_profile(origin)
            profile_path = credentials.auth_profile_path(ws.slug, "primary")
            original_atomic_write = credentials._atomic_private_json
            original_profile_lock = credentials.auth_profile_lock
            write_entered = threading.Event()
            allow_write = threading.Event()
            broker_reached_lock = threading.Event()
            legacy_called = threading.Event()
            browser_called = threading.Event()
            save_errors: list[BaseException] = []
            broker_errors: list[BaseException] = []
            broker_results: list[dict] = []

            def paused_atomic_write(path, value):
                if path == profile_path:
                    write_entered.set()
                    if not allow_write.wait(5):
                        raise RuntimeError("timed out waiting to finish profile write")
                return original_atomic_write(path, value)

            @contextmanager
            def observed_profile_lock(target, name):
                if threading.current_thread().name == "broker-dispatch":
                    broker_reached_lock.set()
                with original_profile_lock(target, name):
                    yield

            def save_profile() -> None:
                try:
                    credentials.save_auth_profile(
                        ws.slug, "primary", profile
                    )
                except BaseException as exc:  # captured for the parent test thread
                    save_errors.append(exc)

            def run_broker() -> None:
                try:
                    broker_results.append(dispatch(ws, "credential_login", {
                        "credential": "primary",
                        "url": origin + "/legacy-login",
                        "verify_url": origin + "/legacy-profile",
                        "success_marker": "legacy-marker",
                    }))
                except BaseException as exc:  # captured for the parent test thread
                    broker_errors.append(exc)

            def browser_result(*_args, **_kwargs):
                browser_called.set()
                return {"ok": True, "summary": "profile route", "data": {}}

            def legacy_result(*_args, **_kwargs):
                legacy_called.set()
                return {"ok": True, "summary": "legacy route", "data": {}}

            with (
                patch.object(
                    credentials, "_atomic_private_json",
                    side_effect=paused_atomic_write,
                ),
                patch.object(
                    credentials, "auth_profile_lock", observed_profile_lock,
                ),
                patch(
                    "grypton.toolserver.tools.credential_browser_login",
                    side_effect=browser_result,
                ),
                patch(
                    "grypton.toolserver.tools.credential_login",
                    side_effect=legacy_result,
                ),
            ):
                saver = threading.Thread(
                    target=save_profile, name="profile-saver", daemon=True
                )
                saver.start()
                self.assertTrue(write_entered.wait(5))
                broker = threading.Thread(
                    target=run_broker, name="broker-dispatch", daemon=True
                )
                broker.start()
                self.assertTrue(broker_reached_lock.wait(5))
                self.assertFalse(legacy_called.wait(0.2))
                self.assertFalse(browser_called.is_set())
                allow_write.set()
                saver.join(5)
                broker.join(5)

            self.assertFalse(saver.is_alive())
            self.assertFalse(broker.is_alive())
            self.assertEqual(save_errors, [])
            self.assertEqual(broker_errors, [])
            self.assertFalse(legacy_called.is_set())
            self.assertTrue(browser_called.is_set())
            self.assertEqual(len(broker_results), 1)
            self.assertTrue(broker_results[0]["ok"], broker_results[0])
            self.assertEqual(
                broker_results[0]["data"]["auth_dispatch"]["effective_tool"],
                "credential_browser_login",
            )

    def test_profile_replacement_waits_through_proof_and_revision_recording(self):
        origin = "https://app.example.test"
        with isolated_runtime():
            ws = self._workspace(origin)
            profile_a = credentials.save_auth_profile(
                ws.slug, "primary", status_browser_profile(origin)
            )
            revision_a = credentials.auth_profile_revision(profile_a)
            profile_b = status_browser_profile(origin)
            profile_b["timeout"] = 41
            entered = threading.Event()
            release = threading.Event()
            saved = threading.Event()
            calls: list[dict] = []
            results: list[dict] = []
            errors: list[BaseException] = []

            def delegated(_ws, _url, **kwargs):
                calls.append(dict(kwargs))
                entered.set()
                if not release.wait(5):
                    raise RuntimeError("timed out waiting for profile replacement")
                return {"ok": True, "summary": "proof A", "data": {}}

            def authenticate():
                try:
                    results.append(dispatch(
                        ws, "credential_login", {"credential": "primary"}
                    ))
                except BaseException as exc:
                    errors.append(exc)

            def replace():
                try:
                    credentials.save_auth_profile(ws.slug, "primary", profile_b)
                    saved.set()
                except BaseException as exc:
                    errors.append(exc)

            with patch(
                "grypton.toolserver.tools.credential_browser_login",
                side_effect=delegated,
            ):
                auth_thread = threading.Thread(target=authenticate, daemon=True)
                auth_thread.start()
                self.assertTrue(entered.wait(5))
                save_thread = threading.Thread(target=replace, daemon=True)
                save_thread.start()
                self.assertFalse(saved.wait(0.2))
                release.set()
                auth_thread.join(5)
                save_thread.join(5)

            self.assertFalse(auth_thread.is_alive())
            self.assertFalse(save_thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["timeout"], profile_a["timeout"])
            self.assertEqual(
                results[0]["data"]["auth_dispatch"]["profile_revision"],
                revision_a,
            )
            self.assertTrue(saved.is_set())
            self.assertEqual(
                credentials.auth_profile_revision(
                    credentials.load_auth_profile_optional(ws.slug, "primary")
                ),
                credentials.auth_profile_revision(profile_b),
            )

    def test_absent_profile_snapshot_holds_lock_through_legacy_delegate(self):
        origin = "https://app.example.test"
        with isolated_runtime():
            ws = self._workspace(origin)
            legacy_entered = threading.Event()
            allow_legacy_return = threading.Event()
            save_finished = threading.Event()
            errors: list[BaseException] = []

            def legacy(*_args, **_kwargs):
                legacy_entered.set()
                if not allow_legacy_return.wait(5):
                    raise RuntimeError("timed out waiting to release legacy call")
                return {"ok": True, "summary": "legacy", "data": {}}

            def run_broker():
                try:
                    dispatch(ws, "credential_login", {
                        "credential": "primary",
                        "url": origin + "/legacy-login",
                        "verify_url": origin + "/legacy-verify",
                        "success_marker": "legacy-marker",
                    })
                except BaseException as exc:
                    errors.append(exc)

            def save_profile():
                try:
                    credentials.save_auth_profile(
                        ws.slug, "primary", browser_profile(origin)
                    )
                    save_finished.set()
                except BaseException as exc:
                    errors.append(exc)

            with patch(
                "grypton.toolserver.tools.credential_login", side_effect=legacy
            ):
                broker = threading.Thread(target=run_broker, daemon=True)
                broker.start()
                self.assertTrue(legacy_entered.wait(5))
                saver = threading.Thread(target=save_profile, daemon=True)
                saver.start()
                self.assertFalse(save_finished.wait(0.2))
                allow_legacy_return.set()
                broker.join(5)
                saver.join(5)

            self.assertFalse(broker.is_alive())
            self.assertFalse(saver.is_alive())
            self.assertEqual(errors, [])
            self.assertTrue(save_finished.is_set())
            self.assertIsNotNone(
                credentials.load_auth_profile_optional(ws.slug, "primary")
            )

    def test_public_schemas_require_only_alias_and_all_tools_remain_visible(self):
        for name in ("credential_login", "credential_browser_login"):
            description, schema, _ = REGISTRY[name]
            self.assertEqual(schema["required"], ["credential"])
            self.assertIn("named private credential", description)
            self.assertNotIn("verification", schema["properties"])
            for property_name in schema["properties"]:
                self.assertNotIn("redirect", property_name.lower())
                self.assertNotIn("status", property_name.lower())
            for private_name in (
                "login_status", "authenticated_status", "anonymous_status",
                "expected_post_login_url", "anonymous_redirect_statuses",
            ):
                self.assertNotIn(private_name, schema["properties"])

        with isolated_runtime():
            ws = Workspace("auth-broker-schema")
            ws.create("https://app.example.test", "web")
            response = _handle(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, ws
            )
        names = {item["name"] for item in response["result"]["tools"]}
        self.assertEqual(names, set(REGISTRY))


if __name__ == "__main__":
    unittest.main()
