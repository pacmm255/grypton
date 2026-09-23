from __future__ import annotations

from contextlib import contextmanager, redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from grypton import config, credentials
from grypton.cli import build_parser
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


def browser_profile(origin: str = "https://app.example.test") -> dict:
    return {
        "version": 1,
        "strategy": "browser",
        "login_url": origin + "/login",
        "verify_url": origin + "/profile",
        "success_marker": "private-success-marker",
        "username_transform": "iran-e164",
        "timeout": 45,
        "browser": {
            "username_selector": "[data-login='identity']",
            "password_selector": "[data-login='password']",
            "submit_selector": "button[data-login='submit']",
            "verify_headers": {
                "Accept": "application/json",
                "Origin": origin,
                "Referer": origin + "/login",
                "X-Client-Version": "test-private-profile-value",
            },
        },
    }


def http_profile(origin: str = "https://api.example.test") -> dict:
    return {
        "version": 1,
        "strategy": "http",
        "login_url": origin + "/login",
        "verify_url": origin + "/me",
        "success_marker": '"authenticated":true',
        "username_transform": "stored",
        "timeout": 30,
        "http": {
            "encoding": "json",
            "username_field": "identity",
            "password_field": "proof",
            "fields": {"channel": "web"},
            "headers": {"X-Platform": "pwa"},
        },
    }


class AuthProfileStorageTests(unittest.TestCase):
    def test_private_profile_round_trip_and_safe_status(self):
        with isolated_runtime():
            credentials.save_credential(
                "example", "primary", "0912 345-6789", "password-never-print"
            )
            saved = credentials.save_auth_profile(
                "example", "primary", browser_profile()
            )
            loaded = credentials.load_auth_profile_optional("example", "primary")
            self.assertEqual(loaded, saved)
            self.assertEqual(credentials.list_credentials("example"), ["primary"])

            path = credentials.auth_profile_path("example", "primary")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertFalse(path.is_relative_to(config.ENGAGEMENTS_DIR))

            status = credentials.session_status("example", "primary")
            profile = status["auth_profile"]
            self.assertEqual(profile["strategy"], "browser")
            self.assertEqual(profile["username_transform"], "iran-e164")
            self.assertEqual(profile["login_origin"], "https://app.example.test:443")
            self.assertEqual(len(profile["revision"]), 12)
            observable = json.dumps(status, ensure_ascii=False)
            for private_value in (
                "0912 345-6789",
                "password-never-print",
                "private-success-marker",
                "[data-login='identity']",
                "test-private-profile-value",
                "/login",
                "/profile",
            ):
                self.assertNotIn(private_value, observable)

    def test_http_profile_is_canonical_and_profile_changes_preserve_attempts(self):
        with isolated_runtime():
            credentials.save_credential("example", "primary", "user", "pass")
            credentials.begin_login_attempt("example", "primary")
            saved = credentials.save_auth_profile(
                "example", "primary", http_profile()
            )
            self.assertEqual(saved["http"]["fields"], {"channel": "web"})
            self.assertEqual(
                credentials.session_status("example", "primary")["attempts"], 1
            )

    def test_strict_validation_rejects_unsafe_or_ambiguous_profiles(self):
        cases = []
        value = browser_profile()
        value["unknown"] = "hidden-value"
        cases.append(value)
        value = browser_profile()
        value["verify_url"] = "https://other.example.test/profile"
        cases.append(value)
        value = browser_profile()
        value["browser"]["username_selector"] = ""
        cases.append(value)
        value = browser_profile()
        value["browser"]["verify_headers"] = {"Authorization": "private"}
        cases.append(value)
        value = browser_profile()
        value["browser"]["verify_headers"] = {"Origin": "https://other.example.test"}
        cases.append(value)
        value = browser_profile()
        value["browser"]["verify_headers"] = {"X-Forwarded-Host": "other.test"}
        cases.append(value)
        value = browser_profile()
        value["browser"]["verify_headers"] = {"X-Test": "one", "x-test": "two"}
        cases.append(value)
        value = browser_profile()
        value["browser"]["verify_headers"] = {"X-Test": "one\r\ntwo"}
        cases.append(value)
        value = browser_profile()
        value["browser"]["verify_headers"] = {
            f"X-Test-{index}": "value" for index in range(33)
        }
        cases.append(value)
        value = http_profile()
        value["http"]["fields"] = {"identity": "embedded-identity"}
        cases.append(value)
        value = http_profile()
        value["http"]["password_field"] = "identity"
        cases.append(value)
        value = http_profile()
        value["browser"] = browser_profile()["browser"]
        cases.append(value)

        with isolated_runtime():
            credentials.save_credential("example", "primary", "user", "pass")
            for profile in cases:
                with self.subTest(profile=profile.get("strategy")):
                    with self.assertRaises(credentials.CredentialError):
                        credentials.save_auth_profile("example", "primary", profile)
            self.assertIsNone(
                credentials.load_auth_profile_optional("example", "primary")
            )

    def test_profile_symlinks_are_rejected_and_clear_is_idempotent(self):
        with isolated_runtime() as root:
            credentials.save_credential("example", "primary", "user", "pass")
            path = credentials.auth_profile_path("example", "primary")
            destination = root / "outside-profile.json"
            destination.write_text(json.dumps(browser_profile()))
            os.chmod(destination, 0o600)
            path.symlink_to(destination)
            with self.assertRaisesRegex(credentials.CredentialError, "symlink"):
                credentials.save_auth_profile(
                    "example", "primary", browser_profile()
                )
            with self.assertRaisesRegex(credentials.CredentialError, "symlink"):
                credentials.delete_auth_profile("example", "primary")
            self.assertTrue(destination.exists())

            path.unlink()
            credentials.save_auth_profile("example", "primary", browser_profile())
            self.assertTrue(credentials.delete_auth_profile("example", "primary"))
            self.assertFalse(credentials.delete_auth_profile("example", "primary"))

    def test_malformed_profile_status_is_generic(self):
        with isolated_runtime():
            credentials.save_credential("example", "primary", "user", "pass")
            path = credentials.auth_profile_path("example", "primary")
            path.write_text('{"selector":"content-never-reflect"}\n')
            os.chmod(path, 0o600)
            status = credentials.session_status("example", "primary")
            self.assertEqual(
                status["auth_profile"], {"configured": True, "valid": False}
            )
            self.assertNotIn("content-never-reflect", json.dumps(status))


class AuthProfileCliTests(unittest.TestCase):
    def _workspace(self) -> Workspace:
        ws = Workspace("example")
        ws.create("https://app.example.test", "web")
        ws.save_constraints(Constraints(in_scope=[
            "https://app.example.test/login",
            "https://app.example.test/profile",
        ]))
        credentials.save_credential(ws.slug, "primary", "user", "password")
        return ws

    def _run(self, arguments: list[str]) -> tuple[int, str, str]:
        ns = build_parser().parse_args(arguments)
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = ns.func(ns)
        return result, stdout.getvalue(), stderr.getvalue()

    def test_cli_configure_list_json_and_clear_are_safe(self):
        with isolated_runtime():
            ws = self._workspace()
            configure = [
                "auth", "configure", ws.slug,
                "--name", "primary",
                "--strategy", "browser",
                "--login-url", "https://app.example.test/login",
                "--verify-url", "https://app.example.test/profile",
                "--success-marker", "cli-marker-never-output",
                "--username-selector", "#private-user-selector",
                "--password-selector", "#private-password-selector",
                "--submit-selector", "#private-submit-selector",
                "--verify-headers", json.dumps({
                    "Origin": "https://app.example.test",
                    "X-Client-Version": "private-header-value",
                }),
            ]
            code, output, error = self._run(configure)
            self.assertEqual(code, 0, error)
            for private_value in (
                "cli-marker-never-output", "#private-user-selector",
                "private-header-value", "user", "password",
            ):
                self.assertNotIn(private_value, output + error)

            code, output, error = self._run([
                "auth", "list", ws.slug, "--json"
            ])
            self.assertEqual(code, 0, error)
            listing = json.loads(output)
            profile = listing["credentials"][0]["auth_profile"]
            self.assertEqual(profile["strategy"], "browser")
            self.assertTrue(profile["valid"])
            self.assertNotIn("cli-marker-never-output", output)
            self.assertNotIn("private-header-value", output)

            code, output, error = self._run(["auth", "list", ws.slug])
            self.assertEqual(code, 0, error)
            self.assertIn("browser profile", output)
            self.assertIn("attempts 0/2", output)

            code, output, error = self._run([
                "auth", "clear-profile", ws.slug, "--name", "primary", "--json"
            ])
            self.assertEqual(code, 0, error)
            self.assertTrue(json.loads(output)["removed"])
            self.assertIsNone(
                credentials.load_auth_profile_optional(ws.slug, "primary")
            )

    def test_cli_rejects_out_of_scope_profile_without_saving(self):
        with isolated_runtime():
            ws = self._workspace()
            code, output, error = self._run([
                "auth", "configure", ws.slug,
                "--strategy", "browser",
                "--login-url", "https://outside.example/login",
                "--verify-url", "https://outside.example/profile",
                "--success-marker", "marker",
                "--username-selector", "#user",
                "--password-selector", "#pass",
                "--submit-selector", "#submit",
            ])
            self.assertEqual(code, 2)
            self.assertEqual(output, "")
            self.assertIn("outside the engagement scope", error)
            self.assertIsNone(
                credentials.load_auth_profile_optional(ws.slug, "primary")
            )


if __name__ == "__main__":
    unittest.main()
