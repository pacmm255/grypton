from __future__ import annotations

from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from urllib.error import HTTPError
from unittest.mock import patch

from grypton import config, credentials, temporary_mail, tools
from grypton.bugcrowd import analyze_snapshot
from grypton.cli import main
from grypton.toolserver import REGISTRY, dispatch
from grypton.workspace import Workspace


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
            "TARGET_DATA_DIR": root / "operator-input",
        }
        with patch.multiple(config, **values):
            config.ensure_layout()
            yield root


def authorized_workspace() -> Workspace:
    workspace = Workspace("mail-test")
    workspace.create("https://app.example.test", "web")
    workspace.save_program_brief("Create an account.", {
        "program": "synthetic-public-program",
        "account_workflows_supported": True,
        "self_created_account_permission": True,
        "credential_requirement": False,
        "disposable_email_prohibited": False,
        "temporary_mail_account_bootstrap_allowed": True,
        "brief_text": "Create an account.",
    })
    return workspace


def mailbox_record() -> dict:
    return {
        "version": 1,
        "provider": "mail.tm",
        "account_id": "mail-account-id",
        "address": "researcher@example-mail.test",
        "mailbox_password": "mailbox-password-never-log",
        "bearer_token": "mailbox-bearer-token-never-log",
        "target_password": "target-password-never-log",
        "created_at": 1.0,
        "delivered": {},
    }


class TemporaryMailboxTests(unittest.TestCase):
    def test_fixed_provider_transport_is_mocked_bounded_and_secret_safe(self):
        token = "mail-provider-token-never-reflect"

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b'{"hydra:member": []}'

        class Opener:
            request = None

            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return Response()

        opener = Opener()
        with patch("grypton.temporary_mail.build_opener", return_value=opener):
            result = temporary_mail._request_json(
                "GET", "/messages?page=1", bearer=token, timeout=999
            )
        self.assertEqual(result, {"hydra:member": []})
        self.assertEqual(opener.request.full_url, "https://api.mail.tm/messages?page=1")
        self.assertEqual(opener.request.get_header("Authorization"), "Bearer " + token)
        self.assertEqual(opener.timeout, 30)

        class FailingOpener:
            def open(self, request, timeout):
                raise HTTPError(request.full_url, 422, token, {}, None)

        with patch("grypton.temporary_mail.build_opener", return_value=FailingOpener()):
            with self.assertRaises(temporary_mail.TemporaryMailboxError) as caught:
                temporary_mail._request_json(
                    "POST", "/token", payload={"password": token}
                )
        self.assertNotIn(token, str(caught.exception))
        with self.assertRaises(temporary_mail.TemporaryMailboxError):
            temporary_mail._request_json("GET", "https://other.example/messages")

    def test_registry_exposes_only_create_and_poll_mailbox_tools(self):
        self.assertIn("temporary_mailbox_create", REGISTRY)
        self.assertIn("temporary_mailbox_poll", REGISTRY)
        mailbox_tools = sorted(name for name in REGISTRY if "mailbox" in name)
        self.assertEqual(mailbox_tools, [
            "temporary_mailbox_create", "temporary_mailbox_poll",
        ])
        self.assertEqual(
            REGISTRY["temporary_mailbox_create"][1]["required"], ["alias"]
        )
        self.assertEqual(
            REGISTRY["temporary_mailbox_poll"][1]["required"], ["alias", "kind"]
        )
        signup = REGISTRY["temporary_account_browser_signup"][1]
        self.assertEqual(
            signup["required"],
            ["url", "alias", "verify_url", "success_marker"],
        )
        self.assertNotIn("captcha", json.dumps(signup).lower())

    def test_signup_delegates_to_single_submission_private_browser_path(self):
        with isolated_runtime():
            workspace = authorized_workspace()
            record = mailbox_record()
            credentials.save_mailbox(workspace.slug, "signup", record)
            credentials.save_credential(
                workspace.slug, "signup", record["address"], record["target_password"]
            )
            expected = {"ok": True, "summary": "Signup session proved."}
            with patch(
                "grypton.toolserver.tools.credential_browser_login",
                return_value=expected,
            ) as browser:
                result = dispatch(workspace, "temporary_account_browser_signup", {
                    "url": "https://app.example.test/signup",
                    "alias": "signup",
                    "verify_url": "https://app.example.test/profile",
                    "success_marker": "Account profile",
                    "email_selector": "#email",
                    "password_selector": "#password",
                    "submit_selector": "#register",
                    "fields": {"#name": "Grypton Research", "#size": "small"},
                    "checkboxes": ["#terms"],
                })
            self.assertEqual(result, expected)
            _, called_url = browser.call_args.args
            called = browser.call_args.kwargs
            self.assertEqual(called_url, "https://app.example.test/signup")
            self.assertEqual(called["credential"], "signup")
            self.assertEqual(called["registration_fields"]["#name"], "Grypton Research")
            self.assertEqual(called["registration_checkboxes"], ["#terms"])
            rendered = repr(browser.call_args)
            self.assertNotIn(record["mailbox_password"], rendered)
            self.assertNotIn(record["bearer_token"], rendered)
            self.assertNotIn(record["target_password"], rendered)

    def test_private_otp_continuation_does_not_put_code_in_tool_arguments_or_result(self):
        with isolated_runtime():
            workspace = authorized_workspace()
            record = mailbox_record()
            credentials.save_mailbox(workspace.slug, "signup", record)
            credentials.save_credential(
                workspace.slug, "signup", record["address"], record["target_password"]
            )
            otp = "739251"
            def continue_browser(*_args, **kwargs):
                kwargs["_continuation_observation"]["reserved"] = True
                return {"ok": True, "summary": "Session proved.",
                        "data": {"established": True}}

            with patch("grypton.toolserver.temporary_mail.poll", return_value={
                "ok": True,
                "summary": "OTP ready.",
                "data": {"alias": "signup", "kind": "otp", "ready": True,
                         "value": otp, "_message_id": "mail-otp"},
            }), patch(
                "grypton.toolserver.credentials.load_auth_profile_optional",
                return_value={"strategy": "browser"},
            ), patch(
                "grypton.toolserver.credentials.load_pending_browser_step_up",
                return_value={"available": True},
            ), patch(
                "grypton.toolserver.temporary_mail.mark_delivered",
            ) as mark_delivered, patch(
                "grypton.toolserver.tools.credential_browser_step_up",
                side_effect=continue_browser,
            ) as continuation:
                result = dispatch(
                    workspace, "temporary_account_browser_continue",
                    {"alias": "signup", "sender_domain": "example.test"},
                )
            self.assertTrue(result["ok"])
            self.assertTrue(result["data"]["ready"])
            self.assertEqual(continuation.call_args.kwargs["otp"], otp)
            mark_delivered.assert_called_once_with(
                workspace, "signup", "mail-otp", "otp"
            )
            self.assertNotIn(otp, json.dumps(result))
            audit = (workspace.root / ".ledger/tool-calls.jsonl").read_text()
            self.assertNotIn(otp, audit)

    def test_private_otp_preflight_failure_leaves_mailbox_message_retryable(self):
        with isolated_runtime():
            workspace = authorized_workspace()
            record = mailbox_record()
            credentials.save_mailbox(workspace.slug, "signup", record)
            credentials.save_credential(
                workspace.slug, "signup", record["address"], record["target_password"]
            )
            with patch("grypton.toolserver.temporary_mail.poll", return_value={
                "ok": True,
                "summary": "OTP ready.",
                "data": {"alias": "signup", "kind": "otp", "ready": True,
                         "value": "739251", "_message_id": "mail-otp"},
            }), patch(
                "grypton.toolserver.credentials.load_auth_profile_optional",
                return_value={"strategy": "browser"},
            ), patch(
                "grypton.toolserver.credentials.load_pending_browser_step_up",
                return_value={"available": True},
            ), patch(
                "grypton.toolserver.temporary_mail.mark_delivered",
            ) as mark_delivered, patch(
                "grypton.toolserver.tools.credential_browser_step_up",
                return_value={"ok": False, "summary": "Python Playwright is not installed."},
            ):
                result = dispatch(
                    workspace, "temporary_account_browser_continue",
                    {"alias": "signup", "sender_domain": "example.test"},
                )
            self.assertFalse(result["ok"])
            self.assertFalse(result["data"]["ready"])
            mark_delivered.assert_not_called()

    def test_registration_controls_are_bounded_and_type_checked(self):
        fields, checkboxes = tools._browser_auth_registration_controls(
            {"#name": "Researcher", "#plan": "free"}, ["#terms", "#terms"]
        )
        self.assertEqual(fields, {"#name": "Researcher", "#plan": "free"})
        self.assertEqual(checkboxes, ["#terms"])
        with self.assertRaisesRegex(ValueError, "at most 20"):
            tools._browser_auth_registration_controls(
                {f"#field-{index}": "x" for index in range(21)}, []
            )
        with self.assertRaisesRegex(ValueError, "printable strings"):
            tools._browser_auth_registration_controls({"#name": "bad\nvalue"}, [])

        class Locator:
            def __init__(self, tag, input_type=""):
                self.first = self
                self.details = {"tag": tag, "type": input_type, "disabled": False}
                self.actions = []

            def wait_for(self, **kwargs):
                self.actions.append(("wait", kwargs))

            def evaluate(self, _script):
                return self.details

            def fill(self, value, **kwargs):
                self.actions.append(("fill", value, kwargs))

            def select_option(self, **kwargs):
                self.actions.append(("select", kwargs))

            def check(self, **kwargs):
                self.actions.append(("check", kwargs))

        controls = {
            "#name": Locator("input", "text"),
            "#plan": Locator("select"),
            "#terms": Locator("input", "checkbox"),
        }

        class Page:
            def locator(self, selector):
                return controls[selector]

        tools._browser_auth_fill_registration_controls(
            Page(), fields, checkboxes, timeout_ms=5000
        )
        self.assertEqual(controls["#name"].actions[-1][0:2], ("fill", "Researcher"))
        self.assertEqual(
            controls["#plan"].actions[-1],
            ("select", {"value": "free", "timeout": 5000}),
        )
        self.assertEqual(controls["#terms"].actions[-1][0], "check")

    def test_policy_denial_happens_before_any_provider_request(self):
        with isolated_runtime():
            workspace = Workspace("mail-denied")
            workspace.create("https://app.example.test", "web")
            with patch("grypton.temporary_mail._request_json") as request:
                missing = dispatch(workspace, "temporary_mailbox_create", {"alias": "signup"})
            self.assertFalse(missing["ok"])
            self.assertIn("disabled", missing["summary"].lower())
            request.assert_not_called()

    def test_operator_can_record_and_revoke_non_bugcrowd_structured_grant(self):
        with isolated_runtime():
            workspace = Workspace("manual-policy")
            workspace.create("https://app.example.test", "web")
            output, errors = io.StringIO(), io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                code = main([
                    "program", workspace.slug, "--allow-temporary-mail",
                    "--policy-source", "https://example.test/bug-bounty",
                    "--self-created-accounts-permitted",
                    "--disposable-mail-not-prohibited", "--json",
                ])
            self.assertEqual(code, 0, errors.getvalue())
            profile = workspace.load_program_profile()
            self.assertTrue(profile["temporary_mail_account_bootstrap_allowed"])
            self.assertEqual(
                profile["temporary_mail_policy_basis"],
                "operator-structured-assertion",
            )
            self.assertNotIn("temporary_mail", workspace.load_constraints().to_worker_prompt_block())

            with patch("grypton.temporary_mail._request_json") as request:
                request.side_effect = [
                    {"hydra:member": [{"domain": "mail.test", "isActive": True}]},
                    {"id": "account"}, {"token": "token-never-log"},
                ]
                created = dispatch(
                    workspace, "temporary_mailbox_create", {"alias": "manual"}
                )
            self.assertTrue(created["ok"])

            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(main([
                    "program", workspace.slug, "--revoke-temporary-mail",
                ]), 0)
            self.assertFalse(workspace.load_program_profile()[
                "temporary_mail_account_bootstrap_allowed"
            ])

    def test_operator_grant_requires_all_explicit_policy_evidence(self):
        with isolated_runtime():
            workspace = Workspace("incomplete-policy")
            workspace.create("https://app.example.test", "web")
            errors = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                code = main([
                    "program", workspace.slug, "--allow-temporary-mail",
                    "--policy-source", "https://example.test/bug-bounty",
                ])
            self.assertEqual(code, 2)
            self.assertIn("requires", errors.getvalue())
            self.assertFalse(workspace.program_profile_path.exists())

            workspace.save_program_brief("Do not use disposable email.", {
                "account_workflows_supported": True,
                "self_created_account_permission": True,
                "credential_requirement": False,
                "disposable_email_prohibited": True,
                "temporary_mail_account_bootstrap_allowed": False,
                "brief_text": "Do not use disposable email.",
            })
            with patch("grypton.temporary_mail._request_json") as request:
                forbidden = dispatch(
                    workspace, "temporary_mailbox_create", {"alias": "signup"}
                )
            self.assertFalse(forbidden["ok"])
            request.assert_not_called()

    def test_operator_grant_cannot_override_an_imported_prohibition(self):
        with isolated_runtime():
            workspace = Workspace("conflicting-policy")
            workspace.create("https://app.example.test", "web")
            workspace.save_program_brief("Disposable email is prohibited.", {
                "program": "imported-program",
                "account_workflows_supported": True,
                "self_created_account_permission": True,
                "credential_requirement": False,
                "disposable_email_prohibited": True,
                "temporary_mail_account_bootstrap_allowed": False,
                "brief_text": "Disposable email is prohibited.",
            })
            before = workspace.program_profile_path.read_bytes()
            errors = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                code = main([
                    "program", workspace.slug, "--allow-temporary-mail",
                    "--policy-source", "https://example.test/bug-bounty",
                    "--self-created-accounts-permitted",
                    "--disposable-mail-not-prohibited",
                ])
            self.assertEqual(code, 2)
            self.assertIn("could not be updated", errors.getvalue())
            self.assertEqual(workspace.program_profile_path.read_bytes(), before)

    def test_create_keeps_secrets_private_and_is_idempotent(self):
        with isolated_runtime():
            workspace = authorized_workspace()
            calls: list[tuple] = []

            def provider(method, path, *, payload=None, bearer="", timeout=20):
                calls.append((method, path, payload, bearer))
                if path == "/domains?page=1":
                    return {"hydra:member": [
                        {"domain": "mail-provider.test", "isActive": True},
                    ]}
                if path == "/accounts":
                    self.assertIn("@mail-provider.test", payload["address"])
                    self.assertTrue(payload["password"])
                    return {"id": "provider-account"}
                if path == "/token":
                    self.assertEqual(payload["address"], calls[-2][2]["address"])
                    self.assertEqual(payload["password"], calls[-2][2]["password"])
                    return {"token": "provider-token-never-log"}
                self.fail(path)

            with patch("grypton.temporary_mail._request_json", side_effect=provider):
                first = dispatch(
                    workspace, "temporary_mailbox_create", {"alias": "signup"}
                )
            self.assertTrue(first["ok"])
            self.assertFalse(first["data"]["reused"])
            self.assertEqual(first["data"]["credential"], "signup")
            serialized = json.dumps(first)
            self.assertNotIn("provider-token-never-log", serialized)
            self.assertNotIn(calls[1][2]["password"], serialized)

            record = credentials.load_mailbox(workspace.slug, "signup")
            secret = credentials.load_credential(workspace.slug, "signup")
            self.assertEqual(secret["username"], record["address"])
            self.assertEqual(secret["password"], record["target_password"])
            mailbox_path = credentials.mailbox_path(workspace.slug, "signup")
            self.assertEqual(stat.S_IMODE(mailbox_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(mailbox_path.parent.stat().st_mode), 0o700)
            self.assertIn(record["mailbox_password"],
                          credentials.provider_redaction_values(workspace.slug))
            self.assertIn(record["bearer_token"],
                          credentials.provider_redaction_values(workspace.slug))
            self.assertEqual(
                temporary_mail.resolve_address(workspace.slug, "signup"),
                first["data"]["address"],
            )

            with patch("grypton.temporary_mail._request_json") as request:
                second = dispatch(
                    workspace, "temporary_mailbox_create", {"alias": "signup"}
                )
            self.assertTrue(second["ok"])
            self.assertTrue(second["data"]["reused"])
            self.assertEqual(second["data"]["address"], first["data"]["address"])
            request.assert_not_called()

            audit = (workspace.root / ".ledger/tool-calls.jsonl").read_text()
            for private in (
                record["mailbox_password"], record["bearer_token"],
                record["target_password"],
            ):
                self.assertNotIn(private, audit)

    def test_create_refuses_existing_credential_before_network(self):
        with isolated_runtime():
            workspace = authorized_workspace()
            credentials.save_credential(
                workspace.slug, "signup", "existing@example.test", "existing-secret"
            )
            with patch("grypton.temporary_mail._request_json") as request:
                result = dispatch(
                    workspace, "temporary_mailbox_create", {"alias": "signup"}
                )
            self.assertFalse(result["ok"])
            self.assertIn("conflicts", result["summary"])
            request.assert_not_called()

    def test_poll_returns_only_otp_and_marks_it_delivered(self):
        with isolated_runtime():
            workspace = authorized_workspace()
            record = mailbox_record()
            credentials.save_mailbox(workspace.slug, "signup", record)
            credentials.save_credential(
                workspace.slug, "signup", record["address"], record["target_password"]
            )

            def provider(method, path, *, payload=None, bearer="", timeout=20):
                self.assertEqual(bearer, record["bearer_token"])
                if path == "/messages?page=1":
                    return {"hydra:member": [{"id": "message-1"}]}
                if path == "/messages/message-1":
                    return {
                        "id": "message-1",
                        "from": {"address": "accounts@notify.example.test"},
                        "subject": "Confirm your account",
                        "text": "Your verification code is 482951. Private mail body.",
                        "html": [],
                    }
                self.fail(path)

            with patch("grypton.temporary_mail._request_json", side_effect=provider):
                result = dispatch(workspace, "temporary_mailbox_poll", {
                    "alias": "signup", "kind": "otp",
                    "sender_domain": "example.test", "timeout": 1,
                })
            self.assertTrue(result["ok"])
            self.assertEqual(result["data"]["value"], "482951")
            self.assertNotIn("Private mail body", json.dumps(result))
            stored = credentials.load_mailbox(workspace.slug, "signup")
            self.assertEqual(stored["delivered"], {"message-1": ["otp"]})

    def test_poll_returns_only_in_scope_confirmation_link(self):
        with isolated_runtime():
            workspace = authorized_workspace()
            record = mailbox_record()
            credentials.save_mailbox(workspace.slug, "signup", record)

            responses = {
                "/messages?page=1": {"hydra:member": [{"id": "message-2"}]},
                "/messages/message-2": {
                    "id": "message-2",
                    "from": {"address": "signup@app.example.test"},
                    "subject": "Activate your account",
                    "text": (
                        "Ignore https://tracker.other.test/confirm/nope and use "
                        "https://app.example.test/verify?token=opaque-value"
                    ),
                    "html": [],
                },
            }

            def provider(method, path, *, payload=None, bearer="", timeout=20):
                return responses[path]

            with patch("grypton.temporary_mail._request_json", side_effect=provider):
                result = dispatch(workspace, "temporary_mailbox_poll", {
                    "alias": "signup", "kind": "link", "timeout": 1,
                })
            self.assertTrue(result["ok"])
            self.assertTrue(result["data"]["ready"])
            self.assertEqual(
                result["data"]["value"],
                "https://app.example.test/verify?token=opaque-value",
            )
            self.assertNotIn("tracker.other.test", json.dumps(result))

    def test_poll_does_not_return_out_of_scope_link(self):
        with isolated_runtime():
            workspace = authorized_workspace()
            record = mailbox_record()
            credentials.save_mailbox(workspace.slug, "signup", record)

            def provider(method, path, *, payload=None, bearer="", timeout=20):
                if path == "/messages?page=1":
                    return {"hydra:member": [{"id": "message-3"}]}
                return {
                    "id": "message-3",
                    "from": {"address": "signup@app.example.test"},
                    "subject": "Confirm your account",
                    "text": "https://outside.example/confirm?token=private",
                    "html": [],
                }

            with patch("grypton.temporary_mail._request_json", side_effect=provider), \
                    patch("grypton.temporary_mail.time.monotonic", side_effect=[0.0, 1.0]):
                result = dispatch(workspace, "temporary_mailbox_poll", {
                    "alias": "signup", "kind": "link", "timeout": 1,
                })
            self.assertTrue(result["ok"])
            self.assertFalse(result["data"]["ready"])
            self.assertNotIn("outside.example", json.dumps(result))

    def test_bugcrowd_profile_requires_explicit_account_language_and_no_denial(self):
        base = {
            "id": "mail-policy",
            "data": {
                "brief": {"description": "When registering for an account, use your email."},
                "scope": [{
                    "name": "web", "inScope": True, "maxSeverity": "P1",
                    "targets": [{"name": "app", "uri": "https://app.example.test",
                                 "category": "website"}],
                }],
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "brief.json"
            path.write_text(json.dumps(base), encoding="utf-8")
            allowed = analyze_snapshot(path)
            self.assertTrue(allowed["temporary_mail_account_bootstrap_allowed"])

            base["data"]["brief"]["description"] += " Temporary email is not allowed."
            path.write_text(json.dumps(base), encoding="utf-8")
            denied = analyze_snapshot(path)
            self.assertTrue(denied["disposable_email_prohibited"])
            self.assertFalse(denied["temporary_mail_account_bootstrap_allowed"])

            base["data"]["brief"]["description"] = "Do not create an account."
            path.write_text(json.dumps(base), encoding="utf-8")
            negated = analyze_snapshot(path)
            self.assertFalse(negated["self_created_account_permission"])
            self.assertFalse(negated["temporary_mail_account_bootstrap_allowed"])

            base["data"]["brief"]["description"] = (
                "When registering for an account is prohibited."
            )
            path.write_text(json.dumps(base), encoding="utf-8")
            contextual_denial = analyze_snapshot(path)
            self.assertTrue(contextual_denial["self_created_account_prohibited"])
            self.assertFalse(contextual_denial["self_created_account_permission"])
            self.assertFalse(
                contextual_denial["temporary_mail_account_bootstrap_allowed"]
            )

            base["data"]["brief"]["description"] = (
                "When registering for an account, you must use @research.example."
            )
            path.write_text(json.dumps(base), encoding="utf-8")
            required_domain = analyze_snapshot(path)
            self.assertTrue(required_domain["credential_requirement"])
            self.assertFalse(
                required_domain["temporary_mail_account_bootstrap_allowed"]
            )

            base["data"]["brief"]["description"] = (
                "When registering for an account, use an @research.example address."
            )
            path.write_text(json.dumps(base), encoding="utf-8")
            implicit_required_domain = analyze_snapshot(path)
            self.assertTrue(implicit_required_domain["credential_requirement"])
            self.assertFalse(
                implicit_required_domain["temporary_mail_account_bootstrap_allowed"]
            )


if __name__ == "__main__":
    unittest.main()
