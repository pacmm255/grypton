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
        self.assertEqual(
            signup["properties"]["flow"]["enum"],
            ["one-page", "identifier-otp"],
        )
        self.assertEqual(
            signup["properties"]["submission_origins"]["maxItems"], 8
        )
        self.assertEqual(
            signup["properties"]["submission_preflight_urls"]["maxItems"], 4
        )
        continuation = REGISTRY["temporary_account_browser_continue"][1]
        self.assertIn("otp_submission_url", continuation["properties"])
        stages = continuation["properties"]["post_otp_stages"]
        self.assertEqual(stages["maxItems"], 6)
        self.assertEqual(
            stages["items"]["required"], ["submit_selector"]
        )
        self.assertEqual(
            stages["items"]["properties"]["fields"]["maxProperties"], 20
        )
        self.assertEqual(
            stages["items"]["properties"]["choice_selectors"]["maxItems"], 4
        )
        self.assertEqual(
            stages["items"]["properties"]["action_only"]["type"], "boolean"
        )

    def test_invalid_onboarding_fields_never_enter_the_audit_ledger(self):
        with isolated_runtime():
            workspace = authorized_workspace()
            record = mailbox_record()
            credentials.save_mailbox(workspace.slug, "signup", record)
            credentials.save_credential(
                workspace.slug, "signup", record["address"],
                record["target_password"],
            )
            seventh_private = "seventh-stage-private-never-log"
            nested_private = "nested-private-never-log"
            seven_stages = [
                {
                    "fields": {
                        "#name": (
                            seventh_private if index == 6 else f"stage-{index}"
                        ),
                    },
                    "submit_selector": "#next",
                }
                for index in range(7)
            ]
            too_many = dispatch(
                workspace, "temporary_account_browser_continue",
                {"alias": "signup", "post_otp_stages": seven_stages},
            )
            malformed = dispatch(
                workspace, "temporary_account_browser_continue",
                {
                    "alias": "signup",
                    "post_otp_stages": [{
                        "fields": {"#name": {"wrapped": nested_private}},
                        "submit_selector": "#next",
                    }],
                },
            )

            self.assertFalse(too_many["ok"])
            self.assertFalse(malformed["ok"])
            audit = (workspace.root / ".ledger/tool-calls.jsonl").read_text()
            self.assertNotIn(seventh_private, audit)
            self.assertNotIn(nested_private, audit)
            self.assertIn("[TRUNCATED_STAGES]", audit)
            self.assertIn("[REDACTED]", audit)

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
                    "submission_origins": ["https://api.example.test"],
                    "submission_url": "https://api.example.test/auth/signup",
                    "submission_preflight_urls": [
                        "https://api.example.test/auth/check-email"
                    ],
                })
            self.assertEqual(result, expected)
            _, called_url = browser.call_args.args
            called = browser.call_args.kwargs
            self.assertEqual(called_url, "https://app.example.test/signup")
            self.assertEqual(called["credential"], "signup")
            self.assertEqual(called["registration_fields"]["#name"], "Grypton Research")
            self.assertEqual(called["registration_checkboxes"], ["#terms"])
            self.assertEqual(
                called["_additional_submission_origins"],
                ["https://api.example.test"],
            )
            self.assertEqual(
                called["_submission_url"],
                "https://api.example.test/auth/signup",
            )
            self.assertEqual(called["_submission_preflight_urls"], [
                "https://api.example.test/auth/check-email",
            ])
            candidate = called["_profile_candidate"]
            self.assertEqual(candidate["strategy"], "browser")
            self.assertEqual(
                candidate["login_url"], "https://app.example.test/signup"
            )
            self.assertIsNone(
                credentials.load_auth_profile_optional(workspace.slug, "signup")
            )
            rendered = repr(browser.call_args)
            self.assertNotIn(record["mailbox_password"], rendered)
            self.assertNotIn(record["bearer_token"], rendered)
            self.assertNotIn(record["target_password"], rendered)

    def test_identifier_otp_signup_passes_private_profile_candidate(self):
        with isolated_runtime():
            workspace = authorized_workspace()
            record = mailbox_record()
            credentials.save_mailbox(workspace.slug, "signup", record)
            credentials.save_credential(
                workspace.slug, "signup", record["address"], record["target_password"]
            )
            expected = {"ok": True, "summary": "OTP challenge retained."}
            with patch(
                "grypton.toolserver.tools.credential_browser_begin_step_up",
                return_value=expected,
            ) as browser:
                result = dispatch(workspace, "temporary_account_browser_signup", {
                    "url": "https://app.example.test/signup",
                    "alias": "signup",
                    "verify_url": "https://app.example.test/profile",
                    "success_marker": "Account profile",
                    "flow": "identifier-otp",
                    "email_selector": "input[name='email']",
                    "submit_selector": "form button[type='submit']",
                    "fields": {"#name": "Grypton Research"},
                    "checkboxes": ["#terms", "#privacy"],
                    "submission_origins": ["https://api.example.test"],
                    "submission_url": "https://api.example.test/auth/signup",
                    "submission_preflight_urls": [
                        "https://api.example.test/auth/check-email"
                    ],
                })
            self.assertEqual(result, expected)
            called = browser.call_args.kwargs
            self.assertEqual(called["credential"], "signup")
            self.assertEqual(called["registration_fields"], {
                "#name": "Grypton Research",
            })
            self.assertEqual(called["registration_checkboxes"], [
                "#terms", "#privacy",
            ])
            self.assertEqual(
                called["_additional_submission_origins"],
                ["https://api.example.test"],
            )
            self.assertEqual(
                called["_submission_url"],
                "https://api.example.test/auth/signup",
            )
            self.assertEqual(called["_submission_preflight_urls"], [
                "https://api.example.test/auth/check-email",
            ])
            profile = called["_profile_candidate"]
            self.assertEqual(profile["strategy"], "browser")
            self.assertEqual(
                profile["browser"]["username_selector"], "input[name='email']"
            )
            self.assertIsNone(
                credentials.load_auth_profile_optional(workspace.slug, "signup")
            )
            rendered = repr(browser.call_args)
            for private in (
                record["address"], record["mailbox_password"],
                record["bearer_token"], record["target_password"],
            ):
                self.assertNotIn(private, rendered)

    def test_identifier_otp_scope_failure_does_not_persist_profile(self):
        with isolated_runtime():
            workspace = authorized_workspace()
            record = mailbox_record()
            credentials.save_mailbox(workspace.slug, "signup", record)
            credentials.save_credential(
                workspace.slug, "signup", record["address"], record["target_password"]
            )

            result = dispatch(workspace, "temporary_account_browser_signup", {
                "url": "https://outside.example/signup",
                "alias": "signup",
                "verify_url": "https://outside.example/profile",
                "success_marker": "Account profile",
                "flow": "identifier-otp",
            })

            self.assertFalse(result["ok"], result)
            self.assertIn("Scope blocked", result["summary"])
            self.assertIsNone(
                credentials.load_auth_profile_optional(workspace.slug, "signup")
            )
            self.assertEqual(
                credentials.session_status(workspace.slug, "signup")["attempts"], 0
            )

    def test_private_otp_continuation_does_not_put_code_in_tool_arguments_or_result(self):
        with isolated_runtime():
            workspace = authorized_workspace()
            record = mailbox_record()
            credentials.save_mailbox(workspace.slug, "signup", record)
            credentials.save_credential(
                workspace.slug, "signup", record["address"], record["target_password"]
            )
            otp = "739251"
            private_workspace = "Private Workspace Never Log"
            private_first_name = "Private Given Never Log"
            private_sixth_value = "Private Sixth Stage Never Log"
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
                    {
                        "alias": "signup", "sender_domain": "example.test",
                        "otp_submission_url": (
                            "https://api.example.test/auth/verify-otp"
                        ),
                        "post_otp_stages": [{
                            "fields": {
                                "#workspace": private_workspace,
                                "#first-name": private_first_name,
                            },
                            "checkboxes": ["#profile-consent"],
                            "choice_selectors": [
                                "#company-size-trigger", "#company-small",
                            ],
                            "submit_selector": "#profile-next",
                        }, {
                            "fields": {"#second": "Private Second"},
                            "submit_selector": "#second-next",
                        }, {
                            "fields": {"#third": "Private Third"},
                            "submit_selector": "#third-next",
                        }, {
                            "fields": {"#fourth": "Private Fourth"},
                            "submit_selector": "#fourth-next",
                        }, {
                            "fields": {"#fifth": "Private Fifth"},
                            "submit_selector": "#fifth-next",
                        }, {
                            "fields": {"#sixth": private_sixth_value},
                            "submit_selector": "#sixth-next",
                        }],
                    },
                )
            self.assertTrue(result["ok"])
            self.assertTrue(result["data"]["ready"])
            self.assertEqual(continuation.call_args.kwargs["otp"], otp)
            self.assertEqual(
                continuation.call_args.kwargs["otp_submission_url"],
                "https://api.example.test/auth/verify-otp",
            )
            self.assertEqual(
                continuation.call_args.kwargs["post_otp_stages"][0]["fields"],
                {
                    "#workspace": private_workspace,
                    "#first-name": private_first_name,
                },
            )
            mark_delivered.assert_called_once_with(
                workspace, "signup", "mail-otp", "otp"
            )
            self.assertNotIn(otp, json.dumps(result))
            audit = (workspace.root / ".ledger/tool-calls.jsonl").read_text()
            self.assertNotIn(otp, audit)
            self.assertNotIn(private_workspace, audit)
            self.assertNotIn(private_first_name, audit)
            self.assertNotIn(private_sixth_value, audit)
            self.assertIn("#workspace", audit)

    def test_private_otp_continuation_remains_pending_when_no_code_arrives(self):
        with isolated_runtime():
            workspace = authorized_workspace()
            record = mailbox_record()
            credentials.save_mailbox(workspace.slug, "signup", record)
            credentials.save_credential(
                workspace.slug, "signup", record["address"],
                record["target_password"],
            )
            with patch(
                "grypton.toolserver.temporary_mail.poll",
                return_value={
                    "ok": True,
                    "summary": "No matching OTP arrived.",
                    "data": {"alias": "signup", "ready": False},
                },
            ), patch(
                "grypton.toolserver.credentials.load_auth_profile_optional",
                return_value={"strategy": "browser"},
            ), patch(
                "grypton.toolserver.credentials.load_pending_browser_step_up",
                return_value={"available": True},
            ), patch(
                "grypton.toolserver.tools.credential_browser_step_up",
            ) as continuation:
                result = dispatch(
                    workspace, "temporary_account_browser_continue",
                    {"alias": "signup", "sender_domain": "example.test"},
                )

            self.assertFalse(result["ok"])
            self.assertFalse(result["data"]["ready"])
            self.assertTrue(result["data"]["pending"])
            self.assertIn("remains pending", result["summary"])
            continuation.assert_not_called()

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

        stages = tools._browser_post_otp_stages([{
            "fields": {"#workspace": "Research", "#size": "small"},
            "checkboxes": ["#terms"],
            "choice_selector": "#small-company",
            "submit_selector": "#next",
        }])
        self.assertEqual(len(stages), 1)
        self.assertEqual(stages[0]["fields"]["#size"], "small")
        self.assertEqual(stages[0]["choice_selectors"], ["#small-company"])
        action_only = tools._browser_post_otp_stages([{
            "action_only": True, "submit_selector": "#skip",
        }])
        self.assertTrue(action_only[0]["action_only"])
        self.assertEqual(action_only[0]["fields"], {})
        ordered_choices = tools._browser_post_otp_stages([{
            "fields": {"#workspace": "Research"},
            "choice_selectors": ["#open", "#small"],
            "submit_selector": "#next",
        }])
        self.assertEqual(
            ordered_choices[0]["choice_selectors"], ["#open", "#small"]
        )
        with self.assertRaisesRegex(ValueError, "at most 6"):
            tools._browser_post_otp_stages([
                {"fields": {"#name": "value"}, "submit_selector": "#next"}
                for _index in range(7)
            ])
        with self.assertRaisesRegex(ValueError, "nonempty field"):
            tools._browser_post_otp_stages([{
                "fields": {}, "submit_selector": "#next",
            }])
        with self.assertRaisesRegex(ValueError, "at most 4 choice selectors"):
            tools._browser_post_otp_stages([{
                "fields": {"#name": "value"},
                "choice_selector": "#first",
                "choice_selectors": [
                    "#second", "#third", "#fourth", "#fifth",
                ],
                "submit_selector": "#next",
            }])
        with self.assertRaisesRegex(ValueError, "action_only cannot include"):
            tools._browser_post_otp_stages([{
                "action_only": True,
                "fields": {"#name": "value"},
                "submit_selector": "#skip",
            }])
        with self.assertRaisesRegex(ValueError, "unsupported settings"):
            tools._browser_post_otp_stages([{
                "fields": {"#name": "value"}, "submit_selector": "#next",
                "password": "not accepted",
            }])

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
            Page(), fields, checkboxes, timeout_ms=5000, fill=False
        )
        self.assertFalse(any(
            action[0] in {"fill", "select", "check"}
            for control in controls.values() for action in control.actions
        ))
        tools._browser_auth_fill_registration_controls(
            Page(), fields, checkboxes, timeout_ms=5000
        )
        self.assertEqual(controls["#name"].actions[-1][0:2], ("fill", "Researcher"))
        self.assertEqual(
            controls["#plan"].actions[-1],
            ("select", {"value": "free", "timeout": 5000}),
        )
        self.assertEqual(controls["#terms"].actions[-1][0], "check")
        self.assertTrue(tools._browser_auth_captcha_markup(
            '<script src="https://www.google.com/recaptcha/api.js"></script>'
        ))
        self.assertFalse(tools._browser_auth_captcha_markup(
            '<p>Our privacy policy discusses CAPTCHA protection.</p>'
        ))

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
            self.assertNotIn(calls[1][2]["address"], serialized)
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
                record["address"],
            )

            with patch("grypton.temporary_mail._request_json") as request:
                second = dispatch(
                    workspace, "temporary_mailbox_create", {"alias": "signup"}
                )
            self.assertTrue(second["ok"])
            self.assertTrue(second["data"]["reused"])
            self.assertNotIn("address", second["data"])
            request.assert_not_called()

            audit = (workspace.root / ".ledger/tool-calls.jsonl").read_text()
            for private in (
                record["address"], record["mailbox_password"], record["bearer_token"],
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

    def test_poll_extracts_russian_confirmation_code(self):
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
                    return {"hydra:member": [{"id": "message-ru"}]}
                if path == "/messages/message-ru":
                    return {
                        "id": "message-ru",
                        "from": {"address": "accounts@pachca.example"},
                        "subject": "Ваш код подтверждения",
                        "text": (
                            "Ваш код подтверждения в Пачке: 731905. "
                            "Код действителен в течение 15 минут."
                        ),
                        "html": [],
                    }
                self.fail(path)

            with patch("grypton.temporary_mail._request_json", side_effect=provider):
                result = dispatch(workspace, "temporary_mailbox_poll", {
                    "alias": "signup", "kind": "otp",
                    "sender_domain": "pachca.example", "timeout": 1,
                })
            self.assertTrue(result["ok"])
            self.assertTrue(result["data"]["ready"])
            self.assertEqual(result["data"]["value"], "731905")
            self.assertNotIn("Код действителен", json.dumps(result))

    def test_otp_extraction_rejects_unlabelled_number(self):
        messages = (
            {
                "subject": "Invoice 731905",
                "text": "Your account invoice number is 731905.",
                "html": [],
            },
            {
                "subject": "Ваш промокод",
                "text": "Промокод: 731905.",
                "html": [],
            },
            {
                "subject": "Заказ",
                "text": "Код заказа: 731905.",
                "html": [],
            },
            {
                "subject": "Адрес",
                "text": "Почтовый код: 731905.",
                "html": [],
            },
            {
                "subject": "Ваш код подтверждения",
                "text": "Номер заказа: 731905.",
                "html": [],
            },
            {
                "subject": "Authentication support",
                "text": "Authentication support request reference: 731905.",
                "html": [],
            },
            {
                "subject": "Security newsletter",
                "text": "Security newsletter issue number is 731905.",
                "html": [],
            },
            {
                "subject": "Login activity",
                "text": "Login activity report reference: 731905.",
                "html": [],
            },
            {
                "subject": "Authentication ref",
                "text": "Authentication ref: 731905.",
                "html": [],
            },
            {
                "subject": "Security issue",
                "text": "Security issue: 731905.",
                "html": [],
            },
            {
                "subject": "Login report",
                "text": "Login report: 731905.",
                "html": [],
            },
            {
                "subject": "Confirmation order",
                "text": "Confirmation order: 731905.",
                "html": [],
            },
            {
                "subject": "Заказ",
                "text": "Код подтверждения заказа: 731905.",
                "html": [],
            },
            {
                "subject": "Скидка",
                "text": "Промокод 731905 — код подтверждения скидки.",
                "html": [],
            },
        )
        for message in messages:
            with self.subTest(subject=message["subject"]):
                self.assertEqual(
                    temporary_mail._extract(
                        "otp", message, lambda _url: False
                    ),
                    "",
                )

    def test_otp_extraction_accepts_exact_subject_and_standalone_body(self):
        for message in (
            {
                "subject": "Your verification code",
                "text": "731905",
                "html": [],
            },
            {
                "subject": "Ваш код подтверждения",
                "text": "731905.",
                "html": [],
            },
        ):
            with self.subTest(subject=message["subject"]):
                self.assertEqual(
                    temporary_mail._extract(
                        "otp", message, lambda _url: False
                    ),
                    "731905",
                )

    def test_otp_extraction_accepts_label_is_punctuation(self):
        for text in (
            "Your verification code is: 731905",
            "OTP is: 731905",
            "Authentication code is: 731905",
        ):
            with self.subTest(text=text):
                self.assertEqual(
                    temporary_mail._extract(
                        "otp",
                        {"subject": "", "text": text, "html": []},
                        lambda _url: False,
                    ),
                    "731905",
                )

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
                "brief": {"description": (
                    "Researchers may create an account. "
                    "When registering for an account, use your email."
                )},
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

            for description in (
                (
                    "Researchers may create an account. API requests require "
                    "an Authorization header."
                ),
                "You may sign up for an account using your personal email address.",
                (
                    "Researchers may create an account. Approval is required "
                    "before submitting a vulnerability report."
                ),
                (
                    "Researchers may create an account and test invitation "
                    "acceptance."
                ),
                (
                    "You may create an account and then create an access token "
                    "from Account Settings."
                ),
                "You must create accounts for testing purposes.",
                "Researchers may create an account. No credentials are provided.",
                (
                    "Provided credentials are optional. Researchers may create "
                    "an account."
                ),
                (
                    "Researchers may create an account using self-assigned "
                    "credentials."
                ),
                (
                    "Researchers may create an account. Automated testing is "
                    "not forbidden."
                ),
                (
                    "Researchers may create an account. Temporary email is not "
                    "prohibited."
                ),
                (
                    "Researchers may create an account. No temporary email "
                    "restrictions apply."
                ),
            ):
                with self.subTest(description=description):
                    base["data"]["brief"]["description"] = description
                    path.write_text(json.dumps(base), encoding="utf-8")
                    unrelated = analyze_snapshot(path)
                    self.assertTrue(unrelated["self_created_account_permission"])
                    self.assertFalse(unrelated["credential_requirement"])
                    self.assertFalse(unrelated["automation_prohibited"])
                    self.assertFalse(unrelated["disposable_email_prohibited"])
                    self.assertTrue(
                        unrelated["temporary_mail_account_bootstrap_allowed"]
                    )

            base["data"]["brief"]["description"] = (
                "You may create an access token from the Account Settings page."
            )
            path.write_text(json.dumps(base), encoding="utf-8")
            access_token = analyze_snapshot(path)
            self.assertFalse(access_token["self_created_account_permission"])
            self.assertFalse(
                access_token["temporary_mail_account_bootstrap_allowed"]
            )

            for description in (
                (
                    "You may sign up for an account using your "
                    "@bugcrowdninja.com email address."
                ),
                (
                    "Researchers can sign up for an account using an "
                    "@security.example address."
                ),
                (
                    "You must create accounts using an "
                    "@bugcrowdninja.com email address."
                ),
            ):
                with self.subTest(description=description):
                    base["data"]["brief"]["description"] = description
                    path.write_text(json.dumps(base), encoding="utf-8")
                    required_signup_domain = analyze_snapshot(path)
                    self.assertTrue(required_signup_domain["credential_requirement"])
                    self.assertFalse(
                        required_signup_domain[
                            "temporary_mail_account_bootstrap_allowed"
                        ]
                    )

            base["data"]["brief"]["description"] = (
                'For ordinary customers, select "Sign Up".'
            )
            path.write_text(json.dumps(base), encoding="utf-8")
            ui_instruction = analyze_snapshot(path)
            self.assertFalse(ui_instruction["self_created_account_permission"])
            self.assertFalse(
                ui_instruction["temporary_mail_account_bootstrap_allowed"]
            )

            base["data"]["brief"]["description"] = (
                "When registering for an account, obtain written authorization "
                "from support first."
            )
            path.write_text(json.dumps(base), encoding="utf-8")
            conditional = analyze_snapshot(path)
            self.assertFalse(conditional["self_created_account_permission"])
            self.assertFalse(
                conditional["temporary_mail_account_bootstrap_allowed"]
            )

            for description in (
                'Do not select "Sign Up".',
                'You are not allowed to select "Sign Up".',
                'You are not permitted to select "Sign Up".',
                'It is not allowed to select "Sign Up".',
                "Researchers may create an account. Do not sign up.",
                "Only authorized researchers may create an account.",
                "Invited researchers may create an account.",
                "Researchers may create an account when approved.",
                "By invitation only, researchers may create an account.",
                (
                    "Subject to prior approval, researchers may create an "
                    "account."
                ),
                (
                    "Prior approval required from support. Researchers may "
                    "create an account."
                ),
                (
                    "Researchers may create an account. Obtain written approval "
                    "from support first."
                ),
                (
                    "Researchers may create an account. Approval must be obtained "
                    "from support."
                ),
                (
                    "Researchers can create an account only with prior written "
                    "permission from support."
                ),
                "Researchers may create an account if invited by the program.",
                (
                    "Researchers may create an account provided that support "
                    "approves."
                ),
                (
                    "Researchers may create an account. You must receive written "
                    "approval from support first."
                ),
                (
                    "Researchers may create an account. An invitation from support "
                    "is required."
                ),
                (
                    "Researchers may create an account. Registration requires an "
                    "invitation from support."
                ),
                (
                    "Researchers may create an account. You must be invited by "
                    "support."
                ),
                (
                    "Researchers may create an account. Never create an account "
                    "without approval."
                ),
            ):
                with self.subTest(description=description):
                    base["data"]["brief"]["description"] = description
                    path.write_text(json.dumps(base), encoding="utf-8")
                    qualified = analyze_snapshot(path)
                    self.assertFalse(
                        qualified["self_created_account_permission"]
                    )
                    self.assertFalse(
                        qualified["temporary_mail_account_bootstrap_allowed"]
                    )

            for description in (
                "Researchers may create an account using the assigned credentials.",
                (
                    "Researchers may create an account. Credentials will be "
                    "provided by support."
                ),
                (
                    "Researchers may create an account. Credentials provided by "
                    "support must be used."
                ),
                (
                    "Researchers may create an account. Only program-provided "
                    "accounts may be used."
                ),
                (
                    "Researchers may create an account. Use only the test "
                    "account issued by support."
                ),
                (
                    "Researchers may create an account. Use the login supplied "
                    "by support."
                ),
                "You must create accounts using the assigned credentials.",
                "You must create accounts provided by the program.",
            ):
                with self.subTest(description=description):
                    base["data"]["brief"]["description"] = description
                    path.write_text(json.dumps(base), encoding="utf-8")
                    assigned = analyze_snapshot(path)
                    self.assertTrue(assigned["credential_requirement"])
                    self.assertFalse(assigned["self_created_account_permission"])
                    self.assertFalse(
                        assigned["temporary_mail_account_bootstrap_allowed"]
                    )

            base["data"]["brief"]["description"] = (
                "Researchers may create an account. "
                "When registering for an account, use your email."
            )

            base["data"]["brief"]["description"] += " Temporary email is not allowed."
            path.write_text(json.dumps(base), encoding="utf-8")
            denied = analyze_snapshot(path)
            self.assertTrue(denied["disposable_email_prohibited"])
            self.assertFalse(denied["temporary_mail_account_bootstrap_allowed"])

            base["data"]["brief"]["description"] = (
                "Researchers may create an account. Automated testing is forbidden."
            )
            path.write_text(json.dumps(base), encoding="utf-8")
            automation_denied = analyze_snapshot(path)
            self.assertTrue(automation_denied["automation_prohibited"])

            base["data"]["brief"]["description"] = (
                "Researchers may create an account. Never use temporary email."
            )
            path.write_text(json.dumps(base), encoding="utf-8")
            never_temporary = analyze_snapshot(path)
            self.assertTrue(never_temporary["disposable_email_prohibited"])
            self.assertFalse(
                never_temporary["temporary_mail_account_bootstrap_allowed"]
            )

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

    def test_bugcrowd_profile_recognizes_uxcam_self_provisioning_clause(self):
        snapshot = {
            "id": "uxcam-mail-policy",
            "data": {
                "brief": {"description": ""},
                "scope": [{
                    "name": "web", "inScope": True, "maxSeverity": "P1",
                    "targets": [{
                        "name": "UXCam", "uri": "https://app.uxcam.com",
                        "category": "website",
                    }],
                }],
            },
        }
        affirmative = (
            "Accounts can be self-provisioned for testing at "
            "app.uxcam.com/signup, and you will get a free 14-day trial."
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "brief.json"
            for description, expected in (
                (affirmative, True),
                (
                    affirmative
                    + " Accounts can be self-provisioned for testing only with "
                    "prior approval.",
                    False,
                ),
                (
                    affirmative
                    + " Credentials will be provided by the program.",
                    False,
                ),
                ("Accounts cannot be self-provisioned for testing.", False),
                ("No accounts can be self-provisioned for testing.", False),
                (
                    "Only approved accounts can be self-provisioned for testing.",
                    False,
                ),
                (
                    affirmative + " Self-provisioning accounts is prohibited.",
                    False,
                ),
            ):
                with self.subTest(description=description):
                    snapshot["data"]["brief"]["description"] = description
                    path.write_text(json.dumps(snapshot), encoding="utf-8")
                    profile = analyze_snapshot(path)
                    self.assertEqual(
                        profile["temporary_mail_account_bootstrap_allowed"],
                        expected,
                    )
                    self.assertEqual(
                        profile["self_created_account_permission"], expected
                    )


if __name__ == "__main__":
    unittest.main()
