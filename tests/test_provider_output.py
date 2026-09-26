from __future__ import annotations

import asyncio
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from grypton import config, credentials
from grypton.manager import KryptexManager, ManagerContext
from grypton.providers import (MAX_ASSISTANT_TEXT_CHARS, OpenCodeClient,
                               OpenCodeResult, ProviderError,
                               _select_assistant_text, clean)
from grypton.workspace import Workspace


@contextmanager
def isolated_runtime():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        state = root / ".state"
        values = {
            "STATE_DIR": state,
            "ENGAGEMENTS_DIR": state / "engagements",
            "TARGETS_DIR": state / "engagements",
            "RUNTIME_DIR": state / "runtime",
            "LOG_DIR": state / "runtime/logs",
            "PROVIDER_DIR": state / "providers",
            "CREDENTIALS_DIR": state / "credentials",
            "OPENCODE_WORKSPACES_DIR": root / ".opencode-workspaces",
            "TARGET_DATA_DIR": root / "target",
        }
        with patch.multiple(config, **values):
            config.ensure_layout()
            yield root


class ProviderOutputTests(unittest.TestCase):
    def test_pre_spawn_provider_failure_is_replay_safe(self):
        async def exercise():
            with isolated_runtime():
                workspace = config.ENGAGEMENTS_DIR / "pre-spawn-call"
                workspace.mkdir(parents=True)
                client = OpenCodeClient(
                    role="worker", route=config.WORKER_MODEL, effort="max",
                    workspace=workspace, target_slug="pre-spawn-call",
                    allow_tools=True, agent_prompt="test",
                )
                failure = ProviderError("gateway unavailable")
                with patch.object(
                    client, "_ensure_gateway", AsyncMock(side_effect=failure)
                ), patch.object(
                    config, "require_binary", return_value="/usr/bin/true"
                ), patch(
                    "grypton.providers.asyncio.create_subprocess_exec",
                    new=AsyncMock(),
                ) as spawn:
                    with self.assertRaisesRegex(
                        ProviderError, "gateway unavailable"
                    ) as raised:
                        await client.call("fixture prompt")
                self.assertIs(raised.exception.metadata["replay_safe"], True)
                spawn.assert_not_awaited()

        asyncio.run(exercise())

    def test_selects_and_normalizes_substantive_final_text(self):
        final = "\n".join([
            "Observed POST /app/session returned HTTP 401 without a cookie.",
            "Evidence: flow-17 records the response headers.",
            "Evidence: flow-17 records the response headers.",
            "✅ ✅ ✅ ✅",
            "Now I will provide the final answer.",
            "I should emit final response now.",
            "🏁 Done.",
        ])
        parts = ["Pre-tool narration must not enter the result.", final]
        original = list(parts)

        text, metadata = _select_assistant_text(parts)

        self.assertEqual(parts, original)
        self.assertIn("POST /app/session returned HTTP 401", text)
        self.assertEqual(text.count("flow-17 records the response headers"), 1)
        self.assertNotIn("Pre-tool narration", text)
        self.assertNotIn("provide the final answer", text)
        self.assertNotIn("emit final response", text)
        self.assertNotIn("✅", text)
        self.assertEqual(metadata["raw_text_part_count"], 2)
        self.assertEqual(metadata["raw_final_text_chars"], len(final))
        self.assertEqual(metadata["normalized_text_chars"], len(text))
        self.assertEqual(metadata["selected_text_part_index"], 1)
        self.assertTrue(metadata["text_filtered"])
        self.assertFalse(metadata["text_truncated"])

    def test_falls_back_when_final_part_is_only_chatter(self):
        text, metadata = _select_assistant_text([
            "Authentication was not attempted; the login endpoint is still unknown.",
            "✅\nDone.\nNow I will provide the final response.",
        ])

        self.assertIn("login endpoint is still unknown", text)
        self.assertNotIn("provide the final response", text)
        self.assertEqual(metadata["selected_text_part_index"], 0)
        self.assertTrue(metadata["text_filtered"])

    def test_bounds_unique_substantive_output(self):
        raw = "\n".join(
            f"Evidence {index}: GET /app/item/{index} returned HTTP 200."
            for index in range(1000)
        )

        text, metadata = _select_assistant_text([raw])

        self.assertLessEqual(len(text), MAX_ASSISTANT_TEXT_CHARS)
        self.assertIn("normalized response truncated", text)
        self.assertIn("/app/item/0", text)
        self.assertIn("/app/item/999", text)
        self.assertEqual(metadata["raw_final_text_chars"], len(raw))
        self.assertEqual(metadata["normalized_text_chars"], len(text))
        self.assertTrue(metadata["text_filtered"])
        self.assertTrue(metadata["text_truncated"])

    def test_call_keeps_raw_events_and_records_filter_metadata(self):
        class _Input:
            def write(self, value):
                self.value = value

            async def drain(self):
                return None

            def close(self):
                return None

        class _Stream:
            def __init__(self, payload=b""):
                self.payload = payload

            async def read(self, _size):
                payload, self.payload = self.payload, b""
                return payload

        class _Process:
            pid = 43210

            def __init__(self, stdout):
                self.stdin = _Input()
                self.stdout = _Stream(stdout)
                self.stderr = _Stream()
                self.returncode = None

            async def wait(self):
                self.returncode = 0
                return 0

        async def exercise():
            with isolated_runtime():
                workspace = config.ENGAGEMENTS_DIR / "normalized-call"
                workspace.mkdir(parents=True)
                client = OpenCodeClient(
                    role="worker", route=config.WORKER_MODEL, effort="max",
                    workspace=workspace, target_slug="normalized-call",
                    allow_tools=True, agent_prompt="test",
                )
                final = "Useful result: GET /app returned HTTP 200.\n✅\nDone."
                events = [
                    {"type": "text", "sessionID": "ses-fixture",
                     "part": {"text": "Pre-tool narration."}},
                    {"type": "text", "sessionID": "ses-fixture",
                     "part": {"text": final}},
                ]
                payload = b"".join(
                    (json.dumps(event, ensure_ascii=False) + "\n").encode()
                    for event in events
                )
                process = _Process(payload)
                gateway = SimpleNamespace(
                    model_route=f"openclaude/{config.WORKER_MODEL}",
                    drain_events=lambda: [],
                )
                with patch.object(client, "_ensure_gateway", AsyncMock(return_value=gateway)), \
                        patch.object(client, "_environment", return_value=({}, "fixture-secret")), \
                        patch.object(client, "_ensure_network_broker", AsyncMock()), \
                        patch.object(config, "require_binary", return_value="/usr/bin/true"), \
                        patch("grypton.providers.asyncio.create_subprocess_exec",
                              new=AsyncMock(return_value=process)):
                    result = await client.call("bounded prompt")

                self.assertIn("GET /app returned HTTP 200", result.text)
                self.assertNotIn("Pre-tool narration", result.text)
                raw_events = [json.loads(line) for line in (
                    workspace / "transcripts/worker.opencode.events.jsonl"
                ).read_text().splitlines()]
                self.assertEqual(raw_events, events)
                record = json.loads((
                    workspace / "transcripts/provider-calls.jsonl"
                ).read_text().splitlines()[-1])
                self.assertEqual(len((
                    workspace / "transcripts/provider-calls.jsonl"
                ).read_text().splitlines()), 1)
                self.assertEqual(record["raw_final_text_chars"], len(final))
                self.assertEqual(record["normalized_text_chars"], len(result.text))
                self.assertTrue(record["text_filtered"])

        asyncio.run(exercise())

    def test_clean_redacts_common_native_tool_credentials(self):
        cases = {
            "Set-Cookie: app_session=SYNTHETIC_COOKIE_VALUE; HttpOnly": (
                "SYNTHETIC_COOKIE_VALUE",
            ),
            "Cookie: app_session=SYNTHETIC_COOKIE_VALUE": (
                "SYNTHETIC_COOKIE_VALUE",
            ),
            "Authorization: Basic U1lOVEhFVElDOlZBTFVF": (
                "U1lOVEhFVElDOlZBTFVF",
            ),
            "Authorization: Bearer SYNTHETIC_BEARER+/=": (
                "SYNTHETIC_BEARER+/=",
            ),
            '{"access_token":"SYNTHETIC_ACCESS_VALUE",'
            '"refreshToken":"SYNTHETIC_REFRESH_VALUE",'
            '"session_token":"SYNTHETIC_SESSION_VALUE",'
            '"password":"SYNTHETIC_PASSWORD_VALUE"}': (
                "SYNTHETIC_ACCESS_VALUE", "SYNTHETIC_REFRESH_VALUE",
                "SYNTHETIC_SESSION_VALUE", "SYNTHETIC_PASSWORD_VALUE",
            ),
            "https://synthetic-user:SYNTHETIC_PASSWORD_VALUE@example.test/path": (
                "synthetic-user", "SYNTHETIC_PASSWORD_VALUE",
            ),
            "https://:EMPTY_USER_PASSWORD_VALUE@example.test/path": (
                "EMPTY_USER_PASSWORD_VALUE",
            ),
        }
        for value, secrets in cases.items():
            with self.subTest(value=value.split(":", 1)[0]):
                cleaned = clean(value)
                for secret in secrets:
                    self.assertNotIn(secret, cleaned)
                self.assertIn("[REDACTED]", cleaned)

    def test_clean_preserves_ordinary_authentication_prose(self):
        prose = "Basic authentication is supported; Bearer authentication is optional."
        self.assertEqual(clean(prose), prose)
        self.assertNotIn(
            "SYNTHETIC_BEARER+/=",
            clean("Bearer SYNTHETIC_BEARER+/="),
        )
        self.assertNotIn(
            "U1lOVEhFVElDOlZBTFVF",
            clean("Basic U1lOVEhFVElDOlZBTFVF"),
        )
        self.assertEqual(
            clean("Authorization: Bearer readableword"),
            "Authorization: [REDACTED]",
        )

    def test_call_sanitizes_tool_input_and_output_before_persistence(self):
        class _Input:
            def write(self, value):
                self.value = value

            async def drain(self):
                return None

            def close(self):
                return None

        class _Stream:
            def __init__(self, payload=b""):
                self.payload = payload

            async def read(self, _size):
                payload, self.payload = self.payload, b""
                return payload

        class _Process:
            pid = 43215

            def __init__(self, stdout):
                self.stdin = _Input()
                self.stdout = _Stream(stdout)
                self.stderr = _Stream()
                self.returncode = None

            async def wait(self):
                self.returncode = 0
                return 0

        async def exercise():
            with isolated_runtime():
                workspace = config.ENGAGEMENTS_DIR / "sanitized-native-call"
                workspace.mkdir(parents=True)
                client = OpenCodeClient(
                    role="worker", route=config.WORKER_MODEL, effort="max",
                    workspace=workspace, target_slug="sanitized-native-call",
                    allow_tools=True, agent_prompt="test",
                )
                secrets = {
                    "cookie": "SYNTHETIC_COOKIE_VALUE",
                    "basic": "U1lOVEhFVElDOlZBTFVF",
                    "bearer": "SYNTHETIC_BEARER+/=",
                    "access": "SYNTHETIC_ACCESS_VALUE",
                    "refresh": "SYNTHETIC_REFRESH_VALUE",
                    "session": "SYNTHETIC_SESSION_VALUE",
                    "password": "SYNTHETIC_PASSWORD_VALUE",
                    "userinfo": "synthetic-user",
                    "opaque": "SYNTHETIC_OPAQUE_VALUE",
                }
                output = "\n".join([
                    f"Set-Cookie: app_session={secrets['cookie']}; HttpOnly",
                    f"Cookie: app_session={secrets['cookie']}",
                    f"Authorization: Basic {secrets['basic']}",
                    f"Authorization: Bearer {secrets['bearer']}",
                    json.dumps({
                        "access_token": secrets["access"],
                        "refreshToken": secrets["refresh"],
                        "session_token": secrets["session"],
                        "password": secrets["password"],
                    }),
                    "Unlabelled echoed value: " + secrets["opaque"],
                ])
                events = [
                    {
                        "type": "tool_use", "sessionID": "ses-sanitized",
                        "part": {
                            "callID": "tool-sanitized", "tool": "bash",
                            "state": {
                                "status": "completed",
                                "input": {
                                    "command": (
                                        "curl https://"
                                        f"{secrets['userinfo']}:{secrets['password']}"
                                        "@example.test/path"
                                    ),
                                    "headers": {
                                        "Cookie": secrets["cookie"],
                                        "Authorization": f"Basic {secrets['basic']}",
                                    },
                                    "password": secrets["password"],
                                },
                                "output": output,
                            },
                        },
                    },
                    {
                        "type": "text", "sessionID": "ses-sanitized",
                        "part": {
                            "text": f"Completed with password={secrets['password']}."
                        },
                    },
                ]
                payload = b"".join(
                    (json.dumps(event) + "\n").encode() for event in events
                )
                process = _Process(payload)
                gateway = SimpleNamespace(
                    model_route=f"openclaude/{config.WORKER_MODEL}",
                    drain_events=lambda: [],
                )
                with patch.object(client, "_ensure_gateway", AsyncMock(return_value=gateway)), \
                        patch.object(client, "_environment", return_value=({}, "gateway-secret")), \
                        patch.object(client, "_ensure_network_broker", AsyncMock()), \
                        patch.object(config, "require_binary", return_value="/usr/bin/true"), \
                        patch("grypton.providers.credentials.provider_redaction_values",
                              return_value=(secrets["opaque"],)), \
                        patch("grypton.providers.asyncio.create_subprocess_exec",
                              new=AsyncMock(return_value=process)):
                    result = await client.call("sanitized prompt")

                persisted = (
                    workspace / "transcripts/worker.opencode.events.jsonl"
                ).read_text(encoding="utf-8")
                observable = persisted + json.dumps({
                    "text": result.text,
                    "events": result.events,
                    "tools": result.tools,
                })
                for secret in secrets.values():
                    self.assertNotIn(secret, observable)
                self.assertIn("[REDACTED]", observable)
                self.assertEqual(
                    result.tools[0]["input"]["headers"]["Cookie"], "[REDACTED]"
                )
                self.assertEqual(result.tools[0]["input"]["password"], "[REDACTED]")
                self.assertNotIn("SYNTHETIC_", result.tools[0]["output"])
                self.assertIsNone(result._raw_text)
                self.assertIsNone(result._value_redactor)

        asyncio.run(exercise())

    def test_manager_decodes_raw_json_before_redacting_short_needles(self):
        class _Input:
            def write(self, value):
                self.value = value

            async def drain(self):
                return None

            def close(self):
                return None

        class _Stream:
            def __init__(self, payload=b""):
                self.payload = payload

            async def read(self, _size):
                payload, self.payload = self.payload, b""
                return payload

        class _Process:
            pid = 43219

            def __init__(self, stdout):
                self.stdin = _Input()
                self.stdout = _Stream(stdout)
                self.stderr = _Stream()
                self.returncode = None

            async def wait(self):
                self.returncode = 0
                return 0

        async def exercise():
            with isolated_runtime():
                ws = Workspace("structured-redaction-call")
                ws.create("https://example.test", "web")
                streamed = []
                client = OpenCodeClient(
                    role="manager", route=config.MANAGER_MODEL, effort="xhigh",
                    workspace=ws.root, target_slug=ws.slug,
                    allow_tools=False, agent_prompt="test",
                    event_callback=streamed.append,
                )
                secret = "SYNTHETIC_MANAGER_SECRET"
                response = {
                    "assessment": f"Observed {secret}",
                    "directive": "Retest the strongest lead.",
                    "corrections": [],
                    "new_angles": [],
                    "exhaustion_breaker": "",
                    "scope_enforcement": [],
                    "severity_validations": [],
                    "to_user": "Continuing.",
                    "continue": True,
                    "stop_reason": "",
                    "confidence": 0.84,
                }
                raw_text = json.dumps(response)
                event = {
                    "type": "text", "sessionID": "ses-structured",
                    "part": {"text": raw_text},
                }
                process = _Process((json.dumps(event) + "\n").encode())
                gateway = SimpleNamespace(
                    model_route=f"openclaude/{config.MANAGER_MODEL}",
                    drain_events=lambda: [],
                )
                with patch.object(client, "_ensure_gateway", AsyncMock(return_value=gateway)), \
                        patch.object(client, "_environment", return_value=({}, "gateway-secret")), \
                        patch.object(client, "_ensure_network_broker", AsyncMock()), \
                        patch.object(config, "require_binary", return_value="/usr/bin/true"), \
                        patch("grypton.providers.credentials.provider_redaction_values",
                              return_value=(secret, "0", "true", "false")), \
                        patch("grypton.providers.asyncio.create_subprocess_exec",
                              new=AsyncMock(return_value=process)):
                    result = await client.call("structured prompt")

                persisted = "\n".join([
                    (ws.transcripts_dir / "manager.opencode.events.jsonl").read_text(
                        encoding="utf-8"
                    ),
                    (ws.transcripts_dir / "provider-calls.jsonl").read_text(
                        encoding="utf-8"
                    ),
                ])
                exposed = persisted + result.text + json.dumps({
                    "events": result.events,
                    "tools": result.tools,
                    "streamed": streamed,
                }) + repr(result)
                self.assertNotIn(secret, exposed)
                self.assertIn("[REDACTED]", result.text)
                with self.assertRaises(json.JSONDecodeError):
                    json.loads(result.text)

                manager = KryptexManager(ws, "system")
                manager.client.call = AsyncMock(return_value=result)
                directive = await manager.direct(ManagerContext(
                    target="https://example.test", target_type="web", turn_index=1,
                ))

                self.assertTrue(directive.cont)
                self.assertEqual(directive.confidence, 0.84)
                self.assertEqual(directive.assessment, "Observed [REDACTED]")
                self.assertNotIn(secret, json.dumps(directive.raw))
                self.assertIsNone(result._raw_text)
                self.assertIsNone(result._value_redactor)
                self.assertEqual(manager.client.call.await_count, 1)

        asyncio.run(exercise())

    def test_structured_decoder_clears_private_raw_text_on_failure(self):
        secret = "SYNTHETIC_PRIVATE_RAW_SECRET"
        result = OpenCodeResult(
            text="[REDACTED]", session_id="ses-invalid", events=[], tools=[],
            usage=[], duration_s=0.1, _raw_text="{invalid " + secret,
            _value_redactor=lambda value: value,
        )

        self.assertNotIn(secret, repr(result))
        with self.assertRaises(json.JSONDecodeError):
            result.decode_structured_json(json.loads)
        self.assertIsNone(result._raw_text)
        self.assertIsNone(result._value_redactor)
        self.assertNotIn(secret, repr(result))

    def test_low_specificity_session_values_do_not_corrupt_public_output(self):
        with isolated_runtime():
            target = "session-redaction-specificity"
            credentials.save_credential(target, "primary", "Q", "Z")
            opaque_token = "token-G7mQ2vR9xL4pN8sK6dW3"
            opaque_storage = "storage-J4qP8vN2xR7mK5sD9wL6"
            opaque_cookie = "cookie-N8rW3kP7xM2vL9qD5sJ4"
            credentials.save_tokens(target, "primary", {
                "boolean": "true",
                "counter": "0",
                "opaque": opaque_token,
            }, origin="https://example.test")
            credentials._atomic_private_json(  # type: ignore[attr-defined]
                credentials.browser_storage_path(target, "primary"),
                {
                    "local_storage": {
                        "enabled": "false",
                        "counter": "0",
                        "state": "authenticated",
                        "opaque": opaque_storage,
                    },
                    "session_storage": {
                        "flag": "sessionStorage",
                        "repeat": "falsefalsefalse",
                    },
                    "cookies": [
                        {"value": "1"},
                        {"value": opaque_cookie},
                    ],
                },
            )
            cookie_jar = credentials.cookie_jar_storage_path(target, "primary")
            cookie_jar.write_text(
                "example.test\tFALSE\t/\tTRUE\t0\tflag\tfalse\n"
                f"example.test\tFALSE\t/\tTRUE\t0\tsession\t{opaque_cookie}\n",
                encoding="utf-8",
            )
            cookie_jar.chmod(0o600)

            needles = credentials.provider_redaction_values(target)

            # Named credentials are still exact-redacted even when only one
            # character long. The specificity gate applies to session-derived
            # values only.
            self.assertIn("Q", needles)
            self.assertIn("Z", needles)
            for secret in (opaque_token, opaque_storage, opaque_cookie):
                self.assertIn(secret, needles)
            for public_state in (
                "0", "1", "true", "false", "authenticated",
                "sessionStorage", "falsefalsefalse",
            ):
                self.assertNotIn(public_state, needles)

            public = "F030 continue=true authenticated=false confidence=0"
            self.assertEqual(clean(public, needles), public)
            self.assertEqual(
                clean(
                    f"opaque echoes: {opaque_token} {opaque_storage} {opaque_cookie}",
                    needles,
                ),
                "opaque echoes: [REDACTED] [REDACTED] [REDACTED]",
            )

    def test_short_credential_preserves_provider_control_fields(self):
        class _Input:
            def write(self, value):
                self.value = value

            async def drain(self):
                return None

            def close(self):
                return None

        class _Stream:
            def __init__(self, payload=b""):
                self.payload = payload

            async def read(self, _size):
                payload, self.payload = self.payload, b""
                return payload

        class _Process:
            pid = 43216

            def __init__(self, stdout):
                self.stdin = _Input()
                self.stdout = _Stream(stdout)
                self.stderr = _Stream()
                self.returncode = None

            async def wait(self):
                self.returncode = 0
                return 0

        async def exercise():
            with isolated_runtime():
                credentials.save_credential(
                    "short-secret-call", "short", "a", "fixture-password"
                )
                workspace = config.ENGAGEMENTS_DIR / "short-secret-call"
                workspace.mkdir(parents=True)
                client = OpenCodeClient(
                    role="worker", route=config.WORKER_MODEL, effort="max",
                    workspace=workspace, target_slug="short-secret-call",
                    allow_tools=True, agent_prompt="test",
                )
                event = {
                    "type": "tool_use",
                    "sessionID": "session-alpha",
                    "role": "assistant",
                    "part": {
                        "callID": "call-alpha",
                        "tool": "bash",
                        "state": {
                            "status": "completed",
                            "input": {
                                "command": "printf a",
                                "status": "a", "type": "a", "id": "a",
                                "nested": {"tool": "a"},
                            },
                            "output": {
                                "status": "a", "type": "a", "id": "a",
                                "tool": "a", "payload": "payload a",
                            },
                        },
                    },
                }
                text_event = {
                    "type": "text", "sessionID": "session-alpha",
                    "role": "assistant", "part": {"text": "done"},
                }
                process = _Process((
                    json.dumps(event) + "\n" + json.dumps(text_event) + "\n"
                ).encode())
                gateway = SimpleNamespace(
                    model_route=f"openclaude/{config.WORKER_MODEL}",
                    drain_events=lambda: [],
                )
                with patch.object(client, "_ensure_gateway", AsyncMock(return_value=gateway)), \
                        patch.object(client, "_environment", return_value=({}, "gateway-secret")), \
                        patch.object(client, "_ensure_network_broker", AsyncMock()), \
                        patch.object(config, "require_binary", return_value="/usr/bin/true"), \
                        patch("grypton.providers.asyncio.create_subprocess_exec",
                              new=AsyncMock(return_value=process)):
                    result = await client.call("short-secret prompt")

                self.assertEqual(result.session_id, "session-alpha")
                self.assertEqual(result.events[0]["type"], "tool_use")
                self.assertEqual(result.events[0]["role"], "assistant")
                part = result.events[0]["part"]
                self.assertEqual(part["callID"], "call-alpha")
                self.assertEqual(part["tool"], "bash")
                self.assertEqual(part["state"]["status"], "completed")
                self.assertEqual(
                    part["state"]["input"]["command"], "printf [REDACTED]"
                )
                for key in ("status", "type", "id"):
                    self.assertEqual(
                        part["state"]["input"][key], "[REDACTED]"
                    )
                self.assertEqual(
                    part["state"]["input"]["nested"]["tool"], "[REDACTED]"
                )
                output = part["state"]["output"]
                for key in ("status", "type", "id", "tool"):
                    self.assertEqual(output[key], "[REDACTED]")
                self.assertEqual(
                    output["payload"],
                    "p[REDACTED]ylo[REDACTED]d [REDACTED]",
                )
                tool_output = json.loads(result.tools[0]["output"])
                self.assertEqual(tool_output, output)
                persisted = (
                    workspace / "transcripts/worker.opencode.events.jsonl"
                ).read_text(encoding="utf-8")
                self.assertIn('"sessionID": "session-alpha"', persisted)
                self.assertNotIn('"output": "payload a"', persisted)

        asyncio.run(exercise())

    def test_terminal_gateway_signal_ends_opencode_call_promptly(self):
        class _Input:
            def write(self, value):
                self.value = value

            async def drain(self):
                return None

            def close(self):
                return None

        class _Stream:
            def __init__(self, payload=b""):
                self.payload = payload

            async def read(self, _size):
                payload, self.payload = self.payload, b""
                return payload

        class _Process:
            pid = 43211

            def __init__(self, stdout=b""):
                self.stdin = _Input()
                self.stdout = _Stream(stdout)
                self.stderr = _Stream()
                self.returncode = None
                self.done = asyncio.Event()

            async def wait(self):
                await self.done.wait()
                return self.returncode

        async def exercise():
            with isolated_runtime():
                workspace = config.ENGAGEMENTS_DIR / "terminal-call"
                workspace.mkdir(parents=True)
                client = OpenCodeClient(
                    role="manager", route="go/muse-spark-1.3-contributor",
                    effort="xhigh", workspace=workspace,
                    target_slug="terminal-call", allow_tools=False,
                    agent_prompt="test",
                )
                tool_event = {
                    "type": "tool_use",
                    "part": {
                        "callID": "fixture-tool",
                        "tool": "http_request",
                        "state": {"status": "completed", "input": {}},
                    },
                }
                process = _Process((json.dumps(tool_event) + "\n").encode())
                gateway = SimpleNamespace(
                    model_route="openclaude/go/muse-spark-1.3-contributor",
                    drain_events=lambda: [],
                )

                async def terminate(proc):
                    proc.returncode = -15
                    proc.done.set()

                with patch.object(client, "_ensure_gateway", AsyncMock(return_value=gateway)), \
                        patch.object(client, "_environment", return_value=({}, "fixture-secret")), \
                        patch.object(client, "_ensure_network_broker", AsyncMock()), \
                        patch.object(config, "require_binary", return_value="/usr/bin/true"), \
                        patch("grypton.providers.asyncio.create_subprocess_exec",
                              new=AsyncMock(return_value=process)), \
                        patch("grypton.providers._terminate",
                              new=AsyncMock(side_effect=terminate)) as stop:
                    call = asyncio.create_task(client.call(
                        "fixture prompt", session_id="ses-prior", timeout=30,
                    ))
                    for _ in range(20):
                        if client._terminal_signal is not None:
                            break
                        await asyncio.sleep(0)
                    self.assertIsNotNone(client._terminal_signal)
                    client._on_gateway_event({
                        "type": "openclaude_terminal",
                        "route": "go/muse-spark-1.3-contributor",
                        "reason": "credential_pool_exhausted",
                        "upstream_status": 402,
                        "pool_size": 5,
                        "retry_after_s": 37,
                    })
                    with self.assertRaisesRegex(
                        ProviderError, r"credential pool exhausted \(upstream HTTP 402\)"
                    ) as raised:
                        await asyncio.wait_for(call, timeout=1)
                    stop.assert_awaited_once_with(process)
                    self.assertEqual(raised.exception.metadata, {
                        "source": "openclaude",
                        "type": "openclaude_terminal",
                        "role": "manager",
                        "reason": "credential_pool_exhausted",
                        "upstream_status": 402,
                        "pool_size": 5,
                        "retry_after_s": 37,
                        "tool_count": 1,
                        "replay_safe": False,
                    })

                transcript = (
                    workspace / "transcripts/openclaude.events.jsonl"
                ).read_text(encoding="utf-8")
                self.assertIn('"reason": "credential_pool_exhausted"', transcript)
                self.assertNotIn("fixture-secret", transcript)
                records = [json.loads(line) for line in (
                    workspace / "transcripts/provider-calls.jsonl"
                ).read_text(encoding="utf-8").splitlines()]
                self.assertEqual(len(records), 1)
                record = records[0]
                self.assertFalse(record["ok"])
                self.assertEqual(record["role"], "manager")
                self.assertEqual(record["route"], "go/muse-spark-1.3-contributor")
                self.assertEqual(record["effort"], "xhigh")
                self.assertEqual(record["session_id"], "ses-prior")
                self.assertTrue(record["resumed"])
                self.assertEqual(record["error_class"], "openclaude_terminal")
                self.assertEqual(record["error_type"], "ProviderError")
                self.assertEqual(record["error_reason"], "credential_pool_exhausted")
                self.assertEqual(record["upstream_status"], 402)
                self.assertEqual(record["pool_size"], 5)
                self.assertEqual(record["retry_after_s"], 37)
                self.assertEqual(record["tool_count"], 1)
                self.assertEqual(record["returncode"], -15)
                self.assertEqual(record["prompt_sha256"], hashlib.sha256(
                    b"fixture prompt"
                ).hexdigest())
                self.assertNotIn("fixture-secret", json.dumps(record))

        asyncio.run(exercise())

    def test_timeout_records_one_sanitized_provider_call(self):
        class _Input:
            def write(self, value):
                self.value = value

            async def drain(self):
                return None

            def close(self):
                return None

        class _Stream:
            async def read(self, _size):
                return b""

        class _Process:
            pid = 43212

            def __init__(self):
                self.stdin = _Input()
                self.stdout = _Stream()
                self.stderr = _Stream()
                self.returncode = None
                self.done = asyncio.Event()

            async def wait(self):
                await self.done.wait()
                return self.returncode

        async def exercise():
            with isolated_runtime():
                workspace = config.ENGAGEMENTS_DIR / "timeout-call"
                workspace.mkdir(parents=True)
                client = OpenCodeClient(
                    role="worker", route=config.WORKER_MODEL, effort="max",
                    workspace=workspace, target_slug="timeout-call",
                    allow_tools=True, agent_prompt="test",
                )
                process = _Process()
                gateway = SimpleNamespace(
                    model_route=f"openclaude/{config.WORKER_MODEL}",
                    drain_events=lambda: [],
                )

                async def terminate(proc):
                    proc.returncode = -15
                    proc.done.set()

                with patch.object(client, "_ensure_gateway", AsyncMock(return_value=gateway)), \
                        patch.object(client, "_environment", return_value=({}, "fixture-secret")), \
                        patch.object(client, "_ensure_network_broker", AsyncMock()), \
                        patch.object(config, "require_binary", return_value="/usr/bin/true"), \
                        patch("grypton.providers.asyncio.create_subprocess_exec",
                              new=AsyncMock(return_value=process)), \
                        patch("grypton.providers._terminate",
                              new=AsyncMock(side_effect=terminate)):
                    with self.assertRaisesRegex(
                        ProviderError, "timed out"
                    ) as raised:
                        await client.call("timeout prompt", timeout=0)
                    self.assertIs(raised.exception.metadata["replay_safe"], False)

                records = [json.loads(line) for line in (
                    workspace / "transcripts/provider-calls.jsonl"
                ).read_text(encoding="utf-8").splitlines()]
                self.assertEqual(len(records), 1)
                record = records[0]
                self.assertEqual(record["error_class"], "timeout")
                self.assertEqual(record["error_type"], "ProviderError")
                self.assertFalse(record["ok"])
                self.assertEqual(record["returncode"], -15)
                self.assertNotIn("fixture-secret", json.dumps(record))

        asyncio.run(exercise())

    def test_active_stream_refreshes_provider_timeout(self):
        class _Input:
            def write(self, value):
                self.value = value

            async def drain(self):
                return None

            def close(self):
                return None

        class _ProgressStream:
            def __init__(self):
                self.index = 0

            async def read(self, _size):
                if self.index >= 3:
                    return b""
                await asyncio.sleep(0.05)
                self.index += 1
                return (json.dumps({
                    "type": "text",
                    "sessionID": "ses-active",
                    "part": {"text": f"provider progress {self.index}"},
                }) + "\n").encode()

        class _EmptyStream:
            async def read(self, _size):
                return b""

        class _Process:
            pid = 43213

            def __init__(self):
                self.stdin = _Input()
                self.stdout = _ProgressStream()
                self.stderr = _EmptyStream()
                self.returncode = None

            async def wait(self):
                await asyncio.sleep(0.17)
                self.returncode = 0
                return 0

        async def exercise():
            with isolated_runtime():
                workspace = config.ENGAGEMENTS_DIR / "active-timeout-call"
                workspace.mkdir(parents=True)
                client = OpenCodeClient(
                    role="worker", route=config.WORKER_MODEL, effort="max",
                    workspace=workspace, target_slug="active-timeout-call",
                    allow_tools=True, agent_prompt="test",
                )
                process = _Process()
                gateway = SimpleNamespace(
                    model_route=f"openclaude/{config.WORKER_MODEL}",
                    drain_events=lambda: [],
                )

                with patch.object(client, "_ensure_gateway", AsyncMock(return_value=gateway)), \
                        patch.object(client, "_environment", return_value=({}, "fixture-secret")), \
                        patch.object(client, "_ensure_network_broker", AsyncMock()), \
                        patch.object(config, "require_binary", return_value="/usr/bin/true"), \
                        patch("grypton.providers.asyncio.create_subprocess_exec",
                              new=AsyncMock(return_value=process)):
                    result = await client.call("active prompt", timeout=0.08)

                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.session_id, "ses-active")
                self.assertIn("provider progress 3", result.text)

                records = [json.loads(line) for line in (
                    workspace / "transcripts/provider-calls.jsonl"
                ).read_text(encoding="utf-8").splitlines()]
                self.assertEqual(len(records), 1)
                self.assertTrue(records[0]["ok"])
                self.assertGreater(records[0]["duration_s"], 0.08)

        asyncio.run(exercise())

    def test_nested_gateway_activity_refreshes_provider_timeout(self):
        class _Input:
            def write(self, value):
                self.value = value

            async def drain(self):
                return None

            def close(self):
                return None

        class _DelayedStream:
            def __init__(self):
                self.sent = False

            async def read(self, _size):
                if self.sent:
                    return b""
                await asyncio.sleep(0.16)
                self.sent = True
                return (json.dumps({
                    "type": "text",
                    "sessionID": "ses-nested-active",
                    "part": {"text": "nested task completed"},
                }) + "\n").encode()

        class _EmptyStream:
            async def read(self, _size):
                return b""

        class _Process:
            pid = 43214

            def __init__(self):
                self.stdin = _Input()
                self.stdout = _DelayedStream()
                self.stderr = _EmptyStream()
                self.returncode = None

            async def wait(self):
                await asyncio.sleep(0.17)
                self.returncode = 0
                return 0

        async def exercise():
            with isolated_runtime():
                workspace = config.ENGAGEMENTS_DIR / "nested-active-timeout-call"
                workspace.mkdir(parents=True)
                client = OpenCodeClient(
                    role="worker", route=config.WORKER_MODEL, effort="max",
                    workspace=workspace, target_slug="nested-active-timeout-call",
                    allow_tools=True, agent_prompt="test",
                )
                process = _Process()
                gateway = SimpleNamespace(
                    model_route=f"openclaude/{config.WORKER_MODEL}",
                    drain_events=lambda: [],
                )

                async def nested_activity():
                    for _ in range(3):
                        await asyncio.sleep(0.04)
                        client._on_gateway_event({
                            "type": "openclaude_request",
                            "route": config.WORKER_MODEL,
                        })

                with patch.object(client, "_ensure_gateway", AsyncMock(return_value=gateway)), \
                        patch.object(client, "_environment", return_value=({}, "fixture-secret")), \
                        patch.object(client, "_ensure_network_broker", AsyncMock()), \
                        patch.object(config, "require_binary", return_value="/usr/bin/true"), \
                        patch("grypton.providers.asyncio.create_subprocess_exec",
                              new=AsyncMock(return_value=process)):
                    heartbeat = asyncio.create_task(nested_activity())
                    result = await client.call("nested prompt", timeout=0.07)
                    await heartbeat

                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.session_id, "ses-nested-active")
                self.assertIn("nested task completed", result.text)
                gateway_events = [json.loads(line) for line in (
                    workspace / "transcripts/openclaude.events.jsonl"
                ).read_text(encoding="utf-8").splitlines()]
                self.assertEqual(len(gateway_events), 3)

        asyncio.run(exercise())

    def test_stream_provider_error_records_redacted_failure(self):
        class _Input:
            def write(self, value):
                self.value = value

            async def drain(self):
                return None

            def close(self):
                return None

        class _ErrorStream:
            async def read(self, _size):
                raise ProviderError("stream failed with bearer fixture-secret")

        class _EmptyStream:
            async def read(self, _size):
                return b""

        class _Process:
            pid = 43213

            def __init__(self):
                self.stdin = _Input()
                self.stdout = _ErrorStream()
                self.stderr = _EmptyStream()
                self.returncode = None
                self.done = asyncio.Event()

            async def wait(self):
                await self.done.wait()
                return self.returncode

        async def exercise():
            with isolated_runtime():
                workspace = config.ENGAGEMENTS_DIR / "stream-call"
                workspace.mkdir(parents=True)
                client = OpenCodeClient(
                    role="worker", route=config.WORKER_MODEL, effort="max",
                    workspace=workspace, target_slug="stream-call",
                    allow_tools=True, agent_prompt="test",
                )
                process = _Process()
                gateway = SimpleNamespace(
                    model_route=f"openclaude/{config.WORKER_MODEL}",
                    drain_events=lambda: [],
                )

                async def terminate(proc):
                    proc.returncode = -15
                    proc.done.set()

                with patch.object(client, "_ensure_gateway", AsyncMock(return_value=gateway)), \
                        patch.object(client, "_environment", return_value=({}, "fixture-secret")), \
                        patch.object(client, "_ensure_network_broker", AsyncMock()), \
                        patch.object(config, "require_binary", return_value="/usr/bin/true"), \
                        patch("grypton.providers.asyncio.create_subprocess_exec",
                              new=AsyncMock(return_value=process)), \
                        patch("grypton.providers._terminate",
                              new=AsyncMock(side_effect=terminate)):
                    with self.assertRaisesRegex(
                        ProviderError, "stream failed"
                    ) as raised:
                        await client.call("stream prompt", timeout=30)
                    self.assertIs(raised.exception.metadata["replay_safe"], False)

                record = json.loads((
                    workspace / "transcripts/provider-calls.jsonl"
                ).read_text(encoding="utf-8").splitlines()[0])
                self.assertEqual(record["error_class"], "stream_error")
                self.assertEqual(record["error_type"], "ProviderError")
                self.assertEqual(record["error_message"],
                                 "stream failed with bearer [REDACTED]")
                self.assertNotIn("fixture-secret", json.dumps(record))

        asyncio.run(exercise())

    def test_cancelled_call_records_failure_and_preserves_cancellation(self):
        class _Input:
            def write(self, value):
                self.value = value

            async def drain(self):
                return None

            def close(self):
                return None

        class _Stream:
            async def read(self, _size):
                return b""

        class _Process:
            pid = 43214

            def __init__(self):
                self.stdin = _Input()
                self.stdout = _Stream()
                self.stderr = _Stream()
                self.returncode = None
                self.done = asyncio.Event()

            async def wait(self):
                await self.done.wait()
                return self.returncode

        async def exercise():
            with isolated_runtime():
                workspace = config.ENGAGEMENTS_DIR / "cancelled-call"
                workspace.mkdir(parents=True)
                client = OpenCodeClient(
                    role="manager", route="go/muse-spark-1.3-contributor",
                    effort="xhigh", workspace=workspace,
                    target_slug="cancelled-call", allow_tools=False,
                    agent_prompt="test",
                )
                process = _Process()
                gateway = SimpleNamespace(
                    model_route="openclaude/go/muse-spark-1.3-contributor",
                    drain_events=lambda: [],
                )

                async def terminate(proc):
                    proc.returncode = -15
                    proc.done.set()

                with patch.object(client, "_ensure_gateway", AsyncMock(return_value=gateway)), \
                        patch.object(client, "_environment", return_value=({}, "fixture-secret")), \
                        patch.object(config, "require_binary", return_value="/usr/bin/true"), \
                        patch("grypton.providers.asyncio.create_subprocess_exec",
                              new=AsyncMock(return_value=process)), \
                        patch("grypton.providers._terminate",
                              new=AsyncMock(side_effect=terminate)):
                    call = asyncio.create_task(client.call("cancel prompt", timeout=30))
                    for _ in range(20):
                        if client._terminal_signal is not None:
                            break
                        await asyncio.sleep(0)
                    call.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await call

                records = [json.loads(line) for line in (
                    workspace / "transcripts/provider-calls.jsonl"
                ).read_text(encoding="utf-8").splitlines()]
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["error_class"], "cancelled")
                self.assertEqual(records[0]["error_type"], "CancelledError")
                self.assertFalse(records[0]["ok"])

        asyncio.run(exercise())

    def test_terminal_provider_error_uses_manager_deterministic_fallback(self):
        async def exercise():
            with isolated_runtime():
                workspace = Workspace("terminal-manager")
                workspace.create("example.test", "web")
                events: list[dict] = []
                manager = KryptexManager(workspace, "test", on_event=events.append)
                manager.client.call = AsyncMock(side_effect=ProviderError(
                    "manager OpenClaude credential pool exhausted (upstream HTTP 402)."
                ))

                directive = await manager.direct(ManagerContext(
                    target="example.test", target_type="web", turn_index=3,
                ))

                self.assertTrue(directive.degraded)
                self.assertTrue(directive.cont)
                self.assertEqual(directive.fallback_provider, "deterministic")
                self.assertEqual(events[-1]["type"], "manager_fallback")
                self.assertEqual(events[-1]["via"], "deterministic")

        asyncio.run(exercise())


if __name__ == "__main__":
    unittest.main()
