from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import asyncio
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch
from urllib.request import Request, urlopen

from grypton import config
from grypton.chat import Renderer, _route_input
from grypton.cli import _configure_run, build_parser
from grypton.engine import Engine
from grypton.manager import KryptexManager
from grypton.reporting import audit_workspace
from grypton.openclaude import (
    OpenClaudeGateway,
    OpenClaudeModel,
    TOKEN_ENV,
    resolve_model,
    resolve_openclaude_route,
)
from grypton.worker import OpenCodeWorker, WorkerSpec
from grypton.workspace import Workspace


OPENCLAUDE_ROOT = Path("/root/openclaude")
PRIMARY_KEY = "fixture-primary-key-000000000001"
SPARE_KEY = "fixture-spare-key-000000000002"


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
            "OPENCODE_WORKSPACES_DIR": root / ".opencode-workspaces",
            "TARGET_DATA_DIR": root / "target",
        }
        with patch.multiple(config, **values):
            config.ensure_layout()
            yield root


def catalog_model(*, route: str = "go/muse-spark-1.3-contributor",
                  tools: bool = True) -> OpenClaudeModel:
    return OpenClaudeModel.from_payload({
        "routeId": route,
        "provider": route.split("/", 1)[0],
        "model": route.split("/", 1)[-1],
        "label": "Fixture selectable model",
        "protocol": "responses",
        "status": "available",
        "capabilities": {
            "tools": tools,
            "reasoning": True,
            "temperature": False,
            "input": {"text": True},
            "output": {"text": True},
        },
        "limits": {"context": 200_000, "output": 16_384},
        "effort": {
            "levels": ["minimal", "low", "medium", "high", "xhigh"],
            "default": "auto",
        },
    })


@contextmanager
def rotation_provider():
    calls: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            authorization = self.headers.get("Authorization", "")
            calls.append(authorization)
            if authorization == f"Bearer {PRIMARY_KEY}":
                payload = {
                    "error": {
                        "type": "CreditsError",
                        "message": "Insufficient balance.",
                    }
                }
                status = 401
            elif authorization == f"Bearer {SPARE_KEY}":
                payload = {
                    "id": "chatcmpl_fixture",
                    "object": "chat.completion",
                    "model": "fixture-model",
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": "rotated"},
                        "finish_reason": "stop",
                    }],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                }
                status = 200
            else:
                payload = {"error": {"message": "unexpected fixture credential"}}
                status = 403
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class OpenClaudeAdapterTests(unittest.TestCase):
    def test_legacy_route_resolves_and_enforces_effort_and_tool_capability(self):
        model = catalog_model()
        self.assertEqual(
            resolve_openclaude_route("opencode-go/muse-spark-1.3-contributor"),
            "go/muse-spark-1.3-contributor",
        )
        with patch("grypton.openclaude.list_models", return_value=[model]):
            selected = resolve_model(
                "opencode-go/muse-spark-1.3-contributor",
                effort="xhigh",
                require_tools=True,
            )
            self.assertEqual(selected.route_id, "go/muse-spark-1.3-contributor")
            self.assertEqual(selected.effort, "xhigh")
            with self.assertRaisesRegex(RuntimeError, "unsupported"):
                resolve_model(selected.route_id, effort="max")

        without_tools = catalog_model(route="fixture/text-only", tools=False)
        with patch("grypton.openclaude.list_models", return_value=[without_tools]):
            with self.assertRaisesRegex(RuntimeError, "does not support tool calls"):
                resolve_model(without_tools.route_id, require_tools=True)

    def test_provider_config_uses_loopback_placeholder_and_redacts_gateway_token(self):
        model = catalog_model(route="fixture/selectable")
        with tempfile.TemporaryDirectory() as directory:
            gateway = OpenClaudeGateway(
                model.route_id,
                "xhigh",
                "worker",
                Path(directory) / "transport",
                node_binary=sys.executable,
            )
            gateway._url = "http://127.0.0.1:32123"
            gateway._model = model
            provider = gateway.provider_config()["openclaude"]
            serialized = json.dumps(provider)
            self.assertEqual(provider["npm"], "@ai-sdk/anthropic")
            self.assertEqual(provider["options"]["baseURL"], "http://127.0.0.1:32123/v1")
            self.assertEqual(provider["options"]["apiKey"], "{env:" + TOKEN_ENV + "}")
            self.assertIn("xhigh", provider["models"][model.route_id]["variants"])
            self.assertEqual(gateway.model_route, "openclaude/fixture/selectable")
            self.assertNotIn(gateway.token, repr(gateway))
            self.assertNotIn(gateway.token, serialized)
            self.assertEqual(gateway.environment(), {TOKEN_ENV: gateway.token})
            sanitized = gateway._sanitize_event({
                "type": "openclaude_notice",
                "route": model.route_id,
                "message": "Bearer " + gateway.token,
            })
            self.assertNotIn(gateway.token, json.dumps(sanitized))


class ModelSelectionTests(unittest.IsolatedAsyncioTestCase):
    def test_cli_accepts_role_model_and_effort_flags(self):
        parser = build_parser()
        for arguments in (
            ["init", "--target", "fixture.test"],
            ["resume", "fixture-test"],
            ["plan", "--target", "fixture.test"],
        ):
            parsed = parser.parse_args(arguments + [
                "--kraude-model", "fixture/worker",
                "--kraude-effort", "high",
                "--kryptex-model", "fixture/manager",
                "--kryptex-effort", "xhigh",
            ])
            self.assertEqual(parsed.worker_model, "fixture/worker")
            self.assertEqual(parsed.worker_effort, "high")
            self.assertEqual(parsed.manager_model, "fixture/manager")
            self.assertEqual(parsed.manager_effort, "xhigh")

    def test_run_selection_persists_and_resume_uses_workspace_values(self):
        fields = ("backend", "max_run_seconds", "max_turns", "stop_on_p1")
        saved = {field: getattr(config.CONFIG, field) for field in fields}
        try:
            with isolated_runtime():
                ws = Workspace("model-persistence")
                ws.create("fixture.test", "web")
                fresh = SimpleNamespace(
                    backend="mock", auto_stop_time=None, max_seconds=None,
                    max_turns=None, stop_on_p1=False,
                    worker_model="fixture/worker", worker_effort="high",
                    manager_model="fixture/manager", manager_effort="xhigh",
                )
                selected = _configure_run(fresh, ws, fresh=True)
                meta = ws.load_meta()
                self.assertEqual(selected["worker"], {
                    "route": "fixture/worker", "effort": "high",
                })
                self.assertEqual(selected["manager"], {
                    "route": "fixture/manager", "effort": "xhigh",
                })
                self.assertEqual(meta.worker_model, "fixture/worker")
                self.assertEqual(meta.worker_effort, "high")
                self.assertEqual(meta.manager_model, "fixture/manager")
                self.assertEqual(meta.manager_effort, "xhigh")

                resume = SimpleNamespace(
                    backend="mock", auto_stop_time=None, max_seconds=None,
                    max_turns=None, stop_on_p1=False,
                    worker_model=None, worker_effort=None,
                    manager_model=None, manager_effort=None,
                )
                resumed = _configure_run(resume, ws, fresh=False)
                self.assertEqual(resumed["worker"], selected["worker"])
                self.assertEqual(resumed["manager"], selected["manager"])
                self.assertEqual(resumed["validator"]["route"], config.VALIDATOR_MODEL)
                self.assertEqual(resumed["validator"]["effort"], config.VALIDATOR_EFFORT)
        finally:
            for field, value in saved.items():
                setattr(config.CONFIG, field, value)

    async def test_worker_and_manager_switches_drop_provider_sessions(self):
        with isolated_runtime():
            worker = OpenCodeWorker(WorkerSpec(
                session_uuid="worker-session",
                cwd=config.ENGAGEMENTS_DIR / "switch-lifecycle",
                system_prompt="fixture",
                model="fixture/old-worker",
                effort="medium",
                extra_env={"GRYPTON_TARGET": "switch-lifecycle"},
            ))
            old_worker_client = worker.client
            old_worker_client.cancel = AsyncMock()
            replacement_worker_client = SimpleNamespace()
            with patch.object(worker, "_new_client", return_value=replacement_worker_client):
                await worker.switch_model("fixture/new-worker", "high")
            old_worker_client.cancel.assert_awaited_once()
            self.assertEqual(worker.spec.model, "fixture/new-worker")
            self.assertEqual(worker.spec.effort, "high")
            self.assertEqual(worker.session_id, "")
            self.assertEqual(worker.spec.session_uuid, "")
            self.assertIs(worker.client, replacement_worker_client)

            ws = Workspace("switch-manager")
            ws.create("fixture.test", "web")
            manager = KryptexManager(
                ws, "fixture", manager_model="fixture/old-manager",
                manager_effort="medium",
            )
            manager.session_id = "manager-session"
            old_manager_client = manager.client
            old_manager_client.cancel = AsyncMock()
            replacement_manager_client = SimpleNamespace()
            with patch.object(manager, "_new_client", return_value=replacement_manager_client):
                await manager.switch_model("fixture/new-manager", "xhigh")
            old_manager_client.cancel.assert_awaited_once()
            self.assertEqual(manager.manager_model, "fixture/new-manager")
            self.assertEqual(manager.manager_effort, "xhigh")
            self.assertEqual(manager.session_id, "")
            self.assertIs(manager.client, replacement_manager_client)

    async def test_interactive_model_command_applies_at_queue_boundary_and_persists(self):
        with isolated_runtime():
            ws = Workspace("interactive-model-switch")
            ws.create("fixture.test", "web")
            events = []
            engine = Engine(
                ws.slug,
                backend="mock",
                emit=lambda kind, **data: events.append((kind, data)),
            )
            engine.worker = SimpleNamespace(
                switch_model=AsyncMock(),
                session_id="",
            )
            self.assertFalse(_route_input(
                engine,
                Renderer("quiet"),
                "/model worker fixture/new-worker high",
            ))
            selection = SimpleNamespace(route_id="fixture/new-worker", effort="high")
            with patch("grypton.openclaude.resolve_model", return_value=selection) as resolve:
                await engine._apply_pending_model_switches()
            resolve.assert_called_once_with(
                "fixture/new-worker", effort="high", require_tools=True,
            )
            engine.worker.switch_model.assert_awaited_once_with(
                "fixture/new-worker", "high",
            )
            meta = ws.load_meta()
            self.assertEqual((meta.worker_model, meta.worker_effort),
                             ("fixture/new-worker", "high"))
            ledger = ws.root / ".ledger/model-switches.jsonl"
            row = json.loads(ledger.read_text().splitlines()[-1])
            self.assertEqual((row["role"], row["route"], row["effort"]),
                             ("kraude", "fixture/new-worker", "high"))
            self.assertTrue(any(kind == "model_switch" for kind, _ in events))

    def test_audit_tracks_historical_model_switches_and_ignores_success_warnings(self):
        with isolated_runtime():
            ws = Workspace("model-audit")
            ws.create("fixture.test", "web")
            ws.update_meta(
                worker_model="fixture/new-worker",
                worker_effort="high",
                manager_model="fixture/manager",
                manager_effort="xhigh",
            )
            switch_path = ws.root / ".ledger/model-switches.jsonl"
            switch_path.write_text(
                json.dumps({
                    "at": 1, "role": "worker", "route": "fixture/old-worker",
                    "effort": "medium", "source": "run-start",
                }) + "\n" + json.dumps({
                    "at": 3, "role": "kraude", "route": "fixture/new-worker",
                    "effort": "high", "source": "operator",
                }) + "\n",
                encoding="utf-8",
            )
            calls_path = ws.transcripts_dir / "provider-calls.jsonl"
            calls_path.write_text(
                json.dumps({
                    "at": 2, "role": "worker", "route": "fixture/old-worker",
                    "effort": "medium", "returncode": 0,
                    "stderr_present": True, "ok": True,
                }) + "\n" + json.dumps({
                    "at": 4, "role": "worker", "route": "fixture/new-worker",
                    "effort": "high", "returncode": 0,
                    "stderr_present": False, "ok": True,
                }) + "\n",
                encoding="utf-8",
            )
            audit = audit_workspace(ws)
            self.assertTrue(audit["exact_routes"], audit["route_errors"])
            self.assertEqual(audit["provider_failures"], [])

    def test_role_selection_does_not_change_astra_boundary(self):
        engine = Engine(
            "fixed-astra",
            backend="mock",
            worker_model="fixture/worker",
            worker_effort="high",
            manager_model="fixture/manager",
            manager_effort="xhigh",
        )
        self.assertEqual(engine.current_models()["validator"], {
            "route": config.VALIDATOR_MODEL,
            "effort": config.VALIDATOR_EFFORT,
        })
        findings = [
            {"id": "F1", "severity": "P1", "status": "validation-pending"},
            {"id": "F2", "severity": "P2", "status": "validation-pending"},
            {"id": "F3", "severity": "P3", "status": "validation-not-requested"},
            {"id": "F4", "severity": "P1", "status": "suppressed-by-scope"},
        ]
        self.assertEqual(
            [row["id"] for row in Engine._automatic_validation_candidates(findings)],
            ["F1", "F2"],
        )


@unittest.skipUnless(
    shutil.which("node")
    and (OPENCLAUDE_ROOT / "src/gateway.mjs").is_file()
    and (OPENCLAUDE_ROOT / "src/catalog.mjs").is_file(),
    "local OpenClaude checkout and Node.js are required",
)
class OpenClaudeRotationTests(unittest.IsolatedAsyncioTestCase):
    async def test_spent_key_rotates_once_and_stays_benched(self):
        # Catalog parsing is intentionally bounded but large enough to cross the
        # debug loop's default 100 ms slow-callback threshold on small machines.
        asyncio.get_running_loop().slow_callback_duration = 1.0
        with rotation_provider() as (port, calls), tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key_file = root / "keys"
            key_file.write_text(SPARE_KEY + "\n", encoding="utf-8")
            key_file.chmod(0o600)
            config_path = root / "openclaude.config.json"
            config_path.write_text(json.dumps({
                "defaultRoute": "fixture-chat",
                "fastRoute": "fixture-chat",
                "reasoningRoute": "fixture-chat",
                "retry": {
                    "windowMs": 0,
                    "maxDelayMs": 1000,
                    "keyCooldownMs": 1000,
                },
                "providers": {
                    "fixture": {
                        "baseUrl": f"http://127.0.0.1:{port}/v1",
                        "credential": {
                            "env": "GRYPTON_TEST_ROTATION_KEY",
                            "keyFile": str(key_file),
                        },
                    }
                },
                "routes": {
                    "fixture-chat": {
                        "provider": "fixture",
                        "model": "fixture-model",
                        "protocol": "chat",
                        "label": "Fixture chat",
                        "contextWindow": 128_000,
                        "maxOutputTokens": 4096,
                    }
                },
            }), encoding="utf-8")

            with patch.dict(os.environ, {"GRYPTON_TEST_ROTATION_KEY": PRIMARY_KEY}):
                gateway = OpenClaudeGateway(
                    "fixture-chat",
                    "auto",
                    "worker",
                    root / "transport",
                    openclaude_root=OPENCLAUDE_ROOT,
                    config_path=config_path,
                )
                try:
                    await gateway.start()

                    def post() -> tuple[int, str]:
                        request = Request(
                            gateway.url + "/v1/messages",
                            data=json.dumps({
                                "model": "fixture-chat",
                                "max_tokens": 40,
                                "messages": [{"role": "user", "content": "fixture"}],
                                "stream": False,
                            }).encode(),
                            headers={
                                "content-type": "application/json",
                                "x-api-key": gateway.token,
                            },
                            method="POST",
                        )
                        with urlopen(request, timeout=10) as response:
                            return response.status, response.read().decode()

                    first = await asyncio.to_thread(post)
                    second = await asyncio.to_thread(post)
                    self.assertEqual((first[0], second[0]), (200, 200))
                    self.assertIn("rotated", first[1])
                    self.assertEqual(calls, [
                        f"Bearer {PRIMARY_KEY}",
                        f"Bearer {SPARE_KEY}",
                        f"Bearer {SPARE_KEY}",
                    ])
                    notices = [
                        event for event in gateway.drain_events()
                        if event.get("type") == "openclaude_notice"
                    ]
                    self.assertEqual(len(notices), 1)
                    self.assertIn("continuing on key", notices[0]["message"])
                    serialized = json.dumps(notices)
                    self.assertNotIn(PRIMARY_KEY, serialized)
                    self.assertNotIn(SPARE_KEY, serialized)
                finally:
                    await gateway.close()


if __name__ == "__main__":
    unittest.main()
