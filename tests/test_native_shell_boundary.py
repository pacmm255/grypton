from __future__ import annotations

import asyncio
import fcntl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from grypton import config, credentials
from grypton.native_shell import (
    NativeShellSpec,
    landlock_abi,
    prepare_native_shell,
    sandbox_uid,
)
from grypton.network_broker import ScopedNetworkBroker
from grypton.openclaude import TOKEN_ENV
from grypton.providers import OpenCodeClient
from grypton.workspace import Constraints, Workspace


DOCUMENTS = (
    "findings.md", "attack-surface.md", "tested-techniques.md",
    "scope-rules.md", "progress.md",
)
DIRECTORIES = ("research", "scripts", "loot", "workspace", "flows")


def make_workspace(root: Path) -> tuple[Path, Path, Path]:
    workspace = root / "engagement"
    transport = root / "transport"
    runtime = root / "provider-runtime"
    for directory in (workspace, transport, runtime):
        directory.mkdir(mode=0o700)
    for name in DIRECTORIES:
        (workspace / name).mkdir(mode=0o700)
    for name in DOCUMENTS:
        (workspace / name).write_text("public fixture\n", encoding="utf-8")
    (workspace / ".ledger").mkdir(mode=0o700)
    (workspace / ".ledger/private.json").write_text(
        "ledger-private", encoding="utf-8"
    )
    (transport / "engagement").symlink_to(workspace, target_is_directory=True)
    return workspace, transport, runtime


class NativeShellBoundaryTests(unittest.TestCase):
    def test_target_identity_is_stable_and_separate(self):
        first = sandbox_uid("alpha")
        self.assertEqual(first, sandbox_uid("alpha"))
        self.assertNotEqual(first, sandbox_uid("beta"))
        self.assertGreaterEqual(first, 1_000_000)

    @unittest.skipUnless(
        os.geteuid() == 0 and shutil.which("setfacl") and landlock_abi() >= 1,
        "root, setfacl, and Landlock are required for the isolation check",
    )
    def test_shell_can_work_in_public_engagement_but_cannot_read_private_state(self):
        with tempfile.TemporaryDirectory(prefix="grypton-native-boundary-", dir="/tmp") as raw:
            root = Path(raw)
            workspace, transport, runtime = make_workspace(root)
            private_paths = []
            for name, content in (
                ("operator-state", "OPERATOR_RAW_FIXTURE"),
                ("credential-state", "TARGET_PASSWORD_FIXTURE"),
                ("provider-state", "PROVIDER_KEY_FIXTURE"),
                ("other-engagement", "OTHER_TARGET_FIXTURE"),
            ):
                directory = root / name
                directory.mkdir(mode=0o700)
                secret = directory / "secret.txt"
                secret.write_text(content, encoding="utf-8")
                private_paths.append(secret)
            (runtime / "secret.txt").write_text(
                "PROVIDER_RUNTIME_FIXTURE", encoding="utf-8"
            )
            private_paths.extend((
                runtime / "secret.txt",
                workspace / ".ledger/private.json",
                Path("/proc/self/environ"),
            ))

            spec = prepare_native_shell(
                target_slug="boundary-fixture",
                transport=transport,
                workspace=workspace,
                runtime=runtime,
                source_root=Path(__file__).resolve().parents[1],
            )
            environment = dict(os.environ)
            environment.update(spec.internal_environment())
            environment.update({
                TOKEN_ENV: "GATEWAY_TOKEN_FIXTURE",
                "OPENCODE_CONFIG_CONTENT": "OPENCODE_PRIVATE_FIXTURE",
                "AWS_SECRET_ACCESS_KEY": "AMBIENT_PROVIDER_FIXTURE",
            })
            probes = " ".join(
                "if cat " + shlex.quote(str(path))
                + " 2>/dev/null; then exit 91; else printf denied\\n; fi;"
                for path in private_paths
            )
            command = (
                "ls engagement; "
                "cat engagement/scope-rules.md; "
                "printf native-ok > engagement/workspace/native-result.txt; "
                "if touch AGENTS.md 2>/dev/null; then exit 92; "
                "else printf transport-denied\\n; fi; "
                "if mkdir .opencode 2>/dev/null; then exit 93; "
                "else printf transport-denied\\n; fi; "
                "if printf replaced > .native-bin/curl 2>/dev/null; then exit 94; "
                "else printf transport-denied\\n; fi; "
                "/usr/bin/curl --version >/dev/null; "
                + probes
                + " env; id -u"
            )
            completed = subprocess.run(
                [spec.launcher, "-c", command], cwd=transport,
                env=environment, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=30,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("scope-rules.md", completed.stdout)
            self.assertEqual(
                (workspace / "workspace/native-result.txt").read_text(),
                "native-ok",
            )
            self.assertGreaterEqual(completed.stdout.count("denied"), len(private_paths))
            self.assertEqual(completed.stdout.count("transport-denied"), 3)
            self.assertFalse((transport / "AGENTS.md").exists())
            self.assertFalse((transport / ".opencode").exists())
            for forbidden in (
                "OPERATOR_RAW_FIXTURE", "TARGET_PASSWORD_FIXTURE",
                "PROVIDER_KEY_FIXTURE", "PROVIDER_RUNTIME_FIXTURE",
                "OTHER_TARGET_FIXTURE", "GATEWAY_TOKEN_FIXTURE",
                "OPENCODE_PRIVATE_FIXTURE", "AMBIENT_PROVIDER_FIXTURE",
                "OPENCODE_CONFIG_CONTENT", TOKEN_ENV,
            ):
                self.assertNotIn(forbidden, completed.stdout + completed.stderr)
            self.assertEqual(completed.stdout.rstrip().splitlines()[-1], str(spec.uid))

    @unittest.skipUnless(
        os.geteuid() == 0 and shutil.which("setfacl") and shutil.which("cc")
        and landlock_abi() >= 1,
        "root, setfacl, a C compiler, and Landlock are required",
    )
    def test_scoped_curl_broker_and_network_syscall_boundary(self):
        class Handler(BaseHTTPRequestHandler):
            hits: list[str] = []

            def do_GET(self):
                type(self).hits.append(self.path)
                payload = b"broker-marker"
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_POST(self):
                size = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(size).decode("utf-8", "replace")
                type(self).hits.append(f"POST:{self.path}:{body}")
                payload = b"post-marker"
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        async def exercise(root: Path):
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
                ws = Workspace("network-boundary")
                allowed_url = (
                    f"http://127.0.0.1:{server.server_address[1]}/allowed"
                )
                denied_url = (
                    f"http://127.0.0.1:{server.server_address[1]}/denied"
                )
                ws.create(allowed_url, "web")
                ws.save_constraints(Constraints(in_scope=[allowed_url]))

                transport = root / "transport"
                runtime = root / "provider-runtime"
                transport.mkdir(mode=0o700)
                runtime.mkdir(mode=0o700)
                (transport / "engagement").symlink_to(
                    ws.root, target_is_directory=True
                )

                probe_source = ws.scripts_dir / "io-uring-probe.c"
                probe_binary = ws.scripts_dir / "io-uring-probe"
                probe_source.write_text(
                    """
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void) {
    errno = 0;
    long result = syscall(__NR_io_uring_setup, 1, (void *)0);
    if (result >= 0) { close((int)result); return 90; }
    return errno == EPERM ? 0 : 91;
}
""".strip() + "\n",
                    encoding="utf-8",
                )
                compiled = subprocess.run(
                    ["cc", str(probe_source), "-o", str(probe_binary)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    timeout=30,
                )
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                probe_binary.chmod(0o755)

                spec = prepare_native_shell(
                    target_slug=ws.slug,
                    transport=transport,
                    workspace=ws.root,
                    runtime=runtime,
                    source_root=Path(__file__).resolve().parents[1],
                )
                environment = dict(os.environ)
                environment.update(spec.internal_environment())
                broker = ScopedNetworkBroker(
                    ws.root, ws.slug, spec.broker_socket, spec.uid
                )
                await broker.start()
                try:
                    def run(command: str, **kwargs):
                        return subprocess.run(
                            [spec.launcher, "-c", command], cwd=transport,
                            env=environment, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=30, **kwargs,
                        )

                    allowed = await asyncio.to_thread(run, f"curl {allowed_url}")
                    self.assertEqual(allowed.returncode, 0, allowed.stderr)
                    self.assertIn("broker-marker", allowed.stdout)
                    self.assertEqual(Handler.hits, ["/allowed"])
                    self.assertTrue(any(ws.flows_dir.glob("flow-*.http")))
                    tool_rows = [json.loads(line) for line in (
                        ws.root / ".ledger/tool-calls.jsonl"
                    ).read_text(encoding="utf-8").splitlines()]
                    self.assertEqual(tool_rows[-1]["tool"], "http_request")
                    self.assertTrue(tool_rows[-1]["ok"])
                    self.assertTrue((
                        ws.root / ".ledger/effectful-tool-starts.jsonl"
                    ).is_file())

                    payload_path = ws.scratch_dir / "request-body.txt"
                    payload_path.write_text("file-payload", encoding="utf-8")
                    posted = await asyncio.to_thread(
                        run,
                        "curl --data-binary @engagement/workspace/request-body.txt "
                        + allowed_url,
                    )
                    self.assertEqual(posted.returncode, 0, posted.stderr)
                    self.assertIn("post-marker", posted.stdout)
                    self.assertEqual(
                        Handler.hits,
                        ["/allowed", "POST:/allowed:file-payload"],
                    )

                    queried = await asyncio.to_thread(
                        run,
                        "curl --get --data-urlencode 'q=a b' " + allowed_url,
                    )
                    self.assertEqual(queried.returncode, 0, queried.stderr)
                    self.assertEqual(
                        Handler.hits[-1], "/allowed?q=a+b"
                    )

                    denied = await asyncio.to_thread(run, f"curl {denied_url}")
                    self.assertEqual(denied.returncode, 22, denied.stderr)
                    self.assertEqual(len(Handler.hits), 3)

                    direct = await asyncio.to_thread(
                        run, f"/usr/bin/curl --max-time 2 {allowed_url}"
                    )
                    self.assertNotEqual(direct.returncode, 0)
                    self.assertEqual(len(Handler.hits), 3)

                    direct_socket = await asyncio.to_thread(
                        run,
                        "python3 -c 'import socket,sys; "
                        "\ntry: socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
                        "\nexcept PermissionError: sys.exit(0)"
                        "\nsys.exit(92)'",
                    )
                    self.assertEqual(
                        direct_socket.returncode, 0, direct_socket.stderr
                    )

                    io_uring = await asyncio.to_thread(
                        run, "engagement/scripts/io-uring-probe"
                    )
                    self.assertEqual(io_uring.returncode, 0, io_uring.stderr)

                    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    inherited_fd = fcntl.fcntl(
                        listener.fileno(), fcntl.F_DUPFD, 200
                    )
                    os.set_inheritable(inherited_fd, True)
                    try:
                        inherited = await asyncio.to_thread(
                            run,
                            "python3 -c 'import os,sys; "
                            f"\ntry: os.fstat({inherited_fd})"
                            "\nexcept OSError: sys.exit(0)"
                            "\nsys.exit(93)'",
                            pass_fds=(inherited_fd,),
                        )
                    finally:
                        os.close(inherited_fd)
                        listener.close()
                    self.assertEqual(inherited.returncode, 0, inherited.stderr)
                finally:
                    await broker.close()

        try:
            with tempfile.TemporaryDirectory(
                prefix="grypton-native-network-", dir="/tmp"
            ) as raw:
                asyncio.run(exercise(Path(raw)))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_provider_config_caches_boundary_and_keeps_mcp_direct(self):
        with tempfile.TemporaryDirectory(prefix="grypton-native-config-", dir="/tmp") as raw:
            root = Path(raw)
            workspace, transport, runtime = make_workspace(root)
            client = OpenCodeClient(
                role="worker", route=config.WORKER_MODEL, effort="max",
                workspace=workspace, target_slug="native-config",
                allow_tools=True, agent_prompt="fixture",
            )
            # Avoid touching global runtime paths in this unit check.
            client.transport_workspace = transport
            client.runtime = runtime
            client.gateway = SimpleNamespace(
                model_route=f"openclaude/{config.WORKER_MODEL}",
                token="fixture-gateway-token",
                provider_config=lambda provider_id: {
                    provider_id: {
                        "npm": "@ai-sdk/anthropic",
                        "options": {
                            "baseURL": "http://127.0.0.1:32123/v1",
                            "apiKey": "{env:" + TOKEN_ENV + "}",
                        },
                        "models": {config.WORKER_MODEL: {"variants": {"max": {}}}},
                    }
                },
                environment=lambda: {TOKEN_ENV: "fixture-gateway-token"},
            )
            spec = NativeShellSpec(
                launcher=runtime / "native-shell", transport=transport,
                workspace=workspace, home=transport / ".native-home",
                temporary=transport / ".native-tmp",
                native_bin=transport / ".native-bin",
                broker_socket=transport / ".native-broker/http.sock",
                uid=1_234_567,
            )
            spec.home.mkdir()
            spec.temporary.mkdir()
            spec.native_bin.mkdir()
            (spec.native_bin / "curl").write_text("fixture", encoding="utf-8")
            spec.launcher.write_text("fixture", encoding="utf-8")
            with patch("grypton.providers.prepare_native_shell", return_value=spec) as prepare:
                first, _ = client._environment()
                second, _ = client._environment()

            self.assertEqual(prepare.call_count, 1)
            inline = json.loads(first["OPENCODE_CONFIG_CONTENT"])
            self.assertEqual(inline["shell"], str(spec.launcher))
            self.assertEqual(
                inline["mcp"]["grypton"]["command"],
                [os.sys.executable, "-m", "grypton.toolserver"],
            )
            self.assertNotIn("shell", inline["agent"]["grypton-worker"])
            for name, value in spec.internal_environment().items():
                self.assertEqual(first[name], value)
                self.assertEqual(second[name], value)

    def test_provider_event_file_redacts_stored_credentials(self):
        class Input:
            def write(self, _value):
                pass

            async def drain(self):
                pass

            def close(self):
                pass

        class Stream:
            def __init__(self, payload=b""):
                self.payload = payload

            async def read(self, _size):
                value, self.payload = self.payload, b""
                return value

        class Process:
            pid = 43218

            def __init__(self, payload):
                self.stdin = Input()
                self.stdout = Stream(payload)
                self.stderr = Stream()
                self.returncode = None

            async def wait(self):
                self.returncode = 0
                return 0

        async def exercise(root: Path):
            workspace = root / "workspace"
            workspace.mkdir()
            client = OpenCodeClient(
                role="manager", route=config.MANAGER_MODEL, effort="xhigh",
                workspace=workspace, target_slug="redaction-fixture",
                allow_tools=False, agent_prompt="fixture",
            )
            password = "fixture-password-9z!"
            username = "fixture.user@example.test"
            credentials.save_credential(
                "redaction-fixture", "primary", username, password
            )
            event = {
                "type": "text", "sessionID": "fixture-session",
                "part": {"text": f"observed {username} and {password}"},
            }
            process = Process((json.dumps(event) + "\n").encode())
            gateway = SimpleNamespace(
                model_route=f"openclaude/{config.MANAGER_MODEL}",
                drain_events=lambda: [],
            )
            with patch.object(client, "_ensure_gateway", AsyncMock(return_value=gateway)), \
                    patch.object(client, "_environment", return_value=({}, "gateway-secret")), \
                    patch.object(config, "require_binary", return_value="/usr/bin/true"), \
                    patch("grypton.providers.asyncio.create_subprocess_exec",
                          new=AsyncMock(return_value=process)):
                result = await client.call("fixture prompt")
            persisted = (workspace / "transcripts/manager.opencode.events.jsonl").read_text()
            self.assertNotIn(username, persisted)
            self.assertNotIn(password, persisted)
            self.assertNotIn(username, result.text)
            self.assertNotIn(password, result.text)
            self.assertGreaterEqual(persisted.count("[REDACTED]"), 2)

        with tempfile.TemporaryDirectory(prefix="grypton-native-redact-", dir="/tmp") as raw:
            root = Path(raw)
            with patch.object(config, "CREDENTIALS_DIR", root / "credentials"), \
                    patch.object(config, "PROVIDER_DIR", root / "providers"), \
                    patch.object(config, "OPENCODE_WORKSPACES_DIR", root / "opencode"):
                asyncio.run(exercise(root))


if __name__ == "__main__":
    unittest.main()
