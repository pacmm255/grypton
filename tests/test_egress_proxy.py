from __future__ import annotations

import asyncio
import base64
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import stat
from types import SimpleNamespace
import tempfile
import threading
import unittest
from unittest.mock import patch

from grypton import config, credentials
from grypton.network_broker import PrivateEgressProxyBroker
from grypton.providers import OpenCodeClient, ProviderError
from grypton.tools import (Goja, artifact_download, authenticated_http_request,
                           http_request, httpx_probe, research)
from grypton.workspace import Constraints, Workspace


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"connect-proxy-route-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class _ConnectHandler(socketserver.StreamRequestHandler):
    def handle(self):
        request_line = self.rfile.readline(8192).decode("ascii", "replace").strip()
        headers: dict[str, str] = {}
        while True:
            line = self.rfile.readline(8192)
            if line in {b"", b"\r\n", b"\n"}:
                break
            name, _, value = line.decode("iso-8859-1", "replace").partition(":")
            headers[name.strip().lower()] = value.strip()
        method, endpoint, _ = request_line.split(" ", 2)
        self.server.observed.append((method, endpoint, headers))
        if method != "CONNECT":
            self.wfile.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return
        host, raw_port = endpoint.rsplit(":", 1)
        with socket.create_connection((host.strip("[]"), int(raw_port)), timeout=5) as remote:
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.wfile.flush()
            sockets = (self.connection, remote)
            while True:
                readable, _, _ = select.select(sockets, (), (), 5)
                if not readable:
                    return
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    (remote if source is self.connection else self.connection).sendall(data)


@contextmanager
def connect_route():
    origin = ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
    proxy = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _ConnectHandler)
    proxy.daemon_threads = True
    proxy.observed = []
    threads = [
        threading.Thread(target=origin.serve_forever, daemon=True),
        threading.Thread(target=proxy.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        yield origin.server_address[1], proxy
    finally:
        origin.shutdown()
        proxy.shutdown()
        origin.server_close()
        proxy.server_close()
        for thread in threads:
            thread.join(timeout=2)


@contextmanager
def isolated_runtime():
    with tempfile.TemporaryDirectory(prefix="gpx-") as directory:
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
            "TARGET_DATA_DIR": root / "reserved-data",
        }
        with patch.multiple(config, **values):
            config.ensure_layout()
            yield root


class EgressProxyTests(unittest.TestCase):
    proxy = "http://proxy-user:proxy-password@proxy.invalid:8080"

    def _workspace(self, slug: str = "egress-proxy") -> Workspace:
        workspace = Workspace(slug)
        workspace.create("https://example.test", "web")
        workspace.save_constraints(Constraints(in_scope=["example.test"]))
        return workspace

    def test_http_request_reads_proxy_from_anonymous_config_only(self):
        with isolated_runtime():
            workspace = self._workspace("curl-egress")
            observed: dict[str, object] = {}

            def fake_run(argv, **kwargs):
                observed["argv"] = list(argv)
                observed["env"] = dict(kwargs["env"])
                observed["config"] = Path(
                    argv[argv.index("--config") + 1]
                ).read_text(encoding="utf-8")
                Path(argv[argv.index("--dump-header") + 1]).write_text(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
                    encoding="utf-8",
                )
                kwargs["stdout"].write(b"proxied response")
                return SimpleNamespace(returncode=0, stderr=(
                    "diagnostic " + self.proxy
                ).encode())

            with patch.dict(os.environ, {
                config.EGRESS_PROXY_ENV: self.proxy,
                "HTTPS_PROXY": "http://ambient.invalid:9999",
            }), patch("grypton.tools.config.find_binary", return_value="/usr/bin/curl"), \
                    patch("grypton.tools.subprocess.run", side_effect=fake_run):
                result = http_request(workspace, "https://example.test/resource")

            self.assertTrue(result["ok"], result)
            self.assertIn("proxytunnel", observed["config"])
            self.assertIn(self.proxy, observed["config"])
            self.assertNotIn(self.proxy, json.dumps(observed["argv"]))
            self.assertNotIn(self.proxy, json.dumps(observed["env"]))
            self.assertNotIn("HTTPS_PROXY", observed["env"])
            observable = json.dumps(result) + Path(result["data"]["flow"]).read_text()
            self.assertNotIn(self.proxy, observable)
            self.assertNotIn("proxy-password", observable)
            self.assertNotIn("proxy.invalid", observable)

    def test_http_request_redacts_proxy_from_oserror(self):
        with isolated_runtime():
            workspace = self._workspace("curl-oserror-egress")
            observed: dict[str, int] = {}

            def fail_with_private_route(_argv, **kwargs):
                observed["fd"] = kwargs["pass_fds"][0]
                raise OSError(
                    "transport rejected " + self.proxy
                    + " user=proxy-user password=proxy-password host=proxy.invalid"
                )

            with patch.dict(os.environ, {config.EGRESS_PROXY_ENV: self.proxy}), \
                    patch("grypton.tools.config.find_binary", return_value="/usr/bin/curl"), \
                    patch("grypton.tools.subprocess.run",
                          side_effect=fail_with_private_route):
                result = http_request(
                    workspace, "https://example.test/transport-error"
                )

            self.assertFalse(result["ok"], result)
            observable = json.dumps(result)
            self.assertNotIn(self.proxy, observable)
            self.assertNotIn("proxy-user", observable)
            self.assertNotIn("proxy-password", observable)
            self.assertNotIn("proxy.invalid", observable)
            with self.assertRaises(OSError):
                os.fstat(observed["fd"])

    def test_http_request_uses_authenticated_connect_route(self):
        with isolated_runtime(), connect_route() as (origin_port, proxy):
            target = f"http://127.0.0.1:{origin_port}"
            workspace = Workspace("connect-egress")
            workspace.create(target, "web")
            workspace.save_constraints(Constraints(in_scope=[target]))
            proxy_url = (
                "http://proxy-user:proxy-password@localhost:"
                f"{proxy.server_address[1]}"
            )
            with patch.dict(os.environ, {config.EGRESS_PROXY_ENV: proxy_url}):
                result = http_request(workspace, target + "/through-connect")

            self.assertTrue(result["ok"], result)
            self.assertIn("connect-proxy-route-ok", result["data"]["response"])
            self.assertEqual(len(proxy.observed), 1)
            method, endpoint, headers = proxy.observed[0]
            self.assertEqual(method, "CONNECT")
            self.assertEqual(endpoint, f"127.0.0.1:{origin_port}")
            expected = base64.b64encode(
                b"proxy-user:proxy-password"
            ).decode("ascii")
            self.assertEqual(headers.get("proxy-authorization"), f"Basic {expected}")
            observable = json.dumps(result) + Path(result["data"]["flow"]).read_text()
            self.assertNotIn(proxy_url, observable)
            self.assertNotIn("proxy-password", observable)

    def test_authenticated_http_request_inherits_connect_route(self):
        with isolated_runtime(), connect_route() as (origin_port, proxy):
            target = f"http://127.0.0.1:{origin_port}"
            workspace = Workspace("authenticated-connect-egress")
            workspace.create(target, "web")
            workspace.save_constraints(Constraints(in_scope=[target]))
            credentials.save_credential(
                workspace.slug, "primary", "fixture-user", "fixture-password"
            )
            credentials.record_login_outcome(
                workspace.slug, "primary", established=True, origin=target
            )
            proxy_url = (
                "http://proxy-user:proxy-password@localhost:"
                f"{proxy.server_address[1]}"
            )
            with patch.dict(os.environ, {config.EGRESS_PROXY_ENV: proxy_url}):
                result = authenticated_http_request(
                    workspace, target + "/authenticated", credential="primary"
                )

            self.assertTrue(result["ok"], result)
            self.assertEqual([row[0] for row in proxy.observed], ["CONNECT"])
            observable = json.dumps(result) + Path(result["data"]["flow"]).read_text()
            self.assertNotIn(proxy_url, observable)
            self.assertNotIn("proxy-password", observable)

    def test_unset_proxy_keeps_direct_http_and_httpx_invocations(self):
        with isolated_runtime():
            workspace = self._workspace("direct-egress")

            def fake_curl(argv, **kwargs):
                Path(argv[argv.index("--dump-header") + 1]).write_text(
                    "HTTP/1.1 200 OK\r\n\r\n", encoding="utf-8"
                )
                kwargs["stdout"].write(b"direct")
                return SimpleNamespace(returncode=0, stderr=b"")

            with patch.dict(os.environ, {}, clear=False), \
                    patch("grypton.tools.config.find_binary", return_value="/usr/bin/curl"), \
                    patch("grypton.tools.subprocess.run", side_effect=fake_curl) as run:
                os.environ.pop(config.EGRESS_PROXY_ENV, None)
                os.environ.pop(config.PRIVATE_EGRESS_PROXY_SOCKET_ENV, None)
                result = http_request(workspace, "https://example.test/")
            self.assertTrue(result["ok"], result)
            self.assertNotIn("--config", run.call_args.args[0])
            self.assertNotIn("pass_fds", run.call_args.kwargs)

            with patch.dict(os.environ, {}, clear=False), \
                    patch("grypton.tools.config.find_binary", return_value="/usr/bin/httpx"), \
                    patch("grypton.tools.subprocess.run", return_value=SimpleNamespace(
                        stdout=b"https://example.test [200]", stderr=b"", returncode=0,
                    )) as run:
                os.environ.pop(config.EGRESS_PROXY_ENV, None)
                os.environ.pop(config.PRIVATE_EGRESS_PROXY_SOCKET_ENV, None)
                result = httpx_probe(workspace, "https://example.test/")
            self.assertTrue(result["ok"], result)
            self.assertNotIn("-config", run.call_args.args[0])
            self.assertNotIn("pass_fds", run.call_args.kwargs)

    def test_httpx_proxy_is_pipe_backed_and_redacted(self):
        with isolated_runtime():
            workspace = self._workspace("httpx-egress")
            observed: dict[str, object] = {}

            def fake_run(argv, **kwargs):
                observed["argv"] = list(argv)
                observed["env"] = dict(kwargs["env"])
                observed["config"] = Path(
                    argv[argv.index("-config") + 1]
                ).read_text(encoding="utf-8")
                return SimpleNamespace(
                    stdout=("https://example.test [200] " + self.proxy).encode(),
                    stderr=b"", returncode=0,
                )

            with patch.dict(os.environ, {config.EGRESS_PROXY_ENV: self.proxy}), \
                    patch("grypton.tools.config.find_binary", return_value="/usr/bin/httpx"), \
                    patch("grypton.tools.subprocess.run", side_effect=fake_run):
                result = httpx_probe(workspace, "https://example.test/")

            self.assertTrue(result["ok"], result)
            self.assertIn(self.proxy, observed["config"])
            self.assertNotIn(self.proxy, json.dumps(observed["argv"]))
            self.assertNotIn(self.proxy, json.dumps(observed["env"]))
            self.assertNotIn(self.proxy, json.dumps(result))
            self.assertNotIn("proxy-password", json.dumps(result))

    def test_private_socket_handoff_is_exact_private_and_ephemeral(self):
        async def exercise():
            with tempfile.TemporaryDirectory(prefix="grypton-egress-broker-") as raw:
                path = Path(raw) / "proxy.sock"
                broker = PrivateEgressProxyBroker(path, self.proxy)
                await broker.start()
                try:
                    mode = stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)
                    value = await asyncio.to_thread(
                        config.private_egress_proxy,
                        {config.PRIVATE_EGRESS_PROXY_SOCKET_ENV: str(path)},
                    )
                    self.assertEqual(value, self.proxy)
                    self.assertEqual(mode, 0o600)
                finally:
                    await broker.close()
                self.assertFalse(path.exists())

        asyncio.run(exercise())

    def test_provider_forwards_only_private_socket_reference_to_mcp(self):
        with isolated_runtime():
            workspace = self._workspace("provider-egress")
            client = OpenCodeClient(
                role="worker", route=config.WORKER_MODEL, effort="max",
                workspace=workspace.root, target_slug=workspace.slug,
                allow_tools=True, agent_prompt="test",
            )
            gateway_token = "fixture-local-gateway-token"
            client.gateway = SimpleNamespace(
                model_route=f"openclaude/{config.WORKER_MODEL}",
                token=gateway_token,
                provider_config=lambda provider_id: {provider_id: {
                    "npm": "@ai-sdk/anthropic",
                    "options": {"apiKey": "{env:LOCAL_GATEWAY_TOKEN}"},
                    "models": {},
                }},
                environment=lambda: {"LOCAL_GATEWAY_TOKEN": gateway_token},
            )
            with patch.dict(os.environ, {config.EGRESS_PROXY_ENV: self.proxy}):
                env, _ = client._environment()

            serialized_env = json.dumps(env)
            self.assertNotIn(self.proxy, serialized_env)
            self.assertNotIn("proxy-password", serialized_env)
            self.assertNotIn(config.EGRESS_PROXY_ENV, env)
            inline = json.loads(env["OPENCODE_CONFIG_CONTENT"])
            mcp_env = inline["mcp"]["grypton"]["environment"]
            self.assertIn(config.PRIVATE_EGRESS_PROXY_SOCKET_ENV, mcp_env)
            self.assertNotIn(config.EGRESS_PROXY_ENV, mcp_env)
            self.assertNotIn(self.proxy, json.dumps(inline))

    def test_provider_broker_handoff_rotates_and_closes(self):
        async def exercise():
            with isolated_runtime():
                workspace = self._workspace("p")
                client = OpenCodeClient(
                    role="worker", route=config.WORKER_MODEL, effort="max",
                    workspace=workspace.root, target_slug=workspace.slug,
                    allow_tools=True, agent_prompt="test",
                )
                gateway_token = "fixture-local-gateway-token"
                client.gateway = SimpleNamespace(
                    model_route=f"openclaude/{config.WORKER_MODEL}",
                    token=gateway_token,
                    provider_config=lambda provider_id: {provider_id: {
                        "npm": "@ai-sdk/anthropic", "options": {}, "models": {},
                    }},
                    environment=lambda: {"LOCAL_GATEWAY_TOKEN": gateway_token},
                )
                first_broker = None
                socket_path = None
                try:
                    with patch.dict(os.environ, {
                        config.EGRESS_PROXY_ENV: self.proxy,
                    }):
                        env, _ = client._environment()
                        inline = json.loads(env["OPENCODE_CONFIG_CONTENT"])
                        socket_path = Path(inline["mcp"]["grypton"]["environment"][
                            config.PRIVATE_EGRESS_PROXY_SOCKET_ENV
                        ])
                        await client._ensure_network_broker()
                        first_broker = client.private_egress_broker
                        resolved = await asyncio.to_thread(
                            config.private_egress_proxy,
                            {config.PRIVATE_EGRESS_PROXY_SOCKET_ENV: str(socket_path)},
                        )
                    self.assertEqual(resolved, self.proxy)

                    rotated = "https://next-user:next-password@next.invalid:8443"
                    with patch.dict(os.environ, {
                        config.EGRESS_PROXY_ENV: rotated,
                    }):
                        client._environment()
                        await client._ensure_network_broker()
                        resolved = await asyncio.to_thread(
                            config.private_egress_proxy,
                            {config.PRIVATE_EGRESS_PROXY_SOCKET_ENV: str(socket_path)},
                        )
                    self.assertEqual(resolved, rotated)
                    self.assertIsNot(client.private_egress_broker, first_broker)
                    self.assertIsNone(first_broker.server)
                finally:
                    # The fake gateway is synchronous; only broker cleanup is
                    # relevant to this provider-boundary test.
                    client.gateway = None
                    await client.cancel()
                self.assertIsNotNone(socket_path)
                self.assertFalse(socket_path.exists())

        asyncio.run(exercise())

    def test_toolless_provider_never_reads_or_forwards_proxy(self):
        with isolated_runtime():
            workspace = self._workspace("manager-egress")
            client = OpenCodeClient(
                role="manager", route=config.MANAGER_MODEL, effort="xhigh",
                workspace=workspace.root, target_slug=workspace.slug,
                allow_tools=False, agent_prompt="test",
            )
            gateway_token = "fixture-local-gateway-token"
            client.gateway = SimpleNamespace(
                model_route=f"openclaude/{config.MANAGER_MODEL}",
                token=gateway_token,
                provider_config=lambda provider_id: {provider_id: {
                    "npm": "@ai-sdk/anthropic", "options": {}, "models": {},
                }},
                environment=lambda: {"LOCAL_GATEWAY_TOKEN": gateway_token},
            )
            invalid = "ftp://proxy-user:proxy-password@proxy.invalid:21"
            with patch.dict(os.environ, {config.EGRESS_PROXY_ENV: invalid}):
                env, _ = client._environment()
            self.assertEqual(json.loads(env["OPENCODE_CONFIG_CONTENT"])["mcp"], {})
            self.assertNotIn(invalid, json.dumps(env))
            self.assertEqual(client._private_egress_proxy, "")

    def test_occupied_private_socket_fails_closed_and_rolls_back(self):
        async def exercise():
            with isolated_runtime():
                workspace = self._workspace("q")
                client = OpenCodeClient(
                    role="worker", route=config.WORKER_MODEL, effort="max",
                    workspace=workspace.root, target_slug=workspace.slug,
                    allow_tools=True, agent_prompt="test",
                )
                client.gateway = SimpleNamespace(
                    model_route=f"openclaude/{config.WORKER_MODEL}",
                    token="fixture-local-gateway-token",
                    provider_config=lambda provider_id: {provider_id: {
                        "npm": "@ai-sdk/anthropic", "options": {}, "models": {},
                    }},
                    environment=lambda: {},
                )
                with patch.dict(os.environ, {
                    config.EGRESS_PROXY_ENV: self.proxy,
                }):
                    client._environment()
                    occupied = client._private_egress_socket_path()
                    occupied.parent.mkdir(parents=True, exist_ok=True)
                    occupied.write_text("do-not-replace", encoding="utf-8")
                    with self.assertRaises(ProviderError):
                        await client._ensure_network_broker()
                self.assertIsNone(client.network_broker)
                self.assertIsNone(client.private_egress_broker)
                self.assertEqual(occupied.read_text(encoding="utf-8"), "do-not-replace")
                occupied.unlink()
                client.gateway = None
                await client.cancel()

        asyncio.run(exercise())

    def test_invalid_proxy_fails_without_echoing_private_value(self):
        invalid = "ftp://proxy-user:proxy-password@proxy.invalid:21"
        with isolated_runtime():
            workspace = self._workspace("invalid-egress")
            with patch.dict(os.environ, {config.EGRESS_PROXY_ENV: invalid}):
                result = http_request(workspace, "https://example.test/")
            self.assertFalse(result["ok"], result)
            self.assertNotIn(invalid, json.dumps(result))
            self.assertNotIn("proxy-password", json.dumps(result))

    def test_artifact_download_uses_anonymous_connect_config_and_redacts(self):
        with isolated_runtime():
            workspace = self._workspace("artifact-egress")
            observed: dict[str, object] = {}

            def fake_run(argv, **kwargs):
                observed["argv"] = list(argv)
                observed["env"] = dict(kwargs["env"])
                observed["fd"] = kwargs["pass_fds"][0]
                observed["config"] = Path(
                    argv[argv.index("--config") + 1]
                ).read_text(encoding="utf-8")
                Path(argv[argv.index("--output") + 1]).write_bytes(b"artifact")
                Path(argv[argv.index("--dump-header") + 1]).write_text(
                    "HTTP/1.1 200 OK\r\nX-Proxy: " + self.proxy + "\r\n\r\n",
                    encoding="utf-8",
                )
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with patch.dict(os.environ, {config.EGRESS_PROXY_ENV: self.proxy}), \
                    patch("grypton.tools.config.find_binary", return_value="/usr/bin/curl"), \
                    patch("grypton.tools.subprocess.run", side_effect=fake_run):
                result = artifact_download(
                    workspace, "https://example.test/app.apk", "app.apk"
                )

            self.assertTrue(result["ok"], result)
            self.assertIn("proxytunnel", observed["config"])
            self.assertIn(self.proxy, observed["config"])
            self.assertNotIn(self.proxy, json.dumps(observed["argv"]))
            self.assertNotIn(self.proxy, json.dumps(observed["env"]))
            with self.assertRaises(OSError):
                os.fstat(observed["fd"])
            observable = json.dumps(result) + Path(result["data"]["flow"]).read_text()
            self.assertNotIn(self.proxy, observable)
            self.assertNotIn("proxy-password", observable)
            self.assertNotIn("proxy.invalid", observable)

    def test_target_research_uses_private_route_without_local_resolution(self):
        with isolated_runtime():
            workspace = self._workspace("research-target-egress")
            observed: dict[str, object] = {}

            def fake_run(argv, **kwargs):
                observed["argv"] = list(argv)
                observed["env"] = dict(kwargs["env"])
                observed["config"] = Path(
                    argv[argv.index("--config") + 1]
                ).read_text(encoding="utf-8")
                Path(argv[argv.index("--dump-header") + 1]).write_text(
                    "HTTP/1.1 200 OK\r\n\r\n", encoding="utf-8"
                )
                kwargs["stdout"].write(
                    ("target research " + self.proxy).encode("utf-8")
                )
                return SimpleNamespace(returncode=0, stderr=self.proxy.encode())

            with patch.dict(os.environ, {config.EGRESS_PROXY_ENV: self.proxy}), \
                    patch("grypton.tools.config.find_binary", return_value="/usr/bin/curl"), \
                    patch("grypton.tools.socket.getaddrinfo",
                          side_effect=AssertionError("target DNS must stay at proxy")), \
                    patch("grypton.tools.subprocess.run", side_effect=fake_run):
                result = research(workspace, "https://example.test/guide")

            self.assertTrue(result["ok"], result)
            self.assertIn("proxytunnel", observed["config"])
            self.assertIn(self.proxy, observed["config"])
            self.assertNotIn(self.proxy, json.dumps(observed["argv"]))
            self.assertNotIn(self.proxy, json.dumps(observed["env"]))
            observable = json.dumps(result) + "".join(
                path.read_text() for path in workspace.flows_dir.glob("*.http")
            )
            self.assertNotIn(self.proxy, observable)
            self.assertNotIn("proxy-password", observable)
            self.assertNotIn("proxy.invalid", observable)

    def test_public_documentation_research_stays_pinned_and_direct(self):
        with isolated_runtime():
            workspace = self._workspace("research-doc-egress")
            answer = (
                socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                ("93.184.216.34", 443),
            )
            with patch.dict(os.environ, {config.EGRESS_PROXY_ENV: self.proxy}), \
                    patch("grypton.tools.socket.getaddrinfo", return_value=[answer]) as resolver, \
                    patch("grypton.tools._research_request_once",
                          return_value=(200, "OK", None, b"public docs")) as direct, \
                    patch("grypton.tools._research_request_once_via_private_egress") as proxied:
                result = research(
                    workspace, "https://developer.mozilla.org/docs/Web"
                )

            self.assertTrue(result["ok"], result)
            resolver.assert_called_once_with(
                "developer.mozilla.org", 443, type=socket.SOCK_STREAM
            )
            direct.assert_called_once()
            proxied.assert_not_called()

    def test_goja_uses_explicit_private_fallback_and_never_starts(self):
        with isolated_runtime():
            workspace = self._workspace("goja-egress")
            observed: dict[str, object] = {}

            def fake_run(argv, **kwargs):
                observed["argv"] = list(argv)
                observed["env"] = dict(kwargs["env"])
                observed["config"] = Path(
                    argv[argv.index("--config") + 1]
                ).read_text(encoding="utf-8")
                Path(argv[argv.index("--dump-header") + 1]).write_text(
                    "HTTP/1.1 200 OK\r\n\r\n", encoding="utf-8"
                )
                kwargs["stdout"].write(b"fallback response")
                return SimpleNamespace(returncode=0, stderr=b"")

            with patch.dict(os.environ, {config.EGRESS_PROXY_ENV: self.proxy}), \
                    patch.object(Goja, "start") as start, \
                    patch("grypton.tools.config.find_binary", return_value="/usr/bin/curl"), \
                    patch("grypton.tools.subprocess.run", side_effect=fake_run):
                result = Goja.request(workspace, "https://example.test/")

            self.assertTrue(result["ok"], result)
            start.assert_not_called()
            self.assertFalse(result["data"]["goja_fingerprinting"])
            self.assertEqual(
                result["data"]["transport"], "goja-private-egress-fallback"
            )
            self.assertIn("fingerprinting was unavailable", result["summary"])
            self.assertIn(self.proxy, observed["config"])
            self.assertNotIn(self.proxy, json.dumps(observed["argv"]))
            self.assertNotIn(self.proxy, json.dumps(observed["env"]))
            observable = json.dumps(result) + Path(result["data"]["flow"]).read_text()
            self.assertNotIn(self.proxy, observable)
            self.assertNotIn("proxy-password", observable)

    def test_goja_start_fails_closed_with_private_egress(self):
        with isolated_runtime(), \
                patch.dict(os.environ, {config.EGRESS_PROXY_ENV: self.proxy}), \
                patch("grypton.tools.subprocess.Popen") as popen:
            result = Goja.start()
        self.assertFalse(result["ok"], result)
        self.assertIn("private egress", result["summary"])
        self.assertNotIn(self.proxy, json.dumps(result))
        popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
