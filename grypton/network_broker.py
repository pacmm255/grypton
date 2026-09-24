"""Root-side, scope-checked HTTP broker for Kraude's sandboxed shell."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import socket
import stat
import struct
from typing import Any

from .workspace import Workspace


MAX_BROKER_REQUEST_BYTES = 2 * 1024 * 1024
MAX_BROKER_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_REQUEST_BODY_BYTES = 1_000_000


class NetworkBrokerError(RuntimeError):
    """The scoped shell network broker cannot be started safely."""


class ScopedNetworkBroker:
    """Serve existing audited HTTP tooling to one sandbox identity over Unix."""

    def __init__(self, workspace: Path, target_slug: str,
                 socket_path: Path, peer_uid: int):
        self.workspace = workspace.resolve()
        self.target_slug = target_slug
        self.socket_path = socket_path
        self.peer_uid = int(peer_uid)
        self.server: asyncio.AbstractServer | None = None
        self._socket_inode = 0

    def healthy(self) -> bool:
        if self.server is None:
            return False
        try:
            info = self.socket_path.stat(follow_symlinks=False)
        except OSError:
            return False
        return stat.S_ISSOCK(info.st_mode) and info.st_ino == self._socket_inode

    async def start(self) -> None:
        if self.healthy():
            return
        await self.close()
        directory = self.socket_path.parent
        directory.mkdir(parents=True, exist_ok=True, mode=0o711)
        os.chmod(directory, 0o711)
        if self.socket_path.is_symlink():
            raise NetworkBrokerError("broker socket path is unsafe")
        try:
            existing = self.socket_path.stat(follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not stat.S_ISSOCK(existing.st_mode):
                raise NetworkBrokerError("broker socket path is occupied")
            self.socket_path.unlink()
        try:
            self.server = await asyncio.start_unix_server(
                self._handle, path=str(self.socket_path), limit=MAX_BROKER_REQUEST_BYTES + 1,
            )
            os.chown(self.socket_path, self.peer_uid, self.peer_uid)
            os.chmod(self.socket_path, 0o600)
            self._socket_inode = self.socket_path.stat(follow_symlinks=False).st_ino
        except BaseException as exc:
            await self.close()
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise NetworkBrokerError("scoped network broker failed to start") from exc

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        try:
            info = self.socket_path.stat(follow_symlinks=False)
        except FileNotFoundError:
            info = None
        except OSError:
            info = None
        if info is not None and stat.S_ISSOCK(info.st_mode):
            try:
                self.socket_path.unlink()
            except OSError:
                pass
        self._socket_inode = 0

    @staticmethod
    def _peer_uid(writer: asyncio.StreamWriter) -> int:
        sock = writer.get_extra_info("socket")
        if sock is None or not hasattr(socket, "SO_PEERCRED"):
            return -1
        try:
            raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _, uid, _ = struct.unpack("3i", raw)
            return int(uid)
        except (OSError, struct.error):
            return -1

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        response: dict[str, Any]
        try:
            if self._peer_uid(writer) != self.peer_uid:
                raise NetworkBrokerError("broker peer identity was rejected")
            raw = await reader.readline()
            if not raw or len(raw) > MAX_BROKER_REQUEST_BYTES or not raw.endswith(b"\n"):
                raise NetworkBrokerError("broker request is invalid")
            try:
                request = json.loads(raw)
            except (UnicodeDecodeError, ValueError) as exc:
                raise NetworkBrokerError("broker request is invalid") from exc
            if not isinstance(request, dict) or request.get("operation") != "http_request":
                raise NetworkBrokerError("broker operation is unsupported")
            arguments = request.get("arguments")
            if not isinstance(arguments, dict):
                raise NetworkBrokerError("broker request is invalid")
            arguments = dict(arguments)
            resolved = Workspace(self.target_slug)
            if resolved.root.resolve() != self.workspace:
                raise NetworkBrokerError("broker workspace binding is invalid")
            allowed_keys = {
                "url", "method", "headers", "body", "timeout",
                "follow_redirects", "insecure",
            }
            if set(arguments) - allowed_keys:
                raise NetworkBrokerError("broker request contains unsupported fields")
            if arguments.get("body") is None:
                arguments = {key: value for key, value in arguments.items()
                             if key != "body"}
            elif (not isinstance(arguments["body"], str)
                  or len(arguments["body"].encode("utf-8")) > MAX_REQUEST_BODY_BYTES):
                raise NetworkBrokerError("broker request body exceeded limit")
            # Import lazily to avoid the toolserver -> providers import during
            # module initialization. dispatch provides scope enforcement,
            # effect-intent logging, redacted auditing, and flow capture.
            from .toolserver import dispatch
            result = await asyncio.to_thread(
                dispatch, resolved, "http_request", arguments
            )
            response = {"ok": True, "result": result}
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # The client needs only a stable failure class. Paths, request
            # content, and exception detail never cross this boundary.
            response = {"ok": False, "error": str(exc) if isinstance(
                exc, NetworkBrokerError
            ) else "scoped network request failed"}
        try:
            payload = (json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8")
            if len(payload) > MAX_BROKER_RESPONSE_BYTES:
                payload = b'{"ok":false,"error":"broker response exceeded limit"}\n'
            writer.write(payload)
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


def curl_wrapper_source(socket_path: Path) -> str:
    """Return a standalone curl-compatible client for the Unix broker."""
    path_literal = repr(str(socket_path))
    return f'''#!/usr/bin/python3
import json
import socket
import sys
from urllib.parse import quote_plus

SOCKET_PATH = {path_literal}

def fail(message, code=2):
    print("curl: " + message, file=sys.stderr)
    raise SystemExit(code)

def take(argv, index, option):
    if index + 1 >= len(argv):
        fail("option " + option + " requires a value")
    return argv[index + 1], index + 2

def main():
    argv = sys.argv[1:]
    method = "GET"
    headers = {{}}
    body = None
    timeout = 30
    follow = False
    insecure = False
    use_get = False
    url = ""
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg in ("-s", "--silent", "-S", "--show-error", "-i", "--include", "--compressed"):
            index += 1
        elif arg in ("-k", "--insecure"):
            insecure = True; index += 1
        elif arg in ("-L", "--location"):
            follow = True; index += 1
        elif arg in ("-I", "--head"):
            method = "HEAD"; index += 1
        elif arg in ("-X", "--request"):
            method, index = take(argv, index, arg)
        elif arg in ("-H", "--header"):
            value, index = take(argv, index, arg)
            if ":" not in value:
                fail("header must contain a colon")
            name, item = value.split(":", 1)
            headers[name.strip()] = item.strip()
        elif arg in ("-A", "--user-agent"):
            value, index = take(argv, index, arg); headers["User-Agent"] = value
        elif arg in ("-e", "--referer"):
            value, index = take(argv, index, arg); headers["Referer"] = value
        elif arg in ("-b", "--cookie"):
            value, index = take(argv, index, arg); headers["Cookie"] = value
        elif arg in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json"):
            value, index = take(argv, index, arg)
            if value.startswith("@"):
                source = value[1:]
                try:
                    if source == "-": raw = sys.stdin.buffer.read(1000001)
                    else:
                        with open(source, "rb") as stream: raw = stream.read(1000001)
                except OSError:
                    fail("request body file is unavailable")
                if len(raw) > 1000000:
                    fail("request body exceeds 1000000 bytes")
                value = raw.decode("utf-8", "replace")
            if arg == "--data-urlencode":
                if "=" in value:
                    name, item = value.split("=", 1)
                    value = quote_plus(name) + "=" + quote_plus(item)
                else:
                    value = quote_plus(value)
            body = value if body is None else body + "&" + value
            if method == "GET" and not use_get: method = "POST"
            if arg == "--json": headers.setdefault("Content-Type", "application/json")
        elif arg == "--get":
            method = "GET"; use_get = True; index += 1
        elif arg == "--max-time":
            value, index = take(argv, index, arg)
            try: timeout = max(1, min(120, int(float(value))))
            except ValueError: fail("--max-time requires a number")
        elif arg == "--url":
            url, index = take(argv, index, arg)
        elif arg == "--":
            index += 1
            if index >= len(argv): fail("no URL supplied")
            if url: fail("multiple URLs are unavailable")
            url = argv[index]; index += 1
            if index != len(argv): fail("multiple URLs are unavailable")
        elif arg.startswith("-"):
            fail("unsupported option " + arg)
        else:
            if url: fail("multiple URLs are unavailable")
            url = arg; index += 1
    if not url: fail("no URL supplied")
    if use_get and body is not None:
        url += ("&" if "?" in url else "?") + body
        body = None
    arguments = {{
        "url": url, "method": method, "headers": headers,
        "timeout": timeout, "follow_redirects": follow, "insecure": insecure,
    }}
    if body is not None: arguments["body"] = body
    request = {{"operation": "http_request", "arguments": arguments}}
    payload = (json.dumps(request, ensure_ascii=False) + "\\n").encode()
    try:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(timeout + 10)
        connection.connect(SOCKET_PATH)
        connection.sendall(payload)
        chunks = []
        total = 0
        while True:
            block = connection.recv(65536)
            if not block: break
            chunks.append(block)
            total += len(block)
            if total > {MAX_BROKER_RESPONSE_BYTES}:
                fail("broker response exceeded limit", 7)
        connection.close()
        envelope = json.loads(b"".join(chunks))
    except (OSError, ValueError, TypeError):
        fail("scoped network broker is unavailable", 7)
    if not envelope.get("ok"):
        fail(str(envelope.get("error") or "scoped request failed"), 7)
    result = envelope.get("result") or {{}}
    data = result.get("data") if isinstance(result.get("data"), dict) else {{}}
    response = str(data.get("response") or "")
    if response:
        sys.stdout.write(response)
        if not response.endswith("\\n"): sys.stdout.write("\\n")
    if not result.get("ok"):
        print("curl: " + str(result.get("summary") or "request denied"), file=sys.stderr)
        raise SystemExit(22)
    raise SystemExit(0)

if __name__ == "__main__":
    main()
'''
