"""Loopback-only, read-only dashboard with a fixed asset and API allowlist."""
import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from urllib.parse import unquote, urlsplit

from .config import GryptonError
from .presentation import case_detail, line, state

ASSETS = {"/": "index.html", "/app.css": "app.css", "/app.js": "app.js"}


def make_server(store, port: int = 8765) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "Grypton"
        sys_version = ""

        def log_message(self, format, *args):
            pass

        def send_body(self, status: int, payload: bytes, kind: str = "application/json; charset=utf-8"):
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def allowed(self) -> bool:
            local_port = self.server.server_address[1]
            allowed = {f"127.0.0.1:{local_port}", f"localhost:{local_port}"}
            host = self.headers.get("Host", "")
            origin = self.headers.get("Origin")
            if host not in allowed or (origin is not None and origin not in {"http://" + value for value in allowed}):
                self.send_body(403, b'{"error":"Local dashboard access only."}')
                return False
            if self.headers.get("Sec-Fetch-Site") == "cross-site":
                self.send_body(403, b'{"error":"Cross-site access is disabled."}')
                return False
            return True

        def do_GET(self):
            if not self.allowed():
                return
            path = urlsplit(self.path).path
            try:
                if path in ASSETS:
                    name = ASSETS[path]
                    kind = mimetypes.guess_type(name)[0] or "application/octet-stream"
                    payload = files("grypton").joinpath("resources", "web", name).read_bytes()
                    self.send_body(200, payload, kind + "; charset=utf-8")
                elif path == "/api/state":
                    self.send_body(200, json.dumps(state(store), ensure_ascii=False).encode())
                elif path.startswith("/api/cases/"):
                    case = store.get(unquote(path.removeprefix("/api/cases/")))
                    self.send_body(200, json.dumps(case_detail(case), ensure_ascii=False).encode())
                else:
                    self.send_body(404, b'{"error":"Not found."}')
            except GryptonError as exc:
                self.send_body(400, json.dumps({"error": str(exc)}).encode())
            except OSError:
                self.send_body(500, b'{"error":"Cannot read workspace state."}')

        def do_POST(self):
            self.send_body(405, b'{"error":"This dashboard is read-only. Use the CLI to manage reviews."}')

        do_PUT = do_POST
        do_PATCH = do_POST
        do_DELETE = do_POST

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server


def serve(store, port: int) -> None:
    server = make_server(store, port)
    line(f"Grypton dashboard: http://127.0.0.1:{server.server_address[1]}")
    line("Press Ctrl-C to close the dashboard.")
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
