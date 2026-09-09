"""Instrumented loopback target used for live end-to-end verification."""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import time
from urllib.parse import parse_qs, urlsplit


class LabHandler(BaseHTTPRequestHandler):
    server_version = "GryptonLab/1.0"

    def _log(self, status: int) -> None:
        path = getattr(self.server, "event_log", None)
        if not path:
            return
        record = {"at": time.time(), "client": self.client_address[0],
                  "method": self.command, "path": self.path, "status": status,
                  "headers": {key: value for key, value in self.headers.items()
                              if key.lower() not in {"authorization", "cookie"}}}
        with Path(path).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Lab-Scope", "loopback-only")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self._log(status)

    def do_HEAD(self):
        self.do_GET()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self.send_header("X-Lab-Scope", "loopback-only")
        self.end_headers()
        self._log(204)

    def do_GET(self):
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/":
            body = b"""<!doctype html><title>Grypton Local Lab</title>
<h1>Profile Console</h1><script src=/static/app.js></script>
<a href=/api/me>Current profile</a>"""
            return self._send(200, body, "text/html; charset=utf-8")
        if parsed.path == "/static/app.js":
            body = b"const API=['/api/me','/api/profile?id=1','/api/profile?id=2'];"
            return self._send(200, body, "application/javascript")
        if parsed.path == "/robots.txt":
            return self._send(200, b"Disallow: /debug/config\n", "text/plain")
        if parsed.path == "/api/me":
            user = self.headers.get("X-Lab-User", "1")
            body = json.dumps({"id": user, "role": "member"}).encode()
            return self._send(200, body, "application/json")
        if parsed.path == "/api/profile":
            caller = self.headers.get("X-Lab-User", "1")
            requested = query.get("id", [caller])[0]
            profiles = {
                "1": {"id": "1", "email": "alice@example.invalid", "role": "member"},
                "2": {"id": "2", "email": "bob@example.invalid", "role": "member"},
            }
            if requested not in profiles:
                return self._send(404, b'{"error":"not found"}', "application/json")
            body = json.dumps(profiles[requested]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Lab-Scope", "loopback-only")
            self.send_header("X-Lab-Authorization", "missing-object-check" if requested != caller else "self")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            self._log(200)
            return
        if parsed.path == "/debug/config":
            body = b'{"debug":true,"environment":"synthetic-local-lab"}'
            return self._send(200, body, "application/json")
        return self._send(404, b'{"error":"not found"}', "application/json")

    def log_message(self, format: str, *args) -> None:
        print(f"{self.address_string()} {format % args}", flush=True)


def serve(host: str = "127.0.0.1", port: int = 0, event_log: str = "") -> None:
    server = ThreadingHTTPServer((host, port), LabHandler)
    server.event_log = event_log
    if event_log:
        Path(event_log).parent.mkdir(parents=True, exist_ok=True)
    print(json.dumps({"ready": True, "url": f"http://{host}:{server.server_port}",
                      "event_log": event_log}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run Grypton's instrumented loopback target")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--log", default="")
    args = parser.parse_args(argv)
    serve(args.host, args.port, args.log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
