"""Loopback-only, read-only dashboard for live Grypton workspaces."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
import json
import mimetypes
from pathlib import Path
from urllib.parse import unquote, urlsplit

from . import config
from .scenarios import load_scenarios
from .workspace import Workspace, list_targets

ASSETS = {"/": "index.html", "/app.css": "app.css", "/app.js": "app.js"}


def _jsonl(path: Path, limit: int = 200) -> list[dict]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
    except OSError:
        return []
    rows = []
    for line in lines:
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def engagement_summary(slug: str) -> dict:
    ws = Workspace(slug)
    meta = ws.load_meta()
    findings = ws.findings.all()
    confirmed = ws.confirmed_findings()
    calls = _jsonl(ws.transcripts_dir / "provider-calls.jsonl", 10_000)
    return {"id": slug, "target": meta.target, "type": meta.target_type,
            "status": meta.status, "turns": meta.turn_index,
            "surface": len(ws.surface.all()), "tested": len(ws.tested.all()),
            "findings": len(findings), "confirmed": len(confirmed),
            "needs_more_evidence": sum(
                (row.get("manager_verdict") or {}).get("verdict") == "needs-more-evidence"
                for row in findings
            ),
            "validation_not_requested": sum(
                row.get("status") == "validation-not-requested" for row in findings
            ),
            "validated": sum(isinstance(row.get("manager_verdict"), dict) for row in findings),
            "flows": len(list(ws.flows_dir.glob("flow-*.http"))),
            "tool_calls": len(_jsonl(ws.root / ".ledger/tool-calls.jsonl", 100_000)),
            "provider_calls": {role: sum(row.get("role") == role for row in calls)
                               for role in ("worker", "manager", "validator")}}


def dashboard_state() -> dict:
    engagements = [engagement_summary(slug) for slug in reversed(list_targets())]
    return {"version": "3.0.1", "models": {
        "worker": {"name": "Kraude", "route": config.WORKER_MODEL, "effort": config.WORKER_EFFORT},
        "manager": {"name": "Kryptex", "route": config.MANAGER_MODEL, "effort": config.MANAGER_EFFORT},
        "validator": {"name": "Validator", "route": config.VALIDATOR_MODEL, "effort": config.VALIDATOR_EFFORT}},
        "counts": {"engagements": len(engagements),
                   "running": sum(row["status"] == "running" for row in engagements),
                   "tools": sum(row["tool_calls"] for row in engagements),
                   "findings": sum(row["findings"] for row in engagements),
                   "confirmed": sum(row["confirmed"] for row in engagements)},
        "engagements": engagements}


def engagement_detail(slug: str) -> dict:
    ws = Workspace(slug)
    if not ws.exists():
        raise FileNotFoundError(slug)
    meta = ws.load_meta()
    constraints = ws.load_constraints()
    return {**engagement_summary(slug), "workspace": str(ws.root),
            "scope": {"in_scope": constraints.in_scope, "out_of_scope": constraints.out_of_scope,
                      "hard_rules": constraints.hard_rules,
                      "standing_instructions": constraints.standing_instructions,
                      "notes": constraints.notes},
            "surface_rows": ws.surface.all()[-100:], "tested_rows": ws.tested.all()[-100:],
            "finding_rows": ws.findings.all()[-100:],
            "provider_rows": _jsonl(ws.transcripts_dir / "provider-calls.jsonl", 100),
            "tool_rows": _jsonl(ws.root / ".ledger/tool-calls.jsonl", 100),
            "flow_rows": [{"id": path.stem, "bytes": path.stat().st_size}
                          for path in sorted(ws.flows_dir.glob("flow-*.http"), reverse=True)[:100]],
            "last_directive": meta.last_directive}


def make_server(port: int = 8765) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "Grypton/3.0.1"
        sys_version = ""

        def log_message(self, format, *args):
            pass

        def reply(self, status: int, payload: bytes, content_type="application/json; charset=utf-8"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def local_request(self) -> bool:
            port = self.server.server_address[1]
            hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
            origin = self.headers.get("Origin")
            valid = self.headers.get("Host", "") in hosts and (
                origin is None or origin in {"http://" + host for host in hosts})
            if not valid or self.headers.get("Sec-Fetch-Site") == "cross-site":
                self.reply(403, b'{"error":"loopback dashboard only"}')
                return False
            return True

        def do_GET(self):
            if not self.local_request():
                return
            path = urlsplit(self.path).path
            try:
                if path in ASSETS:
                    name = ASSETS[path]
                    body = files("grypton").joinpath("resources", "web", name).read_bytes()
                    kind = mimetypes.guess_type(name)[0] or "application/octet-stream"
                    return self.reply(200, body, kind + "; charset=utf-8")
                if path == "/api/state":
                    return self.reply(200, json.dumps(dashboard_state(), ensure_ascii=False).encode())
                if path == "/api/scenarios":
                    return self.reply(200, json.dumps(load_scenarios(), ensure_ascii=False).encode())
                if path.startswith("/api/engagements/"):
                    raw = unquote(path.removeprefix("/api/engagements/"))
                    slug = config.slugify(raw)
                    if slug != raw:
                        return self.reply(400, b'{"error":"invalid engagement id"}')
                    return self.reply(200, json.dumps(engagement_detail(slug), ensure_ascii=False).encode())
                return self.reply(404, b'{"error":"not found"}')
            except FileNotFoundError:
                return self.reply(404, b'{"error":"engagement not found"}')
            except (OSError, ValueError):
                return self.reply(500, b'{"error":"cannot read workspace state"}')

        def do_POST(self):
            self.reply(405, b'{"error":"dashboard is read-only"}')

        do_PUT = do_PATCH = do_DELETE = do_POST

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server


def serve(port: int = 8765) -> None:
    server = make_server(port)
    print(f"Grypton dashboard: http://127.0.0.1:{server.server_address[1]}")
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
