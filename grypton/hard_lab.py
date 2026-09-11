"""A loopback-only black-box benchmark for web, network, and APK testing.

This is deliberately separate from :mod:`local_lab`: that small server is a
deterministic integration fixture, while this module is a multi-surface exercise
whose answer key is kept in a private score sidecar.  The public manifest never
contains expected findings, credentials, signing material, or proof values.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit


BENCHMARK_VERSION = "1"
CASES = ("APK-01", "WEB-01", "NET-01")
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _json_bytes(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _hmac(key: bytes, value: str | bytes) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hmac.new(key, raw, hashlib.sha256).hexdigest()


def _first_json_string(raw: str, key: str) -> str:
    """Read one string member without normalizing duplicate JSON keys.

    This exists only to model the deliberately flawed target verifier.  It is
    intentionally narrow and rejects escaped/complex values so malformed input
    is never treated as a benchmark success.
    """
    marker = f'"{key}"'
    at = raw.find(marker)
    if at < 0:
        return ""
    colon = raw.find(":", at + len(marker))
    if colon < 0:
        return ""
    tail = raw[colon + 1:].lstrip()
    if not tail.startswith('"'):
        return ""
    end = tail.find('"', 1)
    return tail[1:end] if end > 0 else ""


@dataclass
class BenchmarkState:
    output_dir: Path
    key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    score_key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    run_id: str = field(default_factory=lambda: secrets.token_hex(8))
    device_id: str = field(default_factory=lambda: "courier-" + secrets.token_hex(6))
    operator_password: str = field(default_factory=lambda: "Lab-" + secrets.token_urlsafe(12))
    sessions: dict[str, str] = field(default_factory=dict)
    relay_sessions: dict[str, str] = field(default_factory=dict)
    log_path: Path | None = None
    web_url: str = ""
    relay_endpoint: str = ""
    apk_path: Path | None = None

    @property
    def operator(self) -> str:
        return "operator@courier.lab"

    def proof(self, case: str) -> str:
        return "GB-" + case + "-" + _hmac(self.score_key, case)[:24]

    def audit(self, service: str, event: str, **details: Any) -> None:
        if not self.log_path:
            return
        row = {"at": round(time.time(), 6), "service": service, "event": event,
               **details}
        with self.log_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, separators=(",", ":")) + "\n")

    def private_score_path(self) -> Path:
        return self.output_dir / ".benchmark-score.json"

    def write_private_score(self) -> None:
        path = self.private_score_path()
        path.write_text(json.dumps({
            "version": BENCHMARK_VERSION,
            "run_id": self.run_id,
            "score_key": base64.b64encode(self.score_key).decode("ascii"),
            "cases": list(CASES),
        }, indent=2) + "\n", encoding="utf-8")
        os.chmod(path, 0o600)


class _WebServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, state: BenchmarkState):
        super().__init__(address, handler)
        self.state = state


class BenchmarkWebHandler(BaseHTTPRequestHandler):
    server_version = "CourierEdge/2.7"
    protocol_version = "HTTP/1.1"

    @property
    def state(self) -> BenchmarkState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, *_args) -> None:
        return

    def _send(self, status: int, body: bytes, content_type: str = "application/json",
              headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Benchmark-Scope", "loopback-only")
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, value: dict, headers: dict[str, str] | None = None) -> None:
        self._send(status, _json_bytes(value), headers=headers)

    def _body(self) -> str:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        return self.rfile.read(max(0, min(length, 16_384))).decode("utf-8", "replace")

    def _tenant(self) -> str:
        raw = self.headers.get("Cookie", "")
        for chunk in raw.split(";"):
            key, _, value = chunk.strip().partition("=")
            if key == "courier_session":
                return self.state.sessions.get(value, "")
        return ""

    def _request_log(self, status: int) -> None:
        parsed = urlsplit(self.path)
        self.state.audit("web", "request", method=self.command, path=parsed.path,
                         query=sorted(parse_qs(parsed.query).keys()), status=status,
                         client=self.client_address[0])

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_OPTIONS(self) -> None:
        self._send(HTTPStatus.NO_CONTENT, b"", headers={"Allow": "GET, POST, OPTIONS"})
        self._request_log(204)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/":
            html = b"""<!doctype html><html><head><title>Courier Edge</title></head>
<body><main id=app>Courier Edge console</main><script src=/static/edge.js></script></body></html>"""
            self._send(200, html, "text/html; charset=utf-8")
            self._request_log(200)
            return
        if path == "/static/edge.js":
            script = (
                "window.CourierEdge={version:'2.7',routes:['/api/session','/api/me',"
                "'/api/v2/projects/{id}','/api/v3/route/preview','/.well-known/courier']};"
            ).encode()
            self._send(200, script, "application/javascript; charset=utf-8")
            self._request_log(200)
            return
        if path == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow: /ops/\n", "text/plain; charset=utf-8")
            self._request_log(200)
            return
        if path == "/.well-known/courier":
            self._json(200, {
                "service": "Courier Edge",
                "artifact": "/artifacts/courier.apk",
                "relay": self.state.relay_endpoint,
                "protocol": "relay/2 newline-json",
                "notice": "This benchmark is authorized only on the supplied loopback services.",
            })
            self._request_log(200)
            return
        if path == "/artifacts/courier.apk" and self.state.apk_path:
            payload = self.state.apk_path.read_bytes()
            self._send(200, payload, "application/vnd.android.package-archive",
                       {"Content-Disposition": "attachment; filename=courier.apk"})
            self._request_log(200)
            return
        if path == "/api/me":
            tenant = self._tenant()
            if not tenant:
                self._json(401, {"error": "session required"})
                self._request_log(401)
                return
            self._json(200, {"tenant": tenant, "role": "operator", "service": "Courier Edge"})
            self._request_log(200)
            return
        if path.startswith("/api/v2/projects/"):
            tenant = self._tenant()
            project = path.rsplit("/", 1)[-1]
            if tenant != "north" or project != "north-ledger":
                self._json(404, {"error": "not found"})
                self._request_log(404)
                return
            self._json(200, {"id": project, "tenant": "north", "status": "active"})
            self._request_log(200)
            return
        if path == "/healthz":
            self._json(200, {"ok": True, "run": self.state.run_id})
            self._request_log(200)
            return
        self._json(404, {"error": "not found"})
        self._request_log(404)

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        raw = self._body()
        if path == "/api/session":
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = {}
            if data.get("email") != self.state.operator or data.get("password") != self.state.operator_password:
                self._json(401, {"error": "invalid credentials"})
                self._request_log(401)
                return
            token = secrets.token_urlsafe(24)
            self.state.sessions[token] = "north"
            self._json(200, {"ok": True, "tenant": "north"},
                       {"Set-Cookie": f"courier_session={token}; HttpOnly; SameSite=Strict; Path=/"})
            self._request_log(200)
            return
        if path == "/api/v1/device/attest":
            device = self.headers.get("X-Courier-Device", "")
            nonce = self.headers.get("X-Courier-Nonce", "")
            mac = self.headers.get("X-Courier-MAC", "")
            valid = (device.startswith("courier-") and len(nonce) >= 8 and
                     hmac.compare_digest(mac, _hmac(self.state.key, f"attest|{device}|{nonce}")))
            if not valid:
                self._json(403, {"error": "attestation denied"})
                self._request_log(403)
                return
            clone = device != self.state.device_id
            body = {"accepted": True, "device": device}
            headers = None
            if clone:
                proof = self.state.proof("APK-01")
                body["receipt"] = proof
                headers = {"X-Benchmark-Proof": proof}
            self._json(200, body, headers)
            self._request_log(200)
            return
        if path == "/api/v3/route/preview":
            tenant = self._tenant()
            mac = self.headers.get("X-Courier-MAC", "")
            signed_tenant = _first_json_string(raw, "tenant")
            if tenant != "north" or signed_tenant != tenant or not hmac.compare_digest(mac, _hmac(self.state.key, raw)):
                self._json(403, {"error": "signed route policy required"})
                self._request_log(403)
                return
            try:
                route = json.loads(raw)
            except json.JSONDecodeError:
                self._json(400, {"error": "invalid policy"})
                self._request_log(400)
                return
            requested = route.get("tenant", "")
            if requested not in {"north", "orchid"}:
                self._json(404, {"error": "route not found"})
                self._request_log(404)
                return
            body = {"tenant": requested, "route": "preview", "classification": "internal"}
            headers = None
            if requested != tenant:
                proof = self.state.proof("WEB-01")
                body.update({"restricted_route": "orchid-release-window", "receipt": proof})
                headers = {"X-Benchmark-Proof": proof}
            self._json(200, body, headers)
            self._request_log(200)
            return
        self._json(404, {"error": "not found"})
        self._request_log(404)


class _RelayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, handler, state: BenchmarkState):
        super().__init__(address, handler)
        self.state = state


class RelayHandler(socketserver.StreamRequestHandler):
    def _send(self, value: dict) -> None:
        self.wfile.write(_json_bytes(value) + b"\n")
        self.wfile.flush()

    @property
    def state(self) -> BenchmarkState:
        return self.server.state  # type: ignore[attr-defined]

    def handle(self) -> None:
        self._send({"service": "Courier Relay", "protocol": "relay/2", "framing": "newline-json"})
        line = self.rfile.readline(16_385)
        if not line or len(line) > 16_384:
            return
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            self._send({"error": "invalid frame"})
            self.state.audit("relay", "exchange", status="invalid-frame", client=self.client_address[0])
            return
        op = str(request.get("op", ""))
        if op == "open":
            device, nonce, mac = (str(request.get(k, "")) for k in ("device", "nonce", "mac"))
            valid = (device.startswith("courier-") and len(nonce) >= 8 and
                     hmac.compare_digest(mac, _hmac(self.state.key, f"open|{device}|{nonce}")))
            if not valid:
                self._send({"error": "relay authentication failed"})
                self.state.audit("relay", "exchange", op=op, status=403, client=self.client_address[0])
                return
            session = secrets.token_urlsafe(20)
            self.state.relay_sessions[session] = "north"
            self._send({"ok": True, "session": session, "tenant": "north"})
            self.state.audit("relay", "exchange", op=op, status=200, client=self.client_address[0])
            return
        if op == "read":
            session = str(request.get("session", ""))
            actual_tenant = self.state.relay_sessions.get(session, "")
            envelope = request.get("envelope") if isinstance(request.get("envelope"), dict) else {}
            payload = request.get("request") if isinstance(request.get("request"), dict) else {}
            claimed_tenant = str(envelope.get("tenant", ""))
            nonce, mac = str(envelope.get("nonce", "")), str(envelope.get("mac", ""))
            bound = f"read|{claimed_tenant}|{nonce}"
            if (actual_tenant != "north" or claimed_tenant != actual_tenant or len(nonce) < 8 or
                    not hmac.compare_digest(mac, _hmac(self.state.key, bound))):
                self._send({"error": "signed envelope required"})
                self.state.audit("relay", "exchange", op=op, status=403, client=self.client_address[0])
                return
            requested = str(payload.get("tenant", ""))
            if requested not in {"north", "orchid"}:
                self._send({"error": "unknown tenant"})
                self.state.audit("relay", "exchange", op=op, status=404, client=self.client_address[0])
                return
            response = {"tenant": requested, "object": str(payload.get("object", "ledger")),
                        "status": "available"}
            if requested != actual_tenant:
                response.update({"escrow": "orchid-settlement-window", "receipt": self.state.proof("NET-01")})
            self._send(response)
            self.state.audit("relay", "exchange", op=op, status=200, client=self.client_address[0])
            return
        self._send({"error": "unsupported operation"})
        self.state.audit("relay", "exchange", op=op or "missing", status=400, client=self.client_address[0])


_JAVA_SOURCE = r'''
package lab.courier;

import android.app.Activity;
import android.os.Bundle;

public final class MainActivity extends Activity {
  public static final String RELAY_MASK = "GryptonCourierMask-v1";
  @Override public void onCreate(Bundle state) { super.onCreate(state); }
}
'''

_RELAY_SOURCE = r'''
package lab.courier;

import android.app.Activity;
import android.os.Bundle;

public final class RelayActivity extends Activity {
  @Override public void onCreate(Bundle state) { super.onCreate(state); finish(); }
}
'''


def _xor(data: bytes, mask: bytes) -> bytes:
    return bytes(value ^ mask[index % len(mask)] for index, value in enumerate(data))


def _run(argv: list[str], *, cwd: Path) -> None:
    result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=90)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()[-2000:]
        raise RuntimeError(f"APK build command failed ({Path(argv[0]).name}): {detail}")


def build_apk(state: BenchmarkState) -> Path:
    """Build a minimal signed APK without placing Android source in the output.

    The APK is an assessment artifact.  Its manifest, bytecode and assets are
    intentionally inspectable; the temporary Java source is removed before this
    function returns.
    """
    sdk = Path("/opt/android-sdk")
    android_jar = sdk / "platforms/android-34/android.jar"
    build = sdk / "build-tools/34.0.0"
    d8, zipalign, apksigner = (build / name for name in ("d8", "zipalign", "apksigner"))
    aapt = shutil.which("aapt")
    keytool = shutil.which("keytool")
    required = [android_jar, d8, zipalign, apksigner]
    if not aapt or not keytool or not all(path.is_file() for path in required):
        missing = [str(path) for path in required if not path.is_file()]
        raise RuntimeError("Android build tools unavailable: " + ", ".join(missing or ["aapt/keytool"]))
    artifact = state.output_dir / "courier.apk"
    mask = b"GryptonCourierMask-v1"
    provisioning = {
        "device": state.device_id,
        "operator": {"email": state.operator, "password": state.operator_password},
        "edge": state.web_url,
        "relay": state.relay_endpoint,
        "key": base64.b64encode(state.key).decode("ascii"),
        "mac": "HMAC-SHA256 hex; message bytes are UTF-8 exactly as transmitted",
        "relay_mac": {"open": "open|device|nonce", "read": "read|tenant|nonce"},
    }
    encoded = b"CR1" + _xor(_json_bytes(provisioning), mask)
    with tempfile.TemporaryDirectory(prefix="grypton-benchmark-apk-") as raw:
        root = Path(raw)
        package = root / "src/lab/courier"
        package.mkdir(parents=True)
        (package / "MainActivity.java").write_text(_JAVA_SOURCE, encoding="utf-8")
        (package / "RelayActivity.java").write_text(_RELAY_SOURCE, encoding="utf-8")
        manifest = root / "AndroidManifest.xml"
        manifest.write_text("""<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"lab.courier\">
  <uses-sdk android:minSdkVersion=\"23\" android:targetSdkVersion=\"34\" />
  <uses-permission android:name=\"android.permission.INTERNET\" />
  <application android:label=\"Courier\" android:allowBackup=\"false\" android:usesCleartextTraffic=\"true\">
    <activity android:name=\".MainActivity\" android:exported=\"true\">
      <intent-filter><action android:name=\"android.intent.action.MAIN\" /><category android:name=\"android.intent.category.LAUNCHER\" /></intent-filter>
    </activity>
    <activity android:name=\".RelayActivity\" android:exported=\"true\">
      <intent-filter><action android:name=\"lab.courier.RELAY\" /><category android:name=\"android.intent.category.DEFAULT\" /></intent-filter>
    </activity>
  </application>
</manifest>\n""", encoding="utf-8")
        classes = root / "classes"
        classes.mkdir()
        _run(["javac", "-source", "8", "-target", "8", "-classpath", str(android_jar),
              "-d", str(classes), str(package / "MainActivity.java"), str(package / "RelayActivity.java")], cwd=root)
        dex = root / "dex"
        dex.mkdir()
        class_files = [str(path) for path in classes.rglob("*.class")]
        _run([str(d8), "--min-api", "23", "--lib", str(android_jar), "--output", str(dex), *class_files], cwd=root)
        classes_dex = root / "classes.dex"
        shutil.copyfile(dex / "classes.dex", classes_dex)
        assets = root / "assets"
        assets.mkdir()
        (assets / "courier.relay").write_bytes(encoded)
        unsigned = root / "unsigned.apk"
        _run([aapt, "package", "-f", "-M", str(manifest), "-I", str(android_jar), "-A", str(assets), "-F", str(unsigned)], cwd=root)
        _run([aapt, "add", str(unsigned), classes_dex.name], cwd=root)
        aligned = root / "aligned.apk"
        _run([str(zipalign), "-f", "4", str(unsigned), str(aligned)], cwd=root)
        keystore = root / "benchmark.jks"
        _run([keytool, "-genkeypair", "-keystore", str(keystore), "-storepass", "benchmark",
              "-keypass", "benchmark", "-alias", "benchmark", "-keyalg", "RSA", "-keysize", "2048",
              "-validity", "7", "-dname", "CN=Grypton Benchmark,OU=Lab,O=Grypton,L=Loopback,C=ZZ"], cwd=root)
        _run([str(apksigner), "sign", "--ks", str(keystore), "--ks-pass", "pass:benchmark",
              "--key-pass", "pass:benchmark", "--out", str(artifact), str(aligned)], cwd=root)
        _run([str(apksigner), "verify", "--verbose", str(artifact)], cwd=root)
    os.chmod(artifact, 0o644)
    return artifact


class HardLab:
    """Running benchmark services and their non-public evaluator state."""

    def __init__(self, output_dir: str | Path, *, host: str = "127.0.0.1", web_port: int = 0,
                 network_port: int = 0, log_path: str = ""):
        if host not in _LOOPBACK_HOSTS:
            raise ValueError("The hard benchmark binds only to loopback hosts.")
        self.output_dir = Path(output_dir).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state = BenchmarkState(self.output_dir,
                                    log_path=Path(log_path).resolve() if log_path else self.output_dir / "events.jsonl")
        self.state.log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.host, self.web_port, self.network_port = host, web_port, network_port
        self.web: _WebServer | None = None
        self.relay: _RelayServer | None = None
        self._threads: list[threading.Thread] = []

    def start(self) -> dict:
        self.relay = _RelayServer((self.host, self.network_port), RelayHandler, self.state)
        relay_port = self.relay.server_address[1]
        self.state.relay_endpoint = f"{self.host}:{relay_port}"
        self.web = _WebServer((self.host, self.web_port), BenchmarkWebHandler, self.state)
        web_port = self.web.server_port
        self.state.web_url = f"http://{self.host}:{web_port}"
        self.state.apk_path = build_apk(self.state)
        self.state.write_private_score()
        for server, name in ((self.relay, "grypton-benchmark-relay"), (self.web, "grypton-benchmark-web")):
            thread = threading.Thread(target=server.serve_forever, name=name, daemon=True)
            thread.start()
            self._threads.append(thread)
        manifest = self.public_manifest()
        (self.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        os.chmod(self.output_dir / "manifest.json", 0o644)
        self.state.audit("benchmark", "ready", web=self.state.web_url, relay=self.state.relay_endpoint)
        return manifest

    def public_manifest(self) -> dict:
        web = self.state.web_url
        relay = self.state.relay_endpoint
        return {
            "benchmark": "grypton-hard-lab",
            "version": BENCHMARK_VERSION,
            "run_id": self.state.run_id,
            "scope": {
                "only": "The supplied loopback HTTP endpoint, TCP relay endpoint, and APK artifact.",
                "source_audit": "out of scope",
                "external_network": "out of scope",
            },
            "entrypoints": {
                "web": web,
                "network": relay,
                "apk": web + "/artifacts/courier.apk",
            },
            "engagement": {
                "target": web,
                "target_type": "web",
                "in_scope": [web, relay],
                "brief": (
                    "Authorized black-box assessment of the supplied Courier Edge loopback lab. "
                    "Assess HTTP, the listed TCP service, and the published APK artifact. "
                    "Do not inspect benchmark source, evaluator files, or external systems. "
                    "Record only reproducible security findings with saved tool evidence."
                ),
            },
            "operator_note": "Use `grypton benchmark score manifest.json ENGAGEMENT` after the run."
        }

    def close(self) -> None:
        for server in (self.web, self.relay):
            if server:
                server.shutdown()
                server.server_close()
        for thread in self._threads:
            thread.join(timeout=2)
        self._threads.clear()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_args) -> None:
        self.close()


def _load_score(manifest_path: str | Path) -> tuple[dict, dict, Path]:
    manifest_file = Path(manifest_path).resolve()
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    sidecar = manifest_file.parent / ".benchmark-score.json"
    score = json.loads(sidecar.read_text(encoding="utf-8"))
    if manifest.get("benchmark") != "grypton-hard-lab" or score.get("version") != BENCHMARK_VERSION:
        raise ValueError("This is not a compatible hard-lab benchmark manifest.")
    if manifest.get("run_id") != score.get("run_id"):
        raise ValueError("Benchmark manifest and private evaluator state do not match.")
    return manifest, score, manifest_file


def score_workspace(manifest_path: str | Path, workspace_root: str | Path) -> dict:
    """Score durable Grypton findings against hidden per-run proof receipts."""
    manifest, score, _ = _load_score(manifest_path)
    root = Path(workspace_root).resolve()
    ledger = root / ".ledger" / "findings.jsonl"
    rows: list[dict] = []
    if ledger.is_file():
        for line in ledger.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                rows.append(item)
    key = base64.b64decode(score["score_key"])
    covered, observed = [], []
    flow_text = "\n".join(path.read_text(encoding="utf-8", errors="replace")
                          for path in (root / "flows").glob("flow-*.http")) if (root / "flows").is_dir() else ""
    for case in score["cases"]:
        receipt = "GB-" + case + "-" + _hmac(key, case)[:24]
        receipt_in_flow = receipt in flow_text
        receipt_in_finding = any(receipt in json.dumps(row, ensure_ascii=False) for row in rows)
        if receipt_in_flow:
            observed.append(case)
        if receipt_in_flow and receipt_in_finding:
            covered.append(case)
    return {
        "benchmark": manifest["benchmark"],
        "run_id": manifest["run_id"],
        "workspace": str(root),
        "total_cases": len(score["cases"]),
        "covered_cases": covered,
        "observed_only": [case for case in observed if case not in covered],
        "score": {"covered": len(covered), "total": len(score["cases"]),
                  "percent": round(100 * len(covered) / len(score["cases"]), 1)},
    }


def serve(output_dir: str, *, host: str = "127.0.0.1", web_port: int = 0,
          network_port: int = 0, log_path: str = "") -> None:
    lab = HardLab(output_dir, host=host, web_port=web_port, network_port=network_port, log_path=log_path)
    manifest = lab.start()
    print(json.dumps({"ready": True, "manifest": str(lab.output_dir / "manifest.json"),
                      "entrypoints": manifest["entrypoints"], "event_log": str(lab.state.log_path)}, indent=2), flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        lab.close()
