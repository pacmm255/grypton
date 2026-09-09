"""Krypton tool implementations (shared by the MCP server and the CLI).

Every function returns a ``dict`` ``{"ok": bool, "summary": str, "data": ...}`` and
degrades gracefully — a missing binary or a failed proxy never raises into the
caller; it returns ``ok: False`` with a clear message so the worker can adapt.

Stdlib-only (subprocess/socket/urllib) so Krypton has no third-party runtime deps.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Optional

from . import config
from .workspace import Workspace


def _ok(summary: str, data=None) -> dict:
    return {"ok": True, "summary": summary, "data": data}


def _err(summary: str, data=None) -> dict:
    return {"ok": False, "summary": summary, "data": data}


def _port_open(hostport: str, timeout: float = 0.4) -> bool:
    host, _, port = hostport.partition(":")
    try:
        with socket.create_connection((host, int(port or 0)), timeout=timeout):
            return True
    except OSError:
        return False


# --------------------------------------------------------------------------
# Goja — SOCKS5 MITM with JA3/JA4 fingerprint spoofing (R17/R18)
# --------------------------------------------------------------------------


class Goja:
    BIN = config.GOJA_DIR / "bin" / "goja-proxy"
    CA = config.GOJA_DIR / "certs" / "certs" / "goja-root-ca.pem"

    @classmethod
    def running(cls) -> bool:
        return _port_open(config.GOJA_SOCKS)

    @classmethod
    def _managed_config(cls) -> Path:
        """Krypton-managed config so we never depend on (or mutate) the user's
        `/root/Goja/config.json`, which may be corrupted. We sanitize a copy by
        truncating any trailing junk after the final closing brace; if that still
        won't parse, we fall back to a minimal valid config."""
        out = config.RUNTIME_DIR / "goja-config.json"
        config.RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        src = config.GOJA_DIR / "config.json"
        try:
            raw = src.read_bytes()
            end = raw.rfind(b"}")
            if end != -1:
                obj = json.loads(raw[: end + 1])
                # keep the dashboard off so we don't need its bcrypt auth
                if isinstance(obj.get("dashboard"), dict):
                    obj["dashboard"]["enabled"] = False
                out.write_text(json.dumps(obj, indent=2))
                return out
        except Exception:
            pass
        out.write_text(json.dumps(cls._minimal_config(), indent=2))
        return out

    @staticmethod
    def _minimal_config() -> dict:
        return {
            "fingerprintPreset": "chrome-139-desktop",
            "dashboard": {"enabled": False},
            "filters": [], "replacements": [], "upstreamProxy": "",
            "reuseConnections": True, "requestTimeoutSec": 30,
            "certificateAuthority": {
                "enabled": True, "persist": True, "directory": "certs",
                "certFile": "certs/certs/goja-root-ca.pem",
                "keyFile": "certs/certs/goja-root-ca.key"},
        }

    @classmethod
    def start(cls, wait_s: float = 10.0) -> dict:
        if cls.running():
            return _ok(f"Goja already running (SOCKS5 {config.GOJA_SOCKS}).")
        if not cls.BIN.exists():
            return _err(f"Goja binary not found at {cls.BIN}. Build it in {config.GOJA_DIR} "
                        f"or curl directly without fingerprint spoofing.")
        log = config.LOG_DIR / "goja.log"
        config.LOG_DIR.mkdir(parents=True, exist_ok=True)
        cfg = cls._managed_config()
        try:
            lf = log.open("ab")
            subprocess.Popen([str(cls.BIN), "-config", str(cfg)],
                             cwd=str(config.GOJA_DIR),
                             stdout=lf, stderr=lf, stdin=subprocess.DEVNULL,
                             start_new_session=True)
        except OSError as e:
            return _err(f"Failed to launch Goja: {e}")
        deadline = time.time() + wait_s
        while time.time() < deadline:
            if cls.running():
                return _ok(f"Goja started (SOCKS5 {config.GOJA_SOCKS}, config {cfg}). Log: {log}")
            time.sleep(0.3)
        tail = ""
        try:
            tail = log.read_text(errors="replace").splitlines()[-3:]
        except OSError:
            pass
        return _err(f"Goja did not open {config.GOJA_SOCKS} within {wait_s}s. Log tail: {tail}")

    @classmethod
    def request(cls, url: str, *, method: str = "GET", headers: Optional[dict] = None,
                body: Optional[str] = None, timeout: int = 30,
                workspace: Optional[Workspace] = None) -> dict:
        """One-shot fingerprinted request routed through the Goja SOCKS5 MITM."""
        curl = shutil.which("curl")
        if not curl:
            return _err("curl not found.")
        start = cls.start()
        if not start["ok"]:
            return start
        argv = [curl, "-sS", "-i", "--max-time", str(timeout),
                "--socks5-hostname", config.GOJA_SOCKS, "-X", method]
        if cls.CA.exists():
            argv += ["--cacert", str(cls.CA)]
        else:
            argv += ["-k"]
        for k, v in (headers or {}).items():
            argv += ["-H", f"{k}: {v}"]
        if body:
            argv += ["--data-raw", body]
        argv.append(url)
        try:
            r = subprocess.run(argv, capture_output=True, timeout=timeout + 5)
        except subprocess.SubprocessError as e:
            return _err(f"Goja request failed: {e}")
        out = r.stdout.decode("utf-8", "replace")
        status_line = next((ln.strip() for ln in out.splitlines()
                            if ln.startswith("HTTP/")), out.splitlines()[0] if out else "")
        flow_path = None
        if workspace is not None:
            flow_path = _save_flow(workspace, method, url, headers, body, out)
        return _ok(f"{status_line} via spoofed JA3 ({method} {url})",
                   {"status_line": status_line, "raw": out[:20000],
                    "flow": str(flow_path) if flow_path else None})


def _save_flow(ws: Workspace, method: str, url: str, headers, body, response: str) -> Path:
    ws.flows_dir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time() * 1000)
    p = ws.flows_dir / f"flow-{ts}.http"
    hdr = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    p.write_text(
        f"### REQUEST\n{method} {url}\n{hdr}\n\n{body or ''}\n\n"
        f"### RESPONSE\n{response[:60000]}\n", encoding="utf-8")
    return p


def proxy_flows(workspace: Workspace, *, query: str = "", limit: int = 20) -> dict:
    """Burp-like view: list/grep captured request/response flows (R18)."""
    if not workspace.flows_dir.exists():
        return _ok("No flows captured yet.", [])
    flows = sorted(workspace.flows_dir.glob("flow-*.http"), reverse=True)
    rows = []
    for f in flows:
        text = f.read_text(errors="replace")
        if query and query.lower() not in text.lower():
            continue
        first = text.splitlines()[1] if len(text.splitlines()) > 1 else f.name
        rows.append({"file": str(f), "summary": first})
        if len(rows) >= limit:
            break
    return _ok(f"{len(rows)} flow(s).", rows)


# --------------------------------------------------------------------------
# httpx (ProjectDiscovery) (R19)
# --------------------------------------------------------------------------


def ensure_httpx() -> Optional[str]:
    path = config.find_binary("httpx")
    if path:
        return path
    # Try a Go install first (if go is present), else download a release binary.
    go = config.find_binary("go")
    if go:
        try:
            subprocess.run([go, "install",
                            "github.com/projectdiscovery/httpx/cmd/httpx@latest"],
                           timeout=600, check=True,
                           env={**os.environ, "GOBIN": "/root/go/bin"})
        except (subprocess.SubprocessError, OSError):
            pass
        path = config.find_binary("httpx")
        if path:
            return path
    return _download_httpx_release()


def _download_httpx_release() -> Optional[str]:
    try:
        with urllib.request.urlopen(
                "https://api.github.com/repos/projectdiscovery/httpx/releases/latest",
                timeout=20) as r:
            rel = json.loads(r.read().decode())
        asset = next((a for a in rel.get("assets", [])
                      if "linux_amd64.zip" in a.get("name", "")), None)
        if not asset:
            return None
        import io
        import zipfile
        with urllib.request.urlopen(asset["browser_download_url"], timeout=120) as r:
            blob = r.read()
        dest_dir = Path("/usr/local/bin")
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            z.extract("httpx", path=str(dest_dir))
        dest = dest_dir / "httpx"
        os.chmod(dest, 0o755)
        return str(dest)
    except Exception:
        return None


def httpx_probe(targets: str, *, extra_args: str = "") -> dict:
    binp = ensure_httpx()
    if not binp:
        return _err("httpx unavailable and auto-install failed; use curl/native tools.")
    argv = [binp, "-silent", "-status-code", "-title", "-tech-detect", "-no-color"]
    if extra_args:
        argv += extra_args.split()
    try:
        r = subprocess.run(argv, input=targets.encode(), capture_output=True, timeout=180)
    except subprocess.SubprocessError as e:
        return _err(f"httpx failed: {e}")
    return _ok("httpx probe complete.", {"output": r.stdout.decode("utf-8", "replace")[:20000]})


# --------------------------------------------------------------------------
# Headless browser through the proxy (R18)
# --------------------------------------------------------------------------


def browse(url: str, *, workspace: Optional[Workspace] = None, timeout: int = 45) -> dict:
    chrome = config.find_binary("chromium") or config.find_binary("chromium-browser") \
        or config.find_binary("google-chrome")
    if not chrome:
        return _err("No Chromium found. Install with: apt-get install -y chromium "
                    "(or use httpx/curl + JS source reads instead).")
    Goja.start()
    out_dir = (workspace.scratch_dir if workspace else config.RUNTIME_DIR / "browse")
    out_dir.mkdir(parents=True, exist_ok=True)
    dump = out_dir / f"page-{int(time.time())}.html"
    argv = [chrome, "--headless=new", "--no-sandbox", "--disable-gpu",
            f"--proxy-server=socks5://{config.GOJA_SOCKS}",
            "--ignore-certificate-errors", "--dump-dom", url]
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout)
    except subprocess.SubprocessError as e:
        return _err(f"browse failed: {e}")
    html = r.stdout.decode("utf-8", "replace")
    dump.write_text(html[:2_000_000], encoding="utf-8")
    return _ok(f"Fetched {url} ({len(html)} bytes DOM) → {dump}",
               {"html_path": str(dump), "bytes": len(html)})


# --------------------------------------------------------------------------
# Install anything (R20)
# --------------------------------------------------------------------------


def install_tool(spec: str, *, manager: str = "auto", timeout: int = 900) -> dict:
    """Install a package/tool via the appropriate manager. The worker can also
    just use Bash directly; this is a convenience dispatcher with sane defaults."""
    spec = spec.strip()
    plans = {
        "apt": ["apt-get", "install", "-y", spec],
        "pip": ["pip3", "install", "--break-system-packages", spec],
        "npm": ["npm", "install", "-g", spec],
        "cargo": ["cargo", "install", spec],
        "go": ["go", "install", spec],
    }
    if manager == "auto":
        order = ["apt", "pip", "npm", "cargo", "go"]
    else:
        order = [manager]
    tried = []
    for mgr in order:
        argv = plans.get(mgr)
        if not argv or not config.find_binary(argv[0]):
            continue
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
        if mgr == "apt":
            try:
                subprocess.run(["apt-get", "update"], timeout=300, env=env,
                               capture_output=True)
            except subprocess.SubprocessError:
                pass
        try:
            r = subprocess.run(argv, timeout=timeout, env=env, capture_output=True)
            tried.append(f"{mgr}: rc={r.returncode}")
            if r.returncode == 0:
                return _ok(f"Installed '{spec}' via {mgr}.", {"manager": mgr})
        except subprocess.SubprocessError as e:
            tried.append(f"{mgr}: {e}")
    return _err(f"Could not install '{spec}'. Tried: {', '.join(tried) or 'no managers available'}.")


# --------------------------------------------------------------------------
# Research (R32)
# --------------------------------------------------------------------------


def research(url: str, *, timeout: int = 30) -> dict:
    """Fetch a URL's text for research. (The worker also has native WebSearch/
    WebFetch; this is a stdlib fallback that works inside the MCP/CLI.)"""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Krypton-Research/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read(2_000_000).decode("utf-8", "replace")
        return _ok(f"Fetched {url} ({len(data)} bytes).", {"text": data[:40000]})
    except Exception as e:
        return _err(f"research fetch failed: {e}")
