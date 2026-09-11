"""Scoped, observable tools shared by Grypton's MCP server and CLI."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import subprocess
import time
from typing import Iterable, Optional
from urllib.parse import urlsplit
import urllib.request
import zipfile

from . import config
from .workspace import Workspace

MAX_RESPONSE_BYTES = 2_000_000
MAX_INLINE_RESPONSE_CHARS = 12_000


def _ok(summary: str, data=None) -> dict:
    return {"ok": True, "summary": summary, "data": data}


def _err(summary: str, data=None) -> dict:
    return {"ok": False, "summary": summary, "data": data}


def _port_open(hostport: str, timeout: float = 0.4) -> bool:
    host, _, port = hostport.rpartition(":")
    try:
        with socket.create_connection((host or "127.0.0.1", int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def _host_from_rule(rule: str) -> str:
    value = rule.strip().lower()
    if "://" in value:
        return (urlsplit(value).hostname or "").rstrip(".")
    value = value.split("/", 1)[0]
    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")]
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value.rstrip(".")


def _host_matches(host: str, rule: str) -> bool:
    host = host.lower().rstrip(".")
    raw = rule.strip().lower()
    candidate = _host_from_rule(raw)
    if raw.startswith("*.") or candidate.startswith("*."):
        suffix = candidate.removeprefix("*.")
        return host.endswith("." + suffix) and host != suffix
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return bool(candidate) and host == candidate


def _rule_port(rule: str) -> Optional[int]:
    """Return a rule's bounded port; host/domain/CIDR rules are port-wide."""
    raw = rule.strip().lower()
    if "://" in raw:
        try:
            parsed = urlsplit(raw)
            return parsed.port or ({"http": 80, "https": 443}.get(parsed.scheme))
        except ValueError:
            return None
    authority = raw.split("/", 1)[0]
    if authority.startswith("[") and "]" in authority:
        suffix = authority[authority.index("]") + 1:]
        return int(suffix[1:]) if suffix.startswith(":") and suffix[1:].isdigit() else None
    if authority.count(":") == 1:
        _, value = authority.rsplit(":", 1)
        return int(value) if value.isdigit() else None
    return None


def _endpoint_matches(host: str, port: int, rule: str) -> bool:
    rule_port = _rule_port(rule)
    return _host_matches(host, rule) and (rule_port is None or rule_port == port)


def scope_rules(workspace: Workspace) -> tuple[list[str], list[str]]:
    constraints = workspace.load_constraints()
    allowed, denied = list(constraints.in_scope), list(constraints.out_of_scope)
    if not allowed and workspace.exists():
        allowed.append(workspace.load_meta().target)
    return allowed, denied


def check_host_scope(workspace: Workspace, host: str) -> tuple[bool, str]:
    allowed, denied = scope_rules(workspace)
    if any(_host_matches(host, rule) for rule in denied):
        return False, f"{host} matches an out-of-scope rule"
    if not allowed:
        return False, "no in-scope host is recorded"
    if not any(_host_matches(host, rule) for rule in allowed):
        return False, f"{host} does not match the in-scope rules"
    return True, "in scope"


def check_url_scope(workspace: Workspace, url: str) -> tuple[bool, str]:
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False, "URL must use http or https and include a hostname"
        if parsed.username or parsed.password:
            return False, "credentials embedded in URLs are not accepted"
        port = parsed.port or (80 if parsed.scheme == "http" else 443)
    except ValueError:
        return False, "invalid URL"
    allowed, denied = scope_rules(workspace)
    if any(_endpoint_matches(parsed.hostname, port, rule) for rule in denied):
        return False, f"{parsed.hostname}:{port} matches an out-of-scope rule"
    if not allowed:
        return False, "no in-scope endpoint is recorded"
    if not any(_endpoint_matches(parsed.hostname, port, rule) for rule in allowed):
        matching_hosts = [rule for rule in allowed if _host_matches(parsed.hostname, rule)]
        if matching_hosts:
            bounded = sorted({p for rule in matching_hosts if (p := _rule_port(rule)) is not None})
            return False, f"port {port} is outside the recorded port scope {bounded}"
        return False, f"{parsed.hostname} does not match the in-scope rules"
    return True, "in scope"


def check_port_scope(workspace: Workspace, host: str, port: int) -> tuple[bool, str]:
    """Scope check for raw TCP/TLS actions, including URL-bound ports."""
    allowed, denied = scope_rules(workspace)
    if any(_endpoint_matches(host, port, rule) for rule in denied):
        return False, f"{host}:{port} matches an out-of-scope rule"
    if not allowed:
        return False, "no in-scope endpoint is recorded"
    if not any(_endpoint_matches(host, port, rule) for rule in allowed):
        if any(_host_matches(host, rule) for rule in allowed):
            return False, f"{host}:{port} is outside the recorded port scope"
        return False, f"{host} does not match the in-scope rules"
    return True, "in scope"


def _scope_error(workspace: Workspace, url: str) -> Optional[dict]:
    allowed, reason = check_url_scope(workspace, url)
    return None if allowed else _err(f"Scope blocked {url}: {reason}.")


def _safe_headers(headers: Optional[dict]) -> dict[str, str]:
    output = {}
    for key, value in (headers or {}).items():
        key, value = str(key).strip(), str(value).replace("\r", "").replace("\n", "")
        if key and re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
            output[key] = value
    return output


def _save_flow(workspace: Workspace, method: str, url: str, headers: Optional[dict],
               body: Optional[str], response: str, *, transport: str,
               returncode: int, stderr: str = "") -> Path:
    workspace.flows_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = workspace.flows_dir / f"flow-{time.time_ns()}.http"
    header_text = "\n".join(f"{k}: {v}" for k, v in _safe_headers(headers).items())
    metadata = json.dumps({"captured_at": time.time(), "transport": transport,
                           "returncode": returncode, "stderr": stderr[:4000]},
                          ensure_ascii=False)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(f"### GRYPTON FLOW {metadata}\n### REQUEST\n{method.upper()} {url}\n"
                     f"{header_text}\n\n{body or ''}\n\n### RESPONSE\n"
                     f"{response[:MAX_RESPONSE_BYTES]}\n")
    return path


def http_request(workspace: Workspace, url: str, *, method: str = "GET",
                 headers: Optional[dict] = None, body: Optional[str] = None,
                 timeout: int = 30, follow_redirects: bool = False,
                 insecure: bool = False, transport: str = "curl", proxy: str = "") -> dict:
    blocked = _scope_error(workspace, url)
    if blocked:
        return blocked
    if follow_redirects:
        return _err(
            "Automatic redirect following is disabled so an off-scope Location cannot be "
            "contacted. Capture this response, scope-check its Location, then request that URL explicitly."
        )
    curl = config.find_binary("curl")
    if not curl:
        return _err("curl is not installed.")
    timeout = max(1, min(int(timeout), 120))
    method = method.strip().upper() or "GET"
    if not re.fullmatch(r"[A-Z]{1,20}", method):
        return _err("Invalid HTTP method.")
    argv = [curl, "--silent", "--show-error", "--include", "--compressed",
            "--max-time", str(timeout), "--connect-timeout", str(min(timeout, 15))]
    # `--request HEAD` only changes the verb; curl still expects a response
    # body and reports error 18 when a conforming server sends none. `--head`
    # selects curl's actual header-only transfer mode.
    if method == "HEAD":
        argv.append("--head")
    else:
        argv += ["--request", method]
    if insecure:
        argv.append("--insecure")
    if proxy:
        argv += ["--proxy", proxy]
    clean_headers = _safe_headers(headers)
    for key, value in clean_headers.items():
        argv += ["--header", f"{key}: {value}"]
    if body is not None:
        argv += ["--data-binary", body]
    argv += ["--", url]
    started = time.time()
    # Write curl output to a real file descriptor. Through some SOCKS/TLS
    # fingerprint proxies curl can report error 23 while writing decoded
    # Brotli data to a subprocess pipe; a regular file avoids that transport
    # failure and still lets us bound what enters the evidence flow/model.
    workspace.scratch_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    capture_path = workspace.scratch_dir / f".curl-{time.time_ns()}.capture"
    fd = os.open(capture_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as capture:
            result = subprocess.run(argv, stdout=capture, stderr=subprocess.PIPE,
                                    timeout=timeout + 5)
        response_bytes = capture_path.stat().st_size
        with capture_path.open("rb") as capture:
            raw_output = capture.read(MAX_RESPONSE_BYTES)
    except subprocess.TimeoutExpired:
        return _err(f"HTTP request timed out after {timeout}s.")
    finally:
        capture_path.unlink(missing_ok=True)
    output = raw_output.decode("utf-8", "replace")
    stderr = result.stderr[:8000].decode("utf-8", "replace")
    flow = _save_flow(workspace, method, url, clean_headers, body, output,
                      transport=transport, returncode=result.returncode, stderr=stderr)
    status = next((line.strip() for line in output.splitlines() if line.startswith("HTTP/")),
                  "no HTTP status")
    data = {"status_line": status, "response": output[:MAX_INLINE_RESPONSE_CHARS],
            "response_truncated": (len(output) > MAX_INLINE_RESPONSE_CHARS or
                                   response_bytes > MAX_RESPONSE_BYTES),
            "response_bytes": response_bytes, "stderr": stderr,
            "returncode": result.returncode, "duration_s": round(time.time() - started, 3),
            "flow": str(flow), "transport": transport}
    if result.returncode:
        return _err(f"curl exited {result.returncode}; capture saved to {flow}.", data)
    return _ok(f"{status} · {method} {url} · captured {flow.name}", data)


class Goja:
    BIN = config.GOJA_DIR / "bin" / "goja-proxy"
    CA = config.GOJA_DIR / "certs" / "certs" / "goja-root-ca.pem"
    PID = config.RUNTIME_DIR / "goja.pid"

    @classmethod
    def running(cls) -> bool:
        return _port_open(config.GOJA_SOCKS)

    @classmethod
    def _managed_config(cls) -> Path:
        output = config.RUNTIME_DIR / "goja-config.json"
        config.RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        try:
            raw = (config.GOJA_DIR / "config.json").read_bytes()
            value = json.loads(raw[:raw.rfind(b"}") + 1])
            if isinstance(value.get("dashboard"), dict):
                value["dashboard"]["enabled"] = False
        except Exception:
            value = {"fingerprintPreset": "chrome-139-desktop",
                     "dashboard": {"enabled": False}, "filters": [], "replacements": [],
                     "upstreamProxy": "", "reuseConnections": True, "requestTimeoutSec": 30,
                     "certificateAuthority": {"enabled": True, "persist": True, "directory": "certs"}}
        output.write_text(json.dumps(value, indent=2), encoding="utf-8")
        return output

    @classmethod
    def status(cls) -> dict:
        try:
            pid = int(cls.PID.read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            pid = None
        running = cls.running()
        return _ok("Goja is running." if running else "Goja is stopped.",
                   {"running": running, "socks": config.GOJA_SOCKS, "managed_pid": pid,
                    "binary": str(cls.BIN), "ca_exists": cls.CA.is_file()})

    @classmethod
    def start(cls, wait_s: float = 10.0) -> dict:
        if cls.running():
            return _ok(f"Goja is listening at SOCKS5 {config.GOJA_SOCKS}.", cls.status()["data"])
        if not cls.BIN.is_file():
            return _err(f"Goja binary is missing at {cls.BIN}.")
        config.LOG_DIR.mkdir(parents=True, exist_ok=True)
        log = config.LOG_DIR / "goja.log"
        try:
            with log.open("ab") as stream:
                process = subprocess.Popen([str(cls.BIN), "-config", str(cls._managed_config())],
                                           cwd=str(config.GOJA_DIR), stdout=stream, stderr=stream,
                                           stdin=subprocess.DEVNULL, start_new_session=True)
            cls.PID.write_text(str(process.pid), encoding="ascii")
        except OSError as exc:
            return _err(f"Could not start Goja: {exc}")
        deadline = time.time() + max(1, min(wait_s, 30))
        while time.time() < deadline:
            if cls.running():
                return _ok(f"Goja started at SOCKS5 {config.GOJA_SOCKS}.", cls.status()["data"])
            if process.poll() is not None:
                break
            time.sleep(0.2)
        return _err(f"Goja did not become ready. Inspect {log}.", cls.status()["data"])

    @classmethod
    def stop(cls) -> dict:
        try:
            pid = int(cls.PID.read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            return _err("No Grypton-managed Goja process is recorded.", cls.status()["data"])
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            cls.PID.unlink(missing_ok=True)
            return _ok("The recorded Goja process had already exited.")
        deadline = time.time() + 5
        while time.time() < deadline and cls.running():
            time.sleep(0.1)
        if cls.running():
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        cls.PID.unlink(missing_ok=True)
        return _ok("Stopped the Grypton-managed Goja process.", cls.status()["data"])

    @classmethod
    def request(cls, workspace: Workspace, url: str, **kwargs) -> dict:
        started = cls.start()
        if not started["ok"]:
            return started
        return http_request(workspace, url, transport="goja",
                            proxy=f"socks5h://{config.GOJA_SOCKS}",
                            insecure=not cls.CA.is_file(), **kwargs)


def proxy_flows(workspace: Workspace, *, query: str = "", limit: int = 20) -> dict:
    rows = []
    for path in sorted(workspace.flows_dir.glob("flow-*.http"), reverse=True):
        text = path.read_text(encoding="utf-8", errors="replace")
        if query and query.lower() not in text.lower():
            continue
        request = next((line for line in text.splitlines() if re.match(r"^[A-Z]+ https?://", line)), path.name)
        status = next((line for line in text.splitlines() if line.startswith("HTTP/")), "")
        rows.append({"id": path.stem, "file": str(path), "request": request, "status": status})
        if len(rows) >= max(1, min(int(limit), 200)):
            break
    return _ok(f"{len(rows)} captured flow(s).", rows)


def _flow_path(workspace: Workspace, flow_id: str) -> Optional[Path]:
    name = Path(flow_id).name
    name = name if name.endswith(".http") else name + ".http"
    if not name.startswith("flow-"):
        return None
    candidate = (workspace.flows_dir / name).resolve()
    try:
        candidate.relative_to(workspace.flows_dir.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def flow_read(workspace: Workspace, flow_id: str, *, max_chars: int = 100_000) -> dict:
    path = _flow_path(workspace, flow_id)
    if path is None:
        return _err(f"Unknown flow {flow_id!r}.")
    value = path.read_text(encoding="utf-8", errors="replace")
    return _ok(f"Read {path.name} ({len(value)} characters).",
               {"id": path.stem, "file": str(path),
                "text": value[:max(1000, min(int(max_chars), 500_000))]})


def flow_replay(workspace: Workspace, flow_id: str, *, url: str = "", method: str = "",
                headers: Optional[dict] = None, body: Optional[str] = None) -> dict:
    read = flow_read(workspace, flow_id, max_chars=500_000)
    if not read["ok"]:
        return read
    split = read["data"]["text"].split("### RESPONSE", 1)[0].split("### REQUEST\n", 1)
    if len(split) != 2:
        return _err("The capture does not contain a replayable request.")
    lines = split[1].splitlines()
    match = re.match(r"^([A-Z]+)\s+(https?://\S+)$", lines[0] if lines else "")
    if not match:
        return _err("The capture request line is invalid.")
    old_method, old_url = match.groups()
    old_headers, index = {}, 1
    while index < len(lines) and lines[index].strip():
        if ":" in lines[index]:
            key, value = lines[index].split(":", 1)
            if key.lower() not in {"host", "content-length"}:
                old_headers[key.strip()] = value.strip()
        index += 1
    old_headers.update(_safe_headers(headers))
    old_body = "\n".join(lines[index + 1:]).strip() or None
    return http_request(workspace, url or old_url, method=method or old_method,
                        headers=old_headers, body=body if body is not None else old_body,
                        transport=f"replay:{Path(flow_id).stem}")


def httpx_probe(workspace: Workspace, targets: str) -> dict:
    binary = config.find_binary("httpx")
    if not binary:
        return _err("ProjectDiscovery httpx is not installed.")
    values = [value for value in re.split(r"[\s,]+", targets.strip()) if value]
    if not values or len(values) > 500:
        return _err("Supply between 1 and 500 scoped hosts or URLs.")
    for value in values:
        if "://" in value:
            allowed, reason = check_url_scope(workspace, value)
        else:
            try:
                parsed = urlsplit("//" + value)
                host = parsed.hostname or ""
                allowed, reason = (check_port_scope(workspace, host, parsed.port)
                                   if parsed.port is not None else check_host_scope(workspace, host))
            except ValueError:
                allowed, reason = False, "invalid host or port"
        if not allowed:
            return _err(f"Scope blocked {value}: {reason}.")
    try:
        result = subprocess.run([binary, "-silent", "-status-code", "-title", "-tech-detect", "-no-color"],
                                input=("\n".join(values) + "\n").encode(),
                                capture_output=True, timeout=180)
    except subprocess.SubprocessError as exc:
        return _err(f"httpx failed: {exc}")
    return _ok(f"httpx completed for {len(values)} scoped target(s).",
               {"output": result.stdout.decode("utf-8", "replace")[:200_000]})


def browse(workspace: Workspace, url: str, *, timeout: int = 45) -> dict:
    blocked = _scope_error(workspace, url)
    if blocked:
        return blocked
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return _err("Python Playwright is not installed; use install_tool or curl/httpx.")
    executable = next((str(path) for path in (
        Path("/opt/google/chrome/chrome"),
        Path(config.find_binary("google-chrome") or ""),
        Path(config.find_binary("chromium") or ""),
    ) if path.is_file()), "")
    if not executable:
        return _err("No Playwright-compatible Chromium or Chrome executable is installed.")
    output = workspace.scratch_dir / f"page-{time.time_ns()}.html"
    denied_requests: list[str] = []
    console: list[dict] = []
    status = 0
    final_url = url
    html = b""
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                executable_path=executable,
                ignore_default_args=["--enable-unsafe-swiftshader"],
                args=["--no-sandbox", "--disable-setuid-sandbox",
                      "--disable-seccomp-filter-sandbox", "--no-zygote", "--single-process",
                      "--disable-gpu", "--disable-software-rasterizer",
                      "--disable-gpu-compositing", "--disable-dev-shm-usage",
                      "--disable-background-networking"],
            )
            context = browser.new_context(ignore_https_errors=True)

            def scope_route(route) -> None:
                request_url = route.request.url
                scheme = urlsplit(request_url).scheme.lower()
                if scheme in {"about", "blob", "data"}:
                    route.continue_()
                    return
                allowed, _ = check_url_scope(workspace, request_url)
                if allowed:
                    route.continue_()
                else:
                    if len(denied_requests) < 100:
                        denied_requests.append(request_url)
                    route.abort("blockedbyclient")

            context.route("**/*", scope_route)
            page = context.new_page()
            page.on("console", lambda message: console.append({
                "type": message.type, "text": message.text[:2000]
            }) if len(console) < 100 else None)
            response = page.goto(url, wait_until="domcontentloaded",
                                 timeout=max(5, min(int(timeout), 120)) * 1000)
            page.wait_for_timeout(250)
            status = response.status if response else 0
            final_url = page.url
            html = page.content().encode("utf-8")[:MAX_RESPONSE_BYTES]
            context.close()
            browser.close()
    except Exception as exc:
        return _err(f"Headless browser failed: {exc}",
                    {"blocked_requests": denied_requests, "console": console})
    output.write_bytes(html)
    rendered = f"HTTP {status}\nFinal-URL: {final_url}\n\n" + html.decode("utf-8", "replace")
    flow = _save_flow(workspace, "GET", url, {}, None, rendered,
                      transport="playwright-chromium", returncode=0)
    data = {"html_path": str(output), "flow": str(flow), "status": status,
            "final_url": final_url, "blocked_requests": denied_requests, "console": console}
    if not html:
        return _err(f"Headless browser returned an empty DOM; capture saved to {flow.name}.", data)
    return _ok(f"Chromium saved {len(html)} bytes to {output.name} and {flow.name}.", data)


def dns_lookup(workspace: Workspace, host: str) -> dict:
    allowed, reason = check_host_scope(workspace, host)
    if not allowed:
        return _err(f"Scope blocked {host}: {reason}.")
    try:
        rows = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
    except OSError as exc:
        return _err(f"DNS lookup failed: {exc}")
    return _ok(f"Resolved {host} to {len(rows)} address(es).", rows)


def tls_certificate(workspace: Workspace, host: str, *, port: int = 443) -> dict:
    port = max(1, min(int(port), 65535))
    allowed, reason = check_port_scope(workspace, host, port)
    if not allowed:
        return _err(f"Scope blocked {host}:{port}: {reason}.")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=host) as wrapped:
                cert, cipher = wrapped.getpeercert(), wrapped.cipher()
    except OSError as exc:
        return _err(f"TLS inspection failed: {exc}")
    return _ok(f"Read the TLS certificate from {host}:{port}.",
               {"certificate": cert, "cipher": cipher})


def port_scan(workspace: Workspace, host: str, ports: Iterable[int], *, timeout_ms: int = 350) -> dict:
    try:
        normalized = sorted({int(port) for port in ports if 0 < int(port) <= 65535})
    except (TypeError, ValueError):
        return _err("Ports must be integers.")
    if not normalized or len(normalized) > 128:
        return _err("Supply 1 to 128 TCP ports.")
    for port in normalized:
        allowed, reason = check_port_scope(workspace, host, port)
        if not allowed:
            return _err(f"Scope blocked {host}:{port}: {reason}.")
    opened = []
    for port in normalized:
        try:
            with socket.create_connection((host, port), timeout=max(0.05, min(timeout_ms / 1000, 2))):
                opened.append(port)
        except OSError:
            pass
    return _ok(f"Checked {len(normalized)} TCP ports on {host}; {len(opened)} open.",
               {"open": opened})


def tcp_exchange(workspace: Workspace, host: str, port: int, payload: str, *, timeout: int = 15) -> dict:
    """Exchange one newline-delimited frame with a scoped TCP service.

    It intentionally keeps the payload as text instead of parsing JSON.  That
    makes protocol parser differentials observable while still enforcing the
    recorded host and port scope and retaining a durable flow capture.
    """
    try:
        port = int(port)
    except (TypeError, ValueError):
        return _err("TCP port must be an integer.")
    allowed, reason = check_port_scope(workspace, host, port)
    if not allowed:
        return _err(f"Scope blocked {host}:{port}: {reason}.")
    if not isinstance(payload, str) or not payload.strip() or "\x00" in payload:
        return _err("TCP payload must be one non-empty text frame.")
    if len(payload.encode("utf-8")) > 16_000:
        return _err("TCP payload exceeds the 16 KB frame limit.")
    timeout = max(1, min(int(timeout), 60))
    banner = response = ""
    status = 0
    error = ""
    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.settimeout(timeout)
            reader = conn.makefile("rb")
            banner = reader.readline(16_385).decode("utf-8", "replace").rstrip("\r\n")
            conn.sendall(payload.encode("utf-8") + b"\n")
            response = reader.readline(16_385).decode("utf-8", "replace").rstrip("\r\n")
            if not response:
                status = 1
                error = "service closed without a response"
    except OSError as exc:
        status, error = 1, str(exc)
    endpoint = f"tcp://{host}:{port}"
    capture = f"BANNER\n{banner}\n\nRESPONSE\n{response}"
    flow = _save_flow(workspace, "TCP", endpoint, {}, payload, capture,
                      transport="scoped-tcp", returncode=status, stderr=error)
    data = {"banner": banner, "response": response, "flow": str(flow)}
    if status:
        return _err(f"TCP exchange with {host}:{port} failed: {error}; capture saved to {flow.name}.", data)
    return _ok(f"TCP exchange with {host}:{port} captured in {flow.name}.", data)


def _loot_file(workspace: Workspace, artifact: str) -> Optional[Path]:
    name = Path(str(artifact)).name
    if not name or name != str(artifact) or name in {".", ".."}:
        return None
    candidate = (workspace.loot_dir / name).resolve()
    try:
        candidate.relative_to(workspace.loot_dir.resolve())
    except ValueError:
        return None
    return candidate


def artifact_download(workspace: Workspace, url: str, filename: str, *, timeout: int = 60) -> dict:
    """Download a scoped binary artifact into the engagement loot directory."""
    blocked = _scope_error(workspace, url)
    if blocked:
        return blocked
    destination = _loot_file(workspace, filename)
    if destination is None:
        return _err("Artifact filename must be a single safe basename.")
    curl = config.find_binary("curl")
    if not curl:
        return _err("curl is not installed.")
    timeout = max(1, min(int(timeout), 120))
    workspace.loot_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = workspace.loot_dir / f".{destination.name}.{time.time_ns()}.part"
    headers = workspace.scratch_dir / f"download-{time.time_ns()}.headers"
    try:
        result = subprocess.run(
            [curl, "--silent", "--show-error", "--fail", "--max-time", str(timeout),
             "--connect-timeout", str(min(timeout, 15)), "--dump-header", str(headers),
             "--output", str(temporary), url],
            capture_output=True, timeout=timeout + 5,
        )
        if result.returncode:
            return _err("Artifact download failed: " + result.stderr.decode("utf-8", "replace")[-2000:])
        os.replace(temporary, destination)
        digest = hashlib.sha256(destination.read_bytes()).hexdigest()
        response_headers = headers.read_text(encoding="utf-8", errors="replace") if headers.exists() else ""
        flow = _save_flow(workspace, "GET", url, {}, None,
                          response_headers + f"\n[Binary saved: {destination.name}; sha256={digest}]",
                          transport="artifact-download", returncode=0)
        return _ok(f"Saved {destination.name} ({destination.stat().st_size} bytes) and {flow.name}.",
                   {"path": str(destination), "sha256": digest, "flow": str(flow),
                    "bytes": destination.stat().st_size})
    except (OSError, subprocess.SubprocessError) as exc:
        return _err(f"Artifact download failed: {exc}")
    finally:
        temporary.unlink(missing_ok=True)
        headers.unlink(missing_ok=True)


def apk_inspect(workspace: Workspace, artifact: str) -> dict:
    """Inspect APK metadata, components, certificate status, and asset names.

    This is binary assessment only.  It never decompiles application source.
    """
    path = _loot_file(workspace, artifact)
    if path is None or not path.is_file():
        return _err("APK artifact is not present in this engagement's loot directory.")
    if not zipfile.is_zipfile(path):
        return _err("Artifact is not a ZIP/APK container.")
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            assets = [{"name": name, "bytes": archive.getinfo(name).file_size}
                      for name in names if name.startswith("assets/") and not name.endswith("/")]
    except (OSError, zipfile.BadZipFile) as exc:
        return _err(f"Unable to inspect APK: {exc}")
    aapt = config.find_binary("aapt")
    manifest = ""
    badging = ""
    signature = {"verified": False, "detail": "apksigner unavailable"}
    if aapt:
        for args, slot in (([aapt, "dump", "badging", str(path)], "badging"),
                           ([aapt, "dump", "xmltree", str(path), "AndroidManifest.xml"], "manifest")):
            try:
                result = subprocess.run(args, capture_output=True, timeout=20)
                value = result.stdout.decode("utf-8", "replace")[:60_000]
                if slot == "badging":
                    badging = value
                else:
                    manifest = value
            except (OSError, subprocess.SubprocessError):
                pass
    apksigner = config.find_binary("apksigner")
    if apksigner:
        try:
            result = subprocess.run([apksigner, "verify", "--verbose", str(path)],
                                    capture_output=True, timeout=20)
            detail = (result.stdout + result.stderr).decode("utf-8", "replace")[-4000:]
            signature = {"verified": result.returncode == 0, "detail": detail}
        except (OSError, subprocess.SubprocessError) as exc:
            signature = {"verified": False, "detail": str(exc)}
    return _ok(f"Inspected {path.name}: {len(names)} entries and {len(assets)} assets.", {
        "path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "entries": len(names), "assets": assets, "has_classes_dex": "classes.dex" in names,
        "badging": badging, "manifest": manifest, "signature": signature,
    })


def apk_extract_asset(workspace: Workspace, artifact: str, asset: str) -> dict:
    """Extract one named APK asset to loot for local binary analysis."""
    path = _loot_file(workspace, artifact)
    safe_asset = str(asset).replace("\\", "/").lstrip("/")
    if path is None or not path.is_file():
        return _err("APK artifact is not present in this engagement's loot directory.")
    if not safe_asset.startswith("assets/") or ".." in safe_asset.split("/"):
        return _err("Asset must be a safe APK path beneath assets/.")
    try:
        with zipfile.ZipFile(path) as archive:
            data = archive.read(safe_asset)
    except (KeyError, OSError, zipfile.BadZipFile) as exc:
        return _err(f"Unable to extract APK asset: {exc}")
    destination = workspace.loot_dir / f"{path.stem}-{Path(safe_asset).name}"
    destination.write_bytes(data)
    return _ok(f"Extracted {safe_asset} to {destination.name} ({len(data)} bytes).", {
        "path": str(destination), "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data), "base64": base64.b64encode(data).decode("ascii")[:32_000],
    })


def subdomain_enum(workspace: Workspace, domain: str, *, timeout: int = 180) -> dict:
    allowed, reason = check_host_scope(workspace, domain)
    if not allowed:
        return _err(f"Scope blocked {domain}: {reason}.")
    binary = config.find_binary("subfinder")
    if not binary:
        return _err("subfinder is not installed.")
    try:
        result = subprocess.run([binary, "-silent", "-d", domain, "-timeout", "30"],
                                capture_output=True, timeout=max(30, min(int(timeout), 300)))
    except subprocess.SubprocessError as exc:
        return _err(f"subfinder failed: {exc}")
    names = sorted({line.strip() for line in result.stdout.decode(errors="replace").splitlines()
                    if line.strip()})
    return _ok(f"subfinder returned {len(names)} name(s) for {domain}.", names[:5000])


def install_tool(spec: str, *, manager: str = "auto", timeout: int = 900) -> dict:
    spec = spec.strip()
    if not spec or any(char in spec for char in "\r\n\x00"):
        return _err("A single package specification is required.")
    manager = "apt" if manager == "auto" else manager
    plans = {"apt": ["apt-get", "install", "-y", spec],
             "pip": ["pip3", "install", "--break-system-packages", spec],
             "npm": ["npm", "install", "-g", spec],
             "cargo": ["cargo", "install", spec], "go": ["go", "install", spec]}
    argv = plans.get(manager)
    if not argv or not config.find_binary(argv[0]):
        return _err(f"Unsupported or unavailable package manager {manager!r}.")
    try:
        result = subprocess.run(argv, capture_output=True, timeout=max(30, min(int(timeout), 1800)),
                                env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"})
    except subprocess.SubprocessError as exc:
        return _err(f"Installation failed: {exc}")
    if result.returncode:
        return _err(f"{manager} exited {result.returncode}: " +
                    result.stderr.decode("utf-8", "replace")[-4000:])
    return _ok(f"Installed {spec!r} with {manager}.")


def research(url: str, *, timeout: int = 30) -> dict:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return _err("Research URL must use http or https.")
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "Grypton-Research/3.0"})
        with urllib.request.urlopen(request, timeout=max(1, min(int(timeout), 60))) as response:
            data = response.read(MAX_RESPONSE_BYTES).decode("utf-8", "replace")
        return _ok(f"Fetched {url} ({len(data)} characters).", {"text": data})
    except Exception as exc:
        return _err(f"Research fetch failed: {exc}")


def inventory() -> dict:
    binaries = ["curl", "httpx", "playwright", "google-chrome", "chromium", "subfinder",
                "nmap", "nuclei", "ffuf", "jq", "openssl", "python3", "node", "go", "cargo",
                "aapt", "apksigner", "keytool", "unzip", "strings"]
    return _ok("Tool inventory collected.",
               {"binaries": {name: config.find_binary(name) for name in binaries},
                "goja": Goja.status()["data"]})
