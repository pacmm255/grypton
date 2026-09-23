"""Scoped, observable tools shared by Grypton's MCP server and CLI."""
from __future__ import annotations

import base64
from contextlib import contextmanager
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from typing import Iterable, Optional
from urllib.parse import quote, quote_plus, unquote, urlencode, urljoin, urlsplit
import zipfile

from . import config, credentials
from .workspace import Workspace

MAX_RESPONSE_BYTES = 2_000_000
MAX_INLINE_RESPONSE_CHARS = 12_000

_SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
})
_SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|"
    r"x-api-key|x-auth-token|x-csrf-token|x-xsrf-token)\s*:\s*).*$"
)
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    ((?:["']?(?:password|passwd|secret|access[_-]?token|refresh[_-]?token|
       id[_-]?token|auth[_-]?token|session[_-]?token|api[_-]?key)["']?)
       \s*[:=]\s*)
    (?:"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^&\s,;}\]]+)
    """
)


def redact_sensitive_text(value: object, secret_values: Iterable[str] = ()) -> str:
    """Remove credentials, cookies, and login tokens from observable text."""
    text = str(value or "")
    for secret in sorted({str(item) for item in secret_values if str(item)},
                         key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    text = _SENSITIVE_HEADER_RE.sub(r"\1[REDACTED]", text)
    return _SENSITIVE_ASSIGNMENT_RE.sub(r"\1[REDACTED]", text)


def _redacted_headers(headers: Optional[dict],
                      secret_values: Iterable[str] = ()) -> dict[str, str]:
    output = {}
    for key, value in _safe_headers(headers).items():
        output[key] = (
            "[REDACTED]" if key.lower() in _SENSITIVE_HEADERS
            else redact_sensitive_text(value, secret_values)
        )
    return output


def _serialized_secret_variants(secret_values: Iterable[str]) -> tuple[str, ...]:
    """Return common transport encodings so captures cannot retain a secret."""
    output: set[str] = set()
    for item in secret_values:
        secret = str(item)
        if not secret:
            continue
        output.add(secret)
        for encoded in (quote(secret, safe=""), quote_plus(secret, safe="")):
            output.add(encoded)
            output.add(re.sub(
                r"%[0-9A-F]{2}", lambda match: match.group(0).lower(), encoded
            ))
        for ensure_ascii in (False, True):
            rendered = json.dumps(secret, ensure_ascii=ensure_ascii)
            output.add(rendered[1:-1])
    return tuple(sorted(output, key=len, reverse=True))


def _redacted_capture_value(value, secret_values: Iterable[str]):
    """Build a structurally separate, secret-free representation for a flow."""
    secrets = tuple(str(item) for item in secret_values if str(item))
    if isinstance(value, dict):
        return {
            redact_sensitive_text(key, secrets): _redacted_capture_value(child, secrets)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_redacted_capture_value(child, secrets) for child in value]
    if isinstance(value, tuple):
        return tuple(_redacted_capture_value(child, secrets) for child in value)
    if isinstance(value, str):
        return redact_sensitive_text(value, secrets)
    return value


def _login_capture_body(values: dict, username_field: str, password_field: str,
                        encoding: str, secret_values: Iterable[str]) -> str:
    capture_values = _redacted_capture_value(values, secret_values)
    capture_values[redact_sensitive_text(username_field, secret_values)] = (
        "__GRYPTON_REDACTED_USERNAME__"
    )
    capture_values[redact_sensitive_text(password_field, secret_values)] = (
        "__GRYPTON_REDACTED_PASSWORD__"
    )
    if encoding == "json":
        return json.dumps(capture_values, ensure_ascii=False, separators=(",", ":"))
    return urlencode(capture_values)


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
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        pass
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


def _host_related_to_rule(host: str, rule: str) -> bool:
    """Return whether a host is the same domain family as a recorded rule."""
    host = host.lower().rstrip(".")
    if _host_matches(host, rule):
        return True
    candidate = _host_from_rule(rule).removeprefix("*.")
    try:
        ipaddress.ip_address(host)
        ipaddress.ip_network(candidate, strict=False)
        return False
    except ValueError:
        pass
    if not candidate:
        return False
    if host.endswith("." + candidate) or candidate.endswith("." + host):
        return True

    def registrable_domain(value: str) -> str:
        labels = value.split(".")
        suffix_labels = 3 if (
            len(labels) >= 3 and len(labels[-1]) == 2
            and labels[-2] in {"ac", "co", "com", "edu", "gov", "net", "org"}
        ) else 2
        return ".".join(labels[-suffix_labels:]) if len(labels) >= suffix_labels else value

    return registrable_domain(host) == registrable_domain(candidate)


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


def _canonical_url_path(path: str) -> Optional[str]:
    """Return a conservative canonical path for scope comparisons.

    Clients and servers differ on when they decode escapes and collapse dot
    segments. Decode repeatedly, reject ambiguous backslash/control forms, and
    collapse dot segments before testing a scope prefix.
    """
    if not isinstance(path, str) or re.search(r"%(?![0-9A-Fa-f]{2})", path):
        return None
    decoded = path or "/"
    for _ in range(4):
        try:
            next_value = unquote(decoded, errors="strict")
        except (UnicodeDecodeError, ValueError):
            return None
        if next_value == decoded:
            break
        decoded = next_value
    if re.search(r"%[0-9A-Fa-f]{2}", decoded):
        return None
    if "\\" in decoded or any(ord(char) < 0x20 or ord(char) == 0x7f for char in decoded):
        return None
    if not decoded.startswith("/"):
        decoded = "/" + decoded
    segments: list[str] = []
    for segment in decoded.split("/"):
        if segment in {"", "."}:
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    return "/" + "/".join(segments)


def _looks_like_path_rule(rule: str) -> bool:
    raw = rule.strip()
    if raw.lower().startswith(("http://", "https://")):
        return True
    try:
        ipaddress.ip_network(raw, strict=False)
        return False
    except ValueError:
        return "/" in raw


def _url_rule(rule: str):
    """Parse HTTP(S) and scheme-less host/path scope rules."""
    raw = rule.strip()
    try:
        explicit_scheme = "://" in raw
        if not explicit_scheme and not _looks_like_path_rule(raw):
            return None
        parsed = urlsplit(raw if explicit_scheme else "//" + raw)
        scheme = parsed.scheme.lower()
        if (explicit_scheme and scheme not in {"http", "https"}) or not parsed.hostname:
            return None
        port = parsed.port
        if port is None and scheme:
            port = 80 if scheme == "http" else 443
        path = _canonical_url_path(parsed.path or "/")
    except ValueError:
        return None
    return None if path is None else (parsed, port, path)


def _path_is_within(path: str, prefix: str) -> bool:
    return prefix == "/" or path == prefix or path.startswith(prefix + "/")


def _url_matches_rule(parsed, port: int, path: str, rule: str) -> bool:
    url_rule = _url_rule(rule)
    if url_rule is None:
        if _looks_like_path_rule(rule):
            return False
        return _endpoint_matches(parsed.hostname, port, rule)
    rule_parts, rule_port, rule_path = url_rule
    return (
        (not rule_parts.scheme or parsed.scheme.lower() == rule_parts.scheme.lower())
        and _host_matches(parsed.hostname, rule)
        and (rule_port is None or port == rule_port)
        and _path_is_within(path, rule_path)
    )


def _path_limited_url_rule(rule: str) -> bool:
    parsed = _url_rule(rule)
    if parsed is not None:
        return parsed[2] != "/"
    # A malformed web path rule must never degrade to a host-wide grant.
    return _looks_like_path_rule(rule)


def _broad_host_rules(rules: Iterable[str], host: str) -> list[str]:
    """Rules that authorize host-level work rather than one URL subtree."""
    return [rule for rule in rules
            if _host_matches(host, rule) and not _path_limited_url_rule(rule)]


def scope_rules(workspace: Workspace) -> tuple[list[str], list[str]]:
    constraints = workspace.load_constraints()
    allowed, denied = list(constraints.in_scope), list(constraints.out_of_scope)
    if not allowed and workspace.exists():
        allowed.append(workspace.load_meta().target)
    return allowed, denied


def check_host_scope(workspace: Workspace, host: str) -> tuple[bool, str]:
    allowed, denied = scope_rules(workspace)
    if any(_host_matches(host, rule) and not _path_limited_url_rule(rule) for rule in denied):
        return False, f"{host} matches an out-of-scope rule"
    if not allowed:
        return False, "no in-scope host is recorded"
    if not _broad_host_rules(allowed, host):
        if any(_host_matches(host, rule) for rule in allowed):
            return False, f"{host} is authorized only for a recorded URL path"
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
        path = _canonical_url_path(parsed.path or "/")
        if path is None:
            return False, "URL path is ambiguous or invalid"
    except ValueError:
        return False, "invalid URL"
    allowed, denied = scope_rules(workspace)
    if any(_url_matches_rule(parsed, port, path, rule) for rule in denied):
        return False, f"{parsed.hostname}:{port}{path} matches an out-of-scope rule"
    if not allowed:
        return False, "no in-scope endpoint is recorded"
    if not any(_url_matches_rule(parsed, port, path, rule) for rule in allowed):
        matching_hosts = [rule for rule in allowed if _host_matches(parsed.hostname, rule)]
        if matching_hosts:
            bounded = sorted({p for rule in matching_hosts if (p := _rule_port(rule)) is not None})
            matching_endpoints = [rule for rule in matching_hosts
                                  if _endpoint_matches(parsed.hostname, port, rule)]
            if matching_endpoints:
                return False, f"URL scheme or path {path} is outside the recorded scope"
            return False, f"port {port} is outside the recorded port scope {bounded}"
        return False, f"{parsed.hostname} does not match the in-scope rules"
    return True, "in scope"


def check_port_scope(workspace: Workspace, host: str, port: int) -> tuple[bool, str]:
    """Scope check for raw TCP/TLS actions, including URL-bound ports."""
    allowed, denied = scope_rules(workspace)
    if any(_endpoint_matches(host, port, rule) and not _path_limited_url_rule(rule)
           for rule in denied):
        return False, f"{host}:{port} matches an out-of-scope rule"
    if not allowed:
        return False, "no in-scope endpoint is recorded"
    broad_allowed = [rule for rule in allowed
                     if _endpoint_matches(host, port, rule) and not _path_limited_url_rule(rule)]
    if not broad_allowed:
        if any(_endpoint_matches(host, port, rule) for rule in allowed):
            return False, f"{host}:{port} is authorized only for a recorded URL path"
        if any(_host_matches(host, rule) for rule in allowed):
            return False, f"{host}:{port} is outside the recorded port scope"
        return False, f"{host} does not match the in-scope rules"
    return True, "in scope"


def check_raw_tcp_scope(workspace: Workspace, host: str, port: int) -> tuple[bool, str]:
    """Block raw payloads when a path exclusion cannot be enforced."""
    allowed, reason = check_port_scope(workspace, host, port)
    if not allowed:
        return allowed, reason
    _, denied = scope_rules(workspace)
    if any(_endpoint_matches(host, port, rule) and _path_limited_url_rule(rule)
           for rule in denied):
        return False, "raw TCP cannot enforce the recorded out-of-scope URL path"
    return True, "in scope"


def _scope_error(workspace: Workspace, url: str) -> Optional[dict]:
    allowed, reason = check_url_scope(workspace, url)
    return None if allowed else _err(f"Scope blocked {url}: {reason}.")


def _safe_headers(headers: Optional[dict]) -> dict[str, str]:
    forbidden = {"host", "proxy-authorization", "proxy-connection"}
    output = {}
    for key, value in (headers or {}).items():
        key, value = str(key).strip(), str(value).replace("\r", "").replace("\n", "")
        if key.lower() in forbidden:
            raise ValueError(
                f"Request header {key!r} is not allowed because it can alter "
                "destination or proxy routing."
            )
        if key and re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
            output[key] = value
    return output


def _extract_auth_tokens(response: str) -> dict[str, str]:
    """Extract narrowly recognized JSON auth tokens for private reuse."""
    chunks = re.split(r"\r?\n\r?\n", response)
    value = None
    for chunk in reversed(chunks):
        try:
            candidate = json.loads(chunk)
        except (TypeError, ValueError):
            continue
        if isinstance(candidate, dict):
            value = candidate
            break
    if value is None:
        return {}
    output: dict[str, str] = {}
    accepted = {"accesstoken", "refreshtoken", "idtoken", "bearertoken", "jwt"}

    def walk(item, depth: int = 0) -> None:
        if not isinstance(item, dict) or depth > 2:
            return
        for key, child in item.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if isinstance(child, str) and child:
                generic_token = (
                    normalized == "token" and depth <= 1
                    and (child.lower().startswith("bearer ") or child.count(".") == 2)
                )
                if normalized in accepted or generic_token:
                    output[str(key)] = (child[7:].strip() if child.lower().startswith("bearer ") else child)
                    continue
            if isinstance(child, dict):
                walk(child, depth + 1)

    walk(value)
    return output


def _authentication_blocker(response: str, status_line: str) -> str:
    """Classify states where autonomous auth must stop rather than retry."""
    lowered = response.lower()
    if re.search(r"(?:\b(?:mfa|2fa|two[- _]factor|one[- ]time password|otp)\b|(?:mfa|otp|two[_-]?factor)[_-]?required\b)", lowered):
        return "interactive MFA/OTP is required; Grypton will not bypass or retry it"
    if "captcha" in lowered:
        return "a CAPTCHA challenge is active; Grypton will not bypass or retry it"
    if re.search(r"\b429\b", status_line):
        return "the authentication endpoint rate-limited the attempt"
    if re.search(r"\b(?:401|403)\b", status_line):
        return "the supplied credential was rejected or blocked"
    return ""


def _save_flow(workspace: Workspace, method: str, url: str, headers: Optional[dict],
               body: Optional[str], response: str, *, transport: str,
               returncode: int, stderr: str = "",
               secret_values: Iterable[str] = (),
               response_bytes: Optional[int] = None) -> Path:
    """Save a useful flow with transport and authentication secrets removed."""
    secrets_to_hide = tuple(str(value) for value in secret_values if str(value))
    workspace.flows_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = workspace.flows_dir / f"flow-{time.time_ns()}.http"
    safe_headers = _redacted_headers(headers, secrets_to_hide)
    header_text = "\n".join(f"{key}: {value}" for key, value in safe_headers.items())
    safe_url = redact_sensitive_text(url, secrets_to_hide)
    safe_body = redact_sensitive_text(body or "", secrets_to_hide)
    safe_response = redact_sensitive_text(response, secrets_to_hide)
    safe_stderr = redact_sensitive_text(stderr[:4000], secrets_to_hide)
    encoded_response = safe_response.encode("utf-8", "replace")
    captured_response = encoded_response[:MAX_RESPONSE_BYTES].decode(
        "utf-8", "ignore"
    )
    captured_bytes = len(captured_response.encode("utf-8"))
    original_bytes = max(0, int(
        len(encoded_response) if response_bytes is None else response_bytes
    ))
    metadata = json.dumps({"captured_at": time.time(), "transport": transport,
                           "returncode": returncode, "stderr": safe_stderr,
                           "response_bytes": original_bytes,
                           "captured_response_bytes": captured_bytes,
                           "response_truncated": (
                               (response_bytes is not None
                                and response_bytes > MAX_RESPONSE_BYTES)
                               or len(encoded_response) > MAX_RESPONSE_BYTES
                           )},
                          ensure_ascii=False)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(f"### GRYPTON FLOW {metadata}\n### REQUEST\n{method.upper()} {safe_url}\n"
                     f"{header_text}\n\n{safe_body}\n\n### RESPONSE\n"
                     f"{captured_response}\n")
    return path


def http_request(workspace: Workspace, url: str, *, method: str = "GET",
                 headers: Optional[dict] = None, body: Optional[str] = None,
                 timeout: int = 30, follow_redirects: bool = False,
                 insecure: bool = False, transport: str = "curl", proxy: str = "",
                 _secret_values: Iterable[str] = (),
                 _cookie_jar: Optional[Path] = None,
                 _bearer_token: str = "", _bearer_origin: str = "",
                 _session_identity: Optional[tuple[str, str, str]] = None,
                 _capture_headers: Optional[dict] = None,
                 _capture_body: Optional[str] = None) -> dict:
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

    try:
        request_origin = credentials.normalize_origin(url)
    except credentials.CredentialError as exc:
        return _err(str(exc))
    session_origin = ""
    if _session_identity:
        try:
            target_slug, credential_name, session_origin = _session_identity
            session_origin = credentials.normalize_origin(session_origin)
        except (TypeError, ValueError, credentials.CredentialError):
            return _err("Authenticated request has an invalid private origin binding.")
        if request_origin != session_origin:
            return _err(
                "Refused authenticated request outside the credential's exact login origin."
            )
    if _bearer_token:
        try:
            bearer_origin = credentials.normalize_origin(_bearer_origin)
        except credentials.CredentialError:
            return _err("Refused bearer authorization without a valid origin binding.")
        if request_origin != bearer_origin:
            return _err("Refused bearer authorization outside its exact login origin.")

    try:
        clean_headers = _safe_headers(headers)
    except ValueError as exc:
        return _err(str(exc))
    if _bearer_token and not any(key.lower() == "authorization" for key in clean_headers):
        clean_headers["Authorization"] = f"Bearer {_bearer_token}"

    argv = [curl, "--disable", "--silent", "--show-error", "--include", "--compressed",
            "--max-time", str(timeout), "--connect-timeout", str(min(timeout, 15))]
    if method == "HEAD":
        argv.append("--head")
    else:
        argv += ["--request", method]
    if insecure:
        argv.append("--insecure")
    if proxy:
        argv += ["--proxy", proxy]

    private_tmp = config.RUNTIME_DIR / "http-tmp" / workspace.slug
    private_tmp.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(private_tmp, 0o700)
    header_path: Optional[Path] = None
    if clean_headers:
        header_path = private_tmp / f".curl-{time.time_ns()}.headers"
        header_fd = os.open(
            header_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(header_fd, "w", encoding="utf-8") as stream:
            for key, value in clean_headers.items():
                stream.write(f"{key}: {value}\n")
        argv += ["--header", f"@{header_path}"]
    if _cookie_jar is not None:
        argv += ["--cookie", str(_cookie_jar), "--cookie-jar", str(_cookie_jar)]
    request_input = None
    if body is not None:
        argv += ["--data-binary", "@-"]
        request_input = body.encode("utf-8")
    argv += ["--", url]

    started = time.time()
    capture_path = private_tmp / f".curl-{time.time_ns()}.capture"
    fd = os.open(capture_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as capture:
            result = subprocess.run(
                argv, input=request_input, stdout=capture, stderr=subprocess.PIPE,
                timeout=timeout + 5, env=_minimal_local_environment(), umask=0o077,
            )
        response_bytes = capture_path.stat().st_size
        with capture_path.open("rb") as capture:
            raw_output = capture.read(MAX_RESPONSE_BYTES)
    except subprocess.TimeoutExpired:
        return _err(f"HTTP request timed out after {timeout}s; it was not retried.")
    except OSError as exc:
        return _err(f"HTTP transport failed before a response was captured: {exc}")
    finally:
        capture_path.unlink(missing_ok=True)
        if header_path is not None:
            header_path.unlink(missing_ok=True)
    if _cookie_jar is not None and _cookie_jar.exists():
        os.chmod(_cookie_jar, 0o600)

    output = raw_output.decode("utf-8", "replace")
    extracted = _extract_auth_tokens(output) if _session_identity else {}
    if _session_identity and extracted:
        saved = credentials.load_tokens(target_slug, credential_name)
        saved.update(extracted)
        try:
            credentials.save_tokens(
                target_slug, credential_name, saved, origin=session_origin
            )
        except credentials.CredentialError as exc:
            return _err(f"Refused unsafe bearer-token state: {exc}")
    secrets_to_hide = tuple(str(value) for value in _secret_values if str(value))
    secrets_to_hide += tuple(extracted.values())
    if _bearer_token:
        secrets_to_hide += (_bearer_token,)
    safe_output = redact_sensitive_text(output, secrets_to_hide)
    stderr = redact_sensitive_text(
        result.stderr[:8000].decode("utf-8", "replace"), secrets_to_hide
    )
    flow_headers = clean_headers if _capture_headers is None else _capture_headers
    flow_body = body if _capture_body is None else _capture_body
    flow = _save_flow(
        workspace, method, url, flow_headers, flow_body, safe_output,
        transport=transport, returncode=result.returncode, stderr=stderr,
        secret_values=secrets_to_hide, response_bytes=response_bytes,
    )
    status_lines = [
        line.strip() for line in output.splitlines() if line.startswith("HTTP/")
    ]
    status = status_lines[-1] if status_lines else "no HTTP status"
    data = {
        "status_line": status,
        "response": safe_output[:MAX_INLINE_RESPONSE_CHARS],
        "response_truncated": (
            len(safe_output) > MAX_INLINE_RESPONSE_CHARS
            or response_bytes > MAX_RESPONSE_BYTES
        ),
        "response_bytes": response_bytes,
        "stderr": stderr,
        "returncode": result.returncode,
        "duration_s": round(time.time() - started, 3),
        "flow": str(flow),
        "transport": transport,
    }
    if _session_identity:
        data["auth_blocker"] = _authentication_blocker(output, status)
    if result.returncode:
        return _err(f"curl exited {result.returncode}; capture saved to {flow}.", data)
    return _ok(f"{status} · {method} {redact_sensitive_text(url, secrets_to_hide)} · captured {flow.name}", data)


def credential_status(workspace: Workspace, name: str = "") -> dict:
    aliases = credentials.list_credentials(workspace.slug)
    if name:
        if name not in aliases:
            return _err(f"Named credential {name!r} is not available.")
        rows = [credentials.session_status(workspace.slug, name)]
    else:
        rows = [credentials.session_status(workspace.slug, alias) for alias in aliases]
    return _ok(f"{len(rows)} named credential(s) available.", rows)


def credential_login(workspace: Workspace, url: str, *, credential: str,
                     verify_url: str, success_marker: str,
                     username_field: str = "username", password_field: str = "password",
                     encoding: str = "json", fields: Optional[dict] = None,
                     headers: Optional[dict] = None, timeout: int = 30) -> dict:
    """Make one login attempt, then prove the session on a scoped endpoint."""
    for candidate in (url, verify_url):
        blocked = _scope_error(workspace, candidate)
        if blocked:
            return blocked
    try:
        login_origin = credentials.normalize_origin(url)
        verify_origin = credentials.normalize_origin(verify_url)
    except credentials.CredentialError as exc:
        return _err(str(exc))
    if verify_origin != login_origin:
        return _err(
            "The verification endpoint must use the login endpoint's exact origin "
            "(scheme, host, and effective port)."
        )
    if not success_marker or len(success_marker) > 200 or any(
        ord(char) < 0x20 for char in success_marker
    ):
        return _err("A printable 1-200 character verification success marker is required.")
    if not re.fullmatch(r"[A-Za-z0-9_.\[\]-]{1,80}", username_field or ""):
        return _err("Invalid username field name.")
    if not re.fullmatch(r"[A-Za-z0-9_.\[\]-]{1,80}", password_field or ""):
        return _err("Invalid password field name.")
    if encoding not in {"json", "form"}:
        return _err("Login encoding must be json or form.")
    if fields is not None and not isinstance(fields, dict):
        return _err("Login fields must be an object.")
    try:
        clean_headers = _safe_headers(headers)
    except ValueError as exc:
        return _err(str(exc))
    try:
        secret = credentials.load_credential(workspace.slug, credential)
    except credentials.CredentialError as exc:
        return _err(str(exc))

    values = dict(fields or {})
    values[username_field] = secret["username"]
    values[password_field] = secret["password"]
    if encoding == "json":
        body = json.dumps(values, ensure_ascii=False, separators=(",", ":"))
        clean_headers.setdefault("Content-Type", "application/json")
    else:
        body = urlencode(values)
        clean_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    raw_secrets = (secret["username"], secret["password"])
    capture_secrets = _serialized_secret_variants(raw_secrets)
    capture_body = _login_capture_body(
        values, username_field, password_field, encoding, raw_secrets
    )
    capture_headers = _redacted_headers(clean_headers, capture_secrets)
    try:
        attempt = credentials.begin_login_attempt(workspace.slug, credential)
        jar = credentials.cookie_jar_path(workspace.slug, credential)
        cookies_before = credentials.cookie_fingerprints(workspace.slug, credential)
    except credentials.CredentialError as exc:
        return _err(str(exc))

    login = http_request(
        workspace, url, method="POST", headers=clean_headers, body=body,
        timeout=timeout, transport=f"credential:{credential}",
        _secret_values=capture_secrets, _cookie_jar=jar,
        _session_identity=(workspace.slug, credential, login_origin),
        _capture_headers=capture_headers, _capture_body=capture_body,
    )
    login_data = login.get("data") if isinstance(login.get("data"), dict) else {}
    blocker = str(login_data.get("auth_blocker") or "")
    if blocker:
        credentials.record_login_outcome(
            workspace.slug, credential, blocked_reason=blocker
        )
        login["ok"] = False
        login["summary"] = (
            f"Authentication stopped after attempt {attempt}: {blocker}. "
            "No automatic retry was attempted."
        )
        return login
    if not login.get("ok"):
        credentials.record_login_outcome(workspace.slug, credential)
        login["summary"] = f"Login attempt {attempt} failed and was not retried."
        return login

    tokens = credentials.load_tokens(workspace.slug, credential)
    material = credentials.session_status(workspace.slug, credential)
    new_cookie_material = bool(
        credentials.cookie_fingerprints(workspace.slug, credential) - cookies_before
    )
    if not (
        material["has_auth_cookies"]
        or material["has_bearer_token"]
        or new_cookie_material
    ):
        credentials.record_login_outcome(workspace.slug, credential)
        login["ok"] = False
        login["summary"] = (
            f"Login attempt {attempt} produced no new cookie or recognizable bearer "
            "session material. It remains unverified and was not retried."
        )
        return login

    verification = http_request(
        workspace, verify_url, method="GET", timeout=timeout,
        transport=f"credential-verify:{credential}",
        _secret_values=(secret["username"], secret["password"], *tokens.values()),
        _cookie_jar=jar, _bearer_token=credentials.select_bearer(tokens),
        _bearer_origin=login_origin,
        _session_identity=(workspace.slug, credential, login_origin),
    )
    verify_data = (
        verification.get("data") if isinstance(verification.get("data"), dict) else {}
    )
    verify_response = str(verify_data.get("response") or "")
    verify_body = re.split(r"\r?\n\r?\n", verify_response)[-1]
    verify_status = str(verify_data.get("status_line") or "")
    # Prove that the marker depends on the new private session. A public page
    # can contain the same words and a tracking cookie can be newly issued;
    # accepting only the authenticated response would misclassify that pair.
    control = http_request(
        workspace, verify_url, method="GET", timeout=timeout,
        transport=f"credential-control:{credential}",
        _secret_values=(secret["username"], secret["password"], *tokens.values()),
    )
    control_data = (
        control.get("data") if isinstance(control.get("data"), dict) else {}
    )
    control_response = str(control_data.get("response") or "")
    control_body = re.split(r"\r?\n\r?\n", control_response)[-1]
    control_status = str(control_data.get("status_line") or "")
    control_match = re.search(r"\b(\d{3})\b", control_status)
    control_code = int(control_match.group(1)) if control_match else 0
    control_is_conclusive = (
        control.get("ok")
        and (200 <= control_code < 300 or control_code in {401, 403, 404})
        and success_marker not in control_body
    )
    established = bool(
        verification.get("ok")
        and re.search(r"\b2\d\d\b", verify_status)
        and success_marker in verify_body
        and control_is_conclusive
    )
    verify_blocker = str(verify_data.get("auth_blocker") or "")
    credentials.record_login_outcome(
        workspace.slug, credential, established=established,
        blocked_reason=verify_blocker,
        origin=login_origin if established else None,
    )
    verify_data["credential"] = credential
    verify_data["login_flow"] = login_data.get("flow")
    verify_data["control_flow"] = control_data.get("flow")
    verify_data["session"] = credentials.session_status(workspace.slug, credential)
    if established:
        verification["summary"] = (
            f"Authenticated session {credential!r} was verified on the scoped "
            f"verification endpoint after attempt {attempt}; secrets were not exposed."
        )
        return verification
    verification["ok"] = False
    verification["summary"] = (
        f"Login attempt {attempt} left unverified session material: the scoped "
        "success marker was absent or was not proven to depend on the session. "
        "No automatic retry was attempted."
    )
    return verification


def authenticated_http_request(workspace: Workspace, url: str, *, credential: str,
                               method: str = "GET", headers: Optional[dict] = None,
                               body: Optional[str] = None, timeout: int = 30) -> dict:
    """Use a named private session without exposing credential material."""
    try:
        clean_headers = _safe_headers(headers)
    except ValueError as exc:
        return _err(str(exc))
    try:
        secret = credentials.load_credential(workspace.slug, credential)
        tokens = credentials.load_tokens(workspace.slug, credential)
        session = credentials.session_status(workspace.slug, credential)
    except credentials.CredentialError as exc:
        return _err(str(exc))
    if not session["established"]:
        return _err(
            f"Named credential {credential!r} has no established session; "
            "call credential_login once first."
        )
    bound_origin = str(session.get("origin") or "")
    try:
        request_origin = credentials.normalize_origin(url)
        bound_origin = credentials.normalize_origin(bound_origin)
    except credentials.CredentialError:
        return _err(
            f"Named credential {credential!r} has no valid private origin binding; "
            "authenticate it again before use."
        )
    if request_origin != bound_origin:
        return _err(
            f"Refused authenticated request for {credential!r}: the URL does not "
            "match the session's exact login origin (scheme, host, and effective port)."
        )
    bearer = credentials.select_bearer(tokens)
    if bearer and credentials.token_origin(workspace.slug, credential) != bound_origin:
        return _err(
            f"Refused bearer authorization for {credential!r}: its private origin "
            "binding is missing or does not match the established session."
        )
    jar = credentials.cookie_jar_path(workspace.slug, credential)
    result = http_request(
        workspace, url, method=method, headers=clean_headers, body=body, timeout=timeout,
        transport=f"authenticated:{credential}",
        _secret_values=(
            secret["username"], secret["password"], *tokens.values()
        ),
        _cookie_jar=jar, _bearer_token=bearer, _bearer_origin=bound_origin,
        _session_identity=(workspace.slug, credential, bound_origin),
    )
    data = result.get("data") if isinstance(result.get("data"), dict) else None
    if data is not None:
        blocker = str(data.get("auth_blocker") or "")
        if blocker:
            credentials.record_login_outcome(
                workspace.slug, credential, established=False,
                blocked_reason=blocker,
            )
            result["ok"] = False
            result["summary"] = (
                f"Authenticated session {credential!r} is no longer usable: {blocker}. "
                "The session was blocked pending operator action."
            )
        data["credential"] = credential
        data["session"] = credentials.session_status(
            workspace.slug, credential
        )
    return result


class Goja:
    BIN = config.GOJA_DIR / "bin" / "goja-proxy"
    CA = config.GOJA_DIR / "certs" / "certs" / "goja-root-ca.pem"

    @classmethod
    def _state_path(cls) -> Path:
        return config.RUNTIME_DIR / "goja-process.json"

    @classmethod
    def _lock_path(cls) -> Path:
        return config.RUNTIME_DIR / "goja-process.lock"

    @classmethod
    def _managed_config_path(cls) -> Path:
        return config.RUNTIME_DIR / "goja-config.json"

    @classmethod
    def _expected_argv(cls) -> list[str]:
        return [str(cls.BIN), "-config", str(cls._managed_config_path())]

    @classmethod
    @contextmanager
    def _lock(cls):
        """Serialize reads and mutations of the singleton Goja process."""
        config.RUNTIME_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(config.RUNTIME_DIR, 0o700)
        fd = os.open(
            cls._lock_path(),
            os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    @staticmethod
    def _process_identity(pid: int) -> Optional[dict]:
        """Return stable Linux identity fields for a live process."""
        if not isinstance(pid, int) or pid <= 1:
            return None
        proc = Path("/proc") / str(pid)
        try:
            stat_text = (proc / "stat").read_text(encoding="ascii")
            close = stat_text.rfind(")")
            if close < 0:
                return None
            fields = stat_text[close + 2:].split()
            # These fields start at proc(5) field 3. Start time is field 22.
            if len(fields) < 20 or fields[0] == "Z":
                return None
            start_time = fields[19]
            raw = (proc / "cmdline").read_bytes()
            argv = [part.decode("utf-8", "surrogateescape")
                    for part in raw.split(b"\0") if part]
            if not argv:
                return None
            return {"pid": pid, "start_time": start_time, "argv": argv}
        except (OSError, ValueError):
            return None

    @classmethod
    def _identity_matches(cls, state: Optional[dict]) -> bool:
        if not isinstance(state, dict) or state.get("version") != 1:
            return False
        try:
            pid = int(state["pid"])
            expected_start = str(state["start_time"])
            recorded_argv = list(state["argv"])
        except (KeyError, TypeError, ValueError):
            return False
        expected_argv = cls._expected_argv()
        if recorded_argv != expected_argv:
            return False
        current = cls._process_identity(pid)
        return bool(
            current
            and current["start_time"] == expected_start
            and current["argv"] == expected_argv
        )

    @classmethod
    def _read_state_unlocked(cls) -> Optional[dict]:
        path = cls._state_path()
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                return None
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else None
        except (OSError, ValueError):
            return None

    @classmethod
    def _write_state_unlocked(cls, state: dict) -> None:
        path = cls._state_path()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
        fd = os.open(
            tmp,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(state, stream, sort_keys=True)
                stream.write("\n")
            os.replace(tmp, path)
            os.chmod(path, 0o600)
        finally:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass

    @classmethod
    def _clear_state_unlocked(cls) -> None:
        try:
            cls._state_path().unlink()
        except FileNotFoundError:
            pass

    @staticmethod
    def _socket_inodes(pid: int) -> set[str]:
        output: set[str] = set()
        try:
            entries = (Path("/proc") / str(pid) / "fd").iterdir()
            for entry in entries:
                try:
                    target = os.readlink(entry)
                except OSError:
                    continue
                match = re.fullmatch(r"socket:\[(\d+)\]", target)
                if match:
                    output.add(match.group(1))
        except OSError:
            return set()
        return output

    @staticmethod
    def _listener_inodes(hostport: str) -> set[str]:
        raw_host, separator, raw_port = hostport.rpartition(":")
        try:
            wanted_port = int(raw_port)
        except ValueError:
            return set()
        host = raw_host.strip("[]") if separator else "127.0.0.1"
        try:
            wanted_addresses = {
                ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
                for _, _, _, _, sockaddr in socket.getaddrinfo(
                    host or "127.0.0.1", wanted_port, type=socket.SOCK_STREAM
                )
            }
        except (OSError, ValueError):
            return set()
        output: set[str] = set()
        tables = (
            (Path("/proc/net/tcp"), socket.AF_INET),
            (Path("/proc/net/tcp6"), socket.AF_INET6),
        )
        for table, family in tables:
            try:
                lines = table.read_text(encoding="ascii").splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                fields = line.split()
                if len(fields) < 10 or fields[3] != "0A":
                    continue
                try:
                    raw_address, port_hex = fields[1].rsplit(":", 1)
                    port = int(port_hex, 16)
                    packed = bytes.fromhex(raw_address)
                    if family == socket.AF_INET:
                        packed = packed[::-1]
                    else:
                        packed = b"".join(
                            packed[index:index + 4][::-1]
                            for index in range(0, len(packed), 4)
                        )
                    address = ipaddress.ip_address(packed)
                except (IndexError, ValueError):
                    continue
                comparable = getattr(address, "ipv4_mapped", None) or address
                if port == wanted_port and (
                    address.is_unspecified or comparable in wanted_addresses
                ):
                    output.add(fields[9])
        return output

    @classmethod
    def _owns_listener(cls, pid: int) -> bool:
        sockets = cls._socket_inodes(pid)
        return bool(sockets and sockets.intersection(
            cls._listener_inodes(config.GOJA_SOCKS)
        ))

    @classmethod
    def _inspect_unlocked(cls, *, clear_stale: bool = True) -> dict:
        state = cls._read_state_unlocked()
        managed = cls._identity_matches(state)
        if not managed and clear_stale:
            path = cls._state_path()
            if state is not None or path.exists() or path.is_symlink():
                cls._clear_state_unlocked()
            state = None
        listener_open = _port_open(config.GOJA_SOCKS)
        pid = int(state["pid"]) if managed else None
        listener_owned = bool(managed and cls._owns_listener(pid))
        return {
            "running": bool(managed and listener_open and listener_owned),
            "managed": managed,
            "managed_pid": pid,
            "listener_open": listener_open,
            "listener_owned": listener_owned,
            "socks": config.GOJA_SOCKS,
            "binary": str(cls.BIN),
            "ca_exists": cls.CA.is_file(),
        }

    @classmethod
    def running(cls) -> bool:
        with cls._lock():
            return cls._inspect_unlocked()["running"]

    @classmethod
    def _managed_config(cls) -> Path:
        output = cls._managed_config_path()
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
        os.chmod(output, 0o600)
        return output

    @classmethod
    def status(cls) -> dict:
        with cls._lock():
            data = cls._inspect_unlocked()
        if data["running"]:
            summary = "Grypton-managed Goja is running."
        elif data["listener_open"]:
            summary = "Goja is stopped; the SOCKS endpoint is occupied by an unmanaged listener."
        elif data["managed"]:
            summary = "The Grypton-managed Goja process exists but is not ready."
        else:
            summary = "Goja is stopped."
        return _ok(summary, data)

    @classmethod
    def start(cls, wait_s: float = 10.0) -> dict:
        with cls._lock():
            current = cls._inspect_unlocked()
            if current["running"]:
                return _ok(
                    f"Goja is listening at SOCKS5 {config.GOJA_SOCKS}.", current
                )
            if current["managed"]:
                return _err(
                    "A Grypton-managed Goja process exists but is not ready; "
                    "stop it before starting another instance.", current
                )
            if current["listener_open"]:
                return _err(
                    f"Cannot start Goja: SOCKS5 {config.GOJA_SOCKS} is occupied "
                    "by an unmanaged listener.", current
                )
            if not cls.BIN.is_file():
                return _err(f"Goja binary is missing at {cls.BIN}.")
            config.LOG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
            log = config.LOG_DIR / "goja.log"
            process = None
            try:
                argv = cls._expected_argv()
                cls._managed_config()
                with log.open("ab") as stream:
                    process = subprocess.Popen(
                        argv, cwd=str(config.GOJA_DIR), stdout=stream, stderr=stream,
                        stdin=subprocess.DEVNULL, start_new_session=True,
                        env=_minimal_local_environment(), umask=0o077,
                    )
                identity = None
                identity_deadline = time.time() + 1.0
                while time.time() < identity_deadline and process.poll() is None:
                    candidate = cls._process_identity(process.pid)
                    if candidate and candidate["argv"] == argv:
                        identity = candidate
                        break
                    time.sleep(0.02)
                if identity is None:
                    if process.poll() is None:
                        process.terminate()
                    return _err("Could not establish the identity of the Goja process.")
                cls._write_state_unlocked({
                    "version": 1,
                    "pid": identity["pid"],
                    "start_time": identity["start_time"],
                    "argv": argv,
                })
            except OSError as exc:
                if process is not None and process.poll() is None:
                    process.terminate()
                return _err(f"Could not start Goja: {exc}")
            deadline = time.time() + max(1, min(wait_s, 30))
            while time.time() < deadline:
                data = cls._inspect_unlocked()
                if data["running"]:
                    return _ok(
                        f"Goja started at SOCKS5 {config.GOJA_SOCKS}.", data
                    )
                if process.poll() is not None or not data["managed"]:
                    break
                time.sleep(0.2)
            data = cls._inspect_unlocked()
            return _err(f"Goja did not become ready. Inspect {log}.", data)

    @classmethod
    def stop(cls) -> dict:
        with cls._lock():
            data = cls._inspect_unlocked()
            if not data["managed"]:
                return _err("No verified Grypton-managed Goja process is recorded.", data)
            state = cls._read_state_unlocked()
            pid = int(state["pid"])
            try:
                pidfd_open = getattr(os, "pidfd_open")
                pidfd_send_signal = getattr(signal, "pidfd_send_signal")
            except AttributeError:
                return _err(
                    "This system cannot safely signal a persisted Goja process "
                    "without Linux pidfd support.", data
                )
            try:
                pidfd = pidfd_open(pid, 0)
            except OSError:
                cls._clear_state_unlocked()
                return _ok("The recorded Goja process had already exited.",
                           cls._inspect_unlocked())
            try:
                # A pidfd pins one process identity. Recheck both the stored
                # start time and exact argv after opening it, then signal only
                # through that descriptor so a reused numeric PID is harmless.
                if not cls._identity_matches(state):
                    cls._clear_state_unlocked()
                    return _err("The recorded Goja PID no longer belongs to Grypton.",
                                cls._inspect_unlocked())
                try:
                    pidfd_send_signal(pidfd, signal.SIGTERM, None, 0)
                except ProcessLookupError:
                    pass
                except OSError as exc:
                    return _err(f"Could not stop Goja safely: {exc}", data)
                deadline = time.time() + 5
                while time.time() < deadline and cls._identity_matches(state):
                    time.sleep(0.1)
                if cls._identity_matches(state):
                    try:
                        pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
                    except ProcessLookupError:
                        pass
                    except OSError as exc:
                        return _err(f"Could not kill Goja safely: {exc}", data)
                    deadline = time.time() + 1
                    while time.time() < deadline and cls._identity_matches(state):
                        time.sleep(0.05)
                if cls._identity_matches(state):
                    return _err("Goja did not exit after termination signals.",
                                cls._inspect_unlocked(clear_stale=False))
            finally:
                os.close(pidfd)
            cls._clear_state_unlocked()
            return _ok("Stopped the Grypton-managed Goja process.",
                       cls._inspect_unlocked())

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
            if key.lower() != "content-length":
                old_headers[key.strip()] = value.strip()
        index += 1
    try:
        old_headers = _safe_headers(old_headers)
        old_headers.update(_safe_headers(headers))
    except ValueError as exc:
        return _err(str(exc))
    old_body = "\n".join(lines[index + 1:]).strip() or None
    return http_request(workspace, url or old_url, method=method or old_method,
                        headers=old_headers, body=body if body is not None else old_body,
                        transport=f"replay:{Path(flow_id).stem}")


def _non_url_rule_authorizes(workspace: Workspace, host: str,
                              port: Optional[int] = None) -> bool:
    """Return whether a bare host/port has a non-URL scope grant."""
    allowed, _ = scope_rules(workspace)
    for rule in allowed:
        if _url_rule(rule) is not None or _looks_like_path_rule(rule):
            continue
        if port is None and _host_matches(host, rule):
            return True
        if port is not None and _endpoint_matches(host, port, rule):
            return True
    return False


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
                if not host or not _non_url_rule_authorizes(workspace, host, parsed.port):
                    allowed, reason = False, (
                        "bare httpx targets require a non-URL host/domain/CIDR scope rule; "
                        "supply a full scoped URL to preserve its scheme and port"
                    )
                else:
                    allowed, reason = (
                        check_port_scope(workspace, host, parsed.port)
                        if parsed.port is not None else check_host_scope(workspace, host)
                    )
            except ValueError:
                allowed, reason = False, "invalid host or port"
        if not allowed:
            return _err(f"Scope blocked {value}: {reason}.")
    try:
        tool_home = config.RUNTIME_DIR / "httpx" / workspace.slug
        tool_home.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(tool_home, 0o700)
        env = _minimal_local_environment()
        env.update({"HOME": str(tool_home), "XDG_CONFIG_HOME": str(tool_home)})
        result = subprocess.run(
            [binary, "-silent", "-status-code", "-title", "-tech-detect", "-no-color"],
            input=("\n".join(values) + "\n").encode(), capture_output=True,
            timeout=180, env=env, umask=0o077,
        )
    except subprocess.SubprocessError as exc:
        return _err(f"httpx failed: {exc}")
    return _ok(f"httpx completed for {len(values)} scoped target(s).",
               {"output": result.stdout.decode("utf-8", "replace")[:200_000]})


_BROWSER_ACCOUNT = "grypton-browser"


def _browser_executable() -> str:
    """Prefer the real Chrome ELF over local wrapper scripts.

    Some CI images replace ``/opt/google/chrome/chrome`` with a convenience
    shell wrapper that points into root's Playwright cache and adds sandbox-
    disabling flags.  The dedicated browser identity cannot use that private
    cache.  The packaged ``chrome.real`` keeps Chrome's normal setuid sandbox
    and its adjacent resources.
    """
    candidates = (
        Path("/opt/google/chrome/chrome.real"),
        Path("/opt/google/chrome/chrome"),
        Path(config.find_binary("google-chrome") or ""),
        Path(config.find_binary("chromium") or ""),
    )
    return next((str(path) for path in candidates if path.is_file()), "")


@contextmanager
def _isolated_browser_profile(executable: str):
    """Yield a Chromium profile that never executes the browser as root."""
    is_root = os.geteuid() == 0
    account = None
    if is_root:
        try:
            account = pwd.getpwnam(_BROWSER_ACCOUNT)
        except KeyError as exc:
            raise RuntimeError(
                "Grypton is running as root and the dedicated "
                f"'{_BROWSER_ACCOUNT}' browser account is unavailable. Run "
                "Grypton as an unprivileged OS user, or provision that fixed "
                "no-login account before enabling browse."
            ) from exc
        if account.pw_uid == 0 or account.pw_gid == 0:
            raise RuntimeError(
                f"The dedicated '{_BROWSER_ACCOUNT}' browser account must have "
                "a non-root uid and gid."
            )

    data_parent = Path("/tmp") if is_root else config.RUNTIME_DIR / "browser"
    if not is_root:
        data_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(data_parent, 0o700)
    data_root = Path(tempfile.mkdtemp(prefix="grypton-browser-", dir=str(data_parent)))
    launcher_root: Optional[Path] = None
    try:
        directories = {
            name: data_root / name
            for name in ("profile", "home", "tmp", "cache", "config", "runtime")
        }
        for directory in directories.values():
            directory.mkdir(mode=0o700)

        launch_executable = executable
        identity = f"uid={os.geteuid()}"
        if account is not None:
            uid, gid = account.pw_uid, account.pw_gid
            for directory in (data_root, *directories.values()):
                os.chown(directory, uid, gid)
                os.chmod(directory, 0o700)

            # This root-owned launcher is outside the browser-writable profile.
            # It drops every inherited group and both IDs before execing Chrome.
            launcher_root = Path(tempfile.mkdtemp(
                prefix="grypton-browser-launcher-", dir="/tmp"
            ))
            os.chmod(launcher_root, 0o755)
            launcher = launcher_root / "launch.py"
            script = (
                f"#!{sys.executable}\n"
                "import os\n"
                "import sys\n"
                "os.umask(0o077)\n"
                f"os.chdir({str(directories['home'])!r})\n"
                "os.setgroups([])\n"
                f"os.setgid({gid})\n"
                f"os.setuid({uid})\n"
                f"if os.geteuid() != {uid} or os.getegid() != {gid}:\n"
                "    raise SystemExit('browser privilege drop failed')\n"
                f"os.execv({executable!r}, [{executable!r}, *sys.argv[1:]])\n"
            )
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(launcher, flags, 0o500)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(script)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(launcher, 0o500)
            launch_executable = str(launcher)
            identity = _BROWSER_ACCOUNT

        env = _minimal_local_environment()
        env.update({
            "HOME": str(directories["home"]),
            "TMPDIR": str(directories["tmp"]),
            "XDG_CACHE_HOME": str(directories["cache"]),
            "XDG_CONFIG_HOME": str(directories["config"]),
            "XDG_RUNTIME_DIR": str(directories["runtime"]),
        })
        yield {
            "executable": launch_executable,
            "profile": str(directories["profile"]),
            "environment": env,
            "identity": identity,
        }
    finally:
        # CPython uses fd-relative deletion here and does not follow profile
        # symlinks planted by a compromised renderer.
        if launcher_root is not None:
            shutil.rmtree(launcher_root, ignore_errors=True)
        shutil.rmtree(data_root, ignore_errors=True)


def browse(workspace: Workspace, url: str, *, timeout: int = 45) -> dict:
    blocked = _scope_error(workspace, url)
    if blocked:
        return blocked
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return _err("Python Playwright is not installed; use the scoped http_request or httpx_probe tool.")
    executable = _browser_executable()
    if not executable:
        return _err("No Playwright-compatible Chromium or Chrome executable is installed.")
    output = workspace.scratch_dir / f"page-{time.time_ns()}.html"
    denied_requests: list[str] = []
    console: list[dict] = []
    status = 0
    final_url = url
    html = b""
    browser_identity = ""
    context = None
    try:
        with _isolated_browser_profile(executable) as launch_profile:
            browser_identity = str(launch_profile["identity"])
            with sync_playwright() as playwright:
                context = playwright.chromium.launch_persistent_context(
                    user_data_dir=launch_profile["profile"],
                    headless=True,
                    executable_path=launch_profile["executable"],
                    ignore_default_args=["--enable-unsafe-swiftshader"],
                    env=launch_profile["environment"],
                    chromium_sandbox=True,
                    ignore_https_errors=True,
                    service_workers="block",
                    args=["--disable-gpu", "--disable-software-rasterizer",
                          "--disable-gpu-compositing", "--disable-dev-shm-usage",
                          "--disable-background-networking"],
                )
                if hasattr(context, "route_web_socket"):
                    # Browser WebSockets do not carry an HTTP path that Grypton's
                    # request capture can audit, so keep them closed in scoped mode.
                    context.route_web_socket("**/*", lambda web_socket: web_socket.close())

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
                final_allowed, final_reason = check_url_scope(workspace, final_url)
                if not final_allowed:
                    raise RuntimeError(f"browser ended outside scope: {final_reason}")
                html = page.content().encode("utf-8")[:MAX_RESPONSE_BYTES]
                context.close()
                context = None
    except Exception as exc:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass
        return _err(f"Headless browser failed: {exc}",
                    {"blocked_requests": denied_requests, "console": console})
    output.write_bytes(html)
    rendered = f"HTTP {status}\nFinal-URL: {final_url}\n\n" + html.decode("utf-8", "replace")
    flow = _save_flow(workspace, "GET", url, {}, None, rendered,
                      transport="playwright-chromium", returncode=0)
    data = {"html_path": str(output), "flow": str(flow), "status": status,
            "final_url": final_url, "blocked_requests": denied_requests,
            "console": console, "browser_identity": browser_identity}
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
    allowed, reason = check_raw_tcp_scope(workspace, host, port)
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
    """Download one bounded, non-redirecting scoped artifact into private storage."""
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
    max_bytes = 256 * 1024 * 1024
    workspace.loot_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(workspace.loot_dir, 0o700)
    workspace.scratch_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(workspace.scratch_dir, 0o700)
    temporary = workspace.loot_dir / f".{destination.name}.{time.time_ns()}.part"
    headers = workspace.scratch_dir / f"download-{time.time_ns()}.headers"
    created: list[Path] = []
    try:
        for path in (temporary, headers):
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(fd)
            created.append(path)
        result = subprocess.run(
            [curl, "--disable", "--silent", "--show-error", "--fail",
             "--max-time", str(timeout), "--connect-timeout", str(min(timeout, 15)),
             "--max-filesize", str(max_bytes), "--dump-header", str(headers),
             "--output", str(temporary), "--", url],
            capture_output=True, timeout=timeout + 5,
            env=_minimal_local_environment(), umask=0o077,
        )
        if result.returncode:
            detail = redact_sensitive_text(result.stderr.decode("utf-8", "replace")[-2000:])
            return _err("Artifact download failed: " + detail)
        size = temporary.stat().st_size
        if size > max_bytes:
            return _err("Artifact download exceeded the 256 MB limit.")
        digest_state = hashlib.sha256()
        with temporary.open("rb") as stream:
            while block := stream.read(1024 * 1024):
                digest_state.update(block)
        digest = digest_state.hexdigest()
        os.replace(temporary, destination)
        response_headers = headers.read_text(
            encoding="utf-8", errors="replace"
        ) if headers.exists() else ""
        flow = _save_flow(workspace, "GET", url, {}, None,
                          response_headers + f"\n[Binary saved: {destination.name}; sha256={digest}]",
                          transport="artifact-download", returncode=0)
        return _ok(f"Saved {destination.name} ({size} bytes) and {flow.name}.",
                   {"path": str(destination), "sha256": digest, "flow": str(flow),
                    "bytes": size})
    except (OSError, subprocess.SubprocessError) as exc:
        return _err(f"Artifact download failed: {redact_sensitive_text(exc)}")
    finally:
        for path in created:
            path.unlink(missing_ok=True)


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
                result = subprocess.run(
                    args, capture_output=True, timeout=20,
                    env=_minimal_local_environment(), umask=0o077,
                )
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
            result = subprocess.run(
                [apksigner, "verify", "--verbose", str(path)],
                capture_output=True, timeout=20,
                env=_minimal_local_environment(), umask=0o077,
            )
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
        result = subprocess.run(
            [binary, "-silent", "-d", domain, "-timeout", "30"],
            capture_output=True, timeout=max(30, min(int(timeout), 300)),
            env=_minimal_local_environment(), umask=0o077,
        )
    except subprocess.SubprocessError as exc:
        return _err(f"subfinder failed: {exc}")
    names = sorted({line.strip() for line in result.stdout.decode(errors="replace").splitlines()
                    if line.strip()})
    return _ok(f"subfinder returned {len(names)} name(s) for {domain}.", names[:5000])


_SAFE_APT_PACKAGES = frozenset({
    "aapt", "android-sdk-build-tools", "apksigner", "binutils",
    "ca-certificates", "chromium", "curl", "default-jre-headless",
    "dnsutils", "file", "jq", "nmap", "openssl", "unzip", "whois", "zip",
})

_RESEARCH_DOCUMENTATION_HOSTS = frozenset({
    "cheatsheetseries.owasp.org", "owasp.org", "www.owasp.org",
    "portswigger.net", "developer.mozilla.org", "docs.python.org",
    "go.dev", "pkg.go.dev", "nodejs.org", "curl.se", "nmap.org",
    "developer.android.com", "source.android.com", "docs.mitmproxy.org",
    "docs.projectdiscovery.io", "www.zaproxy.org", "datatracker.ietf.org",
    "www.rfc-editor.org",
})

_MAX_LOCAL_ANALYZE_BYTES = 64 * 1024 * 1024
_MAX_LOCAL_ANALYZE_OUTPUT = 64_000


def _minimal_local_environment(*, apt: bool = False) -> dict[str, str]:
    allowed = (
        "HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "JAVA_HOME", "ANDROID_HOME",
        "ANDROID_SDK_ROOT", "NODE_EXTRA_CA_CERTS",
    )
    env = {key: os.environ[key] for key in allowed if os.environ.get(key)}
    env.setdefault("HOME", str(Path.home()))
    env.setdefault("PATH", os.defpath)
    env.setdefault("LANG", "C.UTF-8")
    if apt:
        env["DEBIAN_FRONTEND"] = "noninteractive"
    return env


def install_tool(spec: str, *, manager: str = "auto", timeout: int = 900) -> dict:
    """Install one exact package from a small OS-package allowlist.

    Language package managers execute arbitrary package hooks under the Grypton
    process identity. The worker therefore cannot choose a repository, version,
    URL, option, or package name outside this reviewed set.
    """
    spec = str(spec or "").strip()
    manager = "apt" if manager == "auto" else str(manager or "")
    if manager != "apt":
        return _err("Only the curated apt installer is available.")
    if spec not in _SAFE_APT_PACKAGES:
        return _err(
            "Package is not in Grypton's curated installer allowlist. Available: "
            + ", ".join(sorted(_SAFE_APT_PACKAGES))
        )
    binary = config.find_binary("apt-get")
    if not binary:
        return _err("The curated apt installer is unavailable on this host.")
    argv = [binary, "install", "-y", "--no-install-recommends", spec]
    try:
        result = subprocess.run(
            argv, capture_output=True, timeout=max(30, min(int(timeout), 1800)),
            env=_minimal_local_environment(apt=True), umask=0o077,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return _err(f"Installation failed: {exc}")
    if result.returncode:
        detail = redact_sensitive_text(
            result.stderr.decode("utf-8", "replace")[-2000:]
        )
        return _err(f"apt exited {result.returncode}: {detail}")
    return _ok(f"Installed curated package {spec!r} with apt.")


def _open_workspace_regular_file(workspace: Workspace, relative_path: str) -> tuple[int, int]:
    """Open a workspace file without following any path-component symlink."""
    relative = Path(str(relative_path or ""))
    parts = relative.parts
    if relative.is_absolute() or not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("path must be a relative file beneath the engagement workspace")
    directory_fds: list[int] = []
    try:
        directory_fds.append(os.open(
            workspace.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        ))
        for part in parts[:-1]:
            directory_fds.append(os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory_fds[-1],
            ))
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fds[-1])
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            raise ValueError("analysis input must be a regular file")
        if info.st_size > _MAX_LOCAL_ANALYZE_BYTES:
            os.close(fd)
            raise ValueError("analysis input exceeds the 64 MB limit")
        return fd, info.st_size
    finally:
        for directory_fd in reversed(directory_fds):
            os.close(directory_fd)


def local_analyze(workspace: Workspace, path: str, *, analyzer: str = "file",
                  min_length: int = 6) -> dict:
    """Run one fixed, offline analyzer against one safely opened workspace file."""
    analyzer = str(analyzer or "").lower()
    if analyzer not in {"file", "strings", "sha256"}:
        return _err("Analyzer must be one of: file, strings, sha256.")
    try:
        fd, size = _open_workspace_regular_file(workspace, path)
    except (OSError, ValueError) as exc:
        return _err(f"Local analysis input was rejected: {exc}")
    try:
        if analyzer == "sha256":
            digest = hashlib.sha256()
            while block := os.read(fd, 1024 * 1024):
                digest.update(block)
            return _ok(f"Computed SHA-256 for {path} ({size} bytes).", {
                "analyzer": analyzer, "path": path, "bytes": size,
                "sha256": digest.hexdigest(),
            })

        binary = config.find_binary(analyzer)
        if not binary:
            return _err(f"The fixed offline analyzer {analyzer!r} is unavailable.")
        fd_path = f"/proc/self/fd/{fd}"
        if analyzer == "file":
            argv = [binary, "--brief", "--mime-type", "--", fd_path]
        else:
            minimum = max(4, min(int(min_length), 64))
            argv = [binary, "-a", "-n", str(minimum), "--", fd_path]
        os.lseek(fd, 0, os.SEEK_SET)
        result = subprocess.run(
            argv, capture_output=True, timeout=30, pass_fds=(fd,),
            env=_minimal_local_environment(), umask=0o077,
        )
        output = result.stdout.decode("utf-8", "replace")
        truncated = len(output) > _MAX_LOCAL_ANALYZE_OUTPUT
        output = output[:_MAX_LOCAL_ANALYZE_OUTPUT]
        if result.returncode:
            detail = redact_sensitive_text(
                result.stderr.decode("utf-8", "replace")[-2000:]
            )
            return _err(f"{analyzer} exited {result.returncode}: {detail}")
        return _ok(f"Ran offline {analyzer} analysis on {path} ({size} bytes).", {
            "analyzer": analyzer, "path": path, "bytes": size,
            "output": output, "truncated": truncated,
        })
    except (OSError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        return _err(f"Local analysis failed: {exc}")
    finally:
        os.close(fd)


def _research_target_related(workspace: Workspace, hostname: str) -> bool:
    allowed, denied = scope_rules(workspace)
    return any(_host_related_to_rule(hostname, rule) for rule in allowed + denied)


def check_research_scope(workspace: Workspace, url: str) -> tuple[bool, str]:
    """Allow scoped target pages or a fixed set of public documentation hosts."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False, "Research URL must use http or https and include a hostname"
        if parsed.username or parsed.password:
            return False, "credentials embedded in research URLs are not accepted"
        if parsed.query:
            return False, "research URLs must not contain query strings or credentials"
        _ = parsed.port
    except ValueError:
        return False, "Research URL is invalid"
    hostname = parsed.hostname.lower().rstrip(".")
    if _research_target_related(workspace, hostname):
        return check_url_scope(workspace, url)
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global:
        return False, "local, private, reserved, and link-local research hosts are blocked"
    if hostname not in _RESEARCH_DOCUMENTATION_HOSTS:
        return False, "host is not in Grypton's approved public documentation list"
    return True, "approved public documentation host"


_RESEARCH_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_RESEARCH_MAX_REDIRECTS = 10


def _research_resolved_destinations(workspace: Workspace, url: str):
    """Validate one hop and resolve its addresses exactly once before connecting."""
    allowed, reason = check_research_scope(workspace, url)
    if not allowed:
        return _err(f"Scope blocked research URL: {reason}."), None, []
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").rstrip(".")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    target_related = _research_target_related(workspace, hostname)
    try:
        answers = socket.getaddrinfo(
            hostname, port, type=socket.SOCK_STREAM,
        )
    except (OSError, ValueError):
        return _err("Research host resolution failed before any request was sent."), None, []
    destinations = []
    seen = set()
    for family, socket_type, protocol, canonical_name, socket_address in answers:
        try:
            address = str(socket_address[0]).split("%", 1)[0]
            parsed_address = ipaddress.ip_address(address)
        except (IndexError, TypeError, ValueError):
            return _err("Research host resolution returned an invalid address."), None, []
        if not target_related and not parsed_address.is_global:
            return _err(
                "Research host resolved to a local, private, reserved, or link-local address."
            ), None, []
        key = (family, socket_type, protocol, socket_address)
        if key in seen:
            continue
        seen.add(key)
        destinations.append((family, socket_type, protocol, canonical_name, socket_address))
    if not destinations:
        return _err("Research host did not resolve before any request was sent."), None, []
    return None, parsed, destinations


def _pinned_research_socket(destination: tuple, timeout: float, source_address=None):
    """Connect to one already checked address without performing another lookup."""
    family, socket_type, protocol, _canonical_name, socket_address = destination
    sock = socket.socket(family, socket_type, protocol)
    try:
        sock.settimeout(timeout)
        if source_address:
            sock.bind(source_address)
        sock.connect(socket_address)
        return sock
    except BaseException:
        sock.close()
        raise


def _research_request_once(parsed, destinations: list[tuple], timeout: float):
    """Issue one direct GET to a checked address while retaining the URL hostname."""
    hostname = (parsed.hostname or "").rstrip(".")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    deadline = time.monotonic() + timeout
    last_error: BaseException | None = None
    for destination in destinations:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        if parsed.scheme == "https":
            connection = http.client.HTTPSConnection(
                hostname, port, timeout=remaining, context=ssl.create_default_context(),
            )
        else:
            connection = http.client.HTTPConnection(hostname, port, timeout=remaining)

        def create_connection(_address, connection_timeout=remaining,
                              source_address=None, *, pinned=destination):
            effective_timeout = (
                remaining if connection_timeout is socket._GLOBAL_DEFAULT_TIMEOUT
                else float(connection_timeout)
            )
            return _pinned_research_socket(pinned, effective_timeout, source_address)

        connection._create_connection = create_connection
        try:
            connection.request("GET", path, headers={"User-Agent": "Grypton-Research/3.0"})
            response = connection.getresponse()
            status = int(response.status)
            reason = str(response.reason or "")
            location = response.getheader("Location")
            payload = response.read(MAX_RESPONSE_BYTES)
            return status, reason, location, payload
        except (OSError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            connection.close()
    if last_error is not None:
        raise last_error
    raise TimeoutError("research connection deadline reached")


def research(workspace: Workspace, url: str, *, timeout: int = 30) -> dict:
    timeout_seconds = max(1, min(int(timeout), 60))
    current_url = url
    try:
        for redirect_count in range(_RESEARCH_MAX_REDIRECTS + 1):
            blocked, parsed, destinations = _research_resolved_destinations(
                workspace, current_url
            )
            if blocked:
                return blocked
            status, reason, location, payload = _research_request_once(
                parsed, destinations, timeout_seconds
            )
            if status in _RESEARCH_REDIRECT_STATUSES:
                if not location:
                    return _err("Research redirect did not provide a Location header.")
                if redirect_count >= _RESEARCH_MAX_REDIRECTS:
                    return _err("Research fetch exceeded the redirect limit.")
                current_url = urljoin(current_url, location)
                continue
            if status >= 400:
                return _err(f"Research fetch failed: HTTP {status} {reason}".rstrip())
            final_allowed, final_reason = check_research_scope(workspace, current_url)
            if not final_allowed:
                return _err(f"Scope blocked research URL: {final_reason}.")
            data = payload.decode("utf-8", "replace")
            return _ok(
                f"Fetched approved documentation from {urlsplit(url).hostname} "
                f"({len(data)} characters).",
                {"text": data, "final_url": current_url},
            )
        return _err("Research fetch exceeded the redirect limit.")
    except Exception as exc:
        return _err(f"Research fetch failed: {redact_sensitive_text(exc)}")


def inventory() -> dict:
    binaries = ["curl", "httpx", "playwright", "google-chrome", "chromium", "subfinder",
                "nmap", "nuclei", "ffuf", "jq", "openssl", "python3", "node", "go", "cargo",
                "aapt", "apksigner", "keytool", "unzip", "strings"]
    return _ok("Tool inventory collected.",
               {"binaries": {name: config.find_binary(name) for name in binaries},
                "goja": Goja.status()["data"]})
