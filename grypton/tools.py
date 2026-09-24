"""Scoped, observable tools shared by Grypton's MCP server and CLI."""
from __future__ import annotations

import base64
import codecs
from contextlib import contextmanager
import fcntl
import hashlib
from html.parser import HTMLParser
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
from urllib.parse import (parse_qsl, quote, quote_plus, unquote, urlencode,
                          urljoin, urlsplit, urlunsplit)
import zipfile

from . import config, credentials
from .workspace import Workspace

MAX_RESPONSE_BYTES = 2_000_000
MAX_INLINE_RESPONSE_CHARS = 12_000
DEFAULT_FLOW_READ_CHARS = 16_384
MAX_FLOW_READ_CHARS = 32_768
_FLOW_LIST_LINE_CHARS = 64 * 1024
_FLOW_LIST_FIELD_CHARS = 4096
_MAX_FLOW_QUERY_CHARS = 4096
_AUTH_REVALIDATE_INTERVAL_S = 300
_AUTH_EXPIRY_SKEW_S = 60

_SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
})
_SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|"
    r"x-api-key|x-auth-token|x-csrf-token|x-xsrf-token)\s*:\s*).*$"
)
_URL_USERINFO_RE = re.compile(
    r"(?i)\b((?:https?|wss?|ftp)://)[^/\s:@]+(?::[^/\s@]*)?@"
)
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    ((?:["']?(?:authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|
       credentials?|password|passwd|secret|token|access[_-]?token|refresh[_-]?token|
       id[_-]?token|auth[_-]?token|session[_-]?token|api[_-]?key|client[_-]?secret|
       private[_-]?key|x[_-]?api[_-]?key|x[_-]?auth[_-]?token|
       x[_-]?(?:csrf|xsrf)[_-]?token)["']?)
       \s*[:=]\s*)
    (?:"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^&\s,;}\]]+)
    """
)
_AUTH_SCHEME_RE = re.compile(
    r"(?i)(\b(?:bearer|basic)\s+)"
    r"(?=[A-Za-z0-9._~+/=-]{8,})(?=[A-Za-z0-9._~+/=-]*[0-9._~+/=-])"
    r"[A-Za-z0-9._~+/=-]+"
)

_BROWSER_IDENTITY_KEYS = frozenset({
    "username", "identifier", "identity",
    "email", "emailaddress", "phone", "phonenumber", "telephone",
    "mobile", "mobilenumber", "firstname", "lastname", "fullname",
    "displayname", "legalname", "birthdate", "dateofbirth",
    "nationalid", "nationalcode", "customerid", "accountid", "userid",
    "useruuid", "invitationcode", "invitecode",
    "postalcode", "zipcode", "address",
})
_BROWSER_IDENTITY_ASSIGNMENT_RE = re.compile(
    r'''(?ix)
    ((?:["']?(?:user[_-]?name|identifier|identity|email(?:[_-]?address)?|
       phone(?:[_-]?number)?|telephone|mobile(?:[_-]?number)?|first[_-]?name|
       last[_-]?name|full[_-]?name|display[_-]?name|legal[_-]?name|birth[_-]?date|
       date[_-]?of[_-]?birth|national[_-]?(?:id|code)|customer[_-]?id|
       account[_-]?id|user[_-]?(?:id|uuid)|invitation[_-]?code|invite[_-]?code|
       postal[_-]?code|zip[_-]?code|address)["']?)
       \s*[:=]\s*)
    (?:"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^&\s,;}\]<>]+)
    '''
)


def redact_sensitive_text(value: object, secret_values: Iterable[str] = ()) -> str:
    """Remove credentials, cookies, and login tokens from observable text."""
    text = str(value or "")
    for secret in sorted({str(item) for item in secret_values if str(item)},
                         key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    text = _URL_USERINFO_RE.sub(r"\1[REDACTED]@", text)
    text = _SENSITIVE_HEADER_RE.sub(r"\1[REDACTED]", text)
    text = _AUTH_SCHEME_RE.sub(r"\1[REDACTED]", text)
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


def _login_username_redaction_values(username: str,
                                     selected_transform: str = "stored") -> tuple[str, ...]:
    """Return plausible app-side forms of a private login identifier."""
    raw = str(username)
    output = {raw}
    compact = re.sub(r"[\s()\-]+", "", raw.strip())
    if len(compact) >= 4:
        output.add(compact)
    if "@" in raw:
        output.add(raw.strip().lower())
    for transform in dict.fromkeys((selected_transform, "stored", "iran-e164")):
        try:
            transformed = credentials.normalize_login_username(raw, transform)
        except credentials.CredentialError:
            continue
        output.add(transformed)
        if transformed.startswith("+98") and len(transformed) > 3:
            national = transformed[3:]
            output.update({"0" + national, "98" + national, "0098" + national})
    return tuple(sorted((item for item in output if item), key=len, reverse=True))


def _browser_identity_values(texts: Iterable[str]) -> tuple[str, ...]:
    """Extract bounded identity values so echoes can be removed across artifacts."""
    output: set[str] = set()

    def remember(value) -> None:
        if isinstance(value, bool) or value is None:
            return
        if not isinstance(value, (str, int, float)):
            return
        rendered = str(value).strip()
        if (not rendered or len(rendered) > 4096
                or any(ord(char) < 0x20 for char in rendered)):
            return
        output.add(rendered)

    def walk(value, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
                if normalized in _BROWSER_IDENTITY_KEYS:
                    if isinstance(child, list):
                        for item in child[:50]:
                            remember(item)
                    else:
                        remember(child)
                if isinstance(child, (dict, list)):
                    walk(child, depth + 1)
        elif isinstance(value, list):
            for child in value[:100]:
                walk(child, depth + 1)

    for text in texts:
        try:
            parsed = json.loads(str(text))
        except (TypeError, ValueError):
            continue
        walk(parsed)
    return tuple(sorted(output, key=len, reverse=True))


def _browser_redact_identity_text(value: object,
                                  secret_values: Iterable[str] = (),
                                  identity_values: Iterable[str] = ()) -> str:
    """Redact identity echoes in browser-auth artifacts only."""
    text = redact_sensitive_text(value, secret_values)
    for identity in sorted({str(item) for item in identity_values if str(item)},
                           key=len, reverse=True):
        if len(identity) >= 2 and re.fullmatch(r"[\w]+", identity):
            text = re.sub(
                rf"(?<![\w]){re.escape(identity)}(?![\w])",
                "[REDACTED]", text,
            )
        elif len(identity) >= 2:
            text = text.replace(identity, "[REDACTED]")
    return _BROWSER_IDENTITY_ASSIGNMENT_RE.sub(r"\1[REDACTED]", text)


def _browser_redacted_capture_value(value, secret_values: Iterable[str],
                                    identity_values: Iterable[str] = ()):
    """Recursively sanitize browser-auth data without changing generic captures."""
    secrets = tuple(str(item) for item in secret_values if str(item))
    identities = tuple(str(item) for item in identity_values if str(item))
    if isinstance(value, dict):
        output = {}
        for key, child in value.items():
            safe_key = _browser_redact_identity_text(key, secrets, identities)
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            output[safe_key] = (
                "[REDACTED]" if normalized in _BROWSER_IDENTITY_KEYS
                else _browser_redacted_capture_value(child, secrets, identities)
            )
        return output
    if isinstance(value, list):
        return [
            _browser_redacted_capture_value(child, secrets, identities)
            for child in value
        ]
    if isinstance(value, tuple):
        return tuple(
            _browser_redacted_capture_value(child, secrets, identities)
            for child in value
        )
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return _browser_redact_identity_text(value, secrets, identities)
        if isinstance(parsed, (dict, list)):
            return json.dumps(
                _browser_redacted_capture_value(parsed, secrets, identities),
                ensure_ascii=False, separators=(",", ":"),
            )
        return _browser_redact_identity_text(value, secrets, identities)
    return value


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


def _browser_auth_verify_headers(headers: Optional[dict]) -> dict[str, str]:
    """Validate non-secret protocol headers for an exact-origin proof request."""
    if headers is None:
        return {}
    if not isinstance(headers, dict):
        raise ValueError("Browser verification headers must be an object.")
    if len(headers) > 32:
        raise ValueError("Browser verification accepts at most 32 protocol headers.")
    normalized_names: set[str] = set()
    for raw_key, raw_value in headers.items():
        key, value = str(raw_key), str(raw_value)
        if (not key or len(key) > 128
                or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key)):
            raise ValueError("Browser verification contains an invalid header name.")
        if (len(value) > 8192 or "\r" in value or "\n" in value
                or any(ord(char) < 0x20 and char != "\t" for char in value)
                or "\x7f" in value):
            raise ValueError(
                f"Browser verification header {key!r} contains an invalid value."
            )
        normalized = key.lower()
        if normalized in normalized_names:
            raise ValueError(
                "Browser verification headers contain a case-insensitive duplicate."
            )
        normalized_names.add(normalized)
    output = _safe_headers(headers)
    forbidden = _SENSITIVE_HEADERS | {
        "connection", "content-length", "host", "proxy-connection",
        "te", "trailer", "transfer-encoding", "upgrade",
    }
    rejected = sorted(key for key in output if key.lower() in forbidden)
    if rejected:
        raise ValueError(
            "Browser verification headers cannot contain authentication, session, "
            "destination, or hop-by-hop headers: " + ", ".join(rejected)
        )
    return output


def _browser_request_headers(headers: Optional[dict]) -> dict[str, str]:
    """Validate caller headers that are applied only to one browser fetch."""
    if headers is None:
        return {}
    if not isinstance(headers, dict) or len(headers) > 32:
        raise ValueError("Browser request headers must be an object with at most 32 entries.")
    forbidden = _SENSITIVE_HEADERS | {
        "connection", "content-length", "host", "origin", "proxy-connection",
        "referer", "te", "trailer", "transfer-encoding", "upgrade",
    }
    output: dict[str, str] = {}
    normalized_names: set[str] = set()
    for raw_key, raw_value in headers.items():
        if not isinstance(raw_key, str) or not isinstance(raw_value, str):
            raise ValueError("Browser request header names and values must be strings.")
        key = raw_key.strip()
        if (
            not key or len(key) > 128
            or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key)
        ):
            raise ValueError("Browser request contains an invalid header name.")
        normalized = key.lower()
        if normalized in normalized_names:
            raise ValueError("Browser request headers contain a case-insensitive duplicate.")
        if normalized in {"__proto__", "prototype", "constructor"}:
            raise ValueError(
                f"Browser request header {key!r} uses a reserved object property name."
            )
        if normalized in forbidden or normalized.startswith(
            ("proxy-", "sec-", "x-grypton-")
        ):
            raise ValueError(
                f"Browser request header {key!r} cannot set session, routing, or "
                "hop-by-hop state."
            )
        if (
            len(raw_value) > 8192 or "\r" in raw_value or "\n" in raw_value
            or any(ord(char) < 0x20 and char != "\t" for char in raw_value)
            or "\x7f" in raw_value
        ):
            raise ValueError(f"Browser request header {key!r} has an invalid value.")
        normalized_names.add(normalized)
        output[key] = raw_value
    return output


def _browser_request_header_sources(value: Optional[dict],
                                    caller_headers: dict) -> list[dict]:
    """Validate declarative browser-state lookups without accepting script."""
    if value is None:
        return []
    if not isinstance(value, dict) or len(value) > 16:
        raise ValueError("Browser header sources must be an object with at most 16 entries.")
    forbidden = {
        "connection", "content-length", "cookie", "host", "origin",
        "proxy-authorization", "proxy-connection", "referer", "te", "trailer",
        "transfer-encoding", "upgrade",
    }
    seen = {key.lower() for key in caller_headers}
    output: list[dict] = []
    for raw_header, raw_source in value.items():
        if not isinstance(raw_header, str) or not re.fullmatch(
            r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}", raw_header
        ):
            raise ValueError("Browser header sources contain an invalid header name.")
        normalized = raw_header.lower()
        if normalized in seen:
            raise ValueError("Browser request headers contain a case-insensitive duplicate.")
        if normalized in {"__proto__", "prototype", "constructor"}:
            raise ValueError(
                f"Derived browser header {raw_header!r} uses a reserved object property name."
            )
        if normalized in forbidden or normalized.startswith(
            ("proxy-", "sec-", "x-grypton-")
        ):
            raise ValueError(
                f"Derived browser header {raw_header!r} cannot alter cookie, routing, "
                "or hop-by-hop state."
            )
        if not isinstance(raw_source, dict) or set(raw_source) - {
            "source", "name", "prefix", "url_decode",
        }:
            raise ValueError("Each browser header source must be a bounded lookup object.")
        source = raw_source.get("source")
        name = raw_source.get("name")
        prefix = raw_source.get("prefix", "")
        url_decode = raw_source.get("url_decode", False)
        if source not in {"localStorage", "sessionStorage", "cookie", "meta"}:
            raise ValueError("Browser header source type is invalid.")
        if not isinstance(name, str) or len(name) > 512:
            raise ValueError("Browser header source names must be strings up to 512 characters.")
        if source in {"cookie", "meta"} and (
            not name or any(ord(char) < 0x20 or ord(char) == 0x7f for char in name)
        ):
            raise ValueError("Cookie and meta header source names must be printable.")
        if (
            not isinstance(prefix, str) or len(prefix) > 128
            or "\r" in prefix or "\n" in prefix
            or any(ord(char) < 0x20 and char != "\t" for char in prefix)
            or "\x7f" in prefix
        ):
            raise ValueError("Browser header source prefix is invalid.")
        if not isinstance(url_decode, bool):
            raise ValueError("Browser header source url_decode must be a boolean.")
        seen.add(normalized)
        output.append({
            "header": raw_header, "source": source, "name": name,
            "prefix": prefix, "url_decode": url_decode,
        })
    return output


def _browser_private_response_values(body: str, headers: dict) -> tuple[str, ...]:
    """Find response-side token/CSRF values before any observable artifact is written."""
    values: set[str] = set()
    sensitive_names = {
        "token", "tokens", "accesstoken", "refreshtoken", "idtoken",
        "authtoken", "bearertoken", "bearer", "jwt", "secret", "secrets",
        "csrf", "csrftoken", "xsrf", "xsrftoken", "session", "sessionid",
        "sessiontoken", "authorization", "authorizationcode", "cookie",
        "cookies", "setcookie", "apikey", "credential", "credentials", "password",
        "passwd", "oauth", "oauthcode", "code",
    }

    def key_is_sensitive(key: object) -> bool:
        normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
        return (
            normalized in sensitive_names
            or normalized.endswith(("token", "secret", "password", "credential"))
        )

    def remember(value: object) -> None:
        if isinstance(value, str) and value:
            values.add(value)

    class PrivateHTMLValues(HTMLParser):
        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            if tag.lower() not in {"input", "meta"}:
                return
            row = {
                str(key).lower(): str(value)
                for key, value in attrs[:64] if value is not None
            }
            if tag.lower() == "input" and key_is_sensitive(row.get("name", "")):
                remember(row.get("value", ""))
            elif tag.lower() == "meta" and key_is_sensitive(
                row.get("name") or row.get("property") or row.get("http-equiv") or ""
            ):
                remember(row.get("content", ""))

    for key, value in headers.items():
        if key_is_sensitive(key):
            remember(value)
        if isinstance(value, str):
            normalized_header = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if normalized_header == "setcookie":
                for line in value.replace("\r", "\n").split("\n"):
                    pair = line.split(";", 1)[0]
                    _name, separator, cookie_value = pair.partition("=")
                    if separator:
                        remember(cookie_value.strip())
            if normalized_header in {"authorization", "proxyauthorization"}:
                scheme = re.match(
                    r"(?i)^\s*(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{1,})",
                    value,
                )
                if scheme:
                    remember(scheme.group(1))
            try:
                parsed_header_url = urlsplit(value)
            except ValueError:
                parsed_header_url = None
            if parsed_header_url is not None:
                for query_key, query_value in parse_qsl(
                    parsed_header_url.query, keep_blank_values=True
                ):
                    if key_is_sensitive(query_key):
                        remember(query_value)
                for fragment_key, fragment_value in parse_qsl(
                    parsed_header_url.fragment, keep_blank_values=True
                ):
                    if key_is_sensitive(fragment_key):
                        remember(fragment_value)
    try:
        parsed = json.loads(body)
    except (TypeError, ValueError):
        parsed = None

    def walk(item, depth: int = 0, inherited_sensitive: bool = False) -> None:
        if depth > 8:
            return
        if isinstance(item, dict):
            for key, child in list(item.items())[:200]:
                child_sensitive = inherited_sensitive or key_is_sensitive(key)
                if child_sensitive and isinstance(child, (str, int, float)):
                    remember(str(child))
                elif isinstance(child, (dict, list)):
                    walk(child, depth + 1, child_sensitive)
        elif isinstance(item, list):
            for child in item[:200]:
                if inherited_sensitive and isinstance(child, (str, int, float)):
                    remember(str(child))
                else:
                    walk(child, depth + 1, inherited_sensitive)

    walk(parsed)
    # Browser responses commonly return form/query bodies or put one-use values
    # in inert HTML.  Extract those values before any response or flow is made
    # observable; the input is already bounded by MAX_RESPONSE_BYTES.
    try:
        for form_key, form_value in parse_qsl(body, keep_blank_values=True):
            if key_is_sensitive(form_key):
                remember(form_value)
            for match in re.finditer(
                r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{8,})",
                form_value,
            ):
                remember(match.group(1))
    except (TypeError, ValueError):
        pass
    assignment = re.compile(
        r'''(?ix)(?<![A-Za-z0-9_])
        (["']?[A-Za-z][A-Za-z0-9_.-]{0,127}["']?)\s*[:=]\s*
        ("(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^&\s,;}\]<>]+)'''
    )
    for match in assignment.finditer(body):
        if not key_is_sensitive(match.group(1).strip("\"'")):
            continue
        raw = match.group(2)
        remember(raw[1:-1] if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'" else raw)
    for match in re.finditer(
        r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{8,})", body
    ):
        remember(match.group(1))
    try:
        parser = PrivateHTMLValues(convert_charrefs=True)
        parser.feed(body)
        parser.close()
    except (TypeError, ValueError):
        pass
    return tuple(values)


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
    match = re.search(r"\b(\d{3})\b", status_line)
    status = int(match.group(1)) if match else 0
    observed = _browser_auth_blocker(response, (status,) if status else ())
    if "MFA/OTP" in observed:
        return "interactive MFA/OTP is required; Grypton will not bypass or retry it"
    if "CAPTCHA" in observed:
        return "a CAPTCHA challenge is active; Grypton will not bypass or retry it"
    if status == 429:
        return "the authentication endpoint rate-limited the attempt"
    if status in {401, 403}:
        return "the supplied credential was rejected or blocked"
    return ""


def _endpoint_auth_observation(response: str, status_line: str) -> dict[str, object]:
    """Describe one endpoint response without judging the proven session."""
    challenge = _browser_auth_blocker(response, ())
    if "MFA/OTP" in challenge:
        return {
            "kind": "step-up-required",
            "detail": "the endpoint presented an MFA/OTP step-up",
            "conclusive_for_session": False,
            "state_changed": False,
        }
    if "CAPTCHA" in challenge:
        return {
            "kind": "challenge",
            "detail": "the endpoint presented a CAPTCHA challenge",
            "conclusive_for_session": False,
            "state_changed": False,
        }
    match = re.search(r"\b(\d{3})\b", status_line)
    status = int(match.group(1)) if match else 0
    if status == 429:
        return {
            "kind": "rate-limited",
            "detail": "the endpoint returned HTTP 429 rate limiting",
            "conclusive_for_session": False,
            "state_changed": False,
        }
    if status == 401:
        return {
            "kind": "endpoint-unauthenticated",
            "detail": "the endpoint returned HTTP 401 unauthenticated",
            "conclusive_for_session": False,
            "state_changed": False,
        }
    if status == 403:
        return {
            "kind": "endpoint-forbidden",
            "detail": "the endpoint returned HTTP 403 forbidden",
            "conclusive_for_session": False,
            "state_changed": False,
        }
    return {
        "kind": "access-denied",
        "detail": "the endpoint denied this request",
        "conclusive_for_session": False,
        "state_changed": False,
    }


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
                 _capture_body: Optional[str] = None,
                 _response_observation: Optional[dict] = None) -> dict:
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
    if isinstance(_response_observation, dict):
        _response_observation["set_cookie"] = bool(
            re.search(r"(?im)^\s*set-cookie\s*:", output)
        )
        _response_observation["clear_site_data"] = bool(
            re.search(r"(?im)^\s*clear-site-data\s*:", output)
        )
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


def _http_result_status(result: dict) -> int:
    data = result.get("data") if isinstance(result.get("data"), dict) else {}
    match = re.search(r"\b(\d{3})\b", str(data.get("status_line") or ""))
    return int(match.group(1)) if match else 0


def _http_result_header(result: dict, name: str) -> str:
    """Read one response header from the final captured HTTP header block."""
    data = result.get("data") if isinstance(result.get("data"), dict) else {}
    response = str(data.get("response") or "")
    status_starts = list(re.finditer(r"(?im)^HTTP/[^\r\n]+", response))
    if not status_starts:
        return ""
    header_block = re.split(
        r"\r?\n\r?\n", response[status_starts[-1].start():], maxsplit=1
    )[0]
    matches = re.findall(
        rf"(?im)^{re.escape(name)}\s*:\s*([^\r\n]*)\r?$", header_block
    )
    return matches[-1].strip() if matches else ""


def _request_url_identity(url: str) -> tuple[str, str, str]:
    """Compare redirect destinations as requests, ignoring URL fragments."""
    parsed = urlsplit(url)
    return credentials.normalize_origin(url), parsed.path or "/", parsed.query


@contextmanager
def _temporary_cookie_jar(workspace: Workspace):
    """Create a private short-lived cookie jar outside observable workspace state."""
    directory = config.RUNTIME_DIR / "http-tmp" / workspace.slug
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    fd, raw_path = tempfile.mkstemp(prefix=".auth-bootstrap-", suffix=".cookies", dir=directory)
    path = Path(raw_path)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write("# Netscape HTTP Cookie File\n")
        yield path
    finally:
        path.unlink(missing_ok=True)


def _install_cookie_jar(source: Path, destination: Path) -> None:
    """Atomically seed the credential jar with bounded anonymous edge cookies."""
    info = source.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or source.is_symlink():
        raise credentials.CredentialError("bootstrap cookie jar is not a regular file")
    if info.st_size > 1_000_000:
        raise credentials.CredentialError("bootstrap cookie jar exceeded the private size limit")
    payload = source.read_bytes()
    temporary = destination.parent / f".{destination.name}.{time.time_ns()}.tmp"
    fd = os.open(
        temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        os.chmod(destination, 0o600, follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)


def _snapshot_private_material(path: Path) -> tuple[bool, bytes, int]:
    """Read a bounded private file so a denied request can be rolled back."""
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return False, b"", 0o600
    except OSError as exc:
        raise credentials.CredentialError(
            "private session material could not be opened safely"
        ) from exc
    try:
        info = os.fstat(fd)
        mode = stat.S_IMODE(info.st_mode)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or mode & 0o077
        ):
            raise credentials.CredentialError(
                "private session material is not a private regular file"
            )
        if info.st_size > 1_000_000:
            raise credentials.CredentialError(
                "private session material exceeded the size limit"
            )
        chunks: list[bytes] = []
        remaining = 1_000_001
        while remaining:
            chunk = os.read(fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > 1_000_000:
            raise credentials.CredentialError(
                "private session material exceeded the size limit"
            )
        return True, payload, mode
    finally:
        os.close(fd)


def _restore_private_material(
    path: Path, snapshot: tuple[bool, bytes, int]
) -> None:
    """Atomically restore the exact private-file state captured before a call."""
    existed, payload, mode = snapshot
    if not existed:
        path.unlink(missing_ok=True)
        return
    temporary = path.parent / f".{path.name}.{time.time_ns()}.rollback"
    fd = os.open(
        temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
        mode,
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode, follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)


def _credential_bootstrap(workspace: Workspace, url: str, *, credential: str,
                          cookie_jar: Path, timeout: int) -> dict:
    """Clear a one-hop cookie gate anonymously before any credential attempt."""
    flows: list[str] = []
    redirect_codes = {301, 302, 303, 307, 308}
    for request_number in range(2):
        cookies_before = credentials.cookie_jar_fingerprints(cookie_jar)
        response = http_request(
            workspace, url, method="GET", timeout=timeout,
            transport=f"credential-bootstrap:{credential}", _cookie_jar=cookie_jar,
        )
        data = response.get("data") if isinstance(response.get("data"), dict) else {}
        if data.get("flow"):
            flows.append(str(data["flow"]))
        if not response.get("ok"):
            response["summary"] = (
                "Anonymous login bootstrap failed before credentials were sent: "
                + str(response.get("summary") or "transport failure")
            )
            if isinstance(data, dict):
                data["bootstrap_flows"] = flows
            return response

        status = _http_result_status(response)
        if status in redirect_codes:
            location = _http_result_header(response, "Location")
            if not location:
                return _err(
                    "Anonymous login bootstrap stopped at a redirect without a "
                    "Location header; credentials were not sent.",
                    {"bootstrap_flows": flows},
                )
            destination = urljoin(url, location)
            blocked = _scope_error(workspace, destination)
            if blocked:
                return _err(
                    "Anonymous login bootstrap refused an out-of-scope redirect; "
                    "credentials were not sent.",
                    {"bootstrap_flows": flows},
                )
            try:
                is_self_redirect = (
                    _request_url_identity(destination) == _request_url_identity(url)
                )
            except credentials.CredentialError:
                is_self_redirect = False
            if not is_self_redirect:
                return _err(
                    "Anonymous login bootstrap stopped at a different redirect URL; "
                    "update the login endpoint explicitly before sending credentials.",
                    {"bootstrap_flows": flows},
                )
            cookies_after = credentials.cookie_jar_fingerprints(cookie_jar)
            if not (cookies_after - cookies_before):
                return _err(
                    "Anonymous login bootstrap self-redirected without issuing new "
                    "cookie state; credentials were not sent.",
                    {"bootstrap_flows": flows},
                )
            if request_number == 1:
                return _err(
                    "Anonymous login bootstrap remained in a self-redirect loop after "
                    "two captured requests; credentials were not sent.",
                    {"bootstrap_flows": flows},
                )
            continue

        if 300 <= status < 400:
            return _err(
                "Anonymous login bootstrap returned an unsupported redirect; "
                "credentials were not sent.",
                {"bootstrap_flows": flows},
            )
        if not status or status == 429 or status >= 500:
            return _err(
                f"Anonymous login bootstrap stopped at HTTP {status or 'unknown'}; "
                "credentials were not sent.",
                {"bootstrap_flows": flows},
            )
        return _ok(
            f"Anonymous login transport was ready after {request_number + 1} "
            "captured request(s).",
            {"bootstrap_flows": flows},
        )

    return _err(
        "Anonymous login bootstrap did not reach a stable response; credentials were not sent.",
        {"bootstrap_flows": flows},
    )


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
                     username_transform: str = "stored",
                     encoding: str = "json", fields: Optional[dict] = None,
                     headers: Optional[dict] = None, timeout: int = 30) -> dict:
    """Serialize one complete HTTP login proof with other session writers."""
    try:
        with credentials.auth_profile_lock(workspace.slug, credential):
            with credentials.session_material_lock(workspace.slug, credential):
                return _credential_login_locked(
                    workspace, url, credential=credential, verify_url=verify_url,
                    success_marker=success_marker, username_field=username_field,
                    password_field=password_field,
                    username_transform=username_transform, encoding=encoding,
                    fields=fields, headers=headers, timeout=timeout,
                )
    except credentials.CredentialError as exc:
        return _err(str(exc))


def _credential_login_locked(workspace: Workspace, url: str, *, credential: str,
                             verify_url: str, success_marker: str,
                             username_field: str = "username",
                             password_field: str = "password",
                             username_transform: str = "stored",
                             encoding: str = "json",
                             fields: Optional[dict] = None,
                             headers: Optional[dict] = None,
                             timeout: int = 30) -> dict:
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
    if username_transform not in {"stored", "iran-e164"}:
        return _err("Username transform must be stored or iran-e164.")
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
        login_username = credentials.normalize_login_username(
            secret["username"], username_transform
        )
        credentials.ensure_login_attempt_available(workspace.slug, credential)
    except credentials.CredentialError as exc:
        return _err(str(exc))

    with _temporary_cookie_jar(workspace) as bootstrap_jar:
        bootstrap = _credential_bootstrap(
            workspace, url, credential=credential, cookie_jar=bootstrap_jar,
            timeout=timeout,
        )
        if not bootstrap.get("ok"):
            return bootstrap
        bootstrap_data = (
            bootstrap.get("data") if isinstance(bootstrap.get("data"), dict) else {}
        )
        bootstrap_flows = list(bootstrap_data.get("bootstrap_flows") or [])

        values = dict(fields or {})
        values[username_field] = login_username
        values[password_field] = secret["password"]
        if encoding == "json":
            body = json.dumps(values, ensure_ascii=False, separators=(",", ":"))
            clean_headers.setdefault("Content-Type", "application/json")
        else:
            body = urlencode(values)
            clean_headers.setdefault(
                "Content-Type", "application/x-www-form-urlencoded"
            )
        raw_secrets = (secret["username"], login_username, secret["password"])
        capture_secrets = _serialized_secret_variants(raw_secrets)
        capture_body = _login_capture_body(
            values, username_field, password_field, encoding, raw_secrets
        )
        capture_headers = _redacted_headers(clean_headers, capture_secrets)
        try:
            jar = credentials.cookie_jar_path(workspace.slug, credential)
            _install_cookie_jar(bootstrap_jar, jar)
            attempt = credentials.begin_login_attempt(workspace.slug, credential)
            # Edge cookies were installed before this snapshot, so they cannot
            # be mistaken for session material issued by the credential POST.
            cookies_before = credentials.cookie_fingerprints(
                workspace.slug, credential
            )
        except (OSError, credentials.CredentialError) as exc:
            return _err(str(exc))

        login = http_request(
            workspace, url, method="POST", headers=clean_headers, body=body,
            timeout=timeout, transport=f"credential:{credential}",
            _secret_values=capture_secrets, _cookie_jar=jar,
            _session_identity=(workspace.slug, credential, login_origin),
            _capture_headers=capture_headers, _capture_body=capture_body,
        )
        login_data = login.get("data") if isinstance(login.get("data"), dict) else {}
        login_data["bootstrap_flows"] = bootstrap_flows
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
        if 300 <= _http_result_status(login) < 400:
            credentials.record_login_outcome(workspace.slug, credential)
            login["ok"] = False
            login["summary"] = (
                f"Login attempt {attempt} received a redirect after the anonymous "
                "bootstrap. No credential-bearing redirect was followed or retried."
            )
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
            _secret_values=(*capture_secrets, *tokens.values()),
            _cookie_jar=jar, _bearer_token=credentials.select_bearer(tokens),
            _bearer_origin=login_origin,
            _session_identity=(workspace.slug, credential, login_origin),
        )
        verify_data = (
            verification.get("data")
            if isinstance(verification.get("data"), dict) else {}
        )
        verify_response = str(verify_data.get("response") or "")
        verify_body = re.split(r"\r?\n\r?\n", verify_response)[-1]
        verify_status = str(verify_data.get("status_line") or "")
        # Prove that the marker depends on auth material while retaining the
        # same anonymous edge cookies that allowed the verification request to
        # reach the application origin.
        control = http_request(
            workspace, verify_url, method="GET", timeout=timeout,
            transport=f"credential-control:{credential}",
            _secret_values=(*capture_secrets, *tokens.values()),
            _cookie_jar=bootstrap_jar,
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
        verify_data["bootstrap_flows"] = bootstrap_flows
        verify_data["login_flow"] = login_data.get("flow")
        verify_data["control_flow"] = control_data.get("flow")
        verify_data["session"] = credentials.session_status(
            workspace.slug, credential
        )
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
                               body: Optional[str] = None, timeout: int = 30,
                               _profile_headers: Optional[dict] = None,
                               _accepted_statuses: Iterable[int] = ()) -> dict:
    """Use a named private session without exposing credential material."""
    try:
        clean_headers = _safe_headers(headers)
        private_headers = _browser_auth_verify_headers(_profile_headers)
        normalized = {key.lower() for key in private_headers}
        clean_headers = {
            key: value for key, value in clean_headers.items()
            if key.lower() not in normalized
        }
        clean_headers.update(private_headers)
        accepted_statuses = {
            int(value) for value in _accepted_statuses
            if isinstance(value, int) and not isinstance(value, bool)
        }
    except ValueError as exc:
        return _err(str(exc))
    try:
        with credentials.auth_profile_lock(workspace.slug, credential):
            secret = credentials.load_credential(workspace.slug, credential)
            with credentials.session_material_lock(workspace.slug, credential):
                tokens = credentials.load_tokens(workspace.slug, credential)
                session = credentials.session_status(workspace.slug, credential)
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
                        f"Named credential {credential!r} has no valid private origin "
                        "binding; authenticate it again before use."
                    )
                if request_origin != bound_origin:
                    return _err(
                        f"Refused authenticated request for {credential!r}: the URL does "
                        "not match the session's exact login origin (scheme, host, and "
                        "effective port)."
                    )
                bearer = credentials.select_bearer(tokens)
                if (
                    bearer
                    and credentials.token_origin(workspace.slug, credential)
                    != bound_origin
                ):
                    return _err(
                        f"Refused bearer authorization for {credential!r}: its private "
                        "origin binding is missing or does not match the established "
                        "session."
                    )

                jar_storage = credentials.cookie_jar_storage_path(
                    workspace.slug, credential
                )
                token_file = credentials.token_path(workspace.slug, credential)
                storage_file = credentials.browser_storage_path(
                    workspace.slug, credential
                )
                cookie_snapshot = _snapshot_private_material(jar_storage)
                token_snapshot = _snapshot_private_material(token_file)
                storage_snapshot = _snapshot_private_material(storage_file)
                cookie_digest_before = credentials.cookie_jar_digest(jar_storage)
                response_observation: dict[str, bool] = {}
                commit_material = False
                material_restored = False
                try:
                    jar = credentials.cookie_jar_path(workspace.slug, credential)
                    result = http_request(
                        workspace, url, method=method, headers=clean_headers, body=body,
                        timeout=timeout, transport=f"authenticated:{credential}",
                        _secret_values=(
                            secret["username"], secret["password"], *tokens.values(),
                            *private_headers.values(),
                        ),
                        _cookie_jar=jar, _bearer_token=bearer,
                        _bearer_origin=bound_origin,
                        _session_identity=(workspace.slug, credential, bound_origin),
                        _response_observation=response_observation,
                    )
                    data = (
                        result.get("data")
                        if isinstance(result.get("data"), dict) else None
                    )
                    status = _http_result_status(result)
                    blocker = str(data.get("auth_blocker") or "") if data else ""
                    candidate_commit = bool(
                        result.get("ok")
                        and not blocker
                        and (200 <= status < 400 or status in accepted_statuses)
                    )
                    if candidate_commit:
                        try:
                            tokens_changed = (
                                credentials.load_tokens(workspace.slug, credential)
                                != tokens
                            )
                            if (
                                credentials.cookie_jar_digest(jar_storage)
                                != cookie_digest_before
                                or tokens_changed
                                or response_observation.get("set_cookie") is True
                                or response_observation.get("clear_site_data") is True
                            ):
                                # The transports share one proof generation.
                                # curl cannot update exact web storage or retain
                                # rich cookie attributes, so a committed token
                                # or cookie mutation invalidates browser state.
                                storage_file.unlink(missing_ok=True)
                            commit_material = True
                        except Exception:
                            _restore_private_material(jar_storage, cookie_snapshot)
                            _restore_private_material(token_file, token_snapshot)
                            _restore_private_material(storage_file, storage_snapshot)
                            material_restored = True
                            raise
                    else:
                        _restore_private_material(jar_storage, cookie_snapshot)
                        _restore_private_material(token_file, token_snapshot)
                        _restore_private_material(storage_file, storage_snapshot)
                        material_restored = True

                    if data is not None:
                        if blocker:
                            data.pop("auth_blocker", None)
                            data["auth_observation"] = _endpoint_auth_observation(
                                str(data.get("response") or ""),
                                str(data.get("status_line") or ""),
                            )
                            data["session_state_retained"] = True
                            data["session_material_rollback"] = True
                            result["ok"] = False
                            try:
                                profile = credentials.load_auth_profile_optional(
                                    workspace.slug, credential
                                )
                            except credentials.CredentialError:
                                profile = None
                            is_verification_endpoint = bool(
                                profile
                                and str(method or "GET").strip().upper() == "GET"
                                and _browser_auth_url_matches(
                                    url, str(profile.get("verify_url") or "")
                                )
                            )
                            if is_verification_endpoint:
                                result["summary"] = (
                                    f"The configured verification endpoint returned HTTP "
                                    f"{status or 'denial'} for this standalone request. The "
                                    "complete session proof was not rerun, so the established "
                                    "session and its private material were retained."
                                )
                            else:
                                result["summary"] = (
                                    f"Authenticated request for {credential!r} was denied at "
                                    f"this endpoint with HTTP {status or 'denial'}. The "
                                    "independently proven session and its private material "
                                    "were retained."
                                )
                        elif not commit_material:
                            data["session_state_retained"] = True
                            data["session_material_rollback"] = True
                        data["credential"] = credential
                        data["session"] = credentials.session_status(
                            workspace.slug, credential
                        )
                    return result
                finally:
                    if not commit_material and not material_restored:
                        _restore_private_material(jar_storage, cookie_snapshot)
                        _restore_private_material(token_file, token_snapshot)
                        _restore_private_material(storage_file, storage_snapshot)
    except (OSError, credentials.CredentialError) as exc:
        return _err(str(exc))
    except Exception:
        return _err(
            "Authenticated request failed; its private session material was restored."
        )


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


def _flow_contains_text(path: Path, query: str) -> bool:
    """Search a flow without materializing its potentially large body."""
    needle = query.casefold()
    overlap = ""
    overlap_chars = max(16, len(query) * 4)
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        while chunk := stream.read(_FLOW_LIST_LINE_CHARS):
            value = overlap + chunk
            if needle in value.casefold():
                return True
            overlap = value[-overlap_chars:]
    return False


def _flow_listing_metadata(path: Path) -> tuple[str, str]:
    """Read request/status lines with bounded memory."""
    request = path.name
    status = ""
    request_found = False
    at_line_start = True
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        while True:
            piece = stream.readline(_FLOW_LIST_LINE_CHARS)
            if not piece:
                break
            if at_line_start:
                if not request_found and re.match(r"^[A-Z]+ https?://", piece):
                    request = piece.rstrip("\r\n")
                    if len(request) > _FLOW_LIST_FIELD_CHARS:
                        request = request[:_FLOW_LIST_FIELD_CHARS - 3] + "..."
                    request_found = True
                if not status and piece.startswith("HTTP/"):
                    status = piece.rstrip("\r\n")[:_FLOW_LIST_FIELD_CHARS]
            at_line_start = piece.endswith("\n")
            if request_found and status:
                break
    return request, status


def proxy_flows(workspace: Workspace, *, query: str = "", limit: int = 20) -> dict:
    query = str(query or "")
    if len(query) > _MAX_FLOW_QUERY_CHARS:
        return _err("Flow query exceeds the 4096-character limit.")
    try:
        row_limit = max(1, min(int(limit), 200))
    except (TypeError, ValueError):
        return _err("Flow limit must be an integer between 1 and 200.")
    rows = []
    for listed_path in sorted(workspace.flows_dir.glob("flow-*.http"), reverse=True):
        # Apply the same containment check used by flow_read/flow_replay before
        # opening a listing candidate. This skips a flow-shaped symlink whose
        # target is outside the private engagement flow directory.
        path = _flow_path(workspace, listed_path.stem)
        if path is None:
            continue
        if query and not _flow_contains_text(path, query):
            continue
        request, status = _flow_listing_metadata(path)
        rows.append({"id": listed_path.stem, "file": str(path), "request": request,
                     "status": status, "bytes": path.stat().st_size})
        if len(rows) >= row_limit:
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


def flow_read(workspace: Workspace, flow_id: str, *, offset: int = 0,
              max_chars: int = DEFAULT_FLOW_READ_CHARS) -> dict:
    """Read one bounded UTF-8 window from a capture.

    ``offset`` and the returned continuation offsets are byte offsets. Captures
    are written as UTF-8, so an incremental decoder keeps sequential windows
    from splitting a trailing multibyte character.
    """
    path = _flow_path(workspace, flow_id)
    if path is None:
        return _err(f"Unknown flow {flow_id!r}.")
    try:
        byte_offset = int(offset)
        requested_chars = int(max_chars)
    except (TypeError, ValueError):
        return _err("Flow offset and max_chars must be integers.")
    if byte_offset < 0:
        return _err("Flow offset must be zero or greater.")
    if requested_chars < 256:
        return _err("Flow max_chars must be at least 256.")
    window_bytes = min(requested_chars, MAX_FLOW_READ_CHARS)
    total_bytes = path.stat().st_size
    if byte_offset > total_bytes:
        return _err(
            f"Flow offset {byte_offset} is beyond the {total_bytes}-byte capture."
        )
    with path.open("rb") as stream:
        stream.seek(byte_offset)
        raw = stream.read(window_bytes)
    at_eof = byte_offset + len(raw) >= total_bytes
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    value = decoder.decode(raw, final=at_eof)
    pending = b"" if at_eof else decoder.getstate()[0]
    consumed_bytes = len(raw) - len(pending)
    byte_end = byte_offset + consumed_bytes
    next_offset = byte_end if byte_end < total_bytes else None
    capped = requested_chars > MAX_FLOW_READ_CHARS
    return _ok(
        f"Read bytes {byte_offset}-{byte_end} of {total_bytes} from {path.name}.",
        {
            "id": path.stem,
            "file": str(path),
            "text": value,
            "byte_start": byte_offset,
            "byte_end": byte_end,
            "total_bytes": total_bytes,
            "next_offset": next_offset,
            "has_more": next_offset is not None,
            "requested_max_chars": requested_chars,
            "max_chars_applied": window_bytes,
            "request_capped": capped,
        },
    )


def _flow_replay_source(path: Path) -> str:
    """Read only the request side needed by replay, with the historic cap."""
    marker = b"\n### RESPONSE"
    captured = bytearray()
    with path.open("rb") as stream:
        while len(captured) < 2_000_000:
            chunk = stream.read(min(64 * 1024, 2_000_000 - len(captured)))
            if not chunk:
                break
            captured.extend(chunk)
            marker_at = captured.find(marker)
            if marker_at >= 0:
                return bytes(captured[:marker_at + len(marker)]).decode(
                    "utf-8", "replace"
                )[:500_000]
    return bytes(captured).decode("utf-8", "replace")[:500_000]


def flow_replay(workspace: Workspace, flow_id: str, *, url: str = "", method: str = "",
                headers: Optional[dict] = None, body: Optional[str] = None) -> dict:
    path = _flow_path(workspace, flow_id)
    if path is None:
        return _err(f"Unknown flow {flow_id!r}.")
    source = _flow_replay_source(path)
    split = source.split("### RESPONSE", 1)[0].split("### REQUEST\n", 1)
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
_BROWSER_USERNAME_SELECTOR = "[data-testid='login-username']"
_BROWSER_PASSWORD_SELECTOR = "[data-testid='login-password']"
_BROWSER_SUBMIT_SELECTOR = "[data-testid='login-submit']"


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


def _launch_scoped_browser_context(playwright, launch_profile: dict,
                                   workspace: Workspace,
                                   denied_requests: list[str],
                                   bound_header_origin: str = "",
                                   bound_headers: Optional[dict] = None,
                                   bound_header_state: Optional[dict] = None,
                                   credential_submission_state: Optional[dict] = None,
                                   exact_origin: str = "",
                                   network_state: Optional[dict] = None,
                                   launch_timeout_ms: Optional[int] = None):
    """Launch the shared browser boundary and scope-check every network route."""
    launch_options = {}
    if launch_timeout_ms is not None:
        launch_options["timeout"] = max(1, int(launch_timeout_ms))
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
              "--disable-background-networking", "--disable-webrtc-multiple-routes",
              "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
              "--disable-features=WebTransport"],
        **launch_options,
    )
    if hasattr(context, "route_web_socket"):
        # Browser WebSockets do not carry an HTTP path that Grypton's request
        # capture can audit, so keep them closed in scoped mode.
        context.route_web_socket("**/*", lambda web_socket: web_socket.close())

    def scope_route(route) -> None:
        request_url = route.request.url
        scheme = urlsplit(request_url).scheme.lower()
        if scheme in {"about", "blob", "data"}:
            route.continue_()
            return
        if network_state is not None:
            network_state["count"] = int(network_state.get("count") or 0) + 1
            limit = max(1, min(int(network_state.get("limit") or 100), 100))
            if network_state["count"] > limit:
                network_state["blocked"] = int(
                    network_state.get("blocked") or 0
                ) + 1
                if len(denied_requests) < 100:
                    denied_requests.append(request_url)
                route.abort("blockedbyclient")
                return
        allowed, _ = check_url_scope(workspace, request_url)
        if allowed and exact_origin:
            try:
                allowed = credentials.normalize_origin(request_url) == exact_origin
            except credentials.CredentialError:
                allowed = False
        if allowed:
            if (
                credential_submission_state
                and credential_submission_state.get("active")
            ):
                post_data = str(route.request.post_data or "")
                username_values = tuple(
                    credential_submission_state.get("username_values") or ()
                )
                password_values = tuple(
                    credential_submission_state.get("password_values") or ()
                )
                matches_submission = bool(
                    post_data
                    and any(value and value in post_data
                            for value in username_values)
                    and any(value and value in post_data
                            for value in password_values)
                )
                if matches_submission:
                    credential_submission_state["seen"] = int(
                        credential_submission_state.get("seen") or 0
                    ) + 1
                    if credential_submission_state["seen"] > 1:
                        credential_submission_state["blocked"] = int(
                            credential_submission_state.get("blocked") or 0
                        ) + 1
                        route.abort("blockedbyclient")
                        return
            request_headers = None
            active_origin = bound_header_origin
            active_headers = bound_headers
            if bound_header_state and bound_header_state.get("active"):
                active_origin = str(bound_header_state.get("origin") or "")
                state_headers = bound_header_state.get("headers")
                active_headers = state_headers if isinstance(state_headers, dict) else None
            if active_origin and active_headers:
                try:
                    same_origin = (
                        credentials.normalize_origin(request_url)
                        == active_origin
                    )
                except credentials.CredentialError:
                    same_origin = False
                if same_origin:
                    request_headers = dict(route.request.headers)
                    request_headers.update(active_headers)
            if request_headers is None:
                route.continue_()
            else:
                route.continue_(headers=request_headers)
        else:
            if network_state is not None:
                network_state["blocked"] = int(
                    network_state.get("blocked") or 0
                ) + 1
            if len(denied_requests) < 100:
                denied_requests.append(request_url)
            route.abort("blockedbyclient")

    context.route("**/*", scope_route)
    return context


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
                context = _launch_scoped_browser_context(
                    playwright, launch_profile, workspace, denied_requests
                )
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


def _browser_auth_selector(value: str, *, label: str, default: str) -> str:
    selector = str(value or default).strip()
    if (not selector or len(selector) > 500
            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in selector)):
        raise ValueError(f"{label} selector must be 1-500 printable characters")
    return selector


def _browser_auth_snapshot(page) -> tuple[str, str, str]:
    """Read one bounded rendered page snapshot without returning form values."""
    final_url = str(page.url or "")
    try:
        dom = str(page.locator("html").evaluate(
            "(el, limit) => el.outerHTML.slice(0, limit)",
            MAX_RESPONSE_BYTES,
        ) or "")
    except Exception:
        dom = ""
    try:
        visible = str(page.locator("body").evaluate(
            "el => (el.innerText || '').slice(0, 200000)"
        ) or "")
    except Exception:
        visible = ""
    return final_url, dom[:MAX_RESPONSE_BYTES], visible[:200_000]


def _browser_auth_blocker(text: str, statuses: Iterable[int] = ()) -> str:
    """Describe an observed authentication challenge or rejection factually."""
    raw = str(text or "")
    challenge = ""
    json_messages: list[str] = []

    def truthy(value) -> bool:
        if value is True:
            return True
        if isinstance(value, (int, float)):
            return value == 1
        return isinstance(value, str) and value.strip().lower() in {
            "1", "true", "yes", "required", "active", "challenge",
        }

    def walk(value, depth: int = 0) -> None:
        nonlocal challenge
        if challenge or depth > 4:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
                if truthy(child):
                    if normalized in {
                        "otp", "mfa", "2fa", "twofactor", "verificationcode",
                    } or any(term in normalized for term in (
                        "otprequired", "mfarequired", "2farequired",
                        "twofactorrequired", "verificationcoderequired",
                    )):
                        challenge = "MFA/OTP challenge was presented"
                        return
                    if normalized in {
                        "captcha", "recaptcha", "hcaptcha", "turnstile",
                    } or any(term in normalized for term in (
                        "captcharequired", "captchaactive", "captchachallenge",
                    )):
                        challenge = "CAPTCHA challenge was presented"
                        return
                walk(child, depth + 1)
        elif isinstance(value, list):
            for child in value[:100]:
                walk(child, depth + 1)
        elif isinstance(value, str):
            json_messages.append(value[:4000])

    parsed_any = False
    candidates = [raw, *re.split(r"\r?\n\r?\n|\r?\n", raw)]
    for chunk in dict.fromkeys(candidates):
        try:
            parsed = json.loads(chunk)
        except (TypeError, ValueError):
            continue
        parsed_any = True
        walk(parsed)
        if challenge:
            return challenge

    lowered = ("\n".join(json_messages) if parsed_any else raw).lower()

    affirmative_otp = re.search(
        r"(?:\b(?:mfa|2fa|two[- _]factor|one[- ]time(?: password| code)?|otp|"
        r"verification code)\b.{0,50}\b(?:required|challenge|requested|sent|enter|provide)\b|"
        r"\b(?:required|challenge|requested|sent|enter|provide)\b.{0,50}"
        r"\b(?:mfa|2fa|two[- _]factor|one[- ]time(?: password| code)?|otp|"
        r"verification code)\b)",
        lowered,
    )
    if affirmative_otp and not re.search(
        r"\b(?:not|isn't|is not|no)\s+(?:currently\s+)?(?:required|active)\b",
        lowered,
    ):
        return "MFA/OTP challenge was presented"
    affirmative_captcha = re.search(
        r"(?:\b(?:captcha|recaptcha|hcaptcha|turnstile)\b.{0,50}"
        r"\b(?:required|challenge|active|failed|verify|verification)\b|"
        r"\b(?:required|challenge|active|failed|verify|verification)\b.{0,50}"
        r"\b(?:captcha|recaptcha|hcaptcha|turnstile)\b)",
        lowered,
    )
    if affirmative_captcha and not re.search(
        r"\b(?:captcha|recaptcha|hcaptcha|turnstile)\b.{0,20}"
        r"\b(?:not required|inactive|disabled|false|null)\b",
        lowered,
    ):
        return "CAPTCHA challenge was presented"
    codes = {int(value) for value in statuses if str(value).isdigit()}
    if 429 in codes:
        return "authentication endpoint returned HTTP 429 rate limiting"
    if codes.intersection({401, 403}) or re.search(
        r"\b(?:invalid|incorrect|wrong|rejected)\s+(?:credential|credentials|"
        r"password|username|login)\b",
        lowered,
    ):
        return "supplied credential was rejected or blocked"
    return ""


def _browser_auth_locator(page, selector: str, *, role: str, timeout_ms: int):
    locator = page.locator(selector).first
    locator.wait_for(state="visible", timeout=timeout_ms)
    details = locator.evaluate(
        """el => ({tag: el.tagName.toLowerCase(),
                    type: (el.getAttribute('type') || '').toLowerCase(),
                    role: (el.getAttribute('role') || '').toLowerCase(),
                    disabled: !!el.disabled})"""
    )
    tag = str((details or {}).get("tag") or "")
    input_type = str((details or {}).get("type") or "")
    aria_role = str((details or {}).get("role") or "")
    disabled = bool((details or {}).get("disabled"))
    if disabled and role != "submit":
        raise ValueError(f"{role} control is disabled")
    if role == "username":
        accepted = tag == "textarea" or (
            tag == "input" and input_type in {
                "", "text", "email", "tel", "number", "search", "url"
            }
        )
    elif role == "password":
        accepted = tag == "input" and input_type == "password"
    else:
        accepted = (
            tag == "button"
            or (tag == "input" and input_type in {"button", "image", "submit"})
            or aria_role == "button"
        )
    if not accepted:
        raise ValueError(f"{role} selector did not resolve to a compatible form control")
    return locator


def _browser_auth_wait_for_submit(page, locator, timeout_ms: int) -> None:
    """Wait for client-side form validation to enable the submit control."""
    deadline = time.monotonic() + max(1, int(timeout_ms)) / 1000
    while True:
        try:
            enabled = bool(locator.evaluate(
                """el => el.isConnected && !el.disabled &&
                el.getAttribute('aria-disabled') !== 'true'"""
            ))
        except Exception:
            enabled = False
        if enabled:
            return
        remaining_ms = int((deadline - time.monotonic()) * 1000)
        if remaining_ms <= 0:
            raise ValueError(
                "submit control remained disabled after the form fields were populated"
            )
        page.wait_for_timeout(min(100, remaining_ms))


def _browser_auth_collect_responses(responses: list[dict],
                                    workspace: Workspace,
                                    secret_values: Iterable[str]):
    rows: list[dict] = []
    raw_bodies: list[str] = []
    statuses: list[int] = []
    secrets = tuple(secret_values)
    candidates = [
        observed for observed in responses[:8]
        if not observed.get("error")
    ]
    preferred = next((
        observed for observed in candidates
        if observed.get("matches_submission") is True
    ), None)
    if preferred is None:
        preferred = next((
        observed for observed in candidates
        if _browser_auth_response_url(str(observed.get("url") or ""))
        ), candidates[0] if candidates else None)
    for observed in responses[:8]:
        try:
            if observed.get("error"):
                rows.append({
                    "phase": str(observed.get("phase") or "login"),
                    "error": redact_sensitive_text(
                        str(observed.get("error")), secrets
                    )[:1000],
                })
                continue
            response_url = str(observed.get("url") or "")
            allowed, _ = check_url_scope(workspace, response_url)
            if not allowed:
                continue
            body = str(observed.get("body") or "")[:MAX_RESPONSE_BYTES]
            status = int(observed.get("status") or 0)
            if observed is preferred:
                statuses.append(status)
                raw_bodies.append(body)
            rows.append({
                "phase": str(observed.get("phase") or "login"),
                "method": str(observed.get("method") or "").upper(),
                "resource_type": str(observed.get("resource_type") or ""),
                "url": response_url,
                "status": status,
                "body": body[:MAX_INLINE_RESPONSE_CHARS],
                "body_truncated": bool(
                    observed.get("body_truncated")
                    or len(body) > MAX_INLINE_RESPONSE_CHARS
                ),
            })
        except Exception as exc:
            rows.append({
                "phase": str(observed.get("phase") or "login"),
                "error": redact_sensitive_text(str(exc), secrets)[:1000],
            })
    return rows, raw_bodies, statuses


def _browser_auth_response_url(url: str) -> bool:
    try:
        path = urlsplit(url).path.lower()
    except ValueError:
        return False
    return bool(re.search(
        r"(?:^|[/_.-])(?:login|signin|sign-in|auth|session|token|otp)(?:[/_.-]|$)",
        path,
    ))


def _browser_auth_enable_response_capture(context, page, workspace: Workspace,
                                          denied_requests: list[str],
                                          username_values: Iterable[str],
                                          password_values: Iterable[str]):
    """Capture bounded non-GET responses at CDP response stage."""
    session = context.new_cdp_session(page)
    responses: list[dict] = []

    def paused(event: dict) -> None:
        request_id = str(event.get("requestId") or "")
        request = event.get("request") if isinstance(event.get("request"), dict) else {}
        request_url = str(request.get("url") or "")
        method = str(request.get("method") or "").upper()
        resource_type = str(event.get("resourceType") or "").lower()
        post_data = str(request.get("postData") or "")
        matches_submission = bool(
            post_data
            and any(value and value in post_data for value in username_values)
            and any(value and value in post_data for value in password_values)
        )
        resumed = False
        try:
            allowed, _ = check_url_scope(workspace, request_url)
            if not allowed:
                if len(denied_requests) < 100:
                    denied_requests.append(request_url)
                session.send("Fetch.failRequest", {
                    "requestId": request_id,
                    "errorReason": "BlockedByClient",
                })
                resumed = True
                return
            if method == "GET" or len(responses) >= 8:
                return
            headers = event.get("responseHeaders")
            content_length = 0
            if isinstance(headers, list):
                for header in headers:
                    if (isinstance(header, dict)
                            and str(header.get("name") or "").lower() == "content-length"):
                        try:
                            content_length = max(0, int(header.get("value") or 0))
                        except (TypeError, ValueError):
                            content_length = 0
                        break
            body = ""
            truncated = content_length > MAX_RESPONSE_BYTES
            if not truncated:
                result = session.send("Fetch.getResponseBody", {
                    "requestId": request_id,
                })
                raw = str(result.get("body") or "")
                if result.get("base64Encoded"):
                    if len(raw) > ((MAX_RESPONSE_BYTES + 2) // 3) * 4:
                        decoded = b""
                        truncated = True
                    else:
                        decoded = base64.b64decode(raw, validate=False)
                else:
                    if len(raw) > MAX_RESPONSE_BYTES:
                        decoded = raw[:MAX_RESPONSE_BYTES].encode(
                            "utf-8", "replace"
                        )
                        truncated = True
                    else:
                        decoded = raw.encode("utf-8", "replace")
                truncated = len(decoded) > MAX_RESPONSE_BYTES
                body = decoded[:MAX_RESPONSE_BYTES].decode("utf-8", "replace")
            responses.append({
                "phase": "login",
                "method": method,
                "resource_type": resource_type,
                "url": request_url,
                "status": int(event.get("responseStatusCode") or 0),
                "body": body,
                "body_truncated": truncated,
                "matches_submission": matches_submission,
            })
        except Exception as exc:
            responses.append({
                "phase": "login",
                "error": "Login response capture failed: " + str(exc),
            })
        finally:
            if not resumed:
                try:
                    session.send("Fetch.continueResponse", {"requestId": request_id})
                except Exception:
                    try:
                        session.send("Fetch.continueRequest", {"requestId": request_id})
                    except Exception:
                        pass

    session.on("Fetch.requestPaused", paused)
    session.send("Fetch.enable", {
        "patterns": [{"urlPattern": "*", "requestStage": "Response"}]
    })
    return session, responses


def _browser_auth_cookie_payload(cookies: list[dict], login_url: str) -> bytes:
    """Convert applicable Playwright cookies to a private curl cookie jar."""
    cookies = _browser_auth_persistable_cookies(cookies, login_url)
    lines = ["# Netscape HTTP Cookie File"]
    for cookie in cookies:
        domain = str(cookie.get("domain") or "").lower().rstrip(".")
        path = str(cookie.get("path") or "/")
        name = str(cookie.get("name") or "")
        value = str(cookie.get("value") or "")
        include_subdomains = "TRUE" if domain.startswith(".") else "FALSE"
        secure = "TRUE" if bool(cookie.get("secure")) else "FALSE"
        try:
            expires = max(0, int(float(cookie.get("expires") or 0)))
        except (TypeError, ValueError):
            expires = 0
        rendered_domain = domain
        if bool(cookie.get("httpOnly")):
            rendered_domain = "#HttpOnly_" + rendered_domain
        lines.append("\t".join((
            rendered_domain, include_subdomains, path, secure, str(expires),
            name, value,
        )))
    return ("\n".join(lines) + "\n").encode("utf-8")


def _browser_auth_persistable_cookies(cookies: list[dict], login_url: str) -> list[dict]:
    """Keep cookies that can apply to the exact login host and serialize safely."""
    host = (urlsplit(login_url).hostname or "").lower().rstrip(".")
    output: list[dict] = []
    for cookie in cookies:
        domain = str(cookie.get("domain") or "").lower().rstrip(".")
        plain_domain = domain.lstrip(".")
        if not plain_domain or not (
            host == plain_domain
            or (domain.startswith(".") and host.endswith("." + plain_domain))
        ):
            continue
        path = str(cookie.get("path") or "/")
        name = str(cookie.get("name") or "")
        value = str(cookie.get("value") or "")
        if (not name or len(value) > 8192
                or any("\t" in item or "\r" in item or "\n" in item
                           for item in (domain, path, name, value))):
            continue
        output.append(dict(cookie))
    return output


def _browser_auth_cookie_fingerprints(cookies: list[dict]) -> set[str]:
    fields = ("domain", "path", "name", "value", "secure", "httpOnly", "sameSite")
    return {
        hashlib.sha256(json.dumps(
            {key: cookie.get(key) for key in fields},
            sort_keys=True, ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8", "replace")).hexdigest()
        for cookie in cookies
    }


def _browser_auth_has_cookie_delta(before: list[dict], after: list[dict]) -> bool:
    baseline = _browser_auth_cookie_fingerprints(before)
    for cookie in after:
        value = str(cookie.get("value") or "")
        if not 8 <= len(value) <= 8192:
            continue
        if not _browser_auth_cookie_fingerprints([cookie]).issubset(baseline):
            return True
    return False


class _BrowserStorageCaptureError(ValueError):
    """Raised when browser storage cannot be represented exactly and safely."""


def _browser_auth_storage(page, area: str) -> dict:
    if area not in {"localStorage", "sessionStorage"}:
        raise _BrowserStorageCaptureError("browser storage area is invalid")
    try:
        value = page.evaluate(
            """area => {
              const storage = area === 'localStorage' ? localStorage : sessionStorage;
              if (storage.length > 100) return {valid: false};
              const entries = []; let total = 0; let captured = 0;
              for (let i = 0; i < storage.length; i++) {
                const key = storage.key(i);
                if (key === null) continue;
                const item = storage.getItem(key) ?? '';
                if (key.length > 512 || item.length > 65536) return {valid: false};
                total += key.length + item.length;
                if (total > 1000000) return {valid: false};
                entries.push([key, item]); captured += 1;
              }
              return {valid: captured === storage.length, entries};
            }""",
            area,
        )
    except Exception as exc:
        raise _BrowserStorageCaptureError(
            "exact browser storage capture failed"
        ) from exc
    if (
        not isinstance(value, dict)
        or value.get("valid") is not True
        or not isinstance(value.get("entries"), list)
    ):
        raise _BrowserStorageCaptureError(
            "browser storage exceeds the exact private capture limits"
        )
    output: dict[str, str] = {}
    for entry in value["entries"]:
        if (
            not isinstance(entry, list) or len(entry) != 2
            or not isinstance(entry[0], str) or not isinstance(entry[1], str)
            or entry[0] in output
        ):
            raise _BrowserStorageCaptureError(
                "browser storage capture was not exact"
            )
        output[entry[0]] = entry[1]
    if len(output) != len(value["entries"]):
        raise _BrowserStorageCaptureError("browser storage capture was not exact")
    return output


def _browser_auth_local_storage(page) -> dict:
    return _browser_auth_storage(page, "localStorage")


def _browser_auth_session_storage(page) -> dict:
    return _browser_auth_storage(page, "sessionStorage")


def _browser_auth_restore_storage(context, url: str, storage: dict) -> None:
    """Install bounded origin-scoped web storage before page scripts execute."""
    local = storage.get("local_storage")
    session = storage.get("session_storage")
    payload = {
        "url": url,
        "local": local if isinstance(local, dict) else {},
        "session": session if isinstance(session, dict) else {},
    }
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    encoded_literal = json.dumps(encoded, ensure_ascii=True)
    context.add_init_script(script=f"""(() => {{
      const state = JSON.parse({encoded_literal});
      try {{
        if (location.origin !== new URL(state.url).origin) return;
        for (const [key, value] of Object.entries(state.local)) {{
          localStorage.setItem(key, value);
        }}
        for (const [key, value] of Object.entries(state.session)) {{
          sessionStorage.setItem(key, value);
        }}
      }} catch (_) {{}}
    }})()""")


def _browser_auth_tokens(response_bodies: Iterable[str], local_storage: dict,
                         session_storage: Optional[dict] = None) -> dict[str, str]:
    tokens: dict[str, str] = {}
    for body in response_bodies:
        tokens.update(_extract_auth_tokens(str(body)))
    for area in (local_storage, session_storage or {}):
        tokens.update(_extract_auth_tokens(json.dumps(area, ensure_ascii=False)))
        for value in area.values():
            if isinstance(value, str):
                tokens.update(_extract_auth_tokens(value))
    return {
        key: value for key, value in tokens.items()
        if 12 <= len(value) <= 16_384
        and not any(ord(char) < 0x20 or ord(char) == 0x7f for char in value)
    }


def _browser_auth_has_storage_delta(before: dict, after: dict) -> bool:
    """Return whether bounded browser storage changed across login."""
    return before != after


def _browser_auth_install_cookies(workspace: Workspace, credential: str,
                                  cookies: list[dict], login_url: str) -> None:
    payload = _browser_auth_cookie_payload(cookies, login_url)
    with _temporary_cookie_jar(workspace) as temporary:
        fd = os.open(temporary, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _install_cookie_jar(
            temporary, credentials.cookie_jar_path(workspace.slug, credential)
        )


def _browser_auth_save_capture(workspace: Workspace, url: str, capture: dict,
                               rendered_dom: str,
                               secret_values: Iterable[str],
                               identity_values: Iterable[str] = ()) -> tuple[Path, Path]:
    secrets = tuple(secret_values)
    identities = tuple(identity_values)
    safe_capture = _browser_redacted_capture_value(
        capture, secrets, identities
    )
    safe_dom = _browser_redact_identity_text(
        rendered_dom, secrets, identities
    )[:MAX_RESPONSE_BYTES]
    workspace.scratch_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output = workspace.scratch_dir / f"browser-auth-{time.time_ns()}.html"
    fd = os.open(
        output, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(safe_dom)
    flow_body = json.dumps(
        {**safe_capture, "rendered_dom": safe_dom},
        ensure_ascii=False, separators=(",", ":"),
    )
    flow = _save_flow(
        workspace, "BROWSER",
        _browser_redact_identity_text(url, secrets, identities),
        {}, None, flow_body,
        transport="credential-playwright-chromium", returncode=0,
        secret_values=secrets,
    )
    return output, flow


def _browser_auth_url_identity(url: str) -> tuple[str, str, str, str]:
    parsed = urlsplit(str(url or ""))
    return (
        credentials.normalize_origin(url), parsed.path or "/",
        parsed.query, parsed.fragment,
    )


def _browser_auth_url_matches(observed: str, expected: str) -> bool:
    try:
        return _browser_auth_url_identity(observed) == _browser_auth_url_identity(
            expected
        )
    except (ValueError, credentials.CredentialError):
        return False


def _browser_inert_bootstrap_matches(
    request_url: str, *, method: str, resource_type: str,
    origin: str, nonce: str,
) -> bool:
    """Identify the private inert navigation after browser URL normalization."""
    try:
        return bool(
            str(method or "").upper() == "GET"
            and str(resource_type or "").lower() == "document"
            and credentials.normalize_origin(request_url) == origin
            and any(
                key == "__grypton_context__" and value == nonce
                for key, value in parse_qsl(
                    urlsplit(request_url).query, keep_blank_values=True
                )
            )
        )
    except (TypeError, ValueError, credentials.CredentialError):
        return False


def _browser_auth_response_method(response) -> str:
    if response is None:
        return ""
    try:
        return str(response.request.method or "").upper()
    except Exception:
        return ""


def _browser_auth_redirect_chain(response) -> list[dict]:
    """Return ordered redirect responses leading to a terminal navigation."""
    if response is None:
        return []
    reversed_chain: list[dict] = []
    try:
        request = response.request
        while request.redirected_from is not None:
            previous = request.redirected_from
            previous_response = previous.response()
            headers = (
                previous_response.headers
                if previous_response is not None else {}
            )
            reversed_chain.append({
                "status": int(previous_response.status) if previous_response else 0,
                "method": str(previous.method or "").upper(),
                "url": str(previous.url or ""),
                "location": str(headers.get("location") or ""),
                "complete": previous_response is not None,
            })
            request = previous
            if len(reversed_chain) > 8:
                break
    except Exception:
        reversed_chain.append({
            "status": 0, "method": "", "url": "", "location": "",
            "complete": False,
        })
    return list(reversed(reversed_chain))


def _browser_auth_redirect_contract_matches(
    chain: list[dict], expected_statuses: Iterable[int],
    verify_url: str, final_method: str,
) -> bool:
    statuses = list(expected_statuses)
    if str(final_method or "").upper() != "GET" or len(chain) != len(statuses):
        return False
    for hop, expected_status in zip(chain, statuses):
        source_url = str(hop.get("url") or "")
        location = str(hop.get("location") or "")
        try:
            observed_status = int(hop.get("status") or 0)
            configured_status = int(expected_status)
        except (TypeError, ValueError):
            return False
        if (
            hop.get("complete") is not True
            or str(hop.get("method") or "").upper() != "GET"
            or observed_status != configured_status
            or not _browser_auth_url_matches(source_url, verify_url)
            or not location
            or not _browser_auth_url_matches(
                urljoin(source_url, location), verify_url
            )
        ):
            return False
    return True


def _browser_auth_safe_redirect_chain(
    chain: list[dict], verify_url: str,
) -> list[dict]:
    """Expose proof facts without persisting redirect header values."""
    rows: list[dict] = []
    for hop in chain:
        source_url = str(hop.get("url") or "")
        location = str(hop.get("location") or "")
        rows.append({
            "status": int(hop.get("status") or 0),
            "method": str(hop.get("method") or "").upper(),
            "request_url_exact": _browser_auth_url_matches(source_url, verify_url),
            "location_exact": bool(
                location and _browser_auth_url_matches(
                    urljoin(source_url, location), verify_url
                )
            ),
            "complete": hop.get("complete") is True,
        })
    return rows


def _browser_auth_fresh_probe(
    playwright,
    executable: str,
    workspace: Workspace,
    url: str,
    *,
    phase: str,
    denied_requests: list[str],
    console: list[dict],
    timeout_ms: int,
    cookies: Optional[list[dict]] = None,
    bearer_token: str = "",
    verify_headers: Optional[dict] = None,
    browser_storage: Optional[dict] = None,
) -> dict:
    """Load one proof URL in a fresh browser with only supplied session material."""
    with _isolated_browser_profile(executable) as launch_profile:
        proof_headers = dict(verify_headers or {})
        if bearer_token:
            proof_headers["Authorization"] = f"Bearer {bearer_token}"
        context = _launch_scoped_browser_context(
            playwright, launch_profile, workspace, denied_requests,
            credentials.normalize_origin(url) if proof_headers else "",
            proof_headers or None,
        )
        try:
            if cookies:
                context.add_cookies(cookies)
            if browser_storage:
                _browser_auth_restore_storage(context, url, browser_storage)
            page = context.new_page()
            page.on("console", lambda message: console.append({
                "phase": phase,
                "type": str(message.type),
                "text": str(message.text)[:4000],
            }) if len(console) < 100 else None)
            response = page.goto(
                url, wait_until="domcontentloaded", timeout=timeout_ms
            )
            page.wait_for_timeout(250)
            status = int(response.status) if response else 0
            final_url, dom, visible = _browser_auth_snapshot(page)
            allowed, reason = check_url_scope(workspace, final_url)
            if not allowed:
                raise RuntimeError(
                    f"{phase} browser proof ended outside scope: {reason}"
                )
            try:
                body = bytes(response.body() or b"").decode(
                    "utf-8", "replace"
                )[:MAX_RESPONSE_BYTES] if response else ""
            except Exception:
                body = ""
            return {
                "status": status,
                "response_url": str(response.url or "") if response else "",
                "final_url": final_url,
                "method": _browser_auth_response_method(response),
                "redirect_chain": _browser_auth_redirect_chain(response),
                "body": body,
                "source": "\n".join((body, visible, dom)),
                "cookies": list(context.cookies()),
                "local_storage": _browser_auth_local_storage(page),
                "session_storage": _browser_auth_session_storage(page),
            }
        finally:
            context.close()


def _browser_auth_persisted_cookies(
    workspace: Workspace, credential: str, login_url: str,
) -> list[dict]:
    """Translate the private curl jar into a fresh-browser cookie set."""
    host = (urlsplit(login_url).hostname or "").lower().rstrip(".")
    path = credentials.cookie_jar_storage_path(workspace.slug, credential)
    now = int(time.time())
    output: list[dict] = []
    for record in credentials._cookie_records(path):
        columns = record.get("columns")
        if not isinstance(columns, tuple) or len(columns) < 7:
            continue
        domain = str(columns[0] or "").lower().rstrip(".")
        plain_domain = domain.lstrip(".")
        include_subdomains = str(columns[1] or "").upper() == "TRUE"
        if not plain_domain or not (
            host == plain_domain
            or (include_subdomains and host.endswith("." + plain_domain))
        ):
            continue
        try:
            expires = max(0, int(columns[4] or 0))
        except (TypeError, ValueError):
            continue
        if expires and expires <= now:
            continue
        name, value = str(columns[5] or ""), str(columns[6] or "")
        if (
            not name or not 8 <= len(value) <= 8192
            or any("\t" in item or "\r" in item or "\n" in item
                   for item in (domain, columns[2], name, value))
        ):
            continue
        cookie = {
            "name": name,
            "value": value,
            "domain": domain,
            "path": str(columns[2] or "/"),
            "secure": str(columns[3]).upper() == "TRUE",
            "httpOnly": bool(record.get("http_only")),
            # Netscape jars cannot represent SameSite.  Strict is the only
            # conservative legacy import; new browser sessions use the exact
            # rich private browser-state record instead.
            "sameSite": "Strict",
        }
        if expires:
            cookie["expires"] = expires
        output.append(cookie)
    return output


def _browser_status_probe_matches(
    probe: dict, *, status: int, verify_url: str,
    redirect_statuses: Iterable[int],
) -> bool:
    """Match the complete configured GET verifier contract."""
    return bool(
        int(probe.get("status") or 0) == int(status)
        and _browser_auth_redirect_contract_matches(
            list(probe.get("redirect_chain") or []),
            tuple(redirect_statuses), verify_url,
            str(probe.get("method") or "").upper(),
        )
        and _browser_auth_url_matches(
            str(probe.get("response_url") or ""), verify_url
        )
        and _browser_auth_url_matches(
            str(probe.get("final_url") or ""), verify_url
        )
    )


def _browser_session_revalidation_due(
    workspace: Workspace, credential: str, state: dict,
    profile_revision: str,
) -> bool:
    """Use time and cookie expiry only to schedule the authoritative proof."""
    if not state.get("established"):
        return True
    rich_state = credentials.load_browser_storage(workspace.slug, credential)
    has_rich_storage = bool(
        rich_state.get("available")
        and (
            rich_state.get("cookies")
            or any(str(value) for value in dict(
                rich_state.get("local_storage") or {}
            ).values())
            or any(str(value) for value in dict(
                rich_state.get("session_storage") or {}
            ).values())
        )
    )
    if (
        not _browser_auth_persisted_cookies(
            workspace, credential, str(state.get("origin") or "")
        )
        and not credentials.select_bearer(
            credentials.load_tokens(workspace.slug, credential)
        )
        and not has_rich_storage
    ):
        return True
    if str(state.get("proof_profile_revision") or "") != profile_revision:
        return True
    now = time.time()
    verified_at = float(state.get("verified_at") or 0.0)
    if verified_at <= 0 or now - verified_at >= _AUTH_REVALIDATE_INTERVAL_S:
        return True
    jar = credentials.cookie_jar_storage_path(workspace.slug, credential)
    for columns in credentials._cookie_rows(jar):
        try:
            expires = max(0, int(columns[4] or 0))
        except (IndexError, TypeError, ValueError):
            return True
        if expires and expires <= now + _AUTH_EXPIRY_SKEW_S:
            return True
    return False


def ensure_browser_status_session(
    workspace: Workspace, credential: str,
) -> dict:
    """Revalidate and, once per proof generation, renew a profiled session."""
    try:
        with credentials.auth_profile_lock(workspace.slug, credential):
            profile = credentials.load_auth_profile_optional(
                workspace.slug, credential
            )
            verification = (
                profile.get("browser", {}).get("verification")
                if isinstance(profile, dict)
                and profile.get("strategy") == "browser" else None
            )
            if not isinstance(verification, dict):
                return _err(
                    "Automatic renewal is unavailable for this authentication profile."
                )
            profile_revision = credentials.auth_profile_revision(profile)
            for candidate in (
                profile["login_url"], profile["verify_url"],
                verification["expected_post_login_url"],
            ):
                blocked = _scope_error(workspace, candidate)
                if blocked:
                    return blocked
            login_origin = credentials.normalize_origin(profile["login_url"])

            with credentials.session_material_lock(workspace.slug, credential):
                state = credentials.load_attempt_state(
                    workspace.slug, credential
                )
                if not state["ever_established"]:
                    return _err(
                        f"Named credential {credential!r} has no prior proven session."
                    )
                if state["origin"] != login_origin:
                    return _err(
                        f"Named credential {credential!r} has no valid private origin "
                        "binding for its configured authentication profile."
                    )
                generation = int(state["proof_generation"])
                if not _browser_session_revalidation_due(
                    workspace, credential, state, profile_revision
                ):
                    return _ok(
                        f"Authenticated session {credential!r} is within its "
                        "private proof freshness window.",
                        {
                            "credential": credential,
                            "session_maintenance": {
                                "action": "reused",
                                "credential_submission": False,
                            },
                            "session": credentials.session_status(
                                workspace.slug, credential
                            ),
                        },
                    )
                jar_path = credentials.cookie_jar_storage_path(
                    workspace.slug, credential
                )
                token_file = credentials.token_path(
                    workspace.slug, credential
                )
                storage_file = credentials.browser_storage_path(
                    workspace.slug, credential
                )
                attempt_file = credentials.attempt_path(
                    workspace.slug, credential
                )
                cookie_snapshot = _snapshot_private_material(jar_path)
                token_snapshot = _snapshot_private_material(token_file)
                storage_snapshot = _snapshot_private_material(storage_file)
                attempt_snapshot = _snapshot_private_material(attempt_file)
                material_committed = False
                try:
                    try:
                        from playwright.sync_api import sync_playwright
                    except ImportError:
                        return _err("Python Playwright is not installed.")
                    executable = _browser_executable()
                    if not executable:
                        return _err(
                            "No Playwright-compatible Chromium or Chrome executable "
                            "is installed."
                        )
                    timeout_seconds = max(5, min(int(profile["timeout"]), 120))
                    timeout_ms = timeout_seconds * 1000
                    denied_requests: list[str] = []
                    console: list[dict] = []
                    tokens = credentials.load_tokens(
                        workspace.slug, credential
                    )
                    browser_storage = credentials.load_browser_storage(
                        workspace.slug, credential
                    )
                    requires_rich_state = not bool(
                        browser_storage.get("available")
                    )
                    cookies = (
                        list(browser_storage.get("cookies") or [])
                        if not requires_rich_state
                        else _browser_auth_persisted_cookies(
                            workspace, credential, profile["login_url"]
                        )
                    )
                    with sync_playwright() as playwright:
                        current = _browser_auth_fresh_probe(
                            playwright, executable, workspace,
                            profile["verify_url"], phase="renewal-revalidate",
                            denied_requests=denied_requests, console=console,
                            timeout_ms=timeout_ms, cookies=cookies,
                            bearer_token=credentials.select_bearer(tokens),
                            verify_headers=profile["browser"]["verify_headers"],
                            browser_storage=browser_storage,
                        )
                        control = _browser_auth_fresh_probe(
                            playwright, executable, workspace,
                            profile["verify_url"], phase="renewal-control",
                            denied_requests=denied_requests, console=console,
                            timeout_ms=timeout_ms,
                            verify_headers=profile["browser"]["verify_headers"],
                        )

                    current_source = str(current.get("source") or "")
                    control_source = str(control.get("source") or "")
                    challenge = (
                        _browser_auth_blocker(current_source)
                        or _browser_auth_blocker(control_source)
                    )
                    if challenge.startswith(("MFA/OTP", "CAPTCHA")):
                        return _err(
                            "Configured session revalidation was inconclusive; "
                            "no credential was submitted."
                        )
                    current_status = int(current.get("status") or 0)
                    control_status = int(control.get("status") or 0)
                    if 429 in {current_status, control_status}:
                        return _err(
                            "Configured session revalidation was rate-limited; "
                            "no credential was submitted."
                        )

                    control_matches = _browser_status_probe_matches(
                        control,
                        status=verification["anonymous_status"],
                        verify_url=profile["verify_url"],
                        redirect_statuses=verification.get(
                            "anonymous_redirect_statuses", ()
                        ),
                    )
                    current_matches = _browser_status_probe_matches(
                        current,
                        status=verification["authenticated_status"],
                        verify_url=profile["verify_url"],
                        redirect_statuses=(),
                    )
                    authenticated = bool(control_matches and current_matches)
                    stale_chain = list(current.get("redirect_chain") or [])
                    # A fresh anonymous client must match the configured redirect
                    # chain.  The stored session can retain the anonymous edge-gate
                    # cookie, so an otherwise exact anonymous result may reach the
                    # same verifier in zero hops.
                    stale_redirects_match = (
                        _browser_auth_redirect_contract_matches(
                            stale_chain, (), profile["verify_url"],
                            str(current.get("method") or "").upper(),
                        )
                        or _browser_auth_redirect_contract_matches(
                            stale_chain,
                            verification.get("anonymous_redirect_statuses", ()),
                            profile["verify_url"],
                            str(current.get("method") or "").upper(),
                        )
                    )
                    stale = bool(
                        control_matches
                        and current_status == verification["anonymous_status"]
                        and stale_redirects_match
                        and _browser_auth_url_matches(
                            str(current.get("response_url") or ""),
                            profile["verify_url"],
                        )
                        and _browser_auth_url_matches(
                            str(current.get("final_url") or ""),
                            profile["verify_url"],
                        )
                    )
                    if authenticated:
                        refreshed_cookies = _browser_auth_persistable_cookies(
                            list(current.get("cookies") or []),
                            profile["login_url"],
                        )
                        refreshed_tokens = dict(tokens)
                        refreshed_tokens.update(_browser_auth_tokens(
                            (str(current.get("body") or ""),),
                            current.get("local_storage")
                            if isinstance(current.get("local_storage"), dict)
                            else {},
                            current.get("session_storage")
                            if isinstance(current.get("session_storage"), dict)
                            else {},
                        ))
                        refreshed_local = (
                            current.get("local_storage")
                            if isinstance(current.get("local_storage"), dict)
                            else {}
                        )
                        refreshed_session = (
                            current.get("session_storage")
                            if isinstance(current.get("session_storage"), dict)
                            else {}
                        )
                        if not refreshed_cookies and not credentials.select_bearer(
                            refreshed_tokens
                        ) and not any(
                            str(value)
                            for area in (refreshed_local, refreshed_session)
                            for value in area.values()
                        ):
                            return _err(
                                "Configured session revalidation produced no reusable "
                                "private session material; the prior proof was retained.",
                                {
                                    "credential": credential,
                                    "session_maintenance": {
                                        "action": "inconclusive",
                                        "credential_submission": False,
                                    },
                                    "session": credentials.session_status(
                                        workspace.slug, credential
                                    ),
                                },
                            )
                        if not requires_rich_state:
                            credentials.canonical_browser_storage(
                                origin=login_origin, cookies=refreshed_cookies,
                                local_storage=refreshed_local,
                                session_storage=refreshed_session,
                            )
                        # Commit the exact resulting jar, including an empty jar
                        # when the verifier expired its last cookie.
                        try:
                            _browser_auth_install_cookies(
                                workspace, credential, refreshed_cookies,
                                profile["login_url"],
                            )
                            if refreshed_tokens:
                                credentials.save_tokens(
                                    workspace.slug, credential, refreshed_tokens,
                                    origin=login_origin,
                                )
                            credentials.record_session_revalidated(
                                workspace.slug, credential, generation=generation,
                                origin=login_origin,
                                profile_revision=profile_revision,
                            )
                            if not requires_rich_state:
                                credentials.save_browser_storage(
                                    workspace.slug, credential, origin=login_origin,
                                    cookies=refreshed_cookies,
                                    local_storage=refreshed_local,
                                    session_storage=refreshed_session,
                                )
                        except Exception:
                            _restore_private_material(attempt_file, attempt_snapshot)
                            raise
                        material_committed = True
                        return _ok(
                            f"Authenticated session {credential!r} passed its configured "
                            "status-differential revalidation.",
                            {
                                "credential": credential,
                                "session_maintenance": {
                                    "action": (
                                        "revalidated-legacy"
                                        if requires_rich_state else "revalidated"
                                    ),
                                    "credential_submission": False,
                                },
                                "session": credentials.session_status(
                                    workspace.slug, credential
                                ),
                            },
                        )

                    if not stale:
                        return _err(
                            "Configured session revalidation was inconclusive; "
                            "no credential was submitted.",
                            {
                                "credential": credential,
                                "session_maintenance": {
                                    "action": "inconclusive",
                                    "credential_submission": False,
                                },
                                "session": credentials.session_status(
                                    workspace.slug, credential
                                ),
                            },
                        )

                    credentials.record_session_stale(
                        workspace.slug, credential, generation=generation,
                        profile_revision=profile_revision,
                    )
                    state = credentials.load_attempt_state(
                        workspace.slug, credential
                    )
                    if state["refresh_attempted_generation"] == generation:
                        return _err(
                            "Credential renewal was already attempted for the current "
                            "session proof; no credential was submitted.",
                            {
                                "credential": credential,
                                "session_maintenance": {
                                    "action": "renewal-blocked",
                                    "credential_submission": False,
                                },
                                "session": credentials.session_status(
                                    workspace.slug, credential
                                ),
                            },
                        )

                    browser = profile["browser"]
                    renewal = _credential_browser_login_locked(
                        workspace, profile["login_url"], credential=credential,
                        username_transform=profile["username_transform"],
                        username_selector=browser["username_selector"],
                        password_selector=browser["password_selector"],
                        submit_selector=browser["submit_selector"],
                        verify_url=profile["verify_url"], success_marker="",
                        verify_headers=browser["verify_headers"],
                        verification=verification, timeout=profile["timeout"],
                        _refresh_generation=generation,
                        _profile_revision=profile_revision,
                    )
                    renewed_state = credentials.load_attempt_state(
                        workspace.slug, credential
                    )
                    proof_committed = bool(
                        renewed_state["established"]
                        and renewed_state["proof_generation"] > generation
                    )
                    if proof_committed:
                        # The complete proof and its state transition are
                        # authoritative.  A later capture-write failure must not
                        # restore stale material underneath the new generation or
                        # reopen a credential submission.
                        material_committed = True
                    renewed = bool(renewal.get("ok") and proof_committed)
                    if not renewed:
                        if proof_committed:
                            return _ok(
                                f"Authenticated session {credential!r} was renewed, "
                                "but its supplemental browser capture was incomplete.",
                                {
                                    "credential": credential,
                                    "session_maintenance": {
                                        "action": "renewed-capture-incomplete",
                                        "credential_submission": True,
                                    },
                                    "session": credentials.session_status(
                                        workspace.slug, credential
                                    ),
                                },
                            )
                        return renewal
                    renewal_data = (
                        renewal.get("data")
                        if isinstance(renewal.get("data"), dict) else {}
                    )
                    renewal_data["session_maintenance"] = {
                        "action": "renewed",
                        "credential_submission": True,
                        "credential_submission_requests": int(
                            renewal_data.get("credential_submission_requests") or 0
                        ),
                        "blocked_duplicate_submissions": int(
                            renewal_data.get("blocked_duplicate_submissions") or 0
                        ),
                    }
                    renewal["data"] = renewal_data
                    renewal["summary"] = (
                        f"Authenticated session {credential!r} was renewed and passed "
                        "the complete configured status-differential proof."
                    )
                    return renewal
                finally:
                    if not material_committed:
                        _restore_private_material(jar_path, cookie_snapshot)
                        _restore_private_material(token_file, token_snapshot)
                        _restore_private_material(storage_file, storage_snapshot)
    except (OSError, ValueError, credentials.CredentialError) as exc:
        return _err(str(exc))
    except Exception:
        return _err(
            "Configured session revalidation failed; no credential was submitted "
            "and private session material was restored."
        )


def credential_browser_login(
    workspace: Workspace,
    url: str,
    *,
    credential: str,
    username_transform: str = "stored",
    username_selector: str = _BROWSER_USERNAME_SELECTOR,
    password_selector: str = _BROWSER_PASSWORD_SELECTOR,
    submit_selector: str = _BROWSER_SUBMIT_SELECTOR,
    verify_url: str = "",
    success_marker: str = "",
    verify_headers: Optional[dict] = None,
    verification: Optional[dict] = None,
    timeout: int = 45,
) -> dict:
    """Serialize one complete browser login proof with other session writers."""
    try:
        with credentials.auth_profile_lock(workspace.slug, credential):
            profile = credentials.load_auth_profile_optional(
                workspace.slug, credential
            )
            profile_revision = (
                credentials.auth_profile_revision(profile) if profile else ""
            )
            with credentials.session_material_lock(workspace.slug, credential):
                return _credential_browser_login_locked(
                    workspace, url, credential=credential,
                    username_transform=username_transform,
                    username_selector=username_selector,
                    password_selector=password_selector,
                    submit_selector=submit_selector,
                    verify_url=verify_url, success_marker=success_marker,
                    verify_headers=verify_headers, verification=verification,
                    timeout=timeout, _profile_revision=profile_revision,
                )
    except credentials.CredentialError as exc:
        return _err(str(exc))


def _credential_browser_login_locked(
    workspace: Workspace,
    url: str,
    *,
    credential: str,
    username_transform: str = "stored",
    username_selector: str = _BROWSER_USERNAME_SELECTOR,
    password_selector: str = _BROWSER_PASSWORD_SELECTOR,
    submit_selector: str = _BROWSER_SUBMIT_SELECTOR,
    verify_url: str = "",
    success_marker: str = "",
    verify_headers: Optional[dict] = None,
    verification: Optional[dict] = None,
    timeout: int = 45,
    _refresh_generation: Optional[int] = None,
    _upgrade_generation: Optional[int] = None,
    _profile_revision: str = "",
) -> dict:
    """Submit one private credential through a scoped rendered login form."""
    verify_url = str(verify_url or "").strip()
    for candidate in (url, verify_url):
        if not candidate:
            continue
        blocked = _scope_error(workspace, candidate)
        if blocked:
            return blocked
    try:
        login_origin = credentials.normalize_origin(url)
        status_verification = None
        if verification is None:
            if not verify_url or not success_marker:
                return _err(
                    "Browser login requires a scoped verification URL and a printable "
                    "non-secret success marker."
                )
        else:
            if success_marker:
                return _err(
                    "Status-differential browser verification cannot use a success marker."
                )
            status_verification = credentials.validate_browser_verification(
                verification, login_url=url
            )
            blocked = _scope_error(
                workspace, status_verification["expected_post_login_url"]
            )
            if blocked:
                return blocked
            if not verify_url:
                return _err("Browser login requires a scoped verification URL.")
        if verify_url and credentials.normalize_origin(verify_url) != login_origin:
            return _err(
                "The browser verification endpoint must use the login page's "
                "exact origin (scheme, host, and effective port)."
            )
        if username_transform not in {"stored", "iran-e164"}:
            return _err("Username transform must be stored or iran-e164.")
        clean_verify_headers = _browser_auth_verify_headers(verify_headers)
        username_selector = _browser_auth_selector(
            username_selector, label="Username", default=_BROWSER_USERNAME_SELECTOR
        )
        password_selector = _browser_auth_selector(
            password_selector, label="Password", default=_BROWSER_PASSWORD_SELECTOR
        )
        submit_selector = _browser_auth_selector(
            submit_selector, label="Submit", default=_BROWSER_SUBMIT_SELECTOR
        )
        if success_marker and (
            len(success_marker) > 200
            or any(ord(char) < 0x20 for char in success_marker)
        ):
            return _err(
                "Browser verification success marker must be 1-200 printable characters."
            )
        secret = credentials.load_credential(workspace.slug, credential)
        login_username = credentials.normalize_login_username(
            secret["username"], username_transform
        )
        if _refresh_generation is not None and _upgrade_generation is not None:
            return _err("Browser login maintenance mode is invalid.")
        maintenance_generation = (
            _refresh_generation
            if _refresh_generation is not None else _upgrade_generation
        )
        if maintenance_generation is None:
            credentials.ensure_login_attempt_available(workspace.slug, credential)
        elif status_verification is None:
            return _err(
                "Browser session maintenance requires status-differential verification."
            )
    except (ValueError, credentials.CredentialError) as exc:
        return _err(str(exc))

    status_mode = status_verification is not None
    expected_post_login_identity = (
        _browser_auth_url_identity(
            status_verification["expected_post_login_url"]
        ) if status_mode else None
    )

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return _err("Python Playwright is not installed.")
    executable = _browser_executable()
    if not executable:
        return _err("No Playwright-compatible Chromium or Chrome executable is installed.")

    timeout_seconds = max(5, min(int(timeout), 120))
    timeout_ms = timeout_seconds * 1000
    username_redactions = _login_username_redaction_values(
        secret["username"], username_transform
    )
    secret_values = _serialized_secret_variants((
        *username_redactions, secret["password"],
    ))
    denied_requests: list[str] = []
    console: list[dict] = []
    pending_responses: list[dict] = []
    response_rows: list[dict] = []
    raw_response_bodies: list[str] = []
    response_statuses: list[int] = []
    rendered_dom = ""
    visible_text = ""
    final_url = url
    page_status = 0
    verify_status = 0
    verify_response_url = ""
    verify_final_url = ""
    verify_method = ""
    verify_redirect_chain: list[dict] = []
    verify_redirected = False
    verify_source = ""
    verify_body = ""
    replay_status = 0
    replay_source = ""
    replay_response_url = ""
    replay_final_url = ""
    replay_method = ""
    replay_redirect_chain: list[dict] = []
    replay_redirected = False
    control_status = 0
    control_source = ""
    control_response_url = ""
    control_final_url = ""
    control_method = ""
    control_redirect_chain: list[dict] = []
    control_redirected = False
    cookies: list[dict] = []
    observed_cookie_sets: list[list[dict]] = []
    observed_storage_sets: list[dict] = []
    local_storage: dict = {}
    session_storage: dict = {}
    observed_token_sets: list[dict[str, str]] = []
    tokens: dict[str, str] = {}
    identity_sources: list[str] = []
    replay_body = ""
    control_body = ""
    material_delta = False
    login_material_delta = False
    matched_submission_count = 0
    matched_submission_status = 0
    browser_identity = ""
    attempt = 0
    blocker = ""
    failure = ""
    phase = {"name": "initial"}
    context = None
    verify_header_state = {
        "active": False,
        "origin": login_origin,
        "headers": clean_verify_headers,
    }
    credential_submission_state = {
        "active": False,
        "username_values": _serialized_secret_variants(username_redactions),
        "password_values": _serialized_secret_variants((secret["password"],)),
        "seen": 0,
        "blocked": 0,
    }

    def remember_console(message) -> None:
        if len(console) < 100:
            console.append({
                "phase": phase["name"], "type": str(message.type),
                "text": str(message.text)[:4000],
            })

    try:
        with _isolated_browser_profile(executable) as launch_profile:
            browser_identity = str(launch_profile["identity"])
            with sync_playwright() as playwright:
                context = _launch_scoped_browser_context(
                    playwright, launch_profile, workspace, denied_requests,
                    bound_header_state=verify_header_state,
                    credential_submission_state=credential_submission_state,
                )
                page = context.new_page()
                page.on("console", remember_console)
                response = page.goto(
                    url, wait_until="domcontentloaded", timeout=timeout_ms
                )
                page.wait_for_timeout(250)
                page_status = int(response.status) if response else 0
                final_url, rendered_dom, visible_text = _browser_auth_snapshot(page)
                final_allowed, final_reason = check_url_scope(workspace, final_url)
                if not final_allowed:
                    raise RuntimeError(
                        f"browser ended outside scope before login: {final_reason}"
                    )
                initial_observation = _browser_auth_blocker(
                    visible_text,
                    (page_status,) if page_status == 429 else (),
                )
                if initial_observation.startswith(("MFA/OTP", "CAPTCHA")):
                    blocker = initial_observation
                elif page_status == 429:
                    blocker = initial_observation
                elif page_status in {401, 403}:
                    blocker = (
                        f"login page access returned HTTP {page_status} before "
                        "credential submission"
                    )
                if blocker:
                    if maintenance_generation is None:
                        credentials.record_login_outcome(
                            workspace.slug, credential, blocked_reason=blocker
                        )
                else:
                    username = _browser_auth_locator(
                        page, username_selector, role="username", timeout_ms=timeout_ms
                    )
                    password = _browser_auth_locator(
                        page, password_selector, role="password", timeout_ms=timeout_ms
                    )
                    submit = _browser_auth_locator(
                        page, submit_selector, role="submit", timeout_ms=timeout_ms
                    )
                    baseline_cookies = _browser_auth_persistable_cookies(
                        list(context.cookies()), url
                    )
                    baseline_storage = _browser_auth_local_storage(page)
                    baseline_session_storage = _browser_auth_session_storage(page)
                    baseline_tokens = _browser_auth_tokens(
                        (), baseline_storage, baseline_session_storage
                    )
                    observed_cookie_sets.append(baseline_cookies)
                    observed_storage_sets.extend(
                        (baseline_storage, baseline_session_storage)
                    )
                    observed_token_sets.append(baseline_tokens)
                    phase["name"] = "login"
                    capture_session = None
                    try:
                        if maintenance_generation is not None:
                            # Renewal persists its one-submission reservation and
                            # starts capture before secrets enter the form.  Input
                            # handlers can submit without a click.
                            capture_session, pending_responses = (
                                _browser_auth_enable_response_capture(
                                    context, page, workspace, denied_requests,
                                    _serialized_secret_variants(username_redactions),
                                    _serialized_secret_variants((secret["password"],)),
                                )
                            )
                            if _upgrade_generation is not None:
                                attempt = credentials.begin_browser_state_upgrade(
                                    workspace.slug, credential,
                                    generation=_upgrade_generation,
                                )
                            else:
                                attempt = credentials.begin_refresh_attempt(
                                    workspace.slug, credential,
                                    generation=_refresh_generation,
                                )
                            credential_submission_state["active"] = True
                        username.fill(login_username, timeout=timeout_ms)
                        password.fill(secret["password"], timeout=timeout_ms)
                        submission_seen = False
                        if maintenance_generation is not None:
                            # Let Playwright dispatch any request synchronously
                            # triggered by the input/change handler.  The route
                            # guard observes the request before its response,
                            # so a slow login endpoint cannot make us click and
                            # send the credentials a second time.
                            page.wait_for_timeout(100)
                            submission_seen = bool(
                                credential_submission_state["seen"]
                            )
                        if not submission_seen:
                            _browser_auth_wait_for_submit(
                                page, submit, timeout_ms
                            )
                            if maintenance_generation is None:
                                capture_session, pending_responses = (
                                    _browser_auth_enable_response_capture(
                                        context, page, workspace, denied_requests,
                                        _serialized_secret_variants(username_redactions),
                                        _serialized_secret_variants((secret["password"],)),
                                    )
                                )
                                attempt = credentials.begin_login_attempt(
                                    workspace.slug, credential
                                )
                                credential_submission_state["active"] = True
                            submit.click(timeout=timeout_ms)
                        deadline = time.monotonic() + timeout_seconds
                        while time.monotonic() < deadline:
                            submission_seen = any(
                                item.get("matches_submission") is True
                                for item in pending_responses
                                if not item.get("error")
                            )
                            if submission_seen:
                                if not status_mode:
                                    break
                                try:
                                    terminal_seen = (
                                        _browser_auth_url_identity(page.url)
                                        == expected_post_login_identity
                                    )
                                except (ValueError, credentials.CredentialError):
                                    terminal_seen = False
                                if terminal_seen:
                                    # Keep the response-stage listener alive briefly
                                    # so duplicate credential submissions are observed.
                                    page.wait_for_timeout(250)
                                    break
                            page.wait_for_timeout(100)
                    except Exception as exc:
                        failure = (
                            "Browser form submission did not complete: " + str(exc)
                        )
                    finally:
                        credential_submission_state["active"] = False
                        if capture_session is not None:
                            try:
                                capture_session.send("Fetch.disable")
                            except Exception:
                                pass
                    try:
                        page.wait_for_timeout(750)
                    except Exception:
                        pass

                    final_url, rendered_dom, visible_text = _browser_auth_snapshot(page)
                    final_allowed, final_reason = check_url_scope(workspace, final_url)
                    if not final_allowed:
                        raise RuntimeError(
                            f"browser ended outside scope after login: {final_reason}"
                        )
                    response_rows, raw_response_bodies, response_statuses = (
                        _browser_auth_collect_responses(
                            pending_responses, workspace, secret_values
                        )
                    )
                    matched_submissions = [
                        item for item in pending_responses
                        if isinstance(item, dict)
                        and not item.get("error")
                        and item.get("matches_submission") is True
                    ]
                    matched_submission_count = len(matched_submissions)
                    if matched_submission_count == 1:
                        matched_submission_status = int(
                            matched_submissions[0].get("status") or 0
                        )
                    if status_mode:
                        raw_response_bodies = [
                            str(item.get("body") or "")[:MAX_RESPONSE_BYTES]
                            for item in matched_submissions
                        ]
                        response_statuses = [
                            int(item.get("status") or 0)
                            for item in matched_submissions
                        ]
                    identity_sources.extend(
                        str(item.get("body") or "")
                        for item in pending_responses
                        if isinstance(item, dict) and not item.get("error")
                    )
                    if not raw_response_bodies and not response_statuses and not failure:
                        failure = (
                            "No credential submission response was captured before "
                            "the configured deadline."
                        )
                    blocker = _browser_auth_blocker(
                        "\n".join(raw_response_bodies), response_statuses
                    ) or _browser_auth_blocker(visible_text)
                    cookies = _browser_auth_persistable_cookies(
                        list(context.cookies()), url
                    )
                    local_storage = _browser_auth_local_storage(page)
                    session_storage = _browser_auth_session_storage(page)
                    tokens = _browser_auth_tokens(
                        raw_response_bodies, local_storage, session_storage
                    )
                    observed_cookie_sets.append(cookies)
                    observed_storage_sets.extend((local_storage, session_storage))
                    observed_token_sets.append(tokens)
                    login_changed_cookie = _browser_auth_has_cookie_delta(
                        baseline_cookies, cookies
                    )
                    baseline_token_values = set(baseline_tokens.values())
                    login_changed_token = any(
                        value not in baseline_token_values
                        for value in tokens.values()
                    )
                    login_changed_storage = (
                        _browser_auth_has_storage_delta(
                            baseline_storage, local_storage
                        )
                        or _browser_auth_has_storage_delta(
                            baseline_session_storage, session_storage
                        )
                    )
                    login_material_delta = bool(
                        login_changed_cookie or login_changed_token
                        or login_changed_storage
                    )
                    if not blocker:
                        phase["name"] = "verify"
                        verify_header_state["active"] = True
                        verify_response = page.goto(
                            verify_url, wait_until="domcontentloaded", timeout=timeout_ms
                        )
                        page.wait_for_timeout(250)
                        verify_status = int(verify_response.status) if verify_response else 0
                        verify_response_url = (
                            str(verify_response.url or "")
                            if verify_response else ""
                        )
                        verify_final, verify_dom, verify_visible = _browser_auth_snapshot(page)
                        verify_final_url = verify_final
                        verify_method = _browser_auth_response_method(verify_response)
                        verify_redirect_chain = _browser_auth_redirect_chain(
                            verify_response
                        )
                        verify_redirected = bool(verify_redirect_chain)
                        verify_allowed, verify_reason = check_url_scope(
                            workspace, verify_final
                        )
                        if not verify_allowed:
                            raise RuntimeError(
                                f"browser verification ended outside scope: {verify_reason}"
                            )
                        try:
                            verify_body = bytes(verify_response.body() or b"").decode(
                                "utf-8", "replace"
                            )[:MAX_RESPONSE_BYTES] if verify_response else ""
                        except Exception:
                            verify_body = ""
                        verify_source = "\n".join(
                            (verify_body, verify_visible, verify_dom)
                        )
                        identity_sources.append(verify_body)
                        # Verification can rotate cookies or refresh a bearer.
                        # Snapshot only after it completes so persisted state is current.
                        cookies = _browser_auth_persistable_cookies(
                            list(context.cookies()), url
                        )
                        local_storage = _browser_auth_local_storage(page)
                        session_storage = _browser_auth_session_storage(page)
                        tokens = _browser_auth_tokens(
                            (*raw_response_bodies, verify_body), local_storage,
                            session_storage,
                        )
                        observed_cookie_sets.append(cookies)
                        observed_storage_sets.extend((local_storage, session_storage))
                        observed_token_sets.append(tokens)
                        changed_cookie = _browser_auth_has_cookie_delta(
                            baseline_cookies, cookies
                        )
                        changed_token = any(
                            value not in baseline_token_values
                            for value in tokens.values()
                        )
                        changed_storage = (
                            _browser_auth_has_storage_delta(
                                baseline_storage, local_storage
                            )
                            or _browser_auth_has_storage_delta(
                                baseline_session_storage, session_storage
                            )
                        )
                        material_delta = bool(
                            changed_cookie or changed_token or changed_storage
                        )

                    context.close()
                    context = None

                    replay_material_ready = (
                        login_material_delta if status_mode else material_delta
                    )
                    if not blocker and replay_material_ready:
                        phase["name"] = "replay"
                        replay = _browser_auth_fresh_probe(
                            playwright, executable, workspace, verify_url,
                            phase="replay", denied_requests=denied_requests,
                            console=console, timeout_ms=timeout_ms,
                            cookies=cookies,
                            bearer_token=credentials.select_bearer(tokens),
                            verify_headers=clean_verify_headers,
                            browser_storage={
                                "local_storage": local_storage,
                                "session_storage": session_storage,
                            },
                        )
                        replay_status = int(replay.get("status") or 0)
                        replay_response_url = str(
                            replay.get("response_url") or ""
                        )
                        replay_source = str(replay.get("source") or "")
                        replay_body = str(replay.get("body") or "")
                        identity_sources.append(replay_body)
                        replay_final_url = str(replay.get("final_url") or "")
                        replay_method = str(replay.get("method") or "").upper()
                        replay_redirect_chain = list(
                            replay.get("redirect_chain") or []
                        )
                        replay_redirected = bool(replay_redirect_chain)
                        replay_cookies = _browser_auth_persistable_cookies(
                            list(replay.get("cookies") or []), url
                        )
                        replay_tokens = dict(tokens)
                        replay_tokens.update(_browser_auth_tokens(
                            (replay_body,),
                            replay.get("local_storage")
                            if isinstance(replay.get("local_storage"), dict) else {},
                            replay.get("session_storage")
                            if isinstance(replay.get("session_storage"), dict) else {},
                        ))
                        observed_cookie_sets.append(replay_cookies)
                        observed_token_sets.append(replay_tokens)
                        cookies = replay_cookies
                        tokens = replay_tokens
                        local_storage = (
                            replay.get("local_storage")
                            if isinstance(replay.get("local_storage"), dict)
                            else local_storage
                        )
                        session_storage = (
                            replay.get("session_storage")
                            if isinstance(replay.get("session_storage"), dict)
                            else session_storage
                        )
                        observed_storage_sets.extend(
                            (local_storage, session_storage)
                        )

                        phase["name"] = "control"
                        control = _browser_auth_fresh_probe(
                            playwright, executable, workspace, verify_url,
                            phase="control", denied_requests=denied_requests,
                            console=console, timeout_ms=timeout_ms,
                            verify_headers=clean_verify_headers,
                        )
                        control_status = int(control.get("status") or 0)
                        control_response_url = str(
                            control.get("response_url") or ""
                        )
                        control_source = str(control.get("source") or "")
                        control_body = str(control.get("body") or "")
                        identity_sources.append(control_body)
                        control_final_url = str(control.get("final_url") or "")
                        control_method = str(control.get("method") or "").upper()
                        control_redirect_chain = list(
                            control.get("redirect_chain") or []
                        )
                        control_redirected = bool(control_redirect_chain)
                        observed_cookie_sets.append(
                            _browser_auth_persistable_cookies(
                                list(control.get("cookies") or []), url
                            )
                        )
                        observed_token_sets.append(_browser_auth_tokens(
                            (control_body,),
                            control.get("local_storage")
                            if isinstance(control.get("local_storage"), dict) else {},
                            control.get("session_storage")
                            if isinstance(control.get("session_storage"), dict) else {},
                        ))
                        observed_storage_sets.extend((
                            control.get("local_storage")
                            if isinstance(control.get("local_storage"), dict) else {},
                            control.get("session_storage")
                            if isinstance(control.get("session_storage"), dict) else {},
                        ))
    except _BrowserStorageCaptureError:
        # The unknown tail of an oversized state value cannot be safely
        # redacted.  Discard every browser-derived observable and fail closed;
        # private proof/session snapshots below remain uncommitted or rollback.
        failure = "Exact browser storage capture exceeded its private limits."
        console = []
        pending_responses = []
        response_rows = []
        raw_response_bodies = []
        response_statuses = []
        rendered_dom = ""
        visible_text = ""
        verify_source = verify_body = ""
        replay_source = replay_body = ""
        control_source = control_body = ""
        identity_sources = []
        cookies = []
        local_storage = {}
        session_storage = {}
        tokens = {}
        material_delta = False
        login_material_delta = False
    except Exception as exc:
        failure = failure or f"Headless browser authentication failed: {exc}"
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass

    proof_status_ok = 200 <= replay_status < 300
    control_conclusive = bool(
        success_marker
        and (200 <= control_status < 300 or control_status in {401, 403, 404})
        and success_marker not in control_source
    )
    marker_proved = bool(
        success_marker
        and success_marker in replay_source
        and proof_status_ok
        and control_conclusive
    )
    status_proved = bool(
        status_mode
        and attempt
        and not blocker
        and not failure
        and login_material_delta
        and credential_submission_state["seen"] == 1
        and credential_submission_state["blocked"] == 0
        and matched_submission_count == 1
        and matched_submission_status == status_verification["login_status"]
        and _browser_auth_url_matches(
            final_url, status_verification["expected_post_login_url"]
        )
        and verify_status == status_verification["authenticated_status"]
        and _browser_auth_redirect_contract_matches(
            verify_redirect_chain, (), verify_url, verify_method,
        )
        and _browser_auth_url_matches(verify_response_url, verify_url)
        and _browser_auth_url_matches(verify_final_url, verify_url)
        and replay_status == status_verification["authenticated_status"]
        and _browser_auth_redirect_contract_matches(
            replay_redirect_chain, (), verify_url, replay_method,
        )
        and _browser_auth_url_matches(replay_response_url, verify_url)
        and _browser_auth_url_matches(replay_final_url, verify_url)
        and control_status == status_verification["anonymous_status"]
        and _browser_auth_redirect_contract_matches(
            control_redirect_chain,
            status_verification.get("anonymous_redirect_statuses", ()),
            verify_url, control_method,
        )
        and _browser_auth_url_matches(control_response_url, verify_url)
        and _browser_auth_url_matches(control_final_url, verify_url)
    )

    raw_identity_values = _browser_identity_values(identity_sources)
    identity_values = tuple(sorted({
        *raw_identity_values,
        *_serialized_secret_variants(raw_identity_values),
    }, key=len, reverse=True))
    runtime_secrets = [*secret_values]
    for observed_tokens in observed_token_sets:
        runtime_secrets.extend(observed_tokens.values())
    for observed_cookies in observed_cookie_sets:
        runtime_secrets.extend(
            value for cookie in observed_cookies
            if 0 < len(value := str(cookie.get("value") or "")) <= 8192
        )
    for observed_storage in observed_storage_sets:
        runtime_secrets.extend(
            value for value in observed_storage.values()
            if isinstance(value, str) and value
        )
    secret_values = tuple(sorted({
        *secret_values,
        *_serialized_secret_variants(runtime_secrets),
    }, key=len, reverse=True))
    response_rows = _browser_redacted_capture_value(
        response_rows, secret_values, identity_values
    )

    established = False
    if attempt and blocker:
        if maintenance_generation is None:
            credentials.record_login_outcome(
                workspace.slug, credential, blocked_reason=blocker
            )
        elif _upgrade_generation is not None:
            credentials.record_browser_state_upgrade_outcome(
                workspace.slug, credential,
                generation=_upgrade_generation, blocked_reason=blocker,
            )
        else:
            credentials.record_refresh_outcome(
                workspace.slug, credential,
                generation=_refresh_generation, blocked_reason=blocker,
            )
    elif attempt and not failure and (
        status_proved if status_mode else material_delta and marker_proved
    ):
        commit_snapshots: list[tuple[Path, tuple[bool, bytes, int]]] = []
        try:
            credentials.canonical_browser_storage(
                origin=login_origin, cookies=cookies,
                local_storage=local_storage,
                session_storage=session_storage,
            )
            commit_paths = (
                credentials.cookie_jar_storage_path(workspace.slug, credential),
                credentials.token_path(workspace.slug, credential),
                credentials.browser_storage_path(workspace.slug, credential),
                credentials.attempt_path(workspace.slug, credential),
            )
            commit_snapshots = [
                (path, _snapshot_private_material(path))
                for path in commit_paths
            ]
            _browser_auth_install_cookies(
                workspace, credential, cookies, url
            )
            if maintenance_generation is not None:
                # A renewed browser proof is a replacement session.  Keeping a
                # bearer from the stale generation could override the newly
                # proven cookie on subsequent HTTP requests.
                credentials.token_path(
                    workspace.slug, credential
                ).unlink(missing_ok=True)
            if tokens:
                credentials.save_tokens(
                    workspace.slug, credential, tokens, origin=login_origin
                )
            if maintenance_generation is None:
                credentials.record_login_outcome(
                    workspace.slug, credential, established=True,
                    origin=login_origin, profile_revision=_profile_revision,
                )
            elif _upgrade_generation is not None:
                credentials.record_browser_state_upgrade_outcome(
                    workspace.slug, credential,
                    generation=_upgrade_generation, established=True,
                    origin=login_origin, profile_revision=_profile_revision,
                )
            else:
                credentials.record_refresh_outcome(
                    workspace.slug, credential,
                    generation=_refresh_generation, established=True,
                    origin=login_origin, profile_revision=_profile_revision,
                )
            credentials.save_browser_storage(
                workspace.slug, credential, origin=login_origin,
                cookies=cookies, local_storage=local_storage,
                session_storage=session_storage,
            )
            established = True
        except Exception as exc:
            for path, snapshot in reversed(commit_snapshots):
                try:
                    _restore_private_material(path, snapshot)
                except (OSError, credentials.CredentialError):
                    pass
            failure = failure or f"Private browser session could not be saved: {exc}"
    elif attempt:
        if maintenance_generation is None:
            credentials.record_login_outcome(workspace.slug, credential)
        elif _upgrade_generation is not None:
            credentials.record_browser_state_upgrade_outcome(
                workspace.slug, credential, generation=_upgrade_generation
            )
        else:
            credentials.record_refresh_outcome(
                workspace.slug, credential, generation=_refresh_generation
            )

    safe_final_url = _browser_redact_identity_text(
        final_url, secret_values, identity_values
    )
    safe_replay_url = _browser_redact_identity_text(
        replay_final_url, secret_values, identity_values
    )
    safe_verify_final_url = _browser_redact_identity_text(
        verify_final_url, secret_values, identity_values
    )
    safe_control_url = _browser_redact_identity_text(
        control_final_url, secret_values, identity_values
    )
    safe_verify_redirect_chain = _browser_auth_safe_redirect_chain(
        verify_redirect_chain, verify_url
    )
    safe_replay_redirect_chain = _browser_auth_safe_redirect_chain(
        replay_redirect_chain, verify_url
    )
    safe_control_redirect_chain = _browser_auth_safe_redirect_chain(
        control_redirect_chain, verify_url
    )
    safe_console = _browser_redacted_capture_value(
        console, secret_values, identity_values
    )
    safe_denied = [
        _browser_redact_identity_text(value, secret_values, identity_values)
        for value in denied_requests
    ]
    capture = {
        "verification_mode": (
            "status-differential" if status_mode else "marker"
        ),
        "login_status": page_status,
        "final_url": safe_final_url,
        "matched_submission_count": matched_submission_count,
        "credential_submission_requests": credential_submission_state["seen"],
        "blocked_duplicate_submissions": credential_submission_state["blocked"],
        "matched_submission_status": matched_submission_status,
        "login_session_material": login_material_delta,
        "login_api_responses": response_rows,
        "verification": {
            "url": _browser_redact_identity_text(
                verify_url, secret_values, identity_values
            ),
            "headers": _browser_redacted_capture_value(
                clean_verify_headers, secret_values, identity_values
            ),
            "status": verify_status,
            "final_url": safe_verify_final_url,
            "response_url_exact": _browser_auth_url_matches(
                verify_response_url, verify_url
            ),
            "method": verify_method,
            "redirected": verify_redirected,
            "redirect_chain": safe_verify_redirect_chain,
            "marker_present": bool(success_marker and success_marker in verify_source),
        },
        "persisted_session_replay": {
            "status": replay_status,
            "final_url": safe_replay_url,
            "response_url_exact": _browser_auth_url_matches(
                replay_response_url, verify_url
            ),
            "marker_present": bool(success_marker and success_marker in replay_source),
            "new_session_material": material_delta,
            "method": replay_method,
            "redirected": replay_redirected,
            "redirect_chain": safe_replay_redirect_chain,
        },
        "anonymous_control": {
            "status": control_status,
            "final_url": safe_control_url,
            "response_url_exact": _browser_auth_url_matches(
                control_response_url, verify_url
            ),
            "marker_present": bool(success_marker and success_marker in control_source),
            "method": control_method,
            "redirected": control_redirected,
            "redirect_chain": safe_control_redirect_chain,
        },
        "console": safe_console,
        "blocked_requests": safe_denied,
        "auth_blocker": blocker,
        "failure": _browser_redact_identity_text(
            failure, secret_values, identity_values
        ),
    }
    try:
        html_path, flow = _browser_auth_save_capture(
            workspace, url, capture, rendered_dom, secret_values,
            identity_values,
        )
    except OSError as exc:
        return _err(
            "Browser authentication capture could not be saved: "
            + _browser_redact_identity_text(
                str(exc), secret_values, identity_values
            )
        )

    session = credentials.session_status(workspace.slug, credential)
    data = {
        "credential": credential,
        "attempt": attempt,
        "status": page_status,
        "final_url": safe_final_url,
        "verify_status": verify_status,
        "verify_final_url": safe_verify_final_url,
        "verify_redirect_chain": safe_verify_redirect_chain,
        "replay_status": replay_status,
        "replay_redirect_chain": safe_replay_redirect_chain,
        "control_status": control_status,
        "control_redirect_chain": safe_control_redirect_chain,
        "verification_mode": (
            "status-differential" if status_mode else "marker"
        ),
        "matched_submission_count": matched_submission_count,
        "credential_submission_requests": credential_submission_state["seen"],
        "blocked_duplicate_submissions": credential_submission_state["blocked"],
        "matched_submission_status": matched_submission_status,
        "login_session_material": login_material_delta,
        "login_api_responses": response_rows,
        "auth_blocker": blocker,
        "flow": str(flow),
        "html_path": str(html_path),
        "blocked_requests": safe_denied,
        "console": safe_console,
        "browser_identity": browser_identity,
        "session": session,
    }
    if _refresh_generation is not None:
        data["session_renewal"] = {
            "attempted": bool(attempt),
            "proof_completed": established,
        }
    if _upgrade_generation is not None:
        data["browser_state_upgrade"] = {
            "attempted": bool(attempt),
            "proof_completed": established,
        }
    if established:
        proof_kind = (
            "status-differential proof" if status_mode
            else "marker proof"
        )
        return _ok(
            f"Browser session {credential!r} passed {proof_kind} after "
            f"attempt {attempt}; secrets were not exposed.",
            data,
        )
    if blocker:
        position = (
            f"after attempt {attempt}" if attempt
            else "before credential submission"
        )
        return _err(
            f"Browser authentication stopped {position}: {blocker}.",
            data,
        )
    if failure:
        return _err(
            _browser_redact_identity_text(
                failure, secret_values, identity_values
            )
            + f" Capture saved to {flow.name}.",
            data,
        )
    if status_mode:
        if (
            credential_submission_state["seen"] != 1
            or credential_submission_state["blocked"]
        ):
            reason = "exactly one credential submission request was not allowed"
        elif matched_submission_count != 1:
            reason = "exactly one credential submission response was not observed"
        elif matched_submission_status != status_verification["login_status"]:
            reason = "the credential submission status did not match the profile"
        elif not _browser_auth_url_matches(
            final_url, status_verification["expected_post_login_url"]
        ):
            reason = "the passive post-login URL did not match the profile"
        elif not login_material_delta:
            reason = "the login did not produce new reusable session material"
        elif (
            verify_status != status_verification["authenticated_status"]
            or not _browser_auth_redirect_contract_matches(
                verify_redirect_chain, (), verify_url, verify_method,
            )
            or not _browser_auth_url_matches(verify_response_url, verify_url)
            or not _browser_auth_url_matches(verify_final_url, verify_url)
        ):
            reason = (
                "live verification did not match the configured status, URL, "
                "method, and redirect chain"
            )
        elif (
            replay_status != status_verification["authenticated_status"]
            or not _browser_auth_redirect_contract_matches(
                replay_redirect_chain, (), verify_url, replay_method,
            )
            or not _browser_auth_url_matches(replay_response_url, verify_url)
            or not _browser_auth_url_matches(replay_final_url, verify_url)
        ):
            reason = (
                "the persisted session replay did not match the configured status, "
                "URL, method, and redirect chain"
            )
        else:
            reason = (
                "the anonymous control did not match the configured status, URL, "
                "method, and redirect chain"
            )
    elif not material_delta:
        reason = "no new reusable cookie or bearer session material was produced"
    elif success_marker not in replay_source:
        reason = "the persisted session replay did not contain the success marker"
    elif not control_conclusive:
        reason = "the anonymous control did not prove the marker was session-dependent"
    else:
        reason = "the persisted session replay response was not successful"
    return _err(
        f"Browser login attempt {attempt} remains unverified because {reason}. "
        f"Capture saved to {flow.name}.",
        data,
    )


def credential_browser_state_upgrade(workspace: Workspace,
                                     credential: str) -> dict:
    """Explicitly create exact rich state for one proven legacy browser session."""
    try:
        with credentials.auth_profile_lock(workspace.slug, credential):
            profile = credentials.load_auth_profile_optional(
                workspace.slug, credential
            )
            if not isinstance(profile, dict) or profile.get("strategy") != "browser":
                return _err("Browser-state upgrade requires a browser authentication profile.")
            browser = profile["browser"]
            verification = browser.get("verification")
            if not isinstance(verification, dict):
                return _err(
                    "Browser-state upgrade requires status-differential verification."
                )
            profile_revision = credentials.auth_profile_revision(profile)
            with credentials.session_material_lock(workspace.slug, credential):
                state = credentials.load_attempt_state(
                    workspace.slug, credential
                )
                if not state["established"]:
                    return _err("Browser-state upgrade requires an established session.")
                if state["proof_profile_revision"] != profile_revision:
                    return _err(
                        "Browser-state upgrade requires the current authentication profile proof."
                    )
                if credentials.load_browser_storage(
                    workspace.slug, credential
                ).get("available"):
                    return _ok(
                        f"Exact private browser state is already available for {credential!r}.",
                        {
                            "credential": credential,
                            "browser_state_upgrade": {
                                "attempted": False, "proof_completed": True,
                            },
                            "session": credentials.session_status(
                                workspace.slug, credential
                            ),
                        },
                    )
                generation = int(state["proof_generation"])
                if state["refresh_attempted_generation"] == generation:
                    return _err(
                        "Credential submission was already attempted for this session proof."
                    )
                return _credential_browser_login_locked(
                    workspace, profile["login_url"], credential=credential,
                    username_transform=profile["username_transform"],
                    username_selector=browser["username_selector"],
                    password_selector=browser["password_selector"],
                    submit_selector=browser["submit_selector"],
                    verify_url=profile["verify_url"], success_marker="",
                    verify_headers=browser["verify_headers"],
                    verification=verification, timeout=profile["timeout"],
                    _upgrade_generation=generation,
                    _profile_revision=profile_revision,
                )
    except (OSError, ValueError, credentials.CredentialError) as exc:
        return _err(str(exc))


def authenticated_browser_request(
    workspace: Workspace, url: str, *, credential: str,
    method: str = "GET", headers: Optional[dict] = None,
    body: Optional[str] = None, page_url: str = "",
    header_sources: Optional[dict] = None, timeout: int = 30,
    _profile_headers: Optional[dict] = None,
) -> dict:
    """Issue one exact-origin fetch from a private authenticated browser context."""
    try:
        clean_headers = _browser_request_headers(headers)
        sources = _browser_request_header_sources(header_sources, clean_headers)
        private_headers = _browser_auth_verify_headers(_profile_headers)
        normalized_method = str(method or "GET").strip().upper()
        if not normalized_method or not re.fullmatch(
            r"[!#$%&'*+.^_`|~0-9A-Z-]{1,32}", normalized_method
        ):
            raise ValueError("Browser request method is invalid.")
        if normalized_method in {"CONNECT", "TRACE", "TRACK"}:
            raise ValueError("Browser request method is not supported by browser fetch.")
        if body is not None and not isinstance(body, str):
            raise ValueError("Browser request body must be a string.")
        if len((body or "").encode("utf-8")) > 1_000_000:
            raise ValueError("Browser request body exceeds the 1,000,000-byte limit.")
        if normalized_method in {"GET", "HEAD"} and body not in {None, ""}:
            raise ValueError(f"Browser {normalized_method} requests cannot contain a body.")
        timeout_seconds = max(5, min(int(timeout), 120))
        overall_deadline = time.monotonic() + timeout_seconds
    except (TypeError, ValueError) as exc:
        return _err(str(exc))

    try:
        if urlsplit(url).fragment or (page_url and urlsplit(page_url).fragment):
            return _err("Authenticated browser request URLs cannot contain fragments.")
    except ValueError:
        return _err("Authenticated browser request URL is invalid.")

    for candidate in (url, page_url):
        if candidate:
            blocked = _scope_error(workspace, candidate)
            if blocked:
                return blocked

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return _err("Python Playwright is not installed.")
    executable = _browser_executable()
    if not executable:
        return _err("No Playwright-compatible Chromium or Chrome executable is installed.")

    try:
        with credentials.auth_profile_lock(workspace.slug, credential):
            profile = credentials.load_auth_profile_optional(
                workspace.slug, credential
            )
            with credentials.session_material_lock(workspace.slug, credential):
                secret = credentials.load_credential(workspace.slug, credential)
                state = credentials.load_attempt_state(workspace.slug, credential)
                if not state["established"]:
                    return _err(
                        f"Named credential {credential!r} has no established session."
                    )
                if not isinstance(profile, dict) or profile.get("strategy") != "browser":
                    return _err(
                        "Authenticated browser requests require the current configured "
                        "browser authentication profile."
                    )
                current_profile_revision = credentials.auth_profile_revision(profile)
                if str(state.get("proof_profile_revision") or "") != current_profile_revision:
                    return _err(
                        "The browser authentication profile changed after the current "
                        "session proof; reauthenticate before a browser-context request."
                    )
                bound_origin = credentials.normalize_origin(
                    str(state.get("origin") or "")
                )
                if credentials.normalize_origin(url) != bound_origin:
                    return _err(
                        f"Refused authenticated browser request for {credential!r}: "
                        "the URL does not match the session's exact origin."
                    )
                if not page_url:
                    if isinstance(profile, dict) and profile.get("strategy") == "browser":
                        verification = profile.get("browser", {}).get("verification")
                        page_url = str(
                            verification.get("expected_post_login_url")
                            if isinstance(verification, dict)
                            else profile.get("verify_url") or ""
                        )
                    if not page_url:
                        return _err(
                            "Authenticated browser request requires a same-origin page_url "
                            "when no browser profile page is available."
                        )
                blocked = _scope_error(workspace, page_url)
                if blocked:
                    return blocked
                if credentials.normalize_origin(page_url) != bound_origin:
                    return _err(
                        "Authenticated browser page_url must match the session's exact origin."
                    )
                rich_state = credentials.load_browser_storage(
                    workspace.slug, credential
                )
                if not rich_state.get("available"):
                    return _err(
                        "Exact private browser state is unavailable for this proven legacy "
                        "session; call credential_browser_login with "
                        "upgrade_browser_state=true once before using browser-context "
                        "requests.",
                        {
                            "credential": credential,
                            "migration_required": True,
                            "session": credentials.session_status(
                                workspace.slug, credential
                            ),
                        },
                    )
                if (
                    rich_state.get("origin") != bound_origin
                    or rich_state.get("proof_generation") != state["proof_generation"]
                    or rich_state.get("profile_revision")
                    != current_profile_revision
                ):
                    return _err("Private browser state no longer matches the session proof.")
                tokens = credentials.load_tokens(workspace.slug, credential)
                bearer = credentials.select_bearer(tokens)
                if bearer and credentials.token_origin(
                    workspace.slug, credential
                ) != bound_origin:
                    return _err("Private bearer state no longer matches the session origin.")

                source_names = {item["header"].lower() for item in sources}
                caller_names = {key.lower() for key in clean_headers}
                profile_names = {key.lower() for key in private_headers}
                if (caller_names | source_names) & profile_names:
                    return _err(
                        "Browser request headers duplicate a private profile header."
                    )
                route_headers = dict(private_headers)
                if bearer and "authorization" not in source_names:
                    route_headers["Authorization"] = f"Bearer {bearer}"

                denied_requests: list[str] = []
                network_state = {"count": 0, "blocked": 0, "limit": 4}
                request_rows: list[dict] = []
                request_indexes: dict[int, int] = {}
                cdp_requests: dict[str, tuple[str, str]] = {}
                fetch_window = {"active": False, "primary": None}
                bootstrap_nonce = ""
                context = None
                page = None
                browser_identity = ""
                fetch_result: dict = {}
                failure = ""
                final_cookies = list(rich_state.get("cookies") or [])
                final_local = dict(rich_state.get("local_storage") or {})
                final_session = dict(rich_state.get("session_storage") or {})

                def remember_request(request) -> None:
                    if len(request_rows) >= 100:
                        return
                    if bootstrap_nonce and _browser_inert_bootstrap_matches(
                        str(request.url or ""),
                        method=str(request.method or ""),
                        resource_type=str(request.resource_type or ""),
                        origin=bound_origin, nonce=bootstrap_nonce,
                    ):
                        # This document is locally synthesized transport setup,
                        # not target evidence or a network request.
                        return
                    try:
                        request_headers = dict(request.all_headers())
                    except Exception:
                        request_headers = dict(request.headers or {})
                    request_headers = {
                        key: value for key, value in request_headers.items()
                        if str(key).lower() != "x-grypton-private-marker"
                    }
                    row = {
                        "method": str(request.method or "GET").upper(),
                        "url": str(request.url or ""),
                        "headers": request_headers,
                        "body": str(request.post_data or "")[:1_000_000],
                        "resource_type": str(request.resource_type or ""),
                        "status": 0,
                        "response_headers": {},
                        "failed": False,
                        "response_seen": False,
                    }
                    index = len(request_rows)
                    request_rows.append(row)
                    request_indexes[id(request)] = index
                    if (
                        fetch_window["active"]
                        and row["method"] == normalized_method
                        and (
                            (
                                row["method"] == fetch_window.get("primary_method")
                                and row["url"] == fetch_window.get("primary_url")
                            )
                            or _browser_auth_url_matches(row["url"], url)
                        )
                    ):
                        fetch_window["primary"] = index

                def remember_response(response) -> None:
                    index = request_indexes.get(id(response.request))
                    if index is None:
                        response_url = str(response.request.url or "")
                        response_method = str(response.request.method or "GET").upper()
                        index = next((
                            candidate for candidate in range(len(request_rows) - 1, -1, -1)
                            if not request_rows[candidate].get("response_seen")
                            and request_rows[candidate]["method"] == response_method
                            and request_rows[candidate]["url"] == response_url
                        ), None)
                    if index is None:
                        return
                    try:
                        response_headers = dict(response.all_headers())
                    except Exception:
                        response_headers = dict(response.headers or {})
                    request_rows[index]["status"] = int(response.status or 0)
                    request_rows[index]["response_headers"] = response_headers
                    request_rows[index]["response_seen"] = True

                def remember_failure(request) -> None:
                    index = request_indexes.get(id(request))
                    if index is None:
                        request_url = str(request.url or "")
                        request_method = str(request.method or "GET").upper()
                        index = next((
                            candidate for candidate in range(len(request_rows) - 1, -1, -1)
                            if request_rows[candidate]["method"] == request_method
                            and request_rows[candidate]["url"] == request_url
                        ), None)
                    if index is not None:
                        request_rows[index]["failed"] = True

                def remember_cdp_response(url_value: str, method_value: str,
                                          response_value: dict) -> None:
                    index = next((
                        candidate for candidate in range(len(request_rows) - 1, -1, -1)
                        if request_rows[candidate]["method"] == method_value
                        and request_rows[candidate]["url"] == url_value
                    ), None)
                    if index is None:
                        return
                    request_rows[index]["status"] = int(
                        response_value.get("status") or 0
                    )
                    raw_headers = response_value.get("headers")
                    if isinstance(raw_headers, dict):
                        request_rows[index]["response_headers"] = {
                            str(key): str(value) for key, value in raw_headers.items()
                        }
                    request_rows[index]["response_seen"] = True

                try:
                    with _isolated_browser_profile(executable) as launch_profile:
                        browser_identity = str(launch_profile["identity"])
                        with sync_playwright() as playwright:
                            context = _launch_scoped_browser_context(
                                playwright, launch_profile, workspace,
                                denied_requests,
                                bound_header_origin=bound_origin,
                                bound_headers=route_headers,
                                exact_origin=bound_origin,
                                network_state=network_state,
                                launch_timeout_ms=max(
                                    1, int((overall_deadline - time.monotonic()) * 1000)
                                ),
                            )
                            context.add_cookies(
                                list(rich_state.get("cookies") or [])
                            )
                            _browser_auth_restore_storage(
                                context, bound_origin,
                                {
                                    "local_storage": rich_state.get("local_storage") or {},
                                    "session_storage": rich_state.get("session_storage") or {},
                                },
                            )
                            context.on("request", remember_request)
                            context.on("response", remember_response)
                            context.on("requestfailed", remember_failure)
                            bootstrap_parts = urlsplit(page_url)
                            bootstrap_query = parse_qsl(
                                bootstrap_parts.query, keep_blank_values=True
                            )
                            bootstrap_nonce = hashlib.sha256(
                                f"{time.time_ns()}:{credential}".encode()
                            ).hexdigest()[:24]
                            bootstrap_query.append((
                                "__grypton_context__", bootstrap_nonce,
                            ))
                            bootstrap_url = urlunsplit((
                                bootstrap_parts.scheme, bootstrap_parts.netloc,
                                bootstrap_parts.path, urlencode(bootstrap_query), "",
                            ))
                            request_marker = hashlib.sha256(
                                f"request:{time.time_ns()}:{credential}".encode()
                            ).hexdigest()
                            marker_header = "X-Grypton-Private-Marker"

                            def private_context_route(route) -> None:
                                request = route.request
                                if _browser_inert_bootstrap_matches(
                                    str(request.url or ""),
                                    method=str(request.method or ""),
                                    resource_type=str(request.resource_type or ""),
                                    origin=bound_origin, nonce=bootstrap_nonce,
                                ):
                                    route.fulfill(
                                    status=200,
                                    headers={
                                        "Content-Type": "text/html; charset=utf-8",
                                        "Content-Security-Policy": (
                                            "default-src 'none'; connect-src 'self'; "
                                            "img-src 'none'; media-src 'none'; object-src 'none'; "
                                            "frame-src 'none'; worker-src 'none'; form-action 'none'; "
                                            "base-uri 'none'; script-src 'none'"
                                        ),
                                        "Referrer-Policy": "no-referrer",
                                        "X-Content-Type-Options": "nosniff",
                                    },
                                    body="<!doctype html><meta charset=utf-8><title>Grypton</title>",
                                    )
                                    return
                                request_headers = dict(request.headers or {})
                                observed_marker = next((
                                    str(value) for key, value in request_headers.items()
                                    if str(key).lower() == marker_header.lower()
                                ), "")
                                if observed_marker == request_marker:
                                    fetch_window["primary_method"] = str(
                                        request.method or "GET"
                                    ).upper()
                                    fetch_window["primary_url"] = str(request.url or "")
                                    request_headers = {
                                        key: value for key, value in request_headers.items()
                                        if str(key).lower() != marker_header.lower()
                                    }
                                    route.fallback(headers=request_headers)
                                    return
                                route.fallback()

                            # This route runs before the generic exact-origin
                            # boundary and falls back into it for real traffic.
                            context.route("**/*", private_context_route)
                            page = context.new_page()
                            cdp = context.new_cdp_session(page)

                            def cdp_request(event) -> None:
                                request_id = str(event.get("requestId") or "")
                                request_value = event.get("request") or {}
                                method_value = str(
                                    request_value.get("method") or "GET"
                                ).upper()
                                url_value = str(request_value.get("url") or "")
                                redirected = event.get("redirectResponse")
                                prior = cdp_requests.get(request_id)
                                if isinstance(redirected, dict) and prior:
                                    remember_cdp_response(prior[1], prior[0], redirected)
                                cdp_requests[request_id] = (method_value, url_value)

                            def cdp_response(event) -> None:
                                request_id = str(event.get("requestId") or "")
                                response_value = event.get("response") or {}
                                prior = cdp_requests.get(request_id)
                                if prior and isinstance(response_value, dict):
                                    remember_cdp_response(
                                        prior[1], prior[0], response_value
                                    )

                            cdp.on("Network.requestWillBeSent", cdp_request)
                            cdp.on("Network.responseReceived", cdp_response)
                            cdp.send("Network.enable")
                            navigation_timeout_ms = int(
                                (overall_deadline - time.monotonic()) * 1000
                            )
                            if navigation_timeout_ms <= 0:
                                raise TimeoutError(
                                    "authenticated browser request deadline expired"
                                )
                            navigation = page.goto(
                                bootstrap_url, wait_until="domcontentloaded",
                                timeout=navigation_timeout_ms,
                            )
                            if navigation is None or not 200 <= int(navigation.status) < 400:
                                failure = "Authenticated browser bootstrap page did not load successfully."
                            elif credentials.normalize_origin(page.url) != bound_origin:
                                failure = "Authenticated browser bootstrap ended outside its exact origin."
                            else:
                                fetch_window["active"] = True
                                fetch_timeout_ms = int(
                                    (overall_deadline - time.monotonic()) * 1000
                                )
                                if fetch_timeout_ms <= 0:
                                    raise TimeoutError(
                                        "authenticated browser request deadline expired"
                                    )
                                fetch_result = page.evaluate(
                                    """async (input) => {
                                      const overallStarted = Date.now();
                                      const privateHeaders = {};
                                      const missing = [];
                                      let metaDocument = null;
                                      if (input.sources.some((item) => item.source === 'meta')) {
                                        const metaController = new AbortController();
                                        const metaTimer = setTimeout(
                                          () => metaController.abort(), input.timeout_ms
                                        );
                                        try {
                                          const metaResponse = await fetch(input.meta_url, {
                                            method: 'GET', credentials: 'include', redirect: 'manual',
                                            signal: metaController.signal
                                          });
                                          if (!metaResponse.ok || !metaResponse.body) {
                                            return {ok: false, kind: 'meta-fetch-failed'};
                                          }
                                          const reader = metaResponse.body.getReader();
                                          const chunks = [];
                                          let size = 0;
                                          while (true) {
                                            const next = await reader.read();
                                            if (next.done) break;
                                            size += next.value.byteLength;
                                            if (size > 524288) {
                                              await reader.cancel();
                                              return {ok: false, kind: 'meta-fetch-failed'};
                                            }
                                            chunks.push(next.value);
                                          }
                                          const bytes = new Uint8Array(size);
                                          let offset = 0;
                                          for (const chunk of chunks) {
                                            bytes.set(chunk, offset); offset += chunk.byteLength;
                                          }
                                          metaDocument = new DOMParser().parseFromString(
                                            new TextDecoder().decode(bytes), 'text/html'
                                          );
                                        } catch (_) {
                                          return {ok: false, kind: 'meta-fetch-failed'};
                                        } finally {
                                          clearTimeout(metaTimer);
                                        }
                                      }
                                      for (const item of input.sources) {
                                        let value = null;
                                        if (item.source === 'localStorage') {
                                          value = localStorage.getItem(item.name);
                                        } else if (item.source === 'sessionStorage') {
                                          value = sessionStorage.getItem(item.name);
                                        } else if (item.source === 'cookie') {
                                          for (const part of document.cookie.split(';')) {
                                            const trimmed = part.trim();
                                            const split = trimmed.indexOf('=');
                                            const key = split < 0 ? trimmed : trimmed.slice(0, split);
                                            if (key === item.name) {
                                              value = split < 0 ? '' : trimmed.slice(split + 1);
                                              break;
                                            }
                                          }
                                        } else if (item.source === 'meta') {
                                          for (const meta of metaDocument.getElementsByTagName('meta')) {
                                            if (meta.getAttribute('name') === item.name) {
                                              value = meta.getAttribute('content');
                                              break;
                                            }
                                          }
                                        }
                                        if (value === null) {
                                          missing.push(item.header);
                                          continue;
                                        }
                                        if (item.url_decode) {
                                          try { value = decodeURIComponent(value); }
                                          catch (_) { missing.push(item.header); continue; }
                                        }
                                        privateHeaders[item.header] = item.prefix + value;
                                      }
                                      if (missing.length) {
                                        return {ok: false, kind: 'missing-header-source', missing};
                                      }
                                      const requestHeaders = Object.assign({}, input.headers, privateHeaders);
                                      requestHeaders[input.marker_header] = input.marker;
                                      const controller = new AbortController();
                                      const remainingMs = Math.max(
                                        1, input.timeout_ms - (Date.now() - overallStarted)
                                      );
                                      const timer = setTimeout(() => controller.abort(), remainingMs);
                                      try {
                                        const options = {
                                          method: input.method,
                                          headers: requestHeaders,
                                          credentials: 'include',
                                          redirect: 'manual',
                                          signal: controller.signal,
                                        };
                                        if (input.body !== null && input.method !== 'GET' && input.method !== 'HEAD') {
                                          options.body = input.body;
                                        }
                                        const response = await fetch(input.url, options);
                                        const chunks = [];
                                        let captured = 0;
                                        let observed = 0;
                                        let truncated = false;
                                        if (response.body) {
                                          const reader = response.body.getReader();
                                          while (true) {
                                            const next = await reader.read();
                                            if (next.done) break;
                                            observed += next.value.byteLength;
                                            const remaining = Math.max(0, input.max_bytes - captured);
                                            if (remaining > 0) {
                                              const piece = next.value.slice(0, remaining);
                                              chunks.push(piece);
                                              captured += piece.byteLength;
                                            }
                                            if (next.value.byteLength > remaining || captured >= input.max_bytes) {
                                              if (next.value.byteLength > remaining) truncated = true;
                                              const probe = await reader.read();
                                              if (!probe.done) {
                                                observed += probe.value.byteLength;
                                                truncated = true;
                                              }
                                              await reader.cancel();
                                              break;
                                            }
                                          }
                                        }
                                        const bytes = new Uint8Array(captured);
                                        let offset = 0;
                                        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
                                        let binary = '';
                                        for (let i = 0; i < bytes.length; i += 32768) {
                                          binary += String.fromCharCode(...bytes.subarray(i, i + 32768));
                                        }
                                        return {
                                          ok: true,
                                          status: response.status,
                                          status_text: response.statusText,
                                          url: response.url,
                                          redirected: response.redirected,
                                          headers: Object.fromEntries(response.headers.entries()),
                                          body_base64: btoa(binary),
                                          captured_bytes: captured,
                                          observed_bytes: observed,
                                          truncated,
                                        };
                                      } catch (_) {
                                        return {ok: false, kind: 'fetch-failed'};
                                      } finally {
                                        clearTimeout(timer);
                                      }
                                    }""",
                                    {
                                        "url": url, "method": normalized_method,
                                        "headers": clean_headers,
                                        "body": body if body is not None else None,
                                        "sources": sources,
                                        "meta_url": page_url,
                                        "timeout_ms": fetch_timeout_ms,
                                        "max_bytes": MAX_RESPONSE_BYTES,
                                        "marker_header": marker_header,
                                        "marker": request_marker,
                                    },
                                )
                                fetch_window["active"] = False
                                if not isinstance(fetch_result, dict):
                                    fetch_result = {"ok": False, "kind": "fetch-failed"}
                                page.wait_for_timeout(50)
                            if page is not None:
                                final_local = _browser_auth_local_storage(page)
                                final_session = _browser_auth_session_storage(page)
                            final_cookies = _browser_auth_persistable_cookies(
                                list(context.cookies()), bound_origin
                            )
                            context.close()
                            context = None
                except Exception:
                    failure = failure or "Authenticated browser request failed inside Chromium."
                finally:
                    if context is not None:
                        try:
                            if page is not None:
                                final_local = _browser_auth_local_storage(page)
                                final_session = _browser_auth_session_storage(page)
                            final_cookies = _browser_auth_persistable_cookies(
                                list(context.cookies()), bound_origin
                            )
                        except Exception:
                            pass
                        try:
                            context.close()
                        except Exception:
                            pass

                try:
                    body_bytes = base64.b64decode(
                        str(fetch_result.get("body_base64") or ""), validate=True
                    )
                except (ValueError, TypeError):
                    body_bytes = b""
                    failure = failure or "Authenticated browser response capture was invalid."
                if len(body_bytes) > MAX_RESPONSE_BYTES:
                    body_bytes = body_bytes[:MAX_RESPONSE_BYTES]
                    failure = failure or "Authenticated browser response exceeded its capture bound."
                response_body = body_bytes.decode("utf-8", "replace")
                response_headers = (
                    dict(fetch_result.get("headers") or {})
                    if isinstance(fetch_result.get("headers"), dict) else {}
                )
                status = int(fetch_result.get("status") or 0)
                primary_index = fetch_window.get("primary")
                if not isinstance(primary_index, int):
                    primary_index = next((
                        candidate for candidate in range(len(request_rows) - 1, -1, -1)
                        if request_rows[candidate]["method"]
                        == fetch_window.get("primary_method")
                        and request_rows[candidate]["url"]
                        == fetch_window.get("primary_url")
                    ), None)
                    fetch_window["primary"] = primary_index
                if (
                    status == 0 and isinstance(primary_index, int)
                    and 0 <= primary_index < len(request_rows)
                    and 300 <= int(request_rows[primary_index].get("status") or 0) < 400
                ):
                    # Chromium exposes a manually handled cross-origin redirect
                    # as an opaque response.  The routed network event remains
                    # authoritative and no redirect request was issued.
                    status = int(request_rows[primary_index]["status"])
                    response_headers = dict(
                        request_rows[primary_index].get("response_headers") or {}
                    )
                final_url = str(fetch_result.get("url") or url)
                if fetch_result.get("ok"):
                    try:
                        if credentials.normalize_origin(final_url) != bound_origin:
                            failure = failure or "Authenticated browser fetch ended outside its exact origin."
                    except credentials.CredentialError:
                        failure = failure or "Authenticated browser fetch returned an invalid final URL."

                new_tokens = dict(tokens)
                new_tokens.update(_browser_auth_tokens(
                    (response_body,), final_local, final_session
                ))
                runtime_values: list[str] = [
                    secret["username"], secret["password"], *tokens.values(),
                    *new_tokens.values(), *private_headers.values(),
                ]
                for browser_cookies in (
                    rich_state.get("cookies") or [], final_cookies,
                ):
                    runtime_values.extend(
                        str(cookie.get("value") or "")
                        for cookie in browser_cookies
                        if isinstance(cookie, dict) and cookie.get("value") is not None
                    )
                for area in (
                    rich_state.get("local_storage") or {},
                    rich_state.get("session_storage") or {},
                    final_local, final_session,
                ):
                    runtime_values.extend(
                        value for value in area.values()
                        if isinstance(value, str) and value
                    )
                if isinstance(primary_index, int) and primary_index < len(request_rows):
                    primary_headers = request_rows[primary_index].get("headers") or {}
                    for source in sources:
                        for key, value in primary_headers.items():
                            if key.lower() == source["header"].lower() and value:
                                runtime_values.append(str(value))
                runtime_values.extend(
                    _browser_private_response_values(response_body, response_headers)
                )
                for row in request_rows:
                    runtime_values.extend(_browser_private_response_values(
                        "", dict(row.get("response_headers") or {})
                    ))
                    runtime_values.extend(_browser_private_response_values(
                        "", {"location": str(row.get("url") or "")}
                    ))
                secret_values = _serialized_secret_variants(runtime_values)
                identity_values = _browser_identity_values((response_body,))

                commit_material = bool(
                    fetch_result.get("ok") and not failure and 200 <= status < 400
                )
                commit_error = False
                commit_snapshots: list[
                    tuple[Path, tuple[bool, bytes, int]]
                ] = []
                if commit_material:
                    try:
                        credentials.canonical_browser_storage(
                            origin=bound_origin, cookies=final_cookies,
                            local_storage=final_local,
                            session_storage=final_session,
                        )
                        current_state = credentials.load_attempt_state(
                            workspace.slug, credential
                        )
                        if (
                            not current_state["established"]
                            or current_state["proof_generation"] != state["proof_generation"]
                            or str(current_state.get("proof_profile_revision") or "")
                            != str(state.get("proof_profile_revision") or "")
                        ):
                            raise credentials.CredentialError(
                                "authenticated session proof changed during browser request"
                            )
                        paths = (
                            credentials.cookie_jar_storage_path(workspace.slug, credential),
                            credentials.token_path(workspace.slug, credential),
                            credentials.browser_storage_path(workspace.slug, credential),
                            credentials.attempt_path(workspace.slug, credential),
                        )
                        commit_snapshots = [
                            (path, _snapshot_private_material(path)) for path in paths
                        ]
                        _browser_auth_install_cookies(
                            workspace, credential, final_cookies, bound_origin
                        )
                        if new_tokens:
                            credentials.save_tokens(
                                workspace.slug, credential, new_tokens,
                                origin=bound_origin,
                            )
                        credentials.save_browser_storage(
                            workspace.slug, credential, origin=bound_origin,
                            cookies=final_cookies, local_storage=final_local,
                            session_storage=final_session,
                        )
                    except Exception:
                        commit_error = True
                        commit_material = False
                        for path, snapshot in reversed(commit_snapshots):
                            try:
                                _restore_private_material(path, snapshot)
                            except (OSError, credentials.CredentialError):
                                pass

                safe_denied = [
                    redact_sensitive_text(value, secret_values)
                    for value in denied_requests[:100]
                ]
                derived_names = {item["header"].lower() for item in sources}
                flow_paths: list[str] = []
                primary_flow = ""
                capture_failed = False
                for index, row in enumerate(request_rows):
                    request_headers = {
                        str(key): (
                            "[REDACTED]" if str(key).lower() in derived_names
                            else str(value)
                        )
                        for key, value in dict(row.get("headers") or {}).items()
                        if str(key).lower() not in {
                            "host", "proxy-authorization", "proxy-connection",
                        }
                    }
                    row_response_headers = dict(row.get("response_headers") or {})
                    response_text = "HTTP " + str(int(row.get("status") or 0))
                    if row_response_headers:
                        response_text += "\n" + "\n".join(
                            f"{key}: {value}"
                            for key, value in row_response_headers.items()
                        )
                    response_bytes = None
                    if index == primary_index:
                        response_text += "\n\n" + response_body
                        response_bytes = int(
                            fetch_result.get("observed_bytes") or len(body_bytes)
                        )
                    try:
                        flow = _save_flow(
                            workspace, str(row.get("method") or "GET"),
                            str(row.get("url") or ""), request_headers,
                            str(row.get("body") or "") or None,
                            response_text,
                            transport=f"credential-playwright:{credential}",
                            returncode=1 if row.get("failed") else 0,
                            secret_values=secret_values,
                            response_bytes=response_bytes,
                        )
                    except OSError:
                        capture_failed = True
                        break
                    flow_paths.append(str(flow))
                    if index == primary_index:
                        primary_flow = str(flow)

                if capture_failed and commit_material:
                    for path, snapshot in reversed(commit_snapshots):
                        try:
                            _restore_private_material(path, snapshot)
                        except (OSError, credentials.CredentialError):
                            pass
                    commit_material = False

                safe_body = _browser_redact_identity_text(
                    response_body[:MAX_INLINE_RESPONSE_CHARS],
                    secret_values, identity_values,
                )
                safe_headers = {
                    str(key): (
                        "[REDACTED]"
                        if str(key).lower() in _SENSITIVE_HEADERS
                        else _browser_redact_identity_text(
                            value, secret_values, identity_values
                        )
                    )
                    for key, value in response_headers.items()
                }
                safe_final_url = _browser_redact_identity_text(
                    final_url, secret_values, identity_values
                )
                network_summary = [
                    {
                        "method": str(row.get("method") or "GET"),
                        "url": redact_sensitive_text(
                            str(row.get("url") or ""), secret_values
                        ),
                        "status": int(row.get("status") or 0),
                        "failed": bool(row.get("failed")),
                        "flow": flow_paths[index] if index < len(flow_paths) else "",
                    }
                    for index, row in enumerate(request_rows)
                ]
                data = {
                    "credential": credential,
                    "status": status,
                    "status_text": redact_sensitive_text(
                        fetch_result.get("status_text") or "", secret_values
                    ),
                    "final_url": safe_final_url,
                    "redirected": bool(fetch_result.get("redirected")),
                    "headers": safe_headers,
                    "response": safe_body,
                    "response_bytes": int(
                        fetch_result.get("observed_bytes") or len(body_bytes)
                    ),
                    "response_truncated": bool(fetch_result.get("truncated")),
                    "flow": primary_flow,
                    "flows": flow_paths,
                    "network_requests": network_summary,
                    "network_request_count": int(network_state.get("count") or 0),
                    "blocked_requests": safe_denied,
                    "blocked_request_count": int(network_state.get("blocked") or 0),
                    "derived_headers": [item["header"] for item in sources],
                    "browser_identity": browser_identity,
                    "session_material_committed": commit_material,
                    "session_material_rollback": not commit_material,
                    "session": credentials.session_status(
                        workspace.slug, credential
                    ),
                }
                if capture_failed:
                    return _err(
                        "Authenticated browser request completed, but its request capture "
                        "could not be saved.", data,
                    )
                if commit_error:
                    return _err(
                        "Authenticated browser request completed, but rotated private "
                        "session material could not be committed and was restored.", data,
                    )
                if failure:
                    return _err(failure, data)
                if fetch_result.get("kind") == "missing-header-source":
                    missing = fetch_result.get("missing")
                    safe_missing = [
                        str(item) for item in missing[:16]
                    ] if isinstance(missing, list) else []
                    data["missing_header_sources"] = safe_missing
                    return _err(
                        "Authenticated browser request did not start because a private "
                        "header source was unavailable.", data,
                    )
                if not fetch_result.get("ok"):
                    return _err(
                        "Authenticated browser fetch failed; private session material "
                        "was retained.", data,
                    )
                if status in {401, 403}:
                    data["auth_observation"] = _endpoint_auth_observation(
                        response_body, f"HTTP {status}"
                    )
                    return _err(
                        f"Browser-context request returned HTTP {status}; the proven "
                        "session and its prior private material were retained.", data,
                    )
                return _ok(
                    f"Browser-context request returned HTTP {status}; "
                    f"{len(flow_paths)} browser request capture(s) were saved.",
                    data,
                )
    except (OSError, ValueError, credentials.CredentialError) as exc:
        return _err(str(exc))
    except Exception:
        return _err(
            "Authenticated browser request failed; private session material was retained."
        )


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
_MAX_LOCAL_SEARCH_PATTERN_BYTES = 4096
_MAX_LOCAL_SEARCH_MATCHES = 50
_MAX_LOCAL_SEARCH_CONTEXT_BYTES = 2048
_MAX_LOCAL_SEARCH_RETURN_BYTES = 48_000
_MAX_LOCAL_SEARCH_MATCH_PREVIEW_BYTES = 512
_LOCAL_REGEX_TIMEOUT_SECONDS = 10


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


def _workspace_relative_file_path(workspace: Workspace, path: str) -> str:
    """Translate transport-visible workspace paths to the canonical relative form.

    OpenCode runs from a private transport directory where the engagement is
    exposed as ``engagement/``. Kraude can therefore copy either that alias or
    the exact absolute engagement path from a tool result. Normalize only those
    two representations; the component-by-component no-symlink opener remains
    the authority for traversal and file-type checks.
    """
    raw = str(path or "").strip()
    candidate = Path(raw)
    if candidate.is_absolute():
        try:
            return str(candidate.relative_to(workspace.root))
        except ValueError:
            return raw
    parts = candidate.parts
    if parts and parts[0] == "engagement":
        return str(Path(*parts[1:])) if len(parts) > 1 else ""
    return raw


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


def _read_open_file(fd: int, size: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(fd, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _literal_search_positions(data: bytes, pattern: bytes, *, ignore_case: bool,
                              limit: int) -> list[tuple[int, int]]:
    haystack = data.lower() if ignore_case else data
    needle = pattern.lower() if ignore_case else pattern
    positions: list[tuple[int, int]] = []
    cursor = 0
    while len(positions) < limit:
        start = haystack.find(needle, cursor)
        if start < 0:
            break
        end = start + len(needle)
        positions.append((start, end))
        cursor = end
    return positions


def _regex_search_positions(fd: int, size: int, pattern: str, *,
                            ignore_case: bool, limit: int) -> list[tuple[int, int]]:
    helper = Path(__file__).with_name("_search_helper.py")
    request = json.dumps({
        "pattern": pattern,
        "ignore_case": bool(ignore_case),
        "limit": limit,
    }).encode("utf-8")
    result = subprocess.run(
        [sys.executable, str(helper), str(fd)], input=request,
        capture_output=True, timeout=_LOCAL_REGEX_TIMEOUT_SECONDS,
        pass_fds=(fd,), env=_minimal_local_environment(), umask=0o077,
    )
    try:
        payload = json.loads(result.stdout.decode("utf-8", "replace"))
    except (UnicodeError, ValueError) as exc:
        raise ValueError("regular-expression search returned an invalid result") from exc
    if result.returncode or not payload.get("ok"):
        detail = str(payload.get("error") or "regular-expression search failed")
        raise ValueError(detail)
    positions = payload.get("positions")
    if not isinstance(positions, list):
        raise ValueError("regular-expression search returned invalid offsets")
    output: list[tuple[int, int]] = []
    previous_start = -1
    for value in positions:
        if (not isinstance(value, list) or len(value) != 2
                or not all(isinstance(item, int) for item in value)):
            raise ValueError("regular-expression search returned invalid offsets")
        start, end = value
        if start < previous_start or start < 0 or end < start or end > size:
            raise ValueError("regular-expression search returned invalid offsets")
        output.append((start, end))
        previous_start = start
    return output


def _match_preview(data: bytes, start: int, end: int) -> tuple[str, bool]:
    matched = data[start:end]
    if len(matched) <= _MAX_LOCAL_SEARCH_MATCH_PREVIEW_BYTES:
        return matched.decode("utf-8", "replace"), False
    half = _MAX_LOCAL_SEARCH_MATCH_PREVIEW_BYTES // 2
    omitted = len(matched) - (half * 2)
    value = (
        matched[:half].decode("utf-8", "replace")
        + f"\n... [{omitted} matched bytes omitted] ...\n"
        + matched[-half:].decode("utf-8", "replace")
    )
    return value, True


def _render_search_matches(data: bytes, positions: list[tuple[int, int]], *,
                           context_bytes: int) -> tuple[list[dict], bool]:
    matches: list[dict] = []
    returned_bytes = 0
    line = 1
    line_start_byte = 0
    line_cursor = 0
    truncated = False
    for start, end in positions:
        between = data[line_cursor:start]
        newlines = between.count(b"\n")
        if newlines:
            line += newlines
            line_start_byte = data.rfind(b"\n", line_cursor, start) + 1
        line_cursor = start

        context_start = max(0, start - context_bytes)
        context_end = min(len(data), end + context_bytes)
        preview, match_truncated = _match_preview(data, start, end)
        before = data[context_start:start].decode("utf-8", "replace")
        after = data[end:context_end].decode("utf-8", "replace")
        rendered = before + preview + after
        rendered_bytes = len(rendered.encode("utf-8"))
        if matches and returned_bytes + rendered_bytes > _MAX_LOCAL_SEARCH_RETURN_BYTES:
            truncated = True
            break
        returned_bytes += rendered_bytes
        matches.append({
            "byte_start": start,
            "byte_end": end,
            "match_bytes": end - start,
            "line_start": line,
            "line_end": line + data.count(b"\n", start, end),
            "line_byte_offset": start - line_start_byte,
            "context_byte_start": context_start,
            "context_byte_end": context_end,
            "context": rendered,
            "match_preview": preview,
            "match_truncated": match_truncated,
        })
    return matches, truncated


def local_analyze(workspace: Workspace, path: str, *, analyzer: str = "file",
                  min_length: int = 6, pattern: str = "",
                  ignore_case: bool = False, context_bytes: int = 160,
                  max_matches: int = 20) -> dict:
    """Run one fixed, offline analyzer against one safely opened workspace file."""
    analyzer = str(analyzer or "").lower()
    if analyzer not in {"file", "strings", "sha256", "literal", "regex"}:
        return _err("Analyzer must be one of: file, strings, sha256, literal, regex.")
    path = _workspace_relative_file_path(workspace, path)
    try:
        fd, size = _open_workspace_regular_file(workspace, path)
    except (OSError, ValueError) as exc:
        return _err(f"Local analysis input was rejected: {exc}")
    try:
        if analyzer in {"literal", "regex"}:
            try:
                encoded_pattern = str(pattern or "").encode("utf-8")
                requested_matches = int(max_matches)
                requested_context = int(context_bytes)
            except (TypeError, ValueError, UnicodeError):
                return _err("Search parameters must be valid UTF-8 text and integers.")
            if not encoded_pattern:
                return _err("Search pattern must not be empty.")
            if len(encoded_pattern) > _MAX_LOCAL_SEARCH_PATTERN_BYTES:
                return _err("Search pattern exceeds the 4096-byte limit.")
            if not 1 <= requested_matches <= _MAX_LOCAL_SEARCH_MATCHES:
                return _err("max_matches must be between 1 and 50.")
            if not 0 <= requested_context <= _MAX_LOCAL_SEARCH_CONTEXT_BYTES:
                return _err("context_bytes must be between 0 and 2048.")
            search_limit = requested_matches + 1
            if analyzer == "literal":
                data = _read_open_file(fd, size)
                positions = _literal_search_positions(
                    data, encoded_pattern, ignore_case=bool(ignore_case),
                    limit=search_limit,
                )
            else:
                positions = _regex_search_positions(
                    fd, size, str(pattern), ignore_case=bool(ignore_case),
                    limit=search_limit,
                )
                data = _read_open_file(fd, size)
            more_matches = len(positions) > requested_matches
            selected = positions[:requested_matches]
            matches, response_truncated = _render_search_matches(
                data, selected, context_bytes=requested_context,
            )
            truncated = more_matches or response_truncated or len(matches) < len(selected)
            qualifier = "; additional matches omitted" if truncated else ""
            return _ok(
                f"Found {len(matches)} {analyzer} match(es) in {path}{qualifier}.",
                {
                    "analyzer": analyzer,
                    "path": path,
                    "bytes": size,
                    "matches_returned": len(matches),
                    "truncated": truncated,
                    "context_bytes": requested_context,
                    "matches": matches,
                },
            )

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
