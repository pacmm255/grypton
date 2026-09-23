"""Private named credentials and authenticated HTTP session state.

Credential values never belong to an engagement workspace. The worker sees a
short alias and calls a dedicated MCP tool; only that local tool process reads
this store and substitutes the values immediately before transport.
"""
from __future__ import annotations

import json
import fcntl
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import secrets
import stat
from urllib.parse import urlsplit

from . import config


_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class CredentialError(ValueError):
    """A named credential is absent, unsafe, or malformed."""


def _safe_name(value: str, *, label: str) -> str:
    name = str(value or "").strip()
    if not _NAME.fullmatch(name):
        raise CredentialError(
            f"{label} must be 1-64 letters, digits, dots, underscores, or hyphens"
        )
    return name


def _private_dir(path: Path) -> Path:
    if path.is_symlink():
        raise CredentialError(f"private credential path must not be a symlink: {path.name}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        raise CredentialError(f"private credential path is not a directory: {path.name}")
    os.chmod(path, 0o700)
    return path


def credential_dir(target: str) -> Path:
    slug = _safe_name(config.slugify(target), label="target")
    return _private_dir(config.CREDENTIALS_DIR / slug)


def _credential_path(target: str, name: str) -> Path:
    return credential_dir(target) / (_safe_name(name, label="credential name") + ".json")



def _session_dir(target: str) -> Path:
    return _private_dir(credential_dir(target) / ".sessions")


def cookie_jar_path(target: str, name: str) -> Path:
    alias = _safe_name(name, label="credential name")
    path = _session_dir(target) / (alias + ".cookies")
    if path.is_symlink():
        raise CredentialError("cookie jar must not be a symlink")
    if path.exists() and not path.is_file():
        raise CredentialError("cookie jar must be a regular file")
    if not path.exists():
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write("# Netscape HTTP Cookie File\n")
    os.chmod(path, 0o600, follow_symlinks=False)
    return path


def token_path(target: str, name: str) -> Path:
    alias = _safe_name(name, label="credential name")
    return _session_dir(target) / (alias + ".tokens.json")


def attempt_path(target: str, name: str) -> Path:
    alias = _safe_name(name, label="credential name")
    return _session_dir(target) / (alias + ".attempts.json")


def _atomic_private_json(path: Path, value: dict) -> None:
    _private_dir(path.parent)
    temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def save_credential(target: str, name: str, username: str, password: str) -> str:
    alias = _safe_name(name, label="credential name")
    if not str(username):
        raise CredentialError("username must not be empty")
    if not str(password):
        raise CredentialError("password must not be empty")
    _atomic_private_json(_credential_path(target, alias), {
        "version": 1,
        "username": str(username),
        "password": str(password),
    })
    for path in (token_path(target, alias), attempt_path(target, alias),
                 _session_dir(target) / (alias + ".cookies")):
        path.unlink(missing_ok=True)
    return alias


def _read_private_json(path: Path) -> dict:
    try:
        info = path.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise CredentialError("named credential does not exist") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise CredentialError("credential file must be a private regular file (mode 0600)")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CredentialError("credential file is unreadable or malformed") from exc
    if not isinstance(value, dict):
        raise CredentialError("credential file is malformed")
    return value


def load_credential(target: str, name: str) -> dict[str, str]:
    value = _read_private_json(_credential_path(target, name))
    username, password = value.get("username"), value.get("password")
    if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
        raise CredentialError("credential file does not contain a username and password")
    return {"username": username, "password": password}


def list_credentials(target: str) -> list[str]:
    directory = credential_dir(target)
    return sorted(
        path.stem for path in directory.glob("*.json")
        if _NAME.fullmatch(path.stem) and path.is_file() and not path.is_symlink()
    )


def normalize_origin(url: str) -> str:
    """Return a canonical HTTP origin including its effective port."""
    try:
        parsed = urlsplit(str(url or ""))
        port = parsed.port
    except ValueError as exc:
        raise CredentialError("session origin is not a valid URL") from exc
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    if scheme not in {"http", "https"} or not host:
        raise CredentialError("session origin must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise CredentialError("session origin must not contain URL credentials")
    if "%" in host:
        raise CredentialError("session origin must not contain an IPv6 zone identifier")
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise CredentialError("session origin contains an invalid host") from exc
    if port is None:
        port = 443 if scheme == "https" else 80
    rendered_host = f"[{host}]" if ":" in host else host
    return f"{scheme}://{rendered_host}:{port}"


def token_origin(target: str, name: str) -> str:
    path = token_path(target, name)
    if not path.exists():
        return ""
    value = _read_private_json(path)
    origin = value.get("origin")
    if not isinstance(origin, str) or not origin:
        return ""
    try:
        return normalize_origin(origin)
    except CredentialError:
        return ""


def save_tokens(target: str, name: str, tokens: dict[str, str], *, origin: str) -> None:
    safe = {
        str(key): str(value) for key, value in tokens.items()
        if str(key) and isinstance(value, str) and value
    }
    if safe:
        bound_origin = normalize_origin(origin)
        existing_origin = token_origin(target, name)
        if existing_origin and existing_origin != bound_origin:
            raise CredentialError(
                "refusing to move bearer tokens to a different session origin"
            )
        _atomic_private_json(token_path(target, name), {
            "version": 2,
            "origin": bound_origin,
            "tokens": safe,
        })


def load_tokens(target: str, name: str) -> dict[str, str]:
    path = token_path(target, name)
    if not path.exists():
        return {}
    value = _read_private_json(path)
    tokens = value.get("tokens")
    if not isinstance(tokens, dict):
        return {}
    return {str(key): str(item) for key, item in tokens.items()
            if isinstance(item, str) and item}


def load_attempt_state(target: str, name: str) -> dict:
    path = attempt_path(target, name)
    if not path.exists():
        return {
            "attempts": 0,
            "established": False,
            "blocked_reason": "",
            "origin": "",
        }
    value = _read_private_json(path)
    origin = value.get("origin")
    if not isinstance(origin, str) or not origin:
        origin = ""
    else:
        try:
            origin = normalize_origin(origin)
        except CredentialError:
            origin = ""
    return {
        "attempts": max(0, int(value.get("attempts") or 0)),
        "established": bool(value.get("established")),
        "blocked_reason": str(value.get("blocked_reason") or ""),
        "origin": origin,
    }

def _assert_login_attempt_available(state: dict) -> None:
    if state["established"]:
        raise CredentialError(
            "an authenticated session already exists; use authenticated_http_request"
        )
    if state["blocked_reason"]:
        raise CredentialError(
            f"authentication is blocked: {state['blocked_reason']}; "
            "operator action is required"
        )
    if state["attempts"] >= 2:
        raise CredentialError(
            "the two-attempt authentication budget is exhausted; "
            "operator action is required"
        )


def ensure_login_attempt_available(target: str, name: str) -> None:
    """Check the attempt budget without reserving an authentication attempt."""
    lock_path = attempt_path(target, name).with_suffix(".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        _assert_login_attempt_available(load_attempt_state(target, name))


def begin_login_attempt(target: str, name: str) -> int:
    """Atomically reserve one login attempt; never retry internally."""
    lock_path = attempt_path(target, name).with_suffix(".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        state = load_attempt_state(target, name)
        _assert_login_attempt_available(state)
        state["attempts"] += 1
        _atomic_private_json(attempt_path(target, name), {"version": 1, **state})
        return state["attempts"]


def record_login_outcome(target: str, name: str, *, established: bool = False,
                         blocked_reason: str = "", origin: str | None = None) -> None:
    lock_path = attempt_path(target, name).with_suffix(".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        state = load_attempt_state(target, name)
        state["established"] = bool(established)
        state["blocked_reason"] = str(blocked_reason or "")
        if origin is not None:
            state["origin"] = normalize_origin(origin)
        if state["established"] and not state["origin"]:
            raise CredentialError(
                "an authenticated session requires an exact origin binding"
            )
        _atomic_private_json(attempt_path(target, name), {"version": 1, **state})


def _cookie_rows(path: Path) -> list[tuple[str, ...]]:
    """Read valid Netscape cookie rows, including the curl HttpOnly extension."""
    if not path.is_file() or path.is_symlink():
        return []
    rows: list[tuple[str, ...]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for raw in lines:
        line = raw.strip()
        if line.startswith("#HttpOnly_"):
            line = line[len("#HttpOnly_"):]
        elif not line or line.startswith("#"):
            continue
        columns = tuple(line.split(chr(9)))
        if len(columns) >= 7 and columns[5]:
            rows.append(columns)
    return rows


def cookie_jar_fingerprints(path: Path) -> set[str]:
    """Return opaque identities for cookies in a private Netscape jar."""
    return {
        hashlib.sha256(chr(9).join(row).encode("utf-8", "replace")).hexdigest()
        for row in _cookie_rows(path)
    }


def cookie_fingerprints(target: str, name: str) -> set[str]:
    """Return opaque identities for private cookies without exposing values."""
    alias = _safe_name(name, label="credential name")
    return cookie_jar_fingerprints(_session_dir(target) / (alias + ".cookies"))


def session_status(target: str, name: str) -> dict[str, bool | str | int]:
    alias = _safe_name(name, label="credential name")
    cookie_path = _session_dir(target) / (alias + ".cookies")
    cookie_rows = _cookie_rows(cookie_path)
    has_cookies = bool(cookie_rows)
    has_auth_cookies = False
    for columns in cookie_rows:
        cookie_name = columns[5].lower()
        if (
            re.search(r"(?:session|sessid|auth|access|refresh|jwt|sid)", cookie_name)
            and "csrf" not in cookie_name and "xsrf" not in cookie_name
        ):
            has_auth_cookies = True
    attempt = load_attempt_state(target, alias)
    state = (
        "blocked" if attempt["blocked_reason"]
        else "authenticated" if attempt["established"]
        else "exhausted" if attempt["attempts"] >= 2
        else "stored"
    )
    return {
        "name": alias,
        "state": state,
        "has_cookies": has_cookies,
        "has_auth_cookies": has_auth_cookies,
        "has_bearer_token": bool(select_bearer(load_tokens(target, alias))),
        "attempts": attempt["attempts"],
        "exhausted": state == "exhausted",
        "established": attempt["established"],
        "blocked_reason": attempt["blocked_reason"],
        "origin": attempt["origin"],
    }


def select_bearer(tokens: dict[str, str]) -> str:
    normalized = {
        re.sub(r"[^a-z0-9]", "", key.lower()): value
        for key, value in tokens.items()
    }
    for name in ("accesstoken", "bearertoken", "token", "idtoken", "jwt"):
        if normalized.get(name):
            value = normalized[name]
            return value[7:].strip() if value.lower().startswith("bearer ") else value
    return ""
