"""Private named credentials and authenticated HTTP session state.

Credential values never belong to an engagement workspace. The worker sees a
short alias and calls a dedicated MCP tool; only that local tool process reads
this store and substitutes the values immediately before transport.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import fcntl
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import secrets
import stat
import threading
from urllib.parse import urlsplit

from . import config


_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_PHONE_SEPARATORS = re.compile(r"[\s().\-\u2010-\u2015]+")
_IRAN_LOCAL_MOBILE = re.compile(r"09[0-9]{9}\Z")
_IRAN_E164_MOBILE = re.compile(r"(?:\+98|0098|98)9[0-9]{9}\Z")
_EMAIL_USERNAME = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+\Z")
_FIELD_NAME = re.compile(r"[A-Za-z0-9_.\[\]-]{1,80}\Z")
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}\Z")
_AUTH_PROFILE_STRATEGIES = frozenset({"browser", "http"})
_USERNAME_TRANSFORMS = frozenset({"stored", "iran-e164"})
_PROFILE_SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
})
_PROFILE_TRANSPORT_HEADERS = frozenset({
    "connection", "content-length", "expect", "forwarded", "host",
    "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding",
    "upgrade", "x-http-method-override", "x-original-url", "x-rewrite-url",
})
_PROFILE_THREAD_LOCKS: dict[str, threading.RLock] = {}
_PROFILE_THREAD_LOCKS_GUARD = threading.Lock()
_PROFILE_LOCK_STATE = threading.local()


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


def _profile_dir(target: str) -> Path:
    return _private_dir(credential_dir(target) / ".profiles")


def auth_profile_path(target: str, name: str) -> Path:
    alias = _safe_name(name, label="credential name")
    return _profile_dir(target) / (alias + ".json")


def _private_thread_lock(path: Path) -> threading.RLock:
    key = str(path)
    with _PROFILE_THREAD_LOCKS_GUARD:
        return _PROFILE_THREAD_LOCKS.setdefault(key, threading.RLock())


@contextmanager
def _private_interprocess_lock(lock_path: Path, *, error: str):
    key = str(lock_path)
    thread_lock = _private_thread_lock(lock_path)
    with thread_lock:
        depths = getattr(_PROFILE_LOCK_STATE, "depths", None)
        if depths is None:
            depths = {}
            _PROFILE_LOCK_STATE.depths = depths
        if depths.get(key, 0):
            depths[key] += 1
            try:
                yield
            finally:
                depths[key] -= 1
            return

        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = -1
        try:
            fd = os.open(lock_path, flags, 0o600)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OSError("lock is not a private regular file")
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError as exc:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise CredentialError(error) from exc

        depths[key] = 1
        try:
            yield
        finally:
            depths.pop(key, None)
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


@contextmanager
def auth_profile_lock(target: str, name: str):
    """Serialize one alias's profile snapshot, save, and delete operations."""
    alias = _safe_name(name, label="credential name")
    lock_path = _profile_dir(target) / f".{alias}.lock"
    with _private_interprocess_lock(
        lock_path, error="authentication profile lock is unavailable"
    ):
        yield


@contextmanager
def session_material_lock(target: str, name: str):
    """Serialize session writers and authenticated transactions for one alias."""
    alias = _safe_name(name, label="credential name")
    lock_path = _session_dir(target) / f".{alias}.material.lock"
    with _private_interprocess_lock(
        lock_path, error="private session lock is unavailable"
    ):
        yield


def _session_dir(target: str) -> Path:
    return _private_dir(credential_dir(target) / ".sessions")


def cookie_jar_storage_path(target: str, name: str) -> Path:
    """Return the private jar path without creating session material."""
    alias = _safe_name(name, label="credential name")
    return _session_dir(target) / (alias + ".cookies")


def cookie_jar_path(target: str, name: str) -> Path:
    path = cookie_jar_storage_path(target, name)
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
    with session_material_lock(target, alias):
        _atomic_private_json(_credential_path(target, alias), {
            "version": 1,
            "username": str(username),
            "password": str(password),
        })
        for path in (token_path(target, alias), attempt_path(target, alias),
                     cookie_jar_storage_path(target, alias)):
            path.unlink(missing_ok=True)
    return alias


def _read_private_json(path: Path, *, label: str = "credential file") -> dict:
    try:
        info = path.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise CredentialError("named credential does not exist") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise CredentialError(f"{label} must be a private regular file (mode 0600)")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CredentialError(f"{label} is unreadable or malformed") from exc
    if not isinstance(value, dict):
        raise CredentialError(f"{label} is malformed")
    return value


def load_credential(target: str, name: str) -> dict[str, str]:
    value = _read_private_json(_credential_path(target, name))
    username, password = value.get("username"), value.get("password")
    if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
        raise CredentialError("credential file does not contain a username and password")
    return {"username": username, "password": password}


def normalize_login_username(username: str, transform: str = "stored") -> str:
    """Return the private identifier representation requested by a login form."""
    value = str(username)
    if transform == "stored":
        return value
    if transform != "iran-e164":
        raise CredentialError("username transform must be stored or iran-e164")

    compact = _PHONE_SEPARATORS.sub("", value.strip())
    if _IRAN_LOCAL_MOBILE.fullmatch(compact):
        return "+98" + compact[1:]
    if _IRAN_E164_MOBILE.fullmatch(compact):
        if compact.startswith("+98"):
            national = compact[3:]
        elif compact.startswith("0098"):
            national = compact[4:]
        else:
            national = compact[2:]
        return "+98" + national
    raise CredentialError(
        "stored username is not an unambiguous Iranian mobile identifier"
    )


def classify_username(username: str) -> str:
    """Describe an identifier coarsely without returning any of its content."""
    value = str(username).strip()
    if _EMAIL_USERNAME.fullmatch(value):
        return "email"
    compact = _PHONE_SEPARATORS.sub("", value)
    if _IRAN_LOCAL_MOBILE.fullmatch(compact):
        return "iran-local-phone"
    if _IRAN_E164_MOBILE.fullmatch(compact):
        return "iran-e164-phone"
    return "opaque"


def list_credentials(target: str) -> list[str]:
    directory = credential_dir(target)
    return sorted(
        path.stem for path in directory.glob("*.json")
        if _NAME.fullmatch(path.stem) and path.is_file() and not path.is_symlink()
    )


def _profile_url(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 8192:
        raise CredentialError(f"{label} must be an absolute HTTP(S) URL")
    if any(ord(char) < 0x20 or ord(char) == 0x7f for char in value):
        raise CredentialError(f"{label} contains invalid characters")
    try:
        parsed = urlsplit(value)
        normalize_origin(value)
    except (CredentialError, ValueError) as exc:
        raise CredentialError(f"{label} must be an absolute HTTP(S) URL") from exc
    if parsed.fragment:
        raise CredentialError(f"{label} must not contain a URL fragment")
    return value


def _profile_text(value: object, *, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise CredentialError(f"{label} must be 1-{maximum} printable characters")
    if any(ord(char) < 0x20 or ord(char) == 0x7f for char in value):
        raise CredentialError(f"{label} must be 1-{maximum} printable characters")
    return value


def _profile_object(value: object, *, label: str) -> dict:
    if not isinstance(value, dict):
        raise CredentialError(f"{label} must be an object")
    return value


def _reject_unknown_keys(value: dict, allowed: set[str], *, label: str) -> None:
    unknown = sorted(str(key) for key in value if key not in allowed)
    if unknown:
        raise CredentialError(
            f"{label} contains unsupported field(s): {', '.join(unknown)}"
        )


def _profile_headers(
    value: object, *, label: str, origin: str, maximum: int = 50
) -> dict[str, str]:
    headers = _profile_object(value, label=label)
    if len(headers) > maximum:
        raise CredentialError(f"{label} may contain at most {maximum} headers")
    result: dict[str, str] = {}
    normalized_names: set[str] = set()
    forbidden = _PROFILE_SENSITIVE_HEADERS | _PROFILE_TRANSPORT_HEADERS
    for raw_key, raw_value in headers.items():
        if not isinstance(raw_key, str) or not _HEADER_NAME.fullmatch(raw_key):
            raise CredentialError(f"{label} contains an invalid header name")
        key = raw_key.strip()
        lowered = key.lower()
        if (
            lowered in forbidden
            or lowered.startswith("sec-")
            or lowered.startswith("x-forwarded-")
        ):
            raise CredentialError(f"{label} contains a private or transport header")
        if lowered in normalized_names:
            raise CredentialError(f"{label} contains a duplicate header name")
        normalized_names.add(lowered)
        if not isinstance(raw_value, str) or len(raw_value) > 4096:
            raise CredentialError(f"{label} values must be strings up to 4096 characters")
        if any(ord(char) < 0x20 and char != "\t" for char in raw_value) or "\x7f" in raw_value:
            raise CredentialError(f"{label} contains an invalid header value")
        if lowered == "origin":
            try:
                header_origin = normalize_origin(raw_value)
            except CredentialError as exc:
                raise CredentialError(f"{label} Origin must use the login origin") from exc
            if header_origin != origin or urlsplit(raw_value).path not in {"", "/"}:
                raise CredentialError(f"{label} Origin must use the login origin")
        elif lowered in {"referer", "referrer"}:
            try:
                header_origin = normalize_origin(raw_value)
            except CredentialError as exc:
                raise CredentialError(f"{label} Referer must use the login origin") from exc
            if header_origin != origin:
                raise CredentialError(f"{label} Referer must use the login origin")
        result[key] = raw_value
    return result


def validate_browser_verification(value: object, *, login_url: str) -> dict:
    """Validate the private status-differential browser proof contract."""
    verification = _profile_object(value, label="browser verification settings")
    required = {
        "mode", "login_status", "authenticated_status", "anonymous_status",
        "expected_post_login_url",
    }
    redirect_fields = {"anonymous_redirect_statuses"}
    _reject_unknown_keys(
        verification, required | redirect_fields,
        label="browser verification settings",
    )
    missing = sorted(required.difference(verification))
    if missing:
        raise CredentialError(
            "browser verification settings are incomplete"
        )
    if verification.get("mode") != "status-differential":
        raise CredentialError(
            "browser verification mode must be status-differential"
        )

    login_status = verification.get("login_status")
    authenticated_status = verification.get("authenticated_status")
    anonymous_status = verification.get("anonymous_status")
    if (
        isinstance(login_status, bool) or not isinstance(login_status, int)
        or not 200 <= login_status <= 299
    ):
        raise CredentialError("browser login status must be an exact 2xx status")
    if (
        isinstance(authenticated_status, bool)
        or not isinstance(authenticated_status, int)
        or not (
            200 <= authenticated_status <= 299
            or 400 <= authenticated_status <= 499
        )
        or authenticated_status in {401, 403, 429}
    ):
        raise CredentialError(
            "browser authenticated status must be 2xx or 4xx except 401, 403, or 429"
        )
    if (
        isinstance(anonymous_status, bool)
        or anonymous_status not in {401, 403}
    ):
        raise CredentialError("browser anonymous status must be exactly 401 or 403")
    expected_url = _profile_url(
        verification.get("expected_post_login_url"),
        label="expected post-login URL",
    )
    if normalize_origin(expected_url) != normalize_origin(login_url):
        raise CredentialError(
            "expected post-login URL must use the login page's exact origin"
        )
    canonical = {
        "mode": "status-differential",
        "login_status": login_status,
        "authenticated_status": authenticated_status,
        "anonymous_status": anonymous_status,
        "expected_post_login_url": expected_url,
    }
    allowed_redirect_statuses = {301, 302, 303, 307, 308}
    for field in sorted(redirect_fields):
        if field not in verification:
            continue
        statuses = verification[field]
        if not isinstance(statuses, list) or len(statuses) > 8:
            raise CredentialError(
                "browser redirect status chains must be lists of at most 8 statuses"
            )
        if any(
            isinstance(status, bool)
            or not isinstance(status, int)
            or status not in allowed_redirect_statuses
            for status in statuses
        ):
            raise CredentialError(
                "browser redirect status chains may contain only 301, 302, 303, 307, or 308"
            )
        canonical[field] = list(statuses)
    return canonical


def validate_auth_profile(profile: object) -> dict:
    """Return a canonical private auth profile after strict validation."""
    value = _profile_object(profile, label="authentication profile")
    _reject_unknown_keys(value, {
        "version", "strategy", "login_url", "verify_url", "success_marker",
        "username_transform", "timeout", "browser", "http",
    }, label="authentication profile")
    if value.get("version") != 1:
        raise CredentialError("authentication profile version must be 1")
    strategy = value.get("strategy")
    if strategy not in _AUTH_PROFILE_STRATEGIES:
        raise CredentialError("authentication profile strategy must be browser or http")
    login_url = _profile_url(value.get("login_url"), label="login URL")
    verify_url = _profile_url(value.get("verify_url"), label="verification URL")
    login_origin = normalize_origin(login_url)
    if normalize_origin(verify_url) != login_origin:
        raise CredentialError(
            "authentication profile URLs must use the same exact origin"
        )
    transform = value.get("username_transform", "stored")
    if transform not in _USERNAME_TRANSFORMS:
        raise CredentialError("username transform must be stored or iran-e164")
    timeout = value.get("timeout", 45 if strategy == "browser" else 30)
    minimum_timeout = 5 if strategy == "browser" else 1
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not minimum_timeout <= timeout <= 120:
        raise CredentialError(
            f"authentication profile timeout must be {minimum_timeout}-120 seconds"
        )

    canonical = {
        "version": 1,
        "strategy": strategy,
        "login_url": login_url,
        "verify_url": verify_url,
        "username_transform": transform,
        "timeout": timeout,
    }
    if strategy == "browser":
        if value.get("http") is not None:
            raise CredentialError("browser authentication profile cannot contain HTTP settings")
        browser = _profile_object(value.get("browser"), label="browser settings")
        _reject_unknown_keys(browser, {
            "username_selector", "password_selector", "submit_selector",
            "verify_headers", "verification",
        }, label="browser settings")
        verification = browser.get("verification")
        if verification is None:
            canonical["success_marker"] = _profile_text(
                value.get("success_marker"), label="success marker", maximum=200
            )
        else:
            if "success_marker" in value:
                raise CredentialError(
                    "status-differential browser profiles must omit success marker"
                )
        canonical_browser = {
            "username_selector": _profile_text(
                browser.get("username_selector"), label="username selector", maximum=500
            ),
            "password_selector": _profile_text(
                browser.get("password_selector"), label="password selector", maximum=500
            ),
            "submit_selector": _profile_text(
                browser.get("submit_selector"), label="submit selector", maximum=500
            ),
            "verify_headers": _profile_headers(
                browser.get("verify_headers", {}),
                label="browser verification headers", origin=login_origin,
                maximum=32,
            ),
        }
        if verification is not None:
            canonical_browser["verification"] = validate_browser_verification(
                verification, login_url=login_url
            )
        canonical["browser"] = canonical_browser
    else:
        if value.get("browser") is not None:
            raise CredentialError("HTTP authentication profile cannot contain browser settings")
        canonical["success_marker"] = _profile_text(
            value.get("success_marker"), label="success marker", maximum=200
        )
        http = _profile_object(value.get("http"), label="HTTP settings")
        _reject_unknown_keys(http, {
            "encoding", "username_field", "password_field", "fields", "headers",
        }, label="HTTP settings")
        encoding = http.get("encoding", "json")
        if encoding not in {"json", "form"}:
            raise CredentialError("HTTP encoding must be json or form")
        username_field = http.get("username_field", "username")
        password_field = http.get("password_field", "password")
        if not isinstance(username_field, str) or not _FIELD_NAME.fullmatch(username_field):
            raise CredentialError("HTTP username field name is invalid")
        if not isinstance(password_field, str) or not _FIELD_NAME.fullmatch(password_field):
            raise CredentialError("HTTP password field name is invalid")
        if username_field == password_field:
            raise CredentialError("HTTP credential field names must be distinct")
        fields = _profile_object(http.get("fields", {}), label="HTTP fields")
        if len(fields) > 50:
            raise CredentialError("HTTP fields may contain at most 50 values")
        clean_fields: dict[str, str] = {}
        for key, item in fields.items():
            if not isinstance(key, str) or not _FIELD_NAME.fullmatch(key):
                raise CredentialError("HTTP fields contain an invalid field name")
            if key in {username_field, password_field}:
                raise CredentialError("HTTP fields cannot replace credential fields")
            if not isinstance(item, str) or len(item) > 4096:
                raise CredentialError("HTTP field values must be strings up to 4096 characters")
            clean_fields[key] = item
        canonical["http"] = {
            "encoding": encoding,
            "username_field": username_field,
            "password_field": password_field,
            "fields": clean_fields,
            "headers": _profile_headers(
                http.get("headers", {}), label="HTTP headers", origin=login_origin
            ),
        }
    return canonical


def auth_profile_revision(profile: dict) -> str:
    canonical = validate_auth_profile(profile)
    payload = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:12]


def save_auth_profile(target: str, name: str, profile: object) -> dict:
    """Save validated routing metadata beside, but separate from, a credential."""
    alias = _safe_name(name, label="credential name")
    load_credential(target, alias)
    canonical = validate_auth_profile(profile)
    with auth_profile_lock(target, alias):
        path = auth_profile_path(target, alias)
        if path.is_symlink():
            raise CredentialError("authentication profile must not be a symlink")
        if path.exists() and not path.is_file():
            raise CredentialError("authentication profile must be a regular file")
        _atomic_private_json(path, canonical)
    return canonical


def _load_auth_profile_optional_unlocked(target: str, name: str) -> dict | None:
    path = auth_profile_path(target, name)
    if not path.exists() and not path.is_symlink():
        return None
    return validate_auth_profile(
        _read_private_json(path, label="authentication profile")
    )


def load_auth_profile_optional(target: str, name: str) -> dict | None:
    with auth_profile_lock(target, name):
        return _load_auth_profile_optional_unlocked(target, name)


def delete_auth_profile(target: str, name: str) -> bool:
    with auth_profile_lock(target, name):
        path = auth_profile_path(target, name)
        if path.is_symlink():
            raise CredentialError("authentication profile must not be a symlink")
        if not path.exists():
            return False
        if not path.is_file():
            raise CredentialError("authentication profile must be a regular file")
        path.unlink()
        return True


def auth_profile_summary(target: str, name: str) -> dict[str, object]:
    profile = load_auth_profile_optional(target, name)
    if profile is None:
        return {"configured": False}
    return {
        "configured": True,
        "valid": True,
        "strategy": profile["strategy"],
        "username_transform": profile["username_transform"],
        "login_origin": normalize_origin(profile["login_url"]),
        "verification_origin": normalize_origin(profile["verify_url"]),
        "revision": auth_profile_revision(profile),
    }


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
        with session_material_lock(target, name):
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
    with session_material_lock(target, name):
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
    with session_material_lock(target, name):
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


def session_status(target: str, name: str) -> dict[str, object]:
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
    try:
        username_kind = classify_username(load_credential(target, alias)["username"])
    except CredentialError:
        username_kind = "opaque"
    try:
        profile_status = auth_profile_summary(target, alias)
    except CredentialError:
        # Status is deliberately metadata-only. A corrupt private profile is
        # visible as a state fact without reflecting any of its content.
        profile_status = {"configured": True, "valid": False}
    return {
        "name": alias,
        "username_kind": username_kind,
        "state": state,
        "has_cookies": has_cookies,
        "has_auth_cookies": has_auth_cookies,
        "has_bearer_token": bool(select_bearer(load_tokens(target, alias))),
        "attempts": attempt["attempts"],
        "exhausted": state == "exhausted",
        "established": attempt["established"],
        "blocked_reason": attempt["blocked_reason"],
        "origin": attempt["origin"],
        "auth_profile": profile_status,
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
