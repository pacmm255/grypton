"""Private, exact-origin HTTP policy storage and shared rate enforcement.

Header values are operator state.  Only origin, header names, and the rate
ceiling are projected into a worker workspace; transports resolve the values
immediately before a request is sent.
"""
from __future__ import annotations

import fcntl
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
from typing import Mapping
from urllib.parse import urlsplit

from . import config, credentials


class RequestPolicyError(ValueError):
    """An engagement request policy is absent, corrupt, or unsafe."""


_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}\Z")
_FORBIDDEN_HEADERS = frozenset({
    "authorization", "connection", "content-length", "cookie", "expect",
    "forwarded", "host", "keep-alive", "origin", "proxy-authenticate",
    "proxy-authorization", "proxy-connection", "referer", "set-cookie", "te",
    "trailer", "transfer-encoding", "upgrade", "x-http-method-override",
    "x-original-url", "x-rewrite-url",
})
_MAX_POLICY_BYTES = 1_000_000
_MAX_HEADERS = 32
_MIN_REQUESTS_PER_SECOND = 0.1
_MAX_REQUESTS_PER_SECOND = 1000.0
_SOURCE_ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_RATE_BUCKET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def canonical_origin(value: str) -> str:
    """Return one canonical HTTP(S) origin with no path, query, or fragment."""
    try:
        origin = credentials.normalize_origin(str(value or ""))
    except credentials.CredentialError as exc:
        raise RequestPolicyError("request policy origin must be a valid HTTP(S) origin") from exc
    # normalize_origin deliberately ignores paths.  Reject them here so an
    # operator cannot mistake an origin policy for a path-limited rule.
    parsed = urlsplit(str(value or "").strip())
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username:
        raise RequestPolicyError(
            "request policy origin must contain only scheme, host, and optional port"
        )
    return origin


def canonical_headers(value: Mapping[str, str] | None) -> dict[str, str]:
    """Validate fixed headers that every supported transport can apply safely."""
    if value is None:
        return {}
    if not isinstance(value, Mapping) or len(value) > _MAX_HEADERS:
        raise RequestPolicyError(
            f"request policy accepts at most {_MAX_HEADERS} mandatory headers"
        )
    output: dict[str, str] = {}
    seen: set[str] = set()
    for raw_name, raw_value in value.items():
        if not isinstance(raw_name, str) or not isinstance(raw_value, str):
            raise RequestPolicyError("request policy header names and values must be strings")
        name = raw_name.strip()
        normalized = name.lower()
        if not _HEADER_NAME.fullmatch(name):
            raise RequestPolicyError("request policy contains an invalid header name")
        if normalized in seen:
            raise RequestPolicyError(
                "request policy contains a case-insensitive duplicate header name"
            )
        if (
            normalized in _FORBIDDEN_HEADERS
            or normalized.startswith(("proxy-", "sec-", "x-grypton-"))
        ):
            raise RequestPolicyError(
                f"request policy header {name!r} cannot alter session, destination, "
                "browser-controlled, or hop-by-hop state"
            )
        if (
            len(raw_value.encode("utf-8")) > 8192
            or "\r" in raw_value or "\n" in raw_value
            or any(ord(char) < 0x20 and char != "\t" for char in raw_value)
            or "\x7f" in raw_value
        ):
            raise RequestPolicyError(
                f"request policy header {name!r} contains an invalid value"
            )
        seen.add(normalized)
        output[name] = raw_value
    return output


def canonical_header_sources(value: Mapping[str, object] | None,
                             *, static_headers: Mapping[str, str] = ()) -> dict[str, dict[str, str]]:
    """Validate private values resolved just before transport."""
    if value is None:
        return {}
    if not isinstance(value, Mapping) or len(value) > _MAX_HEADERS:
        raise RequestPolicyError(
            f"request policy accepts at most {_MAX_HEADERS} mandatory header sources"
        )
    seen = {str(name).lower() for name in static_headers}
    output: dict[str, dict[str, str]] = {}
    for raw_name, raw_source in value.items():
        if not isinstance(raw_name, str):
            raise RequestPolicyError("request policy header source name must be a string")
        name = raw_name.strip()
        normalized = name.lower()
        # Reuse the header validator so both fixed and resolved values have the
        # exact same transport-safe name rules.
        canonical_headers({name: "x"})
        if normalized in seen:
            raise RequestPolicyError(
                "request policy contains a case-insensitive duplicate header name"
            )
        if (
            not isinstance(raw_source, Mapping)
            or set(raw_source) != {"kind", "alias"}
            or raw_source.get("kind") != "mailbox-address"
            or not isinstance(raw_source.get("alias"), str)
            or not _SOURCE_ALIAS.fullmatch(str(raw_source.get("alias")))
        ):
            raise RequestPolicyError("request policy header source is invalid")
        seen.add(normalized)
        output[name] = {
            "kind": "mailbox-address",
            "alias": str(raw_source["alias"]),
        }
    if len(seen) > _MAX_HEADERS:
        raise RequestPolicyError(
            f"request policy accepts at most {_MAX_HEADERS} mandatory headers"
        )
    return output


def canonical_rate(value: object) -> float:
    if isinstance(value, bool):
        raise RequestPolicyError("maximum requests per second must be a number")
    try:
        rate = float(value)
    except (TypeError, ValueError) as exc:
        raise RequestPolicyError("maximum requests per second must be a number") from exc
    if not math.isfinite(rate) or not _MIN_REQUESTS_PER_SECOND <= rate <= _MAX_REQUESTS_PER_SECOND:
        raise RequestPolicyError(
            "maximum requests per second must be between 0.1 and 1000"
        )
    return rate


def _policy_path(target_slug: str) -> Path:
    return (
        config.STATE_DIR / "operator" / "engagements"
        / config.slugify(target_slug) / "request-policy.json"
    )


@contextmanager
def _policy_lock(target_slug: str):
    path = _policy_path(target_slug).with_suffix(".lock")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd = os.open(
        path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600
    )
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _canonical_policy(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) - {
        "headers", "header_sources", "max_requests_per_second", "rate_bucket",
    }:
        raise RequestPolicyError("request policy entry is invalid")
    headers = canonical_headers(value.get("headers"))
    rate_bucket = value.get("rate_bucket", "engagement")
    if not isinstance(rate_bucket, str) or not _RATE_BUCKET.fullmatch(rate_bucket):
        raise RequestPolicyError("request policy rate bucket is invalid")
    return {
        "headers": headers,
        "header_sources": canonical_header_sources(
            value.get("header_sources"), static_headers=headers
        ),
        "max_requests_per_second": canonical_rate(
            value.get("max_requests_per_second")
        ),
        "rate_bucket": rate_bucket,
    }


def load(target_slug: str) -> dict[str, dict[str, object]]:
    """Load and validate private policy state, failing closed if it is corrupt."""
    path = _policy_path(target_slug)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise RequestPolicyError("private request policy could not be opened") from exc
    if (
        not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o077
        or info.st_size > _MAX_POLICY_BYTES
    ):
        raise RequestPolicyError("private request policy is not a private regular file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise RequestPolicyError("private request policy is invalid") from exc
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise RequestPolicyError("private request policy has an unsupported version")
    origins = payload.get("origins")
    if not isinstance(origins, dict) or len(origins) > 256:
        raise RequestPolicyError("private request policy origin map is invalid")
    output: dict[str, dict[str, object]] = {}
    for raw_origin, raw_policy in origins.items():
        if not isinstance(raw_origin, str):
            raise RequestPolicyError("private request policy origin is invalid")
        origin = canonical_origin(raw_origin)
        if origin != raw_origin or origin in output:
            raise RequestPolicyError("private request policy origin is not canonical")
        output[origin] = _canonical_policy(raw_policy)
    bucket_rates: dict[str, float] = {}
    for policy in output.values():
        bucket = str(policy["rate_bucket"])
        rate = float(policy["max_requests_per_second"])
        if bucket in bucket_rates and bucket_rates[bucket] != rate:
            raise RequestPolicyError(
                "request policies sharing a rate bucket must use the same maximum rate"
            )
        bucket_rates[bucket] = rate
    return output


def _atomic_save(target_slug: str, policies: Mapping[str, object]) -> None:
    path = _policy_path(target_slug)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    fd = os.open(
        temporary,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"version": 1, "origins": policies}, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600, follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)


def set_origin_policy(target_slug: str, origin: str, *, headers: Mapping[str, str],
                      header_sources: Mapping[str, object] | None = None,
                      max_requests_per_second: object,
                      rate_bucket: str = "engagement") -> dict[str, object]:
    canonical = canonical_origin(origin)
    fixed_headers = canonical_headers(headers)
    if not isinstance(rate_bucket, str) or not _RATE_BUCKET.fullmatch(rate_bucket):
        raise RequestPolicyError("request policy rate bucket is invalid")
    policy = {
        "headers": fixed_headers,
        "header_sources": canonical_header_sources(
            header_sources, static_headers=fixed_headers
        ),
        "max_requests_per_second": canonical_rate(max_requests_per_second),
        "rate_bucket": rate_bucket,
    }
    with _policy_lock(target_slug):
        policies = load(target_slug)
        for existing_origin, existing in policies.items():
            if (
                existing_origin != canonical
                and existing.get("rate_bucket") == rate_bucket
                and float(existing["max_requests_per_second"])
                != float(policy["max_requests_per_second"])
            ):
                raise RequestPolicyError(
                    "request policies sharing a rate bucket must use the same maximum rate"
                )
        policies[canonical] = policy
        _atomic_save(target_slug, dict(sorted(policies.items())))
    return public_policy(canonical, policy)


def remove_origin_policy(target_slug: str, origin: str) -> bool:
    canonical = canonical_origin(origin)
    with _policy_lock(target_slug):
        policies = load(target_slug)
        removed = policies.pop(canonical, None) is not None
        if removed:
            _atomic_save(target_slug, dict(sorted(policies.items())))
    return removed


def policy_for_url(target_slug: str, url: str) -> tuple[str, dict[str, object] | None]:
    try:
        origin = credentials.normalize_origin(url)
    except credentials.CredentialError as exc:
        raise RequestPolicyError("request URL has no valid HTTP(S) origin") from exc
    return origin, load(target_slug).get(origin)


def public_policy(origin: str, policy: Mapping[str, object]) -> dict[str, object]:
    headers = policy.get("headers")
    sources = policy.get("header_sources")
    names = set(str(name) for name in headers) if isinstance(headers, Mapping) else set()
    if isinstance(sources, Mapping):
        names.update(str(name) for name in sources)
    return {
        "origin": origin,
        "mandatory_header_names": sorted(names),
        "max_requests_per_second": float(policy["max_requests_per_second"]),
        "rate_bucket": str(policy.get("rate_bucket") or "engagement"),
    }


def public_view(target_slug: str) -> list[dict[str, object]]:
    return [public_policy(origin, policy) for origin, policy in load(target_slug).items()]


def policies_for_host(target_slug: str, host: str) -> list[dict[str, object]]:
    """Return binding HTTP policies for a host, without resolving any values."""
    candidate = str(host or "").lower().rstrip(".")
    output = []
    for origin, policy in load(target_slug).items():
        if (urlsplit(origin).hostname or "").lower().rstrip(".") == candidate:
            output.append(policy)
    return output


def worker_facts(target_slug: str) -> list[str]:
    """Return value-free facts suitable for the model-visible scope projection."""
    facts = []
    for row in public_view(target_slug):
        names = row["mandatory_header_names"]
        headers = ", ".join(names) if names else "none"
        rate = float(row["max_requests_per_second"])
        facts.append(
            f"- Request policy for {row['origin']}: maximum {rate:g} requests/second; "
            f"shared rate bucket: {row['rate_bucket']}; mandatory header names: {headers}"
        )
    return facts


def resolved_headers(target_slug: str,
                     policy: Mapping[str, object] | None) -> dict[str, str]:
    """Resolve trusted private sources without putting their values in prompts."""
    if not isinstance(policy, Mapping):
        return {}
    fixed = policy.get("headers")
    output = {
        str(name): str(value) for name, value in fixed.items()
    } if isinstance(fixed, Mapping) else {}
    sources = policy.get("header_sources")
    if not isinstance(sources, Mapping):
        return output
    try:
        from .temporary_mail import resolve_address
    except (ImportError, AttributeError) as exc:
        raise RequestPolicyError(
            "mandatory mailbox-backed request header is not available yet"
        ) from exc
    for name, source in sources.items():
        try:
            address = resolve_address(target_slug, str(source["alias"]))
        except Exception as exc:
            raise RequestPolicyError(
                f"mandatory mailbox-backed request header {name!r} is not available yet"
            ) from exc
        if not isinstance(address, str) or not address or "\r" in address or "\n" in address:
            raise RequestPolicyError(
                f"mandatory mailbox-backed request header {name!r} is invalid"
            )
        output[str(name)] = address
    return output


def merge_mandatory_headers(headers: Mapping[str, str],
                            mandatory: Mapping[str, str]) -> dict[str, str]:
    output = dict(headers)
    if not mandatory:
        return output
    mandatory_names = {str(name).lower() for name in mandatory}
    output = {
        name: value for name, value in output.items()
        if str(name).lower() not in mandatory_names
    }
    output.update({str(name): str(value) for name, value in mandatory.items()})
    return output


def secret_values(headers: Mapping[str, str]) -> tuple[str, ...]:
    return tuple(str(value) for value in headers.values() if str(value))


def all_resolved_secret_values(target_slug: str) -> tuple[str, ...]:
    """Return currently resolvable values for trusted artifact redaction."""
    values: set[str] = set()
    for policy in load(target_slug).values():
        try:
            values.update(secret_values(resolved_headers(target_slug, policy)))
        except RequestPolicyError:
            # An unresolved source blocks its matching request. Other origins
            # remain usable and still contribute their known redaction values.
            continue
    return tuple(sorted(values, key=len, reverse=True))


def enforce_rate_limit(target_slug: str, origin: str,
                       policy: Mapping[str, object] | None) -> None:
    """Serialize one named engagement bucket across processes with burst one."""
    if not isinstance(policy, Mapping):
        return
    rate = canonical_rate(policy.get("max_requests_per_second"))
    interval = 1.0 / rate
    bucket = str(policy.get("rate_bucket") or "engagement")
    if not _RATE_BUCKET.fullmatch(bucket):
        raise RequestPolicyError("request policy rate bucket is invalid")
    digest = hashlib.sha256(bucket.encode("utf-8")).hexdigest()
    directory = (
        config.RUNTIME_DIR / "request-policy-rate" / config.slugify(target_slug)
    )
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    lock_path = directory / f"{digest}.lock"
    state_path = directory / f"{digest}.stamp"
    fd = os.open(
        lock_path,
        os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        now = time.monotonic()
        previous = 0.0
        try:
            raw = state_path.read_text(encoding="ascii")
            previous = float(raw)
        except (FileNotFoundError, OSError, UnicodeError, ValueError):
            previous = 0.0
        # A larger persisted monotonic value denotes a reboot/stale clock and
        # must not create an unbounded wait.
        if 0.0 < previous <= now:
            delay = previous + interval - now
            if delay > 0:
                time.sleep(min(delay, interval))
        reserved = time.monotonic()
        temporary = state_path.with_name(
            f".{state_path.name}.{os.getpid()}.{time.time_ns()}.tmp"
        )
        state_fd = os.open(
            temporary,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            with os.fdopen(state_fd, "w", encoding="ascii") as stream:
                stream.write(f"{reserved:.9f}\n")
            os.replace(temporary, state_path)
            os.chmod(state_path, 0o600, follow_symlinks=False)
        finally:
            temporary.unlink(missing_ok=True)
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
