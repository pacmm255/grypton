"""Policy-gated private Mail.tm accounts for target account bootstrap.

Only the generated address and a requested confirmation value cross the MCP
boundary. Mail.tm passwords and bearer tokens remain in the per-engagement
credential store and are included in provider-output redaction needles.
"""
from __future__ import annotations

from html import unescape
from html.parser import HTMLParser
import json
import re
import secrets
import string
import time
from typing import Callable, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import (HTTPRedirectHandler, ProxyHandler, Request,
                            build_opener)

from . import credentials
from .workspace import Workspace


_API_ORIGIN = "https://api.mail.tm"
_MAX_RESPONSE_BYTES = 1_048_576
_ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_DOMAIN = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}\Z"
)
_OTP = re.compile(
    r"(?is)(?:verification|confirmation|security|one[ -]?time|login|auth|otp)"
    r"(?:\s|&nbsp;|<[^>]+>|[:#-]){0,20}(?:code|password|pin)?"
    r"(?:\s|&nbsp;|<[^>]+>|[A-Za-z:()#-]){0,24}\b([0-9]{4,8})\b"
)
_OTP_REVERSED = re.compile(
    r"(?is)\b([0-9]{4,8})\b(?:\s|&nbsp;|<[^>]+>|[:#-]){0,20}"
    r"(?:verification|confirmation|security|one[ -]?time|login|auth|otp)"
    r"(?:\s+(?:code|password|pin))?"
)
_LINK = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_VERIFY_WORDS = re.compile(
    r"(?i)(?:verify|verification|confirm|confirmation|activate|activation|signup|register)"
)


class TemporaryMailboxError(ValueError):
    """Mailbox policy, storage, or fixed-provider failure."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def _plain_html(value: str) -> str:
    parser = _Text()
    try:
        parser.feed(unescape(str(value or "")))
    except ValueError:
        return ""
    return " ".join(parser.parts)


def _policy(workspace: Workspace) -> dict:
    try:
        profile = workspace.load_program_profile()
    except ValueError as exc:
        raise TemporaryMailboxError(
            "Temporary mailbox use is disabled: no eligible structured program policy is recorded."
        ) from exc
    if profile.get("temporary_mail_account_bootstrap_allowed") is not True:
        raise TemporaryMailboxError(
            "Temporary mailbox use is disabled by the recorded program policy."
        )
    if (profile.get("account_workflows_supported") is not True
            or profile.get("self_created_account_permission") is not True
            or profile.get("self_created_account_prohibited") is True
            or profile.get("automation_prohibited") is True
            or profile.get("credential_requirement") is True
            or profile.get("disposable_email_prohibited") is True):
        raise TemporaryMailboxError(
            "Temporary mailbox use is disabled by the recorded program policy."
        )
    return profile


def _request_json(method: str, path: str, *, payload: Optional[dict] = None,
                  bearer: str = "", timeout: int = 20) -> dict:
    """Call the fixed Mail.tm API without redirects or environment proxies."""
    if not re.fullmatch(r"/[A-Za-z0-9/?=&._%~-]+", path or ""):
        raise TemporaryMailboxError("Mail.tm request path is invalid.")
    body = None
    headers = {
        "Accept": "application/ld+json, application/json",
        "User-Agent": "Grypton/3.4 temporary-mail (mail.tm)",
    }
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    request = Request(_API_ORIGIN + path, data=body, headers=headers, method=method)
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=max(1, min(int(timeout), 30))) as response:
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(raw) > _MAX_RESPONSE_BYTES:
                raise TemporaryMailboxError("Mail.tm returned an oversized response.")
            if not 200 <= int(response.status) < 300:
                raise TemporaryMailboxError(
                    f"Mail.tm request failed with HTTP {int(response.status)}."
                )
    except HTTPError as exc:
        raise TemporaryMailboxError(
            f"Mail.tm request failed with HTTP {int(exc.code)}."
        ) from None
    except (OSError, URLError, TimeoutError, ValueError):
        raise TemporaryMailboxError("Mail.tm request failed before a response was received.") from None
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise TemporaryMailboxError("Mail.tm returned a malformed response.") from None
    if not isinstance(value, dict):
        raise TemporaryMailboxError("Mail.tm returned a malformed response.")
    return value


def _members(value: dict) -> list[dict]:
    members = value.get("hydra:member")
    if not isinstance(members, list):
        raise TemporaryMailboxError("Mail.tm returned a malformed collection.")
    return [item for item in members if isinstance(item, dict)]


def _record(value: dict) -> dict:
    required = {
        "provider": str, "account_id": str, "address": str,
        "mailbox_password": str, "bearer_token": str,
        "target_password": str, "delivered": dict,
    }
    for key, expected in required.items():
        item = value.get(key)
        if not isinstance(item, expected) or (key != "delivered" and not item):
            raise TemporaryMailboxError("Private mailbox state is malformed.")
        if isinstance(item, str) and (
            len(item) > 8192
            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in item)
        ):
            raise TemporaryMailboxError("Private mailbox state is malformed.")
    if value["provider"] != "mail.tm":
        raise TemporaryMailboxError("Private mailbox provider is unsupported.")
    return value


def _random_local_part(alias: str) -> str:
    stem = re.sub(r"[^a-z0-9]", "", alias.casefold())[:12] or "research"
    return f"grypton-{stem}-{secrets.token_hex(6)}"


def _target_password() -> str:
    alphabet = string.ascii_letters + string.digits + "!@#%_-"
    return "Gy!7" + "".join(secrets.choice(alphabet) for _ in range(28))


def _ensure_paired_credential(workspace: Workspace, alias: str, record: dict) -> None:
    existing = alias in credentials.list_credentials(workspace.slug)
    if existing:
        secret = credentials.load_credential(workspace.slug, alias)
        if (secret["username"] != record["address"]
                or secret["password"] != record["target_password"]):
            raise TemporaryMailboxError(
                "The mailbox alias conflicts with an existing named credential."
            )
        return
    credentials.save_credential(
        workspace.slug, alias, record["address"], record["target_password"]
    )


def resolve_address(target_slug: str, alias: str) -> str:
    """Resolve only the public mailbox address for trusted local integrations."""
    try:
        record = _record(credentials.load_mailbox(target_slug, alias))
    except credentials.CredentialError as exc:
        raise TemporaryMailboxError(str(exc)) from exc
    return str(record["address"])


def require_mailbox(workspace: Workspace, alias: str) -> dict:
    """Enforce current policy and return a validated paired private record."""
    _policy(workspace)
    alias = str(alias or "").strip()
    if not _ALIAS.fullmatch(alias):
        raise TemporaryMailboxError("Invalid mailbox alias.")
    try:
        record = _record(credentials.load_mailbox(workspace.slug, alias))
    except credentials.CredentialError as exc:
        raise TemporaryMailboxError(str(exc)) from exc
    secret = credentials.load_credential(workspace.slug, alias)
    if (secret["username"] != record["address"]
            or secret["password"] != record["target_password"]):
        raise TemporaryMailboxError(
            "The mailbox alias is not paired with its private target credential."
        )
    return record


def create(workspace: Workspace, alias: str) -> dict:
    """Create or recover one private Mail.tm mailbox and paired target login."""
    _policy(workspace)
    alias = str(alias or "").strip()
    if not _ALIAS.fullmatch(alias):
        raise TemporaryMailboxError(
            "Mailbox alias must be 1-64 letters, digits, dots, underscores, or hyphens."
        )
    with credentials.mailbox_lock(workspace.slug, alias):
        try:
            existing = _record(credentials.load_mailbox(workspace.slug, alias))
        except credentials.CredentialError:
            existing = None
        if existing is not None:
            with credentials.session_material_lock(workspace.slug, alias):
                _ensure_paired_credential(workspace, alias, existing)
            return {
                "ok": True,
                "summary": f"Temporary mailbox {alias!r} is ready.",
                "data": {"alias": alias, "credential": alias,
                         "provider": "mail.tm", "reused": True},
            }

        with credentials.session_material_lock(workspace.slug, alias):
            if alias in credentials.list_credentials(workspace.slug):
                raise TemporaryMailboxError(
                    "The mailbox alias conflicts with an existing named credential."
                )

            domains = _members(_request_json("GET", "/domains?page=1"))
            domain = next((
                str(item.get("domain") or "").strip().lower()
                for item in domains
                if item.get("isActive") is not False
                and item.get("isPrivate") is not True
                and _DOMAIN.fullmatch(str(item.get("domain") or "").strip())
            ), "")
            if not domain:
                raise TemporaryMailboxError("Mail.tm returned no active public domain.")
            address = _random_local_part(alias) + "@" + domain
            mailbox_password = secrets.token_urlsafe(32)
            account = _request_json(
                "POST", "/accounts",
                payload={"address": address, "password": mailbox_password},
            )
            account_id = str(account.get("id") or "").strip()
            if not account_id:
                raise TemporaryMailboxError("Mail.tm did not return an account identifier.")
            token_response = _request_json(
                "POST", "/token",
                payload={"address": address, "password": mailbox_password},
            )
            bearer = str(token_response.get("token") or "").strip()
            if not bearer:
                raise TemporaryMailboxError("Mail.tm did not return an access token.")
            record = _record({
                "version": 1,
                "provider": "mail.tm",
                "account_id": account_id,
                "address": address,
                "mailbox_password": mailbox_password,
                "bearer_token": bearer,
                "target_password": _target_password(),
                "created_at": time.time(),
                "delivered": {},
            })
            credentials.save_mailbox(workspace.slug, alias, record)
            _ensure_paired_credential(workspace, alias, record)
        return {
            "ok": True,
            "summary": f"Temporary mailbox {alias!r} was created.",
            "data": {"alias": alias, "credential": alias,
                     "provider": "mail.tm", "reused": False},
        }


def _message_text(message: dict) -> str:
    html = message.get("html")
    if isinstance(html, list):
        html_text = " ".join(str(item) for item in html[:8])
    elif isinstance(html, str):
        html_text = html
    else:
        html_text = ""
    return " ".join((
        str(message.get("subject") or ""),
        str(message.get("text") or ""),
        _plain_html(html_text),
    ))[:262_144]


def _sender_domain(message: dict) -> str:
    sender = message.get("from")
    address = str(sender.get("address") or "") if isinstance(sender, dict) else ""
    return address.rsplit("@", 1)[-1].casefold() if "@" in address else ""


def _extract(kind: str, message: dict,
             scope_check: Callable[[str], bool]) -> str:
    text = _message_text(message)
    if kind == "otp":
        match = _OTP.search(text) or _OTP_REVERSED.search(text)
        return match.group(1) if match else ""
    subject = str(message.get("subject") or "")
    for raw in _LINK.findall(text):
        candidate = unescape(raw).rstrip(".,;:!?)]}>")
        if not _VERIFY_WORDS.search(subject + " " + candidate):
            continue
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            continue
        if parsed.scheme in {"http", "https"} and parsed.hostname and scope_check(candidate):
            return candidate
    return ""


def poll(workspace: Workspace, alias: str, *, kind: str,
         sender_domain: str = "", timeout: int = 30,
         scope_check: Callable[[str], bool] = lambda _url: False,
         consume: bool = True,
         sleep: Callable[[float], None] = time.sleep) -> dict:
    """Poll for one OTP or one in-scope verification link without returning mail."""
    _policy(workspace)
    alias = str(alias or "").strip()
    if not _ALIAS.fullmatch(alias):
        raise TemporaryMailboxError("Invalid mailbox alias.")
    if kind not in {"otp", "link"}:
        raise TemporaryMailboxError("Mailbox poll kind must be otp or link.")
    expected_sender = str(sender_domain or "").strip().casefold().lstrip("@")
    if expected_sender and not _DOMAIN.fullmatch(expected_sender):
        raise TemporaryMailboxError("Expected sender domain is invalid.")
    try:
        timeout = max(1, min(int(timeout), 120))
    except (TypeError, ValueError):
        raise TemporaryMailboxError("Mailbox poll timeout must be 1-120 seconds.") from None

    deadline = time.monotonic() + timeout
    with credentials.mailbox_lock(workspace.slug, alias):
        try:
            record = _record(credentials.load_mailbox(workspace.slug, alias))
        except credentials.CredentialError as exc:
            raise TemporaryMailboxError(str(exc)) from exc
        while True:
            listing = _members(_request_json(
                "GET", "/messages?page=1", bearer=record["bearer_token"],
            ))
            delivered = record["delivered"]
            for summary in listing[:5]:
                message_id = str(summary.get("id") or "").strip()
                previous = delivered.get(message_id, [])
                if not isinstance(previous, list):
                    raise TemporaryMailboxError("Private mailbox state is malformed.")
                if not message_id or kind in previous:
                    continue
                message = _request_json(
                    "GET", "/messages/" + quote(message_id, safe=""),
                    bearer=record["bearer_token"],
                )
                from_domain = _sender_domain(message)
                if expected_sender and not (
                    from_domain == expected_sender
                    or from_domain.endswith("." + expected_sender)
                ):
                    continue
                value = _extract(kind, message, scope_check)
                if not value:
                    continue
                if consume:
                    delivered.setdefault(message_id, []).append(kind)
                    credentials.save_mailbox(workspace.slug, alias, record)
                data = {"alias": alias, "kind": kind, "ready": True,
                        "value": value, "sender_domain": from_domain}
                if not consume:
                    data["_message_id"] = message_id
                return {
                    "ok": True,
                    "summary": f"Temporary mailbox {alias!r} received a {kind} value.",
                    "data": data,
                }
            if time.monotonic() >= deadline:
                return {
                    "ok": True,
                    "summary": f"No matching {kind} arrived for temporary mailbox {alias!r}.",
                    "data": {"alias": alias, "kind": kind, "ready": False},
                }
            sleep(min(2.0, max(0.0, deadline - time.monotonic())))


def mark_delivered(workspace: Workspace, alias: str, message_id: str,
                   kind: str) -> None:
    """Mark a privately consumed confirmation value after its bound action."""
    if kind not in {"otp", "link"} or not str(message_id or ""):
        raise TemporaryMailboxError("Mailbox delivery marker is invalid.")
    with credentials.mailbox_lock(workspace.slug, alias):
        try:
            record = _record(credentials.load_mailbox(workspace.slug, alias))
        except credentials.CredentialError as exc:
            raise TemporaryMailboxError(str(exc)) from exc
        delivered = record["delivered"]
        previous = delivered.setdefault(str(message_id), [])
        if not isinstance(previous, list):
            raise TemporaryMailboxError("Private mailbox state is malformed.")
        if kind not in previous:
            previous.append(kind)
            credentials.save_mailbox(workspace.slug, alias, record)
