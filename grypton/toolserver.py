"""Grypton MCP stdio server and matching command-line tool surface."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import sys
import time
from typing import Callable

from . import config, credentials, tools
from .providers import append_jsonl
from .workspace import FINDING_NARRATIVE_FIELDS, Workspace

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "grypton", "version": "3.4.0"}


def _workspace() -> Workspace:
    return Workspace(os.environ.get("GRYPTON_TARGET") or
                     os.environ.get("KRYPTON_TARGET") or "default")


def _string(description: str) -> dict:
    return {"type": "string", "description": description}


def _object(properties: dict, required=()) -> dict:
    return {"type": "object", "additionalProperties": False,
            "properties": properties, "required": list(required)}


def _record_finding(ws, args):
    required = ("title", "severity", "vuln_class", "surface", "description", "poc", "evidence")
    missing = [key for key in required if not str(args.get(key) or "").strip()]
    if missing:
        return {
            "ok": False,
            "summary": (
                "Finding quality gate rejected the candidate; supply "
                + ", ".join(missing)
                + ". Keep incomplete hypotheses in tested_technique_log."
            ),
        }
    record = ws.record_finding(title=args["title"], severity=args["severity"],
        vuln_class=args.get("vuln_class", ""), surface=args.get("surface", ""),
        description=args.get("description", ""), poc=args.get("poc", ""),
        evidence=args.get("evidence", ""), source="worker")
    if config.astra_auto_validation_required(record["severity"]):
        summary = f"Recorded {record['id']} for independent Astra validation."
    else:
        summary = f"Recorded {record['id']}; automatic Astra validation is not requested for {record['severity']}."
    return {"ok": True, "summary": summary,
            "data": record}


def _revise_finding(ws, args):
    allowed = {"finding_id", "reason", *FINDING_NARRATIVE_FIELDS}
    invalid = sorted(set(args) - allowed)
    if invalid:
        return {
            "ok": False,
            "summary": "Finding revision rejected immutable or unsupported fields: "
                       + ", ".join(invalid) + ".",
        }
    changes = {
        field_name: args[field_name]
        for field_name in FINDING_NARRATIVE_FIELDS
        if field_name in args
    }
    try:
        record = ws.revise_finding(
            args.get("finding_id", ""),
            reason=args.get("reason", ""),
            source="worker",
            **changes,
        )
    except (KeyError, ValueError) as exc:
        return {"ok": False, "summary": str(exc).strip("'")}
    revision = (record.get("revisions") or [])[-1]
    fields = ", ".join((revision.get("changes") or {}).keys())
    return {
        "ok": True,
        "summary": (
            f"Recorded amendment {revision.get('id')} for {record['id']} "
            f"({fields}); severity remains {record['severity']}."
        ),
        "data": record,
    }


def _surface(ws, args):
    record = ws.append_attack_surface(item=args["item"], kind=args.get("kind", "endpoint"),
        detail=args.get("detail", ""), interesting=args.get("interesting", ""), source="worker")
    return {"ok": True, "summary": f"Added surface {record['id']}: {record['item']}", "data": record}


def _tested(ws, args):
    record = ws.log_tested_technique(surface=args["surface"], technique=args["technique"],
        result=args.get("result", "blocked"), evidence=args.get("evidence", ""), source="worker")
    return {"ok": True, "summary": f"Logged {record['id']}: {record['result']}", "data": record}


def _prior(ws, args):
    rows = ws.prior_attempts(args["surface"], args.get("technique", ""))
    return {"ok": True, "summary": f"{len(rows)} prior attempt(s).", "data": rows}


def _http(ws, args):
    return tools.http_request(ws, args["url"], method=args.get("method", "GET"),
        headers=args.get("headers"), body=args.get("body"), timeout=args.get("timeout", 30),
        follow_redirects=args.get("follow_redirects", False), insecure=args.get("insecure", False))


def _credential_status(ws, args):
    return tools.credential_status(ws, args.get("credential", ""))


def _auth_dispatch_metadata(requested: str, effective: str, *,
                            configured: bool, revision: str = "") -> dict:
    return {
        "requested_tool": requested,
        "effective_tool": effective,
        "profile_configured": bool(configured),
        "profile_revision": str(revision or ""),
    }


def _with_auth_dispatch(result: dict, metadata: dict) -> dict:
    output = dict(result) if isinstance(result, dict) else {
        "ok": False, "summary": "Authentication dispatch returned an invalid result."
    }
    data = output.get("data")
    if not isinstance(data, dict):
        data = {} if data is None else {"result": data}
    else:
        data = dict(data)
    data["auth_dispatch"] = metadata
    output["data"] = data
    return output


def _http_login_from_args(ws: Workspace, args: dict) -> dict:
    return tools.credential_login(
        ws, args.get("url", ""), credential=args.get("credential", ""),
        verify_url=args.get("verify_url", ""),
        success_marker=args.get("success_marker", ""),
        username_field=args.get("username_field", "username"),
        password_field=args.get("password_field", "password"),
        username_transform=args.get("username_transform", "stored"),
        encoding=args.get("encoding", "json"), fields=args.get("fields"),
        headers=args.get("headers"), timeout=args.get("timeout", 30),
    )


def _browser_login_from_args(ws: Workspace, args: dict) -> dict:
    return tools.credential_browser_login(
        ws, args.get("url", ""), credential=args.get("credential", ""),
        username_transform=args.get("username_transform", "stored"),
        username_selector=args.get(
            "username_selector", "[data-testid='login-username']"
        ),
        password_selector=args.get(
            "password_selector", "[data-testid='login-password']"
        ),
        submit_selector=args.get(
            "submit_selector", "[data-testid='login-submit']"
        ),
        verify_url=args.get("verify_url", ""),
        success_marker=args.get("success_marker", ""),
        verify_headers=args.get("verify_headers"),
        timeout=args.get("timeout", 45),
    )


def _profiled_auth_login(ws: Workspace, requested: str,
                         credential: object, profile: dict,
                         *, upgrade_browser_state: bool = False) -> dict:
    effective = (
        "credential_browser_login"
        if profile["strategy"] == "browser" else "credential_login"
    )
    metadata = _auth_dispatch_metadata(
        requested, effective, configured=True,
        revision=credentials.auth_profile_revision(profile),
    )
    scoped_urls = [profile["login_url"], profile["verify_url"]]
    if profile["strategy"] == "browser":
        verification = profile["browser"].get("verification")
        if isinstance(verification, dict):
            scoped_urls.append(verification["expected_post_login_url"])
    for candidate in scoped_urls:
        allowed, _ = tools.check_url_scope(ws, candidate)
        if not allowed:
            return _with_auth_dispatch({
                "ok": False,
                "summary": (
                    "Configured authentication profile is outside the engagement scope."
                ),
            }, metadata)

    if profile["strategy"] == "browser":
        browser = profile["browser"]
        verification = browser.get("verification")
        state = credentials.load_attempt_state(ws.slug, str(credential or ""))
        if isinstance(verification, dict) and state["ever_established"]:
            result = (
                tools.credential_browser_state_upgrade(
                    ws, str(credential or "")
                )
                if requested == "credential_browser_login"
                and upgrade_browser_state
                else tools.ensure_browser_status_session(
                    ws, str(credential or "")
                )
            )
            return _with_auth_dispatch(result, metadata)
        browser_args = {
            "credential": credential,
            "username_transform": profile["username_transform"],
            "username_selector": browser["username_selector"],
            "password_selector": browser["password_selector"],
            "submit_selector": browser["submit_selector"],
            "verify_url": profile["verify_url"],
            "success_marker": profile.get("success_marker", ""),
            "verify_headers": browser["verify_headers"],
            "timeout": profile["timeout"],
        }
        if verification is not None:
            browser_args["verification"] = verification
        result = tools.credential_browser_login(
            ws, profile["login_url"], **browser_args
        )
    else:
        http = profile["http"]
        result = tools.credential_login(
            ws, profile["login_url"], credential=credential,
            verify_url=profile["verify_url"],
            success_marker=profile["success_marker"],
            username_field=http["username_field"],
            password_field=http["password_field"],
            username_transform=profile["username_transform"],
            encoding=http["encoding"], fields=http["fields"],
            headers=http["headers"], timeout=profile["timeout"],
        )
    return _with_auth_dispatch(result, metadata)


def _auth_login(ws: Workspace, args: dict, *, requested: str) -> dict:
    credential = str(args.get("credential") or "")
    if (
        "upgrade_browser_state" in args
        and not isinstance(args.get("upgrade_browser_state"), bool)
    ):
        return _with_auth_dispatch({
            "ok": False,
            "summary": "upgrade_browser_state must be a literal boolean.",
        }, _auth_dispatch_metadata(requested, "", configured=False))
    configured = False
    try:
        with credentials.auth_profile_lock(ws.slug, credential):
            profile_path = credentials.auth_profile_path(ws.slug, credential)
            configured = profile_path.exists() or profile_path.is_symlink()
            profile = credentials.load_auth_profile_optional(
                ws.slug, credential
            )
            if not configured and profile is None:
                result = (
                    _browser_login_from_args(ws, args)
                    if requested == "credential_browser_login"
                    else _http_login_from_args(ws, args)
                )
                return _with_auth_dispatch(result, _auth_dispatch_metadata(
                    requested, requested, configured=False
                ))
            if profile is not None:
                # Keep the canonical profile snapshot stable through routing,
                # proof, and the revision recorded with that proof.
                return _profiled_auth_login(
                    ws, requested, credential, profile,
                    upgrade_browser_state=args.get("upgrade_browser_state") is True,
                )
    except credentials.CredentialError:
        metadata = _auth_dispatch_metadata(
            requested, "", configured=configured
        )
        return _with_auth_dispatch({
            "ok": False,
            "summary": (
                "Configured authentication profile is invalid; replace or clear it."
                if configured else "Credential alias or profile state is invalid."
            ),
        }, metadata)

    if configured and profile is None:
        return _with_auth_dispatch({
            "ok": False,
            "summary": "Configured authentication profile is unavailable; retry later.",
        }, _auth_dispatch_metadata(
            requested, "", configured=True
        ))
    return _with_auth_dispatch({
        "ok": False,
        "summary": "Configured authentication profile is unavailable; retry later.",
    }, _auth_dispatch_metadata(requested, "", configured=True))


def _credential_login(ws, args):
    return _auth_login(ws, args, requested="credential_login")


def _credential_browser_login(ws, args):
    return _auth_login(ws, args, requested="credential_browser_login")


def _authenticated_http(ws, args):
    credential = str(args.get("credential") or "")
    try:
        with credentials.auth_profile_lock(ws.slug, credential):
            with credentials.session_material_lock(ws.slug, credential):
                profile = credentials.load_auth_profile_optional(
                    ws.slug, credential
                )
                verification = (
                    profile.get("browser", {}).get("verification")
                    if isinstance(profile, dict)
                    and profile.get("strategy") == "browser" else None
                )
                maintenance = None
                request_headers = args.get("headers")
                accepted_statuses: tuple[int, ...] = ()
                private_headers = None
                state = credentials.load_attempt_state(ws.slug, credential)
                if isinstance(verification, dict) and state["ever_established"]:
                    ensured = tools.ensure_browser_status_session(
                        ws, credential
                    )
                    ensured_data = (
                        ensured.get("data")
                        if isinstance(ensured.get("data"), dict) else {}
                    )
                    maintenance = ensured_data.get("session_maintenance")
                    if not ensured.get("ok"):
                        state_after = credentials.load_attempt_state(
                            ws.slug, credential
                        )
                        if not state_after["established"]:
                            return ensured
                        if not isinstance(maintenance, dict):
                            maintenance = {
                                "action": "revalidation-deferred",
                                "credential_submission": False,
                            }
                    if (
                        str(args.get("method") or "GET").strip().upper() == "GET"
                        and tools._browser_auth_url_matches(
                            str(args.get("url") or ""),
                            str(profile.get("verify_url") or ""),
                        )
                    ):
                        private_headers = profile["browser"]["verify_headers"]
                        accepted_statuses = (
                            int(verification["authenticated_status"]),
                        )
                result = tools.authenticated_http_request(
                    ws, args["url"], credential=credential,
                    method=args.get("method", "GET"),
                    headers=request_headers, body=args.get("body"),
                    timeout=args.get("timeout", 30),
                    _profile_headers=private_headers,
                    _accepted_statuses=accepted_statuses,
                )
                if isinstance(maintenance, dict):
                    data = (
                        dict(result.get("data"))
                        if isinstance(result.get("data"), dict) else {}
                    )
                    data["session_maintenance"] = maintenance
                    result["data"] = data
                return result
    except credentials.CredentialError as exc:
        return {"ok": False, "summary": str(exc)}


def _authenticated_browser(ws, args):
    credential = str(args.get("credential") or "")
    try:
        with credentials.auth_profile_lock(ws.slug, credential):
            profile = credentials.load_auth_profile_optional(
                ws.slug, credential
            )
            verification = (
                profile.get("browser", {}).get("verification")
                if isinstance(profile, dict)
                and profile.get("strategy") == "browser" else None
            )
            maintenance = None
            state = credentials.load_attempt_state(ws.slug, credential)
            if isinstance(verification, dict) and state["ever_established"]:
                ensured = tools.ensure_browser_status_session(ws, credential)
                ensured_data = (
                    ensured.get("data")
                    if isinstance(ensured.get("data"), dict) else {}
                )
                maintenance = ensured_data.get("session_maintenance")
                if not ensured.get("ok"):
                    state_after = credentials.load_attempt_state(
                        ws.slug, credential
                    )
                    if not state_after["established"]:
                        return ensured
                    if not isinstance(maintenance, dict):
                        maintenance = {
                            "action": "revalidation-deferred",
                            "credential_submission": False,
                        }
            profile_headers = None
            if (
                isinstance(profile, dict)
                and profile.get("strategy") == "browser"
                and str(args.get("method") or "GET").strip().upper() == "GET"
                and tools._browser_auth_url_matches(
                    str(args.get("url") or ""),
                    str(profile.get("verify_url") or ""),
                )
            ):
                profile_headers = profile.get("browser", {}).get("verify_headers")
            result = tools.authenticated_browser_request(
                ws, args["url"], credential=credential,
                method=args.get("method", "GET"),
                headers=args.get("headers"), body=args.get("body"),
                page_url=args.get("page_url", ""),
                header_sources=args.get("header_sources"),
                timeout=args.get("timeout", 30),
                _profile_headers=profile_headers,
            )
            if isinstance(maintenance, dict):
                data = (
                    dict(result.get("data"))
                    if isinstance(result.get("data"), dict) else {}
                )
                data["session_maintenance"] = maintenance
                result["data"] = data
            return result
    except credentials.CredentialError as exc:
        return {"ok": False, "summary": str(exc)}


def _goja_request(ws, args):
    return tools.Goja.request(ws, args["url"], method=args.get("method", "GET"),
        headers=args.get("headers"), body=args.get("body"), timeout=args.get("timeout", 30),
        follow_redirects=args.get("follow_redirects", False))


def _flow_replay(ws, args):
    return tools.flow_replay(ws, args["flow_id"], url=args.get("url", ""),
        method=args.get("method", ""), headers=args.get("headers"), body=args.get("body"))


def _save_research(ws, args):
    path = ws.save_research(args["topic"], args["content"])
    return {"ok": True, "summary": f"Saved {path}.", "data": {"path": str(path)}}


def _read_doc(ws, args):
    mapping = {"findings": "findings.md", "surface": "attack-surface.md",
        "tested": "tested-techniques.md", "progress": "progress.md", "scope": "scope-rules.md"}
    name = args.get("name", "findings")
    if name not in mapping:
        return {"ok": False, "summary": "That engagement document is not worker-readable."}
    path = ws.root / mapping[name]
    if not path.is_file():
        return {"ok": True, "summary": f"{path.name} is not attached to this engagement.",
                "data": {"text": "", "present": False}}
    value = path.read_text(encoding="utf-8", errors="replace")
    return {"ok": True, "summary": f"Read {path.name} ({len(value)} characters).",
            "data": {"text": value[:200_000], "present": True}}


REGISTRY: dict[str, tuple[str, dict, Callable]] = {
    "record_finding": ("Record a fully evidenced candidate. P1/P2 candidates enter automatic Astra validation.",
        _object({"title": _string("Short title"),
                 "severity": {"type": "string", "enum": ["P1", "P2", "P3", "P4", "P5"]},
                 "vuln_class": _string("Vulnerability class"), "surface": _string("Affected surface"),
                 "description": _string("Impact and behavior"), "poc": _string("Reproduction steps"),
                 "evidence": _string("Capture path or concrete evidence")},
                ("title", "severity", "vuln_class", "surface", "description", "poc", "evidence")),
        _record_finding),
    "revise_finding": ("Correct or narrow a finding narrative with durable before/after history.",
        {**_object({
            "finding_id": _string("Existing finding ID"),
            "reason": _string("Why the evidence requires this amendment"),
            "title": _string("Revised short title"),
            "vuln_class": _string("Revised vulnerability class"),
            "surface": _string("Revised affected surface"),
            "description": _string("Revised impact and behavior"),
            "poc": _string("Revised reproduction steps"),
            "evidence": _string("Revised capture path or concrete evidence"),
        }, ("finding_id", "reason")),
         "anyOf": [{"required": [field_name]}
                   for field_name in FINDING_NARRATIVE_FIELDS]},
        _revise_finding),
    "attack_surface_add": ("Record a discovered in-scope host, route, parameter, behavior, or clue.",
        _object({"item": _string("Observed surface"), "kind": _string("Surface kind"),
                 "detail": _string("Concrete detail"), "interesting": _string("Why it matters")},
                ("item",)), _surface),
    "tested_technique_log": ("Record a bounded technique and its observed result.",
        _object({"surface": _string("Tested surface"), "technique": _string("Technique"),
                 "result": _string("Observed result"), "evidence": _string("Capture/evidence")},
                ("surface", "technique")), _tested),
    "prior_attempts": ("Read prior attempts before repeating work.",
        _object({"surface": _string("Surface"), "technique": _string("Optional filter")}, ("surface",)),
        _prior),
    "http_request": ("Send one scoped curl request and save a Burp-like request/response capture.",
        _object({"url": _string("In-scope HTTP(S) URL"), "method": _string("HTTP method"),
                 "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                 "body": _string("Request body"), "timeout": {"type": "integer", "minimum": 1, "maximum": 120},
                 "follow_redirects": {"type": "boolean"}, "insecure": {"type": "boolean"}}, ("url",)), _http),
    "credential_status": (
        "List named credential aliases and session state metadata.",
        _object({"credential": _string("Optional credential alias")}), _credential_status),
    "credential_login": (
        "Authenticate with a named private credential and capture the resulting "
        "application behavior.",
        _object({
            "url": _string("In-scope login endpoint"),
            "credential": _string("Credential alias"),
            "verify_url": _string("Scoped endpoint that proves the session"),
            "success_marker": _string("Exact non-secret text required in verification response body"),
            "username_field": _string("Login username/mobile field name"),
            "password_field": _string("Login password field name"),
            "username_transform": {
                "type": "string",
                "enum": ["stored", "iran-e164"],
                "description": "Username representation for this login",
            },
            "encoding": {"type": "string", "enum": ["json", "form"]},
            "fields": {"type": "object", "additionalProperties": {"type": "string"}},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "timeout": {"type": "integer", "minimum": 1, "maximum": 120},
        }, ("credential",)), _credential_login),
    "credential_browser_login": (
        "Authenticate with a named private credential and capture the resulting "
        "application behavior.",
        _object({
            "url": _string("In-scope rendered login page"),
            "credential": _string("Credential alias"),
            "username_transform": {
                "type": "string",
                "enum": ["stored", "iran-e164"],
                "description": "Username representation for this login",
            },
            "username_selector": _string(
                "Username CSS selector; defaults to Milli login-username testid"
            ),
            "password_selector": _string(
                "Password CSS selector; defaults to Milli login-password testid"
            ),
            "submit_selector": _string(
                "Submit CSS selector; defaults to Milli login-submit testid"
            ),
            "verify_url": _string(
                "Scoped same-origin page or endpoint for session proof"
            ),
            "success_marker": _string(
                "Exact non-secret text used for independent session proof"
            ),
            "verify_headers": {
                "type": "object",
                "additionalProperties": {"type": "string"},
                "description": "Same-origin protocol headers for session proof",
            },
            "timeout": {"type": "integer", "minimum": 5, "maximum": 120},
            "upgrade_browser_state": {
                "type": "boolean",
                "description": "Explicit one-attempt upgrade for a proven legacy session",
            },
        }, ("credential",)),
        _credential_browser_login),
    "authenticated_http_request": (
        "Send one scoped request with a named private cookie/bearer session and a sanitized capture.",
        _object({
            "url": _string("In-scope HTTP(S) URL"),
            "credential": _string("Credential alias"),
            "method": _string("HTTP method"),
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "body": _string("Optional non-secret request body"),
            "timeout": {"type": "integer", "minimum": 1, "maximum": 120},
        }, ("url", "credential")), _authenticated_http),
    "authenticated_browser_request": (
        "Send one scoped request from a named private authenticated browser context "
        "and save bounded request captures.",
        _object({
            "url": _string("In-scope HTTP(S) URL on the proven session origin"),
            "credential": _string("Credential alias"),
            "method": _string("HTTP method"),
            "headers": {
                "type": "object", "maxProperties": 32,
                "additionalProperties": {"type": "string"},
            },
            "body": _string("Optional request body up to 1,000,000 bytes"),
            "page_url": _string(
                "Same-origin URL used for an inert browser context; its HTML is "
                "fetched and parsed without scripts only when a meta header source is used"
            ),
            "header_sources": {
                "type": "object", "maxProperties": 16,
                "description": (
                    "Headers resolved privately from browser state; meta sources add one "
                    "bounded same-origin HTML fetch before the primary request"
                ),
                "additionalProperties": {
                    "type": "object", "additionalProperties": False,
                    "properties": {
                        "source": {
                            "type": "string",
                            "enum": [
                                "localStorage", "sessionStorage", "cookie", "meta",
                            ],
                        },
                        "name": {"type": "string", "maxLength": 512},
                        "prefix": {"type": "string", "maxLength": 128},
                        "url_decode": {"type": "boolean"},
                    },
                    "required": ["source", "name"],
                },
            },
            "timeout": {"type": "integer", "minimum": 5, "maximum": 120},
        }, ("url", "credential")), _authenticated_browser),
    "goja_start": ("Start Grypton's managed Goja SOCKS5 TLS-fingerprint proxy.", _object({}),
        lambda ws, args: tools.Goja.start()),
    "goja_status": ("Read managed Goja status.", _object({}), lambda ws, args: tools.Goja.status()),
    "goja_stop": ("Stop the Grypton-managed Goja process.", _object({}),
        lambda ws, args: tools.Goja.stop()),
    "goja_request": ("Send one scoped request through Goja and capture the complete flow.",
        _object({"url": _string("In-scope HTTP(S) URL"), "method": _string("HTTP method"),
                 "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                 "body": _string("Request body"), "timeout": {"type": "integer"},
                 "follow_redirects": {"type": "boolean"}}, ("url",)), _goja_request),
    "proxy_flows": ("List and grep Burp-like captured request/response flows.",
        _object({"query": _string("Substring filter"), "limit": {"type": "integer"}}),
        lambda ws, a: tools.proxy_flows(ws, query=a.get("query", ""), limit=a.get("limit", 20))),
    "flow_read": ("Read one bounded byte window from a captured request/response flow.",
        _object({
            "flow_id": _string("flow-... ID"),
            "offset": {
                "type": "integer", "minimum": 0,
                "description": "Byte offset; continue with next_offset from the prior result",
            },
            "max_chars": {
                "type": "integer", "minimum": 256,
                "description": (
                    "Requested text window; requests above 32768 are accepted "
                    "but capped, with next_offset returned for continuation"
                ),
            },
        }, ("flow_id",)),
        lambda ws, a: tools.flow_read(
            ws, a["flow_id"], offset=a.get("offset", 0),
            max_chars=a.get("max_chars", tools.DEFAULT_FLOW_READ_CHARS),
        )),
    "flow_replay": ("Replay a captured scoped request with optional URL/method/header/body overrides.",
        _object({"flow_id": _string("flow-... ID"), "url": _string("Optional scoped URL"),
                 "method": _string("Optional method"),
                 "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                 "body": _string("Optional replacement body")}, ("flow_id",)), _flow_replay),
    "httpx_probe": ("Probe scoped hosts with ProjectDiscovery httpx.",
        _object({"targets": _string("Whitespace-separated scoped hosts/URLs")}, ("targets",)),
        lambda ws, a: tools.httpx_probe(ws, a["targets"])),
    "browse": ("Load a scoped page with headless Chromium and save its DOM/capture.",
        _object({"url": _string("In-scope URL"), "timeout": {"type": "integer"}}, ("url",)),
        lambda ws, a: tools.browse(ws, a["url"], timeout=a.get("timeout", 45))),
    "dns_lookup": ("Resolve an in-scope hostname.", _object({"host": _string("Hostname")}, ("host",)),
        lambda ws, a: tools.dns_lookup(ws, a["host"])),
    "tls_certificate": ("Inspect the TLS certificate on an in-scope host.",
        _object({"host": _string("Hostname"), "port": {"type": "integer"}}, ("host",)),
        lambda ws, a: tools.tls_certificate(ws, a["host"], port=a.get("port", 443))),
    "port_scan": ("Check at most 128 TCP ports on one in-scope host.",
        _object({"host": _string("Hostname or IP"),
                 "ports": {"type": "array", "items": {"type": "integer"}, "maxItems": 128},
                 "timeout_ms": {"type": "integer"}}, ("host", "ports")),
        lambda ws, a: tools.port_scan(ws, a["host"], a["ports"], timeout_ms=a.get("timeout_ms", 350))),
    "tcp_exchange": ("Send one newline-delimited frame to a scoped TCP endpoint and save the banner and response.",
        _object({"host": _string("In-scope hostname or IP"), "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                 "payload": _string("One text protocol frame without its trailing newline"),
                 "timeout": {"type": "integer", "minimum": 1, "maximum": 60}}, ("host", "port", "payload")),
        lambda ws, a: tools.tcp_exchange(ws, a["host"], a["port"], a["payload"], timeout=a.get("timeout", 15))),
    "artifact_download": ("Download one scoped binary artifact into the engagement loot directory.",
        _object({"url": _string("In-scope HTTP(S) artifact URL"), "filename": _string("Safe destination basename"),
                 "timeout": {"type": "integer", "minimum": 1, "maximum": 120}}, ("url", "filename")),
        lambda ws, a: tools.artifact_download(ws, a["url"], a["filename"], timeout=a.get("timeout", 60))),
    "apk_inspect": ("Inspect an APK's binary metadata, manifest components, signature status, and asset names; no source decompilation.",
        _object({"artifact": _string("APK basename previously downloaded to loot")}, ("artifact",)),
        lambda ws, a: tools.apk_inspect(ws, a["artifact"])),
    "apk_extract_asset": ("Extract one named APK asset into loot for local binary analysis.",
        _object({"artifact": _string("APK basename previously downloaded to loot"),
                 "asset": _string("APK asset path beneath assets/")}, ("artifact", "asset")),
        lambda ws, a: tools.apk_extract_asset(ws, a["artifact"], a["asset"])),
    "subdomain_enum": ("Run passive subfinder enumeration for an in-scope domain.",
        _object({"domain": _string("In-scope base domain"), "timeout": {"type": "integer"}}, ("domain",)),
        lambda ws, a: tools.subdomain_enum(ws, a["domain"], timeout=a.get("timeout", 180))),
    "local_analyze": ("Inspect or search one engagement or worker tool-output file with bounded output.",
        _object({"path": _string(
                    "Engagement-relative path, engagement/... alias, opencode-tool-output/... alias, or an exact allowed absolute path"
                 ),
                 "analyzer": {"type": "string", "enum": ["file", "strings", "sha256", "literal", "regex"]},
                 "min_length": {"type": "integer", "minimum": 4, "maximum": 64},
                 "pattern": _string("Required literal text or byte-oriented regular expression for search analyzers"),
                 "ignore_case": {"type": "boolean"},
                 "context_bytes": {"type": "integer", "minimum": 0, "maximum": 2048},
                 "max_matches": {"type": "integer", "minimum": 1, "maximum": 50}},
                ("path", "analyzer")),
        lambda ws, a: tools.local_analyze(
            ws, a["path"], analyzer=a["analyzer"], min_length=a.get("min_length", 6),
            pattern=a.get("pattern", ""), ignore_case=a.get("ignore_case", False),
            context_bytes=a.get("context_bytes", 160), max_matches=a.get("max_matches", 20),
        )),
    "install_tool": ("Install one approved OS package from Grypton's fixed allowlist.",
        _object({"spec": _string("Exact approved OS package name"),
                 "manager": {"type": "string", "enum": ["auto", "apt"]}},
                ("spec",)), lambda ws, a: tools.install_tool(a["spec"], manager=a.get("manager", "auto"))),
    "research": ("Fetch target-scoped material or approved public security/tool documentation.",
        _object({"url": _string("HTTP(S) URL"), "timeout": {"type": "integer"}}, ("url",)),
        lambda ws, a: tools.research(ws, a["url"], timeout=a.get("timeout", 30))),
    "save_research": ("Save a research note in the engagement workspace.",
        _object({"topic": _string("Topic"), "content": _string("Markdown")}, ("topic", "content")),
        _save_research),
    "read_doc": ("Read findings, surface, tested, progress, or the projected scope document.",
        _object({"name": {"type": "string", "enum": ["findings", "surface", "tested", "progress", "scope"]}}),
        _read_doc),
    "tool_inventory": ("List available native binaries and Goja state.", _object({}),
        lambda ws, args: tools.inventory()),
}


_SENSITIVE_AUDIT_KEYS = {
    "authorization", "cookie", "set-cookie", "proxy-authorization",
    "password", "passwd", "secret", "token", "access_token", "refresh_token",
    "id_token", "api_key", "x-api-key", "x-auth-token", "x-courier-mac",
    "x-courier-signature",
}


# These handlers only inspect private engagement state or local artifacts. An
# engine crash after one of them returns can safely be retried because the call
# cannot send traffic, change a process, install software, or mutate engagement
# state. New tools default to guarded so a later side-effecting handler cannot
# accidentally reopen the supervisor replay race.
_RESTART_SAFE_READ_ONLY_TOOLS = frozenset({
    "prior_attempts",
    "credential_status",
    "goja_status",
    "proxy_flows",
    "flow_read",
    "apk_inspect",
    "local_analyze",
    "read_doc",
    "tool_inventory",
})


def _record_effectful_tool_start(workspace: Workspace, name: str) -> None:
    """Durably mark a potentially effectful call before invoking its handler.

    The completed-call audit is necessarily written after dispatch and cannot
    distinguish a pre-call crash from a crash after an external side effect.
    This small argument-free ledger closes that gap. A partial final record is
    still counted conservatively by the supervisor.
    """
    path = workspace.root / ".ledger" / "effectful-tool-starts.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        payload = (json.dumps({
            "at": time.time(),
            "tool": name,
        }, ensure_ascii=False) + "\n").encode("utf-8")
        remaining = memoryview(payload)
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                raise OSError("short write while recording effectful tool start")
            remaining = remaining[written:]
        os.fsync(fd)
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _redacted(value, secret_values=()):
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]" if str(key).lower() in _SENSITIVE_AUDIT_KEYS
                else _redacted(item, secret_values)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redacted(item, secret_values) for item in value]
    if isinstance(value, str):
        return tools.redact_sensitive_text(value, secret_values)
    return value


def _audit_secret_values(workspace: Workspace, name: str, args: dict) -> tuple[str, ...]:
    if name not in {"credential_login", "credential_browser_login"}:
        return ()
    try:
        secret = credentials.load_credential(
            workspace.slug, str(args.get("credential") or "")
        )
    except credentials.CredentialError:
        return ()
    values = [secret["password"]]
    values.extend(tools._login_username_redaction_values(
        secret["username"], str(args.get("username_transform") or "stored")
    ))
    return tools._serialized_secret_variants(values)


def _audit_auth_dispatch(name: str, result: dict) -> dict | None:
    if name not in {"credential_login", "credential_browser_login"}:
        return None
    data = result.get("data") if isinstance(result, dict) else None
    value = data.get("auth_dispatch") if isinstance(data, dict) else None
    if not isinstance(value, dict):
        return None
    requested = str(value.get("requested_tool") or "")
    effective = str(value.get("effective_tool") or "")
    revision = str(value.get("profile_revision") or "")
    allowed_tools = {"", "credential_login", "credential_browser_login"}
    if (requested not in allowed_tools or effective not in allowed_tools
            or (revision and not re.fullmatch(r"[0-9a-f]{12}", revision))):
        return None
    return {
        "requested_tool": requested,
        "effective_tool": effective,
        "profile_configured": bool(value.get("profile_configured")),
        "profile_revision": revision,
    }


def dispatch(workspace: Workspace, name: str, args: dict) -> dict:
    started = time.time()
    if name not in REGISTRY:
        result = {"ok": False, "summary": f"Unknown tool {name!r}."}
    elif not workspace.exists():
        result = {"ok": False, "summary": "The engagement workspace is not initialized."}
    else:
        guarded = name not in _RESTART_SAFE_READ_ONLY_TOOLS
        marker_error = False
        if guarded:
            try:
                # This must complete before the handler can perform an external
                # or persistent action. Failure is closed: do not dispatch a
                # call the supervisor could later replay unknowingly.
                _record_effectful_tool_start(workspace, name)
            except OSError:
                marker_error = True
        if marker_error:
            result = {
                "ok": False,
                "summary": (
                    f"{name} was not started because its restart-safety "
                    "marker could not be persisted."
                ),
            }
        else:
            try:
                result = REGISTRY[name][2](workspace, args or {})
            except Exception as exc:
                result = {"ok": False, "summary": f"{name} failed: {exc}"}
    try:
        audit_secrets = _audit_secret_values(workspace, name, args or {})
        audit_row = {
            "at": time.time(), "tool": name,
            "args": _redacted(args or {}, audit_secrets),
            "ok": bool(result.get("ok")), "summary": result.get("summary", "")[:1000],
            "duration_s": round(time.time() - started, 3),
        }
        auth_dispatch = _audit_auth_dispatch(name, result)
        if auth_dispatch is not None:
            audit_row["auth_dispatch"] = auth_dispatch
        append_jsonl(workspace.root / ".ledger" / "tool-calls.jsonl", audit_row)
    except OSError:
        pass
    return result


def _rpc_result(request_id, result):
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _handle(message: dict, workspace: Workspace):
    method, request_id = message.get("method"), message.get("id")
    if method == "initialize":
        return _rpc_result(request_id, {"protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}}, "serverInfo": SERVER_INFO})
    if method in {"notifications/initialized", "initialized"}:
        return None
    if method == "ping":
        return _rpc_result(request_id, {})
    if method == "tools/list":
        return _rpc_result(request_id, {"tools": [
            {"name": name, "description": description, "inputSchema": schema}
            for name, (description, schema, _) in REGISTRY.items()]})
    if method == "tools/call":
        params = message.get("params") or {}
        result = dispatch(workspace, params.get("name", ""), params.get("arguments") or {})
        return _rpc_result(request_id, {"content": [{"type": "text",
            "text": json.dumps(result, ensure_ascii=False, indent=2)}],
            "isError": not result.get("ok", False)})
    return {"jsonrpc": "2.0", "id": request_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"}}


def mcp_main() -> int:
    workspace = _workspace()
    for line in sys.stdin:
        try:
            message = json.loads(line)
            response = _handle(message, workspace)
        except Exception as exc:
            response = {"jsonrpc": "2.0", "id": None,
                        "error": {"code": -32603, "message": f"Internal error: {exc}"}}
        if response is not None:
            print(json.dumps(response, ensure_ascii=False), flush=True)
    return 0


def _headers(value: str) -> dict:
    if not value:
        return {}
    result = json.loads(value)
    if not isinstance(result, dict):
        raise argparse.ArgumentTypeError("headers must be a JSON object")
    return result


def cli_main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="grypton-tool", description="Grypton's scoped tool surface")
    parser.add_argument("--target", default=os.environ.get("GRYPTON_TARGET") or
                        os.environ.get("KRYPTON_TARGET") or "default")
    parser.add_argument("--json", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    request = sub.add_parser("http"); request.add_argument("url"); request.add_argument("--method", default="GET")
    request.add_argument("--headers", type=_headers, default={}); request.add_argument("--body")
    request.add_argument("--follow", action="store_true"); request.add_argument("--insecure", action="store_true")
    goja_request = sub.add_parser("goja-request"); goja_request.add_argument("url")
    goja_request.add_argument("--method", default="GET"); goja_request.add_argument("--headers", type=_headers, default={})
    goja_request.add_argument("--body")
    for name in ("goja-start", "goja-status", "goja-stop", "inventory"):
        sub.add_parser(name)
    flows = sub.add_parser("flows"); flows.add_argument("--query", default=""); flows.add_argument("--limit", type=int, default=20)
    flow_read_parser = sub.add_parser("flow-read"); flow_read_parser.add_argument("flow_id")
    flow_read_parser.add_argument("--offset", type=int, default=0)
    flow_read_parser.add_argument("--max-chars", type=int, default=tools.DEFAULT_FLOW_READ_CHARS)
    replay = sub.add_parser("flow-replay"); replay.add_argument("flow_id"); replay.add_argument("--url", default="")
    replay.add_argument("--method", default=""); replay.add_argument("--headers", type=_headers, default={}); replay.add_argument("--body")
    httpx = sub.add_parser("httpx"); httpx.add_argument("targets")
    dns = sub.add_parser("dns"); dns.add_argument("host")
    tls = sub.add_parser("tls"); tls.add_argument("host"); tls.add_argument("--port", type=int, default=443)
    ports = sub.add_parser("ports"); ports.add_argument("host"); ports.add_argument("ports", help="comma-separated")
    tcp = sub.add_parser("tcp"); tcp.add_argument("host"); tcp.add_argument("port", type=int); tcp.add_argument("payload")
    artifact = sub.add_parser("artifact-download"); artifact.add_argument("url"); artifact.add_argument("filename")
    apk_inspect_parser = sub.add_parser("apk-inspect"); apk_inspect_parser.add_argument("artifact")
    apk_extract_parser = sub.add_parser("apk-extract-asset"); apk_extract_parser.add_argument("artifact"); apk_extract_parser.add_argument("asset")
    browse = sub.add_parser("browse"); browse.add_argument("url")
    surface = sub.add_parser("surface"); surface.add_argument("item"); surface.add_argument("--kind", default="endpoint")
    surface.add_argument("--detail", default=""); surface.add_argument("--interesting", default="")
    tested = sub.add_parser("tested"); tested.add_argument("surface"); tested.add_argument("technique")
    tested.add_argument("--result", default="blocked"); tested.add_argument("--evidence", default="")
    finding = sub.add_parser("finding"); finding.add_argument("title"); finding.add_argument("severity")
    finding.add_argument("--class", dest="vuln_class", default=""); finding.add_argument("--surface", default="")
    finding.add_argument("--description", default=""); finding.add_argument("--poc", default=""); finding.add_argument("--evidence", default="")
    revision = sub.add_parser("finding-revise"); revision.add_argument("finding_id")
    revision.add_argument("--reason", required=True)
    revision.add_argument("--title"); revision.add_argument("--class", dest="vuln_class")
    revision.add_argument("--surface"); revision.add_argument("--description")
    revision.add_argument("--poc"); revision.add_argument("--evidence")
    read = sub.add_parser("read"); read.add_argument("name", choices=["findings", "surface", "tested", "progress", "scope"])
    analyze = sub.add_parser("local-analyze"); analyze.add_argument("path")
    analyze.add_argument("--analyzer", choices=["file", "strings", "sha256", "literal", "regex"], default="file")
    analyze.add_argument("--min-length", type=int, default=6)
    analyze.add_argument("--pattern", default="")
    analyze.add_argument("--ignore-case", action="store_true")
    analyze.add_argument("--context-bytes", type=int, default=160)
    analyze.add_argument("--max-matches", type=int, default=20)
    install = sub.add_parser("install"); install.add_argument("spec")
    install.add_argument("--manager", choices=["auto", "apt"], default="auto")

    ns = parser.parse_args(argv)
    os.environ["GRYPTON_TARGET"] = ns.target
    mapping = {"http": ("http_request", {"url": ns.url, "method": ns.method, "headers": ns.headers,
                "body": ns.body, "follow_redirects": ns.follow, "insecure": ns.insecure})} if ns.command == "http" else {}
    if ns.command == "goja-request": mapping = {ns.command: ("goja_request", {"url": ns.url, "method": ns.method, "headers": ns.headers, "body": ns.body})}
    elif ns.command in {"goja-start", "goja-status", "goja-stop"}: mapping = {ns.command: (ns.command.replace("-", "_"), {})}
    elif ns.command == "inventory": mapping = {ns.command: ("tool_inventory", {})}
    elif ns.command == "flows": mapping = {ns.command: ("proxy_flows", {"query": ns.query, "limit": ns.limit})}
    elif ns.command == "flow-read": mapping = {ns.command: ("flow_read", {
        "flow_id": ns.flow_id, "offset": ns.offset, "max_chars": ns.max_chars,
    })}
    elif ns.command == "flow-replay": mapping = {ns.command: ("flow_replay", {"flow_id": ns.flow_id, "url": ns.url, "method": ns.method, "headers": ns.headers, "body": ns.body})}
    elif ns.command == "httpx": mapping = {ns.command: ("httpx_probe", {"targets": ns.targets})}
    elif ns.command == "dns": mapping = {ns.command: ("dns_lookup", {"host": ns.host})}
    elif ns.command == "tls": mapping = {ns.command: ("tls_certificate", {"host": ns.host, "port": ns.port})}
    elif ns.command == "ports": mapping = {ns.command: ("port_scan", {"host": ns.host, "ports": [int(x) for x in ns.ports.split(",")]})}
    elif ns.command == "tcp": mapping = {ns.command: ("tcp_exchange", {"host": ns.host, "port": ns.port, "payload": ns.payload})}
    elif ns.command == "artifact-download": mapping = {ns.command: ("artifact_download", {"url": ns.url, "filename": ns.filename})}
    elif ns.command == "apk-inspect": mapping = {ns.command: ("apk_inspect", {"artifact": ns.artifact})}
    elif ns.command == "apk-extract-asset": mapping = {ns.command: ("apk_extract_asset", {"artifact": ns.artifact, "asset": ns.asset})}
    elif ns.command == "browse": mapping = {ns.command: ("browse", {"url": ns.url})}
    elif ns.command == "surface": mapping = {ns.command: ("attack_surface_add", {"item": ns.item, "kind": ns.kind, "detail": ns.detail, "interesting": ns.interesting})}
    elif ns.command == "tested": mapping = {ns.command: ("tested_technique_log", {"surface": ns.surface, "technique": ns.technique, "result": ns.result, "evidence": ns.evidence})}
    elif ns.command == "finding": mapping = {ns.command: ("record_finding", {"title": ns.title, "severity": ns.severity, "vuln_class": ns.vuln_class, "surface": ns.surface, "description": ns.description, "poc": ns.poc, "evidence": ns.evidence})}
    elif ns.command == "finding-revise":
        revision_args = {"finding_id": ns.finding_id, "reason": ns.reason}
        for field_name in FINDING_NARRATIVE_FIELDS:
            value = getattr(ns, field_name)
            if value is not None:
                revision_args[field_name] = value
        mapping = {ns.command: ("revise_finding", revision_args)}
    elif ns.command == "read": mapping = {ns.command: ("read_doc", {"name": ns.name})}
    elif ns.command == "local-analyze": mapping = {ns.command: ("local_analyze", {
        "path": ns.path, "analyzer": ns.analyzer, "min_length": ns.min_length,
        "pattern": ns.pattern, "ignore_case": ns.ignore_case,
        "context_bytes": ns.context_bytes, "max_matches": ns.max_matches,
    })}
    elif ns.command == "install": mapping = {ns.command: ("install_tool", {"spec": ns.spec, "manager": ns.manager})}
    tool_name, args = mapping[ns.command]
    result = dispatch(Workspace(ns.target), tool_name, args)
    print(json.dumps(result, ensure_ascii=False, indent=2) if ns.json else result.get("summary", ""))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(mcp_main())
