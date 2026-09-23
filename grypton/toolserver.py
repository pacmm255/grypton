"""Grypton MCP stdio server and matching command-line tool surface."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import sys
import time
from typing import Callable

from . import config, credentials, tools
from .providers import append_jsonl
from .workspace import Workspace

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


def _credential_login(ws, args):
    return tools.credential_login(
        ws, args["url"], credential=args["credential"], verify_url=args["verify_url"], success_marker=args["success_marker"],
        username_field=args.get("username_field", "username"),
        password_field=args.get("password_field", "password"),
        username_transform=args.get("username_transform", "stored"),
        encoding=args.get("encoding", "json"), fields=args.get("fields"),
        headers=args.get("headers"), timeout=args.get("timeout", 30),
    )


def _authenticated_http(ws, args):
    return tools.authenticated_http_request(
        ws, args["url"], credential=args["credential"],
        method=args.get("method", "GET"), headers=args.get("headers"),
        body=args.get("body"), timeout=args.get("timeout", 30),
    )


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
        "tested": "tested-techniques.md", "progress": "progress.md", "scope": "scope-rules.md",
        "program": "program-brief.md"}
    path = ws.root / mapping.get(args.get("name", "findings"), "findings.md")
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
        "Warm a scoped cookie gate, submit a named private credential to its "
        "login endpoint, and verify the resulting session.",
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
        }, ("url", "credential", "verify_url", "success_marker")), _credential_login),
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
    "flow_read": ("Read a captured request/response flow by ID.",
        _object({"flow_id": _string("flow-... ID"), "max_chars": {"type": "integer"}}, ("flow_id",)),
        lambda ws, a: tools.flow_read(ws, a["flow_id"], max_chars=a.get("max_chars", 100000))),
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
    "local_analyze": ("Inspect or search one regular file inside this engagement with bounded output.",
        _object({"path": _string("Relative engagement file path"),
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
    "read_doc": ("Read findings, surface, tested, progress, scope, or an attached program brief.",
        _object({"name": {"type": "string", "enum": ["findings", "surface", "tested", "progress", "scope", "program"]}}),
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
    if name != "credential_login":
        return ()
    try:
        secret = credentials.load_credential(
            workspace.slug, str(args.get("credential") or "")
        )
    except credentials.CredentialError:
        return ()
    values = [secret["username"], secret["password"]]
    try:
        transformed = credentials.normalize_login_username(
            secret["username"], str(args.get("username_transform") or "stored")
        )
    except credentials.CredentialError:
        pass
    else:
        values.append(transformed)
    return tools._serialized_secret_variants(values)


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
        append_jsonl(workspace.root / ".ledger" / "tool-calls.jsonl", {
            "at": time.time(), "tool": name,
            "args": _redacted(args or {}, audit_secrets),
            "ok": bool(result.get("ok")), "summary": result.get("summary", "")[:1000],
            "duration_s": round(time.time() - started, 3),
        })
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
    read = sub.add_parser("read"); read.add_argument("name", choices=["findings", "surface", "tested", "progress", "scope", "program"])
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
    elif ns.command == "flow-read": mapping = {ns.command: ("flow_read", {"flow_id": ns.flow_id})}
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
