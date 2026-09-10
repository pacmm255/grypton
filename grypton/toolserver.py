"""Grypton MCP stdio server and matching command-line tool surface."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Callable

from . import config, tools
from .providers import append_jsonl
from .workspace import Workspace

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "grypton", "version": "3.0.1"}


def _workspace() -> Workspace:
    return Workspace(os.environ.get("GRYPTON_TARGET") or
                     os.environ.get("KRYPTON_TARGET") or "default")


def _string(description: str) -> dict:
    return {"type": "string", "description": description}


def _object(properties: dict, required=()) -> dict:
    return {"type": "object", "additionalProperties": False,
            "properties": properties, "required": list(required)}


def _record_finding(ws, args):
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
    path = ws.root / mapping.get(args.get("name", "findings"), "findings.md")
    value = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    return {"ok": True, "summary": f"Read {path.name} ({len(value)} characters).",
            "data": {"text": value[:200_000]}}


REGISTRY: dict[str, tuple[str, dict, Callable]] = {
    "record_finding": ("Record an evidence-backed finding for independent Astra validation.",
        _object({"title": _string("Short title"),
                 "severity": {"type": "string", "enum": ["P1", "P2", "P3", "P4", "P5"]},
                 "vuln_class": _string("Vulnerability class"), "surface": _string("Affected surface"),
                 "description": _string("Impact and behavior"), "poc": _string("Reproduction steps"),
                 "evidence": _string("Capture path or concrete evidence")}, ("title", "severity")),
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
    "goja_start": ("Start Grypton's managed Goja SOCKS5 TLS-fingerprint proxy.", _object({}),
        lambda ws, args: tools.Goja.start()),
    "goja_status": ("Read managed Goja status.", _object({}), lambda ws, args: tools.Goja.status()),
    "goja_stop": ("Stop only the Goja process started by Grypton.", _object({}),
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
    "subdomain_enum": ("Run passive subfinder enumeration for an in-scope domain.",
        _object({"domain": _string("In-scope base domain"), "timeout": {"type": "integer"}}, ("domain",)),
        lambda ws, a: tools.subdomain_enum(ws, a["domain"], timeout=a.get("timeout", 180))),
    "install_tool": ("Install a local dependency needed to clear an operational blocker.",
        _object({"spec": _string("Single package specification"),
                 "manager": {"type": "string", "enum": ["auto", "apt", "pip", "npm", "cargo", "go"]}},
                ("spec",)), lambda ws, a: tools.install_tool(a["spec"], manager=a.get("manager", "auto"))),
    "research": ("Fetch public documentation or research material without treating it as target evidence.",
        _object({"url": _string("HTTP(S) URL"), "timeout": {"type": "integer"}}, ("url",)),
        lambda ws, a: tools.research(a["url"], timeout=a.get("timeout", 30))),
    "save_research": ("Save a research note in the engagement workspace.",
        _object({"topic": _string("Topic"), "content": _string("Markdown")}, ("topic", "content")),
        _save_research),
    "read_doc": ("Read findings, surface, tested, progress, or scope.",
        _object({"name": {"type": "string", "enum": ["findings", "surface", "tested", "progress", "scope"]}}),
        _read_doc),
    "tool_inventory": ("List available native binaries and Goja state.", _object({}),
        lambda ws, args: tools.inventory()),
}


def _redacted(value):
    if isinstance(value, dict):
        return {key: ("[REDACTED]" if key.lower() in {"authorization", "cookie", "proxy-authorization"}
                      else _redacted(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [_redacted(item) for item in value]
    return value


def dispatch(workspace: Workspace, name: str, args: dict) -> dict:
    started = time.time()
    if name not in REGISTRY:
        result = {"ok": False, "summary": f"Unknown tool {name!r}."}
    elif not workspace.exists():
        result = {"ok": False, "summary": "The engagement workspace is not initialized."}
    else:
        try:
            result = REGISTRY[name][2](workspace, args or {})
        except Exception as exc:
            result = {"ok": False, "summary": f"{name} failed: {exc}"}
    try:
        append_jsonl(workspace.root / ".ledger" / "tool-calls.jsonl", {
            "at": time.time(), "tool": name, "args": _redacted(args or {}),
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
    browse = sub.add_parser("browse"); browse.add_argument("url")
    surface = sub.add_parser("surface"); surface.add_argument("item"); surface.add_argument("--kind", default="endpoint")
    surface.add_argument("--detail", default=""); surface.add_argument("--interesting", default="")
    tested = sub.add_parser("tested"); tested.add_argument("surface"); tested.add_argument("technique")
    tested.add_argument("--result", default="blocked"); tested.add_argument("--evidence", default="")
    finding = sub.add_parser("finding"); finding.add_argument("title"); finding.add_argument("severity")
    finding.add_argument("--class", dest="vuln_class", default=""); finding.add_argument("--surface", default="")
    finding.add_argument("--description", default=""); finding.add_argument("--poc", default=""); finding.add_argument("--evidence", default="")
    read = sub.add_parser("read"); read.add_argument("name", choices=["findings", "surface", "tested", "progress", "scope"])
    install = sub.add_parser("install"); install.add_argument("spec"); install.add_argument("--manager", default="auto")

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
    elif ns.command == "browse": mapping = {ns.command: ("browse", {"url": ns.url})}
    elif ns.command == "surface": mapping = {ns.command: ("attack_surface_add", {"item": ns.item, "kind": ns.kind, "detail": ns.detail, "interesting": ns.interesting})}
    elif ns.command == "tested": mapping = {ns.command: ("tested_technique_log", {"surface": ns.surface, "technique": ns.technique, "result": ns.result, "evidence": ns.evidence})}
    elif ns.command == "finding": mapping = {ns.command: ("record_finding", {"title": ns.title, "severity": ns.severity, "vuln_class": ns.vuln_class, "surface": ns.surface, "description": ns.description, "poc": ns.poc, "evidence": ns.evidence})}
    elif ns.command == "read": mapping = {ns.command: ("read_doc", {"name": ns.name})}
    elif ns.command == "install": mapping = {ns.command: ("install_tool", {"spec": ns.spec, "manager": ns.manager})}
    tool_name, args = mapping[ns.command]
    result = dispatch(Workspace(ns.target), tool_name, args)
    print(json.dumps(result, ensure_ascii=False, indent=2) if ns.json else result.get("summary", ""))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(mcp_main())
