"""Read-only engagement auditing and report rendering."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from . import config
from .tools import (check_host_scope, check_port_scope, check_raw_tcp_scope,
                    check_research_scope, check_url_scope)


FLOW_RE = re.compile(r"flow-\d+\.http")
NETWORK_TOOLS = {
    "http_request", "httpx_probe", "browse", "dns_lookup", "tls_certificate",
    "port_scan", "subdomain_enum", "goja_request", "flow_replay", "artifact_download",
    "tcp_exchange", "research", "credential_login", "credential_browser_login",
    "authenticated_http_request", "authenticated_browser_request",
}


def read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return rows
    for line in lines:
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _urls(value) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for child in value.values():
            found.extend(_urls(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_urls(child))
    elif isinstance(value, str):
        found.extend(re.findall(r"https?://[^\s\"'<>]+", value))
    return [item.rstrip("),.;") for item in found]


def final_severity(finding: dict) -> str:
    verdict = finding.get("manager_verdict") or {}
    return str(verdict.get("severity") or finding.get("severity") or "?").upper()


def audit_workspace(ws) -> dict:
    meta = ws.load_meta()
    models = config.effective_role_models(meta)
    findings = ws.findings.all()
    surface = ws.surface.all()
    tested = ws.tested.all()
    calls = read_jsonl(ws.transcripts_dir / "provider-calls.jsonl")
    tools = read_jsonl(ws.root / ".ledger" / "tool-calls.jsonl")

    expected = {
        "worker": (models["worker"]["route"], models["worker"]["effort"]),
        "manager": (models["manager"]["route"], models["manager"]["effort"]),
        "validator": (models["validator"]["route"], models["validator"]["effort"]),
    }
    route_errors = []
    provider_counts = Counter()
    role_aliases = {"kraude": "worker", "kryptex": "manager"}
    selections = []
    for row in read_jsonl(ws.root / ".ledger" / "model-switches.jsonl"):
        role = role_aliases.get(str(row.get("role") or "").lower(),
                                str(row.get("role") or "").lower())
        if role not in {"worker", "manager"}:
            continue
        try:
            selected_at = float(row.get("at") or 0)
        except (TypeError, ValueError):
            selected_at = 0.0
        selections.append({
            "role": role,
            "at": selected_at,
            "route": config.normalize_model_route(str(row.get("route") or "")),
            "effort": str(row.get("effort") or ""),
        })

    def expected_for_call(role: str, call: dict) -> tuple[str, str]:
        if role == "validator":
            return expected[role]
        try:
            called_at = float(call.get("at") or 0)
        except (TypeError, ValueError):
            called_at = 0.0
        prior = [
            row for row in selections
            if row["role"] == role and row["at"] <= called_at
        ]
        if prior:
            selected = max(prior, key=lambda row: row["at"])
            return selected["route"], selected["effort"]
        return expected[role]

    for call in calls:
        role = str(call.get("role") or "unknown")
        provider_counts[role] += 1
        if role not in expected:
            route_errors.append(f"unknown provider role {role}")
            continue
        route, effort = expected_for_call(role, call)
        observed_route = str(call.get("route") or "")
        if role != "validator":
            observed_route = config.normalize_model_route(observed_route)
        if (observed_route, call.get("effort")) != (route, effort):
            route_errors.append(
                f"{role}: {call.get('route')} · {call.get('effort')}"
            )

    def provider_failed(row: dict) -> bool:
        if "ok" in row:
            return row.get("ok") is not True
        return row.get("returncode") != 0 or bool(row.get("stderr_present"))

    provider_failures = [
        {"role": row.get("role"), "returncode": row.get("returncode"),
         "stderr": bool(row.get("stderr_present"))}
        for row in calls
        if provider_failed(row)
    ]

    unvalidated = []
    validation_not_requested = []
    for finding in findings:
        verdict = finding.get("manager_verdict") or {}
        explicitly_reviewed = (
            isinstance(finding.get("manager_verdict"), dict) and bool(verdict)
        )
        if finding.get("status") == "suppressed-by-scope" and not explicitly_reviewed:
            continue
        automatic = (
            finding.get("status") != "suppressed-by-scope"
            and config.astra_auto_validation_required(finding.get("severity", ""))
        )
        if not automatic and not explicitly_reviewed:
            validation_not_requested.append(finding.get("id"))
            continue
        if (verdict.get("validator_model"), verdict.get("validator_effort")) != (
            config.VALIDATOR_MODEL, config.VALIDATOR_EFFORT
        ):
            unvalidated.append(finding.get("id"))

    canonical = findings + tested + surface
    references = sorted(set(FLOW_RE.findall(json.dumps(canonical, ensure_ascii=False))))
    missing_flows = [name for name in references if not (ws.flows_dir / name).is_file()]

    scope_violations = []
    network_calls = 0
    for row in tools:
        if row.get("tool") not in NETWORK_TOOLS:
            continue
        network_calls += 1
        args = row.get("args") if isinstance(row.get("args"), dict) else {}
        for url in _urls(args):
            if row.get("tool") == "research":
                allowed, reason = check_research_scope(ws, url)
            else:
                allowed, reason = check_url_scope(ws, url)
            if not allowed:
                scope_violations.append({"tool": row.get("tool"), "value": url,
                                         "reason": reason})
        tool_name = row.get("tool")
        host_value = args.get("host")
        host = (
            urlsplit("//" + host_value).hostname or host_value
            if isinstance(host_value, str) and host_value and "://" not in host_value
            else ""
        )
        if host and tool_name == "port_scan":
            ports = args.get("ports") if isinstance(args.get("ports"), list) else []
            for port in ports:
                try:
                    allowed, reason = check_port_scope(ws, host, int(port))
                except (TypeError, ValueError):
                    allowed, reason = False, "port is invalid"
                if not allowed:
                    scope_violations.append({
                        "tool": tool_name, "value": f"{host}:{port}", "reason": reason,
                    })
        elif host and tool_name in {"tls_certificate", "tcp_exchange"}:
            try:
                port = int(args.get("port", 443))
                checker = check_raw_tcp_scope if tool_name == "tcp_exchange" else check_port_scope
                allowed, reason = checker(ws, host, port)
            except (TypeError, ValueError):
                allowed, reason = False, "port is invalid"
            if not allowed:
                scope_violations.append({
                    "tool": tool_name, "value": f"{host}:{args.get('port', 443)}",
                    "reason": reason,
                })
        for key in ("host", "domain"):
            value = args.get(key)
            if isinstance(value, str) and value and "://" not in value:
                host = urlsplit("//" + value).hostname or value
                if key == "host" and tool_name in {
                    "port_scan", "tls_certificate", "tcp_exchange",
                }:
                    continue
                allowed, reason = check_host_scope(ws, host)
                if not allowed:
                    scope_violations.append({"tool": tool_name, "value": value,
                                             "reason": reason})

    event_failures = []
    for event in read_jsonl(ws.transcripts_dir / "worker.opencode.events.jsonl"):
        part = event.get("part") if isinstance(event.get("part"), dict) else {}
        state = part.get("state") if isinstance(part.get("state"), dict) else {}
        if event.get("type") == "tool_use" and state.get("status") in {"error", "failed"}:
            event_failures.append({
                "tool": part.get("tool"),
                "error": str(state.get("error") or state.get("message") or "unknown"),
            })

    target_dir = config.TARGET_DATA_DIR
    target_dir_empty = target_dir.is_dir() and not any(target_dir.iterdir())
    result = {
        "target": meta.target,
        "slug": ws.slug,
        "status": meta.status,
        "turns": meta.turn_index,
        "models": models,
        "counts": {
            "findings": len(findings),
            "confirmed_findings": len(ws.confirmed_findings()),
            "surface": len(surface),
            "tested": len(tested),
            "flows": len(list(ws.flows_dir.glob("flow-*.http"))),
            "tool_calls": len(tools),
            "network_tool_calls": network_calls,
            "provider_calls": dict(provider_counts),
            "tool_event_failures": len(event_failures),
        },
        "exact_routes": not route_errors,
        "route_errors": route_errors,
        "provider_failures": provider_failures,
        "unvalidated_findings": unvalidated,
        "validation_not_requested": validation_not_requested,
        "canonical_flow_references": len(references),
        "missing_canonical_flows": missing_flows,
        "scope_violations": scope_violations,
        "target_dir_empty": target_dir_empty,
        "tool_event_failures": event_failures,
    }
    result["ok"] = not any((
        route_errors, provider_failures, unvalidated, missing_flows, scope_violations,
    )) and target_dir_empty
    return result


def render_report(ws) -> str:
    audit = audit_workspace(ws)
    findings = ws.findings.all()
    lines = [
        f"# Grypton report — {ws.slug}", "",
        f"- **Target:** `{audit['target']}`",
        f"- **Status:** {audit['status']}",
        f"- **Turns:** {audit['turns']}",
        f"- **Audit:** {'PASS' if audit['ok'] else 'ATTENTION REQUIRED'}", "",
        "## Model routes", "",
        f"- Kraude: `{audit['models']['worker']['route']}` · `{audit['models']['worker']['effort']}`",
        f"- Kryptex: `{audit['models']['manager']['route']}` · `{audit['models']['manager']['effort']}`",
        f"- Validator: `{audit['models']['validator']['route']}` · `{audit['models']['validator']['effort']}`", "",
        "## Activity", "",
        f"- {audit['counts']['tool_calls']} structured tool events, "
        f"{audit['counts']['network_tool_calls']} network tool calls",
        f"- {audit['counts']['flows']} bounded request/response flows",
        f"- {audit['counts']['surface']} surface records and "
        f"{audit['counts']['tested']} tested techniques", "",
        "## Findings", "",
        "| ID | Status | Severity | Astra verdict | Title |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in findings:
        verdict = finding.get("manager_verdict") or {}
        astra_state = verdict.get("verdict") or (
            "pending"
            if config.astra_auto_validation_required(finding.get("severity", ""))
            and finding.get("status") != "suppressed-by-scope"
            else "not requested"
        )
        values = [
            finding.get("id", "?"), finding.get("status", "reported"),
            final_severity(finding), astra_state,
            finding.get("title", ""),
        ]
        lines.append("| " + " | ".join(str(v).replace("|", "\\|") for v in values) + " |")
    lines.extend(["", "## Integrity", "",
        f"- Exact provider routes: {'yes' if audit['exact_routes'] else 'no'}",
        f"- Required Astra validation gaps: {len(audit['unvalidated_findings'])}",
        f"- Lower-severity findings not explicitly submitted to Astra: "
        f"{len(audit['validation_not_requested'])}",
        f"- Missing canonical flow references: {len(audit['missing_canonical_flows'])}",
        f"- Structured scope violations: {len(audit['scope_violations'])}",
        f"- Top-level `target/` empty: {'yes' if audit['target_dir_empty'] else 'no'}",
        "",
    ])
    return "\n".join(lines)
