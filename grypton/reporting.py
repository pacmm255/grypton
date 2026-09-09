"""Read-only engagement auditing and report rendering."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from . import config
from .tools import check_host_scope, check_url_scope


FLOW_RE = re.compile(r"flow-\d+\.http")
NETWORK_TOOLS = {
    "http_request", "httpx_probe", "browse", "dns_lookup", "tls_certificate",
    "port_scan", "subdomain_enum", "goja_request", "flow_replay",
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
    findings = ws.findings.all()
    surface = ws.surface.all()
    tested = ws.tested.all()
    calls = read_jsonl(ws.transcripts_dir / "provider-calls.jsonl")
    tools = read_jsonl(ws.root / ".ledger" / "tool-calls.jsonl")

    expected = {
        "worker": (config.WORKER_MODEL, config.WORKER_EFFORT),
        "manager": (config.MANAGER_MODEL, config.MANAGER_EFFORT),
        "validator": (config.VALIDATOR_MODEL, config.VALIDATOR_EFFORT),
    }
    route_errors = []
    provider_counts = Counter()
    for call in calls:
        role = str(call.get("role") or "unknown")
        provider_counts[role] += 1
        if role not in expected:
            route_errors.append(f"unknown provider role {role}")
            continue
        route, effort = expected[role]
        if (call.get("route"), call.get("effort")) != (route, effort):
            route_errors.append(
                f"{role}: {call.get('route')} · {call.get('effort')}"
            )

    provider_failures = [
        {"role": row.get("role"), "returncode": row.get("returncode"),
         "stderr": bool(row.get("stderr_present"))}
        for row in calls
        if row.get("returncode") != 0 or row.get("stderr_present")
    ]

    unvalidated = []
    for finding in findings:
        verdict = finding.get("manager_verdict") or {}
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
            allowed, reason = check_url_scope(ws, url)
            if not allowed:
                scope_violations.append({"tool": row.get("tool"), "value": url,
                                         "reason": reason})
        for key in ("host", "domain"):
            value = args.get(key)
            if isinstance(value, str) and value and "://" not in value:
                host = urlsplit("//" + value).hostname or value
                allowed, reason = check_host_scope(ws, host)
                if not allowed:
                    scope_violations.append({"tool": row.get("tool"), "value": value,
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

    target_dir = config.GRYPTON_HOME / "target"
    target_dir_empty = target_dir.is_dir() and not any(target_dir.iterdir())
    result = {
        "target": ws.load_meta().target,
        "slug": ws.slug,
        "status": ws.load_meta().status,
        "turns": ws.load_meta().turn_index,
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
        f"- Kraude: `{config.WORKER_MODEL}` · `{config.WORKER_EFFORT}`",
        f"- Kryptex: `{config.MANAGER_MODEL}` · `{config.MANAGER_EFFORT}`",
        f"- Validator: `{config.VALIDATOR_MODEL}` · `{config.VALIDATOR_EFFORT}`", "",
        "## Activity", "",
        f"- {audit['counts']['tool_calls']} structured tool events, "
        f"{audit['counts']['network_tool_calls']} network tool calls",
        f"- {audit['counts']['flows']} complete request/response flows",
        f"- {audit['counts']['surface']} surface records and "
        f"{audit['counts']['tested']} tested techniques", "",
        "## Findings", "",
        "| ID | Status | Severity | Astra verdict | Title |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in findings:
        verdict = finding.get("manager_verdict") or {}
        values = [
            finding.get("id", "?"), finding.get("status", "reported"),
            final_severity(finding), verdict.get("verdict", "pending"),
            finding.get("title", ""),
        ]
        lines.append("| " + " | ".join(str(v).replace("|", "\\|") for v in values) + " |")
    lines.extend(["", "## Integrity", "",
        f"- Exact provider routes: {'yes' if audit['exact_routes'] else 'no'}",
        f"- Independently validated findings: "
        f"{len(findings) - len(audit['unvalidated_findings'])}/{len(findings)}",
        f"- Missing canonical flow references: {len(audit['missing_canonical_flows'])}",
        f"- Structured scope violations: {len(audit['scope_violations'])}",
        f"- Top-level `target/` empty: {'yes' if audit['target_dir_empty'] else 'no'}",
        "",
    ])
    return "\n".join(lines)
