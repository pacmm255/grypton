"""Terminal and HTTP views share the same public state projection."""
import json
import shutil
import sys
import textwrap

from . import __version__
from .backends import clean
from .config import MODELS


def latest(case: dict) -> dict:
    return case["runs"][-1] if case.get("runs") else {}


def case_summary(case: dict) -> dict:
    run = latest(case)
    stale = bool(run) and case["status"] == "draft"
    validation = {} if stale else run.get("stages", {}).get("validation", {})
    return {key: case[key] for key in ("id", "title", "status", "updated_at")} | {
        "target": case.get("target", ""),
        "claim": case.get("claim", ""),
        "evidence_count": len(case["evidence"]), "run_count": len(case["runs"]),
        "mode": run.get("mode", "none"), "verdict": validation.get("verdict", "outdated" if stale else "unreviewed"),
        "severity": validation.get("severity", "unknown"), "stage_count": len(run.get("stages", {})),
        "validation_complete": bool(validation), "review_complete": not stale and run.get("status") == "complete",
        "finding_count": len(case.get("findings", [])),
        "validated_finding_count": sum(item.get("status") in {"supported", "refuted", "inconclusive"}
                                       for item in case.get("findings", [])),
        "observation_count": len(case.get("observations", [])),
        "surface_count": len(case.get("surface", [])),
        "message_count": len(case.get("messages", [])),
        "standing_instruction_count": len(case.get("standing_instructions", [])),
    }


def state(store) -> dict:
    cases = [case_summary(case) for case in store.list()]
    return {"project": "Grypton", "version": __version__, "models": {role: model.public() for role, model in MODELS.items()},
            "cases": cases, "counts": {"total": len(cases), "running": sum(c["status"] == "running" for c in cases),
                "findings": sum(c["finding_count"] for c in cases),
                "validated": sum(c["validated_finding_count"] for c in cases),
                "supported": sum(c["mode"] == "live" and c["review_complete"] and c["verdict"] == "supported" for c in cases),
                "inconclusive": sum(c["verdict"] == "inconclusive" for c in cases)}}


def case_detail(case: dict) -> dict:
    # This allowlist keeps evidence and conversation text out of the HTTP projection,
    # including if future internal fields are added to the case record.
    public = {key: case.get(key) for key in
              ("id", "title", "target", "claim", "brief", "status", "created_at",
               "updated_at", "schema_version", "scope")}
    findings = [{key: item.get(key) for key in
                 ("id", "title", "claim", "evidence_ids", "source", "status", "severity",
                  "created_at", "updated_at", "validation", "summary", "validation_history")}
                for item in case.get("findings", [])]
    return {**public, "review_stale": bool(latest(case)) and case["status"] == "draft",
            "message_count": len(case.get("messages", [])),
            "standing_instruction_count": len(case.get("standing_instructions", [])),
            "observation_count": len(case.get("observations", [])),
            "surface": case.get("surface", []),
            "findings": findings,
            "resource_events": case.get("resource_events", [])[-50:],
            "activity": [{"role": item.get("role"), "at": item.get("at"),
                          "disposition": item.get("disposition", "")}
                         for item in case.get("messages", [])[-50:]],
            "runs": case.get("runs", []),
            "evidence": [{key: value for key, value in item.items() if key != "text"}
                                 for item in case["evidence"]]}


def line(text: str = "", *, stream=None) -> None:
    stream = stream or sys.stdout
    width = max(20, min(shutil.get_terminal_size((100, 30)).columns, 110))
    for paragraph in clean(str(text)).splitlines() or [""]:
        print(textwrap.fill(paragraph, width=width, replace_whitespace=False) if paragraph else "", file=stream)


def print_state(value: dict) -> None:
    line("╔══ Grypton ══╗  engagements")
    line()
    for role, model in value["models"].items():
        line(f"{model['name']} ({role}): {model['qualified']} · {model['effort']}")
    line()
    if not value["cases"]:
        line('No engagements yet. Start with: grypton init "target or project"')
        line("For an offline walkthrough: grypton demo")
        return
    for case in value["cases"]:
        marker = " [MOCK]" if case["mode"] == "mock" else ""
        line(f"{case.get('target') or case['title']}{marker}")
        line(f"  {case['id']}  |  {case['status']}  |  {case['verdict']}  | "
             f"{case['evidence_count']} artifact(s) | {case['finding_count']} finding(s)")
    line()
    line("Open the local dashboard: grypton serve")


def markdown_report(case: dict) -> str:
    run = latest(case)
    stages = run.get("stages", {})
    validation = stages.get("validation", {})
    title = clean(case["title"]).replace("\n", " ")
    lines = [f"# {title}", "", f"Engagement: {case['id']}",
             f"Target/project: {clean(case.get('target') or case['title'])}", f"Review status: {case['status']}",
             f"Mode: {run.get('mode', 'not run')}", "", "## Claim", "", clean(case["claim"]), "",
             "## Evidence", ""]
    if run and case["status"] == "draft":
        lines[6:6] = ["", "Evidence changed after this review. The previous result below is historical; start a new review.", ""]
    lines.extend(f"- {e['id']}: {clean(e['name'])} (SHA-256: {e['sha256']})" for e in case["evidence"])
    scope = case.get("scope", {})
    lines.extend(["", "## Scope", "", f"Type: {clean(scope.get('type', 'auto'))}"])
    for key in ("in_scope", "out_of_scope", "only_severities", "include_classes", "exclude_classes", "rules"):
        values = scope.get(key, [])
        if values:
            lines.append(f"- {key.replace('_', ' ').title()}: " + "; ".join(clean(item) for item in values))
    if validation:
        lines.extend(["", "## Independent validation", "", f"Verdict: {validation['verdict']}",
                      f"Severity: {validation['severity']}", "", clean(validation["rationale"]), "",
                      "Evidence validation does not establish live reproduction.", "", "### Limitations", ""])
        lines.extend("- " + clean(value) for value in validation["limitations"])
        lines.extend(["", "### Remediation", ""])
        lines.extend("- " + clean(value) for value in validation["remediation"])
    if "summary" in stages:
        lines.extend(["", "## Kryptex summary", "", clean(stages["summary"]["summary"]), ""])
        lines.extend("- " + clean(value) for value in stages["summary"]["next_steps"])
    if case.get("findings"):
        lines.extend(["", "## Finding ledger", ""])
        for finding in case["findings"]:
            lines.append(f"- {finding['id']}: {clean(finding['title'])} — {finding['status']} / {finding.get('severity', 'unknown')}")
    if run.get("calls"):
        lines.extend(["", "## Model call audit", ""])
        for call in run["calls"]:
            lines.append(f"- {call['stage']}: {call['route']['qualified']} / {call['route']['effort']} — "
                         f"{call['status']} in {call['duration_ms']} ms; input {call['input_sha256'][:16]}…")
    if run.get("error"):
        lines.extend(["", "## Review error", "", clean(run["error"])])
    return "\n".join(lines) + "\n"


def json_output(value: dict | list) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False))
