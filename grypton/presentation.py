"""Terminal and HTTP views share the same public state projection."""
import json
import shutil
import sys
import textwrap

from .backends import clean
from .config import MODELS


def latest(case: dict) -> dict:
    return case["runs"][-1] if case.get("runs") else {}


def case_summary(case: dict) -> dict:
    run = latest(case)
    stale = bool(run) and case["status"] == "draft"
    validation = {} if stale else run.get("stages", {}).get("validation", {})
    return {key: case[key] for key in ("id", "title", "status", "updated_at")} | {
        "evidence_count": len(case["evidence"]), "run_count": len(case["runs"]),
        "mode": run.get("mode", "none"), "verdict": validation.get("verdict", "outdated" if stale else "unreviewed"),
        "severity": validation.get("severity", "unknown"), "stage_count": len(run.get("stages", {})),
        "validation_complete": bool(validation), "review_complete": not stale and run.get("status") == "complete",
    }


def state(store) -> dict:
    cases = [case_summary(case) for case in store.list()]
    return {"project": "Grypton", "version": "2.0.0", "models": {role: model.public() for role, model in MODELS.items()},
            "cases": cases, "counts": {"total": len(cases), "running": sum(c["status"] == "running" for c in cases),
                "supported": sum(c["mode"] == "live" and c["review_complete"] and c["verdict"] == "supported" for c in cases),
                "inconclusive": sum(c["verdict"] == "inconclusive" for c in cases)}}


def case_detail(case: dict) -> dict:
    # Evidence content is displayed only by explicit CLI show --evidence, never broadcast by the dashboard.
    return {**case, "review_stale": bool(latest(case)) and case["status"] == "draft",
            "evidence": [{key: value for key, value in item.items() if key != "text"}
                                 for item in case["evidence"]]}


def line(text: str = "", *, stream=None) -> None:
    stream = stream or sys.stdout
    width = max(20, min(shutil.get_terminal_size((100, 30)).columns, 110))
    for paragraph in clean(str(text)).splitlines() or [""]:
        print(textwrap.fill(paragraph, width=width, replace_whitespace=False) if paragraph else "", file=stream)


def print_state(value: dict) -> None:
    line("GRYPTON  /  Evidence review")
    line()
    for role, model in value["models"].items():
        line(f"{model['name']} ({role}): {model['qualified']} · {model['effort']}")
    line()
    if not value["cases"]:
        line('No cases yet. Start with: grypton init "Case title" --claim "The specific claim"')
        line("For an offline walkthrough: grypton demo")
        return
    for case in value["cases"]:
        marker = " [MOCK]" if case["mode"] == "mock" else ""
        line(f"{case['title']}{marker}")
        line(f"  {case['id']}  |  {case['status']}  |  {case['verdict']}  |  {case['evidence_count']} artifact(s)")
    line()
    line("Open the local dashboard: grypton serve")


def markdown_report(case: dict) -> str:
    run = latest(case)
    stages = run.get("stages", {})
    validation = stages.get("validation", {})
    title = clean(case["title"]).replace("\n", " ")
    lines = [f"# {title}", "", f"Case: {case['id']}", f"Review status: {case['status']}",
             f"Mode: {run.get('mode', 'not run')}", "", "## Claim", "", clean(case["claim"]), "",
             "## Evidence", ""]
    if run and case["status"] == "draft":
        lines[4:4] = ["", "Evidence changed after this review. The previous result below is historical; start a new review.", ""]
    lines.extend(f"- {e['id']}: {clean(e['name'])} (SHA-256: {e['sha256']})" for e in case["evidence"])
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
    if run.get("error"):
        lines.extend(["", "## Review error", "", clean(run["error"])])
    return "\n".join(lines) + "\n"


def json_output(value: dict | list) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False))
