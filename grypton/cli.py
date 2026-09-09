"""A predictable CLI: parseable JSON, actionable errors, and explicit live calls."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from pathlib import Path

from . import __version__
from .backends import LiveBackend, MockBackend, clean
from .config import GryptonError, MODELS, Settings, resource
from .doctor import doctor
from .engine import review, stop, validate_finding
from .presentation import case_detail, case_summary, json_output, line, markdown_report, print_state, state
from .storage import SCOPE_KEYS, Store, atomic_json


def common(parser):
    parser.add_argument("--root", default=argparse.SUPPRESS, help="Grypton workspace (or GRYPTON_ROOT)")
    parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="Emit one JSON result on stdout")


def scope_args(parser):
    parser.add_argument("--type", choices=["auto", "web", "apk", "network", "cidr", "binary", "contract", "code"],
                        default=argparse.SUPPRESS, help="Engagement material type")
    parser.add_argument("--in-scope", default=argparse.SUPPRESS, help="Comma-separated in-scope labels")
    parser.add_argument("--out-scope", default=argparse.SUPPRESS, help="Comma-separated excluded labels")
    parser.add_argument("--only", default=argparse.SUPPRESS, help="Comma-separated severities to retain")
    parser.add_argument("--include", default=argparse.SUPPRESS, help="Comma-separated review classes to emphasize")
    parser.add_argument("--exclude", default=argparse.SUPPRESS, help="Comma-separated review classes to exclude")
    parser.add_argument("--rule", action="append", default=argparse.SUPPRESS, help="Binding scope rule; repeatable")


def scope_values(args) -> dict:
    mapping = {"in_scope": "in_scope", "out_scope": "out_of_scope", "only": "only_severities",
               "include": "include_classes", "exclude": "exclude_classes"}
    value = {}
    if hasattr(args, "type"):
        value["type"] = args.type
    for attribute, key in mapping.items():
        if hasattr(args, attribute):
            value[key] = [item.strip() for item in getattr(args, attribute).split(",") if item.strip()]
    if hasattr(args, "rule"):
        value["rules"] = args.rule
    return value


def safe_lab_path(value: Path) -> Path:
    path = value.expanduser().absolute()
    if ({"target", "targets"} & set(path.parts) or path == Path("/root/krypton")
            or Path("/root/krypton") in path.parents
            or any(parent.is_symlink() for parent in (path, *path.parents))):
        raise GryptonError("Lab files cannot use original-project, target, or symlinked paths.")
    return path


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="grypton", description="Review supplied security evidence with Kraude, Kryptex, and an independent Codex validator.",
        epilog="Live review sends the attached evidence to the configured providers. Use demo or review --mock for offline work.")
    root.add_argument("--version", action="version", version=f"grypton {__version__}")
    common(root)
    commands = root.add_subparsers(dest="command")
    status = commands.add_parser("status", help="List engagements and review outcomes")
    common(status)
    status.add_argument("target", nargs="?", help="Optional engagement ID or target")
    for name, help_text in [("models", "Show the exact model and plan routes"),
                            ("doctor", "Check installed CLIs, model variants, and authentication"),
                            ("scenarios", "List packaged review scenarios")]:
        common(commands.add_parser(name, help=help_text))
    audit = commands.add_parser("audit", help="Verify fork integrity, routes, assets, and source parity")
    common(audit)
    audit.add_argument("--source", type=Path, default=Path("/root/krypton"),
                       help="Original source root to verify (default: /root/krypton)")
    audit.add_argument("--skip-source", action="store_true", help="Skip the recorded original-source hash check")
    audit.add_argument("--auth", action="store_true", help="Verify connector credentials without displaying values")
    init = commands.add_parser("init", help="Initialize an engagement and open its console")
    common(init)
    init.add_argument("target", nargs="?", help="Target or project label")
    init.add_argument("--target", dest="target_option", help="Target or project label (Krypton-compatible form)")
    init.add_argument("-m", "--brief", default="", help="Mission brief or standing instruction")
    init.add_argument("--claim", help="Explicit evidence claim (defaults to a target-relevant assessment)")
    init.add_argument("--mock", action="store_true", help="Use offline model responses in the console")
    init.add_argument("--no-interact", action="store_true", help="Create the engagement without opening a TTY console")
    scope_args(init)
    evidence = commands.add_parser("evidence", help="Attach or list supplied text artifacts")
    common(evidence)
    ev = evidence.add_subparsers(dest="evidence_command", required=True)
    add = ev.add_parser("add", help="Import one regular UTF-8 file")
    common(add)
    add.add_argument("case")
    add.add_argument("file", type=Path)
    ls = ev.add_parser("list", help="List artifact IDs and hashes")
    common(ls)
    ls.add_argument("case")
    run = commands.add_parser("review", help="Run the manager/worker/validator review sequence")
    common(run)
    run.add_argument("case")
    run.add_argument("--mock", action="store_true", help="Use deterministic offline responses")
    run.add_argument("--dry-run", action="store_true", help="Show the plan without invoking models")
    run.add_argument("--resume", action="store_true", help="Reuse completed checkpoints after a failure or stop")
    run.add_argument("--timeout", type=float, default=600, help="Per-call timeout in seconds (default: 600)")
    resume = commands.add_parser("resume", help="Resume an engagement console")
    common(resume)
    resume.add_argument("case")
    resume.add_argument("-m", "--brief", default="", help="New standing instruction for Kryptex")
    resume.add_argument("--mock", action="store_true", help="Use offline model responses in the console")
    resume.add_argument("--review", action="store_true", help="Resume an interrupted review immediately")
    resume.add_argument("--timeout", type=float, default=600, help="Per-call timeout in seconds (default: 600)")
    resume.add_argument("--no-interact", action="store_true", help="Show state without opening a TTY console")
    show = commands.add_parser("show", help="Show a case and its review checkpoints")
    common(show)
    show.add_argument("case")
    show.add_argument("--evidence", action="store_true", help="Include the explicitly attached artifact text")
    report = commands.add_parser("report", help="Write a Markdown report to stdout")
    common(report)
    report.add_argument("case")
    cancel = commands.add_parser("stop", help="Cancel an active review and preserve its checkpoints")
    common(cancel)
    cancel.add_argument("case")
    demo = commands.add_parser("demo", help="Create and review a synthetic case offline")
    common(demo)
    demo.add_argument("--scenario", choices=[s["id"] for s in json.loads(resource("scenarios.json"))], default="configuration-review")
    serve = commands.add_parser("serve", help="Open a read-only dashboard on 127.0.0.1")
    common(serve)
    serve.add_argument("--port", type=int, default=8765)
    scope = commands.add_parser("scope", help="Show or update the stored engagement boundary")
    common(scope)
    scope_sub = scope.add_subparsers(dest="scope_command", required=True)
    scope_show = scope_sub.add_parser("show", help="Show scope and binding rules")
    common(scope_show)
    scope_show.add_argument("case")
    scope_set = scope_sub.add_parser("set", help="Replace selected scope fields")
    common(scope_set)
    scope_set.add_argument("case")
    scope_args(scope_set)
    history = commands.add_parser("history", help="Show explicit terminal conversation history")
    common(history)
    history.add_argument("case")
    history.add_argument("--limit", type=int, default=20)
    note = commands.add_parser("note", help="Append a workspace observation")
    common(note)
    note.add_argument("case")
    note.add_argument("text")
    surface = commands.add_parser("surface", help="Manage supplied attack-surface records")
    common(surface)
    surface_sub = surface.add_subparsers(dest="surface_command", required=True)
    surface_list = surface_sub.add_parser("list", help="List surface records")
    common(surface_list)
    surface_list.add_argument("case")
    surface_add = surface_sub.add_parser("add", help="Append a surface record")
    common(surface_add)
    surface_add.add_argument("case")
    surface_add.add_argument("kind")
    surface_add.add_argument("text")
    findings = commands.add_parser("findings", help="Manage the persistent finding ledger")
    common(findings)
    finding_sub = findings.add_subparsers(dest="finding_command", required=True)
    finding_list = finding_sub.add_parser("list", help="List candidate and validated findings")
    common(finding_list)
    finding_list.add_argument("case")
    finding_add = finding_sub.add_parser("add", help="Add a candidate backed by attached evidence")
    common(finding_add)
    finding_add.add_argument("case")
    finding_add.add_argument("claim")
    finding_add.add_argument("--title", default="")
    finding_add.add_argument("--evidence", action="append", default=None, help="Attached artifact ID; repeatable")
    finding_validate = finding_sub.add_parser("validate", help="Have Kryptex coordinate independent Astra validation")
    common(finding_validate)
    finding_validate.add_argument("case")
    finding_validate.add_argument("finding")
    finding_validate.add_argument("--mock", action="store_true")
    finding_validate.add_argument("--timeout", type=float, default=600)
    lab = commands.add_parser("lab", help="Inspect or score the bundled nine-turn regression lab")
    common(lab)
    lab_sub = lab.add_subparsers(dest="lab_command", required=True)
    for name, help_text in (("list", "List fixed synthetic scenarios and evidence turns"),
                            ("verify", "Validate the suite and print its stable digest")):
        common(lab_sub.add_parser(name, help=help_text))
    lab_run = lab_sub.add_parser("run", help="Run fixed fixtures through the complete model pipeline")
    common(lab_run)
    lab_run.add_argument("--scenario", help="Run one scenario (default: all three)")
    mode = lab_run.add_mutually_exclusive_group()
    mode.add_argument("--mock", dest="live", action="store_false", help="Run without provider calls (default)")
    mode.add_argument("--live", dest="live", action="store_true", help="Call the configured models with synthetic fixtures")
    lab_run.set_defaults(live=False)
    lab_run.add_argument("--save", type=Path, help="Write complete result JSON to a private file")
    lab_score = lab_sub.add_parser("score", help="Score a JSON result map without invoking models")
    common(lab_score)
    lab_score.add_argument("results", type=Path)
    return root


def dispatch(args) -> tuple[object, int]:
    settings = Settings.load(getattr(args, "root", None), getattr(args, "timeout", 600))
    store = Store(settings)
    command = args.command or "status"
    if command == "status":
        value = state(store)
        if getattr(args, "target", None):
            case_id = store.resolve(args.target)
            value["cases"] = [case_summary(store.get(case_id))]
            selected = value["cases"][0]
            value["counts"] = {"total": 1, "running": int(selected["status"] == "running"),
                               "findings": selected["finding_count"],
                               "validated": selected["validated_finding_count"],
                               "supported": int(selected["mode"] == "live" and selected["review_complete"]
                                                and selected["verdict"] == "supported"),
                               "inconclusive": int(selected["verdict"] == "inconclusive")}
        if not getattr(args, "json", False):
            print_state(value)
            return None, 0
        return value, 0
    if command == "models":
        return {role: model.public() for role, model in MODELS.items()}, 0
    if command == "doctor":
        value = asyncio.run(doctor())
        return value, 0 if value["ok"] else 1
    if command == "audit":
        from .integrity import audit_project
        value = audit_project(settings.root, source_root=None if args.skip_source else args.source,
                              check_auth=args.auth)
        return value, 0 if value["ok"] else 1
    if command == "scenarios":
        return [{k: v for k, v in item.items() if k != "evidence"} for item in json.loads(resource("scenarios.json"))], 0
    if command == "init":
        if args.target and args.target_option and args.target != args.target_option:
            raise GryptonError("Provide the target once, either positionally or with --target.")
        target = (args.target or args.target_option or "").strip()
        if not target:
            raise GryptonError("Provide a target: `grypton init TARGET` or `grypton init --target TARGET`.")
        claim = (args.claim or f"Assess the supplied evidence relevant to {target}.").strip()
        try:
            existing = store.resolve(target)
        except GryptonError as exc:
            if not str(exc).startswith("Unknown engagement:"):
                raise
            case = store.create(target, claim, stable=True, target=target, brief=args.brief)
        else:
            case = store.set_target(existing, store.get(existing).get("target") or target)
            if args.claim:
                case = store.set_claim(existing, args.claim)
            if args.brief:
                case = store.set_brief(existing, args.brief)
        values = scope_values(args)
        if not case["scope"]["in_scope"] and "in_scope" not in values:
            values["in_scope"] = [target]
        if values:
            case = store.set_scope(case["id"], values)
        if sys.stdin.isatty() and not args.no_interact and not getattr(args, "json", False):
            from .console import interact
            asyncio.run(interact(store, case["id"], MockBackend() if args.mock else LiveBackend(settings)))
            return None, 0
        return {**case_summary(case), "target": target,
                "next": f"grypton resume {case['id']}"}, 0
    if command == "evidence":
        case_id = store.resolve(args.case)
        case = store.add_evidence(case_id, args.file) if args.evidence_command == "add" else store.get(case_id)
        return case_detail(case)["evidence"], 0
    if command == "show":
        case = store.get(store.resolve(args.case))
        if getattr(args, "json", False):
            detail = case_detail(case)
            if args.evidence:
                detail["evidence"] = case["evidence"]
            return detail, 0
        print(markdown_report(case), end="")
        if args.evidence:
            for evidence in case["evidence"]:
                line(f"\n{evidence['id']} · {evidence['name']}")
                line(evidence["text"])
        return None, 0
    if command == "report":
        report = markdown_report(store.get(store.resolve(args.case)))
        if getattr(args, "json", False):
            return {"markdown": report}, 0
        print(report, end="")
        return None, 0
    if command == "stop":
        return stop(store, store.resolve(args.case)), 0
    if command == "serve":
        if not 0 <= args.port <= 65535:
            raise GryptonError("Port must be between 0 and 65535.")
        from .web import serve
        serve(store, args.port)
        return None, 0
    if command == "scope":
        case_id = store.resolve(args.case)
        if args.scope_command == "set":
            values = scope_values(args)
            if not values:
                raise GryptonError("Provide at least one scope field to update.")
            case = store.set_scope(case_id, values)
        else:
            case = store.get(case_id)
        return {"engagement": case_id, "scope": case["scope"]}, 0
    if command == "history":
        if not 1 <= args.limit <= 200:
            raise GryptonError("History limit must be between 1 and 200.")
        case_id = store.resolve(args.case)
        case = store.get(case_id)
        return {"engagement": case_id, "messages": case["messages"][-args.limit:],
                "standing_instructions": case["standing_instructions"]}, 0
    if command == "note":
        case_id = store.resolve(args.case)
        return {"engagement": case_id, "observation": store.append_record(case_id, "observations", args.text)}, 0
    if command == "surface":
        case_id = store.resolve(args.case)
        if args.surface_command == "add":
            item = store.append_record(case_id, "surface", args.text, category=args.kind)
            return {"engagement": case_id, "surface": item}, 0
        return {"engagement": case_id, "surface": store.get(case_id)["surface"]}, 0
    if command == "findings":
        case_id = store.resolve(args.case)
        if args.finding_command == "list":
            return {"engagement": case_id, "findings": store.get(case_id)["findings"]}, 0
        if args.finding_command == "add":
            title = args.title.strip() or args.claim.strip().splitlines()[0][:200]
            finding = store.add_finding(case_id, title, args.claim, evidence_ids=args.evidence)
            return {"engagement": case_id, "finding": finding,
                    "next": f"grypton findings validate {case_id} {finding['id']}"}, 0
        backend = MockBackend() if args.mock else LiveBackend(settings)
        def event(item):
            line(f"[{item['stage']}] {item['status']}: {item['detail']}", stream=sys.stderr)
        return asyncio.run(validate_finding(store, case_id, args.finding, backend, emit=event)), 0
    if command == "lab":
        from .lab import canonical_digest, load_suite, score_suite
        suite = load_suite()
        if args.lab_command == "list":
            return {"suite_id": suite["suite_id"], "offline_only": suite["offline_only"],
                    "scenarios": [{"id": item["id"], "title": item["title"],
                                   "turns": [{"id": turn["id"], "expected_verdict": turn["expected"]["verdict"],
                                              "expected_severity": turn["expected"]["severity"]}
                                             for turn in item["turns"]]}
                                  for item in suite["scenarios"]]}, 0
        if args.lab_command == "verify":
            return {"ok": True, "suite_id": suite["suite_id"], "suite_sha256": canonical_digest(suite),
                    "scenario_count": len(suite["scenarios"]),
                    "turn_count": sum(len(item["turns"]) for item in suite["scenarios"]),
                    "model_calls": 0, "target_interaction": False}, 0
        if args.lab_command == "run":
            from .lab_runner import run_lab
            def progress(item):
                line(f"[lab] {item['scenario']} / {item['turn']} · {item['status']}" +
                     (f" · score {item['score']:.3f}" if "score" in item else ""), stream=sys.stderr)
            result = asyncio.run(run_lab(settings, scenario_id=args.scenario, live=args.live, emit=progress))
            result["suite_sha256"] = canonical_digest(suite)
            if args.save:
                path = safe_lab_path(args.save)
                atomic_json(path, result)
                result["saved_to"] = str(path)
            return result, 0
        path = safe_lab_path(args.results)
        try:
            results = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError) as exc:
            raise GryptonError("Lab results must be a readable UTF-8 JSON object.") from exc
        if (isinstance(results, dict) and isinstance(results.get("results"), dict)
                and results.get("suite_id") == suite["suite_id"]):
            results = results["results"]
        return score_suite(results, suite), 0
    if command == "demo":
        scenario = next(s for s in json.loads(resource("scenarios.json")) if s["id"] == args.scenario)
        case = store.create(scenario["title"], scenario["claim"])
        with tempfile.TemporaryDirectory(prefix="grypton-demo-") as name:
            path = Path(name) / "synthetic-evidence.txt"
            path.write_text(scenario["evidence"], encoding="utf-8")
            store.add_evidence(case["id"], path)
        value = asyncio.run(review(store, case["id"], MockBackend()))
        return {"case": case["id"], "run": value, "next": f"grypton show {case['id']}"}, 0
    if command == "resume":
        case_id = store.resolve(args.case)
        if args.brief:
            store.set_brief(case_id, args.brief)
        if args.review:
            backend = MockBackend() if args.mock else LiveBackend(settings)
            def event(item):
                line(f"[{item['stage']}] {item['status']}: {item['detail']}", stream=sys.stderr)
            return asyncio.run(review(store, case_id, backend, resume=True, emit=event)), 0
        if sys.stdin.isatty() and not args.no_interact and not getattr(args, "json", False):
            from .console import interact
            asyncio.run(interact(store, case_id, MockBackend() if args.mock else LiveBackend(settings)))
            return None, 0
        case = store.get(case_id)
        return {**case_detail(case), "next": f"grypton resume {case_id}"}, 0
    if command == "review":
        case_id = store.resolve(args.case)
        case = store.get(case_id)
        if args.dry_run:
            return {"case": case_id, "evidence_count": len(case["evidence"]),
                    "mode": "mock" if args.mock else "live", "models": {role: model.public() for role, model in MODELS.items()},
                    "stages": ["Kryptex plans", "Kraude assesses", "At most one local-requirement follow-up",
                               "Codex independently validates", "Kryptex summarizes"],
                    "max_model_calls": 5, "tools": "disabled", "timeout_per_call": settings.timeout}, 0
        def event(item):
            line(f"[{item['stage']}] {item['status']}: {item['detail']}", stream=sys.stderr)
        backend = MockBackend() if args.mock else LiveBackend(settings)
        return asyncio.run(review(store, case_id, backend, resume=args.resume, emit=event)), 0
    raise GryptonError("Unknown command.")


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        value, code = dispatch(args)
        if value is not None:
            if getattr(args, "json", False):
                json_output(value)
            else:
                render(value)
        return code
    except (KeyboardInterrupt, asyncio.CancelledError):
        line("Review interrupted. Use grypton resume CASE with the same backend to continue.", stream=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0
    except (GryptonError, OSError) as exc:
        message = clean(str(exc))
        if getattr(args, "json", False):
            json_output({"ok": False, "error": message})
        else:
            line("grypton: " + message, stream=sys.stderr)
        return 1


def render(value):
    if isinstance(value, dict) and "checks" in value and "ok" in value:
        for check in value["checks"]:
            line(f"{'OK' if check['ok'] else 'FAIL'}  {check['check']}: {check['detail']}")
        for note in value.get("notes", []):
            line(note)
    elif isinstance(value, dict) and set(value) == set(MODELS):
        for role, model in value.items():
            line(f"{model['name']} ({role})  {model['qualified']}  /  {model['effort']}")
    elif isinstance(value, dict) and "stages" in value and "mode" in value and "id" in value:
        line(f"Review {value['status']} · {value['mode']}")
        verdict = value["stages"].get("validation", {})
        if verdict:
            line(f"Verdict: {verdict['verdict']} · Severity: {verdict['severity']}")
            line(verdict["rationale"])
        if "summary" in value["stages"]:
            line(value["stages"]["summary"]["summary"])
    elif isinstance(value, dict) and "next" in value:
        line(f"Engagement: {value.get('case', value.get('id', ''))}")
        if "run" in value:
            line("Offline demonstration complete · MOCK · Inconclusive")
        line(value["next"])
    elif isinstance(value, dict) and "findings" in value:
        line(f"Findings for {value['engagement']}")
        if not value["findings"]:
            line("  (none)")
        for finding in value["findings"]:
            line(f"  {finding['id']} · {finding['status']} · {finding.get('severity', 'unknown')} · {finding['title']}")
    elif isinstance(value, dict) and "scope" in value:
        line(f"Scope for {value['engagement']} · type {value['scope']['type']}")
        for key in SCOPE_KEYS:
            line(f"  {key.replace('_', ' ')}: " + (", ".join(value["scope"][key]) or "(unset)"))
    elif isinstance(value, dict) and "messages" in value and "standing_instructions" in value:
        line(f"Conversation for {value['engagement']}")
        for item in value["messages"]:
            line(f"  {item['role']}: {item['text']}")
        if not value["messages"]:
            line("  (no messages)")
    elif isinstance(value, dict) and "validation" in value and str(value.get("id", "")).startswith("finding-"):
        line(f"{value['id']} · {value['status']} · {value.get('severity', 'unknown')}")
        line(value["validation"]["rationale"])
    elif isinstance(value, dict) and "suite_id" in value:
        if "mode" in value and "score" in value:
            score = value["score"].get("score", 0)
            line(f"Lab {value['suite_id']} · {value['mode']} · {value['scenario_count']} scenario(s) · "
                 f"{value['turn_count']} turn(s) · score {score:.3f}")
            if value.get("saved_to"):
                line("Saved complete results to " + value["saved_to"])
        elif "component_names" in value:
            line(f"Lab score {value['suite_id']} · {value['score']:.3f} · "
                 f"transition adaptation {value.get('transition_adaptation')}")
        elif "scenarios" in value:
            line(f"Lab {value['suite_id']} · {len(value['scenarios'])} scenario(s)")
            for scenario in value["scenarios"]:
                line(f"  {scenario['id']} · {len(scenario['turns'])} evidence turn(s) · {scenario['title']}")
        else:
            line(f"Lab {value['suite_id']} verified · {value.get('scenario_count', 0)} scenario(s) · "
                 f"{value.get('turn_count', 0)} turn(s) · sha256:{value.get('suite_sha256', '')}")
    else:
        line(json.dumps(value, ensure_ascii=False, indent=2))


def worker_main() -> int:
    from .console import role_console
    return role_console("worker")


def manager_main() -> int:
    from .console import role_console
    return role_console("manager")
