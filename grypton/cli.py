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
from .engine import review, stop
from .presentation import case_detail, case_summary, json_output, line, markdown_report, print_state, state
from .storage import Store


def common(parser):
    parser.add_argument("--root", default=argparse.SUPPRESS, help="Grypton workspace (or GRYPTON_ROOT)")
    parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="Emit one JSON result on stdout")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="grypton", description="Review supplied security evidence with Kraude, Kryptex, and an independent Codex validator.",
        epilog="Live review sends the attached evidence to the configured providers. Use demo or review --mock for offline work.")
    root.add_argument("--version", action="version", version=f"grypton {__version__}")
    common(root)
    commands = root.add_subparsers(dest="command")
    for name, help_text in [("status", "List cases and review outcomes"), ("models", "Show the exact model and plan routes"),
                            ("doctor", "Check installed CLIs, model variants, and authentication"),
                            ("scenarios", "List packaged defensive review scenarios")]:
        common(commands.add_parser(name, help=help_text))
    init = commands.add_parser("init", help="Create a case for a specific claim")
    common(init)
    init.add_argument("title")
    init.add_argument("--claim", required=True)
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
    for command in ("review", "resume"):
        run = commands.add_parser(command, help="Run a bounded review" if command == "review" else "Resume completed checkpoints after a failure or stop")
        common(run)
        run.add_argument("case")
        run.add_argument("--mock", action="store_true", help="Use deterministic offline responses")
        run.add_argument("--dry-run", action="store_true", help="Show the plan without invoking models")
        run.add_argument("--timeout", type=float, default=600, help="Per-call timeout in seconds (default: 600)")
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
    return root


def dispatch(args) -> tuple[object, int]:
    settings = Settings.load(getattr(args, "root", None), getattr(args, "timeout", 600))
    store = Store(settings)
    command = args.command or "status"
    if command == "status":
        value = state(store)
        if not getattr(args, "json", False):
            print_state(value)
            return None, 0
        return value, 0
    if command == "models":
        return {role: model.public() for role, model in MODELS.items()}, 0
    if command == "doctor":
        value = asyncio.run(doctor())
        return value, 0 if value["ok"] else 1
    if command == "scenarios":
        return [{k: v for k, v in item.items() if k != "evidence"} for item in json.loads(resource("scenarios.json"))], 0
    if command == "init":
        case = store.create(args.title, args.claim)
        return {**case_summary(case), "next": f"grypton evidence add {case['id']} /path/to/evidence.txt"}, 0
    if command == "evidence":
        case = store.add_evidence(args.case, args.file) if args.evidence_command == "add" else store.get(args.case)
        return case_detail(case)["evidence"], 0
    if command == "show":
        case = store.get(args.case)
        if getattr(args, "json", False):
            return case if args.evidence else case_detail(case), 0
        print(markdown_report(case), end="")
        if args.evidence:
            for evidence in case["evidence"]:
                line(f"\n{evidence['id']} · {evidence['name']}")
                line(evidence["text"])
        return None, 0
    if command == "report":
        report = markdown_report(store.get(args.case))
        if getattr(args, "json", False):
            return {"markdown": report}, 0
        print(report, end="")
        return None, 0
    if command == "stop":
        return stop(store, args.case), 0
    if command == "serve":
        if not 0 <= args.port <= 65535:
            raise GryptonError("Port must be between 0 and 65535.")
        from .web import serve
        serve(store, args.port)
        return None, 0
    if command == "demo":
        scenario = next(s for s in json.loads(resource("scenarios.json")) if s["id"] == args.scenario)
        case = store.create(scenario["title"], scenario["claim"])
        with tempfile.TemporaryDirectory(prefix="grypton-demo-") as name:
            path = Path(name) / "synthetic-evidence.txt"
            path.write_text(scenario["evidence"], encoding="utf-8")
            store.add_evidence(case["id"], path)
        value = asyncio.run(review(store, case["id"], MockBackend()))
        return {"case": case["id"], "run": value, "next": f"grypton show {case['id']}"}, 0
    if command in ("review", "resume"):
        case = store.get(args.case)
        if args.dry_run:
            return {"case": args.case, "evidence_count": len(case["evidence"]),
                    "mode": "mock" if args.mock else "live", "models": {role: model.public() for role, model in MODELS.items()},
                    "stages": ["Kryptex plans", "Kraude assesses", "At most one local-requirement follow-up",
                               "Codex independently validates", "Kryptex summarizes"],
                    "max_model_calls": 5, "tools": "disabled", "timeout_per_call": settings.timeout}, 0
        def event(item):
            line(f"[{item['stage']}] {item['status']}: {item['detail']}", stream=sys.stderr)
        backend = MockBackend() if args.mock else LiveBackend(settings)
        return asyncio.run(review(store, args.case, backend, resume=command == "resume", emit=event)), 0
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
        line(f"Case: {value.get('case', value.get('id', ''))}")
        if "run" in value:
            line("Offline demonstration complete · MOCK · Inconclusive")
        line(value["next"])
    else:
        line(json.dumps(value, ensure_ascii=False, indent=2))


def worker_main() -> int:
    line("Kraude is managed through a Grypton evidence review. Use: grypton review CASE")
    return 0


def manager_main() -> int:
    return main()
