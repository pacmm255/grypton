"""Command-line entry point for the autonomous Grypton orchestrator."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from urllib.parse import urlsplit

from . import config
from .workspace import Constraints, Workspace, list_targets


def _csv(value: str) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _target_value(ns) -> str:
    positional = (getattr(ns, "target", "") or "").strip()
    named = (getattr(ns, "target_option", "") or "").strip()
    if positional and named and positional != named:
        raise ValueError(f"target conflict: positional {positional!r} != --target {named!r}")
    target = named or positional
    if not target:
        raise ValueError("a target is required (use `grypton init --target HOST`)")
    return target


def _constraints(ns, target: str) -> Constraints:
    program_profile = None
    program_path = getattr(ns, "bugcrowd_brief", None)
    if program_path:
        from .bugcrowd import analyze_snapshot, matching_scope_rules, out_of_scope_rules
        program_profile = analyze_snapshot(program_path)
        if program_profile["automation_prohibited"]:
            raise ValueError(
                "Bugcrowd brief prohibits automated tools/scanners; this program is "
                "incompatible with an autonomous Grypton run"
            )
        matches = matching_scope_rules(program_profile, target)
        if not matches:
            raise ValueError("target does not match an in-scope target in the Bugcrowd brief")
        ns._bugcrowd_profile = program_profile
    else:
        matches = []

    value = Constraints(
        included_severities=_csv(getattr(ns, "only", "")),
        excluded_classes=_csv(getattr(ns, "exclude", "")),
        included_classes=_csv(getattr(ns, "include", "")),
        in_scope=_csv(getattr(ns, "in_scope", "")) or matches or [target],
        out_of_scope=_csv(getattr(ns, "out_scope", "")),
    )
    if program_profile:
        value.out_of_scope = list(dict.fromkeys(
            value.out_of_scope + out_of_scope_rules(program_profile)
        ))
        value.add_rule(
            "Read program-brief.md before testing a new target or vulnerability class; "
            "program exclusions and access rules are binding."
        )
        if program_profile["credential_requirement"]:
            value.add_rule(
                "The program has a Bugcrowd credential/account requirement. Do not "
                "substitute an unrelated inbox or identity; use assigned researcher "
                "credentials or choose an anonymous target that does not require them."
            )
    for rule in getattr(ns, "rule", []) or []:
        value.add_rule(rule)
    value.add_rule("Network actions must match an in-scope host and avoid every out-of-scope rule.")
    authorization = getattr(ns, "authorization_file", None)
    notes = []
    if authorization:
        path = Path(authorization).expanduser().resolve()
        data = path.read_bytes()
        notes.append(f"Authorization record: {path.name}; sha256="
                     f"{hashlib.sha256(data).hexdigest()}; recorded={int(time.time())}")
    else:
        notes.append("The operator started this engagement explicitly from the CLI.")
    if program_profile:
        notes.append(
            f"Bugcrowd brief: {Path(program_profile['source']).name}; "
            f"sha256={program_profile['sha256']}."
        )
    value.notes = " ".join(notes)
    return value


def _configure_run(ns) -> None:
    if getattr(ns, "auto_stop_time", None) is not None:
        config.CONFIG.max_run_seconds = int(ns.auto_stop_time) * 60
    elif getattr(ns, "max_seconds", None) is not None:
        config.CONFIG.max_run_seconds = int(ns.max_seconds)
    if getattr(ns, "max_turns", None) is not None:
        config.CONFIG.max_turns = int(ns.max_turns)
    config.CONFIG.stop_on_p1 = bool(getattr(ns, "stop_on_p1", False))
    config.CONFIG.backend = getattr(ns, "backend", "real")


def _run_engagement(ws: Workspace, ns, *, brief: str, fresh: bool) -> int:
    from .chat import Renderer, interact
    from .engine import Engine

    _configure_run(ns)
    renderer = Renderer()
    engine = Engine(ws.slug, backend=config.CONFIG.backend, emit=renderer.emit)

    async def execute():
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda s=sig: engine.request_stop(f"signal {s.name}"))
            except (NotImplementedError, RuntimeError):
                pass
        meta = ws.load_meta()
        await engine.setup(brief=brief, target=meta.target, target_type=meta.target_type,
                           fresh_clone=fresh)
        await interact(engine)

    try:
        asyncio.run(execute())
    except KeyboardInterrupt:
        print("\nGrypton stopped.")
    return 0


def cmd_init(ns) -> int:
    try:
        target = _target_value(ns)
        constraints = _constraints(ns, target)
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    slug = config.slugify(target)
    ws = Workspace(slug)
    if ws.exists() and not ns.force:
        print(f"ERROR: engagement {slug!r} already exists; use `grypton resume {slug}` "
              "or `grypton init --force --target ...`.", file=sys.stderr)
        return 2
    if not ws.exists():
        ws.create(target, ns.type)
    else:
        ws.update_meta(target=target, target_type=ns.type, turn_index=0,
                       last_directive="", worker_uuid="", manager_session_id="")
    ws.save_constraints(constraints)
    profile = getattr(ns, "_bugcrowd_profile", None)
    if profile:
        ws.save_program_brief(profile["brief_text"], profile)
    print(f"Grypton engagement: {slug}\n"
          f"  target     {target}\n"
          f"  scope      {', '.join(constraints.in_scope)}\n"
          f"  Kraude     {config.WORKER_MODEL} · {config.WORKER_EFFORT}\n"
          f"  Kryptex    {config.MANAGER_MODEL} · {config.MANAGER_EFFORT}\n"
          f"  validator  {config.VALIDATOR_MODEL} · {config.VALIDATOR_EFFORT} "
          f"(automatic for P1/P2 only)\n")
    return _run_engagement(ws, ns, brief=ns.brief or f"Assess {target} within recorded scope.", fresh=True)


def cmd_resume(ns) -> int:
    slug = config.slugify(ns.target)
    ws = Workspace(slug)
    if not ws.exists():
        print(f"ERROR: no engagement {slug!r}.", file=sys.stderr)
        return 2
    return _run_engagement(ws, ns, brief=ns.brief or "", fresh=False)


def _count_lines(path: Path) -> int:
    try:
        with path.open(encoding="utf-8") as stream:
            return sum(1 for line in stream if line.strip())
    except OSError:
        return 0


def _status(slug: str) -> dict:
    ws = Workspace(slug)
    if not ws.exists():
        return {"slug": slug, "missing": True}
    meta = ws.load_meta()
    calls = ws.transcripts_dir / "provider-calls.jsonl"
    by_role = {"worker": 0, "manager": 0, "validator": 0}
    try:
        for line in calls.read_text(encoding="utf-8").splitlines():
            role = json.loads(line).get("role")
            if role in by_role:
                by_role[role] += 1
    except (OSError, ValueError):
        pass
    return {"slug": slug, "target": meta.target, "status": meta.status,
            "type": meta.target_type, "turns": meta.turn_index,
            "findings": len(ws.findings.all()),
            "confirmed_findings": len(ws.confirmed_findings()),
            "confirmed_p1": len(ws.confirmed_p1s()),
            "surface": len(ws.surface.all()), "tested": len(ws.tested.all()),
            "tool_calls": _count_lines(ws.root / ".ledger" / "tool-calls.jsonl"),
            "provider_calls": by_role,
            "models": {"worker": f"{config.WORKER_MODEL} · {config.WORKER_EFFORT}",
                       "manager": f"{config.MANAGER_MODEL} · {config.MANAGER_EFFORT}",
                       "validator": f"{config.VALIDATOR_MODEL} · {config.VALIDATOR_EFFORT}"},
            "workspace": str(ws.root)}


def cmd_status(ns) -> int:
    slugs = [config.slugify(ns.target)] if ns.target else list_targets()
    rows = [_status(slug) for slug in slugs]
    if ns.json:
        print(json.dumps(rows[0] if ns.target and rows else rows, indent=2))
        return 0
    if not rows:
        print("No engagements yet.")
        return 0
    for row in rows:
        if row.get("missing"):
            print(f"{row['slug']}: missing")
            continue
        calls = row["provider_calls"]
        print(f"{row['slug']}: {row['status']} · turns={row['turns']} · tools={row['tool_calls']} · "
              f"surface={row['surface']} · tested={row['tested']} · "
              f"findings={row['findings']} ({row['confirmed_findings']} confirmed) · "
              f"providers=Kraude:{calls['worker']}/Kryptex:{calls['manager']}/Astra:{calls['validator']}")
    return 0


def _existing_workspace(target: str) -> Workspace:
    ws = Workspace(config.slugify(target))
    if not ws.exists():
        raise ValueError(f"no engagement {target!r}")
    return ws


def cmd_show(ns) -> int:
    try:
        ws = _existing_workspace(ns.target)
    except ValueError as exc:
        print(f"ERROR: {exc}.", file=sys.stderr)
        return 2
    row = _status(ws.slug)
    meta = ws.load_meta()
    row["scope"] = ws.load_constraints().in_scope
    row["last_directive"] = meta.last_directive
    row["files"] = {name: str(ws.root / name) for name in (
        "findings.md", "attack-surface.md", "tested-techniques.md",
        "progress.md", "scope-rules.md",
    )}
    if ns.json:
        print(json.dumps(row, ensure_ascii=False, indent=2))
    else:
        cmd_status(argparse.Namespace(target=ws.slug, json=False))
        print(f"  scope={', '.join(row['scope']) or '(none)'}")
        print(f"  workspace={ws.root}")
        if meta.last_directive:
            print(f"  last directive={meta.last_directive.splitlines()[0][:180]}")
    return 0


def cmd_findings(ns) -> int:
    try:
        ws = _existing_workspace(ns.target)
    except ValueError as exc:
        print(f"ERROR: {exc}.", file=sys.stderr)
        return 2
    rows = ws.findings.all()
    if ns.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    if not rows:
        print("No findings recorded.")
        return 0
    for row in rows:
        verdict = row.get("manager_verdict") or {}
        severity = verdict.get("severity") or row.get("severity") or "?"
        astra_state = verdict.get("verdict") or (
            "pending"
            if config.astra_auto_validation_required(row.get("severity", ""))
            and row.get("status") != "suppressed-by-scope"
            else "not-requested"
        )
        print(f"{row.get('id')}: {severity} · {row.get('status', 'reported')} · "
              f"Astra={astra_state} · {row.get('title', '')}")
    return 0


async def _validate_requested_findings(ws: Workspace, findings: list[dict]) -> list[dict]:
    """Run explicit Astra reviews without invoking the Spark manager model."""
    from .manager import KryptexManager, ManagerContext
    from .prompts import manager_system

    meta = ws.load_meta()
    constraints = ws.load_constraints()
    manager = KryptexManager(
        ws,
        manager_system(target=meta.target, target_type=meta.target_type, workspace=ws.root),
    )
    context = ManagerContext(
        target=meta.target,
        target_type=meta.target_type,
        turn_index=meta.turn_index,
        constraints_block=constraints.to_prompt_block(),
        findings_summary=(ws.root / "findings.md").read_text(
            encoding="utf-8", errors="replace"
        )[-12_000:],
        new_findings=findings,
        p1_count=len(ws.confirmed_p1s()),
    )
    results = []
    try:
        for finding in findings:
            verdict = await manager.validate_severity(finding, context, explicit=True)
            ws.set_severity_verdict(str(finding.get("id") or ""), verdict)
            results.append(verdict)
    finally:
        await manager.aclose()
    return results


def cmd_validate(ns) -> int:
    try:
        ws = _existing_workspace(ns.target)
    except ValueError as exc:
        print(f"ERROR: {exc}.", file=sys.stderr)
        return 2
    if ns.all and ns.finding_ids:
        print("ERROR: use finding IDs or --all, not both.", file=sys.stderr)
        return 2
    rows = ws.findings.all()
    by_id = {str(row.get("id") or "").upper(): row for row in rows}
    if ns.all:
        selected = rows
    else:
        requested = [value.upper() for value in ns.finding_ids]
        if not requested:
            print("ERROR: provide at least one finding ID or --all.", file=sys.stderr)
            return 2
        missing = [value for value in requested if value not in by_id]
        if missing:
            print(f"ERROR: unknown finding ID(s): {', '.join(missing)}.", file=sys.stderr)
            return 2
        selected = [by_id[value] for value in requested]
    if not selected:
        print("No findings recorded.")
        return 0
    results = asyncio.run(_validate_requested_findings(ws, selected))
    if ns.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        for verdict in results:
            print(f"{verdict.get('finding_id')}: Astra={verdict.get('verdict')} · "
                  f"{verdict.get('severity')} · confidence={verdict.get('confidence')}")
    return 1 if any(verdict.get("degraded") for verdict in results) else 0


def cmd_surface(ns) -> int:
    try:
        ws = _existing_workspace(ns.target)
    except ValueError as exc:
        print(f"ERROR: {exc}.", file=sys.stderr)
        return 2
    rows = ws.surface.all()
    if ns.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        for row in rows:
            print(f"{row.get('id')}: [{row.get('kind')}] {row.get('item')}")
    return 0


def cmd_history(ns) -> int:
    try:
        ws = _existing_workspace(ns.target)
    except ValueError as exc:
        print(f"ERROR: {exc}.", file=sys.stderr)
        return 2
    from .reporting import read_jsonl
    rows = read_jsonl(ws.transcripts_dir / "turns.jsonl")
    if ns.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        for row in rows:
            summary = str(row.get("assistant_text") or "").strip().splitlines()
            print(f"Turn {row.get('turn')}: tools={len(row.get('tools') or [])} · "
                  f"{(summary[-1] if summary else '(no summary)')[:180]}")
    return 0


def cmd_scope(ns) -> int:
    try:
        ws = _existing_workspace(ns.target)
    except ValueError as exc:
        print(f"ERROR: {exc}.", file=sys.stderr)
        return 2
    if ns.json:
        from dataclasses import asdict
        print(json.dumps(asdict(ws.load_constraints()), ensure_ascii=False, indent=2))
    else:
        print(ws.load_constraints().to_prompt_block())
    return 0


def cmd_audit(ns) -> int:
    try:
        ws = _existing_workspace(ns.target)
    except ValueError as exc:
        print(f"ERROR: {exc}.", file=sys.stderr)
        return 2
    from .reporting import audit_workspace
    result = audit_workspace(ws)
    if ns.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"Grypton audit — {ws.slug}: {'PASS' if result['ok'] else 'ATTENTION REQUIRED'}")
        print(f"  exact routes       {'yes' if result['exact_routes'] else 'no'}")
        print(f"  provider failures  {len(result['provider_failures'])}")
        print(f"  required gaps      {len(result['unvalidated_findings'])}")
        print(f"  not requested      {len(result['validation_not_requested'])}")
        print(f"  missing flows      {len(result['missing_canonical_flows'])}")
        print(f"  scope violations   {len(result['scope_violations'])}")
        print(f"  target/ empty      {'yes' if result['target_dir_empty'] else 'no'}")
        counts = result["counts"]
        print(f"  evidence           tools={counts['tool_calls']} flows={counts['flows']} "
              f"surface={counts['surface']} tested={counts['tested']}")
    return 0 if result["ok"] else 1


def cmd_report(ns) -> int:
    try:
        ws = _existing_workspace(ns.target)
    except ValueError as exc:
        print(f"ERROR: {exc}.", file=sys.stderr)
        return 2
    from .reporting import audit_workspace, render_report
    if ns.format == "json":
        content = json.dumps({"audit": audit_workspace(ws),
                              "findings": ws.findings.all()}, ensure_ascii=False, indent=2) + "\n"
    else:
        content = render_report(ws)
    if ns.output:
        path = Path(ns.output).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(path)
    else:
        print(content, end="" if content.endswith("\n") else "\n")
    return 0


def cmd_stop(ns) -> int:
    ws = Workspace(config.slugify(ns.target))
    if not ws.exists():
        print(f"ERROR: no engagement {ns.target!r}.", file=sys.stderr)
        return 2
    path = ws.root / ".ledger" / "STOP"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"requested {time.time()}\n", encoding="utf-8")
    print(f"Stop requested for {ws.slug}; active provider processes are interrupted within one second.")
    return 0


def cmd_models(ns) -> int:
    print(f"Kraude    {config.WORKER_MODEL} · {config.WORKER_EFFORT} · OpenCode Z.AI Coding Plan\n"
          f"Kryptex   {config.MANAGER_MODEL} · {config.MANAGER_EFFORT} · OpenCode Go\n"
          f"Validator {config.VALIDATOR_MODEL} · {config.VALIDATOR_EFFORT} · "
          f"Codex (fresh; automatic P1/P2 only)")
    return 0


def _model_in_catalog(route: str) -> bool:
    provider, model = route.split("/", 1)
    try:
        result = subprocess.run([config.require_binary("opencode"), "models", provider],
                                capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and any(line.strip() == route for line in result.stdout.splitlines())


def _mcp_probe() -> tuple[bool, str]:
    env = {**os.environ, "GRYPTON_TARGET": "doctor", "KRYPTON_TARGET": "doctor"}
    try:
        result = subprocess.run([sys.executable, "-m", "grypton.toolserver"],
            input=(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n" +
                   json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n"),
            capture_output=True, text=True, timeout=10, env=env, cwd=str(config.GRYPTON_HOME))
        rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        count = len(rows[1]["result"]["tools"])
        return result.returncode == 0 and count >= 20, f"{count} tools"
    except Exception as exc:
        return False, str(exc)


def cmd_doctor(ns) -> int:
    from .providers import opencode_credential
    checks = []
    for binary in ("opencode", "codex", "curl", "httpx", "playwright",
                   "google-chrome", "subfinder"):
        found = config.find_binary(binary)
        checks.append((binary, bool(found), found or "missing"))
    for provider in (config.WORKER_PROVIDER, config.MANAGER_PROVIDER):
        try:
            opencode_credential(provider)
            checks.append((provider + " connector", True, "connected (credential hidden)"))
        except Exception as exc:
            checks.append((provider + " connector", False, str(exc)))
    checks.append((config.WORKER_MODEL, _model_in_catalog(config.WORKER_MODEL), "OpenCode catalog"))
    checks.append((config.MANAGER_MODEL, _model_in_catalog(config.MANAGER_MODEL), "OpenCode catalog"))
    mcp_ok, mcp_detail = _mcp_probe()
    checks.append(("Grypton MCP", mcp_ok, mcp_detail))
    checks.append(("Goja", (config.GOJA_DIR / "bin/goja-proxy").is_file(),
                   str(config.GOJA_DIR / "bin/goja-proxy")))
    print("Grypton doctor")
    for name, passed, detail in checks:
        print(f"  {'OK' if passed else 'FAIL':4}  {name:45} {detail}")
    return 0 if all(passed for _, passed, _ in checks) else 1


def cmd_tools(ns) -> int:
    from .toolserver import cli_main
    return cli_main(ns.arguments)


def cmd_scenarios(ns) -> int:
    from .scenarios import load_scenarios
    rows = load_scenarios()
    if ns.json:
        print(json.dumps(rows, indent=2))
    else:
        for row in rows:
            print(f"{row['id']}: {row['title']} [{', '.join(row['target_types'])}]")
            for move in row["moves"]:
                print(f"  - {move}")
    return 0


def cmd_lab(ns) -> int:
    from .local_lab import serve
    serve(ns.host, ns.port, ns.log)
    return 0


def cmd_bugcrowd_brief(ns) -> int:
    from .bugcrowd import analyze_snapshot, matching_scope_rules, public_profile
    try:
        profile = analyze_snapshot(ns.file)
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    output = public_profile(profile)
    if ns.target:
        output["target"] = ns.target
        output["matching_scope_rules"] = matching_scope_rules(profile, ns.target)
    blocked = output["automation_prohibited"] or bool(
        ns.target and not output.get("matching_scope_rules")
    )
    if ns.json:
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        if output["automation_prohibited"]:
            compatibility = "BLOCKED: automation prohibited"
        elif ns.target and not output.get("matching_scope_rules"):
            compatibility = "BLOCKED: target is not in listed scope"
        else:
            compatibility = "autonomous preflight passed"
        print(f"Bugcrowd brief: {output['program']} · {compatibility}\n"
              f"  in-scope targets  {sum(1 for row in output['targets'] if row['in_scope'])}\n"
              f"  credential rule  {'yes' if output['credential_requirement'] else 'no'}\n"
              f"  known issues     {'login required' if output['known_issues_enabled'] and not output['logged_in_snapshot'] else 'available/none'}")
        if ns.target:
            print(f"  target matches   {', '.join(output['matching_scope_rules']) or 'NONE'}")
        print("\nHighest-signal listed targets:")
        for row in output["recommended_targets"][:8]:
            print(f"  {row['group']}: {row['name']} ({row['category']}, score={row['score']})")
    return 1 if blocked else 0


def cmd_serve(ns) -> int:
    from .web import serve
    serve(ns.port)
    return 0


def cmd_demo(ns) -> int:
    ns.target = "http://127.0.0.1:1"
    ns.target_option = ""
    ns.type = "web"
    ns.brief = "Exercise the autonomous loop with deterministic mock backends."
    ns.only = ns.exclude = ns.include = ns.in_scope = ns.out_scope = ""
    ns.rule = []
    ns.authorization_file = None
    ns.force = True
    ns.backend = "mock"
    ns.max_turns = ns.turns
    ns.max_seconds = None
    ns.auto_stop_time = None
    ns.stop_on_p1 = False
    return cmd_init(ns)


def _run_options(parser) -> None:
    parser.add_argument("-m", "--brief", default="", help="Engagement mission")
    parser.add_argument("--backend", choices=["real", "mock"], default="real", help=argparse.SUPPRESS)
    parser.add_argument("--max-seconds", type=int, default=None)
    parser.add_argument("--max-turns", type=int, default=None)
    parser.add_argument("--auto-stop-time", type=int, metavar="MINUTES", default=None)
    parser.add_argument("--stop-on-p1", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="grypton",
        description="Autonomous scoped testing with GLM Kraude, Spark Kryptex, and Astra validation")
    parser.add_argument("--version", action="version", version="Grypton 3.1.0")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Create and immediately run an engagement")
    init.add_argument("target", nargs="?")
    init.add_argument("--target", dest="target_option")
    init.add_argument("--type", choices=["auto", "web", "api", "network", "cidr", "binary", "contract"], default="auto")
    init.add_argument("--only", default=""); init.add_argument("--exclude", default="")
    init.add_argument("--include", default=""); init.add_argument("--in-scope", default="")
    init.add_argument("--out-scope", default=""); init.add_argument("--rule", action="append", default=[])
    init.add_argument("--authorization-file"); init.add_argument("--bugcrowd-brief")
    init.add_argument("--force", action="store_true")
    _run_options(init); init.set_defaults(func=cmd_init)
    resume = sub.add_parser("resume", help="Resume a persistent engagement")
    resume.add_argument("target"); _run_options(resume); resume.set_defaults(func=cmd_resume)
    status = sub.add_parser("status"); status.add_argument("target", nargs="?")
    status.add_argument("--json", action="store_true"); status.set_defaults(func=cmd_status)
    show = sub.add_parser("show", help="Show one engagement and its review paths")
    show.add_argument("target"); show.add_argument("--json", action="store_true")
    show.set_defaults(func=cmd_show)
    findings = sub.add_parser("findings", help="List findings with independent verdicts")
    findings.add_argument("target"); findings.add_argument("--json", action="store_true")
    findings.set_defaults(func=cmd_findings)
    validate = sub.add_parser(
        "validate",
        help="Explicitly request Astra review for selected findings (including P3-P5)",
    )
    validate.add_argument("target")
    validate.add_argument("finding_ids", nargs="*")
    validate.add_argument("--all", action="store_true")
    validate.add_argument("--json", action="store_true")
    validate.set_defaults(func=cmd_validate)
    surface = sub.add_parser("surface", help="List recorded attack-surface items")
    surface.add_argument("target"); surface.add_argument("--json", action="store_true")
    surface.set_defaults(func=cmd_surface)
    history = sub.add_parser("history", help="Show persistent worker turn history")
    history.add_argument("target"); history.add_argument("--json", action="store_true")
    history.set_defaults(func=cmd_history)
    scope = sub.add_parser("scope", help="Show binding scope and standing instructions")
    scope.add_argument("target"); scope.add_argument("--json", action="store_true")
    scope.set_defaults(func=cmd_scope)
    audit = sub.add_parser("audit", help="Verify routes, validation, scope, and evidence integrity")
    audit.add_argument("target"); audit.add_argument("--json", action="store_true")
    audit.set_defaults(func=cmd_audit)
    report = sub.add_parser("report", help="Render a Markdown or JSON engagement report")
    report.add_argument("target"); report.add_argument("--format", choices=["markdown", "json"],
                                                        default="markdown")
    report.add_argument("--output"); report.set_defaults(func=cmd_report)
    stop = sub.add_parser("stop"); stop.add_argument("target"); stop.set_defaults(func=cmd_stop)
    models = sub.add_parser("models"); models.set_defaults(func=cmd_models)
    doctor = sub.add_parser("doctor"); doctor.set_defaults(func=cmd_doctor)
    tools_parser = sub.add_parser("tools", help="Call the scoped HTTP/Goja/capture tool surface")
    tools_parser.add_argument("arguments", nargs=argparse.REMAINDER); tools_parser.set_defaults(func=cmd_tools)
    scenarios = sub.add_parser("scenarios", help="Show autonomous target-type playbooks")
    scenarios.add_argument("--json", action="store_true"); scenarios.set_defaults(func=cmd_scenarios)
    brief = sub.add_parser("bugcrowd-brief", help="Inspect a saved Bugcrowd brief before autonomous testing")
    brief.add_argument("file"); brief.add_argument("--target", default="")
    brief.add_argument("--json", action="store_true"); brief.set_defaults(func=cmd_bugcrowd_brief)
    lab = sub.add_parser("lab", help="Run the instrumented loopback integration target")
    lab.add_argument("--host", default="127.0.0.1"); lab.add_argument("--port", type=int, default=0)
    lab.add_argument("--log", default=""); lab.set_defaults(func=cmd_lab)
    serve = sub.add_parser("serve", help="Run the loopback read-only operations dashboard")
    serve.add_argument("--port", type=int, default=8765); serve.set_defaults(func=cmd_serve)
    demo = sub.add_parser("demo"); demo.add_argument("--turns", type=int, default=5); demo.set_defaults(func=cmd_demo)
    return parser


def main(argv=None) -> int:
    # Keep progress visible when output is piped through tee or a log collector.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True, write_through=True)
        except (AttributeError, OSError):
            pass
    config.ensure_layout()
    arguments = list(sys.argv[1:] if argv is None else argv)
    # The tool CLI owns its option namespace. Dispatch it before the outer
    # parser so flags such as `--target` and `--json` reach the tool parser.
    if arguments and arguments[0] == "tools":
        from .toolserver import cli_main
        return cli_main(arguments[1:])
    ns = build_parser().parse_args(arguments)
    return ns.func(ns)


def worker_main(argv=None) -> int:
    print(f"Kraude is pinned to {config.WORKER_MODEL} · {config.WORKER_EFFORT}. "
          "Start it with `grypton init --target HOST`.")
    return 0


def manager_main(argv=None) -> int:
    print(f"Kryptex is pinned to {config.MANAGER_MODEL} · {config.MANAGER_EFFORT}; "
          f"automatic P1/P2 validation uses "
          f"{config.VALIDATOR_MODEL} · {config.VALIDATOR_EFFORT}.")
    return 0
