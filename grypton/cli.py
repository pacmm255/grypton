"""Command-line entry point for the autonomous Grypton orchestrator."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shlex
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
    from .chat import Renderer, interact, print_console_header
    from .engine import Engine

    _configure_run(ns)
    renderer = Renderer(getattr(ns, "console", "normal"))
    engine = Engine(ws.slug, backend=config.CONFIG.backend, emit=renderer.emit)

    async def execute():
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda s=sig: engine.request_stop(f"signal {s.name}"))
            except (NotImplementedError, RuntimeError):
                pass
        meta = ws.load_meta()
        # The terminal shell comes first.  Provider setup emits live status
        # events, and printing it after setup puts startup lines above the
        # console frame and looks like a broken interactive session.
        print_console_header(target=meta.target, target_type=meta.target_type,
                             backend=config.CONFIG.backend, renderer=renderer)
        await engine.setup(brief=brief, target=meta.target, target_type=meta.target_type,
                           fresh_clone=fresh)
        await interact(engine, renderer, accept_input=not getattr(ns, "print_mode", False),
                       show_header=False)

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


def _jsonl_tail(path: Path, limit: int) -> list[dict]:
    """Read a small JSONL tail for a human-facing live view."""
    rows: list[dict] = []
    try:
        with path.open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except ValueError:
                    continue
                if isinstance(value, dict):
                    rows.append(value)
    except OSError:
        return []
    return rows[-max(1, min(int(limit), 100)):]


_INLINE_SECRET_RX = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|cookie)"
    r"([:=]\s*|%3[dD])[^\s,;&]+"
)


def _redact_summary(value: object) -> str:
    """Keep live operational views useful without reproducing sensitive values."""
    text = " ".join(str(value or "").split())
    return _INLINE_SECRET_RX.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)


def _finding_overview(row: dict | None) -> dict | None:
    if not row:
        return None
    verdict = row.get("manager_verdict") or {}
    return {
        "id": row.get("id"),
        "title": row.get("title"),
        "claimed_severity": row.get("severity"),
        "severity": verdict.get("severity") or row.get("severity"),
        "status": row.get("status"),
        "validator_verdict": verdict.get("verdict"),
        "confidence": verdict.get("confidence"),
    }


def _activity_snapshot(ws: Workspace, limit: int) -> dict:
    """Return summaries only: capture bodies and tool arguments stay private."""
    tools = []
    for row in _jsonl_tail(ws.root / ".ledger" / "tool-calls.jsonl", limit):
        tools.append({"at": row.get("at"), "tool": row.get("tool"), "ok": row.get("ok"),
                      "summary": _redact_summary(row.get("summary")),
                      "duration_s": row.get("duration_s")})
    turns = []
    for row in _jsonl_tail(ws.transcripts_dir / "turns.jsonl", limit):
        text = " ".join(str(row.get("assistant_text") or "").strip().split())
        turns.append({"turn": row.get("turn"), "tools": len(row.get("tools") or []),
                      "error": bool(row.get("is_error")), "summary": _redact_summary(text[-240:])})
    try:
        flows = sorted(ws.flows_dir.glob("flow-*.http"), key=lambda path: path.stat().st_mtime,
                       reverse=True)[:limit]
    except OSError:
        flows = []
    try:
        progress = [line for line in (ws.root / "progress.md").read_text(
            encoding="utf-8", errors="replace").splitlines() if line.strip()][-limit:]
    except OSError:
        progress = []
    return {
        "tools": tools,
        "turns": turns,
        "flows": [{"id": path.stem, "bytes": path.stat().st_size} for path in flows],
        "progress": [_redact_summary(line) for line in progress],
    }


def cmd_activity(ns) -> int:
    try:
        ws = _existing_workspace(ns.target)
    except ValueError as exc:
        print(f"ERROR: {exc}.", file=sys.stderr)
        return 2
    limit = max(1, min(ns.limit, 100))
    snapshot = _activity_snapshot(ws, limit)
    requested = ns.kind
    output = {requested: snapshot[requested]} if requested != "all" else snapshot
    if ns.json:
        print(json.dumps({"target": ws.slug, **output}, ensure_ascii=False, indent=2))
        return 0
    if requested in ("all", "tools"):
        print("Tool activity")
        if not snapshot["tools"]:
            print("  (none)")
        for row in snapshot["tools"]:
            marker = "OK" if row.get("ok") else "ERR"
            print(f"  {marker:3}  {str(row.get('tool') or '?'):<24} "
                  f"{str(row.get('summary') or '')[:180]}")
    if requested in ("all", "turns"):
        print("Worker turns")
        if not snapshot["turns"]:
            print("  (none)")
        for row in snapshot["turns"]:
            print(f"  turn {str(row.get('turn') or '?'):>3} · tools={row['tools']} · "
                  f"{row['summary'] or '(no summary)'}")
    if requested in ("all", "flows"):
        print("Captured flows")
        if not snapshot["flows"]:
            print("  (none)")
        for row in snapshot["flows"]:
            print(f"  {row['id']:<34} {row['bytes']:>8} bytes")
    if requested in ("all", "progress"):
        print("Progress")
        for line in snapshot["progress"] or ["(none)"]:
            print(f"  {line}")
    return 0


def cmd_overview(ns) -> int:
    try:
        ws = _existing_workspace(ns.target)
    except ValueError as exc:
        print(f"ERROR: {exc}.", file=sys.stderr)
        return 2
    row = _status(ws.slug)
    meta = ws.load_meta()
    constraints = ws.load_constraints()
    findings = ws.findings.all()
    latest = findings[-1] if findings else None
    output = {
        **row,
        "scope": constraints.in_scope,
        "out_of_scope": constraints.out_of_scope,
        "standing_instruction_count": len(constraints.standing_instructions),
        "last_directive": _redact_summary(meta.last_directive),
        "latest_finding": _finding_overview(latest),
        "activity": _activity_snapshot(ws, max(1, min(ns.limit, 100))),
    }
    if ns.json:
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0
    calls = row["provider_calls"]
    print(f"Grypton overview — {row['slug']} · {row['status']}")
    print(f"  target       {row['target']} ({row['type']})")
    print(f"  coverage     turns={row['turns']} tools={row['tool_calls']} surface={row['surface']} "
          f"tested={row['tested']} findings={row['confirmed_findings']}/{row['findings']} confirmed")
    print(f"  model calls  Kraude={calls['worker']} Kryptex={calls['manager']} Astra={calls['validator']}")
    print(f"  scope        {', '.join(constraints.in_scope) or '—'}")
    if latest:
        verdict = latest.get("manager_verdict") or {}
        print(f"  latest       {latest.get('id')} · {verdict.get('severity') or latest.get('severity', '?')} · "
              f"{verdict.get('verdict') or latest.get('status', 'recorded')} · {latest.get('title', '')}")
    else:
        print("  latest       no finding recorded")
    directive = _redact_summary(meta.last_directive)
    print(f"  next         {directive[:240] or 'No manager directive recorded yet.'}")
    print(f"  workspace    {row['workspace']}")
    return 0


def cmd_plan(ns) -> int:
    """Preflight a run without creating an engagement or starting a provider."""
    try:
        target = _target_value(ns)
        constraints = _constraints(ns, target)
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    from .scenarios import load_scenarios
    selected_type = ns.type
    scenarios = [row["id"] for row in load_scenarios()
                 if selected_type == "auto" or selected_type in row.get("target_types", [])]
    output = {
        "target": target,
        "type": selected_type,
        "slug": config.slugify(target),
        "workspace": str(Workspace(config.slugify(target)).root),
        "scope": constraints.in_scope,
        "out_of_scope": constraints.out_of_scope,
        "hard_rules": constraints.hard_rules,
        "models": {
            "worker": {"route": config.WORKER_MODEL, "effort": config.WORKER_EFFORT},
            "manager": {"route": config.MANAGER_MODEL, "effort": config.MANAGER_EFFORT},
            "validator": {"route": config.VALIDATOR_MODEL, "effort": config.VALIDATOR_EFFORT,
                          "automatic_severities": sorted(config.ASTRA_AUTO_SEVERITIES)},
        },
        "scenario_ids": scenarios,
        "created": False,
    }
    if ns.json:
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0
    command = f"grypton init --target {shlex.quote(target)} --type {shlex.quote(selected_type)}"
    if ns.brief:
        command += f" --brief {shlex.quote(ns.brief)}"
    print("Grypton preflight — no workspace or provider was started")
    print(f"  target       {target} ({selected_type})")
    print(f"  workspace    {output['workspace']}")
    print(f"  in scope     {', '.join(constraints.in_scope) or '—'}")
    print(f"  out of scope {', '.join(constraints.out_of_scope) or '—'}")
    print(f"  models       GLM → Spark → Astra (P1/P2 automatic)")
    print(f"  playbooks    {', '.join(scenarios) or 'auto routing at startup'}")
    print(f"  start        {command}")
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


def cmd_benchmark_serve(ns) -> int:
    from .hard_lab import serve
    try:
        serve(ns.out, host=ns.host, web_port=ns.web_port, network_port=ns.network_port,
              log_path=ns.log)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: benchmark did not start: {exc}", file=sys.stderr)
        return 2
    return 0


def cmd_benchmark_score(ns) -> int:
    from .hard_lab import score_workspace
    workspace = ns.workspace or str(Workspace(ns.target).root)
    try:
        result = score_workspace(ns.manifest, workspace)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot score benchmark: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False) if ns.json else
          f"Benchmark score: {result['score']['covered']}/{result['score']['total']} "
          f"({result['score']['percent']}%)\n"
          f"Covered: {', '.join(result['covered_cases']) or 'none'}\n"
          f"Observed but not recorded: {', '.join(result['observed_only']) or 'none'}")
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
    parser.add_argument("--model", dest="worker_model", choices=["glm", "glm-5.3", "zai-coding-plan/glm-5.3"],
                        help="Kraude route alias; the worker remains pinned to GLM 5.3")
    parser.add_argument("--permission-mode", choices=["scoped"], default="scoped",
                        help="Use Grypton's recorded-scope, captured-tool permission mode")
    parser.add_argument("-p", "--print", dest="print_mode", action="store_true",
                        help="Run without interactive console input; retain the event stream")
    parser.add_argument("--console", choices=["quiet", "normal", "full"], default="normal",
                        help="Initial terminal detail level (default: normal)")
    parser.add_argument("--backend", choices=["real", "mock"], default="real", help=argparse.SUPPRESS)
    parser.add_argument("--max-seconds", type=int, default=None)
    parser.add_argument("--max-turns", type=int, default=None)
    parser.add_argument("--auto-stop-time", type=int, metavar="MINUTES", default=None)
    parser.add_argument("--stop-on-p1", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="grypton", usage="grypton [options] [command] [prompt]",
        description="Grypton Code: scoped testing with GLM Kraude, Spark Kryptex, and Astra validation.",
        epilog=("Claude Code-style shortcuts: `grypton --target HOST \"mission\"`, "
                "`grypton -p --target HOST \"mission\"`, `grypton -c`, and `grypton -r ENGAGEMENT`."),
    )
    parser.add_argument("--version", action="version", version="Grypton 3.4.0")
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
    plan = sub.add_parser("plan", help="Preview scope, models, and playbooks without starting a run")
    plan.add_argument("target", nargs="?")
    plan.add_argument("--target", dest="target_option")
    plan.add_argument("--type", choices=["auto", "web", "api", "network", "cidr", "binary", "contract"],
                      default="auto")
    plan.add_argument("-m", "--brief", default="", help="Proposed engagement mission")
    plan.add_argument("--only", default=""); plan.add_argument("--exclude", default="")
    plan.add_argument("--include", default=""); plan.add_argument("--in-scope", default="")
    plan.add_argument("--out-scope", default=""); plan.add_argument("--rule", action="append", default=[])
    plan.add_argument("--authorization-file"); plan.add_argument("--bugcrowd-brief")
    plan.add_argument("--json", action="store_true"); plan.set_defaults(func=cmd_plan)
    resume = sub.add_parser("resume", help="Resume a persistent engagement")
    resume.add_argument("target"); _run_options(resume); resume.set_defaults(func=cmd_resume)
    status = sub.add_parser("status", aliases=["ls"], help="List engagements and current run counters")
    status.add_argument("target", nargs="?")
    status.add_argument("--json", action="store_true"); status.set_defaults(func=cmd_status)
    show = sub.add_parser("show", help="Show one engagement and its review paths")
    show.add_argument("target"); show.add_argument("--json", action="store_true")
    show.set_defaults(func=cmd_show)
    overview = sub.add_parser("overview", aliases=["inspect"],
                              help="Show a compact engagement picture and current next step")
    overview.add_argument("target"); overview.add_argument("--limit", type=int, default=5)
    overview.add_argument("--json", action="store_true"); overview.set_defaults(func=cmd_overview)
    activity = sub.add_parser("activity", aliases=["tail"],
                              help="Review sanitized tool, turn, capture, or progress summaries")
    activity.add_argument("target")
    activity.add_argument("--kind", choices=["all", "tools", "turns", "flows", "progress"], default="all")
    activity.add_argument("--limit", type=int, default=10)
    activity.add_argument("--json", action="store_true"); activity.set_defaults(func=cmd_activity)
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
    benchmark = sub.add_parser("benchmark", help="Run or score the black-box loopback web, network, and APK lab")
    benchmark_sub = benchmark.add_subparsers(dest="benchmark_command", required=True)
    benchmark_serve = benchmark_sub.add_parser("serve", help="Start a new hard loopback benchmark")
    benchmark_serve.add_argument("--out", default=".state/benchmarks/hard-lab",
                                 help="Directory for public manifest, APK artifact, logs, and private evaluator state")
    benchmark_serve.add_argument("--host", default="127.0.0.1")
    benchmark_serve.add_argument("--web-port", type=int, default=0)
    benchmark_serve.add_argument("--network-port", type=int, default=0)
    benchmark_serve.add_argument("--log", default="", help="Sanitized JSONL event log path")
    benchmark_serve.set_defaults(func=cmd_benchmark_serve)
    benchmark_score = benchmark_sub.add_parser("score", help="Score one engagement's durable findings")
    benchmark_score.add_argument("manifest", help="Public manifest.json produced by benchmark serve")
    benchmark_score.add_argument("target", nargs="?", default="", help="Grypton engagement slug")
    benchmark_score.add_argument("--workspace", default="", help="Explicit engagement workspace path")
    benchmark_score.add_argument("--json", action="store_true")
    benchmark_score.set_defaults(func=cmd_benchmark_score)
    serve = sub.add_parser("serve", help="Run the loopback read-only operations dashboard")
    serve.add_argument("--port", type=int, default=8765); serve.set_defaults(func=cmd_serve)
    demo = sub.add_parser("demo"); demo.add_argument("--turns", type=int, default=5); demo.set_defaults(func=cmd_demo)
    return parser


_COMMAND_NAMES = {
    "init", "plan", "resume", "status", "ls", "show", "overview", "inspect", "activity", "tail",
    "findings", "validate", "surface", "history", "scope", "audit", "report", "stop", "models",
    "doctor", "tools", "scenarios", "bugcrowd-brief", "lab", "benchmark", "serve", "demo",
}
_COMPAT_VALUE_OPTIONS = {
    "--target", "--type", "--only", "--exclude", "--include", "--in-scope", "--out-scope", "--rule",
    "--authorization-file", "--bugcrowd-brief", "-m", "--brief", "--max-seconds", "--max-turns",
    "--auto-stop-time", "--console", "--model", "--permission-mode", "--backend",
}


def _looks_like_target(value: str) -> bool:
    candidate = (value or "").strip()
    if not candidate or any(char.isspace() for char in candidate):
        return False
    parsed = urlsplit(candidate if "://" in candidate else "//" + candidate)
    host = parsed.hostname or ""
    return bool(host and ("." in host or host == "localhost" or ":" in candidate))


def _latest_engagement_slug() -> str:
    rows = []
    for slug in list_targets():
        try:
            rows.append((Workspace(slug).root.stat().st_mtime, slug))
        except OSError:
            continue
    if not rows:
        raise ValueError("no engagement to continue; start one with `grypton --target HOST \"mission\"`")
    return max(rows)[1]


def _claude_style_arguments(arguments: list[str]) -> list[str]:
    """Translate familiar direct invocation into the explicit Grypton commands.

    The normal command surface stays available.  This adapter supplies the
    high-frequency Claude Code forms without weakening target/scope requirements.
    """
    if not arguments or arguments[0] in _COMMAND_NAMES or arguments[0] in {"-h", "--help", "--version"}:
        return arguments
    passthrough: list[str] = []
    free: list[str] = []
    resume_slug = ""
    continue_requested = False
    brief_seen = False
    index = 0
    while index < len(arguments):
        value = arguments[index]
        if value in ("-c", "--continue"):
            continue_requested = True
            index += 1
            continue
        if value in ("-r", "--resume"):
            if index + 1 < len(arguments) and not arguments[index + 1].startswith("-"):
                resume_slug = arguments[index + 1]
                index += 2
            else:
                continue_requested = True
                index += 1
            continue
        if value.startswith("--resume="):
            resume_slug = value.partition("=")[2]
            index += 1
            continue
        if value in _COMPAT_VALUE_OPTIONS:
            passthrough.append(value)
            if index + 1 < len(arguments):
                passthrough.append(arguments[index + 1])
                if value in ("-m", "--brief"):
                    brief_seen = True
                index += 2
                continue
            index += 1
            continue
        if value.startswith("--brief="):
            brief_seen = True
            passthrough.append(value)
            index += 1
            continue
        if value.startswith("-"):
            passthrough.append(value)
        else:
            free.append(value)
        index += 1

    if resume_slug or continue_requested:
        slug = config.slugify(resume_slug) if resume_slug else _latest_engagement_slug()
        return ["resume", slug, *passthrough]

    has_named_target = any(value == "--target" or value.startswith("--target=") for value in passthrough)
    if not has_named_target and free and _looks_like_target(free[0]):
        passthrough.extend(("--target", free.pop(0)))
        has_named_target = True
    if has_named_target and free and not brief_seen:
        passthrough.extend(("--brief", " ".join(free)))
        free = []
    return ["init", *passthrough, *free]


def main(argv=None) -> int:
    # Keep progress visible when output is piped through tee or a log collector.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True, write_through=True)
        except (AttributeError, OSError):
            pass
    config.ensure_layout()
    arguments = _claude_style_arguments(list(sys.argv[1:] if argv is None else argv))
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
