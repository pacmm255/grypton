"""Krypton command-line interface.

    krypton init <target> [-m brief] [--type ...] [--only P1,P2] [--exclude CORS] ...
    krypton resume <target>
    krypton freeze [--session TERM | --session-id UUID | --session-file PATH] [--force]
    krypton sessions
    krypton status [target]
    krypton stop <target>
    krypton doctor
    krypton test
    krypton tool ...            (delegates to the krypton-tool surface)
"""
from __future__ import annotations

import argparse
import asyncio
import signal
import sys
from pathlib import Path

from . import config, sessions
from .workspace import Constraints, Workspace, list_targets


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _csv(s: str) -> list[str]:
    return [x.strip() for x in (s or "").split(",") if x.strip()]


def _build_constraints(ns) -> Constraints:
    c = Constraints()
    c.included_severities = _csv(getattr(ns, "only", "") or "")
    c.excluded_classes = _csv(getattr(ns, "exclude", "") or "")
    c.included_classes = _csv(getattr(ns, "include", "") or "")
    c.in_scope = _csv(getattr(ns, "in_scope", "") or "")
    c.out_of_scope = _csv(getattr(ns, "out_scope", "") or "")
    for r in (getattr(ns, "rule", None) or []):
        c.add_rule(r)
    return c


def _print_candidates(cands) -> None:
    for i, r in enumerate(cands):
        print(f"  [{i}] {r.uuid}  ({sessions._fmt_size(r.size_bytes)}, "
              f"proj={r.project_dir}, score={r.match_score:.0f})")


def _ensure_init0(term: str, *, session_id=None, session_file=None,
                  auto: bool = True) -> bool:
    """Make sure Init 0 is frozen. Returns True if available."""
    if sessions.init0_exists():
        return True
    print(f"Init 0 not frozen yet. Resolving session for: {term!r}")
    cands = sessions.resolve_named_session(term, session_id=session_id,
                                           session_file=session_file)
    if not cands:
        print(config_err(f"No Claude session matched {term!r}. "
                         f"Pass --session-id or --session-file."))
        return False
    _print_candidates(cands)
    chosen = cands[0]
    print(f"Freezing Init 0 from [{chosen.uuid}] "
          f"({sessions._fmt_size(chosen.size_bytes)})… this copies, never touches the original.")
    sessions.freeze_init0(chosen, progress=lambda m: print(f"  · {m}"))
    print("Init 0 frozen and locked read-only.")
    return True


def config_err(s: str) -> str:
    return f"ERROR: {s}"


def _run_overrides(*, manager_kind=None, worker_model=None,
                   full_codex: bool = False, current_meta=None) -> tuple[dict, list[str]]:
    """Resolve run-mode flags into target metadata patches plus status lines."""
    notes: list[str] = []
    meta_patch = {}

    if full_codex:
        if manager_kind and manager_kind.strip().lower() != "codex":
            raise ValueError("--full-codex conflicts with --manager claude")
        if worker_model:
            raise ValueError("--full-codex conflicts with --worker-model; it pins the worker to Codex gpt-5.5")
        manager_kind = "codex"
        meta_patch["manager_model"] = config.FULL_CODEX_MODEL
        meta_patch["manager_effort"] = config.FULL_CODEX_EFFORT
        meta_patch["worker_kind"] = "codex"
        meta_patch["worker_model"] = config.FULL_CODEX_MODEL
        meta_patch["worker_project_dir"] = "codex"
        if current_meta is not None:
            current_kind = (getattr(current_meta, "worker_kind", "") or "").strip().lower() or "claude"
            if current_kind != "codex":
                meta_patch["worker_uuid"] = ""
        notes.append(
            f"Full Codex mode: manager, severity validation, and worker use "
            f"{config.FULL_CODEX_MODEL!r} at {config.FULL_CODEX_EFFORT!r}.")

    if manager_kind:
        meta_patch["manager_kind"] = manager_kind.strip().lower()
    if worker_model:
        meta_patch["worker_model"] = config.resolve_worker_model(worker_model)

    return meta_patch, notes


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def cmd_freeze(ns) -> int:
    if sessions.init0_exists() and not ns.force:
        m = sessions.init0_manifest()
        print(f"Init 0 already frozen: orig_uuid={m['orig_uuid']} "
              f"({sessions._fmt_size(m['main_jsonl_bytes'])}, "
              f"{m['sidecar_files']} sidecar files). Use --force to replace.")
        ok = sessions.verify_init0()
        print(f"Integrity: {'OK' if ok else 'MISMATCH'}")
        return 0
    cands = sessions.resolve_named_session(
        ns.session, session_id=ns.session_id, session_file=ns.session_file)
    if not cands:
        print(config_err(f"No session matched {ns.session!r}."))
        return 1
    print("Candidate sessions (best first):")
    _print_candidates(cands)
    chosen = cands[ns.pick] if ns.pick < len(cands) else cands[0]
    print(f"\nFreezing Init 0 from [{chosen.uuid}] "
          f"({sessions._fmt_size(chosen.size_bytes)}). The original is only read, never modified.")
    sessions.freeze_init0(chosen, force=ns.force, progress=lambda m: print(f"  · {m}"))
    print(f"Init 0 frozen → {config.INIT0_DIR}  (read-only). "
          f"Integrity: {'OK' if sessions.verify_init0() else 'MISMATCH'}")
    return 0


def cmd_sessions(ns) -> int:
    print(f"Resolving Claude sessions for: {ns.session!r}\n")
    cands = sessions.resolve_named_session(ns.session)
    if not cands:
        print("  (no matches)")
    else:
        _print_candidates(cands)
    print()
    if sessions.init0_exists():
        m = sessions.init0_manifest()
        print(f"Init 0: FROZEN  orig_uuid={m['orig_uuid']} "
              f"size={sessions._fmt_size(m['main_jsonl_bytes'])} "
              f"sidecar_files={m['sidecar_files']} created={m.get('created_at_iso','?')}")
        print(f"Integrity: {'OK' if sessions.verify_init0() else 'MISMATCH'}")
    else:
        print("Init 0: NOT FROZEN  (run `krypton freeze`)")
    print("\nTargets:", ", ".join(list_targets()) or "(none)")
    return 0


def _run_engagement(slug, *, brief, target, target_type, backend, fresh_clone,
                    constraints=None, max_seconds=None, max_turns=None,
                    stop_on_p1=None, auto_stop_time=None,
                    manager_kind=None, worker_model=None,
                    full_codex: bool = False) -> int:
    from .chat import Renderer, interact
    from .engine import Engine

    # --auto-stop-time wins over --max-seconds (it's the human-friendly knob).
    if auto_stop_time is not None:
        config.CONFIG.max_run_seconds = int(auto_stop_time) * 60
    elif max_seconds is not None:
        config.CONFIG.max_run_seconds = max_seconds
    if max_turns is not None:
        config.CONFIG.max_turns = max_turns
    if stop_on_p1 is not None:
        config.CONFIG.stop_on_p1 = stop_on_p1
    config.CONFIG.backend = backend

    ws = Workspace(slug)
    if not ws.exists():
        ws.create(target, target_type)
    if constraints is not None:
        ws.save_constraints(constraints)

    # Persist per-target manager+worker overrides BEFORE the engine reads meta.
    # Hot-swap loop in engine picks these up each tick, so init/resume flags
    # behave identically to the dedicated `krypton manager` / `krypton model`
    # commands.
    try:
        meta_patch, override_notes = _run_overrides(
            manager_kind=manager_kind, worker_model=worker_model,
            full_codex=full_codex, current_meta=ws.load_meta())
    except ValueError as e:
        print(config_err(str(e)))
        return 1
    if meta_patch:
        ws.update_meta(**meta_patch)
        for note in override_notes:
            print(note)
        if "manager_kind" in meta_patch:
            if meta_patch["manager_kind"] == "claude":
                print("Manager set to 'claude' "
                      "(codex will only do severity validation in claude mode).")
            else:
                print("Manager set to 'codex' "
                      "(codex drives directive/chat and severity validation).")
        if "manager_model" in meta_patch or "manager_effort" in meta_patch:
            print(f"Codex manager set to "
                  f"{meta_patch.get('manager_model') or '(config default)'!r} / "
                  f"{meta_patch.get('manager_effort') or config.MANAGER_EFFORT!r}.")
        if "worker_model" in meta_patch:
            print(f"Worker model set to {meta_patch['worker_model']!r}.")
        if meta_patch.get("worker_kind") == "codex":
            print("Worker backend set to 'codex' (Kryptex/Codex worker; Claude Init 0 is not used).")

    renderer = Renderer()
    engine = Engine(ws.slug, backend=backend, emit=renderer.emit)

    async def main():
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda: engine.request_stop("signal"))
            except (NotImplementedError, RuntimeError):
                pass
        await engine.setup(brief=brief, target=target, target_type=target_type,
                           fresh_clone=fresh_clone)
        await interact(engine)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
    return 0


def cmd_init(ns) -> int:
    if (ns.backend == "real" and not getattr(ns, "full_codex", False)
            and not _ensure_init0(
                ns.session, session_id=ns.session_id, session_file=ns.session_file)):
        return 1
    slug = config.slugify(ns.target)
    constraints = _build_constraints(ns)
    print(f"Initializing target {slug!r} (type={ns.type}, backend={ns.backend}).")
    return _run_engagement(
        slug, brief=ns.brief or "", target=ns.target, target_type=ns.type,
        backend=ns.backend, fresh_clone=not ns.no_fresh, constraints=constraints,
        max_seconds=ns.max_seconds, max_turns=ns.max_turns, stop_on_p1=ns.stop_on_p1,
        auto_stop_time=ns.auto_stop_time,
        manager_kind=getattr(ns, "manager", None),
        worker_model=getattr(ns, "worker_model", None),
        full_codex=getattr(ns, "full_codex", False))


def cmd_resume(ns) -> int:
    slug = config.slugify(ns.target)
    ws = Workspace(slug)
    if not ws.exists():
        print(config_err(f"No target {slug!r}. Use `krypton init {ns.target}` first."))
        return 1
    meta = ws.load_meta()
    worker_kind = (getattr(meta, "worker_kind", "") or "claude").strip().lower()
    print(f"Resuming target {slug!r} (worker {worker_kind}:{meta.worker_uuid or '?'}).")
    return _run_engagement(
        slug, brief=ns.brief or "", target=meta.target, target_type=meta.target_type,
        backend=ns.backend, fresh_clone=False,
        max_seconds=ns.max_seconds, max_turns=ns.max_turns, stop_on_p1=ns.stop_on_p1,
        auto_stop_time=ns.auto_stop_time,
        manager_kind=getattr(ns, "manager", None),
        worker_model=getattr(ns, "worker_model", None),
        full_codex=getattr(ns, "full_codex", False))


def cmd_status(ns) -> int:
    targets = [config.slugify(ns.target)] if ns.target else list_targets()
    if not targets:
        print("No targets yet.")
        return 0
    for slug in targets:
        ws = Workspace(slug)
        if not ws.exists():
            print(f"{slug}: (missing)")
            continue
        m = ws.load_meta()
        worker_kind = (getattr(m, "worker_kind", "") or "claude").strip().lower()
        print(f"{slug}: status={m.status} type={m.target_type} turns={m.turn_index} "
              f"findings={len(ws.findings.all())} surface={len(ws.surface.all())} "
              f"P1s={len(ws.confirmed_p1s())} worker={worker_kind}:{m.worker_uuid or '-'}")
    return 0


def cmd_stop(ns) -> int:
    ws = Workspace(config.slugify(ns.target))
    if not ws.exists():
        print(config_err(f"No target {ns.target!r}."))
        return 1
    (ws.root / ".ledger").mkdir(parents=True, exist_ok=True)
    (ws.root / ".ledger" / "STOP").write_text("stop")
    print(f"Stop flag set for {ws.slug}. A running engine will stop after the current turn.")
    return 0


def cmd_model(ns) -> int:
    """Set the worker model for a target — applies MID-SESSION (no engine
    restart) to a running engine that has the hot-swap loop. Engines started
    before the feature shipped need one restart to pick it up."""
    slug = config.slugify(ns.target)
    ws = Workspace(slug)
    if not ws.exists():
        print(config_err(f"No target {slug!r}."))
        return 1
    current = ws.load_meta()
    if (getattr(current, "worker_kind", "") or "").strip().lower() == "codex":
        model = ns.model.strip()
        if (model.lower() in config.WORKER_MODEL_ALIASES
                or model.lower().startswith("claude-")):
            print(config_err("this target uses a Codex worker; pass a Codex model id, not a Claude worker alias"))
            return 1
    else:
        model = config.resolve_worker_model(ns.model)
    meta = ws.update_meta(worker_model=model)
    (ws.root / ".ledger").mkdir(parents=True, exist_ok=True)
    (ws.root / ".ledger" / "RESTART_WORKER").write_text("swap")
    print(f"Set worker_model = {model!r} for {slug}.")
    print("RESTART_WORKER flag written → a running engine (with the hot-swap loop) "
          "will restart its worker on the new model on the next loop tick.")
    print("If the engine is on older code, you'll need to "
          f"`./krypton stop {slug}` + `./krypton resume {slug}` once.")
    return 0


def cmd_manager(ns) -> int:
    """Switch the Kryptex manager kind mid-engagement. No process restart —
    the engine reads `meta.manager_kind` each tick. `claude` runs Claude for
    direct + chat and reserves Codex for severity validation only."""
    slug = config.slugify(ns.target)
    ws = Workspace(slug)
    if not ws.exists():
        print(config_err(f"No target {slug!r}."))
        return 1
    kind = ns.kind.strip().lower()
    if kind not in ("codex", "claude"):
        print(config_err(f"manager kind must be 'codex' or 'claude', got {ns.kind!r}"))
        return 1
    ws.update_meta(manager_kind=kind)
    print(f"Set manager_kind = {kind!r} for {slug}.")
    if kind == "claude":
        print("Codex will only handle severity validation from the next turn; "
              "direct + chat go through Claude.")
    else:
        print("Codex will drive direct + chat from the next turn (Claude is the fallback).")
    return 0


def cmd_doctor(ns) -> int:
    import os
    import shutil
    print("Krypton doctor\n" + "=" * 40)
    rows = []

    def chk(name, ok, detail=""):
        rows.append((name, "OK" if ok else "MISSING", detail))

    claude = config.find_binary("claude")
    codex = config.find_binary("codex")
    chk("claude", bool(claude), claude or "")
    chk("codex", bool(codex), codex or "")
    chk("python3", True, sys.version.split()[0])
    chk("curl", bool(config.find_binary("curl")))
    chk("Goja binary", (config.GOJA_DIR / "bin" / "goja-proxy").exists(),
        str(config.GOJA_DIR / "bin" / "goja-proxy"))
    chk("httpx", bool(config.find_binary("httpx")), "(auto-installs on first use)")
    chk("chromium", bool(config.find_binary("chromium") or config.find_binary("chromium-browser")),
        "(install for browser tool)")
    chk("Claude creds", (config.CLAUDE_HOME / ".credentials.json").exists())
    chk("Codex auth", (config.CODEX_HOME / "auth.json").exists())
    chk("Init 0 frozen", sessions.init0_exists(),
        sessions.init0_manifest()["orig_uuid"] if sessions.init0_exists() else "(run krypton freeze)")
    # egress
    egress = False
    try:
        import urllib.request
        urllib.request.urlopen("https://example.com", timeout=8)
        egress = True
    except Exception:
        pass
    chk("Internet egress", egress)
    total, used, free = shutil.disk_usage("/")
    chk("Disk free", free > 5 << 30, f"{free // (1<<30)} GiB free")

    width = max(len(r[0]) for r in rows)
    for name, status, detail in rows:
        mark = "\033[32m[OK]\033[0m" if status == "OK" else "\033[31m[--]\033[0m"
        print(f"  {mark} {name.ljust(width)}  {status}  {detail}")
    return 0


def cmd_test(ns) -> int:
    import subprocess
    runner = config.KRYPTON_HOME / "tests" / "run_all.py"
    if not runner.exists():
        print(config_err(f"test runner missing: {runner}"))
        return 1
    return subprocess.call([sys.executable, str(runner)])


def cmd_tool(ns, extra) -> int:
    from .toolserver import cli_main
    return cli_main(extra)


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="krypton",
        description="Krypton — autonomous, non-stop bug-bounty hunter (Codex manages Claude).")
    sub = p.add_subparsers(dest="cmd", required=True)

    def scope_args(sp):
        sp.add_argument("--only", default="", help="Only these severities, e.g. P1,P2")
        sp.add_argument("--exclude", default="", help="Excluded vuln classes, e.g. CORS,clickjacking")
        sp.add_argument("--include", default="", help="Focus only on these classes")
        sp.add_argument("--in-scope", dest="in_scope", default="", help="In-scope hosts/paths (csv)")
        sp.add_argument("--out-scope", dest="out_scope", default="", help="Out-of-scope (csv)")
        sp.add_argument("--rule", action="append", help="Free-form binding rule (repeatable)")

    def session_args(sp):
        sp.add_argument("--session", default=config.DEFAULT_INIT0_RESUME_TERM,
                        help="Resume search term for the Init 0 source session")
        sp.add_argument("--session-id", default=None, help="Exact Claude session UUID")
        sp.add_argument("--session-file", default=None, help="Path to a session .jsonl")

    def run_args(sp):
        sp.add_argument("--backend", choices=["real", "mock"], default="real")
        sp.add_argument("--max-seconds", type=int, default=None,
                        help="Safety ceiling on run time in seconds (0/None = unbounded)")
        sp.add_argument("--auto-stop-time", type=int, default=None,
                        help="Auto-stop after N MINUTES (no default; sets max_run_seconds=N*60)")
        sp.add_argument("--max-turns", type=int, default=None,
                        help="Safety ceiling on number of turns (0/None = unbounded)")
        sp.add_argument("--stop-on-p1", action="store_true", default=None,
                        help="Stop when a P1 is confirmed (default: keep hunting)")
        sp.add_argument("--manager", choices=["codex", "claude"], default=None,
                        help="Which model drives Kryptex (default: codex). "
                             "'claude' runs Claude for direct+chat; codex is then "
                             "used ONLY for severity validation.")
        sp.add_argument("--full-codex", action="store_true",
                        help="Force Kryptex fully onto Codex gpt-5.5 at xhigh: "
                             "directive/chat, severity validation, and worker execution "
                             "all use Codex.")
        sp.add_argument("--worker-model", dest="worker_model", default=None,
                        help="Override the Kraude worker model (default: "
                             "claude-sonnet-5). Accepts a full id (e.g. "
                             "claude-sonnet-5, claude-opus-4-8) OR a shortcut: "
                             "opus | sonnet | sonnet5 | sonnet46 | haiku.")

    sp = sub.add_parser("init", help="Initialize & start a target (clones Init 0).")
    sp.add_argument("target")
    sp.add_argument("-m", "--brief", default="", help="Mission brief for the manager")
    sp.add_argument("--type", default="auto",
                    choices=["auto", "web", "apk", "network", "cidr", "binary", "contract"])
    sp.add_argument("--no-fresh", action="store_true", help="Reuse an existing clone if present")
    scope_args(sp); session_args(sp); run_args(sp)
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("resume", help="Resume an existing target.")
    sp.add_argument("target")
    sp.add_argument("-m", "--brief", default="", help="Optional new instruction on resume")
    run_args(sp)
    sp.set_defaults(func=cmd_resume)

    sp = sub.add_parser("freeze", help="Freeze the Init 0 snapshot from the live session.")
    session_args(sp)
    sp.add_argument("--force", action="store_true")
    sp.add_argument("--pick", type=int, default=0, help="Pick the Nth candidate (default 0)")
    sp.set_defaults(func=cmd_freeze)

    sp = sub.add_parser("sessions", help="List resolvable sessions and Init 0 status.")
    sp.add_argument("--session", default=config.DEFAULT_INIT0_RESUME_TERM)
    sp.set_defaults(func=cmd_sessions)

    sp = sub.add_parser("status", help="Show target status.")
    sp.add_argument("target", nargs="?")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("stop", help="Signal a running engagement to stop.")
    sp.add_argument("target")
    sp.set_defaults(func=cmd_stop)

    sp = sub.add_parser("model", help="Set/swap the worker model for a target.")
    sp.add_argument("target")
    sp.add_argument("model",
                    help="Full id (claude-opus-4-8, claude-sonnet-5, "
                         "claude-haiku-4-5-20251001, claude-opus-4-7) OR a "
                         "shortcut: opus | sonnet | sonnet5 | sonnet46 | haiku.")
    sp.set_defaults(func=cmd_model)

    sp = sub.add_parser("manager",
                        help="Switch the Kryptex manager kind (codex|claude). "
                             "Mid-engagement, no restart.")
    sp.add_argument("target")
    sp.add_argument("kind", choices=["codex", "claude"],
                    help="'codex' = Codex drives direct+chat, Claude is fallback. "
                         "'claude' = Claude drives direct+chat; Codex used only "
                         "for severity validation.")
    sp.set_defaults(func=cmd_manager)

    sp = sub.add_parser("doctor", help="Check the environment.")
    sp.set_defaults(func=cmd_doctor)

    sp = sub.add_parser("test", help="Run the offline end-to-end test suite.")
    sp.set_defaults(func=cmd_test)

    sp = sub.add_parser("tool", help="Run a Krypton tool (delegates to krypton-tool).")
    sp.set_defaults(func=cmd_tool)

    return p


def main(argv=None) -> int:
    # Line-buffer stdout so live output is visible immediately even when piped
    # or redirected (Python block-buffers a non-TTY by default).
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    argv = list(sys.argv[1:] if argv is None else argv)
    # `krypton tool ...` passes the remainder straight through.
    if argv and argv[0] == "tool":
        from .toolserver import cli_main
        return cli_main(argv[1:])
    parser = build_parser()
    ns = parser.parse_args(argv)
    try:
        return ns.func(ns)
    except sessions.IsolationError as e:
        print(config_err(str(e)))
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
