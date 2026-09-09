#!/usr/bin/env python3
"""Live integration smoke tests (make REAL, paid model calls — run explicitly).

Validates the two integration seams the offline suite can't:
  * worker.py  → drives the real `claude` in stream-json, resuming a session.
  * manager.py → drives the real `codex` to emit a schema-constrained directive.

Uses cheap settings (small model / low effort) since it only checks plumbing.
    python3 tests/live_smoke.py [worker|manager|all]
"""
import asyncio
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from krypton import config  # noqa: E402

CHEAP_CLAUDE = os.environ.get("KRYPTON_SMOKE_CLAUDE_MODEL", "claude-haiku-4-5-20251001")


def smoke_worker() -> bool:
    print("\n== LIVE worker (claude stream-json resume) ==")
    from krypton.worker import KraudeWorker, WorkerSpec

    claude = config.find_binary("claude")
    if not claude:
        print("  SKIP: claude not found")
        return True
    tmp = Path(tempfile.mkdtemp(prefix="krypton-smoke-worker-"))
    sid = str(uuid.uuid4())
    # 1) materialise a fresh tiny session with a codeword to recall on resume.
    create = subprocess.run(
        [claude, "-p", "--session-id", sid, "--model", CHEAP_CLAUDE,
         "--dangerously-skip-permissions",
         "Remember this codeword for later: BANANA42. Reply with just: OK"],
        cwd=str(tmp), capture_output=True, text=True, timeout=180)
    print(f"  create rc={create.returncode} out={create.stdout.strip()[:80]!r}")
    if create.returncode != 0:
        print(f"  FAIL: could not create session. stderr: {create.stderr[-300:]}")
        return False

    # 2) resume it via the real worker driver and recall the codeword.
    async def run():
        spec = WorkerSpec(session_uuid=sid, cwd=tmp,
                          system_prompt="You are a terse test worker.",
                          model=CHEAP_CLAUDE, effort="low", turn_timeout_s=180,
                          log_path=tmp / "stream.jsonl")
        w = KraudeWorker(spec)
        await w.start()
        try:
            t = await w.run_turn("What was the codeword I told you? Reply with just the word.")
            return t
        finally:
            await w.aclose()

    try:
        turn = asyncio.run(run())
    except Exception as e:
        print(f"  FAIL: worker run errored: {e}")
        return False
    ok = "BANANA42" in (turn.assistant_text or "").upper()
    print(f"  worker replied: {turn.assistant_text!r}")
    print(f"  result: is_error={turn.is_error} num_turns={turn.num_turns} cost=${turn.cost_usd:.4f}")
    print(f"  {'PASS' if ok else 'FAIL'}: stream-json resume + multi-turn I/O")
    return ok


def smoke_manager() -> bool:
    print("\n== LIVE manager (codex structured directive) ==")
    from krypton.manager import KryptexManager, ManagerContext
    from krypton.workspace import Workspace

    codex = config.find_binary("codex")
    if not codex:
        print("  SKIP: codex not found")
        return True
    config.MANAGER_EFFORT = "low"  # keep it fast/cheap for the smoke
    tmpslug = "smoke-mgr"
    ws = Workspace(tmpslug)
    if not ws.exists():
        ws.create("https://smoke.example", "web")
    mgr = KryptexManager(ws, system_prompt=(
        "You are Kryptex, a bug-bounty manager. Return ONLY the JSON directive."))
    ctx = ManagerContext(
        target="https://smoke.example", target_type="web", turn_index=1,
        constraints_block="(no special constraints)",
        worker_last_text="(engagement start) Give the opening move: where to begin recon.",
        surface_summary="(empty)", findings_summary="(none)")

    async def run():
        return await mgr.direct(ctx)

    try:
        d = asyncio.run(run())
    except Exception as e:
        print(f"  FAIL: manager errored: {e}")
        return False
    print(f"  codex session id: {mgr.session_id}")
    print(f"  directive: {d.directive[:160]!r}")
    print(f"  to_user: {d.to_user[:120]!r}  continue={d.cont}  degraded={d.degraded}")
    ok = bool(d.directive.strip()) and d.cont and not d.degraded
    print(f"  {'PASS' if ok else 'FAIL'}: codex emitted a usable structured directive")
    return ok


def smoke_fallback() -> bool:
    print("\n== LIVE Claude fallback manager (codex stand-in) ==")
    import json as _json
    from krypton.manager import KryptexManager
    from krypton.workspace import Workspace
    claude = config.find_binary("claude")
    if not claude:
        print("  SKIP: claude not found")
        return True
    slug = "fb-live-smoke"
    ws = Workspace(slug)
    if ws.exists():
        import shutil; shutil.rmtree(ws.root)
    ws.create("https://example.com", "web")
    mgr = KryptexManager(ws, system_prompt=(
        "You are Kryptex, a bug-bounty manager. Return ONLY the JSON directive."))
    schema = _json.loads((config.PROMPTS_DIR / "directive_schema.json").read_text())
    prompt = ("Engagement start on https://example.com. Give the opening JSON directive: "
              "first move should be light recon (headers + robots.txt). Be concrete.")

    async def run():
        # Call the fallback runner directly — this is what kicks in when codex fails
        return await mgr._run_claude_fallback(prompt, schema_dict=schema, timeout=240)

    try:
        data = asyncio.run(run())
    except Exception as e:
        print(f"  FAIL: fallback raised: {e}")
        return False
    print(f"  directive    : {(data.get('directive') or '')[:160]!r}")
    print(f"  assessment   : {(data.get('assessment') or '')[:100]!r}")
    print(f"  continue     : {data.get('continue')}")
    sid = ws.load_meta().fallback_manager_session_id
    print(f"  fallback sid : {sid}")
    # second call should resume the same session (continuity across fallback turns)
    try:
        data2 = asyncio.run(run())
    except Exception as e:
        print(f"  FAIL: second call raised: {e}")
        return False
    ok = (bool(data and data.get("directive") and data.get("continue") is True)
          and bool(data2 and data2.get("directive"))
          and bool(sid))
    print(f"  second-call directive: {(data2.get('directive') or '')[:80]!r}")
    print(f"  RESULT: {'PASS — Claude fallback produces a valid directive + session continuity' if ok else 'FAIL'}")
    import shutil; shutil.rmtree(ws.root, ignore_errors=True)
    return ok


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    results = {}
    if which in ("worker", "all"):
        results["worker"] = smoke_worker()
    if which in ("manager", "all"):
        results["manager"] = smoke_manager()
    if which in ("fallback", "all"):
        results["fallback"] = smoke_fallback()
    print("\n== SMOKE SUMMARY ==")
    for k, v in results.items():
        print(f"  {k}: {'PASS' if v else 'FAIL'}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
