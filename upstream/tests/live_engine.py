#!/usr/bin/env python3
"""Live FULL-LOOP integration test: real Codex managing real Claude (paid).

Proves the production path end-to-end: freeze a small Init 0 → clone it for a
target → the engine drives a real `claude` worker, a real `codex` manager directs
it, and tool/workspace wiring is live. Uses cheap settings (haiku + low effort)
and a benign target; runs 2 turns then cleans up its test Init 0 + target.

    python3 tests/live_engine.py
"""
import asyncio
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

# Cheap + safe BEFORE importing krypton (config reads these at import).
os.environ.setdefault("KRYPTON_WORKER_MODEL", "claude-haiku-4-5-20251001")
os.environ.setdefault("KRYPTON_WORKER_EFFORT", "low")
os.environ.setdefault("KRYPTON_MANAGER_EFFORT", "low")

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from krypton import config, sessions  # noqa: E402
from krypton.workspace import Workspace  # noqa: E402

BRIEF = ("AUTOMATED INTEGRATION TEST — keep it tiny and safe. Only target is "
         "https://example.com. Do at most one harmless GET to https://example.com "
         "(or just call the krypton attack_surface_add tool with item='/it-ok'). "
         "Do NOT scan, attack, or touch any other host. Keep replies to 2 sentences.")


def main() -> int:
    claude = config.find_binary("claude")
    codex = config.find_binary("codex")
    if not (claude and codex):
        print("SKIP: need both claude and codex")
        return 0

    had_init0 = sessions.init0_exists()
    backup = None
    if had_init0:  # preserve any existing (production) Init 0
        backup = config.SESSIONS_DIR / "init0.bak"
        sessions._set_tree_writable(config.INIT0_DIR)
        if backup.exists():
            sessions._set_tree_writable(backup); shutil.rmtree(backup)
        shutil.move(str(config.INIT0_DIR), str(backup))

    slug = "it-live"
    try:
        # 1) make a tiny real session to serve as a fast, safe Init 0
        sid = str(uuid.uuid4())
        seed_cwd = config.RUNTIME_DIR / "it-seed"
        seed_cwd.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(
            [claude, "-p", "--session-id", sid, "--model", config.WORKER_MODEL,
             "--dangerously-skip-permissions", "Integration-test seed session. Reply OK."],
            cwd=str(seed_cwd), capture_output=True, text=True, timeout=180)
        if r.returncode != 0:
            print(f"FAIL: seed session creation failed: {r.stderr[-300:]}")
            return 1
        # locate + freeze it as Init 0
        seed_jsonl = config.project_dir_for(seed_cwd) / f"{sid}.jsonl"
        if not seed_jsonl.exists():
            print(f"FAIL: seed transcript not found at {seed_jsonl}")
            return 1
        ref = sessions._ref_from_path(seed_jsonl)
        sessions.freeze_init0(ref, force=True, progress=lambda m: print("  ·", m))
        print("Init 0 (test) frozen.")

        # 2) run the engine for 2 real turns
        config.CONFIG.max_turns = 2
        config.CONFIG.backend = "real"
        from krypton.engine import Engine

        emits = []
        ws = Workspace(slug)
        if ws.exists():
            shutil.rmtree(ws.root)

        async def go():
            eng = Engine(slug, backend="real", emit=lambda k, **d: emits.append((k, d)))
            await eng.setup(brief=BRIEF, target="https://example.com", target_type="web",
                            fresh_clone=True)
            await eng.run()
            return eng

        eng = asyncio.run(go())

        # 3) assertions
        kinds = [k for k, _ in emits]
        worker_turns = [d for k, d in emits if k == "worker_turn"]
        mgr = [d for k, d in emits if k == "manager"]
        non_degraded = [d for d in mgr if not d.get("degraded")]
        ran = eng.turn_index >= 1
        worker_spoke = any((d.get("text") or "").strip() for d in worker_turns)
        mgr_drove = len(non_degraded) >= 1

        print("\n== LIVE ENGINE RESULTS ==")
        print(f"  turns: {eng.turn_index}")
        print(f"  worker produced text: {worker_spoke}")
        print(f"  real (non-degraded) manager directives: {len(non_degraded)}")
        print(f"  surface items logged by worker: {len(ws.surface.all())}")
        print(f"  stop reason: {eng.stop_reason}")
        ok = ran and worker_spoke and mgr_drove
        print(f"  {'PASS' if ok else 'FAIL'}: full real loop (engine ↔ claude ↔ codex)")
        return 0 if ok else 1
    finally:
        # cleanup: remove test target, test Init 0, restore any backup
        try:
            ws = Workspace(slug)
            if ws.exists():
                # also drop the cloned worker session from ~/.claude/projects
                m = ws.load_meta()
                proj = config.CLAUDE_PROJECTS_DIR / (m.worker_project_dir or "")
                shutil.rmtree(ws.root, ignore_errors=True)
        except Exception:
            pass
        try:
            if config.INIT0_DIR.exists():
                sessions._set_tree_writable(config.INIT0_DIR)
                shutil.rmtree(config.INIT0_DIR, ignore_errors=True)
            if backup and backup.exists():
                shutil.move(str(backup), str(config.INIT0_DIR))
                print("Restored pre-existing Init 0.")
        except Exception as e:
            print(f"cleanup note: {e}")


if __name__ == "__main__":
    sys.exit(main())
