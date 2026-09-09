"""Session resolution, Init 0 freezing, and isolated cloning.

This is the safety-critical core of Krypton's isolation guarantee (R5–R7, I1–I2):

  * ``resolve_named_session`` finds the live Claude session the user names
    (e.g. ``bitpanda-graphql-security-assessment``) without opening it writably.
  * ``freeze_init0`` makes a read-only, checksummed snapshot of that session —
    transcript + the entire sidecar tree (subagents/, tool-results/). This is the
    canonical, immutable "Init 0" state.
  * ``clone_for_target`` derives a fully self-consistent, isolated copy of Init 0
    for a single hunt: a fresh UUID and project dir, with every internal absolute
    path and UUID reference rewritten so the clone references only itself.

The original session and the Init 0 snapshot are NEVER opened by a writable
``claude`` process and are never mutated by Krypton after the initial copy.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
import uuid as _uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from . import config

MANIFEST_PATH = config.INIT0_DIR / "manifest.json"
_READONLY_FILE = 0o444
_READONLY_DIR = 0o555


# --------------------------------------------------------------------------
# Data structures
# --------------------------------------------------------------------------


@dataclass
class SessionRef:
    """A resolved top-level Claude session on disk."""

    uuid: str
    project_dir: str            # e.g. "-root"
    main_jsonl: Path            # .../projects/<project_dir>/<uuid>.jsonl
    sidecar_dir: Path           # .../projects/<project_dir>/<uuid>   (may not exist)
    size_bytes: int
    mtime: float
    match_score: float = 0.0

    @property
    def sidecar_abs_prefix(self) -> str:
        return f"{self.sidecar_dir}/"


@dataclass
class CloneResult:
    """The product of cloning Init 0 for one target."""

    new_uuid: str
    new_project_dir: str
    main_jsonl: Path
    sidecar_dir: Path
    worker_cwd: Path
    source_manifest: dict


class IsolationError(RuntimeError):
    """Raised when an operation would violate session isolation (I1/I2)."""


# --------------------------------------------------------------------------
# Hashing / sizing helpers
# --------------------------------------------------------------------------


def _sha256(path: Path, _buf: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(_buf), b""):
            h.update(chunk)
    return h.hexdigest()


def _fmt_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == "TB":
            return f"{f:.0f}{u}" if u == "B" else f"{f:.1f}{u}"
        f /= 1024
    return f"{n}B"


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------


def _iter_top_level_sessions():
    """Yield (uuid, project_dir, jsonl_path) for every top-level session file,
    skipping subagent/auto-compact sidecar transcripts."""
    root = config.CLAUDE_PROJECTS_DIR
    if not root.exists():
        return
    for proj in sorted(root.iterdir()):
        if not proj.is_dir():
            continue
        for jsonl in proj.glob("*.jsonl"):
            stem = jsonl.stem
            # Top-level sessions are UUID-named; sidecar files live one level deeper.
            yield stem, proj.name, jsonl


def _grep_contains(path: Path, term: str, fixed: bool = True) -> bool:
    """Fast early-exit substring test using system grep (streams, stops at 1st hit)."""
    grep = shutil.which("grep")
    if not grep:
        # Fallback: bounded pure-python scan (first 4 MB) for small/medium files.
        try:
            with path.open("rb") as f:
                blob = f.read(4 << 20)
            return term.encode("utf-8", "ignore").lower() in blob.lower()
        except OSError:
            return False
    flags = ["-l", "-m1", "-i"]
    if fixed:
        flags.append("-F")
    try:
        r = subprocess.run(
            [grep, *flags, "-e", term, str(path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120,
        )
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def resolve_named_session(
    term: str,
    *,
    session_id: Optional[str] = None,
    session_file: Optional[str] = None,
    limit: int = 8,
) -> list[SessionRef]:
    """Resolve the session(s) matching a resume term, ranked best-first.

    Resolution precedence:
      1. explicit ``session_file`` path,
      2. explicit ``session_id`` (exact UUID filename),
      3. content search for ``term`` across all top-level sessions, ranked by
         (filename-exact, content-match, size, recency). Mirrors what
         ``claude --resume "<term>"`` would surface, biased to the largest match
         (the user's Init 0 is the 200 MB+ session).
    """
    # 1) explicit file
    if session_file:
        p = Path(session_file).resolve()
        if not p.exists():
            raise FileNotFoundError(f"--session-file not found: {p}")
        return [_ref_from_path(p, score=10_000)]

    # 2) explicit uuid
    if session_id:
        for stem, proj, jsonl in _iter_top_level_sessions():
            if stem == session_id:
                return [_ref_from_path(jsonl, score=10_000)]
        raise FileNotFoundError(f"No session file named {session_id}.jsonl under {config.CLAUDE_PROJECTS_DIR}")

    # 3) search
    candidates: list[SessionRef] = []
    term_norm = term.strip()
    for stem, proj, jsonl in _iter_top_level_sessions():
        try:
            st = jsonl.stat()
        except OSError:
            continue
        score = 0.0
        if stem == term_norm:
            score += 10_000
        # content match (literal first, then relaxed word-AND if needed)
        matched = _grep_contains(jsonl, term_norm, fixed=True)
        if matched:
            score += 1000
        if score == 0:
            continue
        # size & recency weighting (favour the big, pre-trained session)
        score += min(st.st_size / (1024 * 1024), 1000)  # +1 per MB, capped
        score += max(0.0, 50 - (time.time() - st.st_mtime) / 86400)  # recency, days
        candidates.append(_ref_from_path(jsonl, score=score, stat=st))

    if not candidates:
        # relaxed: split term into words, require all present
        words = [w for w in __import__("re").split(r"[^A-Za-z0-9]+", term_norm) if len(w) > 2]
        for stem, proj, jsonl in _iter_top_level_sessions():
            if words and all(_grep_contains(jsonl, w, fixed=True) for w in words):
                try:
                    st = jsonl.stat()
                except OSError:
                    continue
                score = 500 + min(st.st_size / (1024 * 1024), 1000)
                candidates.append(_ref_from_path(jsonl, score=score, stat=st))

    candidates.sort(key=lambda r: r.match_score, reverse=True)
    return candidates[:limit]


def _ref_from_path(jsonl: Path, score: float = 0.0, stat: Optional[os.stat_result] = None) -> SessionRef:
    st = stat or jsonl.stat()
    return SessionRef(
        uuid=jsonl.stem,
        project_dir=jsonl.parent.name,
        main_jsonl=jsonl,
        sidecar_dir=jsonl.parent / jsonl.stem,
        size_bytes=st.st_size,
        mtime=st.st_mtime,
        match_score=score,
    )


# --------------------------------------------------------------------------
# Freezing Init 0
# --------------------------------------------------------------------------


def init0_exists() -> bool:
    return MANIFEST_PATH.exists()


def init0_manifest() -> dict:
    if not MANIFEST_PATH.exists():
        raise IsolationError("Init 0 is not frozen yet. Run `krypton freeze` first.")
    return json.loads(MANIFEST_PATH.read_text())


def _set_tree_readonly(root: Path) -> None:
    if root.is_file():
        os.chmod(root, _READONLY_FILE)
        return
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            try:
                os.chmod(Path(dirpath) / fn, _READONLY_FILE)
            except OSError:
                pass
        try:
            os.chmod(dirpath, _READONLY_DIR)
        except OSError:
            pass


def _set_tree_writable(root: Path) -> None:
    """Used only to re-freeze (``--force``): make the old snapshot deletable."""
    for dirpath, dirnames, filenames in os.walk(root):
        try:
            os.chmod(dirpath, 0o755)
        except OSError:
            pass
        for fn in filenames:
            try:
                os.chmod(Path(dirpath) / fn, 0o644)
            except OSError:
                pass


def freeze_init0(ref: SessionRef, *, force: bool = False, progress=lambda *_: None) -> dict:
    """Create the immutable Init 0 snapshot from a resolved live session.

    Reads (copies) the original; never writes to it. The snapshot and its
    manifest are made read-only (0444/0555). Returns the manifest dict.
    """
    config.ensure_layout()

    if init0_exists() and not force:
        raise IsolationError(
            "Init 0 already frozen. Use `krypton freeze --force` to replace it."
        )

    if config.INIT0_DIR.exists():
        _set_tree_writable(config.INIT0_DIR)
        shutil.rmtree(config.INIT0_DIR)
    config.INIT0_DIR.mkdir(parents=True, exist_ok=True)

    if not ref.main_jsonl.exists():
        raise FileNotFoundError(f"Source transcript missing: {ref.main_jsonl}")

    # 1) Copy the main transcript verbatim.
    progress(f"Copying transcript {ref.uuid} ({_fmt_size(ref.size_bytes)})…")
    frozen_main = config.INIT0_DIR / f"{ref.uuid}.jsonl"
    shutil.copy2(ref.main_jsonl, frozen_main)

    # 2) Copy the entire sidecar tree (subagents/, tool-results/), if present.
    sidecar_files = 0
    frozen_sidecar = config.INIT0_DIR / ref.uuid
    if ref.sidecar_dir.exists():
        progress(f"Copying sidecar tree ({_fmt_size(_dir_size(ref.sidecar_dir))})…")
        shutil.copytree(ref.sidecar_dir, frozen_sidecar)
        sidecar_files = sum(1 for _ in frozen_sidecar.rglob("*") if _.is_file())

    # 3) Checksum and write the manifest.
    progress("Hashing snapshot…")
    main_sha = _sha256(frozen_main)
    manifest = {
        "schema": 1,
        "created_at": time.time(),
        "created_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "orig_uuid": ref.uuid,
        "orig_project_dir": ref.project_dir,
        "orig_main_jsonl": str(ref.main_jsonl),
        "orig_sidecar_dir": str(ref.sidecar_dir),
        "orig_sidecar_abs_prefix": ref.sidecar_abs_prefix,
        "main_jsonl_bytes": frozen_main.stat().st_size,
        "main_jsonl_sha256": main_sha,
        "sidecar_files": sidecar_files,
        "frozen_main": str(frozen_main),
        "frozen_sidecar": str(frozen_sidecar),
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))

    # 4) Lock the snapshot read-only.
    progress("Locking snapshot read-only…")
    _set_tree_readonly(frozen_main)
    if frozen_sidecar.exists():
        _set_tree_readonly(frozen_sidecar)
    os.chmod(MANIFEST_PATH, _READONLY_FILE)
    return manifest


def verify_init0() -> bool:
    """Re-hash the frozen transcript and confirm it matches the manifest."""
    m = init0_manifest()
    frozen_main = Path(m["frozen_main"])
    if not frozen_main.exists():
        raise IsolationError("Init 0 transcript missing from snapshot.")
    return _sha256(frozen_main) == m["main_jsonl_sha256"]


def _dir_size(root: Path) -> int:
    return sum(f.stat().st_size for f in root.rglob("*") if f.is_file())


# --------------------------------------------------------------------------
# Cloning Init 0 for a target (isolated)
# --------------------------------------------------------------------------


def _rewrite_jsonl(src: Path, dst: Path, replacements: list[tuple[bytes, bytes]]) -> None:
    """Stream-copy a JSONL applying ordered byte replacements per line.

    Byte-level (not text) to guarantee the transcript round-trips exactly except
    for the targeted UUID/path rewrites — no unicode re-encoding artefacts.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open("rb") as fi, dst.open("wb") as fo:
        for line in fi:
            for old, new in replacements:
                if old in line:
                    line = line.replace(old, new)
            fo.write(line)


def clone_for_target(
    target_slug: str,
    *,
    worker_cwd: Optional[Path] = None,
    progress=lambda *_: None,
) -> CloneResult:
    """Produce an isolated, self-consistent clone of Init 0 for ``target_slug``.

    Steps:
      1. Allocate a fresh UUID and compute the clone's project dir from the
         worker's cwd (so ``claude --resume <uuid>`` finds it).
      2. Stream-rewrite the transcript: original sidecar absolute-path prefix →
         clone prefix, then original UUID → new UUID.
      3. Rewrite every subagent transcript identically; copy tool-result blobs
         verbatim. The result references only itself.
    """
    m = init0_manifest()
    orig_uuid: str = m["orig_uuid"]
    orig_prefix: str = m["orig_sidecar_abs_prefix"]
    frozen_main = Path(m["frozen_main"])
    frozen_sidecar = Path(m["frozen_sidecar"])

    if not frozen_main.exists():
        raise IsolationError("Init 0 snapshot is incomplete; re-run `krypton freeze`.")

    worker_cwd = Path(worker_cwd or (config.TARGETS_DIR / target_slug)).resolve()
    worker_cwd.mkdir(parents=True, exist_ok=True)

    new_uuid = str(_uuid.uuid4())
    new_project_dir = config.encode_project_dir(worker_cwd)
    proj_path = config.CLAUDE_PROJECTS_DIR / new_project_dir
    proj_path.mkdir(parents=True, exist_ok=True)

    new_main = proj_path / f"{new_uuid}.jsonl"
    new_sidecar = proj_path / new_uuid
    new_prefix = f"{new_sidecar}/"

    # Guard: never write inside the original project dir or the frozen snapshot.
    _assert_write_safe(new_main, m)
    _assert_write_safe(new_sidecar, m)

    replacements = [
        (orig_prefix.encode(), new_prefix.encode()),   # longer/more specific first
        (orig_uuid.encode(), new_uuid.encode()),
    ]

    progress(f"Rewriting transcript → {new_uuid} …")
    _rewrite_jsonl(frozen_main, new_main, replacements)

    if frozen_sidecar.exists():
        progress("Rewriting sidecar (subagents) & copying tool-results…")
        for item in frozen_sidecar.rglob("*"):
            rel = item.relative_to(frozen_sidecar)
            target = new_sidecar / rel
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            elif item.suffix == ".jsonl":
                _rewrite_jsonl(item, target, replacements)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, target)

    progress("Clone ready.")
    return CloneResult(
        new_uuid=new_uuid,
        new_project_dir=new_project_dir,
        main_jsonl=new_main,
        sidecar_dir=new_sidecar,
        worker_cwd=worker_cwd,
        source_manifest=m,
    )


def _assert_write_safe(path: Path, manifest: dict) -> None:
    """Refuse any write that would land in the original project dir or Init 0 (I1/I2)."""
    p = str(path.resolve())
    orig_proj = str((config.CLAUDE_PROJECTS_DIR / manifest["orig_project_dir"]).resolve())
    if p.startswith(orig_proj + os.sep) or p == orig_proj:
        raise IsolationError(f"Refusing to write inside original session project dir: {p}")
    if p.startswith(str(config.INIT0_DIR.resolve()) + os.sep):
        raise IsolationError(f"Refusing to write inside the frozen Init 0 snapshot: {p}")


# --------------------------------------------------------------------------
# Session rewind — edit the worker's history when a directive was refused
# --------------------------------------------------------------------------


def _is_user_typed_message(obj: dict) -> bool:
    """True if a session-jsonl entry is a *typed* user message (not a tool_result
    echo). Used to find the boundary of "the last user→assistant turn"."""
    if obj.get("type") != "user":
        return False
    msg = obj.get("message") or {}
    if msg.get("role") != "user":
        return False
    content = msg.get("content")
    if isinstance(content, str):
        return True
    if isinstance(content, list):
        return any(isinstance(c, dict) and c.get("type") == "text" for c in content)
    return False


def _assistant_pair_has_tool_use(lines, user_idx) -> bool:
    """Did the assistant response immediately following the user-typed line at
    ``user_idx`` contain at least one tool_use block? (i.e. a productive turn)"""
    for j in range(user_idx + 1, len(lines)):
        s = lines[j].strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except ValueError:
            continue
        # Stop at the next user-typed message (boundary of this turn)
        if _is_user_typed_message(obj):
            break
        if obj.get("type") == "assistant":
            content = (obj.get("message") or {}).get("content") or []
            for block in content if isinstance(content, list) else []:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    return True
    return False


def rewind_idle_tail(jsonl_path: Path, max_pairs: int = 200) -> int:
    """Strip the *entire tail of consecutive idle (no-tool-use) turns* from the
    session JSONL — back to the last productive turn (one with ≥1 tool_use).

    This is the deep version of ``rewind_last_user_turn``: it removes not just
    the most recent refusal but the whole anchored refusal streak that bakes a
    "we're done" worldview into the session memory. Returns the number of pairs
    removed (0 if the most recent turn was already productive).
    """
    if not jsonl_path.exists():
        return 0
    try:
        raw = jsonl_path.read_bytes()
    except OSError:
        return 0
    if not raw:
        return 0
    lines = raw.splitlines(keepends=True)
    removed = 0
    for _ in range(max_pairs):
        last_user_idx = -1
        for i in range(len(lines) - 1, -1, -1):
            s = lines[i].strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
            except ValueError:
                continue
            if _is_user_typed_message(obj):
                last_user_idx = i
                break
        if last_user_idx < 0:
            break
        if _assistant_pair_has_tool_use(lines, last_user_idx):
            break              # most recent turn is productive — stop
        lines = lines[:last_user_idx]
        removed += 1
    if removed > 0:
        new_data = b"".join(lines)
        tmp = jsonl_path.with_suffix(jsonl_path.suffix + ".tmp")
        tmp.write_bytes(new_data)
        os.replace(tmp, jsonl_path)
    return removed


def rewind_last_user_turn(jsonl_path: Path) -> bool:
    """Truncate ``jsonl_path`` back to JUST BEFORE the last user-typed message,
    removing that user message and everything written after it (i.e. the
    assistant's response). Returns True if a rewind happened.

    Used after the worker refused/idled on a directive: by deleting the
    refused turn from history before sending Kryptex's reframe, the worker
    never sees its own refusal and won't anchor on it.
    """
    if not jsonl_path.exists():
        return False
    try:
        raw = jsonl_path.read_bytes()
    except OSError:
        return False
    if not raw:
        return False
    lines = raw.splitlines(keepends=True)
    last_user_idx = -1
    for i in range(len(lines) - 1, -1, -1):
        s = lines[i].strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except ValueError:
            continue
        if _is_user_typed_message(obj):
            last_user_idx = i
            break
    if last_user_idx < 0:
        return False
    new_data = b"".join(lines[:last_user_idx])
    tmp = jsonl_path.with_suffix(jsonl_path.suffix + ".tmp")
    tmp.write_bytes(new_data)
    os.replace(tmp, jsonl_path)
    return True


def discard_clone(clone: CloneResult) -> None:
    """Remove a clone's transcript + sidecar (used on re-init / cleanup)."""
    for p in (clone.main_jsonl, clone.sidecar_dir):
        try:
            if p.is_dir():
                shutil.rmtree(p)
            elif p.exists():
                p.unlink()
        except OSError:
            pass
