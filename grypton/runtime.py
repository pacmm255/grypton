"""Private background-run supervisor for long Grypton engagements.

The supervisor deliberately keeps the engine's mission out of process arguments,
status output, and operational logs.  A private 0600 spec supplies the mission to
an internal engine child in memory.  Supervisor events contain only lifecycle and
counter data; engagement evidence remains in the normal private workspace.
"""
from __future__ import annotations

import errno
import fcntl
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time
from typing import Any

from . import config
from .finding_views import astra_confirmed_cases_at_or_above
from .workspace import Workspace


_RUN_ID_RX = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{8}$")
_SUPERVISED_RUN_ENV = "GRYPTON_SUPERVISOR_RUN_ID"
_RESTART_BACKOFF_SECONDS = (2, 4, 8, 16, 30, 60, 120, 300, 600, 900)
_SUSTAINED_ENGINE_RUNTIME_SECONDS = 300.0


@dataclass(frozen=True)
class _ProcessIdentity:
    """One Linux process identity that cannot survive numeric PID reuse."""

    pid: int
    start_time: str
    pgid: int


@dataclass(frozen=True)
class _ProcessSnapshot:
    """Identity and parentage read atomically from one procfs record."""

    identity: _ProcessIdentity
    ppid: int


_ProcessGroups = dict[int, set[_ProcessIdentity]]


def _valid_run_id(run_id: str) -> bool:
    return bool(_RUN_ID_RX.fullmatch(str(run_id or "")))


def _root(slug: str) -> Path:
    return config.RUNTIME_DIR / "supervisors" / config.slugify(slug)


def _current_path(slug: str) -> Path:
    return _root(slug) / "current.json"


def _run_dir(slug: str, run_id: str) -> Path:
    return _root(slug) / "runs" / run_id


def _paths(slug: str, run_id: str) -> dict[str, Path]:
    if not _valid_run_id(run_id):
        raise ValueError("invalid supervisor run id")
    root = _run_dir(slug, run_id)
    return {
        "root": root,
        "spec": root / "spec.json",
        "state": root / "state.json",
        "events": root / "events.jsonl",
        "supervisor_pid": root / "supervisor.pid",
        "engine_pid": root / "engine.pid",
        # An existing entry is a fail-closed signal: Kraude may have executed
        # a native OpenCode tool whose side effect is invisible to MCP ledgers.
        "provider_call_window": root / "worker-provider-call.active",
    }


def _mkdir_private(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    runtime_root = config.RUNTIME_DIR.resolve()
    current = path.resolve()
    while current == runtime_root or runtime_root in current.parents:
        os.chmod(current, 0o700)
        if current == runtime_root:
            break
        current = current.parent


def _write_text_private(path: Path, value: str) -> None:
    _mkdir_private(path.parent)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(value)
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _write_json(path: Path, value: dict[str, Any]) -> None:
    _write_text_private(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def _sync_file_and_parent(path: Path) -> None:
    """Make a small runtime marker durable across an abrupt child exit."""
    file_flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        file_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        file_flags |= os.O_NOFOLLOW
    fd = os.open(path, file_flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    parent_fd = os.open(path.parent, directory_flags)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _create_provider_call_marker(path: Path, value: dict[str, Any]) -> None:
    """Create and sync a marker without replacing an earlier active window."""
    _mkdir_private(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        # A partial entry remains active by design; completion cannot remove it
        # without reading the expected nonce from a complete regular file.
        raise
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    parent_fd = os.open(path.parent, directory_flags)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _read_provider_call_marker(path: Path) -> dict[str, Any]:
    """Read one regular marker without following a worker-created symlink."""
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError:
        return {}
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _provider_call_window_begin(slug: str, *, turn: int, attempt: int) -> str:
    """Publish a supervised Kraude provider window and return its nonce.

    Foreground engines have no supervisor to restart them and therefore return
    an empty nonce. The marker contains counters only; prompts, tool arguments,
    URLs, and provider output never enter supervisor state.
    """
    run_id = str(os.environ.get(_SUPERVISED_RUN_ENV) or "")
    if not run_id:
        return ""
    slug = config.slugify(slug)
    if not _valid_run_id(run_id):
        raise RuntimeError("invalid supervised run identity")
    paths = _paths(slug, run_id)
    spec = _read_json(paths["spec"])
    if spec.get("slug") != slug or spec.get("run_id") != run_id:
        raise RuntimeError("supervised run identity does not match private state")
    nonce = secrets.token_hex(16)
    try:
        _create_provider_call_marker(paths["provider_call_window"], {
            "version": 1,
            "state": "active",
            "nonce": nonce,
            "engine_pid": os.getpid(),
            "turn": max(0, int(turn)),
            "attempt": max(0, int(attempt)),
            "started_at": time.time(),
        })
    except FileExistsError as exc:
        raise RuntimeError(
            "a prior Kraude provider call window is still active"
        ) from exc
    return nonce


def _provider_call_window_complete(slug: str, nonce: str) -> None:
    """Clear only the provider window opened by ``nonce``.

    A missing, corrupt, or replaced marker stays fail-closed. Raising here
    leaves the entry in place, so an abnormal engine exit cannot be restarted
    into a possibly repeated native action.
    """
    if not nonce:
        return
    run_id = str(os.environ.get(_SUPERVISED_RUN_ENV) or "")
    if not _valid_run_id(run_id):
        raise RuntimeError("missing supervised run identity for provider completion")
    path = _paths(config.slugify(slug), run_id)["provider_call_window"]
    marker = _read_provider_call_marker(path)
    recorded = marker.get("nonce")
    if not isinstance(recorded, str) or not secrets.compare_digest(recorded, nonce):
        if not _provider_call_window_active(slug, run_id):
            # A native tool or external actor removed the marker while the
            # provider was active. Recreate it before raising so the supervisor
            # cannot mistake this failure for a safe pre-call crash.
            try:
                _create_provider_call_marker(path, {
                    "version": 1,
                    "state": "active",
                    "nonce": nonce,
                    "engine_pid": os.getpid(),
                    "recovered_missing_marker": True,
                    "started_at": time.time(),
                })
            except FileExistsError:
                pass
        raise RuntimeError("provider call window changed before durable completion")
    path.unlink()
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    parent_fd = os.open(path.parent, directory_flags)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _provider_call_window_active(slug: str, run_id: str) -> bool:
    """Treat every filesystem entry at the marker path as active."""
    path = _paths(config.slugify(slug), run_id)["provider_call_window"]
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        # An unreadable marker is still evidence that replay may be unsafe.
        return True
    return True


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _append_event(path: Path, event: str, **fields: Any) -> None:
    """Append a controlled, content-free operational event."""
    _mkdir_private(path.parent)
    row = {"at": time.time(), "event": event, **fields}
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    os.chmod(path, 0o600)


def _process_cmdline(pid: int) -> list[str]:
    if pid <= 1:
        return []
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return []
    return [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]


def pid_matches(pid: int, role: str, slug: str, run_id: str) -> bool:
    """Verify a recorded PID before signaling it; protects against PID reuse."""
    argv = _process_cmdline(int(pid or 0))
    marker = ["-m", "grypton.runtime", role, config.slugify(slug), run_id]
    return any(argv[index:index + len(marker)] == marker
               for index in range(max(0, len(argv) - len(marker) + 1)))


def _current(slug: str) -> tuple[str, dict[str, Path]]:
    pointer = _read_json(_current_path(slug))
    run_id = str(pointer.get("run_id") or "")
    if not _valid_run_id(run_id):
        return "", {}
    return run_id, _paths(slug, run_id)


def _line_count(path: Path) -> int:
    try:
        with path.open(encoding="utf-8", errors="replace") as stream:
            return sum(1 for line in stream if line.strip())
    except OSError:
        return 0


def engine_lock_path(workspace: Workspace) -> Path:
    """Return the shared lock path used by every engine launch."""
    return workspace.root / ".ledger" / "engine.lock"


def engine_lock_is_available(workspace: Workspace) -> bool:
    """Probe the shared engine lock without retaining it.

    The actual foreground or supervised engine holds this same advisory lock for
    its full lifetime. Background startup uses this probe to reject a foreground
    engine that is already active; a launch race is resolved by the engine's
    nonblocking acquisition, so two engines cannot overlap.
    """
    path = engine_lock_path(workspace)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    acquired = False
    try:
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        acquired = True
        return True
    finally:
        if acquired:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _require_pidfd_support() -> None:
    """Reject supervision when race-free descendant cleanup is unavailable."""
    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    if not callable(pidfd_open) or not callable(pidfd_send_signal):
        raise RuntimeError(
            "background supervision requires Linux pidfd cleanup support"
        )
    descriptor: int | None = None
    try:
        descriptor = pidfd_open(os.getpid(), 0)
        # Signal zero performs permission/existence checks without delivering a
        # signal. It verifies both syscalls before any supervisor is launched.
        pidfd_send_signal(descriptor, 0, None, 0)
    except OSError as exc:
        raise RuntimeError(
            "background supervision requires working Linux pidfd cleanup support"
        ) from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _health(slug: str, engine_pid: int) -> dict[str, Any]:
    """Return counters only; never copy prompts, evidence, URLs, or tool input."""
    ws = Workspace(slug)
    meta_status = "missing"
    turns = 0
    family_stagnation = 0
    coverage_rotation = 0
    proof_rotation = 0
    if ws.exists():
        try:
            meta = ws.load_meta()
            meta_status = meta.status
            turns = int(meta.turn_index)
        except (OSError, ValueError, TypeError):
            meta_status = "unreadable"
        else:
            try:
                family_stagnation = max(0, int(meta.family_stagnation_streak))
                coverage_rotation = max(0, int(meta.coverage_rotation_cursor))
                proof_rotation = max(0, int(meta.proof_rotation_cursor))
            except (ValueError, TypeError):
                family_stagnation = 0
                coverage_rotation = 0
                proof_rotation = 0
    ledger = ws.root / ".ledger"
    finding_cases = _line_count(ledger / "findings.jsonl")
    finding_families = 0
    if finding_cases:
        try:
            finding_families = len(ws.finding_family_catalog())
        except (OSError, TypeError, ValueError):
            # Health reporting must not take down the supervisor when an interrupted
            # or externally edited ledger needs repair.
            finding_families = 0
    return {
        "engine_pid": int(engine_pid or 0),
        "engine_alive": pid_matches(engine_pid, "engine", slug,
                                    _current(slug)[0]) if engine_pid else False,
        "workspace_status": meta_status,
        "turns": turns,
        "family_stagnation_streak": family_stagnation,
        "coverage_rotation_cursor": coverage_rotation,
        "proof_rotation_cursor": proof_rotation,
        "tool_calls": _line_count(ledger / "tool-calls.jsonl"),
        "effectful_tool_starts": _line_count(
            ledger / "effectful-tool-starts.jsonl"
        ),
        "findings": finding_cases,
        "finding_cases": finding_cases,
        "finding_families": finding_families,
        "surface": _line_count(ledger / "attack-surface.jsonl"),
        "tested": _line_count(ledger / "tested-techniques.jsonl"),
        "provider_calls": _line_count(ws.transcripts_dir / "provider-calls.jsonl"),
    }


def _astra_completion_count(slug: str, until_severity: str) -> int:
    """Count durable Astra verdicts that satisfy an indefinite run policy."""
    findings = [
        finding for finding in Workspace(slug).findings.all()
        if isinstance(finding, dict)
    ]
    return len(astra_confirmed_cases_at_or_above(findings, until_severity))


def _state_update(path: Path, state: dict[str, Any], **changes: Any) -> None:
    """Merge state changes under a process lock; parent and child start concurrently."""
    _mkdir_private(path.parent)
    lock_path = path.with_suffix(path.suffix + ".lock")
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(lock_path, flags, 0o600)
    os.fchmod(fd, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        latest = _read_json(path) or dict(state)
        latest.update(changes)
        latest["updated_at"] = time.time()
        _write_json(path, latest)
        state.clear()
        state.update(latest)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _start_background_locked(
    ws: Workspace,
    *,
    brief: str,
    backend: str,
    max_run_seconds: int,
    max_turns: int,
    stop_on_p1: bool,
    worker_model: str,
    worker_effort: str,
    manager_model: str,
    manager_effort: str,
    forever: bool = False,
    until_severity: str = "",
    fresh_worker_session: bool = False,
    health_interval_seconds: int = 600,
    restart_limit: int | None = None,
) -> dict[str, Any]:
    """Start one detached supervisor and return its public, secret-free state."""
    duration = int(max_run_seconds or 0)
    interval = int(health_interval_seconds or 0)
    indefinite = bool(forever)
    threshold = str(until_severity or "").strip().upper()
    if indefinite:
        if duration > 0 or int(max_turns or 0) > 0:
            raise ValueError("--forever cannot have a duration or turn ceiling")
        if threshold not in {"P1", "P2"}:
            threshold = "P1" if stop_on_p1 else "P2"
        if restart_limit is not None:
            raise ValueError("--forever uses unlimited safe restarts")
        retries: int | None = None
    else:
        if duration <= 0:
            raise ValueError(
                "background runs require a finite --duration, --max-seconds, "
                "or --auto-stop-time (or use --forever)"
            )
        if threshold and threshold not in {"P1", "P2"}:
            raise ValueError("--until-severity must be P1 or P2")
        retries = 3 if restart_limit is None else int(restart_limit)
    if not 5 <= interval <= 3600:
        raise ValueError("--health-interval must be between 5 seconds and 1 hour")
    if retries is not None and not 0 <= retries <= 20:
        raise ValueError("--restart-limit must be between 0 and 20")
    _require_pidfd_support()

    prior_id, prior_paths = _current(ws.slug)
    if prior_id and prior_paths:
        prior = _read_json(prior_paths["state"])
        prior_pid = int(prior.get("supervisor_pid") or 0)
        if pid_matches(prior_pid, "supervise", ws.slug, prior_id):
            raise RuntimeError(f"a background supervisor is already running for {ws.slug}")
    if not engine_lock_is_available(ws):
        raise RuntimeError(f"an engagement engine is already running for {ws.slug}")

    now = time.time()
    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now)) + "-" + secrets.token_hex(4)
    paths = _paths(ws.slug, run_id)
    _mkdir_private(paths["root"])
    deadline = None if indefinite else now + duration
    # This is the only supervisor file containing the brief. It is never
    # returned by status, appended to events, or placed in any process argv.
    spec = {
        "version": 2,
        "slug": ws.slug,
        "run_id": run_id,
        "brief": str(brief or ""),
        "backend": str(backend),
        "deadline_at": deadline,
        "starting_turn_index": int(ws.load_meta().turn_index),
        "run_mode": "until-finding" if indefinite else "finite",
        "until_severity": threshold,
        "max_turns": int(max_turns or 0),
        "stop_on_p1": bool(stop_on_p1),
        "worker_model": str(worker_model),
        "worker_effort": str(worker_effort),
        "manager_model": str(manager_model),
        "manager_effort": str(manager_effort),
        # This is private one-shot launch state. It is consumed by the first
        # engine child so a supervisor restart resumes the replacement worker
        # conversation instead of repeatedly discarding it.
        "fresh_worker_session": bool(fresh_worker_session),
        "fresh_worker_session_consumed": False,
        "health_interval_seconds": interval,
        "restart_limit": retries,
        # Persistent engine modes continue through convergence. A finite run
        # ends at its deadline; an indefinite run ends at its Astra threshold.
        "run_until_deadline": not indefinite,
        "run_until_stopped": indefinite,
    }
    _write_json(paths["spec"], spec)
    state = {
        "version": 2,
        "run_id": run_id,
        "slug": ws.slug,
        "status": "starting",
        "started_at": now,
        "deadline_at": deadline,
        "run_mode": "until-finding" if indefinite else "finite",
        "until_severity": threshold,
        "restart_policy": "unlimited-safe" if indefinite else "limited",
        "health_interval_seconds": interval,
        "restart_limit": retries,
        "restarts": 0,
        "consecutive_failures": 0,
        "consecutive_immediate_failures": 0,
        "retry_delay_seconds": 0,
        "next_retry_at": None,
        "supervisor_pid": 0,
        "engine_pid": 0,
        "last_health": {},
    }
    _write_json(paths["state"], state)
    _write_json(_current_path(ws.slug), {"run_id": run_id})
    try:
        (ws.root / ".ledger" / "STOP").unlink(missing_ok=True)
    except OSError:
        pass

    env = os.environ.copy()
    env["GRYPTON_HOME"] = str(config.GRYPTON_HOME)
    argv = [sys.executable, "-m", "grypton.runtime", "supervise", ws.slug, run_id]
    process = subprocess.Popen(
        argv,
        cwd=str(config.SOURCE_ROOT),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )
    _write_text_private(paths["supervisor_pid"], f"{process.pid}\n")
    _state_update(paths["state"], state, supervisor_pid=process.pid)
    _append_event(
        paths["events"],
        "supervisor_spawned",
        supervisor_pid=process.pid,
        run_mode=state["run_mode"],
        until_severity=threshold,
    )
    ready_by = time.monotonic() + 5
    while time.monotonic() < ready_by:
        current = _read_json(paths["state"])
        if (int(current.get("supervisor_pid") or 0) == process.pid
                and current.get("status") in {"running", "restarting"}
                and pid_matches(process.pid, "supervise", ws.slug, run_id)):
            _append_event(paths["events"], "supervisor_ready", supervisor_pid=process.pid)
            return public_status(ws.slug)
        if process.poll() is not None:
            _state_update(paths["state"], state, status="failed",
                          stop_reason="supervisor exited before readiness",
                          ended_at=time.time())
            raise RuntimeError("background supervisor exited before it became ready")
        time.sleep(0.05)
    try:
        process.terminate()
    except OSError:
        pass
    _state_update(paths["state"], state, status="failed",
                  stop_reason="supervisor readiness timeout", ended_at=time.time())
    raise RuntimeError("background supervisor did not become ready within 5 seconds")


def start_background(ws: Workspace, **options: Any) -> dict[str, Any]:
    """Serialize the live-check and current-pointer update for one engagement."""
    root = _root(ws.slug)
    _mkdir_private(root)
    lock_path = root / "start.lock"
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(lock_path, flags, 0o600)
    os.fchmod(fd, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return _start_background_locked(ws, **options)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def public_status(slug: str) -> dict[str, Any]:
    """Return a safe operational view; private spec content is intentionally absent."""
    slug = config.slugify(slug)
    run_id, paths = _current(slug)
    if not run_id:
        return {"slug": slug, "status": "not-started", "alive": False}
    state = _read_json(paths["state"])
    supervisor_pid = int(state.get("supervisor_pid") or 0)
    alive = pid_matches(supervisor_pid, "supervise", slug, run_id)
    status = str(state.get("status") or "unknown")
    if status in {"starting", "running", "restarting", "stopping"} and not alive:
        status = "orphaned"
    allowed = (
        "version", "run_id", "slug", "started_at", "deadline_at", "ended_at",
        "health_interval_seconds", "restart_limit", "restarts", "supervisor_pid",
        "engine_pid", "last_health", "last_exit_code", "stop_reason", "updated_at",
        "run_mode", "until_severity", "restart_policy", "consecutive_failures",
        "consecutive_immediate_failures", "retry_delay_seconds", "next_retry_at",
        "last_engine_runtime_seconds",
    )
    result = {key: state.get(key) for key in allowed if key in state}
    result.update({"status": status, "alive": alive, "events": str(paths["events"])})
    return result


def read_events(slug: str, limit: int = 20) -> list[dict[str, Any]]:
    run_id, paths = _current(slug)
    if not run_id:
        return []
    rows: list[dict[str, Any]] = []
    try:
        with paths["events"].open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                try:
                    value = json.loads(line)
                except ValueError:
                    continue
                if isinstance(value, dict):
                    rows.append(value)
    except OSError:
        return []
    return rows[-max(1, min(int(limit), 200)):]


def request_background_stop(slug: str) -> bool:
    """Signal only the verified current supervisor; return whether one was live."""
    slug = config.slugify(slug)
    run_id, paths = _current(slug)
    if not run_id:
        return False
    state = _read_json(paths["state"])
    pid = int(state.get("supervisor_pid") or 0)
    if not pid_matches(pid, "supervise", slug, run_id):
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return False
    return True


def _process_snapshot(pid: int) -> _ProcessSnapshot | None:
    """Read identity, group, and parent from one Linux procfs snapshot."""
    if not isinstance(pid, int) or pid <= 1:
        return None
    try:
        stat_bytes = Path(f"/proc/{pid}/stat").read_bytes()
    except OSError:
        return None
    # comm is arbitrary bytes and may contain spaces or ')'. The kernel's final
    # ')' is the only reliable boundary before the fixed-width numeric fields.
    open_marker = stat_bytes.find(b" (")
    close = stat_bytes.rfind(b")")
    if (open_marker <= 0 or close <= open_marker + 1
            or stat_bytes[close + 1:close + 2] != b" "):
        return None
    fields = stat_bytes[close + 2:].split()
    # These values begin at proc(5) field 3. Parent PID is field 4, process
    # group is field 5, and process start time is field 22.
    if len(fields) < 20 or fields[0] == b"Z":
        return None
    try:
        recorded_pid = int(stat_bytes[:open_marker])
        if recorded_pid != pid:
            return None
        return _ProcessSnapshot(
            identity=_ProcessIdentity(
                pid=pid,
                pgid=int(fields[2]),
                start_time=fields[19].decode("ascii"),
            ),
            ppid=int(fields[1]),
        )
    except (UnicodeDecodeError, ValueError):
        return None


def _process_identity(pid: int) -> _ProcessIdentity | None:
    snapshot = _process_snapshot(pid)
    return snapshot.identity if snapshot is not None else None


def _descendant_pgids(root_pid: int) -> _ProcessGroups:
    """Snapshot stable identities grouped below the live engine process."""
    snapshots: dict[int, _ProcessSnapshot] = {}
    try:
        entries = list(Path("/proc").iterdir())
    except OSError:
        return {}
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        snapshot = _process_snapshot(pid)
        if snapshot is not None:
            snapshots[pid] = snapshot

    # Recheck after the complete scan. If a numeric PID was reused while procfs
    # was being enumerated, remove that node before its numeric PPID can connect
    # an unrelated process to a historical descendant chain.
    stable = {
        pid: snapshot for pid, snapshot in snapshots.items()
        if _process_snapshot(pid) == snapshot
    }
    if int(root_pid) not in stable:
        return {}
    descendants = {int(root_pid)}
    changed = True
    while changed:
        changed = False
        for pid, snapshot in stable.items():
            if snapshot.ppid in descendants and pid not in descendants:
                descendants.add(pid)
                changed = True
    groups: _ProcessGroups = {}
    own_group = os.getpgrp()
    for pid in descendants:
        identity = stable[pid].identity
        if identity.pgid > 1 and identity.pgid != own_group:
            groups.setdefault(identity.pgid, set()).add(identity)
    return groups


def _merge_process_groups(target: _ProcessGroups, source: _ProcessGroups) -> None:
    """Retain every process identity observed while below a live engine."""
    for pgid, identities in source.items():
        target.setdefault(pgid, set()).update(identities)


def _group_members(pgid: int) -> set[_ProcessIdentity]:
    """Return current members of a process group as stable identities."""
    members: set[_ProcessIdentity] = set()
    try:
        entries = list(Path("/proc").iterdir())
    except OSError:
        return members
    for entry in entries:
        if not entry.name.isdigit():
            continue
        identity = _process_identity(int(entry.name))
        if identity is not None and identity.pgid == pgid:
            members.add(identity)
    return members


def _identity_matches(identity: _ProcessIdentity) -> bool:
    current = _process_identity(identity.pid)
    return bool(
        current
        and current.pid == identity.pid
        and current.start_time == identity.start_time
    )


def _identity_still_in_group(identity: _ProcessIdentity, pgid: int) -> bool:
    current = _process_identity(identity.pid)
    return bool(
        current
        and current.pid == identity.pid
        and current.start_time == identity.start_time
        and current.pgid == pgid
    )


def _open_verified_pidfd(
    identity: _ProcessIdentity,
) -> tuple[int | None, bool]:
    """Return a pinned descriptor and whether opening it avoided an op failure."""
    if not _identity_matches(identity):
        return None, True
    pidfd_open = getattr(os, "pidfd_open", None)
    if not callable(pidfd_open):
        return None, False
    try:
        descriptor = pidfd_open(identity.pid, 0)
    except OSError as exc:
        return None, exc.errno == errno.ESRCH
    if _identity_matches(identity):
        return descriptor, True
    try:
        os.close(descriptor)
    except OSError:
        pass
    return None, True


def _signal_process_groups(
    groups: _ProcessGroups,
    sig: signal.Signals,
) -> bool:
    """Signal verified members and report whether pidfd operations succeeded."""
    own_group = os.getpgrp()
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    if not callable(pidfd_send_signal):
        # There is no race-free numeric-PID fallback.
        return not any(
            _identity_matches(identity)
            for identities in groups.values()
            for identity in identities
        )

    operational_ok = True
    for group, observed in sorted(groups.items()):
        if group <= 1 or group == own_group:
            continue
        historical = tuple(observed)
        descriptors: dict[int, int] = {}
        try:
            # Pin every previously observed identity independently. A process
            # remains eligible even if it changed groups after observation.
            for identity in sorted(historical, key=lambda item: item.pid):
                if identity.pid in descriptors:
                    continue
                descriptor, opened = _open_verified_pidfd(identity)
                operational_ok = operational_ok and opened
                if descriptor is not None:
                    descriptors[identity.pid] = descriptor

            # Discover additional group members only while an observed identity
            # still proves this is the original process group.
            current_members: set[_ProcessIdentity] = set()
            if any(_identity_still_in_group(identity, group)
                   for identity in historical):
                current_members = _group_members(group)
                for identity in sorted(current_members, key=lambda item: item.pid):
                    if identity.pid in descriptors:
                        continue
                    descriptor, opened = _open_verified_pidfd(identity)
                    operational_ok = operational_ok and opened
                    if descriptor is not None:
                        descriptors[identity.pid] = descriptor
                observed.update(current_members)

            for descriptor in descriptors.values():
                try:
                    pidfd_send_signal(descriptor, sig, None, 0)
                except OSError as exc:
                    if exc.errno != errno.ESRCH:
                        operational_ok = False
        finally:
            for descriptor in descriptors.values():
                try:
                    os.close(descriptor)
                except OSError:
                    pass
    return operational_ok


def _known_groups_are_gone(groups: _ProcessGroups) -> bool:
    return not any(
        _identity_matches(identity)
        for identities in groups.values()
        for identity in identities
    )


def _reap_known_groups(groups: _ProcessGroups) -> bool:
    """Terminate verified providers and confirm no recorded identity survived."""
    if not groups:
        return True
    operational_ok = _signal_process_groups(groups, signal.SIGTERM)
    time.sleep(0.2)
    operational_ok = _signal_process_groups(groups, signal.SIGKILL) and operational_ok
    for _attempt in range(10):
        if _known_groups_are_gone(groups):
            return True
        time.sleep(0.05)
    survivors_gone = _known_groups_are_gone(groups)
    # Operational errors are material only while a verified process survives.
    if not survivors_gone and not operational_ok:
        return False
    return survivors_gone


def _stop_engine(
    process: subprocess.Popen,
    known_groups: _ProcessGroups | None = None,
) -> bool:
    """Stop the engine and return whether every verified process was reaped."""
    groups: _ProcessGroups = {
        pgid: set(identities) for pgid, identities in (known_groups or {}).items()
    }
    # Never discover through a PID after Popen says its process exited: that PID
    # can be reused before cleanup runs. Only identities captured while it was
    # demonstrably alive are eligible for later orphan cleanup.
    if process.poll() is not None:
        return _reap_known_groups(groups)
    _merge_process_groups(groups, _descendant_pgids(process.pid))
    _signal_engine(process, signal.SIGTERM)
    try:
        process.wait(timeout=15)
        return _reap_known_groups(groups)
    except subprocess.TimeoutExpired:
        pass
    _merge_process_groups(groups, _descendant_pgids(process.pid))
    _signal_process_groups(groups, signal.SIGTERM)
    try:
        process.wait(timeout=3)
        return _reap_known_groups(groups)
    except subprocess.TimeoutExpired:
        pass
    _merge_process_groups(groups, _descendant_pgids(process.pid))
    _signal_process_groups(groups, signal.SIGKILL)
    _signal_engine(process, signal.SIGKILL)
    engine_stopped = True
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        engine_stopped = False
    return _reap_known_groups(groups) and engine_stopped


def _signal_engine(process: subprocess.Popen, sig: signal.Signals) -> None:
    """Signal the dedicated engine process group created by the supervisor."""
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, sig)
    except (OSError, ProcessLookupError):
        try:
            process.send_signal(sig)
        except OSError:
            pass


def _engine_argv(slug: str, run_id: str) -> list[str]:
    # The mission and every model/request option are loaded from the private spec
    # inside this child. They never appear in /proc/<pid>/cmdline or ps output.
    return [sys.executable, "-m", "grypton.runtime", "engine", slug, run_id]


def _advance_health_deadline(
    scheduled_at: float,
    observed_at: float,
    interval: float,
) -> float:
    """Return the first scheduled health deadline after ``observed_at``.

    A zero deadline represents the immediate first health check. Later checks
    stay anchored to their original cadence, and a delayed supervisor skips
    missed slots instead of permanently shifting every subsequent check.
    """
    if scheduled_at <= 0:
        return observed_at + interval
    elapsed = max(0.0, observed_at - scheduled_at)
    slots = math.floor(elapsed / interval) + 1
    return scheduled_at + (slots * interval)


def _restart_delay(consecutive_failures: int) -> int:
    """Return bounded backoff for one uninterrupted engine-failure streak."""
    index = max(1, int(consecutive_failures)) - 1
    return _RESTART_BACKOFF_SECONDS[min(index, len(_RESTART_BACKOFF_SECONDS) - 1)]


def _failure_streak(previous: int, runtime_seconds: float | None) -> tuple[int, bool]:
    """Advance a failure streak, resetting after a sustained engine runtime.

    A spawn failure has no runtime and is necessarily immediate. A child that
    stayed alive for five minutes has demonstrated enough liveness that its
    next recovery starts at the shortest delay again.
    """
    immediate = (
        runtime_seconds is None
        or runtime_seconds < _SUSTAINED_ENGINE_RUNTIME_SECONDS
    )
    return ((max(0, int(previous)) + 1) if immediate else 1, immediate)


def supervise(slug: str, run_id: str) -> int:
    slug = config.slugify(slug)
    paths = _paths(slug, run_id)
    spec = _read_json(paths["spec"])
    if spec.get("slug") != slug or spec.get("run_id") != run_id:
        return 2
    state = _read_json(paths["state"])
    _write_text_private(paths["supervisor_pid"], f"{os.getpid()}\n")
    run_mode = str(spec.get("run_mode") or "finite")
    indefinite = run_mode == "until-finding"
    threshold = str(spec.get("until_severity") or "").strip().upper()
    if indefinite and threshold not in {"P1", "P2"}:
        return 2
    deadline_value = spec.get("deadline_at")
    if indefinite:
        deadline: float | None = None
    else:
        try:
            deadline = float(deadline_value)
        except (TypeError, ValueError):
            return 2
    raw_restart_limit = spec.get("restart_limit", 3)
    if indefinite and raw_restart_limit is None:
        restart_limit: int | None = None
    else:
        try:
            restart_limit = int(raw_restart_limit)
        except (TypeError, ValueError):
            return 2
        if not 0 <= restart_limit <= 20:
            return 2

    _state_update(paths["state"], state, supervisor_pid=os.getpid(), status="running")
    _append_event(
        paths["events"],
        "supervisor_started",
        supervisor_pid=os.getpid(),
        run_mode=run_mode,
        until_severity=threshold,
    )

    stop_requested = False

    def on_stop(_signum, _frame) -> None:
        nonlocal stop_requested
        stop_requested = True

    previous_term = signal.getsignal(signal.SIGTERM)
    previous_int = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGTERM, on_stop)
    signal.signal(signal.SIGINT, on_stop)
    interval = int(spec["health_interval_seconds"])
    restarts = 0
    consecutive_failures = 0
    consecutive_immediate_failures = 0
    exit_status = "failed"
    stop_reason = "supervisor failure"
    child: subprocess.Popen | None = None
    observed_groups: _ProcessGroups = {}
    cleanup_complete = True

    try:
        while True:
            if stop_requested:
                exit_status, stop_reason = "stopped", "operator stop"
                break
            if indefinite and _astra_completion_count(slug, threshold):
                exit_status = "completed"
                stop_reason = f"Astra confirmed {threshold} or higher"
                break
            if deadline is not None and time.time() >= deadline:
                exit_status, stop_reason = "expired", "duration reached"
                break

            env = os.environ.copy()
            env["GRYPTON_HOME"] = str(config.GRYPTON_HOME)
            env["GRYPTON_SUPERVISED"] = "1"
            try:
                child = subprocess.Popen(
                    _engine_argv(slug, run_id),
                    cwd=str(config.SOURCE_ROOT),
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                    close_fds=True,
                )
            except OSError as exc:
                _append_event(paths["events"], "engine_spawn_failed",
                              error_type=type(exc).__name__, restart=restarts)
                if restart_limit is not None and restarts >= restart_limit:
                    exit_status, stop_reason = "failed", "restart limit reached"
                    break
                restarts += 1
                consecutive_failures, _ = _failure_streak(
                    consecutive_failures, None
                )
                consecutive_immediate_failures += 1
                delay = _restart_delay(consecutive_failures)
                retry_until = time.time() + delay
                if deadline is not None:
                    retry_until = min(retry_until, deadline)
                _state_update(
                    paths["state"],
                    state,
                    status="restarting",
                    restarts=restarts,
                    engine_pid=0,
                    consecutive_failures=consecutive_failures,
                    consecutive_immediate_failures=consecutive_immediate_failures,
                    retry_delay_seconds=delay,
                    next_retry_at=retry_until,
                )
                _append_event(
                    paths["events"],
                    "restart_scheduled",
                    restart=restarts,
                    previous_failure="spawn",
                    consecutive_failures=consecutive_failures,
                    consecutive_immediate_failures=consecutive_immediate_failures,
                    delay_seconds=delay,
                    next_retry_at=retry_until,
                )
                while time.time() < retry_until and not stop_requested:
                    time.sleep(0.25)
                continue

            engine_started_at = time.monotonic()
            _write_text_private(paths["engine_pid"], f"{child.pid}\n")
            _state_update(
                paths["state"],
                state,
                status="running",
                engine_pid=child.pid,
                restarts=restarts,
                retry_delay_seconds=0,
                next_retry_at=None,
            )
            _append_event(paths["events"], "engine_started", engine_pid=child.pid,
                          restart=restarts)
            next_health = 0.0
            timed_out = False
            stopped = False
            threshold_met = False
            backoff_reset = False
            observed_groups = _descendant_pgids(child.pid)
            while child.poll() is None:
                _merge_process_groups(
                    observed_groups, _descendant_pgids(child.pid)
                )
                now = time.time()
                engine_runtime = max(0.0, time.monotonic() - engine_started_at)
                if (not backoff_reset
                        and consecutive_failures
                        and engine_runtime >= _SUSTAINED_ENGINE_RUNTIME_SECONDS):
                    consecutive_failures = 0
                    consecutive_immediate_failures = 0
                    backoff_reset = True
                    _state_update(
                        paths["state"],
                        state,
                        consecutive_failures=0,
                        consecutive_immediate_failures=0,
                    )
                    _append_event(
                        paths["events"],
                        "restart_backoff_reset",
                        engine_runtime_seconds=round(engine_runtime, 3),
                    )
                if stop_requested:
                    stopped = True
                    _state_update(paths["state"], state, status="stopping")
                    _signal_engine(child, signal.SIGTERM)
                    break
                if indefinite and _astra_completion_count(slug, threshold):
                    threshold_met = True
                    _state_update(paths["state"], state, status="stopping")
                    _signal_engine(child, signal.SIGTERM)
                    break
                if deadline is not None and now >= deadline:
                    timed_out = True
                    _state_update(paths["state"], state, status="stopping")
                    _signal_engine(child, signal.SIGTERM)
                    break
                if now >= next_health:
                    health = _health(slug, child.pid)
                    _state_update(paths["state"], state, last_health=health)
                    _append_event(paths["events"], "health", **health)
                    next_health = _advance_health_deadline(
                        next_health,
                        time.time(),
                        interval,
                    )
                time.sleep(0.5)

            if stopped or timed_out or threshold_met:
                cleanup_complete = _stop_engine(child, observed_groups)
                if cleanup_complete:
                    if threshold_met:
                        exit_status = "completed"
                        stop_reason = f"Astra confirmed {threshold} or higher"
                    elif stopped:
                        exit_status, stop_reason = "stopped", "operator stop"
                    else:
                        exit_status, stop_reason = "expired", "duration reached"
                else:
                    exit_status = "failed"
                    stop_reason = "verified process cleanup incomplete"
                break

            returncode = int(child.wait())
            engine_runtime = max(0.0, time.monotonic() - engine_started_at)
            # The engine may have been killed after spawning providers in their
            # own sessions. Reap the groups observed while it was alive even
            # though their PPID may already have changed.
            cleanup_complete = _stop_engine(child, observed_groups)
            _append_event(
                paths["events"],
                "engine_exited",
                returncode=returncode,
                restart=restarts,
                engine_runtime_seconds=round(engine_runtime, 3),
            )
            _state_update(
                paths["state"],
                state,
                last_exit_code=returncode,
                last_engine_runtime_seconds=round(engine_runtime, 3),
                engine_pid=0,
            )
            try:
                paths["engine_pid"].unlink(missing_ok=True)
            except OSError:
                pass
            if not cleanup_complete:
                exit_status = "failed"
                stop_reason = "verified process cleanup incomplete"
                break
            # In finite mode a zero exit is terminal for compatibility. In an
            # indefinite run it is successful only when the durable Astra
            # threshold is present; a premature clean exit is safely resumed.
            if returncode == 0:
                if not indefinite:
                    exit_status, stop_reason = "completed", "clean engine exit"
                    break
                if _astra_completion_count(slug, threshold):
                    exit_status = "completed"
                    stop_reason = f"Astra confirmed {threshold} or higher"
                    break
            if stop_requested:
                exit_status, stop_reason = "stopped", "operator stop"
                break
            if deadline is not None and time.time() >= deadline:
                exit_status, stop_reason = "expired", "duration reached"
                break
            after = _health(slug, 0)
            stop_flag = Workspace(slug).root / ".ledger" / "STOP"
            if (not indefinite
                    and (stop_flag.exists()
                         or after.get("workspace_status") == "stopped")):
                exit_status, stop_reason = "completed", "persisted engine stop"
                break
            if _provider_call_window_active(slug, run_id):
                exit_status = "failed"
                stop_reason = (
                    "abnormal exit during a Kraude provider call; replay disabled"
                )
                _append_event(
                    paths["events"],
                    "restart_suppressed",
                    reason="worker_provider_call_active",
                )
                break
            if restart_limit is not None and restarts >= restart_limit:
                exit_status, stop_reason = "failed", "restart limit reached"
                break

            restarts += 1
            consecutive_failures, immediate = _failure_streak(
                consecutive_failures, engine_runtime
            )
            if immediate:
                consecutive_immediate_failures += 1
            else:
                consecutive_immediate_failures = 0
            delay = _restart_delay(consecutive_failures)
            until = time.time() + delay
            if deadline is not None:
                until = min(until, deadline)
            _state_update(
                paths["state"],
                state,
                status="restarting",
                restarts=restarts,
                consecutive_failures=consecutive_failures,
                consecutive_immediate_failures=consecutive_immediate_failures,
                retry_delay_seconds=delay,
                next_retry_at=until,
            )
            _append_event(
                paths["events"],
                "restart_scheduled",
                restart=restarts,
                previous_returncode=returncode,
                consecutive_failures=consecutive_failures,
                consecutive_immediate_failures=consecutive_immediate_failures,
                immediate_failure=immediate,
                engine_runtime_seconds=round(engine_runtime, 3),
                delay_seconds=delay,
                next_retry_at=until,
            )
            while time.time() < until and not stop_requested:
                time.sleep(0.25)
    finally:
        if child is not None:
            cleanup_complete = (
                _stop_engine(child, observed_groups) and cleanup_complete
            )
        if not cleanup_complete:
            exit_status = "failed"
            stop_reason = "verified process cleanup incomplete"
            _append_event(paths["events"], "cleanup_failed")
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)
        try:
            paths["engine_pid"].unlink(missing_ok=True)
            paths["supervisor_pid"].unlink(missing_ok=True)
        except OSError:
            pass
        _state_update(paths["state"], state, status=exit_status, stop_reason=stop_reason,
                      ended_at=time.time(), engine_pid=0, restarts=restarts)
        _append_event(paths["events"], "supervisor_stopped", status=exit_status,
                      reason=stop_reason, restarts=restarts)
    return 0 if exit_status in {"completed", "stopped", "expired"} else 1


def run_engine(slug: str, run_id: str) -> int:
    """Load private settings and invoke resume without exposing them in argv."""
    slug = config.slugify(slug)
    spec = _read_json(_paths(slug, run_id)["spec"])
    if spec.get("slug") != slug or spec.get("run_id") != run_id:
        return 2
    run_mode = str(spec.get("run_mode") or "finite")
    indefinite = run_mode == "until-finding"
    if indefinite:
        remaining = None
    else:
        remaining = max(
            1,
            int(math.ceil(float(spec["deadline_at"]) - time.time())),
        )
    fresh_worker_session = (
        spec.get("fresh_worker_session") is True
        and spec.get("fresh_worker_session_consumed") is not True
    )
    if fresh_worker_session:
        # Clear the inherited worker UUID before consuming the one-shot bit.
        # Both writes are idempotent: a crash between them retries the clear,
        # while a crash after them cannot resume the pre-run conversation.
        Workspace(slug).update_meta(worker_uuid="")
        spec["fresh_worker_session_consumed"] = True
        _write_json(_paths(slug, run_id)["spec"], spec)
    arguments = [
        "resume", slug, "-p", "--console", "quiet",
        "--backend", str(spec.get("backend") or "real"),
        "--kraude-model", str(spec.get("worker_model") or config.CONFIG.worker_model),
        "--kraude-effort", str(spec.get("worker_effort") or config.CONFIG.worker_effort),
        "--kryptex-model", str(spec.get("manager_model") or config.CONFIG.manager_model),
        "--kryptex-effort", str(spec.get("manager_effort") or config.CONFIG.manager_effort),
    ]
    if remaining is not None:
        arguments.extend(("--max-seconds", str(remaining)))
    starting_turn = spec.get("starting_turn_index")
    if isinstance(starting_turn, bool) or not isinstance(starting_turn, int):
        # A supervisor created by an older release has no starting-turn
        # checkpoint. Its private restart count still distinguishes the first
        # child from a replacement, so never replay a one-shot login/mission
        # brief merely because the spec predates this field.
        legacy_state = _read_json(_paths(slug, run_id)["state"])
        legacy_restarts = legacy_state.get("restarts")
        brief_pending = bool(
            isinstance(legacy_restarts, int)
            and not isinstance(legacy_restarts, bool)
            and legacy_restarts == 0
        )
    else:
        try:
            brief_pending = Workspace(slug).load_meta().turn_index == starting_turn
        except (OSError, TypeError, ValueError):
            return 2
    if spec.get("brief") and brief_pending:
        arguments.extend(("--brief", str(spec["brief"])))
    if int(spec.get("max_turns") or 0):
        arguments.extend(("--max-turns", str(int(spec["max_turns"]))))
    if spec.get("stop_on_p1"):
        arguments.append("--stop-on-p1")
    if spec.get("until_severity"):
        arguments.extend(("--until-severity", str(spec["until_severity"])))
    if spec.get("run_until_deadline"):
        arguments.append("--run-until-deadline")
    if spec.get("run_until_stopped"):
        arguments.append("--run-until-stopped")
    if fresh_worker_session:
        arguments.append("--fresh-worker-session")
    from .cli import main
    prior_run_id = os.environ.get(_SUPERVISED_RUN_ENV)
    os.environ[_SUPERVISED_RUN_ENV] = run_id
    try:
        return int(main(arguments))
    finally:
        if prior_run_id is None:
            os.environ.pop(_SUPERVISED_RUN_ENV, None)
        else:
            os.environ[_SUPERVISED_RUN_ENV] = prior_run_id


_ERROR_SECRET_RX = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|cookie)"
    r"(\s*[:=]\s*)[^\s,;&]+"
)
_ERROR_BEARER_RX = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_ERROR_LONG_NUMBER_RX = re.compile(r"(?<!\d)\d{8,}(?!\d)")


def _safe_error(exc: BaseException, spec: dict[str, Any]) -> str:
    """Bound and redact a child failure without copying a mission or credential."""
    value = " ".join(str(exc or "").split())
    brief = str(spec.get("brief") or "")
    if brief:
        value = value.replace(brief, "[REDACTED BRIEF]")
    value = _ERROR_SECRET_RX.sub(lambda match: f"{match.group(1)}=[REDACTED]", value)
    value = _ERROR_BEARER_RX.sub("Bearer [REDACTED]", value)
    value = _ERROR_LONG_NUMBER_RX.sub("[REDACTED NUMBER]", value)
    return value[:240] or "no message"


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 3 or args[0] not in {"supervise", "engine"}:
        return 2
    role, slug, run_id = args
    if not _valid_run_id(run_id):
        return 2
    try:
        return supervise(slug, run_id) if role == "supervise" else run_engine(slug, run_id)
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            return int(getattr(exc, "code", 1) or 0)
        paths = _paths(config.slugify(slug), run_id)
        spec = _read_json(paths["spec"])
        try:
            _append_event(paths["events"], f"{role}_process_failed",
                          error_type=type(exc).__name__, message=_safe_error(exc, spec))
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
